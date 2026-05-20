//! Windows Installer Authenticode digest (`MSISIP.DLL`) vs PKCS#7 `SpcIndirectData`.
//!
//! The traversal matches **Signify** `SignedMsiFile` (`signify/authenticode/signed_file/msi.py`,
//! Apache-2.0): sorted UTF-16 code-unit order on sibling names, skip `\u{5}DigitalSignature` and
//! `\u{5}MsiDigitalSignatureEx`, optional metadata **pre-hash** when `MsiDigitalSignatureEx` exists,
//! then recursive stream hashing plus per-storage CLSID little-endian bytes at each storage close.
//! **MSISIP.DLL** uses **`DigestStorageMetadataHelper`** / **`DigestStorageContentHelper`** for storage traversal;
//! see **`docs/windows-signing-components.md`**.

use super::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use cfb::{CompoundFile, Entry};
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// OLE stream names use a leading VT_LPWSTR length marker `\x05` (SIGNIFY / olefile convention).
const DIGITAL_SIGNATURE_ENTRY: &str = "\u{5}DigitalSignature";
const EXTENDED_SIGNATURE_ENTRY: &str = "\u{5}MsiDigitalSignatureEx";

/// FILETIME ticks between 1601-01-01 UTC and 1970-01-01 UTC (100 ns units).
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

fn root_stream(name: &str) -> PathBuf {
    Path::new("/").join(name)
}

fn cmp_utf16_name(a: &str, b: &str) -> Ordering {
    let ae: Vec<u8> = a.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let be: Vec<u8> = b.encode_utf16().flat_map(u16::to_le_bytes).collect();
    ae.cmp(&be)
}

fn hash_utf16_name<H: Digest>(name: &str, hasher: &mut H) {
    for u in name.encode_utf16() {
        hasher.update(u.to_le_bytes());
    }
}

fn system_time_to_filetime_le(st: SystemTime) -> [u8; 8] {
    let ticks = match st.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let t = d.as_secs().saturating_mul(10_000_000) + u64::from(d.subsec_nanos()) / 100;
            t.saturating_add(FILETIME_UNIX_EPOCH)
        }
        Err(_) => 0,
    };
    ticks.to_le_bytes()
}

fn prehash_entry<H: Digest>(entry: &Entry, hasher: &mut H) {
    if !entry.is_root() {
        hash_utf16_name(entry.name(), hasher);
    }
    if entry.is_root() || entry.is_storage() {
        hasher.update(entry.clsid().to_bytes_le());
    }
    if entry.is_stream() {
        let sz = u32::try_from(entry.len()).unwrap_or(0xffff_ffff);
        hasher.update(sz.to_le_bytes());
    }
    hasher.update(entry.state_bits().to_le_bytes());
    if !entry.is_root() {
        hasher.update(system_time_to_filetime_le(entry.created()));
        hasher.update(system_time_to_filetime_le(entry.modified()));
    }
}

fn prehash_storage_recursive<F: Read + Seek, H: Digest>(
    cfb: &CompoundFile<F>,
    storage_path: &Path,
    hasher: &mut H,
) -> Result<()> {
    let meta = cfb.entry(storage_path)?;
    prehash_entry(&meta, hasher);

    let mut entries: Vec<Entry> = cfb.read_storage(storage_path)?.collect();
    entries.sort_by(|a, b| cmp_utf16_name(a.name(), b.name()));

    for e in entries {
        if e.name() == DIGITAL_SIGNATURE_ENTRY || e.name() == EXTENDED_SIGNATURE_ENTRY {
            continue;
        }
        if e.is_storage() {
            prehash_storage_recursive(cfb, e.path(), hasher)?;
        } else {
            prehash_entry(&e, hasher);
        }
    }
    Ok(())
}

fn hash_storage_content_recursive<F: Read + Seek, H: Digest>(
    cfb: &mut CompoundFile<F>,
    storage_path: &Path,
    hasher: &mut H,
) -> Result<()> {
    let mut entries: Vec<Entry> = cfb.read_storage(storage_path)?.collect();
    entries.sort_by(|a, b| cmp_utf16_name(a.name(), b.name()));

    for e in entries {
        if e.name() == DIGITAL_SIGNATURE_ENTRY || e.name() == EXTENDED_SIGNATURE_ENTRY {
            continue;
        }
        if e.is_storage() {
            hash_storage_content_recursive(cfb, e.path(), hasher)?;
        } else if e.is_stream() {
            let mut stream = cfb.open_stream(e.path())?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf)?;
            hasher.update(&buf);
        }
    }

    let st = cfb.entry(storage_path)?;
    hasher.update(st.clsid().to_bytes_le());
    Ok(())
}

fn msi_has_extended<F: Read + Seek>(cfb: &CompoundFile<F>) -> bool {
    cfb.exists(root_stream(EXTENDED_SIGNATURE_ENTRY))
}

fn compute_prehash<F: Read + Seek>(
    cfb: &CompoundFile<F>,
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => {
            let mut h = Sha1::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha256 => {
            let mut h = Sha256::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha384 => {
            let mut h = Sha384::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha512 => {
            let mut h = Sha512::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
    })
}

fn compute_msi_fingerprint<F: Read + Seek>(
    cfb: &mut CompoundFile<F>,
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => {
            let mut h = Sha1::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha256 => {
            let mut h = Sha256::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha384 => {
            let mut h = Sha384::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha512 => {
            let mut h = Sha512::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
    })
}

/// Compute the Windows Installer Authenticode SIP fingerprint for MSI-like OLE packages.
pub fn compute_msi_authenticode_digest(
    data: &[u8],
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    let cur = std::io::Cursor::new(data);
    let mut cfb = CompoundFile::open(cur).map_err(|e| anyhow!("open as OLE compound file: {e}"))?;
    compute_msi_fingerprint(&mut cfb, kind)
}

fn read_stream_all<F: Read + Seek>(cfb: &mut CompoundFile<F>, path: &Path) -> Result<Vec<u8>> {
    let mut s = cfb.open_stream(path)?;
    let mut v = Vec::new();
    s.read_to_end(&mut v)?;
    Ok(v)
}

/// PKCS#7 **`SignedData`** bytes from the root **`\u{5}DigitalSignature`** stream (same layout **`verify_msi`** reads).
pub fn msi_digital_signature_pkcs7_from_cfb<F: Read + Seek>(
    cfb: &mut CompoundFile<F>,
) -> Result<Vec<u8>> {
    let sig_path = root_stream(DIGITAL_SIGNATURE_ENTRY);
    if !cfb.exists(&sig_path) {
        return Err(anyhow!(
            "MSI is missing {} stream",
            DIGITAL_SIGNATURE_ENTRY.escape_debug()
        ));
    }
    read_stream_all(cfb, &sig_path)
}

/// PKCS#7 DER from **`\\u{5}DigitalSignature`** after opening **`data`** as a compound file.
pub fn msi_digital_signature_pkcs7_der(data: &[u8]) -> Result<Vec<u8>> {
    let cur = std::io::Cursor::new(data);
    let mut cfb = CompoundFile::open(cur).map_err(|e| anyhow!("open as OLE compound file: {e}"))?;
    msi_digital_signature_pkcs7_from_cfb(&mut cfb)
}

/// Create or replace the root **`\u{5}DigitalSignature`** stream in an MSI/MSP OLE file.
pub fn write_msi_digital_signature_pkcs7(path: &Path, pkcs7: &[u8]) -> Result<()> {
    let mut cfb =
        cfb::open_rw(path).map_err(|e| anyhow!("open OLE compound file read/write: {e}"))?;
    let sig_path = root_stream(DIGITAL_SIGNATURE_ENTRY);
    let mut s = cfb.create_stream(&sig_path)?;
    s.write_all(pkcs7)?;
    Ok(())
}

/// Copy an MSI/MSP OLE file and write the root **`\u{5}DigitalSignature`** PKCS#7 stream.
pub fn msi_embed_authenticode_pkcs7_signature(
    input: &Path,
    output: &Path,
    pkcs7: &[u8],
) -> Result<()> {
    let same_path = input == output
        || match (std::fs::canonicalize(input), std::fs::canonicalize(output)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
    if !same_path {
        std::fs::copy(input, output)?;
    }
    write_msi_digital_signature_pkcs7(output, pkcs7)
}

/// **RS256** prehash over **`SignerInfo`** authenticated attributes for MSI-embedded PKCS#7 (same as **`pkcs7-signer-rs256-prehash`** on [`msi_digital_signature_pkcs7_der`] output).
pub fn msi_rsa_sha256_signer_prehash_digest(data: &[u8], signer_index: usize) -> Result<Vec<u8>> {
    let pkcs7 = msi_digital_signature_pkcs7_der(data)?;
    let sd = crate::pkcs7::parse_pkcs7_signed_data_der(&pkcs7)?;
    crate::pkcs7::signed_data_rsa_sha256_signer_prehash_digest(&sd, signer_index)
}

/// Compare PKCS#7 indirect digest with a Rust MSI SIP fingerprint (Signify-compatible).
pub fn verify_msi_digest_consistency(path: &Path) -> Result<()> {
    let mut cfb = CompoundFile::open(File::open(path)?)?;

    let pkcs7 = msi_digital_signature_pkcs7_from_cfb(&mut cfb)?;
    let sig = AuthenticodeSignature::from_bytes(&pkcs7)
        .map_err(|e| anyhow!("MSI Authenticode PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;

    let computed = compute_msi_fingerprint(&mut cfb, kind)?;
    if computed.as_slice() != embedded {
        return Err(anyhow!(
            "MSI Authenticode digest mismatch (Rust SIP fingerprint vs PKCS#7 indirect digest)"
        ));
    }

    if msi_has_extended(&cfb) {
        let expected = read_stream_all(&mut cfb, &root_stream(EXTENDED_SIGNATURE_ENTRY))?;
        let pre = compute_prehash(&cfb, kind)?;
        if pre != expected {
            return Err(anyhow!(
                "MSI extended metadata digest mismatch (MsiDigitalSignatureEx stream vs Rust pre-hash)"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod msi_pkcs7_tests {
    use super::*;

    #[test]
    fn msi_digital_signature_pkcs7_der_matches_pe_fixture_on_stub() {
        let msi =
            include_bytes!("../../../tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi");
        let pe =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let got = msi_digital_signature_pkcs7_der(msi.as_slice()).expect("msi pkcs7");
        let want =
            crate::verify_pe::pe_first_pkcs7_signed_data_der(pe.as_slice()).expect("pe pkcs7");
        assert_eq!(got, want);
    }

    #[test]
    fn msi_rsa_sha256_signer_prehash_matches_direct_on_stub() {
        let msi =
            include_bytes!("../../../tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi");
        let pkcs7 = msi_digital_signature_pkcs7_der(msi.as_slice()).expect("pkcs7");
        let sd = crate::pkcs7::parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
        let direct = crate::pkcs7::signer_info_sha256_digest_over_signed_attrs(si).expect("direct");
        let via = msi_rsa_sha256_signer_prehash_digest(msi.as_slice(), 0).expect("msi helper");
        assert_eq!(direct, via);
    }

    #[test]
    fn msi_rsa_sha256_signer_prehash_errors_when_not_ole() {
        assert!(msi_rsa_sha256_signer_prehash_digest(b"not an msi", 0).is_err());
    }

    #[test]
    fn generated_signed_installer_fixtures_match_msi_sip_digest() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for rel in [
            "tests/fixtures/generated-signed/installer/tiny.msi",
            "tests/fixtures/generated-signed/installer/tiny-patch.msp",
        ] {
            let path = root.join(rel);
            verify_msi_digest_consistency(&path)
                .unwrap_or_else(|e| panic!("verify {rel} MSI SIP digest: {e:#}"));
        }
    }
}
