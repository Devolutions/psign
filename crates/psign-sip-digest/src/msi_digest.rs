//! Windows Installer Authenticode digest (`MSISIP.DLL`) vs PKCS#7 `SpcIndirectData`.
//!
//! The traversal matches **Signify** `SignedMsiFile` (`signify/authenticode/signed_file/msi.py`,
//! Apache-2.0): sorted UTF-16 byte order on sibling names (longer prefix first), skip root
//! `\u{5}DigitalSignature` and `\u{5}MsiDigitalSignatureEx`, optional metadata **pre-hash** when
//! `MsiDigitalSignatureEx` exists,
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
use std::io::{Cursor, Read, Seek, Write};
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
    let common = ae.len().min(be.len());
    ae[..common]
        .cmp(&be[..common])
        .then_with(|| be.len().cmp(&ae.len()))
}

fn hash_utf16_name<H: Digest>(name: &str, hasher: &mut H) {
    for u in name.encode_utf16() {
        hasher.update(u.to_le_bytes());
    }
}

fn system_time_to_filetime_le(st: SystemTime) -> [u8; 8] {
    let ticks = match st.duration_since(UNIX_EPOCH) {
        Ok(d) => FILETIME_UNIX_EPOCH.saturating_add(duration_to_filetime_ticks(d)),
        Err(e) => FILETIME_UNIX_EPOCH.saturating_sub(duration_to_filetime_ticks(e.duration())),
    };
    ticks.to_le_bytes()
}

fn duration_to_filetime_ticks(duration: std::time::Duration) -> u64 {
    duration.as_secs().saturating_mul(10_000_000) + u64::from(duration.subsec_nanos()) / 100
}

fn prehash_entry<H: Digest>(entry: &Entry, hasher: &mut H) {
    if !entry.is_root() {
        hash_utf16_name(entry.name(), hasher);
    }
    if entry.is_root() || entry.is_storage() {
        hasher.update(entry.clsid().to_bytes_le());
    }
    if entry.is_stream() {
        // MSISIP hashes the low DWORD of the stream size.
        let sz = entry.len() as u32;
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
        if storage_path == Path::new("/")
            && (e.name() == DIGITAL_SIGNATURE_ENTRY || e.name() == EXTENDED_SIGNATURE_ENTRY)
        {
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
        if storage_path == Path::new("/")
            && (e.name() == DIGITAL_SIGNATURE_ENTRY || e.name() == EXTENDED_SIGNATURE_ENTRY)
        {
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

/// Compute the signing digest for an MSI/MSP that already carries a valid metadata digest stream.
pub fn compute_prepared_msi_authenticode_digest(
    data: &[u8],
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    let mut cfb = CompoundFile::open(Cursor::new(data))
        .map_err(|e| anyhow!("open as OLE compound file: {e}"))?;
    let extended_path = root_stream(EXTENDED_SIGNATURE_ENTRY);
    if !cfb.exists(&extended_path) {
        return Err(anyhow!(
            "MSI signing requires the root {} stream; stage the image with prepare_msi_for_authenticode_signing",
            EXTENDED_SIGNATURE_ENTRY.escape_debug()
        ));
    }
    let extended = read_stream_all(&mut cfb, &extended_path)?;
    let expected = compute_prehash(&cfb, kind)?;
    if extended != expected {
        return Err(anyhow!(
            "MSI {} stream does not match its metadata digest",
            EXTENDED_SIGNATURE_ENTRY.escape_debug()
        ));
    }
    compute_msi_fingerprint(&mut cfb, kind)
}

/// MSI image staged for Authenticode signing, including the metadata digest stream required by
/// the Windows Installer SIP.
pub struct PreparedMsiAuthenticode {
    image: Vec<u8>,
    digest: Vec<u8>,
}

impl PreparedMsiAuthenticode {
    /// Compound-file bytes containing the root `MsiDigitalSignatureEx` stream.
    pub fn image(&self) -> &[u8] {
        &self.image
    }

    /// Authenticode digest of [`Self::image`].
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

/// Stage an MSI/MSP for signing and compute the Windows Installer SIP digest.
///
/// Windows requires the root `MsiDigitalSignatureEx` stream to contain the package metadata
/// digest. That stream must exist before the final Authenticode digest is computed.
pub fn prepare_msi_for_authenticode_signing(
    data: &[u8],
    kind: PeAuthenticodeHashKind,
) -> Result<PreparedMsiAuthenticode> {
    let cursor = Cursor::new(data.to_vec());
    let mut cfb =
        CompoundFile::open(cursor).map_err(|e| anyhow!("open as OLE compound file: {e}"))?;
    let metadata_digest = compute_prehash(&cfb, kind)?;
    {
        let mut stream = cfb.create_stream(root_stream(EXTENDED_SIGNATURE_ENTRY))?;
        stream.write_all(&metadata_digest)?;
    }
    let digest = compute_msi_fingerprint(&mut cfb, kind)?;
    let image = cfb.into_inner().into_inner();
    Ok(PreparedMsiAuthenticode { image, digest })
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

/// Write a staged MSI/MSP image and its root **`\u{5}DigitalSignature`** PKCS#7 stream.
pub fn msi_embed_prepared_authenticode_pkcs7_signature(
    prepared: &PreparedMsiAuthenticode,
    output: &Path,
    pkcs7: &[u8],
) -> Result<()> {
    std::fs::write(output, prepared.image())?;
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

    fn compound_with_signature_named_streams(root_byte: u8, nested_byte: u8) -> Vec<u8> {
        let mut cfb = CompoundFile::create(Cursor::new(Vec::new())).expect("create compound file");
        {
            let mut root_signature = cfb
                .create_stream(root_stream(DIGITAL_SIGNATURE_ENTRY))
                .expect("create root signature stream");
            root_signature
                .write_all(&[root_byte])
                .expect("write root signature stream");
        }
        cfb.create_storage("/Nested").expect("create storage");
        {
            let mut nested_signature = cfb
                .create_stream(Path::new("/Nested").join(DIGITAL_SIGNATURE_ENTRY))
                .expect("create nested signature-named stream");
            nested_signature
                .write_all(&[nested_byte])
                .expect("write nested signature-named stream");
        }
        cfb.into_inner().into_inner()
    }

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

    #[test]
    fn preparing_msi_writes_metadata_digest_before_computing_signing_digest() {
        let msi =
            include_bytes!("../../../tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi");
        for kind in [
            PeAuthenticodeHashKind::Sha1,
            PeAuthenticodeHashKind::Sha256,
            PeAuthenticodeHashKind::Sha384,
            PeAuthenticodeHashKind::Sha512,
        ] {
            let prepared = prepare_msi_for_authenticode_signing(msi, kind).expect("prepare MSI");
            let mut cfb =
                CompoundFile::open(Cursor::new(prepared.image())).expect("open prepared MSI");
            let extended = read_stream_all(&mut cfb, &root_stream(EXTENDED_SIGNATURE_ENTRY))
                .expect("read MsiDigitalSignatureEx");
            assert_eq!(
                extended,
                compute_prehash(&cfb, kind).expect("metadata digest")
            );
            assert_eq!(
                prepared.digest(),
                compute_msi_fingerprint(&mut cfb, kind).expect("MSI signing digest")
            );

            let prepared_again = prepare_msi_for_authenticode_signing(prepared.image(), kind)
                .expect("prepare MSI again");
            assert_eq!(prepared_again.digest(), prepared.digest());
        }
    }

    #[test]
    fn sip_name_order_puts_longer_prefix_first() {
        assert_eq!(cmp_utf16_name("NameExtra", "Name"), Ordering::Less);
        assert_eq!(cmp_utf16_name("Name", "NameExtra"), Ordering::Greater);
    }

    #[test]
    fn filetime_conversion_preserves_pre_unix_values() {
        assert_eq!(
            system_time_to_filetime_le(UNIX_EPOCH - std::time::Duration::from_secs(1)),
            (FILETIME_UNIX_EPOCH - 10_000_000).to_le_bytes()
        );
    }

    #[test]
    fn only_root_signature_streams_are_excluded_from_content_digest() {
        let kind = PeAuthenticodeHashKind::Sha256;
        let baseline = compound_with_signature_named_streams(1, 1);
        let changed_root = compound_with_signature_named_streams(2, 1);
        let changed_nested = compound_with_signature_named_streams(1, 2);

        assert_eq!(
            compute_msi_authenticode_digest(&baseline, kind).expect("baseline digest"),
            compute_msi_authenticode_digest(&changed_root, kind).expect("changed root digest")
        );
        assert_ne!(
            compute_msi_authenticode_digest(&baseline, kind).expect("baseline digest"),
            compute_msi_authenticode_digest(&changed_nested, kind).expect("changed nested digest")
        );
    }

    #[test]
    fn prepared_signing_digest_requires_matching_extended_stream() {
        let msi =
            include_bytes!("../../../tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi");
        let kind = PeAuthenticodeHashKind::Sha256;
        let missing = compute_prepared_msi_authenticode_digest(msi, kind)
            .expect_err("unstaged MSI must be rejected");
        assert!(missing.to_string().contains("MsiDigitalSignatureEx"));

        let prepared = prepare_msi_for_authenticode_signing(msi, kind).expect("prepare MSI");
        let mut cfb =
            CompoundFile::open(Cursor::new(prepared.image().to_vec())).expect("open prepared MSI");
        {
            let mut extended = cfb
                .create_stream(root_stream(EXTENDED_SIGNATURE_ENTRY))
                .expect("replace MsiDigitalSignatureEx");
            extended
                .write_all(&[0; 32])
                .expect("write bad metadata digest");
        }
        let tampered = cfb.into_inner().into_inner();
        assert!(compute_prepared_msi_authenticode_digest(&tampered, kind).is_err());
    }
}
