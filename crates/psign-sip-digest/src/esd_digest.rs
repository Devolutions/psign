//! ESD/WIM Authenticode digest (`EsdSip.dll`): hash a byte prefix of the file, then PKCS#7 + signature tail.
//!
//! Layout follows **`EsdSip.dll`** (**`GetHashDataOffset`**, **`WimFileHashReadLoop`**, …):
//! - `GetHashDataOffset` walks three 16-byte regions in the packed WIM header at offsets **0x30**, **0x48**, **0x7C**
//!   (base offsets **48**, **72**, **124**); the region at **96** is skipped (same loop structure as MSISIP sibling scan).
//! - `WimFileHashReadLoop` hashes from file offset 0 for **`total`** bytes: `total` is the QWORD at header offset **188**
//!   (`0xBC`) when non-zero; otherwise `GetHashDataOffset`.
//! - `EsdSipGetSignature` reads PKCS#7 bytes at file offset QWORD **188**, length DWORD **180** (`0xB4`).
//! - `EsdSipCreateHash` hashes the signed prefix with the 8-byte signature-length/reserved region
//!   at **0xB4..0xBC** zeroed; the signature offset at **0xBC** remains part of the hash.
//! - `EsdSipIsMyFileType` requires the first QWORD to match `MSWIM\\0\\0\\0` and `dwHeaderSize` at offset 8 to be **208** (`0xD0`).

use super::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

/// Packed WIM header size used by `EsdSipCreateHash` / `EsdSipVerifyHash`.
pub const WIM_HEADER_PACKED_SIZE: usize = 0xD0;

const WIM_MAGIC_QWORD_LE: u64 = u64::from_le_bytes(*b"MSWIM\0\0\0");

/// DWORD at `0xB4`: PKCS#7 byte length (when signed).
const OFF_PKCS7_CB: usize = 0xB4;
/// QWORD at `0xBC`: hashed-prefix length (and PKCS#7 file offset when signed).
const OFF_HASH_END_OR_SIG_OFF: usize = 0xBC;

/// Region bases (bytes from start of packed header) contributing to `GetHashDataOffset`. Offset **96** is excluded.
const HASH_EXTENT_REGION_BASES: [usize; 3] = [48, 72, 124];

fn read_u64_le(slice: &[u8], off: usize) -> Result<u64> {
    slice
        .get(off..off + 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| anyhow!("WIM header slice too small at offset {off}"))
}

fn read_u32_le(slice: &[u8], off: usize) -> Result<u32> {
    slice
        .get(off..off + 4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| anyhow!("WIM header slice too small at offset {off}"))
}

/// Mirrors `GetHashDataOffset`: maximum end offset from selected header regions.
pub fn get_hash_data_offset(header: &[u8; WIM_HEADER_PACKED_SIZE]) -> Result<u64> {
    let mut max_end: u64 = 0;
    for base in HASH_EXTENT_REGION_BASES {
        let offset_masked = read_u64_le(header.as_slice(), base)? & 0x00FF_FFFF_FFFF_FFFF;
        let length = read_u64_le(header.as_slice(), base + 8)?;
        let end = offset_masked
            .checked_add(length)
            .ok_or_else(|| anyhow!("WIM header region at 0x{base:x}: offset/length overflow"))?;
        max_end = max_end.max(end);
    }
    Ok(max_end)
}

/// Bytes to hash from the start of the file (`WimFileHashReadLoop` total).
pub fn wim_hash_byte_count(header: &[u8; WIM_HEADER_PACKED_SIZE]) -> Result<u64> {
    let explicit = read_u64_le(header.as_slice(), OFF_HASH_END_OR_SIG_OFF)?;
    if explicit != 0 {
        Ok(explicit)
    } else {
        get_hash_data_offset(header)
    }
}

fn validate_wim_header_prefix(header: &[u8; WIM_HEADER_PACKED_SIZE]) -> Result<()> {
    let magic = read_u64_le(header.as_slice(), 0)?;
    if magic != WIM_MAGIC_QWORD_LE {
        return Err(anyhow!(
            "not a WIM/ESD image (missing MSWIM magic at offset 0)"
        ));
    }
    let hdr_cb = read_u32_le(header.as_slice(), 8)?;
    if hdr_cb != WIM_HEADER_PACKED_SIZE as u32 {
        return Err(anyhow!(
            "unexpected WIM packed header size {hdr_cb} (expected {})",
            WIM_HEADER_PACKED_SIZE
        ));
    }
    Ok(())
}

fn hash_prefix<R: Read>(
    mut reader: R,
    total: u64,
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    const CHUNK: usize = 0x10000;
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = total;
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => {
            let mut h = Sha1::new();
            while remaining > 0 {
                let n = (remaining.min(CHUNK as u64)) as usize;
                reader.read_exact(&mut buf[..n])?;
                h.update(&buf[..n]);
                remaining -= n as u64;
            }
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha256 => {
            let mut h = Sha256::new();
            while remaining > 0 {
                let n = (remaining.min(CHUNK as u64)) as usize;
                reader.read_exact(&mut buf[..n])?;
                h.update(&buf[..n]);
                remaining -= n as u64;
            }
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha384 => {
            let mut h = Sha384::new();
            while remaining > 0 {
                let n = (remaining.min(CHUNK as u64)) as usize;
                reader.read_exact(&mut buf[..n])?;
                h.update(&buf[..n]);
                remaining -= n as u64;
            }
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha512 => {
            let mut h = Sha512::new();
            while remaining > 0 {
                let n = (remaining.min(CHUNK as u64)) as usize;
                reader.read_exact(&mut buf[..n])?;
                h.update(&buf[..n]);
                remaining -= n as u64;
            }
            h.finalize().to_vec()
        }
    })
}

/// Recompute the ESD SIP image digest for `path` using the given packed header (first `WIM_HEADER_PACKED_SIZE` bytes).
pub fn compute_wim_image_digest_from_header(
    path: &Path,
    header: &[u8; WIM_HEADER_PACKED_SIZE],
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    validate_wim_header_prefix(header)?;
    let total = wim_hash_byte_count(header)?;
    let mut f = File::open(path)?;
    let mut hash_header = *header;
    hash_header[OFF_PKCS7_CB..OFF_HASH_END_OR_SIG_OFF].fill(0);
    if total <= WIM_HEADER_PACKED_SIZE as u64 {
        return hash_prefix(&hash_header[..total as usize], total, kind);
    }
    f.seek(std::io::SeekFrom::Start(WIM_HEADER_PACKED_SIZE as u64))?;
    hash_prefix(
        hash_header
            .as_slice()
            .chain(f.take(total - WIM_HEADER_PACKED_SIZE as u64)),
        total,
        kind,
    )
}

/// PKCS#7 blob embedded after the hashed prefix (`EsdSipGetSignature`).
pub fn read_embedded_pkcs7(path: &Path, header: &[u8; WIM_HEADER_PACKED_SIZE]) -> Result<Vec<u8>> {
    validate_wim_header_prefix(header)?;
    let cb = read_u32_le(header.as_slice(), OFF_PKCS7_CB)? as u64;
    let off = read_u64_le(header.as_slice(), OFF_HASH_END_OR_SIG_OFF)?;
    if cb == 0 || off == 0 {
        return Err(anyhow!(
            "WIM/ESD file has no embedded Authenticode signature (cb=0 or offset=0 in header)"
        ));
    }
    let meta = std::fs::metadata(path)?;
    let len = meta.len();
    let end = off
        .checked_add(cb)
        .ok_or_else(|| anyhow!("signature extent overflow"))?;
    if end > len {
        return Err(anyhow!(
            "embedded PKCS#7 extent exceeds file size (offset={off}, cb={cb}, file_len={len})"
        ));
    }
    let mut f = File::open(path)?;
    let mut out = vec![0u8; cb as usize];
    f.seek(std::io::SeekFrom::Start(off))?;
    f.read_exact(&mut out)?;
    Ok(out)
}

/// Compare PKCS#7 indirect digest with a Rust ESD/WIM SIP prefix hash (`EsdSipVerifyHash` semantics).
pub fn verify_wim_esd_digest_consistency(path: &Path) -> Result<()> {
    let mut head = [0u8; WIM_HEADER_PACKED_SIZE];
    let mut f = File::open(path)?;
    f.read_exact(&mut head)?;

    let pkcs7 = read_embedded_pkcs7(path, &head)?;
    let sig = AuthenticodeSignature::from_bytes(&pkcs7)
        .map_err(|e| anyhow!("WIM/ESD PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;

    let computed = compute_wim_image_digest_from_header(path, &head, kind)?;
    if computed.as_slice() != embedded {
        return Err(anyhow!(
            "WIM/ESD Authenticode digest mismatch (Rust SIP prefix hash vs PKCS#7 indirect digest)"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_wim(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "psign_esd_digest_{}_{}.wim",
            name,
            std::process::id()
        ));
        let mut f = std::fs::File::create(&p).expect("create temp wim");
        f.write_all(bytes).expect("write temp wim");
        p
    }

    #[test]
    fn wim_verify_rejects_non_mswim_magic() {
        // `verify_wim_esd_digest_consistency` reads a full **208**-byte header first; use wrong magic with full prefix.
        let mut junk = vec![0xFFu8; WIM_HEADER_PACKED_SIZE];
        junk[0..8].copy_from_slice(b"XXXXIM\0\0");
        let p = write_temp_wim("not_wim", &junk);
        let err = verify_wim_esd_digest_consistency(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        let msg = format!("{err:#}");
        assert!(
            msg.contains("MSWIM") || msg.contains("WIM"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn wim_verify_rejects_bad_packed_header_size() {
        let mut h = vec![0u8; WIM_HEADER_PACKED_SIZE];
        h[0..8].copy_from_slice(b"MSWIM\0\0\0");
        h[8..12].copy_from_slice(&100u32.to_le_bytes());
        let p = write_temp_wim("bad_hdr", &h);
        let err = verify_wim_esd_digest_consistency(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        let msg = format!("{err:#}");
        assert!(
            msg.contains("packed header") || msg.contains("208") || msg.contains("0xd0"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn wim_verify_rejects_unsigned_header_no_pkcs7() {
        let mut h = vec![0u8; WIM_HEADER_PACKED_SIZE];
        h[0..8].copy_from_slice(b"MSWIM\0\0\0");
        h[8..12].copy_from_slice(&(WIM_HEADER_PACKED_SIZE as u32).to_le_bytes());
        let p = write_temp_wim("unsigned", &h);
        let err = verify_wim_esd_digest_consistency(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        let msg = format!("{err:#}");
        assert!(
            msg.contains("embedded") || msg.contains("PKCS") || msg.contains("signature"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn get_hash_data_offset_matches_simple_regions() {
        let mut h = [0u8; WIM_HEADER_PACKED_SIZE];
        // Region @48: offset 0x10, length 0x20 -> end 0x30
        h[48..56].copy_from_slice(&0x10u64.to_le_bytes());
        h[56..64].copy_from_slice(&0x20u64.to_le_bytes());
        // Region @72: offset 0, length 0x50 -> end 0x50 (max)
        h[72..80].copy_from_slice(&0u64.to_le_bytes());
        h[80..88].copy_from_slice(&0x50u64.to_le_bytes());
        // Region @124: offset 0x100, length 1 -> end 0x101 (max)
        h[124..132].copy_from_slice(&0x100u64.to_le_bytes());
        h[132..140].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(get_hash_data_offset(&h).unwrap(), 0x101);
    }

    #[test]
    fn wim_hash_byte_count_uses_explicit_qword() {
        let mut h = [0u8; WIM_HEADER_PACKED_SIZE];
        h[OFF_HASH_END_OR_SIG_OFF..OFF_HASH_END_OR_SIG_OFF + 8]
            .copy_from_slice(&999u64.to_le_bytes());
        assert_eq!(wim_hash_byte_count(&h).unwrap(), 999);
    }
}
