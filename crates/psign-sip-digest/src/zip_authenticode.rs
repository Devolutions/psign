//! Devolutions ZIP Authenticode convention.
//!
//! This is not a Windows SIP. The ZIP EOCD comment stores a single
//! `ZipAuthenticode=<zip digest>,<PowerShell Authenticode PKCS#7>` line.

use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const EOCD_LEN: usize = 22;
const EOCD_COMMENT_LEN_OFFSET: usize = 20;
const MAX_ZIP_COMMENT_LEN: usize = 65_535;
const ZIP_AUTHENTICODE_PREFIX: &str = "ZipAuthenticode=";
const SHA256_DIGEST_PREFIX: &str = "sha256:";
const BEGIN_SIG_BLOCK: &str = "# SIG # Begin signature block";
const END_SIG_BLOCK: &str = "# SIG # End signature block";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZipEocd {
    pub offset: usize,
    pub comment_offset: usize,
    pub comment_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZipAuthenticodeSignature {
    pub digest: String,
    pub pkcs7_base64: String,
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("ZIP EOCD field out of range"))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

pub fn find_eocd(bytes: &[u8]) -> Result<ZipEocd> {
    if bytes.len() < EOCD_LEN {
        return Err(anyhow!("ZIP file is too short to contain an EOCD record"));
    }

    let last_possible = bytes.len() - EOCD_LEN;
    let first_possible = bytes.len().saturating_sub(EOCD_LEN + MAX_ZIP_COMMENT_LEN);

    for offset in (first_possible..=last_possible).rev() {
        if bytes.get(offset..offset + 4) != Some(&EOCD_SIG) {
            continue;
        }
        let comment_len = read_u16_le(bytes, offset + EOCD_COMMENT_LEN_OFFSET)? as usize;
        let comment_offset = offset + EOCD_LEN;
        if comment_offset + comment_len == bytes.len() {
            return Ok(ZipEocd {
                offset,
                comment_offset,
                comment_len,
            });
        }
    }

    Err(anyhow!(
        "could not find a valid ZIP end-of-central-directory record"
    ))
}

pub fn zip_comment(bytes: &[u8]) -> Result<&[u8]> {
    let eocd = find_eocd(bytes)?;
    Ok(&bytes[eocd.comment_offset..eocd.comment_offset + eocd.comment_len])
}

pub fn compute_zip_authenticode_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    let eocd = find_eocd(bytes)?;
    let mut tbs = bytes[..eocd.comment_offset].to_vec();
    tbs[eocd.offset + EOCD_COMMENT_LEN_OFFSET] = 0;
    tbs[eocd.offset + EOCD_COMMENT_LEN_OFFSET + 1] = 0;
    Ok(Sha256::digest(&tbs).into())
}

pub fn zip_authenticode_digest_string(bytes: &[u8]) -> Result<String> {
    let digest = compute_zip_authenticode_digest(bytes)?;
    Ok(format!("{SHA256_DIGEST_PREFIX}{}", hex_lower(&digest)))
}

pub fn signature_comment_line(bytes: &[u8]) -> Result<String> {
    let comment = zip_comment(bytes)?;
    let text = std::str::from_utf8(comment).context("ZIP comment is not UTF-8")?;
    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with(ZIP_AUTHENTICODE_PREFIX))
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("ZIP Authenticode signature comment not found"))
}

fn is_sha256_digest_string(value: &str) -> bool {
    value.len() == SHA256_DIGEST_PREFIX.len() + 64
        && value.starts_with(SHA256_DIGEST_PREFIX)
        && value[SHA256_DIGEST_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
}

pub fn parse_signature_comment_line(line: &str) -> Result<ZipAuthenticodeSignature> {
    let rest = line
        .trim()
        .strip_prefix(ZIP_AUTHENTICODE_PREFIX)
        .ok_or_else(|| {
            anyhow!("ZIP signature comment must start with {ZIP_AUTHENTICODE_PREFIX}")
        })?;
    let (digest, pkcs7_base64) = rest
        .split_once(',')
        .ok_or_else(|| anyhow!("ZIP signature comment is missing PKCS#7 separator"))?;
    if !is_sha256_digest_string(digest) {
        return Err(anyhow!(
            "ZIP signature digest must use sha256:<64 hex chars>"
        ));
    }
    if pkcs7_base64.trim().is_empty() {
        return Err(anyhow!("ZIP signature PKCS#7 payload is empty"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(pkcs7_base64.trim())
        .context("ZIP signature PKCS#7 base64 decode")?;
    Ok(ZipAuthenticodeSignature {
        digest: digest.to_ascii_lowercase(),
        pkcs7_base64: pkcs7_base64.trim().to_owned(),
    })
}

pub fn signature_pkcs7_der(sig: &ZipAuthenticodeSignature) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(sig.pkcs7_base64.trim())
        .context("ZIP signature PKCS#7 base64 decode")
}

pub fn signature_script_from_parts(digest: &str, pkcs7_base64: &str) -> String {
    let mut out = String::new();
    out.push_str(digest);
    out.push_str("\r\n");
    out.push_str(BEGIN_SIG_BLOCK);
    out.push_str("\r\n");
    for chunk in pkcs7_base64.as_bytes().chunks(64) {
        out.push_str("# ");
        out.push_str(std::str::from_utf8(chunk).expect("base64 chunk is ASCII"));
        out.push_str("\r\n");
    }
    out.push_str(END_SIG_BLOCK);
    out.push_str("\r\n");
    out
}

pub fn signature_comment_line_from_pkcs7_der(digest: &str, pkcs7_der: &[u8]) -> Result<String> {
    if !is_sha256_digest_string(digest) {
        return Err(anyhow!(
            "ZIP signature digest must use sha256:<64 hex chars>"
        ));
    }
    let pkcs7_base64 = base64::engine::general_purpose::STANDARD.encode(pkcs7_der);
    let line = format!(
        "{ZIP_AUTHENTICODE_PREFIX}{},{}",
        digest.to_ascii_lowercase(),
        pkcs7_base64
    );
    parse_signature_comment_line(&line)?;
    Ok(line)
}

pub fn signature_script_from_comment_line(line: &str) -> Result<String> {
    let sig = parse_signature_comment_line(line)?;
    Ok(signature_script_from_parts(&sig.digest, &sig.pkcs7_base64))
}

pub fn unsigned_signature_script_bytes(digest: &str) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

pub fn signature_comment_line_from_script(script: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(script).context("signed ZIP .sig.ps1 is not UTF-8")?;
    let mut lines = text.lines();
    let digest = lines
        .next()
        .map(str::trim)
        .ok_or_else(|| anyhow!("signed ZIP .sig.ps1 is empty"))?;
    if !is_sha256_digest_string(digest) {
        return Err(anyhow!(
            "signed ZIP .sig.ps1 first line must be sha256:<64 hex chars>"
        ));
    }

    let mut in_block = false;
    let mut pkcs7_base64 = String::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed == BEGIN_SIG_BLOCK {
            in_block = true;
            continue;
        }
        if trimmed == END_SIG_BLOCK {
            break;
        }
        if in_block && let Some(rest) = trimmed.strip_prefix("# ") {
            pkcs7_base64.push_str(rest.trim());
        }
    }

    let line = format!(
        "{ZIP_AUTHENTICODE_PREFIX}{},{}",
        digest.to_ascii_lowercase(),
        pkcs7_base64
    );
    parse_signature_comment_line(&line)?;
    Ok(line)
}

pub fn set_zip_comment(bytes: &[u8], comment: &[u8]) -> Result<Vec<u8>> {
    if comment.len() > MAX_ZIP_COMMENT_LEN {
        return Err(anyhow!(
            "ZIP comment is too large for EOCD comment field ({} > {MAX_ZIP_COMMENT_LEN})",
            comment.len()
        ));
    }
    let eocd = find_eocd(bytes)?;
    let mut out = bytes[..eocd.comment_offset].to_vec();
    let len = comment.len() as u16;
    out[eocd.offset + EOCD_COMMENT_LEN_OFFSET..eocd.offset + EOCD_COMMENT_LEN_OFFSET + 2]
        .copy_from_slice(&len.to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

pub fn embed_signature_comment_line(bytes: &[u8], line: &str) -> Result<Vec<u8>> {
    parse_signature_comment_line(line)?;
    set_zip_comment(bytes, line.as_bytes())
}

pub fn verify_zip_digest_binding(bytes: &[u8]) -> Result<ZipAuthenticodeSignature> {
    let line = signature_comment_line(bytes)?;
    let sig = parse_signature_comment_line(&line)?;
    let computed = zip_authenticode_digest_string(bytes)?;
    if sig.digest != computed {
        return Err(anyhow!(
            "ZIP Authenticode digest mismatch: embedded {} computed {}",
            sig.digest,
            computed
        ));
    }
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_zip(comment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[
            0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        let central_offset = out.len() as u32;
        out.extend_from_slice(&[
            0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        out.extend_from_slice(&EOCD_SIG);
        out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        out.extend_from_slice(&46u32.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
        out
    }

    #[test]
    fn digest_ignores_existing_comment() {
        let unsigned = tiny_zip(b"");
        let commented = tiny_zip(b"hello");
        assert_eq!(
            zip_authenticode_digest_string(&unsigned).unwrap(),
            zip_authenticode_digest_string(&commented).unwrap()
        );
    }

    #[test]
    fn eocd_scan_rejects_false_signature_in_comment() {
        let zip = tiny_zip(b"prefix PK\x05\x06 fake");
        let eocd = find_eocd(&zip).unwrap();
        assert_eq!(eocd.comment_len, b"prefix PK\x05\x06 fake".len());
    }

    #[test]
    fn signature_comment_roundtrips_script_format() {
        let pkcs7 = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]);
        let line = format!("ZipAuthenticode=sha256:{},{}", "a".repeat(64), pkcs7);
        let script = signature_script_from_comment_line(&line).unwrap();
        assert!(script.contains(BEGIN_SIG_BLOCK));
        assert_eq!(
            signature_comment_line_from_script(script.as_bytes()).unwrap(),
            line
        );
    }

    #[test]
    fn embed_replaces_zip_comment() {
        let zip = tiny_zip(b"old");
        let pkcs7 = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]);
        let line = format!("ZipAuthenticode=sha256:{},{}", "b".repeat(64), pkcs7);
        let signed = embed_signature_comment_line(&zip, &line).unwrap();
        assert_eq!(zip_comment(&signed).unwrap(), line.as_bytes());
    }
}
