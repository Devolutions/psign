//! PowerShell-class Authenticode (`pwrshsip.dll`) — digest parity vs PKCS#7 indirect data.
//!
//! Marker strings and extensions match **`pwrshsip.dll`** **`InitFormatInfo`** (PowerShell SIP). Hashing in Windows is line-oriented UTF-16 (`PsScriptFile::GetNextChunkToHash`); this module
//! uses a **UTF-16 range removal** heuristic then hashes remaining code units as little-endian bytes.

use crate::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use base64::Engine;
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarkerFamily {
    Hash,
    Xml,
    Mof,
}

fn marker_family(ext: &str) -> Result<MarkerFamily> {
    match ext.to_ascii_lowercase().as_str() {
        "ps1" | "psd1" | "psm1" => Ok(MarkerFamily::Hash),
        "ps1xml" | "psc1" | "cdxml" => Ok(MarkerFamily::Xml),
        "mof" => Ok(MarkerFamily::Mof),
        _ => Err(anyhow!(
            "extension .{ext} is not handled by pwrshsip-style markers"
        )),
    }
}

fn u16s_from_str(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn find_subslice(haystack: &[u16], needle: &[u16]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn markers(family: MarkerFamily) -> (Vec<u16>, Vec<u16>, Vec<u16>, Vec<u16>) {
    match family {
        MarkerFamily::Hash => (
            u16s_from_str("\r\n# SIG # Begin signature block\r\n"),
            u16s_from_str("# SIG # Begin signature block"),
            u16s_from_str("# SIG # End signature block\r\n"),
            u16s_from_str("# SIG # End signature block"),
        ),
        MarkerFamily::Xml => (
            u16s_from_str("\r\n<!-- SIG # Begin signature block -->\r\n"),
            u16s_from_str("<!-- SIG # Begin signature block -->"),
            u16s_from_str("<!-- SIG # End signature block -->\r\n"),
            u16s_from_str("<!-- SIG # End signature block -->"),
        ),
        MarkerFamily::Mof => (
            u16s_from_str("\r\n/* SIG # Begin signature block */\r\n"),
            u16s_from_str("/* SIG # Begin signature block */"),
            u16s_from_str("/* SIG # End signature block */\r\n"),
            u16s_from_str("/* SIG # End signature block */"),
        ),
    }
}

/// Decode file bytes to UTF-16 code units (BOM-aware LE/BE; otherwise UTF-8 → UTF-16).
pub fn file_utf16_units(raw: &[u8]) -> Vec<u16> {
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        return raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
    }
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        return raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
    }
    let lossy = String::from_utf8_lossy(raw);
    lossy.encode_utf16().collect()
}

pub(crate) fn utf16le_bytes(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len().saturating_mul(2));
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn strip_signature_region_utf16(units: &[u16], family: MarkerFamily) -> Result<Vec<u16>> {
    let (begin_cr, begin, end_cr, end) = markers(family);
    let start = find_subslice(units, &begin_cr)
        .or_else(|| find_subslice(units, &begin))
        .ok_or_else(|| {
            anyhow!("signature begin marker not found when interpreting file as UTF-16")
        })?;
    let tail = &units[start..];
    let (end_rel, pat_len) = if let Some(i) = find_subslice(tail, &end_cr) {
        (i, end_cr.len())
    } else if let Some(i) = find_subslice(tail, &end) {
        (i, end.len())
    } else {
        return Err(anyhow!(
            "signature end marker not found when interpreting file as UTF-16"
        ));
    };
    let end_exclusive = start + end_rel + pat_len;
    Ok(units[..start]
        .iter()
        .chain(units[end_exclusive..].iter())
        .copied()
        .collect())
}

pub(crate) fn hash_payload(kind: PeAuthenticodeHashKind, payload: &[u8]) -> Result<Vec<u8>> {
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => {
            let mut h = Sha1::new();
            h.update(payload);
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha256 => {
            let mut h = Sha256::new();
            h.update(payload);
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha384 => {
            let mut h = Sha384::new();
            h.update(payload);
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha512 => {
            let mut h = Sha512::new();
            h.update(payload);
            h.finalize().to_vec()
        }
    })
}

fn looks_like_b64_token(s: &str) -> bool {
    s.len() >= 16
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Extract PKCS#7 DER from a BOM-aware UTF-16 view of the signature block.
fn extract_pkcs7_der_from_script(raw: &[u8], family: MarkerFamily) -> Result<Vec<u8>> {
    let mut units = file_utf16_units(raw);
    if raw.starts_with(&[0xff, 0xfe]) {
        units.insert(0, 0xfeff_u16);
    }
    let text = String::from_utf16_lossy(&units);
    let (begin_pat, end_pat) = match family {
        MarkerFamily::Hash => (
            "# SIG # Begin signature block",
            "# SIG # End signature block",
        ),
        MarkerFamily::Xml => (
            "<!-- SIG # Begin signature block -->",
            "<!-- SIG # End signature block -->",
        ),
        MarkerFamily::Mof => (
            "/* SIG # Begin signature block */",
            "/* SIG # End signature block */",
        ),
    };
    let start = text
        .find(begin_pat)
        .ok_or_else(|| anyhow!("signature begin not found (UTF-8 lossy view)"))?;
    let tail = &text[start..];
    let end_rel = tail
        .find(end_pat)
        .ok_or_else(|| anyhow!("signature end not found (UTF-8 lossy view)"))?;
    let block = &tail[..end_rel + end_pat.len()];
    let mut b64 = String::new();
    match family {
        MarkerFamily::Hash => {
            for line in block.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("# ") {
                    let token = rest.trim();
                    if looks_like_b64_token(token) {
                        b64.push_str(token);
                    }
                }
            }
        }
        MarkerFamily::Xml => {
            for line in block.lines() {
                let t = line.trim();
                if let Some(mid) = t.strip_prefix("<!--").and_then(|x| x.strip_suffix("-->")) {
                    let token = mid.trim();
                    if looks_like_b64_token(token) {
                        b64.push_str(token);
                    }
                }
            }
        }
        MarkerFamily::Mof => {
            for line in block.lines() {
                let t = line.trim();
                if let Some(mid) = t.strip_prefix("/*").and_then(|x| x.strip_suffix("*/")) {
                    let token = mid.trim();
                    if looks_like_b64_token(token) {
                        b64.push_str(token);
                    }
                }
            }
        }
    }
    if b64.is_empty() {
        return Err(anyhow!("no base64 tokens parsed inside signature block"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow!("base64 decode: {e}"))
}

/// Extensions whose digest logic is implemented via `pwrshsip`-style markers.
pub fn extension_supported(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "ps1" | "psd1" | "psm1" | "ps1xml" | "psc1" | "cdxml" | "mof"
    )
}

pub fn is_wsh_extension(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "js" | "jse" | "vbs" | "vbe" | "wsf"
    )
}

/// Compare PKCS#7 indirect digest with a heuristic UTF-16 hash over the file excluding the sig block.
pub(crate) fn verify_powershell_class_digest(raw: &[u8], ext: &str) -> Result<()> {
    let ext_l = ext.to_ascii_lowercase();
    if !extension_supported(&ext_l) {
        return Err(anyhow!(
            "Rust SIP script digest does not support extension .{ext_l}"
        ));
    }
    let family = marker_family(&ext_l)?;
    let pkcs7 = extract_pkcs7_der_from_script(raw, family)?;
    let sig = AuthenticodeSignature::from_bytes(&pkcs7)
        .map_err(|e| anyhow!("Authenticode PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;
    let mut units = file_utf16_units(raw);
    if raw.starts_with(&[0xff, 0xfe]) {
        units.insert(0, 0xfeff_u16);
    }
    let stripped = strip_signature_region_utf16(&units, family)?;
    let payload = utf16le_bytes(&stripped);
    let computed = hash_payload(kind, &payload)?;
    if computed.as_slice() != embedded {
        return Err(anyhow!(
            "script Authenticode digest mismatch (experimental UTF-16 strip heuristic vs PKCS#7)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_removes_hash_style_block_utf16() {
        let mut inner = u16s_from_str("\r\n# SIG # Begin signature block\r\n");
        inner.extend(u16s_from_str("# SIG # End signature block\r\n"));
        let mut units = u16s_from_str("before");
        units.extend(inner);
        units.extend(u16s_from_str("after"));
        let out = strip_signature_region_utf16(&units, MarkerFamily::Hash).unwrap();
        assert_eq!(String::from_utf16_lossy(&out), "beforeafter");
    }

    #[test]
    fn script_digest_unsigned_errors_missing_markers() {
        let raw = b"# no signature markers\nWrite-Output 1\n";
        let err = verify_powershell_class_digest(raw, "ps1").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("marker") || msg.contains("signature"),
            "unexpected: {msg}"
        );
    }
}
