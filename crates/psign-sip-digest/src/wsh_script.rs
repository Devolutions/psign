//! Windows Script Host Authenticode (`wshext.dll`) — PKCS#7 indirect digest vs recomputed hash.
//!
//! Markers and **`HashFile`** semantics match **`wshext.dll`** (WSH SIP):
//! - `BegSigBlock` / `EndSigBlock` / `Comment` wide strings
//! - `HashFile`: `CryptHashData` over `SysStringByteLen(wchars)` bytes of the stripped script BSTR, then
//!   hashes a trailing little-endian **u32** equal to the **wchar index** of the begin marker in the
//!   original wide subject string (`VerifyIndirectData` → `StripSignature` out-parameter).
//!
//! File bytes are decoded with [`super::ps_script::file_utf16_units`] (UTF-16 BOM or UTF-8 → UTF-16).
//! Native signing uses COM `IConvertXMLBytesToUnicode` (`ConvertTextToUnicode`); parity may diverge for
//! ANSI-only or exotic encodings.

use crate::pe_digest::PeAuthenticodeHashKind;
use crate::ps_script::{file_utf16_units, hash_payload, utf16le_bytes};
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use base64::Engine;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WshKind {
    /// `.vbs` / `.vbe` — `OID_VBSSIP`
    Vbs,
    /// `.js` / `.jse` — `OID_JSSIP`
    Js,
    /// `.wsf`
    Wsf,
}

pub fn wsh_kind_from_ext(ext: &str) -> Option<WshKind> {
    match ext.to_ascii_lowercase().as_str() {
        "vbs" | "vbe" => Some(WshKind::Vbs),
        "js" | "jse" => Some(WshKind::Js),
        "wsf" => Some(WshKind::Wsf),
        _ => None,
    }
}

fn beg_marker(kind: WshKind) -> &'static str {
    match kind {
        WshKind::Vbs => "\r\n'' SIG '' Begin signature block",
        WshKind::Js => "\r\n// SIG // Begin signature block",
        WshKind::Wsf => "\r\n<signature>",
    }
}

fn end_marker(kind: WshKind) -> &'static str {
    match kind {
        WshKind::Vbs => "\r\n'' SIG '' End signature block\r\n",
        WshKind::Js => "\r\n// SIG // End signature block\r\n",
        WshKind::Wsf => "\r\n</signature>\r\n",
    }
}

/// Line-local prefix inside the signature block (`Comment` without the leading `\r\n`).
fn sig_line_prefix(kind: WshKind) -> &'static str {
    match kind {
        WshKind::Vbs => "'' SIG '' ",
        WshKind::Js => "// SIG // ",
        WshKind::Wsf => "** SIG ** ",
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

fn find_last_subslice(haystack: &[u16], needle: &[u16]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let mut last = None;
    for i in 0..=haystack.len() - needle.len() {
        if haystack[i..].starts_with(needle) {
            last = Some(i);
        }
    }
    last
}

fn strip_prefix_units<'a>(line: &'a [u16], prefix: &[u16]) -> Option<&'a [u16]> {
    if line.len() >= prefix.len() && line[..prefix.len()] == *prefix {
        Some(&line[prefix.len()..])
    } else {
        None
    }
}

fn trim_cr(mut line: &[u16]) -> &[u16] {
    while line.first() == Some(&('\r' as u16)) {
        line = &line[1..];
    }
    while line.last() == Some(&('\r' as u16)) {
        line = &line[..line.len() - 1];
    }
    line
}

fn split_lines_utf16(region: &[u16]) -> impl Iterator<Item = &[u16]> + '_ {
    let mut rest = region;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        if let Some(i) = rest.iter().position(|c| *c == '\n' as u16) {
            let line = &rest[..i];
            rest = &rest[(i + 1).min(rest.len())..];
            Some(line)
        } else {
            let line = rest;
            rest = &[];
            Some(line)
        }
    })
}

fn extract_base64_ascii(region: &[u16], kind: WshKind) -> Result<Vec<u8>> {
    let prefix = u16s_from_str(sig_line_prefix(kind));
    let mut ascii = String::new();
    for raw_line in split_lines_utf16(region) {
        let line = trim_cr(raw_line);
        if line.is_empty() {
            continue;
        }
        let Some(rest) = strip_prefix_units(line, &prefix) else {
            return Err(anyhow!(
                "WSH signature region line missing {:?} prefix",
                sig_line_prefix(kind)
            ));
        };
        for cu in rest {
            if *cu < 128 {
                ascii.push(char::from_u32(u32::from(*cu)).unwrap_or('\u{FFFD}'));
            } else {
                return Err(anyhow!("non-ASCII in WSH base64 payload"));
            }
        }
    }
    let trimmed = ascii
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    if trimmed.is_empty() {
        return Err(anyhow!("empty WSH base64 payload"));
    }
    Ok(trimmed.into_bytes())
}

pub(crate) fn strip_wsh_signature_units(units: &[u16], kind: WshKind) -> Result<(Vec<u16>, u32)> {
    let beg = u16s_from_str(beg_marker(kind));
    let last = find_last_subslice(units, &beg).ok_or_else(|| {
        anyhow!(
            "WSH begin signature marker not found ({:?})",
            beg_marker(kind)
        )
    })?;
    let tail = &units[last..];
    let end = u16s_from_str(end_marker(kind));
    let er =
        find_subslice(tail, &end).ok_or_else(|| anyhow!("WSH end signature marker not found"))?;
    let after = last + er + end.len();
    let mut out = Vec::with_capacity(last.saturating_add(units.len().saturating_sub(after)));
    out.extend_from_slice(&units[..last]);
    out.extend_from_slice(&units[after..]);
    Ok((out, last as u32))
}

fn extract_pkcs7_der(units: &[u16], kind: WshKind) -> Result<Vec<u8>> {
    let beg = u16s_from_str(beg_marker(kind));
    let last =
        find_last_subslice(units, &beg).ok_or_else(|| anyhow!("WSH begin marker not found"))?;
    let content_start = last + beg.len();
    let tail = &units[content_start..];
    let end = u16s_from_str(end_marker(kind));
    let er = find_subslice(tail, &end).ok_or_else(|| anyhow!("WSH end marker not found"))?;
    let region = &tail[..er];
    let ascii = extract_base64_ascii(region, kind)?;
    base64::engine::general_purpose::STANDARD
        .decode(&ascii)
        .map_err(|e| anyhow!("WSH base64 decode: {e}"))
}

pub fn verify_wsh_digest_consistency(raw: &[u8], ext: &str) -> Result<()> {
    let kind =
        wsh_kind_from_ext(ext).ok_or_else(|| anyhow!("not a WSH script extension .{ext}"))?;
    let mut units = file_utf16_units(raw);
    if raw.starts_with(&[0xef, 0xbb, 0xbf]) && units.first() == Some(&(0xfeff_u16)) {
        units.remove(0);
    }
    let pkcs7 = extract_pkcs7_der(&units, kind)?;
    let sig = AuthenticodeSignature::from_bytes(&pkcs7)
        .map_err(|e| anyhow!("Authenticode PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();
    let hkind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;
    let (stripped, begin_off) = strip_wsh_signature_units(&units, kind)?;
    let mut payload = utf16le_bytes(&stripped);
    payload.extend_from_slice(&begin_off.to_le_bytes());
    let computed = hash_payload(hkind, &payload)?;
    if computed.as_slice() != embedded {
        return Err(anyhow!(
            "WSH Authenticode digest mismatch (wshext strip + offset dword vs PKCS#7)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_js_block_finds_last_marker() {
        let beg = u16s_from_str(beg_marker(WshKind::Js));
        let end = u16s_from_str(end_marker(WshKind::Js));
        let mut units = u16s_from_str("aaa");
        units.extend_from_slice(&beg);
        units.extend_from_slice(&u16s_from_str("ignored"));
        units.extend_from_slice(&end);
        units.extend_from_slice(&u16s_from_str("zzz"));
        let (out, off) = strip_wsh_signature_units(&units, WshKind::Js).unwrap();
        assert_eq!(String::from_utf16_lossy(&out), "aaazzz");
        assert_eq!(off, 3);
    }

    #[test]
    fn wsh_digest_unsigned_errors_missing_markers() {
        let raw = b"// no sig markers\nconsole.log(1);\n";
        let err = verify_wsh_digest_consistency(raw, "js").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("marker") || msg.contains("Begin") || msg.contains("PKCS"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn strip_wsh_block_rejects_missing_end_marker() {
        let mut units = u16s_from_str("before");
        units.extend_from_slice(&u16s_from_str(beg_marker(WshKind::Vbs)));
        units.extend_from_slice(&u16s_from_str("'' SIG '' QUJD"));

        let err = strip_wsh_signature_units(&units, WshKind::Vbs).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("end signature marker"), "{msg}");
    }

    #[test]
    fn extract_wsh_base64_rejects_missing_prefix_non_ascii_and_empty_payload() {
        let err = extract_base64_ascii(&u16s_from_str("QUJD"), WshKind::Js).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing"), "{msg}");

        let non_ascii = u16s_from_str("// SIG // \u{0100}\r\n");
        let err = extract_base64_ascii(&non_ascii, WshKind::Js).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("non-ASCII"), "{msg}");

        let empty = u16s_from_str("// SIG // \r\n");
        let err = extract_base64_ascii(&empty, WshKind::Js).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("empty"), "{msg}");
    }

    #[test]
    fn wsh_extension_classification_is_case_insensitive_and_limited() {
        assert_eq!(wsh_kind_from_ext("VBE"), Some(WshKind::Vbs));
        assert_eq!(wsh_kind_from_ext("JSE"), Some(WshKind::Js));
        assert_eq!(wsh_kind_from_ext("WSF"), Some(WshKind::Wsf));
        assert_eq!(wsh_kind_from_ext("ps1"), None);
    }
}
