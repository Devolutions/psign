//! Parse Microsoft CTL **`eContent`** bodies for SHA-1 **`SubjectIdentifier`** thumbprints.

use anyhow::{Result, anyhow};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, SliceReader};

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// Extract trusted-subject SHA-1 identifiers from an AuthRoot-style `.stl` blob.
///
/// Expects PKCS#7 **`ContentInfo` → `SignedData`** (same framing as catalog `.cat` roots). On parse
/// failure returns an **empty** list (callers still merge PKCS#7-embedded certificates separately).
pub fn ctl_subject_sha1_thumbprints_from_stl_bytes(buf: &[u8]) -> Vec<[u8; 20]> {
    let mut thumbs = ctl_thumbs_from_signed_data_econtent(buf).unwrap_or_default();
    thumbs.sort();
    thumbs.dedup();
    thumbs
}

fn ctl_thumbs_from_signed_data_econtent(buf: &[u8]) -> Result<Vec<[u8; 20]>> {
    let mut r = SliceReader::new(buf).map_err(|_| anyhow!("empty STL buffer"))?;
    let ci = ContentInfo::decode(&mut r).map_err(|_| anyhow!("STL is not PKCS#7 ContentInfo"))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(anyhow!("STL ContentInfo is not SignedData"));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| anyhow!("STL SignedData decode: {e}"))?;
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .map(|a| a.value())
        .unwrap_or_default();
    parse_ctl_inner_subject_sha1s(econtent)
}

fn parse_ctl_inner_subject_sha1s(econtent: &[u8]) -> Result<Vec<[u8; 20]>> {
    let mut out = Vec::new();
    if let Ok(seq_content) = tlv_sequence_payload(econtent) {
        let children = tlv_collect_children(seq_content)?;
        for child in children {
            if let Ok(mut ts) = parse_subject_list(child) {
                out.append(&mut ts);
            }
        }
    }
    if out.is_empty() {
        out.extend(parse_subject_list(econtent).unwrap_or_default());
    }
    Ok(out)
}

fn parse_subject_list(seq_tlv: &[u8]) -> Result<Vec<[u8; 20]>> {
    let content = tlv_sequence_payload(seq_tlv)?;
    let els = tlv_collect_children(content)?;
    let mut thumbs = Vec::new();
    for el in els {
        if el.first().copied() != Some(0x30) {
            continue;
        }
        let inner = tlv_sequence_payload(el)?;
        let parts = tlv_collect_children(inner)?;
        if let Some(first) = parts.first()
            && let Some(t) = tlv_octet_string_fixed(first, 20)
        {
            thumbs.push(t);
        }
    }
    Ok(thumbs)
}

fn tlv_sequence_payload(input: &[u8]) -> Result<&[u8]> {
    if input.first().copied() != Some(0x30) {
        return Err(anyhow!("expected SEQUENCE"));
    }
    let (len, hdr) = parse_der_len(&input[1..])?;
    let end = 1 + hdr + len;
    if end > input.len() {
        return Err(anyhow!("truncated SEQUENCE"));
    }
    Ok(&input[1 + hdr..end])
}

fn parse_der_len(bytes: &[u8]) -> Result<(usize, usize)> {
    let first = *bytes.first().ok_or_else(|| anyhow!("truncated DER"))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || bytes.len() < 1 + n {
        return Err(anyhow!("invalid DER length"));
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | bytes[1 + i] as usize;
    }
    Ok((len, 1 + n))
}

fn tlv_collect_children(content: &[u8]) -> Result<Vec<&[u8]>> {
    let mut i = 0usize;
    let mut v = Vec::new();
    while i < content.len() {
        let total = tlv_total_len(&content[i..])?;
        v.push(&content[i..i + total]);
        i += total;
    }
    Ok(v)
}

fn tlv_total_len(input: &[u8]) -> Result<usize> {
    let _tag = *input.first().ok_or_else(|| anyhow!("eof"))?;
    let (len, hdr) = parse_der_len(&input[1..])?;
    Ok(1 + hdr + len)
}

fn tlv_octet_string_fixed(input: &[u8], expected_len: usize) -> Option<[u8; 20]> {
    if input.first().copied()? != 0x04 {
        return None;
    }
    let (len, hdr) = parse_der_len(&input[1..]).ok()?;
    if len != expected_len || input.len() < 1 + hdr + len {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&input[1 + hdr..1 + hdr + expected_len]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subject_list_finds_sha1_octet_string() {
        let twenty = [7u8; 20];
        let mut inner = vec![0x04, 20];
        inner.extend_from_slice(&twenty);
        let mut ts = vec![0x30];
        ts.extend(der_len(inner.len()));
        ts.extend_from_slice(&inner);
        let mut sl = vec![0x30];
        sl.extend(der_len(ts.len()));
        sl.extend_from_slice(&ts);
        let thumbs = parse_subject_list(&sl).expect("parse");
        assert_eq!(thumbs, vec![twenty]);
    }

    fn der_len(n: usize) -> Vec<u8> {
        assert!(n < 128);
        vec![n as u8]
    }
}
