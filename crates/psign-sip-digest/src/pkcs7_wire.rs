//! PKCS#7 / CMS wire normalization (portable counterpart to Win32 `CryptVerifyDetachedMessageSignature` helpers).

use std::borrow::Cow;

/// PKCS #7 `ContentInfo` wrapping `signedData` — OID `1.2.840.113549.1.7.2`.
const PKCS7_SIGNED_DATA_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];

fn der_encode_definite_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut n = len;
    let mut stack = Vec::new();
    while n > 0 {
        stack.push((n & 0xff) as u8);
        n >>= 8;
    }
    stack.reverse();
    let mut out = vec![0x80 | (stack.len() as u8)];
    out.extend(stack);
    out
}

fn der_encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + content.len());
    out.push(tag);
    out.extend(der_encode_definite_length(content.len()));
    out.extend_from_slice(content);
    out
}

#[derive(Clone, Copy, Debug)]
struct DerTlv {
    tag: u8,
    tag_start: usize,
    value_start: usize,
    value_end: usize,
}

impl DerTlv {
    fn end(self) -> usize {
        self.value_end
    }
}

/// First TLV is `SEQUENCE`; return payload bytes inside it (excluding tag and length).
fn tlv_outer_sequence_payload(data: &[u8]) -> Option<&[u8]> {
    if data.first().copied()? != 0x30 {
        return None;
    }
    let (len, hdr) = parse_der_definite_length(&data[1..])?;
    let total = 1 + hdr + len;
    if data.len() < total {
        return None;
    }
    Some(&data[1 + hdr..total])
}

fn parse_der_definite_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n_octets = (first & 0x7f) as usize;
    if n_octets == 0 || n_octets > 4 || bytes.len() < 1 + n_octets {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n_octets {
        len = (len << 8) | bytes[1 + i] as usize;
    }
    Some((len, 1 + n_octets))
}

fn pkcs7_content_info_signed_data(signed_data_der: &[u8]) -> Vec<u8> {
    let explicit_wrapped_len = signed_data_der.len();
    let mut explicit = Vec::with_capacity(2 + explicit_wrapped_len + 8);
    explicit.push(0xA0);
    explicit.extend(der_encode_definite_length(explicit_wrapped_len));
    explicit.extend_from_slice(signed_data_der);

    let inner_len = PKCS7_SIGNED_DATA_OID_DER.len() + explicit.len();
    let mut out = Vec::with_capacity(2 + inner_len + 8);
    out.push(0x30);
    out.extend(der_encode_definite_length(inner_len));
    out.extend_from_slice(PKCS7_SIGNED_DATA_OID_DER);
    out.extend(explicit);
    out
}

fn der_tlv_at(data: &[u8], offset: usize, limit: usize) -> Option<DerTlv> {
    if offset >= limit || limit > data.len() {
        return None;
    }
    let tag = *data.get(offset)?;
    let (len, hdr) = parse_der_definite_length(data.get(offset + 1..limit)?)?;
    let value_start = offset + 1 + hdr;
    let value_end = value_start.checked_add(len)?;
    if value_end > limit {
        return None;
    }
    Some(DerTlv {
        tag,
        tag_start: offset,
        value_start,
        value_end,
    })
}

fn der_tlv_children(data: &[u8], start: usize, end: usize) -> Option<Vec<DerTlv>> {
    let mut out = Vec::new();
    let mut offset = start;
    while offset < end {
        let tlv = der_tlv_at(data, offset, end)?;
        offset = tlv.end();
        out.push(tlv);
    }
    (offset == end).then_some(out)
}

fn replace_child_tlv(parent: DerTlv, child: DerTlv, replacement: &[u8], data: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(
        parent.value_end - parent.value_start - (child.end() - child.tag_start) + replacement.len(),
    );
    content.extend_from_slice(&data[parent.value_start..child.tag_start]);
    content.extend_from_slice(replacement);
    content.extend_from_slice(&data[child.end()..parent.value_end]);
    der_encode_tlv(parent.tag, &content)
}

fn dedupe_signed_data_certificate_set(content_info_der: &[u8]) -> Option<Vec<u8>> {
    let outer = der_tlv_at(content_info_der, 0, content_info_der.len())?;
    if outer.tag != 0x30 {
        return None;
    }
    let outer_children = der_tlv_children(content_info_der, outer.value_start, outer.value_end)?;
    let content_type = *outer_children.first()?;
    if &content_info_der[content_type.tag_start..content_type.end()] != PKCS7_SIGNED_DATA_OID_DER {
        return None;
    }
    let explicit = *outer_children.get(1)?;
    if explicit.tag != 0xa0 {
        return None;
    }
    let explicit_children =
        der_tlv_children(content_info_der, explicit.value_start, explicit.value_end)?;
    let signed_data = *explicit_children.first()?;
    if signed_data.tag != 0x30 {
        return None;
    }

    let signed_children = der_tlv_children(
        content_info_der,
        signed_data.value_start,
        signed_data.value_end,
    )?;
    let certificates = signed_children
        .iter()
        .copied()
        .skip(3)
        .find(|child| child.tag == 0xa0)?;
    let certificate_children = der_tlv_children(
        content_info_der,
        certificates.value_start,
        certificates.value_end,
    )?;

    let mut unique = Vec::<&[u8]>::new();
    let mut cert_content = Vec::with_capacity(certificates.value_end - certificates.value_start);
    let mut removed_duplicate = false;
    for child in certificate_children {
        let encoded = &content_info_der[child.tag_start..child.end()];
        if unique.contains(&encoded) {
            removed_duplicate = true;
            continue;
        }
        unique.push(encoded);
        cert_content.extend_from_slice(encoded);
    }
    if !removed_duplicate {
        return None;
    }

    let certificates_deduped = der_encode_tlv(certificates.tag, &cert_content);
    let signed_data_deduped = replace_child_tlv(
        signed_data,
        certificates,
        &certificates_deduped,
        content_info_der,
    );
    let explicit_deduped = replace_child_tlv(
        explicit,
        signed_data,
        &signed_data_deduped,
        content_info_der,
    );
    Some(replace_child_tlv(
        outer,
        explicit,
        &explicit_deduped,
        content_info_der,
    ))
}

/// Total byte length of a definite-length DER TLV whose tag is **`data[0]`** (used for PKCS#7 **`SEQUENCE`** / **`0x30`**).
pub fn der_tlv_total_len_from_start(data: &[u8]) -> Option<usize> {
    if data.first().copied()? != 0x30 {
        return None;
    }
    let (content_len, hdr) = parse_der_definite_length(&data[1..])?;
    Some(1 + hdr + content_len)
}

/// PKCS#7 **`ContentInfo`** bytes at the start of **`data`**, trimming trailing octets (e.g. **`WIN_CERTIFICATE`** 8-byte alignment padding).
pub fn pkcs7_outer_sequence_prefix(data: &[u8]) -> Option<&[u8]> {
    let n = der_tlv_total_len_from_start(data)?;
    data.get(..n)
}

/// Strip the Windows AppX/AppInstaller **PKCX** wrapper used by standalone
/// `AppxSignature.p7x` files, returning the inner PKCS#7 DER.
pub fn strip_pkcx_p7x_wrapper(data: &[u8]) -> Option<&[u8]> {
    data.strip_prefix(b"PKCX")
}

/// Normalize detached PKCS#7 blobs: PKCX-wrapped AppX `AppxSignature.p7x` files
/// are unwrapped, and bare `SignedData` sequences are wrapped as PKCS#7 `ContentInfo`.
pub fn normalize_pkcs7_der_for_authenticode(sig_blob: &[u8]) -> Cow<'_, [u8]> {
    let sig_blob = strip_pkcx_p7x_wrapper(sig_blob).unwrap_or(sig_blob);
    let Some(inner) = tlv_outer_sequence_payload(sig_blob) else {
        return Cow::Borrowed(sig_blob);
    };
    let normalized = match inner.first().copied() {
        Some(0x06) => Cow::Borrowed(sig_blob),
        Some(0x02) => Cow::Owned(pkcs7_content_info_signed_data(sig_blob)),
        _ => Cow::Borrowed(sig_blob),
    };
    match dedupe_signed_data_certificate_set(normalized.as_ref()) {
        Some(deduped) => Cow::Owned(deduped),
        None => normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn len_bytes(len: usize) -> Vec<u8> {
        der_encode_definite_length(len)
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        der_encode_tlv(tag, content)
    }

    #[test]
    fn normalize_removes_exact_duplicate_signed_data_certificates() {
        let cert_a = tlv(0x30, b"cert-a");
        let cert_b = tlv(0x30, b"cert-b");
        let certificates = tlv(
            0xa0,
            &[cert_a.as_slice(), cert_b.as_slice(), cert_a.as_slice()].concat(),
        );
        let signed_data = tlv(
            0x30,
            &[
                tlv(0x02, &[1]).as_slice(),
                tlv(0x31, &[]).as_slice(),
                tlv(0x30, &[]).as_slice(),
                certificates.as_slice(),
                tlv(0x31, &[]).as_slice(),
            ]
            .concat(),
        );
        let oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
        ];
        let content_info = tlv(
            0x30,
            &[oid.as_slice(), tlv(0xa0, &signed_data).as_slice()].concat(),
        );

        let normalized = normalize_pkcs7_der_for_authenticode(&content_info);
        assert!(matches!(normalized, Cow::Owned(_)));
        assert_eq!(
            normalized
                .as_ref()
                .windows(cert_a.len())
                .filter(|w| *w == cert_a)
                .count(),
            1
        );
        assert_eq!(
            normalized
                .as_ref()
                .windows(cert_b.len())
                .filter(|w| *w == cert_b)
                .count(),
            1
        );
    }

    #[test]
    fn normalize_preserves_pkcs7_without_duplicate_certificates() {
        let cert_a = tlv(0x30, b"cert-a");
        let certificates = tlv(0xa0, &cert_a);
        let signed_data = tlv(
            0x30,
            &[
                tlv(0x02, &[1]).as_slice(),
                tlv(0x31, &[]).as_slice(),
                tlv(0x30, &[]).as_slice(),
                certificates.as_slice(),
                tlv(0x31, &[]).as_slice(),
            ]
            .concat(),
        );
        let oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
        ];
        let content_info = tlv(
            0x30,
            &[oid.as_slice(), tlv(0xa0, &signed_data).as_slice()].concat(),
        );

        let normalized = normalize_pkcs7_der_for_authenticode(&content_info);
        assert!(matches!(normalized, Cow::Borrowed(_)));
        assert_eq!(normalized.as_ref(), content_info);
    }

    #[test]
    fn definite_length_helper_keeps_short_lengths_short() {
        assert_eq!(len_bytes(3), vec![3]);
    }
}
