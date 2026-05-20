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

/// Normalize detached PKCS#7 blobs: bare `SignedData` sequences are wrapped as PKCS#7 `ContentInfo`.
pub fn normalize_pkcs7_der_for_authenticode(sig_blob: &[u8]) -> Cow<'_, [u8]> {
    let Some(inner) = tlv_outer_sequence_payload(sig_blob) else {
        return Cow::Borrowed(sig_blob);
    };
    match inner.first().copied() {
        Some(0x06) => Cow::Borrowed(sig_blob),
        Some(0x02) => Cow::Owned(pkcs7_content_info_signed_data(sig_blob)),
        _ => Cow::Borrowed(sig_blob),
    }
}
