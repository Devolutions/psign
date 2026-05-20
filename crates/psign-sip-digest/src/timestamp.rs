//! RFC 3161 **TimeStampReq** / **TimeStampResp** helpers for TSA **`application/timestamp-query`**
//! / **`application/timestamp-reply`** workflows.
//!
//! Portable trust reads nested **`TSTInfo.genTime`** / PKCS#9 **`signing-time`** for **`exact_date`**
//! when **`--prefer-timestamp-signing-time`** is set (**`psign-authenticode-trust`**). This module
//! encodes minimal **§2.4.1** requests (version 1, **`messageImprint`**, optional **`nonce`** /
//! **`certReq`**) and parses **§2.4.2** responses far enough to read **PKIStatus** and locate the
//! optional **`timeStampToken`** TLV. **HTTP transport** is implemented in **`psign-tool portable`**
//! behind **`--features timestamp-http`** (**`rfc3161-timestamp-http-post`**). Optional **`failInfo`**
//! (**`PKIFailureInfo`**) **`BIT STRING`** values can be decoded to RFC 2510 Appendix A bit names
//! (**`badAlg`** … **`badPOP`**) for logging; **CMS signature / `MessageImprint` verification** remain out of scope.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, SliceReader};

/// Plan for a single **`TimeStampReq`**.
#[derive(Debug, Clone)]
pub struct Rfc3161TimestampRequestPlan {
    /// Digest algorithm OID (e.g. **`2.16.840.1.101.3.4.2.1`** for SHA-256).
    pub digest_alg_oid: &'static str,
    /// Optional **`nonce`** (**`INTEGER`**, minimal unsigned DER encoding).
    pub nonce: Option<u64>,
    /// When **`true`**, append **`certReq BOOLEAN TRUE`** (RFC default is false — omitted when false).
    pub cert_req: bool,
}

impl Default for Rfc3161TimestampRequestPlan {
    fn default() -> Self {
        Self {
            digest_alg_oid: "2.16.840.1.101.3.4.2.1",
            nonce: None,
            cert_req: false,
        }
    }
}

struct DigestAlgSpec {
    /// Full **`AlgorithmIdentifier`** DER (**`SEQUENCE { OID, NULL }`**).
    algorithm_identifier_der: &'static [u8],
    digest_octet_len: usize,
}

fn digest_alg_spec(oid: &str) -> Option<DigestAlgSpec> {
    match oid.trim() {
        "1.3.14.3.2.26" => Some(DigestAlgSpec {
            algorithm_identifier_der: &[
                0x30, 0x0b, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
            ],
            digest_octet_len: 20,
        }),
        "2.16.840.1.101.3.4.2.1" => Some(DigestAlgSpec {
            algorithm_identifier_der: &[
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00,
            ],
            digest_octet_len: 32,
        }),
        "2.16.840.1.101.3.4.2.2" => Some(DigestAlgSpec {
            algorithm_identifier_der: &[
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                0x00,
            ],
            digest_octet_len: 48,
        }),
        "2.16.840.1.101.3.4.2.3" => Some(DigestAlgSpec {
            algorithm_identifier_der: &[
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                0x00,
            ],
            digest_octet_len: 64,
        }),
        _ => None,
    }
}

fn push_der_definite_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(0x83);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
}

/// Minimal non-negative **`INTEGER`** DER (**`INTEGER { … }`** value bytes only after tag/len).
pub fn der_integer_u64(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0x02, 0x01, 0x00];
    }
    let mut buf = [0u8; 9];
    let mut x = n;
    let mut idx = 9usize;
    while x > 0 {
        idx -= 1;
        buf[idx] = (x & 0xff) as u8;
        x >>= 8;
    }
    let mut digits = buf[idx..].to_vec();
    if digits[0] & 0x80 != 0 {
        digits.insert(0, 0);
    }
    let mut out = vec![0x02];
    push_der_definite_length(&mut out, digits.len());
    out.extend_from_slice(&digits);
    out
}

/// Build **DER** **`TimeStampReq`** bytes for **`imprint_preimage`** (raw digest octets for
/// **`MessageImprint.hashedMessage`**).
///
/// Returns **`None`** when the OID is unknown or **`imprint_preimage.len()`** does not match the
/// digest size for that algorithm.
pub fn build_timestamp_request_bytes(
    plan: &Rfc3161TimestampRequestPlan,
    imprint_preimage: &[u8],
) -> Option<Vec<u8>> {
    let spec = digest_alg_spec(plan.digest_alg_oid)?;
    if imprint_preimage.len() != spec.digest_octet_len {
        return None;
    }

    let mut message_imprint_value =
        Vec::with_capacity(spec.algorithm_identifier_der.len() + 2 + imprint_preimage.len());
    message_imprint_value.extend_from_slice(spec.algorithm_identifier_der);
    message_imprint_value.push(0x04);
    push_der_definite_length(&mut message_imprint_value, imprint_preimage.len());
    message_imprint_value.extend_from_slice(imprint_preimage);

    let mut ts_req_value = Vec::with_capacity(3 + 2 + message_imprint_value.len() + 32);
    ts_req_value.extend_from_slice(&[0x02, 0x01, 0x01]); // INTEGER version = 1
    ts_req_value.push(0x30);
    push_der_definite_length(&mut ts_req_value, message_imprint_value.len());
    ts_req_value.extend_from_slice(&message_imprint_value);

    if let Some(nonce) = plan.nonce {
        ts_req_value.extend_from_slice(&der_integer_u64(nonce));
    }
    if plan.cert_req {
        ts_req_value.extend_from_slice(&[0x01, 0x01, 0xff]); // BOOLEAN TRUE
    }

    let mut out = Vec::with_capacity(2 + ts_req_value.len());
    out.push(0x30);
    push_der_definite_length(&mut out, ts_req_value.len());
    out.extend_from_slice(&ts_req_value);
    Some(out)
}

// --- TimeStampResp (RFC 3161 §2.4.2) — definite-length TLVs, single-byte tags only.

/// **PKIStatus** integer from **`PKIStatusInfo.status`** (RFC 3161 / PKIXCMP-style codes used by TSAs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rfc3161PkiStatus {
    Granted,
    GrantedWithMods,
    Rejection,
    Waiting,
    RevocationWarning,
    RevocationNotification,
    Unknown(u32),
}

impl Rfc3161PkiStatus {
    pub fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Granted,
            1 => Self::GrantedWithMods,
            2 => Self::Rejection,
            3 => Self::Waiting,
            4 => Self::RevocationWarning,
            5 => Self::RevocationNotification,
            _ => Self::Unknown(v),
        }
    }

    pub fn granted(self) -> bool {
        matches!(self, Self::Granted | Self::GrantedWithMods)
    }

    /// **`PKIStatusInfo.status`** INTEGER value (RFC 3161 / CMP-style); **`Unknown(v)`** preserves **`v`**.
    pub fn as_raw_integer(self) -> u32 {
        match self {
            Self::Granted => 0,
            Self::GrantedWithMods => 1,
            Self::Rejection => 2,
            Self::Waiting => 3,
            Self::RevocationWarning => 4,
            Self::RevocationNotification => 5,
            Self::Unknown(v) => v,
        }
    }
}

/// Parsed **`TimeStampResp`** ( **`PKIStatusInfo`** fields used by TSAs + optional **`timeStampToken`** ).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTimeStampResp<'a> {
    pub pki_status: Rfc3161PkiStatus,
    /// Optional raw **`timeStampToken`** TLV bytes (typically **`ContentInfo`**).
    pub time_stamp_token: Option<&'a [u8]>,
    /// **`PKIStatusInfo.statusString`** (**`PKIFreeText`**) as UTF-8 strings when the SEQUENCE of **`UTF8String`** encodes cleanly.
    pub status_strings: Vec<String>,
    /// Raw **`PKIFailureInfo`** **`BIT STRING`** TLV bytes (tag **`0x03`**) when present.
    pub fail_info_tlv: Option<&'a [u8]>,
}

/// Parsed **RFC 3161 `TSTInfo`** fields from a **`timeStampToken`**.
///
/// This is structural parsing only. It does **not** verify the CMS signature, TSA chain, EKU,
/// nonce binding to a request, or **`MessageImprint`** against an Authenticode signature value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRfc3161TstInfo {
    pub policy_oid: String,
    pub message_imprint_digest_alg_oid: String,
    pub message_imprint_hashed_message: Vec<u8>,
    pub serial_number_hex: String,
    pub gen_time: String,
    pub nonce_hex: Option<String>,
}

/// Decode a **`PKIFailureInfo`**-style **`BIT STRING`** TLV (tag **`0x03`**) into sorted RFC 2510
/// Appendix A names for bits **0**–**9** (**`badAlg`** … **`badPOP`**). Higher set bits are reported as
/// **`bit_N`** (DER definite-length subset; rejects malformed unused-bit counts or oversized values).
pub fn pkifailure_info_flag_labels_from_bit_string_tlv(tlv: &[u8]) -> Option<Vec<String>> {
    if tlv.first().copied()? != 0x03 {
        return None;
    }
    let body = der_tlv_body(tlv)?;
    let (&unused_u8, value_octets) = body.split_first()?;
    let unused = unused_u8 as usize;
    if unused > 7 {
        return None;
    }
    if value_octets.is_empty() {
        return Some(Vec::new());
    }
    if value_octets.len().checked_mul(8)? < unused {
        return None;
    }
    let total_bits = value_octets.len() * 8 - unused;
    if total_bits > 256 {
        return None;
    }
    const NAMES: &[&str] = &[
        "badAlg",
        "badMessageCheck",
        "badRequest",
        "badTime",
        "badCertId",
        "badDataFormat",
        "wrongAuthority",
        "incorrectData",
        "missingTimeStamp",
        "badPOP",
    ];
    let mut labels = Vec::new();
    for i in 0..total_bits {
        let oi = i / 8;
        let bi = i % 8;
        let oct = *value_octets.get(oi)?;
        let mask = 0x80u8 >> bi;
        if (oct & mask) == 0 {
            continue;
        }
        let label = if let Some(s) = NAMES.get(i) {
            (*s).to_string()
        } else {
            format!("bit_{i}")
        };
        labels.push(label);
    }
    Some(labels)
}

fn der_definite_tlv_total_len(input: &[u8]) -> Option<usize> {
    if input.is_empty() {
        return None;
    }
    let mut pos = 1usize;
    let ll = *input.get(pos)?;
    pos += 1;
    let body_len = if ll < 0x80 {
        ll as usize
    } else if ll == 0x81 {
        let v = *input.get(pos)? as usize;
        pos += 1;
        v
    } else if ll == 0x82 {
        let v = ((*input.get(pos)? as usize) << 8) | (*input.get(pos + 1)? as usize);
        pos += 2;
        v
    } else {
        return None;
    };
    pos.checked_add(body_len)
}

fn der_read_tlv0(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let n = der_definite_tlv_total_len(input)?;
    if n > input.len() {
        return None;
    }
    Some((&input[..n], &input[n..]))
}

fn der_tlv_body(tlv: &[u8]) -> Option<&[u8]> {
    let total = der_definite_tlv_total_len(tlv)?;
    if total > tlv.len() {
        return None;
    }
    let lfs = tlv_len_field_size(tlv)?;
    tlv.get((1 + lfs)..total)
}

fn tlv_len_field_size(tlv: &[u8]) -> Option<usize> {
    let ll = *tlv.get(1)?;
    Some(if ll < 0x80 {
        1
    } else if ll == 0x81 {
        2
    } else if ll == 0x82 {
        3
    } else {
        return None;
    })
}

fn der_integer_value_body(int_tlv: &[u8]) -> Option<&[u8]> {
    if int_tlv.first().copied()? != 0x02 {
        return None;
    }
    der_tlv_body(int_tlv)
}

/// Decode a nonnegative **`INTEGER`** value body (no tag/length): up to **4** significant octets after
/// **DER**-correct leading-zero removal (do not strip **`00`** when the following octet has bit **8** set).
fn der_decode_small_nonnegative_integer(body: &[u8]) -> Option<u32> {
    let mut body = body;
    // Strip leading **`0x00`** only when the next octet does not need the high bit as a sign bit
    // (**DER INTEGER** rule: preserve **`00 80`** as **128**, not **`80`** as negative).
    while body.len() > 1 && body[0] == 0 && (body[1] & 0x80) == 0 {
        body = &body[1..];
    }
    if body.is_empty() || body.len() > 4 {
        return None;
    }
    if body[0] & 0x80 != 0 {
        return None;
    }
    let mut v: u32 = 0;
    for &b in body {
        v = v.checked_shl(8)?.checked_add(b as u32)?;
    }
    Some(v)
}

fn parse_pkifree_text_utf8_strings(seq_tlv: &[u8]) -> Option<Vec<String>> {
    if seq_tlv.first().copied()? != 0x30 {
        return None;
    }
    let body = der_tlv_body(seq_tlv)?;
    let mut sl = body;
    let mut out = Vec::new();
    while !sl.is_empty() {
        let (tlv, rest) = der_read_tlv0(sl)?;
        sl = rest;
        if tlv.first().copied()? != 0x0c {
            return None;
        }
        let utf8 = der_tlv_body(tlv)?;
        out.push(String::from_utf8_lossy(utf8).into_owned());
    }
    Some(out)
}

type ParsedPkiStatusInfo<'a> = (Rfc3161PkiStatus, Vec<String>, Option<&'a [u8]>);

/// Parse **`PKIStatusInfo`**: **`status`** INTEGER, optional **`statusString`** (**`SEQUENCE OF UTF8String`**),
/// optional **`failInfo`** (**`BIT STRING`**). Rejects unknown extra TLVs or wrong field order.
fn parse_pki_status_info_complete<'a>(
    status_info_tlv: &'a [u8],
) -> Option<ParsedPkiStatusInfo<'a>> {
    let inner = der_tlv_body(status_info_tlv)?;
    let (first, mut tail) = der_read_tlv0(inner)?;
    let int_body = der_integer_value_body(first)?;
    let raw = der_decode_small_nonnegative_integer(int_body)?;
    let status = Rfc3161PkiStatus::from_raw(raw);
    let mut status_strings = Vec::new();
    let mut fail_info_tlv: Option<&'a [u8]> = None;
    // 0 = before statusString; 1 = after statusString (only failInfo or end); 2 = closed
    let mut phase = 0u8;
    while !tail.is_empty() {
        let (tlv, rest) = der_read_tlv0(tail)?;
        tail = rest;
        match tlv.first().copied()? {
            0x30 if phase == 0 => {
                status_strings = parse_pkifree_text_utf8_strings(tlv)?;
                phase = 1;
            }
            0x03 if phase <= 1 => {
                if fail_info_tlv.is_some() {
                    return None;
                }
                fail_info_tlv = Some(tlv);
                phase = 2;
            }
            _ => return None,
        }
    }
    Some((status, status_strings, fail_info_tlv))
}

/// Parse **DER** **`TimeStampResp`**: **`PKIStatusInfo`** ( **`status`**, optional **`statusString`**
/// (**`PKIFreeText`**: **`SEQUENCE OF UTF8String`**), then optional **`failInfo`**) and optional **`timeStampToken`**.
/// **`failInfo`** before **`statusString`** is rejected (**`None`**) to match the canonical field order TSAs use.
/// Unknown TLVs inside **`PKIStatusInfo`** or extra **`TimeStampResp`** fields after **`timeStampToken`** cause **`None`**.
pub fn parse_time_stamp_resp_der(input: &[u8]) -> Option<ParsedTimeStampResp<'_>> {
    if input.first().copied()? != 0x30 {
        return None;
    }
    let outer_len = der_definite_tlv_total_len(input)?;
    if outer_len != input.len() {
        return None;
    }
    let outer = der_tlv_body(input)?;
    let (first, rest) = der_read_tlv0(outer)?;
    let (pki_status, status_strings, fail_info_tlv) = parse_pki_status_info_complete(first)?;
    let time_stamp_token = if rest.is_empty() {
        None
    } else {
        let (tok, tail) = der_read_tlv0(rest)?;
        if !tail.is_empty() {
            return None;
        }
        Some(tok)
    };
    Some(ParsedTimeStampResp {
        pki_status,
        time_stamp_token,
        status_strings,
        fail_info_tlv,
    })
}

/// Parse a **`timeStampToken`** **`ContentInfo`** and return its encapsulated **`TSTInfo`** fields.
///
/// This intentionally performs structural extraction only; callers must layer CMS signature, TSA
/// certificate, nonce, and **`MessageImprint`** verification on top before treating the timestamp
/// as trusted.
pub fn parse_time_stamp_token_tst_info(token_tlv: &[u8]) -> Option<ParsedRfc3161TstInfo> {
    const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    const ID_CT_TSTINFO: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

    let mut r = SliceReader::new(token_tlv).ok()?;
    let ci = ContentInfo::decode(&mut r).ok()?;
    if ci.content_type != ID_SIGNED_DATA {
        return None;
    }
    let sd: SignedData = ci.content.decode_as().ok()?;
    if sd.encap_content_info.econtent_type != ID_CT_TSTINFO {
        return None;
    }
    let any = sd.encap_content_info.econtent.as_ref()?;
    let tstinfo_der = peel_to_tstinfo_sequence(any.value())?;
    parse_tst_info_der(tstinfo_der)
}

/// Parse **RFC 3161 `TSTInfo`** DER enough for deterministic timestamp tests and diagnostics.
pub fn parse_tst_info_der(tstinfo_der: &[u8]) -> Option<ParsedRfc3161TstInfo> {
    let outer = der_tlv_body(tstinfo_der)?;
    if tstinfo_der.first().copied()? != 0x30 {
        return None;
    }
    let mut pos = outer;
    let (version, rest) = der_read_tlv0(pos)?;
    pos = rest;
    if version.first().copied()? != 0x02 {
        return None;
    }
    let (policy_tlv, rest) = der_read_tlv0(pos)?;
    pos = rest;
    let policy_oid = oid_tlv_to_string(policy_tlv)?;

    let (message_imprint_tlv, rest) = der_read_tlv0(pos)?;
    pos = rest;
    let (message_imprint_digest_alg_oid, message_imprint_hashed_message) =
        parse_message_imprint(message_imprint_tlv)?;

    let (serial_tlv, rest) = der_read_tlv0(pos)?;
    pos = rest;
    if serial_tlv.first().copied()? != 0x02 {
        return None;
    }
    let serial_number_hex = hex_lower(der_tlv_body(serial_tlv)?);

    let (gen_time_tlv, rest) = der_read_tlv0(pos)?;
    pos = rest;
    if gen_time_tlv.first().copied()? != 0x18 {
        return None;
    }
    let gen_time = std::str::from_utf8(der_tlv_body(gen_time_tlv)?)
        .ok()?
        .to_string();

    let mut nonce_hex = None;
    while !pos.is_empty() {
        let (tlv, rest) = der_read_tlv0(pos)?;
        pos = rest;
        match tlv.first().copied()? {
            0x02 => nonce_hex = Some(hex_lower(der_tlv_body(tlv)?)),
            0x30 | 0x01 | 0xa0 | 0xa1 => {}
            _ => return None,
        }
    }

    Some(ParsedRfc3161TstInfo {
        policy_oid,
        message_imprint_digest_alg_oid,
        message_imprint_hashed_message,
        serial_number_hex,
        gen_time,
        nonce_hex,
    })
}

fn parse_message_imprint(message_imprint_tlv: &[u8]) -> Option<(String, Vec<u8>)> {
    if message_imprint_tlv.first().copied()? != 0x30 {
        return None;
    }
    let body = der_tlv_body(message_imprint_tlv)?;
    let (alg_tlv, rest) = der_read_tlv0(body)?;
    let (hashed_tlv, tail) = der_read_tlv0(rest)?;
    if !tail.is_empty() || hashed_tlv.first().copied()? != 0x04 {
        return None;
    }
    let alg_oid = algorithm_identifier_oid(alg_tlv)?;
    let hashed = der_tlv_body(hashed_tlv)?.to_vec();
    Some((alg_oid, hashed))
}

fn algorithm_identifier_oid(alg_tlv: &[u8]) -> Option<String> {
    if alg_tlv.first().copied()? != 0x30 {
        return None;
    }
    let body = der_tlv_body(alg_tlv)?;
    let (oid_tlv, _rest) = der_read_tlv0(body)?;
    oid_tlv_to_string(oid_tlv)
}

fn oid_tlv_to_string(oid_tlv: &[u8]) -> Option<String> {
    if oid_tlv.first().copied()? != 0x06 {
        return None;
    }
    ObjectIdentifier::from_der(oid_tlv)
        .ok()
        .map(|oid| oid.to_string())
}

fn peel_to_tstinfo_sequence(mut sl: &[u8]) -> Option<&[u8]> {
    for _ in 0..8 {
        match sl.first().copied()? {
            0x30 => return Some(sl),
            0x04 => sl = der_tlv_body(sl)?,
            tag if tag == 0xa0 || tag == 0xa1 => sl = der_tlv_body(sl)?,
            _ => return None,
        }
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_timestamp_request_sha256_zeros_structure_and_length() {
        let plan = Rfc3161TimestampRequestPlan::default();
        let preimage = [0u8; 32];
        let got = build_timestamp_request_bytes(&plan, &preimage).expect("encode");
        assert_eq!(got.len(), 56, "TimeStampReq + SHA-256 MessageImprint (DER)");
        assert_eq!(&got[..6], &[0x30, 0x36, 0x02, 0x01, 0x01, 0x30]);
        assert_eq!(
            &got[22..24],
            &[0x04, 0x20],
            "hashedMessage OCTET STRING tag/len"
        );
        assert_eq!(&got[24..], preimage.as_slice());
    }

    #[test]
    fn build_timestamp_request_with_nonce_and_cert_req_extends_der() {
        let plan = Rfc3161TimestampRequestPlan {
            digest_alg_oid: "2.16.840.1.101.3.4.2.1",
            nonce: Some(0x0102_0304_0506_0708),
            cert_req: true,
        };
        let preimage = [0u8; 32];
        let got = build_timestamp_request_bytes(&plan, &preimage).expect("encode");
        assert!(got.len() > 56);
        assert!(
            got.windows(3).any(|w| w == [0x01, 0x01, 0xff]),
            "BOOLEAN certReq"
        );
        assert!(
            got.windows(2).any(|w| w[0] == 0x02 && w[1] > 0),
            "nonce INTEGER"
        );
    }

    #[test]
    fn build_timestamp_request_wrong_preimage_len_returns_none() {
        let plan = Rfc3161TimestampRequestPlan::default();
        assert!(build_timestamp_request_bytes(&plan, &[0u8; 31]).is_none());
        assert!(build_timestamp_request_bytes(&plan, &[0u8; 33]).is_none());
    }

    #[test]
    fn build_timestamp_request_unknown_oid_returns_none() {
        let plan = Rfc3161TimestampRequestPlan {
            digest_alg_oid: "1.2.3.4",
            ..Default::default()
        };
        assert!(build_timestamp_request_bytes(&plan, &[0u8; 32]).is_none());
    }

    #[test]
    fn build_timestamp_request_sha1_length_20() {
        let plan = Rfc3161TimestampRequestPlan {
            digest_alg_oid: "1.3.14.3.2.26",
            ..Default::default()
        };
        let v = build_timestamp_request_bytes(&plan, &[7u8; 20]).expect("sha1");
        assert_eq!(v.len(), 40);
        assert!(v.starts_with(&[0x30, 0x26]));
    }

    #[test]
    fn build_timestamp_request_sha384_and_sha512_nonzero_preimage() {
        for (oid, n) in [
            ("2.16.840.1.101.3.4.2.2", 48usize),
            ("2.16.840.1.101.3.4.2.3", 64usize),
        ] {
            let plan = Rfc3161TimestampRequestPlan {
                digest_alg_oid: oid,
                ..Default::default()
            };
            let mut p = vec![0xabu8; n];
            p[n - 1] = 0xcd;
            let der = build_timestamp_request_bytes(&plan, &p).expect(oid);
            assert!(der.starts_with(&[0x30]), "{oid}");
            assert!(
                der.windows(p.len()).any(|w| w == p.as_slice()),
                "{oid}: preimage"
            );
            let expect_len = match n {
                48 => 72,
                64 => 88,
                _ => panic!("unexpected digest width"),
            };
            assert_eq!(der.len(), expect_len, "{oid} TimeStampReq DER total length");
        }
    }

    /// Each supported digest OID’s **`AlgorithmIdentifier`** DER is embedded verbatim inside **`MessageImprint`**.
    #[test]
    fn build_timestamp_request_each_supported_alg_embeds_algorithm_identifier_in_message_imprint() {
        for oid in [
            "1.3.14.3.2.26",
            "2.16.840.1.101.3.4.2.1",
            "2.16.840.1.101.3.4.2.2",
            "2.16.840.1.101.3.4.2.3",
        ] {
            let spec = digest_alg_spec(oid).expect(oid);
            let preimage = vec![0xcd_u8; spec.digest_octet_len];
            let plan = Rfc3161TimestampRequestPlan {
                digest_alg_oid: oid,
                ..Default::default()
            };
            let der = build_timestamp_request_bytes(&plan, &preimage).expect(oid);
            assert!(
                der.windows(spec.algorithm_identifier_der.len())
                    .any(|w| w == spec.algorithm_identifier_der),
                "{oid}: AlgorithmIdentifier inside MessageImprint"
            );
            assert!(
                der.windows(spec.digest_octet_len)
                    .any(|w| w == preimage.as_slice()),
                "{oid}: hashedMessage"
            );
        }
    }

    #[test]
    fn parse_tst_info_extracts_core_fields_and_nonce() {
        let mut imprint_body = Vec::new();
        imprint_body.extend_from_slice(
            digest_alg_spec("2.16.840.1.101.3.4.2.1")
                .unwrap()
                .algorithm_identifier_der,
        );
        imprint_body.push(0x04);
        imprint_body.push(32);
        imprint_body.extend_from_slice(&[0x22u8; 32]);
        let mut imprint = vec![0x30];
        push_der_definite_length(&mut imprint, imprint_body.len());
        imprint.extend_from_slice(&imprint_body);

        let mut body = vec![0x02, 0x01, 0x01];
        body.extend_from_slice(&[0x06, 0x03, 0x2a, 0x03, 0x04]);
        body.extend_from_slice(&imprint);
        body.extend_from_slice(&[0x02, 0x01, 0x7f]);
        body.extend_from_slice(&[
            0x18, 0x0f, b'2', b'0', b'2', b'4', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4',
            b'0', b'5', b'Z',
        ]);
        body.extend_from_slice(&[0x02, 0x01, 0x09]);

        let mut tstinfo = vec![0x30];
        push_der_definite_length(&mut tstinfo, body.len());
        tstinfo.extend_from_slice(&body);

        let parsed = parse_tst_info_der(&tstinfo).expect("TSTInfo");
        assert_eq!(parsed.policy_oid, "1.2.3.4");
        assert_eq!(
            parsed.message_imprint_digest_alg_oid,
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(parsed.message_imprint_hashed_message, vec![0x22; 32]);
        assert_eq!(parsed.serial_number_hex, "7f");
        assert_eq!(parsed.gen_time, "20240102030405Z");
        assert_eq!(parsed.nonce_hex.as_deref(), Some("09"));
    }

    /// Minimal **`TimeStampResp`**: **`granted`**, no token.
    const TS_RESP_GRANTED_NO_TOKEN: &[u8] = &[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];

    /// **`TimeStampResp`** with outer **`SEQUENCE`** length **`0x81`** (see workspace fixture **`tests/fixtures/rfc3161/ts_resp_granted_outer_len81.der`**).
    #[test]
    fn parse_time_stamp_resp_granted_with_status_string_outer_sequence_length_0x81() {
        static DER: &[u8] =
            include_bytes!("../../../tests/fixtures/rfc3161/ts_resp_granted_outer_len81.der");
        assert_eq!(DER.len(), 138, "fixture byte length");
        let p = parse_time_stamp_resp_der(DER).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Granted);
        assert_eq!(p.status_strings.len(), 1);
        assert_eq!(p.status_strings[0].len(), 125);
        assert!(p.status_strings[0].chars().all(|c| c == 'y'));
        assert!(p.time_stamp_token.is_none());
    }

    #[test]
    fn parse_time_stamp_resp_granted_without_token() {
        let p = parse_time_stamp_resp_der(TS_RESP_GRANTED_NO_TOKEN).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Granted);
        assert_eq!(p.pki_status.as_raw_integer(), 0);
        assert!(p.pki_status.granted());
        assert!(p.time_stamp_token.is_none());
        assert!(p.status_strings.is_empty());
        assert!(p.fail_info_tlv.is_none());
    }

    #[test]
    fn parse_time_stamp_resp_granted_with_mods() {
        let der = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::GrantedWithMods);
        assert_eq!(p.pki_status.as_raw_integer(), 1);
        assert!(p.pki_status.granted());
        assert!(p.status_strings.is_empty());
    }

    #[test]
    fn parse_time_stamp_resp_waiting_revocation_and_unknown_status_ints() {
        let der_waiting = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x03];
        let p = parse_time_stamp_resp_der(&der_waiting).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Waiting);
        assert_eq!(p.pki_status.as_raw_integer(), 3);
        assert!(!p.pki_status.granted());

        let der_rw = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x04];
        let p = parse_time_stamp_resp_der(&der_rw).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::RevocationWarning);
        assert_eq!(p.pki_status.as_raw_integer(), 4);

        let der_rn = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05];
        let p = parse_time_stamp_resp_der(&der_rn).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::RevocationNotification);
        assert_eq!(p.pki_status.as_raw_integer(), 5);

        let der = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x63];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Unknown(99));
        assert_eq!(p.pki_status.as_raw_integer(), 99);
    }

    #[test]
    fn parse_time_stamp_resp_granted_malformed_fail_info_tlv_decode_returns_none() {
        let der: [u8; 11] = [
            0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x08, 0x00,
        ];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        let fi = p.fail_info_tlv.expect("failInfo");
        assert!(pkifailure_info_flag_labels_from_bit_string_tlv(fi).is_none());
    }

    #[test]
    fn parse_time_stamp_resp_rejection_with_pkifreetext_status_string() {
        let der: [u8; 15] = [
            0x30, 0x0d, 0x30, 0x0b, 0x02, 0x01, 0x02, 0x30, 0x06, 0x0c, 0x04, 0x6e, 0x6f, 0x70,
            0x65,
        ];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Rejection);
        assert_eq!(p.status_strings, vec!["nope".to_string()]);
        assert!(p.fail_info_tlv.is_none());
    }

    /// **`PKIFreeText`** with multiple **`UTF8String`** elements (RFC 3161 **`statusString`**).
    #[test]
    fn parse_time_stamp_resp_rejection_with_multi_pkifreetext_status_strings() {
        let der: [u8; 19] = [
            0x30, 0x11, 0x30, 0x0f, 0x02, 0x01, 0x02, 0x30, 0x0a, 0x0c, 0x01, 0x61, 0x0c, 0x02,
            0x62, 0x62, 0x0c, 0x01, 0x63,
        ];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Rejection);
        assert_eq!(
            p.status_strings,
            vec!["a".to_string(), "bb".to_string(), "c".to_string()]
        );
        assert!(p.fail_info_tlv.is_none());
    }

    /// **`failInfo`** before **`statusString`** is not valid for our strict field-order parser.
    #[test]
    fn parse_time_stamp_resp_rejects_fail_info_before_status_string() {
        let der: [u8; 16] = [
            0x30, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x02, 0x03, 0x02, 0x00, 0xc0, 0x30, 0x03, 0x0c,
            0x01, 0x77,
        ];
        assert!(parse_time_stamp_resp_der(&der).is_none());
    }

    #[test]
    fn parse_time_stamp_resp_granted_with_fail_info_bit_string() {
        // TimeStampResp { PKIStatusInfo { granted, failInfo BIT STRING } }
        let der: [u8; 11] = [
            0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x00, 0xc0,
        ];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Granted);
        assert!(p.fail_info_tlv.is_some());
        assert_eq!(p.fail_info_tlv.unwrap(), &[0x03, 0x02, 0x00, 0xc0]);
    }

    #[test]
    fn parse_time_stamp_resp_granted_with_status_string_and_fail_info() {
        let der: [u8; 16] = [
            0x30, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x00, 0x30, 0x03, 0x0c, 0x01, 0x77, 0x03, 0x02,
            0x00, 0xc0,
        ];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Granted);
        assert_eq!(p.status_strings, vec!["w".to_string()]);
        assert_eq!(p.fail_info_tlv, Some(&[0x03u8, 0x02, 0x00, 0xc0][..]));
    }

    #[test]
    fn parse_time_stamp_resp_rejection() {
        let der = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Rejection);
        assert!(!p.pki_status.granted());
    }

    #[test]
    fn parse_time_stamp_resp_granted_with_token_tlv() {
        // SEQUENCE { PKIStatusInfo(granted), dummy SEQUENCE token }
        let der: &[u8] = &[
            0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x03, 0x02, 0x01, 0x2a,
        ];
        let p = parse_time_stamp_resp_der(der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Granted);
        assert!(p.status_strings.is_empty());
        let tok = p.time_stamp_token.expect("token");
        assert_eq!(
            tok.first().copied(),
            Some(0x30),
            "timeStampToken TLV is a SEQUENCE"
        );
        assert_eq!(tok, &[0x30, 0x03, 0x02, 0x01, 0x2a]);
    }

    /// Second **`TimeStampResp`** field is returned as opaque TLV bytes (no CMS shape check).
    #[test]
    fn parse_time_stamp_resp_accepts_integer_second_tlv_as_opaque_time_stamp_token() {
        let der: [u8; 10] = [0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x2a];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        let tok = p.time_stamp_token.expect("token");
        assert_eq!(tok, &[0x02, 0x01, 0x2a]);
    }

    #[test]
    fn parse_time_stamp_resp_rejects_trailing_garbage() {
        let mut v = TS_RESP_GRANTED_NO_TOKEN.to_vec();
        v.push(0xff);
        assert!(parse_time_stamp_resp_der(&v).is_none());
    }

    #[test]
    fn parse_time_stamp_resp_rejects_empty_input() {
        assert!(parse_time_stamp_resp_der(&[]).is_none());
    }

    /// Outer **`SEQUENCE`** length does not cover the declared body (truncated TLV).
    #[test]
    fn parse_time_stamp_resp_rejects_outer_length_longer_than_buffer() {
        let der: [u8; 6] = [0x30, 0x0a, 0x30, 0x03, 0x02, 0x01];
        assert!(parse_time_stamp_resp_der(&der).is_none());
    }

    #[test]
    fn parse_time_stamp_resp_rejects_non_sequence_outer_tag() {
        assert!(parse_time_stamp_resp_der(&[0x31, 0x00]).is_none());
    }

    /// Indefinite-length (**`0x80`**) outer encoding is not supported (definite-length subset only).
    #[test]
    fn parse_time_stamp_resp_rejects_indefinite_length_outer() {
        assert!(parse_time_stamp_resp_der(&[0x30, 0x80, 0x00, 0x00]).is_none());
    }

    /// **`TimeStampResp`** allows at most one trailing TLV after **`PKIStatusInfo`** (opaque token).
    #[test]
    fn parse_time_stamp_resp_rejects_two_trailing_tlvs_after_status_info() {
        // Outer SEQUENCE length 0x0b = 11: PKIStatusInfo(5) + OCTET STRING(3) + OCTET STRING(3).
        let der: [u8; 13] = [
            0x30, 0x0b, 0x30, 0x03, 0x02, 0x01, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x01,
        ];
        assert!(parse_time_stamp_resp_der(&der).is_none());
    }

    /// Unknown TLV inside **`PKIStatusInfo`** after **`status`** (here **`OCTET STRING`**) is rejected.
    #[test]
    fn parse_time_stamp_resp_rejects_unknown_tlv_inside_pki_status_info() {
        let der: [u8; 11] = [
            0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00,
        ];
        assert!(parse_time_stamp_resp_der(&der).is_none());
    }

    /// **`PKIStatus`** INTEGER **128** uses two-byte encoding (**`02 02 00 80`**).
    #[test]
    fn parse_time_stamp_resp_unknown_status_integer_128() {
        let der: [u8; 8] = [0x30, 0x06, 0x30, 0x04, 0x02, 0x02, 0x00, 0x80];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Unknown(128));
        assert_eq!(p.pki_status.as_raw_integer(), 128);
    }

    /// **`PKIStatus`** **256** (**`02 02 01 00`**) maps to **`Unknown(256)`**.
    #[test]
    fn parse_time_stamp_resp_unknown_status_integer_256() {
        let der: [u8; 8] = [0x30, 0x06, 0x30, 0x04, 0x02, 0x02, 0x01, 0x00];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Unknown(256));
        assert_eq!(p.pki_status.as_raw_integer(), 256);
    }

    /// **`INTEGER`** value encodings longer than four significant octets (after stripping leading zeros) are rejected.
    #[test]
    fn parse_time_stamp_resp_rejects_oversized_pki_status_integer() {
        let der: [u8; 12] = [
            0x30, 0x0a, 0x30, 0x08, 0x02, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        assert!(parse_time_stamp_resp_der(&der).is_none());
    }

    /// **`PKIFreeText`** must be **`UTF8String`** elements; **`IA5String`** inside the sequence is rejected.
    #[test]
    fn parse_time_stamp_resp_rejects_pkifreetext_ia5string_instead_of_utf8string() {
        let der: [u8; 12] = [
            0x30, 0x0a, 0x30, 0x08, 0x02, 0x01, 0x02, 0x30, 0x03, 0x16, 0x01, 0x41,
        ];
        assert!(parse_time_stamp_resp_der(&der).is_none());
    }

    /// Empty **`PKIFreeText`** (**`SEQUENCE`** length **0**) is accepted.
    #[test]
    fn parse_time_stamp_resp_rejection_with_empty_pkifreetext() {
        let der: [u8; 9] = [0x30, 0x07, 0x30, 0x05, 0x02, 0x01, 0x02, 0x30, 0x00];
        let p = parse_time_stamp_resp_der(&der).expect("parse");
        assert_eq!(p.pki_status, Rfc3161PkiStatus::Rejection);
        assert!(p.status_strings.is_empty());
        assert!(p.fail_info_tlv.is_none());
    }

    #[test]
    fn der_integer_u64_roundtrip_small() {
        assert_eq!(der_integer_u64(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(der_integer_u64(127), vec![0x02, 0x01, 0x7f]);
        assert_eq!(der_integer_u64(128), vec![0x02, 0x02, 0x00, 0x80]);
    }

    /// Leading zero byte when the first magnitude octet has bit **7** set (DER INTEGER rule).
    #[test]
    fn der_integer_u64_max_value_includes_leading_zero_pad() {
        assert_eq!(
            der_integer_u64(u64::MAX),
            vec![
                0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
    }

    /// Two-byte magnitude with leading **`0x00`** so the value is nonnegative in DER.
    #[test]
    fn der_integer_u64_65535_inserts_leading_zero_when_high_bit_set() {
        assert_eq!(der_integer_u64(65535), vec![0x02, 0x03, 0x00, 0xff, 0xff]);
    }

    #[test]
    fn build_timestamp_request_with_nonce_u64_max_extends_outer_length() {
        let plan = Rfc3161TimestampRequestPlan {
            nonce: Some(u64::MAX),
            ..Default::default()
        };
        let preimage = [0u8; 32];
        let got = build_timestamp_request_bytes(&plan, &preimage).expect("encode");
        assert_eq!(
            got.len(),
            56 + 11,
            "base SHA-256 req + INTEGER(u64::MAX) DER"
        );
        assert!(
            got.windows(11)
                .any(|w| w == der_integer_u64(u64::MAX).as_slice()),
            "nonce INTEGER TLV embedded"
        );
    }

    #[test]
    fn pkifailure_info_bad_alg_and_bad_message_check() {
        let tlv = [0x03u8, 0x02, 0x00, 0xc0];
        let v = pkifailure_info_flag_labels_from_bit_string_tlv(&tlv).expect("decode");
        assert_eq!(v, vec!["badAlg".to_string(), "badMessageCheck".to_string()]);
    }

    #[test]
    fn pkifailure_info_bad_time_only() {
        // bit 3
        let tlv = [0x03u8, 0x02, 0x00, 0x10];
        let v = pkifailure_info_flag_labels_from_bit_string_tlv(&tlv).expect("decode");
        assert_eq!(v, vec!["badTime".to_string()]);
    }

    #[test]
    fn pkifailure_info_bad_request_and_bad_time() {
        // Bits 2 and 3 set (MSB-first): 0x30 = 0011_0000 → **badRequest** + **badTime**
        let tlv = [0x03u8, 0x02, 0x00, 0x30];
        let v = pkifailure_info_flag_labels_from_bit_string_tlv(&tlv).expect("decode");
        assert_eq!(v, vec!["badRequest".to_string(), "badTime".to_string()]);
    }

    #[test]
    fn pkifailure_info_bit_10_unnamed() {
        let tlv = [0x03u8, 0x03, 0x00, 0x00, 0x20];
        let v = pkifailure_info_flag_labels_from_bit_string_tlv(&tlv).expect("decode");
        assert_eq!(v, vec!["bit_10".to_string()]);
    }

    #[test]
    fn pkifailure_info_empty_bit_string() {
        let tlv = [0x03u8, 0x01, 0x00];
        let v = pkifailure_info_flag_labels_from_bit_string_tlv(&tlv).expect("decode");
        assert!(v.is_empty());
    }

    /// **`BIT STRING`** with **`unused`** = **7** and a single subject bit (**`badAlg`**).
    #[test]
    fn pkifailure_info_unused_seven_single_bit_bad_alg() {
        let tlv = [0x03u8, 0x03, 0x07, 0x80, 0x00];
        let v = pkifailure_info_flag_labels_from_bit_string_tlv(&tlv).expect("decode");
        assert_eq!(v, vec!["badAlg".to_string()]);
    }

    #[test]
    fn pkifailure_info_rejects_wrong_tag() {
        assert!(pkifailure_info_flag_labels_from_bit_string_tlv(&[0x04, 0x01, 0x00]).is_none());
    }

    #[test]
    fn pkifailure_info_rejects_unused_gt_7() {
        assert!(
            pkifailure_info_flag_labels_from_bit_string_tlv(&[0x03, 0x02, 0x08, 0x00]).is_none()
        );
    }
}
