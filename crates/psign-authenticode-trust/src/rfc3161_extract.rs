//! Best-effort RFC3161 / Authenticode nested timestamp extraction for verification instant selection.
//!
//! Extracts **`genTime`** from CMS **`id-ct-TSTInfo`** timestamp tokens (typically carried in
//! **`SignerInfo` unsigned attributes**) and falls back to PKCS#9 **`signing-time`** in signed
//! attributes. The `trusted_*` helper also verifies the timestamp token signature, MessageImprint,
//! TSA EKU, and TSA chain against explicit anchors.

use crate::anchor::{AnchorStore, cert_sha1_thumbprint};
use crate::chain::{
    issuer_chain_excluding_leaf_online, merge_unique_certs, terminal_root_cert_owned,
};
use crate::online::check_revocation_chain;
use crate::policy::OnlineTrustOptions;
use anyhow::{Result, anyhow};
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::asn1::{GeneralizedTime, ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode, Header, Reader, SliceReader, Tag};
use picky::x509::certificate::Cert;
use picky::x509::date::UtcDate;
use psign_sip_digest::pkcs7::{
    signed_data_certificate_for_signer_identifier,
    verify_signed_data_pkcs9_message_digest_and_rsa_sha256_pkcs1v15_signature,
};
use sha2::Digest as _;
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::time::Time;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// **`id-ct-TSTInfo`** (RFC 3161).
const ID_CT_TSTINFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// PKCS#9 **`signing-time`**.
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// **`id-aa-timeStampToken`** (RFC 5035 / CMS).
const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// Microsoft nested Authenticode timestamp attribute (common on PE).
const OID_MS_TIMESTAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
const EKU_EXTENSION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const TIME_STAMPING_EKU_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// Returns signing time from an embedded timestamp token and/or PKCS#9 **`signing-time`** when
/// parsing succeeds.
///
/// **Precedence:** nested RFC3161 **`TSTInfo.genTime`** from unsigned attributes on any signer, then
/// PKCS#9 **`signing-time`** from the **first** signer that carries it.
///
/// On failure returns **`None`**; callers fall back to wall-clock **`UtcDate::now()`** unless
/// [`crate::policy::AuthenticodeTrustPolicy::require_valid_timestamp`] forces an error.
pub fn utc_date_from_authenticode_timestamp_token(pkcs7_der: &[u8]) -> Option<UtcDate> {
    let sd = signed_data_from_pkcs7(pkcs7_der)?;
    let mut signing_time_fallback = None;

    for si in sd.signer_infos.0.iter() {
        if let Some(d) = utc_date_from_signer_unsigned_attrs(si) {
            return Some(d);
        }
        if signing_time_fallback.is_none() {
            signing_time_fallback = utc_date_from_signer_signed_attrs(si);
        }
    }
    signing_time_fallback
}

pub fn trusted_utc_date_from_authenticode_timestamp_token(
    pkcs7_der: &[u8],
    anchors: &AnchorStore,
    anchor_certs: &[Cert],
    online: &OnlineTrustOptions,
    verbose_chain: bool,
) -> Result<Option<UtcDate>> {
    let outer_sd = match signed_data_from_pkcs7(pkcs7_der) {
        Some(sd) => sd,
        None => return Ok(None),
    };
    let Some(primary_si) = outer_sd.signer_infos.0.as_slice().first() else {
        return Ok(None);
    };
    let primary_signature = primary_si.signature.as_bytes();
    let Some((token, tstinfo_der, gen_date)) =
        timestamp_token_from_signer_unsigned_attrs(primary_si)
    else {
        return Ok(None);
    };

    let ts_sd: SignedData = token
        .content
        .decode_as()
        .map_err(|e| anyhow!("timestamp token SignedData: {e}"))?;
    let parsed = psign_sip_digest::timestamp::parse_tst_info_der(&tstinfo_der)
        .ok_or_else(|| anyhow!("timestamp token TSTInfo parse failed"))?;
    let expected_imprint =
        digest_for_oid(&parsed.message_imprint_digest_alg_oid, primary_signature)?;
    if parsed.message_imprint_hashed_message != expected_imprint {
        return Err(anyhow!(
            "timestamp token MessageImprint does not match primary signer signature"
        ));
    }
    let tst_digest = sha2::Sha256::digest(&tstinfo_der);
    verify_signed_data_pkcs9_message_digest_and_rsa_sha256_pkcs1v15_signature(
        &ts_sd,
        0,
        &tst_digest,
    )
    .map_err(|e| anyhow!("timestamp token CMS signature: {e}"))?;

    let si = ts_sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("timestamp token SignedData has no SignerInfo"))?;
    let tsa_x509 = signed_data_certificate_for_signer_identifier(&ts_sd, &si.sid)
        .map_err(|e| anyhow!("timestamp token signer certificate: {e}"))?;
    if !x509_cert_has_time_stamping_eku(tsa_x509)? {
        return Err(anyhow!(
            "timestamp token signer certificate lacks timeStamping extended key usage"
        ));
    }
    let tsa_der = tsa_x509
        .to_der()
        .map_err(|e| anyhow!("encode timestamp signer certificate: {e}"))?;
    let tsa_leaf = Cert::from_der(&tsa_der).map_err(|e| anyhow!("timestamp signer Cert: {e}"))?;
    let embedded_certs = signed_data_embedded_picky_certs(&ts_sd)?;
    let mut merged = merge_unique_certs(anchor_certs.to_vec(), embedded_certs.clone())?;
    let chain_owned = issuer_chain_excluding_leaf_online(&tsa_leaf, &mut merged, online)?;
    let chain_vec: Vec<&Cert> = chain_owned.iter().collect();
    let root = terminal_root_cert_owned(&tsa_leaf, &chain_owned);
    let root_thumb = cert_sha1_thumbprint(root)?;
    if !anchors.contains_thumbprint(&root_thumb) {
        return Err(anyhow!(
            "timestamp token TSA chain terminates at an untrusted root"
        ));
    }
    check_revocation_chain(&tsa_leaf, &chain_owned, online)?;
    if verbose_chain {
        eprintln!(
            "trust-verify: timestamp TSA leaf subject: {}",
            tsa_leaf.subject_name()
        );
    }
    tsa_leaf
        .verifier()
        .chain(chain_vec.iter().copied())
        .exact_date(&gen_date)
        .verify()
        .map_err(|e| anyhow!("timestamp token TSA chain verification: {e}"))?;
    Ok(Some(gen_date))
}

fn signed_data_from_pkcs7(pkcs7_der: &[u8]) -> Option<SignedData> {
    let mut r = SliceReader::new(pkcs7_der).ok()?;
    let ci = ContentInfo::decode(&mut r).ok()?;
    if ci.content_type != ID_SIGNED_DATA {
        return None;
    }
    ci.content.decode_as::<SignedData>().ok()
}

fn timestamp_token_from_signer_unsigned_attrs(
    si: &SignerInfo,
) -> Option<(ContentInfo, Vec<u8>, UtcDate)> {
    let attrs = si.unsigned_attrs.as_ref()?;
    for attr in attrs
        .iter()
        .filter(|attr| timestamp_attr_priority(attr).is_some())
    {
        if let Some(v) = timestamp_token_from_attribute(attr) {
            return Some(v);
        }
    }
    for attr in attrs
        .iter()
        .filter(|attr| timestamp_attr_priority(attr).is_none())
    {
        if let Some(v) = timestamp_token_from_attribute(attr) {
            return Some(v);
        }
    }
    None
}

fn timestamp_token_from_attribute(attr: &Attribute) -> Option<(ContentInfo, Vec<u8>, UtcDate)> {
    for val in attr.values.iter() {
        let token = decode_content_info_loose(attribute_value_bytes(val))?;
        if token.content_type != ID_SIGNED_DATA {
            continue;
        }
        let sd: SignedData = token.content.decode_as().ok()?;
        if sd.encap_content_info.econtent_type != ID_CT_TSTINFO {
            continue;
        }
        let any = sd.encap_content_info.econtent.as_ref()?;
        let tstinfo_der = tstinfo_bytes_from_encapsulated_econtent(any)?;
        let gen_date = tstinfo_gen_time(tstinfo_der)?;
        return Some((token, tstinfo_der.to_vec(), gen_date));
    }
    None
}

fn digest_for_oid(oid: &str, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match oid {
        "1.3.14.3.2.26" => sha1::Sha1::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.1" => sha2::Sha256::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.2" => sha2::Sha384::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.3" => sha2::Sha512::digest(data).to_vec(),
        _ => {
            return Err(anyhow!(
                "unsupported timestamp MessageImprint digest algorithm {oid}"
            ));
        }
    })
}

fn signed_data_embedded_picky_certs(sd: &SignedData) -> Result<Vec<Cert>> {
    let mut out = Vec::new();
    let Some(set) = &sd.certificates else {
        return Ok(out);
    };
    for choice in set.0.iter() {
        let cms::cert::CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        let der = cert
            .to_der()
            .map_err(|e| anyhow!("encode timestamp embedded certificate: {e}"))?;
        out.push(Cert::from_der(&der).map_err(|e| anyhow!("timestamp embedded certificate: {e}"))?);
    }
    Ok(out)
}

fn x509_cert_has_time_stamping_eku(cert: &x509_cert::Certificate) -> Result<bool> {
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return Ok(false);
    };
    for ext in exts.iter().filter(|e| e.extn_id == EKU_EXTENSION_OID) {
        let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
            .map_err(|e| anyhow!("timestamp ExtendedKeyUsage extension: {e}"))?;
        if eku.0.contains(&TIME_STAMPING_EKU_OID) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn utc_date_from_signer_unsigned_attrs(si: &SignerInfo) -> Option<UtcDate> {
    let attrs = si.unsigned_attrs.as_ref()?;
    for attr in attrs.iter() {
        if timestamp_attr_priority(attr).is_none() {
            continue;
        }
        if let Some(d) = utc_date_from_timestamp_attribute(attr) {
            return Some(d);
        }
    }
    for attr in attrs.iter() {
        if timestamp_attr_priority(attr).is_some() {
            continue;
        }
        if let Some(d) = utc_date_from_timestamp_attribute(attr) {
            return Some(d);
        }
    }
    None
}

/// Lower sorts first: known timestamp OIDs before probing arbitrary attributes.
fn timestamp_attr_priority(attr: &Attribute) -> Option<u8> {
    if attr.oid == ID_AA_TIME_STAMP_TOKEN {
        return Some(0);
    }
    if attr.oid == OID_MS_TIMESTAMP_TOKEN {
        return Some(1);
    }
    None
}

fn utc_date_from_timestamp_attribute(attr: &Attribute) -> Option<UtcDate> {
    for val in attr.values.iter() {
        let payload = attribute_value_bytes(val);
        if let Some(d) = utc_date_from_unsigned_attr_payload(payload) {
            return Some(d);
        }
    }
    None
}

fn attribute_value_bytes(val: &der::asn1::Any) -> &[u8] {
    val.value()
}

fn utc_date_from_unsigned_attr_payload(payload: &[u8]) -> Option<UtcDate> {
    try_extract_from_nested_pkcs7(payload)
}

fn try_extract_from_nested_pkcs7(bytes: &[u8]) -> Option<UtcDate> {
    let ci = decode_content_info_loose(bytes)?;
    extract_gentime_from_timestamp_content_info(&ci)
}

fn decode_content_info_loose(bytes: &[u8]) -> Option<ContentInfo> {
    let mut r = SliceReader::new(bytes).ok()?;
    if let Ok(ci) = ContentInfo::decode(&mut r) {
        return Some(ci);
    }
    let inner = peel_octet_string_outer(bytes)?;
    let mut r2 = SliceReader::new(inner).ok()?;
    ContentInfo::decode(&mut r2).ok()
}

fn peel_octet_string_outer(bytes: &[u8]) -> Option<&[u8]> {
    let mut r = SliceReader::new(bytes).ok()?;
    let o = OctetStringRef::decode(&mut r).ok()?;
    Some(o.as_bytes())
}

fn extract_gentime_from_timestamp_content_info(ci: &ContentInfo) -> Option<UtcDate> {
    if ci.content_type != ID_SIGNED_DATA {
        return None;
    }
    let sd: SignedData = ci.content.decode_as().ok()?;
    gentime_from_signed_data_timestamp(&sd)
}

fn gentime_from_signed_data_timestamp(sd: &SignedData) -> Option<UtcDate> {
    let encap = &sd.encap_content_info;
    if encap.econtent_type != ID_CT_TSTINFO {
        return None;
    }
    let any = encap.econtent.as_ref()?;
    let tst = tstinfo_bytes_from_encapsulated_econtent(any)?;
    tstinfo_gen_time(tst)
}

fn tstinfo_bytes_from_encapsulated_econtent(any: &der::asn1::Any) -> Option<&[u8]> {
    peel_to_tstinfo_sequence(any.value())
}

fn peel_to_tstinfo_sequence(mut sl: &[u8]) -> Option<&[u8]> {
    for _ in 0..8 {
        if sl.is_empty() {
            return None;
        }
        match sl.first().copied()? {
            0x30 => return Some(sl),
            0x04 => sl = peel_octet_string_outer(sl)?,
            tag if tag == 0xa0 || tag == 0xa1 => {
                let mut r = SliceReader::new(sl).ok()?;
                let h = Header::decode(&mut r).ok()?;
                if !h.tag.is_constructed() {
                    return None;
                }
                sl = r.read_slice(h.length).ok()?;
            }
            _ => return None,
        }
    }
    None
}

fn tstinfo_gen_time(tstinfo_der: &[u8]) -> Option<UtcDate> {
    let mut r = SliceReader::new(tstinfo_der).ok()?;
    let hdr = Header::decode(&mut r).ok()?;
    if hdr.tag != Tag::Sequence {
        return None;
    }
    let inner = r.read_slice(hdr.length).ok()?;
    let mut sr = SliceReader::new(inner).ok()?;
    der_skip_tlv(&mut sr)?;
    der_skip_tlv(&mut sr)?;
    der_skip_tlv(&mut sr)?;
    der_skip_tlv(&mut sr)?;
    let gt = GeneralizedTime::decode(&mut sr).ok()?;
    utc_date_from_der_generalized_time(gt)
}

fn utc_date_from_der_generalized_time(gt: GeneralizedTime) -> Option<UtcDate> {
    let secs = i64::try_from(gt.to_unix_duration().as_secs()).ok()?;
    let odt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    Some(UtcDate::from(odt))
}

fn der_skip_tlv<'a, R: Reader<'a>>(reader: &mut R) -> Option<()> {
    let hdr = Header::decode(reader).ok()?;
    reader.read_slice(hdr.length).ok()?;
    Some(())
}

fn utc_date_from_signer_signed_attrs(si: &SignerInfo) -> Option<UtcDate> {
    let attrs = si.signed_attrs.as_ref()?;
    for attr in attrs.iter() {
        if attr.oid != ID_SIGNING_TIME {
            continue;
        }
        for val in attr.values.iter() {
            if let Some(d) = utc_date_from_signing_time_attr_any(val) {
                return Some(d);
            }
        }
    }
    None
}

/// PKCS#9 **`signing-time`** attribute values are **`ANY`** wrapping **`Time`** (UTCTime or GeneralizedTime).
///
/// [`der::asn1::Any::value`] is only the primitive **contents** (no tag); [`Time::decode`] expects a full TLV.
/// Re-encode the [`der::asn1::Any`] as DER (tag + length + value) before decoding as [`Time`].
fn utc_date_from_signing_time_attr_any(val: &der::asn1::Any) -> Option<UtcDate> {
    let tlv = val.to_der().ok()?;
    utc_date_from_signing_time_any(&tlv)
}

fn utc_date_from_signing_time_any(bytes: &[u8]) -> Option<UtcDate> {
    let t = Time::decode(&mut SliceReader::new(bytes).ok()?).ok()?;
    let secs = i64::try_from(t.to_unix_duration().as_secs()).ok()?;
    let odt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    Some(UtcDate::from(odt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::DateTime;
    use der::Encode;
    use der::asn1::UtcTime;
    use psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der;

    #[test]
    fn signing_time_utctime_roundtrip() {
        let dt = DateTime::new(2023, 6, 15, 12, 30, 45).unwrap();
        let ut = UtcTime::from_date_time(dt).unwrap();
        let der = ut.to_der().unwrap();
        let d = utc_date_from_signing_time_any(&der).unwrap();
        assert_eq!(d.year(), 2023);
        assert_eq!(d.month(), 6);
        assert_eq!(d.day(), 15);
    }

    #[test]
    fn signing_time_generalized_roundtrip() {
        let dt = DateTime::new(2023, 7, 1, 12, 0, 0).unwrap();
        let gt = GeneralizedTime::from_date_time(dt);
        let der = gt.to_der().unwrap();
        let d = utc_date_from_signing_time_any(&der).unwrap();
        assert_eq!(d.year(), 2023);
        assert_eq!(d.month(), 7);
        assert_eq!(d.day(), 1);
    }

    #[test]
    fn signing_time_rejects_truncated_or_non_time_der() {
        assert!(utc_date_from_signing_time_any(&[]).is_none());
        assert!(utc_date_from_signing_time_any(&[0x30, 0x00]).is_none());
        assert!(utc_date_from_signing_time_any(&[0x02, 0x01, 0x2a]).is_none());
    }

    #[test]
    fn tstinfo_gen_time_rejects_non_sequence_wrong_tag() {
        assert!(super::tstinfo_gen_time(&[0x02, 0x01, 0x00]).is_none());
    }

    #[test]
    fn tstinfo_gen_time_rejects_empty_sequence() {
        assert!(super::tstinfo_gen_time(&[0x30, 0x00]).is_none());
    }

    /// **`tiny32.signed.efi`** carries PKCS#9 **`signing-time`** (no nested RFC3161 **`TSTInfo`** in unsigned attrs).
    /// Portable extraction uses that for verification-instant selection when **`prefer_timestamp_signing_time`** is on.
    #[test]
    fn tiny32_upstream_pe_pkcs7_pkcs9_signing_time_extracts() {
        static PE: &[u8] =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = pe_first_pkcs7_signed_data_der(PE).expect("extract pkcs7");
        let d = utc_date_from_authenticode_timestamp_token(&pkcs7).expect("PKCS#9 signing-time");
        assert_eq!((d.year(), d.month(), d.day()), (2023, 6, 24));
    }

    /// **`tiny64.signed.efi`** (upstream **`authenticode-rs`** corpus) also carries PKCS#9 **`signing-time`**.
    #[test]
    fn tiny64_upstream_pe_pkcs7_pkcs9_signing_time_extracts() {
        static PE: &[u8] =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        let pkcs7 = pe_first_pkcs7_signed_data_der(PE).expect("extract pkcs7");
        let d = utc_date_from_authenticode_timestamp_token(&pkcs7).expect("PKCS#9 signing-time");
        assert_eq!((d.year(), d.month(), d.day()), (2023, 6, 24));
    }

    /// Portable extraction decodes a PKCS#7 **`ContentInfo`** with **`contentType`** **`signedData`**.
    /// Bare **`SignedData`** DER (no outer **`ContentInfo`**) is rejected so callers do not mis-pass **`SignedData`** blobs.
    #[test]
    fn tiny32_upstream_bare_signed_data_der_does_not_extract_timestamp() {
        use der::Encode;
        use psign_sip_digest::pkcs7::{
            encode_pkcs7_content_info_signed_data_der, parse_pkcs7_signed_data_der,
        };
        use psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der;

        static PE: &[u8] =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = pe_first_pkcs7_signed_data_der(PE).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let bare = sd.to_der().expect("SignedData DER");
        assert!(
            utc_date_from_authenticode_timestamp_token(&bare).is_none(),
            "bare SignedData must not parse as ContentInfo-wrapped PKCS#7"
        );
        let rewrapped = encode_pkcs7_content_info_signed_data_der(&sd).expect("ContentInfo");
        assert!(
            utc_date_from_authenticode_timestamp_token(&rewrapped).is_some(),
            "re-wrapped PKCS#7 must extract PKCS#9 signing-time like the PE fixture"
        );
    }

    /// Same **`ContentInfo`** vs bare **`SignedData`** rule as [`tiny32_upstream_bare_signed_data_der_does_not_extract_timestamp`], on **`tiny64`**.
    #[test]
    fn tiny64_upstream_bare_signed_data_der_does_not_extract_timestamp() {
        use der::Encode;
        use psign_sip_digest::pkcs7::{
            encode_pkcs7_content_info_signed_data_der, parse_pkcs7_signed_data_der,
        };
        use psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der;

        static PE: &[u8] =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        let pkcs7 = pe_first_pkcs7_signed_data_der(PE).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let bare = sd.to_der().expect("SignedData DER");
        assert!(utc_date_from_authenticode_timestamp_token(&bare).is_none());
        let rewrapped = encode_pkcs7_content_info_signed_data_der(&sd).expect("ContentInfo");
        assert!(utc_date_from_authenticode_timestamp_token(&rewrapped).is_some());
    }

    /// **`TSTInfo`** DER with **`genTime`** **2023-07-01T12:00:00Z** (same bytes as **`tstinfo_gen_time_skips_fixed_fields`**).
    const TSTINFO_DER_GEN_2023_07_01: &[u8] = &[
        0x30, 0x58, 0x02, 0x01, 0x01, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x59, 0x0a,
        0x04, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x03, 0x01, 0xe2, 0x40, 0x18, 0x0f,
        0x32, 0x30, 0x32, 0x33, 0x30, 0x37, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a,
    ];

    /// Clone **`tiny32`** **`SignedData`**, attach **`unsigned_attrs`** with nested timestamp **`ContentInfo`**
    /// (**`OCTET STRING`**-wrapped) for integration with **`utc_date_from_authenticode_timestamp_token`**.
    ///
    /// When **`append_pkcs9_signing_time`** is **`true`**, also appends PKCS#9 **`signing-time`** (**2024-01-15**)
    /// to the first **`SignerInfo`** **`signedAttrs`** so precedence (**unsigned nested `genTime`** first) is tested.
    fn tiny32_pkcs7_with_unsigned_nested_timestamp_attr(
        attr_oid: der::asn1::ObjectIdentifier,
        append_pkcs9_signing_time: bool,
    ) -> Vec<u8> {
        use cms::content_info::ContentInfo as CmsContentInfo;
        use cms::signed_data::{SignedAttributes, SignedData, UnsignedAttributes};
        use der::asn1::{Any, OctetStringRef, SetOfVec, UtcTime};
        use der::{DateTime, Decode, Encode, SliceReader};
        use psign_sip_digest::pkcs7::{
            encode_pkcs7_content_info_signed_data_der, parse_pkcs7_signed_data_der,
            signed_data_replace_signer_info_at,
        };
        use psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der;
        use x509_cert::attr::Attribute;

        static PE: &[u8] =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = pe_first_pkcs7_signed_data_der(PE).expect("pkcs7");
        let outer_sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");

        let mut inner_sd: SignedData = outer_sd.clone();
        inner_sd.encap_content_info.econtent_type = super::ID_CT_TSTINFO;
        let os = OctetStringRef::new(TSTINFO_DER_GEN_2023_07_01).expect("TSTInfo octets");
        inner_sd.encap_content_info.econtent =
            Some(Any::new(der::Tag::OctetString, os.as_bytes()).expect("eContent ANY"));

        let inner_sd_der = inner_sd.to_der().expect("inner SignedData DER");
        let mut rd = SliceReader::new(inner_sd_der.as_slice()).expect("reader");
        let inner_content = Any::decode(&mut rd).expect("SignedData as ANY");
        let inner_ci = CmsContentInfo {
            content_type: super::ID_SIGNED_DATA,
            content: inner_content,
        };
        let inner_ci_der = inner_ci.to_der().expect("inner ContentInfo DER");
        // Many TSAs wrap **`ContentInfo`** in an **`OCTET STRING`**; **`decode_content_info_loose`** peels it.
        let inner_ci_wrapped = Any::new(
            der::Tag::OctetString,
            OctetStringRef::new(&inner_ci_der).unwrap().as_bytes(),
        )
        .expect("wrap inner ContentInfo");

        let mut vals = SetOfVec::new();
        vals.insert(inner_ci_wrapped).expect("SET insert");
        let attr = Attribute {
            oid: attr_oid,
            values: vals,
        };
        let uattrs =
            UnsignedAttributes::try_from(vec![attr]).expect("unsigned timestamp attribute");

        let si0 = outer_sd
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo")
            .clone();
        let mut si = si0;
        if append_pkcs9_signing_time {
            let mut merged: Vec<Attribute> = si
                .signed_attrs
                .as_ref()
                .expect("tiny32 SignerInfo has signedAttrs")
                .iter()
                .cloned()
                .collect();
            let dt = DateTime::new(2024, 1, 15, 12, 0, 0).expect("signing-time date");
            let ut = UtcTime::from_date_time(dt).expect("UtcTime");
            let st_der = ut.to_der().expect("signing-time DER");
            let mut st_vals = SetOfVec::new();
            st_vals
                .insert(Any::from_der(&st_der).expect("signing-time ANY"))
                .expect("SET insert signing-time");
            merged.push(Attribute {
                oid: super::ID_SIGNING_TIME,
                values: st_vals,
            });
            si.signed_attrs = Some(
                SignedAttributes::try_from(merged).expect("merged signedAttrs SET OF Attribute"),
            );
        }
        si.unsigned_attrs = Some(uattrs);
        let new_sd =
            signed_data_replace_signer_info_at(&outer_sd, 0, si).expect("splice SignerInfo");
        encode_pkcs7_content_info_signed_data_der(&new_sd).expect("encode PKCS#7")
    }

    /// **`tiny32`** PKCS#7 with **`unsignedAttrs`** cleared and PKCS#9 **`signing-time`** set to **`(y, m, d)`** UTC (**14:30:00**).
    ///
    /// Any existing **`signing-time`** attribute is removed first so the **`SET OF Attribute`** stays well-formed.
    fn tiny32_pkcs7_pkcs9_signing_time_only(y: u16, m: u8, d: u8) -> Vec<u8> {
        use cms::signed_data::SignedAttributes;
        use der::asn1::{Any, SetOfVec, UtcTime};
        use der::{DateTime, Encode};
        use psign_sip_digest::pkcs7::{
            encode_pkcs7_content_info_signed_data_der, parse_pkcs7_signed_data_der,
            signed_data_replace_signer_info_at,
        };
        use psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der;
        use x509_cert::attr::Attribute;

        static PE: &[u8] =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = pe_first_pkcs7_signed_data_der(PE).expect("pkcs7");
        let outer_sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si0 = outer_sd
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo")
            .clone();
        let mut si = si0;
        si.unsigned_attrs = None;

        let mut merged: Vec<Attribute> = si
            .signed_attrs
            .as_ref()
            .expect("tiny32 signedAttrs")
            .iter()
            .filter(|a| a.oid != super::ID_SIGNING_TIME)
            .cloned()
            .collect();
        let dt = DateTime::new(y, m, d, 14, 30, 0).expect("signing-time date");
        let ut = UtcTime::from_date_time(dt).expect("UtcTime");
        let st_der = ut.to_der().expect("signing-time DER");
        let mut st_vals = SetOfVec::new();
        st_vals
            .insert(Any::from_der(&st_der).expect("signing-time ANY"))
            .expect("SET insert");
        merged.push(Attribute {
            oid: super::ID_SIGNING_TIME,
            values: st_vals,
        });
        si.signed_attrs =
            Some(SignedAttributes::try_from(merged).expect("signedAttrs with signing-time"));

        let new_sd =
            signed_data_replace_signer_info_at(&outer_sd, 0, si).expect("splice SignerInfo");
        encode_pkcs7_content_info_signed_data_der(&new_sd).expect("encode PKCS#7")
    }

    /// Same as [`tiny32_pkcs7_pkcs9_signing_time_only`], but PKCS#9 **`signing-time`** uses **`GeneralizedTime`** (RFC 5280 **`Time`** choice).
    fn tiny32_pkcs7_pkcs9_signing_time_generalized_only(y: u16, m: u8, d: u8) -> Vec<u8> {
        use cms::signed_data::SignedAttributes;
        use der::asn1::{Any, GeneralizedTime, SetOfVec};
        use der::{DateTime, Encode};
        use psign_sip_digest::pkcs7::{
            encode_pkcs7_content_info_signed_data_der, parse_pkcs7_signed_data_der,
            signed_data_replace_signer_info_at,
        };
        use psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der;
        use x509_cert::attr::Attribute;

        static PE: &[u8] =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = pe_first_pkcs7_signed_data_der(PE).expect("pkcs7");
        let outer_sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let si0 = outer_sd
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo")
            .clone();
        let mut si = si0;
        si.unsigned_attrs = None;

        let mut merged: Vec<Attribute> = si
            .signed_attrs
            .as_ref()
            .expect("tiny32 signedAttrs")
            .iter()
            .filter(|a| a.oid != super::ID_SIGNING_TIME)
            .cloned()
            .collect();
        let dt = DateTime::new(y, m, d, 9, 15, 30).expect("signing-time date");
        let gt = GeneralizedTime::from_date_time(dt);
        let st_der = gt.to_der().expect("signing-time DER");
        let mut st_vals = SetOfVec::new();
        st_vals
            .insert(Any::from_der(&st_der).expect("signing-time ANY"))
            .expect("SET insert");
        merged.push(Attribute {
            oid: super::ID_SIGNING_TIME,
            values: st_vals,
        });
        si.signed_attrs =
            Some(SignedAttributes::try_from(merged).expect("signedAttrs with signing-time"));

        let new_sd =
            signed_data_replace_signer_info_at(&outer_sd, 0, si).expect("splice SignerInfo");
        encode_pkcs7_content_info_signed_data_der(&new_sd).expect("encode PKCS#7")
    }

    /// **`id-aa-timeStampToken`** unsigned attribute → nested **`SignedData`** with **`id-ct-TSTInfo`** **`eContent`**.
    #[test]
    fn utc_date_from_authenticode_timestamp_token_id_aa_nested_tstinfo_gen_time() {
        use psign_sip_digest::pkcs7::parse_pkcs7_signed_data_der;

        let out =
            tiny32_pkcs7_with_unsigned_nested_timestamp_attr(super::ID_AA_TIME_STAMP_TOKEN, false);
        let round = parse_pkcs7_signed_data_der(&out).expect("round-trip SignedData");
        assert!(
            round.signer_infos.0.as_slice()[0]
                .unsigned_attrs
                .as_ref()
                .is_some()
        );

        let d = utc_date_from_authenticode_timestamp_token(&out).expect("genTime extract");
        assert_eq!((d.year(), d.month(), d.day()), (2023, 7, 1));
    }

    /// Microsoft **`1.3.6.1.4.1.311.3.3.1`** nested timestamp attribute (second-pass OID in **`utc_date_from_signer_unsigned_attrs`**).
    #[test]
    fn utc_date_from_authenticode_timestamp_token_ms_oid_nested_tstinfo_gen_time() {
        let out =
            tiny32_pkcs7_with_unsigned_nested_timestamp_attr(super::OID_MS_TIMESTAMP_TOKEN, false);
        let d = utc_date_from_authenticode_timestamp_token(&out).expect("genTime extract");
        assert_eq!((d.year(), d.month(), d.day()), (2023, 7, 1));
    }

    /// Nested **`TSTInfo.genTime`** (unsigned) is read before PKCS#9 **`signing-time`** on the same **`SignerInfo`**.
    #[test]
    fn utc_date_from_authenticode_timestamp_token_id_aa_nested_tstinfo_preempts_pkcs9_signing_time()
    {
        let out =
            tiny32_pkcs7_with_unsigned_nested_timestamp_attr(super::ID_AA_TIME_STAMP_TOKEN, true);
        let d = utc_date_from_authenticode_timestamp_token(&out).expect("extract");
        assert_eq!(
            (d.year(), d.month(), d.day()),
            (2023, 7, 1),
            "nested genTime must win over appended PKCS#9 signing-time (2024-01-15)"
        );
    }

    /// PKCS#9 **`signing-time`** alone (no nested unsigned timestamp) feeds **`utc_date_from_authenticode_timestamp_token`**.
    #[test]
    fn utc_date_from_authenticode_timestamp_token_pkcs9_signing_time_when_no_unsigned() {
        let out = tiny32_pkcs7_pkcs9_signing_time_only(2022, 11, 8);
        let d = utc_date_from_authenticode_timestamp_token(&out).expect("PKCS#9 signing-time");
        assert_eq!((d.year(), d.month(), d.day()), (2022, 11, 8));
    }

    /// **`resolve_verification_utc_date`** with **`prefer_timestamp_signing_time`** uses PKCS#9 **`signing-time`** when no nested token.
    #[test]
    fn resolve_verification_utc_date_pkcs9_signing_time_when_no_unsigned() {
        use crate::policy::AuthenticodeTrustPolicy;
        use crate::verification_instant::resolve_verification_utc_date;

        let out = tiny32_pkcs7_pkcs9_signing_time_only(2022, 11, 8);
        let policy = AuthenticodeTrustPolicy {
            prefer_timestamp_signing_time: true,
            require_valid_timestamp: false,
            ..AuthenticodeTrustPolicy::default()
        };
        let d = resolve_verification_utc_date(&out, &policy).expect("resolve");
        assert_eq!((d.year(), d.month(), d.day()), (2022, 11, 8));
    }

    #[test]
    fn utc_date_from_authenticode_timestamp_token_pkcs9_signing_time_generalized_when_no_unsigned()
    {
        let out = tiny32_pkcs7_pkcs9_signing_time_generalized_only(2050, 3, 1);
        let d = utc_date_from_authenticode_timestamp_token(&out).expect("PKCS#9 GeneralizedTime");
        assert_eq!((d.year(), d.month(), d.day()), (2050, 3, 1));
    }

    #[test]
    fn resolve_verification_utc_date_pkcs9_signing_time_generalized_require_timestamp_ok() {
        use crate::policy::AuthenticodeTrustPolicy;
        use crate::verification_instant::resolve_verification_utc_date;

        let out = tiny32_pkcs7_pkcs9_signing_time_generalized_only(2050, 3, 1);
        let policy = AuthenticodeTrustPolicy {
            prefer_timestamp_signing_time: true,
            require_valid_timestamp: true,
            ..AuthenticodeTrustPolicy::default()
        };
        let d = resolve_verification_utc_date(&out, &policy).expect("resolve");
        assert_eq!((d.year(), d.month(), d.day()), (2050, 3, 1));
    }

    #[test]
    fn tstinfo_gen_time_skips_fixed_fields() {
        let d = tstinfo_gen_time(TSTINFO_DER_GEN_2023_07_01).unwrap();
        assert_eq!(d.year(), 2023);
        assert_eq!(d.month(), 7);
        assert_eq!(d.day(), 1);
    }
}
