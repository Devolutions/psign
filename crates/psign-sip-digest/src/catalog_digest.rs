//! Windows `.cat` catalog files are a single PKCS#7 `SignedData` blob whose encapsulated content
//! type is usually Microsoft CTL (`1.3.6.1.4.1.311.10.1`), not `SPC_INDIRECT_DATA`, so
//! [`authenticode::AuthenticodeSignature`] does not apply.
//!
//! CMS signing uses the PKCS#9 **`messageDigest`** authenticated attribute; per PKCS#9/CMS practice
//! it matches the digest algorithm in `SignedData` applied to the **payload octets of
//! `EncapsulatedContentInfo.eContent`** (see RFC 5652). We locate the digest inside Microsoft’s
//! wrapped attribute values by scanning for a DER **`OCTET STRING`** whose contents equal that hash.

use super::pe_digest::PeAuthenticodeHashKind;
use crate::pkcs7::AuthenticodeSigningDigest;
use anyhow::{Context, Result, anyhow};
use authenticode::{DigestInfo, SpcAttributeTypeAndOptionalValue, SpcIndirectDataContent};
use cms::signed_data::SignedData;
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode, SliceReader};
use digest::Digest;
use rsa::RsaPrivateKey;
use std::collections::HashSet;
use std::path::Path;
use x509_cert::Certificate;
use x509_cert::spki::AlgorithmIdentifierOwned;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_MS_CTL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1");
const ID_SPC_INDIRECT_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
const ID_SPC_PE_IMAGE_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.15");
const ID_SPC_CAB_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.25");
const ID_MS_CTL_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.1.1");
const ID_MS_CTL_SUBJECT_ALG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.1.2");

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const CATALOG_GENERIC_LINK_VALUE_DER: &[u8] = &[0xa2, 0x02, 0x80, 0x00];
const CATALOG_THIS_UPDATE_UTC: &[u8] = b"700101000000Z";

const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogMember {
    pub subject_identifier: Vec<u8>,
    pub subject_name: Option<String>,
    pub data_oid: ObjectIdentifier,
    pub digest_algorithm_oid: ObjectIdentifier,
    pub digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogMemberMatch {
    pub member_index: usize,
    pub member: CatalogMember,
    pub computed_digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSubjectInput {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogSignResult {
    pub pkcs7_der: Vec<u8>,
    pub members: Vec<CatalogMember>,
}

#[derive(Clone, Copy, Debug)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    full: &'a [u8],
}

fn digest_kind_from_digest_alg_oid(oid: ObjectIdentifier) -> Result<PeAuthenticodeHashKind> {
    if oid == OID_SHA1 {
        Ok(PeAuthenticodeHashKind::Sha1)
    } else if oid == OID_SHA256 {
        Ok(PeAuthenticodeHashKind::Sha256)
    } else if oid == OID_SHA384 {
        Ok(PeAuthenticodeHashKind::Sha384)
    } else if oid == OID_SHA512 {
        Ok(PeAuthenticodeHashKind::Sha512)
    } else {
        Err(anyhow!(
            "unsupported digest algorithm OID {} in catalog SignedData",
            oid
        ))
    }
}

fn hash_econtent(kind: PeAuthenticodeHashKind, econtent: &[u8]) -> Vec<u8> {
    match kind {
        PeAuthenticodeHashKind::Sha1 => sha1::Sha1::digest(econtent).to_vec(),
        PeAuthenticodeHashKind::Sha256 => sha2::Sha256::digest(econtent).to_vec(),
        PeAuthenticodeHashKind::Sha384 => sha2::Sha384::digest(econtent).to_vec(),
        PeAuthenticodeHashKind::Sha512 => sha2::Sha512::digest(econtent).to_vec(),
    }
}

fn hash_subject_bytes(kind: PeAuthenticodeHashKind, bytes: &[u8]) -> Vec<u8> {
    match kind {
        PeAuthenticodeHashKind::Sha1 => sha1::Sha1::digest(bytes).to_vec(),
        PeAuthenticodeHashKind::Sha256 => sha2::Sha256::digest(bytes).to_vec(),
        PeAuthenticodeHashKind::Sha384 => sha2::Sha384::digest(bytes).to_vec(),
        PeAuthenticodeHashKind::Sha512 => sha2::Sha512::digest(bytes).to_vec(),
    }
}

fn digest_algorithm_identifier(
    digest_algorithm: AuthenticodeSigningDigest,
) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: match digest_algorithm {
            AuthenticodeSigningDigest::Sha256 => OID_SHA256,
            AuthenticodeSigningDigest::Sha384 => OID_SHA384,
            AuthenticodeSigningDigest::Sha512 => OID_SHA512,
        },
        parameters: None,
    }
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let len_bytes = &bytes[first..];
    let mut out = Vec::with_capacity(1 + len_bytes.len());
    out.push(0x80 | (len_bytes.len() as u8));
    out.extend_from_slice(len_bytes);
    out
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + value.len());
    out.push(tag);
    out.extend_from_slice(&der_len(value.len()));
    out.extend_from_slice(value);
    out
}

fn concat_der(items: Vec<Vec<u8>>) -> Vec<u8> {
    let len = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(len);
    for item in items {
        out.extend_from_slice(&item);
    }
    out
}

fn der_sequence(items: Vec<Vec<u8>>) -> Vec<u8> {
    der_tlv(TAG_SEQUENCE, &concat_der(items))
}

fn der_set(items: Vec<Vec<u8>>) -> Vec<u8> {
    der_tlv(TAG_SET, &concat_der(items))
}

fn der_oid(oid: ObjectIdentifier) -> Result<Vec<u8>> {
    oid.to_der().map_err(|e| anyhow!("encode OID {oid}: {e}"))
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    der_tlv(TAG_OCTET_STRING, bytes)
}

fn der_utc_time_literal(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() != 13 || bytes.last() != Some(&b'Z') {
        return Err(anyhow!("catalog UTC_TIME literal must be YYMMDDHHMMSSZ"));
    }
    Ok(der_tlv(0x17, bytes))
}

fn catalog_subject_identifier(name: &str) -> Result<Vec<u8>> {
    if name.is_empty() {
        return Err(anyhow!("catalog subject name must not be empty"));
    }
    if name.contains(['/', '\\', '\0']) {
        return Err(anyhow!(
            "catalog subject name must be a file name, not a path: {name}"
        ));
    }
    let decorated = format!("<{name}>\0");
    let mut out = Vec::with_capacity(decorated.len() * 2);
    for unit in decorated.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(out)
}

fn catalog_list_identifier(members: &[CatalogMember]) -> Vec<u8> {
    let mut h = sha2::Sha256::new();
    for member in members {
        h.update(&member.subject_identifier);
        h.update(&member.digest);
    }
    h.finalize()[..16].to_vec()
}

fn catalog_generic_spc_indirect_data(
    digest_algorithm: AuthenticodeSigningDigest,
    subject_digest: &[u8],
) -> Result<SpcIndirectDataContent> {
    let expected = digest_algorithm.pe_hash_kind().digest_output_len();
    if subject_digest.len() != expected {
        return Err(anyhow!(
            "catalog subject digest length {} does not match {:?} ({expected} octets)",
            subject_digest.len(),
            digest_algorithm
        ));
    }
    let digest = OctetString::new(subject_digest.to_vec())
        .map_err(|e| anyhow!("catalog SpcIndirectData digest OCTET STRING: {e}"))?;
    Ok(SpcIndirectDataContent {
        data: SpcAttributeTypeAndOptionalValue {
            value_type: ID_SPC_CAB_DATA,
            value: Any::from_der(CATALOG_GENERIC_LINK_VALUE_DER)
                .map_err(|e| anyhow!("catalog generic SPC link Any: {e}"))?,
        },
        message_digest: DigestInfo {
            digest_algorithm: digest_algorithm_identifier(digest_algorithm),
            digest,
        },
    })
}

fn catalog_subject_indirect_data(
    digest_algorithm: AuthenticodeSigningDigest,
    subject: &[u8],
) -> Result<(SpcIndirectDataContent, ObjectIdentifier, Vec<u8>)> {
    let kind = digest_algorithm.pe_hash_kind();
    if let Ok(pe_digest) = crate::pe_digest::pe_authenticode_digest(subject, kind) {
        let indirect = crate::pkcs7::pe_spc_indirect_data(digest_algorithm, &pe_digest)?;
        return Ok((indirect, ID_SPC_PE_IMAGE_DATA, pe_digest));
    }
    let digest = hash_subject_bytes(kind, subject);
    let indirect = catalog_generic_spc_indirect_data(digest_algorithm, &digest)?;
    Ok((indirect, ID_SPC_CAB_DATA, digest))
}

fn catalog_ctl_entry_der(
    subject_identifier: &[u8],
    indirect: &SpcIndirectDataContent,
) -> Result<Vec<u8>> {
    let indirect_der = indirect
        .to_der()
        .map_err(|e| anyhow!("encode catalog SpcIndirectDataContent: {e}"))?;
    let attr = der_sequence(vec![
        der_oid(ID_SPC_INDIRECT_DATA)?,
        der_set(vec![indirect_der]),
    ]);
    Ok(der_sequence(vec![
        der_octet_string(subject_identifier),
        der_set(vec![attr]),
    ]))
}

/// Build Microsoft CTL `eContent` DER for a portable generic catalog.
pub fn create_catalog_ctl_econtent_der(
    subjects: &[CatalogSubjectInput],
    digest_algorithm: AuthenticodeSigningDigest,
) -> Result<(Vec<u8>, Vec<CatalogMember>)> {
    if subjects.is_empty() {
        return Err(anyhow!(
            "catalog signing requires at least one subject file"
        ));
    }

    let mut seen = HashSet::with_capacity(subjects.len());
    let mut members = Vec::with_capacity(subjects.len());
    let mut entries = Vec::with_capacity(subjects.len());
    for subject in subjects {
        let key = subject.name.to_ascii_lowercase();
        if !seen.insert(key) {
            return Err(anyhow!(
                "catalog contains duplicate subject file name {}",
                subject.name
            ));
        }
        let subject_identifier = catalog_subject_identifier(&subject.name)?;
        let (indirect, data_oid, digest) =
            catalog_subject_indirect_data(digest_algorithm, &subject.bytes)?;
        entries.push(catalog_ctl_entry_der(&subject_identifier, &indirect)?);
        members.push(CatalogMember {
            subject_name: decode_utf16le_subject_identifier(&subject_identifier),
            subject_identifier,
            data_oid,
            digest_algorithm_oid: digest_algorithm_identifier(digest_algorithm).oid,
            digest,
        });
    }

    let trusted_subjects = der_sequence(entries);
    let list_identifier = catalog_list_identifier(&members);
    let ctl_info = der_sequence(vec![
        der_sequence(vec![der_oid(ID_MS_CTL_USAGE)?]),
        der_octet_string(&list_identifier),
        der_utc_time_literal(CATALOG_THIS_UPDATE_UTC)?,
        der_sequence(vec![der_oid(ID_MS_CTL_SUBJECT_ALG)?, der_null()]),
        trusted_subjects,
    ]);
    Ok((ctl_info, members))
}

/// Create a signed portable generic catalog (`.cat`) from CTL members using an RSA private key.
pub fn create_catalog_pkcs7_der_rsa(
    subjects: &[CatalogSubjectInput],
    digest_algorithm: AuthenticodeSigningDigest,
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<CatalogSignResult> {
    let (econtent_der, members) = create_catalog_ctl_econtent_der(subjects, digest_algorithm)?;
    let pkcs7_der = crate::pkcs7::create_pkcs7_signed_data_der_rsa(
        ID_MS_CTL,
        &econtent_der,
        digest_algorithm,
        signer_cert,
        chain_certs,
        private_key,
    )?;
    Ok(CatalogSignResult { pkcs7_der, members })
}

fn der_len_at(data: &[u8], len_off: usize) -> Result<(usize, usize)> {
    let first = *data
        .get(len_off)
        .ok_or_else(|| anyhow!("truncated DER length"))?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 {
        return Err(anyhow!("indefinite DER length is not allowed"));
    }
    if n > std::mem::size_of::<usize>() {
        return Err(anyhow!("DER length too large"));
    }
    let bytes = data
        .get(len_off + 1..len_off + 1 + n)
        .ok_or_else(|| anyhow!("truncated DER long-form length"))?;
    if bytes.first() == Some(&0) {
        return Err(anyhow!("non-minimal DER length"));
    }
    let mut len = 0usize;
    for b in bytes {
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(usize::from(*b)))
            .ok_or_else(|| anyhow!("DER length overflow"))?;
    }
    Ok((len, 1 + n))
}

fn tlv_at(data: &[u8], off: usize) -> Result<(Tlv<'_>, usize)> {
    let tag = *data.get(off).ok_or_else(|| anyhow!("truncated DER tag"))?;
    let (len, len_len) = der_len_at(data, off + 1)?;
    let header_len = 1 + len_len;
    let value_start = off
        .checked_add(header_len)
        .ok_or_else(|| anyhow!("DER offset overflow"))?;
    let value_end = value_start
        .checked_add(len)
        .ok_or_else(|| anyhow!("DER value length overflow"))?;
    let value = data
        .get(value_start..value_end)
        .ok_or_else(|| anyhow!("truncated DER value"))?;
    let full = data
        .get(off..value_end)
        .ok_or_else(|| anyhow!("truncated DER TLV"))?;
    Ok((Tlv { tag, value, full }, value_end))
}

fn children(data: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let (tlv, next) = tlv_at(data, off)?;
        out.push(tlv);
        off = next;
    }
    Ok(out)
}

fn oid_value_bytes(oid: ObjectIdentifier) -> Result<Vec<u8>> {
    let der = oid.to_der().map_err(|e| anyhow!("encode OID {oid}: {e}"))?;
    let (tlv, next) = tlv_at(&der, 0)?;
    if next != der.len() || tlv.tag != TAG_OBJECT_IDENTIFIER {
        return Err(anyhow!("encoded OID {oid} has unexpected DER shape"));
    }
    Ok(tlv.value.to_vec())
}

fn decode_utf16le_subject_identifier(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16(&units).ok()
}

fn spc_indirect_from_attribute_sequence(
    seq_value: &[u8],
    spc_indirect_oid: &[u8],
) -> Result<Option<SpcIndirectDataContent>> {
    let items = children(seq_value)?;
    if items.len() < 2
        || items[0].tag != TAG_OBJECT_IDENTIFIER
        || items[0].value != spc_indirect_oid
        || items[1].tag != TAG_SET
    {
        return Ok(None);
    }
    for value in children(items[1].value)? {
        if value.tag == TAG_SEQUENCE {
            return SpcIndirectDataContent::from_der(value.full)
                .map(Some)
                .map_err(|e| anyhow!("catalog SpcIndirectDataContent: {e}"));
        }
    }
    Err(anyhow!(
        "catalog SPC_INDIRECT_DATA attribute has no SEQUENCE value"
    ))
}

fn find_spc_indirect_in_member_sequence(
    member_value: &[u8],
    spc_indirect_oid: &[u8],
) -> Result<Option<SpcIndirectDataContent>> {
    for child in children(member_value)? {
        if child.tag == TAG_SEQUENCE
            && let Some(indirect) =
                spc_indirect_from_attribute_sequence(child.value, spc_indirect_oid)?
        {
            return Ok(Some(indirect));
        }
        if matches!(child.tag, TAG_SEQUENCE | TAG_SET)
            && let Some(indirect) =
                find_spc_indirect_in_member_sequence(child.value, spc_indirect_oid)?
        {
            return Ok(Some(indirect));
        }
    }
    Ok(None)
}

fn collect_catalog_members_from_sequence(
    seq_value: &[u8],
    spc_indirect_oid: &[u8],
    members: &mut Vec<CatalogMember>,
) -> Result<()> {
    for seq in children(seq_value)? {
        if seq.tag != TAG_SEQUENCE {
            continue;
        }
        let seq_children = children(seq.value)?;
        if let Some(subject) = seq_children.first()
            && subject.tag == TAG_OCTET_STRING
            && let Some(indirect) =
                find_spc_indirect_in_member_sequence(seq.value, spc_indirect_oid)?
        {
            members.push(CatalogMember {
                subject_identifier: subject.value.to_vec(),
                subject_name: decode_utf16le_subject_identifier(subject.value),
                data_oid: indirect.data.value_type,
                digest_algorithm_oid: indirect.message_digest.digest_algorithm.oid,
                digest: indirect.message_digest.digest.as_bytes().to_vec(),
            });
            continue;
        }
        collect_catalog_members_from_sequence(seq.value, spc_indirect_oid, members)?;
    }
    Ok(())
}

/// Return true if `blob` contains a DER-encoded OCTET STRING (tag `0x04`) whose value equals `expected`.
fn blob_contains_octet_string_digest(blob: &[u8], expected: &[u8]) -> bool {
    let len = expected.len();
    let mut i = 0usize;
    while i + 2 + len <= blob.len() {
        if blob[i] == 0x04 {
            let lb = blob[i + 1];
            if lb as usize == len && blob[i + 2..i + 2 + len] == *expected {
                return true;
            }
            // Two-byte length form 0x81 <len> for digest sizes ≤255 (e.g. SHA-384/512).
            if lb == 0x81
                && let Some(l2) = blob.get(i + 2).copied()
                && l2 as usize == len
                && blob.get(i + 3..i + 3 + len) == Some(expected)
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn pkcs9_message_digest_matches(
    attrs: &cms::signed_data::SignedAttributes,
    computed: &[u8],
) -> Result<()> {
    for attr in attrs.iter() {
        if attr.oid != ID_MESSAGE_DIGEST {
            continue;
        }
        for val in attr.values.iter() {
            let payload = val.value();
            if let Ok(oct) = val.decode_as::<der::asn1::OctetString>()
                && oct.as_bytes() == computed
            {
                return Ok(());
            }
            if blob_contains_octet_string_digest(payload, computed) {
                return Ok(());
            }
        }
        return Err(anyhow!(
            "PKCS#9 messageDigest signed attribute present but no OCTET STRING matched eContent hash"
        ));
    }
    Err(anyhow!(
        "catalog SignerInfo is missing PKCS#9 messageDigest authenticated attribute"
    ))
}

/// **RS256** prehash (**SHA-256** over authenticated **`signedAttrs`**) for a **`.cat`**-style file whose body is PKCS#7 **`SignedData`** (same wire as **`pkcs7-signer-rs256-prehash`** after [`crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode`]).
///
/// Typical Microsoft **CTL** catalogs use this CMS shape; Authenticode **PE** PKCS#7 blobs also decode as **`SignedData`** but **`verify_catalog_digest_consistency`** may not apply (different PKCS#9 **`messageDigest`** encoding vs catalog scan).
pub fn catalog_rsa_sha256_signer_prehash_digest(
    data: &[u8],
    signer_index: usize,
) -> Result<Vec<u8>> {
    let normalized = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(data);
    let sd = crate::pkcs7::parse_pkcs7_signed_data_der(normalized.as_ref())?;
    crate::pkcs7::signed_data_rsa_sha256_signer_prehash_digest(&sd, signer_index)
}

fn catalog_signed_data(data: &[u8]) -> Result<SignedData> {
    let mut r = SliceReader::new(data).map_err(|_| anyhow!("empty catalog file"))?;
    let ci = cms::content_info::ContentInfo::decode(&mut r)
        .map_err(|e| anyhow!("catalog PKCS#7 ContentInfo: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(anyhow!(
            "catalog root content type is not SignedData (got {})",
            ci.content_type
        ));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| anyhow!("catalog SignedData: {e}"))?;
    if sd.encap_content_info.econtent_type != ID_MS_CTL {
        return Err(anyhow!(
            "catalog encapsulated content type is not Microsoft CTL (got {})",
            sd.encap_content_info.econtent_type
        ));
    }
    Ok(sd)
}

/// Compute the CMS digest over encapsulated catalog `eContent`, using the first signer digest algorithm.
pub fn catalog_econtent_digest(data: &[u8]) -> Result<Vec<u8>> {
    let sd = catalog_signed_data(data)?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("catalog SignedData has no SignerInfo"))?;
    let kind = digest_kind_from_digest_alg_oid(si.digest_alg.oid)?;
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .map(|a| a.value())
        .unwrap_or_default();
    Ok(hash_econtent(kind, econtent))
}

/// Parse MakeCat-style CTL member entries from a signed catalog.
pub fn catalog_members_bytes(data: &[u8]) -> Result<Vec<CatalogMember>> {
    let sd = catalog_signed_data(data)?;
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .map(|a| a.value())
        .ok_or_else(|| anyhow!("catalog SignedData has no CTL eContent"))?;
    let spc_indirect_oid = oid_value_bytes(ID_SPC_INDIRECT_DATA)?;
    let mut members = Vec::new();
    collect_catalog_members_from_sequence(econtent, &spc_indirect_oid, &mut members)?;
    if members.is_empty() {
        return Err(anyhow!(
            "catalog CTL contains no SPC_INDIRECT_DATA member entries"
        ));
    }
    Ok(members)
}

fn catalog_member_digest_for_subject(member: &CatalogMember, subject: &[u8]) -> Result<Vec<u8>> {
    let kind = digest_kind_from_digest_alg_oid(member.digest_algorithm_oid)?;
    if member.data_oid == ID_SPC_PE_IMAGE_DATA {
        crate::pe_digest::pe_authenticode_digest(subject, kind)
            .context("compute PE Authenticode digest for catalog member")
    } else {
        Ok(hash_subject_bytes(kind, subject))
    }
}

/// Verify that `subject` is represented by one CTL member entry in `catalog`.
pub fn verify_catalog_member_bytes(catalog: &[u8], subject: &[u8]) -> Result<CatalogMemberMatch> {
    let members = catalog_members_bytes(catalog)?;
    let mut digest_errors = Vec::new();
    for (idx, member) in members.iter().enumerate() {
        match catalog_member_digest_for_subject(member, subject) {
            Ok(computed) if computed == member.digest => {
                return Ok(CatalogMemberMatch {
                    member_index: idx,
                    member: member.clone(),
                    computed_digest: computed,
                });
            }
            Ok(_) => {}
            Err(e) => digest_errors.push(format!(
                "{}: {e:#}",
                member.subject_name.as_deref().unwrap_or("<unnamed>")
            )),
        }
    }
    if digest_errors.is_empty() {
        Err(anyhow!(
            "subject file is not a member of the catalog ({} member entr{} checked)",
            members.len(),
            if members.len() == 1 { "y" } else { "ies" }
        ))
    } else {
        Err(anyhow!(
            "subject file is not a member of the catalog; digest errors while checking members: {}",
            digest_errors.join("; ")
        ))
    }
}

/// Verify a file's membership in a catalog by path.
pub fn verify_catalog_member(
    catalog_path: &Path,
    subject_path: &Path,
) -> Result<CatalogMemberMatch> {
    let catalog = std::fs::read(catalog_path)
        .with_context(|| format!("read catalog {}", catalog_path.display()))?;
    let subject = std::fs::read(subject_path)
        .with_context(|| format!("read subject {}", subject_path.display()))?;
    verify_catalog_member_bytes(&catalog, &subject)
}

/// Verify each `SignerInfo`'s PKCS#9 `messageDigest` matches the CMS digest over encapsulated `eContent`.
pub fn verify_catalog_digest_consistency_bytes(data: &[u8]) -> Result<()> {
    let sd = catalog_signed_data(data)?;
    if sd.digest_algorithms.len() != 1 {
        return Err(anyhow!(
            "expected one digest algorithm in SignedData, got {}",
            sd.digest_algorithms.len()
        ));
    }
    let ref_alg = sd.digest_algorithms.as_slice()[0].clone();

    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .map(|a| a.value())
        .unwrap_or_default();

    let n_signers = sd.signer_infos.0.len();
    if n_signers == 0 {
        return Err(anyhow!("catalog SignedData has no SignerInfo"));
    }

    for si in sd.signer_infos.0.iter() {
        if si.digest_alg != ref_alg {
            return Err(anyhow!(
                "SignerInfo digestAlgorithm does not match SignedData.digestAlgorithms"
            ));
        }
        let kind = digest_kind_from_digest_alg_oid(si.digest_alg.oid)?;
        let computed = hash_econtent(kind, econtent);
        let attrs = si
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("catalog SignerInfo missing authenticated attributes"))?;
        pkcs9_message_digest_matches(attrs, &computed)?;
    }

    Ok(())
}

/// PKCS#7 CTL catalog file: CMS `eContent` digest vs PKCS#9 `messageDigest` (all signers).
pub fn verify_catalog_digest_consistency(path: &Path) -> Result<()> {
    let data = std::fs::read(path)?;
    verify_catalog_digest_consistency_bytes(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_string_scan_finds_sha256() {
        let digest = [7u8; 32];
        let mut blob = vec![0x6c, 0x40, 0x30, 0x04, 0x20];
        blob.extend_from_slice(&digest);
        blob.push(0xff);
        assert!(blob_contains_octet_string_digest(&blob, &digest));
    }

    #[test]
    fn octet_string_scan_long_len_form_sha384() {
        let digest = [9u8; 48];
        let mut blob = vec![0x04, 0x81, 48];
        blob.extend_from_slice(&digest);
        assert!(blob_contains_octet_string_digest(&blob, &digest));
    }

    #[test]
    fn catalog_rsa_sha256_signer_prehash_matches_pkcs7_helper_on_tiny32_pe_pkcs7_cat() {
        let cat = include_bytes!(
            "../../../tests/fixtures/catalog-authenticode-upstream/tiny32-content.cat"
        );
        let a =
            super::catalog_rsa_sha256_signer_prehash_digest(cat.as_slice(), 0).expect("catalog");
        let pkcs7 = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(cat.as_slice());
        let sd = crate::pkcs7::parse_pkcs7_signed_data_der(pkcs7.as_ref()).expect("sd");
        let b = crate::pkcs7::signed_data_rsa_sha256_signer_prehash_digest(&sd, 0).expect("pkcs7");
        assert_eq!(a, b);
    }
}
