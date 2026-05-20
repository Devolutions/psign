//! Authenticode **PE page hashes** (`SPC_PE_IMAGE_PAGE_HASHES` authenticated attributes).
//!
//! Native **`verify --verify-page-hashes`** + `WinVerifyTrust` remains authoritative for **exact** `/ph`
//! behavior (checksum / security-directory exclusions differ from a naive byte sweep).
//!
//! This module provides:
//! - **CMS-aware extraction** of page-hash attributes from embedded PKCS#7 `SignedData` (`SignerInfo.signed_attrs`).
//! - **Substring OID TLV fallback** when `ContentInfo`/`SignedData` decoding fails (non-standard wrappers).
//! - **DER peeling + flat table parse** for Microsoft’s Authenticode page-hash blobs (see
//!   [`parse_page_hash_attribute_entries`]): little-endian **`u32` end offsets** followed by digests, terminated by an
//!   all-zero digest (common Signify / PE tooling convention).
//! - **Experimental contiguous verify** ([`verify_page_hash_entries_contiguous_file_offsets`]): hash each
//!   **`[prev_end, page_end_offset)`** slice from the raw PE file (starts at `0`). See that function’s notes vs
//!   `WinVerifyTrust`.

use crate::pe_digest::ParsedPe;
use anyhow::{Context, Result, anyhow};
use authenticode::{AttributeCertificateIterator, WIN_CERT_TYPE_PKCS_SIGNED_DATA};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{ObjectIdentifier, OctetStringRef};
use der::{Decode, Header, Length, Reader, SliceReader, Tag};
use digest::Digest;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// Authenticated-attribute OID **`1.3.6.1.4.1.311.2.3.1`** (`SPC_PE_IMAGE_PAGE_HASHES` V1).
pub const OID_PE_PAGE_HASHES_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.3.1");

/// Authenticated-attribute OID **`1.3.6.1.4.1.311.2.3.2`** (`SPC_PE_IMAGE_PAGE_HASHES` V2).
pub const OID_PE_PAGE_HASHES_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.3.2");

/// Which Microsoft page-hash attribute OID matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageHashAttrKind {
    V1,
    V2,
}

/// One `(kind, raw_attribute_value_bytes)` from a `SignerInfo`'s signed attributes SET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageHashAttrValue {
    pub kind: PageHashAttrKind,
    /// Raw DER of the attribute value (`ANY` inside the SET OF Attribute).
    pub value_der: Vec<u8>,
}

/// Page-hash attributes grouped by PKCS#7 blob index and signer index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PePageHashAttrLocation {
    pub pkcs7_index: usize,
    pub signer_index: usize,
    pub values: Vec<PageHashAttrValue>,
}

/// One slot in the flat Authenticode page-hash table (`u32` LE then digest bytes, repeated).
///
/// `page_end_offset` is the **end offset** within the PE image for the hashed range of this slot (tooling convention;
/// adjacent slots imply start boundaries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageHashTableEntry {
    pub page_end_offset: u32,
    pub digest: Vec<u8>,
}

/// Digest width implied by the authenticated-attribute OID variant (`V1` → SHA-1, `V2` → SHA-256).
pub fn digest_byte_len_for_page_hash_attr(kind: PageHashAttrKind) -> usize {
    match kind {
        PageHashAttrKind::V1 => 20,
        PageHashAttrKind::V2 => 32,
    }
}

fn map_der(e: der::Error) -> anyhow::Error {
    anyhow!("{e}")
}

fn try_spc_serialized_object_data(seq_der: &[u8]) -> Result<Option<&[u8]>> {
    if seq_der.first() != Some(&0x30) {
        return Ok(None);
    }
    let mut r = SliceReader::new(seq_der).map_err(|_| anyhow!("invalid DER slice"))?;
    let hdr = Header::decode(&mut r).map_err(map_der)?;
    if hdr.tag != Tag::Sequence {
        return Ok(None);
    }
    let body = r.read_slice(hdr.length).map_err(map_der)?;
    let mut inner = SliceReader::new(body).map_err(|_| anyhow!("inner DER slice"))?;
    let class_id = OctetStringRef::decode(&mut inner).map_err(map_der)?;
    if class_id.as_bytes().len() != 16 {
        return Ok(None);
    }
    let serialized = OctetStringRef::decode(&mut inner).map_err(map_der)?;
    Ok(Some(serialized.as_bytes()))
}

fn concat_octets_from_set_of_type_and_optional_value(data: &[u8]) -> Result<Vec<u8>> {
    // Flat page-hash tables start with a little-endian offset (often `0x00`); never DER-decode those.
    if data.first().copied() != Some(u8::from(Tag::Set)) {
        return Ok(data.to_vec());
    }
    let mut r = SliceReader::new(data).map_err(|_| anyhow!("invalid DER slice"))?;
    let hdr = Header::decode(&mut r).map_err(map_der)?;
    if hdr.tag != Tag::Set {
        return Ok(data.to_vec());
    }
    let set_body = r.read_slice(hdr.length).map_err(map_der)?;
    let mut sr = SliceReader::new(set_body).map_err(|_| anyhow!("SET body slice"))?;
    let mut concat = Vec::new();
    while sr.remaining_len() != Length::ZERO {
        let seq_hdr = Header::decode(&mut sr).map_err(map_der)?;
        if seq_hdr.tag != Tag::Sequence {
            return Err(anyhow!("SET OF member is not SEQUENCE"));
        }
        let seq_body = sr.read_slice(seq_hdr.length).map_err(map_der)?;
        let mut qr = SliceReader::new(seq_body).map_err(|_| anyhow!("SEQUENCE body"))?;
        let _oid = ObjectIdentifier::decode(&mut qr).map_err(map_der)?;
        let oct = OctetStringRef::decode(&mut qr).map_err(map_der)?;
        concat.extend_from_slice(oct.as_bytes());
    }
    Ok(concat)
}

/// Peel OCTET STRING wrappers and **`SPC_SERIALIZED_OBJECT`** (`SEQUENCE { OCTET STRING classId, OCTET STRING data }`)
/// layers, then flatten an optional outer **`SET OF`** `{ OID, OCTET STRING }` wrapper used for page-hash payloads.
pub fn peel_authenticode_page_hash_attribute_payload(value_der: &[u8]) -> Result<Vec<u8>> {
    let mut cur = value_der.to_vec();
    for _ in 0..8 {
        if cur.is_empty() {
            return Err(anyhow!("empty page-hash attribute payload"));
        }
        match cur.first().copied() {
            Some(0x04) => {
                let mut rd =
                    SliceReader::new(cur.as_slice()).map_err(|_| anyhow!("OCTET STRING slice"))?;
                let oct = OctetStringRef::decode(&mut rd).map_err(map_der)?;
                cur = oct.as_bytes().to_vec();
            }
            Some(0x30) => {
                if let Some(inner) = try_spc_serialized_object_data(cur.as_slice())? {
                    cur = inner.to_vec();
                    continue;
                }
                break;
            }
            _ => break,
        }
    }
    concat_octets_from_set_of_type_and_optional_value(&cur)
}

/// Parse the flat **`offset_le ‖ digest`** repetition after [`peel_authenticode_page_hash_attribute_payload`].
///
/// Stops at the first **all-zero** digest (terminator row) or end of input. Fails on trailing non-padding bytes.
pub fn parse_page_hash_flat_pairs_le(
    data: &[u8],
    digest_len: usize,
) -> Result<Vec<PageHashTableEntry>> {
    if digest_len == 0 {
        return Err(anyhow!("digest_len must be non-zero"));
    }
    let mut i = 0usize;
    let mut out = Vec::new();
    while i + 4 + digest_len <= data.len() {
        let page_end = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let digest = data[i + 4..i + 4 + digest_len].to_vec();
        i += 4 + digest_len;
        if digest.iter().all(|&b| b == 0) {
            break;
        }
        out.push(PageHashTableEntry {
            page_end_offset: page_end,
            digest,
        });
    }
    if i < data.len() && !data[i..].iter().all(|&b| b == 0) {
        return Err(anyhow!(
            "trailing bytes after PE page-hash table (offset {})",
            i
        ));
    }
    Ok(out)
}

/// Full parse: peel wrappers then interpret flat pairs using digest width implied by [`PageHashAttrKind`].
pub fn parse_page_hash_attribute_entries(
    value_der: &[u8],
    kind: PageHashAttrKind,
) -> Result<Vec<PageHashTableEntry>> {
    let digest_len = digest_byte_len_for_page_hash_attr(kind);
    let flat = peel_authenticode_page_hash_attribute_payload(value_der)?;
    parse_page_hash_flat_pairs_le(&flat, digest_len)
}

/// Experimental portable check: **contiguous raw-file ranges** implied by the parsed page-hash table.
///
/// - Sorts rows by ascending [`PageHashTableEntry::page_end_offset`].
/// - For each row, hashes **`pe_image[start..end)`** where `end` is `page_end_offset` and `start` is the previous
///   row’s `end` (initial `start` is `0`).
/// - Uses **SHA-1** for [`PageHashAttrKind::V1`] and **SHA-256** for [`PageHashAttrKind::V2`].
///
/// **Limitation:** Windows `WinVerifyTrust` page hashing can **omit or split** regions around the PE checksum field,
/// security directory pointer, and certificate table. This helper hashes **literal file bytes** only — use it for
/// Rust SIP / fixture testing; compare to native `/ph` only after validating alignment on real signed binaries.
pub fn verify_page_hash_entries_contiguous_file_offsets(
    pe_image: &[u8],
    entries: &[PageHashTableEntry],
    kind: PageHashAttrKind,
) -> Result<()> {
    let expected_digest_len = digest_byte_len_for_page_hash_attr(kind);
    let mut sorted: Vec<&PageHashTableEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| e.page_end_offset);
    let mut start = 0usize;
    for e in sorted {
        if e.digest.len() != expected_digest_len {
            return Err(anyhow!(
                "page-hash digest length {} does not match {:?} expectation {}",
                e.digest.len(),
                kind,
                expected_digest_len
            ));
        }
        let end =
            usize::try_from(e.page_end_offset).map_err(|_| anyhow!("page_end_offset overflow"))?;
        if end > pe_image.len() {
            return Err(anyhow!(
                "page_end_offset {end} exceeds PE image length {}",
                pe_image.len()
            ));
        }
        if end <= start {
            return Err(anyhow!(
                "non-increasing or empty page-hash range (start={start} end={end})"
            ));
        }
        let slice = &pe_image[start..end];
        let computed = match kind {
            PageHashAttrKind::V1 => sha1::Sha1::digest(slice).to_vec(),
            PageHashAttrKind::V2 => sha2::Sha256::digest(slice).to_vec(),
        };
        if computed.as_slice() != e.digest.as_slice() {
            return Err(anyhow!(
                "page-hash digest mismatch for file range [{start},{end}) (kind {:?})",
                kind
            ));
        }
        start = end;
    }
    Ok(())
}

/// Parse every embedded page-hash attribute table and run [`verify_page_hash_entries_contiguous_file_offsets`].
///
/// Returns `Err` if no CMS page-hash attributes exist, if parsing fails, or if no non-empty table verifies.
pub fn verify_pe_embedded_page_hash_tables(pe_image: &[u8]) -> Result<()> {
    let locs = pe_collect_page_hash_auth_attributes(pe_image)?;
    if locs.is_empty() {
        return Err(anyhow!(
            "no CMS signed_attributes carrying SPC_PE_IMAGE_PAGE_HASHES in embedded PKCS#7"
        ));
    }
    let mut verified_table = false;
    for loc in &locs {
        for v in &loc.values {
            let entries = parse_page_hash_attribute_entries(&v.value_der, v.kind)?;
            if entries.is_empty() {
                continue;
            }
            verify_page_hash_entries_contiguous_file_offsets(pe_image, &entries, v.kind)
                .with_context(|| {
                    format!(
                        "pkcs7_index={} signer_index={} kind {:?}",
                        loc.pkcs7_index, loc.signer_index, v.kind
                    )
                })?;
            verified_table = true;
        }
    }
    if !verified_table {
        return Err(anyhow!(
            "PE page-hash attributes present but no non-empty parsable tables"
        ));
    }
    Ok(())
}

fn decode_signed_data(pkcs7_der: &[u8]) -> Result<SignedData> {
    let mut r = SliceReader::new(pkcs7_der).map_err(|_| anyhow!("PKCS#7 empty"))?;
    let ci = ContentInfo::decode(&mut r).map_err(|e| anyhow!("PKCS#7 ContentInfo: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(anyhow!(
            "PKCS#7 root content type is not SignedData (got {})",
            ci.content_type
        ));
    }
    ci.content
        .decode_as::<SignedData>()
        .map_err(|e| anyhow!("SignedData: {e}"))
}

fn page_hash_values_from_signed_data(sd: &SignedData) -> Vec<Vec<PageHashAttrValue>> {
    let mut per_signer = Vec::with_capacity(sd.signer_infos.0.len());
    for si in sd.signer_infos.0.iter() {
        let mut row = Vec::new();
        let Some(attrs) = si.signed_attrs.as_ref() else {
            per_signer.push(row);
            continue;
        };
        for attr in attrs.iter() {
            let kind = if attr.oid == OID_PE_PAGE_HASHES_V1 {
                Some(PageHashAttrKind::V1)
            } else if attr.oid == OID_PE_PAGE_HASHES_V2 {
                Some(PageHashAttrKind::V2)
            } else {
                None
            };
            let Some(k) = kind else {
                continue;
            };
            for val in attr.values.iter() {
                row.push(PageHashAttrValue {
                    kind: k,
                    value_der: val.value().to_vec(),
                });
            }
        }
        per_signer.push(row);
    }
    per_signer
}

/// Parse each embedded PKCS#7 and return non-empty page-hash attribute rows (CMS path only).
///
/// PKCS#7 blobs that fail `ContentInfo`/`SignedData` decoding are skipped (see also
/// [`pe_embedded_pkcs7_contains_page_hash_attribute`] which adds a raw-byte fallback).
pub fn pe_collect_page_hash_auth_attributes(bytes: &[u8]) -> Result<Vec<PePageHashAttrLocation>> {
    let parsed = ParsedPe::parse(bytes)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for (pkcs7_index, entry) in iter.enumerate() {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            continue;
        }
        let sd = match decode_signed_data(attr.data) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let rows = page_hash_values_from_signed_data(&sd);
        for (signer_index, values) in rows.into_iter().enumerate() {
            if values.is_empty() {
                continue;
            }
            out.push(PePageHashAttrLocation {
                pkcs7_index,
                signer_index,
                values,
            });
        }
    }
    Ok(out)
}

/// Microsoft `SPC_PE_IMAGE_PAGE_HASHES` **V1** (`1.3.6.1.4.1.311.2.3.1`) as DER `OBJECT IDENTIFIER`.
pub const SPC_PE_IMAGE_PAGE_HASHES_V1_OID_DER: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x01,
];

/// Microsoft `SPC_PE_IMAGE_PAGE_HASHES` **V2** (`1.3.6.1.4.1.311.2.3.2`) as DER `OBJECT IDENTIFIER`.
pub const SPC_PE_IMAGE_PAGE_HASHES_V2_OID_DER: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x02,
];

/// Return true if `pkcs7_der` contains a DER-encoded OID TLV matching V1 or V2 page-hash attributes.
///
/// This scans **raw bytes** (substring windows). It does not parse CMS structure; rare collisions are
/// theoretically possible inside ciphertext blobs but are unlikely for production PKCS#7 layouts.
pub fn pkcs7_signed_data_contains_page_hash_oid(pkcs7_der: &[u8]) -> bool {
    contains_oid_tlv(pkcs7_der, SPC_PE_IMAGE_PAGE_HASHES_V1_OID_DER)
        || contains_oid_tlv(pkcs7_der, SPC_PE_IMAGE_PAGE_HASHES_V2_OID_DER)
}

fn contains_oid_tlv(haystack: &[u8], oid_tlv: &[u8]) -> bool {
    haystack
        .windows(oid_tlv.len())
        .any(|window| window == oid_tlv)
}

/// Scan every embedded `WIN_CERT_TYPE_PKCS_SIGNED_DATA` attribute certificate in `bytes` (a PE image).
///
/// Returns `Ok(true)` when **either**:
/// - CMS parsing succeeds and any `SignerInfo` carries **`SPC_PE_IMAGE_PAGE_HASHES`** in **signed** attributes, or
/// - a raw-byte OID TLV window matches (covers PKCS#7 blobs that do not decode as top-level `SignedData`).
///
/// `Ok(false)` when there is no certificate table, no PKCS#7 entries, or no match. Fails on invalid PE /
/// certificate table errors consistent with [`crate::verify_pe`].
pub fn pe_embedded_pkcs7_contains_page_hash_attribute(bytes: &[u8]) -> Result<bool> {
    let parsed = ParsedPe::parse(bytes)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Ok(false);
    };

    for entry in iter {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            continue;
        }
        if let Ok(sd) = decode_signed_data(attr.data) {
            let rows = page_hash_values_from_signed_data(&sd);
            if rows.iter().any(|row| !row.is_empty()) {
                return Ok(true);
            }
        }
        if pkcs7_signed_data_contains_page_hash_oid(attr.data) {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use der::asn1::ObjectIdentifier;

    fn tlv_octet(inner: &[u8]) -> Vec<u8> {
        assert!(inner.len() < 128);
        let mut v = vec![0x04, inner.len() as u8];
        v.extend_from_slice(inner);
        v
    }

    fn tlv_sequence(children: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = children.iter().flatten().cloned().collect();
        assert!(body.len() < 128);
        let mut v = vec![0x30, body.len() as u8];
        v.extend_from_slice(&body);
        v
    }

    fn tlv_set(children: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = children.iter().flatten().cloned().collect();
        assert!(body.len() < 128);
        let mut v = vec![0x31, body.len() as u8];
        v.extend_from_slice(&body);
        v
    }

    #[test]
    fn page_hash_oid_tlv_matches_asn1_der_for_known_strings() {
        for (oid_str, expected_tlv) in [
            ("1.3.6.1.4.1.311.2.3.1", SPC_PE_IMAGE_PAGE_HASHES_V1_OID_DER),
            ("1.3.6.1.4.1.311.2.3.2", SPC_PE_IMAGE_PAGE_HASHES_V2_OID_DER),
        ] {
            let oid = ObjectIdentifier::new_unwrap(oid_str);
            let encoded = oid.to_der().expect("OID DER encode");
            assert_eq!(
                encoded.as_slice(),
                expected_tlv,
                "OID TLV mismatch for {oid_str}"
            );
        }
    }

    #[test]
    fn detects_v2_oid_in_buffer() {
        let mut buf = vec![0x30u8, 0x82, 0x01, 0x00];
        buf.extend_from_slice(SPC_PE_IMAGE_PAGE_HASHES_V2_OID_DER);
        assert!(pkcs7_signed_data_contains_page_hash_oid(&buf));
    }

    #[test]
    fn upstream_tiny_fixtures_have_no_page_hash_oid() {
        let pe32 =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pe64 =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        assert!(!pe_embedded_pkcs7_contains_page_hash_attribute(pe32).unwrap());
        assert!(!pe_embedded_pkcs7_contains_page_hash_attribute(pe64).unwrap());
        assert!(
            pe_collect_page_hash_auth_attributes(pe32)
                .unwrap()
                .is_empty()
        );
        assert!(
            pe_collect_page_hash_auth_attributes(pe64)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn parse_flat_page_hash_v2_stops_at_zero_digest() {
        let mut flat = Vec::new();
        flat.extend_from_slice(&0x1000u32.to_le_bytes());
        flat.extend_from_slice(&[0xabu8; 32]);
        flat.extend_from_slice(&0x2000u32.to_le_bytes());
        flat.extend_from_slice(&[0u8; 32]);
        let rows = parse_page_hash_flat_pairs_le(&flat, 32).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].page_end_offset, 0x1000);
        assert_eq!(rows[0].digest, vec![0xabu8; 32]);
    }

    #[test]
    fn parse_page_hash_attribute_through_serialized_object_wrapped_octet() {
        let mut flat = Vec::new();
        flat.extend_from_slice(&0x400u32.to_le_bytes());
        flat.extend_from_slice(&[0x11u8; 20]);
        flat.extend_from_slice(&0x800u32.to_le_bytes());
        flat.extend_from_slice(&[0u8; 20]);
        let guid = [7u8; 16];
        let seq = tlv_sequence(&[tlv_octet(&guid), tlv_octet(&flat)]);
        let value = tlv_octet(&seq);
        let entries = parse_page_hash_attribute_entries(&value, PageHashAttrKind::V1).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].page_end_offset, 0x400);
        assert_eq!(entries[0].digest, vec![0x11u8; 20]);
    }

    #[test]
    fn parse_page_hash_attribute_through_set_of_type_and_optional_value() {
        let mut flat = Vec::new();
        flat.extend_from_slice(&0x50u32.to_le_bytes());
        flat.extend_from_slice(&[0x22u8; 32]);
        flat.extend_from_slice(&0x60u32.to_le_bytes());
        flat.extend_from_slice(&[0u8; 32]);
        let oid_tlv = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1")
            .to_der()
            .unwrap();
        let seq_member = tlv_sequence(&[oid_tlv, tlv_octet(&flat)]);
        let set_wrapped = tlv_set(&[seq_member]);
        let entries =
            parse_page_hash_attribute_entries(&set_wrapped, PageHashAttrKind::V2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].page_end_offset, 0x50);
        assert_eq!(entries[0].digest, vec![0x22u8; 32]);
    }

    #[test]
    fn contiguous_verify_matches_sha256_ranges() {
        let pe = vec![0u8; 64];
        let d1 = sha2::Sha256::digest(&pe[0..32]);
        let d2 = sha2::Sha256::digest(&pe[32..64]);
        let entries = vec![
            PageHashTableEntry {
                page_end_offset: 32,
                digest: d1.as_slice().to_vec(),
            },
            PageHashTableEntry {
                page_end_offset: 64,
                digest: d2.as_slice().to_vec(),
            },
        ];
        verify_page_hash_entries_contiguous_file_offsets(&pe, &entries, PageHashAttrKind::V2)
            .unwrap();
    }

    #[test]
    fn contiguous_verify_rejects_wrong_digest() {
        let pe = vec![1u8; 16];
        let entries = vec![PageHashTableEntry {
            page_end_offset: 16,
            digest: vec![0u8; 32],
        }];
        assert!(
            verify_page_hash_entries_contiguous_file_offsets(&pe, &entries, PageHashAttrKind::V2)
                .is_err()
        );
    }

    #[test]
    fn verify_embedded_tables_errors_when_fixture_has_no_page_hash_attrs() {
        let pe32 =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert!(verify_pe_embedded_page_hash_tables(pe32).is_err());
    }

    /// Regression anchor for the **`/ph`** parity milestone: when adding a signed PE **with** page-hash attrs,
    /// extend this test (or add a sibling) to run [`verify_pe_embedded_page_hash_tables`] on that fixture.
    #[test]
    fn upstream_ph_fixture_gap_is_tracked_here() {
        let pe32 =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert!(
            pe_collect_page_hash_auth_attributes(pe32)
                .unwrap()
                .is_empty(),
            "tiny32 fixture intentionally lacks page-hash attrs; swap corpus when `/ph` regression lands"
        );
    }
}
