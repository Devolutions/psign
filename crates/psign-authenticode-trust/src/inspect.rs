//! Portable Authenticode PKCS#7 **inspection** (nested signatures, timestamp OIDs).
//!
//! Walks nested PKCS#7 blobs under OID **`1.3.6.1.4.1.311.2.4.1`** (Microsoft nested signature),
//! similar to PowerShell OpenAuthenticode [`SignatureHelper.GetFileSignature`](https://github.com/jborean93/PowerShell-OpenAuthenticode/blob/main/src/OpenAuthenticode/SignatureHelper.cs).

use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::asn1::ObjectIdentifier;
use der::{Decode, SliceReader};
use psign_sip_digest::pkcs7_wire::normalize_pkcs7_der_for_authenticode;
use psign_sip_digest::verify_pe::for_each_pe_pkcs7_signed_data;
use serde::Serialize;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// Microsoft **nested signature** attribute (`NestedSignature`).
const OID_MS_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");
/// PKCS#9 **`signing-time`** (legacy Authenticode timestamp hint).
const OID_PKCS9_SIGNING_TIME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// **`id-aa-timeStampToken`** (RFC 5035).
const OID_ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// Microsoft nested Authenticode RFC3161-style timestamp attribute.
const OID_MS_TIMESTAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

const DEFAULT_MAX_NEST_DEPTH: usize = 16;

/// One PKCS#7 `SignedData` layer (outer or nested).
#[derive(Debug, Clone, Serialize)]
pub struct InspectPkcs7Report {
    pub content_type_oid: String,
    pub encap_content_type_oid: Option<String>,
    pub certificate_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticode_digest: Option<InspectAuthenticodeDigest>,
    pub signers: Vec<InspectSigner>,
    /// PKCS#7 blobs found under OID `1.3.6.1.4.1.311.2.4.1` (Microsoft nested signature).
    pub nested_signatures: Vec<InspectPkcs7Report>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectAuthenticodeDigest {
    pub digest_algorithm_oid: String,
    /// Lowercase hex of embedded Authenticode message digest (full length).
    pub digest_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectSigner {
    pub signer_index: usize,
    pub digest_algorithm_oid: String,
    pub signed_attribute_oids: Vec<String>,
    pub unsigned_attribute_oids: Vec<String>,
    pub timestamp_hints: Vec<TimestampHint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimestampHint {
    pub kind: &'static str,
    pub attribute_oid: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectPeEntry {
    pub attribute_certificate_index: usize,
    pub pkcs7: InspectPkcs7Report,
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectPeFileReport {
    pub entries: Vec<InspectPeEntry>,
}

/// Inspect a single PKCS#7 blob (embedded or detached), including nested signatures.
pub fn inspect_authenticode_pkcs7_der(pkcs7_der: &[u8]) -> Result<InspectPkcs7Report> {
    inspect_pkcs7_recursive(pkcs7_der, 0, DEFAULT_MAX_NEST_DEPTH)
}

/// Inspect every **WIN_CERT_TYPE_PKCS_SIGNED_DATA** attribute certificate on a PE image.
pub fn inspect_pe_authenticode(pe_bytes: &[u8]) -> Result<InspectPeFileReport> {
    let mut entries = Vec::new();
    for_each_pe_pkcs7_signed_data(pe_bytes, |idx, der| {
        let pkcs7 = inspect_pkcs7_recursive(der, 0, DEFAULT_MAX_NEST_DEPTH)?;
        entries.push(InspectPeEntry {
            attribute_certificate_index: idx,
            pkcs7,
        });
        Ok(())
    })?;
    Ok(InspectPeFileReport { entries })
}

fn inspect_pkcs7_recursive(
    pkcs7_der: &[u8],
    depth: usize,
    max_depth: usize,
) -> Result<InspectPkcs7Report> {
    if depth > max_depth {
        return Err(anyhow!(
            "nested PKCS#7 depth exceeds limit ({max_depth}); possible corrupt or cyclic structure"
        ));
    }
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let slice = normalized.as_ref();
    let sd = decode_signed_data(slice).map_err(|e| anyhow!("decode SignedData: {e}"))?;

    let authenticode_digest = AuthenticodeSignature::from_bytes(slice).ok().map(|sig| {
        let digest = sig.digest();
        let digest_algorithm_oid = match digest.len() {
            20 => "1.3.14.3.2.26".to_string(),
            32 => "2.16.840.1.101.3.4.2.1".to_string(),
            48 => "2.16.840.1.101.3.4.2.2".to_string(),
            64 => "2.16.840.1.101.3.4.2.3".to_string(),
            n => format!("unknown_digest_length_{n}_bytes"),
        };
        InspectAuthenticodeDigest {
            digest_algorithm_oid,
            digest_hex: digest.iter().map(|b| format!("{b:02x}")).collect(),
        }
    });

    inspect_signed_data(&sd, authenticode_digest, depth, max_depth)
}

fn decode_signed_data(pkcs7_der: &[u8]) -> Result<SignedData> {
    let mut r = SliceReader::new(pkcs7_der).map_err(|_| anyhow!("empty PKCS#7"))?;
    let ci = ContentInfo::decode(&mut r).map_err(|e| anyhow!("ContentInfo: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(anyhow!(
            "expected SignedData ContentInfo, got OID {}",
            ci.content_type
        ));
    }
    ci.content
        .decode_as::<SignedData>()
        .map_err(|e| anyhow!("SignedData: {e}"))
}

fn inspect_signed_data(
    sd: &SignedData,
    authenticode_digest: Option<InspectAuthenticodeDigest>,
    depth: usize,
    max_depth: usize,
) -> Result<InspectPkcs7Report> {
    let encap_content_type_oid = Some(sd.encap_content_info.econtent_type.to_string());
    let certificate_count = sd.certificates.as_ref().map(|set| set.0.len()).unwrap_or(0);

    let mut signers = Vec::new();
    let mut nested_signatures = Vec::new();

    for (signer_index, si) in sd.signer_infos.0.iter().enumerate() {
        signers.push(inspect_signer(signer_index, si));

        let Some(attrs) = si.unsigned_attrs.as_ref() else {
            continue;
        };
        for attr in attrs.iter() {
            if attr.oid != OID_MS_NESTED_SIGNATURE {
                continue;
            }
            for val in attr.values.iter() {
                let payload = val.value();
                match decode_nested_pkcs7_payload(payload) {
                    Ok(der) => {
                        if let Ok(rep) = inspect_pkcs7_recursive(&der, depth + 1, max_depth) {
                            nested_signatures.push(rep);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    Ok(InspectPkcs7Report {
        content_type_oid: ID_SIGNED_DATA.to_string(),
        encap_content_type_oid,
        certificate_count,
        authenticode_digest,
        signers,
        nested_signatures,
    })
}

fn decode_nested_pkcs7_payload(payload: &[u8]) -> Result<Vec<u8>> {
    if decode_signed_data(payload).is_ok() {
        return Ok(payload.to_vec());
    }
    if let Some(inner) = peel_octet_string_outer(payload)
        && decode_signed_data(inner).is_ok()
    {
        return Ok(inner.to_vec());
    }
    Err(anyhow!(
        "nested payload is not a decodable SignedData ContentInfo"
    ))
}

fn peel_octet_string_outer(bytes: &[u8]) -> Option<&[u8]> {
    let mut r = SliceReader::new(bytes).ok()?;
    let o = der::asn1::OctetStringRef::decode(&mut r).ok()?;
    Some(o.as_bytes())
}

fn inspect_signer(signer_index: usize, si: &SignerInfo) -> InspectSigner {
    let digest_algorithm_oid = si.digest_alg.oid.to_string();
    let signed_attribute_oids = si
        .signed_attrs
        .as_ref()
        .map(|a| a.iter().map(|attr| attr.oid.to_string()).collect())
        .unwrap_or_default();
    let unsigned_attribute_oids = si
        .unsigned_attrs
        .as_ref()
        .map(|a| a.iter().map(|attr| attr.oid.to_string()).collect())
        .unwrap_or_default();

    let mut timestamp_hints = Vec::new();
    if let Some(attrs) = si.signed_attrs.as_ref() {
        for attr in attrs.iter() {
            if attr.oid == OID_PKCS9_SIGNING_TIME {
                timestamp_hints.push(TimestampHint {
                    kind: "pkcs9_signing_time",
                    attribute_oid: attr.oid.to_string(),
                });
            }
        }
    }
    if let Some(attrs) = si.unsigned_attrs.as_ref() {
        for attr in attrs.iter() {
            if attr.oid == OID_ID_AA_TIME_STAMP_TOKEN {
                timestamp_hints.push(TimestampHint {
                    kind: "id_aa_time_stamp_token",
                    attribute_oid: attr.oid.to_string(),
                });
            } else if attr.oid == OID_MS_TIMESTAMP_TOKEN {
                timestamp_hints.push(TimestampHint {
                    kind: "microsoft_nested_rfc3161_attribute",
                    attribute_oid: attr.oid.to_string(),
                });
            }
        }
    }

    InspectSigner {
        signer_index,
        digest_algorithm_oid,
        signed_attribute_oids,
        unsigned_attribute_oids,
        timestamp_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn inspect_upstream_signed_pe_has_outer_pkcs7_signers() {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        let bytes = std::fs::read(&p).expect("fixture read");
        let r = inspect_pe_authenticode(&bytes).expect("inspect");
        assert!(!r.entries.is_empty());
        assert!(!r.entries[0].pkcs7.signers.is_empty());
    }
}
