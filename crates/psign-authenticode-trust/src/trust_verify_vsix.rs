//! VSIX (OPC XML digital signature) trust verification.
//!
//! Verifies the package signature the way Visual Studio / `System.IO.Packaging` and dotnet/sign
//! produce it:
//!
//! 1. Exactly one XML signature part (`/package/services/digital-signature/xml-signature/*`).
//! 2. `SignedInfo` is canonicalized (C14N 1.0 or exclusive C14N) and its `SignatureValue` is an
//!    RSA PKCS#1 v1.5 signature (SHA-256/384/512) by a certificate from `KeyInfo`.
//! 3. Every `SignedInfo` reference (`#id` same-document objects) and every `Manifest` reference
//!    (package parts, optionally with C14N / OPC RelationshipTransform) digest matches.
//! 4. The `Manifest` is inside an `Object` covered by `SignedInfo`; every package part except
//!    `[Content_Types].xml` and the signature part is referenced, and each reference's
//!    `ContentType` matches `[Content_Types].xml`.
//! 5. Trust: the signer chain ends at the configured anchors (or the Artifact Signing policy), at
//!    the RFC 3161 time from `<Object><TimeStamp><EncodedTime>` when present (imprint over the
//!    `SignatureValue` octets).

use crate::anchor::parse_cert_bytes;
use crate::artifact_signing::verify_artifact_signing_certificate;
use crate::chain::verify_certificate_chain_to_anchors;
use crate::rfc3161_extract::trusted_utc_date_from_timestamp_token;
use crate::trust_pkcs7::x509_cert_has_code_signing_eku;
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for};
use crate::xml_c14n::{C14nMode, Element, canonicalize, parse_document};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use der::{Decode, Encode};
use picky::x509::certificate::Cert;
use picky::x509::date::UtcDate;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use x509_cert::Certificate;

const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const OPC_DSIG: &str = "http://schemas.openxmlformats.org/package/2006/digital-signature";
const OPC_RELS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const OPC_CONTENT_TYPES: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const RELATIONSHIP_TRANSFORM: &str =
    "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
const SIGNATURE_PART_PREFIX: &str = "package/services/digital-signature/xml-signature/";
const CONTENT_TYPES_PART: &str = "[Content_Types].xml";

#[derive(Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_digest_uri(uri: &str) -> Result<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(Self::Sha384),
            "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(Self::Sha512),
            other => Err(anyhow!("unsupported XMLDSig DigestMethod {other}")),
        }
    }

    fn from_signature_uri(uri: &str) -> Result<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Ok(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Ok(Self::Sha384),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Ok(Self::Sha512),
            other => Err(anyhow!("unsupported XMLDSig SignatureMethod {other}")),
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    fn verify_rsa(self, cert: &Certificate, data: &[u8], signature: &[u8]) -> Result<()> {
        let spki = cert
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| anyhow!("encode SubjectPublicKeyInfo: {e}"))?;
        let key = rsa::RsaPublicKey::from_public_key_der(&spki)
            .map_err(|e| anyhow!("signer public key is not RSA: {e}"))?;
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| anyhow!("SignatureValue octets: {e}"))?;
        let result = match self {
            Self::Sha256 => {
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key).verify(data, &signature)
            }
            Self::Sha384 => {
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key).verify(data, &signature)
            }
            Self::Sha512 => {
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key).verify(data, &signature)
            }
        };
        result.map_err(|e| anyhow!("SignatureValue verification: {e}"))
    }
}

fn decode_base64(text: &str, what: &str) -> Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .with_context(|| format!("{what} is not valid base64"))
}

fn algorithm<'a>(e: &'a Element, child: &str) -> Result<&'a str> {
    e.child(DSIG, child)
        .and_then(|c| c.attr("Algorithm"))
        .ok_or_else(|| anyhow!("XMLDSig {} is missing {child}", e.local_name()))
}

/// Percent-decoded, slash-trimmed OPC part name for ZIP lookup and comparison (case-insensitive).
fn part_key(name: &str) -> String {
    let bytes = name.trim_start_matches('/').as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_ascii_lowercase()
}

struct Package {
    parts: BTreeMap<String, Vec<u8>>,
    /// Part key → content type from `[Content_Types].xml`.
    content_types: BTreeMap<String, String>,
    signature_part: String,
}

fn read_package(data: &[u8]) -> Result<Package> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).context("open VSIX ZIP")?;
    let mut parts = BTreeMap::new();
    let mut raw_content_types = None;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("read VSIX ZIP entry")?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        let mut bytes = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut bytes)
            .with_context(|| format!("read VSIX part {name}"))?;
        if name == CONTENT_TYPES_PART {
            raw_content_types = Some(bytes);
            continue;
        }
        if parts.insert(part_key(&name), bytes).is_some() {
            return Err(anyhow!("VSIX contains duplicate part name {name}"));
        }
    }

    let mut signatures = parts
        .keys()
        .filter(|k| k.starts_with(SIGNATURE_PART_PREFIX))
        .cloned();
    let signature_part = signatures
        .next()
        .ok_or_else(|| anyhow!("VSIX package has no OPC XML signature part"))?;
    if signatures.next().is_some() {
        return Err(anyhow!(
            "VSIX package has more than one OPC XML signature part"
        ));
    }

    let ct_doc = parse_document(
        &raw_content_types.ok_or_else(|| anyhow!("VSIX package has no [Content_Types].xml"))?,
    )
    .context("[Content_Types].xml")?;
    let mut defaults = BTreeMap::new();
    let mut overrides = BTreeMap::new();
    for e in ct_doc.child_elements() {
        match (e.namespace(), e.local_name()) {
            (OPC_CONTENT_TYPES, "Default") => {
                if let (Some(ext), Some(ct)) = (e.attr("Extension"), e.attr("ContentType")) {
                    defaults.insert(ext.to_ascii_lowercase(), ct.to_string());
                }
            }
            (OPC_CONTENT_TYPES, "Override") => {
                if let (Some(p), Some(ct)) = (e.attr("PartName"), e.attr("ContentType")) {
                    overrides.insert(part_key(p), ct.to_string());
                }
            }
            _ => {}
        }
    }
    let content_types = parts
        .keys()
        .filter_map(|k| {
            let ct = overrides.get(k).cloned().or_else(|| {
                let ext = k.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
                defaults.get(ext).cloned()
            })?;
            Some((k.clone(), ct))
        })
        .collect();

    Ok(Package {
        parts,
        content_types,
        signature_part,
    })
}

/// OPC RelationshipTransform (ECMA-376 Part 2): keep the selected relationships sorted by `Id`,
/// with `TargetMode` defaulted, as a new `Relationships` element (then canonicalized).
fn relationship_transform(transform: &Element, rels_xml: &[u8]) -> Result<Element> {
    let source_ids: BTreeSet<&str> = transform
        .children_named(OPC_DSIG, "RelationshipReference")
        .filter_map(|e| e.attr("SourceId"))
        .collect();
    let source_types: BTreeSet<&str> = transform
        .children_named(OPC_DSIG, "RelationshipsGroupReference")
        .filter_map(|e| e.attr("SourceType"))
        .collect();
    let rels = parse_document(rels_xml).context("relationships part")?;
    if !rels.is(OPC_RELS, "Relationships") {
        return Err(anyhow!(
            "RelationshipTransform input is not a Relationships part"
        ));
    }
    let mut selected: Vec<Element> = rels
        .children_named(OPC_RELS, "Relationship")
        .filter(|r| {
            r.attr("Id").is_some_and(|id| source_ids.contains(id))
                || r.attr("Type").is_some_and(|t| source_types.contains(t))
        })
        .map(|r| {
            let mut attrs = Vec::new();
            for name in ["Id", "Target", "TargetMode", "Type"] {
                match r.attr(name) {
                    Some(v) => attrs.push((name.to_string(), v.to_string())),
                    None if name == "TargetMode" => {
                        attrs.push((name.to_string(), "Internal".to_string()))
                    }
                    None => {}
                }
            }
            Element {
                qname: "Relationship".to_string(),
                attrs,
                children: Vec::new(),
                scope: rels.scope.clone(),
            }
        })
        .collect();
    selected.sort_by(|a, b| a.attr("Id").cmp(&b.attr("Id")));
    Ok(Element {
        qname: "Relationships".to_string(),
        attrs: vec![("xmlns".to_string(), OPC_RELS.to_string())],
        children: selected
            .into_iter()
            .map(crate::xml_c14n::Node::Element)
            .collect(),
        scope: [(String::new(), OPC_RELS.to_string())]
            .into_iter()
            .collect(),
    })
}

/// Octets a package-part reference digests, after its transforms.
fn part_reference_octets(reference: &Element, part: &[u8]) -> Result<Vec<u8>> {
    let Some(transforms) = reference.child(DSIG, "Transforms") else {
        return Ok(part.to_vec());
    };
    let mut current: Option<Element> = None;
    let mut octets = part.to_vec();
    for transform in transforms.children_named(DSIG, "Transform") {
        let uri = transform.attr("Algorithm").unwrap_or_default();
        if uri == RELATIONSHIP_TRANSFORM {
            current = Some(relationship_transform(transform, &octets)?);
        } else if let Some(mode) = C14nMode::from_uri(uri) {
            let element = match current.take() {
                Some(e) => e,
                None => parse_document(&octets)?,
            };
            octets = canonicalize(&element, mode);
        } else {
            return Err(anyhow!("unsupported XMLDSig part transform {uri}"));
        }
    }
    if let Some(element) = current {
        octets = canonicalize(&element, C14nMode::Inclusive);
    }
    Ok(octets)
}

/// Octets a same-document (`#id`) reference digests.
fn object_reference_octets(reference: &Element, target: &Element) -> Result<Vec<u8>> {
    let mut mode = C14nMode::Inclusive;
    if let Some(transforms) = reference.child(DSIG, "Transforms") {
        for transform in transforms.children_named(DSIG, "Transform") {
            let uri = transform.attr("Algorithm").unwrap_or_default();
            mode = C14nMode::from_uri(uri)
                .ok_or_else(|| anyhow!("unsupported XMLDSig object transform {uri}"))?;
        }
    }
    Ok(canonicalize(target, mode))
}

fn check_digest(reference: &Element, octets: &[u8], what: &str) -> Result<()> {
    let hash = Hash::from_digest_uri(algorithm(reference, "DigestMethod")?)?;
    let expected = decode_base64(
        &reference
            .child(DSIG, "DigestValue")
            .ok_or_else(|| anyhow!("XMLDSig reference {what} has no DigestValue"))?
            .text(),
        "DigestValue",
    )?;
    if hash.digest(octets) != expected {
        return Err(anyhow!("VSIX signature digest mismatch for {what}"));
    }
    Ok(())
}

/// Verified signature material handed to the trust step.
struct VerifiedXmlSignature {
    signer: Certificate,
    certificates: Vec<Cert>,
    signature_value: Vec<u8>,
    timestamp_token: Option<Vec<u8>>,
    reference_count: usize,
}

fn verify_xml_signature(package: &Package) -> Result<VerifiedXmlSignature> {
    let doc =
        parse_document(&package.parts[&package.signature_part]).context("VSIX signature XML")?;
    if !doc.is(DSIG, "Signature") {
        return Err(anyhow!("VSIX signature part is not an XMLDSig Signature"));
    }
    let signed_info = doc
        .child(DSIG, "SignedInfo")
        .ok_or_else(|| anyhow!("XMLDSig Signature has no SignedInfo"))?;
    let c14n_uri = algorithm(signed_info, "CanonicalizationMethod")?;
    let c14n = C14nMode::from_uri(c14n_uri)
        .ok_or_else(|| anyhow!("unsupported XMLDSig CanonicalizationMethod {c14n_uri}"))?;
    let sig_hash = Hash::from_signature_uri(algorithm(signed_info, "SignatureMethod")?)?;
    let signature_value = decode_base64(
        &doc.child(DSIG, "SignatureValue")
            .ok_or_else(|| anyhow!("XMLDSig Signature has no SignatureValue"))?
            .text(),
        "SignatureValue",
    )?;

    // KeyInfo certificates; the signer is the one whose key verifies SignedInfo.
    let mut x509 = Vec::new();
    if let Some(key_info) = doc.child(DSIG, "KeyInfo") {
        for data in key_info.children_named(DSIG, "X509Data") {
            for cert in data.children_named(DSIG, "X509Certificate") {
                x509.push(decode_base64(&cert.text(), "X509Certificate")?);
            }
        }
    }
    let canonical_signed_info = canonicalize(signed_info, c14n);
    let signer = x509
        .iter()
        .filter_map(|der| Certificate::from_der(der).ok())
        .find(|cert| {
            sig_hash
                .verify_rsa(cert, &canonical_signed_info, &signature_value)
                .is_ok()
        })
        .ok_or_else(|| {
            anyhow!("VSIX SignatureValue does not verify with any KeyInfo X509Certificate")
        })?;
    let certificates = x509
        .iter()
        .map(|der| parse_cert_bytes(der))
        .collect::<Result<Vec<_>>>()?;

    // SignedInfo references: same-document objects.
    let mut covered_objects: Vec<&Element> = Vec::new();
    for reference in signed_info.children_named(DSIG, "Reference") {
        let uri = reference.attr("URI").unwrap_or_default();
        let id = uri
            .strip_prefix('#')
            .ok_or_else(|| anyhow!("unsupported SignedInfo reference URI {uri:?}"))?;
        let mut targets = Vec::new();
        doc.find_all(&|e| e.attr("Id") == Some(id), &mut targets);
        let [target] = targets[..] else {
            return Err(anyhow!(
                "SignedInfo reference #{id} must match exactly one element"
            ));
        };
        check_digest(reference, &object_reference_octets(reference, target)?, uri)?;
        covered_objects.push(target);
    }

    // The package manifest must sit inside a covered object.
    let mut manifests = Vec::new();
    for object in &covered_objects {
        object.find_all(&|e| e.is(DSIG, "Manifest"), &mut manifests);
    }
    if manifests.is_empty() {
        return Err(anyhow!("VSIX signature does not sign a package Manifest"));
    }
    let mut referenced = BTreeSet::new();
    for manifest in manifests {
        for reference in manifest.children_named(DSIG, "Reference") {
            let uri = reference.attr("URI").unwrap_or_default();
            let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
            if !path.starts_with('/') {
                return Err(anyhow!("unsupported Manifest reference URI {uri:?}"));
            }
            let key = part_key(path);
            let part = package
                .parts
                .get(&key)
                .ok_or_else(|| anyhow!("VSIX signature references missing part {path}"))?;
            if let Some(ct) = query.strip_prefix("ContentType=")
                && package.content_types.get(&key).map(String::as_str) != Some(ct)
            {
                return Err(anyhow!(
                    "VSIX part {path} content type differs from the signed {ct}"
                ));
            }
            check_digest(reference, &part_reference_octets(reference, part)?, path)?;
            referenced.insert(key);
        }
    }
    if let Some(unsigned) = package
        .parts
        .keys()
        .find(|k| **k != package.signature_part && !referenced.contains(*k))
    {
        return Err(anyhow!(
            "VSIX part /{unsigned} is not covered by the signature"
        ));
    }

    let mut stamps = Vec::new();
    doc.find_all(&|e| e.is(OPC_DSIG, "EncodedTime"), &mut stamps);
    let timestamp_token = match stamps[..] {
        [] => None,
        [stamp] => Some(decode_base64(&stamp.text(), "EncodedTime")?),
        _ => return Err(anyhow!("VSIX signature has more than one timestamp")),
    };

    Ok(VerifiedXmlSignature {
        signer,
        certificates,
        signature_value,
        timestamp_token,
        reference_count: referenced.len(),
    })
}

/// A VSIX signature whose XMLDSig structure, part digests, and `SignatureValue` verified.
#[derive(Debug, Clone)]
pub struct VsixSignature {
    /// DER of the `KeyInfo` certificate whose key produced the `SignatureValue`.
    pub signer_certificate_der: Vec<u8>,
    /// RFC 3161 token from `<TimeStamp><EncodedTime>` (not yet trust-verified).
    pub timestamp_token: Option<Vec<u8>>,
    /// Number of package parts covered by the signed manifest.
    pub reference_count: usize,
}

/// Verify the VSIX signature binding (steps 1-4 of the module docs) without any trust decision.
pub fn verify_vsix_signature_bytes(data: &[u8]) -> Result<VsixSignature> {
    let sig = verify_xml_signature(&read_package(data)?)?;
    Ok(VsixSignature {
        signer_certificate_der: sig
            .signer
            .to_der()
            .map_err(|e| anyhow!("encode signer certificate: {e}"))?,
        timestamp_token: sig.timestamp_token,
        reference_count: sig.reference_count,
    })
}

/// Trust-verify a signed VSIX package; see the module documentation for the checks.
pub fn trust_verify_vsix_bytes(
    data: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let package = read_package(data)?;
    let sig = verify_xml_signature(&package)?;
    let mut report = TrustVerifyPeReport::new(&anchors);

    if let Some(policy) = &opts.artifact_signing {
        report
            .artifact_signing
            .push(verify_artifact_signing_certificate(
                &sig.signer,
                sig.certificates,
                sig.timestamp_token
                    .as_deref()
                    .map(|t| (t, sig.signature_value.as_slice())),
                0,
                policy,
                opts,
            )?);
    } else {
        if opts.policy.strict_code_signing_eku && !x509_cert_has_code_signing_eku(&sig.signer)? {
            return Err(anyhow!(
                "VSIX signer certificate lacks the code signing EKU"
            ));
        }
        let instant = match &opts.verification_instant_override {
            Some(instant) => instant.clone(),
            None if opts.policy.prefer_timestamp_signing_time => match &sig.timestamp_token {
                Some(token) => trusted_utc_date_from_timestamp_token(
                    token,
                    &sig.signature_value,
                    &anchors,
                    &anchor_certs,
                    &opts.online,
                    opts.verbose_chain,
                )
                .context("VSIX timestamp")?,
                None if opts.policy.require_valid_timestamp => {
                    return Err(anyhow!("VSIX signature has no RFC 3161 timestamp"));
                }
                None => UtcDate::now(),
            },
            None => UtcDate::now(),
        };
        let leaf_der = sig
            .signer
            .to_der()
            .map_err(|e| anyhow!("encode signer certificate: {e}"))?;
        let leaf = parse_cert_bytes(&leaf_der)?;
        verify_certificate_chain_to_anchors(
            &leaf,
            sig.certificates,
            &anchors,
            &anchor_certs,
            &opts.online,
            &instant,
            opts.verbose_chain,
        )?;
    }
    report.pkcs7_entries_verified = 1;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_keys_are_decoded_and_case_insensitive() {
        assert_eq!(part_key("/_rels/.rels"), "_rels/.rels");
        assert_eq!(part_key("/A%20b.TXT"), "a b.txt");
    }

    #[test]
    fn relationship_transform_selects_and_sorts() {
        let transform = parse_document(
            br#"<Transform xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:m="http://schemas.openxmlformats.org/package/2006/digital-signature"><m:RelationshipReference SourceId="R2"/><m:RelationshipReference SourceId="R1"/></Transform>"#,
        )
        .unwrap();
        let rels = br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Type="t2" Target="/b" Id="R2"/><Relationship Type="t3" Target="/c" Id="R3"/><Relationship Type="t1" Target="http://x" TargetMode="External" Id="R1"/></Relationships>"#;
        let out = canonicalize(
            &relationship_transform(&transform, rels).unwrap(),
            C14nMode::Inclusive,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            concat!(
                r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
                r#"<Relationship Id="R1" Target="http://x" TargetMode="External" Type="t1"></Relationship>"#,
                r#"<Relationship Id="R2" Target="/b" TargetMode="Internal" Type="t2"></Relationship>"#,
                "</Relationships>"
            )
        );
    }
}
