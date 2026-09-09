//! Shared PKCS#7 Authenticode trust step (digest already known).

use crate::anchor::{AnchorStore, cert_sha1_thumbprint};
use crate::chain::{
    issuer_chain_excluding_leaf_online, merge_unique_certs, terminal_root_cert_owned,
};
use crate::policy::{AuthenticodeTrustPolicy, OnlineTrustOptions};
use anyhow::{Result, anyhow};
use cms::cert::CertificateChoices;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode, Header, Reader, SliceReader, Tag};
use picky::x509::certificate::Cert;
use picky::x509::date::UtcDate;
use picky::x509::pkcs7::authenticode::AuthenticodeSignature;
use psign_sip_digest::pkcs7::{
    parse_pkcs7_signed_data_der, signed_data_certificate_for_signer_identifier,
    verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature,
    verify_signed_data_pkcs9_message_digest_and_rsa_sha256_pkcs1v15_signature,
};
use psign_sip_digest::pkcs7_wire::normalize_pkcs7_der_for_authenticode;
use x509_cert::Certificate;

const EKU_EXTENSION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// **`id-kp-codeSigning`** (RFC 5280).
const CODE_SIGNING_EKU_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Validate canonical base-128 subidentifiers without imposing a fixed integer width on each arc.
fn oid_value_is_well_formed(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }

    let mut starts_subidentifier = true;
    for &byte in value {
        if starts_subidentifier && byte == 0x80 {
            return false;
        }
        starts_subidentifier = byte & 0x80 == 0;
    }

    starts_subidentifier
}

/// Search an EKU sequence without decoding unrelated OIDs into `u32` arcs.
///
/// Azure Artifact Signing identity EKUs contain valid five-byte arcs which `const-oid 0.9`
/// rejects, even though the code-signing OID itself is representable by that dependency.
fn extended_key_usage_contains(der: &[u8], expected: ObjectIdentifier) -> Result<bool> {
    let mut outer =
        SliceReader::new(der).map_err(|e| anyhow!("ExtendedKeyUsage extension reader: {e}"))?;
    let header = Header::decode(&mut outer)
        .map_err(|e| anyhow!("ExtendedKeyUsage extension header: {e}"))?;
    if header.tag != Tag::Sequence {
        return Err(anyhow!("ExtendedKeyUsage extension is not a SEQUENCE"));
    }
    let body = outer
        .read_slice(header.length)
        .map_err(|e| anyhow!("ExtendedKeyUsage extension body: {e}"))?;
    outer
        .finish(())
        .map_err(|e| anyhow!("ExtendedKeyUsage extension trailing data: {e}"))?;

    let mut entries =
        SliceReader::new(body).map_err(|e| anyhow!("ExtendedKeyUsage extension entries: {e}"))?;
    let mut found = false;
    while !entries.is_finished() {
        let header = Header::decode(&mut entries)
            .map_err(|e| anyhow!("ExtendedKeyUsage OID header: {e}"))?;
        if header.tag != Tag::ObjectIdentifier {
            return Err(anyhow!(
                "ExtendedKeyUsage entry is not an OBJECT IDENTIFIER"
            ));
        }
        let value = entries
            .read_slice(header.length)
            .map_err(|e| anyhow!("ExtendedKeyUsage OID value: {e}"))?;
        if !oid_value_is_well_formed(value) {
            return Err(anyhow!("ExtendedKeyUsage contains a malformed OID"));
        }
        found |= value == expected.as_bytes();
    }

    Ok(found)
}

fn x509_cert_has_code_signing_eku(cert: &Certificate) -> Result<bool> {
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return Ok(false);
    };
    for ext in exts.iter().filter(|e| e.extn_id == EKU_EXTENSION_OID) {
        if extended_key_usage_contains(ext.extn_value.as_bytes(), CODE_SIGNING_EKU_OID)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn signed_data_embedded_picky_certs(sd: &SignedData) -> Result<Vec<Cert>> {
    let mut out = Vec::new();
    let Some(set) = &sd.certificates else {
        return Ok(out);
    };
    for choice in set.0.iter() {
        let CertificateChoices::Certificate(cert) = choice else {
            continue;
        };
        let der = cert
            .to_der()
            .map_err(|e| anyhow!("encode embedded certificate: {e}"))?;
        out.push(Cert::from_der(&der).map_err(|e| anyhow!("picky embedded certificate: {e}"))?);
    }
    Ok(out)
}

fn verify_trust_chain_verbose(
    pkcs7_index: usize,
    leaf: &Cert,
    chain_vec: &[&Cert],
    root: &Cert,
    root_thumb: &[u8; 20],
    verification_instant: &UtcDate,
    verbose_chain: bool,
) -> Result<()> {
    if verbose_chain {
        let thumb_hex: String = root_thumb.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "trust-verify: PKCS#7[{pkcs7_index}] leaf subject: {}",
            leaf.subject_name()
        );
        for (i, c) in chain_vec.iter().enumerate() {
            eprintln!(
                "trust-verify:   chain[{i}] subject: {} issuer: {}",
                c.subject_name(),
                c.issuer_name()
            );
        }
        eprintln!(
            "trust-verify:   root subject: {} (thumb SHA-1 {thumb_hex})",
            root.subject_name(),
        );
    }

    if leaf.subject_name() == leaf.issuer_name()
        && cert_sha1_thumbprint(leaf).as_ref().ok() == Some(root_thumb)
    {
        return Ok(());
    }

    leaf.verifier()
        .chain(chain_vec.iter().copied())
        .exact_date(verification_instant)
        .verify()
        .map_err(|e| anyhow!("certificate chain verification (PKCS#7 {pkcs7_index}): {e}"))?;

    Ok(())
}

enum CmsDigestCheck<'a> {
    AuthenticodeIndirect(&'a [u8]),
    Pkcs9MessageDigest(&'a [u8]),
}

/// When **`picky`** cannot deserialize the content, validate the relevant digest binding, **RSA/SHA-256**
/// **`SignerInfo`** signature over **`signedAttrs`**, then run the same explicit-anchor chain walk as the picky path.
#[allow(clippy::too_many_arguments)] // CMS fallback mirrors picky path parameters; grouping would obscure control flow.
fn verify_pkcs7_trust_cms_rsa_sha256_fallback(
    slice: &[u8],
    pkcs7_index: usize,
    digest_check: CmsDigestCheck<'_>,
    anchors: &AnchorStore,
    anchor_certs: &[Cert],
    policy: &AuthenticodeTrustPolicy,
    online: &OnlineTrustOptions,
    verification_instant: &UtcDate,
    verbose_chain: bool,
) -> Result<()> {
    let sd = parse_pkcs7_signed_data_der(slice)
        .map_err(|e| anyhow!("CMS SignedData decode (non-PE SpcIndirectData PKCS#7): {e}"))?;

    match digest_check {
        CmsDigestCheck::AuthenticodeIndirect(subject_digest) => {
            verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
                &sd,
                0,
                subject_digest,
            )
            .map_err(|e| {
                anyhow!("CMS RSA/SHA-256 Authenticode fallback (PKCS#7 {pkcs7_index}): {e}")
            })?;
        }
        CmsDigestCheck::Pkcs9MessageDigest(content_digest) => {
            verify_signed_data_pkcs9_message_digest_and_rsa_sha256_pkcs1v15_signature(
                &sd,
                0,
                content_digest,
            )
            .map_err(|e| {
                anyhow!("CMS RSA/SHA-256 detached fallback (PKCS#7 {pkcs7_index}): {e}")
            })?;
        }
    }

    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("SignedData has no SignerInfo"))?;
    let x509_leaf = signed_data_certificate_for_signer_identifier(&sd, &si.sid).map_err(|e| {
        anyhow!("CMS fallback: resolve signer certificate (PKCS#7 {pkcs7_index}): {e}")
    })?;

    if policy.strict_code_signing_eku && !x509_cert_has_code_signing_eku(x509_leaf)? {
        return Err(anyhow!(
            "CMS fallback: leaf certificate lacks code-signing extended key usage (PKCS#7 {pkcs7_index})"
        ));
    }

    let embedded_certs = signed_data_embedded_picky_certs(&sd)?;
    let mut merged = merge_unique_certs(anchor_certs.to_vec(), embedded_certs.clone())?;

    let leaf_der = x509_leaf
        .to_der()
        .map_err(|e| anyhow!("encode signer certificate: {e}"))?;
    let leaf_from_x509 =
        Cert::from_der(&leaf_der).map_err(|e| anyhow!("picky signer certificate: {e}"))?;
    let leaf_thumb = cert_sha1_thumbprint(&leaf_from_x509)?;
    // Prefer the embedded PKCS#7 encoding for the signer (then anchors) so picky **`Cert`**
    // instances match the **`trust-verify-pe`** path when both exist.
    let leaf = embedded_certs
        .iter()
        .chain(anchor_certs.iter())
        .find(|c| cert_sha1_thumbprint(c).ok().as_ref() == Some(&leaf_thumb))
        .cloned()
        .unwrap_or(leaf_from_x509);

    let chain_owned =
        issuer_chain_excluding_leaf_online(&leaf, &mut merged, online, Some(anchors))?;
    let chain_vec: Vec<&Cert> = chain_owned.iter().collect();
    let root = terminal_root_cert_owned(&leaf, &chain_owned);

    let root_thumb = cert_sha1_thumbprint(root)?;
    if !anchors.contains_thumbprint(&root_thumb) {
        return Err(anyhow!(
            "terminal root certificate is not in the anchor store (SHA-1 thumbprint {:02x}{:02x}…)",
            root_thumb[0],
            root_thumb[1]
        ));
    }
    crate::online::check_revocation_chain(&leaf, &chain_owned, online)?;

    verify_trust_chain_verbose(
        pkcs7_index,
        &leaf,
        &chain_vec,
        root,
        &root_thumb,
        verification_instant,
        verbose_chain,
    )
}

/// Verify picky Authenticode PKCS#7 cryptographic checks and certificate chain to configured anchors.
///
/// `subject_digest` must match the PKCS#7 indirect **`messageDigest`** (same bytes used for PE/CAB
/// Authenticode image digest, etc.).
#[allow(clippy::too_many_arguments)]
pub fn verify_authenticode_pkcs7_trust(
    pkcs7_der: &[u8],
    pkcs7_index: usize,
    subject_digest: &[u8],
    anchors: &AnchorStore,
    anchor_certs: &[Cert],
    policy: &AuthenticodeTrustPolicy,
    online: &OnlineTrustOptions,
    verification_instant: &UtcDate,
    verbose_chain: bool,
) -> Result<()> {
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let slice = normalized.as_ref();

    let picky_sig_result = AuthenticodeSignature::from_der(slice);

    let picky_sig = match picky_sig_result {
        Ok(sig) => sig,
        Err(_) => {
            return verify_pkcs7_trust_cms_rsa_sha256_fallback(
                slice,
                pkcs7_index,
                CmsDigestCheck::AuthenticodeIndirect(subject_digest),
                anchors,
                anchor_certs,
                policy,
                online,
                verification_instant,
                verbose_chain,
            );
        }
    };

    if policy.strict_code_signing_eku {
        picky_sig
            .authenticode_verifier()
            .require_basic_authenticode_validation(subject_digest.to_vec())
            .ignore_chain_check()
            .exact_date(verification_instant)
            .require_signing_certificate_check()
            .verify()
            .map_err(|e| anyhow!("picky Authenticode validation (PKCS#7 {pkcs7_index}): {e}"))?;
    } else {
        picky_sig
            .authenticode_verifier()
            .require_basic_authenticode_validation(subject_digest.to_vec())
            .ignore_chain_check()
            .exact_date(verification_instant)
            .ignore_signing_certificate_check()
            .verify()
            .map_err(|e| anyhow!("picky Authenticode validation (PKCS#7 {pkcs7_index}): {e}"))?;
    }

    let embedded = picky_sig.0.decode_certificates();
    let mut merged = merge_unique_certs(embedded, anchor_certs.iter().cloned())?;

    let leaf = picky_sig
        .signing_certificate(&merged)
        .map_err(|e| anyhow!("resolve signing certificate: {e}"))?;

    let leaf = leaf.clone();
    let chain_owned =
        issuer_chain_excluding_leaf_online(&leaf, &mut merged, online, Some(anchors))?;
    let chain_vec: Vec<&Cert> = chain_owned.iter().collect();
    let root = terminal_root_cert_owned(&leaf, &chain_owned);

    let root_thumb = cert_sha1_thumbprint(root)?;
    if !anchors.contains_thumbprint(&root_thumb) {
        return Err(anyhow!(
            "terminal root certificate is not in the anchor store (SHA-1 thumbprint {:02x}{:02x}…)",
            root_thumb[0],
            root_thumb[1]
        ));
    }
    crate::online::check_revocation_chain(&leaf, &chain_owned, online)?;

    verify_trust_chain_verbose(
        pkcs7_index,
        &leaf,
        &chain_vec,
        root,
        &root_thumb,
        verification_instant,
        verbose_chain,
    )
}

/// Verify CMS/PKCS#7 where PKCS#9 `messageDigest` binds the signature to an external content digest.
#[allow(clippy::too_many_arguments)]
pub fn verify_pkcs9_message_digest_pkcs7_trust(
    pkcs7_der: &[u8],
    pkcs7_index: usize,
    content_digest: &[u8],
    anchors: &AnchorStore,
    anchor_certs: &[Cert],
    policy: &AuthenticodeTrustPolicy,
    online: &OnlineTrustOptions,
    verification_instant: &UtcDate,
    verbose_chain: bool,
) -> Result<()> {
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let slice = normalized.as_ref();
    verify_pkcs7_trust_cms_rsa_sha256_fallback(
        slice,
        pkcs7_index,
        CmsDigestCheck::Pkcs9MessageDigest(content_digest),
        anchors,
        anchor_certs,
        policy,
        online,
        verification_instant,
        verbose_chain,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_base128(mut value: u64) -> Vec<u8> {
        let mut encoded = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value != 0 {
            encoded.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        encoded.reverse();
        encoded
    }

    fn encode_oid(arcs: &[u64]) -> Vec<u8> {
        assert!(arcs.len() >= 2);
        let mut value = encode_base128(arcs[0] * 40 + arcs[1]);
        for &arc in &arcs[2..] {
            value.extend(encode_base128(arc));
        }

        let mut encoded = vec![Tag::ObjectIdentifier.into(), value.len() as u8];
        encoded.extend(value);
        encoded
    }

    fn encode_extended_key_usage(oids: &[&[u64]]) -> Vec<u8> {
        let body: Vec<u8> = oids.iter().flat_map(|oid| encode_oid(oid)).collect();
        let mut encoded = vec![Tag::Sequence.into(), body.len() as u8];
        encoded.extend(body);
        encoded
    }

    const CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];
    const TEST_LIFETIME_SIGNING: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 10, 3, 13];
    const TEST_IDENTITY: &[u64] = &[
        1,
        3,
        6,
        1,
        4,
        1,
        311,
        97,
        1,
        2,
        548_345_392,
        570_456_524,
        348_779_735,
        628_493_769,
    ];
    const PUBLIC_TRUST: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 97, 1, 0];
    const PRODUCTION_IDENTITY: &[u64] = &[
        1,
        3,
        6,
        1,
        4,
        1,
        311,
        97,
        872_172_236,
        817_999_856,
        585_183_201,
        971_782_747,
    ];

    #[test]
    fn accepts_azure_test_signing_extended_key_usages() {
        let der = encode_extended_key_usage(&[TEST_LIFETIME_SIGNING, TEST_IDENTITY, CODE_SIGNING]);

        assert!(extended_key_usage_contains(&der, CODE_SIGNING_EKU_OID).unwrap());
    }

    #[test]
    fn accepts_azure_production_signing_extended_key_usages() {
        let der = encode_extended_key_usage(&[PUBLIC_TRUST, PRODUCTION_IDENTITY, CODE_SIGNING]);

        assert!(extended_key_usage_contains(&der, CODE_SIGNING_EKU_OID).unwrap());
    }

    #[test]
    fn rejects_malformed_unknown_extended_key_usage() {
        let der = [0x30, 0x03, 0x06, 0x01, 0x80];

        assert!(extended_key_usage_contains(&der, CODE_SIGNING_EKU_OID).is_err());
    }
}
