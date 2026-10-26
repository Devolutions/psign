//! Azure **Artifact Signing** (formerly Trusted Signing) certificate identity and pinned-root trust.
//!
//! Artifact Signing certificates are renewed daily and live for 72 hours, so pinning a thumbprint
//! or public key is not durable. Each certificate profile instead carries a custom EKU under
//! **`1.3.6.1.4.1.311.97.`** whose remaining arcs stay stable for the lifetime of the profile;
//! this module exposes that suffix as the **publisher ID**.
//!
//! | Profile type | Identity EKU | Notes |
//! |--------------|--------------|-------|
//! | Public Trust | `1.3.6.1.4.1.311.97.<id>` | Also carries the `1.3.6.1.4.1.311.97.1.0` marker EKU. |
//! | Public Trust Test | `1.3.6.1.4.1.311.97.1.2.<id>` | Not chained to a production Microsoft root. |
//! | Private Trust | `1.3.6.1.4.1.311.97.1.3.1.<id>` | Chains to a subscriber-specific root. |
//! | Private Trust CI Policy | `1.3.6.1.4.1.311.97.1.4.1.<id>` | No code signing EKU (WDAC policy signing only). |
//!
//! Public Trust signatures (and the `timestamp.acs.microsoft.com` TSA) chain to
//! **Microsoft Identity Verification Root Certificate Authority 2020**, which is pinned here instead
//! of trusting the full AuthRoot program.
//!
//! References:
//! - <https://learn.microsoft.com/azure/artifact-signing/concept-certificate-management>
//! - <https://www.microsoft.com/pkiops/docs/repository.htm>

use crate::anchor::{AnchorStore, cert_sha1_thumbprint, parse_cert_bytes};
use crate::chain::verify_certificate_chain_to_anchors;
use crate::chain::{issuer_chain_excluding_leaf, merge_unique_certs, terminal_root_cert};
use crate::policy::AuthenticodeTrustPolicy;
use crate::rfc3161_extract::{
    trusted_utc_date_from_authenticode_timestamp_token, trusted_utc_date_from_timestamp_token,
};
use crate::trust_pkcs7::{Pkcs7DigestBinding, verify_pkcs7_trust_with_binding};
use crate::trust_verify_pe::TrustVerifyPeOptions;
use anyhow::{Context, Result, anyhow};
use der::asn1::ObjectIdentifier;
use der::{Decode, Header, Reader, SliceReader, Tag};
use picky::x509::certificate::Cert;
use picky::x509::date::UtcDate;
use psign_sip_digest::pkcs7::{
    parse_pkcs7_signed_data_der, signed_data_certificate_for_signer_identifier,
};
use psign_sip_digest::pkcs7_wire::normalize_pkcs7_der_for_authenticode;
use psign_sip_digest::verify_pe::for_each_pe_pkcs7_signed_data;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::PathBuf;
use x509_cert::Certificate;

const EKU_EXTENSION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// Arcs shared by every Artifact Signing EKU (`1.3.6.1.4.1.311.97`).
const ARTIFACT_SIGNING_EKU_ARCS: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 97];
const CODE_SIGNING_EKU_ARCS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];

/// Prefix of every Artifact Signing EKU, including the trailing dot.
pub const ARTIFACT_SIGNING_EKU_PREFIX: &str = "1.3.6.1.4.1.311.97.";
/// EKU present on every Artifact Signing **Public Trust** certificate.
pub const PUBLIC_TRUST_MARKER_EKU: &str = "1.3.6.1.4.1.311.97.1.0";

/// A Microsoft root certificate pinned for Artifact Signing validation.
#[derive(Debug, Clone, Copy)]
pub struct PinnedRoot {
    pub name: &'static str,
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
    pem: &'static str,
}

impl PinnedRoot {
    /// Parse the embedded certificate and confirm it matches both pinned thumbprints.
    pub fn certificate(&self) -> Result<Cert> {
        let cert = parse_cert_bytes(self.pem.as_bytes())
            .with_context(|| format!("parse pinned root {}", self.name))?;
        let der = cert
            .to_der()
            .map_err(|e| anyhow!("encode pinned root {}: {e}", self.name))?;
        if cert_sha1_thumbprint(&cert)? != self.sha1
            || sha2::Sha256::digest(&der).as_slice() != self.sha256
        {
            return Err(anyhow!(
                "embedded pinned root {} does not match its pinned thumbprints",
                self.name
            ));
        }
        Ok(cert)
    }
}

/// **Microsoft Identity Verification Root Certificate Authority 2020**: issues
/// *Microsoft ID Verified Code Signing PCA 2021* (Artifact Signing Public Trust) and
/// *Microsoft Public RSA Timestamping CA 2020* (`timestamp.acs.microsoft.com`).
pub const MICROSOFT_IDENTITY_VERIFICATION_ROOT_2020: PinnedRoot = PinnedRoot {
    name: "Microsoft Identity Verification Root Certificate Authority 2020",
    sha1: hex_array("f40042e2e5f7e8ef8189fed15519aece42c3bfa2"),
    sha256: hex_array("5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270"),
    pem: include_str!("../certs/microsoft-identity-verification-root-ca-2020.pem"),
};

/// Roots accepted for Artifact Signing **Public Trust** code signing and its timestamps.
pub const PUBLIC_TRUST_ROOTS: &[PinnedRoot] = &[MICROSOFT_IDENTITY_VERIFICATION_ROOT_2020];

const fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid lowercase hex digit"),
        }
    }
    let bytes = hex.as_bytes();
    assert!(bytes.len() == N * 2, "hex length mismatch");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(bytes[i * 2]) << 4) | nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSigningCertificateKind {
    PublicTrust,
    PublicTrustTest,
    PrivateTrust,
    PrivateTrustCiPolicy,
}

impl ArtifactSigningCertificateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicTrust => "public_trust",
            Self::PublicTrustTest => "public_trust_test",
            Self::PrivateTrust => "private_trust",
            Self::PrivateTrustCiPolicy => "private_trust_ci_policy",
        }
    }
}

/// Durable Artifact Signing identity decoded from a certificate's EKU extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSigningIdentity {
    pub kind: ArtifactSigningCertificateKind,
    /// Dotted arcs that follow the profile-type prefix (stable across daily certificate renewals).
    pub publisher_id: String,
    /// Full identity EKU OID (`1.3.6.1.4.1.311.97.…`).
    pub identity_eku: String,
    pub has_public_trust_marker: bool,
    pub has_code_signing_eku: bool,
}

/// Decode the EKU `SEQUENCE OF OBJECT IDENTIFIER` into arcs.
///
/// Decoded by hand because Artifact Signing identity arcs can need five base-128 octets, which
/// `const-oid 0.9` rejects (see `trust_pkcs7::extended_key_usage_contains`).
fn decode_eku_arcs(der: &[u8]) -> Result<Vec<Vec<u64>>> {
    let mut outer = SliceReader::new(der).map_err(|e| anyhow!("ExtendedKeyUsage reader: {e}"))?;
    let header = Header::decode(&mut outer).map_err(|e| anyhow!("ExtendedKeyUsage header: {e}"))?;
    if header.tag != Tag::Sequence {
        return Err(anyhow!("ExtendedKeyUsage extension is not a SEQUENCE"));
    }
    let body = outer
        .read_slice(header.length)
        .map_err(|e| anyhow!("ExtendedKeyUsage body: {e}"))?;
    outer
        .finish(())
        .map_err(|e| anyhow!("ExtendedKeyUsage trailing data: {e}"))?;

    let mut entries =
        SliceReader::new(body).map_err(|e| anyhow!("ExtendedKeyUsage entries: {e}"))?;
    let mut out = Vec::new();
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
        out.push(decode_oid_arcs(value)?);
    }
    Ok(out)
}

fn decode_oid_arcs(value: &[u8]) -> Result<Vec<u64>> {
    let mut subidentifiers = Vec::new();
    let mut current: u64 = 0;
    let mut starts_subidentifier = true;
    for &byte in value {
        if starts_subidentifier && byte == 0x80 {
            return Err(anyhow!("ExtendedKeyUsage contains a non-canonical OID"));
        }
        if current > (u64::MAX >> 7) {
            return Err(anyhow!("ExtendedKeyUsage OID arc exceeds 64 bits"));
        }
        current = (current << 7) | u64::from(byte & 0x7f);
        starts_subidentifier = byte & 0x80 == 0;
        if starts_subidentifier {
            subidentifiers.push(current);
            current = 0;
        }
    }
    if !starts_subidentifier || subidentifiers.is_empty() {
        return Err(anyhow!("ExtendedKeyUsage contains a truncated OID"));
    }

    let first = subidentifiers[0];
    let (a, b) = match first {
        0..=39 => (0, first),
        40..=79 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut arcs = vec![a, b];
    arcs.extend_from_slice(&subidentifiers[1..]);
    Ok(arcs)
}

fn dotted(arcs: &[u64]) -> String {
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// Classify the arcs after `1.3.6.1.4.1.311.97`; `None` for the marker and unknown sub-types.
fn classify_identity_suffix(rest: &[u64]) -> Option<(ArtifactSigningCertificateKind, &[u64])> {
    use ArtifactSigningCertificateKind::*;
    let (kind, id) = match rest {
        [1, 2, id @ ..] => (PublicTrustTest, id),
        [1, 3, 1, id @ ..] => (PrivateTrust, id),
        [1, 4, 1, id @ ..] => (PrivateTrustCiPolicy, id),
        [1, ..] => return None,
        id => (PublicTrust, id),
    };
    (!id.is_empty()).then_some((kind, id))
}

/// Extract the Artifact Signing identity from an X.509 certificate.
///
/// Returns `Ok(None)` when the certificate has no Artifact Signing identity EKU, and an error when it
/// carries more than one distinct identity EKU.
pub fn artifact_signing_identity_from_certificate(
    cert: &Certificate,
) -> Result<Option<ArtifactSigningIdentity>> {
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return Ok(None);
    };

    let mut identity: Option<ArtifactSigningIdentity> = None;
    let mut has_public_trust_marker = false;
    let mut has_code_signing_eku = false;
    for ext in exts.iter().filter(|e| e.extn_id == EKU_EXTENSION_OID) {
        for arcs in decode_eku_arcs(ext.extn_value.as_bytes())? {
            if arcs == CODE_SIGNING_EKU_ARCS {
                has_code_signing_eku = true;
                continue;
            }
            let Some(rest) = arcs.strip_prefix(ARTIFACT_SIGNING_EKU_ARCS) else {
                continue;
            };
            if rest == [1, 0] {
                has_public_trust_marker = true;
                continue;
            }
            let Some((kind, id)) = classify_identity_suffix(rest) else {
                continue;
            };
            let found = ArtifactSigningIdentity {
                kind,
                publisher_id: dotted(id),
                identity_eku: dotted(&arcs),
                has_public_trust_marker: false,
                has_code_signing_eku: false,
            };
            match &identity {
                Some(prev) if prev.identity_eku != found.identity_eku => {
                    return Err(anyhow!(
                        "certificate carries multiple Artifact Signing identity EKUs ({} and {})",
                        prev.identity_eku,
                        found.identity_eku
                    ));
                }
                Some(_) => {}
                None => identity = Some(found),
            }
        }
    }

    Ok(identity.map(|mut id| {
        id.has_public_trust_marker = has_public_trust_marker;
        id.has_code_signing_eku = has_code_signing_eku;
        id
    }))
}

/// [`artifact_signing_identity_from_certificate`] for a DER or PEM encoded certificate.
pub fn artifact_signing_identity_from_cert_bytes(
    raw: &[u8],
) -> Result<Option<ArtifactSigningIdentity>> {
    let der = parse_cert_bytes(raw)?
        .to_der()
        .map_err(|e| anyhow!("certificate DER encode failed: {e}"))?;
    let cert = Certificate::from_der(&der).map_err(|e| anyhow!("X.509 decode: {e}"))?;
    artifact_signing_identity_from_certificate(&cert)
}

/// Subject DN via picky (decodes BMPString attributes that `x509-cert` prints as hex).
fn subject_display(cert: &Certificate) -> String {
    der::Encode::to_der(cert)
        .ok()
        .and_then(|der| Cert::from_der(&der).ok())
        .map(|c| c.subject_name().to_string())
        .unwrap_or_else(|| cert.tbs_certificate.subject.to_string())
}

/// Signer certificate (first `SignerInfo`) and its Artifact Signing identity from a PKCS#7 blob.
fn pkcs7_signer_identity(
    pkcs7_der: &[u8],
) -> Result<(Certificate, Option<ArtifactSigningIdentity>)> {
    let sd = parse_pkcs7_signed_data_der(pkcs7_der)?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("SignedData has no SignerInfo"))?;
    let cert = signed_data_certificate_for_signer_identifier(&sd, &si.sid)?.clone();
    let identity = artifact_signing_identity_from_certificate(&cert)?;
    Ok((cert, identity))
}

/// Artifact Signing identity of the primary signer in a PKCS#7 / CMS `SignedData` blob.
pub fn artifact_signing_identity_from_pkcs7_der(
    pkcs7_der: &[u8],
) -> Result<Option<ArtifactSigningIdentity>> {
    Ok(pkcs7_signer_identity(pkcs7_der)?.1)
}

/// Signer identity for one PE certificate-table PKCS#7 entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSigningSignerIdentity {
    pub pkcs7_index: usize,
    pub signer_subject: String,
    pub identity: Option<ArtifactSigningIdentity>,
}

/// Artifact Signing identities of every embedded PE Authenticode signature (no trust checks).
pub fn artifact_signing_identities_from_pe(
    pe_bytes: &[u8],
) -> Result<Vec<ArtifactSigningSignerIdentity>> {
    let mut out = Vec::new();
    for_each_pe_pkcs7_signed_data(pe_bytes, |pkcs7_index, pkcs7_der| {
        let (cert, identity) = pkcs7_signer_identity(pkcs7_der)
            .with_context(|| format!("PKCS#7 index {pkcs7_index}"))?;
        out.push(ArtifactSigningSignerIdentity {
            pkcs7_index,
            signer_subject: subject_display(&cert),
            identity,
        });
        Ok(())
    })?;
    Ok(out)
}

/// Artifact Signing policy applied by every `trust_verify_*` entry point when
/// [`TrustVerifyPeOptions::artifact_signing`] is set.
///
/// Replaces the generic anchor set (`--anchor-dir`, `--trusted-ca`, AuthRoot) with
/// [`PUBLIC_TRUST_ROOTS`] (Public Trust) or [`Self::private_trust_root_files`] (Private Trust /
/// Public Trust Test). `verification_instant_override`, `online`, and `verbose_chain` still come
/// from [`TrustVerifyPeOptions`].
#[derive(Debug, Clone)]
pub struct ArtifactSigningPolicy {
    /// When non-empty, the signer's publisher ID must equal one of these values.
    pub expected_publisher_ids: Vec<String>,
    /// Subscriber roots for Private Trust / Public Trust Test signatures (PEM or DER files).
    /// Public Trust signatures always use [`PUBLIC_TRUST_ROOTS`] and ignore these.
    pub private_trust_root_files: Vec<PathBuf>,
    /// Require a timestamp countersignature chained to [`PUBLIC_TRUST_ROOTS`] (default `true`).
    ///
    /// When `false` and no timestamp is present, the wall clock is used; Artifact Signing
    /// certificates expire after 72 hours so such signatures fail soon after signing.
    pub require_timestamp: bool,
}

impl Default for ArtifactSigningPolicy {
    fn default() -> Self {
        Self {
            expected_publisher_ids: Vec::new(),
            private_trust_root_files: Vec::new(),
            require_timestamp: true,
        }
    }
}

/// One verified Artifact Signing signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSigningVerifiedSignature {
    /// PE certificate-table entry index; `0` for single-signature formats.
    pub signature_index: usize,
    pub signer_subject: String,
    pub identity: ArtifactSigningIdentity,
    /// Subject of the trust anchor that terminates the signer chain.
    pub root_subject: String,
    /// Lowercase hex SHA-1 thumbprint of that trust anchor.
    pub root_sha1: String,
    /// `true` when the verification time came from a trusted timestamp countersignature.
    pub timestamped: bool,
    /// RFC 3339 instant used for certificate validity checks.
    pub verification_time: String,
}

impl std::fmt::Display for ArtifactSigningVerifiedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "signature[{}] {} publisher_id={} kind={} root={} time={}{}",
            self.signature_index,
            self.signer_subject,
            self.identity.publisher_id,
            self.identity.kind.as_str(),
            self.root_sha1,
            self.verification_time,
            if self.timestamped { " (timestamp)" } else { "" }
        )
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn anchors_from_certs(certs: Vec<Cert>) -> Result<(AnchorStore, Vec<Cert>)> {
    let mut store = AnchorStore::empty();
    store.merge_cert_thumbprints(&certs)?;
    Ok((store, certs))
}

/// Pinned Microsoft roots used for Public Trust signer chains and timestamp countersignatures.
pub fn public_trust_anchor_certs() -> Result<Vec<Cert>> {
    PUBLIC_TRUST_ROOTS
        .iter()
        .map(PinnedRoot::certificate)
        .collect()
}

/// Anchor store holding only [`PUBLIC_TRUST_ROOTS`].
pub fn public_trust_anchors() -> Result<(AnchorStore, Vec<Cert>)> {
    anchors_from_certs(public_trust_anchor_certs()?)
}

/// Identity of `signer`, checked against the Artifact Signing rules and the publisher pin.
fn checked_identity(
    signer: &Certificate,
    policy: &ArtifactSigningPolicy,
) -> Result<(String, ArtifactSigningIdentity)> {
    use ArtifactSigningCertificateKind::*;

    let signer_subject = subject_display(signer);
    let identity = artifact_signing_identity_from_certificate(signer)?.ok_or_else(|| {
        anyhow!(
            "signer {signer_subject:?} has no Artifact Signing identity EKU ({ARTIFACT_SIGNING_EKU_PREFIX}…)"
        )
    })?;

    match identity.kind {
        PublicTrust if !identity.has_public_trust_marker => {
            return Err(anyhow!(
                "Public Trust signer lacks the {PUBLIC_TRUST_MARKER_EKU} marker EKU"
            ));
        }
        PrivateTrustCiPolicy => {
            return Err(anyhow!(
                "Private Trust CI Policy certificates sign WDAC policies, not Authenticode code"
            ));
        }
        _ => {}
    }
    if !identity.has_code_signing_eku {
        return Err(anyhow!("signer lacks the code signing EKU"));
    }
    if !policy.expected_publisher_ids.is_empty()
        && !policy
            .expected_publisher_ids
            .iter()
            .any(|id| id.trim() == identity.publisher_id)
    {
        return Err(anyhow!(
            "Artifact Signing publisher ID {} is not one of the expected IDs ({})",
            identity.publisher_id,
            policy.expected_publisher_ids.join(", ")
        ));
    }
    Ok((signer_subject, identity))
}

/// Verification instant: the override, else a timestamp verified against [`PUBLIC_TRUST_ROOTS`].
///
/// `trusted_timestamp` verifies the format's timestamp with the given anchors; `Ok(None)` means
/// the signature carries no timestamp.
fn artifact_signing_instant(
    policy: &ArtifactSigningPolicy,
    opts: &TrustVerifyPeOptions,
    trusted_timestamp: impl FnOnce(&AnchorStore, &[Cert]) -> Result<Option<UtcDate>>,
) -> Result<(bool, UtcDate)> {
    if let Some(instant) = &opts.verification_instant_override {
        return Ok((false, instant.clone()));
    }
    let (ms_anchors, ms_anchor_certs) = public_trust_anchors()?;
    match trusted_timestamp(&ms_anchors, &ms_anchor_certs)
        .context("Artifact Signing timestamp countersignature")?
    {
        Some(instant) => Ok((true, instant)),
        None if policy.require_timestamp => Err(anyhow!(
            "Artifact Signing signature has no RFC 3161 timestamp countersignature"
        )),
        None => Ok((false, UtcDate::now())),
    }
}

/// Anchors for an identity kind: [`PUBLIC_TRUST_ROOTS`] for Public Trust, else the subscriber roots.
fn artifact_signing_anchors(
    kind: ArtifactSigningCertificateKind,
    policy: &ArtifactSigningPolicy,
) -> Result<(AnchorStore, Vec<Cert>)> {
    if kind == ArtifactSigningCertificateKind::PublicTrust {
        return public_trust_anchors();
    }
    if policy.private_trust_root_files.is_empty() {
        return Err(anyhow!(
            "{} signature requires the subscriber root certificate (private trust root)",
            kind.as_str()
        ));
    }
    let (_, certs) = AnchorStore::load_files(&policy.private_trust_root_files)?;
    // Microsoft production roots must never anchor a non-Public-Trust profile.
    let certs: Vec<Cert> = certs
        .into_iter()
        .filter(|c| {
            cert_sha1_thumbprint(c)
                .map(|t| !PUBLIC_TRUST_ROOTS.iter().any(|r| r.sha1 == t))
                .unwrap_or(false)
        })
        .collect();
    if certs.is_empty() {
        return Err(anyhow!(
            "no usable private trust roots (Microsoft Public Trust roots are not accepted for {})",
            kind.as_str()
        ));
    }
    anchors_from_certs(certs)
}

fn verified_signature(
    signature_index: usize,
    signer_subject: String,
    identity: ArtifactSigningIdentity,
    root: &Cert,
    timestamped: bool,
    verification_instant: &UtcDate,
) -> Result<ArtifactSigningVerifiedSignature> {
    Ok(ArtifactSigningVerifiedSignature {
        signature_index,
        signer_subject,
        identity,
        root_subject: root.subject_name().to_string(),
        root_sha1: hex_lower(&cert_sha1_thumbprint(root)?),
        timestamped,
        verification_time: utc_date_rfc3339(verification_instant),
    })
}

/// Verify one PKCS#7 as an Artifact Signing signature whose digest binding equals `subject_digest`.
///
/// Checks, in order: the signer carries an Artifact Signing identity EKU (and the Public Trust
/// marker for Public Trust profiles), the publisher ID matches
/// [`ArtifactSigningPolicy::expected_publisher_ids`], the timestamp countersignature chains to a
/// pinned Microsoft root, and the signer chain terminates at a pinned Microsoft root (Public
/// Trust) or a supplied subscriber root (Private Trust / Public Trust Test) with the CMS
/// signature and code-signing EKU valid at the timestamp.
pub fn verify_artifact_signing_pkcs7(
    pkcs7_der: &[u8],
    pkcs7_index: usize,
    subject_digest: &[u8],
    binding: Pkcs7DigestBinding,
    policy: &ArtifactSigningPolicy,
    opts: &TrustVerifyPeOptions,
) -> Result<ArtifactSigningVerifiedSignature> {
    let (signer, _) = pkcs7_signer_identity(pkcs7_der)?;
    let (signer_subject, identity) = checked_identity(&signer, policy)?;
    let (timestamped, verification_instant) =
        artifact_signing_instant(policy, opts, |anchors, certs| {
            trusted_utc_date_from_authenticode_timestamp_token(
                pkcs7_der,
                anchors,
                certs,
                &opts.online,
                opts.verbose_chain,
            )
        })?;
    let (anchors, anchor_certs) = artifact_signing_anchors(identity.kind, policy)?;

    let trust_policy = AuthenticodeTrustPolicy {
        strict_code_signing_eku: true,
        prefer_timestamp_signing_time: false,
        require_valid_timestamp: false,
    };
    verify_pkcs7_trust_with_binding(
        binding,
        pkcs7_der,
        pkcs7_index,
        subject_digest,
        &anchors,
        &anchor_certs,
        &trust_policy,
        &opts.online,
        &verification_instant,
        opts.verbose_chain,
    )?;

    let root = signer_terminal_root(pkcs7_der, &anchors, &anchor_certs)?;
    verified_signature(
        pkcs7_index,
        signer_subject,
        identity,
        &root,
        timestamped,
        &verification_instant,
    )
}

/// Artifact Signing policy for signatures that are not CMS (VSIX XMLDSig): the caller has already
/// verified the signature value with `signer`'s key, so this checks the identity, the timestamp
/// token (`timestamp` = token DER and the bytes it covers), and `signer`'s chain to the anchors.
pub fn verify_artifact_signing_certificate(
    signer: &Certificate,
    extra_certs: Vec<Cert>,
    timestamp: Option<(&[u8], &[u8])>,
    signature_index: usize,
    policy: &ArtifactSigningPolicy,
    opts: &TrustVerifyPeOptions,
) -> Result<ArtifactSigningVerifiedSignature> {
    let (signer_subject, identity) = checked_identity(signer, policy)?;
    let (timestamped, verification_instant) =
        artifact_signing_instant(policy, opts, |anchors, certs| {
            timestamp
                .map(|(token, covered)| {
                    trusted_utc_date_from_timestamp_token(
                        token,
                        covered,
                        anchors,
                        certs,
                        &opts.online,
                        opts.verbose_chain,
                    )
                })
                .transpose()
        })?;
    let (anchors, anchor_certs) = artifact_signing_anchors(identity.kind, policy)?;

    let leaf_der =
        der::Encode::to_der(signer).map_err(|e| anyhow!("encode signer certificate: {e}"))?;
    let leaf = Cert::from_der(&leaf_der).map_err(|e| anyhow!("picky signer certificate: {e}"))?;
    let root = verify_certificate_chain_to_anchors(
        &leaf,
        extra_certs,
        &anchors,
        &anchor_certs,
        &opts.online,
        &verification_instant,
        opts.verbose_chain,
    )?;
    verified_signature(
        signature_index,
        signer_subject,
        identity,
        &root,
        timestamped,
        &verification_instant,
    )
}

/// Re-walk the (already verified) signer chain to report which anchor terminated it.
fn signer_terminal_root(
    pkcs7_der: &[u8],
    anchors: &AnchorStore,
    anchor_certs: &[Cert],
) -> Result<Cert> {
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let sd = parse_pkcs7_signed_data_der(normalized.as_ref())?;
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow!("SignedData has no SignerInfo"))?;
    let leaf_der =
        der::Encode::to_der(signed_data_certificate_for_signer_identifier(&sd, &si.sid)?)
            .map_err(|e| anyhow!("encode signer certificate: {e}"))?;
    let leaf = Cert::from_der(&leaf_der).map_err(|e| anyhow!("picky signer certificate: {e}"))?;
    let embedded: Vec<Cert> = sd
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(c) => der::Encode::to_der(c).ok(),
            _ => None,
        })
        .filter_map(|der| Cert::from_der(&der).ok())
        .collect();
    let pool = merge_unique_certs(anchor_certs.to_vec(), embedded)?;
    let chain = issuer_chain_excluding_leaf(&leaf, &pool, Some(anchors))?;
    Ok(terminal_root_cert(&leaf, &chain).clone())
}

fn utc_date_rfc3339(d: &UtcDate) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute(),
        d.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/artifact-signing")
            .join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    fn eku(oids: &[&[u64]]) -> Vec<u8> {
        fn base128(mut v: u64) -> Vec<u8> {
            let mut out = vec![(v & 0x7f) as u8];
            v >>= 7;
            while v != 0 {
                out.push(((v & 0x7f) as u8) | 0x80);
                v >>= 7;
            }
            out.reverse();
            out
        }
        let mut body = Vec::new();
        for arcs in oids {
            let mut value = base128(arcs[0] * 40 + arcs[1]);
            for &a in &arcs[2..] {
                value.extend(base128(a));
            }
            body.push(0x06);
            body.push(value.len() as u8);
            body.extend(value);
        }
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);
        der
    }

    fn identity_from_eku(
        oids: &[&[u64]],
    ) -> Result<Option<(ArtifactSigningCertificateKind, String)>> {
        let mut kinds = None;
        for arcs in decode_eku_arcs(&eku(oids))? {
            if let Some(rest) = arcs.strip_prefix(ARTIFACT_SIGNING_EKU_ARCS)
                && let Some((kind, id)) = classify_identity_suffix(rest)
            {
                kinds = Some((kind, dotted(id)));
            }
        }
        Ok(kinds)
    }

    const MS: [u64; 8] = [1, 3, 6, 1, 4, 1, 311, 97];

    fn arcs(suffix: &[u64]) -> Vec<u64> {
        let mut v = MS.to_vec();
        v.extend_from_slice(suffix);
        v
    }

    #[test]
    fn pinned_root_matches_thumbprints() {
        let roots = public_trust_anchor_certs().expect("pinned roots");
        assert_eq!(roots.len(), 1);
        assert_eq!(
            roots[0].subject_name().to_string(),
            roots[0].issuer_name().to_string(),
            "pinned root must be self-signed"
        );
    }

    #[test]
    fn classifies_documented_identity_ekus() {
        use ArtifactSigningCertificateKind::*;
        let cases: &[(&[u64], ArtifactSigningCertificateKind, &str)] = &[
            (
                &[990309390, 766961637, 194916062, 941502583],
                PublicTrust,
                "990309390.766961637.194916062.941502583",
            ),
            (
                &[1, 2, 548_345_392, 570_456_524, 348_779_735, 628_493_769],
                PublicTrustTest,
                "548345392.570456524.348779735.628493769",
            ),
            (
                &[
                    1, 3, 1, 29433, 35007, 34545, 16815, 37291, 11644, 53265, 56135,
                ],
                PrivateTrust,
                "29433.35007.34545.16815.37291.11644.53265.56135",
            ),
            (
                &[
                    1, 4, 1, 29433, 35007, 34545, 16815, 37291, 11644, 53265, 56135,
                ],
                PrivateTrustCiPolicy,
                "29433.35007.34545.16815.37291.11644.53265.56135",
            ),
        ];
        for (suffix, kind, id) in cases {
            let oid = arcs(suffix);
            let got = identity_from_eku(&[&oid]).unwrap().expect("identity");
            assert_eq!(got, (*kind, id.to_string()));
        }
    }

    #[test]
    fn marker_and_unknown_subtypes_are_not_identities() {
        let marker = arcs(&[1, 0]);
        let unknown = arcs(&[1, 9, 7]);
        assert_eq!(identity_from_eku(&[&marker, &unknown]).unwrap(), None);
    }

    #[test]
    fn rejects_truncated_and_non_canonical_oids() {
        assert!(decode_eku_arcs(&[0x30, 0x03, 0x06, 0x01, 0x80]).is_err());
        assert!(decode_eku_arcs(&[0x30, 0x04, 0x06, 0x02, 0x80, 0x01]).is_err());
    }

    #[test]
    fn extracts_publisher_id_from_real_signer_certificate() {
        let id = artifact_signing_identity_from_cert_bytes(&fixture("devolutions-signer.pem"))
            .expect("parse")
            .expect("identity");
        assert_eq!(id.kind, ArtifactSigningCertificateKind::PublicTrust);
        assert_eq!(id.publisher_id, "285218949.549339218.252840042.443064405");
        assert_eq!(
            id.identity_eku,
            "1.3.6.1.4.1.311.97.285218949.549339218.252840042.443064405"
        );
        assert!(id.has_public_trust_marker);
        assert!(id.has_code_signing_eku);
    }

    #[test]
    fn non_artifact_signing_certificate_has_no_identity() {
        let root = MICROSOFT_IDENTITY_VERIFICATION_ROOT_2020.pem.as_bytes();
        assert_eq!(
            artifact_signing_identity_from_cert_bytes(root).unwrap(),
            None
        );
    }

    fn real_pkcs7_and_digest() -> (Vec<u8>, Vec<u8>) {
        let pkcs7 = fixture("psign-tool.pkcs7.der");
        let normalized = normalize_pkcs7_der_for_authenticode(&pkcs7);
        let digest = authenticode::AuthenticodeSignature::from_bytes(normalized.as_ref())
            .expect("authenticode parse")
            .digest()
            .to_vec();
        (pkcs7, digest)
    }

    fn verify_real(
        digest: &[u8],
        policy: ArtifactSigningPolicy,
        opts: TrustVerifyPeOptions,
    ) -> Result<ArtifactSigningVerifiedSignature> {
        let (pkcs7, _) = real_pkcs7_and_digest();
        verify_artifact_signing_pkcs7(
            &pkcs7,
            0,
            digest,
            Pkcs7DigestBinding::AuthenticodeIndirect,
            &policy,
            &opts,
        )
    }

    fn pinned(ids: &[&str]) -> ArtifactSigningPolicy {
        ArtifactSigningPolicy {
            expected_publisher_ids: ids.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn verifies_real_public_trust_signature_at_timestamp() {
        let (_, digest) = real_pkcs7_and_digest();
        let report = verify_real(&digest, pinned(&[]), Default::default()).expect("ok");
        assert!(report.timestamped);
        assert_eq!(
            report.identity.publisher_id,
            "285218949.549339218.252840042.443064405"
        );
        assert_eq!(report.root_sha1, "f40042e2e5f7e8ef8189fed15519aece42c3bfa2");
    }

    #[test]
    fn rejects_unexpected_publisher_id() {
        let (_, digest) = real_pkcs7_and_digest();
        let policy = pinned(&["990309390.766961637.194916062.941502583"]);
        let err = verify_real(&digest, policy, Default::default()).unwrap_err();
        assert!(
            format!("{err:#}").contains("not one of the expected"),
            "{err:#}"
        );
    }

    #[test]
    fn accepts_expected_publisher_id() {
        let (_, digest) = real_pkcs7_and_digest();
        let policy = pinned(&["1.2.3.4", "285218949.549339218.252840042.443064405"]);
        verify_real(&digest, policy, Default::default()).expect("ok");
    }

    #[test]
    fn rejects_signer_outside_72_hour_validity_without_timestamp_time() {
        let (_, digest) = real_pkcs7_and_digest();
        let opts = TrustVerifyPeOptions {
            verification_instant_override: Some(
                crate::parse_verification_date_ymd("2026-11-01").unwrap(),
            ),
            ..Default::default()
        };
        assert!(verify_real(&digest, pinned(&[]), opts).is_err());
    }

    #[test]
    fn rejects_digest_mismatch() {
        let (_, mut digest) = real_pkcs7_and_digest();
        digest[0] ^= 0xff;
        assert!(verify_real(&digest, pinned(&[]), Default::default()).is_err());
    }

    #[test]
    fn generic_anchors_cannot_satisfy_artifact_signing_policy() {
        let pe_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        let pe = std::fs::read(&pe_path).expect("fixture");
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root.der");
        std::fs::write(
            &root,
            crate::pe_first_pkcs7_terminal_root(&pe)
                .unwrap()
                .to_der()
                .unwrap(),
        )
        .unwrap();
        let mut opts = TrustVerifyPeOptions {
            trusted_ca_files: vec![root],
            verification_instant_override: Some(
                crate::parse_verification_date_ymd("2023-07-01").unwrap(),
            ),
            ..Default::default()
        };
        crate::trust_verify_pe_bytes(&pe, &opts).expect("generic trust with explicit root");

        opts.artifact_signing = Some(pinned(&[]));
        let err = crate::trust_verify_pe_bytes(&pe, &opts).unwrap_err();
        assert!(
            format!("{err:#}").contains("no Artifact Signing identity EKU"),
            "{err:#}"
        );
    }
}
