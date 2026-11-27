//! MSIX / AppX (and bundle) Authenticode trust: APPX SIP digest + PKCS#7 chain.

use crate::anchor::{AnchorStore, cert_der_sha1_hex, cert_der_sha256_hex};
use crate::artifact_signing::{
    ArtifactSigningCertificateKind, ArtifactSigningIdentity, ArtifactSigningPolicy,
    artifact_signing_identity_from_certificate, public_trust_anchor_certs, subject_display,
};
use crate::policy::OnlineTrustOptions;
use crate::rfc3161_extract::trusted_utc_date_from_authenticode_timestamp_token;
use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material, trust_material_for,
    verify_pkcs7_entry,
};
use anyhow::{Context, Result, anyhow, bail};
use der::{Decode, Encode};
use picky::x509::date::UtcDate;
use picky::x509::pkcs7::authenticode::AuthenticodeSignature;
use psign_sip_digest::msix_digest::msix_verified_signature;
use psign_sip_digest::pkcs7::{
    parse_pkcs7_signed_data_der, signed_data_certificate_for_signer_identifier,
    verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature,
};
use psign_sip_digest::pkcs7_wire::normalize_pkcs7_der_for_authenticode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;
use x509_cert::Certificate;

/// Recommended durable pin for a verified MSIX signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsixRecommendedPin {
    /// Azure Artifact Signing certificate profile publisher ID (stable across 72h renewals).
    ArtifactSigningPublisherId(String),
    /// Lowercase hex SHA-256 thumbprint of the leaf signing certificate DER.
    CertificateSha256(String),
}

/// Cryptographically verified signer details for an MSIX / AppX package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsixVerifiedSigner {
    /// DER-encoded leaf signing certificate.
    #[serde(skip)]
    pub signer_certificate_der: Vec<u8>,
    /// Lowercase hex SHA-256 thumbprint of [`Self::signer_certificate_der`].
    pub signer_sha256_hex: String,
    /// Lowercase hex SHA-1 thumbprint of [`Self::signer_certificate_der`].
    pub signer_sha1_hex: String,
    /// Subject distinguished name of the leaf signing certificate.
    pub signer_subject: String,
    /// Decoded Azure Artifact Signing identity when present on the leaf certificate.
    pub artifact_signing: Option<ArtifactSigningIdentity>,
    /// Recommended pin for this verified signer.
    pub recommended_pin: MsixRecommendedPin,
}

/// Options for pinning and trust-verifying an MSIX / AppX package via [`verify_msix_with_pins`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsixPinVerifyOptions {
    /// Allowed leaf certificate thumbprints.
    ///
    /// Accepts lowercase/uppercase hex with optional `:`, `-`, or whitespace separators and an
    /// optional `sha256:` / `sha-256:` / `sha1:` / `sha-1:` prefix. 64 hex digits match SHA-256;
    /// 40 hex digits match SHA-1.
    pub expected_cert_thumbprints: Vec<String>,
    /// Allowed Azure Artifact Signing publisher IDs (exact dotted-decimal string match).
    pub expected_artifact_signing_publisher_ids: Vec<String>,
    /// Explicit trusted CA / subscriber root files (PEM or DER).
    pub trusted_ca_files: Vec<PathBuf>,
    /// Explicit trusted CA / subscriber root certificates as DER bytes.
    pub trusted_ca_der: Vec<Vec<u8>>,
    /// When `true` and [`Self::expected_cert_thumbprints`] is non-empty with no explicit
    /// `trusted_ca_*`, allows a thumbprint-matched leaf certificate to satisfy trust when
    /// standard CA trust fails, provided the leaf is currently valid or covered by a trusted
    /// RFC 3161 timestamp.
    pub allow_pinned_leaf_trust: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedThumbprintPin {
    Sha256(String),
    Sha1(String),
}

impl ParsedThumbprintPin {
    fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let lower = trimmed.to_ascii_lowercase();
        let (forced_kind, rest) = if let Some(s) = lower
            .strip_prefix("sha256:")
            .or_else(|| lower.strip_prefix("sha-256:"))
        {
            (Some("sha256"), s)
        } else if let Some(s) = lower
            .strip_prefix("sha1:")
            .or_else(|| lower.strip_prefix("sha-1:"))
        {
            (Some("sha1"), s)
        } else {
            (None, lower.as_str())
        };

        let mut hex = String::with_capacity(rest.len());
        for ch in rest.chars() {
            if matches!(ch, ':' | '-') || ch.is_ascii_whitespace() {
                continue;
            }
            if !ch.is_ascii_hexdigit() {
                bail!(
                    "invalid certificate thumbprint pin {raw:?}: contains non-hex character {ch:?}"
                );
            }
            hex.push(ch);
        }

        match (forced_kind, hex.len()) {
            (Some("sha256") | None, 64) => Ok(Self::Sha256(hex)),
            (Some("sha1") | None, 40) => Ok(Self::Sha1(hex)),
            (Some("sha256"), n) => {
                bail!(
                    "invalid SHA-256 certificate thumbprint pin {raw:?}: expected 64 hex digits, got {n}"
                )
            }
            (Some("sha1"), n) => {
                bail!(
                    "invalid SHA-1 certificate thumbprint pin {raw:?}: expected 40 hex digits, got {n}"
                )
            }
            (None, n) => {
                bail!(
                    "invalid certificate thumbprint pin {raw:?}: expected 64 (SHA-256) or 40 (SHA-1) hex digits, got {n}"
                )
            }
            _ => unreachable!(),
        }
    }

    fn matches(&self, sha256_hex: &str, sha1_hex: &str) -> bool {
        match self {
            Self::Sha256(expected) => expected == sha256_hex,
            Self::Sha1(expected) => expected == sha1_hex,
        }
    }
}

fn ensure_single_msix_signer(pkcs7: &[u8]) -> Result<()> {
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7);
    let sd = parse_pkcs7_signed_data_der(&normalized)?;
    if sd.signer_infos.0.len() != 1 {
        bail!("MSIX signature must contain exactly one signer");
    }
    Ok(())
}

/// Verify package integrity and the embedded CMS signature without evaluating certificate trust
/// or validity. Returns the DER-encoded signing certificate, which must be subject to the caller's
/// publisher policy. This is not a trust verification.
///
/// The signer must have the code-signing EKU. Cryptographic algorithms are those accepted by
/// the portable trust verifier, including its RSA/SHA-256 CMS fallback.
///
/// # Errors
///
/// Returns an error for malformed or tampered packages, invalid signatures, unsupported
/// algorithms, ambiguous signers, or a signer without the code-signing EKU.
pub fn verify_msix_signature_without_trust(data: &[u8], extension: &str) -> Result<Vec<u8>> {
    let (pkcs7, digest) = msix_verified_signature(data, extension)?;
    verify_msix_pkcs7_without_trust(&pkcs7, &digest)
}

fn verify_msix_pkcs7_without_trust(pkcs7: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7);
    let sd = parse_pkcs7_signed_data_der(&normalized)?;
    let signers = sd.signer_infos.0.as_slice();
    let [signer] = signers else {
        bail!("MSIX signature must contain exactly one signer");
    };
    let cert = signed_data_certificate_for_signer_identifier(&sd, &signer.sid)?;
    if !crate::trust_pkcs7::x509_cert_has_code_signing_eku(cert)? {
        bail!("MSIX signing certificate lacks code-signing extended key usage");
    }

    match AuthenticodeSignature::from_der(&normalized) {
        Ok(sig) => sig
            .authenticode_verifier()
            .require_basic_authenticode_validation(digest.to_vec())
            .ignore_chain_check()
            .ignore_signing_certificate_check()
            .verify()
            .map_err(|e| anyhow!("MSIX Authenticode signature validation: {e}"))?,
        Err(_) => {
            verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
                &sd, 0, digest,
            )
            .context("MSIX CMS signature validation")?;
        }
    }
    cert.to_der().context("encode MSIX signer certificate")
}

/// Select OS trust anchors or a pinned automatic AuthRoot cache when no anchors are configured.
///
/// Without an independently obtained CAB SHA-256 pin, loads system TLS CA certificates rather
/// than the CLI's unauthenticated HTTP AuthRoot. System TLS roots do not imply Windows
/// Authenticode policy equivalence. With a pin, resolves the CLI's AuthRoot cache and verifies
/// the pin during trust verification. Explicit CA files, DER certificates, directories, or CABs
/// are retained. The cache resolution reports any stale-cache fallback and its refresh error.
///
/// # Errors
///
/// Returns an error if system roots or pinned AuthRoot cannot be loaded.
pub fn msix_options_with_auto_authroot(
    opts: &TrustVerifyPeOptions,
) -> Result<(
    TrustVerifyPeOptions,
    Option<crate::authroot_cache::AuthRootCacheResolution>,
)> {
    let mut resolved = opts.clone();
    let cache = if resolved.artifact_signing.is_none()
        && resolved.authroot_cab.is_none()
        && resolved.anchor_dir.is_none()
        && resolved.trusted_ca_files.is_empty()
        && resolved.trusted_ca_der.is_empty()
    {
        if resolved.expect_authroot_cab_sha256.is_some() {
            crate::authroot_cache::get_or_download_authroot_cab_from_env()?
        } else {
            let roots = rustls_native_certs::load_native_certs();
            if !roots.errors.is_empty() {
                bail!("failed to load system trust anchors: {:?}", roots.errors);
            }
            if roots.certs.is_empty() {
                bail!("system trust store contains no certificates");
            }
            resolved.trusted_ca_der = roots.certs.into_iter().map(|cert| cert.to_vec()).collect();
            resolved.online.enable_aia = true;
            None
        }
    } else {
        None
    };
    if let Some(cache) = &cache {
        resolved.authroot_cab = Some(cache.path.clone());
    }
    if resolved.authroot_cab.is_some() {
        resolved.online.enable_aia = true;
    }
    Ok((resolved, cache))
}

/// Trust-verify at the current time, falling back to a cryptographically trusted RFC 3161
/// timestamp if current-time validation fails. This does not resolve automatic AuthRoot; use
/// [`msix_options_with_auto_authroot`] first when CLI-like automatic anchors are desired.
///
/// # Errors
///
/// Returns an error if neither current-time verification nor trusted-timestamp verification
/// succeeds, or if an explicit verification time or Artifact Signing policy is supplied.
pub fn trust_verify_msix_current_or_timestamp(
    data: &[u8],
    extension: &str,
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    current_or_timestamp(opts, |opts| trust_verify_msix_bytes(data, extension, opts))
}

fn current_or_timestamp<T>(
    opts: &TrustVerifyPeOptions,
    mut verify: impl FnMut(&TrustVerifyPeOptions) -> Result<T>,
) -> Result<T> {
    if opts.verification_instant_override.is_some() || opts.artifact_signing.is_some() {
        bail!(
            "current-or-timestamp verification cannot use an explicit instant or Artifact Signing policy"
        );
    }
    let mut current = opts.clone();
    current.policy.prefer_timestamp_signing_time = false;
    current.policy.require_valid_timestamp = false;
    match verify(&current) {
        Ok(report) => Ok(report),
        Err(current_error) => {
            current.policy.prefer_timestamp_signing_time = true;
            current.policy.require_valid_timestamp = true;
            verify(&current).map_err(|timestamp_error| {
                anyhow!(
                    "MSIX current-time verification failed: {current_error:#}; trusted-timestamp verification failed: {timestamp_error:#}"
                )
            })
        }
    }
}

/// Trust-verify a cleartext `.msix` / `.appx` / `.msixbundle` / `.appxbundle` package.
///
/// `extension` is the package extension without the dot. The APPX `messageDigest` blob
/// (AXPC/AXCD/AXCT/AXBM[/AXCI]) is recomputed and compared before the PKCS#7 trust step.
///
/// # Errors
///
/// Returns an error if the package digest check, single-signer requirement, CMS signature,
/// or certificate trust verification fails.
pub fn trust_verify_msix_bytes(
    data: &[u8],
    extension: &str,
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let (pkcs7, digest) = msix_verified_signature(data, extension)?;
    ensure_single_msix_signer(&pkcs7)?;
    let mut report = TrustVerifyPeReport::new(&anchors);
    verify_pkcs7_entry(
        &pkcs7,
        0,
        &digest,
        Pkcs7DigestBinding::AuthenticodeIndirect,
        &anchors,
        &anchor_certs,
        opts,
        &mut report,
    )?;
    Ok(report)
}

fn utc_date_to_system_time(d: &UtcDate) -> Result<SystemTime> {
    let month = time::Month::try_from(d.month())
        .map_err(|_| anyhow!("invalid timestamp month {}", d.month()))?;
    let date = time::Date::from_calendar_date(i32::from(d.year()), month, d.day())
        .map_err(|e| anyhow!("invalid timestamp date: {e}"))?;
    let clock = time::Time::from_hms(d.hour(), d.minute(), d.second())
        .map_err(|e| anyhow!("invalid timestamp time: {e}"))?;
    Ok(SystemTime::from(time::OffsetDateTime::new_utc(date, clock)))
}

fn verify_pinned_leaf_validity(pkcs7: &[u8], signer: &Certificate) -> Result<()> {
    let not_before = signer.tbs_certificate.validity.not_before.to_system_time();
    let not_after = signer.tbs_certificate.validity.not_after.to_system_time();
    let now = SystemTime::now();
    if now >= not_before && now <= not_after {
        return Ok(());
    }

    let mut tsa_anchors = AnchorStore::empty();
    let mut tsa_certs = public_trust_anchor_certs()?;
    tsa_anchors.merge_cert_thumbprints(&tsa_certs)?;
    if let Ok((sys_opts, _)) = msix_options_with_auto_authroot(&TrustVerifyPeOptions::default())
        && let Ok((sys_anchors, sys_certs)) = load_trust_material(&sys_opts)
    {
        tsa_anchors.merge_cert_thumbprints(&sys_certs)?;
        let _ = sys_anchors;
        tsa_certs.extend(sys_certs);
    }

    let online = OnlineTrustOptions {
        enable_aia: true,
        ..Default::default()
    };
    let ts_date = trusted_utc_date_from_authenticode_timestamp_token(
        pkcs7,
        &tsa_anchors,
        &tsa_certs,
        &online,
        false,
    )
    .context("pinned MSIX signer certificate is expired or not yet valid; trusted timestamp check failed")?;
    let Some(ts_date) = ts_date else {
        bail!(
            "pinned MSIX signer certificate is not valid at current time (not_before={}, not_after={}) and has no trusted RFC 3161 timestamp",
            signer.tbs_certificate.validity.not_before,
            signer.tbs_certificate.validity.not_after
        );
    };
    let ts_time = utc_date_to_system_time(&ts_date)?;
    if ts_time < not_before || ts_time > not_after {
        bail!(
            "pinned MSIX signer certificate was not valid at timestamp time (not_before={}, not_after={})",
            signer.tbs_certificate.validity.not_before,
            signer.tbs_certificate.validity.not_after
        );
    }
    Ok(())
}

/// Verify an MSIX / AppX package and enforce optional certificate thumbprint and Azure Artifact
/// Signing publisher ID pins.
///
/// Always verifies package digests, single-signer CMS signature, and Code Signing EKU over
/// `data` before evaluating pins and trust.
///
/// # Errors
///
/// Returns an error for malformed pin values, tampered or invalid MSIX signatures, pin
/// mismatches, untrusted certificate chains, or expired untimestamped certificates.
pub fn verify_msix_with_pins(
    data: &[u8],
    extension: &str,
    opts: &MsixPinVerifyOptions,
) -> Result<MsixVerifiedSigner> {
    let parsed_thumbprints: Vec<ParsedThumbprintPin> = opts
        .expected_cert_thumbprints
        .iter()
        .map(|s| ParsedThumbprintPin::parse(s))
        .collect::<Result<_>>()?;
    let expected_publisher_ids: Vec<String> = opts
        .expected_artifact_signing_publisher_ids
        .iter()
        .map(|id| {
            let trimmed = id.trim();
            if trimmed.is_empty() {
                bail!("expected Artifact Signing publisher ID cannot be empty");
            }
            Ok(trimmed.to_owned())
        })
        .collect::<Result<_>>()?;

    let (pkcs7, digest) = msix_verified_signature(data, extension)?;
    let signer_certificate_der = verify_msix_pkcs7_without_trust(&pkcs7, &digest)?;
    let signer_sha256_hex = cert_der_sha256_hex(&signer_certificate_der);
    let signer_sha1_hex = cert_der_sha1_hex(&signer_certificate_der);
    let x509_signer = Certificate::from_der(&signer_certificate_der)
        .map_err(|e| anyhow!("decode MSIX signer certificate: {e}"))?;
    let signer_subject = subject_display(&x509_signer);
    let artifact_signing = artifact_signing_identity_from_certificate(&x509_signer)?;
    if matches!(
        &artifact_signing,
        Some(id) if id.kind == ArtifactSigningCertificateKind::PrivateTrustCiPolicy
    ) {
        bail!("Private Trust CI Policy certificates sign WDAC policies, not Authenticode code");
    }

    if !parsed_thumbprints.is_empty()
        && !parsed_thumbprints
            .iter()
            .any(|pin| pin.matches(&signer_sha256_hex, &signer_sha1_hex))
    {
        bail!(
            "MSIX signer certificate thumbprint (sha256={signer_sha256_hex}, sha1={signer_sha1_hex}) does not match any expected pin"
        );
    }

    let has_explicit_ca = !opts.trusted_ca_files.is_empty() || !opts.trusted_ca_der.is_empty();
    let is_public_trust_as = matches!(
        &artifact_signing,
        Some(id)
            if id.kind == ArtifactSigningCertificateKind::PublicTrust
                && id.has_public_trust_marker
                && id.has_code_signing_eku
    );
    let is_private_or_test_as = matches!(
        &artifact_signing,
        Some(id)
            if matches!(
                id.kind,
                ArtifactSigningCertificateKind::PrivateTrust
                    | ArtifactSigningCertificateKind::PublicTrustTest
            ) && id.has_code_signing_eku
    );

    let artifact_signing_verified = if !expected_publisher_ids.is_empty() {
        let Some(identity) = &artifact_signing else {
            bail!(
                "MSIX signer certificate {signer_subject:?} has no Artifact Signing identity EKU"
            );
        };
        let require_timestamp =
            !has_explicit_ca || identity.kind == ArtifactSigningCertificateKind::PublicTrust;
        let policy = ArtifactSigningPolicy {
            expected_publisher_ids,
            private_trust_root_files: opts.trusted_ca_files.clone(),
            private_trust_root_der: opts.trusted_ca_der.clone(),
            require_timestamp,
        };
        let trust_opts = TrustVerifyPeOptions {
            artifact_signing: Some(policy),
            ..Default::default()
        };
        trust_verify_msix_bytes(data, extension, &trust_opts)?;
        true
    } else if !parsed_thumbprints.is_empty() {
        if has_explicit_ca {
            let trust_opts = TrustVerifyPeOptions {
                trusted_ca_files: opts.trusted_ca_files.clone(),
                trusted_ca_der: opts.trusted_ca_der.clone(),
                ..Default::default()
            };
            trust_verify_msix_current_or_timestamp(data, extension, &trust_opts)?;
            false
        } else {
            let standard_result = if is_public_trust_as {
                let trust_opts = TrustVerifyPeOptions {
                    artifact_signing: Some(ArtifactSigningPolicy::default()),
                    ..Default::default()
                };
                trust_verify_msix_bytes(data, extension, &trust_opts).map(|_| true)
            } else {
                msix_options_with_auto_authroot(&TrustVerifyPeOptions::default())
                    .and_then(|(resolved, _)| {
                        trust_verify_msix_current_or_timestamp(data, extension, &resolved)
                    })
                    .map(|_| false)
            };
            match standard_result {
                Ok(as_verified) => as_verified,
                Err(standard_err) if opts.allow_pinned_leaf_trust => {
                    verify_pinned_leaf_validity(&pkcs7, &x509_signer).with_context(|| {
                        format!(
                            "standard trust failed ({standard_err:#}) and pinned leaf validity check failed"
                        )
                    })?;
                    false
                }
                Err(standard_err) => return Err(standard_err),
            }
        }
    } else if has_explicit_ca {
        if is_private_or_test_as {
            let policy = ArtifactSigningPolicy {
                expected_publisher_ids: Vec::new(),
                private_trust_root_files: opts.trusted_ca_files.clone(),
                private_trust_root_der: opts.trusted_ca_der.clone(),
                require_timestamp: false,
            };
            let trust_opts = TrustVerifyPeOptions {
                artifact_signing: Some(policy),
                ..Default::default()
            };
            trust_verify_msix_bytes(data, extension, &trust_opts)?;
            true
        } else {
            let trust_opts = TrustVerifyPeOptions {
                trusted_ca_files: opts.trusted_ca_files.clone(),
                trusted_ca_der: opts.trusted_ca_der.clone(),
                ..Default::default()
            };
            trust_verify_msix_current_or_timestamp(data, extension, &trust_opts)?;
            false
        }
    } else if is_public_trust_as {
        let trust_opts = TrustVerifyPeOptions {
            artifact_signing: Some(ArtifactSigningPolicy::default()),
            ..Default::default()
        };
        trust_verify_msix_bytes(data, extension, &trust_opts)?;
        true
    } else {
        let (resolved, _) = msix_options_with_auto_authroot(&TrustVerifyPeOptions::default())?;
        trust_verify_msix_current_or_timestamp(data, extension, &resolved)?;
        false
    };

    let recommended_pin = match (&artifact_signing, artifact_signing_verified) {
        (Some(id), true) => MsixRecommendedPin::ArtifactSigningPublisherId(id.publisher_id.clone()),
        _ => MsixRecommendedPin::CertificateSha256(signer_sha256_hex.clone()),
    };

    Ok(MsixVerifiedSigner {
        signer_certificate_der,
        signer_sha256_hex,
        signer_sha1_hex,
        signer_subject,
        artifact_signing,
        recommended_pin,
    })
}

/// Trust-verify an MSIX / AppX package and return its cryptographically bound signer details
/// with a recommended durable pin (`ArtifactSigningPublisherId` for verified Artifact Signing
/// certificates, or `CertificateSha256` otherwise).
///
/// Fails closed if the signature does not chain to a trusted root (pinned Microsoft root for
/// Public Trust Artifact Signing, supplied `trusted_ca_files`, or system CA roots).
///
/// # Errors
///
/// Returns an error if the MSIX signature is invalid, untrusted, or expired without a trusted
/// timestamp.
pub fn verify_msix_for_pinning(
    data: &[u8],
    extension: &str,
    trusted_ca_files: &[PathBuf],
) -> Result<MsixVerifiedSigner> {
    let opts = MsixPinVerifyOptions {
        trusted_ca_files: trusted_ca_files.to_vec(),
        ..Default::default()
    };
    verify_msix_with_pins(data, extension, &opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_without_trust_rejects_modified_cms_signature() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated-signed/msix/sample.msix");
        let data = std::fs::read(path).unwrap();
        let (mut pkcs7, digest) = msix_verified_signature(&data, "msix").unwrap();
        verify_msix_pkcs7_without_trust(&pkcs7, &digest).expect("valid CMS signature");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).unwrap();
        let signature = sd.signer_infos.0.as_slice()[0].signature.as_bytes();
        let offset = pkcs7
            .windows(signature.len())
            .position(|w| w == signature)
            .unwrap();
        pkcs7[offset] ^= 1;
        assert!(verify_msix_pkcs7_without_trust(&pkcs7, &digest).is_err());
    }

    #[test]
    fn current_or_timestamp_requires_trusted_fallback() {
        let mut calls = Vec::new();
        let result = current_or_timestamp(&TrustVerifyPeOptions::default(), |opts| {
            calls.push((
                opts.policy.prefer_timestamp_signing_time,
                opts.policy.require_valid_timestamp,
            ));
            if calls.len() == 1 {
                bail!("expired")
            }
            Ok("timestamp verified")
        });
        assert_eq!(result.unwrap(), "timestamp verified");
        assert_eq!(calls, [(false, false), (true, true)]);

        let err = current_or_timestamp(&TrustVerifyPeOptions::default(), |opts| -> Result<()> {
            if opts.policy.require_valid_timestamp {
                bail!("untrusted timestamp")
            }
            bail!("expired")
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("untrusted timestamp"));
    }

    #[test]
    fn current_or_timestamp_does_not_require_timestamp_for_current_signature() {
        let mut count = 0;
        let result = current_or_timestamp(&TrustVerifyPeOptions::default(), |opts| {
            count += 1;
            assert!(!opts.policy.prefer_timestamp_signing_time);
            assert!(!opts.policy.require_valid_timestamp);
            Ok(())
        });
        assert!(result.is_ok());
        assert_eq!(count, 1);
    }

    #[test]
    fn thumbprint_pin_parser_normalizes_and_validates() {
        let sha256 = "ab".repeat(32);
        let sha1 = "cd".repeat(20);

        assert_eq!(
            ParsedThumbprintPin::parse(&sha256).unwrap(),
            ParsedThumbprintPin::Sha256(sha256.clone())
        );
        assert_eq!(
            ParsedThumbprintPin::parse(&format!("SHA256: {}", "AB:".repeat(31) + "AB")).unwrap(),
            ParsedThumbprintPin::Sha256(sha256.clone())
        );
        assert_eq!(
            ParsedThumbprintPin::parse(&format!("sha-256:{}", "ab-".repeat(31) + "ab")).unwrap(),
            ParsedThumbprintPin::Sha256(sha256.clone())
        );
        assert_eq!(
            ParsedThumbprintPin::parse(&format!("sha1: {}", "CD ".repeat(20))).unwrap(),
            ParsedThumbprintPin::Sha1(sha1.clone())
        );
        assert_eq!(
            ParsedThumbprintPin::parse(&format!("SHA-1:{sha1}")).unwrap(),
            ParsedThumbprintPin::Sha1(sha1.clone())
        );

        assert!(ParsedThumbprintPin::parse("").is_err());
        assert!(ParsedThumbprintPin::parse("not-hex").is_err());
        assert!(ParsedThumbprintPin::parse(&format!("sha256:{sha1}")).is_err());
        assert!(ParsedThumbprintPin::parse(&format!("sha1:{sha256}")).is_err());
        assert!(ParsedThumbprintPin::parse("aabbcc").is_err());
    }
}
