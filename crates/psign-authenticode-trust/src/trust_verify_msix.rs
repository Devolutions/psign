//! MSIX / AppX (and bundle) Authenticode trust: APPX SIP digest + PKCS#7 chain.

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
use anyhow::{Context, Result, anyhow, bail};
use der::Encode;
use picky::x509::pkcs7::authenticode::AuthenticodeSignature;
use psign_sip_digest::msix_digest::msix_verified_signature;
use psign_sip_digest::pkcs7::{
    parse_pkcs7_signed_data_der, signed_data_certificate_for_signer_identifier,
    verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature,
};
use psign_sip_digest::pkcs7_wire::normalize_pkcs7_der_for_authenticode;

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
pub fn trust_verify_msix_bytes(
    data: &[u8],
    extension: &str,
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let (pkcs7, digest) = msix_verified_signature(data, extension)?;
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
}
