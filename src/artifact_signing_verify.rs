//! `psign-tool verify --artifact-signing…`: Azure Artifact Signing policy shared by both tool modes.
//!
//! Windows mode runs this after `WinVerifyTrust` succeeds; portable mode runs it instead of the
//! generic AuthRoot trust. Either way the same `psign-authenticode-trust` entry points evaluate
//! the signature, so both modes accept and reject exactly the same files.

use crate::cli::{PortableRevocationMode, VerifyArgs};
use anyhow::{Context, Result, anyhow};
use psign_authenticode_trust::policy::{OnlineTrustOptions, RevocationMode};
use psign_authenticode_trust::{
    ArtifactSigningPolicy, TrustVerifyPeOptions, TrustVerifyPeReport, parse_verification_date_ymd,
    trust_verify_catalog_bytes, trust_verify_detached_bytes, trust_verify_path,
};
use std::fmt::Write as _;
use std::path::Path;

/// NuGet / VSIX packages: signed with CMS or XMLDSig inside a ZIP, with no Windows SIP, so
/// `WinVerifyTrust` cannot evaluate them and Windows mode relies on the shared check alone.
pub fn is_package_without_windows_sip(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "nupkg" | "snupkg" | "vsix"))
}

/// `true` when any `--artifact-signing*` option was given.
pub fn requested(args: &VerifyArgs) -> bool {
    args.artifact_signing
        || !args.artifact_signing_publisher_id.is_empty()
        || !args.artifact_signing_private_trust_root.is_empty()
        || args.artifact_signing_allow_missing_timestamp
}

/// Reject options that would widen or contradict the Artifact Signing policy.
pub fn validate(args: &VerifyArgs) -> Result<()> {
    let conflicts = [
        (args.anchor_dir.is_some(), "--anchor-dir"),
        (!args.trusted_ca.is_empty(), "--trusted-ca"),
        (
            !args.additional_trusted_ca.is_empty(),
            "--additional-trusted-ca",
        ),
        (args.authroot_cab.is_some(), "--authroot-cab"),
        (
            args.expect_authroot_cab_sha256.is_some(),
            "--expect-authroot-cab-sha256",
        ),
        (args.allow_loose_signing_cert, "--allow-loose-signing-cert"),
        (args.catalog_search.is_some(), "--catalog-search"),
        (
            args.catalog_database_guid.is_some(),
            "--catalog-database-guid",
        ),
        (args.kernel_policy, "--kernel-policy"),
    ];
    if let Some((_, flag)) = conflicts.iter().find(|(set, _)| *set) {
        return Err(anyhow!(
            "{flag} cannot be combined with --artifact-signing: Artifact Signing pins its own roots \
             (use --artifact-signing-private-trust-root for Private Trust)"
        ));
    }
    Ok(())
}

fn trust_options(args: &VerifyArgs) -> Result<TrustVerifyPeOptions> {
    Ok(TrustVerifyPeOptions {
        verification_instant_override: args
            .as_of
            .as_deref()
            .map(parse_verification_date_ymd)
            .transpose()?,
        verbose_chain: args.verbose_chain,
        online: OnlineTrustOptions {
            enable_aia: args.online_aia,
            aia_url_override: args.aia_url_override.clone(),
            enable_ocsp: args.online_ocsp,
            ocsp_url_override: args.ocsp_url_override.clone(),
            revocation_mode: match args.revocation_mode {
                None | Some(PortableRevocationMode::Off) => RevocationMode::Off,
                Some(PortableRevocationMode::BestEffort) => RevocationMode::BestEffort,
                Some(PortableRevocationMode::Require) => RevocationMode::Require,
            },
            crl_url_override: args.crl_url_override.clone(),
            timeout: std::time::Duration::from_secs(args.online_timeout_secs),
            max_download_bytes: args.online_max_download_bytes,
        },
        artifact_signing: Some(ArtifactSigningPolicy {
            expected_publisher_ids: args.artifact_signing_publisher_id.clone(),
            private_trust_root_files: args.artifact_signing_private_trust_root.clone(),
            require_timestamp: !args.artifact_signing_allow_missing_timestamp,
        }),
        ..Default::default()
    })
}

fn append_report(out: &mut String, path: &Path, report: &TrustVerifyPeReport) {
    let _ = writeln!(out, "Artifact Signing verified: {}", path.display());
    for sig in &report.artifact_signing {
        let _ = writeln!(out, "  {sig}");
    }
}

/// Verify every verify target as an Artifact Signing signature; returns report text.
///
/// Detached (`--detached-pkcs7`) checks the PKCS#7 against its content; `--catalog` checks the
/// catalog signature (member hashes are left to the caller's normal catalog verification).
pub fn verify_targets(args: &VerifyArgs) -> Result<String> {
    validate(args)?;
    let opts = trust_options(args)?;
    let mut out = String::new();
    if let Some(signature) = &args.detached_pkcs7 {
        let content_path = args
            .detached_pkcs7_content
            .as_ref()
            .or(args.files.first())
            .ok_or_else(|| anyhow!("--detached-pkcs7 requires a content file"))?;
        let content = std::fs::read(content_path)
            .with_context(|| format!("read {}", content_path.display()))?;
        let pkcs7 =
            std::fs::read(signature).with_context(|| format!("read {}", signature.display()))?;
        let report = trust_verify_detached_bytes(&content, &pkcs7, &opts)
            .with_context(|| format!("Artifact Signing {}", signature.display()))?;
        append_report(&mut out, signature, &report);
    } else if let Some(catalog) = &args.catalog {
        let bytes =
            std::fs::read(catalog).with_context(|| format!("read {}", catalog.display()))?;
        let report = trust_verify_catalog_bytes(&bytes, &opts)
            .with_context(|| format!("Artifact Signing {}", catalog.display()))?;
        append_report(&mut out, catalog, &report);
    } else {
        for path in &args.files {
            let report = trust_verify_path(path, &opts)
                .with_context(|| format!("Artifact Signing {}", path.display()))?;
            append_report(&mut out, path, &report);
        }
    }
    Ok(out)
}
