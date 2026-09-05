use crate::CommandOutput;
use crate::cli::{AzureCredentialType, DigestAlgorithm, GlobalOpts, SignArgs, SignExitCodes};
use crate::{AZURE_SIGN_EXIT_ALL_FAILED, AZURE_SIGN_EXIT_PARTIAL_SUCCESS};
use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;
use glob::glob;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
#[cfg(feature = "artifact-signing-rest")]
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

#[cfg(feature = "artifact-signing-rest")]
#[derive(Debug, Deserialize)]
#[allow(non_snake_case, dead_code)]
struct ArtifactSigningMetadataDoc {
    Endpoint: String,
    CodeSigningAccountName: String,
    CertificateProfileName: String,
    #[serde(default)]
    CorrelationId: Option<String>,
    #[serde(default)]
    ExcludeCredentials: Option<Vec<String>>,
}

pub fn sign_file(args: &SignArgs, _global: &GlobalOpts) -> Result<CommandOutput> {
    if artifact_signing_requested(args) && azure_key_vault_requested(args) {
        return Err(anyhow!(
            "portable sign accepts either Azure Artifact Signing or Azure Key Vault options, not both"
        ));
    }
    if artifact_signing_requested(args) {
        return sign_file_artifact_signing(args);
    }
    if azure_key_vault_requested(args) {
        return sign_file_azure_key_vault(args);
    }
    validate_supported_options(args)?;
    let targets = expand_sign_targets(args)?;
    if targets.is_empty() {
        return Err(anyhow!("portable sign requires at least one file"));
    }

    let identity = args
        .pfx
        .is_none()
        .then(|| {
            let thumbprint = args.cert_sha1.as_deref().ok_or_else(|| {
                anyhow!("portable sign requires --sha1 <thumbprint> without --pfx")
            })?;
            crate::cert_store::resolve_signing_identity(
                args.cert_store_dir.as_deref(),
                args.machine_store,
                &args.store_name,
                thumbprint,
            )
        })
        .transpose()?;

    execute_sign_batch(args, &targets, |target| {
        try_sign_one_local(target, args, identity.as_ref())
    })
}

fn sign_file_artifact_signing(args: &SignArgs) -> Result<CommandOutput> {
    validate_artifact_signing_supported_options(args)?;
    let targets = expand_sign_targets(args)?;
    if targets.is_empty() {
        return Err(anyhow!(
            "portable Artifact Signing sign requires at least one file"
        ));
    }

    execute_sign_batch(args, &targets, |target| {
        try_sign_one_artifact_signing(target, args)
    })
}

fn sign_file_azure_key_vault(args: &SignArgs) -> Result<CommandOutput> {
    validate_azure_key_vault_supported_options(args)?;
    let targets = expand_sign_targets(args)?;
    if targets.is_empty() {
        return Err(anyhow!(
            "portable Azure Key Vault sign requires at least one file"
        ));
    }

    execute_sign_batch(args, &targets, |target| {
        try_sign_one_azure_key_vault(target, args)
    })
}

fn execute_sign_batch<F>(args: &SignArgs, targets: &[PathBuf], sign_one: F) -> Result<CommandOutput>
where
    F: Fn(&Path) -> Result<String> + Sync,
{
    let parallel = args.max_degree_parallelism != Some(1)
        && targets.len() > 1
        && !has_duplicate_target_identities(targets);
    let threads = args
        .max_degree_parallelism
        .unwrap_or_else(rayon::current_num_threads);
    let rows: Vec<(usize, Result<String>)> = if parallel {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads.max(1))
            .build()
            .map_err(|e| anyhow!("thread pool: {e}"))?;
        pool.install(|| {
            targets
                .par_iter()
                .enumerate()
                .map(|(idx, target)| (idx, sign_one(target)))
                .collect()
        })
    } else {
        targets
            .iter()
            .enumerate()
            .map(|(idx, target)| (idx, sign_one(target)))
            .collect()
    };

    let mut ordered = rows;
    ordered.sort_by_key(|(idx, _)| *idx);
    let mut combined = String::new();
    let mut successes = 0;
    let mut failures = 0;
    for (position, (idx, result)) in ordered.into_iter().enumerate() {
        if position > 0 {
            combined.push('\n');
        }
        match result {
            Ok(block) => {
                successes += 1;
                combined.push_str(&block);
            }
            Err(error) if args.continue_on_error => {
                failures += 1;
                combined.push_str(&format!("Failed: {}: {error:#}\n", targets[idx].display()));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(CommandOutput::with_exit(
        combined,
        batch_exit_code(resolved_sign_exit_codes(args), successes, failures),
    ))
}

fn validate_supported_options(args: &SignArgs) -> Result<()> {
    match args.digest {
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512 => {}
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => {
            return Err(anyhow!(
                "portable sign supports only --fd SHA256, SHA384, or SHA512, got {}",
                args.digest.as_signtool_name()
            ));
        }
    }
    if args.pfx.is_some() && args.cert_sha1.is_some() {
        return Err(anyhow!(
            "portable sign accepts either --f/--pfx or --sha1 certificate-store material, not both"
        ));
    }
    if args.password.is_some() && args.pfx.is_none() {
        return Err(anyhow!(
            "portable sign accepts --p/--password only together with --f/--pfx"
        ));
    }
    reject_bool_option("--a/--auto-select", args.auto_select)?;
    reject_string_option("--n/--subject-name", &args.subject_name)?;
    reject_string_option("--i/--issuer-name", &args.issuer_name)?;
    reject_string_option("--csp", &args.csp)?;
    reject_string_option("--kc/--key-container", &args.key_container)?;
    reject_bool_option("--ph/--page-hashes", args.page_hashes)?;
    reject_bool_option("--nph/--no-page-hashes", args.no_page_hashes)?;
    reject_path_option("--dlib", &args.dlib)?;
    reject_path_option("--dmdf", &args.dmdf)?;
    reject_path_option(
        "--trusted-signing-dlib-root",
        &args.trusted_signing_dlib_root,
    )?;
    if args.timestamp_url.is_some() && args.timestamp_digest.is_none() {
        return Err(anyhow!(
            "portable sign requires --td/--timestamp-digest with --tr/--timestamp-url"
        ));
    }
    if args.timestamp_url.is_none() && args.timestamp_digest.is_some() {
        return Err(anyhow!(
            "portable sign requires --tr/--timestamp-url with --td/--timestamp-digest"
        ));
    }
    reject_string_option("--t/--legacy-timestamp-url", &args.legacy_timestamp_url)?;
    reject_string_option("--tseal/--seal-timestamp-url", &args.seal_timestamp_url)?;
    reject_string_option("--d/--description", &args.description)?;
    reject_string_option("--du/--description-url", &args.description_url)?;
    reject_string_option("--r/--root-subject-name", &args.root_subject_name)?;
    reject_string_option("--u/--eku-oid", &args.eku_oid)?;
    reject_bool_option(
        "--uw/--eku-windows-system-component",
        args.eku_windows_system_component,
    )?;
    reject_string_option(
        "--signing-cert-eku-prefix",
        &args.signing_cert_eku_oid_prefix,
    )?;
    reject_path_option("--dg/--digest-generate", &args.digest_generate)?;
    reject_bool_option("--ds/--digest-sign-only", args.digest_sign_only)?;
    reject_path_option("--di/--digest-ingest", &args.digest_ingest)?;
    reject_bool_option("--dxml/--digest-xml", args.digest_xml)?;
    reject_path_option("--p7/--pkcs7-output-dir", &args.pkcs7_output_dir)?;
    reject_string_option("--p7co/--pkcs7-content-oid", &args.pkcs7_content_oid)?;
    reject_option(
        "--p7ce/--pkcs7-content-embedding",
        args.pkcs7_content_embedding.is_some(),
    )?;
    reject_string_option("--certificate-template", &args.certificate_template)?;
    reject_option("--sa/--sign-auth", !args.sign_auth_pairs.is_empty())?;
    reject_bool_option("--fdchw", args.warn_fd_digest_vs_cert_signature_hash)?;
    reject_bool_option("--tdchw", args.warn_td_digest_vs_cert_signature_hash)?;
    reject_bool_option("--rmc", args.relaxed_pe_marker_check)?;
    reject_bool_option("--seal", args.add_sealing_signature)?;
    reject_bool_option("--itos", args.intent_to_seal)?;
    reject_bool_option("--force", args.force_seal_or_resign)?;
    reject_bool_option("--nosealwarn", args.sign_no_seal_warn)?;
    reject_bool_option("--noenclavewarn", args.sign_no_enclave_warn)?;
    reject_option("--rust-sip", args.rust_sip.is_some())?;
    reject_string_option("--azure-key-vault-url", &args.azure_key_vault_url)?;
    reject_string_option(
        "--azure-key-vault-certificate",
        &args.azure_key_vault_certificate,
    )?;
    reject_string_option(
        "--azure-key-vault-certificate-version",
        &args.azure_key_vault_certificate_version,
    )?;
    reject_string_option(
        "--azure-key-vault-client-id",
        &args.azure_key_vault_client_id,
    )?;
    reject_string_option(
        "--azure-key-vault-client-secret",
        &args.azure_key_vault_client_secret,
    )?;
    reject_string_option(
        "--azure-key-vault-tenant-id",
        &args.azure_key_vault_tenant_id,
    )?;
    reject_string_option(
        "--azure-key-vault-accesstoken",
        &args.azure_key_vault_access_token,
    )?;
    reject_bool_option(
        "--azure-key-vault-managed-identity",
        args.azure_key_vault_managed_identity,
    )?;
    reject_option(
        "--azure-key-vault-credential-type",
        args.azure_key_vault_credential_type.is_some(),
    )?;
    reject_string_option("--azure-authority", &args.azure_authority)?;
    reject_artifact_signing_options(args)?;
    if args.max_degree_parallelism == Some(0) {
        return Err(anyhow!(
            "portable sign requires --max-degree-of-parallelism to be at least 1"
        ));
    }
    Ok(())
}

fn expand_glob_pattern(
    pattern: &str,
    out: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
) -> Result<()> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Ok(());
    }
    if pattern.contains('*') || pattern.contains('?') {
        for entry in glob(pattern).map_err(|e| anyhow!("{e}"))? {
            let p = entry.map_err(|e| anyhow!("{e}"))?;
            insert_sign_target(p, out, seen);
        }
    } else {
        let p = PathBuf::from(pattern);
        insert_sign_target(p, out, seen);
    }
    Ok(())
}

fn insert_sign_target(path: PathBuf, out: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>) {
    let identity = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    if seen.insert(identity) {
        out.push(path);
    }
}

fn expand_sign_targets(args: &SignArgs) -> Result<Vec<PathBuf>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    if let Some(ifl) = &args.sign_input_file_list {
        let txt = std::fs::read_to_string(ifl)
            .with_context(|| format!("read --input-file-list {}", ifl.display()))?;
        for line in txt.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            expand_glob_pattern(t, &mut out, &mut seen)?;
        }
    }
    for p in &args.files {
        let pattern = p.to_string_lossy();
        if pattern.contains('*') || pattern.contains('?') {
            expand_glob_pattern(&pattern, &mut out, &mut seen)?;
        } else {
            // Native-shaped trailing targets are operations, not a set: signing the same
            // PE twice with --append-signature intentionally adds two signatures.
            out.push(p.clone());
        }
    }
    Ok(out)
}

fn has_duplicate_target_identities(targets: &[PathBuf]) -> bool {
    let mut seen = HashSet::new();
    targets.iter().any(|target| {
        let identity = std::fs::canonicalize(target).unwrap_or_else(|_| target.clone());
        !seen.insert(identity)
    })
}

fn try_sign_one_artifact_signing(target: &Path, args: &SignArgs) -> Result<String> {
    if args.skip_signed && target_should_skip_signed(target)? {
        return Ok(format!("Skipped (already signed): {}\n", target.display()));
    }
    sign_one_target_artifact_signing(target, args)
        .with_context(|| format!("portable Artifact Signing sign '{}'", target.display()))?;
    Ok(format!(
        "Signed: {}\nartifact_signing_profile={}\n",
        target.display(),
        args.artifact_signing_profile_name
            .as_deref()
            .unwrap_or("<metadata>")
    ))
}

fn target_should_skip_signed(target: &Path) -> Result<bool> {
    let ext = target_extension_lower(target);
    match ext.as_str() {
        ext if is_pe_winmd_extension(ext) => target_has_valid_existing_pe_signature(target),
        "cab" => {
            let bytes =
                std::fs::read(target).with_context(|| format!("read '{}'", target.display()))?;
            Ok(psign_sip_digest::cab_digest::cab_signature_pkcs7_der(&bytes).is_ok())
        }
        "msi" | "msp" => {
            let bytes =
                std::fs::read(target).with_context(|| format!("read '{}'", target.display()))?;
            Ok(psign_sip_digest::msi_digest::msi_digital_signature_pkcs7_der(&bytes).is_ok())
        }
        "msix" | "appx" | "msixbundle" | "appxbundle" => {
            Ok(psign_sip_digest::msix_digest::verify_msix_digest_consistency(target).is_ok())
        }
        _ => Ok(false),
    }
}

fn validate_azure_key_vault_supported_options(args: &SignArgs) -> Result<()> {
    match args.digest {
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512 => {}
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => {
            return Err(anyhow!(
                "portable Azure Key Vault sign supports only --fd SHA256, SHA384, or SHA512, got {}",
                args.digest.as_signtool_name()
            ));
        }
    }
    reject_path_option("--f/--pfx", &args.pfx)?;
    reject_string_option("--p/--password", &args.password)?;
    reject_bool_option("--a/--auto-select", args.auto_select)?;
    reject_string_option("--n/--subject-name", &args.subject_name)?;
    reject_string_option("--i/--issuer-name", &args.issuer_name)?;
    reject_string_option("--sha1", &args.cert_sha1)?;
    reject_string_option("--csp", &args.csp)?;
    reject_string_option("--kc/--key-container", &args.key_container)?;
    reject_bool_option("--sm/--machine-store", args.machine_store)?;
    reject_option("--s/--store", args.store_name != "MY")?;
    reject_path_option("--cert-store-dir", &args.cert_store_dir)?;
    reject_bool_option("--ph/--page-hashes", args.page_hashes)?;
    reject_bool_option("--nph/--no-page-hashes", args.no_page_hashes)?;
    reject_path_option("--dlib", &args.dlib)?;
    reject_path_option(
        "--trusted-signing-dlib-root",
        &args.trusted_signing_dlib_root,
    )?;
    reject_path_option("--dmdf", &args.dmdf)?;
    reject_workload_identity(
        "--azure-key-vault-credential-type",
        args.azure_key_vault_credential_type,
    )?;
    if args.timestamp_url.is_some() && args.timestamp_digest.is_none() {
        return Err(anyhow!(
            "portable Azure Key Vault sign requires --td/--timestamp-digest with --tr/--timestamp-url"
        ));
    }
    if args.timestamp_url.is_none() && args.timestamp_digest.is_some() {
        return Err(anyhow!(
            "portable Azure Key Vault sign requires --tr/--timestamp-url with --td/--timestamp-digest"
        ));
    }
    reject_string_option("--t/--legacy-timestamp-url", &args.legacy_timestamp_url)?;
    reject_string_option("--tseal/--seal-timestamp-url", &args.seal_timestamp_url)?;
    reject_string_option("--d/--description", &args.description)?;
    reject_string_option("--du/--description-url", &args.description_url)?;
    reject_string_option("--r/--root-subject-name", &args.root_subject_name)?;
    reject_string_option("--u/--eku-oid", &args.eku_oid)?;
    reject_bool_option(
        "--uw/--eku-windows-system-component",
        args.eku_windows_system_component,
    )?;
    reject_string_option(
        "--signing-cert-eku-prefix",
        &args.signing_cert_eku_oid_prefix,
    )?;
    reject_path_option("--dg/--digest-generate", &args.digest_generate)?;
    reject_bool_option("--ds/--digest-sign-only", args.digest_sign_only)?;
    reject_path_option("--di/--digest-ingest", &args.digest_ingest)?;
    reject_bool_option("--dxml/--digest-xml", args.digest_xml)?;
    reject_path_option("--p7/--pkcs7-output-dir", &args.pkcs7_output_dir)?;
    reject_string_option("--p7co/--pkcs7-content-oid", &args.pkcs7_content_oid)?;
    reject_option(
        "--p7ce/--pkcs7-content-embedding",
        args.pkcs7_content_embedding.is_some(),
    )?;
    reject_string_option("--certificate-template", &args.certificate_template)?;
    reject_option("--sa/--sign-auth", !args.sign_auth_pairs.is_empty())?;
    reject_bool_option("--fdchw", args.warn_fd_digest_vs_cert_signature_hash)?;
    reject_bool_option("--tdchw", args.warn_td_digest_vs_cert_signature_hash)?;
    reject_bool_option("--rmc", args.relaxed_pe_marker_check)?;
    reject_bool_option("--seal", args.add_sealing_signature)?;
    reject_bool_option("--itos", args.intent_to_seal)?;
    reject_bool_option("--force", args.force_seal_or_resign)?;
    reject_bool_option("--nosealwarn", args.sign_no_seal_warn)?;
    reject_bool_option("--noenclavewarn", args.sign_no_enclave_warn)?;
    reject_option("--rust-sip", args.rust_sip.is_some())?;
    reject_artifact_signing_options(args)?;
    if args.max_degree_parallelism == Some(0) {
        return Err(anyhow!(
            "portable Azure Key Vault sign requires --max-degree-of-parallelism to be at least 1"
        ));
    }
    Ok(())
}

fn validate_artifact_signing_supported_options(args: &SignArgs) -> Result<()> {
    match args.digest {
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512 => {}
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => {
            return Err(anyhow!(
                "portable Artifact Signing sign supports only --fd SHA256, SHA384, or SHA512, got {}",
                args.digest.as_signtool_name()
            ));
        }
    }
    reject_path_option("--f/--pfx", &args.pfx)?;
    reject_string_option("--p/--password", &args.password)?;
    reject_bool_option("--a/--auto-select", args.auto_select)?;
    reject_string_option("--n/--subject-name", &args.subject_name)?;
    reject_string_option("--i/--issuer-name", &args.issuer_name)?;
    reject_string_option("--sha1", &args.cert_sha1)?;
    reject_string_option("--csp", &args.csp)?;
    reject_string_option("--kc/--key-container", &args.key_container)?;
    reject_bool_option("--sm/--machine-store", args.machine_store)?;
    reject_option("--s/--store", args.store_name != "MY")?;
    reject_path_option("--cert-store-dir", &args.cert_store_dir)?;
    reject_bool_option("--ph/--page-hashes", args.page_hashes)?;
    reject_bool_option("--nph/--no-page-hashes", args.no_page_hashes)?;
    reject_path_option("--dlib", &args.dlib)?;
    reject_path_option(
        "--trusted-signing-dlib-root",
        &args.trusted_signing_dlib_root,
    )?;
    if args.artifact_signing_metadata.is_some() && args.dmdf.is_some() {
        return Err(anyhow!(
            "use either --artifact-signing-metadata or --dmdf as Artifact Signing metadata, not both"
        ));
    }
    if args.timestamp_url.is_some() && args.timestamp_digest.is_none() {
        return Err(anyhow!(
            "portable Artifact Signing sign requires --td/--timestamp-digest with --tr/--timestamp-url"
        ));
    }
    if args.timestamp_url.is_none() && args.timestamp_digest.is_some() {
        return Err(anyhow!(
            "portable Artifact Signing sign requires --tr/--timestamp-url with --td/--timestamp-digest"
        ));
    }
    reject_string_option("--t/--legacy-timestamp-url", &args.legacy_timestamp_url)?;
    reject_string_option("--tseal/--seal-timestamp-url", &args.seal_timestamp_url)?;
    reject_string_option("--d/--description", &args.description)?;
    reject_string_option("--du/--description-url", &args.description_url)?;
    reject_string_option("--r/--root-subject-name", &args.root_subject_name)?;
    reject_string_option("--u/--eku-oid", &args.eku_oid)?;
    reject_bool_option(
        "--uw/--eku-windows-system-component",
        args.eku_windows_system_component,
    )?;
    reject_string_option(
        "--signing-cert-eku-prefix",
        &args.signing_cert_eku_oid_prefix,
    )?;
    reject_path_option("--dg/--digest-generate", &args.digest_generate)?;
    reject_bool_option("--ds/--digest-sign-only", args.digest_sign_only)?;
    reject_path_option("--di/--digest-ingest", &args.digest_ingest)?;
    reject_bool_option("--dxml/--digest-xml", args.digest_xml)?;
    reject_path_option("--p7/--pkcs7-output-dir", &args.pkcs7_output_dir)?;
    reject_string_option("--p7co/--pkcs7-content-oid", &args.pkcs7_content_oid)?;
    reject_option(
        "--p7ce/--pkcs7-content-embedding",
        args.pkcs7_content_embedding.is_some(),
    )?;
    reject_string_option("--certificate-template", &args.certificate_template)?;
    reject_option("--sa/--sign-auth", !args.sign_auth_pairs.is_empty())?;
    reject_bool_option("--fdchw", args.warn_fd_digest_vs_cert_signature_hash)?;
    reject_bool_option("--tdchw", args.warn_td_digest_vs_cert_signature_hash)?;
    reject_bool_option("--rmc", args.relaxed_pe_marker_check)?;
    reject_bool_option("--seal", args.add_sealing_signature)?;
    reject_bool_option("--itos", args.intent_to_seal)?;
    reject_bool_option("--force", args.force_seal_or_resign)?;
    reject_bool_option("--nosealwarn", args.sign_no_seal_warn)?;
    reject_bool_option("--noenclavewarn", args.sign_no_enclave_warn)?;
    reject_option("--rust-sip", args.rust_sip.is_some())?;
    if args.max_degree_parallelism == Some(0) {
        return Err(anyhow!(
            "portable Artifact Signing sign requires --max-degree-of-parallelism to be at least 1"
        ));
    }
    Ok(())
}

fn try_sign_one_local(
    target: &Path,
    args: &SignArgs,
    identity: Option<&crate::cert_store::SigningIdentity>,
) -> Result<String> {
    if args.skip_signed && target_should_skip_signed(target)? {
        return Ok(format!("Skipped (already signed): {}\n", target.display()));
    }

    let mut request = portable_sign_request(target, temporary_output_path(target), args)?;
    if let Some(pfx) = &args.pfx {
        request.pfx_path = Some(pfx.clone());
        request.pfx_password = args.password.clone();
    } else {
        let identity = identity.expect("certificate-store identity is resolved before signing");
        request.certificate_path = Some(identity.cert_path.clone());
        request.private_key_path = Some(identity.key_path.clone());
    }
    run_portable_core_sign(request, "portable sign")?;

    let mut block = format!("Signed: {}\n", target.display());
    if let Some(identity) = identity {
        block.push_str(&format!(
            "thumbprint_sha1={}\nstore={}\\{}\n",
            identity.thumbprint_sha1, identity.scope, identity.store_name
        ));
    } else {
        block.push_str(&format!(
            "pfx={}\n",
            args.pfx.as_ref().expect("PFX source is selected").display()
        ));
    }
    Ok(block)
}

fn try_sign_one_azure_key_vault(target: &Path, args: &SignArgs) -> Result<String> {
    if args.skip_signed && target_should_skip_signed(target)? {
        return Ok(format!("Skipped (already signed): {}\n", target.display()));
    }

    let mut request = portable_sign_request(target, temporary_output_path(target), args)?;
    request.azure_key_vault_url =
        text_opt(args.azure_key_vault_url.as_deref()).map(ToOwned::to_owned);
    request.azure_key_vault_certificate =
        text_opt(args.azure_key_vault_certificate.as_deref()).map(ToOwned::to_owned);
    request.azure_key_vault_certificate_version =
        text_opt(args.azure_key_vault_certificate_version.as_deref()).map(ToOwned::to_owned);
    request.azure_key_vault_access_token =
        text_opt(args.azure_key_vault_access_token.as_deref()).map(ToOwned::to_owned);
    request.azure_key_vault_client_id =
        text_opt(args.azure_key_vault_client_id.as_deref()).map(ToOwned::to_owned);
    request.azure_key_vault_client_secret =
        text_opt(args.azure_key_vault_client_secret.as_deref()).map(ToOwned::to_owned);
    request.azure_key_vault_tenant_id =
        text_opt(args.azure_key_vault_tenant_id.as_deref()).map(ToOwned::to_owned);
    request.azure_key_vault_managed_identity =
        Some(effective_azure_key_vault_managed_identity(args));
    request.azure_authority = text_opt(args.azure_authority.as_deref()).map(ToOwned::to_owned);

    run_portable_core_sign(request, "portable Azure Key Vault sign")?;
    Ok(format!(
        "Signed: {}\nazure_key_vault_certificate={}\n",
        target.display(),
        args.azure_key_vault_certificate
            .as_deref()
            .unwrap_or("<missing>")
    ))
}

fn portable_sign_request(
    target: &Path,
    output: PathBuf,
    args: &SignArgs,
) -> Result<psign_portable_core::PortableSignRequest> {
    validate_portable_core_target(target, args.append_signature)?;
    Ok(psign_portable_core::PortableSignRequest {
        path: target.to_path_buf(),
        append_signature: args.append_signature,
        skip_signed: args.skip_signed,
        output_path: Some(output),
        hash_algorithm: portable_core_digest(args.digest)?,
        chain_certificate_paths: args.additional_certs.clone(),
        timestamp_server: text_opt(args.timestamp_url.as_deref()).map(ToOwned::to_owned),
        timestamp_hash_algorithm: args
            .timestamp_digest
            .map(portable_core_timestamp_digest)
            .transpose()?,
        ..Default::default()
    })
}

fn validate_portable_core_target(
    target: &Path,
    append_signature: bool,
) -> Result<psign_portable_core::PortableFileFormat> {
    let ext = target_extension_lower(target);
    if psign_sip_digest::msix_digest::is_encrypted_msix_extension(&ext) {
        return Err(anyhow!(
            "portable signing does not support encrypted MSIX/AppX packages (.{ext}); encrypted packages require Windows AppxSip OS delegation: {}",
            target.display()
        ));
    }
    if matches!(ext.as_str(), "appxupload" | "msixupload") {
        return Err(anyhow!(
            "portable signing does not support MSIX/AppX upload bundles (.{ext}); upload containers wrap flat packages produced by `dotnet/SignTool`-style tooling and are not AppX SIP verify subjects: {}",
            target.display()
        ));
    }
    let format = psign_portable_core::infer_format(target);
    match format {
        psign_portable_core::PortableFileFormat::Catalog => {
            return Err(anyhow!(
                "portable native-shaped signing does not support catalog targets; use `psign-tool portable sign-catalog` with an explicit subject list"
            ));
        }
        psign_portable_core::PortableFileFormat::WshScript => {
            return Err(anyhow!(
                "portable native-shaped signing does not support WSH script targets (.vbs, .js, .wsf): {}",
                target.display()
            ));
        }
        psign_portable_core::PortableFileFormat::Unknown => {
            return Err(anyhow!(
                "portable native-shaped signing supports PE/WinMD, CAB, MSI/MSP, MSIX/AppX packages and bundles, NuGet, VSIX, ClickOnce manifests, App Installer, ZIP, and PowerShell scripts; got {}",
                target.display()
            ));
        }
        _ => {}
    }
    if append_signature && format != psign_portable_core::PortableFileFormat::Pe {
        return Err(anyhow!(
            "--as/--append-signature is only supported for portable PE/WinMD signing"
        ));
    }
    Ok(format)
}

fn run_portable_core_sign(
    request: psign_portable_core::PortableSignRequest,
    operation: &str,
) -> Result<()> {
    let target = request.path.clone();
    let output = request
        .output_path
        .clone()
        .expect("portable sign output is set");
    let format = validate_portable_core_target(&target, request.append_signature)?;
    let companion = (format == psign_portable_core::PortableFileFormat::AppInstaller)
        .then(|| appinstaller_companion_path(&output));
    let result = psign_portable_core::portable_sign(request)
        .map(|_| ())
        .with_context(|| format!("{operation} '{}'", target.display()))
        .and_then(|_| {
            std::fs::copy(&output, &target)
                .with_context(|| format!("replace '{}' with signed output", target.display()))?;
            if let Some(companion) = &companion {
                let target_companion = appinstaller_companion_path(&target);
                std::fs::copy(companion, &target_companion).with_context(|| {
                    format!(
                        "replace App Installer companion '{}' with '{}'",
                        target_companion.display(),
                        companion.display()
                    )
                })?;
            }
            Ok(())
        });
    let _ = std::fs::remove_file(&output);
    if let Some(companion) = companion {
        let _ = std::fs::remove_file(companion);
    }
    result
}

fn appinstaller_companion_path(path: &Path) -> PathBuf {
    path.with_extension(
        path.extension()
            .map(|extension| format!("{}.p7", extension.to_string_lossy()))
            .unwrap_or_else(|| "p7".to_string()),
    )
}

fn sign_one_target_artifact_signing(target: &Path, args: &SignArgs) -> Result<()> {
    let ext = target_extension_lower(target);
    let tmp = temporary_output_path(target);
    let result = match ext.as_str() {
        ext if is_pe_winmd_extension(ext) => run_portable_sign_pe_artifact_signing(target, &tmp, args),
        ext if is_portable_powershell_script_extension(ext) => {
            if args.append_signature {
                Err(anyhow!(
                    "--as/--append-signature is only supported for portable PE/WinMD signing"
                ))
            } else {
                run_portable_sign_script_artifact_signing(target, &tmp, args)
            }
        }
        _ if args.append_signature => Err(anyhow!(
            "--as/--append-signature is only supported for portable PE/WinMD signing"
        )),
        "cab" => run_portable_sign_cab_artifact_signing(target, &tmp, args),
        "msi" | "msp" => run_portable_sign_msi_artifact_signing(target, &tmp, args),
        "appx" | "msix" | "msixbundle" | "appxbundle" => {
            run_portable_sign_msix_artifact_signing(target, &tmp, args)
        }
        "cat" => Err(anyhow!(
            "portable Artifact Signing for catalog targets is available through `psign-tool portable sign-catalog ... --artifact-signing-*`; native-shaped in-place .cat signing needs a catalog-authenticode replacement path and is not implemented yet"
        )),
        _ => Err(anyhow!(
            "portable Artifact Signing is currently implemented for PE/WinMD, PowerShell Authenticode scripts (.ps1, .psd1, .psm1, .ps1xml, .psc1, .cdxml, .mof), CAB, MSI/MSP, and MSIX/AppX package or bundle targets; got {}",
            target.display()
        )),
    }
        .and_then(|_| {
            std::fs::copy(&tmp, target)
                .with_context(|| format!("replace '{}' with signed output", target.display()))?;
            Ok(())
        })
        .and_then(|_| {
            std::fs::remove_file(&tmp)
                .with_context(|| format!("remove temporary output '{}'", tmp.display()))
        });
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn target_extension_lower(target: &Path) -> String {
    target
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default()
}

fn is_pe_winmd_extension(ext: &str) -> bool {
    matches!(ext, "exe" | "dll" | "sys" | "ocx" | "efi" | "winmd")
}

fn is_portable_powershell_script_extension(ext: &str) -> bool {
    psign_sip_digest::ps_script::extension_supported(ext)
}

fn target_has_valid_existing_pe_signature(target: &Path) -> Result<bool> {
    let ext = target_extension_lower(target);
    if !is_pe_winmd_extension(&ext) {
        return Ok(false);
    }
    let bytes = std::fs::read(target).with_context(|| format!("read '{}'", target.display()))?;
    Ok(
        psign_sip_digest::verify_pe::verify_pe_authenticode_digest_consistency_if_signed(&bytes)
            .with_context(|| {
                format!(
                    "check existing PE/WinMD Authenticode signature on '{}'",
                    target.display()
                )
            })?
            .is_some(),
    )
}

fn run_portable_sign_pe_artifact_signing(
    target: &Path,
    output: &Path,
    args: &SignArgs,
) -> Result<()> {
    let mut argv = vec![
        OsString::from("psign-tool"),
        OsString::from("sign-pe"),
        target.as_os_str().to_os_string(),
        OsString::from("--digest"),
        OsString::from(portable_digest_name(args.digest)?),
    ];
    if args.append_signature {
        argv.push(OsString::from("--append-signature"));
    }
    for chain_cert in &args.additional_certs {
        argv.push(OsString::from("--chain-cert"));
        argv.push(chain_cert.as_os_str().to_os_string());
    }
    push_option(&mut argv, "--timestamp-url", &args.timestamp_url);
    if let Some(timestamp_digest) = args.timestamp_digest {
        argv.push(OsString::from("--timestamp-digest"));
        argv.push(OsString::from(timestamp_digest_name(timestamp_digest)?));
    }
    let metadata = args
        .artifact_signing_metadata
        .as_ref()
        .or(args.dmdf.as_ref());
    push_path_option(&mut argv, "--artifact-signing-metadata", metadata);
    push_option(
        &mut argv,
        "--artifact-signing-region",
        &args.artifact_signing_region,
    );
    push_option(
        &mut argv,
        "--artifact-signing-endpoint",
        &args.artifact_signing_endpoint,
    );
    push_option(
        &mut argv,
        "--artifact-signing-account-name",
        &args.artifact_signing_account_name,
    );
    push_option(
        &mut argv,
        "--artifact-signing-profile-name",
        &args.artifact_signing_profile_name,
    );
    push_option(
        &mut argv,
        "--artifact-signing-signature-algorithm",
        &args.artifact_signing_signature_algorithm,
    );
    push_option(
        &mut argv,
        "--artifact-signing-api-version",
        &args.artifact_signing_api_version,
    );
    push_option(
        &mut argv,
        "--artifact-signing-correlation-id",
        &args.artifact_signing_correlation_id,
    );
    push_option(
        &mut argv,
        "--artifact-signing-access-token",
        &args.artifact_signing_access_token,
    );
    if effective_artifact_signing_managed_identity(args) {
        argv.push(OsString::from("--artifact-signing-managed-identity"));
    }
    push_option(
        &mut argv,
        "--artifact-signing-managed-identity-resource-id",
        &args.artifact_signing_managed_identity_resource_id,
    );
    if let Some(value) = args.artifact_signing_credential_type {
        argv.push(OsString::from("--artifact-signing-credential-type"));
        argv.push(OsString::from(
            value.to_possible_value().unwrap().get_name(),
        ));
    }
    push_option(
        &mut argv,
        "--artifact-signing-tenant-id",
        &args.artifact_signing_tenant_id,
    );
    push_option(
        &mut argv,
        "--artifact-signing-client-id",
        &args.artifact_signing_client_id,
    );
    push_option(
        &mut argv,
        "--artifact-signing-client-secret",
        &args.artifact_signing_client_secret,
    );
    push_option(
        &mut argv,
        "--artifact-signing-federated-token-file",
        &args.artifact_signing_federated_token_file,
    );
    push_option(
        &mut argv,
        "--artifact-signing-authority",
        &args.artifact_signing_authority,
    );
    push_option(
        &mut argv,
        "--artifact-signing-endpoint-base-url",
        &args.artifact_signing_endpoint_base_url,
    );
    argv.push(OsString::from("--output"));
    argv.push(output.as_os_str().to_os_string());

    std::thread::Builder::new()
        .name("psign-portable-sign-pe-artifact".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || psign_digest_cli::run_from(argv))
        .map_err(|e| anyhow!("spawn portable Artifact Signing sign-pe runner: {e}"))?
        .join()
        .map_err(|_| anyhow!("portable Artifact Signing sign-pe runner panicked"))?
}

fn run_portable_sign_cab_artifact_signing(
    target: &Path,
    output: &Path,
    args: &SignArgs,
) -> Result<()> {
    let mut argv = vec![
        OsString::from("psign-tool"),
        OsString::from("sign-cab"),
        target.as_os_str().to_os_string(),
        OsString::from("--digest"),
        OsString::from(portable_digest_name(args.digest)?),
    ];
    for chain_cert in &args.additional_certs {
        argv.push(OsString::from("--chain-cert"));
        argv.push(chain_cert.as_os_str().to_os_string());
    }
    push_timestamp_options(&mut argv, args)?;
    push_artifact_signing_options(&mut argv, args);
    argv.push(OsString::from("--output"));
    argv.push(output.as_os_str().to_os_string());

    std::thread::Builder::new()
        .name("psign-portable-sign-cab-artifact".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || psign_digest_cli::run_from(argv))
        .map_err(|e| anyhow!("spawn portable Artifact Signing sign-cab runner: {e}"))?
        .join()
        .map_err(|_| anyhow!("portable Artifact Signing sign-cab runner panicked"))?
}

fn run_portable_sign_msi_artifact_signing(
    target: &Path,
    output: &Path,
    args: &SignArgs,
) -> Result<()> {
    let mut argv = vec![
        OsString::from("psign-tool"),
        OsString::from("sign-msi"),
        target.as_os_str().to_os_string(),
        OsString::from("--digest"),
        OsString::from(portable_digest_name(args.digest)?),
    ];
    for chain_cert in &args.additional_certs {
        argv.push(OsString::from("--chain-cert"));
        argv.push(chain_cert.as_os_str().to_os_string());
    }
    push_timestamp_options(&mut argv, args)?;
    push_artifact_signing_options(&mut argv, args);
    argv.push(OsString::from("--output"));
    argv.push(output.as_os_str().to_os_string());

    std::thread::Builder::new()
        .name("psign-portable-sign-msi-artifact".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || psign_digest_cli::run_from(argv))
        .map_err(|e| anyhow!("spawn portable Artifact Signing sign-msi runner: {e}"))?
        .join()
        .map_err(|_| anyhow!("portable Artifact Signing sign-msi runner panicked"))?
}

#[cfg(feature = "artifact-signing-rest")]
fn run_portable_sign_msix_artifact_signing(
    target: &Path,
    output: &Path,
    args: &SignArgs,
) -> Result<()> {
    run_portable_sign_portable_core_artifact_signing(target, output, args, "MSIX/AppX")
}

#[cfg(feature = "artifact-signing-rest")]
fn run_portable_sign_script_artifact_signing(
    target: &Path,
    output: &Path,
    args: &SignArgs,
) -> Result<()> {
    run_portable_sign_portable_core_artifact_signing(target, output, args, "PowerShell script")
}

#[cfg(feature = "artifact-signing-rest")]
fn run_portable_sign_portable_core_artifact_signing(
    target: &Path,
    output: &Path,
    args: &SignArgs,
    target_kind: &str,
) -> Result<()> {
    let metadata = artifact_signing_metadata(args)?;
    let endpoint = text_opt(args.artifact_signing_endpoint.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| metadata.as_ref().map(|m| m.Endpoint.clone()))
        .or_else(|| {
            text_opt(args.artifact_signing_endpoint_base_url.as_deref()).map(ToOwned::to_owned)
        })
        .or_else(|| {
            text_opt(args.artifact_signing_region.as_deref())
                .map(|region| format!("https://{region}.codesigning.azure.net"))
        })
        .ok_or_else(|| {
            anyhow!(
                "portable {target_kind} Artifact Signing requires --artifact-signing-endpoint, --artifact-signing-endpoint-base-url, --artifact-signing-region, or metadata Endpoint"
            )
        })?;
    let account_name = text_opt(args.artifact_signing_account_name.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| metadata.as_ref().map(|m| m.CodeSigningAccountName.clone()))
        .ok_or_else(|| anyhow!("portable {target_kind} Artifact Signing requires --artifact-signing-account-name or metadata CodeSigningAccountName"))?;
    let profile_name = text_opt(args.artifact_signing_profile_name.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| metadata.as_ref().map(|m| m.CertificateProfileName.clone()))
        .ok_or_else(|| anyhow!("portable {target_kind} Artifact Signing requires --artifact-signing-profile-name or metadata CertificateProfileName"))?;
    let correlation_id = text_opt(args.artifact_signing_correlation_id.as_deref())
        .map(ToOwned::to_owned)
        .or_else(|| metadata.as_ref().and_then(|m| m.CorrelationId.clone()));
    if correlation_id.is_some()
        || text_present(&args.artifact_signing_signature_algorithm)
        || text_present(&args.artifact_signing_api_version)
        || text_present(&args.artifact_signing_authority)
    {
        return Err(anyhow!(
            "native-shaped portable {target_kind} Artifact Signing does not yet support correlation ID, signature-algorithm, api-version, or authority overrides"
        ));
    }

    let mut exclude_credentials = metadata
        .as_ref()
        .and_then(|m| m.ExcludeCredentials.clone())
        .unwrap_or_default();
    let credential_type = args
        .artifact_signing_credential_type
        .map(|value| value.to_possible_value().unwrap().get_name().to_string());
    let request = psign_portable_core::PortableSignRequest {
        path: target.to_path_buf(),
        output_path: Some(output.to_path_buf()),
        hash_algorithm: portable_core_digest(args.digest)?,
        chain_certificate_paths: args.additional_certs.clone(),
        timestamp_server: text_opt(args.timestamp_url.as_deref()).map(ToOwned::to_owned),
        timestamp_hash_algorithm: args
            .timestamp_digest
            .map(portable_core_timestamp_digest)
            .transpose()?,
        artifact_signing_endpoint: Some(endpoint),
        artifact_signing_account_name: Some(account_name),
        artifact_signing_profile_name: Some(profile_name),
        artifact_signing_access_token: text_opt(args.artifact_signing_access_token.as_deref())
            .map(ToOwned::to_owned),
        artifact_signing_managed_identity: Some(effective_artifact_signing_managed_identity(args)),
        artifact_signing_managed_identity_resource_id: text_opt(
            args.artifact_signing_managed_identity_resource_id
                .as_deref(),
        )
        .map(ToOwned::to_owned),
        artifact_signing_credential_type: credential_type,
        artifact_signing_tenant_id: text_opt(args.artifact_signing_tenant_id.as_deref())
            .map(ToOwned::to_owned),
        artifact_signing_client_id: text_opt(args.artifact_signing_client_id.as_deref())
            .map(ToOwned::to_owned),
        artifact_signing_client_secret: text_opt(args.artifact_signing_client_secret.as_deref())
            .map(ToOwned::to_owned),
        artifact_signing_federated_token_file: text_opt(
            args.artifact_signing_federated_token_file.as_deref(),
        )
        .map(ToOwned::to_owned),
        artifact_signing_exclude_credentials: std::mem::take(&mut exclude_credentials),
        ..Default::default()
    };
    psign_portable_core::portable_sign(request)
        .map(|_| ())
        .with_context(|| {
            format!(
                "portable Artifact Signing {target_kind} target '{}'",
                target.display()
            )
        })
}

#[cfg(not(feature = "artifact-signing-rest"))]
fn run_portable_sign_msix_artifact_signing(
    _target: &Path,
    _output: &Path,
    _args: &SignArgs,
) -> Result<()> {
    Err(anyhow!(
        "portable MSIX/AppX Artifact Signing support is not compiled into this build (feature: artifact-signing-rest)"
    ))
}

#[cfg(not(feature = "artifact-signing-rest"))]
fn run_portable_sign_script_artifact_signing(
    _target: &Path,
    _output: &Path,
    _args: &SignArgs,
) -> Result<()> {
    Err(anyhow!(
        "portable PowerShell script Artifact Signing support is not compiled into this build (feature: artifact-signing-rest)"
    ))
}

#[cfg(feature = "artifact-signing-rest")]
fn artifact_signing_metadata(args: &SignArgs) -> Result<Option<ArtifactSigningMetadataDoc>> {
    let metadata_path = args
        .artifact_signing_metadata
        .as_ref()
        .or(args.dmdf.as_ref());
    let Some(path) = metadata_path else {
        return Ok(None);
    };
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read '{}'", path.display()))?;
    let doc = serde_json::from_str::<ArtifactSigningMetadataDoc>(&text)
        .with_context(|| format!("parse Artifact Signing metadata '{}'", path.display()))?;
    Ok(Some(doc))
}

fn portable_core_digest(
    digest: crate::cli::DigestAlgorithm,
) -> Result<psign_portable_core::PortableDigestAlgorithm> {
    Ok(match digest {
        crate::cli::DigestAlgorithm::Sha256 => psign_portable_core::PortableDigestAlgorithm::Sha256,
        crate::cli::DigestAlgorithm::Sha384 => psign_portable_core::PortableDigestAlgorithm::Sha384,
        crate::cli::DigestAlgorithm::Sha512 => psign_portable_core::PortableDigestAlgorithm::Sha512,
        crate::cli::DigestAlgorithm::Sha1 | crate::cli::DigestAlgorithm::CertHash => {
            return Err(anyhow!(
                "portable signing supports SHA256, SHA384, and SHA512 file digests"
            ));
        }
    })
}

fn portable_core_timestamp_digest(
    digest: crate::cli::DigestAlgorithm,
) -> Result<psign_portable_core::PortableTimestampDigestAlgorithm> {
    Ok(match digest {
        crate::cli::DigestAlgorithm::Sha1 => {
            psign_portable_core::PortableTimestampDigestAlgorithm::Sha1
        }
        crate::cli::DigestAlgorithm::Sha256 => {
            psign_portable_core::PortableTimestampDigestAlgorithm::Sha256
        }
        crate::cli::DigestAlgorithm::Sha384 => {
            psign_portable_core::PortableTimestampDigestAlgorithm::Sha384
        }
        crate::cli::DigestAlgorithm::Sha512 => {
            psign_portable_core::PortableTimestampDigestAlgorithm::Sha512
        }
        crate::cli::DigestAlgorithm::CertHash => {
            return Err(anyhow!(
                "portable signing timestamp digest does not support certHash"
            ));
        }
    })
}

fn push_artifact_signing_options(argv: &mut Vec<OsString>, args: &SignArgs) {
    let metadata = args
        .artifact_signing_metadata
        .as_ref()
        .or(args.dmdf.as_ref());
    push_path_option(argv, "--artifact-signing-metadata", metadata);
    push_option(
        argv,
        "--artifact-signing-region",
        &args.artifact_signing_region,
    );
    push_option(
        argv,
        "--artifact-signing-endpoint",
        &args.artifact_signing_endpoint,
    );
    push_option(
        argv,
        "--artifact-signing-account-name",
        &args.artifact_signing_account_name,
    );
    push_option(
        argv,
        "--artifact-signing-profile-name",
        &args.artifact_signing_profile_name,
    );
    push_option(
        argv,
        "--artifact-signing-signature-algorithm",
        &args.artifact_signing_signature_algorithm,
    );
    push_option(
        argv,
        "--artifact-signing-api-version",
        &args.artifact_signing_api_version,
    );
    push_option(
        argv,
        "--artifact-signing-correlation-id",
        &args.artifact_signing_correlation_id,
    );
    push_option(
        argv,
        "--artifact-signing-access-token",
        &args.artifact_signing_access_token,
    );
    if effective_artifact_signing_managed_identity(args) {
        argv.push(OsString::from("--artifact-signing-managed-identity"));
    }
    push_option(
        argv,
        "--artifact-signing-managed-identity-resource-id",
        &args.artifact_signing_managed_identity_resource_id,
    );
    if let Some(value) = args.artifact_signing_credential_type {
        argv.push(OsString::from("--artifact-signing-credential-type"));
        argv.push(OsString::from(
            value.to_possible_value().unwrap().get_name(),
        ));
    }
    push_option(
        argv,
        "--artifact-signing-tenant-id",
        &args.artifact_signing_tenant_id,
    );
    push_option(
        argv,
        "--artifact-signing-client-id",
        &args.artifact_signing_client_id,
    );
    push_option(
        argv,
        "--artifact-signing-client-secret",
        &args.artifact_signing_client_secret,
    );
    push_option(
        argv,
        "--artifact-signing-federated-token-file",
        &args.artifact_signing_federated_token_file,
    );
    push_option(
        argv,
        "--artifact-signing-authority",
        &args.artifact_signing_authority,
    );
    push_option(
        argv,
        "--artifact-signing-endpoint-base-url",
        &args.artifact_signing_endpoint_base_url,
    );
}

fn push_timestamp_options(argv: &mut Vec<OsString>, args: &SignArgs) -> Result<()> {
    push_option(argv, "--timestamp-url", &args.timestamp_url);
    if let Some(timestamp_digest) = args.timestamp_digest {
        argv.push(OsString::from("--timestamp-digest"));
        argv.push(OsString::from(timestamp_digest_name(timestamp_digest)?));
    }
    Ok(())
}

fn portable_digest_name(digest: DigestAlgorithm) -> Result<&'static str> {
    match digest {
        DigestAlgorithm::Sha256 => Ok("sha256"),
        DigestAlgorithm::Sha384 => Ok("sha384"),
        DigestAlgorithm::Sha512 => Ok("sha512"),
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => Err(anyhow!(
            "portable Azure Key Vault sign supports only SHA-2 file digests"
        )),
    }
}

fn timestamp_digest_name(digest: DigestAlgorithm) -> Result<&'static str> {
    match digest {
        DigestAlgorithm::Sha1 => Ok("sha1"),
        DigestAlgorithm::Sha256 => Ok("sha256"),
        DigestAlgorithm::Sha384 => Ok("sha384"),
        DigestAlgorithm::Sha512 => Ok("sha512"),
        DigestAlgorithm::CertHash => Err(anyhow!(
            "portable Azure Key Vault timestamping supports only explicit hash algorithms"
        )),
    }
}

fn push_option(argv: &mut Vec<OsString>, name: &str, value: &Option<String>) {
    if let Some(value) = value.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        argv.push(OsString::from(name));
        argv.push(OsString::from(value));
    }
}

fn push_path_option(argv: &mut Vec<OsString>, name: &str, value: Option<&PathBuf>) {
    if let Some(value) = value {
        argv.push(OsString::from(name));
        argv.push(value.as_os_str().to_os_string());
    }
}

fn temporary_output_path(target: &Path) -> PathBuf {
    let stem = target
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("signed-output");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    target.hash(&mut hasher);
    let target_id = hasher.finish();
    match target.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => target.with_file_name(format!(
            "{stem}.psign-{}-{target_id:016x}.{extension}",
            std::process::id()
        )),
        None => target.with_file_name(format!(
            "{stem}.psign-{}-{target_id:016x}",
            std::process::id()
        )),
    }
}

fn azure_key_vault_requested(args: &SignArgs) -> bool {
    text_present(&args.azure_key_vault_url)
        || text_present(&args.azure_key_vault_certificate)
        || text_present(&args.azure_key_vault_certificate_version)
        || text_present(&args.azure_key_vault_client_id)
        || text_present(&args.azure_key_vault_client_secret)
        || text_present(&args.azure_key_vault_tenant_id)
        || text_present(&args.azure_key_vault_access_token)
        || args.azure_key_vault_managed_identity
        || args.azure_key_vault_credential_type.is_some()
        || text_present(&args.azure_authority)
}

fn artifact_signing_requested(args: &SignArgs) -> bool {
    args.artifact_signing_metadata.is_some()
        || args.dmdf.is_some()
        || text_present(&args.artifact_signing_region)
        || text_present(&args.artifact_signing_endpoint)
        || text_present(&args.artifact_signing_account_name)
        || text_present(&args.artifact_signing_profile_name)
        || text_present(&args.artifact_signing_signature_algorithm)
        || text_present(&args.artifact_signing_api_version)
        || text_present(&args.artifact_signing_correlation_id)
        || text_present(&args.artifact_signing_access_token)
        || args.artifact_signing_managed_identity
        || text_present(&args.artifact_signing_managed_identity_resource_id)
        || args.artifact_signing_credential_type.is_some()
        || text_present(&args.artifact_signing_tenant_id)
        || text_present(&args.artifact_signing_client_id)
        || text_present(&args.artifact_signing_client_secret)
        || text_present(&args.artifact_signing_federated_token_file)
        || text_present(&args.artifact_signing_authority)
        || text_present(&args.artifact_signing_endpoint_base_url)
}

fn text_present(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|s| !s.trim().is_empty())
}

fn text_opt(value: Option<&str>) -> Option<&str> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn effective_azure_key_vault_managed_identity(args: &SignArgs) -> bool {
    args.azure_key_vault_managed_identity
        || matches!(
            args.azure_key_vault_credential_type,
            Some(AzureCredentialType::ManagedIdentity)
        )
}

fn effective_artifact_signing_managed_identity(args: &SignArgs) -> bool {
    args.artifact_signing_managed_identity
        || matches!(
            args.artifact_signing_credential_type,
            Some(AzureCredentialType::ManagedIdentity)
        )
}

fn reject_workload_identity(name: &str, value: Option<AzureCredentialType>) -> Result<()> {
    if matches!(value, Some(AzureCredentialType::WorkloadIdentity)) {
        return Err(anyhow!(
            "{name}=workload-identity is accepted by provider planning but is not wired for portable Azure Key Vault signing execution yet"
        ));
    }
    Ok(())
}

fn resolved_sign_exit_codes(args: &SignArgs) -> SignExitCodes {
    if let Some(x) = args.exit_codes {
        return x;
    }
    match crate::env_var_with_legacy(crate::ENV_EXIT_CODES, crate::LEGACY_ENV_EXIT_CODES) {
        Some(v) => {
            let t = v.trim();
            if t.eq_ignore_ascii_case("azure") || t.eq_ignore_ascii_case("azuresigntool") {
                SignExitCodes::Azuresigntool
            } else {
                SignExitCodes::Signtool
            }
        }
        None => SignExitCodes::Signtool,
    }
}

fn batch_exit_code(exit_style: SignExitCodes, successes: usize, failures: usize) -> i32 {
    match exit_style {
        SignExitCodes::Signtool => {
            if failures > 0 {
                1
            } else {
                0
            }
        }
        SignExitCodes::Azuresigntool => {
            if successes > 0 && failures == 0 {
                0
            } else if successes > 0 && failures > 0 {
                AZURE_SIGN_EXIT_PARTIAL_SUCCESS
            } else if successes == 0 && failures > 0 {
                AZURE_SIGN_EXIT_ALL_FAILED
            } else {
                0
            }
        }
    }
}

fn reject_option(name: &str, present: bool) -> Result<()> {
    if present {
        return Err(anyhow!(
            "portable sign does not support {name}; local PFX/certificate-store and Azure Key Vault signing support PE/WinMD, CAB, MSI/MSP, MSIX/AppX packages and bundles, NuGet, VSIX, ClickOnce manifests, App Installer, ZIP, and PowerShell scripts, while Azure Artifact Signing supports its documented native-shaped subset"
        ));
    }
    Ok(())
}

fn reject_bool_option(name: &str, value: bool) -> Result<()> {
    reject_option(name, value)
}

fn reject_string_option(name: &str, value: &Option<String>) -> Result<()> {
    reject_option(name, value.as_deref().is_some_and(|s| !s.trim().is_empty()))
}

fn reject_path_option(name: &str, value: &Option<PathBuf>) -> Result<()> {
    reject_option(name, value.is_some())
}

fn reject_artifact_signing_options(args: &SignArgs) -> Result<()> {
    reject_path_option(
        "--artifact-signing-metadata",
        &args.artifact_signing_metadata,
    )?;
    reject_string_option("--artifact-signing-region", &args.artifact_signing_region)?;
    reject_string_option(
        "--artifact-signing-endpoint",
        &args.artifact_signing_endpoint,
    )?;
    reject_string_option(
        "--artifact-signing-account-name",
        &args.artifact_signing_account_name,
    )?;
    reject_string_option(
        "--artifact-signing-profile-name",
        &args.artifact_signing_profile_name,
    )?;
    reject_string_option(
        "--artifact-signing-signature-algorithm",
        &args.artifact_signing_signature_algorithm,
    )?;
    reject_string_option(
        "--artifact-signing-api-version",
        &args.artifact_signing_api_version,
    )?;
    reject_string_option(
        "--artifact-signing-correlation-id",
        &args.artifact_signing_correlation_id,
    )?;
    reject_string_option(
        "--artifact-signing-access-token",
        &args.artifact_signing_access_token,
    )?;
    reject_bool_option(
        "--artifact-signing-managed-identity",
        args.artifact_signing_managed_identity,
    )?;
    reject_string_option(
        "--artifact-signing-managed-identity-resource-id",
        &args.artifact_signing_managed_identity_resource_id,
    )?;
    reject_option(
        "--artifact-signing-credential-type",
        args.artifact_signing_credential_type.is_some(),
    )?;
    reject_string_option(
        "--artifact-signing-tenant-id",
        &args.artifact_signing_tenant_id,
    )?;
    reject_string_option(
        "--artifact-signing-client-id",
        &args.artifact_signing_client_id,
    )?;
    reject_string_option(
        "--artifact-signing-client-secret",
        &args.artifact_signing_client_secret,
    )?;
    reject_string_option(
        "--artifact-signing-federated-token-file",
        &args.artifact_signing_federated_token_file,
    )?;
    reject_string_option(
        "--artifact-signing-authority",
        &args.artifact_signing_authority,
    )?;
    reject_string_option(
        "--artifact-signing-endpoint-base-url",
        &args.artifact_signing_endpoint_base_url,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        expand_sign_targets, has_duplicate_target_identities, insert_sign_target,
        temporary_output_path,
    };
    use crate::cli::{Cli, Command};
    use clap::Parser;
    use std::collections::HashSet;

    #[test]
    fn deduplicates_existing_path_aliases() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.ps1");
        std::fs::write(&target, "Write-Output test").expect("write target");
        let alias = directory.path().join(".").join("target.ps1");

        let mut targets = Vec::new();
        let mut seen = HashSet::new();
        insert_sign_target(target, &mut targets, &mut seen);
        insert_sign_target(alias, &mut targets, &mut seen);

        assert_eq!(targets.len(), 1);
    }

    #[test]
    fn temporary_output_paths_do_not_collide_for_same_named_targets() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first = directory.path().join("one").join("target.ps1");
        let second = directory.path().join("two").join("target.ps1");

        assert_ne!(
            temporary_output_path(&first),
            temporary_output_path(&second)
        );
    }

    #[test]
    fn preserves_repeated_direct_targets_and_runs_them_sequentially() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.exe");
        std::fs::write(&target, "test").expect("write target");
        let cli = Cli::try_parse_from([
            "psign-tool",
            "sign",
            "--sha1",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--digest",
            "sha256",
            target.to_str().expect("UTF-8 target"),
            target.to_str().expect("UTF-8 target"),
        ])
        .expect("parse repeated targets");
        let Command::Sign(args) = cli.command else {
            panic!("expected sign command");
        };

        let targets = expand_sign_targets(&args).expect("expand targets");
        assert_eq!(targets, vec![target.clone(), target]);
        assert!(has_duplicate_target_identities(&targets));
    }
}
