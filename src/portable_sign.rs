use crate::CommandOutput;
use crate::cli::{DigestAlgorithm, GlobalOpts, SignArgs};
use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};

pub fn sign_file(args: &SignArgs, _global: &GlobalOpts) -> Result<CommandOutput> {
    validate_supported_options(args)?;
    if args.files.is_empty() {
        return Err(anyhow!("portable sign requires at least one file"));
    }
    let thumbprint = args
        .cert_sha1
        .as_deref()
        .ok_or_else(|| anyhow!("portable sign requires --sha1 <thumbprint>"))?;
    let identity = crate::cert_store::resolve_signing_identity(
        args.cert_store_dir.as_deref(),
        args.machine_store,
        &args.store_name,
        thumbprint,
    )?;

    let mut combined = String::new();
    for (idx, target) in args.files.iter().enumerate() {
        if idx > 0 {
            combined.push('\n');
        }
        let signed = sign_one_target(target, &identity)
            .with_context(|| format!("portable sign '{}'", target.display()))?;
        std::fs::write(target, signed)
            .with_context(|| format!("write signed file '{}'", target.display()))?;
        combined.push_str(&format!(
            "Signed: {}\nthumbprint_sha1={}\nstore={}\\{}\n",
            target.display(),
            identity.thumbprint_sha1,
            identity.scope,
            identity.store_name
        ));
    }
    Ok(CommandOutput::with_exit(combined, success_exit_code(args)))
}

fn validate_supported_options(args: &SignArgs) -> Result<()> {
    if args.digest != DigestAlgorithm::Sha256 {
        return Err(anyhow!(
            "portable sign currently supports only --fd SHA256, got {}",
            args.digest.as_signtool_name()
        ));
    }
    reject_path_option("--f/--pfx", &args.pfx)?;
    reject_string_option("--p/--password", &args.password)?;
    reject_bool_option("--a/--auto-select", args.auto_select)?;
    reject_string_option("--n/--subject-name", &args.subject_name)?;
    reject_string_option("--i/--issuer-name", &args.issuer_name)?;
    reject_string_option("--csp", &args.csp)?;
    reject_string_option("--kc/--key-container", &args.key_container)?;
    reject_bool_option("--as/--append-signature", args.append_signature)?;
    reject_bool_option("--ph/--page-hashes", args.page_hashes)?;
    reject_bool_option("--nph/--no-page-hashes", args.no_page_hashes)?;
    reject_path_option("--dlib", &args.dlib)?;
    reject_path_option("--dmdf", &args.dmdf)?;
    reject_path_option(
        "--trusted-signing-dlib-root",
        &args.trusted_signing_dlib_root,
    )?;
    reject_string_option("--tr/--timestamp-url", &args.timestamp_url)?;
    reject_string_option("--t/--legacy-timestamp-url", &args.legacy_timestamp_url)?;
    reject_string_option("--tseal/--seal-timestamp-url", &args.seal_timestamp_url)?;
    reject_option("--td/--timestamp-digest", args.timestamp_digest.is_some())?;
    reject_string_option("--d/--description", &args.description)?;
    reject_string_option("--du/--description-url", &args.description_url)?;
    reject_vec_option("--ac/--additional-cert", &args.additional_certs)?;
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
    reject_string_option("--azure-authority", &args.azure_authority)?;
    reject_path_option("--input-file-list", &args.sign_input_file_list)?;
    reject_bool_option("--continue-on-error", args.continue_on_error)?;
    reject_bool_option("--skip-signed", args.skip_signed)?;
    reject_option(
        "--max-degree-of-parallelism",
        args.max_degree_parallelism.is_some(),
    )?;
    Ok(())
}

fn sign_one_target(
    target: &Path,
    identity: &crate::cert_store::SigningIdentity,
) -> Result<Vec<u8>> {
    let ext = target
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !matches!(
        ext.as_str(),
        "exe" | "dll" | "sys" | "ocx" | "efi" | "winmd"
    ) {
        return Err(anyhow!(
            "portable thumbprint signing is currently implemented only for PE/WinMD targets; got {}",
            target.display()
        ));
    }
    let bytes = std::fs::read(target).with_context(|| format!("read '{}'", target.display()))?;
    psign_sip_digest::pe_sign::sign_pe_image_rsa_sha256(
        &bytes,
        &identity.cert_der,
        &identity.key_pem,
    )
}

fn success_exit_code(args: &SignArgs) -> i32 {
    match args.exit_codes {
        Some(crate::cli::SignExitCodes::Azuresigntool) => 0,
        Some(crate::cli::SignExitCodes::Signtool) | None => 0,
    }
}

fn reject_option(name: &str, present: bool) -> Result<()> {
    if present {
        return Err(anyhow!(
            "portable sign does not support {name}; supported subset is --sha1, --store/--s, --machine-store/--sm, --cert-store-dir, --fd SHA256, and PE/WinMD file paths"
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

fn reject_vec_option(name: &str, value: &[PathBuf]) -> Result<()> {
    reject_option(name, !value.is_empty())
}
