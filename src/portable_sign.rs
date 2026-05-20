use crate::CommandOutput;
use crate::cli::{DigestAlgorithm, GlobalOpts, SignArgs};
use anyhow::{Context, Result, anyhow};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

fn sign_file_artifact_signing(args: &SignArgs) -> Result<CommandOutput> {
    validate_artifact_signing_supported_options(args)?;
    if args.files.is_empty() {
        return Err(anyhow!(
            "portable Artifact Signing sign requires at least one file"
        ));
    }

    let mut combined = String::new();
    for (idx, target) in args.files.iter().enumerate() {
        if idx > 0 {
            combined.push('\n');
        }
        sign_one_target_artifact_signing(target, args)
            .with_context(|| format!("portable Artifact Signing sign '{}'", target.display()))?;
        combined.push_str(&format!(
            "Signed: {}\nartifact_signing_profile={}\n",
            target.display(),
            args.artifact_signing_profile_name
                .as_deref()
                .unwrap_or("<metadata>")
        ));
    }
    Ok(CommandOutput::with_exit(combined, success_exit_code(args)))
}

fn sign_file_azure_key_vault(args: &SignArgs) -> Result<CommandOutput> {
    validate_azure_key_vault_supported_options(args)?;
    if args.files.is_empty() {
        return Err(anyhow!(
            "portable Azure Key Vault sign requires at least one file"
        ));
    }

    let mut combined = String::new();
    for (idx, target) in args.files.iter().enumerate() {
        if idx > 0 {
            combined.push('\n');
        }
        sign_one_target_azure_key_vault(target, args)
            .with_context(|| format!("portable Azure Key Vault sign '{}'", target.display()))?;
        combined.push_str(&format!(
            "Signed: {}\nazure_key_vault_certificate={}\n",
            target.display(),
            args.azure_key_vault_certificate
                .as_deref()
                .unwrap_or("<missing>")
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
    reject_artifact_signing_options(args)?;
    reject_path_option("--input-file-list", &args.sign_input_file_list)?;
    reject_bool_option("--continue-on-error", args.continue_on_error)?;
    reject_bool_option("--skip-signed", args.skip_signed)?;
    reject_option(
        "--max-degree-of-parallelism",
        args.max_degree_parallelism.is_some(),
    )?;
    Ok(())
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
    reject_bool_option("--as/--append-signature", args.append_signature)?;
    reject_bool_option("--ph/--page-hashes", args.page_hashes)?;
    reject_bool_option("--nph/--no-page-hashes", args.no_page_hashes)?;
    reject_path_option("--dlib", &args.dlib)?;
    reject_path_option(
        "--trusted-signing-dlib-root",
        &args.trusted_signing_dlib_root,
    )?;
    reject_path_option("--dmdf", &args.dmdf)?;
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
    reject_path_option("--input-file-list", &args.sign_input_file_list)?;
    reject_bool_option("--continue-on-error", args.continue_on_error)?;
    reject_bool_option("--skip-signed", args.skip_signed)?;
    reject_option(
        "--max-degree-of-parallelism",
        args.max_degree_parallelism.is_some(),
    )?;
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
    reject_bool_option("--as/--append-signature", args.append_signature)?;
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

fn sign_one_target_azure_key_vault(target: &Path, args: &SignArgs) -> Result<()> {
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
            "portable Azure Key Vault signing is currently implemented only for PE/WinMD targets; got {}",
            target.display()
        ));
    }

    let tmp = temporary_output_path(target);
    let result = run_portable_sign_pe_azure_key_vault(target, &tmp, args)
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

fn sign_one_target_artifact_signing(target: &Path, args: &SignArgs) -> Result<()> {
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
            "portable Artifact Signing is currently implemented only for PE/WinMD targets; got {}",
            target.display()
        ));
    }

    let tmp = temporary_output_path(target);
    let result = run_portable_sign_pe_artifact_signing(target, &tmp, args)
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

fn run_portable_sign_pe_azure_key_vault(
    target: &Path,
    output: &Path,
    args: &SignArgs,
) -> Result<()> {
    let mut argv = Vec::new();
    argv.push(OsString::from("psign-tool"));
    argv.push(OsString::from("sign-pe"));
    argv.push(target.as_os_str().to_os_string());
    argv.push(OsString::from("--digest"));
    argv.push(OsString::from(portable_digest_name(args.digest)?));
    for chain_cert in &args.additional_certs {
        argv.push(OsString::from("--chain-cert"));
        argv.push(chain_cert.as_os_str().to_os_string());
    }
    push_option(&mut argv, "--timestamp-url", &args.timestamp_url);
    if let Some(timestamp_digest) = args.timestamp_digest {
        argv.push(OsString::from("--timestamp-digest"));
        argv.push(OsString::from(timestamp_digest_name(timestamp_digest)?));
    }
    push_option(
        &mut argv,
        "--azure-key-vault-url",
        &args.azure_key_vault_url,
    );
    push_option(
        &mut argv,
        "--azure-key-vault-certificate",
        &args.azure_key_vault_certificate,
    );
    push_option(
        &mut argv,
        "--azure-key-vault-certificate-version",
        &args.azure_key_vault_certificate_version,
    );
    push_option(
        &mut argv,
        "--azure-key-vault-accesstoken",
        &args.azure_key_vault_access_token,
    );
    if args.azure_key_vault_managed_identity {
        argv.push(OsString::from("--azure-key-vault-managed-identity"));
    }
    push_option(
        &mut argv,
        "--azure-key-vault-tenant-id",
        &args.azure_key_vault_tenant_id,
    );
    push_option(
        &mut argv,
        "--azure-key-vault-client-id",
        &args.azure_key_vault_client_id,
    );
    push_option(
        &mut argv,
        "--azure-key-vault-client-secret",
        &args.azure_key_vault_client_secret,
    );
    push_option(&mut argv, "--azure-authority", &args.azure_authority);
    argv.push(OsString::from("--output"));
    argv.push(output.as_os_str().to_os_string());

    std::thread::Builder::new()
        .name("psign-portable-sign-pe".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || psign_digest_cli::run_from(argv))
        .map_err(|e| anyhow!("spawn portable sign-pe runner: {e}"))?
        .join()
        .map_err(|_| anyhow!("portable sign-pe runner panicked"))?
}

fn run_portable_sign_pe_artifact_signing(
    target: &Path,
    output: &Path,
    args: &SignArgs,
) -> Result<()> {
    let mut argv = Vec::new();
    argv.push(OsString::from("psign-tool"));
    argv.push(OsString::from("sign-pe"));
    argv.push(target.as_os_str().to_os_string());
    argv.push(OsString::from("--digest"));
    argv.push(OsString::from(portable_digest_name(args.digest)?));
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
    if args.artifact_signing_managed_identity {
        argv.push(OsString::from("--artifact-signing-managed-identity"));
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
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("signed-output");
    target.with_file_name(format!("{}.psign-{}.tmp", file_name, std::process::id()))
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
        || text_present(&args.artifact_signing_tenant_id)
        || text_present(&args.artifact_signing_client_id)
        || text_present(&args.artifact_signing_client_secret)
        || text_present(&args.artifact_signing_authority)
        || text_present(&args.artifact_signing_endpoint_base_url)
}

fn text_present(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|s| !s.trim().is_empty())
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
            "portable sign does not support {name}; supported subsets are local store PE/WinMD signing (--sha1, --store/--s, --machine-store/--sm, --cert-store-dir, --fd SHA256), Azure Key Vault PE/WinMD signing (--azure-key-vault-*, --fd SHA256/SHA384/SHA512), and Azure Artifact Signing PE/WinMD signing (--artifact-signing-* or --dmdf)"
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
        "--artifact-signing-authority",
        &args.artifact_signing_authority,
    )?;
    reject_string_option(
        "--artifact-signing-endpoint-base-url",
        &args.artifact_signing_endpoint_base_url,
    )?;
    Ok(())
}
