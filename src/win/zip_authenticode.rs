use crate::CommandOutput;
use crate::cli::{GlobalOpts, SignArgs, VerifyArgs};
use crate::win::verify::output_with_verify_warnings;
use crate::win::verify::run_embedded_for_target;
use anyhow::{Context as _, Result, anyhow};
use psign_sip_digest::pkcs7;
use psign_sip_digest::rdp;
use psign_sip_digest::zip_authenticode;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn is_zip_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
}

fn temporary_sig_path(target: &Path) -> PathBuf {
    let stem = target
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("zip")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    std::env::temp_dir().join(format!(
        "psign_zip_authenticode_{}_{}_{}.sig.ps1",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        stem
    ))
}

fn validate_zip_sign_args(args: &SignArgs) -> Result<()> {
    if args.append_signature {
        return Err(anyhow!(
            "ZIP Authenticode signing stores one signature in the ZIP comment; --append-signature is not supported"
        ));
    }
    if args.page_hashes || args.no_page_hashes {
        return Err(anyhow!(
            "ZIP Authenticode signing does not support page-hash flags"
        ));
    }
    if args.add_sealing_signature
        || args.intent_to_seal
        || args.force_seal_or_resign
        || args.sign_no_seal_warn
        || args.sign_no_enclave_warn
    {
        return Err(anyhow!(
            "ZIP Authenticode signing does not support sealing or enclave signing flags"
        ));
    }
    Ok(())
}

fn zip_digest_algorithm(args: &SignArgs) -> Result<pkcs7::AuthenticodeSigningDigest> {
    Ok(match args.digest {
        crate::cli::DigestAlgorithm::Sha256 | crate::cli::DigestAlgorithm::CertHash => {
            pkcs7::AuthenticodeSigningDigest::Sha256
        }
        crate::cli::DigestAlgorithm::Sha384 => pkcs7::AuthenticodeSigningDigest::Sha384,
        crate::cli::DigestAlgorithm::Sha512 => pkcs7::AuthenticodeSigningDigest::Sha512,
        crate::cli::DigestAlgorithm::Sha1 => {
            return Err(anyhow!(
                "ZIP Authenticode PFX signing supports SHA-256, SHA-384, or SHA-512 script signatures"
            ));
        }
    })
}

fn can_sign_zip_directly_from_pfx(args: &SignArgs) -> bool {
    args.pfx.is_some()
        && args.timestamp_url.is_none()
        && args.legacy_timestamp_url.is_none()
        && args.seal_timestamp_url.is_none()
        && args.dlib.is_none()
        && args.trusted_signing_dlib_root.is_none()
        && args.dmdf.is_none()
        && args.azure_key_vault_url.is_none()
        && args.artifact_signing_metadata.is_none()
}

fn sign_zip_comment_from_pfx(args: &SignArgs, digest: &str) -> Result<Option<String>> {
    if !can_sign_zip_directly_from_pfx(args) {
        return Ok(None);
    }
    let pfx = args
        .pfx
        .as_ref()
        .expect("can_sign_zip_directly_from_pfx checked PFX");
    let pfx_bytes = std::fs::read(pfx).with_context(|| format!("read PFX {}", pfx.display()))?;
    let (cert_der, key_pem) = crate::cert_store::load_pfx_cert_and_key(
        &pfx_bytes,
        args.password.as_deref().unwrap_or_default(),
    )
    .with_context(|| format!("parse PFX {}", pfx.display()))?;
    let signer_cert = rdp::parse_certificate(&cert_der).context("parse PFX signer certificate")?;
    let private_key =
        rdp::parse_rsa_private_key(key_pem.as_bytes()).context("parse PFX private key")?;
    let mut chain = Vec::with_capacity(args.additional_certs.len());
    for cert in &args.additional_certs {
        let bytes = std::fs::read(cert)
            .with_context(|| format!("read additional cert {}", cert.display()))?;
        chain.push(
            rdp::parse_certificate(&bytes)
                .with_context(|| format!("parse additional cert {}", cert.display()))?,
        );
    }
    let pkcs7 = pkcs7::create_script_authenticode_pkcs7_der_rsa(
        &zip_authenticode::unsigned_signature_script_bytes(digest),
        zip_digest_algorithm(args)?,
        signer_cert,
        chain,
        private_key,
    )?;
    zip_authenticode::signature_comment_line_from_pkcs7_der(digest, &pkcs7).map(Some)
}

fn validate_zip_verify_args(args: &VerifyArgs) -> Result<()> {
    if args.detached_pkcs7.is_some()
        || args.detached_pkcs7_content.is_some()
        || args.catalog.is_some()
        || args.catalog_search.is_some()
        || args.catalog_database_guid.is_some()
    {
        return Err(anyhow!(
            "ZIP Authenticode verification cannot be combined with detached PKCS#7 or catalog verification modes"
        ));
    }
    if args.all_signatures || args.signature_index.is_some() || args.multiple_semantics {
        return Err(anyhow!(
            "ZIP Authenticode stores a single custom comment signature; signature enumeration flags are not supported"
        ));
    }
    if args.verify_page_hashes || args.verify_sealing_signatures {
        return Err(anyhow!(
            "ZIP Authenticode verification does not support page-hash or sealing checks"
        ));
    }
    if args.rust_sip_pe_digest_check
        || args.rust_sip_msi_digest_check
        || args.rust_sip_esd_digest_check
        || args.rust_sip_msix_digest_check
        || args.rust_sip_cab_digest_check
        || args.rust_sip_catalog_digest_check
        || args.rust_sip_all_digest_checks
    {
        return Err(anyhow!(
            "ZIP Authenticode verification uses the custom ZIP digest plus a reconstructed PowerShell signature; non-script Rust SIP checks do not apply"
        ));
    }
    Ok(())
}

pub(crate) fn sign_zip_with<F>(args: &SignArgs, target: &Path, sign_script: F) -> Result<String>
where
    F: FnOnce(&Path) -> Result<String>,
{
    validate_zip_sign_args(args)?;
    let original = std::fs::read(target).with_context(|| format!("read {}", target.display()))?;
    let digest = zip_authenticode::zip_authenticode_digest_string(&original)?;
    let tmp = temporary_sig_path(target);
    let result = (|| {
        std::fs::write(
            &tmp,
            zip_authenticode::unsigned_signature_script_bytes(&digest),
        )
        .with_context(|| format!("write temporary ZIP signature script {}", tmp.display()))?;
        let (comment_line, report) = if let Some(comment_line) =
            sign_zip_comment_from_pfx(args, &digest)?
        {
            let report = format!(
                "Successfully signed\nmode=zip-authenticode-pfx\nfile={}\ndigest={}\n",
                target.display(),
                args.digest.as_signtool_name()
            );
            (comment_line, report)
        } else {
            let report = sign_script(&tmp)?;
            let signed_script = std::fs::read(&tmp)
                .with_context(|| format!("read signed ZIP signature script {}", tmp.display()))?;
            (
                zip_authenticode::signature_comment_line_from_script(&signed_script)?,
                report.replace(&tmp.display().to_string(), &target.display().to_string()),
            )
        };
        let signed_zip = zip_authenticode::embed_signature_comment_line(&original, &comment_line)?;
        std::fs::write(target, signed_zip)
            .with_context(|| format!("write signed ZIP {}", target.display()))?;
        Ok(report + &format!("zip_authenticode_digest={digest}\n"))
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

pub(crate) fn verify_zip(
    target: &Path,
    args: &VerifyArgs,
    global: &GlobalOpts,
) -> Result<CommandOutput> {
    validate_zip_verify_args(args)?;
    let zip = std::fs::read(target).with_context(|| format!("read {}", target.display()))?;
    let sig = zip_authenticode::verify_zip_digest_binding(&zip)?;
    let script = zip_authenticode::signature_script_from_parts(&sig.digest, &sig.pkcs7_base64);
    let tmp = temporary_sig_path(target);
    let result = (|| {
        std::fs::write(&tmp, script).with_context(|| {
            format!("write temporary ZIP verification script {}", tmp.display())
        })?;
        let (out, post_warnings, summary, ts_none) = run_embedded_for_target(&tmp, args, global)?;
        let mut zip_out = out.replace(&tmp.display().to_string(), &target.display().to_string());
        if global.verbose {
            zip_out.push_str("ZIP Authenticode: custom EOCD comment signature\n");
            zip_out.push_str(&format!("ZIP digest: {}\n", sig.digest));
        }
        Ok(output_with_verify_warnings(
            args,
            zip_out,
            summary.as_ref(),
            &post_warnings,
            ts_none,
        ))
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}
