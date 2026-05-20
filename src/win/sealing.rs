use crate::cli::{SignArgs, TimestampArgs};
use anyhow::{Result, anyhow};

fn extension(path: &std::path::Path) -> String {
    path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

pub fn is_appx_family(path: &std::path::Path) -> bool {
    matches!(
        extension(path).as_str(),
        "appx"
            | "appxbundle"
            | "msix"
            | "msixbundle"
            | "eappx"
            | "eappxbundle"
            | "emsix"
            | "emsixbundle"
    )
}

pub fn validate_sign_constraints(args: &SignArgs) -> Result<()> {
    validate_sign_constraints_paths(args, args.files.iter().map(|p| p.as_path()))
}

pub fn validate_sign_constraints_paths<'a>(
    args: &SignArgs,
    paths: impl IntoIterator<Item = &'a std::path::Path>,
) -> Result<()> {
    let decoupled_digest =
        (args.dlib.is_some() || args.trusted_signing_dlib_root.is_some()) && args.dmdf.is_some();
    if (args.dlib.is_some() || args.trusted_signing_dlib_root.is_some()) != args.dmdf.is_some() {
        return Err(anyhow!(
            "--dmdf must be provided together with either --dlib or --trusted-signing-dlib-root"
        ));
    }
    if args.timestamp_digest.is_some()
        && args.timestamp_url.is_none()
        && args.seal_timestamp_url.is_none()
    {
        return Err(anyhow!(
            "--timestamp-digest requires --timestamp-url or --seal-timestamp-url (RFC3161 sign-time timestamp)"
        ));
    }
    if (args.timestamp_url.is_some() || args.seal_timestamp_url.is_some())
        && args.timestamp_digest.is_none()
    {
        return Err(anyhow!(
            "No /td flag specified. RFC3161 timestamping requires --timestamp-digest (/td)"
        ));
    }
    if args.timestamp_url.is_some() && args.legacy_timestamp_url.is_some() {
        return Err(anyhow!(
            "choose either --timestamp-url (RFC3161) or --legacy-timestamp-url (/t), not both"
        ));
    }

    for path in paths.into_iter() {
        let is_appx = is_appx_family(path);
        if is_appx && args.timestamp_url.is_none() && args.seal_timestamp_url.is_none() {
            return Err(anyhow!(
                "AppX/MSIX packages must be timestamped during signing (--timestamp-url or --seal-timestamp-url /tseal)"
            ));
        }
        if is_appx && args.append_signature {
            return Err(anyhow!(
                "AppX/MSIX signing does not support append-signature mode in this implementation"
            ));
        }
        if is_appx && args.page_hashes && !decoupled_digest {
            return Err(anyhow!(
                "AppX/MSIX page hashes require decoupled digest inputs (--dlib or --trusted-signing-dlib-root, with --dmdf)"
            ));
        }
    }
    if args.page_hashes && args.no_page_hashes {
        return Err(anyhow!(
            "--page-hashes and --no-page-hashes (/ph and /nph) are mutually exclusive"
        ));
    }

    if args.certificate_template.is_some() {
        return Err(anyhow!(
            "sign /c (certificate template name) is not implemented; use native signtool"
        ));
    }
    if !args.sign_auth_pairs.is_empty() {
        return Err(anyhow!(
            "sign /sa (authenticated attributes OID + value) is not implemented; use native signtool"
        ));
    }
    if args.warn_fd_digest_vs_cert_signature_hash {
        return Err(anyhow!(
            "sign /fdchw (warn on file digest vs cert signature hash mismatch) is not implemented; use native signtool"
        ));
    }
    if args.warn_td_digest_vs_cert_signature_hash {
        return Err(anyhow!(
            "sign /tdchw (warn on timestamp digest vs cert signature hash mismatch) is not implemented; use native signtool"
        ));
    }
    if args.relaxed_pe_marker_check {
        return Err(anyhow!(
            "sign /rmc (relaxed PE marker check) is not implemented; use native signtool"
        ));
    }
    if args.add_sealing_signature {
        return Err(anyhow!(
            "sign /seal (add sealing signature) is not implemented; use native signtool"
        ));
    }
    if args.intent_to_seal {
        return Err(anyhow!(
            "sign /itos (intent-to-seal attribute) is not implemented; use native signtool"
        ));
    }
    if args.force_seal_or_resign {
        return Err(anyhow!(
            "sign /force (remove signature for sealing) is not implemented; use native signtool"
        ));
    }
    if args.sign_no_seal_warn {
        return Err(anyhow!(
            "sign /nosealwarn is not implemented; use native signtool"
        ));
    }
    if args.sign_no_enclave_warn {
        return Err(anyhow!(
            "sign /noenclavewarn is not implemented; use native signtool"
        ));
    }

    Ok(())
}

pub fn validate_timestamp_constraints(args: &TimestampArgs) -> Result<()> {
    let has_rfc3161 = args.rfc3161_url.is_some();
    let has_legacy = args.legacy_url.is_some();
    let has_seal = args.seal_timestamp_url.is_some();
    let count = has_rfc3161 as u8 + has_legacy as u8 + has_seal as u8;
    if count != 1 {
        return Err(anyhow!(
            "choose exactly one timestamp mode: --rfc3161-url, --legacy-url, or --seal-timestamp-url (/tseal)"
        ));
    }
    if (has_rfc3161 || has_seal) && args.digest.is_none() {
        return Err(anyhow!(
            "No /td flag specified. RFC3161 timestamping requires --digest (/td)"
        ));
    }

    for path in &args.files {
        if is_appx_family(path) && has_legacy {
            return Err(anyhow!(
                "AppX/MSIX files must be timestamped with RFC3161 mode (--rfc3161-url)"
            ));
        }
    }
    Ok(())
}
