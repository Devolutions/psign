use crate::CommandOutput;
use crate::cli::{CatalogSearchMode, GlobalOpts, VerifyArgs, VerifyPolicy};
use crate::win::verify_authcode::{
    format_verify_description_lines, pe_image_page_hashes_present_from_wvt_state,
    sp_opus_from_wvt_state,
};
use crate::win::verify_catalog::verify_with_catalog;
use crate::win::verify_catalog_resolve::resolve_catalog_for_verify;
use crate::win::verify_chain::VerifyChainSummary;
use crate::win::verify_chain::{
    chain_root_subject_contains, intermediate_ca_thumbprints_match, leaf_cert_from_state,
    pca_2010_warning_message_lines, summarize_from_state, verify_signer_thumbprints_allowed,
    warn_missing_eku_messages,
};
use crate::win::verify_detached::verify_detached_pkcs7;
use crate::win::verify_format::{format_verify_failure, format_verify_success};
use anyhow::{Result, anyhow};
use std::ffi::c_void;
use std::iter::once;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use uuid::Uuid;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG;
use windows::Win32::Security::WinTrust::{
    DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WINTRUST_SIGNATURE_SETTINGS, WINTRUST_SIGNATURE_SETTINGS_FLAGS,
    WSS_GET_SECONDARY_SIG_COUNT, WSS_VERIFY_SEALING, WSS_VERIFY_SPECIFIC, WTD_CHOICE_FILE,
    WTD_GENERIC_CHAIN_POLICY_CREATE_INFO, WTD_GENERIC_CHAIN_POLICY_DATA, WTD_HASH_ONLY_FLAG,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTD_UICONTEXT_EXECUTE, WTD_USE_DEFAULT_OSVER_CHECK, WinVerifyTrust,
};
use windows::core::{GUID, PCWSTR, PWSTR};

fn to_wide(path: &std::path::Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(once(0)).collect()
}

fn policy_action(args: &VerifyArgs) -> Result<GUID> {
    if args.kernel_policy {
        return Ok(DRIVER_ACTION_VERIFY);
    }
    match args.policy {
        VerifyPolicy::Pa => Ok(WINTRUST_ACTION_GENERIC_VERIFY_V2),
        VerifyPolicy::Default => Ok(DRIVER_ACTION_VERIFY),
        VerifyPolicy::Pg => {
            let raw = args
                .policy_guid
                .as_ref()
                .ok_or_else(|| anyhow!("--policy pg requires --policy-guid"))?;
            let parsed = Uuid::parse_str(raw)
                .map_err(|e| anyhow!("invalid --policy-guid '{}': {}", raw, e))?;
            Ok(GUID::from_u128(parsed.as_u128()))
        }
    }
}

fn combine_sig_settings_flags(
    base: WINTRUST_SIGNATURE_SETTINGS_FLAGS,
    verify_sealing: bool,
) -> WINTRUST_SIGNATURE_SETTINGS_FLAGS {
    if verify_sealing {
        WINTRUST_SIGNATURE_SETTINGS_FLAGS(base.0 | WSS_VERIFY_SEALING)
    } else {
        base
    }
}

fn embedded_signature_settings(args: &VerifyArgs) -> Option<WINTRUST_SIGNATURE_SETTINGS> {
    let sealing = args.verify_sealing_signatures;
    match (args.signature_index, sealing) {
        (Some(idx), true) => Some(WINTRUST_SIGNATURE_SETTINGS {
            cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
            dwIndex: idx,
            dwFlags: combine_sig_settings_flags(WSS_VERIFY_SPECIFIC, true),
            cSecondarySigs: 0,
            dwVerifiedSigIndex: 0,
            pCryptoPolicy: std::ptr::null_mut(),
        }),
        (Some(idx), false) => Some(WINTRUST_SIGNATURE_SETTINGS {
            cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
            dwIndex: idx,
            dwFlags: WSS_VERIFY_SPECIFIC,
            cSecondarySigs: 0,
            dwVerifiedSigIndex: 0,
            pCryptoPolicy: std::ptr::null_mut(),
        }),
        (None, true) => Some(WINTRUST_SIGNATURE_SETTINGS {
            cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
            dwIndex: 0,
            dwFlags: WINTRUST_SIGNATURE_SETTINGS_FLAGS(WSS_VERIFY_SEALING),
            cSecondarySigs: 0,
            dwVerifiedSigIndex: 0,
            pCryptoPolicy: std::ptr::null_mut(),
        }),
        (None, false) => None,
    }
}

/// Native `timestamp /tseal` succeeds only when a **sealing** signature is already present.
pub(crate) fn require_sealing_signature_for_seal_timestamp(target: &Path) -> Result<()> {
    let wide = to_wide(target);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut sig_settings = WINTRUST_SIGNATURE_SETTINGS {
        cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
        dwIndex: 0,
        dwFlags: WINTRUST_SIGNATURE_SETTINGS_FLAGS(WSS_VERIFY_SEALING),
        cSecondarySigs: 0,
        dwVerifiedSigIndex: 0,
        pCryptoPolicy: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WTD_REVOCATION_CHECK_NONE,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: &mut sig_settings,
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };
    if status != 0 {
        return Err(anyhow!(
            "No sealing signature was found. The file must be sealed before it can be seal timestamped."
        ));
    }
    Ok(())
}

fn build_provider_flags(
    args: &VerifyArgs,
    apply_os_version_check: bool,
) -> windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS {
    use windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS;
    let mut f = if args.revocation_check {
        WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
    } else {
        WTD_REVOCATION_CHECK_NONE
    };
    if args.verify_page_hashes {
        f = WINTRUST_DATA_PROVIDER_FLAGS(f.0 | WTD_HASH_ONLY_FLAG.0);
    }
    if apply_os_version_check && args.os_version_check.is_some() {
        f = WINTRUST_DATA_PROVIDER_FLAGS(f.0 | WTD_USE_DEFAULT_OSVER_CHECK.0);
    }
    f
}

type EmbeddedVerifyResult = (
    i32,
    Option<VerifyChainSummary>,
    Vec<String>,
    Option<(String, Option<String>)>,
);

fn verify_embedded_once(
    target: &Path,
    args: &VerifyArgs,
    signature_settings: Option<&mut WINTRUST_SIGNATURE_SETTINGS>,
) -> Result<EmbeddedVerifyResult> {
    let wide = to_wide(target);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut signer_chain = WTD_GENERIC_CHAIN_POLICY_CREATE_INFO::default();
    let mut policy_data = WTD_GENERIC_CHAIN_POLICY_DATA::default();
    let policy_ptr = if args.allow_test_root {
        signer_chain.dwFlags = CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG.0;
        policy_data.pSignerChainInfo = &mut signer_chain;
        &mut policy_data as *mut WTD_GENERIC_CHAIN_POLICY_DATA as *mut c_void
    } else {
        std::ptr::null_mut()
    };
    let is_probe_count = signature_settings
        .as_ref()
        .map(|s| (s.dwFlags & WSS_GET_SECONDARY_SIG_COUNT) != WINTRUST_SIGNATURE_SETTINGS_FLAGS(0))
        .unwrap_or(false);
    let (signer_idx, p_sig) = match signature_settings {
        Some(s) => (s.dwIndex, s as *mut WINTRUST_SIGNATURE_SETTINGS),
        None => (0, std::ptr::null_mut()),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: policy_ptr,
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: if args.revocation_check {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        },
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: build_provider_flags(args, false),
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: p_sig,
    };
    let mut action = policy_action(args)?;
    let status = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };

    if status == 0
        && let Some(needle) = args.chain_root_subject.as_deref()
    {
        let chain_ok = if let Some(leaf) = leaf_cert_from_state(data.hWVTStateData) {
            chain_root_subject_contains(leaf, needle).map_err(|e| anyhow!("{e}"))?
        } else {
            false
        };
        if !chain_ok {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = unsafe {
                WinVerifyTrust(
                    HWND(std::ptr::null_mut()),
                    &mut action,
                    &mut data as *mut _ as *mut c_void,
                )
            };
            return Err(anyhow!(
                "signing certificate chain does not match requested root subject '{needle}'"
            ));
        }
    }

    let mut post_warnings = Vec::new();
    if status == 0
        && let Some(leaf) = leaf_cert_from_state(data.hWVTStateData)
    {
        let constraints = (|| -> Result<Vec<String>> {
            verify_signer_thumbprints_allowed(leaf, &args.signer_thumbprint_sha1)?;
            if !intermediate_ca_thumbprints_match(leaf, &args.intermediate_ca_sha1)? {
                return Err(anyhow!(
                    "Verification failed: no intermediate CA certificate matched /ca thumbprints"
                ));
            }
            let mut w = warn_missing_eku_messages(leaf, &args.warn_if_missing_eku)?;
            w.extend(pca_2010_warning_message_lines(
                leaf,
                matches!(args.policy, VerifyPolicy::Default),
                args.kernel_policy,
                args.warn_pca_2010,
                args.no_warn_pca_2010,
            )?);
            Ok(w)
        })();
        match constraints {
            Ok(w) => post_warnings = w,
            Err(e) => {
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                let _ = unsafe {
                    WinVerifyTrust(
                        HWND(std::ptr::null_mut()),
                        &mut action,
                        &mut data as *mut _ as *mut c_void,
                    )
                };
                return Err(e);
            }
        }
    }

    let summary = if status == 0 {
        summarize_from_state(data.hWVTStateData)
    } else {
        None
    };

    let sp_opus = if status == 0 && args.print_description && !is_probe_count {
        sp_opus_from_wvt_state(data.hWVTStateData, signer_idx)
    } else {
        None
    };

    if status == 0
        && args.verify_page_hashes
        && !is_probe_count
        && !pe_image_page_hashes_present_from_wvt_state(data.hWVTStateData, signer_idx)
    {
        post_warnings.push("SignTool Warning: No page hashes are present.\n".to_string());
    }

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };
    Ok((status, summary, post_warnings, sp_opus))
}

fn verify_all_signatures(
    target: &Path,
    args: &VerifyArgs,
) -> Result<(String, Vec<String>, Option<VerifyChainSummary>)> {
    let mut count_settings = WINTRUST_SIGNATURE_SETTINGS {
        cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
        dwIndex: 0,
        dwFlags: combine_sig_settings_flags(
            WSS_GET_SECONDARY_SIG_COUNT,
            args.verify_sealing_signatures,
        ),
        cSecondarySigs: 0,
        dwVerifiedSigIndex: 0,
        pCryptoPolicy: std::ptr::null_mut(),
    };
    let (status, first_summary, mut accum_warnings, _) =
        verify_embedded_once(target, args, Some(&mut count_settings))?;
    if status != 0 {
        return Err(anyhow!(format_verify_failure(target, status)));
    }
    let secondary = count_settings.cSecondarySigs;
    let total = secondary.saturating_add(1);
    let mut out = format_verify_success(target, first_summary.as_ref());
    out.push_str(&format!("Total signatures: {total}\n"));

    for idx in 0..total {
        let mut settings = WINTRUST_SIGNATURE_SETTINGS {
            cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
            dwIndex: idx,
            dwFlags: combine_sig_settings_flags(
                WSS_VERIFY_SPECIFIC,
                args.verify_sealing_signatures,
            ),
            cSecondarySigs: 0,
            dwVerifiedSigIndex: 0,
            pCryptoPolicy: std::ptr::null_mut(),
        };
        let (sig_status, sig_summary, w, sig_opus) =
            verify_embedded_once(target, args, Some(&mut settings))?;
        accum_warnings.extend(w);
        if sig_status != 0 {
            return Err(anyhow!(format!(
                "signature index {idx} failed: {}",
                format_verify_failure(target, sig_status)
            )));
        }
        if let Some(summary) = sig_summary {
            out.push_str(&format!(
                "Signature {idx}: verified (algorithm={}, timestamp={}, signer={})\n",
                summary.algorithm, summary.timestamp, summary.signer_subject
            ));
        } else {
            out.push_str(&format!("Signature {idx}: verified\n"));
        }
        if let Some((n, u)) = sig_opus {
            out.push_str(&format_verify_description_lines(&n, u.as_deref()));
        }
    }
    Ok((out, accum_warnings, first_summary))
}

fn output_with_verify_warnings(
    args: &VerifyArgs,
    out: String,
    summary: Option<&VerifyChainSummary>,
    extra: &[String],
    extra_timestamp_none: bool,
) -> CommandOutput {
    let ts_warn = args.warn_if_not_timestamped
        && (extra_timestamp_none
            || summary
                .map(|s| s.timestamp.as_str() == "none")
                .unwrap_or(false));
    let any_warn = ts_warn || !extra.is_empty();
    if !any_warn {
        return CommandOutput::ok(out);
    }
    let mut w = out;
    for e in extra {
        w.push_str(e);
    }
    if ts_warn {
        w.push_str("Warning: signature is not timestamped\n");
    }
    CommandOutput::warning(w)
}

fn embedded_verbose_suffix(args: &VerifyArgs, global: &GlobalOpts) -> String {
    if !global.verbose {
        return String::new();
    }
    let mut s = String::new();
    s.push_str(&format!(
        "Policy: {:?}\nRevocation: {}\n",
        args.policy,
        if args.revocation_check {
            "enabled"
        } else {
            "disabled"
        }
    ));
    if args.verify_pkcs7_file {
        s.push_str(
            "verify-pkcs7-file: using WinTrust file verification (limited PKCS#7 semantics)\n",
        );
    }
    if args.verify_sealing_signatures {
        s.push_str("verify-sealing-signatures: WinTrust WSS_VERIFY_SEALING enabled\n");
    }
    if args.multiple_semantics {
        s.push_str("multiple-semantics: using default WinVerifyTrust behavior\n");
    }
    s
}

/// Embedded WinTrust verify for one path; returns stdout block, post-filter warnings, summary, and whether timestamp is absent.
fn run_embedded_for_target(
    target: &Path,
    args: &VerifyArgs,
    global: &GlobalOpts,
) -> Result<(String, Vec<String>, Option<VerifyChainSummary>, bool)> {
    if global.debug {
        let fmt = crate::win::code_sign_format::detect(target);
        eprintln!(
            "[psign debug] verify embedded target format={fmt:?} sip_hint={}",
            fmt.sip_hint()
        );
    }
    let mut sig_settings = embedded_signature_settings(args);

    let (status, summary, post_warnings, sp_opus) =
        verify_embedded_once(target, args, sig_settings.as_mut())?;
    if status != 0 {
        return Err(anyhow!(format_verify_failure(target, status)));
    }
    let mut out = format_verify_success(target, summary.as_ref());
    out.push_str(&embedded_verbose_suffix(args, global));
    if let Some((n, u)) = sp_opus {
        out.push_str(&format_verify_description_lines(&n, u.as_deref()));
    }
    let ts_none = summary
        .as_ref()
        .map(|s| s.timestamp.as_str() == "none")
        .unwrap_or(true);

    #[cfg(windows)]
    let rust_all = args.rust_sip_all_digest_checks;

    #[cfg(windows)]
    if args.rust_sip_pe_digest_check || rust_all {
        use crate::win::code_sign_format::CodeSignFormat;
        let fmt = crate::win::code_sign_format::detect(target);
        if matches!(
            fmt,
            CodeSignFormat::PortableExecutable | CodeSignFormat::WindowsMetadata
        ) {
            let bytes = std::fs::read(target)?;
            let diag =
                crate::win::sip_rust::verify_pe::verify_pe_authenticode_digest_consistency(&bytes)
                    .map_err(|e| anyhow!("Rust SIP PE digest check failed: {e}"))?;
            if global.debug {
                eprintln!(
                    "[psign debug] rust_sip_pe_digest_check ok digest_hex={} pkcs7_entries={}",
                    diag.recomputed_digest_hex, diag.pkcs7_authenticode_entries
                );
            }
        } else if global.debug {
            eprintln!(
                "[psign debug] rust_sip_pe_digest_check skipped (format={fmt:?}) for {}",
                target.display()
            );
        }
    }

    #[cfg(windows)]
    if args.rust_sip_script_digest_check || rust_all {
        use crate::win::code_sign_format::CodeSignFormat;
        let fmt = crate::win::code_sign_format::detect(target);
        let ext = target
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let candidate = matches!(
            fmt,
            CodeSignFormat::PowerShellScript
                | CodeSignFormat::PowerShellModule
                | CodeSignFormat::PowerShellManifest
                | CodeSignFormat::WindowsScriptHost
        ) || crate::win::sip_rust::ps_script::extension_supported(&ext)
            || crate::win::sip_rust::ps_script::is_wsh_extension(&ext);
        if candidate {
            let bytes = std::fs::read(target)?;
            crate::win::sip_rust::verify_script_digest_consistency(&bytes, &ext)
                .map_err(|e| anyhow!("Rust SIP script digest check failed: {e}"))?;
            if global.debug {
                eprintln!(
                    "[psign debug] rust_sip_script_digest_check ok for {}",
                    target.display()
                );
            }
        } else if global.debug {
            eprintln!(
                "[psign debug] rust_sip_script_digest_check skipped (format={fmt:?} ext={ext}) for {}",
                target.display()
            );
        }
    }

    #[cfg(windows)]
    if args.rust_sip_msi_digest_check || rust_all {
        use crate::win::code_sign_format::CodeSignFormat;
        let fmt = crate::win::code_sign_format::detect(target);
        if matches!(fmt, CodeSignFormat::WindowsInstaller) {
            crate::win::sip_rust::msi_digest::verify_msi_digest_consistency(target)
                .map_err(|e| anyhow!("Rust SIP MSI digest check failed: {e}"))?;
            if global.debug {
                eprintln!(
                    "[psign debug] rust_sip_msi_digest_check ok for {}",
                    target.display()
                );
            }
        } else if global.debug {
            eprintln!(
                "[psign debug] rust_sip_msi_digest_check skipped (format={fmt:?}) for {}",
                target.display()
            );
        }
    }

    #[cfg(windows)]
    if args.rust_sip_esd_digest_check || rust_all {
        use crate::win::code_sign_format::CodeSignFormat;
        let fmt = crate::win::code_sign_format::detect(target);
        if matches!(fmt, CodeSignFormat::WimImage) {
            crate::win::sip_rust::esd_digest::verify_wim_esd_digest_consistency(target)
                .map_err(|e| anyhow!("Rust SIP WIM/ESD digest check failed: {e}"))?;
            if global.debug {
                eprintln!(
                    "[psign debug] rust_sip_esd_digest_check ok for {}",
                    target.display()
                );
            }
        } else if global.debug {
            eprintln!(
                "[psign debug] rust_sip_esd_digest_check skipped (format={fmt:?}) for {}",
                target.display()
            );
        }
    }

    #[cfg(windows)]
    if args.rust_sip_cab_digest_check || rust_all {
        use crate::win::code_sign_format::CodeSignFormat;
        let fmt = crate::win::code_sign_format::detect(target);
        if matches!(fmt, CodeSignFormat::Cabinet) {
            crate::win::sip_rust::cab_digest::verify_cab_digest_consistency(target)
                .map_err(|e| anyhow!("Rust SIP CAB digest check failed: {e}"))?;
            if global.debug {
                eprintln!(
                    "[psign debug] rust_sip_cab_digest_check ok for {}",
                    target.display()
                );
            }
        } else if global.debug {
            eprintln!(
                "[psign debug] rust_sip_cab_digest_check skipped (format={fmt:?}) for {}",
                target.display()
            );
        }
    }

    #[cfg(windows)]
    if args.rust_sip_catalog_digest_check || rust_all {
        use crate::win::code_sign_format::CodeSignFormat;
        let fmt = crate::win::code_sign_format::detect(target);
        if matches!(fmt, CodeSignFormat::Catalog) {
            crate::win::sip_rust::catalog_digest::verify_catalog_digest_consistency(target)
                .map_err(|e| anyhow!("Rust SIP catalog digest check failed: {e}"))?;
            if global.debug {
                eprintln!(
                    "[psign debug] rust_sip_catalog_digest_check ok for {}",
                    target.display()
                );
            }
        } else if global.debug {
            eprintln!(
                "[psign debug] rust_sip_catalog_digest_check skipped (format={fmt:?}) for {}",
                target.display()
            );
        }
    }

    #[cfg(windows)]
    if args.rust_sip_msix_digest_check || rust_all {
        use crate::win::code_sign_format::CodeSignFormat;
        let fmt = crate::win::code_sign_format::detect(target);
        let ext = target
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(fmt, CodeSignFormat::MsixFamily) {
            crate::win::sip_rust::msix_digest::verify_msix_digest_consistency(target)
                .map_err(|e| anyhow!("Rust SIP MSIX/AppX digest check failed: {e}"))?;
            if global.debug {
                eprintln!(
                    "[psign debug] rust_sip_msix_digest_check ok for {}",
                    target.display()
                );
            }
        } else if global.debug {
            eprintln!(
                "[psign debug] rust_sip_msix_digest_check skipped (format={fmt:?} ext={ext}) for {}",
                target.display()
            );
        }
    }

    Ok((out, post_warnings, summary, ts_none))
}

pub fn verify_file(args: &VerifyArgs, global: &GlobalOpts) -> Result<CommandOutput> {
    if args.print_description && !global.verbose {
        return Err(anyhow!(
            "verify --print-description (/d) requires --verbose (-v), matching native signtool"
        ));
    }
    if args.verify_page_hashes && !global.verbose {
        return Err(anyhow!(
            "verify --verify-page-hashes (/ph) requires --verbose (-v), matching native signtool"
        ));
    }
    if args.verify_sealing_signatures && args.detached_pkcs7.is_some() {
        return Err(anyhow!(
            "verify --verify-sealing-signatures (/sl) is not supported with detached PKCS#7 in psign"
        ));
    }
    if args.verify_sealing_signatures && args.catalog.is_some() {
        return Err(anyhow!(
            "verify --verify-sealing-signatures (/sl) is not supported with --catalog <path> in psign"
        ));
    }
    if args.policy != VerifyPolicy::Pg && args.policy_guid.is_some() {
        return Err(anyhow!("--policy-guid is only valid with --policy pg"));
    }
    if args.kernel_policy && args.policy == VerifyPolicy::Pg {
        return Err(anyhow!(
            "--kernel-policy cannot be combined with --policy pg (conflicting trust modes)"
        ));
    }
    if args.detached_pkcs7.is_some() && args.catalog.is_some() {
        return Err(anyhow!(
            "--detached-pkcs7 and --catalog are mutually exclusive verify modes"
        ));
    }
    if args.catalog.is_some()
        && (args.catalog_search.is_some() || args.catalog_database_guid.is_some())
    {
        return Err(anyhow!(
            "--catalog path cannot be combined with catalog search options"
        ));
    }
    if args.all_signatures && args.signature_index.is_some() {
        return Err(anyhow!(
            "--all-signatures cannot be combined with --signature-index"
        ));
    }
    if args.detached_pkcs7_content.is_some() && args.detached_pkcs7.is_none() {
        return Err(anyhow!(
            "--detached-pkcs7-content requires --detached-pkcs7"
        ));
    }
    if args.warn_pca_2010 && args.no_warn_pca_2010 {
        return Err(anyhow!(
            "--warn-pca-2010 and --no-warn-pca-2010 cannot be used together"
        ));
    }
    if args.biometric_policy {
        return Err(anyhow!(
            "verify /bp (biometric signing policy) is not implemented; use native signtool"
        ));
    }
    if args.enclave_policy {
        return Err(anyhow!(
            "verify /enclave (enclave signing policy) is not implemented; use native signtool"
        ));
    }
    if args.files.is_empty() {
        return Err(anyhow!("verify requires at least one file"));
    }
    if args.detached_pkcs7.is_some() && args.files.len() != 1 {
        return Err(anyhow!(
            "detached PKCS#7 verify supports exactly one content file; got {}",
            args.files.len()
        ));
    }
    if args.print_description && args.detached_pkcs7.is_some() {
        return Err(anyhow!(
            "verify --print-description (/d) is not supported with detached PKCS#7 in psign"
        ));
    }
    if args.verify_page_hashes && args.detached_pkcs7.is_some() {
        return Err(anyhow!(
            "verify --verify-page-hashes (/ph) is not supported with detached PKCS#7 in psign"
        ));
    }
    for p in &args.files {
        if !p.exists() {
            return Err(anyhow!("file not found: {}", p.display()));
        }
    }
    if args.catalog.is_some()
        && (!args.signer_thumbprint_sha1.is_empty()
            || !args.intermediate_ca_sha1.is_empty()
            || !args.warn_if_missing_eku.is_empty())
    {
        return Err(anyhow!(
            "thumbprint / intermediate CA / warn-missing-eku filters cannot be combined with --catalog <path>"
        ));
    }
    if args.os_version_check.is_some() {
        let catalog_mode = args.catalog.is_some()
            || args.catalog_search.is_some()
            || args.catalog_database_guid.is_some();
        if !catalog_mode {
            return Err(anyhow!(
                "verify --os-version-check (/o) requires catalog verification (--catalog <path> or --catalog-search / --catalog-database-guid); \
                 native signtool rejects /o with embedded verify unless /a /ad /as /c are used"
            ));
        }
    }

    if let Some(sig) = &args.detached_pkcs7 {
        let target = &args.files[0];
        let content = args.detached_pkcs7_content.as_ref().unwrap_or(target);
        let (summary, detached_warnings) = verify_detached_pkcs7(content, sig, args)?;
        let out = format!(
            "File: {path}\nIndex  Algorithm  Timestamp    \n========================================\n0      detached   none         \nSigner: {signer}\n\nSuccessfully verified: {path}\n",
            path = target.display(),
            signer = summary.signer_subject
        );
        return Ok(output_with_verify_warnings(
            args,
            out,
            None,
            &detached_warnings,
            false,
        ));
    }

    if args.all_signatures {
        if args.files.len() == 1 {
            let target = &args.files[0];
            let (mut out, extra_warn, first_summary) = verify_all_signatures(target, args)?;
            if global.verbose && args.multiple_semantics {
                out.insert_str(
                    0,
                    "multiple-semantics: WinVerifyTrust behavior follows OS defaults\n",
                );
            }
            return Ok(output_with_verify_warnings(
                args,
                out,
                first_summary.as_ref(),
                &extra_warn,
                false,
            ));
        }
        let mut combined = String::new();
        let mut extra_warn = Vec::new();
        let mut any_ts_none = false;
        for (i, target) in args.files.iter().enumerate() {
            let (out, w, first_summary) = verify_all_signatures(target, args)?;
            if args.warn_if_not_timestamped
                && first_summary
                    .as_ref()
                    .map(|s| s.timestamp.as_str() == "none")
                    .unwrap_or(true)
            {
                any_ts_none = true;
            }
            if i > 0 {
                combined.push('\n');
            }
            combined.push_str(&out);
            extra_warn.extend(w);
        }
        if global.verbose && args.multiple_semantics {
            combined.insert_str(
                0,
                "multiple-semantics: WinVerifyTrust behavior follows OS defaults\n",
            );
        }
        return Ok(output_with_verify_warnings(
            args,
            combined,
            None,
            &extra_warn,
            any_ts_none,
        ));
    }

    if let Some(catalog) = &args.catalog {
        let action = policy_action(args)?;
        if args.files.len() == 1 {
            let target = &args.files[0];
            let (summary, sp_opus, cat_warns) = verify_with_catalog(args, target, catalog, action)?;
            let mut out = format_verify_success(target, Some(&summary));
            if global.verbose {
                out.push_str(&format!("Catalog: {}\n", catalog.display()));
            }
            if let Some((n, u)) = sp_opus {
                out.push_str(&format_verify_description_lines(&n, u.as_deref()));
            }
            return Ok(output_with_verify_warnings(
                args,
                out,
                Some(&summary),
                &cat_warns,
                false,
            ));
        }
        let mut blocks = Vec::new();
        let mut any_ts_none = false;
        let mut cat_warn_all = Vec::new();
        for target in &args.files {
            let (summary, sp_opus, cat_warns) = verify_with_catalog(args, target, catalog, action)?;
            cat_warn_all.extend(cat_warns);
            if args.warn_if_not_timestamped && summary.timestamp == "none" {
                any_ts_none = true;
            }
            let mut out = format_verify_success(target, Some(&summary));
            if global.verbose {
                out.push_str(&format!("Catalog: {}\n", catalog.display()));
            }
            if let Some((n, u)) = sp_opus {
                out.push_str(&format_verify_description_lines(&n, u.as_deref()));
            }
            blocks.push(out);
        }
        let joined = blocks.join("\n");
        return Ok(output_with_verify_warnings(
            args,
            joined,
            None,
            &cat_warn_all,
            any_ts_none,
        ));
    }

    if matches!(args.catalog_search, Some(CatalogSearchMode::All))
        && args.catalog_database_guid.is_some()
    {
        return Err(anyhow!(
            "do not combine --catalog-search all with --catalog-database-guid"
        ));
    }

    if args.catalog_search.is_some() || args.catalog_database_guid.is_some() {
        let action = policy_action(args)?;
        let mut ordered: Vec<String> = Vec::new();
        let mut combined_post: Vec<String> = Vec::new();
        let mut extra_ts_none = false;
        let mut first_summary_single: Option<VerifyChainSummary> = None;

        for target in &args.files {
            let resolved = resolve_catalog_for_verify(
                target,
                args.catalog_search,
                args.catalog_database_guid.as_deref(),
                args.catalog_hash_algorithm,
            )?;
            if let Some(cat_path) = resolved {
                let (summary, sp_opus, cat_warns) =
                    verify_with_catalog(args, target, &cat_path, action)?;
                combined_post.extend(cat_warns);
                if args.warn_if_not_timestamped && summary.timestamp == "none" {
                    extra_ts_none = true;
                }
                let mut out = format_verify_success(target, Some(&summary));
                if global.verbose {
                    out.push_str(&format!("Catalog resolved: {}\n", cat_path.display()));
                }
                if let Some((n, u)) = sp_opus {
                    out.push_str(&format_verify_description_lines(&n, u.as_deref()));
                }
                ordered.push(out);
                if args.files.len() == 1 {
                    first_summary_single = Some(summary);
                }
            } else if matches!(args.catalog_search, Some(CatalogSearchMode::All)) {
                let (out, post, summary, ts_none) = run_embedded_for_target(target, args, global)?;
                if args.warn_if_not_timestamped && ts_none {
                    extra_ts_none = true;
                }
                combined_post.extend(post);
                ordered.push(out);
                if args.files.len() == 1 {
                    first_summary_single = summary;
                }
            } else {
                return Err(anyhow!(
                    "could not resolve a catalog for this file with the requested catalog database options"
                ));
            }
        }

        let joined = ordered.join("\n");
        let summary_ref = first_summary_single
            .as_ref()
            .filter(|_| args.files.len() == 1);
        return Ok(output_with_verify_warnings(
            args,
            joined,
            summary_ref,
            &combined_post,
            extra_ts_none && args.files.len() > 1,
        ));
    }

    if args.files.len() == 1 {
        let target = &args.files[0];
        let (out, post_warnings, summary, _) = run_embedded_for_target(target, args, global)?;
        return Ok(output_with_verify_warnings(
            args,
            out,
            summary.as_ref(),
            &post_warnings,
            false,
        ));
    }

    let mut blocks = Vec::new();
    let mut merged_post = Vec::new();
    let mut any_ts_none = false;
    for target in &args.files {
        let (out, post, _summary, ts_none) = run_embedded_for_target(target, args, global)?;
        if args.warn_if_not_timestamped && ts_none {
            any_ts_none = true;
        }
        merged_post.extend(post);
        blocks.push(out);
    }
    let joined = blocks.join("\n");
    Ok(output_with_verify_warnings(
        args,
        joined,
        None,
        &merged_post,
        any_ts_none,
    ))
}
