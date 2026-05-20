//! Windows Authenticode / Cryptography helpers call many FFI entry points with raw pointers (`PCCERT_CONTEXT`,
//! etc.). Those wrappers stay safe at the Rust abstraction boundary; Clippy's `not_unsafe_ptr_arg_deref` lint does not
//! apply cleanly across the entire Win32 surface.
//!
//! The **`win`** module is **`cfg(windows)`** only; non-Windows builds expose CLI parsing (`cli`, `native_argv`,
//! `response_argv`) and depend on **`psign-sip-digest`** for portable digest code.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod cert_store;
pub mod cli;
pub mod native_argv;
pub mod portable_sign;
pub mod rdp;
pub mod response_argv;
#[cfg(windows)]
pub mod win;

/// Process-oriented result matching native `signtool` exit semantics (`0` ok, `2` warning).
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub exit_code: i32,
}

impl CommandOutput {
    pub fn ok(stdout: String) -> Self {
        Self {
            stdout,
            exit_code: 0,
        }
    }

    pub fn with_exit(stdout: String, exit_code: i32) -> Self {
        Self { stdout, exit_code }
    }

    pub fn warning(stdout: String) -> Self {
        Self {
            stdout,
            exit_code: 2,
        }
    }
}

/// AzureSignTool-style HRESULT batch outcomes ([documented here](https://github.com/vcsjones/AzureSignTool/blob/main/README.md#exit-codes)).
pub const AZURE_SIGN_EXIT_PARTIAL_SUCCESS: i32 = 0x2000_0001_u32 as i32;
pub const AZURE_SIGN_EXIT_ALL_FAILED: i32 = 0xA000_0002_u32 as i32;

pub const ENV_TOOL_MODE: &str = "PSIGN_TOOL_MODE";
pub const ENV_RUST_SIP: &str = "PSIGN_RUST_SIP";
pub const ENV_EXIT_CODES: &str = "PSIGN_EXIT_CODES";

pub const LEGACY_ENV_RUST_SIP: &str = "SIGNTOOL_RS_RUST_SIP";
pub const LEGACY_ENV_EXIT_CODES: &str = "SIGNTOOL_RS_EXIT_CODES";

pub fn env_var_with_legacy(name: &str, legacy_name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .or_else(|| std::env::var(legacy_name).ok())
}

fn parse_tool_mode(value: &str) -> anyhow::Result<crate::cli::ToolMode> {
    use crate::cli::ToolMode;
    let t = value.trim();
    if t.eq_ignore_ascii_case("auto") {
        Ok(ToolMode::Auto)
    } else if t.eq_ignore_ascii_case("windows") || t.eq_ignore_ascii_case("win32") {
        Ok(ToolMode::Windows)
    } else if t.eq_ignore_ascii_case("portable") {
        Ok(ToolMode::Portable)
    } else {
        Err(anyhow::anyhow!(
            "{ENV_TOOL_MODE} must be one of: auto, windows, portable"
        ))
    }
}

fn resolved_tool_mode(global: &crate::cli::GlobalOpts) -> anyhow::Result<crate::cli::ToolMode> {
    if let Some(mode) = global.mode {
        return Ok(mode);
    }
    match std::env::var(ENV_TOOL_MODE) {
        Ok(value) => parse_tool_mode(&value),
        Err(_) => Ok(crate::cli::ToolMode::Auto),
    }
}

fn effective_tool_mode(mode: crate::cli::ToolMode) -> crate::cli::ToolMode {
    match mode {
        crate::cli::ToolMode::Auto => {
            if cfg!(windows) {
                crate::cli::ToolMode::Windows
            } else {
                crate::cli::ToolMode::Portable
            }
        }
        explicit => explicit,
    }
}

fn print_output(global: &crate::cli::GlobalOpts, out: &CommandOutput) {
    if global.debug {
        eprintln!(
            "[debug] exit_code={} stdout_len={}",
            out.exit_code,
            out.stdout.len()
        );
    }
    if !global.quiet || out.exit_code != 0 {
        print!("{}", out.stdout);
    }
}

fn run_portable_args(args: &[std::ffi::OsString]) -> anyhow::Result<CommandOutput> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(std::ffi::OsString::from("psign-tool"));
    if args.is_empty() {
        argv.push(std::ffi::OsString::from("--help"));
    } else {
        argv.extend(args.iter().cloned());
    }
    std::thread::Builder::new()
        .name("psign-portable-cli".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || psign_digest_cli::run_from(argv))
        .map_err(|e| anyhow::anyhow!("spawn portable CLI runner: {e}"))?
        .join()
        .map_err(|_| anyhow::anyhow!("portable CLI runner panicked"))??;
    Ok(CommandOutput::ok(String::new()))
}

fn portable_command_for_path(path: &std::path::Path) -> anyhow::Result<&'static str> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "exe" | "dll" | "sys" | "ocx" | "efi" | "winmd" => Ok("verify-pe"),
        "cab" => Ok("verify-cab"),
        "msi" | "msp" => Ok("verify-msi"),
        "wim" | "esd" => Ok("verify-esd"),
        "msix" | "appx" | "msixbundle" | "appxbundle" => Ok("verify-msix"),
        "cat" => Ok("verify-catalog"),
        "ps1" | "psd1" | "psm1" | "ps1xml" | "psc1" | "cdxml" | "mof" | "js" | "vbs" | "wsf" => {
            Ok("verify-script")
        }
        _ => Err(anyhow::anyhow!(
            "portable verify cannot infer a supported SIP format for {}",
            path.display()
        )),
    }
}

fn portable_verify_unsupported(args: &crate::cli::VerifyArgs) -> bool {
    args.policy != crate::cli::VerifyPolicy::Default
        || args.policy_guid.is_some()
        || args.revocation_check
        || args.detached_pkcs7.is_some()
        || args.catalog.is_some()
        || args.catalog_search.is_some()
        || args.catalog_database_guid.is_some()
        || args.os_version_check.is_some()
        || args.kernel_policy
        || args.all_signatures
        || args.allow_test_root
        || args.warn_if_not_timestamped
        || args.signature_index.is_some()
        || args.multiple_semantics
        || args.verify_pkcs7_file
        || args.print_description
        || args.verify_page_hashes
        || args.chain_root_subject.is_some()
        || !args.signer_thumbprint_sha1.is_empty()
        || !args.intermediate_ca_sha1.is_empty()
        || !args.warn_if_missing_eku.is_empty()
        || args.detached_pkcs7_content.is_some()
        || args.warn_pca_2010
        || args.no_warn_pca_2010
        || args.verify_sealing_signatures
        || args.rust_sip_pe_digest_check
        || args.rust_sip_script_digest_check
        || args.rust_sip_msi_digest_check
        || args.rust_sip_esd_digest_check
        || args.rust_sip_msix_digest_check
        || args.rust_sip_cab_digest_check
        || args.rust_sip_catalog_digest_check
        || args.rust_sip_all_digest_checks
        || args.biometric_policy
        || args.enclave_policy
}

fn portable_verify_trust_requested(args: &crate::cli::VerifyArgs) -> bool {
    args.anchor_dir.is_some()
        || !args.trusted_ca.is_empty()
        || args.authroot_cab.is_some()
        || args.expect_authroot_cab_sha256.is_some()
        || args.verbose_chain
        || args.allow_loose_signing_cert
        || args.prefer_timestamp_signing_time
        || args.require_valid_timestamp
        || args.online_aia
        || args.aia_url_override.is_some()
        || args.online_ocsp
        || args.ocsp_url_override.is_some()
        || args.revocation_mode.is_some()
        || args.crl_url_override.is_some()
        || args.as_of.is_some()
        || args.online_timeout_secs != 5
        || args.online_max_download_bytes != 1024 * 1024
}

fn execute_portable_verify(args: &crate::cli::VerifyArgs) -> anyhow::Result<CommandOutput> {
    if portable_verify_unsupported(args) {
        return Err(anyhow::anyhow!(
            "--mode portable verify currently supports bare file digest-consistency verification; use `psign-tool portable ...` for portable trust/diagnostic commands"
        ));
    }
    for path in &args.files {
        let command = if portable_verify_trust_requested(args) {
            match portable_command_for_path(path)? {
                "verify-pe" => "trust-verify-pe",
                "verify-cab" => "trust-verify-cab",
                "verify-msi" => "trust-verify-msi",
                "verify-esd" => "trust-verify-esd",
                "verify-catalog" => "trust-verify-catalog",
                other => {
                    return Err(anyhow::anyhow!(
                        "--mode portable verify trust options are not supported for inferred command {other}"
                    ));
                }
            }
        } else {
            portable_command_for_path(path)?
        };
        let mut argv = Vec::new();
        argv.push(std::ffi::OsString::from(command));
        if let Some(dir) = &args.anchor_dir {
            argv.push(std::ffi::OsString::from("--anchor-dir"));
            argv.push(dir.as_os_str().to_os_string());
        }
        for ca in &args.trusted_ca {
            argv.push(std::ffi::OsString::from("--trusted-ca"));
            argv.push(ca.as_os_str().to_os_string());
        }
        if let Some(cab) = &args.authroot_cab {
            argv.push(std::ffi::OsString::from("--authroot-cab"));
            argv.push(cab.as_os_str().to_os_string());
        }
        if let Some(expected) = &args.expect_authroot_cab_sha256 {
            argv.push(std::ffi::OsString::from("--expect-authroot-cab-sha256"));
            argv.push(std::ffi::OsString::from(expected));
        }
        if args.verbose_chain {
            argv.push(std::ffi::OsString::from("--verbose-chain"));
        }
        if args.allow_loose_signing_cert {
            argv.push(std::ffi::OsString::from("--allow-loose-signing-cert"));
        }
        if args.prefer_timestamp_signing_time {
            argv.push(std::ffi::OsString::from("--prefer-timestamp-signing-time"));
        }
        if args.require_valid_timestamp {
            argv.push(std::ffi::OsString::from("--require-valid-timestamp"));
        }
        if args.online_aia {
            argv.push(std::ffi::OsString::from("--online-aia"));
        }
        if let Some(url) = &args.aia_url_override {
            argv.push(std::ffi::OsString::from("--aia-url-override"));
            argv.push(std::ffi::OsString::from(url));
        }
        if args.online_ocsp {
            argv.push(std::ffi::OsString::from("--online-ocsp"));
        }
        if let Some(url) = &args.ocsp_url_override {
            argv.push(std::ffi::OsString::from("--ocsp-url-override"));
            argv.push(std::ffi::OsString::from(url));
        }
        if let Some(mode) = args.revocation_mode {
            argv.push(std::ffi::OsString::from("--revocation-mode"));
            argv.push(std::ffi::OsString::from(mode.as_arg()));
        }
        if let Some(url) = &args.crl_url_override {
            argv.push(std::ffi::OsString::from("--crl-url-override"));
            argv.push(std::ffi::OsString::from(url));
        }
        if let Some(as_of) = &args.as_of {
            argv.push(std::ffi::OsString::from("--as-of"));
            argv.push(std::ffi::OsString::from(as_of));
        }
        if args.online_timeout_secs != 5 {
            argv.push(std::ffi::OsString::from("--online-timeout-secs"));
            argv.push(std::ffi::OsString::from(
                args.online_timeout_secs.to_string(),
            ));
        }
        if args.online_max_download_bytes != 1024 * 1024 {
            argv.push(std::ffi::OsString::from("--online-max-download-bytes"));
            argv.push(std::ffi::OsString::from(
                args.online_max_download_bytes.to_string(),
            ));
        }
        argv.push(path.as_os_str().to_os_string());
        run_portable_args(&argv)?;
    }
    Ok(CommandOutput::ok(String::new()))
}

fn execute_portable_inspect(
    args: &crate::cli::InspectSignatureArgs,
) -> anyhow::Result<CommandOutput> {
    let input = match args.input {
        crate::cli::InspectSignatureInput::Pe => "pe",
        crate::cli::InspectSignatureInput::Pkcs7 => "pkcs7",
    };
    let argv = [
        std::ffi::OsString::from("inspect-authenticode"),
        args.path.as_os_str().to_os_string(),
        std::ffi::OsString::from("--input"),
        std::ffi::OsString::from(input),
    ];
    run_portable_args(&argv)
}

#[cfg(windows)]
fn execute_windows(cli: &crate::cli::Cli) -> anyhow::Result<CommandOutput> {
    use crate::cli::Command;
    match &cli.command {
        Command::CertStore(args) => crate::cert_store::cert_store_command(args),
        Command::Portable(args) => run_portable_args(&args.args),
        Command::Verify(args) => crate::win::verify::verify_file(args, &cli.global),
        Command::Sign(args) => crate::win::sign::sign_file(args, &cli.global),
        Command::Timestamp(args) => crate::win::timestamp::timestamp_file(args, &cli.global),
        Command::Catdb(args) => crate::win::catdb::catdb_command(args, &cli.global),
        Command::Remove(args) => crate::win::remove_signature::remove_command(args, &cli.global),
        Command::InspectSignature(args) => {
            crate::win::inspect_signature::inspect_signature_command(args, &cli.global)
        }
        Command::Rdp(args) => crate::win::rdp::rdp_command(args, &cli.global),
        #[cfg(feature = "artifact-signing-rest")]
        Command::ArtifactSigningSubmit(args) => {
            crate::win::artifact_signing_rest::artifact_signing_submit_command(args, &cli.global)
        }
    }
}

#[cfg(not(windows))]
fn execute_windows(_cli: &crate::cli::Cli) -> anyhow::Result<CommandOutput> {
    Err(anyhow::anyhow!(
        "--mode windows requires Microsoft Windows (WinVerifyTrust, SignerSignEx3, registered CryptSIP)"
    ))
}

fn execute_portable(cli: &crate::cli::Cli) -> anyhow::Result<CommandOutput> {
    use crate::cli::Command;
    match &cli.command {
        Command::CertStore(args) => crate::cert_store::cert_store_command(args),
        Command::Portable(args) => run_portable_args(&args.args),
        Command::Verify(args) => execute_portable_verify(args),
        Command::InspectSignature(args) => execute_portable_inspect(args),
        Command::Sign(args) => crate::portable_sign::sign_file(args, &cli.global),
        Command::Timestamp(_) => Err(anyhow::anyhow!(
            "--mode portable timestamp is not implemented; portable timestamp helpers are available under `psign-tool portable ...`"
        )),
        Command::Catdb(_) => Err(anyhow::anyhow!(
            "--mode portable catdb is unsupported because catalog database operations require Win32"
        )),
        Command::Remove(_) => Err(anyhow::anyhow!(
            "--mode portable remove is unsupported; embedded signature removal currently requires the Windows implementation"
        )),
        Command::Rdp(_) => Err(anyhow::anyhow!(
            "--mode portable rdp is available as `psign-tool portable rdp ...`"
        )),
        #[cfg(feature = "artifact-signing-rest")]
        Command::ArtifactSigningSubmit(_) => Err(anyhow::anyhow!(
            "--mode portable artifact-signing-submit is available as `psign-tool portable artifact-signing-submit ...`"
        )),
    }
}

fn execute(cli: &crate::cli::Cli) -> anyhow::Result<CommandOutput> {
    if let crate::cli::Command::CertStore(args) = &cli.command {
        return crate::cert_store::cert_store_command(args);
    }
    if let crate::cli::Command::Portable(args) = &cli.command {
        return run_portable_args(&args.args);
    }
    match effective_tool_mode(resolved_tool_mode(&cli.global)?) {
        crate::cli::ToolMode::Windows => execute_windows(cli),
        crate::cli::ToolMode::Portable => execute_portable(cli),
        crate::cli::ToolMode::Auto => unreachable!("auto mode is resolved before dispatch"),
    }
}

pub fn run_tool_cli() -> ! {
    use crate::cli::Cli;
    use clap::Parser;

    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let Some((executable, tail)) = argv.split_first().map(|(e, t)| (e.clone(), t.to_vec())) else {
        std::process::exit(0);
    };

    let invocations = match crate::response_argv::expand_invocations(executable, tail) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    };

    let mut batch_exit = 0i32;
    for invocation in invocations {
        let argv = crate::native_argv::normalize_native_signtool_argv(invocation);
        let cli = match Cli::try_parse_from(argv) {
            Ok(c) => c,
            Err(e) => e.exit(),
        };

        match execute(&cli) {
            Ok(out) => {
                print_output(&cli.global, &out);
                batch_exit =
                    crate::response_argv::combine_batch_exit_codes(batch_exit, out.exit_code);
            }
            Err(e) => {
                if !cli.global.quiet {
                    eprintln!("{e:#}");
                }
                batch_exit = crate::response_argv::combine_batch_exit_codes(batch_exit, 1);
            }
        }
    }

    std::process::exit(batch_exit);
}
