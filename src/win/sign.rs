use crate::cli::{GlobalOpts, RustSipBackend, SignArgs, SignExitCodes};
use crate::win::code_sign_format::CodeSignFormat;
use crate::win::sealing::validate_sign_constraints_paths;
use crate::win::sign_core::sign_with_mssign32;
use crate::win::sign_digest_pipeline::reject_split_digest_flags;
use crate::{AZURE_SIGN_EXIT_ALL_FAILED, AZURE_SIGN_EXIT_PARTIAL_SUCCESS, CommandOutput};
use anyhow::{Context as _, Result, anyhow};
use glob::glob;
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn rust_sip_backend(args: &SignArgs) -> Option<RustSipBackend> {
    use RustSipBackend::*;
    if matches!(args.rust_sip, Some(Off)) {
        return None;
    }
    if let Some(b) = args.rust_sip {
        return match b {
            Off => None,
            Pe | Script | Msi | Esd | Msix | Cab | Catalog => Some(b),
        };
    }
    if crate::env_var_with_legacy(crate::ENV_RUST_SIP, crate::LEGACY_ENV_RUST_SIP)
        .map(|v| v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
    {
        return None;
    }
    match crate::env_var_with_legacy(crate::ENV_RUST_SIP, crate::LEGACY_ENV_RUST_SIP) {
        Some(v) => {
            let t = v.trim();
            if t.eq_ignore_ascii_case("pe") {
                Some(Pe)
            } else if t.eq_ignore_ascii_case("script") {
                Some(Script)
            } else if t.eq_ignore_ascii_case("msi") {
                Some(Msi)
            } else if t.eq_ignore_ascii_case("esd") {
                Some(Esd)
            } else if t.eq_ignore_ascii_case("msix") {
                Some(Msix)
            } else if t.eq_ignore_ascii_case("cab") {
                Some(Cab)
            } else if t.eq_ignore_ascii_case("catalog") {
                Some(Catalog)
            } else {
                None
            }
        }
        None => None,
    }
}

fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|s| s.to_ascii_lowercase())
}

fn script_extensions_detected(path: &Path) -> bool {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        PowerShellScript | PowerShellModule | PowerShellManifest | WindowsScriptHost => true,
        _ => extension_lower(path)
            .map(|e| {
                #[cfg(windows)]
                {
                    crate::win::sip_rust::ps_script::extension_supported(&e)
                        || crate::win::sip_rust::ps_script::is_wsh_extension(&e)
                }
                #[cfg(not(windows))]
                {
                    matches!(
                        e.as_str(),
                        "ps1"
                            | "psd1"
                            | "psm1"
                            | "ps1xml"
                            | "psc1"
                            | "cdxml"
                            | "mof"
                            | "js"
                            | "vbs"
                            | "wsf"
                    )
                }
            })
            .unwrap_or(false),
    }
}

fn ensure_rust_sip_pe_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        PortableExecutable | WindowsMetadata => Ok(()),
        MsixFamily => Err(anyhow!(
            "--rust-sip pe (or PSIGN_RUST_SIP=pe) does not apply to MSIX/AppX packages; \
             use the OS AppX SIP / native signtool — disable Rust SIP with `--rust-sip off`"
        )),
        PowerShellScript | PowerShellModule | PowerShellManifest => Err(anyhow!(
            "use `--rust-sip script` (or PSIGN_RUST_SIP=script) for PowerShell-class files, not `--rust-sip pe`"
        )),
        WindowsInstaller | Catalog | Cabinet | WimImage => Err(anyhow!(
            "--rust-sip pe applies only to PE-based portable executables (.exe, .dll, .winmd, …); \
             got a non-PE SIP format for {}",
            path.display()
        )),
        WindowsScriptHost => Err(anyhow!(
            "use `--rust-sip script` for WSH scripts — PE Rust SIP does not apply to {}",
            path.display()
        )),
        Unknown => Err(anyhow!(
            "--rust-sip pe requires a PE-backed format; extension unknown for {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_msi_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        WindowsInstaller => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip msi` applies only to Windows Installer `.msi` packages; got {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_esd_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        WimImage => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip esd` applies only to WIM/ESD images (.wim, .esd); got {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_msix_allowed_for_format(path: &Path) -> Result<()> {
    let ext = extension_lower(path).unwrap_or_default();
    if matches!(ext.as_str(), "msix" | "appx" | "msixbundle" | "appxbundle") {
        return Ok(());
    }
    Err(anyhow!(
        "`--rust-sip msix` applies only to MSIX / APPX packages (`.msix`, `.appx`, `.msixbundle`, `.appxbundle`); got {}",
        path.display()
    ))
}

fn ensure_rust_sip_cab_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        Cabinet => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip cab` applies only to `.cab` files; got {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_catalog_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        Catalog => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip catalog` applies only to `.cat` files; got {}",
            path.display()
        )),
    }
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
            if seen.insert(p.clone()) {
                out.push(p);
            }
        }
    } else {
        let p = PathBuf::from(pattern);
        if seen.insert(p.clone()) {
            out.push(p);
        }
    }
    Ok(())
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
        expand_glob_pattern(&p.to_string_lossy(), &mut out, &mut seen)?;
    }
    Ok(out)
}

/// Best-effort PE embedded Authenticode detection for `--skip-signed` (certificate data directory).
fn file_has_embedded_authenticode(path: &Path) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };
    if data.len() < 0x40 {
        return false;
    }
    let Ok(pe_off_u32) = <[u8; 4]>::try_from(&data[0x3c..0x40]) else {
        return false;
    };
    let pe_off = u32::from_le_bytes(pe_off_u32) as usize;
    if pe_off + 0x200 > data.len() {
        return false;
    }
    if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return false;
    }
    let opt_off = pe_off + 24;
    let Some(magic_slice) = data.get(opt_off..opt_off + 2) else {
        return false;
    };
    let magic = u16::from_le_bytes([magic_slice[0], magic_slice[1]]);
    let dd_base = opt_off
        + match magic {
            0x20b => 112,
            0x10b => 96,
            _ => return false,
        };
    let cert_entry = dd_base + 4 * 8;
    let Some(chunk) = data.get(cert_entry..cert_entry + 8) else {
        return false;
    };
    let rva = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
    let size = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
    rva != 0 && size != 0
}

fn sign_one_target(args: &SignArgs, global: &GlobalOpts, target: &Path) -> Result<String> {
    #[cfg(feature = "azure-kv-sign")]
    if args
        .azure_key_vault_url
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return crate::win::azure_kv_sign::sign_with_azure_key_vault(args, target, global);
    }
    #[cfg(not(feature = "azure-kv-sign"))]
    if args
        .azure_key_vault_url
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(anyhow!(
            "Azure Key Vault signing requires building with `--features azure-kv-sign`"
        ));
    }
    sign_with_mssign32(args, target, global)
}

fn post_sign_rust_sip(
    backend: Option<RustSipBackend>,
    target: &Path,
    global: &GlobalOpts,
) -> Result<()> {
    match backend {
        Some(RustSipBackend::Pe) => {
            if matches!(
                crate::win::code_sign_format::detect(target),
                CodeSignFormat::PortableExecutable | CodeSignFormat::WindowsMetadata
            ) {
                crate::win::sip_rust::sign_pe::post_sign_digest_parity_check(target, global)?;
            }
        }
        Some(RustSipBackend::Script) => {
            let ext = extension_lower(target).unwrap_or_default();
            if crate::win::sip_rust::ps_script::extension_supported(&ext)
                || crate::win::sip_rust::ps_script::is_wsh_extension(&ext)
            {
                crate::win::sip_rust::sign_script::post_sign_script_digest_parity_check(
                    target, global,
                )?;
            }
        }
        Some(RustSipBackend::Msi) => {
            if matches!(
                crate::win::code_sign_format::detect(target),
                CodeSignFormat::WindowsInstaller
            ) {
                crate::win::sip_rust::sign_msi::post_sign_msi_digest_parity_check(target, global)?;
            }
        }
        Some(RustSipBackend::Esd) => {
            if matches!(
                crate::win::code_sign_format::detect(target),
                CodeSignFormat::WimImage
            ) {
                crate::win::sip_rust::sign_esd::post_sign_wim_esd_digest_parity_check(
                    target, global,
                )?;
            }
        }
        Some(RustSipBackend::Msix) => {
            let ext = extension_lower(target).unwrap_or_default();
            if matches!(ext.as_str(), "msix" | "appx" | "msixbundle" | "appxbundle") {
                crate::win::sip_rust::sign_msix::post_sign_msix_digest_parity_check(
                    target, global,
                )?;
            }
        }
        Some(RustSipBackend::Cab) => {
            if matches!(
                crate::win::code_sign_format::detect(target),
                CodeSignFormat::Cabinet
            ) {
                crate::win::sip_rust::sign_cab::post_sign_cab_digest_parity_check(target, global)?;
            }
        }
        Some(RustSipBackend::Catalog) => {
            if matches!(
                crate::win::code_sign_format::detect(target),
                CodeSignFormat::Catalog
            ) {
                crate::win::sip_rust::sign_catalog::post_sign_catalog_digest_parity_check(
                    target, global,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn try_sign_one(
    args: &SignArgs,
    global: &GlobalOpts,
    backend: Option<RustSipBackend>,
    target: &Path,
) -> Result<String> {
    if args.skip_signed && file_has_embedded_authenticode(target) {
        return Ok(format!("Skipped (already signed): {}\n", target.display()));
    }
    let block = sign_one_target(args, global, target)?;
    post_sign_rust_sip(backend, target, global)?;
    Ok(block)
}

fn ensure_rust_sip_script_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    if !script_extensions_detected(path) {
        return Err(anyhow!(
            "--rust-sip script applies only to PowerShell-class or WSH script files; got {}",
            path.display()
        ));
    }
    match crate::win::code_sign_format::detect(path) {
        PortableExecutable | WindowsMetadata | MsixFamily | WindowsInstaller | Catalog
        | Cabinet | WimImage => Err(anyhow!(
            "--rust-sip script does not apply to {}",
            path.display()
        )),
        _ => Ok(()),
    }
}

pub fn sign_file(args: &SignArgs, global: &GlobalOpts) -> Result<CommandOutput> {
    reject_split_digest_flags(args)?;
    if args.files.is_empty() && args.sign_input_file_list.is_none() {
        return Err(anyhow!("sign requires at least one file"));
    }

    #[cfg(feature = "azure-kv-sign")]
    crate::win::azure_kv_sign::validate_azure_kv_mutex(args)?;

    let targets = expand_sign_targets(args)?;
    if targets.is_empty() {
        return Err(anyhow!(
            "sign expanded to zero files (check globs and --input-file-list)"
        ));
    }

    validate_sign_constraints_paths(args, targets.iter().map(|p| p.as_path()))?;

    #[cfg(not(feature = "azure-kv-sign"))]
    if args
        .azure_key_vault_url
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(anyhow!(
            "Azure Key Vault signing requires building with `--features azure-kv-sign`"
        ));
    }

    let backend = rust_sip_backend(args);
    if matches!(backend, Some(RustSipBackend::Pe)) {
        for p in &targets {
            ensure_rust_sip_pe_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Script)) {
        for p in &targets {
            ensure_rust_sip_script_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Msi)) {
        for p in &targets {
            ensure_rust_sip_msi_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Esd)) {
        for p in &targets {
            ensure_rust_sip_esd_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Msix)) {
        for p in &targets {
            ensure_rust_sip_msix_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Cab)) {
        for p in &targets {
            ensure_rust_sip_cab_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Catalog)) {
        for p in &targets {
            ensure_rust_sip_catalog_allowed_for_format(p)?;
        }
    }

    let exit_style = resolved_sign_exit_codes(args);
    let parallel = args.max_degree_parallelism != Some(1) && targets.len() > 1;
    let threads = args
        .max_degree_parallelism
        .unwrap_or_else(rayon::current_num_threads)
        .max(1);

    struct Row {
        idx: usize,
        result: Result<String, anyhow::Error>,
    }

    let rows: Vec<Row> = if parallel {
        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| anyhow!("thread pool: {e}"))?;
        pool.install(|| {
            targets
                .par_iter()
                .enumerate()
                .map(|(idx, target)| Row {
                    idx,
                    result: try_sign_one(args, global, backend, target),
                })
                .collect()
        })
    } else {
        targets
            .iter()
            .enumerate()
            .map(|(idx, target)| Row {
                idx,
                result: try_sign_one(args, global, backend, target),
            })
            .collect()
    };

    let mut ordered = rows;
    ordered.sort_by_key(|r| r.idx);

    let mut combined = String::new();
    let mut successes: usize = 0;
    let mut failures: usize = 0;

    for (n, row) in ordered.into_iter().enumerate() {
        if n > 0 {
            combined.push('\n');
        }
        let target_display = targets[row.idx].display().to_string();
        match row.result {
            Ok(block) => {
                successes += 1;
                combined.push_str(&block);
            }
            Err(e) => {
                failures += 1;
                if args.continue_on_error {
                    combined.push_str(&format!("Failed: {target_display}: {e:#}\n"));
                } else {
                    return Err(e);
                }
            }
        }
    }

    let exit_code = match exit_style {
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
    };

    Ok(CommandOutput::with_exit(combined, exit_code))
}
