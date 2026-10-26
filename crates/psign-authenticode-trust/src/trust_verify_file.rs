//! Path-based format dispatch over the `trust_verify_*` entry points.
//!
//! Used where a caller has a file path rather than a known format (unified `psign-tool verify`
//! in both Windows and portable modes), so every caller applies the same per-format checks.

use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport};
use crate::{
    trust_verify_cab_bytes, trust_verify_catalog_bytes, trust_verify_msi_bytes,
    trust_verify_msix_bytes, trust_verify_nuget_bytes, trust_verify_pe_bytes,
    trust_verify_script_bytes, trust_verify_vsix_bytes, trust_verify_wim_esd_path,
    trust_verify_zip_bytes,
};
use anyhow::{Context, Result, anyhow};
use std::path::Path;

/// Trust-verify `path`, choosing the format from its extension (same mapping as portable
/// `psign-tool verify`).
pub fn trust_verify_path(path: &Path, opts: &TrustVerifyPeOptions) -> Result<TrustVerifyPeReport> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if matches!(ext.as_str(), "wim" | "esd") {
        return trust_verify_wim_esd_path(path, opts);
    }
    let read = || std::fs::read(path).with_context(|| format!("read {}", path.display()));
    match ext.as_str() {
        "exe" | "dll" | "sys" | "ocx" | "efi" | "winmd" => trust_verify_pe_bytes(&read()?, opts),
        "cab" => trust_verify_cab_bytes(&read()?, opts),
        "msi" | "msp" => trust_verify_msi_bytes(&read()?, opts),
        "cat" => trust_verify_catalog_bytes(&read()?, opts),
        "zip" => trust_verify_zip_bytes(&read()?, opts),
        "ps1" | "psd1" | "psm1" | "ps1xml" | "psc1" | "cdxml" | "mof" | "js" | "jse" | "vbs"
        | "vbe" | "wsf" => trust_verify_script_bytes(&read()?, &ext, opts),
        "msix" | "appx" | "msixbundle" | "appxbundle" => {
            trust_verify_msix_bytes(&read()?, &ext, opts)
        }
        "nupkg" | "snupkg" => trust_verify_nuget_bytes(&read()?, opts),
        "vsix" => trust_verify_vsix_bytes(&read()?, opts),
        _ => Err(anyhow!(
            "portable trust verification does not support this file format: {}",
            path.display()
        )),
    }
}
