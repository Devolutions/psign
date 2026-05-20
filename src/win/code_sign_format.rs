//! Code-signing **file formats** on Windows are handled by registered Cryptography **Subject Interface
//! Packages** (SIPs). `SignerSignEx3`, `SignerTimeStampEx*`, and `WinVerifyTrust` resolve the SIP from
//! the file path (extension / subject GUID); the SIP implementation lives in OS DLLs (provider-specific).
//!
//! Sign/timestamp/embedded-verify paths call the same Win32 APIs as native `signtool.exe`, so
//! PowerShell scripts (`.ps1`), PE files, Windows metadata (`.winmd`), MSIX packages, Windows Installer
//! packages (`.msi`), WIM/ESD images (`.wim`, `.esd`), etc. use the **existing Windows SIP DLL** at runtime by default.
//!
//! **Experimental:** `--rust-sip pe` (and `PSIGN_RUST_SIP=pe`) runs an optional **post-sign**
//! PE Authenticode digest consistency check in Rust after `SignerSignEx3`; it does not replace OS SIP
//! registration. See `src/win/sip_rust/` (re-exports `psign-sip-digest`) and `docs/rust-sip-architecture.md`.
//!
//! The types below exist for diagnostics (`--debug`), PE-centric `remove` validation, and documentation parity.

use anyhow::{Result, anyhow};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeSignFormat {
    /// `.ps1` — Authenticode signature block in script; OS PowerShell SIP.
    PowerShellScript,
    /// `.psm1`
    PowerShellModule,
    /// `.psd1`
    PowerShellManifest,
    /// `.exe`, `.dll`, `.sys`, … — PE `WIN_CERTIFICATE` embedding.
    PortableExecutable,
    /// `.winmd` — Windows metadata (CLI assembly); PE-based container, OS Authenticode SIP.
    WindowsMetadata,
    /// `.msix`, `.appx`, bundles — packaged via SIP (often with decoupled digest `/dlib` in tooling).
    MsixFamily,
    /// `.msi`, `.msp`, `.mst` — Windows Installer SIP (Authenticode over OLE compound storage).
    WindowsInstaller,
    /// `.wim`, `.esd` — WIM/ESD image SIP (`EsdSip.dll`).
    WimImage,
    /// `.cat` — catalog SIP (distinct from PE strip/remove paths).
    Catalog,
    /// `.cab` — cabinet SIP.
    Cabinet,
    /// `.js`, `.vbs`, `.wsf` — WSH script SIP where registered.
    WindowsScriptHost,
    /// Extension not mapped here; Windows may still resolve a SIP at runtime.
    Unknown,
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// Best-effort format from the path only (no file I/O). Used for logging and PE-only checks.
pub fn detect(path: &Path) -> CodeSignFormat {
    match extension(path).as_str() {
        "ps1" => CodeSignFormat::PowerShellScript,
        "psm1" => CodeSignFormat::PowerShellModule,
        "psd1" => CodeSignFormat::PowerShellManifest,
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "efi" | "mui" => {
            CodeSignFormat::PortableExecutable
        }
        "winmd" => CodeSignFormat::WindowsMetadata,
        "appx" | "appxbundle" | "msix" | "msixbundle" | "eappx" | "eappxbundle" | "emsix"
        | "emsixbundle" => CodeSignFormat::MsixFamily,
        "msi" | "msp" | "mst" => CodeSignFormat::WindowsInstaller,
        "wim" | "esd" => CodeSignFormat::WimImage,
        "cat" => CodeSignFormat::Catalog,
        "cab" => CodeSignFormat::Cabinet,
        "js" | "vbs" | "wsf" => CodeSignFormat::WindowsScriptHost,
        _ => CodeSignFormat::Unknown,
    }
}

impl CodeSignFormat {
    /// Hint for `--debug` output; exact DLL names vary by Windows version.
    pub fn sip_hint(self) -> &'static str {
        match self {
            CodeSignFormat::PowerShellScript
            | CodeSignFormat::PowerShellModule
            | CodeSignFormat::PowerShellManifest => {
                "PowerShell Authenticode SIP (OS-provided; loaded via CryptSIP)"
            }
            CodeSignFormat::PortableExecutable => {
                "PE SIP / Authenticode (OS-provided; loaded via CryptSIP)"
            }
            CodeSignFormat::WindowsMetadata => {
                "Windows metadata (.winmd) Authenticode — PE-based CLI assembly SIP (OS-provided)"
            }
            CodeSignFormat::MsixFamily => {
                "AppX/MSIX SIP (OS-provided; often with decoupled digest helpers)"
            }
            CodeSignFormat::WindowsInstaller => {
                "Windows Installer SIP / OLE storage Authenticode (OS-provided)"
            }
            CodeSignFormat::WimImage => {
                "WIM/ESD image Authenticode SIP (OS-provided; `EsdSip.dll`)"
            }
            CodeSignFormat::Catalog => "Catalog SIP (OS-provided)",
            CodeSignFormat::Cabinet => "Cabinet SIP (OS-provided)",
            CodeSignFormat::WindowsScriptHost => {
                "Windows Script Host SIP where registered (OS-provided)"
            }
            CodeSignFormat::Unknown => {
                "unknown extension — SIP chosen by Windows at runtime if registered"
            }
        }
    }
}

/// `remove /s`, `remove /c`, and `remove /u` use PE `Image*` certificate APIs only.
pub fn assert_pe_image_authenticode_container(path: &Path) -> Result<()> {
    match detect(path) {
        CodeSignFormat::PowerShellScript
        | CodeSignFormat::PowerShellModule
        | CodeSignFormat::PowerShellManifest
        | CodeSignFormat::WindowsScriptHost => Err(anyhow!(
            "remove uses PE Image certificate APIs and does not apply to script-signed files ({})",
            path.display()
        )),
        CodeSignFormat::Catalog => Err(anyhow!(
            "remove uses PE Image certificate APIs and does not apply to catalog files ({})",
            path.display()
        )),
        CodeSignFormat::Cabinet => Err(anyhow!(
            "remove uses PE Image certificate APIs and does not apply to cabinet files ({})",
            path.display()
        )),
        CodeSignFormat::WindowsInstaller => Err(anyhow!(
            "remove uses PE Image certificate APIs and does not apply to Windows Installer packages ({})",
            path.display()
        )),
        CodeSignFormat::WimImage => Err(anyhow!(
            "remove uses PE Image certificate APIs and does not apply to WIM/ESD images ({})",
            path.display()
        )),
        CodeSignFormat::MsixFamily => Err(anyhow!(
            "remove uses PE Image certificate APIs and does not apply to AppX/MSIX packages ({}) — use package tooling or native signtool where supported",
            path.display()
        )),
        CodeSignFormat::Unknown => Err(anyhow!(
            "remove --strip-signature (/s) and related modes require a PE-image-backed file; unknown extension for ({}) — use native signtool or a mapped format (.exe, .dll, .winmd, …)",
            path.display()
        )),
        CodeSignFormat::PortableExecutable | CodeSignFormat::WindowsMetadata => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_extensions() {
        assert_eq!(
            detect(Path::new(r"C:\x\y\Script.PS1")),
            CodeSignFormat::PowerShellScript
        );
        assert_eq!(
            detect(Path::new("mod.PSM1")),
            CodeSignFormat::PowerShellModule
        );
        assert_eq!(
            detect(Path::new("manifest.PSD1")),
            CodeSignFormat::PowerShellManifest
        );
        assert_eq!(
            detect(Path::new("kernel.sys")),
            CodeSignFormat::PortableExecutable
        );
        assert_eq!(
            detect(Path::new("app.msixbundle")),
            CodeSignFormat::MsixFamily
        );
        assert_eq!(detect(Path::new("pkg.eappx")), CodeSignFormat::MsixFamily);
        assert_eq!(
            detect(Path::new(r"C:\scripts\run.JS")),
            CodeSignFormat::WindowsScriptHost
        );
        assert_eq!(
            detect(Path::new("macro.vbs")),
            CodeSignFormat::WindowsScriptHost
        );
        assert_eq!(
            detect(Path::new("chain.wsf")),
            CodeSignFormat::WindowsScriptHost
        );
        assert_eq!(
            detect(Path::new("setup.msi")),
            CodeSignFormat::WindowsInstaller
        );
        assert_eq!(detect(Path::new("image.wim")), CodeSignFormat::WimImage);
        assert_eq!(
            detect(Path::new(r"C:\install.esd")),
            CodeSignFormat::WimImage
        );
        assert_eq!(
            detect(Path::new(r"C:\sdk\Windows.Win32.winmd")),
            CodeSignFormat::WindowsMetadata
        );
    }
}
