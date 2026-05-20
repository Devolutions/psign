//! Portable **Authenticode SIP-style digest** recomputation used by `psign`.
//!
//! This crate has **no `windows` dependency** — it is intended to build on Linux/macOS for unit tests
//! and tooling. Signing and default verification still use Win32 in the main binary.

pub mod cab_digest;
pub mod catalog_digest;
pub mod esd_digest;
pub mod msi_digest;
pub mod msix_digest;
pub mod page_hashes;
pub mod pe_digest;
pub mod pe_embed;
pub mod pe_sign;
pub mod pkcs7;
pub mod pkcs7_wire;
pub mod ps_script;
pub mod rdp;
pub mod timestamp;
pub mod verify_pe;
pub mod wsh_script;

use anyhow::Result;

/// PowerShell-class (`pwrshsip.dll`) or WSH (`wshext.dll`) script digest vs PKCS#7 indirect data.
pub fn verify_script_digest_consistency(raw: &[u8], ext: &str) -> Result<()> {
    let ext_l = ext.to_ascii_lowercase();
    if ps_script::is_wsh_extension(&ext_l) {
        wsh_script::verify_wsh_digest_consistency(raw, &ext_l)
    } else {
        ps_script::verify_powershell_class_digest(raw, &ext_l)
    }
}
