use crate::cli::GlobalOpts;
use anyhow::{Context, Result};
use psign_sip_digest::verify_pe::{
    PeDigestConsistencyResult, verify_pe_authenticode_digest_consistency,
};
use std::path::Path;

/// After OS signing, validate PKCS#7 indirect digest vs Rust PE Authenticode digest recomputation.
pub fn post_sign_digest_parity_check(target: &Path, global: &GlobalOpts) -> Result<()> {
    let bytes = std::fs::read(target).with_context(|| format!("read {}", target.display()))?;
    let diag = verify_pe_authenticode_digest_consistency(&bytes)
        .with_context(|| format!("Rust SIP PE digest parity failed for {}", target.display()))?;
    if global.debug {
        eprintln!(
            "[psign debug] rust_sip_pe digest_hex={} pkcs7_entries={} last_cert_index={}",
            diag.recomputed_digest_hex,
            diag.pkcs7_authenticode_entries,
            diag.matched_attribute_certificate_index
        );
    }
    Ok(())
}

/// Structured diagnostics for tooling (parity scripts, tests).
pub fn pe_authenticode_digest_diagnostics(bytes: &[u8]) -> Result<PeDigestConsistencyResult> {
    verify_pe_authenticode_digest_consistency(bytes)
}
