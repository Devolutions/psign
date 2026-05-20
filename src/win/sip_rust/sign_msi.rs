use crate::cli::GlobalOpts;
use anyhow::{Context, Result};
use psign_sip_digest::msi_digest;
use std::path::Path;

pub fn post_sign_msi_digest_parity_check(target: &Path, global: &GlobalOpts) -> Result<()> {
    msi_digest::verify_msi_digest_consistency(target)
        .with_context(|| format!("Rust SIP MSI digest parity failed for {}", target.display()))?;
    if global.debug {
        eprintln!(
            "[psign debug] rust_sip_msi digest check ok for {}",
            target.display()
        );
    }
    Ok(())
}
