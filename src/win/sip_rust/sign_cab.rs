use crate::cli::GlobalOpts;
use anyhow::{Context, Result};
use psign_sip_digest::cab_digest;
use std::path::Path;

pub fn post_sign_cab_digest_parity_check(target: &Path, global: &GlobalOpts) -> Result<()> {
    cab_digest::verify_cab_digest_consistency(target)
        .with_context(|| format!("Rust SIP CAB digest parity failed for {}", target.display()))?;
    if global.debug {
        eprintln!(
            "[psign debug] rust_sip_cab digest check ok for {}",
            target.display()
        );
    }
    Ok(())
}
