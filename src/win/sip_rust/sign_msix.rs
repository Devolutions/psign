use crate::cli::GlobalOpts;
use anyhow::{Context, Result};
use psign_sip_digest::msix_digest;
use std::path::Path;

pub fn post_sign_msix_digest_parity_check(target: &Path, global: &GlobalOpts) -> Result<()> {
    msix_digest::verify_msix_digest_consistency(target).with_context(|| {
        format!(
            "Rust SIP MSIX/AppX digest parity failed for {}",
            target.display()
        )
    })?;
    if global.debug {
        eprintln!(
            "[psign debug] rust_sip_msix digest check ok for {}",
            target.display()
        );
    }
    Ok(())
}
