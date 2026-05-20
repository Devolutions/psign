use crate::cli::GlobalOpts;
use anyhow::{Context, Result};
use psign_sip_digest::catalog_digest;
use std::path::Path;

pub fn post_sign_catalog_digest_parity_check(target: &Path, global: &GlobalOpts) -> Result<()> {
    catalog_digest::verify_catalog_digest_consistency(target).with_context(|| {
        format!(
            "Rust SIP catalog digest parity failed for {}",
            target.display()
        )
    })?;
    if global.debug {
        eprintln!(
            "[psign debug] rust_sip_catalog digest check ok for {}",
            target.display()
        );
    }
    Ok(())
}
