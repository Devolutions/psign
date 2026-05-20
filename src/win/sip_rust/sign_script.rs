use crate::cli::GlobalOpts;
use anyhow::{Context, Result};
use psign_sip_digest::verify_script_digest_consistency;
use std::path::Path;

pub fn post_sign_script_digest_parity_check(target: &Path, global: &GlobalOpts) -> Result<()> {
    let raw = std::fs::read(target).with_context(|| format!("read {}", target.display()))?;
    let ext = target
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default();
    verify_script_digest_consistency(&raw, ext).with_context(|| {
        format!(
            "Rust SIP script digest parity failed for {}",
            target.display()
        )
    })?;
    if global.debug {
        eprintln!(
            "[psign debug] rust_sip_script digest check ok for {}",
            target.display()
        );
    }
    Ok(())
}
