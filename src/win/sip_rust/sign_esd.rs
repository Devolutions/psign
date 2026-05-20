use crate::cli::GlobalOpts;
use anyhow::{Context, Result};
use psign_sip_digest::esd_digest;
use std::path::Path;

pub fn post_sign_wim_esd_digest_parity_check(target: &Path, global: &GlobalOpts) -> Result<()> {
    esd_digest::verify_wim_esd_digest_consistency(target).with_context(|| {
        format!(
            "Rust SIP WIM/ESD digest parity failed for {}",
            target.display()
        )
    })?;
    if global.debug {
        eprintln!(
            "[psign debug] rust_sip_esd digest check ok for {}",
            target.display()
        );
    }
    Ok(())
}
