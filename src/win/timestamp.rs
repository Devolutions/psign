use crate::CommandOutput;
use crate::cli::{GlobalOpts, TimestampArgs};
use crate::win::timestamp_core::timestamp_with_mssign32;
use anyhow::{Result, anyhow};

pub fn timestamp_file(args: &TimestampArgs, global: &GlobalOpts) -> Result<CommandOutput> {
    if args.timestamp_pkcs7_files {
        return Err(anyhow!(
            "PKCS#7 timestamp mode (/p7) is not implemented; use native signtool"
        ));
    }
    if args.remove_seal {
        return Err(anyhow!(
            "timestamp /force (remove sealing signature before timestamp) is not implemented; use native signtool"
        ));
    }
    if args.no_seal_warn {
        return Err(anyhow!(
            "timestamp /nosealwarn is not implemented; use native signtool"
        ));
    }
    if args.files.is_empty() {
        return Err(anyhow!("timestamp requires at least one file"));
    }
    let mut combined = String::new();
    for (i, target) in args.files.iter().enumerate() {
        let block = timestamp_with_mssign32(args, target, global)?;
        if i > 0 {
            combined.push('\n');
        }
        combined.push_str(&block);
    }
    Ok(CommandOutput::ok(combined))
}
