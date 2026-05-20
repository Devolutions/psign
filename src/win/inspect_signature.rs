//! JSON inspection of Authenticode PKCS#7 (see [`psign_authenticode_trust::inspect`]).

use crate::CommandOutput;
use crate::cli::{GlobalOpts, InspectSignatureArgs, InspectSignatureInput};
use anyhow::{Context as _, Result};
use psign_authenticode_trust::{inspect_authenticode_pkcs7_der, inspect_pe_authenticode};

pub fn inspect_signature_command(
    args: &InspectSignatureArgs,
    global: &GlobalOpts,
) -> Result<CommandOutput> {
    let bytes =
        std::fs::read(&args.path).with_context(|| format!("read {}", args.path.display()))?;
    let json = match args.input {
        InspectSignatureInput::Pe => {
            serde_json::to_string_pretty(&inspect_pe_authenticode(&bytes)?)?
        }
        InspectSignatureInput::Pkcs7 => {
            serde_json::to_string_pretty(&inspect_authenticode_pkcs7_der(&bytes)?)?
        }
    };
    if global.debug {
        eprintln!("[debug] inspect-signature {}", args.path.display());
    }
    Ok(CommandOutput::ok(format!("{json}\n")))
}
