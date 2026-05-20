use crate::cli::SignArgs;
use anyhow::{Result, anyhow};

/// Native `/dg`, `/ds`, `/di`, `/dxml` implement a multi-step workflow that stages files on disk.
/// This crate focuses on atomic embedded signing (`SignerSignEx3`) and decoupled `/dlib` flows.
pub fn reject_split_digest_flags(args: &SignArgs) -> Result<()> {
    if args.digest_generate.is_some()
        || args.digest_sign_only
        || args.digest_ingest.is_some()
        || args.digest_xml
    {
        return Err(anyhow!(
            "split digest workflow (/dg, /ds, /di, /dxml) is not implemented; \
             use native signtool.exe for staged digest signing, or use embedded signing / decoupled --dlib"
        ));
    }
    if args.pkcs7_output_dir.is_some()
        || args.pkcs7_content_oid.is_some()
        || args.pkcs7_content_embedding.is_some()
    {
        return Err(anyhow!(
            "PKCS#7 product output modes (/p7, /p7ce, /p7co) are not implemented for this SIP-centric signer"
        ));
    }
    Ok(())
}
