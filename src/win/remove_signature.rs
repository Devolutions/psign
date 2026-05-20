use crate::CommandOutput;
use crate::cli::{GlobalOpts, RemoveArgs};
use crate::win::code_sign_format;
use anyhow::{Result, anyhow};
use std::fs::OpenOptions;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    CERT_SECTION_TYPE_ANY, ImageEnumerateCertificates, ImageRemoveCertificate,
};

pub fn remove_command(args: &RemoveArgs, global: &GlobalOpts) -> Result<CommandOutput> {
    let has_s = args.strip_signature;
    let has_c = args.strip_chain_except_signer;
    let has_u = args.strip_unauthenticated_attributes;
    if !has_s && !has_c && !has_u {
        return Err(anyhow!(
            "remove requires one of --strip-signature (/s), --strip-chain-except-signer (/c), or --strip-unauthenticated-attributes (/u)"
        ));
    }
    if has_s && (has_c || has_u) {
        return Err(anyhow!(
            "combining --strip-signature (/s) with /c or /u is not supported in psign; use /s alone or native signtool"
        ));
    }

    if args.files.is_empty() {
        return Err(anyhow!("remove requires at least one file"));
    }

    if has_s || has_u || has_c {
        for path in &args.files {
            code_sign_format::assert_pe_image_authenticode_container(path)?;
        }
    }

    if has_c && has_u {
        let mut lines = String::new();
        for path in &args.files {
            lines.push_str(
                &crate::win::remove_unauth::strip_chain_and_unauthenticated_file(
                    path,
                    global.quiet,
                )?,
            );
        }
        return Ok(CommandOutput::ok(lines));
    }

    if has_c {
        let mut lines = String::new();
        for path in &args.files {
            lines.push_str(&crate::win::remove_unauth::strip_chain_except_signer_file(
                path,
                global.quiet,
            )?);
        }
        return Ok(CommandOutput::ok(lines));
    }

    if has_u {
        let mut lines = String::new();
        for path in &args.files {
            lines.push_str(
                &crate::win::remove_unauth::strip_unauthenticated_attributes_file(
                    path,
                    global.quiet,
                )?,
            );
        }
        return Ok(CommandOutput::ok(lines));
    }

    let mut lines = String::new();
    for path in &args.files {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
        let handle = HANDLE(file.as_raw_handle() as *mut _);

        loop {
            let mut count = 0u32;
            unsafe {
                ImageEnumerateCertificates(handle, CERT_SECTION_TYPE_ANY as u16, &mut count, None)
            }
            .map_err(|e| anyhow!("ImageEnumerateCertificates failed: {e}"))?;
            if count == 0 {
                break;
            }
            unsafe { ImageRemoveCertificate(handle, 0) }
                .map_err(|e| anyhow!("ImageRemoveCertificate failed: {e}"))?;
        }

        if !global.quiet {
            lines.push_str(&format!(
                "Removed embedded Authenticode data from {}\n",
                path.display()
            ));
        }
    }

    Ok(CommandOutput::ok(lines))
}
