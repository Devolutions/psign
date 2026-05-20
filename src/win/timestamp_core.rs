use crate::cli::{DigestAlgorithm, GlobalOpts, TimestampArgs};
use crate::win::code_sign_format;
use crate::win::sealing::validate_timestamp_constraints;
use anyhow::{Context, Result, anyhow};
use std::ffi::CString;
use std::iter::once;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::{
    ALG_ID, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, CALG_SHA1, SIGNER_CONTEXT, SIGNER_FILE_INFO,
    SIGNER_SUBJECT_FILE, SIGNER_SUBJECT_INFO, SIGNER_SUBJECT_INFO_0, SIGNER_TIMESTAMP_AUTHENTICODE,
    SIGNER_TIMESTAMP_FLAGS, SIGNER_TIMESTAMP_RFC3161, SignerFreeSignerContext, SignerTimeStampEx2,
    SignerTimeStampEx3,
};
use windows::core::{PCSTR, PCWSTR};

fn to_wide(path: &std::path::Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(once(0)).collect()
}

fn alg_id(d: DigestAlgorithm) -> ALG_ID {
    match d {
        DigestAlgorithm::Sha1 => CALG_SHA1,
        DigestAlgorithm::Sha256 => CALG_SHA_256,
        DigestAlgorithm::Sha384 => CALG_SHA_384,
        DigestAlgorithm::Sha512 => CALG_SHA_512,
        DigestAlgorithm::CertHash => CALG_SHA_256,
    }
}

fn alg_oid_narrow(d: DigestAlgorithm) -> Result<CString> {
    let oid = match d {
        DigestAlgorithm::Sha1 => "1.3.14.3.2.26",
        DigestAlgorithm::Sha256 => "2.16.840.1.101.3.4.2.1",
        DigestAlgorithm::Sha384 => "2.16.840.1.101.3.4.2.2",
        DigestAlgorithm::Sha512 => "2.16.840.1.101.3.4.2.3",
        DigestAlgorithm::CertHash => "2.16.840.1.101.3.4.2.1",
    };
    CString::new(oid).context("digest OID")
}

fn log_ts_format(target: &Path, global: &GlobalOpts) {
    if !global.debug {
        return;
    }
    let fmt = code_sign_format::detect(target);
    eprintln!(
        "[psign debug] timestamp target format={fmt:?} sip_hint={}",
        fmt.sip_hint()
    );
}

pub fn timestamp_with_mssign32(
    args: &TimestampArgs,
    target: &Path,
    global: &GlobalOpts,
) -> Result<String> {
    validate_timestamp_constraints(args)?;
    log_ts_format(target, global);

    if args.seal_timestamp_url.is_some() {
        super::verify::require_sealing_signature_for_seal_timestamp(target)?;
    }

    let file_w = to_wide(target);
    let mut file_info = SIGNER_FILE_INFO {
        cbSize: size_of::<SIGNER_FILE_INFO>() as u32,
        pwszFileName: PCWSTR(file_w.as_ptr()),
        hFile: HANDLE::default(),
    };
    let mut index = 0u32;
    let subject = SIGNER_SUBJECT_INFO {
        cbSize: size_of::<SIGNER_SUBJECT_INFO>() as u32,
        pdwIndex: &mut index,
        dwSubjectChoice: SIGNER_SUBJECT_FILE,
        Anonymous: SIGNER_SUBJECT_INFO_0 {
            pSignerFileInfo: (&mut file_info as *mut SIGNER_FILE_INFO),
        },
    };

    let mut signer_context: *mut SIGNER_CONTEXT = std::ptr::null_mut();

    let rfc3161_or_seal = args
        .rfc3161_url
        .as_deref()
        .or(args.seal_timestamp_url.as_deref());
    if let Some(url) = rfc3161_or_seal {
        let url_w: Vec<u16> = std::ffi::OsStr::new(url)
            .encode_wide()
            .chain(once(0))
            .collect();
        let digest = args.digest.ok_or_else(|| {
            anyhow!("No /td flag specified. RFC3161 timestamping requires --digest (/td)")
        })?;
        let oid_c = alg_oid_narrow(digest)?;
        let idx = args.signature_index.unwrap_or(0);
        // Win32 metadata types the OID parameter as `PCWSTR`, but `SignerTimeStampEx3` interprets it like
        // `SignerSignEx3` — a narrow, null-terminated OID string (`szOID_*`), not UTF-16.
        let oid_narrow = PCSTR::from_raw(oid_c.as_ptr().cast());
        let oid_as_binding_ty: PCWSTR = unsafe { std::mem::transmute(oid_narrow) };
        unsafe {
            SignerTimeStampEx3(
                SIGNER_TIMESTAMP_FLAGS(SIGNER_TIMESTAMP_RFC3161.0),
                idx,
                &subject,
                PCWSTR(url_w.as_ptr()),
                oid_as_binding_ty,
                None,
                None,
                &mut signer_context,
                None,
                None,
            )
        }
        .map_err(|e| anyhow!("SignerTimeStampEx3 failed: {e}"))?;
    } else if let Some(url) = &args.legacy_url {
        if args.signature_index.is_some() && args.signature_index.unwrap() != 0 {
            return Err(anyhow!(
                "legacy timestamp mode does not support non-zero --signature-index (/tp)"
            ));
        }
        let url_w: Vec<u16> = std::ffi::OsStr::new(url)
            .encode_wide()
            .chain(once(0))
            .collect();
        // SAFETY: pointers are valid for call duration.
        let maybe_ctx = unsafe {
            SignerTimeStampEx2(
                Some(SIGNER_TIMESTAMP_AUTHENTICODE),
                &subject,
                PCWSTR(url_w.as_ptr()),
                alg_id(args.digest.unwrap_or(DigestAlgorithm::Sha256)),
                std::ptr::null(),
                std::ptr::null(),
            )
        }
        .map_err(|e| anyhow!("SignerTimeStampEx2 failed: {e}"))?;
        signer_context = maybe_ctx;
    }

    if !signer_context.is_null() {
        // SAFETY: returned signer context must be released by SignerFreeSignerContext.
        unsafe {
            let _ = SignerFreeSignerContext(signer_context);
        }
    }

    let mut report = String::new();
    report.push_str("Successfully timestamped\n");
    report.push_str(&format!("file={}\n", target.display()));
    if let Some(url) = &args.rfc3161_url {
        report.push_str("mode=rfc3161\n");
        report.push_str(&format!("url={url}\n"));
    } else if let Some(url) = &args.seal_timestamp_url {
        report.push_str("mode=rfc3161-seal\n");
        report.push_str(&format!("url={url}\n"));
    }
    if let Some(url) = &args.legacy_url {
        report.push_str("mode=legacy\n");
        report.push_str(&format!("url={url}\n"));
    }
    Ok(report)
}
