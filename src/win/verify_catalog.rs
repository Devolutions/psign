use crate::cli::VerifyArgs;
use crate::win::verify_authcode::{
    pe_image_page_hashes_present_from_wvt_state, sp_opus_from_wvt_state,
};
use crate::win::verify_chain::{VerifyChainSummary, summarize_from_state};
use anyhow::{Result, anyhow};
use std::ffi::c_void;
use std::iter::once;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG;
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminReleaseContext,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS,
    WTD_CHOICE_CATALOG, WTD_GENERIC_CHAIN_POLICY_CREATE_INFO, WTD_GENERIC_CHAIN_POLICY_DATA,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTD_UICONTEXT_EXECUTE, WTD_USE_DEFAULT_OSVER_CHECK, WinVerifyTrust,
};
use windows::core::{PCWSTR, PWSTR};

fn to_wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(once(0))
        .collect()
}

fn to_hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
}

type CatalogVerifyResult = (
    VerifyChainSummary,
    Option<(String, Option<String>)>,
    Vec<String>,
);

fn calculate_member_hash(path: &std::path::Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let hfile = windows::Win32::Foundation::HANDLE(file.as_raw_handle() as *mut _);
    let mut hcatadmin: isize = 0;
    // SAFETY: out parameter is valid.
    unsafe {
        CryptCATAdminAcquireContext2(
            &mut hcatadmin,
            None,
            windows::core::PCWSTR::null(),
            None,
            None,
        )
    }
    .map_err(|e| anyhow!("CryptCATAdminAcquireContext2 failed: {e}"))?;
    let mut hash_len = 0u32;
    // SAFETY: requesting size with null hash buffer.
    unsafe { CryptCATAdminCalcHashFromFileHandle2(hcatadmin, hfile, &mut hash_len, None, None) }
        .map_err(|e| anyhow!("CryptCATAdminCalcHashFromFileHandle2(size) failed: {e}"))?;
    let mut hash = vec![0u8; hash_len as usize];
    // SAFETY: hash buffer valid for requested size.
    unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            hcatadmin,
            hfile,
            &mut hash_len,
            Some(hash.as_mut_ptr()),
            None,
        )
    }
    .map_err(|e| anyhow!("CryptCATAdminCalcHashFromFileHandle2(data) failed: {e}"))?;
    // SAFETY: context acquired above.
    unsafe {
        let _ = CryptCATAdminReleaseContext(hcatadmin, 0);
    }
    hash.truncate(hash_len as usize);
    Ok(hash)
}

pub fn verify_with_catalog(
    args: &VerifyArgs,
    member_path: &std::path::Path,
    catalog: &std::path::Path,
    mut action: windows::core::GUID,
) -> Result<CatalogVerifyResult> {
    if !catalog.exists() {
        return Err(anyhow!("catalog not found: {}", catalog.display()));
    }
    let mut calc_hash = calculate_member_hash(member_path)?;
    let file_path_w = to_wide(&member_path.display().to_string());
    let catalog_w = to_wide(&catalog.display().to_string());
    let tag_w = to_wide(&to_hex_upper(&calc_hash));

    let mut catalog_info = WINTRUST_CATALOG_INFO {
        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
        dwCatalogVersion: 0,
        pcwszCatalogFilePath: PCWSTR(catalog_w.as_ptr()),
        pcwszMemberTag: PCWSTR(tag_w.as_ptr()),
        pcwszMemberFilePath: PCWSTR(file_path_w.as_ptr()),
        hMemberFile: Default::default(),
        pbCalculatedFileHash: calc_hash.as_mut_ptr(),
        cbCalculatedFileHash: calc_hash.len() as u32,
        pcCatalogContext: std::ptr::null_mut(),
        hCatAdmin: 0,
    };
    let mut signer_chain = WTD_GENERIC_CHAIN_POLICY_CREATE_INFO::default();
    let mut policy_data = WTD_GENERIC_CHAIN_POLICY_DATA::default();
    let policy_ptr = if args.allow_test_root {
        signer_chain.dwFlags = CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG.0;
        policy_data.pSignerChainInfo = &mut signer_chain;
        &mut policy_data as *mut WTD_GENERIC_CHAIN_POLICY_DATA as *mut c_void
    } else {
        std::ptr::null_mut()
    };

    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: policy_ptr,
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: if args.revocation_check {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        },
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut catalog_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: {
            let mut f = if args.revocation_check {
                WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            } else {
                WTD_REVOCATION_CHECK_NONE
            };
            if args.os_version_check.is_some() {
                f = WINTRUST_DATA_PROVIDER_FLAGS(f.0 | WTD_USE_DEFAULT_OSVER_CHECK.0);
            }
            f
        },
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: std::ptr::null_mut(),
    };

    // SAFETY: WinTrust pointers reference valid stack/heap structures for call duration.
    let status = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };
    if status != 0 {
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: closing state handle created by verification call.
        let _ = unsafe {
            WinVerifyTrust(
                HWND(std::ptr::null_mut()),
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
            )
        };
        return Err(anyhow!("catalog verify failed with status 0x{status:08X}"));
    }

    let summary = summarize_from_state(data.hWVTStateData).unwrap_or(VerifyChainSummary {
        algorithm: "unknown".to_string(),
        timestamp: "none".to_string(),
        signer_subject: "unknown".to_string(),
    });
    let sp_opus = if args.print_description {
        sp_opus_from_wvt_state(data.hWVTStateData, 0)
    } else {
        None
    };
    let mut extra_warnings = Vec::new();
    if args.verify_page_hashes
        && !pe_image_page_hashes_present_from_wvt_state(data.hWVTStateData, 0)
    {
        extra_warnings.push("SignTool Warning: No page hashes are present.\n".to_string());
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closing state handle created by verification call.
    let _ = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast::<c_void>(),
        )
    };

    Ok((summary, sp_opus, extra_warnings))
}
