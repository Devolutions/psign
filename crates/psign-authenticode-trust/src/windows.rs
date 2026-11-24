//! Windows Authenticode trust verification using the system trust provider.

use anyhow::{Result, anyhow};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, WinVerifyTrust,
};
use windows::core::{PCWSTR, PWSTR};

/// Verify an embedded signature using the Windows Authenticode `/pa` policy.
///
/// This checks the Windows system trust store and uses the CLI's default revocation settings.
/// It verifies the file by path; callers must prevent replacement between this call and any
/// subsequent signature inspection.
///
/// # Errors
///
/// Returns an error when the path contains a NUL or Windows rejects the signature.
pub fn verify_authenticode_path(path: &Path) -> Result<()> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(anyhow!("path contains a NUL character"));
    }
    wide.push(0);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WTD_REVOCATION_CHECK_NONE,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: std::ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: the UTF-16 path, file info and trust data remain alive until both calls return.
    let status = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut std::ffi::c_void,
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: the same trust data and provider state are passed to the matching close operation.
    unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action,
            &mut data as *mut _ as *mut std::ffi::c_void,
        );
    }
    if status != 0 {
        return Err(anyhow!(
            "WinVerifyTrust failed for {}: 0x{:08x}",
            path.display(),
            status as u32
        ));
    }
    Ok(())
}
