//! C ABI boundary for `psign-portable-core`.

use std::panic::{AssertUnwindSafe, catch_unwind};

use psign_portable_core::{
    PortableErrorCode, PortableErrorResponse, portable_clear_signature, portable_error_response,
    portable_get_signature, portable_sign, portable_validate_powershell_script, version,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

const STATUS_OK: u32 = 0;
const STATUS_INVALID_REQUEST: u32 = 1;
const STATUS_OPERATION_FAILED: u32 = 2;
const STATUS_PANIC: u32 = 3;

#[repr(C)]
pub struct PsignFfiBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct PsignFfiResult {
    pub status_code: u32,
    pub json: PsignFfiBuffer,
}

#[unsafe(no_mangle)]
pub extern "C" fn psign_core_version() -> PsignFfiResult {
    ok_json(&version())
}

/// Free a buffer returned by another `psign_core_*` function.
///
/// # Safety
///
/// `buffer` must be a `PsignFfiBuffer` returned by this library and must not have
/// been freed already. Passing any other pointer, length, or capacity is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn psign_core_free(buffer: PsignFfiBuffer) {
    if buffer.ptr.is_null() {
        return;
    }
    if buffer.cap == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.cap);
    }
}

/// Inspect a file's portable Authenticode signature.
///
/// # Safety
///
/// `request_json_ptr` must point to `request_json_len` readable UTF-8 bytes for the duration
/// of the call. The returned buffer must be released with `psign_core_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn psign_core_get_signature(
    request_json_ptr: *const u8,
    request_json_len: usize,
) -> PsignFfiResult {
    invoke_json(request_json_ptr, request_json_len, portable_get_signature)
}

/// Validate a PowerShell script/module signature from in-memory content.
///
/// # Safety
///
/// `request_json_ptr` must point to `request_json_len` readable UTF-8 bytes for the duration
/// of the call. The returned buffer must be released with `psign_core_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn psign_core_validate_powershell_script(
    request_json_ptr: *const u8,
    request_json_len: usize,
) -> PsignFfiResult {
    invoke_json(
        request_json_ptr,
        request_json_len,
        portable_validate_powershell_script,
    )
}

/// Sign a file with the portable Authenticode core.
///
/// # Safety
///
/// `request_json_ptr` must point to `request_json_len` readable UTF-8 bytes for the duration
/// of the call. The returned buffer must be released with `psign_core_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn psign_core_sign(
    request_json_ptr: *const u8,
    request_json_len: usize,
) -> PsignFfiResult {
    invoke_json(request_json_ptr, request_json_len, portable_sign)
}

/// Clear a file's portable Authenticode signature.
///
/// # Safety
///
/// `request_json_ptr` must point to `request_json_len` readable UTF-8 bytes for the duration
/// of the call. The returned buffer must be released with `psign_core_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn psign_core_clear_signature(
    request_json_ptr: *const u8,
    request_json_len: usize,
) -> PsignFfiResult {
    invoke_json(request_json_ptr, request_json_len, portable_clear_signature)
}

fn invoke_json<TRequest, TResponse>(
    request_json_ptr: *const u8,
    request_json_len: usize,
    f: impl FnOnce(TRequest) -> anyhow::Result<TResponse>,
) -> PsignFfiResult
where
    TRequest: DeserializeOwned,
    TResponse: Serialize,
{
    match catch_unwind(AssertUnwindSafe(|| {
        let request_json = unsafe { request_json_string(request_json_ptr, request_json_len) }?;
        let request = serde_json::from_str::<TRequest>(request_json)
            .map_err(|e| portable_error_response(PortableErrorCode::InvalidRequest, e))?;
        f(request).map_err(|e| portable_error_response(PortableErrorCode::OperationFailed, e))
    })) {
        Ok(Ok(response)) => ok_json(&response),
        Ok(Err(error)) => error_json(status_invalid_request_or_operation(&error), &error),
        Err(_) => error_json(
            STATUS_PANIC,
            &portable_error_response(
                PortableErrorCode::Panic,
                "panic crossing psign portable FFI boundary",
            ),
        ),
    }
}

fn status_invalid_request_or_operation(error: &PortableErrorResponse) -> u32 {
    match error.code {
        PortableErrorCode::InvalidRequest => STATUS_INVALID_REQUEST,
        _ => STATUS_OPERATION_FAILED,
    }
}

unsafe fn request_json_string<'a>(
    request_json_ptr: *const u8,
    request_json_len: usize,
) -> Result<&'a str, PortableErrorResponse> {
    if request_json_ptr.is_null() {
        return Err(portable_error_response(
            PortableErrorCode::InvalidRequest,
            "request JSON pointer is null",
        ));
    }
    let slice = unsafe { std::slice::from_raw_parts(request_json_ptr, request_json_len) };
    std::str::from_utf8(slice)
        .map_err(|e| portable_error_response(PortableErrorCode::InvalidRequest, e))
}

fn ok_json(value: &impl Serialize) -> PsignFfiResult {
    match serde_json::to_vec(value) {
        Ok(bytes) => PsignFfiResult {
            status_code: STATUS_OK,
            json: into_buffer(bytes),
        },
        Err(error) => error_json(
            STATUS_OPERATION_FAILED,
            &portable_error_response(PortableErrorCode::OperationFailed, error),
        ),
    }
}

fn error_json(status_code: u32, error: &PortableErrorResponse) -> PsignFfiResult {
    let bytes = serde_json::to_vec(error).unwrap_or_else(|_| {
        br#"{"schema_version":1,"code":"OperationFailed","message":"failed to serialize psign portable error"}"#.to_vec()
    });
    PsignFfiResult {
        status_code,
        json: into_buffer(bytes),
    }
}

fn into_buffer(mut bytes: Vec<u8>) -> PsignFfiBuffer {
    bytes.shrink_to_fit();
    let buffer = PsignFfiBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        cap: bytes.capacity(),
    };
    std::mem::forget(bytes);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn result_json(result: PsignFfiResult) -> String {
        let slice = unsafe { std::slice::from_raw_parts(result.json.ptr, result.json.len) };
        let text = std::str::from_utf8(slice).expect("utf-8").to_owned();
        unsafe { psign_core_free(result.json) };
        text
    }

    #[test]
    fn version_returns_json() {
        let result = psign_core_version();
        assert_eq!(result.status_code, STATUS_OK);
        let json = unsafe { result_json(result) };
        assert!(json.contains("psign-portable-core"));
    }

    #[test]
    fn invalid_json_returns_structured_error() {
        let request = b"{not json";
        let result = unsafe { psign_core_get_signature(request.as_ptr(), request.len()) };
        assert_eq!(result.status_code, STATUS_INVALID_REQUEST);
        let json = unsafe { result_json(result) };
        assert!(json.contains("InvalidRequest"));
    }

    #[test]
    fn validate_powershell_script_returns_json() {
        let request =
            br#"{"source_path_or_extension":".ps1","content_base64":"V3JpdGUtT3V0cHV0IDENCg=="}"#;
        let result =
            unsafe { psign_core_validate_powershell_script(request.as_ptr(), request.len()) };
        assert_eq!(result.status_code, STATUS_OK);
        let json = unsafe { result_json(result) };
        assert!(json.contains("PowerShellScript"));
        assert!(json.contains("NotSigned"));
    }
}
