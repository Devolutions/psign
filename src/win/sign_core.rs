use crate::cli::{DigestAlgorithm, GlobalOpts, SignArgs};
use crate::win::code_sign_format;
use anyhow::{Context, Result, anyhow};
use std::ffi::CString;
use std::iter::once;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::BOOL;
use windows::Win32::Foundation::{
    CloseHandle, FreeLibrary, GENERIC_READ, GENERIC_WRITE, HANDLE, HMODULE, HWND,
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Cryptography::{
    ALG_ID, AT_SIGNATURE, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, CALG_SHA1, CERT_CONTEXT,
    CERT_FIND_FLAGS, CERT_FIND_HASH, CERT_FIND_ISSUER_STR_W, CERT_FIND_SUBJECT_STR_W,
    CERT_KEY_PROV_INFO_PROP_ID, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_SIGN_HASH_CNG_ALG_PROP_ID,
    CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_PROV_MEMORY, CERT_STORE_PROV_SYSTEM_W,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_ATTRIBUTES,
    CRYPT_INTEGER_BLOB, CertAddCertificateContextToStore, CertCloseStore,
    CertCreateCertificateContext, CertDuplicateCertificateContext, CertEnumCertificatesInStore,
    CertFindCertificateInStore, CertFreeCertificateContext, CertGetCertificateContextProperty,
    CertGetNameStringW, CertOpenStore, HCERTSTORE, HCRYPTPROV_LEGACY, PFN_AUTHENTICODE_DIGEST_SIGN,
    PFN_AUTHENTICODE_DIGEST_SIGN_EX, PFN_AUTHENTICODE_DIGEST_SIGN_EX_WITHFILEHANDLE,
    PFN_AUTHENTICODE_DIGEST_SIGN_WITHFILEHANDLE, PFXImportCertStore, PKCS12_ALLOW_OVERWRITE_KEY,
    PKCS12_ALWAYS_CNG_KSP, PKCS12_INCLUDE_EXTENDED_PROPERTIES, SIG_APPEND, SIGNER_ATTR_AUTHCODE,
    SIGNER_AUTHCODE_ATTR, SIGNER_CERT, SIGNER_CERT_0, SIGNER_CERT_POLICY_CHAIN, SIGNER_CERT_STORE,
    SIGNER_CERT_STORE_INFO, SIGNER_CONTEXT, SIGNER_DIGEST_SIGN_INFO, SIGNER_DIGEST_SIGN_INFO_0,
    SIGNER_FILE_INFO, SIGNER_NO_ATTR, SIGNER_PROVIDER_INFO, SIGNER_PROVIDER_INFO_0,
    SIGNER_SIGN_FLAGS, SIGNER_SIGNATURE_INFO, SIGNER_SIGNATURE_INFO_0, SIGNER_SUBJECT_FILE,
    SIGNER_SUBJECT_INFO, SIGNER_SUBJECT_INFO_0, SIGNER_TIMESTAMP_AUTHENTICODE,
    SIGNER_TIMESTAMP_RFC3161, SignerFreeSignerContext, SignerSignEx3,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::core::{PCSTR, PCWSTR, PWSTR};

/// Appx/MSIX **`SignerSignEx3`** often requires **`SIGNER_FILE_INFO.hFile`** be a live handle with
/// read/write access; path-only (`INVALID_HANDLE_VALUE`) can yield `APPX_E_MISSING_PUBLIC_KEY_OR_REQUIRED_DATA`.
struct SubjectPackageFileHandle(Option<HANDLE>);

impl SubjectPackageFileHandle {
    fn open_msix_subject(
        target: &std::path::Path,
        file_info: &mut SIGNER_FILE_INFO,
        path_wide: &[u16],
        debug: bool,
    ) -> Self {
        if !matches!(
            code_sign_format::detect(target),
            code_sign_format::CodeSignFormat::MsixFamily
        ) {
            return Self(None);
        }
        match unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(h) if !h.is_invalid() && h != INVALID_HANDLE_VALUE => {
                file_info.hFile = h;
                Self(Some(h))
            }
            Ok(h) => {
                if debug {
                    eprintln!(
                        "[psign debug] msix CreateFileW returned unusable handle {:?} for {}",
                        h,
                        target.display()
                    );
                }
                file_info.hFile = INVALID_HANDLE_VALUE;
                Self(None)
            }
            Err(e) => {
                if debug {
                    eprintln!(
                        "[psign debug] msix CreateFileW failed for {}: {}",
                        target.display(),
                        e
                    );
                }
                file_info.hFile = INVALID_HANDLE_VALUE;
                Self(None)
            }
        }
    }
}

impl Drop for SubjectPackageFileHandle {
    fn drop(&mut self) {
        if let Some(h) = self.0.take()
            && !h.is_invalid()
            && h != INVALID_HANDLE_VALUE
        {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
    }
}

/// Aggregates flat signing inputs for [`AppxSipClientData`] — same layout as SDK **`SIGNER_SIGN_EX2_PARAMS`**
/// ([Programmatically sign an app package](https://learn.microsoft.com/en-us/windows/win32/appxpkg/how-to-programmatically-sign-a-package)).
#[repr(C)]
struct SignerSignEx2Params {
    dw_flags: u32,
    p_subject_info: *const SIGNER_SUBJECT_INFO,
    p_signing_cert: *const SIGNER_CERT,
    p_signature_info: *const SIGNER_SIGNATURE_INFO,
    p_provider_info: *const SIGNER_PROVIDER_INFO,
    dw_timestamp_flags: u32,
    psz_algorithm_oid: PCSTR,
    pwsz_timestamp_url: PCWSTR,
    p_crypt_attrs: *const CRYPT_ATTRIBUTES,
    p_sip_data: *mut core::ffi::c_void,
    p_signer_context: *mut *mut SIGNER_CONTEXT,
    p_crypto_policy: *const core::ffi::c_void,
    p_reserved: *const core::ffi::c_void,
}

/// Passed as **`SignerSignEx3`** **`pSipData`** for **`.msix` / `.appx` / bundles**. Without this,
/// **`AppxSip.dll`** leaves **`SIP_SUBJECTINFO.pClientData`** unset and fails with **`0x80080209`**.
#[repr(C)]
struct AppxSipClientData {
    p_signer_params: *const SignerSignEx2Params,
    p_appx_sip_state: *mut core::ffi::c_void,
}

unsafe fn release_appx_sip_com_object(p: *mut core::ffi::c_void) {
    if p.is_null() {
        return;
    }
    unsafe {
        let vtbl = *(p as *const *const usize);
        let release = *vtbl.add(2);
        let release_fn: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32 =
            std::mem::transmute(release);
        release_fn(p);
    }
}

pub(crate) struct CertStore(pub(crate) HCERTSTORE);

impl Drop for CertStore {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: valid HCERTSTORE closed once.
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }
}

pub(crate) struct CertContext(pub(crate) *mut CERT_CONTEXT);

impl Drop for CertContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer is owned duplicate/find result and released once.
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0.cast_const()));
            }
        }
    }
}

/// Native `/nph`: Authenticode SIP consults `SIGNTOOL_PAGE_HASHES` during `SignerSignEx3`.
struct SignToolPageHashesEnvGuard(Option<Option<String>>);

impl SignToolPageHashesEnvGuard {
    fn install(no_page_hashes: bool) -> Self {
        if !no_page_hashes {
            return Self(None);
        }
        let prev = std::env::var("SIGNTOOL_PAGE_HASHES").ok();
        // SAFETY: signing runs on the main thread; matches native SignTool `/nph` env semantics.
        unsafe {
            std::env::set_var("SIGNTOOL_PAGE_HASHES", "0");
        }
        Self(Some(prev))
    }
}

impl Drop for SignToolPageHashesEnvGuard {
    fn drop(&mut self) {
        let Some(prev) = self.0.take() else {
            return;
        };
        // SAFETY: restoring prior environment after SignerSignEx3 returns.
        unsafe {
            match prev {
                Some(v) => std::env::set_var("SIGNTOOL_PAGE_HASHES", v),
                None => std::env::remove_var("SIGNTOOL_PAGE_HASHES"),
            }
        }
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(once(0))
        .collect()
}

pub(crate) fn encoding() -> CERT_QUERY_ENCODING_TYPE {
    CERT_QUERY_ENCODING_TYPE(0x0001_0001)
}

fn digest_alg_id(d: DigestAlgorithm) -> ALG_ID {
    match d {
        DigestAlgorithm::Sha1 => CALG_SHA1,
        DigestAlgorithm::Sha256 => CALG_SHA_256,
        DigestAlgorithm::Sha384 => CALG_SHA_384,
        DigestAlgorithm::Sha512 => CALG_SHA_512,
        DigestAlgorithm::CertHash => CALG_SHA_256,
    }
}

fn digest_oid(d: DigestAlgorithm) -> &'static str {
    match d {
        DigestAlgorithm::Sha1 => "1.3.14.3.2.26",
        DigestAlgorithm::Sha256 => "2.16.840.1.101.3.4.2.1",
        DigestAlgorithm::Sha384 => "2.16.840.1.101.3.4.2.2",
        DigestAlgorithm::Sha512 => "2.16.840.1.101.3.4.2.3",
        DigestAlgorithm::CertHash => "2.16.840.1.101.3.4.2.1",
    }
}

/// Path to `Azure.CodeSigning.Dlib.dll` under an extracted **Microsoft.ArtifactSigning.Client**-style layout.
pub(crate) fn artifact_signing_dlib_path(root: &std::path::Path) -> std::path::PathBuf {
    let arch = if cfg!(target_pointer_width = "64") {
        "x64"
    } else {
        "x86"
    };
    root.join("bin")
        .join(arch)
        .join("Azure.CodeSigning.Dlib.dll")
}

/// Effective decoupled digest DLL path: explicit `--dlib` or derived from `--trusted-signing-dlib-root`.
pub(crate) fn resolved_decoupled_dlib_path(args: &SignArgs) -> Option<std::path::PathBuf> {
    if let Some(p) = &args.dlib {
        return Some(p.clone());
    }
    args.trusted_signing_dlib_root
        .as_ref()
        .map(|p| artifact_signing_dlib_path(p))
}

fn load_decoupled_digest_info(
    dlib: &std::path::Path,
    dmdf: &std::path::Path,
) -> Result<(
    HMODULE,
    SIGNER_DIGEST_SIGN_INFO,
    CRYPT_INTEGER_BLOB,
    Vec<u8>,
    &'static str,
)> {
    let metadata =
        std::fs::read(dmdf).with_context(|| format!("failed to read dmdf '{}'", dmdf.display()))?;
    if metadata.is_empty() {
        return Err(anyhow!("dmdf metadata file must not be empty"));
    }
    let mut metadata_owned = metadata;
    let mut blob = CRYPT_INTEGER_BLOB {
        cbData: metadata_owned.len() as u32,
        pbData: metadata_owned.as_mut_ptr(),
    };
    let dlib_w = to_wide(&dlib.display().to_string());
    let arch = if cfg!(target_pointer_width = "64") {
        "x64"
    } else {
        "x86"
    };
    // SAFETY: library path pointer is valid and NUL terminated.
    let module = unsafe { LoadLibraryW(PCWSTR(dlib_w.as_ptr())) }
        .map_err(|e| {
            anyhow!(
                "LoadLibraryW('{}') failed: {e}. \
If using Azure Artifact Signing: install .NET 8, deploy the full NuGet `bin\\{arch}` directory (all dependent DLLs), and use the {arch} `Azure.CodeSigning.Dlib.dll` with a {arch} psign-tool build.",
                dlib.display()
            )
        })?;

    fn resolve_proc<T>(module: HMODULE, name: &str) -> Option<T> {
        let c = CString::new(name).ok()?;
        // SAFETY: module is loaded and proc name is NUL-terminated.
        let p = unsafe { GetProcAddress(module, PCSTR(c.as_ptr().cast())) }?;
        // SAFETY: caller selects matching function signature T.
        Some(unsafe { std::mem::transmute_copy(&p) })
    }

    let ex_with_file = resolve_proc::<PFN_AUTHENTICODE_DIGEST_SIGN_EX_WITHFILEHANDLE>(
        module,
        "AuthenticodeDigestSignExWithFileHandle",
    );
    let ex = resolve_proc::<PFN_AUTHENTICODE_DIGEST_SIGN_EX>(module, "AuthenticodeDigestSignEx");
    let with_file = resolve_proc::<PFN_AUTHENTICODE_DIGEST_SIGN_WITHFILEHANDLE>(
        module,
        "AuthenticodeDigestSignWithFileHandle",
    );
    let basic = resolve_proc::<PFN_AUTHENTICODE_DIGEST_SIGN>(module, "AuthenticodeDigestSign");
    let (choice, export_name, anon) = if let Some(pfn) = ex_with_file {
        let mut a = SIGNER_DIGEST_SIGN_INFO_0::default();
        a.pfnAuthenticodeDigestSignExWithFileHandle = pfn;
        (4u32, "AuthenticodeDigestSignExWithFileHandle", a)
    } else if let Some(pfn) = ex {
        let mut a = SIGNER_DIGEST_SIGN_INFO_0::default();
        a.pfnAuthenticodeDigestSignEx = pfn;
        (3u32, "AuthenticodeDigestSignEx", a)
    } else if let Some(pfn) = with_file {
        let mut a = SIGNER_DIGEST_SIGN_INFO_0::default();
        a.pfnAuthenticodeDigestSignWithFileHandle = pfn;
        (2u32, "AuthenticodeDigestSignWithFileHandle", a)
    } else if let Some(pfn) = basic {
        let mut a = SIGNER_DIGEST_SIGN_INFO_0::default();
        a.pfnAuthenticodeDigestSign = pfn;
        (1u32, "AuthenticodeDigestSign", a)
    } else {
        // SAFETY: library handle was loaded in this function.
        unsafe {
            let _ = FreeLibrary(module);
        }
        return Err(anyhow!(
            "dlib does not export a supported AuthenticodeDigestSign* function"
        ));
    };

    let digest = SIGNER_DIGEST_SIGN_INFO {
        cbSize: size_of::<SIGNER_DIGEST_SIGN_INFO>() as u32,
        dwDigestSignChoice: choice,
        Anonymous: anon,
        pMetadataBlob: &mut blob,
        dwReserved: 0,
        dwReserved2: 0,
        dwReserved3: 0,
    };
    Ok((module, digest, blob, metadata_owned, export_name))
}

fn load_store_from_pfx(args: &SignArgs, pfx_path: &std::path::Path) -> Result<CertStore> {
    let pfx = std::fs::read(pfx_path)
        .with_context(|| format!("failed to read PFX '{}'", pfx_path.display()))?;
    let password = to_wide(args.password.as_deref().unwrap_or_default());
    let blob = CRYPT_INTEGER_BLOB {
        cbData: pfx.len() as u32,
        pbData: pfx.as_ptr() as *mut u8,
    };
    // SAFETY: blob/password buffers valid during call.
    // Include extended properties + CNG KSP so PKCS#12 keys work with SignerSignEx3 (esp. MSIX SIP).
    let import_flags =
        PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_INCLUDE_EXTENDED_PROPERTIES | PKCS12_ALWAYS_CNG_KSP;
    let store = unsafe { PFXImportCertStore(&blob, PCWSTR(password.as_ptr()), import_flags) }
        .map_err(|e| anyhow!("PFXImportCertStore failed: {e}"))?;
    Ok(CertStore(store))
}

fn load_store_from_system(args: &SignArgs) -> Result<CertStore> {
    let flags = CERT_OPEN_STORE_FLAGS(if args.machine_store {
        CERT_SYSTEM_STORE_LOCAL_MACHINE
    } else {
        CERT_SYSTEM_STORE_CURRENT_USER
    });
    let name = to_wide(&args.store_name);
    // SAFETY: pvPara points to a valid, nul-terminated store name for duration of call.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            encoding(),
            Some(HCRYPTPROV_LEGACY(0)),
            flags,
            Some(name.as_ptr().cast()),
        )
    }
    .map_err(|e| anyhow!("CertOpenStore('{}') failed: {e}", args.store_name))?;
    Ok(CertStore(store))
}

fn load_store(args: &SignArgs) -> Result<CertStore> {
    if let Some(pfx) = &args.pfx {
        return load_store_from_pfx(args, pfx);
    }
    load_store_from_system(args)
}

#[cfg_attr(not(feature = "azure-kv-sign"), allow(dead_code))]
pub(crate) fn open_memory_cert_store() -> Result<CertStore> {
    // SAFETY: `CERT_STORE_PROV_MEMORY` with null para opens an empty in-memory certificate store.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            encoding(),
            Some(HCRYPTPROV_LEGACY(0)),
            CERT_OPEN_STORE_FLAGS(0),
            None,
        )
    }
    .map_err(|e| anyhow!("CertOpenStore(MEMORY) failed: {e}"))?;
    Ok(CertStore(store))
}

pub(crate) fn adopt_cert(ctx: *mut CERT_CONTEXT) -> Result<CertContext> {
    if ctx.is_null() {
        return Err(anyhow!("certificate selection returned null context"));
    }
    // SAFETY: duplicate context to obtain owned pointer independent of store enumeration lifetime.
    let dup = unsafe { CertDuplicateCertificateContext(Some(ctx.cast_const())) };
    if dup.is_null() {
        return Err(anyhow!("failed to duplicate certificate context"));
    }
    Ok(CertContext(dup))
}

fn parse_sha1_hex(input: &str) -> Result<[u8; 20]> {
    let clean = input.replace([':', ' '], "");
    if clean.len() != 40 {
        return Err(anyhow!("--cert-sha1 must be 40 hex characters"));
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        let b = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("--cert-sha1 contains invalid hex"))?;
        out[i] = b;
    }
    Ok(out)
}

pub(crate) fn merge_additional_cert_file(store: HCERTSTORE, path: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read additional cert '{}'", path.display()))?;
    // SAFETY: bytes are DER/serialized certificate bytes.
    let ctx = unsafe { CertCreateCertificateContext(encoding(), &bytes) };
    if ctx.is_null() {
        return Err(anyhow!(
            "failed to parse certificate from '{}'",
            path.display()
        ));
    }
    unsafe {
        let r = CertAddCertificateContextToStore(
            Some(store),
            ctx.cast_const(),
            CERT_STORE_ADD_REPLACE_EXISTING,
            None,
        );
        let _ = CertFreeCertificateContext(Some(ctx.cast_const()));
        r.map_err(|e| anyhow!("CertAddCertificateContextToStore: {e}"))?;
    }
    Ok(())
}

pub(crate) fn infer_digest_for_cert(cert: *const CERT_CONTEXT) -> Result<DigestAlgorithm> {
    let mut cb = 0u32;
    let _ = unsafe {
        CertGetCertificateContextProperty(cert, CERT_SIGN_HASH_CNG_ALG_PROP_ID, None, &mut cb)
    };
    if cb == 0 {
        return Ok(DigestAlgorithm::Sha256);
    }
    let mut buf = vec![0u8; cb as usize];
    unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_SIGN_HASH_CNG_ALG_PROP_ID,
            Some(buf.as_mut_ptr().cast()),
            &mut cb,
        )?;
    }
    let wide: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&x| x != 0)
        .collect();
    let s = String::from_utf16_lossy(&wide).to_ascii_uppercase();
    if s.contains("SHA512") {
        return Ok(DigestAlgorithm::Sha512);
    }
    if s.contains("SHA384") {
        return Ok(DigestAlgorithm::Sha384);
    }
    if s.contains("SHA256") {
        return Ok(DigestAlgorithm::Sha256);
    }
    if s.contains("SHA1") {
        return Ok(DigestAlgorithm::Sha1);
    }
    Ok(DigestAlgorithm::Sha256)
}

fn cert_usage_strings(cert: *const CERT_CONTEXT) -> Result<Vec<String>> {
    crate::win::cert_props::enhanced_key_usage_oids(cert)
}

fn issuer_simple_contains(cert: *const CERT_CONTEXT, needle: &str) -> Result<bool> {
    let len = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG,
            None,
            None,
        )
    };
    if len == 0 {
        return Ok(false);
    }
    let mut buf = vec![0u16; len as usize];
    let n = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG,
            None,
            Some(buf.as_mut_slice()),
        )
    };
    let issuer = String::from_utf16_lossy(&buf[..n.saturating_sub(1) as usize]);
    Ok(issuer
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase()))
}

pub(crate) fn validate_cert_constraints(cert: *const CERT_CONTEXT, args: &SignArgs) -> Result<()> {
    if let Some(prefix) = args
        .signing_cert_eku_oid_prefix
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let usages = cert_usage_strings(cert)?;
        if !usages.iter().any(|oid| oid.starts_with(prefix)) {
            return Err(anyhow!(
                "certificate does not include an enhanced key usage OID starting with '{prefix}'"
            ));
        }
    }
    if let Some(want) = &args.eku_oid {
        let usages = cert_usage_strings(cert)?;
        let ok = usages
            .iter()
            .any(|u| u == want || u.contains(want.as_str()));
        if !ok {
            return Err(anyhow!(
                "certificate does not include requested enhanced key usage '{want}'"
            ));
        }
    }
    if args.eku_windows_system_component {
        let usages = cert_usage_strings(cert)?;
        let oid = "1.3.6.1.4.1.311.10.3.6";
        if !usages.iter().any(|u| u == oid) {
            return Err(anyhow!(
                "certificate does not include Windows System Component Verification EKU"
            ));
        }
    }
    if let Some(root_needle) = &args.root_subject_name {
        let ok = crate::win::verify_chain::chain_root_subject_contains(cert, root_needle)
            .map_err(|e| anyhow!("{e}"))?;
        if !ok {
            return Err(anyhow!(
                "certificate chain root does not match subject filter '{}'",
                root_needle
            ));
        }
    }
    Ok(())
}

fn cert_matches_signing_eku_prefix(cert: *const CERT_CONTEXT, args: &SignArgs) -> Result<bool> {
    let Some(prefix) = args
        .signing_cert_eku_oid_prefix
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(true);
    };
    Ok(cert_usage_strings(cert)?
        .iter()
        .any(|oid| oid.starts_with(prefix)))
}

fn find_cert(store: HCERTSTORE, args: &SignArgs) -> Result<CertContext> {
    if let Some(thumb) = &args.cert_sha1 {
        let bytes = parse_sha1_hex(thumb)?;
        let hash = CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        };
        // SAFETY: pointers point to valid in-scope data.
        let ctx = unsafe {
            CertFindCertificateInStore(
                store,
                CERT_QUERY_ENCODING_TYPE(0x0001_0001),
                0,
                CERT_FIND_FLAGS(CERT_FIND_HASH.0),
                Some((&hash as *const CRYPT_INTEGER_BLOB).cast()),
                None,
            )
        };
        if ctx.is_null() {
            return Err(anyhow!(
                "certificate with requested SHA1 was not found in PFX"
            ));
        }
        let c = adopt_cert(ctx)?;
        validate_cert_constraints(c.0 as *const _, args)?;
        return Ok(c);
    }

    if let Some(subject) = &args.subject_name {
        let wide = to_wide(subject);
        // SAFETY: pointers point to valid in-scope data.
        let ctx = unsafe {
            CertFindCertificateInStore(
                store,
                CERT_QUERY_ENCODING_TYPE(0x0001_0001),
                0,
                CERT_FIND_FLAGS(CERT_FIND_SUBJECT_STR_W.0),
                Some(wide.as_ptr().cast()),
                None,
            )
        };
        if ctx.is_null() {
            return Err(anyhow!(
                "certificate with subject '{}' was not found in selected store",
                subject
            ));
        }
        let c = adopt_cert(ctx)?;
        if let Some(iss) = &args.issuer_name
            && !issuer_simple_contains(c.0 as *const _, iss)?
        {
            return Err(anyhow!(
                "certificate issuer does not match requested issuer filter '{iss}'"
            ));
        }
        validate_cert_constraints(c.0 as *const _, args)?;
        return Ok(c);
    }

    if let Some(issuer) = &args.issuer_name {
        let wide = to_wide(issuer);
        let ctx = unsafe {
            CertFindCertificateInStore(
                store,
                CERT_QUERY_ENCODING_TYPE(0x0001_0001),
                0,
                CERT_FIND_FLAGS(CERT_FIND_ISSUER_STR_W.0),
                Some(wide.as_ptr().cast()),
                None,
            )
        };
        if ctx.is_null() {
            return Err(anyhow!(
                "certificate with issuer '{}' was not found in selected store",
                issuer
            ));
        }
        let c = adopt_cert(ctx)?;
        validate_cert_constraints(c.0 as *const _, args)?;
        return Ok(c);
    }

    fn has_private_key(cert: *const CERT_CONTEXT) -> bool {
        let mut len = 0u32;
        // SAFETY: probing property length only.
        unsafe {
            CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, None, &mut len)
                .is_ok()
        }
    }
    fn ft_to_u64(ft: windows::Win32::Foundation::FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }
    let mut best_ctx: Option<CertContext> = None;
    let mut best_not_after: u64 = 0;
    let mut prev: Option<*const CERT_CONTEXT> = None;
    loop {
        // SAFETY: enumeration uses previous context pointer from this loop only.
        let current = unsafe { CertEnumCertificatesInStore(store, prev) };
        if current.is_null() {
            break;
        }
        // SAFETY: current points to valid context returned by CertEnumCertificatesInStore.
        let not_after = unsafe {
            if (*current).pCertInfo.is_null() {
                0
            } else {
                ft_to_u64((*(*current).pCertInfo).NotAfter)
            }
        };
        if has_private_key(current.cast_const()) {
            if cert_matches_signing_eku_prefix(current.cast_const(), args)?
                && (best_ctx.is_none() || not_after > best_not_after)
            {
                best_ctx = Some(adopt_cert(current)?);
                best_not_after = not_after;
            }
        } else if best_ctx.is_none() && cert_matches_signing_eku_prefix(current.cast_const(), args)?
        {
            best_ctx = Some(adopt_cert(current)?);
            best_not_after = not_after;
        }
        prev = Some(current.cast_const());
    }
    let selected = best_ctx.ok_or_else(|| {
        if args
            .signing_cert_eku_oid_prefix
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            anyhow!("no certificate in the selected store matched --signing-cert-eku-prefix")
        } else {
            anyhow!("selected store does not contain a signing certificate")
        }
    })?;
    if !args.auto_select && args.pfx.is_none() {
        return Err(anyhow!(
            "system-store signing requires --auto-select or explicit certificate filters"
        ));
    }
    validate_cert_constraints(selected.0 as *const _, args)?;
    Ok(selected)
}

fn read_thumbprint(cert: *const CERT_CONTEXT) -> Result<String> {
    crate::win::cert_props::cert_sha1_thumbprint_upper(cert)
}

fn log_sign_format(target: &std::path::Path, global: &GlobalOpts) {
    if !global.debug {
        return;
    }
    let fmt = code_sign_format::detect(target);
    eprintln!(
        "[psign debug] sign target format={fmt:?} sip_hint={}",
        fmt.sip_hint()
    );
}

/// Windows layout for `CERT_KEY_PROV_INFO_PROP_ID` (`Crypt32`).
#[repr(C)]
struct CryptKeyProvInfoBlob {
    pwsz_container_name: *mut u16,
    pwsz_prov_name: *mut u16,
    dw_prov_type: u32,
    dw_flags: u32,
    c_prov_param: u32,
    rg_prov_param: *mut std::ffi::c_void,
    dw_key_spec: u32,
}

fn clone_wstr_with_nul(ptr: *const u16) -> Option<Vec<u16>> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` must point at a NUL-terminated wide string (Crypt32 property blob).
    unsafe {
        let mut len = 0usize;
        loop {
            let w = *ptr.add(len);
            if w == 0 {
                break;
            }
            len += 1;
            if len > 4096 {
                return None;
            }
        }
        let mut v = Vec::with_capacity(len.saturating_add(1));
        for i in 0..len {
            v.push(*ptr.add(i));
        }
        v.push(0);
        Some(v)
    }
}

/// Optional CSP/KSP binding from `CERT_KEY_PROV_INFO_PROP_ID`. Some SIP paths (notably AppX/MSIX)
/// fail `SignerSignEx3` with `CRYPT_E_NO_PROVIDER` unless this is passed explicitly.
struct AutoSignerProviderScratch {
    inner: SIGNER_PROVIDER_INFO,
    _prov_name: Vec<u16>,
    _container_name: Vec<u16>,
}

fn auto_signer_provider_scratch(
    cert: *const CERT_CONTEXT,
) -> Result<Option<AutoSignerProviderScratch>> {
    let mut cb: u32 = 0;
    unsafe {
        let _ = CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, None, &mut cb);
    }
    if (cb as usize) < size_of::<CryptKeyProvInfoBlob>() {
        return Ok(None);
    }
    let mut buf = vec![0u8; cb as usize];
    unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_KEY_PROV_INFO_PROP_ID,
            Some(buf.as_mut_ptr().cast()),
            &mut cb,
        )
        .map_err(|e| {
            anyhow!("CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID): {e}")
        })?;
    }
    // SAFETY: Crypt32 returns a packed `CRYPT_KEY_PROV_INFO`; string pointers reference `buf`.
    let info = unsafe { &*(buf.as_ptr() as *const CryptKeyProvInfoBlob) };
    let Some(container_name) = clone_wstr_with_nul(info.pwsz_container_name.cast_const()) else {
        return Ok(None);
    };
    let Some(prov_name) = clone_wstr_with_nul(info.pwsz_prov_name.cast_const()) else {
        return Ok(None);
    };
    let inner = SIGNER_PROVIDER_INFO {
        cbSize: size_of::<SIGNER_PROVIDER_INFO>() as u32,
        pwszProviderName: PCWSTR(prov_name.as_ptr()),
        dwProviderType: info.dw_prov_type,
        dwKeySpec: info.dw_key_spec,
        dwPvkChoice: windows::Win32::Security::Cryptography::PVK_TYPE_KEYCONTAINER,
        Anonymous: SIGNER_PROVIDER_INFO_0 {
            pwszKeyContainer: PWSTR(container_name.as_ptr().cast_mut()),
        },
    };
    Ok(Some(AutoSignerProviderScratch {
        inner,
        _prov_name: prov_name,
        _container_name: container_name,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn authenticode_sign_embedded(
    args: &SignArgs,
    target: &std::path::Path,
    global: &GlobalOpts,
    store: HCERTSTORE,
    cert: &CertContext,
    resolved_digest: DigestAlgorithm,
    provider_ptr: Option<*const SIGNER_PROVIDER_INFO>,
    digest_ptr: Option<*const SIGNER_DIGEST_SIGN_INFO>,
    mode_report: &'static str,
    store_report_name: &str,
    free_library_target: Option<HMODULE>,
    decoupled_report: Option<(&'static str, usize)>,
) -> Result<String> {
    let msix_family = matches!(
        code_sign_format::detect(target),
        code_sign_format::CodeSignFormat::MsixFamily
    );
    let file_w = to_wide(&target.display().to_string());
    let mut file_info = SIGNER_FILE_INFO {
        cbSize: size_of::<SIGNER_FILE_INFO>() as u32,
        pwszFileName: PCWSTR(file_w.as_ptr()),
        hFile: if msix_family {
            INVALID_HANDLE_VALUE
        } else {
            HANDLE::default()
        },
    };
    let _msix_subject_handle =
        SubjectPackageFileHandle::open_msix_subject(target, &mut file_info, &file_w, global.debug);
    if global.debug && msix_family {
        eprintln!(
            "[psign debug] msix SIGNER_FILE_INFO.hFile={:?} is_invalid={}",
            file_info.hFile,
            file_info.hFile.is_invalid()
        );
    }
    let mut index = 0u32;
    let subject = SIGNER_SUBJECT_INFO {
        cbSize: size_of::<SIGNER_SUBJECT_INFO>() as u32,
        pdwIndex: &mut index,
        dwSubjectChoice: SIGNER_SUBJECT_FILE,
        Anonymous: SIGNER_SUBJECT_INFO_0 {
            pSignerFileInfo: &mut file_info,
        },
    };

    let mut cert_store_info = SIGNER_CERT_STORE_INFO {
        cbSize: size_of::<SIGNER_CERT_STORE_INFO>() as u32,
        pSigningCert: cert.0 as *const CERT_CONTEXT,
        dwCertPolicy: SIGNER_CERT_POLICY_CHAIN,
        hCertStore: store,
    };
    let signer_cert = SIGNER_CERT {
        cbSize: size_of::<SIGNER_CERT>() as u32,
        dwCertChoice: SIGNER_CERT_STORE,
        Anonymous: SIGNER_CERT_0 {
            pCertStoreInfo: &mut cert_store_info,
        },
        hwnd: HWND(std::ptr::null_mut()),
    };

    let desc_store = args.description.as_ref().map(|s| to_wide(s));
    let url_store = args.description_url.as_ref().map(|s| to_wide(s));
    let use_authcode = args.description.is_some() || args.description_url.is_some();
    let mut authcode = SIGNER_ATTR_AUTHCODE {
        cbSize: size_of::<SIGNER_ATTR_AUTHCODE>() as u32,
        fCommercial: BOOL::from(false),
        fIndividual: BOOL::from(false),
        pwszName: desc_store
            .as_ref()
            .map(|w| PCWSTR(w.as_ptr()))
            .unwrap_or(PCWSTR::null()),
        pwszInfo: url_store
            .as_ref()
            .map(|w| PCWSTR(w.as_ptr()))
            .unwrap_or(PCWSTR::null()),
    };
    let sig_union = SIGNER_SIGNATURE_INFO_0 {
        pAttrAuthcode: if use_authcode {
            std::ptr::addr_of_mut!(authcode)
        } else {
            std::ptr::null_mut()
        },
    };
    let signature = SIGNER_SIGNATURE_INFO {
        cbSize: size_of::<SIGNER_SIGNATURE_INFO>() as u32,
        algidHash: digest_alg_id(resolved_digest),
        dwAttrChoice: if use_authcode {
            SIGNER_AUTHCODE_ATTR
        } else {
            SIGNER_NO_ATTR
        },
        Anonymous: sig_union,
        psAuthenticated: std::ptr::null_mut(),
        psUnauthenticated: std::ptr::null_mut(),
    };

    let mut flags = SIGNER_SIGN_FLAGS(0);
    if args.append_signature {
        flags |= SIG_APPEND;
    }

    let mut signer_context: *mut SIGNER_CONTEXT = std::ptr::null_mut();

    let sign_rfc3161_ts = args
        .timestamp_url
        .as_deref()
        .or(args.seal_timestamp_url.as_deref());
    let ts_digest_for_report = match (&sign_rfc3161_ts, &args.legacy_timestamp_url) {
        (Some(_), None) => args.timestamp_digest.ok_or_else(|| {
            anyhow!("No /td flag specified. RFC3161 timestamping requires --timestamp-digest (/td)")
        })?,
        _ => resolved_digest,
    };

    let (stamp_policy, oid_stamp, url_stamp) = match (&sign_rfc3161_ts, &args.legacy_timestamp_url)
    {
        (Some(u), None) => {
            let td = args.timestamp_digest.ok_or_else(|| {
                anyhow!(
                    "No /td flag specified. RFC3161 timestamping requires --timestamp-digest (/td)"
                )
            })?;
            (
                Some(SIGNER_TIMESTAMP_RFC3161),
                CString::new(digest_oid(td)).context("invalid digest OID")?,
                to_wide(u),
            )
        }
        (None, Some(u)) => (
            Some(SIGNER_TIMESTAMP_AUTHENTICODE),
            CString::new(digest_oid(resolved_digest)).context("invalid digest OID")?,
            to_wide(u),
        ),
        (None, None) => (
            None,
            CString::new("").context("invalid digest OID")?,
            vec![0u16],
        ),
        _ => {
            return Err(anyhow!(
                "choose either --timestamp-url (RFC3161) or --legacy-timestamp-url (/t), not both"
            ));
        }
    };

    let _page_hash_guard = SignToolPageHashesEnvGuard::install(args.no_page_hashes);

    // Cleartext MSIX/Appx **`CryptSIPPutSignedDataMsg`** always runs **`AppxSipClientData::Initialize`**, which
    // requires **`SIP_SUBJECTINFO.pClientData`** — including decoupled **`/dlib`** signing (**`pDigestSignInfo`** is separate).
    let use_appx_sip_client_data = msix_family;

    let sign_result = if use_appx_sip_client_data {
        let ts_flags = stamp_policy.map(|t| t.0).unwrap_or(0);
        let oid_pcstr = if stamp_policy.is_some() {
            PCSTR(oid_stamp.as_ptr().cast())
        } else {
            PCSTR::null()
        };
        let url_pcwstr = if stamp_policy.is_some() {
            PCWSTR(url_stamp.as_ptr())
        } else {
            PCWSTR::null()
        };
        let prov = provider_ptr.unwrap_or(std::ptr::null());
        let mut appx_sip_data = AppxSipClientData {
            p_signer_params: std::ptr::null(),
            p_appx_sip_state: std::ptr::null_mut(),
        };
        let appx_raw = std::ptr::addr_of_mut!(appx_sip_data);
        let ex2_params = SignerSignEx2Params {
            dw_flags: flags.0,
            p_subject_info: std::ptr::addr_of!(subject),
            p_signing_cert: std::ptr::addr_of!(signer_cert),
            p_signature_info: std::ptr::addr_of!(signature),
            p_provider_info: prov,
            dw_timestamp_flags: ts_flags,
            psz_algorithm_oid: oid_pcstr,
            pwsz_timestamp_url: url_pcwstr,
            p_crypt_attrs: std::ptr::null(),
            p_sip_data: appx_raw.cast(),
            p_signer_context: std::ptr::addr_of_mut!(signer_context),
            p_crypto_policy: std::ptr::null(),
            p_reserved: std::ptr::null(),
        };
        // SAFETY: `AppxSipClientData` / `SignerSignEx2Params` match the MSVC layout Microsoft documents for
        // package signing; circular `p_sip_data` ↔ `p_signer_params` pointers match the official sample.
        unsafe {
            (*appx_raw).p_signer_params = &ex2_params;
            let r = SignerSignEx3(
                flags,
                &subject,
                &signer_cert,
                &signature,
                provider_ptr,
                stamp_policy,
                oid_pcstr,
                url_pcwstr,
                None,
                Some(appx_raw.cast()),
                &mut signer_context,
                None,
                digest_ptr,
                None,
            );
            release_appx_sip_com_object(appx_sip_data.p_appx_sip_state);
            r
        }
    } else {
        // SAFETY: all passed structures point to valid memory for the duration of call.
        unsafe {
            SignerSignEx3(
                flags,
                &subject,
                &signer_cert,
                &signature,
                provider_ptr,
                stamp_policy,
                if stamp_policy.is_some() {
                    PCSTR(oid_stamp.as_ptr().cast())
                } else {
                    PCSTR::null()
                },
                if stamp_policy.is_some() {
                    PCWSTR(url_stamp.as_ptr())
                } else {
                    PCWSTR::null()
                },
                None,
                None,
                &mut signer_context,
                None,
                digest_ptr,
                None,
            )
        }
    };
    if let Some(module) = free_library_target {
        // SAFETY: module loaded by LoadLibraryW in this call path.
        unsafe {
            let _ = FreeLibrary(module);
        }
    }

    if !signer_context.is_null() {
        // SAFETY: returned by SignerSignEx3 and must be freed with SignerFreeSignerContext.
        unsafe {
            let _ = SignerFreeSignerContext(signer_context);
        }
    }

    sign_result.map_err(|e| anyhow!("SignerSignEx3 failed: {e}"))?;

    let thumb = read_thumbprint(cert.0 as *const CERT_CONTEXT)
        .unwrap_or_else(|_| "<unavailable>".to_string());
    let mut report = String::new();
    report.push_str("Successfully signed\n");
    report.push_str(&format!("mode={mode_report}\n"));
    report.push_str(&format!("file={}\n", target.display()));
    report.push_str(&format!("digest={}\n", resolved_digest.as_signtool_name()));
    report.push_str(&format!(
        "timestamp_digest={}\n",
        ts_digest_for_report.as_signtool_name()
    ));
    report.push_str(&format!("thumbprint={thumb}\n"));
    report.push_str(&format!("store={store_report_name}\n"));
    report.push_str(&format!(
        "store_scope={}\n",
        if args.machine_store {
            "machine"
        } else {
            "user"
        }
    ));
    if let Some((export_name, dmdf_len)) = decoupled_report {
        report.push_str(&format!("decoupled_export={export_name}\n"));
        report.push_str(&format!("dmdf_bytes={dmdf_len}\n"));
    }
    if let Some(url) = &args.timestamp_url {
        report.push_str(&format!("timestamp_url={url}\n"));
    } else if let Some(url) = &args.seal_timestamp_url {
        report.push_str(&format!("seal_timestamp_url={url}\n"));
    }
    if let Some(url) = &args.legacy_timestamp_url {
        report.push_str(&format!("legacy_timestamp_url={url}\n"));
    }
    Ok(report)
}

pub fn sign_with_mssign32(
    args: &SignArgs,
    target: &std::path::Path,
    global: &GlobalOpts,
) -> Result<String> {
    log_sign_format(target, global);
    crate::win::sealing::validate_sign_constraints_paths(args, std::iter::once(target))?;
    let decoupled = resolved_decoupled_dlib_path(args).is_some() && args.dmdf.is_some();
    if args.page_hashes && !decoupled {
        return Err(anyhow!(
            "--page-hashes requires --dlib or --trusted-signing-dlib-root and --dmdf in this implementation"
        ));
    }

    let store_wrap = load_store(args)?;
    for ac in &args.additional_certs {
        merge_additional_cert_file(store_wrap.0, ac)?;
    }
    let cert = find_cert(store_wrap.0, args)?;
    let auto_provider_scratch = auto_signer_provider_scratch(cert.0 as *const CERT_CONTEXT)?;
    let resolved_digest = match args.digest {
        DigestAlgorithm::CertHash => infer_digest_for_cert(cert.0 as *const CERT_CONTEXT)?,
        other => other,
    };

    let provider_name_w;
    let key_container_w;
    let mut provider = SIGNER_PROVIDER_INFO::default();
    let provider_ptr = if args.csp.is_some() || args.key_container.is_some() {
        provider_name_w = to_wide(args.csp.as_deref().unwrap_or_default());
        key_container_w = to_wide(args.key_container.as_deref().unwrap_or_default());
        provider.cbSize = size_of::<SIGNER_PROVIDER_INFO>() as u32;
        provider.pwszProviderName = if args.csp.is_some() {
            PCWSTR(provider_name_w.as_ptr())
        } else {
            PCWSTR::null()
        };
        provider.dwProviderType = 0;
        provider.dwKeySpec = AT_SIGNATURE.0;
        provider.dwPvkChoice = windows::Win32::Security::Cryptography::PVK_TYPE_KEYCONTAINER;
        provider.Anonymous = SIGNER_PROVIDER_INFO_0 {
            pwszKeyContainer: if args.key_container.is_some() {
                PWSTR(key_container_w.as_ptr() as *mut _)
            } else {
                PWSTR::null()
            },
        };
        Some(&provider as *const SIGNER_PROVIDER_INFO)
    } else {
        auto_provider_scratch
            .as_ref()
            .map(|ap| &ap.inner as *const SIGNER_PROVIDER_INFO)
    };

    let mut decoupled_runtime: Option<(
        HMODULE,
        SIGNER_DIGEST_SIGN_INFO,
        CRYPT_INTEGER_BLOB,
        Vec<u8>,
        &'static str,
    )> = None;
    if decoupled {
        let dlib = resolved_decoupled_dlib_path(args)
            .ok_or_else(|| anyhow!("internal error: decoupled mode without dlib path"))?;
        let dmdf = args
            .dmdf
            .as_ref()
            .ok_or_else(|| anyhow!("internal error: decoupled mode without --dmdf"))?;
        decoupled_runtime = Some(load_decoupled_digest_info(&dlib, dmdf)?);
    }
    let digest_ptr = decoupled_runtime
        .as_ref()
        .map(|(_, digest_info, _, _, _)| digest_info as *const SIGNER_DIGEST_SIGN_INFO);
    let free_library_target = decoupled_runtime.as_ref().map(|(m, _, _, _, _)| *m);
    let decoupled_report = decoupled_runtime
        .as_ref()
        .map(|(_, _, _, metadata, export_name)| (*export_name, metadata.len()));

    authenticode_sign_embedded(
        args,
        target,
        global,
        store_wrap.0,
        &cert,
        resolved_digest,
        provider_ptr,
        digest_ptr,
        if decoupled {
            "decoupled-rust-core"
        } else {
            "embedded-rust-core"
        },
        &args.store_name,
        free_library_target,
        decoupled_report,
    )
}
