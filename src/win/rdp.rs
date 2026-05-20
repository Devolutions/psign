use crate::cli::{GlobalOpts, RdpArgs};
use crate::rdp;
use crate::{CommandOutput, response_argv};
use anyhow::{Context, Result, anyhow};
use sha2::{Digest as _, Sha256};
use std::ffi::CString;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows::Win32::Foundation::{FILETIME, GetLastError};
use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CONTEXT, CERT_OPEN_STORE_FLAGS,
    CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_SIGN_MESSAGE_PARA, CertCloseStore,
    CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertOpenStore, CryptSignMessage,
    HCERTSTORE, HCRYPTPROV_LEGACY,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, RegCloseKey, RegOpenKeyExW, RegQueryValueExW,
};
use windows::core::{PCWSTR, PSTR};

const MY_STORE: &str = "MY";
const DEFAULT_RDP_HASH_OID: &str = "2.16.840.1.101.3.4.2.1";
const RDP_SIGNING_EKUS: &[&str] = &[
    "1.3.6.1.5.5.7.3.1",
    "1.3.6.1.5.5.7.3.3",
    "1.3.6.1.4.1.311.54.1.1",
];

struct CertStore(HCERTSTORE);

impl Drop for CertStore {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }
}

struct CertContext(*mut CERT_CONTEXT);

impl Drop for CertContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0.cast_const()));
            }
        }
    }
}

struct ChainContext(*mut CERT_CHAIN_CONTEXT);

impl Drop for ChainContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CertFreeCertificateChain(self.0);
            }
        }
    }
}

pub fn rdp_command(args: &RdpArgs, global: &GlobalOpts) -> Result<CommandOutput> {
    let cert = find_rdp_certificate(args)?;
    let hash_oid = rdp_hash_algorithm_oid()?;
    let mut stdout = String::new();
    let mut exit_code = 0;

    for path in &args.files {
        match sign_one(path, &cert, &hash_oid, args.dry_run) {
            Ok(()) => {
                if global.verbose {
                    if args.dry_run {
                        stdout.push_str(&format!("Test signed {}\n", path.display()));
                    } else {
                        stdout.push_str(&format!("Signed {}\n", path.display()));
                    }
                }
            }
            Err(e) => {
                exit_code = response_argv::combine_batch_exit_codes(exit_code, 1);
                stdout.push_str(&format!("Failed to sign {}: {e:#}\n", path.display()));
            }
        }
    }

    if exit_code == 0 && !global.verbose {
        stdout.push_str("All rdp file(s) have been successfully signed.\n");
    }

    Ok(CommandOutput::with_exit(stdout, exit_code))
}

fn sign_one(path: &Path, cert: &CertContext, hash_oid: &CString, dry_run: bool) -> Result<()> {
    let input = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let text = rdp::decode_rdp_text(&input);
    let records = rdp::parse_records(&text);
    let mut prepared = rdp::prepare_for_signature(records)?;
    let pkcs7 = sign_secure_blob(&prepared.secure_blob, cert, hash_oid)?;
    rdp::apply_pkcs7_signature(&mut prepared.records, &pkcs7);

    if !dry_run {
        let output = rdp::encode_native_unicode(&rdp::records_to_text(&prepared.records));
        std::fs::write(path, output).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

fn sign_secure_blob(blob: &[u8], cert: &CertContext, hash_oid: &CString) -> Result<Vec<u8>> {
    validate_rdp_signing_cert(cert.0.cast_const())?;
    let chain = build_chain(cert.0.cast_const())?;
    let mut chain_certs = chain_cert_contexts(&chain)?;
    if chain_certs.is_empty() {
        chain_certs.push(cert.0);
    }

    let mut sign_para = CRYPT_SIGN_MESSAGE_PARA {
        cbSize: size_of::<CRYPT_SIGN_MESSAGE_PARA>() as u32,
        dwMsgEncodingType: encoding().0,
        pSigningCert: cert.0.cast_const(),
        ..Default::default()
    };
    sign_para.HashAlgorithm.pszObjId = PSTR(hash_oid.as_ptr() as *mut u8);
    sign_para.cMsgCert = chain_certs.len() as u32;
    sign_para.rgpMsgCert = chain_certs.as_mut_ptr();

    let blob_ptr = blob.as_ptr();
    let blob_len = blob.len() as u32;
    let mut signed_len = 0u32;
    unsafe {
        CryptSignMessage(
            &sign_para,
            true,
            1,
            Some(&blob_ptr),
            &blob_len,
            None,
            &mut signed_len,
        )
        .with_context(|| format!("CryptSignMessage length failed: {:?}", GetLastError()))?;
    }
    let mut signed = vec![0u8; signed_len as usize];
    unsafe {
        CryptSignMessage(
            &sign_para,
            true,
            1,
            Some(&blob_ptr),
            &blob_len,
            Some(signed.as_mut_ptr()),
            &mut signed_len,
        )
        .with_context(|| format!("CryptSignMessage failed: {:?}", GetLastError()))?;
    }
    signed.truncate(signed_len as usize);
    Ok(signed)
}

fn find_rdp_certificate(args: &RdpArgs) -> Result<CertContext> {
    let wanted = requested_thumbprint(args)?;
    for location in [
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CERT_SYSTEM_STORE_CURRENT_USER,
    ] {
        let store = open_system_store(location)?;
        if let Some(cert) = find_cert_in_store(store.0, &wanted)? {
            return Ok(cert);
        }
    }
    Err(anyhow!(
        "RDP signing certificate with requested {} thumbprint was not found in LocalMachine\\MY or CurrentUser\\MY",
        wanted.label
    ))
}

struct Thumbprint {
    bytes: Vec<u8>,
    label: &'static str,
}

fn requested_thumbprint(args: &RdpArgs) -> Result<Thumbprint> {
    if let Some(value) = &args.cert_sha256 {
        return Ok(Thumbprint {
            bytes: parse_hex(value, 32, "SHA256")?,
            label: "SHA256",
        });
    }
    if let Some(value) = &args.cert_sha1 {
        return Ok(Thumbprint {
            bytes: parse_hex(value, 20, "SHA1")?,
            label: "SHA1",
        });
    }
    Err(anyhow!("rdp signing requires --sha256 or --sha1"))
}

fn find_cert_in_store(store: HCERTSTORE, wanted: &Thumbprint) -> Result<Option<CertContext>> {
    let mut prev: Option<*const CERT_CONTEXT> = None;
    loop {
        let current = unsafe { CertEnumCertificatesInStore(store, prev) };
        if current.is_null() {
            return Ok(None);
        }
        if cert_thumbprint_matches(current.cast_const(), wanted)? {
            return duplicate_cert(current.cast_const()).map(Some);
        }
        prev = Some(current.cast_const());
    }
}

fn cert_thumbprint_matches(cert: *const CERT_CONTEXT, wanted: &Thumbprint) -> Result<bool> {
    if wanted.label == "SHA1" {
        let actual = crate::win::cert_props::cert_sha1_thumbprint_upper(cert)?;
        return Ok(actual.as_bytes().eq(hex_upper(&wanted.bytes).as_bytes()));
    }
    let encoded = unsafe {
        std::slice::from_raw_parts((*cert).pbCertEncoded, (*cert).cbCertEncoded as usize)
    };
    let actual = Sha256::digest(encoded);
    Ok(actual[..] == wanted.bytes[..])
}

fn duplicate_cert(cert: *const CERT_CONTEXT) -> Result<CertContext> {
    let dup = unsafe { CertDuplicateCertificateContext(Some(cert)) };
    if dup.is_null() {
        return Err(anyhow!("failed to duplicate certificate context"));
    }
    Ok(CertContext(dup))
}

fn open_system_store(location: u32) -> Result<CertStore> {
    let name = to_wide(MY_STORE);
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            encoding(),
            Some(HCRYPTPROV_LEGACY(0)),
            CERT_OPEN_STORE_FLAGS(location),
            Some(name.as_ptr().cast()),
        )
    }
    .with_context(|| format!("open certificate store {MY_STORE}"))?;
    Ok(CertStore(store))
}

fn build_chain(cert: *const CERT_CONTEXT) -> Result<ChainContext> {
    let chain_para = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    unsafe { CertGetCertificateChain(None, cert, None, None, &chain_para, 0, None, &mut chain) }
        .context("CertGetCertificateChain failed")?;
    Ok(ChainContext(chain))
}

fn chain_cert_contexts(chain: &ChainContext) -> Result<Vec<*mut CERT_CONTEXT>> {
    if chain.0.is_null() {
        return Ok(Vec::new());
    }
    let simple = unsafe { *(*chain.0).rgpChain };
    if simple.is_null() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for idx in 0..unsafe { (*simple).cElement } {
        let element = unsafe { *(*simple).rgpElement.add(idx as usize) };
        if !element.is_null() {
            let cert = unsafe { (*element).pCertContext };
            if !cert.is_null() {
                out.push(cert.cast_mut());
            }
        }
    }
    Ok(out)
}

fn validate_rdp_signing_cert(cert: *const CERT_CONTEXT) -> Result<()> {
    let usages = crate::win::cert_props::enhanced_key_usage_oids(cert)?;
    if !usages.is_empty()
        && !RDP_SIGNING_EKUS
            .iter()
            .any(|oid| usages.iter().any(|u| u == oid))
    {
        return Err(anyhow!(
            "certificate is not valid for RDP signing; expected serverAuth, codeSigning, or RDP signing EKU"
        ));
    }
    if !cert_time_valid_now(cert) {
        return Err(anyhow!("certificate is outside its validity period"));
    }
    Ok(())
}

fn cert_time_valid_now(cert: *const CERT_CONTEXT) -> bool {
    if cert.is_null() {
        return false;
    }
    let info = unsafe { (*cert).pCertInfo };
    if info.is_null() {
        return false;
    }
    let now = system_time_as_filetime();
    let not_before = filetime_to_u64(unsafe { (*info).NotBefore });
    let not_after = filetime_to_u64(unsafe { (*info).NotAfter });
    now >= not_before && now <= not_after
}

fn system_time_as_filetime() -> u64 {
    const WINDOWS_TICK: u64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs() + SEC_TO_UNIX_EPOCH) * WINDOWS_TICK + u64::from(now.subsec_nanos() / 100)
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

fn rdp_hash_algorithm_oid() -> Result<CString> {
    match read_rdp_hash_algorithm_oid()? {
        Some(oid) if !oid.trim().is_empty() => CString::new(oid.trim())
            .map_err(|_| anyhow!("RDP HashAlgorithm registry value contains NUL")),
        _ => CString::new(DEFAULT_RDP_HASH_OID).map_err(|e| anyhow!("{e}")),
    }
}

fn read_rdp_hash_algorithm_oid() -> Result<Option<String>> {
    let key_path = to_wide(r"System\CurrentControlSet\Services\TScPubRPC");
    let value_name = to_wide("HashAlgorithm");
    let mut key = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            KEY_READ,
            &mut key,
        )
    }
    .is_err()
    {
        return Ok(None);
    }
    let _guard = RegistryKey(key);

    let mut ty = REG_SZ;
    let mut bytes = 0u32;
    if unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut ty),
            None,
            Some(&mut bytes),
        )
    }
    .is_err()
        || bytes == 0
    {
        return Ok(None);
    }
    if ty != REG_SZ {
        return Err(anyhow!(
            "RDP HashAlgorithm registry value has unexpected type"
        ));
    }
    let mut buf = vec![0u8; bytes as usize];
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr()),
            Some(&mut bytes),
        )
    };
    if status.is_err() {
        return Err(anyhow!("read RDP HashAlgorithm registry value: {status:?}"));
    }
    let words: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    Ok(Some(String::from_utf16_lossy(&words)))
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn parse_hex(input: &str, len: usize, label: &str) -> Result<Vec<u8>> {
    let clean = input.replace([':', ' ', '\u{200e}', '\u{200f}'], "");
    if clean.len() != len * 2 {
        return Err(anyhow!(
            "{label} thumbprint must be {} hex characters",
            len * 2
        ));
    }
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(
            u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("{label} thumbprint contains invalid hex"))?,
        );
    }
    Ok(out)
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

fn encoding() -> CERT_QUERY_ENCODING_TYPE {
    CERT_QUERY_ENCODING_TYPE(0x0001_0001)
}

fn to_wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
