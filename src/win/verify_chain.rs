use crate::cli::DigestAlgorithm;
use std::ffi::CStr;
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CONTEXT, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CertFreeCertificateChain, CertGetCertificateChain, CertGetNameStringW,
};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
};

pub struct VerifyChainSummary {
    pub algorithm: String,
    pub timestamp: String,
    pub signer_subject: String,
}

fn alg_from_oid(oid: &str) -> String {
    match oid {
        "1.3.14.3.2.26" => DigestAlgorithm::Sha1.as_signtool_name().to_string(),
        "2.16.840.1.101.3.4.2.1" => DigestAlgorithm::Sha256.as_signtool_name().to_string(),
        "2.16.840.1.101.3.4.2.2" => DigestAlgorithm::Sha384.as_signtool_name().to_string(),
        "2.16.840.1.101.3.4.2.3" => DigestAlgorithm::Sha512.as_signtool_name().to_string(),
        _ => "unknown".to_string(),
    }
}

fn cert_name(cert: *const windows::Win32::Security::Cryptography::CERT_CONTEXT) -> String {
    if cert.is_null() {
        return "unknown".to_string();
    }
    // SAFETY: query required chars.
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if len == 0 {
        return "unknown".to_string();
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: writes up to returned size.
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(buf.as_mut_slice()),
        )
    };
    if written == 0 {
        return "unknown".to_string();
    }
    String::from_utf16_lossy(&buf[..written.saturating_sub(1) as usize])
}

pub fn summarize_from_state(hstate: HANDLE) -> Option<VerifyChainSummary> {
    if hstate.is_invalid() {
        return None;
    }
    // SAFETY: hstate comes from WinVerifyTrust state handle.
    let pprov = unsafe { WTHelperProvDataFromStateData(hstate) };
    if pprov.is_null() {
        return None;
    }
    // SAFETY: pprov is valid provider data pointer.
    let signer = unsafe { WTHelperGetProvSignerFromChain(pprov, 0, false, 0) };
    if signer.is_null() {
        return None;
    }
    // SAFETY: signer points to a CRYPT_PROVIDER_SGNR with optional signer-info.
    let algorithm = unsafe {
        let psigner = (*signer).psSigner;
        if psigner.is_null() || (*psigner).HashAlgorithm.pszObjId.is_null() {
            "unknown".to_string()
        } else {
            let oid = CStr::from_ptr((*psigner).HashAlgorithm.pszObjId.0.cast())
                .to_string_lossy()
                .to_string();
            alg_from_oid(&oid)
        }
    };
    // SAFETY: signer chain index 0 if present.
    let prov_cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    let signer_subject = if prov_cert.is_null() {
        "unknown".to_string()
    } else {
        // SAFETY: provider cert has cert pointer or null.
        unsafe { cert_name((*prov_cert).pCert) }
    };
    // SAFETY: counter signer count inspected from signer struct.
    let timestamp = unsafe {
        if (*signer).csCounterSigners > 0 {
            "RFC3161".to_string()
        } else {
            "none".to_string()
        }
    };
    Some(VerifyChainSummary {
        algorithm,
        timestamp,
        signer_subject,
    })
}

pub fn leaf_cert_from_state(hstate: HANDLE) -> Option<*const CERT_CONTEXT> {
    if hstate.is_invalid() {
        return None;
    }
    // SAFETY: WinVerifyTrust returned a provider state handle.
    let pprov = unsafe { WTHelperProvDataFromStateData(hstate) };
    if pprov.is_null() {
        return None;
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(pprov, 0, false, 0) };
    if signer.is_null() {
        return None;
    }
    let prov_cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if prov_cert.is_null() {
        return None;
    }
    Some(unsafe { (*prov_cert).pCert })
}

pub fn chain_root_subject_contains(
    leaf: *const CERT_CONTEXT,
    needle: &str,
) -> windows::core::Result<bool> {
    if leaf.is_null() {
        return Ok(false);
    }
    let chain_para = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    unsafe {
        CertGetCertificateChain(None, leaf, None, None, &chain_para, 0, None, &mut chain)?;
    }
    if chain.is_null() {
        return Ok(false);
    }
    // SAFETY: CertGetCertificateChain returned a chain context.
    let simple = unsafe { *(*chain).rgpChain };
    if simple.is_null() {
        unsafe { CertFreeCertificateChain(chain) };
        return Ok(false);
    }
    let count = unsafe { (*simple).cElement };
    if count == 0 {
        unsafe { CertFreeCertificateChain(chain) };
        return Ok(false);
    }
    let last_idx = (count - 1) as isize;
    let el = unsafe { *(*simple).rgpElement.offset(last_idx) };
    if el.is_null() {
        unsafe { CertFreeCertificateChain(chain) };
        return Ok(false);
    }
    let root = unsafe { (*el).pCertContext };
    let name = cert_name(root);
    unsafe { CertFreeCertificateChain(chain) };
    Ok(name
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase()))
}

/// Require leaf signer SHA1 to match one of the thumbprints (native verify `/sha1`, repeatable).
pub fn verify_signer_thumbprints_allowed(
    leaf: *const CERT_CONTEXT,
    wanted: &[String],
) -> anyhow::Result<()> {
    use anyhow::anyhow;
    if wanted.is_empty() {
        return Ok(());
    }
    if leaf.is_null() {
        return Err(anyhow!("internal: null certificate context"));
    }
    let tp = crate::win::cert_props::cert_sha1_thumbprint_upper(leaf)?;
    let ok = wanted.iter().any(|w| {
        crate::win::cert_props::normalize_sha1_hex(w.trim())
            .map(|n| n == tp)
            .unwrap_or(false)
    });
    if !ok {
        return Err(anyhow!(
            "Verification failed: signing certificate SHA1 thumbprint does not match any /sha1 filter"
        ));
    }
    Ok(())
}

/// True if every non-empty `/ca` thumbprint matches some intermediate CA in the chain (excluding leaf and root).
pub fn intermediate_ca_thumbprints_match(
    leaf: *const CERT_CONTEXT,
    wanted: &[String],
) -> anyhow::Result<bool> {
    use anyhow::anyhow;
    if wanted.is_empty() {
        return Ok(true);
    }
    if leaf.is_null() {
        return Ok(false);
    }
    let mut normalized_wanted = Vec::with_capacity(wanted.len());
    for w in wanted {
        normalized_wanted.push(crate::win::cert_props::normalize_sha1_hex(w.trim())?);
    }

    let chain_para = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    unsafe { CertGetCertificateChain(None, leaf, None, None, &chain_para, 0, None, &mut chain) }
        .map_err(|e| anyhow!("CertGetCertificateChain failed: {e}"))?;
    if chain.is_null() {
        return Ok(false);
    }
    let simple = unsafe { *(*chain).rgpChain };
    if simple.is_null() {
        unsafe { CertFreeCertificateChain(chain) };
        return Ok(false);
    }
    let count = unsafe { (*simple).cElement };
    let mut found = false;
    if count >= 3 {
        for idx in 1..(count - 1) {
            let el = unsafe { *(*simple).rgpElement.offset(idx as isize) };
            if el.is_null() {
                continue;
            }
            let cert = unsafe { (*el).pCertContext };
            let tp = crate::win::cert_props::cert_sha1_thumbprint_upper(cert)?;
            if normalized_wanted.contains(&tp) {
                found = true;
                break;
            }
        }
    }
    unsafe { CertFreeCertificateChain(chain) };
    Ok(found)
}

/// Warning lines (including trailing newline) for each requested EKU missing from the signer (native verify `/u`).
pub fn warn_missing_eku_messages(
    leaf: *const CERT_CONTEXT,
    wanted: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    if wanted.is_empty() || leaf.is_null() {
        return Ok(out);
    }
    let usages = crate::win::cert_props::enhanced_key_usage_oids(leaf)?;
    for oid in wanted {
        let oid = oid.trim();
        if oid.is_empty() {
            continue;
        }
        if !usages.iter().any(|u| u == oid || u.contains(oid)) {
            out.push(format!(
                "Warning: signer certificate does not include enhanced key usage '{oid}'\n"
            ));
        }
    }
    Ok(out)
}

fn subject_looks_like_windows_pca_2010(cert: *const CERT_CONTEXT) -> bool {
    if cert.is_null() {
        return false;
    }
    let name = cert_name(cert).to_ascii_lowercase();
    name.contains("windows pca 2010")
}

/// True if any certificate in the leaf chain has a subject consistent with Microsoft Windows PCA 2010.
pub fn chain_contains_windows_pca_2010(leaf: *const CERT_CONTEXT) -> anyhow::Result<bool> {
    use anyhow::anyhow;
    if leaf.is_null() {
        return Ok(false);
    }
    let chain_para = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    unsafe { CertGetCertificateChain(None, leaf, None, None, &chain_para, 0, None, &mut chain) }
        .map_err(|e| anyhow!("CertGetCertificateChain failed: {e}"))?;
    if chain.is_null() {
        return Ok(false);
    }
    let simple = unsafe { *(*chain).rgpChain };
    if simple.is_null() {
        unsafe { CertFreeCertificateChain(chain) };
        return Ok(false);
    }
    let count = unsafe { (*simple).cElement };
    let mut hit = false;
    for idx in 0..count {
        let el = unsafe { *(*simple).rgpElement.offset(idx as isize) };
        if el.is_null() {
            continue;
        }
        let cert = unsafe { (*el).pCertContext };
        if subject_looks_like_windows_pca_2010(cert) {
            hit = true;
            break;
        }
    }
    unsafe { CertFreeCertificateChain(chain) };
    Ok(hit)
}

/// Warning lines when PCA 2010 policy applies (native `/w2010pca`, `/now2010pca`, driver/kp defaults).
pub fn pca_2010_warning_message_lines(
    leaf: *const CERT_CONTEXT,
    policy_default: bool,
    kernel_policy: bool,
    warn_pca_2010: bool,
    no_warn_pca_2010: bool,
) -> anyhow::Result<Vec<String>> {
    if no_warn_pca_2010 {
        return Ok(vec![]);
    }
    let auto = policy_default || kernel_policy;
    if !warn_pca_2010 && !auto {
        return Ok(vec![]);
    }
    if leaf.is_null() {
        return Ok(vec![]);
    }
    if chain_contains_windows_pca_2010(leaf)? {
        Ok(vec![
            "Warning: Microsoft Windows PCA 2010 appears in the signing certificate chain.\n"
                .to_string(),
        ])
    } else {
        Ok(vec![])
    }
}
