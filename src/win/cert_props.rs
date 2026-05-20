//! Shared certificate property helpers (thumbprints, EKU) for verify and sign paths.

use anyhow::{Result, anyhow};
use std::ffi::CStr;
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_SHA1_HASH_PROP_ID, CTL_USAGE, CertGetCertificateContextProperty,
    CertGetEnhancedKeyUsage,
};

pub fn normalize_sha1_hex(input: &str) -> Result<String> {
    let clean = input.replace([':', ' '], "");
    if clean.len() != 40 {
        return Err(anyhow!("SHA1 thumbprint must be 40 hex characters"));
    }
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("SHA1 thumbprint contains invalid hex"));
    }
    Ok(clean.to_ascii_uppercase())
}

/// Uppercase hex SHA1 thumbprint (no colons), matching signtool-style comparisons.
pub fn cert_sha1_thumbprint_upper(cert: *const CERT_CONTEXT) -> Result<String> {
    let mut len = 0u32;
    unsafe { CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, None, &mut len) }?;
    let mut buf = vec![0u8; len as usize];
    unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_SHA1_HASH_PROP_ID,
            Some(buf.as_mut_ptr().cast()),
            &mut len,
        )
    }?;
    Ok(buf[..len as usize]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(""))
}

pub fn enhanced_key_usage_oids(cert: *const CERT_CONTEXT) -> Result<Vec<String>> {
    let mut cb = 0u32;
    if unsafe { CertGetEnhancedKeyUsage(cert, 0, None, &mut cb) }.is_err() {
        return Ok(vec![]);
    }
    if cb == 0 {
        return Ok(vec![]);
    }
    let mut buf = vec![0u8; cb as usize];
    let usage_ptr = buf.as_mut_ptr() as *mut CTL_USAGE;
    unsafe { CertGetEnhancedKeyUsage(cert, 0, Some(usage_ptr), &mut cb)? };
    let usage = unsafe { &*usage_ptr };
    if usage.rgpszUsageIdentifier.is_null() || usage.cUsageIdentifier == 0 {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for i in 0..usage.cUsageIdentifier {
        let p = unsafe { *usage.rgpszUsageIdentifier.add(i as usize) };
        if p.is_null() {
            continue;
        }
        let s = unsafe { CStr::from_ptr(p.0.cast()).to_string_lossy().into_owned() };
        out.push(s);
    }
    Ok(out)
}
