//! MSIX / AppX (and bundle) Authenticode trust: APPX SIP digest + PKCS#7 chain.

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
use anyhow::Result;
use psign_sip_digest::msix_digest::msix_verified_signature;

/// Trust-verify a cleartext `.msix` / `.appx` / `.msixbundle` / `.appxbundle` package.
///
/// `extension` is the package extension without the dot. The APPX `messageDigest` blob
/// (AXPC/AXCD/AXCT/AXBM[/AXCI]) is recomputed and compared before the PKCS#7 trust step.
pub fn trust_verify_msix_bytes(
    data: &[u8],
    extension: &str,
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let (pkcs7, digest) = msix_verified_signature(data, extension)?;
    let mut report = TrustVerifyPeReport::new(&anchors);
    verify_pkcs7_entry(
        &pkcs7,
        0,
        &digest,
        Pkcs7DigestBinding::AuthenticodeIndirect,
        &anchors,
        &anchor_certs,
        opts,
        &mut report,
    )?;
    Ok(report)
}
