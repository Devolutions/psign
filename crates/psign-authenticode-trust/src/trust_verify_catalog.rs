//! Catalog `.cat` Authenticode trust (CMS digest consistency + PKCS#7 chain).

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
use anyhow::Result;
use psign_sip_digest::catalog_digest;

pub fn trust_verify_catalog_bytes(
    data: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    catalog_digest::verify_catalog_digest_consistency_bytes(data)?;

    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let digest = catalog_digest::catalog_econtent_digest(data)?;

    let mut report = TrustVerifyPeReport::new(&anchors);
    verify_pkcs7_entry(
        data,
        0,
        digest.as_slice(),
        Pkcs7DigestBinding::Pkcs9MessageDigest,
        &anchors,
        &anchor_certs,
        opts,
        &mut report,
    )?;
    Ok(report)
}
