//! Catalog `.cat` Authenticode trust (CMS digest consistency + PKCS#7 chain).

use crate::trust_pkcs7::verify_pkcs9_message_digest_pkcs7_trust;
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material};
use crate::verification_instant::resolve_verification_instant_for_pkcs7_with_trust;
use anyhow::Result;
use psign_sip_digest::catalog_digest;

pub fn trust_verify_catalog_bytes(
    data: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    catalog_digest::verify_catalog_digest_consistency_bytes(data)?;

    let (anchors, anchor_certs) = load_trust_material(opts)?;
    let digest = catalog_digest::catalog_econtent_digest(data)?;

    let verification_instant = resolve_verification_instant_for_pkcs7_with_trust(
        data,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
        &anchors,
        &anchor_certs,
        &opts.online,
        opts.verbose_chain,
    )?;
    verify_pkcs9_message_digest_pkcs7_trust(
        data,
        0,
        digest.as_slice(),
        &anchors,
        &anchor_certs,
        &opts.policy,
        &opts.online,
        &verification_instant,
        opts.verbose_chain,
    )?;

    Ok(TrustVerifyPeReport {
        pkcs7_entries_verified: 1,
        anchor_thumbprints: anchors.thumbprint_count(),
    })
}
