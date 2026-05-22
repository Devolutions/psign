//! PowerShell script Authenticode trust (script SIP digest + PKCS#7 chain).

use crate::trust_pkcs7::verify_authenticode_pkcs7_trust;
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material};
use crate::verification_instant::resolve_verification_instant_for_pkcs7_with_trust;
use anyhow::Result;
use psign_sip_digest::ps_script::powershell_class_digest_report;

pub fn trust_verify_script_bytes(
    data: &[u8],
    extension: &str,
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = load_trust_material(opts)?;
    let script_report = powershell_class_digest_report(data, extension)?;

    let verification_instant = resolve_verification_instant_for_pkcs7_with_trust(
        &script_report.pkcs7_der,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
        &anchors,
        &anchor_certs,
        &opts.online,
        opts.verbose_chain,
    )?;
    verify_authenticode_pkcs7_trust(
        &script_report.pkcs7_der,
        0,
        &script_report.computed_digest,
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
