//! PowerShell script Authenticode trust (script SIP digest + PKCS#7 chain).

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
use anyhow::Result;
use psign_sip_digest::ps_script::powershell_class_digest_report;

pub fn trust_verify_script_bytes(
    data: &[u8],
    extension: &str,
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let script_report = powershell_class_digest_report(data, extension)?;

    let mut report = TrustVerifyPeReport::new(&anchors);
    verify_pkcs7_entry(
        &script_report.pkcs7_der,
        0,
        &script_report.computed_digest,
        Pkcs7DigestBinding::AuthenticodeIndirect,
        &anchors,
        &anchor_certs,
        opts,
        &mut report,
    )?;
    Ok(report)
}
