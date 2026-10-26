//! Custom ZIP Authenticode trust (Devolutions ZIP comment convention).

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
use anyhow::Result;
use psign_sip_digest::ps_script::powershell_class_digest_report;
use psign_sip_digest::zip_authenticode;

pub fn trust_verify_zip_bytes(
    data: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let sig = zip_authenticode::verify_zip_digest_binding(data)?;
    let script = zip_authenticode::signature_script_from_parts(&sig.digest, &sig.pkcs7_base64);
    let script_report = powershell_class_digest_report(script.as_bytes(), "ps1")?;

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
