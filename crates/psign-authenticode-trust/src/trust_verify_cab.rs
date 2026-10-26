//! CAB Authenticode trust (digest + PKCS#7 chain).

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use psign_sip_digest::cab_digest::{
    cab_signature_pkcs7_der, compute_cab_authenticode_digest, parse_cab_context,
};
use psign_sip_digest::pe_digest::PeAuthenticodeHashKind;

pub fn trust_verify_cab_bytes(
    data: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = trust_material_for(opts)?;
    let ctx = parse_cab_context(data)?;
    let pkcs7 = cab_signature_pkcs7_der(data)?;

    let sig = AuthenticodeSignature::from_bytes(pkcs7).map_err(|e| anyhow!("CAB PKCS#7: {e}"))?;
    let embedded_digest = sig.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded_digest.len())?;
    let cab_digest = compute_cab_authenticode_digest(data, &ctx, kind)?;
    if cab_digest.as_slice() != embedded_digest {
        return Err(anyhow!(
            "CAB Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)"
        ));
    }

    let mut report = TrustVerifyPeReport::new(&anchors);
    verify_pkcs7_entry(
        pkcs7,
        0,
        cab_digest.as_slice(),
        Pkcs7DigestBinding::AuthenticodeIndirect,
        &anchors,
        &anchor_certs,
        opts,
        &mut report,
    )?;
    Ok(report)
}
