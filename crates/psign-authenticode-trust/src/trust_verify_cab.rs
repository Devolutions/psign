//! CAB Authenticode trust (digest + PKCS#7 chain).

use crate::trust_pkcs7::verify_authenticode_pkcs7_trust;
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material};
use crate::verification_instant::resolve_verification_instant_for_pkcs7_with_trust;
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
    let (anchors, anchor_certs) = load_trust_material(opts)?;
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

    let verification_instant = resolve_verification_instant_for_pkcs7_with_trust(
        pkcs7,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
        &anchors,
        &anchor_certs,
        &opts.online,
        opts.verbose_chain,
    )?;
    verify_authenticode_pkcs7_trust(
        pkcs7,
        0,
        cab_digest.as_slice(),
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
