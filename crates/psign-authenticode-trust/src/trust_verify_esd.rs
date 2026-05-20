//! WIM/ESD Authenticode trust (ESD SIP digest + PKCS#7 chain).

use crate::trust_pkcs7::verify_authenticode_pkcs7_trust;
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material};
use crate::verification_instant::resolve_verification_instant_for_pkcs7_with_trust;
use anyhow::{Context, Result, anyhow};
use authenticode::AuthenticodeSignature;
use psign_sip_digest::esd_digest::{
    WIM_HEADER_PACKED_SIZE, compute_wim_image_digest_from_header, read_embedded_pkcs7,
};
use psign_sip_digest::pe_digest::PeAuthenticodeHashKind;
use std::io::Read;
use std::path::Path;

pub fn trust_verify_wim_esd_path(
    path: &Path,
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = load_trust_material(opts)?;

    let mut header = [0u8; WIM_HEADER_PACKED_SIZE];
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    f.read_exact(&mut header)
        .with_context(|| format!("read WIM/ESD header {}", path.display()))?;

    let pkcs7 = read_embedded_pkcs7(path, &header)?;
    let sig = AuthenticodeSignature::from_bytes(&pkcs7)
        .map_err(|e| anyhow!("WIM/ESD PKCS#7 parse failed: {e}"))?;
    let embedded_digest = sig.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded_digest.len())?;
    let computed = compute_wim_image_digest_from_header(path, &header, kind)?;
    if computed.as_slice() != embedded_digest {
        return Err(anyhow!(
            "WIM/ESD Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)"
        ));
    }

    let verification_instant = resolve_verification_instant_for_pkcs7_with_trust(
        &pkcs7,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
        &anchors,
        &anchor_certs,
        &opts.online,
        opts.verbose_chain,
    )?;
    verify_authenticode_pkcs7_trust(
        &pkcs7,
        0,
        computed.as_slice(),
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
