//! WIM/ESD Authenticode trust (ESD SIP digest + PKCS#7 chain).

use crate::trust_pkcs7::Pkcs7DigestBinding;
use crate::trust_verify_pe::{
    TrustVerifyPeOptions, TrustVerifyPeReport, trust_material_for, verify_pkcs7_entry,
};
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
    let (anchors, anchor_certs) = trust_material_for(opts)?;

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

    let mut report = TrustVerifyPeReport::new(&anchors);
    verify_pkcs7_entry(
        &pkcs7,
        0,
        computed.as_slice(),
        Pkcs7DigestBinding::AuthenticodeIndirect,
        &anchors,
        &anchor_certs,
        opts,
        &mut report,
    )?;
    Ok(report)
}
