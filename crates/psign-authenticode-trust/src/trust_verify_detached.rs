//! Detached PKCS#7 Authenticode trust (content bytes vs indirect digest).

use crate::trust_pkcs7::{
    verify_authenticode_pkcs7_trust, verify_pkcs9_message_digest_pkcs7_trust,
};
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material};
use crate::verification_instant::resolve_verification_instant_for_pkcs7_with_trust;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use digest::Digest;
use psign_sip_digest::pe_digest::PeAuthenticodeHashKind;
use psign_sip_digest::pkcs7::{
    parse_pkcs7_signed_data_der, signer_info_pkcs9_message_digest_octets,
};
use psign_sip_digest::pkcs7_wire::normalize_pkcs7_der_for_authenticode;

fn hash_content_implicit(content: &[u8], embedded_len: usize) -> Result<Vec<u8>> {
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded_len)?;
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => sha1::Sha1::digest(content).to_vec(),
        PeAuthenticodeHashKind::Sha256 => sha2::Sha256::digest(content).to_vec(),
        PeAuthenticodeHashKind::Sha384 => sha2::Sha384::digest(content).to_vec(),
        PeAuthenticodeHashKind::Sha512 => sha2::Sha512::digest(content).to_vec(),
    })
}

pub fn trust_verify_detached_bytes(
    content: &[u8],
    pkcs7_der: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = load_trust_material(opts)?;
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let slice = normalized.as_ref();

    let verification_instant = resolve_verification_instant_for_pkcs7_with_trust(
        slice,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
        &anchors,
        &anchor_certs,
        &opts.online,
        opts.verbose_chain,
    )?;

    match AuthenticodeSignature::from_bytes(slice) {
        Ok(sig) => {
            let embedded_digest = sig.digest();
            let computed = hash_content_implicit(content, embedded_digest.len())?;
            if computed.as_slice() != embedded_digest {
                return Err(anyhow!(
                    "detached content digest does not match PKCS#7 indirect digest (algorithm inferred from embedded digest length)"
                ));
            }
            verify_authenticode_pkcs7_trust(
                slice,
                0,
                computed.as_slice(),
                &anchors,
                &anchor_certs,
                &opts.policy,
                &opts.online,
                &verification_instant,
                opts.verbose_chain,
            )?;
        }
        Err(authenticode_err) => {
            let sd = parse_pkcs7_signed_data_der(slice).map_err(|cms_err| {
                anyhow!(
                    "detached PKCS#7: {authenticode_err}; CMS detached fallback parse failed: {cms_err}"
                )
            })?;
            let si = sd.signer_infos.0.as_slice().first().ok_or_else(|| {
                anyhow!("detached PKCS#7: CMS detached fallback found no SignerInfo")
            })?;
            let embedded_digest = signer_info_pkcs9_message_digest_octets(si).map_err(|e| {
                anyhow!("detached PKCS#7: CMS detached fallback missing messageDigest: {e}")
            })?;
            let computed = hash_content_implicit(content, embedded_digest.len())?;
            if computed.as_slice() != embedded_digest {
                return Err(anyhow!(
                    "detached content digest does not match PKCS#9 messageDigest (algorithm inferred from embedded digest length)"
                ));
            }
            verify_pkcs9_message_digest_pkcs7_trust(
                slice,
                0,
                computed.as_slice(),
                &anchors,
                &anchor_certs,
                &opts.policy,
                &opts.online,
                &verification_instant,
                opts.verbose_chain,
            )?;
        }
    }

    Ok(TrustVerifyPeReport {
        pkcs7_entries_verified: 1,
        anchor_thumbprints: anchors.thumbprint_count(),
    })
}

#[cfg(test)]
mod detached_trust_tests {
    use super::*;
    use crate::parse_verification_date_ymd;
    use crate::pe_first_pkcs7_terminal_root;
    use psign_sip_digest::verify_pe;

    fn tiny32_fixture() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
    }

    #[test]
    fn detached_trust_errors_without_anchors() {
        let pe = std::fs::read(tiny32_fixture()).expect("read tiny32");
        let pkcs7 = verify_pe::pe_first_pkcs7_signed_data_der(&pe).expect("pkcs7");
        let opts = TrustVerifyPeOptions::default();
        let err = trust_verify_detached_bytes(&pe, &pkcs7, &opts).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no trust anchors"), "unexpected: {msg}");
    }

    #[test]
    fn detached_trust_pe_content_mismatches_embedded_pkcs7_digest() {
        let pe = std::fs::read(tiny32_fixture()).expect("read tiny32");
        let pkcs7 = verify_pe::pe_first_pkcs7_signed_data_der(&pe).expect("pkcs7");
        let root = pe_first_pkcs7_terminal_root(&pe).expect("root");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("anchor.crt"), root.to_der().expect("der"))
            .expect("write anchor");

        let opts = TrustVerifyPeOptions {
            anchor_dir: Some(dir.path().to_path_buf()),
            verification_instant_override: Some(
                parse_verification_date_ymd("2023-07-01").expect("date"),
            ),
            ..Default::default()
        };

        let err = trust_verify_detached_bytes(&pe, &pkcs7, &opts).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("detached content digest") || msg.contains("does not match"),
            "unexpected: {msg}"
        );
    }
}
