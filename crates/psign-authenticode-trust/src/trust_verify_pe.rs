//! Portable PE Authenticode **trust** verification: picky CMS + explicit anchors.

use crate::anchor::AnchorStore;
use crate::chain::{issuer_chain_excluding_leaf, merge_unique_certs, terminal_root_cert};
use crate::policy::{AuthenticodeTrustPolicy, OnlineTrustOptions};
use crate::trust_pkcs7::verify_authenticode_pkcs7_trust;
use crate::verification_instant::resolve_verification_instant_for_pkcs7_with_trust;
use anyhow::{Context, Result, anyhow};
use picky::x509::certificate::Cert;
use picky::x509::date::UtcDate;
use picky::x509::pkcs7::authenticode::AuthenticodeSignature;
use psign_sip_digest::pe_digest::{PeAuthenticodeHashKind, pe_authenticode_digest};
use psign_sip_digest::verify_pe::for_each_pe_pkcs7_signed_data;
use sha2::Digest;

#[derive(Debug, Clone, Default)]
pub struct TrustVerifyPeOptions {
    pub anchor_dir: Option<std::path::PathBuf>,
    pub trusted_ca_files: Vec<std::path::PathBuf>,
    pub authroot_cab: Option<std::path::PathBuf>,
    /// When set, require the AuthRoot CAB file to match this SHA-256 (bootstrap integrity).
    pub expect_authroot_cab_sha256: Option<[u8; 32]>,
    /// When set, use this instant for picky **`exact_date`** instead of wall clock / timestamp policy.
    pub verification_instant_override: Option<UtcDate>,
    pub verbose_chain: bool,
    pub online: OnlineTrustOptions,
    pub policy: AuthenticodeTrustPolicy,
}

#[derive(Debug, Clone)]
pub struct TrustVerifyPeReport {
    pub pkcs7_entries_verified: usize,
    pub anchor_thumbprints: usize,
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Load anchors from **`--anchor-dir`**, optional AuthRoot CAB bytes (certs + CTL thumbs), apply CAB pin.
pub fn load_trust_material(opts: &TrustVerifyPeOptions) -> Result<(AnchorStore, Vec<Cert>)> {
    let (mut anchor_store, mut anchor_certs) = if let Some(dir) = &opts.anchor_dir {
        AnchorStore::load_dir(dir).with_context(|| format!("anchor-dir {}", dir.display()))?
    } else {
        (AnchorStore::empty(), Vec::new())
    };

    if !opts.trusted_ca_files.is_empty() {
        let (_file_store, file_certs) = AnchorStore::load_files(&opts.trusted_ca_files)?;
        anchor_store.merge_thumbprints_only(
            &file_certs
                .iter()
                .map(crate::anchor::cert_sha1_thumbprint)
                .collect::<Result<Vec<_>>>()?,
        );
        anchor_certs.extend(file_certs);
    }

    if let Some(cab) = &opts.authroot_cab {
        let cab_bytes = std::fs::read(cab).with_context(|| format!("read {}", cab.display()))?;
        if let Some(expected) = opts.expect_authroot_cab_sha256 {
            let digest = sha2::Sha256::digest(&cab_bytes);
            if digest.as_slice() != expected.as_slice() {
                return Err(anyhow!(
                    "authroot CAB SHA-256 mismatch (pin differs from file {} — {} vs {})",
                    cab.display(),
                    hex_lower(digest.as_slice()),
                    hex_lower(&expected),
                ));
            }
        }
        let (cab_certs, ctl_thumbs) = crate::authroot_cab::ingest_authroot_cab_bytes(&cab_bytes)
            .with_context(|| format!("authroot-cab {}", cab.display()))?;
        anchor_store.merge_cert_thumbprints(&cab_certs)?;
        anchor_store.merge_thumbprints_only(&ctl_thumbs);
        anchor_certs.extend(cab_certs);
    }

    if anchor_store.thumbprint_count() == 0 {
        return Err(anyhow!(
            "no trust anchors configured (use --anchor-dir and/or --authroot-cab)"
        ));
    }

    Ok((anchor_store, anchor_certs))
}

pub fn trust_verify_pe_bytes(
    pe_bytes: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchor_store, anchor_certs) = load_trust_material(opts)?;

    let pkcs7_verified = for_each_pe_pkcs7_signed_data(pe_bytes, |idx, pkcs7_der| {
        verify_one_pkcs7(pe_bytes, idx, pkcs7_der, &anchor_store, &anchor_certs, opts)
    })?;

    Ok(TrustVerifyPeReport {
        pkcs7_entries_verified: pkcs7_verified,
        anchor_thumbprints: anchor_store.thumbprint_count(),
    })
}

fn verify_one_pkcs7(
    pe_bytes: &[u8],
    pkcs7_index: usize,
    pkcs7_der: &[u8],
    anchors: &AnchorStore,
    anchor_certs: &[Cert],
    opts: &TrustVerifyPeOptions,
) -> Result<()> {
    let sig_authenticode = authenticode::AuthenticodeSignature::from_bytes(pkcs7_der)
        .map_err(|e| anyhow!("authenticode-rs PKCS#7 parse (digest probe): {e}"))?;
    let embedded_digest = sig_authenticode.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded_digest.len())?;
    let pe_digest = pe_authenticode_digest(pe_bytes, kind)?;
    if pe_digest.as_slice() != embedded_digest {
        return Err(anyhow!(
            "PE digest mismatch before trust checks for PKCS#7 index {pkcs7_index}"
        ));
    }

    let verification_instant = resolve_verification_instant_for_pkcs7_with_trust(
        pkcs7_der,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
        anchors,
        anchor_certs,
        &opts.online,
        opts.verbose_chain,
    )?;
    verify_authenticode_pkcs7_trust(
        pkcs7_der,
        pkcs7_index,
        pe_digest.as_slice(),
        anchors,
        anchor_certs,
        &opts.policy,
        &opts.online,
        &verification_instant,
        opts.verbose_chain,
    )
}

/// Extract the terminal root [`Cert`] from a PKCS#7 **`SignedData`** blob using only certs embedded in that PKCS#7.
///
/// Same chain walk as [`pe_first_pkcs7_terminal_root`], but accepts raw PKCS#7 DER (e.g. extracted CAB/MSI/CMS).
pub fn pkcs7_signed_data_der_terminal_root(pkcs7_der: &[u8]) -> Result<Cert> {
    let picky_sig =
        AuthenticodeSignature::from_der(pkcs7_der).map_err(|e| anyhow!("picky PKCS#7: {e}"))?;
    let embedded = picky_sig.0.decode_certificates();
    let merged = merge_unique_certs(embedded, std::iter::empty())?;
    let leaf = picky_sig
        .signing_certificate(&merged)
        .map_err(|e| anyhow!("resolve signing certificate: {e}"))?;
    let chain_vec = issuer_chain_excluding_leaf(leaf, &merged)?;
    let root = terminal_root_cert(leaf, &chain_vec);
    Ok(root.clone())
}

/// Extract the terminal root [`Cert`] from the **first** embedded PKCS#7 using only certs in that PKCS#7.
///
/// Useful for building a temporary **`--anchor-dir`** from a signed PE whose root is embedded.
pub fn pe_first_pkcs7_terminal_root(pe_bytes: &[u8]) -> Result<Cert> {
    let mut first_pkcs7: Option<Vec<u8>> = None;
    for_each_pe_pkcs7_signed_data(pe_bytes, |_i, der| {
        if first_pkcs7.is_none() {
            first_pkcs7 = Some(der.to_vec());
        }
        Ok(())
    })?;
    let pkcs7_der = first_pkcs7.ok_or_else(|| anyhow!("no PKCS#7 in PE"))?;
    pkcs7_signed_data_der_terminal_root(&pkcs7_der)
}
