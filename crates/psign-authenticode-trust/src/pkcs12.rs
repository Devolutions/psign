//! PKCS#12 (`.pfx` / `.p12`) signer identity and certificate-chain extraction.

use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, bail};
use picky::key::PrivateKey;
use picky::pkcs12::{
    Pfx, Pkcs12AttributeKind, Pkcs12CryptoContext, Pkcs12ParsingParams, SafeBag, SafeBagKind,
    SafeContentsKind,
};
use picky::x509::Cert as PickyCert;

/// Parsed signer identity and accompanying certificate chain extracted from a PKCS#12 (`.pfx`) archive.
#[derive(Debug, Clone)]
pub struct ParsedPfxIdentity {
    pub signer_cert_der: Vec<u8>,
    pub private_key_pem: String,
    pub chain_certs_der: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PfxCertEntry {
    der: Vec<u8>,
    local_key_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PfxKeyEntry {
    pem: String,
    key: PrivateKey,
    local_key_id: Option<Vec<u8>>,
}

/// Parse a PKCS#12 (`.pfx`) archive into its matched signer certificate, PKCS#8 PEM private key,
/// and any additional issuer/root certificates bundled in the PFX.
///
/// # Errors
///
/// Returns an error if the PFX cannot be decrypted or parsed, or if no certificate matches an
/// included private key.
pub fn parse_pfx_identity(bytes: &[u8], password: &str) -> Result<ParsedPfxIdentity> {
    let crypto_context = Pkcs12CryptoContext::new_with_password(password)?;
    let parsing_params = Pkcs12ParsingParams::default();
    let pfx = Pfx::from_der(bytes, &crypto_context, &parsing_params)?;
    let mut certs = Vec::new();
    let mut keys = Vec::new();
    for safe_contents in pfx.safe_contents() {
        collect_pfx_bags(safe_contents.kind(), &mut certs, &mut keys)?;
    }
    if certs.is_empty() {
        bail!("PFX did not contain an X.509 certificate");
    }
    if keys.is_empty() {
        bail!("PFX did not contain a private key");
    }

    let matched = find_matching_pfx_pair(&certs, &keys).ok_or_else(|| {
        anyhow!("PFX did not contain a certificate matching an included private key")
    })?;
    let signer_cert_der = certs[matched.0].der.clone();
    let private_key_pem = keys[matched.1].pem.clone();

    let mut seen = HashSet::with_capacity(certs.len());
    seen.insert(signer_cert_der.clone());
    let mut chain_certs_der = Vec::new();
    for entry in certs {
        if seen.insert(entry.der.clone()) {
            chain_certs_der.push(entry.der);
        }
    }

    Ok(ParsedPfxIdentity {
        signer_cert_der,
        private_key_pem,
        chain_certs_der,
    })
}

fn find_matching_pfx_pair(certs: &[PfxCertEntry], keys: &[PfxKeyEntry]) -> Option<(usize, usize)> {
    // Prefer an explicit PKCS#12 localKeyId match that also satisfies public-key equality.
    for (ci, cert) in certs.iter().enumerate() {
        let Some(cert_id) = cert.local_key_id.as_deref() else {
            continue;
        };
        for (ki, key) in keys.iter().enumerate() {
            if key.local_key_id.as_deref() == Some(cert_id)
                && key_matches_cert(&cert.der, &key.key).is_ok()
            {
                return Some((ci, ki));
            }
        }
    }
    for (ci, cert) in certs.iter().enumerate() {
        for (ki, key) in keys.iter().enumerate() {
            if key_matches_cert(&cert.der, &key.key).is_ok() {
                return Some((ci, ki));
            }
        }
    }
    None
}

fn collect_pfx_bags(
    kind: &SafeContentsKind,
    certs: &mut Vec<PfxCertEntry>,
    keys: &mut Vec<PfxKeyEntry>,
) -> Result<()> {
    match kind {
        SafeContentsKind::SafeBags(bags)
        | SafeContentsKind::EncryptedSafeBags {
            safe_bags: bags, ..
        } => {
            for bag in bags {
                collect_safe_bag(bag, certs, keys)?;
            }
        }
        SafeContentsKind::Unknown => {}
    }
    Ok(())
}

fn collect_safe_bag(
    bag: &SafeBag,
    certs: &mut Vec<PfxCertEntry>,
    keys: &mut Vec<PfxKeyEntry>,
) -> Result<()> {
    let local_key_id = bag.attributes().iter().find_map(|attr| match attr.kind() {
        Pkcs12AttributeKind::LocalKeyId(id) => Some(id.clone()),
        _ => None,
    });
    match bag.kind() {
        SafeBagKind::PrivateKey(key) | SafeBagKind::EncryptedPrivateKey { key, .. } => {
            let mut pem = key
                .to_pem_str()
                .context("encode PFX private key as PKCS#8 PEM")?;
            pem.push('\n');
            keys.push(PfxKeyEntry {
                pem,
                key: key.clone(),
                local_key_id,
            });
        }
        SafeBagKind::Certificate(cert) => {
            let der = cert.to_der().context("encode PFX certificate as DER")?;
            certs.push(PfxCertEntry { der, local_key_id });
        }
        SafeBagKind::Nested(bags) => {
            for nested in bags {
                collect_safe_bag(nested, certs, keys)?;
            }
        }
        SafeBagKind::Secret(_) | SafeBagKind::Unknown => {}
    }
    Ok(())
}

pub(crate) fn key_matches_cert(cert_der: &[u8], key: &PrivateKey) -> Result<()> {
    let cert = PickyCert::from_der(cert_der).context("parse certificate for key matching")?;
    let key_public = key
        .to_public_key()
        .context("derive public key from private key")?;
    if cert.public_key() != &key_public {
        bail!("private key does not match certificate public key");
    }
    Ok(())
}
