//! Simple issuer walk for PKCS#7 embedded + anchor pools (RFC 5280 subset delegated to picky).

use anyhow::{Result, anyhow};
use picky::x509::certificate::Cert;

/// Follow `leaf.issuer_name` through `pool` until a self-signed certificate is reached.
///
/// Returns certificates **from the leaf's immediate issuer toward the terminal self-signed root**
/// (same order picky [`Cert::verifier`](picky::x509::certificate::Cert::verifier) expects).
pub fn issuer_chain_excluding_leaf<'a>(leaf: &'a Cert, pool: &'a [Cert]) -> Result<Vec<&'a Cert>> {
    if leaf.subject_name() == leaf.issuer_name() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut issuer_dn = leaf.issuer_name();
    let mut steps = 0usize;

    loop {
        let parent = pool
            .iter()
            .find(|c| c.subject_name() == issuer_dn)
            .ok_or_else(|| {
                anyhow!(
                    "could not resolve issuer certificate for subject {:?}",
                    issuer_dn
                )
            })?;

        out.push(parent);
        steps += 1;
        if steps > 32 {
            return Err(anyhow!("certificate chain too long (possible loop)"));
        }

        if parent.subject_name() == parent.issuer_name() {
            break;
        }
        issuer_dn = parent.issuer_name();
    }

    Ok(out)
}

/// Follow `leaf.issuer_name` through `pool`, fetching missing issuers through explicit online
/// options when enabled. Returned certificates are owned so fetched intermediates can live for
/// the duration of the caller's verification step without mutating global state.
pub fn issuer_chain_excluding_leaf_online(
    leaf: &Cert,
    pool: &mut Vec<Cert>,
    online: &crate::policy::OnlineTrustOptions,
) -> Result<Vec<Cert>> {
    if leaf.subject_name() == leaf.issuer_name() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut current = leaf.clone();
    let mut steps = 0usize;

    loop {
        let issuer_dn = current.issuer_name();
        if let Some(parent) = pool.iter().find(|c| c.subject_name() == issuer_dn).cloned() {
            steps += 1;
            if steps > 32 {
                return Err(anyhow!("certificate chain too long (possible loop)"));
            }
            let done = parent.subject_name() == parent.issuer_name();
            out.push(parent.clone());
            if done {
                break;
            }
            current = parent;
            continue;
        }

        let fetched = crate::online::issuer_candidates_from_aia(&current, online)?;
        if fetched.is_empty() {
            return Err(anyhow!(
                "could not resolve issuer certificate for subject {:?}",
                issuer_dn
            ));
        }
        pool.extend(fetched);
    }

    Ok(out)
}

pub fn terminal_root_cert<'a>(leaf: &'a Cert, chain: &'a [&'a Cert]) -> &'a Cert {
    if leaf.subject_name() == leaf.issuer_name() {
        leaf
    } else {
        chain.last().copied().expect("non-empty issuer chain")
    }
}

pub fn terminal_root_cert_owned<'a>(leaf: &'a Cert, chain: &'a [Cert]) -> &'a Cert {
    if leaf.subject_name() == leaf.issuer_name() {
        leaf
    } else {
        chain.last().expect("non-empty issuer chain")
    }
}

/// Merge certificate bags and drop duplicates by SHA-1 thumbprint (Windows-style cert hash).
pub fn merge_unique_certs(
    primary: Vec<Cert>,
    extra: impl IntoIterator<Item = Cert>,
) -> Result<Vec<Cert>> {
    use crate::anchor::cert_sha1_thumbprint;
    use std::collections::HashSet;

    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for c in primary.into_iter().chain(extra) {
        let thumb = cert_sha1_thumbprint(&c)?;
        if seen.insert(thumb) {
            out.push(c);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::cert_sha1_thumbprint;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };

    fn synthetic_ca_and_leaf() -> (Cert, Cert) {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Trust Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).expect("self-signed ca");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::new(vec!["leaf.trust.test".into()]).expect("san");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("issued leaf");

        let ca_der = ca.der().to_vec();
        let leaf_der = leaf.der().to_vec();

        (
            Cert::from_der(&ca_der).expect("picky ca"),
            Cert::from_der(&leaf_der).expect("picky leaf"),
        )
    }

    #[test]
    fn issuer_chain_single_ca() {
        let (ca, leaf) = synthetic_ca_and_leaf();
        let pool = vec![ca.clone(), leaf.clone()];
        let chain = issuer_chain_excluding_leaf(&leaf, &pool).expect("chain");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].subject_name(), ca.subject_name());
    }

    #[test]
    fn merge_unique_drops_duplicate_thumbprints() {
        let (_, leaf) = synthetic_ca_and_leaf();
        let thumb = cert_sha1_thumbprint(&leaf).expect("thumb");
        let merged = merge_unique_certs(vec![leaf.clone()], [leaf.clone()]).expect("merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(cert_sha1_thumbprint(&merged[0]).expect("t"), thumb);
    }
}
