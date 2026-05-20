//! Phase B: extract root certificates and CTL thumbprints from `authrootstl`-style CAB files.

use crate::authroot_ctl::ctl_subject_sha1_thumbprints_from_stl_bytes;
use anyhow::{Context, Result};
use cab::Cabinet;
use picky::x509::certificate::Cert;
use picky::x509::pkcs7::Pkcs7;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

/// Returns embedded certs plus CTL **SubjectIdentifier** SHA-1 entries harvested from `*.stl` members.
pub fn ingest_authroot_cab_bytes(cab_bytes: &[u8]) -> Result<(Vec<Cert>, Vec<[u8; 20]>)> {
    let mut cab = Cabinet::new(Cursor::new(cab_bytes))
        .map_err(|e| anyhow::anyhow!("CAB open failed: {e}"))?;

    let mut names = Vec::new();
    for folder in cab.folder_entries() {
        for entry in folder.file_entries() {
            names.push(entry.name().to_string());
        }
    }
    names.sort();
    names.dedup();

    let mut collected_certs = Vec::new();
    let mut ctl_thumbs = Vec::new();

    for name in names {
        let lower = name.to_ascii_lowercase();
        if !lower.ends_with(".stl") {
            continue;
        }
        let mut reader = cab
            .read_file(&name)
            .map_err(|e| anyhow::anyhow!("CAB read_file {name}: {e}"))?;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .with_context(|| format!("read CAB member {name}"))?;
        collected_certs.extend(certs_from_maybe_pkcs7_der(&buf));
        ctl_thumbs.extend(ctl_subject_sha1_thumbprints_from_stl_bytes(&buf));
    }

    ctl_thumbs.sort();
    ctl_thumbs.dedup();

    Ok((collected_certs, ctl_thumbs))
}

/// Backwards-compatible alias: certificates only (no CTL thumbprints).
pub fn certs_from_authroot_cab(path: &Path) -> Result<Vec<Cert>> {
    let file = File::open(path).with_context(|| format!("open CAB {}", path.display()))?;
    let mut cab_bytes = Vec::new();
    let mut r = file;
    r.read_to_end(&mut cab_bytes)?;
    Ok(ingest_authroot_cab_bytes(&cab_bytes)?.0)
}

fn certs_from_maybe_pkcs7_der(bytes: &[u8]) -> Vec<Cert> {
    let Ok(pkcs7) = Pkcs7::from_der(bytes) else {
        return Vec::new();
    };
    pkcs7.decode_certificates()
}
