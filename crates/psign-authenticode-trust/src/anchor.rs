//! Load trust anchors (Phase A: PEM/DER roots from a directory).

use anyhow::{Context, Result, anyhow};
use picky::x509::certificate::Cert;
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AnchorStore {
    sha1_thumbs: HashSet<[u8; 20]>,
}

impl AnchorStore {
    pub fn empty() -> Self {
        Self {
            sha1_thumbs: HashSet::new(),
        }
    }

    pub fn merge_cert_thumbprints(&mut self, certs: &[Cert]) -> Result<()> {
        for c in certs {
            self.sha1_thumbs.insert(cert_sha1_thumbprint(c)?);
        }
        Ok(())
    }

    /// Merge raw SHA-1 subject identifiers (e.g. from AuthRoot CTL entries) without full certs.
    pub fn merge_thumbprints_only(&mut self, thumbs: &[[u8; 20]]) {
        for t in thumbs {
            self.sha1_thumbs.insert(*t);
        }
    }

    pub fn contains_thumbprint(&self, thumb: &[u8; 20]) -> bool {
        self.sha1_thumbs.contains(thumb)
    }

    pub fn thumbprint_count(&self) -> usize {
        self.sha1_thumbs.len()
    }

    /// Parse every `*.crt`, `*.cer`, and `*.pem` under `dir` (non-recursive).
    pub fn load_dir(dir: &Path) -> Result<(Self, Vec<Cert>)> {
        let mut certs = Vec::new();
        let rd = fs::read_dir(dir).with_context(|| format!("read anchor dir {}", dir.display()))?;
        let mut paths: Vec<_> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        paths.sort();

        for path in paths {
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if ext != "crt" && ext != "cer" && ext != "pem" {
                continue;
            }
            let raw = fs::read(&path).with_context(|| format!("read anchor {}", path.display()))?;
            let parsed = parse_cert_bytes(&raw)
                .with_context(|| format!("parse anchor certificate {}", path.display()))?;
            certs.push(parsed);
        }

        if certs.is_empty() {
            return Err(anyhow!(
                "no certificates loaded from anchor dir {} (expected .crt/.cer/.pem)",
                dir.display()
            ));
        }

        let mut store = Self::empty();
        store.merge_cert_thumbprints(&certs)?;
        Ok((store, certs))
    }

    /// Parse explicitly supplied certificate files and use them as trust anchors.
    pub fn load_files(paths: &[PathBuf]) -> Result<(Self, Vec<Cert>)> {
        let mut certs = Vec::new();
        for path in paths {
            let raw = fs::read(path).with_context(|| format!("read anchor {}", path.display()))?;
            let parsed = parse_cert_bytes(&raw)
                .with_context(|| format!("parse anchor certificate {}", path.display()))?;
            certs.push(parsed);
        }

        if certs.is_empty() {
            return Err(anyhow!("no trusted CA files were supplied"));
        }

        let mut store = Self::empty();
        store.merge_cert_thumbprints(&certs)?;
        Ok((store, certs))
    }
}

pub fn cert_sha1_thumbprint(cert: &Cert) -> Result<[u8; 20]> {
    let der = cert
        .to_der()
        .map_err(|e| anyhow!("certificate DER encode failed: {e}"))?;
    let digest = Sha1::digest(&der);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn parse_cert_bytes(raw: &[u8]) -> Result<Cert> {
    let trimmed = raw.trim_ascii_start();
    if trimmed.starts_with(b"-----BEGIN ") {
        let s =
            std::str::from_utf8(trimmed).map_err(|e| anyhow!("anchor PEM is not UTF-8: {e}"))?;
        Cert::from_pem_str(s).map_err(|e| anyhow!("PEM parse failed: {e}"))
    } else {
        Cert::from_der(trimmed).map_err(|e| anyhow!("DER parse failed: {e}"))
    }
}
