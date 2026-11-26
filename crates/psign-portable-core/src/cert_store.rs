//! Portable file-backed certificate store resolution (`~/.psign/cert-store` or `PSIGN_CERT_STORE`).

use anyhow::{Context, Result, anyhow};
use picky::key::PrivateKey;
use picky::x509::Cert as PickyCert;
use std::path::{Path, PathBuf};
use x509_cert::Certificate;
use x509_cert::der::Decode;

/// Environment variable overriding the portable certificate store base directory.
pub const ENV_CERT_STORE: &str = "PSIGN_CERT_STORE";

/// Resolved signing certificate and private key from the portable certificate store.
#[derive(Debug, Clone)]
pub struct SigningIdentity {
    pub thumbprint_sha1: String,
    pub scope: &'static str,
    pub store_name: String,
    pub store_dir: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub cert_der: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Resolve a signing certificate and matching unencrypted PKCS#8 private key by SHA-1 thumbprint.
///
/// The base directory defaults to `PSIGN_CERT_STORE` when set, otherwise `~/.psign/cert-store`.
/// Layout: `{base}/{CurrentUser|LocalMachine}/{store_name}/{THUMBPRINT}.der` and `{THUMBPRINT}.key`.
///
/// # Errors
///
/// Returns an error if the store directory cannot be determined, the store name or thumbprint
/// is invalid, the certificate or private key file is missing or malformed, or the private key
/// does not match the certificate public key.
pub fn resolve_signing_identity(
    cert_store_dir: Option<&Path>,
    machine_store: bool,
    store_name: &str,
    sha1: &str,
) -> Result<SigningIdentity> {
    let base_dir = resolve_base_dir(cert_store_dir)?;
    let scope = if machine_store {
        "LocalMachine"
    } else {
        "CurrentUser"
    };
    let store_name = normalize_store_name(store_name)?;
    let store_dir = base_dir.join(scope).join(&store_name);
    let thumbprint = normalize_sha1_hex(sha1)?;
    let cert_path = store_dir.join(format!("{thumbprint}.der"));
    let key_path = store_dir.join(format!("{thumbprint}.key"));
    let cert_der = read_existing_cert(&cert_path).with_context(|| {
        format!("resolve signing certificate SHA1 {thumbprint} in {scope}\\{store_name}")
    })?;
    Certificate::from_der(&cert_der)
        .with_context(|| format!("parse X.509 certificate '{}'", cert_path.display()))?;
    let key_text = std::fs::read_to_string(&key_path).with_context(|| {
        format!("resolve private key for SHA1 {thumbprint} in {scope}\\{store_name}")
    })?;
    let key = validate_pkcs8_key_pem(&key_text).with_context(|| {
        format!(
            "parse private key '{}'; expected PEM unencrypted PKCS#8 (BEGIN PRIVATE KEY)",
            key_path.display()
        )
    })?;
    ensure_key_matches_cert(&cert_der, &key)?;
    let key_pem = canonical_pkcs8_key_pem(&key)?.into_bytes();
    Ok(SigningIdentity {
        thumbprint_sha1: thumbprint,
        scope,
        store_name,
        store_dir,
        cert_path,
        key_path,
        cert_der,
        key_pem,
    })
}

/// Resolve the portable certificate store base directory from an explicit override, `PSIGN_CERT_STORE`, or home.
///
/// # Errors
///
/// Returns an error when no override or environment variable is set and no home directory can be resolved.
pub fn resolve_base_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os(ENV_CERT_STORE).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    Ok(home_dir()?.join(".psign").join("cert-store"))
}

fn home_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(profile));
    }
    match (
        std::env::var_os("HOMEDRIVE").filter(|v| !v.is_empty()),
        std::env::var_os("HOMEPATH").filter(|v| !v.is_empty()),
    ) {
        (Some(drive), Some(path)) => {
            let mut out = PathBuf::from(drive);
            out.push(path);
            Ok(out)
        }
        _ => Err(anyhow!(
            "cannot resolve default cert-store path: set {ENV_CERT_STORE} or --cert-store-dir"
        )),
    }
}

/// Canonicalize well-known certificate store names and reject path traversal segments.
///
/// # Errors
///
/// Returns an error if the store name is empty or contains path separators or traversal segments.
pub fn normalize_store_name(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("certificate store name must not be empty"));
    }
    if trimmed.contains(['/', '\\', ':', '\0']) || matches!(trimmed, "." | "..") {
        return Err(anyhow!(
            "certificate store name must not contain path separators or traversal segments"
        ));
    }
    let canonical = match trimmed.to_ascii_lowercase().as_str() {
        "my" => "MY",
        "root" => "Root",
        "ca" => "CA",
        "trust" => "Trust",
        "disallowed" => "Disallowed",
        _ => trimmed,
    };
    Ok(canonical.to_string())
}

/// Normalize a SHA-1 thumbprint by stripping colons and ASCII whitespace and uppercasing hex digits.
///
/// # Errors
///
/// Returns an error if the cleaned string is not 40 valid hex characters.
pub fn normalize_sha1_hex(input: &str) -> Result<String> {
    let clean: String = input
        .chars()
        .filter(|c| *c != ':' && !c.is_ascii_whitespace())
        .collect();
    if clean.len() != 40 {
        return Err(anyhow!("SHA1 thumbprint must be 40 hex characters"));
    }
    if !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("SHA1 thumbprint contains invalid hex"));
    }
    Ok(clean.to_ascii_uppercase())
}

fn read_existing_cert(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        return Err(anyhow!("certificate '{}' was not found", path.display()));
    }
    std::fs::read(path).with_context(|| format!("read certificate '{}'", path.display()))
}

/// Validate an unencrypted PKCS#8 PEM private key (`BEGIN PRIVATE KEY`).
///
/// # Errors
///
/// Returns an error if PEM decoding fails, the PEM label is not `PRIVATE KEY`, or PKCS#8 parsing fails.
pub fn validate_pkcs8_key_pem(pem: &str) -> Result<PrivateKey> {
    let parsed = picky::pem::parse_pem(pem.as_bytes()).context("parse private key PEM")?;
    if parsed.label() != "PRIVATE KEY" {
        return Err(anyhow!(
            "private key PEM label must be PRIVATE KEY, got {}",
            parsed.label()
        ));
    }
    PrivateKey::from_pkcs8(parsed.data()).context("parse unencrypted PKCS#8 private key")
}

/// Encode a validated private key to canonical PKCS#8 PEM with a trailing newline.
///
/// # Errors
///
/// Returns an error if PEM encoding fails.
pub fn canonical_pkcs8_key_pem(key: &PrivateKey) -> Result<String> {
    key.to_pem_str()
        .map(|mut s| {
            s.push('\n');
            s
        })
        .context("encode PKCS#8 private key PEM")
}

/// Verify that `key` matches the public key in `cert_der`.
///
/// # Errors
///
/// Returns an error if the certificate cannot be parsed, the public key cannot be derived, or they differ.
pub fn ensure_key_matches_cert(cert_der: &[u8], key: &PrivateKey) -> Result<()> {
    let cert = PickyCert::from_der(cert_der).context("parse certificate for key matching")?;
    let key_public = key
        .to_public_key()
        .context("derive public key from private key")?;
    if cert.public_key() != &key_public {
        return Err(anyhow!("private key does not match certificate public key"));
    }
    Ok(())
}
