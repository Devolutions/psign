use crate::CommandOutput;
use crate::cli::{
    CertStoreArgs, CertStoreCommand, CertStoreExportArgs, CertStoreImportArgs,
    CertStoreImportPfxArgs, CertStoreListArgs, CertStorePrintArgs, CertStoreRemoveArgs,
    CertStoreSelectionArgs,
};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use picky::key::PrivateKey;
use picky::pkcs12::{
    Pfx, Pkcs12CryptoContext, Pkcs12ParsingParams, SafeBag, SafeBagKind, SafeContentsKind,
};
use picky::x509::Cert as PickyCert;
use serde::Serialize;
use sha1::{Digest as _, Sha1};
use std::path::{Path, PathBuf};
use x509_cert::Certificate;
use x509_cert::der::Decode;

pub const ENV_CERT_STORE: &str = "PSIGN_CERT_STORE";

#[derive(Debug, Clone)]
struct StoreLocation {
    scope: &'static str,
    store_name: String,
    store_dir: PathBuf,
}

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

#[derive(Debug, Clone, Serialize)]
struct CertificateDetails {
    thumbprint_sha1: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    path: PathBuf,
    has_private_key: bool,
    key_path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ImportReport {
    thumbprint_sha1: String,
    scope: &'static str,
    store: String,
    path: PathBuf,
    imported: bool,
    key_path: Option<PathBuf>,
    key_imported: bool,
}

#[derive(Debug, Serialize)]
struct ListReport {
    scope: &'static str,
    store: String,
    path: PathBuf,
    certificates: Vec<CertificateDetails>,
}

pub fn cert_store_command(args: &CertStoreArgs) -> Result<CommandOutput> {
    match &args.command {
        CertStoreCommand::Import(a) => import_cert(a),
        CertStoreCommand::ImportPfx(a) => import_pfx(a),
        CertStoreCommand::List(a) => list_certs(a),
        CertStoreCommand::Print(a) => print_cert(a),
        CertStoreCommand::Export(a) => export_cert(a),
        CertStoreCommand::Remove(a) => remove_cert(a),
    }
}

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
    let loc = StoreLocation {
        scope,
        store_name,
        store_dir,
    };
    let thumbprint = normalize_sha1_hex(sha1)?;
    let cert_path = cert_path(&loc, &thumbprint);
    let key_path = key_path(&loc, &thumbprint);
    let cert_der = read_existing_cert(&cert_path).with_context(|| {
        format!(
            "resolve signing certificate SHA1 {thumbprint} in {}\\{}",
            loc.scope, loc.store_name
        )
    })?;
    Certificate::from_der(&cert_der)
        .with_context(|| format!("parse X.509 certificate '{}'", cert_path.display()))?;
    let key_text = std::fs::read_to_string(&key_path).with_context(|| {
        format!(
            "resolve private key for SHA1 {thumbprint} in {}\\{}",
            loc.scope, loc.store_name
        )
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
        scope: loc.scope,
        store_name: loc.store_name,
        store_dir: loc.store_dir,
        cert_path,
        key_path,
        cert_der,
        key_pem,
    })
}

fn import_cert(args: &CertStoreImportArgs) -> Result<CommandOutput> {
    let loc = resolve_location(&args.selection)?;
    let der = load_cert_der(&args.cert)?;
    let thumbprint = sha1_thumbprint_upper(&der);
    let path = cert_path(&loc, &thumbprint);
    std::fs::create_dir_all(&loc.store_dir)
        .with_context(|| format!("create cert store '{}'", loc.store_dir.display()))?;
    let imported = if path.exists() {
        false
    } else {
        std::fs::write(&path, &der)
            .with_context(|| format!("write certificate '{}'", path.display()))?;
        true
    };
    let (key_path, key_imported) = if let Some(key) = &args.key {
        let (key_pem, private_key) = load_pkcs8_key_pem(key)?;
        ensure_key_matches_cert(&der, &private_key)?;
        let key_path = key_path(&loc, &thumbprint);
        let imported = write_key_if_needed(&key_path, key_pem.as_bytes())?;
        (Some(key_path), imported)
    } else {
        (None, false)
    };
    let report = ImportReport {
        thumbprint_sha1: thumbprint,
        scope: loc.scope,
        store: loc.store_name,
        path,
        imported,
        key_path,
        key_imported,
    };
    Ok(CommandOutput::ok(format_import_report(&report)))
}

fn import_pfx(args: &CertStoreImportPfxArgs) -> Result<CommandOutput> {
    let loc = resolve_location(&args.selection)?;
    let pfx_bytes =
        std::fs::read(&args.pfx).with_context(|| format!("read PFX '{}'", args.pfx.display()))?;
    let (der, key_pem) = load_pfx_cert_and_key(&pfx_bytes, &args.password)
        .with_context(|| format!("parse PFX '{}'", args.pfx.display()))?;
    let thumbprint = sha1_thumbprint_upper(&der);
    let path = cert_path(&loc, &thumbprint);
    std::fs::create_dir_all(&loc.store_dir)
        .with_context(|| format!("create cert store '{}'", loc.store_dir.display()))?;
    let imported = if path.exists() {
        false
    } else {
        std::fs::write(&path, &der)
            .with_context(|| format!("write certificate '{}'", path.display()))?;
        true
    };
    let key_path = key_path(&loc, &thumbprint);
    let key_imported = write_key_if_needed(&key_path, key_pem.as_bytes())?;
    let report = ImportReport {
        thumbprint_sha1: thumbprint,
        scope: loc.scope,
        store: loc.store_name,
        path,
        imported,
        key_path: Some(key_path),
        key_imported,
    };
    Ok(CommandOutput::ok(format_import_report(&report)))
}

fn list_certs(args: &CertStoreListArgs) -> Result<CommandOutput> {
    let loc = resolve_location(&args.selection)?;
    let mut certificates = Vec::new();
    if loc.store_dir.exists() {
        for entry in std::fs::read_dir(&loc.store_dir)
            .with_context(|| format!("read cert store '{}'", loc.store_dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("read cert store '{}'", loc.store_dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("der") {
                continue;
            }
            let der = std::fs::read(&path)
                .with_context(|| format!("read certificate '{}'", path.display()))?;
            certificates.push(details_from_der_path(&loc, &der, path)?);
        }
    }
    certificates.sort_by(|a, b| a.thumbprint_sha1.cmp(&b.thumbprint_sha1));
    let report = ListReport {
        scope: loc.scope,
        store: loc.store_name,
        path: loc.store_dir,
        certificates,
    };
    if args.json {
        return Ok(CommandOutput::ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&report)?
        )));
    }
    Ok(CommandOutput::ok(format_list_report(&report)))
}

fn print_cert(args: &CertStorePrintArgs) -> Result<CommandOutput> {
    let loc = resolve_location(&args.selection)?;
    let thumbprint = normalize_sha1_hex(&args.sha1)?;
    let path = cert_path(&loc, &thumbprint);
    let der = read_existing_cert(&path)?;
    let details = details_from_der_path(&loc, &der, path)?;
    if args.json {
        return Ok(CommandOutput::ok(format!(
            "{}\n",
            serde_json::to_string_pretty(&details)?
        )));
    }
    Ok(CommandOutput::ok(format_details(&details)))
}

fn export_cert(args: &CertStoreExportArgs) -> Result<CommandOutput> {
    let loc = resolve_location(&args.selection)?;
    let thumbprint = normalize_sha1_hex(&args.sha1)?;
    let path = cert_path(&loc, &thumbprint);
    let der = read_existing_cert(&path)?;
    Certificate::from_der(&der)
        .with_context(|| format!("parse X.509 certificate '{}'", path.display()))?;
    let key_path = key_path(&loc, &thumbprint);
    if args.with_key && !key_path.exists() {
        return Err(anyhow!(
            "private key for SHA1 thumbprint {thumbprint} was not found in {}\\{}",
            loc.scope,
            loc.store_name
        ));
    }
    let key_out = if args.with_key {
        Some(
            args.key_out
                .as_ref()
                .ok_or_else(|| anyhow!("--key-out is required when exporting with --with-key"))?,
        )
    } else {
        None
    };
    if args.out.exists() && !args.force {
        return Err(anyhow!(
            "output file '{}' already exists; use --force to replace it",
            args.out.display()
        ));
    }
    if let Some(key_out) = key_out
        && key_out.exists()
        && !args.force
    {
        return Err(anyhow!(
            "key output file '{}' already exists; use --force to replace it",
            key_out.display()
        ));
    }
    std::fs::write(&args.out, der)
        .with_context(|| format!("write exported certificate '{}'", args.out.display()))?;
    let mut out = format!(
        "Exported certificate\nthumbprint_sha1={thumbprint}\npath={}\nout={}\n",
        path.display(),
        args.out.display()
    );
    if let Some(key_out) = key_out {
        let key_pem = read_existing_key(&key_path)?;
        std::fs::write(key_out, key_pem)
            .with_context(|| format!("write exported private key '{}'", key_out.display()))?;
        out.push_str(&format!(
            "key_path={}\nkey_out={}\n",
            key_path.display(),
            key_out.display()
        ));
    }
    Ok(CommandOutput::ok(out))
}

fn remove_cert(args: &CertStoreRemoveArgs) -> Result<CommandOutput> {
    let loc = resolve_location(&args.selection)?;
    let thumbprint = normalize_sha1_hex(&args.sha1)?;
    let path = cert_path(&loc, &thumbprint);
    if !path.exists() {
        return Err(anyhow!(
            "certificate with SHA1 thumbprint {thumbprint} was not found in {}\\{}",
            loc.scope,
            loc.store_name
        ));
    }
    std::fs::remove_file(&path)
        .with_context(|| format!("remove certificate '{}'", path.display()))?;
    let key_path = key_path(&loc, &thumbprint);
    let key_removed = if key_path.exists() {
        std::fs::remove_file(&key_path)
            .with_context(|| format!("remove private key '{}'", key_path.display()))?;
        true
    } else {
        false
    };
    Ok(CommandOutput::ok(format!(
        "Removed certificate\nthumbprint_sha1={thumbprint}\nstore={}\\{}\npath={}\nkey_removed={key_removed}\n",
        loc.scope,
        loc.store_name,
        path.display()
    )))
}

fn resolve_location(selection: &CertStoreSelectionArgs) -> Result<StoreLocation> {
    let base_dir = resolve_base_dir(selection.cert_store_dir.as_deref())?;
    let scope = if selection.machine_store {
        "LocalMachine"
    } else {
        "CurrentUser"
    };
    let store_name = normalize_store_name(&selection.store_name)?;
    let store_dir = base_dir.join(scope).join(&store_name);
    Ok(StoreLocation {
        scope,
        store_name,
        store_dir,
    })
}

fn resolve_base_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os(ENV_CERT_STORE) {
        return Ok(PathBuf::from(path));
    }
    Ok(home_dir()?.join(".psign").join("cert-store"))
}

fn home_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home));
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(profile));
    }
    match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
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

fn normalize_store_name(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("certificate store name must not be empty"));
    }
    if trimmed.contains(['/', '\\', '\0']) {
        return Err(anyhow!(
            "certificate store name must not contain path separators"
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

fn normalize_sha1_hex(input: &str) -> Result<String> {
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

fn cert_path(loc: &StoreLocation, thumbprint: &str) -> PathBuf {
    loc.store_dir.join(format!("{thumbprint}.der"))
}

fn key_path(loc: &StoreLocation, thumbprint: &str) -> PathBuf {
    loc.store_dir.join(format!("{thumbprint}.key"))
}

fn read_existing_cert(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        return Err(anyhow!("certificate '{}' was not found", path.display()));
    }
    std::fs::read(path).with_context(|| format!("read certificate '{}'", path.display()))
}

fn read_existing_key(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        return Err(anyhow!("private key '{}' was not found", path.display()));
    }
    std::fs::read(path).with_context(|| format!("read private key '{}'", path.display()))
}

fn load_cert_der(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read certificate '{}'", path.display()))?;
    let der = pem_or_der_to_der(&bytes)
        .with_context(|| format!("parse certificate '{}'", path.display()))?;
    Certificate::from_der(&der)
        .with_context(|| format!("parse X.509 certificate '{}'", path.display()))?;
    Ok(der)
}

fn pem_or_der_to_der(bytes: &[u8]) -> Result<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Ok(bytes.to_vec());
    };
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let Some(start) = text.find(begin) else {
        return Ok(bytes.to_vec());
    };
    let body_start = start + begin.len();
    let body_end = text[body_start..]
        .find(end)
        .map(|i| body_start + i)
        .ok_or_else(|| anyhow!("PEM certificate is missing END CERTIFICATE marker"))?;
    let encoded: String = text[body_start..body_end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .context("decode PEM certificate base64")
}

fn load_pkcs8_key_pem(path: &Path) -> Result<(String, PrivateKey)> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("read private key '{}'", path.display()))?;
    let key = validate_pkcs8_key_pem(&pem).with_context(|| {
        format!(
            "parse private key '{}'; expected PEM unencrypted PKCS#8 (BEGIN PRIVATE KEY)",
            path.display()
        )
    })?;
    Ok((canonical_pkcs8_key_pem(&key)?, key))
}

fn validate_pkcs8_key_pem(pem: &str) -> Result<PrivateKey> {
    let parsed = picky::pem::parse_pem(pem.as_bytes()).context("parse private key PEM")?;
    if parsed.label() != "PRIVATE KEY" {
        return Err(anyhow!(
            "private key PEM label must be PRIVATE KEY, got {}",
            parsed.label()
        ));
    }
    PrivateKey::from_pkcs8(parsed.data()).context("parse unencrypted PKCS#8 private key")
}

fn canonical_pkcs8_key_pem(key: &PrivateKey) -> Result<String> {
    key.to_pem_str()
        .map(|mut s| {
            s.push('\n');
            s
        })
        .context("encode PKCS#8 private key PEM")
}

fn ensure_key_matches_cert(cert_der: &[u8], key: &PrivateKey) -> Result<()> {
    let cert = PickyCert::from_der(cert_der).context("parse certificate for key matching")?;
    let key_public = key
        .to_public_key()
        .context("derive public key from private key")?;
    if cert.public_key() != &key_public {
        return Err(anyhow!("private key does not match certificate public key"));
    }
    Ok(())
}

fn write_key_if_needed(path: &Path, key_pem: &[u8]) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    write_private_key_file(path, key_pem)?;
    Ok(true)
}

fn write_private_key_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("write private key '{}'", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write private key '{}'", path.display()))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
            .with_context(|| format!("write private key '{}'", path.display()))
    }
}

fn load_pfx_cert_and_key(bytes: &[u8], password: &str) -> Result<(Vec<u8>, String)> {
    let crypto_context = Pkcs12CryptoContext::new_with_password(password)?;
    let parsing_params = Pkcs12ParsingParams::default();
    let pfx = Pfx::from_der(bytes, &crypto_context, &parsing_params)?;
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut keys: Vec<(String, PrivateKey)> = Vec::new();
    for safe_contents in pfx.safe_contents() {
        collect_pfx_bags(safe_contents.kind(), &mut certs, &mut keys)?;
    }
    if certs.is_empty() {
        return Err(anyhow!("PFX did not contain an X.509 certificate"));
    }
    if keys.is_empty() {
        return Err(anyhow!("PFX did not contain a private key"));
    }
    for cert in certs {
        for (key_pem, key) in &keys {
            if ensure_key_matches_cert(&cert, key).is_ok() {
                return Ok((cert, key_pem.clone()));
            }
        }
    }
    Err(anyhow!(
        "PFX did not contain a certificate matching an included private key"
    ))
}

fn collect_pfx_bags(
    kind: &SafeContentsKind,
    certs: &mut Vec<Vec<u8>>,
    keys: &mut Vec<(String, PrivateKey)>,
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
    certs: &mut Vec<Vec<u8>>,
    keys: &mut Vec<(String, PrivateKey)>,
) -> Result<()> {
    match bag.kind() {
        SafeBagKind::PrivateKey(key) | SafeBagKind::EncryptedPrivateKey { key, .. } => {
            let mut pem = key
                .to_pem_str()
                .context("encode PFX private key as PKCS#8 PEM")?;
            pem.push('\n');
            keys.push((pem, key.clone()));
        }
        SafeBagKind::Certificate(cert) => {
            certs.push(cert.to_der().context("encode PFX certificate as DER")?);
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

fn sha1_thumbprint_upper(der: &[u8]) -> String {
    let digest = Sha1::digest(der);
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

fn details_from_der_path(
    loc: &StoreLocation,
    der: &[u8],
    path: PathBuf,
) -> Result<CertificateDetails> {
    let cert = Certificate::from_der(der)
        .with_context(|| format!("parse X.509 certificate '{}'", path.display()))?;
    let thumbprint = sha1_thumbprint_upper(der);
    let key_path = key_path(loc, &thumbprint);
    let has_private_key = key_path.exists();
    Ok(CertificateDetails {
        thumbprint_sha1: thumbprint,
        subject: cert.tbs_certificate.subject.to_string(),
        issuer: cert.tbs_certificate.issuer.to_string(),
        not_before: cert.tbs_certificate.validity.not_before.to_string(),
        not_after: cert.tbs_certificate.validity.not_after.to_string(),
        path,
        has_private_key,
        key_path: has_private_key.then_some(key_path),
    })
}

fn format_import_report(report: &ImportReport) -> String {
    let mut out = format!(
        "{} certificate\nthumbprint_sha1={}\nstore={}\\{}\npath={}\n",
        if report.imported {
            "Imported"
        } else {
            "Certificate already present"
        },
        report.thumbprint_sha1,
        report.scope,
        report.store,
        report.path.display()
    );
    if let Some(key_path) = &report.key_path {
        out.push_str(&format!(
            "{} private key\nkey_path={}\n",
            if report.key_imported {
                "Imported"
            } else {
                "Private key already present"
            },
            key_path.display()
        ));
    }
    out
}

fn format_list_report(report: &ListReport) -> String {
    let mut out = format!(
        "Store: {}\\{}\nPath: {}\n",
        report.scope,
        report.store,
        report.path.display()
    );
    if report.certificates.is_empty() {
        out.push_str("No certificates found\n");
        return out;
    }
    for cert in &report.certificates {
        out.push_str(&format!(
            "{}\n  subject={}\n  issuer={}\n  not_before={}\n  not_after={}\n  has_private_key={}\n  path={}\n",
            cert.thumbprint_sha1,
            cert.subject,
            cert.issuer,
            cert.not_before,
            cert.not_after,
            cert.has_private_key,
            cert.path.display()
        ));
    }
    out
}

fn format_details(details: &CertificateDetails) -> String {
    format!(
        "Certificate\nthumbprint_sha1={}\nsubject={}\nissuer={}\nnot_before={}\nnot_after={}\nhas_private_key={}\npath={}\n",
        details.thumbprint_sha1,
        details.subject,
        details.issuer,
        details.not_before,
        details.not_after,
        details.has_private_key,
        details.path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_sha1_thumbprints() {
        let value = "aa:bb ccdd eeff 0011 2233 4455 6677 8899 aabb ccdd";
        assert_eq!(
            normalize_sha1_hex(value).unwrap(),
            "AABBCCDDEEFF00112233445566778899AABBCCDD"
        );
    }

    #[test]
    fn rejects_store_path_separators() {
        assert!(normalize_store_name("MY/Other").is_err());
        assert!(normalize_store_name("MY\\Other").is_err());
    }

    #[test]
    fn canonicalizes_known_store_names() {
        assert_eq!(normalize_store_name("my").unwrap(), "MY");
        assert_eq!(normalize_store_name("root").unwrap(), "Root");
        assert_eq!(normalize_store_name("ca").unwrap(), "CA");
    }

    #[test]
    fn derives_key_path_from_thumbprint() {
        let loc = StoreLocation {
            scope: "CurrentUser",
            store_name: "MY".to_string(),
            store_dir: PathBuf::from("store").join("CurrentUser").join("MY"),
        };
        assert_eq!(
            key_path(&loc, "ABCDEF")
                .file_name()
                .and_then(|n| n.to_str()),
            Some("ABCDEF.key")
        );
    }

    #[test]
    fn rejects_non_pkcs8_private_key_pem_label() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n";
        let err = validate_pkcs8_key_pem(pem).unwrap_err();
        assert!(err.to_string().contains("PRIVATE KEY"));
    }
}
