//! Reusable portable Authenticode operations for CLI adapters and foreign-function callers.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use psign_authenticode_trust::inspect_authenticode_pkcs7_der;
use psign_authenticode_trust::inspect_pe_authenticode;
use psign_sip_digest::pkcs7::AuthenticodeSigningDigest;
use psign_sip_digest::verify_pe::verify_pe_authenticode_digest_consistency;
use psign_sip_digest::{
    cab_digest, msi_digest, msix_digest, pe_embed, pkcs7, ps_script, rdp,
    verify_script_digest_consistency, zip_authenticode,
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableFileFormat {
    Pe,
    Cab,
    Msi,
    Msix,
    Catalog,
    Zip,
    PowerShellScript,
    WshScript,
    Unknown,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableSignatureStatus {
    Valid,
    NotSigned,
    HashMismatch,
    NotTrusted,
    NotSupportedFileFormat,
    Incompatible,
    UnknownError,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableDigestAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl From<PortableDigestAlgorithm> for AuthenticodeSigningDigest {
    fn from(value: PortableDigestAlgorithm) -> Self {
        match value {
            PortableDigestAlgorithm::Sha256 => Self::Sha256,
            PortableDigestAlgorithm::Sha384 => Self::Sha384,
            PortableDigestAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableGetSignatureRequest {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSignRequest {
    pub path: PathBuf,
    #[serde(default)]
    pub output_path: Option<PathBuf>,
    #[serde(default)]
    pub hash_algorithm: PortableDigestAlgorithm,
    #[serde(default)]
    pub certificate_path: Option<PathBuf>,
    #[serde(default)]
    pub private_key_path: Option<PathBuf>,
    #[serde(default)]
    pub certificate_der_base64: Option<String>,
    #[serde(default)]
    pub private_key_der_base64: Option<String>,
    #[serde(default)]
    pub chain_certificate_paths: Vec<PathBuf>,
    #[serde(default)]
    pub chain_certificates_der_base64: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSignatureResponse {
    pub schema_version: u32,
    pub path: PathBuf,
    pub format: PortableFileFormat,
    pub status: PortableSignatureStatus,
    pub status_message: String,
    pub signature_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timestamp_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSignResponse {
    pub schema_version: u32,
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub format: PortableFileFormat,
    pub signature: PortableSignatureResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableVersionResponse {
    pub schema_version: u32,
    pub crate_name: &'static str,
    pub crate_version: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableErrorResponse {
    pub schema_version: u32,
    pub code: PortableErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableErrorCode {
    InvalidRequest,
    Io,
    NotSupportedFileFormat,
    UnsupportedOperation,
    OperationFailed,
    Panic,
}

pub fn version() -> PortableVersionResponse {
    PortableVersionResponse {
        schema_version: SCHEMA_VERSION,
        crate_name: env!("CARGO_PKG_NAME"),
        crate_version: env!("CARGO_PKG_VERSION"),
    }
}

pub fn portable_sign(request: PortableSignRequest) -> Result<PortableSignResponse> {
    let format = infer_format(&request.path);
    let output_path = request
        .output_path
        .clone()
        .unwrap_or_else(|| request.path.clone());

    match format {
        PortableFileFormat::Pe => sign_pe(&request, &output_path),
        PortableFileFormat::Cab => sign_cab(&request, &output_path),
        PortableFileFormat::Msi => sign_msi(&request, &output_path),
        PortableFileFormat::Msix => sign_msix(&request, &output_path),
        PortableFileFormat::Zip => sign_zip(&request, &output_path),
        PortableFileFormat::PowerShellScript => sign_script(&request, &output_path),
        PortableFileFormat::WshScript => bail!("portable WSH script signing is not supported yet"),
        PortableFileFormat::Catalog => bail!(
            "portable catalog signing requires an explicit subject list and is not available through PortableSignRequest yet"
        ),
        PortableFileFormat::Unknown => {
            bail!(
                "unsupported portable signing format: {}",
                request.path.display()
            )
        }
    }?;

    let signature = portable_get_signature(PortableGetSignatureRequest {
        path: output_path.clone(),
    })?;

    Ok(PortableSignResponse {
        schema_version: SCHEMA_VERSION,
        input_path: request.path,
        output_path,
        format,
        signature,
    })
}

pub fn portable_get_signature(
    request: PortableGetSignatureRequest,
) -> Result<PortableSignatureResponse> {
    let format = infer_format(&request.path);
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;

    let response = match format {
        PortableFileFormat::Pe => inspect_pe(&request.path, &data),
        PortableFileFormat::Cab => inspect_cab(&request.path),
        PortableFileFormat::Msi => inspect_msi(&request.path),
        PortableFileFormat::Msix => inspect_msix(&request.path),
        PortableFileFormat::Zip => inspect_zip(&request.path, &data),
        PortableFileFormat::PowerShellScript | PortableFileFormat::WshScript => {
            inspect_script(&request.path, &data)
        }
        PortableFileFormat::Catalog => inspect_pkcs7_file(&request.path, format),
        PortableFileFormat::Unknown => Ok(base_response(
            request.path,
            format,
            PortableSignatureStatus::NotSupportedFileFormat,
            "Unsupported file format for portable Authenticode inspection.",
        )),
    }?;

    Ok(response)
}

pub fn infer_format(path: &Path) -> PortableFileFormat {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return PortableFileFormat::Unknown;
    };
    match ext.to_ascii_lowercase().as_str() {
        "exe" | "dll" | "sys" | "efi" | "winmd" | "mui" | "ocx" | "scr" | "cpl" => {
            PortableFileFormat::Pe
        }
        "cab" => PortableFileFormat::Cab,
        "msi" | "msp" => PortableFileFormat::Msi,
        "msix" | "appx" | "msixbundle" | "appxbundle" => PortableFileFormat::Msix,
        "cat" => PortableFileFormat::Catalog,
        "zip" | "vsix" | "nupkg" => PortableFileFormat::Zip,
        "ps1" | "psm1" | "psd1" | "ps1xml" => PortableFileFormat::PowerShellScript,
        "vbs" | "js" | "wsf" => PortableFileFormat::WshScript,
        _ => PortableFileFormat::Unknown,
    }
}

pub fn portable_error_response(
    code: PortableErrorCode,
    error: impl std::fmt::Display,
) -> PortableErrorResponse {
    PortableErrorResponse {
        schema_version: SCHEMA_VERSION,
        code,
        message: error.to_string(),
    }
}

fn sign_pe(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let pe =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let pkcs7 = pkcs7::create_pe_authenticode_pkcs7_der_rsa(
        &pe,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| {
        format!(
            "create portable PE Authenticode signature for {}",
            request.path.display()
        )
    })?;
    let signed = pe_embed::pe_append_authenticode_pkcs7_certificate(pe, &pkcs7)
        .with_context(|| format!("embed Authenticode signature in {}", request.path.display()))?;
    std::fs::write(output_path, signed).with_context(|| format!("write {}", output_path.display()))
}

fn sign_cab(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let cab =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let pkcs7 = pkcs7::create_cab_authenticode_pkcs7_der_rsa(
        &cab,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| {
        format!(
            "create portable CAB Authenticode signature for {}",
            request.path.display()
        )
    })?;
    let signed = cab_digest::cab_append_authenticode_pkcs7_signature(&cab, &pkcs7)
        .with_context(|| format!("embed Authenticode signature in {}", request.path.display()))?;
    std::fs::write(output_path, signed).with_context(|| format!("write {}", output_path.display()))
}

fn sign_msi(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let msi =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let pkcs7 = pkcs7::create_msi_authenticode_pkcs7_der_rsa(
        &msi,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| {
        format!(
            "create portable MSI Authenticode signature for {}",
            request.path.display()
        )
    })?;
    msi_digest::msi_embed_authenticode_pkcs7_signature(&request.path, output_path, &pkcs7)
        .with_context(|| format!("embed Authenticode signature in {}", request.path.display()))
}

fn sign_msix(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let ext = request
        .path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(ext.as_str(), "msix" | "appx") {
        bail!("portable MSIX signing currently supports flat .msix/.appx packages");
    }

    let package =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let staged = stage_flat_msix_for_signature(&package, request.hash_algorithm)
        .with_context(|| format!("stage {} for MSIX signing", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let pkcs7 = pkcs7::create_msix_authenticode_pkcs7_der_rsa(
        &staged,
        &ext,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| {
        format!(
            "create portable MSIX Authenticode signature for {}",
            request.path.display()
        )
    })?;
    let mut p7x = b"PKCX".to_vec();
    p7x.extend_from_slice(&pkcs7);
    let signed = replace_msix_signature_part(&staged, &p7x)
        .with_context(|| format!("embed AppxSignature.p7x in {}", request.path.display()))?;
    std::fs::write(output_path, signed).with_context(|| format!("write {}", output_path.display()))
}

fn sign_zip(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let zip =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let digest = zip_authenticode::zip_authenticode_digest_string(&zip).with_context(|| {
        format!(
            "compute ZIP Authenticode digest for {}",
            request.path.display()
        )
    })?;
    let script = zip_authenticode::unsigned_signature_script_bytes(&digest);
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let pkcs7 = pkcs7::create_script_authenticode_pkcs7_der_rsa(
        &script,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| {
        format!(
            "create portable ZIP signature script Authenticode signature for {}",
            request.path.display()
        )
    })?;
    let line = zip_authenticode::signature_comment_line_from_pkcs7_der(&digest, &pkcs7)?;
    let signed =
        zip_authenticode::embed_signature_comment_line(&zip, &line).with_context(|| {
            format!(
                "embed ZIP Authenticode comment in {}",
                request.path.display()
            )
        })?;
    std::fs::write(output_path, signed).with_context(|| format!("write {}", output_path.display()))
}

fn sign_script(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let ext = request
        .path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("ps1")
        .to_ascii_lowercase();
    if !matches!(ext.as_str(), "ps1" | "psd1" | "psm1") {
        bail!("portable script signing currently supports ps1, psd1, and psm1 hash-marker scripts");
    }

    let script =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let pkcs7 = pkcs7::create_script_authenticode_pkcs7_der_rsa(
        &script,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| {
        format!(
            "create portable script Authenticode signature for {}",
            request.path.display()
        )
    })?;
    let block = format_powershell_signature_block(&pkcs7);
    let mut signed = script;
    signed.extend_from_slice(block.as_bytes());
    std::fs::write(output_path, signed).with_context(|| format!("write {}", output_path.display()))
}

fn load_signing_material(
    request: &PortableSignRequest,
) -> Result<(
    x509_cert::Certificate,
    rsa::RsaPrivateKey,
    Vec<x509_cert::Certificate>,
)> {
    let cert_bytes = match (&request.certificate_der_base64, &request.certificate_path) {
        (Some(_), Some(_)) => {
            bail!("provide only one of certificate_der_base64 or certificate_path")
        }
        (Some(b64), None) => base64::engine::general_purpose::STANDARD
            .decode(b64)
            .context("decode certificate_der_base64")?,
        (None, Some(path)) => {
            std::fs::read(path).with_context(|| format!("read {}", path.display()))?
        }
        (None, None) => {
            bail!("portable signing requires certificate_der_base64 or certificate_path")
        }
    };
    let key_bytes = match (&request.private_key_der_base64, &request.private_key_path) {
        (Some(_), Some(_)) => {
            bail!("provide only one of private_key_der_base64 or private_key_path")
        }
        (Some(b64), None) => base64::engine::general_purpose::STANDARD
            .decode(b64)
            .context("decode private_key_der_base64")?,
        (None, Some(path)) => {
            std::fs::read(path).with_context(|| format!("read {}", path.display()))?
        }
        (None, None) => {
            bail!("portable signing requires private_key_der_base64 or private_key_path")
        }
    };

    let signer_cert = rdp::parse_certificate(&cert_bytes).context("parse signer certificate")?;
    let private_key = rdp::parse_rsa_private_key(&key_bytes).context("parse RSA private key")?;
    let mut chain = Vec::new();
    for path in &request.chain_certificate_paths {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        chain.push(
            rdp::parse_certificate(&bytes)
                .with_context(|| format!("parse chain certificate {}", path.display()))?,
        );
    }
    for (index, b64) in request.chain_certificates_der_base64.iter().enumerate() {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .with_context(|| format!("decode chain_certificates_der_base64[{index}]"))?;
        chain.push(
            rdp::parse_certificate(&bytes)
                .with_context(|| format!("parse chain certificate {index}"))?,
        );
    }

    Ok((signer_cert, private_key, chain))
}

fn inspect_pe(path: &Path, data: &[u8]) -> Result<PortableSignatureResponse> {
    let inspect = inspect_pe_authenticode(data);
    match verify_pe_authenticode_digest_consistency(data) {
        Ok(result) => {
            let (digest_algorithm, timestamp_kinds) = inspect
                .ok()
                .map(|r| summarize_pkcs7_reports(r.entries.into_iter().map(|e| e.pkcs7)))
                .unwrap_or_default();
            Ok(PortableSignatureResponse {
                schema_version: SCHEMA_VERSION,
                path: path.to_path_buf(),
                format: PortableFileFormat::Pe,
                status: PortableSignatureStatus::Valid,
                status_message: "Portable digest binding is valid; trust was not evaluated."
                    .to_string(),
                signature_count: result.pkcs7_authenticode_entries,
                digest_algorithm,
                timestamp_kinds,
                diagnostics: vec![format!(
                    "matched_attribute_certificate_index={}",
                    result.matched_attribute_certificate_index
                )],
            })
        }
        Err(error) => Ok(map_digest_error(path, PortableFileFormat::Pe, error)),
    }
}

fn inspect_cab(path: &Path) -> Result<PortableSignatureResponse> {
    match cab_digest::verify_cab_digest_consistency(path) {
        Ok(()) => Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::Cab,
            PortableSignatureStatus::Valid,
            "Portable digest binding is valid; trust was not evaluated.",
        )),
        Err(error) => Ok(map_digest_error(path, PortableFileFormat::Cab, error)),
    }
}

fn inspect_msi(path: &Path) -> Result<PortableSignatureResponse> {
    match msi_digest::verify_msi_digest_consistency(path) {
        Ok(()) => Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::Msi,
            PortableSignatureStatus::Valid,
            "Portable digest binding is valid; trust was not evaluated.",
        )),
        Err(error) => Ok(map_digest_error(path, PortableFileFormat::Msi, error)),
    }
}

fn inspect_msix(path: &Path) -> Result<PortableSignatureResponse> {
    match msix_digest::verify_msix_digest_consistency(path) {
        Ok(()) => Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::Msix,
            PortableSignatureStatus::Valid,
            "Portable MSIX digest binding is valid; trust was not evaluated.",
        )),
        Err(error) => Ok(map_digest_error(path, PortableFileFormat::Msix, error)),
    }
}

fn inspect_zip(path: &Path, data: &[u8]) -> Result<PortableSignatureResponse> {
    let sig = match zip_authenticode::verify_zip_digest_binding(data) {
        Ok(sig) => sig,
        Err(error) => return Ok(map_digest_error(path, PortableFileFormat::Zip, error)),
    };
    let script = zip_authenticode::signature_script_from_parts(&sig.digest, &sig.pkcs7_base64);
    if let Err(error) = verify_script_digest_consistency(script.as_bytes(), "ps1") {
        return Ok(map_digest_error(path, PortableFileFormat::Zip, error));
    }
    let pkcs7 = zip_authenticode::signature_pkcs7_der(&sig)?;
    let report = inspect_authenticode_pkcs7_der(&pkcs7).ok();
    let (digest_algorithm, timestamp_kinds) = report
        .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
        .unwrap_or_default();
    Ok(PortableSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path: path.to_path_buf(),
        format: PortableFileFormat::Zip,
        status: PortableSignatureStatus::Valid,
        status_message: "Portable ZIP digest binding is valid; trust was not evaluated."
            .to_string(),
        signature_count: 1,
        digest_algorithm,
        timestamp_kinds,
        diagnostics: Vec::new(),
    })
}

fn inspect_script(path: &Path, data: &[u8]) -> Result<PortableSignatureResponse> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("ps1");
    match verify_script_digest_consistency(data, ext) {
        Ok(()) => {
            let report = if ps_script::is_wsh_extension(&ext.to_ascii_lowercase()) {
                None
            } else {
                ps_script::powershell_class_digest_report(data, ext)
                    .ok()
                    .and_then(|r| inspect_authenticode_pkcs7_der(&r.pkcs7_der).ok())
            };
            let (digest_algorithm, timestamp_kinds) = report
                .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
                .unwrap_or_default();
            Ok(PortableSignatureResponse {
                schema_version: SCHEMA_VERSION,
                path: path.to_path_buf(),
                format: infer_format(path),
                status: PortableSignatureStatus::Valid,
                status_message: "Portable script digest binding is valid; trust was not evaluated."
                    .to_string(),
                signature_count: 1,
                digest_algorithm,
                timestamp_kinds,
                diagnostics: Vec::new(),
            })
        }
        Err(error) => Ok(map_digest_error(path, infer_format(path), error)),
    }
}

fn inspect_pkcs7_file(
    path: &Path,
    format: PortableFileFormat,
) -> Result<PortableSignatureResponse> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    match inspect_authenticode_pkcs7_der(&data) {
        Ok(report) => {
            let (digest_algorithm, timestamp_kinds) =
                summarize_pkcs7_reports(std::iter::once(report));
            Ok(PortableSignatureResponse {
                schema_version: SCHEMA_VERSION,
                path: path.to_path_buf(),
                format,
                status: PortableSignatureStatus::Valid,
                status_message:
                    "PKCS#7 structure is valid; detached content and trust were not evaluated."
                        .to_string(),
                signature_count: 1,
                digest_algorithm,
                timestamp_kinds,
                diagnostics: Vec::new(),
            })
        }
        Err(error) => Ok(map_digest_error(path, format, error)),
    }
}

fn summarize_pkcs7_reports(
    reports: impl IntoIterator<Item = psign_authenticode_trust::inspect::InspectPkcs7Report>,
) -> (Option<String>, Vec<String>) {
    let mut digest_algorithm = None;
    let mut timestamp_kinds = Vec::new();
    for report in reports {
        collect_pkcs7_summary(&report, &mut digest_algorithm, &mut timestamp_kinds);
    }
    (digest_algorithm, timestamp_kinds)
}

fn collect_pkcs7_summary(
    report: &psign_authenticode_trust::inspect::InspectPkcs7Report,
    digest_algorithm: &mut Option<String>,
    timestamp_kinds: &mut Vec<String>,
) {
    if digest_algorithm.is_none()
        && let Some(digest) = &report.authenticode_digest
    {
        *digest_algorithm = Some(digest.digest_algorithm_oid.clone());
    }
    for signer in &report.signers {
        for hint in &signer.timestamp_hints {
            let kind = hint.kind.to_string();
            if !timestamp_kinds.contains(&kind) {
                timestamp_kinds.push(kind);
            }
        }
    }
    for nested in &report.nested_signatures {
        collect_pkcs7_summary(nested, digest_algorithm, timestamp_kinds);
    }
}

fn base_response(
    path: PathBuf,
    format: PortableFileFormat,
    status: PortableSignatureStatus,
    message: impl Into<String>,
) -> PortableSignatureResponse {
    PortableSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path,
        format,
        status,
        status_message: message.into(),
        signature_count: usize::from(status == PortableSignatureStatus::Valid),
        digest_algorithm: None,
        timestamp_kinds: Vec::new(),
        diagnostics: Vec::new(),
    }
}

fn map_digest_error(
    path: &Path,
    format: PortableFileFormat,
    error: anyhow::Error,
) -> PortableSignatureResponse {
    let message = error.to_string();
    let status = if looks_unsigned(&message) {
        PortableSignatureStatus::NotSigned
    } else if message.to_ascii_lowercase().contains("mismatch") {
        PortableSignatureStatus::HashMismatch
    } else if format == PortableFileFormat::Unknown {
        PortableSignatureStatus::NotSupportedFileFormat
    } else {
        PortableSignatureStatus::Incompatible
    };
    PortableSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path: path.to_path_buf(),
        format,
        status,
        status_message: message,
        signature_count: 0,
        digest_algorithm: None,
        timestamp_kinds: Vec::new(),
        diagnostics: Vec::new(),
    }
}

fn looks_unsigned(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not found")
        || lower.contains("not signed")
        || lower.contains("no certificate table")
        || lower.contains("no pkcs#7")
        || lower.contains("digital signature stream")
        || lower.contains("signature comment not found")
        || lower.contains("appxsignature.p7x")
        || lower.contains("signature block")
}

fn stage_flat_msix_for_signature(
    package: &[u8],
    digest_algorithm: PortableDigestAlgorithm,
) -> Result<Vec<u8>> {
    let mut source = ZipArchive::new(Cursor::new(package)).context("open MSIX ZIP")?;
    let mut payloads = Vec::new();
    let mut content_types = None;

    for i in 0..source.len() {
        let mut entry = source.by_index(i).context("read MSIX ZIP entry")?;
        let name = entry.name().replace('\\', "/");
        if name.ends_with('/') {
            continue;
        }
        match name.as_str() {
            "[Content_Types].xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                content_types = Some(data);
            }
            "AppxBlockMap.xml" | "AppxSignature.p7x" | "AppxMetadata/CodeIntegrity.cat" => {}
            _ => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                payloads.push((name, data));
            }
        }
    }

    if !payloads.iter().any(|(name, _)| name == "AppxManifest.xml") {
        bail!("flat MSIX package is missing AppxManifest.xml");
    }
    let content_types = add_msix_signature_content_type(
        std::str::from_utf8(
            content_types
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("MSIX package is missing [Content_Types].xml"))?,
        )
        .context("[Content_Types].xml is not UTF-8")?,
    )?;
    let block_map = build_flat_msix_block_map(&payloads, digest_algorithm)?;

    let mut out = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut out);
        let stored = FileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, data) in &payloads {
            writer.start_file(name, stored)?;
            writer.write_all(data)?;
        }
        writer.start_file("AppxBlockMap.xml", stored)?;
        writer.write_all(block_map.as_bytes())?;
        writer.start_file("[Content_Types].xml", stored)?;
        writer.write_all(content_types.as_bytes())?;
        writer.start_file("AppxSignature.p7x", stored)?;
        writer.write_all(b"PKCX")?;
        writer.finish()?;
    }
    Ok(out.into_inner())
}

fn replace_msix_signature_part(package: &[u8], p7x: &[u8]) -> Result<Vec<u8>> {
    let mut source = ZipArchive::new(Cursor::new(package)).context("open staged MSIX ZIP")?;
    let mut out = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut out);
        for i in 0..source.len() {
            let mut entry = source.by_index(i).context("read staged MSIX ZIP entry")?;
            if entry.name().ends_with('/') {
                continue;
            }
            let name = entry.name().to_owned();
            let options = FileOptions::default().compression_method(entry.compression());
            writer.start_file(&name, options)?;
            if name == "AppxSignature.p7x" {
                writer.write_all(p7x)?;
            } else {
                std::io::copy(&mut entry, &mut writer)?;
            }
        }
        writer.finish()?;
    }
    Ok(out.into_inner())
}

fn add_msix_signature_content_type(xml: &str) -> Result<String> {
    if xml.contains("PartName=\"/AppxSignature.p7x\"")
        || xml.contains("PartName='/AppxSignature.p7x'")
    {
        return Ok(xml.to_string());
    }
    let insertion = r#"<Override PartName="/AppxSignature.p7x" ContentType="application/vnd.ms-appx.signature"/>"#;
    if let Some(pos) = xml.rfind("</Types>") {
        let mut out = String::with_capacity(xml.len() + insertion.len());
        out.push_str(&xml[..pos]);
        out.push_str(insertion);
        out.push_str(&xml[pos..]);
        return Ok(out);
    }
    bail!("[Content_Types].xml does not contain a closing </Types> element");
}

fn build_flat_msix_block_map(
    payloads: &[(String, Vec<u8>)],
    digest_algorithm: PortableDigestAlgorithm,
) -> Result<String> {
    let hash_method = match digest_algorithm {
        PortableDigestAlgorithm::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        PortableDigestAlgorithm::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        PortableDigestAlgorithm::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
    };
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="{hash_method}">"#
    );
    for (name, data) in payloads {
        let escaped_name = xml_escape_attr(name);
        xml.push_str(&format!(
            r#"<File Name="{escaped_name}" Size="{}" LfhSize="{}">"#,
            data.len(),
            30 + name.len()
        ));
        for chunk in data.chunks(64 * 1024) {
            let digest = match digest_algorithm {
                PortableDigestAlgorithm::Sha256 => sha2::Sha256::digest(chunk).to_vec(),
                PortableDigestAlgorithm::Sha384 => sha2::Sha384::digest(chunk).to_vec(),
                PortableDigestAlgorithm::Sha512 => sha2::Sha512::digest(chunk).to_vec(),
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
            xml.push_str(&format!(r#"<Block Hash="{encoded}"/>"#));
        }
        xml.push_str("</File>");
    }
    xml.push_str("</BlockMap>");
    Ok(xml)
}

fn xml_escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn format_powershell_signature_block(pkcs7_der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs7_der);
    let mut block = String::from("\r\n# SIG # Begin signature block\r\n");
    for chunk in b64.as_bytes().chunks(64) {
        block.push_str("# ");
        block.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        block.push_str("\r\n");
    }
    block.push_str("# SIG # End signature block\r\n");
    block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infers_expected_formats() {
        assert_eq!(infer_format(Path::new("tool.exe")), PortableFileFormat::Pe);
        assert_eq!(
            infer_format(Path::new("driver.SYS")),
            PortableFileFormat::Pe
        );
        assert_eq!(
            infer_format(Path::new("package.nupkg")),
            PortableFileFormat::Zip
        );
        assert_eq!(
            infer_format(Path::new("install.msi")),
            PortableFileFormat::Msi
        );
        assert_eq!(
            infer_format(Path::new("script.ps1")),
            PortableFileFormat::PowerShellScript
        );
        assert_eq!(
            infer_format(Path::new("unknown.bin")),
            PortableFileFormat::Unknown
        );
    }

    #[test]
    fn reports_unsigned_pe_without_error() {
        let path = PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.efi");
        let response =
            portable_get_signature(PortableGetSignatureRequest { path }).expect("inspect PE");
        assert_eq!(response.status, PortableSignatureStatus::NotSigned);
    }

    #[test]
    fn reports_signed_pe_as_valid_digest_binding() {
        let path = PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let response =
            portable_get_signature(PortableGetSignatureRequest { path }).expect("inspect PE");
        assert_eq!(response.status, PortableSignatureStatus::Valid);
        assert!(response.signature_count > 0);
    }
}
