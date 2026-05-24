//! Reusable portable Authenticode operations for CLI adapters and foreign-function callers.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use der::Encode as _;
use picky::key::PrivateKey;
use picky::pkcs12::{
    Pfx, Pkcs12CryptoContext, Pkcs12ParsingParams, SafeBag, SafeBagKind, SafeContentsKind,
};
use picky::x509::Cert as PickyCert;
use picky::x509::date::UtcDate;
use psign_authenticode_trust::policy::{OnlineTrustOptions, RevocationMode};
use psign_authenticode_trust::{
    AuthenticodeTrustPolicy, TrustVerifyPeOptions, inspect_authenticode_pkcs7_der,
    inspect_pe_authenticode, trust_verify_cab_bytes, trust_verify_msi_bytes, trust_verify_pe_bytes,
    trust_verify_script_bytes, trust_verify_zip_bytes,
};
use psign_sip_digest::pkcs7::AuthenticodeSigningDigest;
use psign_sip_digest::verify_pe::verify_pe_authenticode_digest_consistency;
use psign_sip_digest::{
    cab_digest, msi_digest, msix_digest, pe_embed, pkcs7, ps_script, rdp, timestamp,
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
    NuGet,
    Vsix,
    ClickOnceManifest,
    AppInstaller,
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableTimestampDigestAlgorithm {
    Sha1,
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableRevocationMode {
    #[default]
    Off,
    BestEffort,
    Require,
}

impl From<PortableRevocationMode> for RevocationMode {
    fn from(value: PortableRevocationMode) -> Self {
        match value {
            PortableRevocationMode::Off => Self::Off,
            PortableRevocationMode::BestEffort => Self::BestEffort,
            PortableRevocationMode::Require => Self::Require,
        }
    }
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
    #[serde(default)]
    pub trusted_certificate_paths: Vec<PathBuf>,
    #[serde(default)]
    pub trusted_certificates_der_base64: Vec<String>,
    #[serde(default)]
    pub anchor_directory: Option<PathBuf>,
    #[serde(default)]
    pub authroot_cab: Option<PathBuf>,
    #[serde(default)]
    pub as_of: Option<String>,
    #[serde(default)]
    pub prefer_timestamp_signing_time: bool,
    #[serde(default)]
    pub require_valid_timestamp: bool,
    #[serde(default)]
    pub online_aia: bool,
    #[serde(default)]
    pub online_ocsp: bool,
    #[serde(default)]
    pub revocation_mode: PortableRevocationMode,
}

impl PortableGetSignatureRequest {
    pub fn path_only(path: PathBuf) -> Self {
        Self {
            path,
            trusted_certificate_paths: Vec::new(),
            trusted_certificates_der_base64: Vec::new(),
            anchor_directory: None,
            authroot_cab: None,
            as_of: None,
            prefer_timestamp_signing_time: false,
            require_valid_timestamp: false,
            online_aia: false,
            online_ocsp: false,
            revocation_mode: PortableRevocationMode::Off,
        }
    }
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
    pub pfx_path: Option<PathBuf>,
    #[serde(default)]
    pub pfx_password: Option<String>,
    #[serde(default)]
    pub chain_certificate_paths: Vec<PathBuf>,
    #[serde(default)]
    pub chain_certificates_der_base64: Vec<String>,
    #[serde(default)]
    pub timestamp_server: Option<String>,
    #[serde(default)]
    pub timestamp_hash_algorithm: Option<PortableTimestampDigestAlgorithm>,
    // Azure Key Vault cloud signing
    #[serde(default)]
    pub azure_key_vault_url: Option<String>,
    #[serde(default)]
    pub azure_key_vault_certificate: Option<String>,
    #[serde(default)]
    pub azure_key_vault_access_token: Option<String>,
    #[serde(default)]
    pub azure_key_vault_client_id: Option<String>,
    #[serde(default)]
    pub azure_key_vault_client_secret: Option<String>,
    #[serde(default)]
    pub azure_key_vault_tenant_id: Option<String>,
    #[serde(default)]
    pub azure_key_vault_managed_identity: Option<bool>,
    // Azure Artifact Signing / Trusted Signing
    #[serde(default)]
    pub artifact_signing_endpoint: Option<String>,
    #[serde(default)]
    pub artifact_signing_account_name: Option<String>,
    #[serde(default)]
    pub artifact_signing_profile_name: Option<String>,
    #[serde(default)]
    pub artifact_signing_access_token: Option<String>,
    #[serde(default)]
    pub artifact_signing_managed_identity: Option<bool>,
    #[serde(default)]
    pub artifact_signing_tenant_id: Option<String>,
    #[serde(default)]
    pub artifact_signing_client_id: Option<String>,
    #[serde(default)]
    pub artifact_signing_client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSignatureResponse {
    pub schema_version: u32,
    pub path: PathBuf,
    pub format: PortableFileFormat,
    pub status: PortableSignatureStatus,
    pub status_message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_status: Option<PortableSignatureStatus>,
    pub signature_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_certificate_der_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamper_certificate_der_base64: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub embedded_certificate_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timestamp_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_signing_time: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
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
        PortableFileFormat::NuGet => sign_nuget(&request, &output_path),
        PortableFileFormat::Vsix => sign_vsix(&request, &output_path),
        PortableFileFormat::ClickOnceManifest => sign_clickonce_manifest(&request, &output_path),
        PortableFileFormat::AppInstaller => sign_appinstaller(&request, &output_path),
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

    let signature =
        portable_get_signature(PortableGetSignatureRequest::path_only(output_path.clone()))?;

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

    let mut response = match format {
        PortableFileFormat::Pe => inspect_pe(&request.path, &data),
        PortableFileFormat::Cab => inspect_cab(&request.path),
        PortableFileFormat::Msi => inspect_msi(&request.path),
        PortableFileFormat::Msix => inspect_msix(&request.path),
        PortableFileFormat::NuGet => inspect_nuget(&request.path, &data),
        PortableFileFormat::Vsix => inspect_vsix_opc(&request.path, &data),
        PortableFileFormat::ClickOnceManifest => inspect_clickonce_manifest(&request.path, &data),
        PortableFileFormat::AppInstaller => inspect_appinstaller(&request.path),
        PortableFileFormat::Zip => inspect_zip(&request.path, &data),
        PortableFileFormat::PowerShellScript | PortableFileFormat::WshScript => {
            inspect_script(&request.path, &data)
        }
        PortableFileFormat::Catalog => inspect_pkcs7_file(&request.path, format),
        PortableFileFormat::Unknown => Ok(base_response(
            request.path.clone(),
            format,
            PortableSignatureStatus::NotSupportedFileFormat,
            "Unsupported file format for portable Authenticode inspection.",
        )),
    }?;

    apply_trust_if_requested(&request, format, &data, &mut response)?;

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
        "nupkg" | "snupkg" => PortableFileFormat::NuGet,
        "vsix" => PortableFileFormat::Vsix,
        "manifest" | "application" | "vsto" => PortableFileFormat::ClickOnceManifest,
        "appinstaller" => PortableFileFormat::AppInstaller,
        "zip" => PortableFileFormat::Zip,
        "ps1" | "psm1" | "psd1" | "ps1xml" | "psc1" | "cdxml" | "mof" => {
            PortableFileFormat::PowerShellScript
        }
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
    let pkcs7 = maybe_timestamp_pkcs7(request, pkcs7)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
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
    let pkcs7 = maybe_timestamp_pkcs7(request, pkcs7)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
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
    let pkcs7 = maybe_timestamp_pkcs7(request, pkcs7)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
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
    let pkcs7 = maybe_timestamp_pkcs7(request, pkcs7)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
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
    let pkcs7 = maybe_timestamp_pkcs7(request, pkcs7)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
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

fn sign_nuget(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let nuget_alg = match request.hash_algorithm {
        PortableDigestAlgorithm::Sha256 => psign_opc_sign::nuget::NuGetHashAlgorithm::Sha256,
        PortableDigestAlgorithm::Sha384 => psign_opc_sign::nuget::NuGetHashAlgorithm::Sha384,
        PortableDigestAlgorithm::Sha512 => psign_opc_sign::nuget::NuGetHashAlgorithm::Sha512,
    };
    let unsigned = psign_opc_sign::nuget::canonical_unsigned_package_bytes(Cursor::new(data))
        .with_context(|| {
            format!(
                "canonicalize NuGet package for signing {}",
                request.path.display()
            )
        })?;
    let content =
        psign_opc_sign::nuget::signature_content_bytes(nuget_alg, &nuget_alg.hash(&unsigned));
    // Create a CMS SignedData with id-data content type, then detach eContent
    let econtent_der = der_encode_octet_string(&content)?;
    let id_data = der::asn1::ObjectIdentifier::new_unwrap(pkcs7::PKCS7_ID_DATA_OID);
    let pkcs7_bytes = pkcs7::create_pkcs7_signed_data_der_rsa(
        id_data,
        &econtent_der,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| format!("create NuGet CMS signature for {}", request.path.display()))?;
    // Detach eContent (NuGet signatures are detached CMS)
    let mut sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7_bytes)
        .context("parse generated CMS before detaching eContent")?;
    sd.encap_content_info.econtent = None;
    let pkcs7_detached = pkcs7::encode_pkcs7_content_info_signed_data_der(&sd)?;
    let pkcs7_final = maybe_timestamp_pkcs7(request, pkcs7_detached)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
    let mut out = Cursor::new(Vec::new());
    psign_opc_sign::nuget::embed_signature(Cursor::new(unsigned), &mut out, &pkcs7_final, false)
        .with_context(|| format!("embed NuGet signature into {}", request.path.display()))?;
    std::fs::write(output_path, out.into_inner())
        .with_context(|| format!("write {}", output_path.display()))
}

fn sign_vsix(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    let vsix_alg = match request.hash_algorithm {
        PortableDigestAlgorithm::Sha256 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha256,
        PortableDigestAlgorithm::Sha384 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha384,
        PortableDigestAlgorithm::Sha512 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha512,
    };
    let signed_info = psign_opc_sign::vsix::signed_info_xml(Cursor::new(data.clone()), vsix_alg)
        .with_context(|| format!("create VSIX SignedInfo XML for {}", request.path.display()))?;
    let cert_der = signer_cert.to_der().context("encode signer cert DER")?;
    let signature = sign_xml_signed_info_rsa(vsix_alg, &signed_info, &private_key)?;
    let _chain = chain; // chain included in KeyInfo is just the signer cert for VSIX
    let xml = psign_opc_sign::vsix::signature_xml_from_signed_info(
        &signed_info,
        &signature,
        Some(&cert_der),
    )
    .into_bytes();
    let mut out = Cursor::new(Vec::new());
    psign_opc_sign::vsix::embed_signature_xml(Cursor::new(data), &mut out, &xml, false)
        .with_context(|| format!("embed VSIX signature XML into {}", request.path.display()))?;
    std::fs::write(output_path, out.into_inner())
        .with_context(|| format!("write {}", output_path.display()))
}

fn sign_clickonce_manifest(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let text = std::str::from_utf8(&data).with_context(|| {
        format!(
            "read ClickOnce manifest {} as UTF-8",
            request.path.display()
        )
    })?;
    let (signer_cert, private_key, _chain) = load_signing_material(request)?;
    let vsix_alg = match request.hash_algorithm {
        PortableDigestAlgorithm::Sha256 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha256,
        PortableDigestAlgorithm::Sha384 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha384,
        PortableDigestAlgorithm::Sha512 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha512,
    };
    let unsigned = remove_clickonce_xml_signature(text);
    let signed_info = clickonce_manifest_signed_info_xml_bytes(&unsigned, vsix_alg);
    let cert_der = signer_cert.to_der().context("encode signer cert DER")?;
    let signature = sign_xml_signed_info_rsa(vsix_alg, &signed_info, &private_key)?;
    let signature_xml = build_clickonce_signature_xml(&signed_info, &signature, &cert_der);
    let signed = insert_clickonce_signature_in_manifest(&unsigned, &signature_xml)?;
    std::fs::write(output_path, signed.as_bytes())
        .with_context(|| format!("write {}", output_path.display()))
}

fn sign_appinstaller(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    // Create a detached CMS over the descriptor content
    let econtent_der = der_encode_octet_string(&data)?;
    let id_data = der::asn1::ObjectIdentifier::new_unwrap(pkcs7::PKCS7_ID_DATA_OID);
    let pkcs7_bytes = pkcs7::create_pkcs7_signed_data_der_rsa(
        id_data,
        &econtent_der,
        request.hash_algorithm.into(),
        signer_cert,
        chain,
        private_key,
    )
    .with_context(|| {
        format!(
            "create detached PKCS#7 companion signature for {}",
            request.path.display()
        )
    })?;
    // Detach eContent
    let mut sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7_bytes)
        .context("parse generated CMS before detaching eContent")?;
    sd.encap_content_info.econtent = None;
    let pkcs7_detached = pkcs7::encode_pkcs7_content_info_signed_data_der(&sd)?;
    let pkcs7_final = maybe_timestamp_pkcs7(request, pkcs7_detached)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
    // Write the .p7 companion alongside the output descriptor
    let companion_path = output_path.with_extension(
        output_path
            .extension()
            .map(|e| format!("{}.p7", e.to_string_lossy()))
            .unwrap_or_else(|| "p7".to_string()),
    );
    // Copy the original descriptor to output if needed
    if output_path != request.path {
        std::fs::copy(&request.path, output_path).with_context(|| {
            format!(
                "copy {} to {}",
                request.path.display(),
                output_path.display()
            )
        })?;
    }
    std::fs::write(&companion_path, pkcs7_final)
        .with_context(|| format!("write companion {}", companion_path.display()))
}

fn sign_xml_signed_info_rsa(
    algorithm: psign_opc_sign::vsix::VsixHashAlgorithm,
    signed_info: &[u8],
    private_key: &rsa::RsaPrivateKey,
) -> Result<Vec<u8>> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::SignatureEncoding;
    use rsa::signature::Signer;

    let signature = match algorithm {
        psign_opc_sign::vsix::VsixHashAlgorithm::Sha256 => {
            let signing_key = SigningKey::<sha2::Sha256>::new(private_key.clone());
            signing_key.sign(signed_info).to_vec()
        }
        psign_opc_sign::vsix::VsixHashAlgorithm::Sha384 => {
            let signing_key = SigningKey::<sha2::Sha384>::new(private_key.clone());
            signing_key.sign(signed_info).to_vec()
        }
        psign_opc_sign::vsix::VsixHashAlgorithm::Sha512 => {
            let signing_key = SigningKey::<sha2::Sha512>::new(private_key.clone());
            signing_key.sign(signed_info).to_vec()
        }
    };
    Ok(signature)
}

/// Remove an existing XML `<Signature>` element from a ClickOnce manifest.
fn remove_clickonce_xml_signature(text: &str) -> String {
    // Find `<Signature xmlns=` and remove the entire element
    if let Some(start) = text.find("<Signature")
        && let Some(end) = text[start..].find("</Signature>")
    {
        let end = start + end + "</Signature>".len();
        let mut out = String::with_capacity(text.len() - (end - start));
        out.push_str(&text[..start]);
        out.push_str(&text[end..]);
        return out;
    }
    text.to_owned()
}

/// Build the SignedInfo XML for a ClickOnce manifest (enveloped signature).
fn clickonce_manifest_signed_info_xml_bytes(
    unsigned_manifest_text: &str,
    algorithm: psign_opc_sign::vsix::VsixHashAlgorithm,
) -> Vec<u8> {
    let manifest_digest = algorithm.hash(unsigned_manifest_text.as_bytes());
    let digest_b64 = base64::engine::general_purpose::STANDARD.encode(manifest_digest);
    format!(
        r#"<SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="{}"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="{}"/><DigestValue>{digest_b64}</DigestValue></Reference></SignedInfo>"#,
        algorithm.signature_uri(),
        algorithm.digest_uri(),
    )
    .into_bytes()
}

fn build_clickonce_signature_xml(signed_info: &[u8], signature: &[u8], cert_der: &[u8]) -> String {
    let signed_info_str = String::from_utf8_lossy(signed_info);
    format!(
        r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{signed_info_str}<SignatureValue>{}</SignatureValue><KeyInfo><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo></Signature>"#,
        base64::engine::general_purpose::STANDARD.encode(signature),
        base64::engine::general_purpose::STANDARD.encode(cert_der)
    )
}

fn insert_clickonce_signature_in_manifest(text: &str, signature_xml: &str) -> Result<String> {
    // Find the last closing tag of the root element and insert before it
    let close_pos = text.rfind("</").ok_or_else(|| {
        anyhow::anyhow!("ClickOnce manifest does not have a closing root element tag")
    })?;
    let mut out = String::with_capacity(text.len() + signature_xml.len());
    out.push_str(&text[..close_pos]);
    out.push_str(signature_xml);
    out.push_str(&text[close_pos..]);
    Ok(out)
}

fn sign_script(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let ext = request
        .path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("ps1")
        .to_ascii_lowercase();
    if !matches!(
        ext.as_str(),
        "ps1" | "psd1" | "psm1" | "ps1xml" | "psc1" | "cdxml" | "mof"
    ) {
        bail!(
            "portable script signing supports ps1, psd1, psm1, ps1xml, psc1, cdxml, and mof scripts"
        );
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
    let pkcs7 = maybe_timestamp_pkcs7(request, pkcs7)
        .with_context(|| format!("timestamp {}", request.path.display()))?;
    let block = format_powershell_signature_block(&pkcs7, &ext);
    let mut signed = script;
    signed.extend_from_slice(block.as_bytes());
    std::fs::write(output_path, signed).with_context(|| format!("write {}", output_path.display()))
}

fn has_azure_key_vault_provider(request: &PortableSignRequest) -> bool {
    request.azure_key_vault_url.is_some()
}

fn has_artifact_signing_provider(request: &PortableSignRequest) -> bool {
    request.artifact_signing_endpoint.is_some() || request.artifact_signing_account_name.is_some()
}

fn has_local_signing_material(request: &PortableSignRequest) -> bool {
    request.certificate_path.is_some()
        || request.certificate_der_base64.is_some()
        || request.pfx_path.is_some()
        || request.private_key_path.is_some()
        || request.private_key_der_base64.is_some()
}

fn load_signing_material(
    request: &PortableSignRequest,
) -> Result<(
    x509_cert::Certificate,
    rsa::RsaPrivateKey,
    Vec<x509_cert::Certificate>,
)> {
    // Reject mixed local + cloud providers
    let has_akv = has_azure_key_vault_provider(request);
    let has_as = has_artifact_signing_provider(request);
    let has_local = has_local_signing_material(request);

    if has_akv && has_as {
        bail!(
            "provide only one cloud signing provider (Azure Key Vault or Artifact Signing), not both"
        );
    }
    if has_akv && has_local {
        bail!(
            "provide either Azure Key Vault cloud signing or local certificate/key material, not both"
        );
    }
    if has_as && has_local {
        bail!(
            "provide either Artifact Signing cloud signing or local certificate/key material, not both"
        );
    }
    if has_akv {
        #[cfg(feature = "azure-kv-sign")]
        {
            bail!(
                "Azure Key Vault portable signing is not yet available through this API — use psign-tool code azure-key-vault"
            );
        }
        #[cfg(not(feature = "azure-kv-sign"))]
        {
            bail!(
                "Azure Key Vault signing support is not compiled into this build (feature: azure-kv-sign)"
            );
        }
    }
    if has_as {
        #[cfg(feature = "artifact-signing-rest")]
        {
            bail!(
                "Artifact Signing portable signing is not yet available through this API — use psign-tool code artifact-signing"
            );
        }
        #[cfg(not(feature = "artifact-signing-rest"))]
        {
            bail!(
                "Artifact Signing support is not compiled into this build (feature: artifact-signing-rest)"
            );
        }
    }

    let uses_pfx = request.pfx_path.is_some();
    if uses_pfx
        && (request.certificate_der_base64.is_some()
            || request.certificate_path.is_some()
            || request.private_key_der_base64.is_some()
            || request.private_key_path.is_some())
    {
        bail!("provide either pfx_path or certificate/private key material, not both");
    }

    let (cert_bytes, key_bytes) = if let Some(pfx_path) = &request.pfx_path {
        let pfx_bytes =
            std::fs::read(pfx_path).with_context(|| format!("read {}", pfx_path.display()))?;
        let password = request.pfx_password.as_deref().unwrap_or_default();
        load_pfx_cert_and_key(&pfx_bytes, password)
            .with_context(|| format!("parse PFX {}", pfx_path.display()))?
    } else {
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
        (cert_bytes, key_bytes)
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

fn load_pfx_cert_and_key(bytes: &[u8], password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let crypto_context = Pkcs12CryptoContext::new_with_password(password)?;
    let parsing_params = Pkcs12ParsingParams::default();
    let pfx = Pfx::from_der(bytes, &crypto_context, &parsing_params)?;
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut keys: Vec<(Vec<u8>, PrivateKey)> = Vec::new();
    for safe_contents in pfx.safe_contents() {
        collect_pfx_bags(safe_contents.kind(), &mut certs, &mut keys)?;
    }
    if certs.is_empty() {
        bail!("PFX did not contain an X.509 certificate");
    }
    if keys.is_empty() {
        bail!("PFX did not contain a private key");
    }
    for cert in certs {
        for (key_pem, key) in &keys {
            if ensure_key_matches_cert(&cert, key).is_ok() {
                return Ok((cert, key_pem.clone()));
            }
        }
    }
    bail!("PFX did not contain a certificate matching an included private key")
}

fn collect_pfx_bags(
    kind: &SafeContentsKind,
    certs: &mut Vec<Vec<u8>>,
    keys: &mut Vec<(Vec<u8>, PrivateKey)>,
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
    keys: &mut Vec<(Vec<u8>, PrivateKey)>,
) -> Result<()> {
    match bag.kind() {
        SafeBagKind::PrivateKey(key) | SafeBagKind::EncryptedPrivateKey { key, .. } => {
            let mut pem = key
                .to_pem_str()
                .context("encode PFX private key as PKCS#8 PEM")?;
            pem.push('\n');
            keys.push((pem.into_bytes(), key.clone()));
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

fn ensure_key_matches_cert(cert_der: &[u8], key: &PrivateKey) -> Result<()> {
    let cert = PickyCert::from_der(cert_der).context("parse certificate for key matching")?;
    let key_public = key
        .to_public_key()
        .context("derive public key from private key")?;
    if cert.public_key() != &key_public {
        bail!("private key does not match certificate public key");
    }
    Ok(())
}

fn maybe_timestamp_pkcs7(request: &PortableSignRequest, pkcs7_der: Vec<u8>) -> Result<Vec<u8>> {
    let Some(timestamp_server) = request.timestamp_server.as_deref() else {
        if request.timestamp_hash_algorithm.is_some() {
            bail!("timestamp_hash_algorithm requires timestamp_server");
        }
        return Ok(pkcs7_der);
    };
    let alg = request.timestamp_hash_algorithm.unwrap_or_default();
    timestamp_pkcs7_der_rfc3161(&pkcs7_der, timestamp_server, alg)
}

fn timestamp_pkcs7_der_rfc3161(
    pkcs7_der: &[u8],
    timestamp_server: &str,
    timestamp_digest: PortableTimestampDigestAlgorithm,
) -> Result<Vec<u8>> {
    let sd = pkcs7::parse_pkcs7_signed_data_der(pkcs7_der).context("parse PKCS#7 SignedData")?;
    let signer = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or_else(|| anyhow::anyhow!("PKCS#7 SignedData has no SignerInfo to timestamp"))?;
    let imprint = digest_bytes_for_timestamp_alg(timestamp_digest, signer.signature.as_bytes());
    let request = timestamp::build_timestamp_request_bytes(
        &timestamp::Rfc3161TimestampRequestPlan {
            digest_alg_oid: timestamp_digest_oid(timestamp_digest),
            nonce: None,
            cert_req: true,
        },
        &imprint,
    )
    .ok_or_else(|| anyhow::anyhow!("build RFC3161 TimeStampReq"))?;
    let response = reqwest::blocking::Client::new()
        .post(timestamp_server)
        .header("Content-Type", "application/timestamp-query")
        .header("Accept", "application/timestamp-reply")
        .body(request)
        .send()
        .with_context(|| format!("POST TimeStampReq to {timestamp_server}"))?
        .error_for_status()
        .with_context(|| format!("TSA returned an HTTP error from {timestamp_server}"))?
        .bytes()
        .context("read TSA TimeStampResp body")?;
    let parsed = timestamp::parse_time_stamp_resp_der(&response)
        .ok_or_else(|| anyhow::anyhow!("could not parse TimeStampResp DER from TSA response"))?;
    if !parsed.pki_status.granted() {
        bail!(
            "TimeStampResp status is not granted (status={})",
            parsed.pki_status.as_raw_integer()
        );
    }
    let token = parsed
        .time_stamp_token
        .ok_or_else(|| anyhow::anyhow!("TimeStampResp has no timeStampToken"))?;
    let stamped = pkcs7::signed_data_add_rfc3161_timestamp_token(&sd, 0, token)
        .context("attach RFC3161 timestamp token")?;
    pkcs7::encode_pkcs7_content_info_signed_data_der(&stamped)
}

fn timestamp_digest_oid(alg: PortableTimestampDigestAlgorithm) -> &'static str {
    match alg {
        PortableTimestampDigestAlgorithm::Sha1 => "1.3.14.3.2.26",
        PortableTimestampDigestAlgorithm::Sha256 => "2.16.840.1.101.3.4.2.1",
        PortableTimestampDigestAlgorithm::Sha384 => "2.16.840.1.101.3.4.2.2",
        PortableTimestampDigestAlgorithm::Sha512 => "2.16.840.1.101.3.4.2.3",
    }
}

fn digest_bytes_for_timestamp_alg(alg: PortableTimestampDigestAlgorithm, input: &[u8]) -> Vec<u8> {
    match alg {
        PortableTimestampDigestAlgorithm::Sha1 => sha1::Sha1::digest(input).to_vec(),
        PortableTimestampDigestAlgorithm::Sha256 => sha2::Sha256::digest(input).to_vec(),
        PortableTimestampDigestAlgorithm::Sha384 => sha2::Sha384::digest(input).to_vec(),
        PortableTimestampDigestAlgorithm::Sha512 => sha2::Sha512::digest(input).to_vec(),
    }
}

fn apply_trust_if_requested(
    request: &PortableGetSignatureRequest,
    format: PortableFileFormat,
    data: &[u8],
    response: &mut PortableSignatureResponse,
) -> Result<()> {
    if !trust_requested(request) || response.status != PortableSignatureStatus::Valid {
        return Ok(());
    }

    let (opts, temp_dir) = trust_options(request)?;
    let trust_result = match format {
        PortableFileFormat::Pe => trust_verify_pe_bytes(data, &opts).map(|r| {
            format!(
                "explicit_trust=valid pkcs7_entries_verified={} anchors={}",
                r.pkcs7_entries_verified, r.anchor_thumbprints
            )
        }),
        PortableFileFormat::Cab => trust_verify_cab_bytes(data, &opts).map(|r| {
            format!(
                "explicit_trust=valid pkcs7_entries_verified={} anchors={}",
                r.pkcs7_entries_verified, r.anchor_thumbprints
            )
        }),
        PortableFileFormat::Msi => trust_verify_msi_bytes(data, &opts).map(|r| {
            format!(
                "explicit_trust=valid pkcs7_entries_verified={} anchors={}",
                r.pkcs7_entries_verified, r.anchor_thumbprints
            )
        }),
        PortableFileFormat::Zip => trust_verify_zip_bytes(data, &opts).map(|r| {
            format!(
                "explicit_trust=valid pkcs7_entries_verified={} anchors={}",
                r.pkcs7_entries_verified, r.anchor_thumbprints
            )
        }),
        PortableFileFormat::PowerShellScript => {
            let extension = request
                .path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("ps1");
            trust_verify_script_bytes(data, extension, &opts).map(|r| {
                format!(
                    "explicit_trust=valid pkcs7_entries_verified={} anchors={}",
                    r.pkcs7_entries_verified, r.anchor_thumbprints
                )
            })
        }
        PortableFileFormat::NuGet
        | PortableFileFormat::AppInstaller
        | PortableFileFormat::Vsix
        | PortableFileFormat::ClickOnceManifest => Err(anyhow::anyhow!(
            "explicit trust verification is not yet available for format {:?} through the portable inspection path",
            format
        )),
        _ => Err(anyhow::anyhow!(
            "explicit trust verification is not implemented for format {:?}",
            format
        )),
    };
    if let Some(dir) = temp_dir {
        let _ = std::fs::remove_dir_all(dir);
    }

    match trust_result {
        Ok(diagnostic) => {
            response.status_message =
                "Portable digest binding and explicit trust verification are valid.".to_string();
            response.trust_status = Some(PortableSignatureStatus::Valid);
            response.diagnostics.push(diagnostic);
        }
        Err(error) => {
            response.status = PortableSignatureStatus::NotTrusted;
            response.trust_status = Some(PortableSignatureStatus::NotTrusted);
            response.status_message = error.to_string();
            response
                .diagnostics
                .push("explicit_trust=failed".to_string());
        }
    }

    Ok(())
}

fn trust_requested(request: &PortableGetSignatureRequest) -> bool {
    !request.trusted_certificate_paths.is_empty()
        || !request.trusted_certificates_der_base64.is_empty()
        || request.anchor_directory.is_some()
        || request.authroot_cab.is_some()
}

fn trust_options(
    request: &PortableGetSignatureRequest,
) -> Result<(TrustVerifyPeOptions, Option<PathBuf>)> {
    let mut trusted_ca_files = request.trusted_certificate_paths.clone();
    let mut temp_dir = None;
    if !request.trusted_certificates_der_base64.is_empty() {
        let dir = std::env::temp_dir().join(format!(
            "psign-portable-trust-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create temporary trust directory {}", dir.display()))?;
        for (index, cert) in request.trusted_certificates_der_base64.iter().enumerate() {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(cert)
                .with_context(|| format!("decode trusted_certificates_der_base64[{index}]"))?;
            let path = dir.join(format!("trusted-{index}.cer"));
            std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
            trusted_ca_files.push(path);
        }
        temp_dir = Some(dir);
    }

    // When using authroot_cab, automatically enable AIA fetching so the chain builder
    // can download missing root certificates from the intermediate cert's AIA extension.
    // The AuthRoot CAB only contains SHA-1 thumbprints of trusted roots, not their DER
    // bytes. AIA fetching allows the chain builder to obtain the root cert on demand and
    // then verify its thumbprint against the anchor store.
    let effective_aia = request.online_aia || request.authroot_cab.is_some();

    Ok((
        TrustVerifyPeOptions {
            anchor_dir: request.anchor_directory.clone(),
            trusted_ca_files,
            authroot_cab: request.authroot_cab.clone(),
            expect_authroot_cab_sha256: None,
            verification_instant_override: request
                .as_of
                .as_deref()
                .map(parse_utc_date)
                .transpose()?,
            verbose_chain: false,
            online: OnlineTrustOptions {
                enable_aia: effective_aia,
                enable_ocsp: request.online_ocsp,
                revocation_mode: request.revocation_mode.into(),
                ..OnlineTrustOptions::default()
            },
            policy: AuthenticodeTrustPolicy {
                strict_code_signing_eku: false,
                prefer_timestamp_signing_time: request.prefer_timestamp_signing_time
                    || request.require_valid_timestamp,
                require_valid_timestamp: request.require_valid_timestamp,
            },
        },
        temp_dir,
    ))
}

fn parse_utc_date(input: &str) -> Result<UtcDate> {
    let date = input
        .split_once('T')
        .map(|(date, _)| date)
        .unwrap_or(input)
        .trim();
    let mut parts = date.split('-');
    let year = parts
        .next()
        .context("missing year in as_of date")?
        .parse::<u16>()
        .with_context(|| format!("invalid year in as_of date '{input}'"))?;
    let month = parts
        .next()
        .context("missing month in as_of date")?
        .parse::<u8>()
        .with_context(|| format!("invalid month in as_of date '{input}'"))?;
    let day = parts
        .next()
        .context("missing day in as_of date")?
        .parse::<u8>()
        .with_context(|| format!("invalid day in as_of date '{input}'"))?;
    if parts.next().is_some() {
        bail!("invalid as_of date '{input}': expected yyyy-MM-dd");
    }

    UtcDate::ymd(year, month, day).ok_or_else(|| {
        anyhow::anyhow!("invalid as_of date '{input}': expected a valid yyyy-MM-dd date")
    })
}

fn inspect_pe(path: &Path, data: &[u8]) -> Result<PortableSignatureResponse> {
    let inspect = inspect_pe_authenticode(data);
    match verify_pe_authenticode_digest_consistency(data) {
        Ok(result) => {
            let summary = inspect
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
                trust_status: None,
                signature_count: result.pkcs7_authenticode_entries,
                signer_index: summary.signer_index,
                signer_certificate_der_base64: summary.signer_certificate_der_base64,
                timestamper_certificate_der_base64: summary.timestamper_certificate_der_base64,
                embedded_certificate_count: summary.embedded_certificate_count,
                digest_algorithm: summary.digest_algorithm,
                timestamp_kinds: summary.timestamp_kinds,
                timestamp_signing_time: summary.timestamp_signing_time,
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
        Ok(()) => {
            let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            let summary = cab_digest::cab_signature_pkcs7_der(&data)
                .ok()
                .and_then(|pkcs7| inspect_authenticode_pkcs7_der(pkcs7).ok())
                .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
                .unwrap_or_default();
            Ok(valid_response(
                path.to_path_buf(),
                PortableFileFormat::Cab,
                "Portable digest binding is valid; trust was not evaluated.",
                summary,
            ))
        }
        Err(error) => Ok(map_digest_error(path, PortableFileFormat::Cab, error)),
    }
}

fn inspect_msi(path: &Path) -> Result<PortableSignatureResponse> {
    match msi_digest::verify_msi_digest_consistency(path) {
        Ok(()) => {
            let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            let summary = msi_digest::msi_digital_signature_pkcs7_der(&data)
                .ok()
                .and_then(|pkcs7| inspect_authenticode_pkcs7_der(&pkcs7).ok())
                .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
                .unwrap_or_default();
            Ok(valid_response(
                path.to_path_buf(),
                PortableFileFormat::Msi,
                "Portable digest binding is valid; trust was not evaluated.",
                summary,
            ))
        }
        Err(error) => Ok(map_digest_error(path, PortableFileFormat::Msi, error)),
    }
}

fn inspect_msix(path: &Path) -> Result<PortableSignatureResponse> {
    match msix_digest::verify_msix_digest_consistency(path) {
        Ok(()) => {
            let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            let summary = msix_signature_pkcs7_der(&data)
                .ok()
                .and_then(|pkcs7| inspect_authenticode_pkcs7_der(&pkcs7).ok())
                .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
                .unwrap_or_default();
            Ok(valid_response(
                path.to_path_buf(),
                PortableFileFormat::Msix,
                "Portable MSIX digest binding is valid; trust was not evaluated.",
                summary,
            ))
        }
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
    let summary = report
        .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
        .unwrap_or_default();
    Ok(PortableSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path: path.to_path_buf(),
        format: PortableFileFormat::Zip,
        status: PortableSignatureStatus::Valid,
        status_message: "Portable ZIP digest binding is valid; trust was not evaluated."
            .to_string(),
        trust_status: None,
        signature_count: 1,
        signer_index: summary.signer_index,
        signer_certificate_der_base64: summary.signer_certificate_der_base64,
        timestamper_certificate_der_base64: summary.timestamper_certificate_der_base64,
        embedded_certificate_count: summary.embedded_certificate_count,
        digest_algorithm: summary.digest_algorithm,
        timestamp_kinds: summary.timestamp_kinds,
        timestamp_signing_time: summary.timestamp_signing_time,
        diagnostics: Vec::new(),
    })
}

fn inspect_nuget(path: &Path, data: &[u8]) -> Result<PortableSignatureResponse> {
    let has_sig = psign_opc_sign::nuget::inspect_nupkg_path(path)
        .map(|info| info.signed)
        .unwrap_or(false);
    if !has_sig {
        return Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::NuGet,
            PortableSignatureStatus::NotSigned,
            "NuGet package does not contain .signature.p7s",
        ));
    }
    // Extract signature and parse CMS
    let sig_bytes = extract_nuget_signature_p7s(data)?;
    let report = inspect_authenticode_pkcs7_der(&sig_bytes).ok();
    let summary = report
        .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
        .unwrap_or_default();
    Ok(PortableSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path: path.to_path_buf(),
        format: PortableFileFormat::NuGet,
        status: PortableSignatureStatus::Valid,
        status_message:
            "NuGet package signature (.signature.p7s) is present; trust was not evaluated."
                .to_string(),
        trust_status: None,
        signature_count: 1,
        signer_index: summary.signer_index,
        signer_certificate_der_base64: summary.signer_certificate_der_base64,
        timestamper_certificate_der_base64: summary.timestamper_certificate_der_base64,
        embedded_certificate_count: summary.embedded_certificate_count,
        digest_algorithm: summary.digest_algorithm,
        timestamp_kinds: summary.timestamp_kinds,
        timestamp_signing_time: summary.timestamp_signing_time,
        diagnostics: Vec::new(),
    })
}

fn inspect_vsix_opc(path: &Path, data: &[u8]) -> Result<PortableSignatureResponse> {
    let has_sig = psign_opc_sign::vsix::inspect_vsix_path(path)
        .map(|info| info.has_opc_signature)
        .unwrap_or(false);
    if !has_sig {
        return Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::Vsix,
            PortableSignatureStatus::NotSigned,
            "VSIX package does not contain an OPC digital signature",
        ));
    }
    // Extract the signature XML and report
    let sig_xml = psign_opc_sign::vsix::extract_signature_xml_path(path).unwrap_or_default();
    if sig_xml.is_empty() {
        return Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::Vsix,
            PortableSignatureStatus::NotSigned,
            "VSIX package OPC signature part could not be extracted",
        ));
    }
    // Verify reference digests
    let vsix_alg = psign_opc_sign::vsix::VsixHashAlgorithm::Sha256;
    let refs_ok =
        psign_opc_sign::vsix::verify_signature_reference_xml(Cursor::new(data), &sig_xml, vsix_alg)
            .is_ok();
    let status = if refs_ok {
        PortableSignatureStatus::Valid
    } else {
        PortableSignatureStatus::HashMismatch
    };
    let message = if refs_ok {
        "VSIX OPC XMLDSig signature references are valid; trust was not evaluated."
    } else {
        "VSIX OPC XMLDSig signature reference digests do not match package content."
    };
    Ok(base_response(
        path.to_path_buf(),
        PortableFileFormat::Vsix,
        status,
        message,
    ))
}

fn inspect_clickonce_manifest(path: &Path, data: &[u8]) -> Result<PortableSignatureResponse> {
    let text = std::str::from_utf8(data).unwrap_or("");
    let has_sig = text.contains("<Signature") && text.contains("</Signature>");
    if !has_sig {
        return Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::ClickOnceManifest,
            PortableSignatureStatus::NotSigned,
            "ClickOnce manifest does not contain an XMLDSig Signature element",
        ));
    }
    Ok(base_response(
        path.to_path_buf(),
        PortableFileFormat::ClickOnceManifest,
        PortableSignatureStatus::Valid,
        "ClickOnce manifest contains an XMLDSig Signature; trust was not evaluated.",
    ))
}

fn inspect_appinstaller(path: &Path) -> Result<PortableSignatureResponse> {
    // Check for companion .p7 file
    let companion_path = path.with_extension(
        path.extension()
            .map(|e| format!("{}.p7", e.to_string_lossy()))
            .unwrap_or_else(|| "p7".to_string()),
    );
    if !companion_path.exists() {
        return Ok(base_response(
            path.to_path_buf(),
            PortableFileFormat::AppInstaller,
            PortableSignatureStatus::NotSigned,
            "App Installer descriptor does not have a companion .p7 signature file",
        ));
    }
    let pkcs7_bytes = std::fs::read(&companion_path)
        .with_context(|| format!("read companion {}", companion_path.display()))?;
    let report = inspect_authenticode_pkcs7_der(&pkcs7_bytes).ok();
    let summary = report
        .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
        .unwrap_or_default();
    Ok(PortableSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path: path.to_path_buf(),
        format: PortableFileFormat::AppInstaller,
        status: PortableSignatureStatus::Valid,
        status_message:
            "App Installer companion .p7 signature is present; trust was not evaluated.".to_string(),
        trust_status: None,
        signature_count: 1,
        signer_index: summary.signer_index,
        signer_certificate_der_base64: summary.signer_certificate_der_base64,
        timestamper_certificate_der_base64: summary.timestamper_certificate_der_base64,
        embedded_certificate_count: summary.embedded_certificate_count,
        digest_algorithm: summary.digest_algorithm,
        timestamp_kinds: summary.timestamp_kinds,
        timestamp_signing_time: summary.timestamp_signing_time,
        diagnostics: Vec::new(),
    })
}

fn extract_nuget_signature_p7s(data: &[u8]) -> Result<Vec<u8>> {
    let mut archive = ZipArchive::new(Cursor::new(data)).context("open NuGet ZIP")?;
    let mut entry = archive
        .by_name(psign_opc_sign::nuget::PACKAGE_SIGNATURE_FILE_NAME)
        .context("read .signature.p7s")?;
    let mut p7s = Vec::new();
    entry.read_to_end(&mut p7s)?;
    Ok(p7s)
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
            let summary = report
                .map(|r| summarize_pkcs7_reports(std::iter::once(r)))
                .unwrap_or_default();
            Ok(PortableSignatureResponse {
                schema_version: SCHEMA_VERSION,
                path: path.to_path_buf(),
                format: infer_format(path),
                status: PortableSignatureStatus::Valid,
                status_message: "Portable script digest binding is valid; trust was not evaluated."
                    .to_string(),
                trust_status: None,
                signature_count: 1,
                signer_index: summary.signer_index,
                signer_certificate_der_base64: summary.signer_certificate_der_base64,
                timestamper_certificate_der_base64: summary.timestamper_certificate_der_base64,
                embedded_certificate_count: summary.embedded_certificate_count,
                digest_algorithm: summary.digest_algorithm,
                timestamp_kinds: summary.timestamp_kinds,
                timestamp_signing_time: summary.timestamp_signing_time,
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
            let summary = summarize_pkcs7_reports(std::iter::once(report));
            Ok(PortableSignatureResponse {
                schema_version: SCHEMA_VERSION,
                path: path.to_path_buf(),
                format,
                status: PortableSignatureStatus::Valid,
                status_message:
                    "PKCS#7 structure is valid; detached content and trust were not evaluated."
                        .to_string(),
                trust_status: None,
                signature_count: 1,
                signer_index: summary.signer_index,
                signer_certificate_der_base64: summary.signer_certificate_der_base64,
                timestamper_certificate_der_base64: summary.timestamper_certificate_der_base64,
                embedded_certificate_count: summary.embedded_certificate_count,
                digest_algorithm: summary.digest_algorithm,
                timestamp_kinds: summary.timestamp_kinds,
                timestamp_signing_time: summary.timestamp_signing_time,
                diagnostics: Vec::new(),
            })
        }
        Err(error) => Ok(map_digest_error(path, format, error)),
    }
}

#[derive(Default)]
struct Pkcs7Summary {
    digest_algorithm: Option<String>,
    timestamp_kinds: Vec<String>,
    timestamp_signing_time: Option<String>,
    signer_index: Option<usize>,
    signer_certificate_der_base64: Option<String>,
    timestamper_certificate_der_base64: Option<String>,
    embedded_certificate_count: usize,
}

fn summarize_pkcs7_reports(
    reports: impl IntoIterator<Item = psign_authenticode_trust::inspect::InspectPkcs7Report>,
) -> Pkcs7Summary {
    let mut summary = Pkcs7Summary::default();
    for report in reports {
        collect_pkcs7_summary(&report, &mut summary);
    }
    summary
}

fn collect_pkcs7_summary(
    report: &psign_authenticode_trust::inspect::InspectPkcs7Report,
    summary: &mut Pkcs7Summary,
) {
    summary.embedded_certificate_count += report.certificate_count;
    if summary.timestamp_signing_time.is_none() {
        summary.timestamp_signing_time = report.timestamp_signing_time.clone();
    }
    if summary.digest_algorithm.is_none()
        && let Some(digest) = &report.authenticode_digest
    {
        summary.digest_algorithm = Some(digest.digest_algorithm_oid.clone());
    }
    for signer in &report.signers {
        if summary.signer_index.is_none() {
            summary.signer_index = Some(signer.signer_index);
        }
        if summary.signer_certificate_der_base64.is_none() {
            summary.signer_certificate_der_base64 = signer.signer_certificate_der_base64.clone();
        }
        if summary.timestamper_certificate_der_base64.is_none() {
            summary.timestamper_certificate_der_base64 =
                signer.timestamp_signer_certificate_der_base64.clone();
        }
        for hint in &signer.timestamp_hints {
            let kind = hint.kind.to_string();
            if !summary.timestamp_kinds.contains(&kind) {
                summary.timestamp_kinds.push(kind);
            }
        }
    }
    for nested in &report.nested_signatures {
        collect_pkcs7_summary(nested, summary);
    }
}

fn valid_response(
    path: PathBuf,
    format: PortableFileFormat,
    message: impl Into<String>,
    summary: Pkcs7Summary,
) -> PortableSignatureResponse {
    PortableSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path,
        format,
        status: PortableSignatureStatus::Valid,
        status_message: message.into(),
        trust_status: None,
        signature_count: 1,
        signer_index: summary.signer_index,
        signer_certificate_der_base64: summary.signer_certificate_der_base64,
        timestamper_certificate_der_base64: summary.timestamper_certificate_der_base64,
        embedded_certificate_count: summary.embedded_certificate_count,
        digest_algorithm: summary.digest_algorithm,
        timestamp_kinds: summary.timestamp_kinds,
        timestamp_signing_time: summary.timestamp_signing_time,
        diagnostics: Vec::new(),
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
        trust_status: None,
        signature_count: usize::from(status == PortableSignatureStatus::Valid),
        signer_index: None,
        signer_certificate_der_base64: None,
        timestamper_certificate_der_base64: None,
        embedded_certificate_count: 0,
        digest_algorithm: None,
        timestamp_kinds: Vec::new(),
        timestamp_signing_time: None,
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
        trust_status: None,
        signature_count: 0,
        signer_index: None,
        signer_certificate_der_base64: None,
        timestamper_certificate_der_base64: None,
        embedded_certificate_count: 0,
        digest_algorithm: None,
        timestamp_kinds: Vec::new(),
        timestamp_signing_time: None,
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

fn msix_signature_pkcs7_der(package: &[u8]) -> Result<Vec<u8>> {
    let mut archive = ZipArchive::new(Cursor::new(package)).context("open MSIX ZIP")?;
    let mut entry = archive
        .by_name("AppxSignature.p7x")
        .context("read AppxSignature.p7x")?;
    let mut p7x = Vec::new();
    entry.read_to_end(&mut p7x)?;
    let pkcs7 = p7x
        .strip_prefix(b"PKCX")
        .ok_or_else(|| anyhow::anyhow!("AppxSignature.p7x missing PKCX prefix"))?;
    Ok(pkcs7.to_vec())
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

fn der_encode_octet_string(data: &[u8]) -> Result<Vec<u8>> {
    let octet = der::asn1::OctetString::new(data)
        .map_err(|e| anyhow::anyhow!("encode OCTET STRING: {e}"))?;
    octet
        .to_der()
        .map_err(|e| anyhow::anyhow!("encode OCTET STRING DER: {e}"))
}

fn format_powershell_signature_block(pkcs7_der: &[u8], extension: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs7_der);
    let (begin, line_prefix, line_suffix, end) = match extension.to_ascii_lowercase().as_str() {
        "ps1xml" | "psc1" | "cdxml" => (
            "\r\n<!-- SIG # Begin signature block -->\r\n",
            "<!-- ",
            " -->\r\n",
            "<!-- SIG # End signature block -->\r\n",
        ),
        "mof" => (
            "\r\n/* SIG # Begin signature block */\r\n",
            "/* ",
            " */\r\n",
            "/* SIG # End signature block */\r\n",
        ),
        _ => (
            "\r\n# SIG # Begin signature block\r\n",
            "# ",
            "\r\n",
            "# SIG # End signature block\r\n",
        ),
    };
    let mut block = String::from(begin);
    for chunk in b64.as_bytes().chunks(64) {
        block.push_str(line_prefix);
        block.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        block.push_str(line_suffix);
    }
    block.push_str(end);
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
            PortableFileFormat::NuGet
        );
        assert_eq!(
            infer_format(Path::new("symbols.snupkg")),
            PortableFileFormat::NuGet
        );
        assert_eq!(
            infer_format(Path::new("extension.vsix")),
            PortableFileFormat::Vsix
        );
        assert_eq!(
            infer_format(Path::new("archive.zip")),
            PortableFileFormat::Zip
        );
        assert_eq!(
            infer_format(Path::new("app.manifest")),
            PortableFileFormat::ClickOnceManifest
        );
        assert_eq!(
            infer_format(Path::new("deploy.application")),
            PortableFileFormat::ClickOnceManifest
        );
        assert_eq!(
            infer_format(Path::new("addin.vsto")),
            PortableFileFormat::ClickOnceManifest
        );
        assert_eq!(
            infer_format(Path::new("installer.appinstaller")),
            PortableFileFormat::AppInstaller
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
            infer_format(Path::new("types.ps1xml")),
            PortableFileFormat::PowerShellScript
        );
        assert_eq!(
            infer_format(Path::new("console.psc1")),
            PortableFileFormat::PowerShellScript
        );
        assert_eq!(
            infer_format(Path::new("module.cdxml")),
            PortableFileFormat::PowerShellScript
        );
        assert_eq!(
            infer_format(Path::new("config.mof")),
            PortableFileFormat::PowerShellScript
        );
        assert_eq!(
            infer_format(Path::new("unknown.bin")),
            PortableFileFormat::Unknown
        );
    }

    #[test]
    fn formats_script_signature_marker_family() {
        let ps1_block = format_powershell_signature_block(b"abc", "ps1");
        assert!(ps1_block.contains("# SIG # Begin signature block"));
        assert!(ps1_block.contains("# YWJj"));
        assert!(ps1_block.contains("# SIG # End signature block"));

        let ps1xml_block = format_powershell_signature_block(b"abc", "ps1xml");
        assert!(ps1xml_block.contains("<!-- SIG # Begin signature block -->"));
        assert!(ps1xml_block.contains("<!-- YWJj -->"));
        assert!(ps1xml_block.contains("<!-- SIG # End signature block -->"));

        let mof_block = format_powershell_signature_block(b"abc", "mof");
        assert!(mof_block.contains("/* SIG # Begin signature block */"));
        assert!(mof_block.contains("/* YWJj */"));
        assert!(mof_block.contains("/* SIG # End signature block */"));
    }

    #[test]
    fn reports_unsigned_pe_without_error() {
        let path = PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.efi");
        let response = portable_get_signature(PortableGetSignatureRequest::path_only(path))
            .expect("inspect PE");
        assert_eq!(response.status, PortableSignatureStatus::NotSigned);
    }

    #[test]
    fn reports_signed_pe_as_valid_digest_binding() {
        let path = PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let response = portable_get_signature(PortableGetSignatureRequest::path_only(path))
            .expect("inspect PE");
        assert_eq!(response.status, PortableSignatureStatus::Valid);
        assert!(response.signature_count > 0);
    }

    #[test]
    fn rejects_mixed_azure_key_vault_and_local_material() {
        let request = PortableSignRequest {
            path: PathBuf::from("test.dll"),
            azure_key_vault_url: Some("https://myvault.vault.azure.net".to_string()),
            azure_key_vault_certificate: Some("my-cert".to_string()),
            certificate_path: Some(PathBuf::from("cert.pem")),
            private_key_path: Some(PathBuf::from("key.pem")),
            ..default_sign_request()
        };
        let err = load_signing_material(&request).unwrap_err();
        assert!(
            err.to_string().contains("not both"),
            "expected mutual exclusion error, got: {err}"
        );
    }

    #[test]
    fn rejects_mixed_azure_key_vault_and_artifact_signing() {
        let request = PortableSignRequest {
            path: PathBuf::from("test.dll"),
            azure_key_vault_url: Some("https://myvault.vault.azure.net".to_string()),
            azure_key_vault_certificate: Some("my-cert".to_string()),
            artifact_signing_endpoint: Some("https://signing.example.com".to_string()),
            ..default_sign_request()
        };
        let err = load_signing_material(&request).unwrap_err();
        assert!(
            err.to_string().contains("not both"),
            "expected mutual exclusion error, got: {err}"
        );
    }

    #[test]
    fn rejects_azure_key_vault_without_compiled_feature() {
        let request = PortableSignRequest {
            path: PathBuf::from("test.dll"),
            azure_key_vault_url: Some("https://myvault.vault.azure.net".to_string()),
            azure_key_vault_certificate: Some("my-cert".to_string()),
            ..default_sign_request()
        };
        let err = load_signing_material(&request).unwrap_err();
        // Without the feature compiled, we get either "not compiled" or "not yet available"
        let msg = err.to_string();
        assert!(
            msg.contains("Azure Key Vault"),
            "expected AKV error, got: {msg}"
        );
    }

    #[test]
    fn rejects_artifact_signing_without_compiled_feature() {
        let request = PortableSignRequest {
            path: PathBuf::from("test.dll"),
            artifact_signing_endpoint: Some("https://signing.example.com".to_string()),
            ..default_sign_request()
        };
        let err = load_signing_material(&request).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Artifact Signing"),
            "expected AS error, got: {msg}"
        );
    }

    fn default_sign_request() -> PortableSignRequest {
        PortableSignRequest {
            path: PathBuf::from("test.dll"),
            output_path: None,
            hash_algorithm: PortableDigestAlgorithm::Sha256,
            certificate_path: None,
            private_key_path: None,
            certificate_der_base64: None,
            private_key_der_base64: None,
            pfx_path: None,
            pfx_password: None,
            chain_certificate_paths: vec![],
            chain_certificates_der_base64: vec![],
            timestamp_server: None,
            timestamp_hash_algorithm: None,
            azure_key_vault_url: None,
            azure_key_vault_certificate: None,
            azure_key_vault_access_token: None,
            azure_key_vault_client_id: None,
            azure_key_vault_client_secret: None,
            azure_key_vault_tenant_id: None,
            azure_key_vault_managed_identity: None,
            artifact_signing_endpoint: None,
            artifact_signing_account_name: None,
            artifact_signing_profile_name: None,
            artifact_signing_access_token: None,
            artifact_signing_managed_identity: None,
            artifact_signing_tenant_id: None,
            artifact_signing_client_id: None,
            artifact_signing_client_secret: None,
        }
    }
}
