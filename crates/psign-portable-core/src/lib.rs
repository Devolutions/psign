//! Reusable portable Authenticode operations for CLI adapters and foreign-function callers.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use authenticode::SpcIndirectDataContent;
use base64::Engine as _;
use der::Encode as _;
use der::asn1::ObjectIdentifier;
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
use psign_sip_digest::verify_pe::{
    pe_nth_pkcs7_signed_data_der, verify_pe_authenticode_digest_consistency,
    verify_pe_authenticode_digest_consistency_if_signed,
};
use psign_sip_digest::{
    cab_digest, catalog_digest, msi_digest, msix_digest, pe_digest, pe_embed, pkcs7, ps_script,
    rdp, timestamp, verify_script_digest_consistency, zip_authenticode,
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableCatalogValidationStatus {
    Valid,
    ValidationFailed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PortableCatalogItemStatus {
    Valid,
    Missing,
    HashMismatch,
    NotInCatalog,
    Skipped,
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
pub struct PortableNewFileCatalogRequest {
    pub catalog_file_path: PathBuf,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub catalog_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableTestFileCatalogRequest {
    pub catalog_file_path: PathBuf,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub files_to_skip: Vec<String>,
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

impl PortableTestFileCatalogRequest {
    fn signature_request(&self) -> PortableGetSignatureRequest {
        PortableGetSignatureRequest {
            path: self.catalog_file_path.clone(),
            trusted_certificate_paths: self.trusted_certificate_paths.clone(),
            trusted_certificates_der_base64: self.trusted_certificates_der_base64.clone(),
            anchor_directory: self.anchor_directory.clone(),
            authroot_cab: self.authroot_cab.clone(),
            as_of: self.as_of.clone(),
            prefer_timestamp_signing_time: self.prefer_timestamp_signing_time,
            require_valid_timestamp: self.require_valid_timestamp,
            online_aia: self.online_aia,
            online_ocsp: self.online_ocsp,
            revocation_mode: self.revocation_mode,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableValidatePowerShellRequest {
    pub source_path_or_extension: PathBuf,
    pub content_base64: String,
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

impl PortableValidatePowerShellRequest {
    fn trust_request(&self) -> PortableGetSignatureRequest {
        PortableGetSignatureRequest {
            path: self.source_path_or_extension.clone(),
            trusted_certificate_paths: self.trusted_certificate_paths.clone(),
            trusted_certificates_der_base64: self.trusted_certificates_der_base64.clone(),
            anchor_directory: self.anchor_directory.clone(),
            authroot_cab: self.authroot_cab.clone(),
            as_of: self.as_of.clone(),
            prefer_timestamp_signing_time: self.prefer_timestamp_signing_time,
            require_valid_timestamp: self.require_valid_timestamp,
            online_aia: self.online_aia,
            online_ocsp: self.online_ocsp,
            revocation_mode: self.revocation_mode,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSignRequest {
    pub path: PathBuf,
    #[serde(default)]
    pub append_signature: bool,
    #[serde(default)]
    pub skip_signed: bool,
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
    pub azure_key_vault_certificate_version: Option<String>,
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
    #[serde(default)]
    pub azure_authority: Option<String>,
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
    pub artifact_signing_managed_identity_resource_id: Option<String>,
    #[serde(default)]
    pub artifact_signing_credential_type: Option<String>,
    #[serde(default)]
    pub artifact_signing_tenant_id: Option<String>,
    #[serde(default)]
    pub artifact_signing_client_id: Option<String>,
    #[serde(default)]
    pub artifact_signing_client_secret: Option<String>,
    #[serde(default)]
    pub artifact_signing_federated_token_file: Option<String>,
    #[serde(default)]
    pub artifact_signing_exclude_credentials: Vec<String>,
}

impl Default for PortableSignRequest {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            append_signature: false,
            skip_signed: false,
            output_path: None,
            hash_algorithm: PortableDigestAlgorithm::default(),
            certificate_path: None,
            private_key_path: None,
            certificate_der_base64: None,
            private_key_der_base64: None,
            pfx_path: None,
            pfx_password: None,
            chain_certificate_paths: Vec::new(),
            chain_certificates_der_base64: Vec::new(),
            timestamp_server: None,
            timestamp_hash_algorithm: None,
            azure_key_vault_url: None,
            azure_key_vault_certificate: None,
            azure_key_vault_certificate_version: None,
            azure_key_vault_access_token: None,
            azure_key_vault_client_id: None,
            azure_key_vault_client_secret: None,
            azure_key_vault_tenant_id: None,
            azure_key_vault_managed_identity: None,
            azure_authority: None,
            artifact_signing_endpoint: None,
            artifact_signing_account_name: None,
            artifact_signing_profile_name: None,
            artifact_signing_access_token: None,
            artifact_signing_managed_identity: None,
            artifact_signing_managed_identity_resource_id: None,
            artifact_signing_credential_type: None,
            artifact_signing_tenant_id: None,
            artifact_signing_client_id: None,
            artifact_signing_client_secret: None,
            artifact_signing_federated_token_file: None,
            artifact_signing_exclude_credentials: Vec::new(),
        }
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs7_der_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableCatalogItem {
    pub path: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableCatalogPathItem {
    pub path: String,
    pub hash: Option<String>,
    pub status: PortableCatalogItemStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableNewFileCatalogResponse {
    pub schema_version: u32,
    pub catalog_file_path: PathBuf,
    pub catalog_version: u32,
    pub hash_algorithm: String,
    pub item_count: usize,
    pub catalog_items: Vec<PortableCatalogItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableTestFileCatalogResponse {
    pub schema_version: u32,
    pub catalog_file_path: PathBuf,
    pub status: PortableCatalogValidationStatus,
    pub hash_algorithm: String,
    pub catalog_items: Vec<PortableCatalogItem>,
    pub path_items: Vec<PortableCatalogPathItem>,
    pub skipped_items: Vec<String>,
    pub signature: PortableSignatureResponse,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableSignResponse {
    pub schema_version: u32,
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub format: PortableFileFormat,
    pub signature: PortableSignatureResponse,
    #[serde(default, skip_serializing_if = "is_false")]
    pub skipped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableClearSignatureRequest {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableClearSignatureResponse {
    pub schema_version: u32,
    pub path: PathBuf,
    pub format: PortableFileFormat,
    pub signature_removed: bool,
    pub bytes_removed: usize,
    pub message: String,
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

    let skipped = match format {
        PortableFileFormat::Pe => sign_pe(&request, &output_path)?,
        PortableFileFormat::Cab => {
            sign_cab(&request, &output_path)?;
            false
        }
        PortableFileFormat::Msi => {
            sign_msi(&request, &output_path)?;
            false
        }
        PortableFileFormat::Msix => {
            sign_msix(&request, &output_path)?;
            false
        }
        PortableFileFormat::NuGet => {
            sign_nuget(&request, &output_path)?;
            false
        }
        PortableFileFormat::Vsix => {
            sign_vsix(&request, &output_path)?;
            false
        }
        PortableFileFormat::ClickOnceManifest => {
            sign_clickonce_manifest(&request, &output_path)?;
            false
        }
        PortableFileFormat::AppInstaller => {
            sign_appinstaller(&request, &output_path)?;
            false
        }
        PortableFileFormat::Zip => {
            sign_zip(&request, &output_path)?;
            false
        }
        PortableFileFormat::PowerShellScript => {
            sign_script(&request, &output_path)?;
            false
        }
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
    };

    let inspect_request = PortableGetSignatureRequest::path_only(output_path.clone());
    let signature = portable_get_signature(inspect_request)?;

    Ok(PortableSignResponse {
        schema_version: SCHEMA_VERSION,
        input_path: request.path,
        output_path,
        format,
        signature,
        skipped,
    })
}

pub fn portable_get_signature(
    request: PortableGetSignatureRequest,
) -> Result<PortableSignatureResponse> {
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let format = infer_format_from_path_or_data(&request.path, &data);

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

pub fn portable_clear_signature(
    request: PortableClearSignatureRequest,
) -> Result<PortableClearSignatureResponse> {
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let format = infer_format_from_path_or_data(&request.path, &data);
    match format {
        PortableFileFormat::Pe => clear_pe_signature(&request.path, format),
        PortableFileFormat::Unknown => bail!(
            "unsupported portable signature clear format: {}",
            request.path.display()
        ),
        _ => bail!(
            "portable signature clear is not supported for {format:?}; use script signature removal for PowerShell files"
        ),
    }
}

pub fn portable_new_file_catalog(
    request: PortableNewFileCatalogRequest,
) -> Result<PortableNewFileCatalogResponse> {
    let catalog_file_path = resolve_catalog_output_path(&request.catalog_file_path);
    let catalog_version = effective_catalog_version(request.catalog_version)?;
    let hash_algorithm = catalog_hash_algorithm_for_version(catalog_version)?;
    let subjects = collect_catalog_subjects(&request.paths, Some(&catalog_file_path))?;
    let inputs = subjects
        .into_iter()
        .map(|subject| {
            let bytes = std::fs::read(&subject.path)
                .with_context(|| format!("read catalog subject {}", subject.path.display()))?;
            Ok(catalog_digest::CatalogSubjectInput {
                name: subject.member_name,
                bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let catalog = catalog_digest::create_unsigned_catalog_pkcs7_der(&inputs, hash_algorithm)
        .with_context(|| format!("create file catalog {}", catalog_file_path.display()))?;
    std::fs::write(&catalog_file_path, &catalog.pkcs7_der)
        .with_context(|| format!("write {}", catalog_file_path.display()))?;
    let catalog_items = catalog
        .members
        .iter()
        .map(portable_catalog_item_from_member)
        .collect::<Vec<_>>();
    Ok(PortableNewFileCatalogResponse {
        schema_version: SCHEMA_VERSION,
        catalog_file_path,
        catalog_version,
        hash_algorithm: catalog_hash_algorithm_label(hash_algorithm).to_string(),
        item_count: catalog_items.len(),
        catalog_items,
    })
}

pub fn portable_test_file_catalog(
    request: PortableTestFileCatalogRequest,
) -> Result<PortableTestFileCatalogResponse> {
    let catalog_file_path = request.catalog_file_path.clone();
    let catalog_bytes = std::fs::read(&catalog_file_path)
        .with_context(|| format!("read catalog {}", catalog_file_path.display()))?;
    let members = catalog_digest::catalog_members_bytes(&catalog_bytes)
        .with_context(|| format!("parse catalog members {}", catalog_file_path.display()))?;
    let catalog_items = members
        .iter()
        .map(portable_catalog_item_from_member)
        .collect::<Vec<_>>();
    let hash_algorithm = members
        .first()
        .map(|m| catalog_hash_algorithm_label_for_oid(m.digest_algorithm_oid).to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let mut member_by_name = std::collections::HashMap::with_capacity(members.len());
    for member in members {
        if let Some(name) = member.subject_name.as_ref() {
            member_by_name.insert(normalize_catalog_member_key(name), member);
        }
    }

    let skip_keys = request
        .files_to_skip
        .iter()
        .flat_map(|skip| catalog_skip_keys(skip))
        .collect::<std::collections::HashSet<_>>();
    let subjects = collect_catalog_subjects(&request.paths, Some(&catalog_file_path))?;
    let mut seen_path_keys = std::collections::HashSet::with_capacity(subjects.len());
    let mut skipped_items = Vec::new();
    let mut path_items = Vec::new();

    for subject in subjects {
        let member_key = normalize_catalog_member_key(&subject.member_name);
        if skip_keys.contains(&member_key)
            || skip_keys.contains(&normalize_catalog_member_key(
                &subject.path.to_string_lossy(),
            ))
            || subject
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| skip_keys.contains(&normalize_catalog_member_key(name)))
        {
            skipped_items.push(subject.member_name);
            continue;
        }

        seen_path_keys.insert(member_key.clone());
        let Some(member) = member_by_name.get(&member_key) else {
            path_items.push(PortableCatalogPathItem {
                path: subject.member_name,
                hash: None,
                status: PortableCatalogItemStatus::NotInCatalog,
                message: Some("File is not listed in the catalog.".to_string()),
            });
            continue;
        };
        let bytes = std::fs::read(&subject.path).with_context(|| {
            format!("read catalog validation subject {}", subject.path.display())
        })?;
        let actual = catalog_digest::catalog_member_digest_for_subject(member, &bytes)
            .with_context(|| {
                format!("hash catalog validation subject {}", subject.path.display())
            })?;
        let actual_hex = hex_lower(&actual);
        let status = if actual == member.digest {
            PortableCatalogItemStatus::Valid
        } else {
            PortableCatalogItemStatus::HashMismatch
        };
        let message = (status == PortableCatalogItemStatus::HashMismatch)
            .then(|| "File hash does not match the catalog.".to_string());
        path_items.push(PortableCatalogPathItem {
            path: subject.member_name,
            hash: Some(actual_hex),
            status,
            message,
        });
    }

    for (key, member) in member_by_name {
        if seen_path_keys.contains(&key) || skip_keys.contains(&key) {
            continue;
        }
        path_items.push(PortableCatalogPathItem {
            path: member
                .subject_name
                .unwrap_or_else(|| hex_lower(&member.subject_identifier)),
            hash: None,
            status: PortableCatalogItemStatus::Missing,
            message: Some("Catalog member was not found under the supplied path.".to_string()),
        });
    }

    path_items.sort_by_key(|item| catalog_path_sort_key(&item.path));
    skipped_items.sort_by_key(|item| catalog_path_sort_key(item));
    let signature = portable_get_signature(request.signature_request())?;
    let status = if path_items
        .iter()
        .all(|item| item.status == PortableCatalogItemStatus::Valid)
    {
        PortableCatalogValidationStatus::Valid
    } else {
        PortableCatalogValidationStatus::ValidationFailed
    };

    Ok(PortableTestFileCatalogResponse {
        schema_version: SCHEMA_VERSION,
        catalog_file_path,
        status,
        hash_algorithm,
        catalog_items,
        path_items,
        skipped_items,
        signature,
    })
}

pub fn portable_validate_powershell_script(
    request: PortableValidatePowerShellRequest,
) -> Result<PortableSignatureResponse> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(&request.content_base64)
        .context("decode content_base64")?;
    let format = infer_powershell_source_format(&request.source_path_or_extension);
    if format != PortableFileFormat::PowerShellScript {
        return Ok(base_response(
            request.source_path_or_extension,
            format,
            PortableSignatureStatus::NotSupportedFileFormat,
            "Unsupported file format for portable PowerShell signature validation.",
        ));
    }

    let mut response = inspect_script(&request.source_path_or_extension, &data)?;
    let trust_request = request.trust_request();
    apply_trust_if_requested(&trust_request, format, &data, &mut response)?;

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

fn infer_format_from_path_or_data(path: &Path, data: &[u8]) -> PortableFileFormat {
    let format = infer_format(path);
    if format != PortableFileFormat::Unknown {
        return format;
    }
    if is_probably_pe(data) {
        PortableFileFormat::Pe
    } else {
        PortableFileFormat::Unknown
    }
}

fn is_probably_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || data.get(0..2) != Some(b"MZ") {
        return false;
    }
    let pe_offset = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    pe_offset
        .checked_add(4)
        .is_some_and(|end| end <= data.len() && data.get(pe_offset..end) == Some(b"PE\0\0"))
}

fn infer_powershell_source_format(path: &Path) -> PortableFileFormat {
    let format = infer_format(path);
    if format != PortableFileFormat::Unknown {
        return format;
    }

    let Some(source) = path.file_name().and_then(|name| name.to_str()) else {
        return PortableFileFormat::Unknown;
    };
    let extension = source.trim_start_matches('.');
    if ps_script::extension_supported(extension) {
        PortableFileFormat::PowerShellScript
    } else {
        PortableFileFormat::Unknown
    }
}

fn script_extension_for(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "ps1".to_string())
}

#[derive(Debug, Clone)]
struct CatalogSubjectPlan {
    path: PathBuf,
    member_name: String,
}

fn resolve_catalog_output_path(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join("catalog.cat")
    } else {
        path.to_path_buf()
    }
}

fn effective_catalog_version(version: u32) -> Result<u32> {
    match version {
        0 => Ok(2),
        1 | 2 => Ok(version),
        _ => bail!("catalog_version must be 1 or 2"),
    }
}

fn catalog_hash_algorithm_for_version(
    version: u32,
) -> Result<catalog_digest::CatalogHashAlgorithm> {
    match version {
        1 => Ok(catalog_digest::CatalogHashAlgorithm::Sha1),
        2 => Ok(catalog_digest::CatalogHashAlgorithm::Sha256),
        _ => bail!("catalog_version must be 1 or 2"),
    }
}

fn catalog_hash_algorithm_label(algorithm: catalog_digest::CatalogHashAlgorithm) -> &'static str {
    match algorithm {
        catalog_digest::CatalogHashAlgorithm::Sha1 => "SHA1",
        catalog_digest::CatalogHashAlgorithm::Sha256 => "SHA256",
        catalog_digest::CatalogHashAlgorithm::Sha384 => "SHA384",
        catalog_digest::CatalogHashAlgorithm::Sha512 => "SHA512",
    }
}

fn catalog_hash_algorithm_label_for_oid(oid: ObjectIdentifier) -> &'static str {
    if oid == ObjectIdentifier::new_unwrap("1.3.14.3.2.26") {
        "SHA1"
    } else if oid == ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1") {
        "SHA256"
    } else if oid == ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2") {
        "SHA384"
    } else if oid == ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3") {
        "SHA512"
    } else {
        "Unknown"
    }
}

fn portable_catalog_item_from_member(
    member: &catalog_digest::CatalogMember,
) -> PortableCatalogItem {
    PortableCatalogItem {
        path: member
            .subject_name
            .clone()
            .unwrap_or_else(|| hex_lower(&member.subject_identifier)),
        hash: hex_lower(&member.digest),
    }
}

fn collect_catalog_subjects(
    paths: &[PathBuf],
    catalog_file_path: Option<&Path>,
) -> Result<Vec<CatalogSubjectPlan>> {
    let effective_paths = if paths.is_empty() {
        vec![std::env::current_dir().context("resolve current directory for catalog paths")?]
    } else {
        paths.to_vec()
    };
    let single_root_directory = effective_paths.len() == 1 && effective_paths[0].is_dir();
    let mut subjects = Vec::new();
    if single_root_directory {
        collect_catalog_directory_subjects(
            &effective_paths[0],
            Some(&effective_paths[0]),
            catalog_file_path,
            &mut subjects,
        )?;
    } else {
        for path in &effective_paths {
            if path.is_dir() {
                collect_catalog_directory_subjects(path, None, catalog_file_path, &mut subjects)?;
            } else if path.is_file() {
                if is_same_existing_path(path, catalog_file_path) {
                    continue;
                }
                subjects.push(CatalogSubjectPlan {
                    path: path.clone(),
                    member_name: catalog_file_name(path)?,
                });
            } else {
                bail!(
                    "catalog path does not exist or is not a file/directory: {}",
                    path.display()
                );
            }
        }
    }
    subjects.sort_by_key(|subject| {
        (
            catalog_path_sort_key(&subject.member_name),
            subject.path.clone(),
        )
    });
    reject_duplicate_catalog_member_names(&subjects)?;
    if subjects.is_empty() {
        bail!("catalog requires at least one subject file");
    }
    Ok(subjects)
}

fn collect_catalog_directory_subjects(
    directory: &Path,
    relative_base: Option<&Path>,
    catalog_file_path: Option<&Path>,
    subjects: &mut Vec<CatalogSubjectPlan>,
) -> Result<()> {
    let mut entries = std::fs::read_dir(directory)
        .with_context(|| format!("read directory {}", directory.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("read directory entry {}", directory.display()))?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat directory entry {}", path.display()))?;
        if file_type.is_dir() {
            collect_catalog_directory_subjects(&path, relative_base, catalog_file_path, subjects)?;
        } else if file_type.is_file() {
            if is_same_existing_path(&path, catalog_file_path) {
                continue;
            }
            let member_name = match relative_base {
                Some(base) => catalog_relative_name(base, &path)?,
                None => catalog_file_name(&path)?,
            };
            subjects.push(CatalogSubjectPlan { path, member_name });
        }
    }
    Ok(())
}

fn catalog_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "catalog subject path has no UTF-8 file name: {}",
                path.display()
            )
        })
}

fn catalog_relative_name(base: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(base)
        .with_context(|| format!("make {} relative to {}", path.display(), base.display()))?;
    let mut parts = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        let Some(part) = part.to_str() else {
            bail!(
                "catalog relative path contains non-UTF-8 component: {}",
                path.display()
            );
        };
        parts.push(part);
    }
    if parts.is_empty() {
        bail!("catalog relative path is empty for {}", path.display());
    }
    Ok(parts.join("/"))
}

fn reject_duplicate_catalog_member_names(subjects: &[CatalogSubjectPlan]) -> Result<()> {
    let mut seen = std::collections::HashSet::with_capacity(subjects.len());
    for subject in subjects {
        let key = normalize_catalog_member_key(&subject.member_name);
        if !seen.insert(key) {
            bail!(
                "catalog contains duplicate subject file name {}",
                subject.member_name
            );
        }
    }
    Ok(())
}

fn is_same_existing_path(path: &Path, other: Option<&Path>) -> bool {
    let Some(other) = other else {
        return false;
    };
    let Ok(left) = path.canonicalize() else {
        return false;
    };
    let Ok(right) = other.canonicalize() else {
        return false;
    };
    left == right
}

fn normalize_catalog_member_key(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn catalog_skip_keys(skip: &str) -> Vec<String> {
    let normalized = normalize_catalog_member_key(skip);
    let file_name = normalized
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    match file_name {
        Some(file_name) if file_name != normalized => vec![normalized, file_name],
        _ => vec![normalized],
    }
}

fn catalog_path_sort_key(path: &str) -> String {
    normalize_catalog_member_key(path)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
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

enum SigningProvider {
    Local(Box<LocalSigningProvider>),
    #[cfg(feature = "azure-kv-sign")]
    AzureKeyVault(Box<AzureKeyVaultSigningProvider>),
    #[cfg(feature = "artifact-signing-rest")]
    ArtifactSigning(Box<ArtifactSigningProvider>),
}

struct LocalSigningProvider {
    signer_cert: x509_cert::Certificate,
    private_key: rsa::RsaPrivateKey,
    chain: Vec<x509_cert::Certificate>,
}

#[cfg(feature = "azure-kv-sign")]
struct AzureKeyVaultSigningProvider {
    http: reqwest::blocking::Client,
    token: String,
    key_vault_certificate: psign_azure_kv_rest::KeyVaultCertificate,
    signer_cert: x509_cert::Certificate,
    chain: Vec<x509_cert::Certificate>,
}

#[cfg(feature = "artifact-signing-rest")]
struct ArtifactSigningProvider {
    endpoint: String,
    account_name: String,
    profile_name: String,
    auth: psign_codesigning_rest::CodesigningAuth,
    chain: Vec<x509_cert::Certificate>,
}

#[cfg(any(feature = "azure-kv-sign", feature = "artifact-signing-rest"))]
struct RemoteSignature {
    signature: Vec<u8>,
    signer_cert: x509_cert::Certificate,
    chain: Vec<x509_cert::Certificate>,
}

impl SigningProvider {
    fn create_authenticode_pkcs7(
        &self,
        indirect: SpcIndirectDataContent,
        digest_algorithm: AuthenticodeSigningDigest,
    ) -> Result<Vec<u8>> {
        match self {
            SigningProvider::Local(local) => pkcs7::create_authenticode_pkcs7_der_rsa(
                indirect,
                digest_algorithm,
                local.signer_cert.clone(),
                local.chain.clone(),
                local.private_key.clone(),
            ),
            #[cfg(feature = "azure-kv-sign")]
            SigningProvider::AzureKeyVault(_) => {
                let prehash = pkcs7::authenticode_remote_rsa_signed_attrs_digest(
                    &indirect,
                    digest_algorithm,
                )?;
                let signed = self.sign_remote_digest(digest_algorithm, &prehash)?;
                pkcs7::create_authenticode_pkcs7_der_with_rsa_signature(
                    indirect,
                    digest_algorithm,
                    signed.signer_cert,
                    signed.chain,
                    &signed.signature,
                )
            }
            #[cfg(feature = "artifact-signing-rest")]
            SigningProvider::ArtifactSigning(_) => {
                let prehash = pkcs7::authenticode_remote_rsa_signed_attrs_digest(
                    &indirect,
                    digest_algorithm,
                )?;
                let signed = self.sign_remote_digest(digest_algorithm, &prehash)?;
                pkcs7::create_authenticode_pkcs7_der_with_rsa_signature(
                    indirect,
                    digest_algorithm,
                    signed.signer_cert,
                    signed.chain,
                    &signed.signature,
                )
            }
        }
    }

    fn create_pkcs7_signed_data(
        &self,
        econtent_type: der::asn1::ObjectIdentifier,
        econtent_der: &[u8],
        digest_algorithm: AuthenticodeSigningDigest,
        content_mode: pkcs7::Pkcs7ContentMode,
    ) -> Result<Vec<u8>> {
        match self {
            SigningProvider::Local(local) => {
                let pkcs7_bytes = pkcs7::create_pkcs7_signed_data_der_rsa(
                    econtent_type,
                    econtent_der,
                    digest_algorithm,
                    local.signer_cert.clone(),
                    local.chain.clone(),
                    local.private_key.clone(),
                )?;
                if content_mode == pkcs7::Pkcs7ContentMode::Attached {
                    return Ok(pkcs7_bytes);
                }
                let mut sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7_bytes)
                    .context("parse generated CMS before detaching eContent")?;
                sd.encap_content_info.econtent = None;
                pkcs7::encode_pkcs7_content_info_signed_data_der(&sd)
            }
            #[cfg(feature = "azure-kv-sign")]
            SigningProvider::AzureKeyVault(_) => {
                let prehash = pkcs7::pkcs7_remote_rsa_signed_attrs_digest(
                    econtent_type,
                    econtent_der,
                    digest_algorithm,
                )?;
                let signed = self.sign_remote_digest(digest_algorithm, &prehash)?;
                pkcs7::create_pkcs7_signed_data_der_with_rsa_signature(
                    econtent_type,
                    econtent_der,
                    digest_algorithm,
                    signed.signer_cert,
                    signed.chain,
                    &signed.signature,
                    content_mode,
                )
            }
            #[cfg(feature = "artifact-signing-rest")]
            SigningProvider::ArtifactSigning(_) => {
                let prehash = pkcs7::pkcs7_remote_rsa_signed_attrs_digest(
                    econtent_type,
                    econtent_der,
                    digest_algorithm,
                )?;
                let signed = self.sign_remote_digest(digest_algorithm, &prehash)?;
                pkcs7::create_pkcs7_signed_data_der_with_rsa_signature(
                    econtent_type,
                    econtent_der,
                    digest_algorithm,
                    signed.signer_cert,
                    signed.chain,
                    &signed.signature,
                    content_mode,
                )
            }
        }
    }

    fn sign_xml_signed_info(
        &self,
        algorithm: psign_opc_sign::vsix::VsixHashAlgorithm,
        signed_info: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            SigningProvider::Local(local) => {
                let cert_der = local
                    .signer_cert
                    .to_der()
                    .context("encode signer cert DER")?;
                let signature =
                    sign_xml_signed_info_rsa(algorithm, signed_info, &local.private_key)?;
                Ok((signature, cert_der))
            }
            #[cfg(feature = "azure-kv-sign")]
            SigningProvider::AzureKeyVault(_) => {
                let digest_algorithm = authenticode_digest_from_vsix_algorithm(algorithm);
                let prehash = algorithm.hash(signed_info);
                let signed = self.sign_remote_digest(digest_algorithm, &prehash)?;
                let cert_der = signed
                    .signer_cert
                    .to_der()
                    .context("encode signer cert DER")?;
                Ok((signed.signature, cert_der))
            }
            #[cfg(feature = "artifact-signing-rest")]
            SigningProvider::ArtifactSigning(_) => {
                let digest_algorithm = authenticode_digest_from_vsix_algorithm(algorithm);
                let prehash = algorithm.hash(signed_info);
                let signed = self.sign_remote_digest(digest_algorithm, &prehash)?;
                let cert_der = signed
                    .signer_cert
                    .to_der()
                    .context("encode signer cert DER")?;
                Ok((signed.signature, cert_der))
            }
        }
    }

    #[cfg(any(feature = "azure-kv-sign", feature = "artifact-signing-rest"))]
    fn sign_remote_digest(
        &self,
        digest_algorithm: AuthenticodeSigningDigest,
        digest: &[u8],
    ) -> Result<RemoteSignature> {
        match self {
            SigningProvider::Local(_) => {
                bail!("internal error: local signing provider cannot remote-sign a digest")
            }
            #[cfg(feature = "azure-kv-sign")]
            SigningProvider::AzureKeyVault(provider) => {
                let signature = psign_azure_kv_rest::kv_sign_digest_from_certificate(
                    &provider.http,
                    &provider.token,
                    &provider.key_vault_certificate,
                    kv_hash_algorithm(digest_algorithm),
                    digest,
                )?;
                Ok(RemoteSignature {
                    signature,
                    signer_cert: provider.signer_cert.clone(),
                    chain: provider.chain.clone(),
                })
            }
            #[cfg(feature = "artifact-signing-rest")]
            SigningProvider::ArtifactSigning(provider) => {
                let params = psign_codesigning_rest::CodesigningSubmitParams {
                    region: "unused".to_string(),
                    account_name: provider.account_name.clone(),
                    profile_name: provider.profile_name.clone(),
                    digest: digest.to_vec(),
                    signature_algorithm: artifact_signature_algorithm(digest_algorithm).to_string(),
                    api_version: psign_codesigning_rest::DEFAULT_API_VERSION.to_string(),
                    correlation_id: None,
                    authority: None,
                    auth: provider.auth.clone(),
                    endpoint_base_url: Some(provider.endpoint.clone()),
                };
                let debug_portable = std::env::var_os("SIGNTOOL_PORTABLE_DEBUG").is_some();
                let signed = psign_codesigning_rest::submit_codesign_hash_signature_blocking(
                    &params,
                    |msg| {
                        if debug_portable {
                            eprintln!("[debug] {msg}");
                        }
                    },
                )?;
                let (signer_cert, mut returned_chain) =
                    pkcs7::parse_artifact_signing_certificates(&signed.signing_certificate)?;
                returned_chain.extend(provider.chain.clone());
                Ok(RemoteSignature {
                    signature: signed.signature,
                    signer_cert,
                    chain: returned_chain,
                })
            }
        }
    }
}

fn load_signing_provider(request: &PortableSignRequest) -> Result<SigningProvider> {
    validate_signing_provider_selection(request)?;
    if has_azure_key_vault_provider(request) {
        return load_azure_key_vault_signing_provider(request);
    }
    if has_artifact_signing_provider(request) {
        return load_artifact_signing_provider(request);
    }
    let (signer_cert, private_key, chain) = load_signing_material(request)?;
    Ok(SigningProvider::Local(Box::new(LocalSigningProvider {
        signer_cert,
        private_key,
        chain,
    })))
}

#[cfg(feature = "azure-kv-sign")]
fn load_azure_key_vault_signing_provider(request: &PortableSignRequest) -> Result<SigningProvider> {
    use std::time::Duration;

    let vault_url = text_opt(request.azure_key_vault_url.as_deref())
        .ok_or_else(|| anyhow::anyhow!("Azure Key Vault signing requires azure_key_vault_url"))?;
    let certificate =
        text_opt(request.azure_key_vault_certificate.as_deref()).ok_or_else(|| {
            anyhow::anyhow!("Azure Key Vault signing requires azure_key_vault_certificate")
        })?;
    validate_kv_auth_inputs(request)?;

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow::anyhow!("HTTP client: {e}"))?;
    let auth = psign_azure_kv_rest::KvAuthParams {
        access_token: request.azure_key_vault_access_token.as_deref(),
        managed_identity: request.azure_key_vault_managed_identity.unwrap_or(false),
        tenant_id: request.azure_key_vault_tenant_id.as_deref(),
        client_id: request.azure_key_vault_client_id.as_deref(),
        client_secret: request.azure_key_vault_client_secret.as_deref(),
        authority: request.azure_authority.as_deref(),
    };
    let token = psign_azure_kv_rest::acquire_kv_access_token(&auth)?;
    let key_vault_certificate = psign_azure_kv_rest::fetch_kv_certificate(
        &http,
        &vault_url,
        &certificate,
        request.azure_key_vault_certificate_version.as_deref(),
        &token,
    )?;
    let signer_cert_der = psign_azure_kv_rest::kv_decode_cer_b64(&key_vault_certificate.cer)?;
    let signer_cert =
        rdp::parse_certificate(&signer_cert_der).context("parse Key Vault signer certificate")?;
    let chain = load_chain_certificates(request)?;
    Ok(SigningProvider::AzureKeyVault(Box::new(
        AzureKeyVaultSigningProvider {
            http,
            token,
            key_vault_certificate,
            signer_cert,
            chain,
        },
    )))
}

#[cfg(not(feature = "azure-kv-sign"))]
fn load_azure_key_vault_signing_provider(
    _request: &PortableSignRequest,
) -> Result<SigningProvider> {
    bail!(
        "Azure Key Vault signing support is not compiled into this build (feature: azure-kv-sign)"
    )
}

#[cfg(feature = "artifact-signing-rest")]
fn load_artifact_signing_provider(request: &PortableSignRequest) -> Result<SigningProvider> {
    let endpoint = text_opt(request.artifact_signing_endpoint.as_deref())
        .ok_or_else(|| anyhow::anyhow!("Artifact Signing requires artifact_signing_endpoint"))?;
    let account_name =
        text_opt(request.artifact_signing_account_name.as_deref()).ok_or_else(|| {
            anyhow::anyhow!("Artifact Signing requires artifact_signing_account_name")
        })?;
    let profile_name =
        text_opt(request.artifact_signing_profile_name.as_deref()).ok_or_else(|| {
            anyhow::anyhow!("Artifact Signing requires artifact_signing_profile_name")
        })?;
    let auth = artifact_signing_auth(request)?;
    let chain = load_chain_certificates(request)?;
    Ok(SigningProvider::ArtifactSigning(Box::new(
        ArtifactSigningProvider {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            account_name,
            profile_name,
            auth,
            chain,
        },
    )))
}

#[cfg(not(feature = "artifact-signing-rest"))]
fn load_artifact_signing_provider(_request: &PortableSignRequest) -> Result<SigningProvider> {
    bail!(
        "Artifact Signing support is not compiled into this build (feature: artifact-signing-rest)"
    )
}

fn validate_signing_provider_selection(request: &PortableSignRequest) -> Result<()> {
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
    Ok(())
}

fn ensure_local_signing_provider(request: &PortableSignRequest) -> Result<()> {
    validate_signing_provider_selection(request)?;
    if has_azure_key_vault_provider(request) {
        bail!("Azure Key Vault cloud signing is not wired for this portable signing format yet");
    }
    if has_artifact_signing_provider(request) {
        bail!("Artifact Signing cloud signing is not wired for this portable signing format yet");
    }
    Ok(())
}

#[cfg(any(feature = "azure-kv-sign", feature = "artifact-signing-rest"))]
fn text_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(feature = "azure-kv-sign")]
fn validate_kv_auth_inputs(request: &PortableSignRequest) -> Result<()> {
    let has_sp = text_opt(request.azure_key_vault_client_secret.as_deref()).is_some();
    let has_tenant = text_opt(request.azure_key_vault_tenant_id.as_deref()).is_some();
    let has_client = text_opt(request.azure_key_vault_client_id.as_deref()).is_some();
    let has_token = text_opt(request.azure_key_vault_access_token.as_deref()).is_some();
    let managed_identity = request.azure_key_vault_managed_identity.unwrap_or(false);

    let sp_count = has_sp as u8 + has_tenant as u8 + has_client as u8;
    if sp_count != 0 && sp_count != 3 {
        bail!(
            "Azure AD client credentials require azure_key_vault_client_id, azure_key_vault_client_secret, and azure_key_vault_tenant_id"
        );
    }
    if has_token && (managed_identity || sp_count == 3) {
        bail!(
            "use either Azure Key Vault access token or managed identity / client credentials, not multiple"
        );
    }
    if managed_identity && (has_token || sp_count == 3) {
        bail!(
            "Azure Key Vault managed identity cannot be combined with access tokens or client secrets"
        );
    }
    if !has_token && !managed_identity && sp_count != 3 {
        bail!(
            "choose Azure Key Vault authentication: access token, managed identity, or client id/secret/tenant"
        );
    }
    Ok(())
}

#[cfg(feature = "artifact-signing-rest")]
fn artifact_signing_auth(
    request: &PortableSignRequest,
) -> Result<psign_codesigning_rest::CodesigningAuth> {
    psign_codesigning_rest::resolve_codesigning_auth(
        &psign_codesigning_rest::CodesigningAuthInput {
            access_token: request.artifact_signing_access_token.clone(),
            managed_identity: request.artifact_signing_managed_identity.unwrap_or(false),
            managed_identity_resource_id: request
                .artifact_signing_managed_identity_resource_id
                .clone(),
            tenant_id: request.artifact_signing_tenant_id.clone(),
            client_id: request.artifact_signing_client_id.clone(),
            client_secret: request.artifact_signing_client_secret.clone(),
            federated_token_file: request.artifact_signing_federated_token_file.clone(),
            credential_type: request
                .artifact_signing_credential_type
                .as_deref()
                .map(parse_artifact_signing_credential_type)
                .transpose()?,
            exclude_credentials: request.artifact_signing_exclude_credentials.clone(),
        },
    )
}

#[cfg(feature = "artifact-signing-rest")]
fn parse_artifact_signing_credential_type(
    value: &str,
) -> Result<psign_codesigning_rest::CodesigningCredentialType> {
    let normalized = value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect::<String>();
    match normalized.as_str() {
        "" | "default" | "defaultazurecredential" => {
            Ok(psign_codesigning_rest::CodesigningCredentialType::Default)
        }
        "managedidentity" | "managedidentitycredential" => {
            Ok(psign_codesigning_rest::CodesigningCredentialType::ManagedIdentity)
        }
        "accesstoken" | "bearer" => {
            Ok(psign_codesigning_rest::CodesigningCredentialType::AccessToken)
        }
        "clientsecret" | "clientsecretcredential" => {
            Ok(psign_codesigning_rest::CodesigningCredentialType::ClientSecret)
        }
        "workloadidentity" | "workloadidentitycredential" => {
            Ok(psign_codesigning_rest::CodesigningCredentialType::WorkloadIdentity)
        }
        _ => bail!("unsupported Artifact Signing credential type '{value}'"),
    }
}

#[cfg(feature = "azure-kv-sign")]
fn kv_hash_algorithm(
    digest_algorithm: AuthenticodeSigningDigest,
) -> psign_azure_kv_rest::KvHashAlg {
    match digest_algorithm {
        AuthenticodeSigningDigest::Sha256 => psign_azure_kv_rest::KvHashAlg::Sha256,
        AuthenticodeSigningDigest::Sha384 => psign_azure_kv_rest::KvHashAlg::Sha384,
        AuthenticodeSigningDigest::Sha512 => psign_azure_kv_rest::KvHashAlg::Sha512,
    }
}

#[cfg(feature = "artifact-signing-rest")]
fn artifact_signature_algorithm(digest_algorithm: AuthenticodeSigningDigest) -> &'static str {
    match digest_algorithm {
        AuthenticodeSigningDigest::Sha256 => "RS256",
        AuthenticodeSigningDigest::Sha384 => "RS384",
        AuthenticodeSigningDigest::Sha512 => "RS512",
    }
}

#[cfg(any(feature = "azure-kv-sign", feature = "artifact-signing-rest"))]
fn authenticode_digest_from_vsix_algorithm(
    algorithm: psign_opc_sign::vsix::VsixHashAlgorithm,
) -> AuthenticodeSigningDigest {
    match algorithm {
        psign_opc_sign::vsix::VsixHashAlgorithm::Sha256 => AuthenticodeSigningDigest::Sha256,
        psign_opc_sign::vsix::VsixHashAlgorithm::Sha384 => AuthenticodeSigningDigest::Sha384,
        psign_opc_sign::vsix::VsixHashAlgorithm::Sha512 => AuthenticodeSigningDigest::Sha512,
    }
}

fn sign_pe(request: &PortableSignRequest, output_path: &Path) -> Result<bool> {
    let mut pe =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    if request.skip_signed
        && verify_pe_authenticode_digest_consistency_if_signed(&pe)
            .with_context(|| {
                format!(
                    "check existing PE/WinMD Authenticode signature for {}",
                    request.path.display()
                )
            })?
            .is_some()
    {
        if output_path != request.path.as_path() {
            std::fs::copy(&request.path, output_path).with_context(|| {
                format!(
                    "copy {} to {}",
                    request.path.display(),
                    output_path.display()
                )
            })?;
        }
        return Ok(true);
    }

    if !request.append_signature {
        pe = pe_embed::pe_remove_authenticode_certificates(pe)
            .with_context(|| {
                format!(
                    "remove existing PE Authenticode signatures from {}",
                    request.path.display()
                )
            })?
            .0;
    }
    let provider = load_signing_provider(request)?;
    let digest_algorithm: AuthenticodeSigningDigest = request.hash_algorithm.into();
    let pe_digest = pe_digest::pe_authenticode_digest(&pe, digest_algorithm.pe_hash_kind())?;
    let indirect = pkcs7::pe_spc_indirect_data(digest_algorithm, &pe_digest)?;
    let pkcs7 = provider
        .create_authenticode_pkcs7(indirect, digest_algorithm)
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
    std::fs::write(output_path, signed)
        .with_context(|| format!("write {}", output_path.display()))?;
    Ok(false)
}

fn clear_pe_signature(
    path: &Path,
    format: PortableFileFormat,
) -> Result<PortableClearSignatureResponse> {
    let image = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let (cleared, bytes_removed) = pe_embed::pe_remove_authenticode_certificates(image)
        .with_context(|| format!("remove PE Authenticode signatures from {}", path.display()))?;

    if bytes_removed == 0 {
        return Ok(PortableClearSignatureResponse {
            schema_version: SCHEMA_VERSION,
            path: path.to_path_buf(),
            format,
            signature_removed: false,
            bytes_removed,
            message: "No PE Authenticode certificate table found.".to_string(),
        });
    }

    std::fs::write(path, cleared).with_context(|| format!("write {}", path.display()))?;
    Ok(PortableClearSignatureResponse {
        schema_version: SCHEMA_VERSION,
        path: path.to_path_buf(),
        format,
        signature_removed: true,
        bytes_removed,
        message: "PE Authenticode certificate table removed.".to_string(),
    })
}

fn sign_cab(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let cab =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let provider = load_signing_provider(request)?;
    let digest_algorithm: AuthenticodeSigningDigest = request.hash_algorithm.into();
    let cab_digest =
        cab_digest::cab_authenticode_digest_for_signing(&cab, digest_algorithm.pe_hash_kind())?;
    let indirect = pkcs7::cab_spc_indirect_data(digest_algorithm, &cab_digest)?;
    let pkcs7 = provider
        .create_authenticode_pkcs7(indirect, digest_algorithm)
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
    let provider = load_signing_provider(request)?;
    let digest_algorithm: AuthenticodeSigningDigest = request.hash_algorithm.into();
    let msi_digest =
        msi_digest::compute_msi_authenticode_digest(&msi, digest_algorithm.pe_hash_kind())?;
    let indirect = pkcs7::msi_spc_indirect_data(digest_algorithm, &msi_digest)?;
    let pkcs7 = provider
        .create_authenticode_pkcs7(indirect, digest_algorithm)
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
    let provider = load_signing_provider(request)?;
    let digest_algorithm = request.hash_algorithm.into();
    let indirect = pkcs7::msix_spc_indirect_data(&staged, &ext, digest_algorithm)?;
    let pkcs7 = provider
        .create_authenticode_pkcs7(indirect, digest_algorithm)
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
    let provider = load_signing_provider(request)?;
    let pkcs7 = create_script_authenticode_pkcs7_with_provider(
        &provider,
        &script,
        request.hash_algorithm.into(),
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
    let provider = load_signing_provider(request)?;
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
    let pkcs7_detached = provider
        .create_pkcs7_signed_data(
            id_data,
            &econtent_der,
            request.hash_algorithm.into(),
            pkcs7::Pkcs7ContentMode::Detached,
        )
        .with_context(|| format!("create NuGet CMS signature for {}", request.path.display()))?;
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
    let provider = load_signing_provider(request)?;
    let vsix_alg = match request.hash_algorithm {
        PortableDigestAlgorithm::Sha256 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha256,
        PortableDigestAlgorithm::Sha384 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha384,
        PortableDigestAlgorithm::Sha512 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha512,
    };
    let signed_info = psign_opc_sign::vsix::signed_info_xml(Cursor::new(data.clone()), vsix_alg)
        .with_context(|| format!("create VSIX SignedInfo XML for {}", request.path.display()))?;
    let (signature, cert_der) = provider.sign_xml_signed_info(vsix_alg, &signed_info)?;
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
    let provider = load_signing_provider(request)?;
    let vsix_alg = match request.hash_algorithm {
        PortableDigestAlgorithm::Sha256 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha256,
        PortableDigestAlgorithm::Sha384 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha384,
        PortableDigestAlgorithm::Sha512 => psign_opc_sign::vsix::VsixHashAlgorithm::Sha512,
    };
    let unsigned = remove_clickonce_xml_signature(text);
    let signed_info = clickonce_manifest_signed_info_xml_bytes(&unsigned, vsix_alg);
    let (signature, cert_der) = provider.sign_xml_signed_info(vsix_alg, &signed_info)?;
    let signature_xml = build_clickonce_signature_xml(&signed_info, &signature, &cert_der);
    let signed = insert_clickonce_signature_in_manifest(&unsigned, &signature_xml)?;
    std::fs::write(output_path, signed.as_bytes())
        .with_context(|| format!("write {}", output_path.display()))
}

fn sign_appinstaller(request: &PortableSignRequest, output_path: &Path) -> Result<()> {
    let data =
        std::fs::read(&request.path).with_context(|| format!("read {}", request.path.display()))?;
    let provider = load_signing_provider(request)?;
    // Create a detached CMS over the descriptor content
    let econtent_der = der_encode_octet_string(&data)?;
    let id_data = der::asn1::ObjectIdentifier::new_unwrap(pkcs7::PKCS7_ID_DATA_OID);
    let pkcs7_detached = provider
        .create_pkcs7_signed_data(
            id_data,
            &econtent_der,
            request.hash_algorithm.into(),
            pkcs7::Pkcs7ContentMode::Detached,
        )
        .with_context(|| {
            format!(
                "create detached PKCS#7 companion signature for {}",
                request.path.display()
            )
        })?;
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
    let ext = script_extension_for(&request.path);
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
    let provider = load_signing_provider(request)?;
    let pkcs7 = create_script_authenticode_pkcs7_with_provider(
        &provider,
        &script,
        request.hash_algorithm.into(),
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
    let signed = append_script_signature_block(script, &block);
    std::fs::write(output_path, signed).with_context(|| format!("write {}", output_path.display()))
}

fn append_script_signature_block(mut script: Vec<u8>, block: &str) -> Vec<u8> {
    if script.starts_with(&[0xFF, 0xFE]) {
        for unit in block.encode_utf16() {
            script.extend_from_slice(&unit.to_le_bytes());
        }
    } else if script.starts_with(&[0xFE, 0xFF]) {
        for unit in block.encode_utf16() {
            script.extend_from_slice(&unit.to_be_bytes());
        }
    } else {
        script.extend_from_slice(block.as_bytes());
    }
    script
}

fn create_script_authenticode_pkcs7_with_provider(
    provider: &SigningProvider,
    script: &[u8],
    digest_algorithm: AuthenticodeSigningDigest,
) -> Result<Vec<u8>> {
    let indirect = pkcs7::script_authenticode_spc_indirect_data(script, digest_algorithm)?;
    provider.create_authenticode_pkcs7(indirect, digest_algorithm)
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
    ensure_local_signing_provider(request)?;

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
    let chain = load_chain_certificates(request)?;

    Ok((signer_cert, private_key, chain))
}

fn load_chain_certificates(request: &PortableSignRequest) -> Result<Vec<x509_cert::Certificate>> {
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
    Ok(chain)
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
            let extension = script_extension_for(&request.path);
            trust_verify_script_bytes(data, &extension, &opts).map(|r| {
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
            let mut summary = inspect
                .ok()
                .map(|r| summarize_pkcs7_reports(r.entries.into_iter().map(|e| e.pkcs7)))
                .unwrap_or_default();
            summary.pkcs7_der_base64 =
                pe_nth_pkcs7_signed_data_der(data, result.matched_attribute_certificate_index)
                    .ok()
                    .map(|der| base64::engine::general_purpose::STANDARD.encode(der));
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
                pkcs7_der_base64: summary.pkcs7_der_base64,
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
                .and_then(summarize_pkcs7_der)
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
                .and_then(|pkcs7| summarize_pkcs7_der(&pkcs7))
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
                .and_then(|pkcs7| summarize_pkcs7_der(&pkcs7))
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
    let summary = summarize_pkcs7_der(&pkcs7).unwrap_or_default();
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
        pkcs7_der_base64: summary.pkcs7_der_base64,
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
    let summary = summarize_pkcs7_der(&sig_bytes).unwrap_or_default();
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
        pkcs7_der_base64: summary.pkcs7_der_base64,
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
    let summary = summarize_pkcs7_der(&pkcs7_bytes).unwrap_or_default();
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
        pkcs7_der_base64: summary.pkcs7_der_base64,
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
    let ext = script_extension_for(path);
    match verify_script_digest_consistency(data, &ext) {
        Ok(()) => {
            let report = if ps_script::is_wsh_extension(&ext.to_ascii_lowercase()) {
                None
            } else {
                ps_script::powershell_class_digest_report(data, &ext)
                    .ok()
                    .and_then(|r| summarize_pkcs7_der(&r.pkcs7_der))
            };
            let summary = report.unwrap_or_default();
            Ok(PortableSignatureResponse {
                schema_version: SCHEMA_VERSION,
                path: path.to_path_buf(),
                format: infer_script_response_format(path),
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
                pkcs7_der_base64: summary.pkcs7_der_base64,
                diagnostics: Vec::new(),
            })
        }
        Err(error) => Ok(map_digest_error(
            path,
            infer_script_response_format(path),
            error,
        )),
    }
}

fn infer_script_response_format(path: &Path) -> PortableFileFormat {
    infer_powershell_source_format(path)
}

fn inspect_pkcs7_file(
    path: &Path,
    format: PortableFileFormat,
) -> Result<PortableSignatureResponse> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if pkcs7::parse_pkcs7_signed_data_der(&data)
        .ok()
        .is_some_and(|sd| sd.signer_infos.0.is_empty())
    {
        let mut response = base_response(
            path.to_path_buf(),
            format,
            PortableSignatureStatus::NotSigned,
            "PKCS#7 SignedData has no SignerInfo.",
        );
        response.pkcs7_der_base64 = Some(base64::engine::general_purpose::STANDARD.encode(&data));
        return Ok(response);
    }
    match inspect_authenticode_pkcs7_der(&data) {
        Ok(report) => {
            let mut summary = summarize_pkcs7_reports(std::iter::once(report));
            summary.pkcs7_der_base64 =
                Some(base64::engine::general_purpose::STANDARD.encode(&data));
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
                pkcs7_der_base64: summary.pkcs7_der_base64,
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
    pkcs7_der_base64: Option<String>,
    signer_index: Option<usize>,
    signer_certificate_der_base64: Option<String>,
    timestamper_certificate_der_base64: Option<String>,
    embedded_certificate_count: usize,
}

fn summarize_pkcs7_der(pkcs7_der: &[u8]) -> Option<Pkcs7Summary> {
    inspect_authenticode_pkcs7_der(pkcs7_der)
        .ok()
        .map(|report| {
            let mut summary = summarize_pkcs7_reports(std::iter::once(report));
            summary.pkcs7_der_base64 =
                Some(base64::engine::general_purpose::STANDARD.encode(pkcs7_der));
            summary
        })
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
        pkcs7_der_base64: summary.pkcs7_der_base64,
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
        pkcs7_der_base64: None,
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
        pkcs7_der_base64: None,
        diagnostics: Vec::new(),
    }
}

fn looks_unsigned(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("not found")
        || lower.contains("not signed")
        || lower.contains("no certificate table")
        || lower.contains("no pkcs#7")
        || lower.contains("no signerinfo")
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
    fn appends_script_signature_block_using_source_utf16_encoding() {
        let block = "\r\n# SIG # Begin signature block\r\n";
        let signed_le = append_script_signature_block(vec![0xFF, 0xFE, b'x', 0], block);
        assert_eq!(&signed_le[..4], &[0xFF, 0xFE, b'x', 0]);
        assert_eq!(
            String::from_utf16(
                &signed_le[2..]
                    .chunks_exact(2)
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                    .collect::<Vec<_>>()
            )
            .expect("UTF-16LE script"),
            format!("x{block}")
        );

        let signed_be = append_script_signature_block(vec![0xFE, 0xFF, 0, b'x'], block);
        assert_eq!(&signed_be[..4], &[0xFE, 0xFF, 0, b'x']);
        assert_eq!(
            String::from_utf16(
                &signed_be[2..]
                    .chunks_exact(2)
                    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                    .collect::<Vec<_>>()
            )
            .expect("UTF-16BE script"),
            format!("x{block}")
        );
    }

    #[test]
    fn infers_powershell_source_extensions() {
        assert_eq!(
            infer_powershell_source_format(Path::new(".ps1")),
            PortableFileFormat::PowerShellScript
        );
        assert_eq!(
            infer_powershell_source_format(Path::new("psm1")),
            PortableFileFormat::PowerShellScript
        );
        assert_eq!(
            infer_powershell_source_format(Path::new("unknown")),
            PortableFileFormat::Unknown
        );
    }

    #[test]
    fn detects_extensionless_pe_from_magic() {
        let pe = std::fs::read("../../tests/fixtures/pe-authenticode-upstream/tiny32.efi")
            .expect("read PE fixture");
        assert_eq!(
            infer_format_from_path_or_data(Path::new("extensionless"), &pe),
            PortableFileFormat::Pe
        );
    }

    #[test]
    fn validates_unsigned_powershell_content_without_temp_file() {
        let request = PortableValidatePowerShellRequest {
            source_path_or_extension: PathBuf::from(".ps1"),
            content_base64: base64::engine::general_purpose::STANDARD
                .encode(b"Write-Output 'unsigned'\n"),
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
        };
        let response = portable_validate_powershell_script(request).expect("validate content");
        assert_eq!(response.status, PortableSignatureStatus::NotSigned);
        assert_eq!(response.format, PortableFileFormat::PowerShellScript);
    }

    #[test]
    fn creates_and_tests_portable_file_catalog_with_relative_paths() {
        let temp_dir = std::env::temp_dir().join(format!(
            "psign-file-catalog-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(temp_dir.join("sub")).expect("create temp dir");
        std::fs::write(temp_dir.join("a.txt"), b"alpha").expect("write a");
        std::fs::write(temp_dir.join("sub").join("b.txt"), b"bravo").expect("write b");
        let catalog_path = temp_dir.join("catalog.cat");

        let created = portable_new_file_catalog(PortableNewFileCatalogRequest {
            catalog_file_path: catalog_path.clone(),
            paths: vec![temp_dir.clone()],
            catalog_version: 2,
        })
        .expect("create catalog");
        assert_eq!(created.catalog_version, 2);
        assert_eq!(created.hash_algorithm, "SHA256");
        assert_eq!(created.item_count, 2);
        assert!(
            created
                .catalog_items
                .iter()
                .any(|item| item.path == "a.txt")
        );
        assert!(
            created
                .catalog_items
                .iter()
                .any(|item| item.path == "sub/b.txt")
        );

        let tested = portable_test_file_catalog(default_catalog_test_request(
            catalog_path.clone(),
            vec![temp_dir.clone()],
            Vec::new(),
        ))
        .expect("test catalog");
        assert_eq!(tested.status, PortableCatalogValidationStatus::Valid);
        assert_eq!(tested.signature.status, PortableSignatureStatus::NotSigned);
        assert_eq!(tested.path_items.len(), 2);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    #[test]
    fn file_catalog_reports_tamper_and_supports_skip() {
        let temp_dir = std::env::temp_dir().join(format!(
            "psign-file-catalog-tamper-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        let file_path = temp_dir.join("a.txt");
        std::fs::write(&file_path, b"alpha").expect("write a");
        let catalog_path = temp_dir.join("catalog.cat");
        portable_new_file_catalog(PortableNewFileCatalogRequest {
            catalog_file_path: catalog_path.clone(),
            paths: vec![temp_dir.clone()],
            catalog_version: 2,
        })
        .expect("create catalog");
        std::fs::write(&file_path, b"tampered").expect("tamper a");

        let failed = portable_test_file_catalog(default_catalog_test_request(
            catalog_path.clone(),
            vec![temp_dir.clone()],
            Vec::new(),
        ))
        .expect("test tampered catalog");
        assert_eq!(
            failed.status,
            PortableCatalogValidationStatus::ValidationFailed
        );
        assert!(failed.path_items.iter().any(|item| {
            item.path == "a.txt" && item.status == PortableCatalogItemStatus::HashMismatch
        }));

        let skipped = portable_test_file_catalog(default_catalog_test_request(
            catalog_path.clone(),
            vec![temp_dir.clone()],
            vec!["a.txt".to_string()],
        ))
        .expect("test skipped catalog");
        assert_eq!(skipped.status, PortableCatalogValidationStatus::Valid);
        assert_eq!(skipped.skipped_items, vec!["a.txt".to_string()]);

        std::fs::remove_dir_all(temp_dir).expect("remove temp dir");
    }

    fn default_catalog_test_request(
        catalog_file_path: PathBuf,
        paths: Vec<PathBuf>,
        files_to_skip: Vec<String>,
    ) -> PortableTestFileCatalogRequest {
        PortableTestFileCatalogRequest {
            catalog_file_path,
            paths,
            files_to_skip,
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

    #[test]
    fn validates_signed_powershell_content_with_explicit_trust() {
        let temp_dir = std::env::temp_dir().join(format!(
            "psign-portable-script-trust-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        let script_path = temp_dir.join("trusted.ps1");
        let signed_path = temp_dir.join("trusted.signed.ps1");
        std::fs::write(&script_path, b"Write-Output 'trusted'\r\n").expect("write script");

        let fixture_dir = PathBuf::from("../../tests/fixtures/devolutions-authenticode");
        let sign_request = PortableSignRequest {
            path: script_path,
            output_path: Some(signed_path.clone()),
            pfx_path: Some(fixture_dir.join("authenticode-test-cert.pfx")),
            pfx_password: Some("CodeSign123!".to_string()),
            chain_certificate_paths: vec![fixture_dir.join("authenticode-test-ca.crt")],
            ..default_sign_request()
        };
        portable_sign(sign_request).expect("sign script");

        let signed = std::fs::read(&signed_path).expect("read signed script");
        let validate_request = PortableValidatePowerShellRequest {
            source_path_or_extension: PathBuf::from(".ps1"),
            content_base64: base64::engine::general_purpose::STANDARD.encode(signed),
            trusted_certificate_paths: vec![fixture_dir.join("authenticode-test-ca.crt")],
            trusted_certificates_der_base64: Vec::new(),
            anchor_directory: None,
            authroot_cab: None,
            as_of: None,
            prefer_timestamp_signing_time: false,
            require_valid_timestamp: false,
            online_aia: false,
            online_ocsp: false,
            revocation_mode: PortableRevocationMode::Off,
        };
        let response =
            portable_validate_powershell_script(validate_request).expect("validate signed script");
        assert_eq!(response.status, PortableSignatureStatus::Valid);
        assert_eq!(response.trust_status, Some(PortableSignatureStatus::Valid));
        assert!(response.signer_certificate_der_base64.is_some());

        let _ = std::fs::remove_dir_all(temp_dir);
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
        assert!(response.pkcs7_der_base64.is_some());
    }

    #[test]
    fn pe_sign_replace_vs_append_signature_count() {
        let temp_dir = std::env::temp_dir().join(format!(
            "psign-portable-pe-append-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let source =
            PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let replaced = temp_dir.join("tiny32.replaced.efi");
        let appended = temp_dir.join("tiny32.appended.efi");
        let fixture_dir = PathBuf::from("../../tests/fixtures/devolutions-authenticode");

        portable_sign(PortableSignRequest {
            path: source.clone(),
            output_path: Some(replaced.clone()),
            pfx_path: Some(fixture_dir.join("authenticode-test-cert.pfx")),
            pfx_password: Some("CodeSign123!".to_string()),
            ..default_sign_request()
        })
        .expect("replace PE signature");

        portable_sign(PortableSignRequest {
            path: source,
            append_signature: true,
            output_path: Some(appended.clone()),
            pfx_path: Some(fixture_dir.join("authenticode-test-cert.pfx")),
            pfx_password: Some("CodeSign123!".to_string()),
            ..default_sign_request()
        })
        .expect("append PE signature");

        let replaced_signature =
            portable_get_signature(PortableGetSignatureRequest::path_only(replaced))
                .expect("inspect replaced PE");
        let appended_signature =
            portable_get_signature(PortableGetSignatureRequest::path_only(appended))
                .expect("inspect appended PE");

        assert_eq!(replaced_signature.signature_count, 1);
        assert_eq!(appended_signature.signature_count, 2);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn pe_sign_skip_signed_signs_unsigned_and_skips_valid_pe() {
        let temp_dir = std::env::temp_dir().join(format!(
            "psign-portable-pe-skip-signed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let fixture_dir = PathBuf::from("../../tests/fixtures/devolutions-authenticode");
        let unsigned_source =
            PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.efi");
        let signed_source =
            PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let unsigned = temp_dir.join("tiny32.unsigned.efi");
        let already_signed = temp_dir.join("tiny32.already-signed.efi");
        std::fs::copy(&unsigned_source, &unsigned).expect("copy unsigned PE");
        std::fs::copy(&signed_source, &already_signed).expect("copy signed PE");

        let signed_response = portable_sign(PortableSignRequest {
            path: unsigned.clone(),
            skip_signed: true,
            pfx_path: Some(fixture_dir.join("authenticode-test-cert.pfx")),
            pfx_password: Some("CodeSign123!".to_string()),
            ..default_sign_request()
        })
        .expect("sign unsigned PE with skip-signed");
        assert!(!signed_response.skipped);
        assert_eq!(signed_response.signature.signature_count, 1);

        let before = std::fs::read(&already_signed).expect("read already signed PE before skip");
        let skipped_response = portable_sign(PortableSignRequest {
            path: already_signed.clone(),
            skip_signed: true,
            pfx_path: Some(fixture_dir.join("authenticode-test-cert.pfx")),
            pfx_password: Some("CodeSign123!".to_string()),
            ..default_sign_request()
        })
        .expect("skip already signed PE");
        let after = std::fs::read(&already_signed).expect("read already signed PE after skip");
        assert!(skipped_response.skipped);
        assert_eq!(before, after);
        assert_eq!(skipped_response.signature.signature_count, 1);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn pe_sign_skip_signed_copies_valid_pe_to_output_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "psign-portable-pe-skip-copy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let fixture_dir = PathBuf::from("../../tests/fixtures/devolutions-authenticode");
        let signed_source =
            PathBuf::from("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let output = temp_dir.join("tiny32.output.efi");

        let skipped_response = portable_sign(PortableSignRequest {
            path: signed_source.clone(),
            output_path: Some(output.clone()),
            skip_signed: true,
            pfx_path: Some(fixture_dir.join("authenticode-test-cert.pfx")),
            pfx_password: Some("CodeSign123!".to_string()),
            ..default_sign_request()
        })
        .expect("copy skipped PE to output path");

        assert!(skipped_response.skipped);
        assert_eq!(
            std::fs::read(&signed_source).expect("read signed source"),
            std::fs::read(&output).expect("read copied output")
        );
        assert_eq!(skipped_response.signature.signature_count, 1);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn pe_sign_skip_signed_rejects_corrupt_existing_signature() {
        let temp_dir = std::env::temp_dir().join(format!(
            "psign-portable-pe-skip-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        let fixture_dir = PathBuf::from("../../tests/fixtures/devolutions-authenticode");
        let target = temp_dir.join("tiny32.corrupt-signed.efi");
        let mut corrupt =
            std::fs::read("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .expect("read signed PE");
        tamper_hashed_pe_byte(&mut corrupt);
        verify_pe_authenticode_digest_consistency(&corrupt)
            .expect_err("tampered PE should fail digest verification");
        std::fs::write(&target, &corrupt).expect("write corrupt signed PE");

        let err = portable_sign(PortableSignRequest {
            path: target.clone(),
            skip_signed: true,
            pfx_path: Some(fixture_dir.join("authenticode-test-cert.pfx")),
            pfx_password: Some("CodeSign123!".to_string()),
            ..default_sign_request()
        })
        .expect_err("corrupt signed PE should not be skipped");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("check existing PE/WinMD Authenticode signature"),
            "unexpected error: {msg}"
        );
        assert!(msg.contains("mismatch"), "unexpected error: {msg}");
        assert_eq!(
            std::fs::read(&target).expect("read corrupt PE after failed skip"),
            corrupt
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    fn tamper_hashed_pe_byte(bytes: &mut [u8]) {
        let ranges =
            pe_digest::pe_authenticode_digest_file_ranges(bytes).expect("PE digest file ranges");
        let offset = ranges
            .into_iter()
            .rev()
            .find(|range| !range.is_empty())
            .expect("non-empty PE digest range")
            .start;
        bytes[offset] ^= 0x01;
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
            append_signature: false,
            skip_signed: false,
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
            azure_key_vault_certificate_version: None,
            azure_key_vault_access_token: None,
            azure_key_vault_client_id: None,
            azure_key_vault_client_secret: None,
            azure_key_vault_tenant_id: None,
            azure_key_vault_managed_identity: None,
            azure_authority: None,
            artifact_signing_endpoint: None,
            artifact_signing_account_name: None,
            artifact_signing_profile_name: None,
            artifact_signing_access_token: None,
            artifact_signing_managed_identity: None,
            artifact_signing_managed_identity_resource_id: None,
            artifact_signing_credential_type: None,
            artifact_signing_tenant_id: None,
            artifact_signing_client_id: None,
            artifact_signing_client_secret: None,
            artifact_signing_federated_token_file: None,
            artifact_signing_exclude_credentials: Vec::new(),
        }
    }
}
