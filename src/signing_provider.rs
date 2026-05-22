use crate::cli::{AzureCredentialType, DigestAlgorithm, SignArgs};
use anyhow::{Result, anyhow};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningProviderKind {
    PortableStore,
    Pfx,
    WindowsStore,
    AzureKeyVault,
    ArtifactSigning,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SigningProviderConfig {
    pub kind: SigningProviderKind,
    pub digest_algorithm: String,
    pub timestamp_url: Option<String>,
    pub timestamp_digest_algorithm: Option<String>,
    pub identity: SigningProviderIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SigningProviderIdentity {
    PortableStore {
        thumbprint_sha1: String,
        machine_store: bool,
        store_name: String,
        cert_store_dir: Option<PathBuf>,
    },
    Pfx {
        pfx: PathBuf,
    },
    WindowsStore {
        auto_select: bool,
        subject_name: Option<String>,
        issuer_name: Option<String>,
        thumbprint_sha1: Option<String>,
        machine_store: bool,
        store_name: String,
    },
    AzureKeyVault {
        vault_url: String,
        certificate: String,
        certificate_version: Option<String>,
        auth: AzureAuthConfig,
    },
    ArtifactSigning {
        metadata: Option<PathBuf>,
        endpoint: Option<String>,
        region: Option<String>,
        account_name: Option<String>,
        profile_name: Option<String>,
        auth: AzureAuthConfig,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum AzureAuthConfig {
    AccessToken {
        authority: Option<String>,
    },
    ClientSecret {
        tenant_id: Option<String>,
        client_id: Option<String>,
        authority: Option<String>,
    },
    ManagedIdentity {
        client_id: Option<String>,
        authority: Option<String>,
    },
    WorkloadIdentity {
        tenant_id: Option<String>,
        client_id: Option<String>,
        authority: Option<String>,
    },
    Ambient {
        authority: Option<String>,
    },
}

pub trait SigningProvider {
    fn kind(&self) -> SigningProviderKind;
    fn certificate_chain_der(&self) -> Result<Vec<Vec<u8>>>;
    fn sign_digest(&self, digest_algorithm: DigestAlgorithm, digest: &[u8]) -> Result<Vec<u8>>;
}

impl SigningProviderConfig {
    pub fn from_sign_args(args: &SignArgs) -> Result<Self> {
        let azure_key_vault = azure_key_vault_requested(args);
        let artifact_signing = artifact_signing_requested(args);
        if azure_key_vault && artifact_signing {
            return Err(anyhow!(
                "signing provider options are ambiguous: choose either Azure Key Vault or Artifact Signing"
            ));
        }

        let timestamp_url = args
            .timestamp_url
            .clone()
            .or_else(|| args.seal_timestamp_url.clone())
            .or_else(|| args.legacy_timestamp_url.clone());
        let timestamp_digest_algorithm = args.timestamp_digest.map(digest_name).map(str::to_owned);

        if azure_key_vault {
            require_remote_digest(args.digest, "Azure Key Vault")?;
            let vault_url =
                required_text("--azure-key-vault-url", args.azure_key_vault_url.as_deref())?;
            let certificate = required_text(
                "--azure-key-vault-certificate",
                args.azure_key_vault_certificate.as_deref(),
            )?;
            return Ok(Self {
                kind: SigningProviderKind::AzureKeyVault,
                digest_algorithm: digest_name(args.digest).to_owned(),
                timestamp_url,
                timestamp_digest_algorithm,
                identity: SigningProviderIdentity::AzureKeyVault {
                    vault_url,
                    certificate,
                    certificate_version: trim_opt(&args.azure_key_vault_certificate_version),
                    auth: azure_auth(
                        args.azure_key_vault_credential_type,
                        args.azure_key_vault_access_token.as_deref(),
                        args.azure_key_vault_managed_identity,
                        args.azure_key_vault_tenant_id.as_deref(),
                        args.azure_key_vault_client_id.as_deref(),
                        args.azure_key_vault_client_secret.as_deref(),
                        args.azure_authority.as_deref(),
                    ),
                },
            });
        }

        if artifact_signing {
            require_remote_digest(args.digest, "Artifact Signing")?;
            return Ok(Self {
                kind: SigningProviderKind::ArtifactSigning,
                digest_algorithm: digest_name(args.digest).to_owned(),
                timestamp_url,
                timestamp_digest_algorithm,
                identity: SigningProviderIdentity::ArtifactSigning {
                    metadata: args
                        .artifact_signing_metadata
                        .clone()
                        .or_else(|| args.dmdf.clone()),
                    endpoint: trim_opt(&args.artifact_signing_endpoint),
                    region: trim_opt(&args.artifact_signing_region),
                    account_name: trim_opt(&args.artifact_signing_account_name),
                    profile_name: trim_opt(&args.artifact_signing_profile_name),
                    auth: azure_auth(
                        args.artifact_signing_credential_type,
                        args.artifact_signing_access_token.as_deref(),
                        args.artifact_signing_managed_identity,
                        args.artifact_signing_tenant_id.as_deref(),
                        args.artifact_signing_client_id.as_deref(),
                        args.artifact_signing_client_secret.as_deref(),
                        args.artifact_signing_authority.as_deref(),
                    ),
                },
            });
        }

        if let Some(pfx) = &args.pfx {
            if args.cert_sha1.is_some()
                || args.auto_select
                || text_present(&args.subject_name)
                || text_present(&args.issuer_name)
            {
                return Err(anyhow!(
                    "signing provider options are ambiguous: do not combine --pfx with certificate store selection options"
                ));
            }
            return Ok(Self {
                kind: SigningProviderKind::Pfx,
                digest_algorithm: digest_name(args.digest).to_owned(),
                timestamp_url,
                timestamp_digest_algorithm,
                identity: SigningProviderIdentity::Pfx { pfx: pfx.clone() },
            });
        }

        if let Some(thumbprint_sha1) = trim_opt(&args.cert_sha1) {
            return Ok(Self {
                kind: SigningProviderKind::PortableStore,
                digest_algorithm: digest_name(args.digest).to_owned(),
                timestamp_url,
                timestamp_digest_algorithm,
                identity: SigningProviderIdentity::PortableStore {
                    thumbprint_sha1,
                    machine_store: args.machine_store,
                    store_name: args.store_name.clone(),
                    cert_store_dir: args.cert_store_dir.clone(),
                },
            });
        }

        if args.auto_select || text_present(&args.subject_name) || text_present(&args.issuer_name) {
            return Ok(Self {
                kind: SigningProviderKind::WindowsStore,
                digest_algorithm: digest_name(args.digest).to_owned(),
                timestamp_url,
                timestamp_digest_algorithm,
                identity: SigningProviderIdentity::WindowsStore {
                    auto_select: args.auto_select,
                    subject_name: trim_opt(&args.subject_name),
                    issuer_name: trim_opt(&args.issuer_name),
                    thumbprint_sha1: trim_opt(&args.cert_sha1),
                    machine_store: args.machine_store,
                    store_name: args.store_name.clone(),
                },
            });
        }

        Err(anyhow!(
            "no signing provider selected; specify --sha1, --pfx, Windows store selection, Azure Key Vault, or Artifact Signing options"
        ))
    }
}

fn azure_key_vault_requested(args: &SignArgs) -> bool {
    text_present(&args.azure_key_vault_url)
        || text_present(&args.azure_key_vault_certificate)
        || text_present(&args.azure_key_vault_certificate_version)
        || text_present(&args.azure_key_vault_client_id)
        || text_present(&args.azure_key_vault_client_secret)
        || text_present(&args.azure_key_vault_tenant_id)
        || text_present(&args.azure_key_vault_access_token)
        || args.azure_key_vault_managed_identity
        || args.azure_key_vault_credential_type.is_some()
        || text_present(&args.azure_authority)
}

fn artifact_signing_requested(args: &SignArgs) -> bool {
    args.artifact_signing_metadata.is_some()
        || args.dmdf.is_some()
        || args.trusted_signing_dlib_root.is_some()
        || text_present(&args.artifact_signing_region)
        || text_present(&args.artifact_signing_endpoint)
        || text_present(&args.artifact_signing_account_name)
        || text_present(&args.artifact_signing_profile_name)
        || text_present(&args.artifact_signing_signature_algorithm)
        || text_present(&args.artifact_signing_api_version)
        || text_present(&args.artifact_signing_correlation_id)
        || text_present(&args.artifact_signing_access_token)
        || args.artifact_signing_managed_identity
        || args.artifact_signing_credential_type.is_some()
        || text_present(&args.artifact_signing_tenant_id)
        || text_present(&args.artifact_signing_client_id)
        || text_present(&args.artifact_signing_client_secret)
        || text_present(&args.artifact_signing_authority)
        || text_present(&args.artifact_signing_endpoint_base_url)
}

fn azure_auth(
    credential_type: Option<AzureCredentialType>,
    access_token: Option<&str>,
    managed_identity: bool,
    tenant_id: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    authority: Option<&str>,
) -> AzureAuthConfig {
    let authority = trim_str(authority).map(str::to_owned);
    match credential_type.unwrap_or(AzureCredentialType::Default) {
        AzureCredentialType::AccessToken => AzureAuthConfig::AccessToken { authority },
        AzureCredentialType::ManagedIdentity => AzureAuthConfig::ManagedIdentity {
            client_id: trim_str(client_id).map(str::to_owned),
            authority,
        },
        AzureCredentialType::ClientSecret => AzureAuthConfig::ClientSecret {
            tenant_id: trim_str(tenant_id).map(str::to_owned),
            client_id: trim_str(client_id).map(str::to_owned),
            authority,
        },
        AzureCredentialType::WorkloadIdentity => AzureAuthConfig::WorkloadIdentity {
            tenant_id: trim_str(tenant_id).map(str::to_owned),
            client_id: trim_str(client_id).map(str::to_owned),
            authority,
        },
        AzureCredentialType::Default => {
            if trim_str(access_token).is_some() {
                AzureAuthConfig::AccessToken { authority }
            } else if managed_identity {
                AzureAuthConfig::ManagedIdentity {
                    client_id: trim_str(client_id).map(str::to_owned),
                    authority,
                }
            } else if trim_str(client_secret).is_some() {
                AzureAuthConfig::ClientSecret {
                    tenant_id: trim_str(tenant_id).map(str::to_owned),
                    client_id: trim_str(client_id).map(str::to_owned),
                    authority,
                }
            } else {
                AzureAuthConfig::Ambient { authority }
            }
        }
    }
}

fn required_text(name: &str, value: Option<&str>) -> Result<String> {
    trim_str(value)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{name} is required for the selected signing provider"))
}

fn require_remote_digest(digest: DigestAlgorithm, provider: &str) -> Result<()> {
    match digest {
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512 => Ok(()),
        DigestAlgorithm::Sha1 | DigestAlgorithm::CertHash => Err(anyhow!(
            "{provider} supports only SHA256, SHA384, or SHA512 file digests"
        )),
    }
}

fn digest_name(digest: DigestAlgorithm) -> &'static str {
    match digest {
        DigestAlgorithm::Sha1 => "sha1",
        DigestAlgorithm::Sha256 => "sha256",
        DigestAlgorithm::Sha384 => "sha384",
        DigestAlgorithm::Sha512 => "sha512",
        DigestAlgorithm::CertHash => "cert-hash",
    }
}

fn text_present(value: &Option<String>) -> bool {
    trim_opt(value).is_some()
}

fn trim_opt(value: &Option<String>) -> Option<String> {
    trim_str(value.as_deref()).map(str::to_owned)
}

fn trim_str(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    #[test]
    fn selects_portable_store_from_sha1() {
        let args = sign_args(["psign-tool", "sign", "--sha1", "ABC", "file.exe"]);
        let provider = SigningProviderConfig::from_sign_args(args).unwrap();
        assert_eq!(provider.kind, SigningProviderKind::PortableStore);
    }

    #[test]
    fn rejects_mixed_cloud_provider_options() {
        let args = sign_args([
            "psign-tool",
            "sign",
            "--azure-key-vault-url",
            "https://vault.example",
            "--azure-key-vault-certificate",
            "cert",
            "--artifact-signing-profile-name",
            "profile",
            "file.exe",
        ]);
        let err = SigningProviderConfig::from_sign_args(args).unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[test]
    fn artifact_signing_uses_client_secret_auth_shape() {
        let args = sign_args([
            "psign-tool",
            "sign",
            "--artifact-signing-endpoint",
            "https://westus.codesigning.azure.net",
            "--artifact-signing-account-name",
            "acct",
            "--artifact-signing-profile-name",
            "profile",
            "--artifact-signing-tenant-id",
            "tenant",
            "--artifact-signing-client-id",
            "client",
            "--artifact-signing-client-secret",
            "secret",
            "file.exe",
        ]);
        let provider = SigningProviderConfig::from_sign_args(args).unwrap();
        assert_eq!(provider.kind, SigningProviderKind::ArtifactSigning);
        match provider.identity {
            SigningProviderIdentity::ArtifactSigning {
                auth: AzureAuthConfig::ClientSecret { client_id, .. },
                ..
            } => assert_eq!(client_id.as_deref(), Some("client")),
            other => panic!("unexpected identity: {other:?}"),
        }
    }

    #[test]
    fn azure_credential_type_managed_identity_maps_to_managed_identity_auth() {
        let args = sign_args([
            "psign-tool",
            "sign",
            "--azure-key-vault-url",
            "https://vault.example",
            "--azure-key-vault-certificate",
            "cert",
            "--azure-key-vault-credential-type",
            "managed-identity",
            "--azure-key-vault-client-id",
            "user-assigned-client",
            "file.exe",
        ]);
        let provider = SigningProviderConfig::from_sign_args(args).unwrap();

        match provider.identity {
            SigningProviderIdentity::AzureKeyVault {
                auth: AzureAuthConfig::ManagedIdentity { client_id, .. },
                ..
            } => assert_eq!(client_id.as_deref(), Some("user-assigned-client")),
            other => panic!("unexpected identity: {other:?}"),
        }
    }

    #[test]
    fn azure_credential_type_workload_identity_is_represented_for_planning() {
        let args = sign_args([
            "psign-tool",
            "sign",
            "--artifact-signing-endpoint",
            "https://westus.codesigning.azure.net",
            "--artifact-signing-account-name",
            "acct",
            "--artifact-signing-profile-name",
            "profile",
            "--artifact-signing-credential-type",
            "workload-identity",
            "--artifact-signing-tenant-id",
            "tenant",
            "--artifact-signing-client-id",
            "client",
            "file.exe",
        ]);
        let provider = SigningProviderConfig::from_sign_args(args).unwrap();

        match provider.identity {
            SigningProviderIdentity::ArtifactSigning {
                auth:
                    AzureAuthConfig::WorkloadIdentity {
                        tenant_id,
                        client_id,
                        ..
                    },
                ..
            } => {
                assert_eq!(tenant_id.as_deref(), Some("tenant"));
                assert_eq!(client_id.as_deref(), Some("client"));
            }
            other => panic!("unexpected identity: {other:?}"),
        }
    }

    fn sign_args<const N: usize>(argv: [&str; N]) -> &'static crate::cli::SignArgs {
        let cli = Cli::try_parse_from(argv).unwrap();
        let Command::Sign(args) = cli.command else {
            panic!("expected sign args");
        };
        Box::leak(Box::new(args))
    }
}
