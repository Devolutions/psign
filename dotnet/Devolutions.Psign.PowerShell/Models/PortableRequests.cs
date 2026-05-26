using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

internal sealed class PortableGetSignatureRequest
{
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("trusted_certificate_paths")]
    public string[] TrustedCertificatePaths { get; init; } = [];

    [JsonPropertyName("trusted_certificates_der_base64")]
    public string[] TrustedCertificatesDerBase64 { get; init; } = [];

    [JsonPropertyName("anchor_directory")]
    public string? AnchorDirectory { get; init; }

    [JsonPropertyName("authroot_cab")]
    public string? AuthRootCab { get; init; }

    [JsonPropertyName("as_of")]
    public string? AsOf { get; init; }

    [JsonPropertyName("prefer_timestamp_signing_time")]
    public bool PreferTimestampSigningTime { get; init; }

    [JsonPropertyName("require_valid_timestamp")]
    public bool RequireValidTimestamp { get; init; }

    [JsonPropertyName("online_aia")]
    public bool OnlineAia { get; init; }

    [JsonPropertyName("online_ocsp")]
    public bool OnlineOcsp { get; init; }

    [JsonPropertyName("revocation_mode")]
    public string RevocationMode { get; init; } = "Off";
}

internal sealed class PortableSignRequest
{
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("append_signature")]
    public bool AppendSignature { get; init; }

    [JsonPropertyName("output_path")]
    public string? OutputPath { get; init; }

    [JsonPropertyName("hash_algorithm")]
    public string HashAlgorithm { get; init; } = "Sha256";

    [JsonPropertyName("certificate_path")]
    public string? CertificatePath { get; init; }

    [JsonPropertyName("private_key_path")]
    public string? PrivateKeyPath { get; init; }

    [JsonPropertyName("certificate_der_base64")]
    public string? CertificateDerBase64 { get; init; }

    [JsonPropertyName("private_key_der_base64")]
    public string? PrivateKeyDerBase64 { get; init; }

    [JsonPropertyName("pfx_path")]
    public string? PfxPath { get; init; }

    [JsonPropertyName("pfx_password")]
    public string? PfxPassword { get; init; }

    [JsonPropertyName("chain_certificate_paths")]
    public string[] ChainCertificatePaths { get; init; } = [];

    [JsonPropertyName("chain_certificates_der_base64")]
    public string[] ChainCertificatesDerBase64 { get; init; } = [];

    [JsonPropertyName("timestamp_server")]
    public string? TimestampServer { get; init; }

    [JsonPropertyName("timestamp_hash_algorithm")]
    public string? TimestampHashAlgorithm { get; init; }

    // Azure Key Vault cloud signing
    [JsonPropertyName("azure_key_vault_url")]
    public string? AzureKeyVaultUrl { get; init; }

    [JsonPropertyName("azure_key_vault_certificate")]
    public string? AzureKeyVaultCertificate { get; init; }

    [JsonPropertyName("azure_key_vault_access_token")]
    public string? AzureKeyVaultAccessToken { get; init; }

    [JsonPropertyName("azure_key_vault_client_id")]
    public string? AzureKeyVaultClientId { get; init; }

    [JsonPropertyName("azure_key_vault_client_secret")]
    public string? AzureKeyVaultClientSecret { get; init; }

    [JsonPropertyName("azure_key_vault_tenant_id")]
    public string? AzureKeyVaultTenantId { get; init; }

    [JsonPropertyName("azure_key_vault_managed_identity")]
    public bool? AzureKeyVaultManagedIdentity { get; init; }

    // Azure Artifact Signing / Trusted Signing
    [JsonPropertyName("artifact_signing_endpoint")]
    public string? ArtifactSigningEndpoint { get; init; }

    [JsonPropertyName("artifact_signing_account_name")]
    public string? ArtifactSigningAccountName { get; init; }

    [JsonPropertyName("artifact_signing_profile_name")]
    public string? ArtifactSigningProfileName { get; init; }

    [JsonPropertyName("artifact_signing_access_token")]
    public string? ArtifactSigningAccessToken { get; init; }

    [JsonPropertyName("artifact_signing_managed_identity")]
    public bool? ArtifactSigningManagedIdentity { get; init; }

    [JsonPropertyName("artifact_signing_tenant_id")]
    public string? ArtifactSigningTenantId { get; init; }

    [JsonPropertyName("artifact_signing_client_id")]
    public string? ArtifactSigningClientId { get; init; }

    [JsonPropertyName("artifact_signing_client_secret")]
    public string? ArtifactSigningClientSecret { get; init; }
}

internal sealed class PortableClearSignatureRequest
{
    [JsonPropertyName("path")]
    public required string Path { get; init; }

}

internal sealed class PortableClearSignatureResponse
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("path")]
    public string Path { get; init; } = string.Empty;

    [JsonPropertyName("format")]
    public string Format { get; init; } = string.Empty;

    [JsonPropertyName("signature_removed")]
    public bool SignatureRemoved { get; init; }

    [JsonPropertyName("bytes_removed")]
    public int BytesRemoved { get; init; }

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}
