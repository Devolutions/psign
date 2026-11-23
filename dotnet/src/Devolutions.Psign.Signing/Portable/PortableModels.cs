using System.Text.Json;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Verification;

namespace Devolutions.Psign.Signing.Portable;

// JSON contract of `psign-portable-core` (serde): field names are snake_case, enums use their PascalCase variant names,
// `#[serde(default)]` request fields may be omitted, and response fields marked `skip_serializing_if` are left out when
// empty. Every model reads with `FromJson` and writes with `ToJsonNode` / `ToJson` in the Rust declaration order.

/// <summary>Detected file format (Rust <c>PortableFileFormat</c>).</summary>
public enum PortableFileFormat
{
    Pe,
    Cab,
    Msi,
    Msix,
    MsixUpload,
    MsixEncrypted,
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

/// <summary>Signature status (Rust <c>PortableSignatureStatus</c>).</summary>
public enum PortableSignatureStatus
{
    Valid,
    NotSigned,
    HashMismatch,
    NotTrusted,
    NotSupportedFileFormat,
    Incompatible,
    UnknownError,
}

/// <summary>File digest algorithm for signing (Rust <c>PortableDigestAlgorithm</c>; default <c>Sha256</c>).</summary>
public enum PortableDigestAlgorithm
{
    Sha256,
    Sha384,
    Sha512,
}

/// <summary>RFC 3161 imprint digest algorithm (Rust <c>PortableTimestampDigestAlgorithm</c>; default <c>Sha256</c>).</summary>
public enum PortableTimestampDigestAlgorithm
{
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// <summary>Revocation checking mode (Rust <c>PortableRevocationMode</c>; default <c>Off</c>).</summary>
public enum PortableRevocationMode
{
    Off,
    BestEffort,
    Require,
}

/// <summary>Catalog validation outcome (Rust <c>PortableCatalogValidationStatus</c>).</summary>
public enum PortableCatalogValidationStatus
{
    Valid,
    ValidationFailed,
}

/// <summary>Per-file catalog validation outcome (Rust <c>PortableCatalogItemStatus</c>).</summary>
public enum PortableCatalogItemStatus
{
    Valid,
    Missing,
    HashMismatch,
    NotInCatalog,
    Skipped,
}

/// <summary>Error category (Rust <c>PortableErrorCode</c>).</summary>
public enum PortableErrorCode
{
    InvalidRequest,
    Io,
    NotSupportedFileFormat,
    UnsupportedOperation,
    OperationFailed,
    Panic,
}

/// <summary>Conversions between the portable enums and the library types.</summary>
public static class PortableEnumExtensions
{
    /// <summary>Authenticode digest for <paramref name="value"/> (Rust <c>From&lt;PortableDigestAlgorithm&gt; for AuthenticodeSigningDigest</c>).</summary>
    public static AuthenticodeHashKind ToHashKind(this PortableDigestAlgorithm value) => value switch
    {
        PortableDigestAlgorithm.Sha384 => AuthenticodeHashKind.Sha384,
        PortableDigestAlgorithm.Sha512 => AuthenticodeHashKind.Sha512,
        _ => AuthenticodeHashKind.Sha256,
    };

    /// <summary>Hash algorithm for the RFC 3161 imprint.</summary>
    public static AuthenticodeHashKind ToHashKind(this PortableTimestampDigestAlgorithm value) => value switch
    {
        PortableTimestampDigestAlgorithm.Sha1 => AuthenticodeHashKind.Sha1,
        PortableTimestampDigestAlgorithm.Sha384 => AuthenticodeHashKind.Sha384,
        PortableTimestampDigestAlgorithm.Sha512 => AuthenticodeHashKind.Sha512,
        _ => AuthenticodeHashKind.Sha256,
    };

    /// <summary>Verification revocation mode (Rust <c>From&lt;PortableRevocationMode&gt; for RevocationMode</c>).</summary>
    public static RevocationMode ToRevocationMode(this PortableRevocationMode value) => value switch
    {
        PortableRevocationMode.BestEffort => RevocationMode.BestEffort,
        PortableRevocationMode.Require => RevocationMode.Require,
        _ => RevocationMode.Off,
    };
}

/// <summary>Azure Artifact Signing validation options (Rust <c>PortableArtifactSigningOptions</c>).</summary>
public sealed class PortableArtifactSigningOptions
{
    internal static readonly string[] Fields = ["publisher_ids", "private_trust_root_paths", "allow_missing_timestamp"];

    /// <summary>When non-empty, the signer's publisher ID must equal one of these values.</summary>
    public List<string> PublisherIds { get; set; } = [];

    /// <summary>Subscriber roots for Private Trust / Public Trust Test signatures.</summary>
    public List<string> PrivateTrustRootPaths { get; set; } = [];

    public bool AllowMissingTimestamp { get; set; }

    internal static PortableArtifactSigningOptions Read(JsonElement element)
    {
        var o = SerdeObject.Nested(element, nameof(PortableArtifactSigningOptions), Fields);
        return new PortableArtifactSigningOptions
        {
            PublisherIds = o.StringList("publisher_ids"),
            PrivateTrustRootPaths = o.StringList("private_trust_root_paths"),
            AllowMissingTimestamp = o.Bool("allow_missing_timestamp"),
        };
    }

    public JsonObject ToJsonNode() => new()
    {
        ["publisher_ids"] = SerdeWrite.StringArray(PublisherIds),
        ["private_trust_root_paths"] = SerdeWrite.StringArray(PrivateTrustRootPaths),
        ["allow_missing_timestamp"] = AllowMissingTimestamp,
    };
}

/// <summary>Options shared by requests that may request explicit trust verification.</summary>
public abstract class PortableTrustRequestBase
{
    public List<string> TrustedCertificatePaths { get; set; } = [];

    public List<string> TrustedCertificatesDerBase64 { get; set; } = [];

    public string? AnchorDirectory { get; set; }

    public string? AuthrootCab { get; set; }

    /// <summary>Verification date <c>yyyy-MM-dd</c> (a <c>T…</c> time suffix is ignored).</summary>
    public string? AsOf { get; set; }

    public bool PreferTimestampSigningTime { get; set; }

    public bool RequireValidTimestamp { get; set; }

    public bool OnlineAia { get; set; }

    public bool OnlineOcsp { get; set; }

    public PortableRevocationMode RevocationMode { get; set; }

    private protected void ReadTrust(SerdeObject o)
    {
        TrustedCertificatePaths = o.StringList("trusted_certificate_paths");
        TrustedCertificatesDerBase64 = o.StringList("trusted_certificates_der_base64");
        AnchorDirectory = o.OptionalString("anchor_directory");
        AuthrootCab = o.OptionalString("authroot_cab");
        AsOf = o.OptionalString("as_of");
        PreferTimestampSigningTime = o.Bool("prefer_timestamp_signing_time");
        RequireValidTimestamp = o.Bool("require_valid_timestamp");
        OnlineAia = o.Bool("online_aia");
        OnlineOcsp = o.Bool("online_ocsp");
        RevocationMode = o.Enum("revocation_mode", PortableRevocationMode.Off);
    }

    private protected void WriteTrust(JsonObject json)
    {
        json["trusted_certificate_paths"] = SerdeWrite.StringArray(TrustedCertificatePaths);
        json["trusted_certificates_der_base64"] = SerdeWrite.StringArray(TrustedCertificatesDerBase64);
        json["anchor_directory"] = SerdeWrite.OptionalString(AnchorDirectory);
        json["authroot_cab"] = SerdeWrite.OptionalString(AuthrootCab);
        json["as_of"] = SerdeWrite.OptionalString(AsOf);
        json["prefer_timestamp_signing_time"] = PreferTimestampSigningTime;
        json["require_valid_timestamp"] = RequireValidTimestamp;
        json["online_aia"] = OnlineAia;
        json["online_ocsp"] = OnlineOcsp;
        json["revocation_mode"] = RevocationMode.ToString();
    }

    private protected static readonly string[] TrustFields =
    [
        "trusted_certificate_paths", "trusted_certificates_der_base64", "anchor_directory", "authroot_cab", "as_of",
        "prefer_timestamp_signing_time", "require_valid_timestamp", "online_aia", "online_ocsp", "revocation_mode",
    ];

    /// <summary>Copy of the trust options as a <see cref="PortableGetSignatureRequest"/> for <paramref name="path"/>.</summary>
    internal PortableGetSignatureRequest ToSignatureRequest(string path) => new()
    {
        Path = path,
        TrustedCertificatePaths = [.. TrustedCertificatePaths],
        TrustedCertificatesDerBase64 = [.. TrustedCertificatesDerBase64],
        AnchorDirectory = AnchorDirectory,
        AuthrootCab = AuthrootCab,
        AsOf = AsOf,
        PreferTimestampSigningTime = PreferTimestampSigningTime,
        RequireValidTimestamp = RequireValidTimestamp,
        OnlineAia = OnlineAia,
        OnlineOcsp = OnlineOcsp,
        RevocationMode = RevocationMode,
    };
}

/// <summary>Inspect (and optionally trust-verify) a file signature (Rust <c>PortableGetSignatureRequest</c>).</summary>
public sealed class PortableGetSignatureRequest : PortableTrustRequestBase
{
    private static readonly string[] Fields = ["path", .. TrustFields, "artifact_signing"];

    public string Path { get; set; } = string.Empty;

    /// <summary>Validate as Azure Artifact Signing (pinned Microsoft roots) instead of the anchors.</summary>
    public PortableArtifactSigningOptions? ArtifactSigning { get; set; }

    /// <summary>Request with only <paramref name="path"/> set (Rust <c>path_only</c>).</summary>
    public static PortableGetSignatureRequest PathOnly(string path) => new() { Path = path };

    public static PortableGetSignatureRequest FromJson(string json) =>
        SerdeObject.Parse(json, nameof(PortableGetSignatureRequest), Fields, o =>
        {
            var r = new PortableGetSignatureRequest { Path = o.RequiredString("path") };
            r.ReadTrust(o);
            r.ArtifactSigning = o.OptionalElement("artifact_signing") is { } a ? PortableArtifactSigningOptions.Read(a) : null;
            return r;
        });

    public JsonObject ToJsonNode()
    {
        var json = new JsonObject { ["path"] = Path };
        WriteTrust(json);
        json["artifact_signing"] = ArtifactSigning?.ToJsonNode();
        return json;
    }

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Validate in-memory PowerShell content (Rust <c>PortableValidatePowerShellRequest</c>).</summary>
public sealed class PortableValidatePowerShellRequest : PortableTrustRequestBase
{
    private static readonly string[] Fields = ["source_path_or_extension", "content_base64", .. TrustFields];

    /// <summary>Source path or bare extension (<c>.ps1</c>, <c>psm1</c>, …) selecting the PowerShell SIP flavor.</summary>
    public string SourcePathOrExtension { get; set; } = string.Empty;

    public string ContentBase64 { get; set; } = string.Empty;

    public static PortableValidatePowerShellRequest FromJson(string json) =>
        SerdeObject.Parse(json, nameof(PortableValidatePowerShellRequest), Fields, o =>
        {
            var r = new PortableValidatePowerShellRequest
            {
                SourcePathOrExtension = o.RequiredString("source_path_or_extension"),
                ContentBase64 = o.RequiredString("content_base64"),
            };
            r.ReadTrust(o);
            return r;
        });

    public JsonObject ToJsonNode()
    {
        var json = new JsonObject
        {
            ["source_path_or_extension"] = SourcePathOrExtension,
            ["content_base64"] = ContentBase64,
        };
        WriteTrust(json);
        return json;
    }

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Create an unsigned file catalog (Rust <c>PortableNewFileCatalogRequest</c>).</summary>
public sealed class PortableNewFileCatalogRequest
{
    private static readonly string[] Fields = ["catalog_file_path", "paths", "catalog_version"];

    /// <summary>Output catalog path; a directory gets <c>catalog.cat</c>.</summary>
    public string CatalogFilePath { get; set; } = string.Empty;

    /// <summary>Subject files / directories (the current directory when empty).</summary>
    public List<string> Paths { get; set; } = [];

    /// <summary>1 (SHA-1) or 2 (SHA-256); 0 means 2.</summary>
    public uint CatalogVersion { get; set; }

    public static PortableNewFileCatalogRequest FromJson(string json) =>
        SerdeObject.Parse(json, nameof(PortableNewFileCatalogRequest), Fields, o => new PortableNewFileCatalogRequest
        {
            CatalogFilePath = o.RequiredString("catalog_file_path"),
            Paths = o.StringList("paths"),
            CatalogVersion = o.U32("catalog_version"),
        });

    public JsonObject ToJsonNode() => new()
    {
        ["catalog_file_path"] = CatalogFilePath,
        ["paths"] = SerdeWrite.StringArray(Paths),
        ["catalog_version"] = CatalogVersion,
    };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Validate files against a catalog (Rust <c>PortableTestFileCatalogRequest</c>).</summary>
public sealed class PortableTestFileCatalogRequest : PortableTrustRequestBase
{
    private static readonly string[] Fields = ["catalog_file_path", "paths", "files_to_skip", .. TrustFields];

    public string CatalogFilePath { get; set; } = string.Empty;

    public List<string> Paths { get; set; } = [];

    public List<string> FilesToSkip { get; set; } = [];

    public static PortableTestFileCatalogRequest FromJson(string json) =>
        SerdeObject.Parse(json, nameof(PortableTestFileCatalogRequest), Fields, o =>
        {
            var r = new PortableTestFileCatalogRequest
            {
                CatalogFilePath = o.RequiredString("catalog_file_path"),
                Paths = o.StringList("paths"),
                FilesToSkip = o.StringList("files_to_skip"),
            };
            r.ReadTrust(o);
            return r;
        });

    public JsonObject ToJsonNode()
    {
        var json = new JsonObject
        {
            ["catalog_file_path"] = CatalogFilePath,
            ["paths"] = SerdeWrite.StringArray(Paths),
            ["files_to_skip"] = SerdeWrite.StringArray(FilesToSkip),
        };
        WriteTrust(json);
        return json;
    }

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Remove a PE signature (Rust <c>PortableClearSignatureRequest</c>).</summary>
public sealed class PortableClearSignatureRequest
{
    private static readonly string[] Fields = ["path"];

    public string Path { get; set; } = string.Empty;

    public static PortableClearSignatureRequest FromJson(string json) =>
        SerdeObject.Parse(json, nameof(PortableClearSignatureRequest), Fields, o => new PortableClearSignatureRequest { Path = o.RequiredString("path") });

    public JsonObject ToJsonNode() => new() { ["path"] = Path };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Decode the Artifact Signing identity of a certificate (Rust <c>PortableArtifactSigningIdentityRequest</c>).</summary>
public sealed class PortableArtifactSigningIdentityRequest
{
    private static readonly string[] Fields = ["certificate_der_base64"];

    public string CertificateDerBase64 { get; set; } = string.Empty;

    public static PortableArtifactSigningIdentityRequest FromJson(string json) =>
        SerdeObject.Parse(json, nameof(PortableArtifactSigningIdentityRequest), Fields, o =>
            new PortableArtifactSigningIdentityRequest { CertificateDerBase64 = o.RequiredString("certificate_der_base64") });

    public JsonObject ToJsonNode() => new() { ["certificate_der_base64"] = CertificateDerBase64 };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Sign a file (Rust <c>PortableSignRequest</c>).</summary>
public sealed class PortableSignRequest
{
    private static readonly string[] Fields =
    [
        "path", "append_signature", "skip_signed", "output_path", "hash_algorithm", "certificate_path", "private_key_path",
        "certificate_der_base64", "private_key_der_base64", "pfx_path", "pfx_password", "chain_certificate_paths",
        "chain_certificates_der_base64", "timestamp_server", "timestamp_hash_algorithm", "azure_key_vault_url",
        "azure_key_vault_certificate", "azure_key_vault_certificate_version", "azure_key_vault_access_token",
        "azure_key_vault_client_id", "azure_key_vault_client_secret", "azure_key_vault_tenant_id",
        "azure_key_vault_managed_identity", "azure_authority", "artifact_signing_endpoint", "artifact_signing_account_name",
        "artifact_signing_profile_name", "artifact_signing_access_token", "artifact_signing_managed_identity",
        "artifact_signing_managed_identity_resource_id", "artifact_signing_credential_type", "artifact_signing_tenant_id",
        "artifact_signing_client_id", "artifact_signing_client_secret", "artifact_signing_federated_token_file",
        "artifact_signing_exclude_credentials", "artifact_signing_correlation_id",
    ];

    public string Path { get; set; } = string.Empty;

    /// <summary>PE only: append a signature instead of replacing existing ones.</summary>
    public bool AppendSignature { get; set; }

    /// <summary>PE / MSIX: leave already-signed files unchanged (copied to <see cref="OutputPath"/> when set).</summary>
    public bool SkipSigned { get; set; }

    /// <summary>Signed output path (defaults to <see cref="Path"/>, signing in place).</summary>
    public string? OutputPath { get; set; }

    public PortableDigestAlgorithm HashAlgorithm { get; set; }

    public string? CertificatePath { get; set; }

    public string? PrivateKeyPath { get; set; }

    public string? CertificateDerBase64 { get; set; }

    public string? PrivateKeyDerBase64 { get; set; }

    public string? PfxPath { get; set; }

    public string? PfxPassword { get; set; }

    public List<string> ChainCertificatePaths { get; set; } = [];

    public List<string> ChainCertificatesDerBase64 { get; set; } = [];

    public string? TimestampServer { get; set; }

    public PortableTimestampDigestAlgorithm? TimestampHashAlgorithm { get; set; }

    public string? AzureKeyVaultUrl { get; set; }

    public string? AzureKeyVaultCertificate { get; set; }

    public string? AzureKeyVaultCertificateVersion { get; set; }

    public string? AzureKeyVaultAccessToken { get; set; }

    public string? AzureKeyVaultClientId { get; set; }

    public string? AzureKeyVaultClientSecret { get; set; }

    public string? AzureKeyVaultTenantId { get; set; }

    public bool? AzureKeyVaultManagedIdentity { get; set; }

    public string? AzureAuthority { get; set; }

    public string? ArtifactSigningEndpoint { get; set; }

    public string? ArtifactSigningAccountName { get; set; }

    public string? ArtifactSigningProfileName { get; set; }

    public string? ArtifactSigningAccessToken { get; set; }

    public bool? ArtifactSigningManagedIdentity { get; set; }

    public string? ArtifactSigningManagedIdentityResourceId { get; set; }

    public string? ArtifactSigningCredentialType { get; set; }

    public string? ArtifactSigningTenantId { get; set; }

    public string? ArtifactSigningClientId { get; set; }

    public string? ArtifactSigningClientSecret { get; set; }

    public string? ArtifactSigningFederatedTokenFile { get; set; }

    public List<string> ArtifactSigningExcludeCredentials { get; set; } = [];

    public string? ArtifactSigningCorrelationId { get; set; }

    public static PortableSignRequest FromJson(string json) =>
        SerdeObject.Parse(json, nameof(PortableSignRequest), Fields, o => new PortableSignRequest
        {
            Path = o.RequiredString("path"),
            AppendSignature = o.Bool("append_signature"),
            SkipSigned = o.Bool("skip_signed"),
            OutputPath = o.OptionalString("output_path"),
            HashAlgorithm = o.Enum("hash_algorithm", PortableDigestAlgorithm.Sha256),
            CertificatePath = o.OptionalString("certificate_path"),
            PrivateKeyPath = o.OptionalString("private_key_path"),
            CertificateDerBase64 = o.OptionalString("certificate_der_base64"),
            PrivateKeyDerBase64 = o.OptionalString("private_key_der_base64"),
            PfxPath = o.OptionalString("pfx_path"),
            PfxPassword = o.OptionalString("pfx_password"),
            ChainCertificatePaths = o.StringList("chain_certificate_paths"),
            ChainCertificatesDerBase64 = o.StringList("chain_certificates_der_base64"),
            TimestampServer = o.OptionalString("timestamp_server"),
            TimestampHashAlgorithm = o.OptionalEnum<PortableTimestampDigestAlgorithm>("timestamp_hash_algorithm"),
            AzureKeyVaultUrl = o.OptionalString("azure_key_vault_url"),
            AzureKeyVaultCertificate = o.OptionalString("azure_key_vault_certificate"),
            AzureKeyVaultCertificateVersion = o.OptionalString("azure_key_vault_certificate_version"),
            AzureKeyVaultAccessToken = o.OptionalString("azure_key_vault_access_token"),
            AzureKeyVaultClientId = o.OptionalString("azure_key_vault_client_id"),
            AzureKeyVaultClientSecret = o.OptionalString("azure_key_vault_client_secret"),
            AzureKeyVaultTenantId = o.OptionalString("azure_key_vault_tenant_id"),
            AzureKeyVaultManagedIdentity = o.OptionalBool("azure_key_vault_managed_identity"),
            AzureAuthority = o.OptionalString("azure_authority"),
            ArtifactSigningEndpoint = o.OptionalString("artifact_signing_endpoint"),
            ArtifactSigningAccountName = o.OptionalString("artifact_signing_account_name"),
            ArtifactSigningProfileName = o.OptionalString("artifact_signing_profile_name"),
            ArtifactSigningAccessToken = o.OptionalString("artifact_signing_access_token"),
            ArtifactSigningManagedIdentity = o.OptionalBool("artifact_signing_managed_identity"),
            ArtifactSigningManagedIdentityResourceId = o.OptionalString("artifact_signing_managed_identity_resource_id"),
            ArtifactSigningCredentialType = o.OptionalString("artifact_signing_credential_type"),
            ArtifactSigningTenantId = o.OptionalString("artifact_signing_tenant_id"),
            ArtifactSigningClientId = o.OptionalString("artifact_signing_client_id"),
            ArtifactSigningClientSecret = o.OptionalString("artifact_signing_client_secret"),
            ArtifactSigningFederatedTokenFile = o.OptionalString("artifact_signing_federated_token_file"),
            ArtifactSigningExcludeCredentials = o.StringList("artifact_signing_exclude_credentials"),
            ArtifactSigningCorrelationId = o.OptionalString("artifact_signing_correlation_id"),
        });

    public JsonObject ToJsonNode() => new()
    {
        ["path"] = Path,
        ["append_signature"] = AppendSignature,
        ["skip_signed"] = SkipSigned,
        ["output_path"] = SerdeWrite.OptionalString(OutputPath),
        ["hash_algorithm"] = HashAlgorithm.ToString(),
        ["certificate_path"] = SerdeWrite.OptionalString(CertificatePath),
        ["private_key_path"] = SerdeWrite.OptionalString(PrivateKeyPath),
        ["certificate_der_base64"] = SerdeWrite.OptionalString(CertificateDerBase64),
        ["private_key_der_base64"] = SerdeWrite.OptionalString(PrivateKeyDerBase64),
        ["pfx_path"] = SerdeWrite.OptionalString(PfxPath),
        ["pfx_password"] = SerdeWrite.OptionalString(PfxPassword),
        ["chain_certificate_paths"] = SerdeWrite.StringArray(ChainCertificatePaths),
        ["chain_certificates_der_base64"] = SerdeWrite.StringArray(ChainCertificatesDerBase64),
        ["timestamp_server"] = SerdeWrite.OptionalString(TimestampServer),
        ["timestamp_hash_algorithm"] = SerdeWrite.OptionalEnum(TimestampHashAlgorithm),
        ["azure_key_vault_url"] = SerdeWrite.OptionalString(AzureKeyVaultUrl),
        ["azure_key_vault_certificate"] = SerdeWrite.OptionalString(AzureKeyVaultCertificate),
        ["azure_key_vault_certificate_version"] = SerdeWrite.OptionalString(AzureKeyVaultCertificateVersion),
        ["azure_key_vault_access_token"] = SerdeWrite.OptionalString(AzureKeyVaultAccessToken),
        ["azure_key_vault_client_id"] = SerdeWrite.OptionalString(AzureKeyVaultClientId),
        ["azure_key_vault_client_secret"] = SerdeWrite.OptionalString(AzureKeyVaultClientSecret),
        ["azure_key_vault_tenant_id"] = SerdeWrite.OptionalString(AzureKeyVaultTenantId),
        ["azure_key_vault_managed_identity"] = SerdeWrite.OptionalBool(AzureKeyVaultManagedIdentity),
        ["azure_authority"] = SerdeWrite.OptionalString(AzureAuthority),
        ["artifact_signing_endpoint"] = SerdeWrite.OptionalString(ArtifactSigningEndpoint),
        ["artifact_signing_account_name"] = SerdeWrite.OptionalString(ArtifactSigningAccountName),
        ["artifact_signing_profile_name"] = SerdeWrite.OptionalString(ArtifactSigningProfileName),
        ["artifact_signing_access_token"] = SerdeWrite.OptionalString(ArtifactSigningAccessToken),
        ["artifact_signing_managed_identity"] = SerdeWrite.OptionalBool(ArtifactSigningManagedIdentity),
        ["artifact_signing_managed_identity_resource_id"] = SerdeWrite.OptionalString(ArtifactSigningManagedIdentityResourceId),
        ["artifact_signing_credential_type"] = SerdeWrite.OptionalString(ArtifactSigningCredentialType),
        ["artifact_signing_tenant_id"] = SerdeWrite.OptionalString(ArtifactSigningTenantId),
        ["artifact_signing_client_id"] = SerdeWrite.OptionalString(ArtifactSigningClientId),
        ["artifact_signing_client_secret"] = SerdeWrite.OptionalString(ArtifactSigningClientSecret),
        ["artifact_signing_federated_token_file"] = SerdeWrite.OptionalString(ArtifactSigningFederatedTokenFile),
        ["artifact_signing_exclude_credentials"] = SerdeWrite.StringArray(ArtifactSigningExcludeCredentials),
        ["artifact_signing_correlation_id"] = SerdeWrite.OptionalString(ArtifactSigningCorrelationId),
    };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Signature inspection / validation result (Rust <c>PortableSignatureResponse</c>).</summary>
public sealed class PortableSignatureResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    public string Path { get; set; } = string.Empty;

    public PortableFileFormat Format { get; set; }

    public PortableSignatureStatus Status { get; set; }

    public string StatusMessage { get; set; } = string.Empty;

    public PortableSignatureStatus? TrustStatus { get; set; }

    public int SignatureCount { get; set; }

    public int? SignerIndex { get; set; }

    public string? SignerCertificateDerBase64 { get; set; }

    public string? TimestamperCertificateDerBase64 { get; set; }

    public int EmbeddedCertificateCount { get; set; }

    /// <summary>Digest algorithm OID of the embedded Authenticode digest.</summary>
    public string? DigestAlgorithm { get; set; }

    public List<string> TimestampKinds { get; set; } = [];

    public string? TimestampSigningTime { get; set; }

    public string? Pkcs7DerBase64 { get; set; }

    public List<string> Diagnostics { get; set; } = [];

    /// <summary>Azure Artifact Signing identity of the signer certificate (decoded, not trust-verified).</summary>
    public ArtifactSigningIdentity? ArtifactSigning { get; set; }

    /// <summary>Set when Artifact Signing validation was requested and succeeded.</summary>
    public ArtifactSigningVerifiedSignature? ArtifactSigningVerification { get; set; }

    public JsonObject ToJsonNode()
    {
        var json = new JsonObject
        {
            ["schema_version"] = SchemaVersion,
            ["path"] = Path,
            ["format"] = Format.ToString(),
            ["status"] = Status.ToString(),
            ["status_message"] = StatusMessage,
        };
        if (TrustStatus is { } trust)
        {
            json["trust_status"] = trust.ToString();
        }

        json["signature_count"] = SignatureCount;
        if (SignerIndex is { } signerIndex)
        {
            json["signer_index"] = signerIndex;
        }

        if (SignerCertificateDerBase64 is not null)
        {
            json["signer_certificate_der_base64"] = SignerCertificateDerBase64;
        }

        if (TimestamperCertificateDerBase64 is not null)
        {
            json["timestamper_certificate_der_base64"] = TimestamperCertificateDerBase64;
        }

        if (EmbeddedCertificateCount != 0)
        {
            json["embedded_certificate_count"] = EmbeddedCertificateCount;
        }

        if (DigestAlgorithm is not null)
        {
            json["digest_algorithm"] = DigestAlgorithm;
        }

        if (TimestampKinds.Count > 0)
        {
            json["timestamp_kinds"] = SerdeWrite.StringArray(TimestampKinds);
        }

        if (TimestampSigningTime is not null)
        {
            json["timestamp_signing_time"] = TimestampSigningTime;
        }

        if (Pkcs7DerBase64 is not null)
        {
            json["pkcs7_der_base64"] = Pkcs7DerBase64;
        }

        if (Diagnostics.Count > 0)
        {
            json["diagnostics"] = SerdeWrite.StringArray(Diagnostics);
        }

        if (ArtifactSigning is not null)
        {
            json["artifact_signing"] = PortableArtifactSigningJson.Identity(ArtifactSigning);
        }

        if (ArtifactSigningVerification is not null)
        {
            json["artifact_signing_verification"] = PortableArtifactSigningJson.Verification(ArtifactSigningVerification);
        }

        return json;
    }

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>JSON for the Artifact Signing types embedded in portable responses (serde field order).</summary>
internal static class PortableArtifactSigningJson
{
    public static JsonObject Identity(ArtifactSigningIdentity identity) => new()
    {
        ["kind"] = identity.Kind.AsStr(),
        ["publisher_id"] = identity.PublisherId,
        ["identity_eku"] = identity.IdentityEku,
        ["has_public_trust_marker"] = identity.HasPublicTrustMarker,
        ["has_code_signing_eku"] = identity.HasCodeSigningEku,
    };

    public static JsonObject Verification(ArtifactSigningVerifiedSignature sig) => new()
    {
        ["signature_index"] = sig.SignatureIndex,
        ["signer_subject"] = sig.SignerSubject,
        ["identity"] = Identity(sig.Identity),
        ["root_subject"] = sig.RootSubject,
        ["root_sha1"] = sig.RootSha1,
        ["timestamped"] = sig.Timestamped,
        ["verification_time"] = sig.VerificationTime,
    };
}

/// <summary>Result of <see cref="PortableCore.PortableSign(PortableSignRequest, PortableCoreOptions?)"/> (Rust <c>PortableSignResponse</c>).</summary>
public sealed class PortableSignResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    public string InputPath { get; set; } = string.Empty;

    public string OutputPath { get; set; } = string.Empty;

    public PortableFileFormat Format { get; set; }

    /// <summary>Post-sign self-inspection of <see cref="OutputPath"/> (digest binding only, no trust).</summary>
    public PortableSignatureResponse Signature { get; set; } = new();

    /// <summary>The file was already signed and <see cref="PortableSignRequest.SkipSigned"/> was set.</summary>
    public bool Skipped { get; set; }

    public JsonObject ToJsonNode()
    {
        var json = new JsonObject
        {
            ["schema_version"] = SchemaVersion,
            ["input_path"] = InputPath,
            ["output_path"] = OutputPath,
            ["format"] = Format.ToString(),
            ["signature"] = Signature.ToJsonNode(),
        };
        if (Skipped)
        {
            json["skipped"] = true;
        }

        return json;
    }

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>One catalog member (Rust <c>PortableCatalogItem</c>).</summary>
public sealed record PortableCatalogItem(string Path, string Hash)
{
    public JsonObject ToJsonNode() => new() { ["path"] = Path, ["hash"] = Hash };
}

/// <summary>One validated path (Rust <c>PortableCatalogPathItem</c>).</summary>
public sealed record PortableCatalogPathItem(string Path, string? Hash, PortableCatalogItemStatus Status, string? Message)
{
    public JsonObject ToJsonNode()
    {
        var json = new JsonObject
        {
            ["path"] = Path,
            ["hash"] = SerdeWrite.OptionalString(Hash),
            ["status"] = Status.ToString(),
        };
        if (Message is not null)
        {
            json["message"] = Message;
        }

        return json;
    }
}

/// <summary>Result of catalog creation (Rust <c>PortableNewFileCatalogResponse</c>).</summary>
public sealed class PortableNewFileCatalogResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    public string CatalogFilePath { get; set; } = string.Empty;

    public uint CatalogVersion { get; set; }

    public string HashAlgorithm { get; set; } = string.Empty;

    public int ItemCount { get; set; }

    public List<PortableCatalogItem> CatalogItems { get; set; } = [];

    public JsonObject ToJsonNode()
    {
        var items = new JsonArray();
        foreach (var item in CatalogItems)
        {
            items.Add((JsonNode)item.ToJsonNode());
        }

        return new JsonObject
        {
            ["schema_version"] = SchemaVersion,
            ["catalog_file_path"] = CatalogFilePath,
            ["catalog_version"] = CatalogVersion,
            ["hash_algorithm"] = HashAlgorithm,
            ["item_count"] = ItemCount,
            ["catalog_items"] = items,
        };
    }

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Result of catalog validation (Rust <c>PortableTestFileCatalogResponse</c>).</summary>
public sealed class PortableTestFileCatalogResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    public string CatalogFilePath { get; set; } = string.Empty;

    public PortableCatalogValidationStatus Status { get; set; }

    public string HashAlgorithm { get; set; } = string.Empty;

    public List<PortableCatalogItem> CatalogItems { get; set; } = [];

    public List<PortableCatalogPathItem> PathItems { get; set; } = [];

    public List<string> SkippedItems { get; set; } = [];

    public PortableSignatureResponse Signature { get; set; } = new();

    public JsonObject ToJsonNode()
    {
        var catalogItems = new JsonArray();
        foreach (var item in CatalogItems)
        {
            catalogItems.Add((JsonNode)item.ToJsonNode());
        }

        var pathItems = new JsonArray();
        foreach (var item in PathItems)
        {
            pathItems.Add((JsonNode)item.ToJsonNode());
        }

        return new JsonObject
        {
            ["schema_version"] = SchemaVersion,
            ["catalog_file_path"] = CatalogFilePath,
            ["status"] = Status.ToString(),
            ["hash_algorithm"] = HashAlgorithm,
            ["catalog_items"] = catalogItems,
            ["path_items"] = pathItems,
            ["skipped_items"] = SerdeWrite.StringArray(SkippedItems),
            ["signature"] = Signature.ToJsonNode(),
        };
    }

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Result of signature removal (Rust <c>PortableClearSignatureResponse</c>).</summary>
public sealed class PortableClearSignatureResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    public string Path { get; set; } = string.Empty;

    public PortableFileFormat Format { get; set; }

    public bool SignatureRemoved { get; set; }

    public int BytesRemoved { get; set; }

    public string Message { get; set; } = string.Empty;

    public JsonObject ToJsonNode() => new()
    {
        ["schema_version"] = SchemaVersion,
        ["path"] = Path,
        ["format"] = Format.ToString(),
        ["signature_removed"] = SignatureRemoved,
        ["bytes_removed"] = BytesRemoved,
        ["message"] = Message,
    };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Decoded Artifact Signing identity (Rust <c>PortableArtifactSigningIdentityResponse</c>).</summary>
public sealed class PortableArtifactSigningIdentityResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    public ArtifactSigningIdentity? Identity { get; set; }

    public JsonObject ToJsonNode() => new()
    {
        ["schema_version"] = SchemaVersion,
        ["identity"] = Identity is null ? null : PortableArtifactSigningJson.Identity(Identity),
    };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Library identity (Rust <c>PortableVersionResponse</c>).</summary>
public sealed class PortableVersionResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    /// <summary><c>psign-portable-core</c> (the Rust crate this implementation mirrors).</summary>
    public string CrateName { get; set; } = PortableCore.CrateName;

    public string CrateVersion { get; set; } = string.Empty;

    public JsonObject ToJsonNode() => new()
    {
        ["schema_version"] = SchemaVersion,
        ["crate_name"] = CrateName,
        ["crate_version"] = CrateVersion,
    };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}

/// <summary>Structured error (Rust <c>PortableErrorResponse</c>).</summary>
public sealed class PortableErrorResponse
{
    public uint SchemaVersion { get; set; } = PortableCore.SchemaVersion;

    public PortableErrorCode Code { get; set; }

    public string Message { get; set; } = string.Empty;

    public JsonObject ToJsonNode() => new()
    {
        ["schema_version"] = SchemaVersion,
        ["code"] = Code.ToString(),
        ["message"] = Message,
    };

    public string ToJson() => RustJson.Compact(ToJsonNode());
}
