using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Signing.Internal;

namespace Devolutions.Psign.Signing.Providers;

/// <summary>Signing provider family (Rust <c>SigningProviderKind</c>, serialized kebab-case).</summary>
public enum SigningProviderKind
{
    PortableStore,
    Pfx,
    WindowsStore,
    AzureKeyVault,
    ArtifactSigning,
}

/// <summary>File digest algorithm as accepted by <c>sign /fd</c> (Rust <c>cli::DigestAlgorithm</c>).</summary>
public enum SignDigestAlgorithm
{
    Sha1,
    Sha256,
    Sha384,
    Sha512,

    /// <summary>Native <c>/fd certHash</c>: digest algorithm follows the signing certificate.</summary>
    CertHash,
}

/// <summary>Azure credential selection (Rust <c>cli::AzureCredentialType</c>).</summary>
public enum AzureCredentialType
{
    Default,
    ManagedIdentity,
    AccessToken,
    ClientSecret,
    WorkloadIdentity,
}

/// <summary>Azure authentication shape (Rust <c>AzureAuthConfig</c>, serialized with a kebab-case <c>mode</c> tag). Secrets are never stored.</summary>
public abstract record AzureAuthConfig(string? Authority)
{
    public sealed record AccessToken(string? Authority) : AzureAuthConfig(Authority);

    public sealed record ClientSecret(string? TenantId, string? ClientId, string? Authority) : AzureAuthConfig(Authority);

    public sealed record ManagedIdentity(string? ClientId, string? ResourceId, string? Authority) : AzureAuthConfig(Authority);

    public sealed record WorkloadIdentity(string? TenantId, string? ClientId, string? FederatedTokenFile, string? Authority) : AzureAuthConfig(Authority);

    public sealed record Ambient(string? Authority) : AzureAuthConfig(Authority);

    /// <summary>JSON object matching the Rust <c>serde</c> output.</summary>
    public JsonObject ToJsonObject() => this switch
    {
        AccessToken a => new JsonObject { ["mode"] = "access-token", ["authority"] = a.Authority },
        ClientSecret c => new JsonObject { ["mode"] = "client-secret", ["tenant_id"] = c.TenantId, ["client_id"] = c.ClientId, ["authority"] = c.Authority },
        ManagedIdentity m => new JsonObject { ["mode"] = "managed-identity", ["client_id"] = m.ClientId, ["resource_id"] = m.ResourceId, ["authority"] = m.Authority },
        WorkloadIdentity w => new JsonObject
        {
            ["mode"] = "workload-identity",
            ["tenant_id"] = w.TenantId,
            ["client_id"] = w.ClientId,
            ["federated_token_file"] = w.FederatedTokenFile,
            ["authority"] = w.Authority,
        },
        Ambient a => new JsonObject { ["mode"] = "ambient", ["authority"] = a.Authority },
        _ => throw new InvalidOperationException(),
    };
}

/// <summary>Who signs (Rust <c>SigningProviderIdentity</c>, serialized with a kebab-case <c>type</c> tag).</summary>
public abstract record SigningProviderIdentity
{
    public sealed record PortableStore(string ThumbprintSha1, bool MachineStore, string StoreName, string? CertStoreDir) : SigningProviderIdentity;

    public sealed record Pfx(string PfxPath) : SigningProviderIdentity;

    public sealed record WindowsStore(bool AutoSelect, string? SubjectName, string? IssuerName, string? ThumbprintSha1, bool MachineStore, string StoreName) : SigningProviderIdentity;

    public sealed record AzureKeyVault(string VaultUrl, string Certificate, string? CertificateVersion, AzureAuthConfig Auth) : SigningProviderIdentity;

    public sealed record ArtifactSigning(string? Metadata, string? Endpoint, string? Region, string? AccountName, string? ProfileName, AzureAuthConfig Auth) : SigningProviderIdentity;

    /// <summary>JSON object matching the Rust <c>serde</c> output.</summary>
    public JsonObject ToJsonObject() => this switch
    {
        PortableStore p => new JsonObject
        {
            ["type"] = "portable-store",
            ["thumbprint_sha1"] = p.ThumbprintSha1,
            ["machine_store"] = p.MachineStore,
            ["store_name"] = p.StoreName,
            ["cert_store_dir"] = p.CertStoreDir,
        },
        Pfx p => new JsonObject { ["type"] = "pfx", ["pfx"] = p.PfxPath },
        WindowsStore w => new JsonObject
        {
            ["type"] = "windows-store",
            ["auto_select"] = w.AutoSelect,
            ["subject_name"] = w.SubjectName,
            ["issuer_name"] = w.IssuerName,
            ["thumbprint_sha1"] = w.ThumbprintSha1,
            ["machine_store"] = w.MachineStore,
            ["store_name"] = w.StoreName,
        },
        AzureKeyVault k => new JsonObject
        {
            ["type"] = "azure-key-vault",
            ["vault_url"] = k.VaultUrl,
            ["certificate"] = k.Certificate,
            ["certificate_version"] = k.CertificateVersion,
            ["auth"] = k.Auth.ToJsonObject(),
        },
        ArtifactSigning a => new JsonObject
        {
            ["type"] = "artifact-signing",
            ["metadata"] = a.Metadata,
            ["endpoint"] = a.Endpoint,
            ["region"] = a.Region,
            ["account_name"] = a.AccountName,
            ["profile_name"] = a.ProfileName,
            ["auth"] = a.Auth.ToJsonObject(),
        },
        _ => throw new InvalidOperationException(),
    };
}

/// <summary>
/// The subset of <c>sign</c> options that select a signing provider (Rust <c>cli::SignArgs</c> fields read by
/// <c>SigningProviderConfig::from_sign_args</c>). Secrets are accepted only to detect which provider is requested.
/// </summary>
public sealed class SigningProviderOptions
{
    public SignDigestAlgorithm Digest { get; set; } = SignDigestAlgorithm.Sha256;

    public string? TimestampUrl { get; set; }

    public string? SealTimestampUrl { get; set; }

    public string? LegacyTimestampUrl { get; set; }

    public SignDigestAlgorithm? TimestampDigest { get; set; }

    public string? AzureKeyVaultUrl { get; set; }

    public string? AzureKeyVaultCertificate { get; set; }

    public string? AzureKeyVaultCertificateVersion { get; set; }

    public string? AzureKeyVaultClientId { get; set; }

    public string? AzureKeyVaultClientSecret { get; set; }

    public string? AzureKeyVaultTenantId { get; set; }

    public string? AzureKeyVaultAccessToken { get; set; }

    public bool AzureKeyVaultManagedIdentity { get; set; }

    public AzureCredentialType? AzureKeyVaultCredentialType { get; set; }

    public string? AzureAuthority { get; set; }

    public string? ArtifactSigningMetadata { get; set; }

    public string? Dmdf { get; set; }

    public string? TrustedSigningDlibRoot { get; set; }

    public string? ArtifactSigningRegion { get; set; }

    public string? ArtifactSigningEndpoint { get; set; }

    public string? ArtifactSigningAccountName { get; set; }

    public string? ArtifactSigningProfileName { get; set; }

    public string? ArtifactSigningSignatureAlgorithm { get; set; }

    public string? ArtifactSigningApiVersion { get; set; }

    public string? ArtifactSigningCorrelationId { get; set; }

    public string? ArtifactSigningAccessToken { get; set; }

    public bool ArtifactSigningManagedIdentity { get; set; }

    public string? ArtifactSigningManagedIdentityResourceId { get; set; }

    public AzureCredentialType? ArtifactSigningCredentialType { get; set; }

    public string? ArtifactSigningTenantId { get; set; }

    public string? ArtifactSigningClientId { get; set; }

    public string? ArtifactSigningClientSecret { get; set; }

    public string? ArtifactSigningFederatedTokenFile { get; set; }

    public string? ArtifactSigningAuthority { get; set; }

    public string? ArtifactSigningEndpointBaseUrl { get; set; }

    public string? Pfx { get; set; }

    public string? CertSha1 { get; set; }

    public bool AutoSelect { get; set; }

    public string? SubjectName { get; set; }

    public string? IssuerName { get; set; }

    public bool MachineStore { get; set; }

    public string StoreName { get; set; } = "MY";

    public string? CertStoreDir { get; set; }
}

/// <summary>Resolved signing provider plan (Rust <c>SigningProviderConfig</c>).</summary>
public sealed record SigningProviderConfig(
    SigningProviderKind Kind,
    string DigestAlgorithm,
    string? TimestampUrl,
    string? TimestampDigestAlgorithm,
    SigningProviderIdentity Identity)
{
    /// <summary>Select a provider from sign options (Rust <c>SigningProviderConfig::from_sign_args</c>).</summary>
    public static SigningProviderConfig FromSignOptions(SigningProviderOptions args)
    {
        var azureKeyVault = AzureKeyVaultRequested(args);
        var artifactSigning = ArtifactSigningRequested(args);
        if (azureKeyVault && artifactSigning)
        {
            throw new PsignException("signing provider options are ambiguous: choose either Azure Key Vault or Artifact Signing");
        }

        var timestampUrl = args.TimestampUrl ?? args.SealTimestampUrl ?? args.LegacyTimestampUrl;
        var timestampDigest = args.TimestampDigest is { } td ? DigestName(td) : null;

        if (azureKeyVault)
        {
            RequireRemoteDigest(args.Digest, "Azure Key Vault");
            var vaultUrl = RequiredText("--azure-key-vault-url", args.AzureKeyVaultUrl);
            var certificate = RequiredText("--azure-key-vault-certificate", args.AzureKeyVaultCertificate);
            return new SigningProviderConfig(
                SigningProviderKind.AzureKeyVault,
                DigestName(args.Digest),
                timestampUrl,
                timestampDigest,
                new SigningProviderIdentity.AzureKeyVault(
                    vaultUrl,
                    certificate,
                    Trim(args.AzureKeyVaultCertificateVersion),
                    AzureAuth(
                        args.AzureKeyVaultCredentialType,
                        args.AzureKeyVaultAccessToken,
                        args.AzureKeyVaultManagedIdentity,
                        null,
                        args.AzureKeyVaultTenantId,
                        args.AzureKeyVaultClientId,
                        args.AzureKeyVaultClientSecret,
                        null,
                        args.AzureAuthority)));
        }

        if (artifactSigning)
        {
            RequireRemoteDigest(args.Digest, "Artifact Signing");
            return new SigningProviderConfig(
                SigningProviderKind.ArtifactSigning,
                DigestName(args.Digest),
                timestampUrl,
                timestampDigest,
                new SigningProviderIdentity.ArtifactSigning(
                    args.ArtifactSigningMetadata ?? args.Dmdf,
                    Trim(args.ArtifactSigningEndpoint),
                    Trim(args.ArtifactSigningRegion),
                    Trim(args.ArtifactSigningAccountName),
                    Trim(args.ArtifactSigningProfileName),
                    AzureAuth(
                        args.ArtifactSigningCredentialType,
                        args.ArtifactSigningAccessToken,
                        args.ArtifactSigningManagedIdentity,
                        args.ArtifactSigningManagedIdentityResourceId,
                        args.ArtifactSigningTenantId,
                        args.ArtifactSigningClientId,
                        args.ArtifactSigningClientSecret,
                        args.ArtifactSigningFederatedTokenFile,
                        args.ArtifactSigningAuthority)));
        }

        if (args.Pfx is { } pfx)
        {
            if (args.CertSha1 is not null || args.AutoSelect || Present(args.SubjectName) || Present(args.IssuerName))
            {
                throw new PsignException("signing provider options are ambiguous: do not combine --pfx with certificate store selection options");
            }

            return new SigningProviderConfig(SigningProviderKind.Pfx, DigestName(args.Digest), timestampUrl, timestampDigest, new SigningProviderIdentity.Pfx(pfx));
        }

        if (Trim(args.CertSha1) is { } thumbprint)
        {
            return new SigningProviderConfig(
                SigningProviderKind.PortableStore,
                DigestName(args.Digest),
                timestampUrl,
                timestampDigest,
                new SigningProviderIdentity.PortableStore(thumbprint, args.MachineStore, args.StoreName, args.CertStoreDir));
        }

        if (args.AutoSelect || Present(args.SubjectName) || Present(args.IssuerName))
        {
            return new SigningProviderConfig(
                SigningProviderKind.WindowsStore,
                DigestName(args.Digest),
                timestampUrl,
                timestampDigest,
                new SigningProviderIdentity.WindowsStore(
                    args.AutoSelect,
                    Trim(args.SubjectName),
                    Trim(args.IssuerName),
                    Trim(args.CertSha1),
                    args.MachineStore,
                    args.StoreName));
        }

        throw new PsignException("no signing provider selected; specify --sha1, --pfx, Windows store selection, Azure Key Vault, or Artifact Signing options");
    }

    /// <summary>JSON object matching the Rust <c>serde</c> output.</summary>
    public JsonObject ToJsonObject() => new()
    {
        ["kind"] = KindName(Kind),
        ["digest_algorithm"] = DigestAlgorithm,
        ["timestamp_url"] = TimestampUrl,
        ["timestamp_digest_algorithm"] = TimestampDigestAlgorithm,
        ["identity"] = Identity.ToJsonObject(),
    };

    /// <summary><c>serde_json::to_string_pretty</c> rendering.</summary>
    public string ToJson() => RustJson.Pretty(ToJsonObject());

    /// <summary>Kebab-case kind name.</summary>
    public static string KindName(SigningProviderKind kind) => kind switch
    {
        SigningProviderKind.PortableStore => "portable-store",
        SigningProviderKind.Pfx => "pfx",
        SigningProviderKind.WindowsStore => "windows-store",
        SigningProviderKind.AzureKeyVault => "azure-key-vault",
        _ => "artifact-signing",
    };

    /// <summary>Lower-case digest name (Rust <c>digest_name</c>).</summary>
    public static string DigestName(SignDigestAlgorithm digest) => digest switch
    {
        SignDigestAlgorithm.Sha1 => "sha1",
        SignDigestAlgorithm.Sha256 => "sha256",
        SignDigestAlgorithm.Sha384 => "sha384",
        SignDigestAlgorithm.Sha512 => "sha512",
        _ => "cert-hash",
    };

    private static bool AzureKeyVaultRequested(SigningProviderOptions a) =>
        Present(a.AzureKeyVaultUrl) || Present(a.AzureKeyVaultCertificate) || Present(a.AzureKeyVaultCertificateVersion)
        || Present(a.AzureKeyVaultClientId) || Present(a.AzureKeyVaultClientSecret) || Present(a.AzureKeyVaultTenantId)
        || Present(a.AzureKeyVaultAccessToken) || a.AzureKeyVaultManagedIdentity || a.AzureKeyVaultCredentialType is not null
        || Present(a.AzureAuthority);

    private static bool ArtifactSigningRequested(SigningProviderOptions a) =>
        a.ArtifactSigningMetadata is not null || a.Dmdf is not null || a.TrustedSigningDlibRoot is not null
        || Present(a.ArtifactSigningRegion) || Present(a.ArtifactSigningEndpoint) || Present(a.ArtifactSigningAccountName)
        || Present(a.ArtifactSigningProfileName) || Present(a.ArtifactSigningSignatureAlgorithm) || Present(a.ArtifactSigningApiVersion)
        || Present(a.ArtifactSigningCorrelationId) || Present(a.ArtifactSigningAccessToken) || a.ArtifactSigningManagedIdentity
        || Present(a.ArtifactSigningManagedIdentityResourceId) || a.ArtifactSigningCredentialType is not null
        || Present(a.ArtifactSigningTenantId) || Present(a.ArtifactSigningClientId) || Present(a.ArtifactSigningClientSecret)
        || Present(a.ArtifactSigningFederatedTokenFile) || Present(a.ArtifactSigningAuthority) || Present(a.ArtifactSigningEndpointBaseUrl);

    private static AzureAuthConfig AzureAuth(
        AzureCredentialType? credentialType,
        string? accessToken,
        bool managedIdentity,
        string? managedIdentityResourceId,
        string? tenantId,
        string? clientId,
        string? clientSecret,
        string? federatedTokenFile,
        string? authority)
    {
        var auth = Trim(authority);
        switch (credentialType ?? AzureCredentialType.Default)
        {
            case AzureCredentialType.AccessToken:
                return new AzureAuthConfig.AccessToken(auth);
            case AzureCredentialType.ManagedIdentity:
                return new AzureAuthConfig.ManagedIdentity(Trim(clientId), Trim(managedIdentityResourceId), auth);
            case AzureCredentialType.ClientSecret:
                return new AzureAuthConfig.ClientSecret(Trim(tenantId), Trim(clientId), auth);
            case AzureCredentialType.WorkloadIdentity:
                return new AzureAuthConfig.WorkloadIdentity(Trim(tenantId), Trim(clientId), Trim(federatedTokenFile), auth);
            default:
                if (Trim(accessToken) is not null)
                {
                    return new AzureAuthConfig.AccessToken(auth);
                }

                if (managedIdentity)
                {
                    return new AzureAuthConfig.ManagedIdentity(Trim(clientId), Trim(managedIdentityResourceId), auth);
                }

                if (Trim(clientSecret) is not null)
                {
                    return new AzureAuthConfig.ClientSecret(Trim(tenantId), Trim(clientId), auth);
                }

                if (Trim(federatedTokenFile) is not null)
                {
                    return new AzureAuthConfig.WorkloadIdentity(Trim(tenantId), Trim(clientId), Trim(federatedTokenFile), auth);
                }

                return new AzureAuthConfig.Ambient(auth);
        }
    }

    private static string RequiredText(string name, string? value) =>
        Trim(value) ?? throw new PsignException($"{name} is required for the selected signing provider");

    private static void RequireRemoteDigest(SignDigestAlgorithm digest, string provider)
    {
        if (digest is SignDigestAlgorithm.Sha1 or SignDigestAlgorithm.CertHash)
        {
            throw new PsignException($"{provider} supports only SHA256, SHA384, or SHA512 file digests");
        }
    }

    private static bool Present(string? value) => Trim(value) is not null;

    private static string? Trim(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }
}
