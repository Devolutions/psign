namespace Devolutions.Psign.Signing.Code;

/// <summary>File / timestamp digest selector of <c>psign-tool code</c> (Rust <c>cli::DigestAlgorithm</c>).</summary>
public enum CodeDigestAlgorithm
{
    Sha1,
    Sha256,
    Sha384,
    Sha512,

    /// <summary>Native <c>/fd certHash</c> (rejected by the <c>code</c> orchestrator).</summary>
    CertHash,
}

/// <summary>Azure.Identity-style credential selector (Rust <c>cli::AzureCredentialType</c>).</summary>
public enum CodeAzureCredentialType
{
    Default,
    ManagedIdentity,
    AccessToken,
    ClientSecret,
    WorkloadIdentity,
}

/// <summary>
/// Options of the dotnet/sign-style <c>psign-tool code</c> orchestrator (Rust <c>cli::CodeArgs</c>). Defaults match the
/// clap defaults (<c>--recurse-containers true</c>, <c>--file-digest sha256</c>, <c>--store MY</c>).
/// </summary>
public sealed class CodeOptions
{
    /// <summary>Base directory used to resolve relative input patterns and file-list entries (default <c>.</c>).</summary>
    public string? BaseDirectory { get; set; }

    /// <summary>Text file containing include and <c>!</c> exclude patterns, one per line.</summary>
    public string? FileList { get; set; }

    /// <summary>Output file or directory.</summary>
    public string? Output { get; set; }

    /// <summary>Recurse into ZIP/OPC containers such as VSIX and NuGet packages.</summary>
    public bool RecurseContainers { get; set; } = true;

    /// <summary>Maximum independent top-level signing concurrency.</summary>
    public int? MaxConcurrency { get; set; }

    public string? ApplicationName { get; set; }

    public string? PublisherName { get; set; }

    public string? Description { get; set; }

    public string? DescriptionUrl { get; set; }

    public CodeDigestAlgorithm FileDigest { get; set; } = CodeDigestAlgorithm.Sha256;

    public string? TimestampUrl { get; set; }

    public CodeDigestAlgorithm? TimestampDigest { get; set; }

    public bool ContinueOnError { get; set; }

    public bool SkipSigned { get; set; }

    public bool Overwrite { get; set; }

    /// <summary>Signer certificate (DER or PEM).</summary>
    public string? Cert { get; set; }

    /// <summary>RSA private key (PKCS#8 / PKCS#1, DER or unencrypted PEM).</summary>
    public string? Key { get; set; }

    public string? Pfx { get; set; }

    public string? Password { get; set; }

    /// <summary>Portable cert-store SHA-1 thumbprint (<c>--sha1</c>).</summary>
    public string? CertSha1 { get; set; }

    public string? CertStoreDir { get; set; }

    public bool MachineStore { get; set; }

    public string StoreName { get; set; } = "MY";

    public string? AzureKeyVaultUrl { get; set; }

    public string? AzureKeyVaultCertificate { get; set; }

    public string? AzureKeyVaultCertificateVersion { get; set; }

    public string? AzureKeyVaultClientId { get; set; }

    public string? AzureKeyVaultClientSecret { get; set; }

    public string? AzureKeyVaultTenantId { get; set; }

    public string? AzureKeyVaultAccessToken { get; set; }

    public bool AzureKeyVaultManagedIdentity { get; set; }

    public CodeAzureCredentialType? AzureKeyVaultCredentialType { get; set; }

    public string? AzureAuthority { get; set; }

    public string? ArtifactSigningMetadata { get; set; }

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

    public CodeAzureCredentialType? ArtifactSigningCredentialType { get; set; }

    public string? ArtifactSigningTenantId { get; set; }

    public string? ArtifactSigningClientId { get; set; }

    public string? ArtifactSigningClientSecret { get; set; }

    public string? ArtifactSigningFederatedTokenFile { get; set; }

    public string? ArtifactSigningAuthority { get; set; }

    public string? ArtifactSigningEndpointBaseUrl { get; set; }

    /// <summary>Additional certificates to include in generated PKCS#7 signatures (<c>--chain-cert</c>).</summary>
    public List<string> ChainCerts { get; set; } = [];

    /// <summary>Build and print the signing graph without modifying files.</summary>
    public bool DryRun { get; set; }

    /// <summary>Emit the dry-run graph as JSON.</summary>
    public bool PlanJson { get; set; }

    /// <summary>Files or glob patterns to include.</summary>
    public List<string> Inputs { get; set; } = [];

    /// <summary>Optional HTTP handler for the TSA / Azure Key Vault / Artifact Signing clients (tests).</summary>
    public HttpMessageHandler? HttpHandler { get; set; }

    /// <summary>Optional environment lookup for the Artifact Signing credential chain and the portable cert store.</summary>
    public Func<string, string?>? Environment { get; set; }
}

/// <summary>Output of <see cref="CodeOrchestrator.Run"/> (Rust <c>CommandOutput</c>).</summary>
public sealed record CodeCommandResult(string Stdout, int ExitCode);
