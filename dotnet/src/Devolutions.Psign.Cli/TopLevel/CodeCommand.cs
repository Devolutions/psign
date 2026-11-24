using System.Globalization;
using System.Text;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Signing.Code;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>Top-level <c>psign-tool code</c> command (Rust <c>cli::CodeArgs</c> + <c>code::code_command</c>).</summary>
internal static class CodeCommand
{
    private static readonly string[] DigestValues = ["sha1", "sha256", "sha384", "sha512", "cert-hash", "certHash"];
    private static readonly string[] CredentialTypeValues = ["default", "managed-identity", "access-token", "client-secret", "workload-identity"];

    public static void Register(CommandSpec root)
    {
        root.Sub("code", "Plan or run dotnet/sign-style code-signing orchestration over files, globs, and nested containers.", c =>
        {
            c.Value("base-directory", "BASE_DIRECTORY", "Base directory used to resolve relative input patterns and file-list entries.");
            c.Value("file-list", "FILE_LIST", "Text file containing include and `!` exclude patterns, one per line.");
            c.Value("output", "OUTPUT", "Output file/directory for future signing runs. Dry-run records it but does not write signed content.");
            var recurse = c.Value("recurse-containers", "RECURSE_CONTAINERS", "Recurse into ZIP/OPC containers such as VSIX and NuGet packages.", "true");
            recurse.IsExplicitBool = true;
            recurse.PossibleValues = ["true", "false"];
            c.Value("max-concurrency", "MAX_CONCURRENCY", "Maximum independent top-level signing concurrency used by the orchestrator.");
            c.Value("application-name", "APPLICATION_NAME", "Authenticode/package application display name.");
            c.Value("publisher-name", "PUBLISHER_NAME", "Package publisher name.");
            c.Value("description", "DESCRIPTION", "Authenticode description.");
            c.Value("description-url", "DESCRIPTION_URL", "Authenticode description URL.");
            c.Choice("file-digest", DigestValues, "sha256", "File digest algorithm for future signing runs.").CaseInsensitive();
            c.Value("timestamp-url", "TIMESTAMP_URL", "RFC3161 timestamp URL for future signing runs.");
            c.Choice("timestamp-digest", DigestValues, null, "RFC3161 timestamp digest algorithm for future signing runs.").CaseInsensitive();
            c.Flag("continue-on-error", "Continue planning/signing remaining top-level inputs after an error.");
            c.Flag("skip-signed", "Skip files already signed when future signing support is enabled.");
            c.Flag("overwrite", "Replace existing package-native signatures instead of failing when NuGet/VSIX signatures are present.").Conflicts("skip-signed");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM for initial local package signing execution.").Requiring("key").Conflicts("sha1", "pfx");
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM for initial local package signing execution.").Requiring("cert").Conflicts("sha1", "pfx");
            c.Value("pfx", "PATH", "PFX/PKCS#12 signer identity for local package signing execution.").Alias("f").Conflicts("sha1");
            c.Value("password", "PASSWORD", "Optional password for the PFX/PKCS#12 signer identity.").Alias("p").Requiring("pfx");
            c.Value("sha1", "CERT_SHA1", "Resolve a local portable cert-store signing identity by SHA-1 thumbprint.").Alias("cert-sha1").Conflicts("pfx");
            c.Value("cert-store-dir", "CERT_STORE_DIR", "Portable certificate store base directory for `--sha1`.");
            c.Flag("machine-store", "Use the LocalMachine scope in the portable certificate store for `--sha1`.").Alias("sm");
            c.Value("store", "STORE_NAME", "Portable certificate store name for `--sha1`.", "MY").Alias("s");
            c.Value("azure-key-vault-url", "AZURE_KEY_VAULT_URL", "Azure Key Vault URL for remote package/orchestrator signing.").Alias("kvu");
            c.Value("azure-key-vault-certificate", "AZURE_KEY_VAULT_CERTIFICATE", "Azure Key Vault signing certificate name.").Alias("kvc");
            c.Value("azure-key-vault-certificate-version", "AZURE_KEY_VAULT_CERTIFICATE_VERSION", "Optional Azure Key Vault certificate version.").Alias("kvcv");
            c.Value("azure-key-vault-client-id", "AZURE_KEY_VAULT_CLIENT_ID").Alias("kvi");
            c.Value("azure-key-vault-client-secret", "AZURE_KEY_VAULT_CLIENT_SECRET").Alias("kvs");
            c.Value("azure-key-vault-tenant-id", "AZURE_KEY_VAULT_TENANT_ID").Alias("kvt");
            c.Value("azure-key-vault-accesstoken", "AZURE_KEY_VAULT_ACCESS_TOKEN").Alias("kva");
            c.Flag("azure-key-vault-managed-identity", "Managed identity / DefaultAzureCredential-style acquisition via IMDS.").Alias("kvm");
            c.Choice("azure-key-vault-credential-type", CredentialTypeValues, null, "Azure.Identity-style credential selector for Key Vault signing.");
            c.Value("azure-authority", "AZURE_AUTHORITY", "OAuth authority host prefix, e.g. `https://login.microsoftonline.com`.").Alias("au");
            c.Value("artifact-signing-metadata", "ARTIFACT_SIGNING_METADATA", "Artifact Signing metadata JSON (same shape as Microsoft's dlib `/dmdf` file).");
            c.Value("artifact-signing-region", "ARTIFACT_SIGNING_REGION", "Artifact Signing regional hostname segment, e.g. `westus`, when not using metadata Endpoint.");
            c.Value("artifact-signing-endpoint", "ARTIFACT_SIGNING_ENDPOINT", "Artifact Signing data-plane endpoint, e.g. `https://wus2.codesigning.azure.net`.");
            c.Value("artifact-signing-account-name", "ARTIFACT_SIGNING_ACCOUNT_NAME");
            c.Value("artifact-signing-profile-name", "ARTIFACT_SIGNING_PROFILE_NAME");
            c.Value("artifact-signing-signature-algorithm", "ARTIFACT_SIGNING_SIGNATURE_ALGORITHM");
            c.Value("artifact-signing-api-version", "ARTIFACT_SIGNING_API_VERSION");
            c.Value("artifact-signing-correlation-id", "ARTIFACT_SIGNING_CORRELATION_ID");
            c.Value("artifact-signing-access-token", "ARTIFACT_SIGNING_ACCESS_TOKEN");
            c.Flag("artifact-signing-managed-identity");
            c.Value("artifact-signing-managed-identity-resource-id", "ARTIFACT_SIGNING_MANAGED_IDENTITY_RESOURCE_ID", "Managed identity resource ID for Artifact Signing user-assigned identity auth.");
            c.Choice("artifact-signing-credential-type", CredentialTypeValues, null, "Azure.Identity-style credential selector for Artifact Signing.");
            c.Value("artifact-signing-tenant-id", "ARTIFACT_SIGNING_TENANT_ID");
            c.Value("artifact-signing-client-id", "ARTIFACT_SIGNING_CLIENT_ID");
            c.Value("artifact-signing-client-secret", "ARTIFACT_SIGNING_CLIENT_SECRET");
            c.Value("artifact-signing-federated-token-file", "ARTIFACT_SIGNING_FEDERATED_TOKEN_FILE", "Federated token file for workload identity Artifact Signing auth.");
            c.Value("artifact-signing-authority", "ARTIFACT_SIGNING_AUTHORITY");
            c.Value("artifact-signing-endpoint-base-url", "ARTIFACT_SIGNING_ENDPOINT_BASE_URL", "Override Artifact Signing data-plane origin for deterministic local tests.").Hide();
            c.Multi("chain-cert", "PATH", "Additional certificate to include in generated PKCS#7 signatures.");
            c.Flag("dry-run", "Build and print the signing graph without modifying files.");
            c.Flag("plan-json", "Emit the dry-run signing graph as JSON.").Requiring("dry-run");
            c.Positionals.Add(new PositionalSpec("inputs", required: false, multiple: true) { ValueName = "INPUTS", Help = "Files or glob patterns to include." });
            c.Handler = Run;
        });
    }

    private static int Run(ParsedCommand p)
    {
        var options = ToOptions(p);
        var result = CodeOrchestrator.Run(options);
        if (p.Flag("debug"))
        {
            Output.ErrorLine($"[debug] exit_code={result.ExitCode} stdout_len={Encoding.UTF8.GetByteCount(result.Stdout)}");
        }

        if (!p.Flag("quiet") || result.ExitCode != 0)
        {
            Output.Write(result.Stdout);
        }

        return result.ExitCode;
    }

    internal static CodeOptions ToOptions(ParsedCommand p) => new()
    {
        BaseDirectory = p.Value("base-directory"),
        FileList = p.Value("file-list"),
        Output = p.Value("output"),
        RecurseContainers = p.Flag("recurse-containers"),
        MaxConcurrency = ParseUsize(p.Value("max-concurrency")),
        ApplicationName = p.Value("application-name"),
        PublisherName = p.Value("publisher-name"),
        Description = p.Value("description"),
        DescriptionUrl = p.Value("description-url"),
        FileDigest = ParseDigest(p.Value("file-digest")) ?? CodeDigestAlgorithm.Sha256,
        TimestampUrl = p.Value("timestamp-url"),
        TimestampDigest = ParseDigest(p.Value("timestamp-digest")),
        ContinueOnError = p.Flag("continue-on-error"),
        SkipSigned = p.Flag("skip-signed"),
        Overwrite = p.Flag("overwrite"),
        Cert = p.Value("cert"),
        Key = p.Value("key"),
        Pfx = p.Value("pfx"),
        Password = p.Value("password"),
        CertSha1 = p.Value("sha1"),
        CertStoreDir = p.Value("cert-store-dir"),
        MachineStore = p.Flag("machine-store"),
        StoreName = p.Value("store") ?? "MY",
        AzureKeyVaultUrl = p.Value("azure-key-vault-url"),
        AzureKeyVaultCertificate = p.Value("azure-key-vault-certificate"),
        AzureKeyVaultCertificateVersion = p.Value("azure-key-vault-certificate-version"),
        AzureKeyVaultClientId = p.Value("azure-key-vault-client-id"),
        AzureKeyVaultClientSecret = p.Value("azure-key-vault-client-secret"),
        AzureKeyVaultTenantId = p.Value("azure-key-vault-tenant-id"),
        AzureKeyVaultAccessToken = p.Value("azure-key-vault-accesstoken"),
        AzureKeyVaultManagedIdentity = p.Flag("azure-key-vault-managed-identity"),
        AzureKeyVaultCredentialType = ParseCredentialType(p.Value("azure-key-vault-credential-type")),
        AzureAuthority = p.Value("azure-authority"),
        ArtifactSigningMetadata = p.Value("artifact-signing-metadata"),
        ArtifactSigningRegion = p.Value("artifact-signing-region"),
        ArtifactSigningEndpoint = p.Value("artifact-signing-endpoint"),
        ArtifactSigningAccountName = p.Value("artifact-signing-account-name"),
        ArtifactSigningProfileName = p.Value("artifact-signing-profile-name"),
        ArtifactSigningSignatureAlgorithm = p.Value("artifact-signing-signature-algorithm"),
        ArtifactSigningApiVersion = p.Value("artifact-signing-api-version"),
        ArtifactSigningCorrelationId = p.Value("artifact-signing-correlation-id"),
        ArtifactSigningAccessToken = p.Value("artifact-signing-access-token"),
        ArtifactSigningManagedIdentity = p.Flag("artifact-signing-managed-identity"),
        ArtifactSigningManagedIdentityResourceId = p.Value("artifact-signing-managed-identity-resource-id"),
        ArtifactSigningCredentialType = ParseCredentialType(p.Value("artifact-signing-credential-type")),
        ArtifactSigningTenantId = p.Value("artifact-signing-tenant-id"),
        ArtifactSigningClientId = p.Value("artifact-signing-client-id"),
        ArtifactSigningClientSecret = p.Value("artifact-signing-client-secret"),
        ArtifactSigningFederatedTokenFile = p.Value("artifact-signing-federated-token-file"),
        ArtifactSigningAuthority = p.Value("artifact-signing-authority"),
        ArtifactSigningEndpointBaseUrl = p.Value("artifact-signing-endpoint-base-url"),
        ChainCerts = p.Values("chain-cert").ToList(),
        DryRun = p.Flag("dry-run"),
        PlanJson = p.Flag("plan-json"),
        Inputs = p.PosAll("inputs").ToList(),
    };

    private static int? ParseUsize(string? value)
    {
        if (value is null)
        {
            return null;
        }

        var digits = value.StartsWith('+') ? value[1..] : value;
        if (digits.Length == 0)
        {
            throw new PsignException($"invalid value '{value}' for '--max-concurrency <MAX_CONCURRENCY>': cannot parse integer from empty string");
        }

        if (!digits.All(char.IsAsciiDigit))
        {
            throw new PsignException($"invalid value '{value}' for '--max-concurrency <MAX_CONCURRENCY>': invalid digit found in string");
        }

        if (!int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var n))
        {
            throw new PsignException($"invalid value '{value}' for '--max-concurrency <MAX_CONCURRENCY>': number too large to fit in target type");
        }

        return n;
    }

    private static CodeDigestAlgorithm? ParseDigest(string? value) => value?.ToLowerInvariant() switch
    {
        null => null,
        "sha1" => CodeDigestAlgorithm.Sha1,
        "sha256" => CodeDigestAlgorithm.Sha256,
        "sha384" => CodeDigestAlgorithm.Sha384,
        "sha512" => CodeDigestAlgorithm.Sha512,
        _ => CodeDigestAlgorithm.CertHash,
    };

    private static CodeAzureCredentialType? ParseCredentialType(string? value) => value switch
    {
        null => null,
        "default" => CodeAzureCredentialType.Default,
        "managed-identity" => CodeAzureCredentialType.ManagedIdentity,
        "access-token" => CodeAzureCredentialType.AccessToken,
        "client-secret" => CodeAzureCredentialType.ClientSecret,
        _ => CodeAzureCredentialType.WorkloadIdentity,
    };
}
