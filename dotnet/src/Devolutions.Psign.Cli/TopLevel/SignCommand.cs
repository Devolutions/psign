using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Text;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.Portable;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.CertStore;
using Devolutions.Psign.Signing.Portable;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>Parsed <c>psign-tool sign</c> arguments (Rust <c>cli::SignArgs</c>). Enum values use their clap names.</summary>
internal sealed record SignArgs
{
    public string? Pfx { get; init; }

    public string? Password { get; init; }

    public bool AutoSelect { get; init; }

    public string? SubjectName { get; init; }

    public string? IssuerName { get; init; }

    public string? CertSha1 { get; init; }

    public string? Csp { get; init; }

    public string? KeyContainer { get; init; }

    public bool MachineStore { get; init; }

    public string StoreName { get; init; } = "MY";

    public string? CertStoreDir { get; init; }

    public bool AppendSignature { get; init; }

    public bool PageHashes { get; init; }

    public bool NoPageHashes { get; init; }

    public string? Dlib { get; init; }

    public string? Dmdf { get; init; }

    public string? TrustedSigningDlibRoot { get; init; }

    /// <summary><c>sha1</c>, <c>sha256</c>, <c>sha384</c>, <c>sha512</c>, or <c>cert-hash</c>.</summary>
    public string Digest { get; init; } = "sha256";

    public string? TimestampUrl { get; init; }

    public string? LegacyTimestampUrl { get; init; }

    public string? SealTimestampUrl { get; init; }

    public string? TimestampDigest { get; init; }

    public string? Description { get; init; }

    public string? DescriptionUrl { get; init; }

    public IReadOnlyList<string> AdditionalCerts { get; init; } = [];

    public string? RootSubjectName { get; init; }

    public string? EkuOid { get; init; }

    public bool EkuWindowsSystemComponent { get; init; }

    public string? SigningCertEkuOidPrefix { get; init; }

    public string? DigestGenerate { get; init; }

    public bool DigestSignOnly { get; init; }

    public string? DigestIngest { get; init; }

    public bool DigestXml { get; init; }

    public string? Pkcs7OutputDir { get; init; }

    public string? Pkcs7ContentOid { get; init; }

    public string? Pkcs7ContentEmbedding { get; init; }

    public string? CertificateTemplate { get; init; }

    public IReadOnlyList<string> SignAuthPairs { get; init; } = [];

    public bool WarnFdDigestVsCertSignatureHash { get; init; }

    public bool WarnTdDigestVsCertSignatureHash { get; init; }

    public bool RelaxedPeMarkerCheck { get; init; }

    public bool AddSealingSignature { get; init; }

    public bool IntentToSeal { get; init; }

    public bool ForceSealOrResign { get; init; }

    public bool SignNoSealWarn { get; init; }

    public bool SignNoEnclaveWarn { get; init; }

    public string? RustSip { get; init; }

    public string? AzureKeyVaultUrl { get; init; }

    public string? AzureKeyVaultCertificate { get; init; }

    public string? AzureKeyVaultCertificateVersion { get; init; }

    public string? AzureKeyVaultClientId { get; init; }

    public string? AzureKeyVaultClientSecret { get; init; }

    public string? AzureKeyVaultTenantId { get; init; }

    public string? AzureKeyVaultAccessToken { get; init; }

    public bool AzureKeyVaultManagedIdentity { get; init; }

    public string? AzureKeyVaultCredentialType { get; init; }

    public string? AzureAuthority { get; init; }

    public string? ArtifactSigningMetadata { get; init; }

    public string? ArtifactSigningRegion { get; init; }

    public string? ArtifactSigningEndpoint { get; init; }

    public string? ArtifactSigningAccountName { get; init; }

    public string? ArtifactSigningProfileName { get; init; }

    public string? ArtifactSigningSignatureAlgorithm { get; init; }

    public string? ArtifactSigningApiVersion { get; init; }

    public string? ArtifactSigningCorrelationId { get; init; }

    public string? ArtifactSigningAccessToken { get; init; }

    public bool ArtifactSigningManagedIdentity { get; init; }

    public string? ArtifactSigningManagedIdentityResourceId { get; init; }

    public string? ArtifactSigningCredentialType { get; init; }

    public string? ArtifactSigningTenantId { get; init; }

    public string? ArtifactSigningClientId { get; init; }

    public string? ArtifactSigningClientSecret { get; init; }

    public string? ArtifactSigningFederatedTokenFile { get; init; }

    public string? ArtifactSigningAuthority { get; init; }

    public string? ArtifactSigningEndpointBaseUrl { get; init; }

    public string? SignInputFileList { get; init; }

    public bool ContinueOnError { get; init; }

    public bool SkipSigned { get; init; }

    public ulong? MaxDegreeParallelism { get; init; }

    /// <summary><c>signtool</c> or <c>azuresigntool</c> when given.</summary>
    public string? ExitCodes { get; init; }

    public IReadOnlyList<string> Files { get; init; } = [];
}

/// <summary>
/// <c>psign-tool sign</c> in portable mode (Rust <c>cli::SignArgs</c> + <c>portable_sign::sign_file</c>): local PFX /
/// portable certificate-store, Azure Key Vault and Azure Artifact Signing signing of every portable format with batch
/// execution (input-file lists, globs, bounded parallelism, continue-on-error, signtool / AzureSignTool exit codes).
/// </summary>
internal static class SignCommand
{
    public const string EnvExitCodes = "PSIGN_EXIT_CODES";

    public const string LegacyEnvExitCodes = "SIGNTOOL_RS_EXIT_CODES";

    internal static readonly string[] DigestValues = ["sha1", "sha256", "sha384", "sha512", "cert-hash"];

    private static readonly string[] CredentialTypeValues = ["default", "managed-identity", "access-token", "client-secret", "workload-identity"];

    private static readonly string[] RustSipValues = ["pe", "script", "msi", "esd", "msix", "cab", "catalog", "off"];

    private static readonly string[] Pkcs7ContentEmbeddingValues = ["embedded", "detached-signed-data", "pkcs7-detached-signed-data"];

    private static readonly string[] ExitCodeValues = ["signtool", "azuresigntool"];

    private const string UnsupportedSuffix =
        "local PFX/certificate-store and Azure Key Vault signing support PE/WinMD, CAB, MSI/MSP, MSIX/AppX packages and bundles, NuGet, VSIX, ClickOnce manifests, App Installer, ZIP, and PowerShell scripts, while Azure Artifact Signing supports its documented native-shaped subset";

    private const string AppendOnlyPe = "--as/--append-signature is only supported for portable PE/WinMD signing";

    /// <summary>Digest choice (clap <c>DigestAlgorithm</c> value enum, <c>ignore_case</c>, hidden alias <c>certHash</c>).</summary>
    internal static OptionSpec DigestChoice(CommandSpec c, string name, string? defaultValue, string help) =>
        c.Choice(name, DigestValues, defaultValue, help).CaseInsensitive().ValueAlias("certHash", "cert-hash");

    public static void Register(CommandSpec root)
    {
        root.Sub("sign", "Sign a file using mssign32 (`SignerSignEx3`).", c =>
        {
            c.Value("pfx", null, "PFX file to use.").Alias("f");
            c.Value("password", null, "Optional password for the PFX.").Alias("p");
            c.Flag("auto-select", "Automatically select the best certificate.").Alias("a");
            c.Value("subject-name", null, "Subject-name match for cert selection.").Alias("n");
            c.Value("issuer-name", null, "Issuer substring filter for cert selection (native /i).").Alias("i");
            c.Value("cert-sha1", null, "SHA1 thumbprint for cert selection.").Alias("sha1");
            c.Value("csp", null, "CSP name for cert private key.");
            c.Value("key-container", null, "Key container name.").Alias("kc");
            c.Flag("machine-store", "Use machine store.").Alias("sm");
            c.Value("store-name", null, "Certificate store name for non-PFX selection (default: MY).", "MY").Alias("s");
            c.Value("cert-store-dir", null, "Portable file-based certificate store root. Defaults to PSIGN_CERT_STORE or ~/.psign/cert-store.");
            c.Flag("append-signature", "Append signature instead of replacing.").Alias("as");
            c.Flag("page-hashes", "Generate page hashes (native /ph; requires decoupled digest for MSIX).").Alias("ph");
            c.Flag("no-page-hashes", "Suppress page hashes for PE when supported (native /nph).").Alias("nph");
            c.Value("dlib", null, "Decoupled digest provider DLL (native /dlib).");
            c.Value("dmdf", null, "Decoupled digest metadata file (native /dmdf).");
            c.Value("trusted-signing-dlib-root", null, "Extracted Microsoft Artifact Signing NuGet root (mutually exclusive with --dlib).")
                .Alias("artifact-signing-dlib-root").Conflicts("dlib");
            DigestChoice(c, "digest", "sha256", "Digest algorithm for signing (native /fd).").Alias("fd");
            c.Value("timestamp-url", null, "RFC3161 timestamp URL at sign time (native /tr).").Alias("tr").Conflicts("legacy-timestamp-url", "seal-timestamp-url");
            c.Value("legacy-timestamp-url", null, "Legacy Authenticode timestamp URL at sign time (native /t).").Alias("t").Conflicts("timestamp-url", "seal-timestamp-url");
            c.Value("seal-timestamp-url", null, "RFC3161 timestamp URL for sealed packages at sign time (native sign /tseal).").Alias("tseal").Conflicts("timestamp-url", "legacy-timestamp-url");
            DigestChoice(c, "timestamp-digest", null, "RFC3161 timestamp digest algorithm (native /td).").Alias("td");
            c.Value("description", null, "Authenticode description string (native /d on sign).").Alias("d");
            c.Value("description-url", null, "Authenticode description URL (native /du).").Alias("du");
            c.Multi("additional-certs", null, "Additional certificate files to include in the signature (native /ac; repeatable).").Alias("ac");
            c.Value("root-subject-name", null, "Root certificate subject substring the signing cert must chain to (native /r).").Alias("r");
            c.Value("eku-oid", null, "Enhanced key usage OID or friendly string required on the signing cert (native /u).").Alias("u");
            c.Flag("eku-windows-system-component", "Require Windows System Component Verification EKU (native /uw).").Alias("uw");
            c.Value("signing-cert-eku-prefix", "SIGNING_CERT_EKU_OID_PREFIX", "When selecting from a certificate store, require an EKU OID string starting with this prefix.");
            c.Value("digest-generate", null, "Split digest: generate digest and unsigned PKCS#7 (native /dg).").Alias("dg");
            c.Flag("digest-sign-only", "Split digest: sign digest file only (native /ds).").Alias("ds");
            c.Value("digest-ingest", null, "Split digest: ingest signed digest (native /di).").Alias("di");
            c.Flag("digest-xml", "With --digest-generate, emit XML (native /dxml).").Alias("dxml");
            c.Value("pkcs7-output-dir", null, "Write PKCS#7 output for each file (native /p7).").Alias("p7");
            c.Value("pkcs7-content-oid", null, "PKCS#7 content OID (native /p7co).").Alias("p7co");
            c.Choice("pkcs7-content-embedding", Pkcs7ContentEmbeddingValues, null, "PKCS#7 content embedding (native /p7ce).").Alias("p7ce");
            c.Value("certificate-template", null, "Certificate template name for cert selection (native /c).").Alias("c");
            var signAuth = c.Multi("sign-auth", "OID> <VALUE", "OID and UTF-8 value as authenticated attributes (native /sa OID value; repeatable).").Alias("sa");
            signAuth.ValuesPerOccurrence = 2;
            c.Flag("fdchw", "Warn if file digest algorithm differs from signing cert signature hash (native /fdchw) — not implemented.");
            c.Flag("tdchw", "Warn if RFC3161 timestamp digest differs from signing cert signature hash (native /tdchw) — not implemented.");
            c.Flag("rmc", "Relaxed PE marker check (native /rmc, MS12-024) — not implemented.");
            c.Flag("seal", "Add sealing signature when supported (native /seal) — not implemented.");
            c.Flag("itos", "Primary signature with intent-to-seal (native /itos) — not implemented.");
            c.Flag("force", "Remove existing signature/seal when required for sealing (native /force) — not implemented.");
            c.Flag("nosealwarn", "Sealing warnings do not change exit code (native /nosealwarn) — not implemented.");
            c.Flag("noenclavewarn", "Enclave warnings do not change exit code (native /noenclavewarn) — not implemented.");
            c.Choice("rust-sip", RustSipValues, null, "Experimental Rust SIP behavior (post-sign digest consistency check).");
            c.Value("azure-key-vault-url", "AZURE_KEY_VAULT_URL", "Azure Key Vault URL (AzureSignTool --azure-key-vault-url / -kvu).").Alias("kvu");
            c.Value("azure-key-vault-certificate", "AZURE_KEY_VAULT_CERTIFICATE", "Key Vault signing certificate name (-kvc).").Alias("kvc");
            c.Value("azure-key-vault-certificate-version", "AZURE_KEY_VAULT_CERTIFICATE_VERSION", "Optional certificate version (-kvcv).").Alias("kvcv");
            c.Value("azure-key-vault-client-id", "AZURE_KEY_VAULT_CLIENT_ID").Alias("kvi");
            c.Value("azure-key-vault-client-secret", "AZURE_KEY_VAULT_CLIENT_SECRET").Alias("kvs");
            c.Value("azure-key-vault-tenant-id", "AZURE_KEY_VAULT_TENANT_ID").Alias("kvt");
            c.Value("azure-key-vault-accesstoken", "AZURE_KEY_VAULT_ACCESS_TOKEN").Alias("kva");
            c.Flag("azure-key-vault-managed-identity", "Managed identity / DefaultAzureCredential-style acquisition via IMDS (-kvm).").Alias("kvm");
            c.Choice("azure-key-vault-credential-type", CredentialTypeValues, null, "Azure.Identity-style credential selector for Key Vault signing.");
            c.Value("azure-authority", "AZURE_AUTHORITY", "OAuth authority host prefix (-au), e.g. https://login.microsoftonline.com.").Alias("au");
            c.Value("artifact-signing-metadata", "ARTIFACT_SIGNING_METADATA", "Artifact Signing metadata JSON (same shape as Microsoft's dlib /dmdf file) for REST-backed portable signing.");
            c.Value("artifact-signing-region", "ARTIFACT_SIGNING_REGION", "Artifact Signing regional hostname segment, e.g. westus, when not using metadata Endpoint.");
            c.Value("artifact-signing-endpoint", "ARTIFACT_SIGNING_ENDPOINT", "Artifact Signing data-plane endpoint, e.g. https://wus2.codesigning.azure.net.");
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
            c.Value("input-file-list", "SIGN_INPUT_FILE_LIST", "Optional text file listing extra inputs to sign, one path per line (-ifl).").Alias("ifl");
            c.Flag("continue-on-error", "Continue signing remaining files when one fails (-coe).").Alias("coe");
            c.Flag("skip-signed", "Skip files that already have a valid embedded signature (AzureSignTool -s).");
            c.Value("max-degree-of-parallelism", "MAX_DEGREE_PARALLELISM", "Cap concurrent signing threads for multi-file batches (-mdop). 1 forces sequential signing.")
                .Alias("mdop").Unsigned();
            c.Choice("exit-codes", ExitCodeValues, null, "Batch exit-code scheme; overrides env when set. Env: PSIGN_EXIT_CODES=azure|signtool.").ValueAlias("azure", "azuresigntool");
            c.Positionals.Add(new PositionalSpec("files", required: false, multiple: true)
            {
                ValueName = "FILES",
                Help = "File(s) to sign (native trailing <filename(s)>).",
                RequiredUnlessPresent = "input-file-list",
            });
            c.Handler = p =>
            {
                var (stdout, exitCode) = SignFile(Parse(p));
                return PsignTool.PrintOutput(p, stdout, exitCode);
            };
        });
    }

    /// <summary>Build <see cref="SignArgs"/> from the parsed command.</summary>
    internal static SignArgs Parse(ParsedCommand p) => new()
    {
        Pfx = p.Value("pfx"),
        Password = p.Value("password"),
        AutoSelect = p.Flag("auto-select"),
        SubjectName = p.Value("subject-name"),
        IssuerName = p.Value("issuer-name"),
        CertSha1 = p.Value("cert-sha1"),
        Csp = p.Value("csp"),
        KeyContainer = p.Value("key-container"),
        MachineStore = p.Flag("machine-store"),
        StoreName = p.Value("store-name") ?? "MY",
        CertStoreDir = p.Value("cert-store-dir"),
        AppendSignature = p.Flag("append-signature"),
        PageHashes = p.Flag("page-hashes"),
        NoPageHashes = p.Flag("no-page-hashes"),
        Dlib = p.Value("dlib"),
        Dmdf = p.Value("dmdf"),
        TrustedSigningDlibRoot = p.Value("trusted-signing-dlib-root"),
        Digest = p.Value("digest") ?? "sha256",
        TimestampUrl = p.Value("timestamp-url"),
        LegacyTimestampUrl = p.Value("legacy-timestamp-url"),
        SealTimestampUrl = p.Value("seal-timestamp-url"),
        TimestampDigest = p.Value("timestamp-digest"),
        Description = p.Value("description"),
        DescriptionUrl = p.Value("description-url"),
        AdditionalCerts = p.Values("additional-certs").ToList(),
        RootSubjectName = p.Value("root-subject-name"),
        EkuOid = p.Value("eku-oid"),
        EkuWindowsSystemComponent = p.Flag("eku-windows-system-component"),
        SigningCertEkuOidPrefix = p.Value("signing-cert-eku-prefix"),
        DigestGenerate = p.Value("digest-generate"),
        DigestSignOnly = p.Flag("digest-sign-only"),
        DigestIngest = p.Value("digest-ingest"),
        DigestXml = p.Flag("digest-xml"),
        Pkcs7OutputDir = p.Value("pkcs7-output-dir"),
        Pkcs7ContentOid = p.Value("pkcs7-content-oid"),
        Pkcs7ContentEmbedding = p.Value("pkcs7-content-embedding"),
        CertificateTemplate = p.Value("certificate-template"),
        SignAuthPairs = p.Values("sign-auth").ToList(),
        WarnFdDigestVsCertSignatureHash = p.Flag("fdchw"),
        WarnTdDigestVsCertSignatureHash = p.Flag("tdchw"),
        RelaxedPeMarkerCheck = p.Flag("rmc"),
        AddSealingSignature = p.Flag("seal"),
        IntentToSeal = p.Flag("itos"),
        ForceSealOrResign = p.Flag("force"),
        SignNoSealWarn = p.Flag("nosealwarn"),
        SignNoEnclaveWarn = p.Flag("noenclavewarn"),
        RustSip = p.Value("rust-sip"),
        AzureKeyVaultUrl = p.Value("azure-key-vault-url"),
        AzureKeyVaultCertificate = p.Value("azure-key-vault-certificate"),
        AzureKeyVaultCertificateVersion = p.Value("azure-key-vault-certificate-version"),
        AzureKeyVaultClientId = p.Value("azure-key-vault-client-id"),
        AzureKeyVaultClientSecret = p.Value("azure-key-vault-client-secret"),
        AzureKeyVaultTenantId = p.Value("azure-key-vault-tenant-id"),
        AzureKeyVaultAccessToken = p.Value("azure-key-vault-accesstoken"),
        AzureKeyVaultManagedIdentity = p.Flag("azure-key-vault-managed-identity"),
        AzureKeyVaultCredentialType = p.Value("azure-key-vault-credential-type"),
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
        ArtifactSigningCredentialType = p.Value("artifact-signing-credential-type"),
        ArtifactSigningTenantId = p.Value("artifact-signing-tenant-id"),
        ArtifactSigningClientId = p.Value("artifact-signing-client-id"),
        ArtifactSigningClientSecret = p.Value("artifact-signing-client-secret"),
        ArtifactSigningFederatedTokenFile = p.Value("artifact-signing-federated-token-file"),
        ArtifactSigningAuthority = p.Value("artifact-signing-authority"),
        ArtifactSigningEndpointBaseUrl = p.Value("artifact-signing-endpoint-base-url"),
        SignInputFileList = p.Value("input-file-list"),
        ContinueOnError = p.Flag("continue-on-error"),
        SkipSigned = p.Flag("skip-signed"),
        MaxDegreeParallelism = p.Value("max-degree-of-parallelism") is { } mdop
            ? ulong.Parse(mdop.StartsWith('+') ? mdop[1..] : mdop, NumberStyles.None, CultureInfo.InvariantCulture)
            : null,
        ExitCodes = p.Value("exit-codes"),
        Files = p.PosAll("files").ToList(),
    };

    // ------------------------------------------------------------------ entry point

    /// <summary>Rust <c>portable_sign::sign_file</c>: returns the combined stdout and the batch exit code.</summary>
    internal static (string Stdout, int ExitCode) SignFile(SignArgs args)
    {
        if (ArtifactSigningRequested(args) && AzureKeyVaultRequested(args))
        {
            throw new PsignException("portable sign accepts either Azure Artifact Signing or Azure Key Vault options, not both");
        }

        if (ArtifactSigningRequested(args))
        {
            ValidateArtifactSigningSupportedOptions(args);
            var asTargets = ExpandSignTargets(args);
            if (asTargets.Count == 0)
            {
                throw new PsignException("portable Artifact Signing sign requires at least one file");
            }

            return ExecuteSignBatch(args, asTargets, target => TrySignOneArtifactSigning(target, args));
        }

        if (AzureKeyVaultRequested(args))
        {
            ValidateAzureKeyVaultSupportedOptions(args);
            var kvTargets = ExpandSignTargets(args);
            if (kvTargets.Count == 0)
            {
                throw new PsignException("portable Azure Key Vault sign requires at least one file");
            }

            return ExecuteSignBatch(args, kvTargets, target => TrySignOneAzureKeyVault(target, args));
        }

        ValidateSupportedOptions(args);
        var targets = ExpandSignTargets(args);
        if (targets.Count == 0)
        {
            throw new PsignException("portable sign requires at least one file");
        }

        CertStoreSigningIdentity? identity = null;
        if (args.Pfx is null)
        {
            var thumbprint = args.CertSha1 ?? throw new PsignException("portable sign requires --sha1 <thumbprint> without --pfx");
            identity = new PortableCertStore().ResolveSigningIdentity(args.CertStoreDir, args.MachineStore, args.StoreName, thumbprint);
        }

        return ExecuteSignBatch(args, targets, target => TrySignOneLocal(target, args, identity));
    }

    // ------------------------------------------------------------------ batch execution

    private sealed record BatchRow(string? Block, Exception? Error);

    /// <summary>
    /// Rust <c>execute_sign_batch</c>: every target is attempted (in parallel when allowed), results are reported in input
    /// order; without <c>--continue-on-error</c> the first failing target's error is returned.
    /// </summary>
    internal static (string Stdout, int ExitCode) ExecuteSignBatch(SignArgs args, IReadOnlyList<string> targets, Func<string, string> signOne)
    {
        bool parallel = args.MaxDegreeParallelism != 1 && targets.Count > 1 && !HasDuplicateTargetIdentities(targets);
        ulong threads = args.MaxDegreeParallelism ?? (ulong)Environment.ProcessorCount;
        var rows = new BatchRow[targets.Count];

        BatchRow Run(string target)
        {
            try
            {
                return new BatchRow(signOne(target), null);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                return new BatchRow(null, e);
            }
        }

        if (parallel)
        {
            var options = new ParallelOptions { MaxDegreeOfParallelism = (int)Math.Min(Math.Max(threads, 1UL), int.MaxValue) };
            Parallel.For(0, targets.Count, options, i => rows[i] = Run(targets[i]));
        }
        else
        {
            for (int i = 0; i < targets.Count; i++)
            {
                rows[i] = Run(targets[i]);
            }
        }

        // A nested usage error exits the Rust process immediately.
        if (rows.FirstOrDefault(r => r.Error is CliExitException) is { Error: { } exit })
        {
            ExceptionDispatchInfo.Capture(exit).Throw();
        }

        var combined = new StringBuilder();
        int successes = 0;
        int failures = 0;
        for (int idx = 0; idx < rows.Length; idx++)
        {
            if (idx > 0)
            {
                combined.Append('\n');
            }

            var row = rows[idx];
            if (row.Error is null)
            {
                successes++;
                combined.Append(row.Block);
            }
            else if (args.ContinueOnError)
            {
                failures++;
                combined.Append("Failed: ").Append(targets[idx]).Append(": ").Append(PsignException.Render(row.Error)).Append('\n');
            }
            else
            {
                ExceptionDispatchInfo.Capture(row.Error).Throw();
            }
        }

        return (combined.ToString(), BatchExitCode(ResolvedSignExitCodes(args, Environment.GetEnvironmentVariable), successes, failures));
    }

    /// <summary>Rust <c>resolved_sign_exit_codes</c>: <c>--exit-codes</c>, else <c>PSIGN_EXIT_CODES</c> / <c>SIGNTOOL_RS_EXIT_CODES</c>.</summary>
    internal static string ResolvedSignExitCodes(SignArgs args, Func<string, string?> environment)
    {
        if (args.ExitCodes is { } explicitScheme)
        {
            return explicitScheme;
        }

        var envValue = environment(EnvExitCodes);
        if (string.IsNullOrWhiteSpace(envValue))
        {
            envValue = environment(LegacyEnvExitCodes);
        }

        if (!string.IsNullOrWhiteSpace(envValue))
        {
            var t = envValue.Trim();
            return RustText.EqualsIgnoreAsciiCase(t, "azure") || RustText.EqualsIgnoreAsciiCase(t, "azuresigntool") ? "azuresigntool" : "signtool";
        }

        return "signtool";
    }

    /// <summary>Rust <c>batch_exit_code</c>.</summary>
    internal static int BatchExitCode(string scheme, int successes, int failures)
    {
        if (scheme == "signtool")
        {
            return failures > 0 ? 1 : 0;
        }

        if (successes > 0 && failures == 0)
        {
            return 0;
        }

        if (successes > 0 && failures > 0)
        {
            return ResponseArgv.AzureSignExitPartialSuccess;
        }

        return successes == 0 && failures > 0 ? ResponseArgv.AzureSignExitAllFailed : 0;
    }

    // ------------------------------------------------------------------ targets

    /// <summary>Rust <c>expand_sign_targets</c>: input-file-list lines (globbed, deduplicated) then trailing targets.</summary>
    internal static List<string> ExpandSignTargets(SignArgs args)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var output = new List<string>();
        if (args.SignInputFileList is { } ifl)
        {
            var text = CliIo.ReadText(ifl, $"read --input-file-list {ifl}");
            foreach (var line in RustText.Lines(text))
            {
                var t = line.Trim();
                if (t.Length == 0 || t.StartsWith('#'))
                {
                    continue;
                }

                ExpandGlobPattern(t, output, seen);
            }
        }

        foreach (var p in args.Files)
        {
            if (!PathExists(p) && HasWildcard(p))
            {
                ExpandGlobPattern(p, output, seen);
            }
            else
            {
                // Native-shaped trailing targets are operations, not a set: signing the same PE twice with
                // --append-signature intentionally adds two signatures.
                output.Add(p);
            }
        }

        return output;
    }

    private static bool PathExists(string path) => File.Exists(path) || Directory.Exists(path);

    private static bool HasWildcard(string pattern) => pattern.IndexOfAny(['*', '?', '[']) >= 0;

    private static void ExpandGlobPattern(string pattern, List<string> output, HashSet<string> seen)
    {
        pattern = pattern.Trim();
        if (pattern.Length == 0)
        {
            return;
        }

        if (!PathExists(pattern) && HasWildcard(pattern))
        {
            foreach (var match in RustGlob.Enumerate(pattern))
            {
                InsertSignTarget(match, output, seen);
            }
        }
        else
        {
            InsertSignTarget(pattern, output, seen);
        }
    }

    internal static void InsertSignTarget(string path, List<string> output, HashSet<string> seen)
    {
        if (seen.Add(TargetIdentity(path)))
        {
            output.Add(path);
        }
    }

    internal static bool HasDuplicateTargetIdentities(IReadOnlyList<string> targets)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        return targets.Any(t => !seen.Add(TargetIdentity(t)));
    }

    /// <summary>
    /// Rust <c>std::fs::canonicalize(path).unwrap_or(path)</c> identity: the resolved absolute path of an existing file
    /// (case-insensitive on Windows), otherwise the path's normalized components.
    /// </summary>
    internal static string TargetIdentity(string path)
    {
        try
        {
            if (File.Exists(path) || Directory.Exists(path))
            {
                var full = Path.GetFullPath(path);
                FileSystemInfo info = File.Exists(full) ? new FileInfo(full) : new DirectoryInfo(full);
                if (info.LinkTarget is not null && info.ResolveLinkTarget(returnFinalTarget: true) is { } resolved)
                {
                    full = resolved.FullName;
                }

                return "c:" + (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? full.ToUpperInvariant() : full);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
        }

        return "p:" + ComponentKey(path);
    }

    private static string ComponentKey(string path)
    {
        var parts = new List<string>();
        int start = 0;
        bool rooted = path.Length > 0 && IsSeparator(path[0]);
        for (int i = 0; i <= path.Length; i++)
        {
            if (i == path.Length || IsSeparator(path[i]))
            {
                var part = path[start..i];
                if (part.Length > 0 && (part != "." || parts.Count == 0))
                {
                    parts.Add(part);
                }

                start = i + 1;
            }
        }

        return (rooted ? "/" : string.Empty) + string.Join('/', parts);
    }

    private static bool IsSeparator(char c) => c == '/' || (OperatingSystem.IsWindows() && c == '\\');

    /// <summary>
    /// Rust <c>temporary_output_path</c>: <c>{stem}.psign-{pid}-{id:016x}.{ext}</c> next to the target (the id hashes the
    /// target path so same-named targets in different directories never collide).
    /// </summary>
    internal static string TemporaryOutputPath(string target)
    {
        var name = RustPath.FileName(target);
        var stem = FileStem(name) ?? "signed-output";
        var id = Fnv1a64(target).ToString("x16", CultureInfo.InvariantCulture);
        var pid = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);
        var fileName = RustPath.Extension(target) is { } ext ? $"{stem}.psign-{pid}-{id}.{ext}" : $"{stem}.psign-{pid}-{id}";
        return WithFileName(target, name, fileName);
    }

    private static string? FileStem(string? name)
    {
        if (name is null)
        {
            return null;
        }

        int dot = name.LastIndexOf('.');
        return dot <= 0 ? name : name[..dot];
    }

    /// <summary>Rust <c>Path::with_file_name</c>.</summary>
    private static string WithFileName(string path, string? currentName, string fileName)
    {
        if (currentName is null)
        {
            return RustGlob.Join(path, fileName);
        }

        int last = -1;
        for (int i = path.Length - 1; i >= 0; i--)
        {
            if (IsSeparator(path[i]))
            {
                last = i;
                break;
            }
        }

        string parent;
        if (last < 0)
        {
            parent = OperatingSystem.IsWindows() && path.Length >= 2 && path[1] == ':' && char.IsAsciiLetter(path[0]) ? path[..2] : string.Empty;
        }
        else
        {
            parent = path[..last].TrimEnd('/', OperatingSystem.IsWindows() ? '\\' : '/');
            bool driveRoot = OperatingSystem.IsWindows() && parent.Length == 2 && parent[1] == ':' && char.IsAsciiLetter(parent[0]);
            if (parent.Length == 0 || driveRoot)
            {
                parent = path[..(last + 1)];
            }
        }

        return RustGlob.Join(parent, fileName);
    }

    private static ulong Fnv1a64(string text)
    {
        ulong hash = 0xcbf29ce484222325;
        foreach (var b in Encoding.UTF8.GetBytes(text))
        {
            hash ^= b;
            hash *= 0x100000001b3;
        }

        return hash;
    }

    private static string TargetExtensionLower(string target) => RustText.ToAsciiLowercase(RustPath.Extension(target) ?? string.Empty);

    private static bool IsPeWinmdExtension(string ext) => ext is "exe" or "dll" or "sys" or "ocx" or "efi" or "winmd";

    // ------------------------------------------------------------------ per-target signing

    private static string TrySignOneLocal(string target, SignArgs args, CertStoreSigningIdentity? identity)
    {
        if (args.SkipSigned && TargetShouldSkipSigned(target))
        {
            return $"Skipped (already signed): {target}\n";
        }

        var request = PortableSignRequestFor(target, TemporaryOutputPath(target), args);
        if (args.Pfx is { } pfx)
        {
            request.PfxPath = pfx;
            request.PfxPassword = args.Password;
        }
        else
        {
            request.CertificatePath = identity!.CertPath;
            request.PrivateKeyPath = identity.KeyPath;
        }

        RunPortableCoreSign(request, "portable sign");
        var block = new StringBuilder($"Signed: {target}\n");
        if (identity is not null)
        {
            block.Append("thumbprint_sha1=").Append(identity.ThumbprintSha1).Append('\n')
                .Append("store=").Append(identity.Scope).Append('\\').Append(identity.StoreName).Append('\n');
        }
        else
        {
            block.Append("pfx=").Append(args.Pfx).Append('\n');
        }

        return block.ToString();
    }

    private static string TrySignOneAzureKeyVault(string target, SignArgs args)
    {
        if (args.SkipSigned && TargetShouldSkipSigned(target))
        {
            return $"Skipped (already signed): {target}\n";
        }

        var request = PortableSignRequestFor(target, TemporaryOutputPath(target), args);
        request.AzureKeyVaultUrl = TextOpt(args.AzureKeyVaultUrl);
        request.AzureKeyVaultCertificate = TextOpt(args.AzureKeyVaultCertificate);
        request.AzureKeyVaultCertificateVersion = TextOpt(args.AzureKeyVaultCertificateVersion);
        request.AzureKeyVaultAccessToken = TextOpt(args.AzureKeyVaultAccessToken);
        request.AzureKeyVaultClientId = TextOpt(args.AzureKeyVaultClientId);
        request.AzureKeyVaultClientSecret = TextOpt(args.AzureKeyVaultClientSecret);
        request.AzureKeyVaultTenantId = TextOpt(args.AzureKeyVaultTenantId);
        request.AzureKeyVaultManagedIdentity = args.AzureKeyVaultManagedIdentity || args.AzureKeyVaultCredentialType == "managed-identity";
        request.AzureAuthority = TextOpt(args.AzureAuthority);
        RunPortableCoreSign(request, "portable Azure Key Vault sign");
        return $"Signed: {target}\nazure_key_vault_certificate={args.AzureKeyVaultCertificate ?? "<missing>"}\n";
    }

    private static string TrySignOneArtifactSigning(string target, SignArgs args)
    {
        if (args.SkipSigned && TargetShouldSkipSigned(target))
        {
            return $"Skipped (already signed): {target}\n";
        }

        try
        {
            SignOneTargetArtifactSigning(target, args);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            throw new PsignException($"portable Artifact Signing sign '{target}'", e);
        }

        return $"Signed: {target}\nartifact_signing_profile={args.ArtifactSigningProfileName ?? "<metadata>"}\n";
    }

    /// <summary>Rust <c>target_should_skip_signed</c>.</summary>
    internal static bool TargetShouldSkipSigned(string target)
    {
        var ext = TargetExtensionLower(target);
        if (IsPeWinmdExtension(ext))
        {
            var image = Output.ReadFile(target, $"read '{target}'");
            try
            {
                return PeAuthenticode.VerifyDigestConsistencyIfSigned(image) is not null;
            }
            catch (Exception e) when (IsOperationError(e))
            {
                throw new PsignException($"check existing PE/WinMD Authenticode signature on '{target}'", e);
            }
        }

        switch (ext)
        {
            case "cab":
                {
                    var bytes = Output.ReadFile(target, $"read '{target}'");
                    return Succeeds(() => CabDigest.SignaturePkcs7Der(bytes));
                }

            case "msi" or "msp":
                {
                    var bytes = Output.ReadFile(target, $"read '{target}'");
                    return Succeeds(() => MsiDigest.DigitalSignaturePkcs7Der(bytes));
                }

            case "msix" or "appx" or "msixbundle" or "appxbundle":
                return Succeeds(() =>
                {
                    MsixDigest.VerifyMsixDigestConsistency(target);
                    return true;
                });
            default:
                return false;
        }
    }

    private static bool Succeeds<T>(Func<T> action)
    {
        try
        {
            action();
            return true;
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return false;
        }
    }

    /// <summary>Errors reported as <c>anyhow</c> errors (not nested process exits or programming errors).</summary>
    private static bool IsOperationError(Exception e) => e is not CliExitException && PortableCore.IsOperationError(e);

    private static PortableSignRequest PortableSignRequestFor(string target, string output, SignArgs args)
    {
        ValidatePortableCoreTarget(target, args.AppendSignature);
        return new PortableSignRequest
        {
            Path = target,
            AppendSignature = args.AppendSignature,
            SkipSigned = args.SkipSigned,
            OutputPath = output,
            HashAlgorithm = PortableCoreDigest(args.Digest),
            ChainCertificatePaths = [.. args.AdditionalCerts],
            TimestampServer = TextOpt(args.TimestampUrl),
            TimestampHashAlgorithm = args.TimestampDigest is { } td ? PortableCoreTimestampDigest(td) : null,
        };
    }

    /// <summary>Rust <c>validate_portable_core_target</c>.</summary>
    internal static PortableFileFormat ValidatePortableCoreTarget(string target, bool appendSignature)
    {
        var ext = TargetExtensionLower(target);
        if (MsixDigest.IsEncryptedMsixExtension(ext))
        {
            throw new PsignException(
                $"portable signing does not support encrypted MSIX/AppX packages (.{ext}); encrypted packages require Windows AppxSip OS delegation: {target}");
        }

        if (ext is "appxupload" or "msixupload")
        {
            throw new PsignException(
                $"portable signing does not support MSIX/AppX upload bundles (.{ext}); upload containers wrap flat packages produced by `dotnet/SignTool`-style tooling and are not AppX SIP verify subjects: {target}");
        }

        var format = PortableCore.InferFormat(target);
        switch (format)
        {
            case PortableFileFormat.Catalog:
                throw new PsignException(
                    "portable native-shaped signing does not support catalog targets; use `psign-tool portable sign-catalog` with an explicit subject list");
            case PortableFileFormat.WshScript:
                throw new PsignException($"portable native-shaped signing does not support WSH script targets (.vbs, .js, .wsf): {target}");
            case PortableFileFormat.Unknown:
                throw new PsignException(
                    $"portable native-shaped signing supports PE/WinMD, CAB, MSI/MSP, MSIX/AppX packages and bundles, NuGet, VSIX, ClickOnce manifests, App Installer, ZIP, and PowerShell scripts; got {target}");
        }

        if (appendSignature && format != PortableFileFormat.Pe)
        {
            throw new PsignException(AppendOnlyPe);
        }

        return format;
    }

    /// <summary>Rust <c>run_portable_core_sign</c>: sign into a temporary output, self-check, then copy over the target.</summary>
    private static void RunPortableCoreSign(PortableSignRequest request, string operation)
    {
        var target = request.Path;
        var output = request.OutputPath!;
        var format = ValidatePortableCoreTarget(target, request.AppendSignature);
        var companion = format == PortableFileFormat.AppInstaller ? PortableCore.AppInstallerCompanionPath(output) : null;
        try
        {
            PortableSignResponse response;
            try
            {
                response = PortableCore.PortableSign(request);
            }
            catch (Exception e) when (IsOperationError(e))
            {
                throw new PsignException($"{operation} '{target}'", e);
            }

            EnsureValidSignatureResponse(response, target);
            CopyFile(output, target, $"replace '{target}' with signed output");
            if (companion is not null)
            {
                var targetCompanion = PortableCore.AppInstallerCompanionPath(target);
                CopyFile(companion, targetCompanion, $"replace App Installer companion '{targetCompanion}' with '{companion}'");
            }
        }
        finally
        {
            TryDelete(output);
            if (companion is not null)
            {
                TryDelete(companion);
            }
        }
    }

    /// <summary>
    /// Rust <c>ensure_valid_signature_response</c>: never replace the target when the post-sign self-check is not
    /// <c>Valid</c> (also for skipped files).
    /// </summary>
    internal static void EnsureValidSignatureResponse(PortableSignResponse response, string target)
    {
        if (response.Signature.Status != PortableSignatureStatus.Valid)
        {
            throw new PsignException(
                $"portable sign produced a signature that failed self-verification for '{target}': {response.Signature.Status} ({response.Signature.StatusMessage})");
        }
    }

    private static void CopyFile(string source, string destination, string context)
    {
        try
        {
            File.Copy(source, destination, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException(context, IoErrorText.Inner(e));
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
        }
    }

    // ------------------------------------------------------------------ Artifact Signing

    private static void SignOneTargetArtifactSigning(string target, SignArgs args)
    {
        var ext = TargetExtensionLower(target);
        var tmp = TemporaryOutputPath(target);
        try
        {
            if (IsPeWinmdExtension(ext))
            {
                RunPortableArtifactSigning("sign-pe", target, tmp, args, includeAppend: true);
            }
            else if (PsScript.ExtensionSupported(ext))
            {
                if (args.AppendSignature)
                {
                    throw new PsignException(AppendOnlyPe);
                }

                RunPortableCoreArtifactSigning(target, tmp, args, "PowerShell script");
            }
            else if (args.AppendSignature)
            {
                throw new PsignException(AppendOnlyPe);
            }
            else
            {
                switch (ext)
                {
                    case "cab":
                        RunPortableArtifactSigning("sign-cab", target, tmp, args, includeAppend: false);
                        break;
                    case "msi" or "msp":
                        RunPortableArtifactSigning("sign-msi", target, tmp, args, includeAppend: false);
                        break;
                    case "appx" or "msix" or "msixbundle" or "appxbundle":
                        RunPortableCoreArtifactSigning(target, tmp, args, "MSIX/AppX");
                        break;
                    case "cat":
                        throw new PsignException(
                            "portable Artifact Signing for catalog targets is available through `psign-tool portable sign-catalog ... --artifact-signing-*`; native-shaped in-place .cat signing needs a catalog-authenticode replacement path and is not implemented yet");
                    default:
                        throw new PsignException(
                            $"portable Artifact Signing is currently implemented for PE/WinMD, PowerShell Authenticode scripts (.ps1, .psd1, .psm1, .ps1xml, .psc1, .cdxml, .mof), CAB, MSI/MSP, and MSIX/AppX package or bundle targets; got {target}");
                }
            }

            CopyFile(tmp, target, $"replace '{target}' with signed output");
            try
            {
                File.Delete(tmp);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new PsignException($"remove temporary output '{tmp}'", IoErrorText.Inner(e));
            }
        }
        catch
        {
            TryDelete(tmp);
            throw;
        }
    }

    /// <summary>In-process <c>psign-tool portable sign-pe|sign-cab|sign-msi ... --artifact-signing-*</c> (Rust <c>run_from</c>).</summary>
    private static void RunPortableArtifactSigning(string command, string target, string output, SignArgs args, bool includeAppend)
    {
        var argv = new List<string> { command, target, "--digest", PortableDigestName(args.Digest) };
        if (includeAppend && args.AppendSignature)
        {
            argv.Add("--append-signature");
        }

        foreach (var chainCert in args.AdditionalCerts)
        {
            argv.Add("--chain-cert");
            argv.Add(chainCert);
        }

        PushOption(argv, "--timestamp-url", args.TimestampUrl);
        if (args.TimestampDigest is { } td)
        {
            argv.Add("--timestamp-digest");
            argv.Add(TimestampDigestName(td));
        }

        PushArtifactSigningOptions(argv, args);
        argv.Add("--output");
        argv.Add(output);
        PsignTool.RunPortableArgs(argv);
    }

    private static void PushArtifactSigningOptions(List<string> argv, SignArgs args)
    {
        if ((args.ArtifactSigningMetadata ?? args.Dmdf) is { } metadata)
        {
            argv.Add("--artifact-signing-metadata");
            argv.Add(metadata);
        }

        PushOption(argv, "--artifact-signing-region", args.ArtifactSigningRegion);
        PushOption(argv, "--artifact-signing-endpoint", args.ArtifactSigningEndpoint);
        PushOption(argv, "--artifact-signing-account-name", args.ArtifactSigningAccountName);
        PushOption(argv, "--artifact-signing-profile-name", args.ArtifactSigningProfileName);
        PushOption(argv, "--artifact-signing-signature-algorithm", args.ArtifactSigningSignatureAlgorithm);
        PushOption(argv, "--artifact-signing-api-version", args.ArtifactSigningApiVersion);
        PushOption(argv, "--artifact-signing-correlation-id", args.ArtifactSigningCorrelationId);
        PushOption(argv, "--artifact-signing-access-token", args.ArtifactSigningAccessToken);
        if (EffectiveArtifactSigningManagedIdentity(args))
        {
            argv.Add("--artifact-signing-managed-identity");
        }

        PushOption(argv, "--artifact-signing-managed-identity-resource-id", args.ArtifactSigningManagedIdentityResourceId);
        if (args.ArtifactSigningCredentialType is { } credentialType)
        {
            argv.Add("--artifact-signing-credential-type");
            argv.Add(credentialType);
        }

        PushOption(argv, "--artifact-signing-tenant-id", args.ArtifactSigningTenantId);
        PushOption(argv, "--artifact-signing-client-id", args.ArtifactSigningClientId);
        PushOption(argv, "--artifact-signing-client-secret", args.ArtifactSigningClientSecret);
        PushOption(argv, "--artifact-signing-federated-token-file", args.ArtifactSigningFederatedTokenFile);
        PushOption(argv, "--artifact-signing-authority", args.ArtifactSigningAuthority);
        PushOption(argv, "--artifact-signing-endpoint-base-url", args.ArtifactSigningEndpointBaseUrl);
    }

    private static void PushOption(List<string> argv, string name, string? value)
    {
        if (TextOpt(value) is { } v)
        {
            argv.Add(name);
            argv.Add(v);
        }
    }

    /// <summary>Rust <c>run_portable_sign_portable_core_artifact_signing</c> (MSIX/AppX and PowerShell scripts).</summary>
    private static void RunPortableCoreArtifactSigning(string target, string output, SignArgs args, string targetKind)
    {
        var metadata = LoadArtifactSigningMetadata(args);
        var endpoint = TextOpt(args.ArtifactSigningEndpoint)
            ?? metadata?.Endpoint
            ?? TextOpt(args.ArtifactSigningEndpointBaseUrl)
            ?? (TextOpt(args.ArtifactSigningRegion) is { } region ? $"https://{region}.codesigning.azure.net" : null)
            ?? throw new PsignException(
                $"portable {targetKind} Artifact Signing requires --artifact-signing-endpoint, --artifact-signing-endpoint-base-url, --artifact-signing-region, or metadata Endpoint");
        var accountName = TextOpt(args.ArtifactSigningAccountName)
            ?? metadata?.CodeSigningAccountName
            ?? throw new PsignException($"portable {targetKind} Artifact Signing requires --artifact-signing-account-name or metadata CodeSigningAccountName");
        var profileName = TextOpt(args.ArtifactSigningProfileName)
            ?? metadata?.CertificateProfileName
            ?? throw new PsignException($"portable {targetKind} Artifact Signing requires --artifact-signing-profile-name or metadata CertificateProfileName");
        var correlationId = TextOpt(args.ArtifactSigningCorrelationId) ?? metadata?.CorrelationId;

        var request = new PortableSignRequest
        {
            Path = target,
            OutputPath = output,
            HashAlgorithm = PortableCoreDigest(args.Digest),
            ChainCertificatePaths = [.. args.AdditionalCerts],
            TimestampServer = TextOpt(args.TimestampUrl),
            TimestampHashAlgorithm = args.TimestampDigest is { } td ? PortableCoreTimestampDigest(td) : null,
            ArtifactSigningEndpoint = endpoint,
            ArtifactSigningAccountName = accountName,
            ArtifactSigningProfileName = profileName,
            ArtifactSigningAccessToken = TextOpt(args.ArtifactSigningAccessToken),
            ArtifactSigningManagedIdentity = EffectiveArtifactSigningManagedIdentity(args),
            ArtifactSigningManagedIdentityResourceId = TextOpt(args.ArtifactSigningManagedIdentityResourceId),
            ArtifactSigningCredentialType = args.ArtifactSigningCredentialType,
            ArtifactSigningTenantId = TextOpt(args.ArtifactSigningTenantId),
            ArtifactSigningClientId = TextOpt(args.ArtifactSigningClientId),
            ArtifactSigningClientSecret = TextOpt(args.ArtifactSigningClientSecret),
            ArtifactSigningFederatedTokenFile = TextOpt(args.ArtifactSigningFederatedTokenFile),
            ArtifactSigningExcludeCredentials = metadata?.ExcludeCredentials?.ToList() ?? [],
            ArtifactSigningCorrelationId = correlationId,
            ArtifactSigningAuthority = TextOpt(args.ArtifactSigningAuthority),
            ArtifactSigningApiVersion = TextOpt(args.ArtifactSigningApiVersion),
            ArtifactSigningSignatureAlgorithm = TextOpt(args.ArtifactSigningSignatureAlgorithm),
        };
        PortableSignResponse response;
        try
        {
            response = PortableCore.PortableSign(request);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            throw new PsignException($"portable Artifact Signing {targetKind} target '{target}'", e);
        }

        EnsureValidSignatureResponse(response, target);
    }

    private static ArtifactSigningMetadata? LoadArtifactSigningMetadata(SignArgs args)
    {
        if ((args.ArtifactSigningMetadata ?? args.Dmdf) is not { } path)
        {
            return null;
        }

        var text = CliIo.ReadText(path, $"read '{path}'");
        try
        {
            return Devolutions.Psign.Signing.ArtifactSigning.ArtifactSigningMetadata.Parse(Encoding.UTF8.GetBytes(text));
        }
        catch (PsignException e)
        {
            var cause = e.Message == "parse Artifact Signing metadata JSON" && e.InnerException is not null ? e.InnerException : e;
            throw new PsignException($"parse Artifact Signing metadata '{path}'", cause);
        }
    }

    // ------------------------------------------------------------------ digests

    private static PortableDigestAlgorithm PortableCoreDigest(string digest) => digest switch
    {
        "sha256" => PortableDigestAlgorithm.Sha256,
        "sha384" => PortableDigestAlgorithm.Sha384,
        "sha512" => PortableDigestAlgorithm.Sha512,
        _ => throw new PsignException("portable signing supports SHA256, SHA384, and SHA512 file digests"),
    };

    private static PortableTimestampDigestAlgorithm PortableCoreTimestampDigest(string digest) => digest switch
    {
        "sha1" => PortableTimestampDigestAlgorithm.Sha1,
        "sha256" => PortableTimestampDigestAlgorithm.Sha256,
        "sha384" => PortableTimestampDigestAlgorithm.Sha384,
        "sha512" => PortableTimestampDigestAlgorithm.Sha512,
        _ => throw new PsignException("portable signing timestamp digest does not support certHash"),
    };

    private static string PortableDigestName(string digest) => digest switch
    {
        "sha256" or "sha384" or "sha512" => digest,
        _ => throw new PsignException("portable Azure Key Vault sign supports only SHA-2 file digests"),
    };

    private static string TimestampDigestName(string digest) => digest switch
    {
        "sha1" or "sha256" or "sha384" or "sha512" => digest,
        _ => throw new PsignException("portable Azure Key Vault timestamping supports only explicit hash algorithms"),
    };

    /// <summary>Rust <c>DigestAlgorithm::as_signtool_name</c>.</summary>
    internal static string SigntoolName(string digest) => digest switch
    {
        "sha1" => "SHA1",
        "sha256" => "SHA256",
        "sha384" => "SHA384",
        "sha512" => "SHA512",
        _ => "certHash",
    };

    private static bool IsSha2(string digest) => digest is "sha256" or "sha384" or "sha512";

    // ------------------------------------------------------------------ option validation

    private static bool TextPresent(string? value) => value is not null && value.Trim().Length > 0;

    private static string? TextOpt(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }

    private static bool EffectiveArtifactSigningManagedIdentity(SignArgs args) =>
        args.ArtifactSigningManagedIdentity || args.ArtifactSigningCredentialType == "managed-identity";

    /// <summary>Rust <c>azure_key_vault_requested</c>.</summary>
    internal static bool AzureKeyVaultRequested(SignArgs args) =>
        TextPresent(args.AzureKeyVaultUrl)
        || TextPresent(args.AzureKeyVaultCertificate)
        || TextPresent(args.AzureKeyVaultCertificateVersion)
        || TextPresent(args.AzureKeyVaultClientId)
        || TextPresent(args.AzureKeyVaultClientSecret)
        || TextPresent(args.AzureKeyVaultTenantId)
        || TextPresent(args.AzureKeyVaultAccessToken)
        || args.AzureKeyVaultManagedIdentity
        || args.AzureKeyVaultCredentialType is not null
        || TextPresent(args.AzureAuthority);

    /// <summary>Rust <c>artifact_signing_requested</c>.</summary>
    internal static bool ArtifactSigningRequested(SignArgs args) =>
        args.ArtifactSigningMetadata is not null
        || args.Dmdf is not null
        || TextPresent(args.ArtifactSigningRegion)
        || TextPresent(args.ArtifactSigningEndpoint)
        || TextPresent(args.ArtifactSigningAccountName)
        || TextPresent(args.ArtifactSigningProfileName)
        || TextPresent(args.ArtifactSigningSignatureAlgorithm)
        || TextPresent(args.ArtifactSigningApiVersion)
        || TextPresent(args.ArtifactSigningCorrelationId)
        || TextPresent(args.ArtifactSigningAccessToken)
        || args.ArtifactSigningManagedIdentity
        || TextPresent(args.ArtifactSigningManagedIdentityResourceId)
        || args.ArtifactSigningCredentialType is not null
        || TextPresent(args.ArtifactSigningTenantId)
        || TextPresent(args.ArtifactSigningClientId)
        || TextPresent(args.ArtifactSigningClientSecret)
        || TextPresent(args.ArtifactSigningFederatedTokenFile)
        || TextPresent(args.ArtifactSigningAuthority)
        || TextPresent(args.ArtifactSigningEndpointBaseUrl);

    private static void Reject(string name, bool present)
    {
        if (present)
        {
            throw new PsignException($"portable sign does not support {name}; {UnsupportedSuffix}");
        }
    }

    private static void RejectString(string name, string? value) => Reject(name, TextPresent(value));

    private static void RejectPath(string name, string? value) => Reject(name, value is not null);

    private static void RequireSha2(string operation, SignArgs args)
    {
        if (!IsSha2(args.Digest))
        {
            throw new PsignException($"{operation} supports only --fd SHA256, SHA384, or SHA512, got {SigntoolName(args.Digest)}");
        }
    }

    private static void RequireTimestampPair(string operation, SignArgs args)
    {
        if (args.TimestampUrl is not null && args.TimestampDigest is null)
        {
            throw new PsignException($"{operation} requires --td/--timestamp-digest with --tr/--timestamp-url");
        }

        if (args.TimestampUrl is null && args.TimestampDigest is not null)
        {
            throw new PsignException($"{operation} requires --tr/--timestamp-url with --td/--timestamp-digest");
        }
    }

    /// <summary>Options rejected identically by every portable route after the timestamp checks.</summary>
    private static void RejectCommonUnsupported(SignArgs args)
    {
        RejectString("--t/--legacy-timestamp-url", args.LegacyTimestampUrl);
        RejectString("--tseal/--seal-timestamp-url", args.SealTimestampUrl);
        RejectString("--d/--description", args.Description);
        RejectString("--du/--description-url", args.DescriptionUrl);
        RejectString("--r/--root-subject-name", args.RootSubjectName);
        RejectString("--u/--eku-oid", args.EkuOid);
        Reject("--uw/--eku-windows-system-component", args.EkuWindowsSystemComponent);
        RejectString("--signing-cert-eku-prefix", args.SigningCertEkuOidPrefix);
        RejectPath("--dg/--digest-generate", args.DigestGenerate);
        Reject("--ds/--digest-sign-only", args.DigestSignOnly);
        RejectPath("--di/--digest-ingest", args.DigestIngest);
        Reject("--dxml/--digest-xml", args.DigestXml);
        RejectPath("--p7/--pkcs7-output-dir", args.Pkcs7OutputDir);
        RejectString("--p7co/--pkcs7-content-oid", args.Pkcs7ContentOid);
        Reject("--p7ce/--pkcs7-content-embedding", args.Pkcs7ContentEmbedding is not null);
        RejectString("--certificate-template", args.CertificateTemplate);
        Reject("--sa/--sign-auth", args.SignAuthPairs.Count > 0);
        Reject("--fdchw", args.WarnFdDigestVsCertSignatureHash);
        Reject("--tdchw", args.WarnTdDigestVsCertSignatureHash);
        Reject("--rmc", args.RelaxedPeMarkerCheck);
        Reject("--seal", args.AddSealingSignature);
        Reject("--itos", args.IntentToSeal);
        Reject("--force", args.ForceSealOrResign);
        Reject("--nosealwarn", args.SignNoSealWarn);
        Reject("--noenclavewarn", args.SignNoEnclaveWarn);
        Reject("--rust-sip", args.RustSip is not null);
    }

    /// <summary>Rust <c>validate_supported_options</c> (local PFX / certificate-store signing).</summary>
    internal static void ValidateSupportedOptions(SignArgs args)
    {
        RequireSha2("portable sign", args);
        if (args.Pfx is not null && args.CertSha1 is not null)
        {
            throw new PsignException("portable sign accepts either --f/--pfx or --sha1 certificate-store material, not both");
        }

        if (args.Password is not null && args.Pfx is null)
        {
            throw new PsignException("portable sign accepts --p/--password only together with --f/--pfx");
        }

        Reject("--a/--auto-select", args.AutoSelect);
        RejectString("--n/--subject-name", args.SubjectName);
        RejectString("--i/--issuer-name", args.IssuerName);
        RejectString("--csp", args.Csp);
        RejectString("--kc/--key-container", args.KeyContainer);
        Reject("--ph/--page-hashes", args.PageHashes);
        Reject("--nph/--no-page-hashes", args.NoPageHashes);
        RejectPath("--dlib", args.Dlib);
        RejectPath("--dmdf", args.Dmdf);
        RejectPath("--trusted-signing-dlib-root", args.TrustedSigningDlibRoot);
        RequireTimestampPair("portable sign", args);
        RejectCommonUnsupported(args);
        RejectString("--azure-key-vault-url", args.AzureKeyVaultUrl);
        RejectString("--azure-key-vault-certificate", args.AzureKeyVaultCertificate);
        RejectString("--azure-key-vault-certificate-version", args.AzureKeyVaultCertificateVersion);
        RejectString("--azure-key-vault-client-id", args.AzureKeyVaultClientId);
        RejectString("--azure-key-vault-client-secret", args.AzureKeyVaultClientSecret);
        RejectString("--azure-key-vault-tenant-id", args.AzureKeyVaultTenantId);
        RejectString("--azure-key-vault-accesstoken", args.AzureKeyVaultAccessToken);
        Reject("--azure-key-vault-managed-identity", args.AzureKeyVaultManagedIdentity);
        Reject("--azure-key-vault-credential-type", args.AzureKeyVaultCredentialType is not null);
        RejectString("--azure-authority", args.AzureAuthority);
        RejectArtifactSigningOptions(args);
        if (args.MaxDegreeParallelism == 0)
        {
            throw new PsignException("portable sign requires --max-degree-of-parallelism to be at least 1");
        }
    }

    /// <summary>Rust <c>validate_azure_key_vault_supported_options</c>.</summary>
    internal static void ValidateAzureKeyVaultSupportedOptions(SignArgs args)
    {
        RequireSha2("portable Azure Key Vault sign", args);
        RejectPath("--f/--pfx", args.Pfx);
        RejectString("--p/--password", args.Password);
        Reject("--a/--auto-select", args.AutoSelect);
        RejectString("--n/--subject-name", args.SubjectName);
        RejectString("--i/--issuer-name", args.IssuerName);
        RejectString("--sha1", args.CertSha1);
        RejectString("--csp", args.Csp);
        RejectString("--kc/--key-container", args.KeyContainer);
        Reject("--sm/--machine-store", args.MachineStore);
        Reject("--s/--store", args.StoreName != "MY");
        RejectPath("--cert-store-dir", args.CertStoreDir);
        Reject("--ph/--page-hashes", args.PageHashes);
        Reject("--nph/--no-page-hashes", args.NoPageHashes);
        RejectPath("--dlib", args.Dlib);
        RejectPath("--trusted-signing-dlib-root", args.TrustedSigningDlibRoot);
        RejectPath("--dmdf", args.Dmdf);
        if (args.AzureKeyVaultCredentialType == "workload-identity")
        {
            throw new PsignException(
                "--azure-key-vault-credential-type=workload-identity is accepted by provider planning but is not wired for portable Azure Key Vault signing execution yet");
        }

        RequireTimestampPair("portable Azure Key Vault sign", args);
        RejectCommonUnsupported(args);
        RejectArtifactSigningOptions(args);
        if (args.MaxDegreeParallelism == 0)
        {
            throw new PsignException("portable Azure Key Vault sign requires --max-degree-of-parallelism to be at least 1");
        }
    }

    /// <summary>Rust <c>validate_artifact_signing_supported_options</c>.</summary>
    internal static void ValidateArtifactSigningSupportedOptions(SignArgs args)
    {
        RequireSha2("portable Artifact Signing sign", args);
        RejectPath("--f/--pfx", args.Pfx);
        RejectString("--p/--password", args.Password);
        Reject("--a/--auto-select", args.AutoSelect);
        RejectString("--n/--subject-name", args.SubjectName);
        RejectString("--i/--issuer-name", args.IssuerName);
        RejectString("--sha1", args.CertSha1);
        RejectString("--csp", args.Csp);
        RejectString("--kc/--key-container", args.KeyContainer);
        Reject("--sm/--machine-store", args.MachineStore);
        Reject("--s/--store", args.StoreName != "MY");
        RejectPath("--cert-store-dir", args.CertStoreDir);
        Reject("--ph/--page-hashes", args.PageHashes);
        Reject("--nph/--no-page-hashes", args.NoPageHashes);
        RejectPath("--dlib", args.Dlib);
        RejectPath("--trusted-signing-dlib-root", args.TrustedSigningDlibRoot);
        if (args.ArtifactSigningMetadata is not null && args.Dmdf is not null)
        {
            throw new PsignException("use either --artifact-signing-metadata or --dmdf as Artifact Signing metadata, not both");
        }

        RequireTimestampPair("portable Artifact Signing sign", args);
        RejectCommonUnsupported(args);
        if (args.MaxDegreeParallelism == 0)
        {
            throw new PsignException("portable Artifact Signing sign requires --max-degree-of-parallelism to be at least 1");
        }
    }

    private static void RejectArtifactSigningOptions(SignArgs args)
    {
        RejectPath("--artifact-signing-metadata", args.ArtifactSigningMetadata);
        RejectString("--artifact-signing-region", args.ArtifactSigningRegion);
        RejectString("--artifact-signing-endpoint", args.ArtifactSigningEndpoint);
        RejectString("--artifact-signing-account-name", args.ArtifactSigningAccountName);
        RejectString("--artifact-signing-profile-name", args.ArtifactSigningProfileName);
        RejectString("--artifact-signing-signature-algorithm", args.ArtifactSigningSignatureAlgorithm);
        RejectString("--artifact-signing-api-version", args.ArtifactSigningApiVersion);
        RejectString("--artifact-signing-correlation-id", args.ArtifactSigningCorrelationId);
        RejectString("--artifact-signing-access-token", args.ArtifactSigningAccessToken);
        Reject("--artifact-signing-managed-identity", args.ArtifactSigningManagedIdentity);
        RejectString("--artifact-signing-managed-identity-resource-id", args.ArtifactSigningManagedIdentityResourceId);
        Reject("--artifact-signing-credential-type", args.ArtifactSigningCredentialType is not null);
        RejectString("--artifact-signing-tenant-id", args.ArtifactSigningTenantId);
        RejectString("--artifact-signing-client-id", args.ArtifactSigningClientId);
        RejectString("--artifact-signing-client-secret", args.ArtifactSigningClientSecret);
        RejectString("--artifact-signing-federated-token-file", args.ArtifactSigningFederatedTokenFile);
        RejectString("--artifact-signing-authority", args.ArtifactSigningAuthority);
        RejectString("--artifact-signing-endpoint-base-url", args.ArtifactSigningEndpointBaseUrl);
    }
}
