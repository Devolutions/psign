using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Utilities;

namespace Devolutions.Psign.PowerShell.Cmdlets;

[Cmdlet(VerbsCommon.Set, "PortableSignature", SupportsShouldProcess = true, DefaultParameterSetName = FilePathParameterSet)]
[OutputType(typeof(PortableSignature))]
public sealed class SetPortableSignatureCommand : PSCmdlet
{
    private const string FilePathParameterSet = "FilePath";
    private const string LiteralPathParameterSet = "LiteralPath";
    private const string ContentParameterSet = "Content";
    private X509Certificate2? pfxCertificate;
    private X509Certificate2? storeCertificate;
    private string? storePrivateKeyDerBase64;

    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = FilePathParameterSet)]
    [Alias("Path")]
    public string[] FilePath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
    [Alias("PSPath", "LP")]
    public string[] LiteralPath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = ContentParameterSet)]
    public string[] SourcePathOrExtension { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = ContentParameterSet)]
    [ValidateNotNullOrEmpty]
    public byte[] Content { get; set; } = [];

    [Parameter]
    public X509Certificate2? Certificate { get; set; }

    [Parameter]
    public string? CertificatePath { get; set; }

    [Parameter]
    public string? PrivateKeyPath { get; set; }

    [Parameter]
    public string? PfxPath { get; set; }

    [Parameter]
    public SecureString? Password { get; set; }

    [Parameter]
    [Alias("Sha1", "PortableStoreThumbprint")]
    public string? Thumbprint { get; set; }

    [Parameter]
    public string? CertStoreDirectory { get; set; }

    [Parameter]
    public string StoreName { get; set; } = "MY";

    [Parameter]
    public SwitchParameter MachineStore { get; set; }

    [Parameter]
    [ValidateSet("Signer", "NotRoot", "All")]
    public string IncludeChain { get; set; } = "NotRoot";

    [Parameter]
    public string[] ChainCertificatePath { get; set; } = [];

    [Parameter]
    public string? TimestampServer { get; set; }

    [Parameter]
    [ValidateSet("Sha1", "Sha256", "Sha384", "Sha512")]
    public string TimestampHashAlgorithm { get; set; } = "Sha256";

    [Parameter]
    [ValidateSet("Sha256", "Sha384", "Sha512")]
    public string HashAlgorithm { get; set; } = "Sha256";

    [Parameter]
    public string? OutputPath { get; set; }

    [Parameter]
    public SwitchParameter Force { get; set; }

    // Azure Key Vault parameters
    [Parameter]
    public string? AzureKeyVaultUrl { get; set; }

    [Parameter]
    public string? AzureKeyVaultCertificate { get; set; }

    [Parameter]
    public string? AzureKeyVaultAccessToken { get; set; }

    [Parameter]
    public string? AzureKeyVaultClientId { get; set; }

    [Parameter]
    public string? AzureKeyVaultClientSecret { get; set; }

    [Parameter]
    public string? AzureKeyVaultTenantId { get; set; }

    [Parameter]
    public SwitchParameter AzureKeyVaultManagedIdentity { get; set; }

    // Artifact Signing / Trusted Signing parameters
    [Parameter]
    public string? ArtifactSigningEndpoint { get; set; }

    [Parameter]
    public string? ArtifactSigningAccountName { get; set; }

    [Parameter]
    public string? ArtifactSigningProfileName { get; set; }

    [Parameter]
    public string? ArtifactSigningAccessToken { get; set; }

    [Parameter]
    public SwitchParameter ArtifactSigningManagedIdentity { get; set; }

    [Parameter]
    public string? ArtifactSigningTenantId { get; set; }

    [Parameter]
    public string? ArtifactSigningClientId { get; set; }

    [Parameter]
    public string? ArtifactSigningClientSecret { get; set; }

    protected override void ProcessRecord()
    {
        ValidateSigningMaterial();
        if (ParameterSetName == ContentParameterSet)
        {
            if (OutputPath is not null)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new PSInvalidOperationException("-OutputPath cannot be used with -Content. Read the signed bytes from the output object's Content property."),
                    "PortableSignatureContentOutputPathUnsupported",
                    ErrorCategory.InvalidArgument,
                    OutputPath));
            }
            foreach (string source in SourcePathOrExtension)
            {
                SignContent(source);
            }
            return;
        }

        bool literal = ParameterSetName == LiteralPathParameterSet;
        string[] inputs = literal ? LiteralPath : FilePath;
        if (OutputPath is not null && inputs.Length != 1)
        {
            ThrowTerminatingError(new ErrorRecord(
                new PSInvalidOperationException("-OutputPath can only be used with a single input file."),
                "PortableSignatureOutputPathRequiresSingleInput",
                ErrorCategory.InvalidArgument,
                OutputPath));
        }

        foreach (string input in inputs)
        {
            IReadOnlyList<string> resolvedPaths = PathResolution.ResolveFilePaths(this, input, literal);
            if (OutputPath is not null
                && (resolvedPaths.Count != 1 || Directory.Exists(resolvedPaths[0])))
            {
                ThrowTerminatingError(new ErrorRecord(
                    new PSInvalidOperationException("-OutputPath can only be used with a single input file, not module directories or wildcard groups."),
                    "PortableSignatureOutputPathRequiresSingleInput",
                    ErrorCategory.InvalidArgument,
                    input));
            }

            foreach (string resolved in resolvedPaths)
            {
                SignPath(resolved);
            }
        }
    }

    private void SignContent(string sourcePathOrExtension)
    {
        string tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDirectory);
        string tempPath = Path.Combine(tempDirectory, ContentFileName(sourcePathOrExtension));
        try
        {
            File.WriteAllBytes(tempPath, Content);
            if (!ShouldProcess(sourcePathOrExtension, "Set portable Authenticode signature on content"))
            {
                return;
            }

                PortableSignResponse response = PsignNative.Sign(new PortableSignRequest
                {
                    Path = tempPath,
                    HashAlgorithm = HashAlgorithm,
                    CertificatePath = CertificatePath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(CertificatePath),
                    PrivateKeyPath = PrivateKeyPath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(PrivateKeyPath),
                    CertificateDerBase64 = GetCertificateDerBase64(),
                    PrivateKeyDerBase64 = GetPrivateKeyDerBase64(),
                    PfxPath = PfxPath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(PfxPath),
                    PfxPassword = Password is null ? null : SecureStringToString(Password),
                    ChainCertificatePaths = GetChainCertificatePaths(),
                    ChainCertificatesDerBase64 = GetChainCertificatesDerBase64(),
                    TimestampServer = TimestampServer,
                    TimestampHashAlgorithm = TimestampServer is null ? null : TimestampHashAlgorithm,
                    AzureKeyVaultUrl = AzureKeyVaultUrl,
                    AzureKeyVaultCertificate = AzureKeyVaultCertificate,
                    AzureKeyVaultAccessToken = AzureKeyVaultAccessToken,
                    AzureKeyVaultClientId = AzureKeyVaultClientId,
                    AzureKeyVaultClientSecret = AzureKeyVaultClientSecret,
                    AzureKeyVaultTenantId = AzureKeyVaultTenantId,
                    AzureKeyVaultManagedIdentity = AzureKeyVaultManagedIdentity.IsPresent ? true : null,
                    ArtifactSigningEndpoint = ArtifactSigningEndpoint,
                    ArtifactSigningAccountName = ArtifactSigningAccountName,
                    ArtifactSigningProfileName = ArtifactSigningProfileName,
                    ArtifactSigningAccessToken = ArtifactSigningAccessToken,
                    ArtifactSigningManagedIdentity = ArtifactSigningManagedIdentity.IsPresent ? true : null,
                    ArtifactSigningTenantId = ArtifactSigningTenantId,
                    ArtifactSigningClientId = ArtifactSigningClientId,
                    ArtifactSigningClientSecret = ArtifactSigningClientSecret,
                });
            response.Signature.SourcePathOrExtension = sourcePathOrExtension;
            response.Signature.Content = File.ReadAllBytes(tempPath);
            WriteObject(response.Signature);
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "SetPortableSignatureContentFailed", ErrorCategory.NotSpecified, sourcePathOrExtension));
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    private void SignPath(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                foreach (string moduleFile in PortableModuleFiles.Enumerate(path))
                {
                    SignPath(moduleFile);
                }
                return;
            }

            string? outputPath = OutputPath is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(OutputPath);
            string target = outputPath ?? path;
            if (!ShouldProcess(target, "Set portable Authenticode signature"))
            {
                return;
            }

            FileAttributes? restoreAttributes = PrepareWritableTarget(path, target);
            try
            {
                PortableSignResponse response = PsignNative.Sign(new PortableSignRequest
                {
                    Path = path,
                    OutputPath = outputPath,
                    HashAlgorithm = HashAlgorithm,
                    CertificatePath = CertificatePath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(CertificatePath),
                    PrivateKeyPath = PrivateKeyPath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(PrivateKeyPath),
                    CertificateDerBase64 = GetCertificateDerBase64(),
                    PrivateKeyDerBase64 = GetPrivateKeyDerBase64(),
                    PfxPath = PfxPath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(PfxPath),
                    PfxPassword = Password is null ? null : SecureStringToString(Password),
                    ChainCertificatePaths = GetChainCertificatePaths(),
                    ChainCertificatesDerBase64 = GetChainCertificatesDerBase64(),
                    TimestampServer = TimestampServer,
                    TimestampHashAlgorithm = TimestampServer is null ? null : TimestampHashAlgorithm,
                    AzureKeyVaultUrl = AzureKeyVaultUrl,
                    AzureKeyVaultCertificate = AzureKeyVaultCertificate,
                    AzureKeyVaultAccessToken = AzureKeyVaultAccessToken,
                    AzureKeyVaultClientId = AzureKeyVaultClientId,
                    AzureKeyVaultClientSecret = AzureKeyVaultClientSecret,
                    AzureKeyVaultTenantId = AzureKeyVaultTenantId,
                    AzureKeyVaultManagedIdentity = AzureKeyVaultManagedIdentity.IsPresent ? true : null,
                    ArtifactSigningEndpoint = ArtifactSigningEndpoint,
                    ArtifactSigningAccountName = ArtifactSigningAccountName,
                    ArtifactSigningProfileName = ArtifactSigningProfileName,
                    ArtifactSigningAccessToken = ArtifactSigningAccessToken,
                    ArtifactSigningManagedIdentity = ArtifactSigningManagedIdentity.IsPresent ? true : null,
                    ArtifactSigningTenantId = ArtifactSigningTenantId,
                    ArtifactSigningClientId = ArtifactSigningClientId,
                    ArtifactSigningClientSecret = ArtifactSigningClientSecret,
                });
                WriteObject(response.Signature);
            }
            finally
            {
                if (restoreAttributes is not null)
                {
                    File.SetAttributes(target, restoreAttributes.Value);
                }
            }
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "SetPortableSignatureFailed", ErrorCategory.NotSpecified, path));
        }
    }

    private FileAttributes? PrepareWritableTarget(string inputPath, string targetPath)
    {
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(targetPath)))
        {
            return null;
        }

        FileAttributes attributes = File.GetAttributes(targetPath);
        if ((attributes & FileAttributes.ReadOnly) == 0)
        {
            return null;
        }

        if (!Force)
        {
            throw new UnauthorizedAccessException(
                $"File '{targetPath}' is read-only. Use -Force to sign it in place.");
        }

        File.SetAttributes(targetPath, attributes & ~FileAttributes.ReadOnly);
        return attributes;
    }

    private void ValidateSigningMaterial()
    {
        int materialCount = 0;
        if (Certificate is not null)
        {
            materialCount++;
        }
        if (CertificatePath is not null || PrivateKeyPath is not null)
        {
            if (CertificatePath is null || PrivateKeyPath is null)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new PSInvalidOperationException("-CertificatePath and -PrivateKeyPath must be supplied together."),
                    "PortableSignatureIncompleteKeyPair",
                    ErrorCategory.InvalidArgument,
                    this));
            }
            materialCount++;
        }
        if (PfxPath is not null)
        {
            materialCount++;
        }
        if (Thumbprint is not null)
        {
            materialCount++;
        }
        if (AzureKeyVaultUrl is not null)
        {
            if (AzureKeyVaultCertificate is null)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new PSInvalidOperationException("-AzureKeyVaultCertificate is required when using -AzureKeyVaultUrl."),
                    "PortableSignatureAkvCertificateRequired",
                    ErrorCategory.InvalidArgument,
                    this));
            }
            materialCount++;
        }
        if (ArtifactSigningEndpoint is not null || ArtifactSigningAccountName is not null)
        {
            materialCount++;
        }

        if (materialCount != 1)
        {
            ThrowTerminatingError(new ErrorRecord(
                new PSInvalidOperationException("Supply exactly one signing source: -Certificate, -CertificatePath/-PrivateKeyPath, -PfxPath, -Thumbprint, -AzureKeyVaultUrl, or -ArtifactSigningEndpoint/-ArtifactSigningAccountName."),
                "PortableSignatureSigningMaterialRequired",
                ErrorCategory.InvalidArgument,
                this));
        }

        ValidateSelectedCertificate();
    }

    private void ValidateSelectedCertificate()
    {
        if (Certificate is not null)
        {
            ValidateCodeSigningCertificate(Certificate, requirePrivateKey: true, "-Certificate");
        }
        else if (CertificatePath is not null)
        {
            string resolved = SessionState.Path.GetUnresolvedProviderPathFromPSPath(CertificatePath);
            using X509Certificate2 certificate = new(resolved);
            ValidateCodeSigningCertificate(certificate, requirePrivateKey: false, "-CertificatePath");
        }
        else if (PfxPath is not null)
        {
            ValidateCodeSigningCertificate(LoadPfxCertificate(), requirePrivateKey: true, "-PfxPath");
        }
        else if (Thumbprint is not null)
        {
            // The portable store loads the private key from a separate .key file,
            // so the X509Certificate2 from the .der file won't report HasPrivateKey.
            // LoadStoreCertificate() already validates the .key file exists.
            ValidateCodeSigningCertificate(LoadStoreCertificate(), requirePrivateKey: false, "-Thumbprint");
        }
    }

    private static void ValidateCodeSigningCertificate(X509Certificate2? certificate, bool requirePrivateKey, string source)
    {
        if (certificate is null)
        {
            throw new PSInvalidOperationException($"{source} did not resolve to a signing certificate.");
        }

        if (requirePrivateKey && !certificate.HasPrivateKey)
        {
            throw new PSInvalidOperationException($"{source} must include an accessible private key.");
        }

        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension is X509KeyUsageExtension keyUsage
                && (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
            {
                throw new PSInvalidOperationException($"{source} certificate is not valid for digital signatures.");
            }

            if (extension is X509EnhancedKeyUsageExtension eku
                && !HasCodeSigningEku(eku))
            {
                throw new PSInvalidOperationException($"{source} certificate is not valid for code signing.");
            }
        }
    }

    private static bool HasCodeSigningEku(X509EnhancedKeyUsageExtension eku)
    {
        foreach (Oid oid in eku.EnhancedKeyUsages)
        {
            if (oid.Value == "1.3.6.1.5.5.7.3.3")
            {
                return true;
            }
        }

        return eku.EnhancedKeyUsages.Count == 0;
    }

    private X509Certificate2? LoadPfxCertificate()
    {
        if (pfxCertificate is not null)
        {
            return pfxCertificate;
        }
        if (PfxPath is null)
        {
            return null;
        }

        string resolved = SessionState.Path.GetUnresolvedProviderPathFromPSPath(PfxPath);
        string? password = Password is null ? null : SecureStringToString(Password);
        try
        {
            pfxCertificate = new X509Certificate2(
                resolved,
                password,
                X509KeyStorageFlags.Exportable);
            return pfxCertificate;
        }
        finally
        {
            if (password is not null)
            {
                password = null;
            }
        }
    }

    private string? GetCertificateDerBase64()
    {
        X509Certificate2? cert = Certificate ?? LoadStoreCertificate();
        if (cert is null)
        {
            return null;
        }
        return Convert.ToBase64String(cert.Export(X509ContentType.Cert));
    }

    private string? GetPrivateKeyDerBase64()
    {
        if (Thumbprint is not null)
        {
            _ = LoadStoreCertificate();
            return storePrivateKeyDerBase64;
        }

        X509Certificate2? cert = Certificate;
        if (cert is null)
        {
            return null;
        }

        using RSA? rsa = cert.GetRSAPrivateKey();
        if (rsa is null)
        {
            throw new PSInvalidOperationException("Portable signing requires an exportable RSA private key.");
        }
        try
        {
            return Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
        }
        catch (CryptographicException ex)
        {
            throw new PSInvalidOperationException(
                "Portable signing requires exportable key material. Use -CertificatePath/-PrivateKeyPath, -PfxPath with an exportable key, or a remote signer.",
                ex);
        }
    }

    private string[] GetChainCertificatePaths()
    {
        if (IncludeChain.Equals("Signer", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        List<string> paths = [];
        foreach (string path in ChainCertificatePath)
        {
            string resolved = SessionState.Path.GetUnresolvedProviderPathFromPSPath(path);
            using X509Certificate2 chainCertificate = new(resolved);
            if (IncludeChain.Equals("NotRoot", StringComparison.OrdinalIgnoreCase)
                && IsSelfSigned(chainCertificate))
            {
                continue;
            }
            paths.Add(resolved);
        }
        return paths.ToArray();
    }

    private string[] GetChainCertificatesDerBase64()
    {
        if (IncludeChain.Equals("Signer", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        X509Certificate2? cert = Certificate ?? LoadPfxCertificate() ?? LoadStoreCertificate();
        if (cert is null)
        {
            return [];
        }

        using X509Chain chain = new()
        {
            ChainPolicy =
            {
                RevocationMode = X509RevocationMode.NoCheck,
                VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority,
            },
        };
        chain.Build(cert);

        List<string> encoded = [];
        foreach (X509ChainElement element in chain.ChainElements)
        {
            X509Certificate2 chainCert = element.Certificate;
            if (StringComparer.OrdinalIgnoreCase.Equals(chainCert.Thumbprint, cert.Thumbprint))
            {
                continue;
            }
            if (IncludeChain.Equals("NotRoot", StringComparison.OrdinalIgnoreCase)
                && IsSelfSigned(chainCert))
            {
                continue;
            }
            encoded.Add(Convert.ToBase64String(chainCert.Export(X509ContentType.Cert)));
        }
        return encoded.ToArray();
    }

    private static bool IsSelfSigned(X509Certificate2 certificate)
    {
        return certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }

    private X509Certificate2? LoadStoreCertificate()
    {
        if (storeCertificate is not null)
        {
            return storeCertificate;
        }
        if (Thumbprint is null)
        {
            return null;
        }

        string normalized = NormalizeSha1Thumbprint(Thumbprint);
        string baseDirectory = ResolveCertStoreBaseDirectory();
        string scope = MachineStore.IsPresent ? "LocalMachine" : "CurrentUser";
        string store = NormalizeStoreName(StoreName);
        string storeDirectory = Path.Combine(baseDirectory, scope, store);
        string certPath = Path.Combine(storeDirectory, normalized + ".der");
        string keyPath = Path.Combine(storeDirectory, normalized + ".key");
        if (!File.Exists(certPath))
        {
            throw new FileNotFoundException(
                $"Portable signing certificate SHA1 {normalized} was not found in {scope}\\{store}.",
                certPath);
        }
        if (!File.Exists(keyPath))
        {
            throw new FileNotFoundException(
                $"Portable signing private key SHA1 {normalized} was not found in {scope}\\{store}.",
                keyPath);
        }

        storeCertificate = new X509Certificate2(File.ReadAllBytes(certPath));
        storePrivateKeyDerBase64 = Convert.ToBase64String(ReadPkcs8PrivateKeyDer(keyPath));
        return storeCertificate;
    }

    private string ResolveCertStoreBaseDirectory()
    {
        if (CertStoreDirectory is not null)
        {
            return SessionState.Path.GetUnresolvedProviderPathFromPSPath(CertStoreDirectory);
        }

        string? envStore = Environment.GetEnvironmentVariable("PSIGN_CERT_STORE");
        if (!string.IsNullOrWhiteSpace(envStore))
        {
            return envStore;
        }

        string? home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetEnvironmentVariable("USERPROFILE");
        if (string.IsNullOrWhiteSpace(home))
        {
            throw new PSInvalidOperationException(
                "Cannot resolve the default portable cert-store path. Set -CertStoreDirectory or PSIGN_CERT_STORE.");
        }

        return Path.Combine(home, ".psign", "cert-store");
    }

    private static string NormalizeStoreName(string storeName)
    {
        string trimmed = storeName.Trim();
        if (trimmed.Length == 0 || trimmed.Contains('/') || trimmed.Contains('\\') || trimmed.Contains('\0'))
        {
            throw new PSInvalidOperationException("Portable certificate store name must not be empty or contain path separators.");
        }

        return trimmed.ToLowerInvariant() switch
        {
            "my" => "MY",
            "root" => "Root",
            "ca" => "CA",
            "trust" => "Trust",
            "disallowed" => "Disallowed",
            _ => trimmed,
        };
    }

    private static string NormalizeSha1Thumbprint(string thumbprint)
    {
        string clean = new(thumbprint.Where(c => c != ':' && !char.IsWhiteSpace(c)).ToArray());
        if (clean.Length != 40 || clean.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new PSInvalidOperationException("SHA1 thumbprint must be 40 hexadecimal characters.");
        }

        return clean.ToUpperInvariant();
    }

    private static byte[] ReadPkcs8PrivateKeyDer(string keyPath)
    {
        string text = File.ReadAllText(keyPath);
        const string begin = "-----BEGIN PRIVATE KEY-----";
        const string end = "-----END PRIVATE KEY-----";
        int beginIndex = text.IndexOf(begin, StringComparison.Ordinal);
        int endIndex = text.IndexOf(end, StringComparison.Ordinal);
        if (beginIndex < 0 || endIndex < 0 || endIndex <= beginIndex)
        {
            throw new PSInvalidOperationException(
                $"Portable cert-store key '{keyPath}' must be unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY).");
        }

        int base64Start = beginIndex + begin.Length;
        string base64 = text[base64Start..endIndex];
        string compact = new(base64.Where(c => !char.IsWhiteSpace(c)).ToArray());
        try
        {
            return Convert.FromBase64String(compact);
        }
        catch (FormatException ex)
        {
            throw new PSInvalidOperationException(
                $"Portable cert-store key '{keyPath}' contains invalid PKCS#8 PEM base64.",
                ex);
        }
    }

    private static string ContentFileName(string sourcePathOrExtension)
    {
        string fileName = Path.GetFileName(sourcePathOrExtension);
        if (!string.IsNullOrWhiteSpace(fileName)
            && Path.HasExtension(fileName)
            && !string.IsNullOrWhiteSpace(Path.GetFileNameWithoutExtension(fileName)))
        {
            return fileName;
        }

        string extension = sourcePathOrExtension.Trim();
        if (!extension.StartsWith('.'))
        {
            extension = "." + extension;
        }
        return "content" + extension;
    }

    private static string SecureStringToString(SecureString value)
    {
        IntPtr ptr = Marshal.SecureStringToBSTR(value);
        try
        {
            return Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            Marshal.ZeroFreeBSTR(ptr);
        }
    }
}
