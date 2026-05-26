using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Utilities;

namespace Devolutions.Psign.PowerShell.Cmdlets;

/// <summary>
/// Signs all policy-checked files in a PowerShell module. This is the signing
/// counterpart to Test-PsignModule — it signs exactly the files that the execution
/// policy engine would validate during Import-Module.
/// </summary>
[Cmdlet(VerbsSecurity.Protect, "PsignModule", SupportsShouldProcess = true)]
[OutputType(typeof(PsignModuleSigningResult))]
public sealed class ProtectPsignModuleCommand : PSCmdlet
{
    private const string PathParameterSet = "Path";
    private const string InputObjectParameterSet = "InputObject";

    [Parameter(Mandatory = true, Position = 0, ValueFromPipelineByPropertyName = true, ParameterSetName = PathParameterSet, HelpMessage = "Path to the PowerShell module directory to sign.")]
    [Alias("ModulePath", "PSPath", "InstalledLocation", "ModuleBase")]
    public string Path { get; set; } = string.Empty;

    [Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = InputObjectParameterSet, HelpMessage = "PowerShell module information returned by Get-Module.")]
    public PSModuleInfo InputObject { get; set; } = null!;

    // Local certificate signing
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

    // Chain / algorithm
    [Parameter]
    [ValidateSet("Signer", "NotRoot", "All")]
    public string IncludeChain { get; set; } = "NotRoot";

    [Parameter]
    public string[] ChainCertificatePath { get; set; } = [];

    [Parameter]
    [ValidateSet("Sha256", "Sha384", "Sha512")]
    public string HashAlgorithm { get; set; } = "Sha256";

    // Timestamp
    [Parameter]
    public string? TimestampServer { get; set; }

    [Parameter]
    [ValidateSet("Sha1", "Sha256", "Sha384", "Sha512")]
    public string TimestampHashAlgorithm { get; set; } = "Sha256";

    // Azure Key Vault
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

    // Artifact Signing / Trusted Signing
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

    /// <summary>
    /// Also sign files not referenced in the manifest (belt-and-suspenders).
    /// </summary>
    [Parameter]
    public SwitchParameter IncludeUnreferenced { get; set; }

    // Extensions that the policy engine checks
    private static readonly HashSet<string> PolicyCheckedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".ps1xml", ".cdxml",
    };

    private static readonly HashSet<string> SignableScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".ps1xml", ".cdxml",
    };

    protected override void ProcessRecord()
    {
        if (!TryResolveModule(out string moduleDir, out string? manifestPath, out string moduleName))
        {
            return;
        }

        // Discover files to sign
        var filesToSign = DiscoverSignableFiles(moduleDir, manifestPath);

        if (filesToSign.Count == 0)
        {
            WriteWarning($"No signable files found in module '{moduleName}'.");
            return;
        }

        if (!ShouldProcess($"{moduleName} ({filesToSign.Count} files)", "Sign module"))
        {
            return;
        }

        // Resolve signing material once
        var certInfo = ResolveSigningCertificate();

        // Sign each file
        var results = new List<PsignModuleFileSignResult>();
        int succeeded = 0;
        int failed = 0;

        foreach (var (relativePath, role) in filesToSign)
        {
            string fullPath = System.IO.Path.Combine(moduleDir, relativePath);
            try
            {
                var response = PsignNative.Sign(CreateSignRequest(fullPath, certInfo));
                results.Add(new PsignModuleFileSignResult
                {
                    RelativePath = relativePath,
                    Role = role,
                    Status = response.Signature.Status,
                    SignerSubject = response.Signature.SignerCertificate?.Subject,
                    Success = true,
                });
                succeeded++;
                WriteVerbose($"Signed: {relativePath}");
            }
            catch (Exception ex)
            {
                results.Add(new PsignModuleFileSignResult
                {
                    RelativePath = relativePath,
                    Role = role,
                    Status = SignatureStatus.UnknownError,
                    Success = false,
                    ErrorMessage = ex.Message,
                });
                failed++;
                WriteWarning($"Failed to sign {relativePath}: {ex.Message}");
            }
        }

        WriteObject(new PsignModuleSigningResult
        {
            ModulePath = moduleDir,
            ModuleName = moduleName,
            TotalFiles = filesToSign.Count,
            Succeeded = succeeded,
            Failed = failed,
            Files = results.ToArray(),
        });
    }

    private bool TryResolveModule(out string moduleDir, out string? manifestPath, out string moduleName)
    {
        moduleDir = string.Empty;
        manifestPath = null;
        moduleName = string.Empty;

        if (ParameterSetName == InputObjectParameterSet)
        {
            return TryResolveModuleInfo(InputObject, out moduleDir, out manifestPath, out moduleName);
        }

        return TryResolvePath(
            Path,
            targetObject: Path,
            moduleNameOverride: null,
            writeTerminatingError: true,
            out moduleDir,
            out manifestPath,
            out moduleName);
    }

    private bool TryResolvePath(
        string input,
        object targetObject,
        string? moduleNameOverride,
        bool writeTerminatingError,
        out string moduleDir,
        out string? manifestPath,
        out string moduleName)
    {
        moduleDir = string.Empty;
        manifestPath = null;
        moduleName = string.Empty;
        string? resolvedPath = null;
        Exception? pathResolutionException = null;

        try
        {
            resolvedPath = SessionState.Path.GetUnresolvedProviderPathFromPSPath(input);
        }
        catch (Exception ex) when (ex is ItemNotFoundException
            or System.Management.Automation.DriveNotFoundException
            or ProviderNotFoundException
            or PSArgumentException
            or NotSupportedException)
        {
            pathResolutionException = ex;
        }

        if (resolvedPath is not null)
        {
            if (Directory.Exists(resolvedPath))
            {
                moduleDir = resolvedPath;
                manifestPath = FindManifest(moduleDir);
                moduleName = moduleNameOverride ?? GetModuleName(moduleDir, manifestPath);
                return true;
            }

            if (File.Exists(resolvedPath) && resolvedPath.EndsWith(".psd1", StringComparison.OrdinalIgnoreCase))
            {
                manifestPath = resolvedPath;
                moduleDir = System.IO.Path.GetDirectoryName(resolvedPath)!;
                moduleName = moduleNameOverride ?? GetModuleName(moduleDir, manifestPath);
                return true;
            }
        }

        string message = pathResolutionException is null
            ? $"Module path not found: {resolvedPath ?? input}"
            : $"Module path not found: {input}. {pathResolutionException.Message}";
        var error = new ErrorRecord(
            new DirectoryNotFoundException(message),
            "ModulePathNotFound", ErrorCategory.ObjectNotFound, targetObject);

        if (writeTerminatingError)
        {
            ThrowTerminatingError(error);
        }
        else
        {
            WriteError(error);
        }

        return false;
    }

    private bool TryResolveModuleInfo(PSModuleInfo module, out string moduleDir, out string? manifestPath, out string moduleName)
    {
        moduleDir = module.ModuleBase;
        moduleName = module.Name;
        manifestPath = null;

        if (!Directory.Exists(moduleDir))
        {
            WriteError(new ErrorRecord(
                new DirectoryNotFoundException($"Module path not found: {moduleDir}"),
                "ModulePathNotFound", ErrorCategory.ObjectNotFound, module));
            return false;
        }

        manifestPath = module.Path.EndsWith(".psd1", StringComparison.OrdinalIgnoreCase)
            ? module.Path
            : FindManifest(moduleDir);
        return true;
    }

    private static string GetModuleName(string moduleDir, string? manifestPath)
    {
        if (manifestPath is not null)
            return System.IO.Path.GetFileNameWithoutExtension(manifestPath);

        return System.IO.Path.GetFileName(moduleDir);
    }

    private List<(string RelativePath, ModuleFileRole Role)> DiscoverSignableFiles(string moduleDir, string? manifestPath)
    {
        var files = new Dictionary<string, ModuleFileRole>(StringComparer.OrdinalIgnoreCase);

        if (manifestPath is not null)
        {
            try
            {
                var manifest = ModuleManifestInfo.Parse(manifestPath);

                // RootModule (if script)
                if (!string.IsNullOrWhiteSpace(manifest.RootModule)
                    && !manifest.RootModule.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    files.TryAdd(manifest.RootModule, ModuleFileRole.RootModule);
                }

                AddFiles(files, manifest.ScriptsToProcess, ModuleFileRole.ScriptsToProcess);
                AddNestedModules(files, manifest.NestedModules);
                AddFiles(files, manifest.TypesToProcess, ModuleFileRole.TypesToProcess);
                AddFiles(files, manifest.FormatsToProcess, ModuleFileRole.FormatsToProcess);

                // Also sign the manifest itself (commonly expected even though engine skips it)
                string relManifest = System.IO.Path.GetRelativePath(moduleDir, manifestPath);
                files.TryAdd(relManifest, ModuleFileRole.Manifest);
            }
            catch (Exception ex)
            {
                WriteWarning($"Failed to parse manifest: {ex.Message}. Falling back to directory scan.");
                return FallbackScan(moduleDir);
            }
        }
        else
        {
            return FallbackScan(moduleDir);
        }

        if (IncludeUnreferenced.IsPresent)
        {
            foreach (string file in Directory.EnumerateFiles(moduleDir, "*", SearchOption.AllDirectories))
            {
                string ext = System.IO.Path.GetExtension(file);
                if (!SignableScriptExtensions.Contains(ext))
                    continue;
                string rel = System.IO.Path.GetRelativePath(moduleDir, file);
                files.TryAdd(rel, ModuleFileRole.Unreferenced);
            }
        }

        // Filter to only signable script extensions
        return files
            .Where(kv => SignableScriptExtensions.Contains(System.IO.Path.GetExtension(kv.Key)))
            .Select(kv => (kv.Key, kv.Value))
            .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private List<(string, ModuleFileRole)> FallbackScan(string moduleDir)
    {
        return Directory.EnumerateFiles(moduleDir, "*", SearchOption.AllDirectories)
            .Where(f => SignableScriptExtensions.Contains(System.IO.Path.GetExtension(f)))
            .Select(f => (System.IO.Path.GetRelativePath(moduleDir, f), ModuleFileRole.Unreferenced))
            .OrderBy(x => x.Item1, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void AddFiles(Dictionary<string, ModuleFileRole> files, string[] paths, ModuleFileRole role)
    {
        foreach (string p in paths)
        {
            if (!string.IsNullOrWhiteSpace(p))
                files.TryAdd(p, role);
        }
    }

    private static void AddNestedModules(Dictionary<string, ModuleFileRole> files, string[] paths)
    {
        foreach (string p in paths)
        {
            if (string.IsNullOrWhiteSpace(p))
                continue;
            if (p.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                continue; // skip binary nested modules
            files.TryAdd(p, ModuleFileRole.NestedModule);
        }
    }

    private SigningCertificateInfo ResolveSigningCertificate()
    {
        // Resolve cert store thumbprint if needed
        string? certDerBase64 = null;
        string? privateKeyDerBase64 = null;

        if (Certificate is not null)
        {
            certDerBase64 = Convert.ToBase64String(Certificate.Export(X509ContentType.Cert));
            if (Certificate.HasPrivateKey)
            {
                using RSA? rsa = Certificate.GetRSAPrivateKey();
                using ECDsa? ecdsa = Certificate.GetECDsaPrivateKey();
                AsymmetricAlgorithm? key = (AsymmetricAlgorithm?)rsa ?? ecdsa;
                if (key is not null)
                {
                    privateKeyDerBase64 = Convert.ToBase64String(key.ExportPkcs8PrivateKey());
                }
            }
        }
        else if (Thumbprint is not null)
        {
            var (cert, pkDer) = Provider.CertStorePathHelper.LoadCertificateAndKey(
                CertStoreDirectory, MachineStore.IsPresent ? "LocalMachine" : "CurrentUser",
                StoreName, Thumbprint);
            certDerBase64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
            if (pkDer is not null)
            {
                privateKeyDerBase64 = Convert.ToBase64String(pkDer);
            }
        }

        return new SigningCertificateInfo
        {
            CertificateDerBase64 = certDerBase64,
            PrivateKeyDerBase64 = privateKeyDerBase64,
        };
    }

    private PortableSignRequest CreateSignRequest(string path, SigningCertificateInfo certInfo)
    {
        return new PortableSignRequest
        {
            Path = path,
            HashAlgorithm = HashAlgorithm,
            CertificatePath = CertificatePath is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(CertificatePath),
            PrivateKeyPath = PrivateKeyPath is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(PrivateKeyPath),
            CertificateDerBase64 = certInfo.CertificateDerBase64,
            PrivateKeyDerBase64 = certInfo.PrivateKeyDerBase64,
            PfxPath = PfxPath is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(PfxPath),
            PfxPassword = Password is null ? null : SecureStringToString(Password),
            ChainCertificatePaths = ChainCertificatePath
                .Select(p => SessionState.Path.GetUnresolvedProviderPathFromPSPath(p))
                .ToArray(),
            ChainCertificatesDerBase64 = [],
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
        };
    }

    private static string? FindManifest(string moduleDir)
    {
        string dirName = System.IO.Path.GetFileName(moduleDir);
        string candidate = System.IO.Path.Combine(moduleDir, dirName + ".psd1");
        if (File.Exists(candidate))
            return candidate;

        string[] manifests = Directory.GetFiles(moduleDir, "*.psd1", SearchOption.TopDirectoryOnly);
        return manifests.Length > 0 ? manifests[0] : null;
    }

    private static string? SecureStringToString(SecureString secureString)
    {
        IntPtr ptr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(secureString);
        try
        {
            return System.Runtime.InteropServices.Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(ptr);
        }
    }

    private sealed class SigningCertificateInfo
    {
        public string? CertificateDerBase64 { get; init; }
        public string? PrivateKeyDerBase64 { get; init; }
    }
}

/// <summary>
/// Per-file result from Protect-PsignModule.
/// </summary>
public sealed class PsignModuleFileSignResult
{
    public string RelativePath { get; init; } = string.Empty;
    public ModuleFileRole Role { get; init; }
    public SignatureStatus Status { get; init; }
    public string? SignerSubject { get; init; }
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}

/// <summary>
/// Aggregate result of Protect-PsignModule.
/// </summary>
public sealed class PsignModuleSigningResult
{
    public string ModulePath { get; init; } = string.Empty;
    public string ModuleName { get; init; } = string.Empty;
    public int TotalFiles { get; init; }
    public int Succeeded { get; init; }
    public int Failed { get; init; }
    public PsignModuleFileSignResult[] Files { get; init; } = [];
}
