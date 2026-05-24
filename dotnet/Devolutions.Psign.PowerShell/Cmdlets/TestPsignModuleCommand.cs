using System.Globalization;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Provider;
using Devolutions.Psign.PowerShell.Trust;
using Devolutions.Psign.PowerShell.Utilities;

namespace Devolutions.Psign.PowerShell.Cmdlets;

/// <summary>
/// Validates whether a PowerShell module's files are correctly signed according
/// to a given execution policy (AllSigned or RemoteSigned). Simulates the checks
/// that PowerShell's engine would perform during Import-Module.
/// </summary>
[Cmdlet(VerbsDiagnostic.Test, "PsignModule")]
[OutputType(typeof(PsignModuleValidationResult))]
public sealed class TestPsignModuleCommand : PSCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, HelpMessage = "Path to the PowerShell module directory to validate.")]
    [Alias("ModulePath", "PSPath")]
    public string Path { get; set; } = string.Empty;

    [Parameter(Position = 1)]
    [ValidateSet("AllSigned", "RemoteSigned")]
    public PsignSigningPolicy Policy { get; set; } = PsignSigningPolicy.AllSigned;

    /// <summary>
    /// When set, also verifies that each signer's leaf certificate is in the
    /// TrustedPublisher store (pcert:\CurrentUser\Trust or pcert:\LocalMachine\Trust).
    /// </summary>
    [Parameter]
    public SwitchParameter RequireTrustedPublisher { get; set; }

    /// <summary>
    /// Also check files found in the module directory that are signable but not
    /// explicitly referenced in the manifest (belt-and-suspenders mode).
    /// </summary>
    [Parameter]
    public SwitchParameter IncludeUnreferenced { get; set; }

    [Parameter]
    public X509Certificate2[] TrustedCertificate { get; set; } = [];

    [Parameter]
    public string[] TrustedCertificatePath { get; set; } = [];

    [Parameter]
    public string? AnchorDirectory { get; set; }

    [Parameter]
    public string? AuthRootCab { get; set; }

    [Parameter]
    public SwitchParameter SkipTrust { get; set; }

    // Extensions that the PowerShell engine's CheckPolicy actually validates
    private static readonly HashSet<string> PolicyCheckedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".ps1xml", ".cdxml",
    };

    // Signable script extensions we enumerate
    private static readonly HashSet<string> SignableScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".ps1xml", ".cdxml",
    };

    protected override void ProcessRecord()
    {
        string resolvedPath = SessionState.Path.GetUnresolvedProviderPathFromPSPath(Path);

        // Find the manifest
        string moduleDir;
        string? manifestPath;

        if (Directory.Exists(resolvedPath))
        {
            moduleDir = resolvedPath;
            manifestPath = FindManifest(moduleDir);
        }
        else if (File.Exists(resolvedPath) && resolvedPath.EndsWith(".psd1", StringComparison.OrdinalIgnoreCase))
        {
            manifestPath = resolvedPath;
            moduleDir = System.IO.Path.GetDirectoryName(resolvedPath)!;
        }
        else
        {
            WriteError(new ErrorRecord(
                new DirectoryNotFoundException($"Module path not found: {resolvedPath}"),
                "ModulePathNotFound", ErrorCategory.ObjectNotFound, resolvedPath));
            return;
        }

        string moduleName = System.IO.Path.GetFileName(moduleDir);

        // Parse manifest to discover referenced files
        var fileRoles = new Dictionary<string, ModuleFileRole>(StringComparer.OrdinalIgnoreCase);

        if (manifestPath is not null)
        {
            string relManifest = System.IO.Path.GetRelativePath(moduleDir, manifestPath);
            fileRoles[relManifest] = ModuleFileRole.Manifest;

            try
            {
                var manifest = ModuleManifestInfo.Parse(manifestPath);
                AddRole(fileRoles, moduleDir, manifest.RootModule, manifest);
                AddRoles(fileRoles, manifest.ScriptsToProcess, ModuleFileRole.ScriptsToProcess);
                AddRoles(fileRoles, manifest.NestedModules, ModuleFileRole.NestedModule);
                AddRoles(fileRoles, manifest.TypesToProcess, ModuleFileRole.TypesToProcess);
                AddRoles(fileRoles, manifest.FormatsToProcess, ModuleFileRole.FormatsToProcess);
                AddRoles(fileRoles, manifest.RequiredAssemblies, ModuleFileRole.BinaryModule);
            }
            catch (Exception ex)
            {
                WriteWarning($"Failed to parse manifest: {ex.Message}. Falling back to directory scan.");
            }
        }

        // Optionally include unreferenced signable files
        if (IncludeUnreferenced.IsPresent)
        {
            foreach (string file in Directory.EnumerateFiles(moduleDir, "*", SearchOption.AllDirectories))
            {
                string ext = System.IO.Path.GetExtension(file);
                if (!SignableScriptExtensions.Contains(ext) && !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                    continue;

                string rel = System.IO.Path.GetRelativePath(moduleDir, file);
                if (!fileRoles.ContainsKey(rel))
                {
                    fileRoles[rel] = ModuleFileRole.Unreferenced;
                }
            }
        }

        // Load trusted publisher thumbprints
        var trustedPublishers = LoadTrustedPublishers();

        // Validate each file
        var results = new List<PsignModuleFileResult>();
        foreach (var (relativePath, role) in fileRoles.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            string fullPath = System.IO.Path.Combine(moduleDir, relativePath);
            if (!File.Exists(fullPath))
            {
                results.Add(new PsignModuleFileResult
                {
                    RelativePath = relativePath,
                    Role = role,
                    RequiredByPolicy = IsRequiredByPolicy(role, relativePath),
                    Status = SignatureStatus.NotSigned,
                    Passes = false,
                    FailureReason = "File not found",
                });
                continue;
            }

            bool requiredByPolicy = IsRequiredByPolicy(role, relativePath);
            var fileResult = ValidateFile(fullPath, relativePath, role, requiredByPolicy, trustedPublishers);
            results.Add(fileResult);
        }

        int failed = results.Count(r => r.RequiredByPolicy && !r.Passes);
        int passed = results.Count(r => r.RequiredByPolicy && r.Passes);
        int skipped = results.Count(r => !r.RequiredByPolicy);
        bool valid = failed == 0;

        string summary = valid
            ? $"Module '{moduleName}' passes {Policy} policy ({passed} files verified)"
            : $"Module '{moduleName}' FAILS {Policy} policy ({failed} file(s) would block loading)";

        WriteObject(new PsignModuleValidationResult
        {
            ModulePath = moduleDir,
            ModuleName = moduleName,
            Policy = Policy,
            RequireTrustedPublisher = RequireTrustedPublisher.IsPresent,
            Valid = valid,
            Summary = summary,
            Files = results.ToArray(),
            FailedCount = failed,
            PassedCount = passed,
            SkippedCount = skipped,
        });
    }

    private bool IsRequiredByPolicy(ModuleFileRole role, string relativePath)
    {
        // PowerShell engine behavior:
        // - .psd1 manifest: NEVER checked (explicit skip in GetScriptInfoForFile)
        // - .dll binary modules: NEVER checked by execution policy
        // - Unreferenced: only checked if IncludeUnreferenced + AllSigned
        if (role is ModuleFileRole.Manifest or ModuleFileRole.BinaryModule)
            return false;

        string ext = System.IO.Path.GetExtension(relativePath);

        // Only extensions in PolicyCheckedExtensions are validated by the engine
        if (!PolicyCheckedExtensions.Contains(ext))
            return false;

        // Under RemoteSigned: on Linux all files are "local" and skipped.
        // We treat ALL files as remote for worst-case validation (portable scenario).
        // Under AllSigned: all policy-checked extensions are required.
        return Policy switch
        {
            PsignSigningPolicy.AllSigned => true,
            PsignSigningPolicy.RemoteSigned => true, // worst-case: treat as remote
            _ => false,
        };
    }

    private PsignModuleFileResult ValidateFile(
        string fullPath, string relativePath, ModuleFileRole role,
        bool requiredByPolicy, HashSet<string> trustedPublishers)
    {
        string ext = System.IO.Path.GetExtension(fullPath);

        // For non-script files that aren't checked, just report their signature status informatively
        if (!SignableScriptExtensions.Contains(ext) && !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
        {
            return new PsignModuleFileResult
            {
                RelativePath = relativePath,
                Role = role,
                RequiredByPolicy = false,
                Status = SignatureStatus.NotSupportedFileFormat,
                Passes = true,
            };
        }

        PortableSignature sig;
        try
        {
            sig = PsignNative.GetSignature(CreateVerifyRequest(fullPath));
        }
        catch (Exception ex)
        {
            return new PsignModuleFileResult
            {
                RelativePath = relativePath,
                Role = role,
                RequiredByPolicy = requiredByPolicy,
                Status = SignatureStatus.UnknownError,
                Passes = false,
                FailureReason = $"Verification error: {ex.Message}",
            };
        }

        // Determine effective status — prefer TrustStatus when available
        SignatureStatus effectiveStatus = sig.TrustStatus ?? sig.Status;
        bool signatureValid = effectiveStatus == SignatureStatus.Valid;

        // Publisher trust check
        string? signerThumbprint = sig.SignerCertificate?.Thumbprint;
        bool isTrustedPublisher = signerThumbprint is not null
            && trustedPublishers.Contains(signerThumbprint);

        bool passes;
        string? failureReason = null;

        if (!requiredByPolicy)
        {
            // Not required by policy — always passes (informational only)
            passes = true;
        }
        else if (!signatureValid)
        {
            passes = false;
            failureReason = effectiveStatus switch
            {
                SignatureStatus.NotSigned => "File is not signed",
                SignatureStatus.HashMismatch => "Signature hash does not match file content",
                SignatureStatus.NotTrusted => "Signing certificate is explicitly distrusted",
                SignatureStatus.Incompatible => "Unsupported signature algorithm",
                _ => $"Signature validation failed: {effectiveStatus}",
            };
        }
        else if (RequireTrustedPublisher.IsPresent && !isTrustedPublisher)
        {
            passes = false;
            failureReason = signerThumbprint is not null
                ? $"Signer {sig.SignerCertificate?.Subject} ({signerThumbprint}) not in TrustedPublisher store"
                : "No signer certificate found";
        }
        else
        {
            passes = true;
        }

        return new PsignModuleFileResult
        {
            RelativePath = relativePath,
            Role = role,
            RequiredByPolicy = requiredByPolicy,
            Status = sig.Status,
            TrustStatus = sig.TrustStatus,
            SignerSubject = sig.SignerCertificate?.Subject,
            SignerThumbprint = signerThumbprint,
            IsTrustedPublisher = isTrustedPublisher,
            Passes = passes,
            FailureReason = failureReason,
        };
    }

    private PortableGetSignatureRequest CreateVerifyRequest(string path)
    {
        string? resolvedAuthRootCab = AuthRootCab is null
            ? null
            : SessionState.Path.GetUnresolvedProviderPathFromPSPath(AuthRootCab);

        if (!SkipTrust.IsPresent
            && resolvedAuthRootCab is null
            && AnchorDirectory is null
            && TrustedCertificatePath.Length == 0
            && TrustedCertificate.Length == 0)
        {
            resolvedAuthRootCab = AuthRootCache.GetOrDownloadAuthRootCab(
                msg => WriteVerbose(msg));
        }

        return new PortableGetSignatureRequest
        {
            Path = path,
            TrustedCertificatePaths = TrustedCertificatePath
                .Select(p => SessionState.Path.GetUnresolvedProviderPathFromPSPath(p))
                .ToArray(),
            TrustedCertificatesDerBase64 = TrustedCertificate
                .Select(c => Convert.ToBase64String(c.Export(X509ContentType.Cert)))
                .ToArray(),
            AnchorDirectory = AnchorDirectory is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(AnchorDirectory),
            AuthRootCab = resolvedAuthRootCab,
            PreferTimestampSigningTime = true,
            RequireValidTimestamp = false,
            OnlineAia = true,
            OnlineOcsp = false,
            RevocationMode = "Off",
        };
    }

    private HashSet<string> LoadTrustedPublishers()
    {
        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!RequireTrustedPublisher.IsPresent)
            return thumbprints;

        string baseDir = CertStorePathHelper.ResolveBaseDirectory();

        // Check both CurrentUser and LocalMachine Trust stores
        foreach (string scope in new[] { "CurrentUser", "LocalMachine" })
        {
            string storePath = System.IO.Path.Combine(baseDir, scope, "Trust");
            if (!Directory.Exists(storePath))
                continue;

            foreach (string certFile in Directory.EnumerateFiles(storePath, "*.der"))
            {
                string thumbprint = System.IO.Path.GetFileNameWithoutExtension(certFile);
                thumbprints.Add(thumbprint);
            }
        }

        return thumbprints;
    }

    private static string? FindManifest(string moduleDir)
    {
        string dirName = System.IO.Path.GetFileName(moduleDir);
        string candidate = System.IO.Path.Combine(moduleDir, dirName + ".psd1");
        if (File.Exists(candidate))
            return candidate;

        // Fallback: any .psd1 in the root
        string[] manifests = Directory.GetFiles(moduleDir, "*.psd1", SearchOption.TopDirectoryOnly);
        return manifests.Length > 0 ? manifests[0] : null;
    }

    private static void AddRole(
        Dictionary<string, ModuleFileRole> roles, string moduleDir,
        string? rootModule, ModuleManifestInfo manifest)
    {
        if (string.IsNullOrWhiteSpace(rootModule))
            return;

        string ext = System.IO.Path.GetExtension(rootModule);
        ModuleFileRole role = ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
            ? ModuleFileRole.BinaryModule
            : ModuleFileRole.RootModule;

        roles.TryAdd(rootModule, role);
    }

    private static void AddRoles(
        Dictionary<string, ModuleFileRole> roles, string[] paths, ModuleFileRole role)
    {
        foreach (string p in paths)
        {
            if (!string.IsNullOrWhiteSpace(p))
            {
                // For nested modules that are DLLs, mark as BinaryModule
                string ext = System.IO.Path.GetExtension(p);
                ModuleFileRole effectiveRole = ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                    ? ModuleFileRole.BinaryModule
                    : role;
                roles.TryAdd(p, effectiveRole);
            }
        }
    }
}
