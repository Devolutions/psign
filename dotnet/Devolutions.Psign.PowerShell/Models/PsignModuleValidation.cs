using System.Management.Automation;

namespace Devolutions.Psign.PowerShell.Models;

/// <summary>
/// Simulated PowerShell execution policy for module signature validation.
/// Mirrors the subset of policies that actually enforce signature checks.
/// </summary>
public enum PsignSigningPolicy
{
    /// <summary>
    /// All script files (.ps1, .psm1, .ps1xml, .cdxml) must have valid signatures.
    /// Mirrors PowerShell's AllSigned execution policy.
    /// </summary>
    AllSigned,

    /// <summary>
    /// Only "remote" files must be signed. Since there's no Zone.Identifier on
    /// Linux/macOS, this mode treats ALL files as remote (worst-case validation).
    /// Mirrors PowerShell's RemoteSigned execution policy.
    /// </summary>
    RemoteSigned,
}

/// <summary>
/// Why a file is required (or not) for policy validation during module loading.
/// </summary>
public enum ModuleFileRole
{
    RootModule,
    ScriptsToProcess,
    NestedModule,
    TypesToProcess,
    FormatsToProcess,

    /// <summary>The .psd1 manifest itself — never checked by the engine.</summary>
    Manifest,

    /// <summary>Binary module (.dll) — never checked by execution policy.</summary>
    BinaryModule,

    /// <summary>File found in module directory but not referenced in manifest.</summary>
    Unreferenced,
}

/// <summary>
/// Per-file validation result within a module validation run.
/// </summary>
public sealed class PsignModuleFileResult
{
    /// <summary>Relative path from the module root.</summary>
    public string RelativePath { get; init; } = string.Empty;

    /// <summary>Role of this file in the module load sequence.</summary>
    public ModuleFileRole Role { get; init; }

    /// <summary>Whether the execution policy actually checks this file's signature.</summary>
    public bool RequiredByPolicy { get; init; }

    /// <summary>Signature status returned by psign verification.</summary>
    public SignatureStatus Status { get; init; } = SignatureStatus.NotSigned;

    /// <summary>Trust status (chain validation result).</summary>
    public SignatureStatus? TrustStatus { get; init; }

    /// <summary>Subject of the signing certificate, if present.</summary>
    public string? SignerSubject { get; init; }

    /// <summary>Thumbprint of the signing certificate leaf.</summary>
    public string? SignerThumbprint { get; init; }

    /// <summary>Whether the signer is in the TrustedPublisher store.</summary>
    public bool IsTrustedPublisher { get; init; }

    /// <summary>Whether the signer is in the Disallowed store.</summary>
    public bool IsDisallowedPublisher { get; init; }

    /// <summary>Whether this file passes the policy check.</summary>
    public bool Passes { get; init; }

    /// <summary>Reason for failure, if any.</summary>
    public string? FailureReason { get; init; }
}

/// <summary>
/// Aggregate result of validating a PowerShell module against a signing policy.
/// </summary>
public sealed class PsignModuleValidationResult
{
    /// <summary>Absolute path to the module root directory.</summary>
    public string ModulePath { get; init; } = string.Empty;

    /// <summary>Module name (from manifest or directory name).</summary>
    public string ModuleName { get; init; } = string.Empty;

    /// <summary>Policy that was validated against.</summary>
    public PsignSigningPolicy Policy { get; init; }

    /// <summary>Whether publisher trust was required.</summary>
    public bool RequireTrustedPublisher { get; init; }

    /// <summary>Overall pass/fail result.</summary>
    public bool Valid { get; init; }

    /// <summary>Summary message.</summary>
    public string Summary { get; init; } = string.Empty;

    /// <summary>Per-file results.</summary>
    public PsignModuleFileResult[] Files { get; init; } = [];

    /// <summary>Count of files that failed policy.</summary>
    public int FailedCount { get; init; }

    /// <summary>Count of files that passed policy.</summary>
    public int PassedCount { get; init; }

    /// <summary>Count of files skipped (not checked by policy).</summary>
    public int SkippedCount { get; init; }
}
