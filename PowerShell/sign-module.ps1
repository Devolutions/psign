param(
    [Parameter(Mandatory = $true)]
    [string] $ModuleRoot,

    [string] $SignerModuleRoot,

    [switch] $VerifyOnly,

    [string] $AzureKeyVaultUrl,

    [string] $AzureKeyVaultCertificate,

    [string] $AzureKeyVaultClientId,

    [string] $AzureKeyVaultClientSecret,

    [string] $AzureKeyVaultTenantId,

    [string] $TimestampServer,

    [ValidateSet('Sha256', 'Sha384', 'Sha512')]
    [string] $HashAlgorithm = 'Sha256',

    [ValidateSet('Sha1', 'Sha256', 'Sha384', 'Sha512')]
    [string] $TimestampHashAlgorithm = 'Sha256'
)

$ErrorActionPreference = 'Stop'

function Get-PsignModuleSigningTargets {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResolvedModuleRoot
    )

    $topLevelExtensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($extension in @('.psd1', '.psm1', '.ps1xml')) {
        [void] $topLevelExtensions.Add($extension)
    }

    $targets = [System.Collections.Generic.List[string]]::new()
    Get-ChildItem -LiteralPath $ResolvedModuleRoot -File |
        Where-Object { $topLevelExtensions.Contains($_.Extension) } |
        Sort-Object FullName |
        ForEach-Object { [void] $targets.Add($_.FullName) }

    $managedAssemblyRoot = Join-Path (Join-Path $ResolvedModuleRoot 'lib') 'net8.0'
    if (Test-Path -LiteralPath $managedAssemblyRoot) {
        Get-ChildItem -LiteralPath $managedAssemblyRoot -Filter '*.dll' -File |
            Sort-Object FullName |
            ForEach-Object { [void] $targets.Add($_.FullName) }
    }

    return $targets.ToArray()
}

function Assert-PsignModuleSigningParameters {
    foreach ($name in @(
        'AzureKeyVaultUrl',
        'AzureKeyVaultCertificate',
        'AzureKeyVaultClientId',
        'AzureKeyVaultClientSecret',
        'AzureKeyVaultTenantId',
        'TimestampServer'
    )) {
        if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $name -ValueOnly))) {
            throw "$name is required when signing a PowerShell module release payload."
        }
    }
}

function Assert-PsignModuleSignatures {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Targets
    )

    foreach ($target in $Targets) {
        $signature = Get-PsignSignature -LiteralPath $target -ErrorAction Stop
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            $relativePath = Resolve-Path -LiteralPath $target -Relative
            throw "Expected valid Authenticode signature for '$relativePath', got '$($signature.Status)': $($signature.StatusMessage)"
        }
    }
}

$resolvedModuleRoot = (Resolve-Path -LiteralPath $ModuleRoot).Path
$manifestPath = Join-Path $resolvedModuleRoot 'Devolutions.Psign.psd1'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Devolutions.Psign manifest not found at '$manifestPath'."
}

$resolvedSignerModuleRoot = if ([string]::IsNullOrWhiteSpace($SignerModuleRoot)) {
    $resolvedModuleRoot
} else {
    (Resolve-Path -LiteralPath $SignerModuleRoot).Path
}
$signerManifestPath = Join-Path $resolvedSignerModuleRoot 'Devolutions.Psign.psd1'
if (-not (Test-Path -LiteralPath $signerManifestPath)) {
    throw "Devolutions.Psign signer manifest not found at '$signerManifestPath'."
}

$targets = @(Get-PsignModuleSigningTargets -ResolvedModuleRoot $resolvedModuleRoot)
if ($targets.Count -eq 0) {
    throw "No PowerShell module signing targets were found under '$resolvedModuleRoot'."
}

Import-Module $signerManifestPath -Force -ErrorAction Stop

if (-not $VerifyOnly.IsPresent) {
    Assert-PsignModuleSigningParameters

    $signingArguments = @{
        AzureKeyVaultUrl = $AzureKeyVaultUrl
        AzureKeyVaultCertificate = $AzureKeyVaultCertificate
        AzureKeyVaultClientId = $AzureKeyVaultClientId
        AzureKeyVaultClientSecret = $AzureKeyVaultClientSecret
        AzureKeyVaultTenantId = $AzureKeyVaultTenantId
        TimestampServer = $TimestampServer
        HashAlgorithm = $HashAlgorithm
        TimestampHashAlgorithm = $TimestampHashAlgorithm
        Force = $true
    }

    foreach ($target in $targets) {
        Set-PsignSignature -LiteralPath $target @signingArguments -ErrorAction Stop | Out-Null
    }
}

Assert-PsignModuleSignatures -Targets $targets

[pscustomobject]@{
    ModuleRoot = $resolvedModuleRoot
    Signed = -not $VerifyOnly.IsPresent
    TargetCount = $targets.Count
    Targets = $targets
}
