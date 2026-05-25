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

    [string] $ArtifactSigningEndpoint,

    [string] $ArtifactSigningAccountName,

    [string] $ArtifactSigningProfileName,

    [string] $ArtifactSigningAccessToken,

    [switch] $ArtifactSigningManagedIdentity,

    [string] $ArtifactSigningTenantId,

    [string] $ArtifactSigningClientId,

    [string] $ArtifactSigningClientSecret,

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

function Test-TextValue {
    param([string] $Value)

    return -not [string]::IsNullOrWhiteSpace($Value)
}

function Assert-RequiredTextParameters {
    param([string[]] $Names)

    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $name -ValueOnly))) {
            throw "$name is required when signing a PowerShell module release payload."
        }
    }
}

function Assert-PsignModuleSigningParameters {
    Assert-RequiredTextParameters -Names @('TimestampServer')

    $hasAzureKeyVault = (Test-TextValue $AzureKeyVaultUrl) -or
        (Test-TextValue $AzureKeyVaultCertificate)
    $hasArtifactSigning = (Test-TextValue $ArtifactSigningEndpoint) -or
        (Test-TextValue $ArtifactSigningAccountName) -or
        (Test-TextValue $ArtifactSigningProfileName)

    if ($hasAzureKeyVault -eq $hasArtifactSigning) {
        throw "Provide exactly one cloud signing provider for the PowerShell module release payload: Azure Key Vault or Artifact Signing."
    }

    if ($hasAzureKeyVault) {
        Assert-RequiredTextParameters -Names @(
            'AzureKeyVaultUrl',
            'AzureKeyVaultCertificate',
            'AzureKeyVaultClientId',
            'AzureKeyVaultClientSecret',
            'AzureKeyVaultTenantId'
        )
        return
    }

    Assert-RequiredTextParameters -Names @(
        'ArtifactSigningEndpoint',
        'ArtifactSigningAccountName',
        'ArtifactSigningProfileName'
    )
}

function Invoke-PsignModuleSigning {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Target
    )

    $signArgs = @{
        LiteralPath = $Target
        TimestampServer = $TimestampServer
        TimestampHashAlgorithm = $TimestampHashAlgorithm
        HashAlgorithm = $HashAlgorithm
        Force = $true
        ErrorAction = 'Stop'
    }

    if (Test-TextValue $AzureKeyVaultUrl) {
        $signArgs.AzureKeyVaultUrl = $AzureKeyVaultUrl
        $signArgs.AzureKeyVaultCertificate = $AzureKeyVaultCertificate
        $signArgs.AzureKeyVaultClientId = $AzureKeyVaultClientId
        $signArgs.AzureKeyVaultClientSecret = $AzureKeyVaultClientSecret
        $signArgs.AzureKeyVaultTenantId = $AzureKeyVaultTenantId
    } else {
        $signArgs.ArtifactSigningEndpoint = $ArtifactSigningEndpoint
        $signArgs.ArtifactSigningAccountName = $ArtifactSigningAccountName
        $signArgs.ArtifactSigningProfileName = $ArtifactSigningProfileName
        if (Test-TextValue $ArtifactSigningAccessToken) {
            $signArgs.ArtifactSigningAccessToken = $ArtifactSigningAccessToken
        }
        if ($ArtifactSigningManagedIdentity.IsPresent) {
            $signArgs.ArtifactSigningManagedIdentity = $true
        }
        if (Test-TextValue $ArtifactSigningTenantId) {
            $signArgs.ArtifactSigningTenantId = $ArtifactSigningTenantId
        }
        if (Test-TextValue $ArtifactSigningClientId) {
            $signArgs.ArtifactSigningClientId = $ArtifactSigningClientId
        }
        if (Test-TextValue $ArtifactSigningClientSecret) {
            $signArgs.ArtifactSigningClientSecret = $ArtifactSigningClientSecret
        }
    }

    Set-PsignSignature @signArgs | Out-Null
}

function Assert-PsignModuleSignatures {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Targets
    )

    foreach ($target in $Targets) {
        $signature = Get-PsignSignature -LiteralPath $target -ErrorAction Stop
        if ($signature.SignatureType -ne [System.Management.Automation.SignatureType]::Authenticode -or
            $signature.Status -notin @(
                [System.Management.Automation.SignatureStatus]::Valid,
                [System.Management.Automation.SignatureStatus]::NotTrusted
            )) {
            $relativePath = Resolve-Path -LiteralPath $target -Relative
            throw "Expected intact Authenticode signature for '$relativePath', got '$($signature.Status)': $($signature.StatusMessage)"
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

    foreach ($target in $targets) {
        Invoke-PsignModuleSigning -Target $target
    }
}

Assert-PsignModuleSignatures -Targets $targets

[pscustomobject]@{
    ModuleRoot = $resolvedModuleRoot
    Signed = -not $VerifyOnly.IsPresent
    TargetCount = $targets.Count
    Targets = $targets
}
