param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [string] $OutputDirectory = (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts') 'powershell'),

    [string] $NativeArtifactsRoot,

    [switch] $SkipNativeBuild,

    [string] $ModuleArchivePath,

    [switch] $SignModule,

    [string] $AzureKeyVaultUrl,

    [string] $AzureKeyVaultCertificate,

    [string] $AzureKeyVaultClientId,

    [string] $AzureKeyVaultClientSecret,

    [string] $AzureKeyVaultTenantId,

    [string] $TimestampServer,

    [string] $PsignToolPath,

    [ValidateSet('Sha256', 'Sha384', 'Sha512')]
    [string] $HashAlgorithm = 'Sha256',

    [ValidateSet('Sha1', 'Sha256', 'Sha384', 'Sha512')]
    [string] $TimestampHashAlgorithm = 'Sha256'
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$moduleRoot = Join-Path $PSScriptRoot 'Devolutions.Psign'
$localRepo = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
$installRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
$repoName = "DevolutionsPsignLocal$([System.Guid]::NewGuid().ToString('N'))"

$buildArgs = @{
    Configuration = $Configuration
}
if ($NativeArtifactsRoot) {
    $buildArgs.NativeArtifactsRoot = $NativeArtifactsRoot
}
if ($SkipNativeBuild) {
    $buildArgs.SkipNativeBuild = $true
}
& (Join-Path $PSScriptRoot 'build.ps1') @buildArgs

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
if ($ModuleArchivePath) {
    $moduleArchiveParent = Split-Path -Parent $ModuleArchivePath
    if (-not [string]::IsNullOrWhiteSpace($moduleArchiveParent)) {
        New-Item -ItemType Directory -Force -Path $moduleArchiveParent | Out-Null
    }
}
New-Item -ItemType Directory -Force -Path $localRepo | Out-Null
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null

$manifestPath = Join-Path $moduleRoot 'Devolutions.Psign.psd1'
$manifest = Test-ModuleManifest -Path $manifestPath
$expectedCmdlets = @('Get-PsignSignature', 'Set-PsignSignature', 'Test-PsignModule', 'Protect-PsignModule', 'Unprotect-PsignSignature')
foreach ($cmdlet in $expectedCmdlets) {
    if ($manifest.ExportedCmdlets.Keys -notcontains $cmdlet) {
        throw "Module manifest does not export expected cmdlet '$cmdlet'."
    }
}

$packageModuleRoot = $moduleRoot
if ($SignModule) {
    New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null
    Copy-Item -LiteralPath $moduleRoot -Destination $stagingRoot -Recurse -Force
    $packageModuleRoot = Join-Path $stagingRoot (Split-Path -Leaf $moduleRoot)

    & (Join-Path $PSScriptRoot 'sign-module.ps1') `
        -ModuleRoot $packageModuleRoot `
        -SignerModuleRoot $moduleRoot `
        -AzureKeyVaultUrl $AzureKeyVaultUrl `
        -AzureKeyVaultCertificate $AzureKeyVaultCertificate `
        -AzureKeyVaultClientId $AzureKeyVaultClientId `
        -AzureKeyVaultClientSecret $AzureKeyVaultClientSecret `
        -AzureKeyVaultTenantId $AzureKeyVaultTenantId `
        -TimestampServer $TimestampServer `
        -PsignToolPath $PsignToolPath `
        -HashAlgorithm $HashAlgorithm `
        -TimestampHashAlgorithm $TimestampHashAlgorithm | Out-Host

    $manifestPath = Join-Path $packageModuleRoot 'Devolutions.Psign.psd1'
    $manifest = Test-ModuleManifest -Path $manifestPath
    foreach ($cmdlet in $expectedCmdlets) {
        if ($manifest.ExportedCmdlets.Keys -notcontains $cmdlet) {
            throw "Signed module manifest does not export expected cmdlet '$cmdlet'."
        }
    }
}

try {
    Register-PSRepository -Name $repoName -SourceLocation $localRepo -PublishLocation $localRepo -InstallationPolicy Trusted
    Publish-Module -Path $packageModuleRoot -Repository $repoName -NuGetApiKey 'local-package'

    $package = Get-ChildItem -Path $localRepo -Filter 'Devolutions.Psign.*.nupkg' |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $package) {
        throw "PowerShell module package was not created in $localRepo"
    }

    Copy-Item -Force -Path $package.FullName -Destination $OutputDirectory
    Save-Module -Name 'Devolutions.Psign' -RequiredVersion $manifest.Version.ToString() -Repository $repoName -Path $installRoot
    $savedManifest = Join-Path (Join-Path (Join-Path $installRoot 'Devolutions.Psign') $manifest.Version.ToString()) 'Devolutions.Psign.psd1'
    Import-Module $savedManifest -Force
    foreach ($cmdlet in $expectedCmdlets) {
        if (-not (Get-Command $cmdlet -Module 'Devolutions.Psign' -ErrorAction SilentlyContinue)) {
            throw "Installed package smoke test did not find cmdlet '$cmdlet'."
        }
    }
    if ($SignModule) {
        $savedModuleRoot = Split-Path -Parent $savedManifest
        & (Join-Path $PSScriptRoot 'sign-module.ps1') -ModuleRoot $savedModuleRoot -VerifyOnly | Out-Host
    }
    $nativeProbe = New-TemporaryFile
    try {
        $null = Get-PsignSignature -LiteralPath $nativeProbe.FullName -ErrorAction Stop
    }
    finally {
        Remove-Item -LiteralPath $nativeProbe.FullName -Force -ErrorAction SilentlyContinue
    }
    if ($ModuleArchivePath) {
        if (Test-Path -LiteralPath $ModuleArchivePath) {
            Remove-Item -LiteralPath $ModuleArchivePath -Force
        }
        Compress-Archive -Path $packageModuleRoot -DestinationPath $ModuleArchivePath -Force
    }
    Get-Item -LiteralPath (Join-Path $OutputDirectory $package.Name)
}
finally {
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
    Unregister-PSRepository -Name $repoName -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $localRepo -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
}
