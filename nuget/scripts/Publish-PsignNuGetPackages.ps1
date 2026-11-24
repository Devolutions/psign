param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$ManagedPackageDir,

    [Parameter(Mandatory = $true)]
    [string]$ToolPackageDir,

    [string]$Source = 'https://api.nuget.org/v3/index.json',

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$') {
    throw "Invalid package version: $Version"
}

$managedIds = @(
    'Devolutions.Psign.Core'
    'Devolutions.Psign.Verification'
    'Devolutions.Psign.Signing'
)
$rids = @('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64', 'osx-x64', 'osx-arm64', 'any')
$packages = @(
    foreach ($id in $managedIds) { Join-Path $ManagedPackageDir "$id.$Version.nupkg" }
    foreach ($rid in $rids) { Join-Path $ToolPackageDir "Devolutions.Psign.Tool.$rid.$Version.nupkg" }
    Join-Path $ToolPackageDir "Devolutions.Psign.Tool.$Version.nupkg"
)

foreach ($package in $packages) {
    if (-not (Test-Path -LiteralPath $package -PathType Leaf)) {
        throw "Missing release package: $package"
    }
}

$apiKey = $env:NUGET_API_KEY
if (-not $DryRun -and [string]::IsNullOrWhiteSpace($apiKey)) {
    throw 'NUGET_API_KEY is required to publish packages.'
}

foreach ($package in $packages) {
    $name = [System.IO.Path]::GetFileName($package)
    if ($DryRun) {
        Write-Host "Would publish $name"
        continue
    }

    Write-Host "Publishing $name"
    dotnet nuget push $package --api-key $apiKey --source $Source --skip-duplicate --no-symbols
    if ($LASTEXITCODE -ne 0) {
        throw "NuGet push failed for $name with exit code $LASTEXITCODE."
    }
}
