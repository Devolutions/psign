param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [string]$Version
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dotnetRoot = Join-Path $repoRoot 'dotnet'
if ([string]::IsNullOrWhiteSpace($Version)) {
    [xml]$props = [System.IO.File]::ReadAllText((Join-Path $dotnetRoot 'Directory.Build.props'))
    $versionNode = $props.SelectSingleNode('/Project/PropertyGroup/Version')
    if ($null -eq $versionNode) {
        throw 'C# package version was not found in dotnet/Directory.Build.props.'
    }
    $Version = $versionNode.InnerText
}

if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$') {
    throw "Invalid package version: $Version"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$outputPath = (Resolve-Path -LiteralPath $OutputDir).Path
$sourceRoot = Join-Path $dotnetRoot 'src'

foreach ($name in @('Core', 'Verification', 'Signing', 'Cli', 'Server')) {
    $id = "Devolutions.Psign.$name"
    $project = Join-Path (Join-Path $sourceRoot $id) "$id.csproj"
    dotnet pack $project -c Release "-p:Version=$Version" -o $outputPath
    if ($LASTEXITCODE -ne 0) {
        throw "Packing $id failed with exit code $LASTEXITCODE."
    }

    $package = Join-Path $outputPath "$id.$Version.nupkg"
    if (-not (Test-Path -LiteralPath $package -PathType Leaf)) {
        throw "Expected package was not produced: $package"
    }
}
