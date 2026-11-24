param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDir,

    [string]$Version
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path (Join-Path $PSScriptRoot '..') '..')).Path
if ([string]::IsNullOrWhiteSpace($Version)) {
    $propsPath = Join-Path (Join-Path $repoRoot 'dotnet') 'Directory.Build.props'
    [xml]$props = [System.IO.File]::ReadAllText($propsPath)
    $versionNode = $props.SelectSingleNode('/Project/PropertyGroup/Version')
    if ($null -eq $versionNode) {
        throw 'C# package version was not found in dotnet/Directory.Build.props.'
    }
    $Version = $versionNode.InnerText
}

$packageSource = (Resolve-Path -LiteralPath $PackageDir).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "psign-managed-packages-$([guid]::NewGuid().ToString('N'))"
$originalPackages = $env:NUGET_PACKAGES

function Invoke-Dotnet {
    param([string[]]$Arguments)

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($Arguments[0]) failed with exit code $LASTEXITCODE."
    }
}

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $env:NUGET_PACKAGES = Join-Path $testRoot 'packages'
    $config = Join-Path $testRoot 'NuGet.Config'
    $escapedSource = [System.Security.SecurityElement]::Escape($packageSource)
    @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$escapedSource" />
  </packageSources>
</configuration>
"@ | Set-Content -LiteralPath $config -Encoding utf8

    $escapedVersion = [System.Security.SecurityElement]::Escape($Version)

    $consumers = @(
        @{
            Name = 'validation-consumer'
            PackageId = 'Devolutions.Psign.Core'
            Types = @(
                'Devolutions.Psign.Core.Authenticode.SpcIndirectDataContent'
                'Devolutions.Psign.Verification.TrustVerifyZip'
            )
        }
        @{
            Name = 'signing-consumer'
            PackageId = 'Devolutions.Psign.Signing'
            Types = @(
                'Devolutions.Psign.Signing.Zip.ZipAuthenticodeSigner'
            )
        }
    )

    foreach ($item in $consumers) {
        $consumer = Join-Path $testRoot $item.Name
        New-Item -ItemType Directory -Path $consumer | Out-Null
        $project = Join-Path $consumer 'Consumer.csproj'
        @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="$($item.PackageId)" Version="$escapedVersion" />
  </ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $project -Encoding utf8
        $types = ($item.Types | ForEach-Object { "        typeof($_)" }) -join ",`n"
        @"
public static class Consumer
{
    public static System.Type[] PackageTypes() => new[]
    {
$types
    };
}
"@ | Set-Content -LiteralPath (Join-Path $consumer 'Consumer.cs') -Encoding utf8

        Invoke-Dotnet -Arguments @('restore', $project, '--configfile', $config)
        Invoke-Dotnet -Arguments @('build', $project, '-c', 'Release', '--no-restore')

        if ($item.PackageId -eq 'Devolutions.Psign.Core') {
            $assetsPath = Join-Path (Join-Path $consumer 'obj') 'project.assets.json'
            $assets = Get-Content -LiteralPath $assetsPath -Raw | ConvertFrom-Json
            if ($assets.libraries.PSObject.Properties.Name -contains "Devolutions.Psign.Signing/$Version") {
                throw 'The validation-only Core consumer unexpectedly resolved the Signing package.'
            }
        }
    }

    Write-Host "Managed NuGet packages $Version passed validation-only and signing consumer smoke tests."
}
finally {
    $env:NUGET_PACKAGES = $originalPackages
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
