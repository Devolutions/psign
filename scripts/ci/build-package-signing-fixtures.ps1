# Build small unsigned and signed NuGet / VSIX package-signing fixtures.
#
# NuGet signing uses `dotnet nuget sign`. VSIX signing uses the Windows
# `System.IO.Packaging.PackageDigitalSignatureManager` reference implementation.
param(
    [string]$WorkspaceRoot = "",
    [string]$OutputDir = "",
    [string]$PfxPath = "",
    [string]$PfxPassword = "CodeSign123!",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$WorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path

if (-not $OutputDir) { $OutputDir = Join-Path $WorkspaceRoot "tests\fixtures\package-signing" }
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir = Join-Path $WorkspaceRoot $OutputDir }

if (-not $PfxPath) {
    $PfxPath = Join-Path $WorkspaceRoot "tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx"
}
elseif (-not [System.IO.Path]::IsPathRooted($PfxPath)) {
    $PfxPath = Join-Path $WorkspaceRoot $PfxPath
}
if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }

Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName WindowsBase

function Convert-ToManifestPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    return [System.IO.Path]::GetRelativePath($WorkspaceRoot, $full)
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function New-CleanDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        if (-not $Force) { throw "Output directory already exists: $Path. Pass -Force to replace it." }
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function New-ZipFromDirectory {
    param(
        [Parameter(Mandatory)][string]$SourceDir,
        [Parameter(Mandatory)][string]$Destination
    )
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($SourceDir, $Destination, [System.IO.Compression.CompressionLevel]::Optimal, $false)
}

function Add-ManifestEntry {
    param(
        [Parameter(Mandatory)]$List,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$Path,
        [string]$SourcePath = "",
        [string]$Tool = ""
    )
    $item = Get-Item -LiteralPath $Path
    $entry = [ordered]@{
        id = $Id
        family = $Family
        state = $State
        path = Convert-ToManifestPath -Path $item.FullName
        size_bytes = $item.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
    }
    if ($SourcePath) { $entry.source_path = Convert-ToManifestPath -Path $SourcePath }
    if ($Tool) { $entry.tool = $Tool }
    $List.Add($entry)
}

function New-UnsignedNuGetPackage {
    param([Parameter(Mandatory)][string]$Path)
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("psign-nupkg-fixture-" + [guid]::NewGuid())
    try {
        New-Item -ItemType Directory -Force -Path (Join-Path $stage "lib\net8.0") | Out-Null
        Write-Utf8NoBom -Path (Join-Path $stage "[Content_Types].xml") -Text @'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="psmdcp" ContentType="application/vnd.openxmlformats-package.core-properties+xml" />
  <Default Extension="txt" ContentType="text/plain" />
  <Default Extension="nuspec" ContentType="application/octet" />
</Types>
'@
        Write-Utf8NoBom -Path (Join-Path $stage "Psign.PackageFixture.nuspec") -Text @'
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Psign.PackageFixture</id>
    <version>1.0.0</version>
    <authors>psign</authors>
    <description>Small NuGet package signing fixture.</description>
  </metadata>
</package>
'@
        Write-Utf8NoBom -Path (Join-Path $stage "lib\net8.0\sample.txt") -Text "psign NuGet fixture`n"
        New-ZipFromDirectory -SourceDir $stage -Destination $Path
    }
    finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function New-UnsignedVsixPackage {
    param([Parameter(Mandatory)][string]$Path)
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("psign-vsix-fixture-" + [guid]::NewGuid())
    try {
        New-Item -ItemType Directory -Force -Path (Join-Path $stage "_rels") | Out-Null
        Write-Utf8NoBom -Path (Join-Path $stage "[Content_Types].xml") -Text @'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="vsixmanifest" ContentType="text/xml" />
  <Default Extension="txt" ContentType="text/plain" />
</Types>
'@
        Write-Utf8NoBom -Path (Join-Path $stage "_rels\.rels") -Text @'
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="R1" Type="http://schemas.microsoft.com/developer/vsx-schema/2011/relationships/extension-manifest" Target="/extension.vsixmanifest" />
</Relationships>
'@
        Write-Utf8NoBom -Path (Join-Path $stage "extension.vsixmanifest") -Text @'
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Id="Psign.PackageFixture" Version="1.0" Language="en-US" Publisher="psign" />
    <DisplayName>psign package fixture</DisplayName>
    <Description xml:space="preserve">Small VSIX package signing fixture.</Description>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Community" Version="[17.0,18.0)" />
  </Installation>
  <Assets />
</PackageManifest>
'@
        Write-Utf8NoBom -Path (Join-Path $stage "payload.txt") -Text "psign VSIX fixture`n"
        New-ZipFromDirectory -SourceDir $stage -Destination $Path
    }
    finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-DotnetNuGetSign {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$CertificatePath
    )
    $output = & dotnet nuget sign $PackagePath --certificate-path $CertificatePath --certificate-password $PfxPassword --hash-algorithm SHA256 --overwrite -v minimal 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet nuget sign failed for $PackagePath`n$($output -join "`n")"
    }
}

function Invoke-VsixSign {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$CertificatePath
    )
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath, $PfxPassword)
    $package = [System.IO.Packaging.Package]::Open($PackagePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
    try {
        $signatureManager = [System.IO.Packaging.PackageDigitalSignatureManager]::new($package)
        $signatureManager.CertificateOption = [System.IO.Packaging.CertificateEmbeddingOption]::InSignaturePart
        $partsToSign = [System.Collections.Generic.List[Uri]]::new()
        foreach ($packagePart in $package.GetParts()) {
            $partsToSign.Add($packagePart.Uri)
        }
        $partsToSign.Add([System.IO.Packaging.PackUriHelper]::GetRelationshipPartUri($signatureManager.SignatureOrigin))
        $partsToSign.Add($signatureManager.SignatureOrigin)
        $partsToSign.Add([System.IO.Packaging.PackUriHelper]::GetRelationshipPartUri([Uri]::new("/", [System.UriKind]::RelativeOrAbsolute)))
        $null = $signatureManager.Sign($partsToSign, $cert)
    }
    finally {
        $package.Close()
    }
}

New-CleanDirectory -Path $OutputDir
$unsignedDir = Join-Path $OutputDir "unsigned"
$signedDir = Join-Path $OutputDir "signed"
New-Item -ItemType Directory -Force -Path $unsignedDir, $signedDir | Out-Null

$unsignedNupkg = Join-Path $unsignedDir "sample.nupkg"
$unsignedSnupkg = Join-Path $unsignedDir "sample.snupkg"
$unsignedVsix = Join-Path $unsignedDir "sample.vsix"
$signedNupkg = Join-Path $signedDir "sample.signed.nupkg"
$signedSnupkg = Join-Path $signedDir "sample.signed.snupkg"
$signedVsix = Join-Path $signedDir "sample.signed.vsix"

New-UnsignedNuGetPackage -Path $unsignedNupkg
New-UnsignedNuGetPackage -Path $unsignedSnupkg
New-UnsignedVsixPackage -Path $unsignedVsix
Copy-Item -LiteralPath $unsignedNupkg -Destination $signedNupkg -Force
Copy-Item -LiteralPath $unsignedSnupkg -Destination $signedSnupkg -Force
Copy-Item -LiteralPath $unsignedVsix -Destination $signedVsix -Force
Invoke-DotnetNuGetSign -PackagePath $signedNupkg -CertificatePath $PfxPath
Invoke-DotnetNuGetSign -PackagePath $signedSnupkg -CertificatePath $PfxPath
Invoke-VsixSign -PackagePath $signedVsix -CertificatePath $PfxPath

$entries = [System.Collections.Generic.List[object]]::new()
Add-ManifestEntry -List $entries -Id "package-nupkg-unsigned" -Family "nuget" -State "unsigned" -Path $unsignedNupkg
Add-ManifestEntry -List $entries -Id "package-nupkg-signed" -Family "nuget" -State "signed" -Path $signedNupkg -SourcePath $unsignedNupkg -Tool "dotnet nuget sign"
Add-ManifestEntry -List $entries -Id "package-snupkg-unsigned" -Family "nuget-symbols" -State "unsigned" -Path $unsignedSnupkg
Add-ManifestEntry -List $entries -Id "package-snupkg-signed" -Family "nuget-symbols" -State "signed" -Path $signedSnupkg -SourcePath $unsignedSnupkg -Tool "dotnet nuget sign"
Add-ManifestEntry -List $entries -Id "package-vsix-unsigned" -Family "vsix" -State "unsigned" -Path $unsignedVsix
Add-ManifestEntry -List $entries -Id "package-vsix-signed" -Family "vsix" -State "signed" -Path $signedVsix -SourcePath $unsignedVsix -Tool "System.IO.Packaging.PackageDigitalSignatureManager"

$manifest = [ordered]@{
    generated_by = "scripts/ci/build-package-signing-fixtures.ps1"
    pfx = Convert-ToManifestPath -Path $PfxPath
    pfx_thumbprint = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $PfxPassword)).Thumbprint
    entries = $entries
}
$manifestPath = Join-Path $OutputDir "package-signing-fixtures.json"
$manifestJson = ($manifest | ConvertTo-Json -Depth 10) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($manifestPath, $manifestJson + "`n", [System.Text.UTF8Encoding]::new($false))

Write-Host "Package signing fixtures: $OutputDir"
