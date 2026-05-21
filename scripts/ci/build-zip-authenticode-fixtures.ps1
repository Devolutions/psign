# Build small unsigned and custom ZIP Authenticode signed fixtures.
param(
    [string]$WorkspaceRoot = "",
    [string]$OutputDir = "",
    [string]$PsignToolPath = "",
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

if (-not $OutputDir) { $OutputDir = Join-Path $WorkspaceRoot "tests\fixtures\zip-authenticode" }
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir = Join-Path $WorkspaceRoot $OutputDir }

if (-not $PfxPath) {
    $PfxPath = Join-Path $WorkspaceRoot "tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx"
}
elseif (-not [System.IO.Path]::IsPathRooted($PfxPath)) {
    $PfxPath = Join-Path $WorkspaceRoot $PfxPath
}
if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Convert-ToManifestPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    return [System.IO.Path]::GetRelativePath($WorkspaceRoot, $full)
}

function Write-ZipEntry {
    param(
        [Parameter(Mandatory)]$Archive,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Text
    )
    $entry = $Archive.CreateEntry($Name, [System.IO.Compression.CompressionLevel]::NoCompression)
    $entry.LastWriteTime = [System.DateTimeOffset]::new(2024, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
    $stream = $entry.Open()
    try {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($Text) }
        finally { $writer.Dispose() }
    }
    finally {
        $stream.Dispose()
    }
}

function New-UnsignedZipFixture {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite)
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            Write-ZipEntry -Archive $zip -Name "README.txt" -Text "psign ZIP Authenticode fixture`n"
            Write-ZipEntry -Archive $zip -Name "payload/config.json" -Text "{`"name`":`"zip-authenticode-fixture`",`"version`":1}`n"
        }
        finally {
            $zip.Dispose()
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Invoke-PsignZipSign {
    param([Parameter(Mandatory)][string]$Path)
    if ($PsignToolPath) {
        $output = & $PsignToolPath sign --pfx $PfxPath --password $PfxPassword --digest sha256 $Path 2>&1
    }
    else {
        Push-Location $WorkspaceRoot
        try {
            $output = & cargo run --quiet --bin psign-tool -- sign --pfx $PfxPath --password $PfxPassword --digest sha256 $Path 2>&1
        }
        finally {
            Pop-Location
        }
    }
    if ($LASTEXITCODE -ne 0) {
        throw "psign ZIP signing failed for $Path`n$($output -join "`n")"
    }
}

function Add-ManifestEntry {
    param(
        [Parameter(Mandatory)]$List,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$Path,
        [string]$SourcePath = "",
        [string]$Tool = ""
    )
    $item = Get-Item -LiteralPath $Path
    $entry = [ordered]@{
        id = $Id
        family = "zip"
        state = $State
        path = Convert-ToManifestPath -Path $item.FullName
        size_bytes = $item.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
    }
    if ($SourcePath) { $entry.source_path = Convert-ToManifestPath -Path $SourcePath }
    if ($Tool) { $entry.tool = $Tool }
    $List.Add($entry)
}

if ((Test-Path -LiteralPath $OutputDir) -and -not $Force) {
    throw "Output directory already exists: $OutputDir. Pass -Force to replace it."
}
if (Test-Path -LiteralPath $OutputDir) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}

$unsignedDir = Join-Path $OutputDir "unsigned"
$signedDir = Join-Path $OutputDir "signed"
New-Item -ItemType Directory -Force -Path $unsignedDir, $signedDir | Out-Null

$unsignedZip = Join-Path $unsignedDir "sample.zip"
$signedZip = Join-Path $signedDir "sample.signed.zip"

New-UnsignedZipFixture -Path $unsignedZip
Copy-Item -LiteralPath $unsignedZip -Destination $signedZip -Force
Invoke-PsignZipSign -Path $signedZip

$entries = [System.Collections.Generic.List[object]]::new()
Add-ManifestEntry -List $entries -Id "zip-authenticode-unsigned" -State "unsigned" -Path $unsignedZip
Add-ManifestEntry -List $entries -Id "zip-authenticode-signed" -State "signed" -Path $signedZip -SourcePath $unsignedZip -Tool "psign ZIP Authenticode"

$manifest = [ordered]@{
    generated_by = "scripts/ci/build-zip-authenticode-fixtures.ps1"
    pfx = Convert-ToManifestPath -Path $PfxPath
    pfx_thumbprint = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $PfxPassword)).Thumbprint
    entries = $entries
}
$manifestPath = Join-Path $OutputDir "zip-authenticode-fixtures.json"
$manifestJson = ($manifest | ConvertTo-Json -Depth 10) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($manifestPath, $manifestJson + "`n", [System.Text.UTF8Encoding]::new($false))

Write-Host "ZIP Authenticode fixtures: $OutputDir"
