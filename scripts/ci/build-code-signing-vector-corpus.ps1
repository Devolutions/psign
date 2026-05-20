# Build a persistent unsigned + signed test-vector corpus.
#
# This script writes files under tests/fixtures/generated-unsigned and
# tests/fixtures/generated-signed, plus per-tree manifests. It uses the vendored
# Devolutions public test PFX by default.
param(
    [string]$WorkspaceRoot = "",
    [string]$UnsignedDir = "",
    [string]$SignedDir = "",
    [string]$SignToolPath = "",
    [string]$PfxPath = "",
    [string]$PfxPassword = "CodeSign123!",
    [string]$TimestampUrl = "",
    [switch]$IncludeSdkPackages,
    [switch]$SignProbeRows,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$WorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path

if (-not $UnsignedDir) { $UnsignedDir = Join-Path $WorkspaceRoot "tests\fixtures\generated-unsigned" }
elseif (-not [System.IO.Path]::IsPathRooted($UnsignedDir)) { $UnsignedDir = Join-Path $WorkspaceRoot $UnsignedDir }

if (-not $SignedDir) { $SignedDir = Join-Path $WorkspaceRoot "tests\fixtures\generated-signed" }
elseif (-not [System.IO.Path]::IsPathRooted($SignedDir)) { $SignedDir = Join-Path $WorkspaceRoot $SignedDir }

function Resolve-File {
    param([string[]]$Candidates, [string]$Name)
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Convert-ToManifestPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path.StartsWith(".\", [System.StringComparison]::Ordinal)) {
        return $Path.Substring(2)
    }
    return $Path
}

if (-not $SignToolPath) {
    $SignToolPath = Resolve-File -Name "signtool.exe" -Candidates @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\App Certification Kit\signtool.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft SDKs\ClickOnce\SignTool\signtool.exe")
    )
}
if (-not $SignToolPath) { throw "signtool.exe not found." }

if (-not $PfxPath) {
    $PfxPath = Join-Path $WorkspaceRoot "tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx"
}
elseif (-not [System.IO.Path]::IsPathRooted($PfxPath)) {
    $PfxPath = Join-Path $WorkspaceRoot $PfxPath
}
if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }

$buildUnsigned = Join-Path $PSScriptRoot "build-code-signing-vector-samples.ps1"
$unsignedArgs = @{
    WorkspaceRoot = $WorkspaceRoot
    OutputDir = $UnsignedDir
    Force = $Force
}
if ($IncludeSdkPackages) { $unsignedArgs.IncludeSdkPackages = $true }
& $buildUnsigned @unsignedArgs

if ((Test-Path -LiteralPath $SignedDir) -and -not $Force) {
    throw "Signed output directory already exists: $SignedDir. Pass -Force to replace it."
}
if (Test-Path -LiteralPath $SignedDir) {
    Remove-Item -LiteralPath $SignedDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $SignedDir | Out-Null

$unsignedManifest = Join-Path $UnsignedDir "generated-vectors.json"
$unsigned = Get-Content -LiteralPath $unsignedManifest -Raw | ConvertFrom-Json
$signedEntries = New-Object System.Collections.Generic.List[object]
$skippedEntries = New-Object System.Collections.Generic.List[object]
$failedEntries = New-Object System.Collections.Generic.List[object]

function Add-ReportEntry {
    param(
        [Parameter(Mandatory)]$List,
        [Parameter(Mandatory)]$Vector,
        [string]$Status,
        [string]$Path = "",
        [string]$Message = ""
    )
    $entry = [ordered]@{
        id = $Vector.id
        family = $Vector.family
        extension = $Vector.extension
        state = $Status
        source_path = $Vector.path
    }
    if ($Path) {
        $file = Get-Item -LiteralPath $Path
        $entry.path = Convert-ToManifestPath -Path (Resolve-Path -LiteralPath $file.FullName -Relative)
        $entry.size_bytes = $file.Length
        $entry.sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    }
    if ($Message) { $entry.message = $Message }
    $List.Add($entry)
}

function New-ArtifactVector {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [Parameter(Mandatory)][string]$Extension,
        [Parameter(Mandatory)][string]$SourcePath
    )
    [pscustomobject]@{
        id = $Id
        family = $Family
        extension = $Extension
        path = $SourcePath
    }
}

function Should-SignEmbedded {
    param($Vector)
    if ($Vector.state -match "negative|placeholder|content|ci-generated-signature|probe" -and $Vector.family -ne "optional-provider" -and -not $SignProbeRows) {
        return $false
    }
    switch ($Vector.family) {
        "pe" { return $Vector.state -ne "negative" }
        "winmd" { return $true }
        "cab" { return $true }
        "powershell-script" { return $true }
        "wsh-script" {
            return @(".js", ".jse", ".vbs", ".vbe", ".wsf") -contains [string]$Vector.extension
        }
        "msix" {
            return @(".msix", ".appx", ".msixbundle", ".appxbundle") -contains [string]$Vector.extension
        }
        "installer" {
            return @(".msi", ".msp", ".mst") -contains [string]$Vector.extension
        }
        "appinstaller" { return $true }
        "p7x" { return $true }
        "optional-provider" { return $true }
        "catalog" {
            return [string]$Vector.extension -eq ".cat" -and $Vector.state -eq "unsigned"
        }
        "wim-esd" {
            return @(".wim", ".esd") -contains [string]$Vector.extension -and $Vector.state -eq "unsigned"
        }
        default { return $false }
    }
}

function Is-ExpectedNativeSignReject {
    param($Vector, [string]$Output)
    if (($Vector.family -eq "powershell-script") -and ($Vector.encoding -eq "utf16be-bom")) {
        return $Output -match "SignerSign\(\) failed" -and $Output -match "0x8007000d"
    }
    if ($Vector.expected_native -match "reject|probe") {
        return $Output -match "SignTool Error|SignerSign\(\) failed|This file format cannot be signed|No certificates were found|0x8007000b|0x8007000d|0x80092006|0x80070057"
    }
    return $false
}

function Invoke-SignTool {
    param([string[]]$Arguments)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $SignToolPath @Arguments 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $saved
    [pscustomobject]@{
        ExitCode = $code
        Output = ($output -join "`n")
    }
}

$appInstallerVectors = @()
foreach ($vector in $unsigned.vectors) {
    $src = Join-Path $WorkspaceRoot $vector.path
    if (-not (Test-Path -LiteralPath $src)) {
        Add-ReportEntry -List $failedEntries -Vector $vector -Status "missing-source" -Message "Source file not found."
        continue
    }

    if (Should-SignEmbedded -Vector $vector) {
        if ($vector.family -eq "appinstaller") {
            $appInstallerVectors += $vector
        }
        $rel = [string]$vector.path
        $prefix = (Convert-ToManifestPath -Path (Resolve-Path -LiteralPath $UnsignedDir -Relative)).TrimEnd('\')
        if ($rel.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel = $rel.Substring($prefix.Length).TrimStart('\')
        }
        $dest = Join-Path $SignedDir $rel
        New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dest -Force

        $args = @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword)
        if (($vector.family -eq "msix") -and $TimestampUrl) {
            $args += @("/tr", $TimestampUrl, "/td", "SHA256")
        }
        $args += @($dest)
        $result = Invoke-SignTool -Arguments $args
        if ($result.ExitCode -eq 0) {
            if ($vector.state -eq "native-pa-verify-rejected") {
                $verify = Invoke-SignTool -Arguments @("verify", "/pa", $dest)
                if ($verify.ExitCode -eq 0) {
                    Add-ReportEntry -List $signedEntries -Vector $vector -Status "signed" -Path $dest
                }
                else {
                    Add-ReportEntry -List $skippedEntries -Vector $vector -Status "signed-native-pa-verify-rejected" -Path $dest -Message $verify.Output
                }
            }
            else {
                Add-ReportEntry -List $signedEntries -Vector $vector -Status "signed" -Path $dest
            }
        }
        elseif (Is-ExpectedNativeSignReject -Vector $vector -Output $result.Output) {
            Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
            Add-ReportEntry -List $skippedEntries -Vector $vector -Status "native-sign-rejected" -Message $result.Output
        }
        else {
            Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
            Add-ReportEntry -List $failedEntries -Vector $vector -Status "sign-failed" -Message $result.Output
        }
    }
    elseif ($vector.family -eq "detached-pkcs7" -and $vector.state -eq "content") {
        continue
    }
    elseif ($vector.state -eq "native-pa-verify-rejected") {
        Add-ReportEntry -List $skippedEntries -Vector $vector -Status "native-pa-verify-rejected"
    }
    elseif ($vector.state -eq "native-sign-rejected") {
        Add-ReportEntry -List $skippedEntries -Vector $vector -Status "native-sign-rejected"
    }
    else {
        Add-ReportEntry -List $skippedEntries -Vector $vector -Status "skipped"
    }
}

$signedMsix = $signedEntries | Where-Object { $_.id -eq "generated-msix-msix" -and $_.state -eq "signed" } | Select-Object -First 1
if ($signedMsix) {
    $packagePath = Join-Path $WorkspaceRoot ([string]$signedMsix.path)
    $p7xPath = Join-Path $SignedDir "p7x\appxsignature-from-sample-msix.p7x"
    New-Item -ItemType Directory -Force -Path (Split-Path $p7xPath -Parent) | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        $signatureEntry = $zip.Entries | Where-Object { $_.FullName -eq "AppxSignature.p7x" } | Select-Object -First 1
        if ($signatureEntry) {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($signatureEntry, $p7xPath, $true)
            $artifact = New-ArtifactVector -Id "generated-p7x-appxsignature-from-msix" -Family "p7x" -Extension ".p7x" -SourcePath ([string]$signedMsix.path)
            Add-ReportEntry -List $signedEntries -Vector $artifact -Status "package-signature-extracted" -Path $p7xPath
        }
        else {
            $artifact = New-ArtifactVector -Id "generated-p7x-appxsignature-from-msix" -Family "p7x" -Extension ".p7x" -SourcePath ([string]$signedMsix.path)
            Add-ReportEntry -List $failedEntries -Vector $artifact -Status "package-signature-missing" -Message "AppxSignature.p7x not found in $($signedMsix.path)."
        }
    }
    finally {
        $zip.Dispose()
    }
}

foreach ($appInstaller in $appInstallerVectors) {
    $src = Join-Path $WorkspaceRoot $appInstaller.path
    $outDir = Join-Path $SignedDir "appinstaller"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $args = @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, "/p7", $outDir, "/p7ce", "DetachedSignedData", "/p7co", "1.2.840.113549.1.7.2", $src)
    $result = Invoke-SignTool -Arguments $args
    $p7 = Get-ChildItem -LiteralPath $outDir -File -Filter "*.p7" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq ((Split-Path ([string]$appInstaller.path) -Leaf) + ".p7") } | Select-Object -First 1
    if ($result.ExitCode -eq 0 -and $p7) {
        $artifact = New-ArtifactVector -Id ($appInstaller.id + "-detached-pkcs7") -Family "appinstaller" -Extension ".p7" -SourcePath ([string]$appInstaller.path)
        Add-ReportEntry -List $signedEntries -Vector $artifact -Status "detached-signed" -Path $p7.FullName
    }
    else {
        $artifact = New-ArtifactVector -Id ($appInstaller.id + "-detached-pkcs7") -Family "appinstaller" -Extension ".p7" -SourcePath ([string]$appInstaller.path)
        Add-ReportEntry -List $failedEntries -Vector $artifact -Status "detached-sign-failed" -Message $result.Output
    }
}

$detachedDir = Join-Path $SignedDir "detached"
New-Item -ItemType Directory -Force -Path $detachedDir | Out-Null
foreach ($content in $unsigned.vectors | Where-Object { $_.family -eq "detached-pkcs7" -and $_.state -eq "content" }) {
    $src = Join-Path $WorkspaceRoot $content.path
    $outDir = Join-Path $detachedDir ([System.IO.Path]::GetFileNameWithoutExtension([string]$content.path))
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $args = @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, "/p7", $outDir, "/p7ce", "DetachedSignedData", "/p7co", "1.2.840.113549.1.7.2", $src)
    $result = Invoke-SignTool -Arguments $args
    $p7 = Get-ChildItem -LiteralPath $outDir -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($result.ExitCode -eq 0 -and $p7) {
        Add-ReportEntry -List $signedEntries -Vector $content -Status "detached-signed" -Path $p7.FullName
    }
    else {
        Add-ReportEntry -List $failedEntries -Vector $content -Status "detached-sign-failed" -Message $result.Output
    }
}

$signedManifest = Join-Path $SignedDir "generated-signed-vectors.json"
$signedJson = [ordered]@{
    generated_by = "scripts/ci/build-code-signing-vector-corpus.ps1"
    signing_tool = "signtool.exe"
    pfx = (Resolve-Path -LiteralPath $PfxPath -Relative)
    timestamp_url = $TimestampUrl
    signed = $signedEntries
    skipped = $skippedEntries
    failed = $failedEntries
} | ConvertTo-Json -Depth 10
$signedJson = $signedJson -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($signedManifest, $signedJson + "`n", [System.Text.UTF8Encoding]::new($false))

Write-Host "Unsigned vectors: $($unsigned.vectors.Count)"
Write-Host "Signed vectors:   $($signedEntries.Count)"
Write-Host "Skipped vectors:  $($skippedEntries.Count)"
Write-Host "Failed vectors:   $($failedEntries.Count)"
Write-Host "Signed manifest:  $signedManifest"
