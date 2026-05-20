param(
    [string]$UnsignedMsix = $env:PSIGN_MSIX_UNSIGNED_FIXTURE,
    [string]$PfxPath = $env:PSIGN_MSIX_TEST_PFX,
    [string]$PfxPassword = $env:PSIGN_MSIX_TEST_PFX_PASSWORD,
    [string]$CertSha1 = $env:PSIGN_MSIX_TEST_CERT_SHA1,
    [string]$TimestampUrl = $env:PSIGN_MSIX_TIMESTAMP_URL,
    [string]$DlibPath = $env:PSIGN_MSIX_DLIB,
    [string]$DmdfPath = $env:PSIGN_MSIX_DMDF,
    [string]$Digest = "SHA256",
    [string]$TimestampDigest = "SHA256",
    [string]$ReportPath,
    [switch]$UseDecoupledDigest,
    [switch]$FailOnSemantic
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$workspace = Split-Path -Parent $PSScriptRoot
if (-not $ReportPath) {
    $ReportPath = Join-Path $workspace "parity-output\msix-parity-sign-report.json"
}

function Resolve-SignTool {
    $src = $null
    if ($env:SIGNTOOL_EXE -and (Test-Path -LiteralPath $env:SIGNTOOL_EXE)) {
        $src = $env:SIGNTOOL_EXE
    }
    if (-not $src) {
        $candidates = @(Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Sort-Object FullName)
        if ($candidates.Count -eq 0) {
            throw "Unable to locate native signtool.exe. Set SIGNTOOL_EXE."
        }
        foreach ($sub in @('\x64\', '\amd64\', '\arm64\', '\x86\', '\arm\')) {
            $hit = $candidates | Where-Object { $_.FullName -match [regex]::Escape($sub) } | Select-Object -Last 1
            if ($hit) {
                $src = $hit.FullName
                break
            }
        }
        if (-not $src) {
            $src = ($candidates | Select-Object -Last 1 -ExpandProperty FullName)
        }
    }
    $dest = Join-Path $env:TEMP "psign_parity_native_msix.exe"
    Copy-Item -LiteralPath $src -Destination $dest -Force
    return $dest
}

function Resolve-RustBin {
    $rustBin = Join-Path $workspace "target\debug\psign-tool.exe"
    if (-not (Test-Path -LiteralPath $rustBin)) {
        cargo build -p psign --bin psign-tool | Out-Null
    }
    if (-not (Test-Path -LiteralPath $rustBin)) {
        throw "Unable to locate psign-tool.exe after build."
    }
    return $rustBin
}

function Test-RequiredValue {
    param([string]$Name, [string]$Value)
    if (-not $Value) {
        throw "Missing required value: $Name"
    }
}

function Invoke-ExternalCommand {
    param(
        [string]$Exe,
        [string[]]$CmdArgs
    )
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $stdoutErr = & "$Exe" @CmdArgs 2>&1
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $saved
    [PSCustomObject]@{
        exitCode = $exitCode
        output = ($stdoutErr -join "`n")
    }
}

Test-RequiredValue -Name "UnsignedMsix" -Value $UnsignedMsix
Test-RequiredValue -Name "TimestampUrl" -Value $TimestampUrl

if (-not (Test-Path -LiteralPath $UnsignedMsix)) {
    throw "Unsigned MSIX not found: $UnsignedMsix"
}
if (-not $PfxPath -and -not $CertSha1) {
    throw "Provide either -PfxPath (or PSIGN_MSIX_TEST_PFX) or -CertSha1 (or PSIGN_MSIX_TEST_CERT_SHA1)."
}
if ($PfxPath -and -not (Test-Path -LiteralPath $PfxPath)) {
    throw "PFX not found: $PfxPath"
}

$decoupled = $UseDecoupledDigest.IsPresent -or ($DlibPath -and $DmdfPath)
if ($decoupled) {
    Test-RequiredValue -Name "DlibPath" -Value $DlibPath
    Test-RequiredValue -Name "DmdfPath" -Value $DmdfPath
    if (-not (Test-Path -LiteralPath $DlibPath)) {
        throw "dlib path not found: $DlibPath"
    }
    if (-not (Test-Path -LiteralPath $DmdfPath)) {
        throw "dmdf path not found: $DmdfPath"
    }
}

$nativeSignTool = Resolve-SignTool
$rustBin = Resolve-RustBin

$nativeMsix = Join-Path $env:TEMP "psign_msix_native_test.msix"
$rustMsix = Join-Path $env:TEMP "psign_msix_rust_test.msix"
Copy-Item -LiteralPath $UnsignedMsix -Destination $nativeMsix -Force
Copy-Item -LiteralPath $UnsignedMsix -Destination $rustMsix -Force

$nativeSignArgs = @("sign", "/fd", $Digest)
if ($PfxPath) {
    $nativeSignArgs += @("/f", $PfxPath)
    if ($PfxPassword) {
        $nativeSignArgs += @("/p", $PfxPassword)
    }
} else {
    $nativeSignArgs += @("/s", "MY", "/sha1", $CertSha1)
}
$nativeSignArgs += @("/tr", $TimestampUrl, "/td", $TimestampDigest)
if ($decoupled) {
    $nativeSignArgs += @("/dlib", $DlibPath, "/dmdf", $DmdfPath, "/ph")
}
$nativeSignArgs += @($nativeMsix)

$rustThumbFromEnv = $null
if ($env:PSIGN_MSIX_TEST_CERT_SHA1 -and $env:PSIGN_MSIX_TEST_CERT_SHA1.Trim()) {
    $rustThumbFromEnv = $env:PSIGN_MSIX_TEST_CERT_SHA1.Trim()
}
elseif ($env:PSIGN_TEST_CERT_SHA1 -and $env:PSIGN_TEST_CERT_SHA1.Trim()) {
    $rustThumbFromEnv = $env:PSIGN_TEST_CERT_SHA1.Trim()
}

$rustSignArgs = @("sign", "--digest", $Digest.ToLowerInvariant(), "--timestamp-url", $TimestampUrl, "--timestamp-digest", $TimestampDigest.ToLowerInvariant())
# Prefer store thumb (post-bootstrap) over `--pfx` for Rust — same rationale as `Get-RustMsixCredentialArgs`.
if ($rustThumbFromEnv) {
    $rustSignArgs += @("--cert-sha1", $rustThumbFromEnv)
}
elseif ($PfxPath) {
    $rustSignArgs += @("--pfx", $PfxPath)
    if ($PfxPassword) {
        $rustSignArgs += @("--password", $PfxPassword)
    }
}
else {
    $rustSignArgs += @("--store-name", "MY", "--cert-sha1", $CertSha1)
}
if ($decoupled) {
    $rustSignArgs += @("--dlib", $DlibPath, "--dmdf", $DmdfPath, "--page-hashes")
}
$rustSignArgs += @($rustMsix)

$nativeSignRun = Invoke-ExternalCommand -Exe $nativeSignTool -CmdArgs $nativeSignArgs
$rustSignRun = Invoke-ExternalCommand -Exe $rustBin -CmdArgs $rustSignArgs

$nativeVerifyRun = Invoke-ExternalCommand -Exe $nativeSignTool -CmdArgs @("verify", "/pa", "/v", $nativeMsix)
$rustVerifyRun = Invoke-ExternalCommand -Exe $nativeSignTool -CmdArgs @("verify", "/pa", "/v", $rustMsix)

$classification = if ($nativeSignRun.exitCode -ne $rustSignRun.exitCode) {
    if ($nativeSignRun.exitCode -eq 0 -and $rustSignRun.exitCode -ne 0) {
        "documented_rust_msix_sign_ex3_gap"
    }
    else {
        "semantic_mismatch"
    }
} elseif ($nativeVerifyRun.exitCode -ne $rustVerifyRun.exitCode) {
    "semantic_mismatch"
} elseif ($nativeSignRun.exitCode -ne 0 -and $rustSignRun.exitCode -ne 0) {
    "shared_failure"
} elseif ($nativeVerifyRun.exitCode -ne 0 -and $rustVerifyRun.exitCode -ne 0) {
    "shared_failure"
} elseif ($nativeVerifyRun.output -ne $rustVerifyRun.output) {
    "format_only_diff"
} else {
    "artifact_semantic_match"
}

$nativeHash = (Get-FileHash -LiteralPath $nativeMsix -Algorithm SHA256).Hash
$rustHash = (Get-FileHash -LiteralPath $rustMsix -Algorithm SHA256).Hash

$report = [PSCustomObject]@{
    generatedAt = (Get-Date).ToString("o")
    nativeSignTool = $nativeSignTool
    rustBinary = $rustBin
    unsignedMsix = $UnsignedMsix
    nativeMsix = $nativeMsix
    rustMsix = $rustMsix
    nativeMsixSha256 = $nativeHash
    rustMsixSha256 = $rustHash
    decoupledDigest = [bool]$decoupled
    classification = $classification
    native = [PSCustomObject]@{
        signExitCode = $nativeSignRun.exitCode
        verifyExitCode = $nativeVerifyRun.exitCode
        signOutput = $nativeSignRun.output
        verifyOutput = $nativeVerifyRun.output
    }
    rust = [PSCustomObject]@{
        signExitCode = $rustSignRun.exitCode
        verifyExitCode = $rustVerifyRun.exitCode
        signOutput = $rustSignRun.output
        verifyOutput = $rustVerifyRun.output
    }
}

$reportDir = Split-Path -Parent $ReportPath
if (-not (Test-Path -LiteralPath $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir | Out-Null
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
Write-Host "Wrote MSIX parity report to $ReportPath"

if ($FailOnSemantic -and $classification -eq "semantic_mismatch") {
    throw "MSIX semantic mismatch detected."
}

exit 0
