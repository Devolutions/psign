# SIP-backed format smoke checklist: native signtool.exe vs psign on the same machine.
# Uses optional PSIGN_* fixtures when set (same variables as scripts/run-parity-diff.ps1).
#
# Format inventory (sign/timestamp/embedded-verify delegate to OS CryptSIP DLLs via SignerSignEx3 / WinVerifyTrust):
#   PE        .exe .dll .sys .ocx .scr .cpl .efi .mui  — Image* APIs apply for remove /s
#   WinMD     .winmd — PE-based metadata assembly; signing via OS SIP; remove /s uses Image* when loadable as PE image
#   PS        .ps1 .psm1 .psd1 — script SIP; remove not supported (not Image*)
#   MSIX      .msix .appx (+bundles) — package SIP; RFC3161 typically required at sign; remove /s not supported here
#   MSI       .msi .msp .mst — Installer SIP; remove /s not supported here
#   WSH       .js .vbs .wsf — when SIP registered; remove /s not supported here
#   CAB/CAT   — catalog SIP paths differ; remove /s not supported here
#   VSIX/other — only if Windows registers a SIP for the extension; otherwise native signtool also fails as a flat file
#
# Usage:
#   ./scripts/sip-format-smoke.ps1
#   ./scripts/sip-format-smoke.ps1 -WorkspaceRoot D:\\dev\\psign
param(
    [string]$WorkspaceRoot = ""
)

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
Set-Location -LiteralPath $WorkspaceRoot

function Resolve-NativeSignTool {
    if ($env:SIGNTOOL_EXE -and (Test-Path -LiteralPath $env:SIGNTOOL_EXE)) {
        return $env:SIGNTOOL_EXE
    }
    $candidates = @(Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Sort-Object FullName)
    if ($candidates.Count -eq 0) {
        throw "signtool.exe not found; set SIGNTOOL_EXE or install Windows SDK."
    }
    foreach ($sub in @('\x64\', '\amd64\', '\arm64\', '\x86\')) {
        $hit = $candidates | Where-Object { $_.FullName -match [regex]::Escape($sub) } | Select-Object -Last 1
        if ($hit) { return $hit.FullName }
    }
    return ($candidates | Select-Object -Last 1 -ExpandProperty FullName)
}

function Test-RsEnvPresent([string]$Name) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    return ($null -ne $v -and $v.Trim().Length -gt 0)
}

$native = Resolve-NativeSignTool
$rustBin = Join-Path $WorkspaceRoot "target\debug\psign-tool.exe"
if (-not (Test-Path -LiteralPath $rustBin)) {
    Write-Host "Building psign-tool (debug)..."
    & cargo build -p psign --bin psign-tool | Out-Null
}

Write-Host "Native: $native"
Write-Host "Rust:   $rustBin"
Write-Host ""

function Invoke-Pair {
    param([string]$Label, [string[]]$NativeArgs, [string[]]$RustArgs)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $null = & $native @NativeArgs 2>&1
    $n = $LASTEXITCODE
    $null = & $rustBin @RustArgs 2>&1
    $r = $LASTEXITCODE
    $ErrorActionPreference = $saved
    $match = if ($n -eq $r) { "match" } else { "MISMATCH" }
    Write-Host ("[{0}] native exit={1} rust exit={2} {3}" -f $Label, $n, $r, $match)
}

# Baseline: TEMP copy of native exe as parity target (always available).
$tmpPe = Join-Path $env:TEMP "psign_sip_smoke_pe.exe"
Copy-Item -LiteralPath $native -Destination $tmpPe -Force
Invoke-Pair "verify_pa_pe" @("verify", "/pa", $tmpPe) @("verify", "--policy", "pa", $tmpPe)
Remove-Item -LiteralPath $tmpPe -Force -ErrorAction SilentlyContinue

if ((Test-RsEnvPresent "PSIGN_UNSIGNED_FIXTURE") -and (Test-RsEnvPresent "PSIGN_TEST_PFX")) {
    $u = $env:PSIGN_UNSIGNED_FIXTURE
    $pfx = $env:PSIGN_TEST_PFX
    $tmpSign = Join-Path $env:TEMP "psign_sip_smoke_unsigned.exe"
    Copy-Item -LiteralPath $u -Destination $tmpSign -Force
    $nativeSign = @("sign", "/fd", "SHA256", "/f", $pfx, $tmpSign)
    $rustSign = @("sign", "--pfx", $pfx, "--digest", "sha256", $tmpSign)
    if (Test-RsEnvPresent "PSIGN_TEST_PFX_PASSWORD") {
        $nativeSign = @("sign", "/fd", "SHA256", "/f", $pfx, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpSign)
        $rustSign = @("sign", "--pfx", $pfx, "--password", $env:PSIGN_TEST_PFX_PASSWORD, "--digest", "sha256", $tmpSign)
    }
    Invoke-Pair "sign_then_verify_pe" $nativeSign $rustSign
    $rustSignRustSip = $rustSign + @("--rust-sip", "pe")
    Invoke-Pair "sign_then_verify_pe_rust_sip_digest_gate" $nativeSign $rustSignRustSip
    Invoke-Pair "verify_signed_pe" @("verify", "/pa", $tmpSign) @("verify", "--policy", "pa", $tmpSign)
    Remove-Item -LiteralPath $tmpSign -Force -ErrorAction SilentlyContinue
    Write-Host "(PE fixture smoke used PSIGN_UNSIGNED_FIXTURE)"
} else {
    Write-Host "[skip] PE sign smoke: set PSIGN_UNSIGNED_FIXTURE and PSIGN_TEST_PFX"
}

if ((Test-RsEnvPresent "PSIGN_WINMD_UNSIGNED_FIXTURE") -and (Test-RsEnvPresent "PSIGN_TEST_PFX")) {
    $w = $env:PSIGN_WINMD_UNSIGNED_FIXTURE
    if (Test-Path -LiteralPath $w) {
        $pfx = $env:PSIGN_TEST_PFX
        $tmpW = Join-Path $env:TEMP "psign_sip_smoke.winmd"
        Copy-Item -LiteralPath $w -Destination $tmpW -Force
        $nativeSign = @("sign", "/fd", "SHA256", "/f", $pfx, $tmpW)
        $rustSign = @("sign", "--pfx", $pfx, "--digest", "sha256", $tmpW)
        if (Test-RsEnvPresent "PSIGN_TEST_PFX_PASSWORD") {
            $nativeSign = @("sign", "/fd", "SHA256", "/f", $pfx, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpW)
            $rustSign = @("sign", "--pfx", $pfx, "--password", $env:PSIGN_TEST_PFX_PASSWORD, "--digest", "sha256", $tmpW)
        }
        if (Test-RsEnvPresent "PSIGN_WINMD_TIMESTAMP_URL") {
            $nativeSign += @("/tr", $env:PSIGN_WINMD_TIMESTAMP_URL, "/td", "SHA256")
            $rustSign += @("--timestamp-url", $env:PSIGN_WINMD_TIMESTAMP_URL, "--timestamp-digest", "sha256")
        }
        Invoke-Pair "sign_then_verify_winmd" $nativeSign $rustSign
        $rustWinmdRustSip = $rustSign + @("--rust-sip", "pe")
        Invoke-Pair "sign_then_verify_winmd_rust_sip_digest_gate" $nativeSign $rustWinmdRustSip
        Invoke-Pair "verify_signed_winmd" @("verify", "/pa", $tmpW) @("verify", "--policy", "pa", $tmpW)
        Remove-Item -LiteralPath $tmpW -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "[skip] WinMD smoke: set PSIGN_WINMD_UNSIGNED_FIXTURE (+ PSIGN_TEST_PFX)"
}

Write-Host ""
Write-Host "Done. Exit-code parity only; see scripts/run-parity-diff.ps1 for full semantic classifications."
