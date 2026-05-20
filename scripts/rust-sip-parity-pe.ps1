# Rust SIP PE parity (experimental): native signtool vs psign with `--rust-sip pe`, then mutual verify.
# Requires: PSIGN_UNSIGNED_FIXTURE, PSIGN_TEST_PFX (optional PSIGN_TEST_PFX_PASSWORD).
#
# Usage:
#   ./scripts/rust-sip-parity-pe.ps1
#   ./scripts/rust-sip-parity-pe.ps1 -WorkspaceRoot D:\\dev\\psign
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

if (-not (Test-RsEnvPresent "PSIGN_UNSIGNED_FIXTURE") -or -not (Test-RsEnvPresent "PSIGN_TEST_PFX")) {
    Write-Host "[skip] rust-sip-parity-pe: set PSIGN_UNSIGNED_FIXTURE and PSIGN_TEST_PFX"
    exit 0
}

$native = Resolve-NativeSignTool
$rustBin = Join-Path $WorkspaceRoot "target\debug\psign-tool.exe"
if (-not (Test-Path -LiteralPath $rustBin)) {
    Write-Host "Building psign-tool (debug)..."
    & cargo build -p psign --bin psign-tool | Out-Host
}

$u = $env:PSIGN_UNSIGNED_FIXTURE
$pfx = $env:PSIGN_TEST_PFX
if (-not (Test-Path -LiteralPath $u)) {
    throw "PSIGN_UNSIGNED_FIXTURE not found: $u"
}
if (-not (Test-Path -LiteralPath $pfx)) {
    throw "PSIGN_TEST_PFX not found: $pfx"
}

$tmpNative = Join-Path $env:TEMP "psign_rust_sip_native.exe"
$tmpRust = Join-Path $env:TEMP "psign_rust_sip_rust.exe"
Copy-Item -LiteralPath $u -Destination $tmpNative -Force
Copy-Item -LiteralPath $u -Destination $tmpRust -Force

$nativeSign = @("sign", "/fd", "SHA256", "/f", $pfx, $tmpNative)
$rustSign = @("sign", "--pfx", $pfx, "--digest", "sha256", "--rust-sip", "pe", $tmpRust)
if (Test-RsEnvPresent "PSIGN_TEST_PFX_PASSWORD") {
    $pw = $env:PSIGN_TEST_PFX_PASSWORD
    $nativeSign = @("sign", "/fd", "SHA256", "/f", $pfx, "/p", $pw, $tmpNative)
    $rustSign = @("sign", "--pfx", $pfx, "--password", $pw, "--digest", "sha256", "--rust-sip", "pe", $tmpRust)
}

Write-Host "Native sign: $native $($nativeSign -join ' ')"
& $native @nativeSign | Out-Host
if ($LASTEXITCODE -ne 0) { throw "native sign failed exit=$LASTEXITCODE" }

Write-Host "Rust sign (rust-sip pe): $($rustSign -join ' ')"
& $rustBin @rustSign | Out-Host
if ($LASTEXITCODE -ne 0) { throw "rust sign with --rust-sip pe failed exit=$LASTEXITCODE" }

Write-Host "Verify native-signed with native + rust /pa"
& $native verify /pa $tmpNative | Out-Host
$n1 = $LASTEXITCODE
& $rustBin verify --policy pa $tmpNative | Out-Host
$r1 = $LASTEXITCODE

Write-Host "Verify rust-signed with native + rust /pa (+ optional rust digest check)"
& $native verify /pa $tmpRust | Out-Host
$n2 = $LASTEXITCODE
& $rustBin verify --policy pa --rust-sip-pe-digest-check $tmpRust | Out-Host
$r2 = $LASTEXITCODE

Remove-Item -LiteralPath $tmpNative -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tmpRust -Force -ErrorAction SilentlyContinue

if ($n1 -ne $r1 -or $n2 -ne $r2) {
    throw "exit-code mismatch: native1=$n1 rust1=$r1 native2=$n2 rust2=$r2"
}
Write-Host "rust-sip-parity-pe: OK (exit codes aligned)"
