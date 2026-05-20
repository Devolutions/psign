# Orchestrate Devolutions PKI bootstrap, derived fixtures, minimal MSIX pack, and run-parity-diff with exhaustive semantic gates.
param(
    [string]$WorkspaceRoot,
    [string]$UnsignedPeRel = "target\debug\psign-tool.exe",
    [switch]$SkipMsixParitySignReport
)

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
Set-Location -LiteralPath $WorkspaceRoot

& (Join-Path $PSScriptRoot "bootstrap-devolutions-authenticode.ps1") -EmitGithubEnv

$unsignedPe = Join-Path $WorkspaceRoot $UnsignedPeRel
if (-not (Test-Path -LiteralPath $unsignedPe)) {
    throw "Unsigned PE not found (build psign-tool first): $unsignedPe"
}

& (Join-Path $PSScriptRoot "prepare-parity-fixtures.ps1") `
    -WorkspaceRoot $WorkspaceRoot `
    -UnsignedPe $unsignedPe `
    -PfxPath $env:PSIGN_TEST_PFX `
    -PfxPassword $env:PSIGN_TEST_PFX_PASSWORD `
    -EmitGithubEnv `
    -RequireDetachedPkcs7

$rt = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$msixOut = Join-Path $rt "psign_parity_minimal.msix"
& (Join-Path $PSScriptRoot "pack-minimal-msix.ps1") `
    -WorkspaceRoot $WorkspaceRoot `
    -PeAsExecutable $unsignedPe `
    -OutputMsix $msixOut

$env:PSIGN_MSIX_UNSIGNED_FIXTURE = $msixOut
$env:PSIGN_UNSIGNED_FIXTURE = $unsignedPe

$winmdOut = Join-Path $rt "psign_parity_minimal.winmd"
& (Join-Path $PSScriptRoot "pack-minimal-winmd.ps1") -PeSource $unsignedPe -OutputWinmd $winmdOut
$env:PSIGN_WINMD_UNSIGNED_FIXTURE = $winmdOut
if ($env:PSIGN_TIMESTAMP_URL) {
    $env:PSIGN_WINMD_TIMESTAMP_URL = $env:PSIGN_TIMESTAMP_URL
}

if ($env:GITHUB_ENV) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Value "PSIGN_MSIX_UNSIGNED_FIXTURE=$msixOut"
    Add-Content -LiteralPath $env:GITHUB_ENV -Value "PSIGN_UNSIGNED_FIXTURE=$unsignedPe"
    Add-Content -LiteralPath $env:GITHUB_ENV -Value "PSIGN_WINMD_UNSIGNED_FIXTURE=$winmdOut"
    if ($env:PSIGN_WINMD_TIMESTAMP_URL) {
        Add-Content -LiteralPath $env:GITHUB_ENV -Value "PSIGN_WINMD_TIMESTAMP_URL=$($env:PSIGN_WINMD_TIMESTAMP_URL)"
    }
}

& (Join-Path $WorkspaceRoot "scripts\run-parity-diff.ps1") -FailOnSemantic -FailOnSemanticExhaustive

if (-not $SkipMsixParitySignReport) {
    & (Join-Path $WorkspaceRoot "scripts\msix-parity-sign.ps1") -FailOnSemantic
}
