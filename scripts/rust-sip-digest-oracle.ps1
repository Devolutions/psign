# Compare PE Authenticode SHA-256 digest (Rust) on tracked upstream tiny fixtures — no signing required.
param(
    [string]$WorkspaceRoot = ""
)

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
Set-Location -LiteralPath $WorkspaceRoot

Write-Host "Running library tests for sip_rust PE digest golden vectors..."
& cargo test golden_tiny --lib -- --nocapture
if ($LASTEXITCODE -ne 0) { throw "digest oracle tests failed" }
