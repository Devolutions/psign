# Write tests/fixtures/catalog-authenticode-upstream/tiny32-content.cat (first PE PKCS#7 from tiny32).
param([string]$WorkspaceRoot = "")

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$pe = Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny32.signed.efi"
$out = Join-Path $WorkspaceRoot "tests\fixtures\catalog-authenticode-upstream\tiny32-content.cat"
if (-not (Test-Path -LiteralPath $pe)) { throw "Missing PE fixture: $pe" }

New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
Push-Location $WorkspaceRoot
try {
    cargo run -p psign --bin psign-tool --locked -- `
        portable extract-pe-pkcs7 $pe --output $out
    if ($LASTEXITCODE -ne 0) { throw "extract-pe-pkcs7 failed" }
}
finally {
    Pop-Location
}
Write-Host "OK -> $out"
