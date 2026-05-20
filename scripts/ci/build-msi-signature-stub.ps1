# Regenerate tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi (OLE stub with PE PKCS#7 in DigitalSignature).
# See tests/fixtures/msi-authenticode-upstream/README.md
param(
    [string]$WorkspaceRoot = ""
)

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$pe = Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny32.signed.efi"
$out = Join-Path $WorkspaceRoot "tests\fixtures\msi-authenticode-upstream\tiny-pkcs7-stub.msi"
if (-not (Test-Path -LiteralPath $pe)) { throw "Missing PE fixture: $pe" }

Push-Location $WorkspaceRoot
try {
    cargo run -p psign-sip-digest --bin psign-gen-msi-signature-stub --locked -- $pe $out
    if ($LASTEXITCODE -ne 0) { throw "psign-gen-msi-signature-stub failed" }
}
finally {
    Pop-Location
}
Write-Host "OK -> $out"
