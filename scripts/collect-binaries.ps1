param(
    [string]$SignToolPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $SignToolPath)) {
    throw "signtool.exe not found at '$SignToolPath'."
}

Write-Host "Generating manifest and static transitive graph from $SignToolPath"
cargo run -p psign --bin psign-depgraph -- --signtool "$SignToolPath"

Write-Host "Artifacts generated:"
Write-Host " - parity-output/binary-manifest.json"
Write-Host " - parity-output/dependency-graph.json"
