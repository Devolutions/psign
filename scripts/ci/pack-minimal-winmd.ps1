# Produce an unsigned `.winmd` path for Authenticode parity by copying PE bytes.
#
# Windows metadata (`.winmd`) is PE-backed; `SignerSignEx3` / inbox SIP treat it like a PE image subject.
# CI uses the same unsigned build output as `PSIGN_UNSIGNED_FIXTURE`, renamed for extension-driven SIP selection.
param(
    [Parameter(Mandatory)][string]$PeSource,
    [Parameter(Mandatory)][string]$OutputWinmd
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $PeSource)) {
    throw "PE source not found: $PeSource"
}
Copy-Item -LiteralPath $PeSource -Destination $OutputWinmd -Force
Write-Host "Wrote unsigned WinMD-shaped PE: $OutputWinmd"
