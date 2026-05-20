# Build a minimal signed .cab for committing as tests/fixtures/cab-authenticode-upstream/*.cab (optional).
# Requires: Windows, makecab.exe, signtool.exe from Windows SDK, Devolutions test PFX (bootstrap script).
#
# Example (from repo root, after ./scripts/ci/bootstrap-devolutions-authenticode.ps1):
#   pwsh -File scripts/ci/build-signed-cab-fixture.ps1 -OutputCab tests/fixtures/cab-authenticode-upstream/tiny-signed.cab
param(
    [string]$WorkspaceRoot = "",
    [Parameter(Mandatory = $true)]
    [string]$OutputCab
)

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

if (-not $env:PSIGN_TEST_PFX -or -not (Test-Path -LiteralPath $env:PSIGN_TEST_PFX)) {
    throw "Set PSIGN_TEST_PFX (run scripts/ci/bootstrap-devolutions-authenticode.ps1 or set env manually)."
}

$kitBinRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
$signtool = $null
if (Test-Path -LiteralPath $kitBinRoot) {
    $verDirs = Get-ChildItem -LiteralPath $kitBinRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+' } |
        Sort-Object Name -Descending
    foreach ($vd in $verDirs) {
        $p = Join-Path $vd.FullName "x64\signtool.exe"
        if (Test-Path -LiteralPath $p) { $signtool = $p; break }
    }
}
if (-not $signtool) { throw "signtool.exe not found under Windows Kits\10\bin" }

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("psign_cab_fixture_" + [Guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $payload = Join-Path $work "hello.txt"
    Set-Content -LiteralPath $payload -Value "psign cab fixture`n" -Encoding ascii

    $ddf = Join-Path $work "cab.ddf"
    $cabPath = Join-Path $work "unsigned.cab"
    @"
.Set CabinetNameTemplate=$cabPath
.Set DiskDirectoryTemplate=
.Set CompressionType=MSZIP
.Set UniqueFiles=on
.Set Cabinet=on
.Set DiskDirectory1=
$payload
"@ | Set-Content -LiteralPath $ddf -Encoding ascii

    Push-Location $work
    try {
        & makecab.exe /f (Split-Path $ddf -Leaf)
        if ($LASTEXITCODE -ne 0) { throw "makecab failed" }
    }
    finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath $cabPath)) { throw "makecab did not produce $cabPath" }

    $outAbs = if ([System.IO.Path]::IsPathRooted($OutputCab)) {
        $OutputCab
    }
    else {
        (Join-Path $WorkspaceRoot $OutputCab)
    }
    $outDir = Split-Path $outAbs -Parent
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $signArgs = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $cabPath)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $signArgs = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $cabPath)
    }
    & $signtool @signArgs
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed" }

    Copy-Item -LiteralPath $cabPath -Destination $outAbs -Force
    Write-Host "Wrote signed CAB -> $outAbs"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
