# Layout tests/fixtures/msix-minimal, copy a PE as noop.exe, run MakeAppx pack → unsigned MSIX path for parity.
param(
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [Parameter(Mandatory)][string]$PeAsExecutable,
    [Parameter(Mandatory)][string]$OutputMsix
)

$ErrorActionPreference = "Stop"
$layoutSrc = Join-Path $WorkspaceRoot "tests\fixtures\msix-minimal"
if (-not (Test-Path -LiteralPath $layoutSrc)) { throw "Missing msix-minimal fixture dir: $layoutSrc" }

$stage = Join-Path $env:TEMP "psign_msix_pack_stage"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
# Do not use -LiteralPath with '*' (no expansion); CI resolves tests/fixtures/msix-minimal children only.
Get-ChildItem -LiteralPath $layoutSrc -Force | Copy-Item -Destination $stage -Recurse -Force
Copy-Item -LiteralPath $PeAsExecutable -Destination (Join-Path $stage "noop.exe") -Force

$assetsDir = Join-Path $stage "Assets"
New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null
$logoPath = Join-Path $assetsDir "StoreLogo.png"
if (-not (Test-Path -LiteralPath $logoPath)) {
    $pngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    [IO.File]::WriteAllBytes($logoPath, [Convert]::FromBase64String($pngB64))
}

$makeAppx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter MakeAppx.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\|\\amd64\\' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $makeAppx) { throw "MakeAppx.exe not found under Windows Kits" }

& $makeAppx.FullName pack /h sha256 /d $stage /p $OutputMsix /o 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "MakeAppx pack failed with exit $LASTEXITCODE"
}
Write-Host "Wrote unsigned MSIX: $OutputMsix"
