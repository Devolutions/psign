# Use the vendored Devolutions public test CA + code-signing PFX, trust the CA, export env vars for parity CI.
# See https://github.com/Devolutions/devolutions-authenticode — test-only PKI; password is public (CodeSign123!).
param(
    [string]$CommitSha = "df20875f2935645a007a4fdc12bf8900f8316362",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$LocalCertRoot = "",
    [switch]$RefreshDownload,
    [switch]$EmitGithubEnv
)

$ErrorActionPreference = "Stop"
$baseUrl = "https://raw.githubusercontent.com/Devolutions/devolutions-authenticode/$CommitSha/data/certs"
$expectedCaSha256 = "a4f2a4df35d8db33f704e32276a5874b6b44906536637e22df579e300aa3bc0e"
$expectedPfxSha256 = "d5b5fc1bb184c5689d2abe2a9c988b72496f79aa19ccb2683271c4c7db31eb8d"
$rt = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$destRoot = Join-Path $rt "devolutions-authenticode-ci"
New-Item -ItemType Directory -Force -Path $destRoot | Out-Null

$caPath = Join-Path $destRoot "authenticode-test-ca.crt"
$pfxPath = Join-Path $destRoot "authenticode-test-cert.pfx"

function Assert-Sha256 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Expected
    )
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "SHA256 mismatch for $Path. Expected $Expected, got $actual."
    }
}

if (-not $LocalCertRoot) {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
    $LocalCertRoot = Join-Path $repoRoot "tests\fixtures\devolutions-authenticode"
}
$localCa = Join-Path $LocalCertRoot "authenticode-test-ca.crt"
$localPfx = Join-Path $LocalCertRoot "authenticode-test-cert.pfx"

if (-not $RefreshDownload -and (Test-Path -LiteralPath $localCa) -and (Test-Path -LiteralPath $localPfx)) {
    Assert-Sha256 -Path $localCa -Expected $expectedCaSha256
    Assert-Sha256 -Path $localPfx -Expected $expectedPfxSha256
    Copy-Item -LiteralPath $localCa -Destination $caPath -Force
    Copy-Item -LiteralPath $localPfx -Destination $pfxPath -Force
    Write-Host "Using vendored Devolutions Authenticode test certs from $LocalCertRoot"
}
else {
    Invoke-WebRequest -Uri "$baseUrl/authenticode-test-ca.crt" -OutFile $caPath -UseBasicParsing
    Invoke-WebRequest -Uri "$baseUrl/authenticode-test-cert.pfx" -OutFile $pfxPath -UseBasicParsing
    Assert-Sha256 -Path $caPath -Expected $expectedCaSha256
    Assert-Sha256 -Path $pfxPath -Expected $expectedPfxSha256
    Write-Host "Downloaded Devolutions Authenticode test certs from pinned commit $CommitSha"
}

try {
    Import-Certificate -FilePath $caPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
}
catch {
    Write-Warning "LocalMachine\Root import failed ($($_.Exception.Message)); trying CurrentUser\Root."
    Import-Certificate -FilePath $caPath -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
}

$pfxPassword = "CodeSign123!"
$lines = @(
    "PSIGN_TEST_PFX=$pfxPath",
    "PSIGN_TEST_PFX_PASSWORD=$pfxPassword",
    "PSIGN_TIMESTAMP_URL=$TimestampUrl",
    "PSIGN_MSIX_TEST_PFX=$pfxPath",
    "PSIGN_MSIX_TEST_PFX_PASSWORD=$pfxPassword",
    "PSIGN_MSIX_TIMESTAMP_URL=$TimestampUrl"
)

# Rust signer signs from store via --cert-sha1 reliably for this PKI; native signtool keeps using /f PFX.
$secure = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force
try {
    $imported = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\My" -Password $secure -Exportable
    $thumb = $imported.Thumbprint
    $lines += @(
        "PSIGN_TEST_CERT_SHA1=$thumb",
        "PSIGN_MSIX_TEST_CERT_SHA1=$thumb"
    )
    Write-Host "Imported test signing cert to CurrentUser\My (thumbprint $thumb)."
}
catch {
    Write-Warning "Import-PfxCertificate to CurrentUser\My failed ($($_.Exception.Message)); set PSIGN_TEST_CERT_SHA1 manually if Rust --pfx signing fails."
}

foreach ($line in $lines) {
    $name, $value = $line.Split("=", 2)
    Set-Item -Path "Env:$name" -Value $value
}

if ($EmitGithubEnv -and $env:GITHUB_ENV) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Value ($lines -join "`n")
}

Write-Host "Devolutions Authenticode bootstrap OK; PFX at $pfxPath"
