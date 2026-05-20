# Prepare CI-only parity inputs: signed PE for timestamp scenarios, detached PKCS#7 pair for verify --detached-pkcs7.
param(
    [Parameter(Mandatory)][string]$WorkspaceRoot,
    [Parameter(Mandatory)][string]$UnsignedPe,
    [Parameter(Mandatory)][string]$PfxPath,
    [Parameter(Mandatory)][string]$PfxPassword,
    [string]$NativeSigntool,
    [switch]$EmitGithubEnv,
    [switch]$RequireDetachedPkcs7
)

$ErrorActionPreference = "Stop"

function Resolve-NativeSignTool {
    if ($NativeSigntool -and (Test-Path -LiteralPath $NativeSigntool)) { return $NativeSigntool }
    $candidates = @(Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Sort-Object FullName)
    if ($candidates.Count -eq 0) { throw "signtool.exe not found" }
    foreach ($sub in @('\x64\', '\amd64\')) {
        $hit = $candidates | Where-Object { $_.FullName -match [regex]::Escape($sub) } | Select-Object -Last 1
        if ($hit) { return $hit.FullName }
    }
    return ($candidates | Select-Object -Last 1 -ExpandProperty FullName)
}

$signtool = Resolve-NativeSignTool
$tempCopy = Join-Path $env:TEMP "psign_parity_ci_signed.exe"
Copy-Item -LiteralPath $UnsignedPe -Destination $tempCopy -Force

$saved = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $signtool sign /fd SHA256 /f $PfxPath /p $PfxPassword $tempCopy 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "native signtool sign failed for CI signed fixture (exit $LASTEXITCODE)" }
$ErrorActionPreference = $saved

$contentPath = Join-Path $env:TEMP "psign_parity_detached_content.bin"
Copy-Item -LiteralPath $UnsignedPe -Destination $contentPath -Force
$p7Dir = Join-Path $env:TEMP "psign_parity_p7_out"
if (Test-Path -LiteralPath $p7Dir) { Remove-Item -LiteralPath $p7Dir -Recurse -Force }
New-Item -ItemType Directory -Path $p7Dir | Out-Null

$ErrorActionPreference = "Continue"
# Current signtool builds require `/p7co` with `/p7`; bare `/p7` always errors — emit detached SignedData directly.
& $signtool sign /fd SHA256 /f $PfxPath /p $PfxPassword /p7 $p7Dir /p7ce DetachedSignedData /p7co 1.2.840.113549.1.7.2 $contentPath 2>&1 | Out-Null
$p7Exit = $LASTEXITCODE
$ErrorActionPreference = $saved

$p7File = Get-ChildItem -LiteralPath $p7Dir -Filter "*.p7" -File -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p7File) {
    $p7File = Get-ChildItem -LiteralPath $p7Dir -File -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($p7Exit -ne 0 -or -not $p7File) {
    if ($RequireDetachedPkcs7) {
        throw "Detached PKCS#7 generation failed (exit $p7Exit). Native signtool /p7 output: $p7Dir"
    }
    Write-Warning "Detached PKCS#7 generation failed (exit $p7Exit); omit PSIGN_DETACHED_* from CI env."
}
else {
    $detachedLines = @(
        "PSIGN_DETACHED_CONTENT=$contentPath",
        "PSIGN_DETACHED_PKCS7=$($p7File.FullName)"
    )
    foreach ($line in $detachedLines) {
        $name, $value = $line.Split("=", 2)
        Set-Item -Path "Env:$name" -Value $value
    }
    if ($EmitGithubEnv -and $env:GITHUB_ENV) {
        Add-Content -LiteralPath $env:GITHUB_ENV -Value ($detachedLines -join "`n")
    }
}

$signedLines = @("PSIGN_SIGNED_FIXTURE=$tempCopy")
Set-Item -Path "Env:PSIGN_SIGNED_FIXTURE" -Value $tempCopy
if ($EmitGithubEnv -and $env:GITHUB_ENV) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Value $signedLines
}

Write-Host "Prepared PSIGN_SIGNED_FIXTURE=$tempCopy"
if ($p7File) {
    Write-Host "Prepared detached PKCS#7 $($p7File.FullName)"
}
