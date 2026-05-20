param(
    [string]$WorkspaceRoot = "",
    [string]$NativeSignTool = "",
    [string]$NativeMakeCat = "",
    [string]$PfxPath = "",
    [string]$PfxPassword = "CodeSign123!"
)

$ErrorActionPreference = "Stop"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$PreferredPath,
        [string[]]$ArchHints = @()
    )
    if ($PreferredPath -and (Test-Path -LiteralPath $PreferredPath)) {
        return (Resolve-Path -LiteralPath $PreferredPath).Path
    }
    $base = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $candidates = @(Get-ChildItem $base -Recurse -Filter $Name -ErrorAction SilentlyContinue | Sort-Object FullName)
    if ($candidates.Count -eq 0) {
        throw "$Name not found under $base"
    }
    foreach ($hint in $ArchHints) {
        $hit = $candidates | Where-Object { $_.FullName -match [regex]::Escape($hint) } | Select-Object -Last 1
        if ($hit) {
            return $hit.FullName
        }
    }
    return ($candidates | Select-Object -Last 1 -ExpandProperty FullName)
}

$makecat = Resolve-WindowsKitTool -Name "makecat.exe" -PreferredPath $NativeMakeCat
$signtool = Resolve-WindowsKitTool -Name "signtool.exe" -PreferredPath $NativeSignTool -ArchHints @("\x64\", "\amd64\")
if (-not $PfxPath) {
    $PfxPath = Join-Path $WorkspaceRoot "tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx"
}
if (-not (Test-Path -LiteralPath $PfxPath)) {
    throw "Missing test signing PFX: $PfxPath"
}

$fixtureRoot = Join-Path $WorkspaceRoot "tests\fixtures\catalog-workflows"
$subjects = Join-Path $fixtureRoot "subjects"
$cdfs = Join-Path $fixtureRoot "cdf"
New-Item -ItemType Directory -Force -Path $subjects, $cdfs | Out-Null

Copy-Item -LiteralPath (Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny32.efi") `
    -Destination (Join-Path $subjects "tiny32.efi") -Force
Set-Content -LiteralPath (Join-Path $subjects "hello.txt") `
    -Value "psign catalog workflow fixture" -NoNewline -Encoding ASCII
[IO.File]::WriteAllBytes((Join-Path $subjects "blob.bin"), [byte[]](0..255))

function Write-Cdf {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Files
    )
    $lines = @(
        "[CatalogHeader]",
        "Name=$Name.cat",
        "ResultDir=.",
        "PublicVersion=0x00000001",
        "EncodingType=0x00010001",
        "CATATTR1=0x10010001:OSAttr:2:10.0",
        "",
        "[HashAlgorithms]",
        "SHA256",
        "",
        "[CatalogFiles]"
    )
    foreach ($key in $Files.Keys | Sort-Object) {
        $lines += "<$key>=$($Files[$key])"
    }
    [IO.File]::WriteAllText(
        (Join-Path $cdfs "$Name.cdf"),
        (($lines -join "`r`n") + "`r`n"),
        [Text.Encoding]::ASCII)
}

Write-Cdf "single-pe" @{ "tiny32.efi" = "subjects\tiny32.efi" }
Write-Cdf "single-text" @{ "hello.txt" = "subjects\hello.txt" }
Write-Cdf "single-binary" @{ "blob.bin" = "subjects\blob.bin" }
Write-Cdf "multi-member" @{
    "tiny32.efi" = "subjects\tiny32.efi"
    "hello.txt" = "subjects\hello.txt"
    "blob.bin" = "subjects\blob.bin"
}

Push-Location $fixtureRoot
try {
    foreach ($cdf in Get-ChildItem $cdfs -Filter "*.cdf" | Sort-Object Name) {
        & $makecat $cdf.FullName | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "makecat failed for $($cdf.Name)"
        }
        $cat = Join-Path $fixtureRoot ([IO.Path]::GetFileNameWithoutExtension($cdf.Name) + ".cat")
        & $signtool sign /fd SHA256 /f $PfxPath /p $PfxPassword $cat | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed for $cat"
        }
    }
}
finally {
    Pop-Location
}

Write-Host "OK -> $fixtureRoot"
