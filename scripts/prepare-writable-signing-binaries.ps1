# Populate parity-output/writable-signing-binaries with writable copies of native
# signing-related PEs (signtool.exe, mssign32.dll, WINTRUST.dll). Installed Kits
# and System32 paths are often not writable next to the file for tooling that
# creates sidecar files in the same directory.
#
# See docs/writable-signing-binaries.md
param(
    [string]$WorkspaceRoot = ""
)

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

$dst = Join-Path $WorkspaceRoot "parity-output\writable-signing-binaries"
New-Item -ItemType Directory -Force -Path $dst | Out-Null

function Copy-IfExists([string]$Src, [string]$DestName) {
    if (Test-Path -LiteralPath $Src) {
        Copy-Item -LiteralPath $Src -Destination (Join-Path $dst $DestName) -Force
        Write-Host "Copied $DestName <- $Src"
        return $true
    }
    Write-Warning "Missing: $Src"
    return $false
}

Copy-IfExists (Join-Path $env:SystemRoot "System32\WINTRUST.dll") "WINTRUST.dll" | Out-Null
Copy-IfExists (Join-Path $env:SystemRoot "System32\mssign32.dll") "mssign32.dll" | Out-Null

$kitBinRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
if (Test-Path -LiteralPath $kitBinRoot) {
    $verDirs = Get-ChildItem -LiteralPath $kitBinRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+' } |
        Sort-Object Name -Descending
    foreach ($leaf in @("signtool.exe", "mssign32.dll")) {
        $copied = $false
        foreach ($vd in $verDirs) {
            $p = Join-Path $vd.FullName "x64\$leaf"
            if (Test-Path -LiteralPath $p) {
                Copy-IfExists $p $leaf | Out-Null
                $copied = $true
                break
            }
        }
        if (-not $copied) {
            Write-Warning "Windows Kit x64\$leaf not found under $kitBinRoot"
        }
    }
}
else {
    Write-Warning "Windows Kits\10\bin not found — skipped signtool.exe / kit mssign32.dll"
}

Write-Host ""
Write-Host "Writable copies under: $dst"
Write-Host "Done."
