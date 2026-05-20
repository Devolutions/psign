# Copy inbox CryptSIP-related DLLs (and optional SDK signtool/mssign32) into parity-output/vendor-binaries/
# for side-by-side comparison with psign-depgraph output. The parity-output/ tree is gitignored.
param(
    [string]$WorkspaceRoot = "",
    [switch]$IncludeCrypt32
)

$ErrorActionPreference = "Stop"
if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

$dst = Join-Path $WorkspaceRoot "parity-output\vendor-binaries"
New-Item -ItemType Directory -Force -Path $dst | Out-Null

$dlls = @(
    "${env:SystemRoot}\System32\AppxSip.dll",
    "${env:SystemRoot}\System32\EsdSip.dll",
    "${env:SystemRoot}\System32\MSISIP.DLL",
    "${env:SystemRoot}\System32\pwrshsip.dll",
    "${env:SystemRoot}\System32\wshext.dll",
    "${env:SystemRoot}\System32\WINTRUST.dll",
    "${env:SystemRoot}\System32\imagehlp.dll"
)

foreach ($d in $dlls) {
    if (Test-Path -LiteralPath $d) {
        Copy-Item -LiteralPath $d -Destination (Join-Path $dst (Split-Path $d -Leaf)) -Force
        Write-Host "Copied $(Split-Path $d -Leaf)"
    }
    else {
        Write-Warning "Missing $d"
    }
}

# 32-bit builds (WOW64) — same SIPs as amd64; optional architecture comparison.
$wowDst = Join-Path $dst "syswow64"
New-Item -ItemType Directory -Force -Path $wowDst | Out-Null
$dllsWow = @(
    "${env:SystemRoot}\SysWOW64\AppxSip.dll",
    "${env:SystemRoot}\SysWOW64\EsdSip.dll",
    "${env:SystemRoot}\SysWOW64\MSISIP.DLL",
    "${env:SystemRoot}\SysWOW64\pwrshsip.dll",
    "${env:SystemRoot}\SysWOW64\wshext.dll",
    "${env:SystemRoot}\SysWOW64\WINTRUST.dll",
    "${env:SystemRoot}\SysWOW64\imagehlp.dll"
)
foreach ($d in $dllsWow) {
    if (Test-Path -LiteralPath $d) {
        Copy-Item -LiteralPath $d -Destination (Join-Path $wowDst (Split-Path $d -Leaf)) -Force
        Write-Host "Copied syswow64\$(Split-Path $d -Leaf)"
    }
    else {
        Write-Warning "Missing WOW64 $d"
    }
}

if ($IncludeCrypt32) {
    $crypt64 = "${env:SystemRoot}\System32\crypt32.dll"
    $crypt32Wow = "${env:SystemRoot}\SysWOW64\crypt32.dll"
    if (Test-Path -LiteralPath $crypt64) {
        Copy-Item -LiteralPath $crypt64 -Destination (Join-Path $dst "crypt32.dll") -Force
        Write-Host "Copied crypt32.dll (amd64 System32)"
    }
    else {
        Write-Warning "Missing $crypt64"
    }
    if (Test-Path -LiteralPath $crypt32Wow) {
        Copy-Item -LiteralPath $crypt32Wow -Destination (Join-Path $wowDst "crypt32.dll") -Force
        Write-Host "Copied syswow64\crypt32.dll"
    }
    else {
        Write-Warning "Missing WOW64 $crypt32Wow"
    }
}

$msoCandidates = @(
    "${env:SystemRoot}\System32\mso.dll",
    "${env:ProgramFiles}\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\Office16\MSO.DLL",
    "${env:ProgramFiles}\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16\MSO.DLL",
    "${env:ProgramFiles(x86)}\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\Office16\MSO.DLL"
)
$msoCopied = $false
foreach ($m in $msoCandidates) {
    if (Test-Path -LiteralPath $m) {
        Copy-Item -LiteralPath $m -Destination (Join-Path $dst "mso.dll") -Force
        Write-Host "Copied mso.dll (from $(Split-Path $m -Leaf))"
        $msoCopied = $true
        break
    }
}
if (-not $msoCopied) {
    Write-Warning "mso.dll / MSO.DLL not found (VBA SIP); install Office or copy manually to parity-output/vendor-binaries"
}

$vbe7Candidates = @(
    "${env:ProgramFiles}\Common Files\Microsoft Shared\VBA\VBA7.1\VBE7.DLL",
    "${env:ProgramFiles}\Common Files\Microsoft Shared\VBA\VBA7.0\VBE7.DLL",
    "${env:ProgramFiles}\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\VBA\VBA7.1\VBE7.DLL",
    "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared\VBA\VBA7.1\VBE7.DLL"
)
$vbeCopied = $false
foreach ($v in $vbe7Candidates) {
    if (Test-Path -LiteralPath $v) {
        Copy-Item -LiteralPath $v -Destination (Join-Path $dst "VBE7.DLL") -Force
        Write-Host "Copied VBE7.DLL (from $(Split-Path $v -Leaf) under $(Split-Path (Split-Path $v) -Leaf))"
        $vbeCopied = $true
        break
    }
}
if (-not $vbeCopied) {
    Write-Warning 'VBE7.DLL not found; macro SIP hash lives in VBE7 - install Office VBA or copy manually to parity-output/vendor-binaries'
}

$kitBinRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
if (Test-Path -LiteralPath $kitBinRoot) {
    $verDirs = Get-ChildItem -LiteralPath $kitBinRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+' } |
        Sort-Object Name -Descending
    foreach ($leaf in @("mssign32.dll", "signtool.exe")) {
        $copied = $false
        foreach ($vd in $verDirs) {
            $p = Join-Path $vd.FullName "x64\$leaf"
            if (Test-Path -LiteralPath $p) {
                Copy-Item -LiteralPath $p -Destination (Join-Path $dst $leaf) -Force
                Write-Host "Copied $leaf (Windows Kits\bin\$($vd.Name)\x64)"
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
    Write-Warning "Windows Kits\10\bin not found — skipped mssign32.dll / signtool.exe"
}

Write-Host "Done -> $dst"
