# Create a repository-independent, valid MSI package for Windows SIP signing parity.
param(
    [Parameter(Mandatory)][string]$OutputMsi
)

$ErrorActionPreference = "Stop"

function Resolve-WixTool([string]$Name) {
    $command = Get-Command "$Name.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @()
    if ($env:WIX) {
        $candidates += Join-Path $env:WIX "bin\$Name.exe"
    }
    $candidates += Join-Path ${env:ProgramFiles(x86)} "WiX Toolset v3.14\bin\$Name.exe"
    $candidates += Join-Path ${env:ProgramFiles(x86)} "WiX Toolset v3.11\bin\$Name.exe"
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }
    throw "Could not find WiX v3 $Name.exe"
}

function Assert-ValidInstallerPackage([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        # Option 1 creates a restricted session and does not change machine state.
        $session = $installer.OpenPackage($Path, 1)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($session)
    }
    finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
}

$parent = Split-Path -Parent $OutputMsi
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}

$source = Join-Path $PSScriptRoot "..\..\tests\fixtures\msi-parity\minimal.wxs"
$work = Join-Path ([IO.Path]::GetTempPath()) "psign-msi-$([guid]::NewGuid())"
$wixObject = Join-Path $work "minimal.wixobj"
$candle = Resolve-WixTool "candle"
$light = Resolve-WixTool "light"

New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    & $candle -nologo -out $wixObject $source
    if ($LASTEXITCODE -ne 0) {
        throw "candle.exe failed with exit code $LASTEXITCODE"
    }

    & $light -nologo -out $OutputMsi $wixObject
    if ($LASTEXITCODE -ne 0) {
        throw "light.exe failed with exit code $LASTEXITCODE"
    }

    Assert-ValidInstallerPackage $OutputMsi
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Created valid minimal MSI parity fixture: $OutputMsi"
