param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$moduleRoot = Join-Path $PSScriptRoot 'Devolutions.Psign'
$libOut = Join-Path (Join-Path $moduleRoot 'lib') 'net8.0'
$projectPath = Join-Path (Join-Path $repo 'dotnet') 'Devolutions.Psign.PowerShell'
$projectPath = Join-Path $projectPath 'Devolutions.Psign.PowerShell.csproj'

Push-Location $repo
try {
    cargo build -p psign-portable-ffi --profile ($Configuration -eq 'Release' ? 'release' : 'dev')
    dotnet publish $projectPath -c $Configuration -o $libOut

    $rid = if ($IsWindows) {
        'win'
    } elseif ($IsMacOS) {
        'osx'
    } else {
        'linux'
    }
    $arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture) {
        'X64' { 'x64' }
        'Arm64' { 'arm64' }
        default { $_.ToString().ToLowerInvariant() }
    }
    $rid = "$rid-$arch"
    $nativeName = if ($IsWindows) {
        'psign_portable.dll'
    } elseif ($IsMacOS) {
        'libpsign_portable.dylib'
    } else {
        'libpsign_portable.so'
    }
    $profileDir = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
    $nativeSource = Join-Path (Join-Path (Join-Path $repo 'target') $profileDir) $nativeName
    $nativeOut = Join-Path (Join-Path (Join-Path $moduleRoot 'runtimes') $rid) 'native'
    New-Item -ItemType Directory -Force -Path $nativeOut | Out-Null
    Copy-Item -Force -Path $nativeSource -Destination (Join-Path $nativeOut $nativeName)
}
finally {
    Pop-Location
}
