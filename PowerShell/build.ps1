param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [string] $NativeArtifactsRoot,

    [switch] $SkipNativeBuild
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$moduleRoot = Join-Path $PSScriptRoot 'Devolutions.Psign'
$libOut = Join-Path (Join-Path $moduleRoot 'lib') 'net8.0'
$projectPath = Join-Path (Join-Path $repo 'dotnet') 'Devolutions.Psign.PowerShell'
$projectPath = Join-Path $projectPath 'Devolutions.Psign.PowerShell.csproj'

Push-Location $repo
try {
    dotnet publish $projectPath -c $Configuration -o $libOut

    if ($NativeArtifactsRoot) {
        & (Join-Path $PSScriptRoot 'import-native.ps1') -ArtifactsRoot $NativeArtifactsRoot -ModuleRoot $moduleRoot
        return
    }

    if ($SkipNativeBuild) {
        return
    }

    cargo build -p psign-portable-ffi --features azure-kv-sign,artifact-signing-rest --profile ($Configuration -eq 'Release' ? 'release' : 'dev')

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
    $cargoNativeName = if ($IsWindows) {
        'psign_core.dll'
    } elseif ($IsMacOS) {
        'libpsign_core.dylib'
    } else {
        'libpsign_core.so'
    }
    $nativeName = if ($IsWindows) {
        'psign-core.dll'
    } elseif ($IsMacOS) {
        'libpsign-core.dylib'
    } else {
        'libpsign-core.so'
    }
    $profileDir = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
    $nativeSource = Join-Path (Join-Path (Join-Path $repo 'target') $profileDir) $cargoNativeName
    $nativeOut = Join-Path (Join-Path (Join-Path $moduleRoot 'runtimes') $rid) 'native'
    New-Item -ItemType Directory -Force -Path $nativeOut | Out-Null
    foreach ($staleName in @('psign_portable.dll', 'libpsign_portable.dylib', 'libpsign_portable.so')) {
        Remove-Item -LiteralPath (Join-Path $nativeOut $staleName) -Force -ErrorAction SilentlyContinue
    }
    Copy-Item -Force -Path $nativeSource -Destination (Join-Path $nativeOut $nativeName)
}
finally {
    Pop-Location
}
