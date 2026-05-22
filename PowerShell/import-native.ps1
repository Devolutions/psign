param(
    [Parameter(Mandatory)]
    [string] $ArtifactsRoot,

    [string] $ModuleRoot = (Join-Path $PSScriptRoot 'Devolutions.Psign')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ArtifactsRoot -PathType Container)) {
    throw "Native artifacts root does not exist: $ArtifactsRoot"
}

$staleNames = @('psign_portable.dll', 'libpsign_portable.dylib', 'libpsign_portable.so')
$artifactDirectories = Get-ChildItem -LiteralPath $ArtifactsRoot -Directory -Recurse |
    Where-Object { $_.Name -match '^psign-core-(?<rid>.+)$' } |
    Sort-Object FullName

if (-not $artifactDirectories) {
    throw "No psign-core native artifacts were found under $ArtifactsRoot"
}

$imported = 0
foreach ($artifactDirectory in $artifactDirectories) {
    if ($artifactDirectory.Name -notmatch '^psign-core-(?<rid>.+)$') {
        continue
    }
    $rid = $Matches['rid']
    $nativeName = if ($rid.StartsWith('win-', [System.StringComparison]::OrdinalIgnoreCase)) {
        'psign-core.dll'
    } elseif ($rid.StartsWith('osx-', [System.StringComparison]::OrdinalIgnoreCase)) {
        'libpsign-core.dylib'
    } elseif ($rid.StartsWith('linux-', [System.StringComparison]::OrdinalIgnoreCase)) {
        'libpsign-core.so'
    } else {
        throw "Unsupported psign-core artifact RID '$rid' from $($artifactDirectory.FullName)"
    }

    $nativeFiles = @(Get-ChildItem -LiteralPath $artifactDirectory.FullName -Recurse -File -Filter $nativeName)
    if ($nativeFiles.Count -ne 1) {
        throw "Expected exactly one $nativeName in $($artifactDirectory.FullName), found $($nativeFiles.Count)."
    }

    $nativeOut = Join-Path (Join-Path (Join-Path $ModuleRoot 'runtimes') $rid) 'native'
    New-Item -ItemType Directory -Force -Path $nativeOut | Out-Null
    foreach ($staleName in $staleNames) {
        Remove-Item -LiteralPath (Join-Path $nativeOut $staleName) -Force -ErrorAction SilentlyContinue
    }
    Copy-Item -Force -LiteralPath $nativeFiles[0].FullName -Destination (Join-Path $nativeOut $nativeName)
    $imported++
}

if ($imported -eq 0) {
    throw "No psign-core native libraries were imported from $ArtifactsRoot"
}

Write-Host "Imported $imported psign-core native librar$(if ($imported -eq 1) { 'y' } else { 'ies' })."
