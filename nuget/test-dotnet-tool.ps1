param(
    [string]$Version = "0.0.0-local",
    [string]$ArtifactsRoot = (Join-Path $PSScriptRoot "..\dist"),
    [string]$StagingRoot = (Join-Path $PSScriptRoot "staging"),
    [string]$OutputDir = (Join-Path $PSScriptRoot "..\dist\nuget"),
    [string]$ToolPath = (Join-Path $PSScriptRoot "tmp-tool")
)

$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "pack-psign-dotnet-tool.ps1") `
    -Version $Version `
    -ArtifactsRoot $ArtifactsRoot `
    -StagingRoot $StagingRoot `
    -OutputDir $OutputDir

if (Test-Path -Path $ToolPath) {
    Remove-Item -Path $ToolPath -Recurse -Force
}

New-Item -Path $ToolPath -ItemType Directory -Force | Out-Null

dotnet tool install Devolutions.Psign.Tool `
    --tool-path $ToolPath `
    --add-source $OutputDir `
    --version $Version

if ($LASTEXITCODE -ne 0) {
    throw "dotnet tool install failed with exit code $LASTEXITCODE"
}

$toolExe = if ($IsWindows) { "psign-tool.exe" } else { "psign-tool" }
$toolExecutablePath = Join-Path $ToolPath $toolExe

& $toolExecutablePath --help
if ($LASTEXITCODE -ne 0) {
    throw "psign-tool --help failed with exit code $LASTEXITCODE"
}

Write-Host "Validated Devolutions.Psign.Tool $Version from $OutputDir"
