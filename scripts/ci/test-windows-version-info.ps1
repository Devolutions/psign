param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$ExpectedVersion = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Executable not found: $Path"
}

if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
    $metadataJson = cargo metadata --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE"
    }

    $metadata = $metadataJson | ConvertFrom-Json
    $package = $metadata.packages | Where-Object { $_.name -eq "psign" } | Select-Object -First 1
    if (-not $package) {
        throw "Unable to resolve psign package version from cargo metadata."
    }

    $ExpectedVersion = [string]$package.version
}

$versionInfo = (Get-Item -LiteralPath $Path).VersionInfo

$expected = [ordered]@{
    FileVersion = $ExpectedVersion
    ProductVersion = $ExpectedVersion
    CompanyName = "Devolutions"
    FileDescription = "psign-tool Authenticode signing and verification tool"
    ProductName = "psign"
    OriginalFilename = "psign-tool.exe"
    InternalName = "psign-tool"
    LegalCopyright = "Copyright (c) Devolutions"
    Comments = "https://github.com/Devolutions/psign"
}

foreach ($name in $expected.Keys) {
    $actual = [string]$versionInfo.$name
    if ($actual -ne $expected[$name]) {
        throw "Unexpected VERSIONINFO '$name' for '$Path': actual '$actual', expected '$($expected[$name])'."
    }
}

Write-Host "Verified Windows VERSIONINFO for $Path"
