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

# The module runs on the pure C# portable stack (Devolutions.Psign.Core / Verification / Signing). Remove any
# psign-core native libraries left over from builds that used the Rust FFI so they are not packaged.
$staleRuntimes = Join-Path $moduleRoot 'runtimes'
if (Test-Path -LiteralPath $staleRuntimes) {
    Remove-Item -LiteralPath $staleRuntimes -Recurse -Force
}

Push-Location $repo
try {
    dotnet publish $projectPath -c $Configuration -o $libOut
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}
