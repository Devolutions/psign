param(
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$buildScript = Join-Path (Join-Path $repo 'PowerShell') 'build.ps1'
& $buildScript -Configuration $Configuration

$pester = Get-Module -ListAvailable Pester |
    Sort-Object Version -Descending |
    Select-Object -First 1
if ($null -eq $pester) {
    throw 'Pester 5.x is required to run the PowerShell module test suite.'
}

Import-Module $pester.Path -Force

$env:PSIGN_PWSH_TEST_SKIP_BUILD = '1'
$env:PSIGN_PWSH_TEST_CONFIGURATION = $Configuration
try {
    $result = Invoke-Pester -Path (Join-Path $PSScriptRoot '*.Tests.ps1') -PassThru
    if ($result.FailedCount -gt 0) {
        throw "PowerShell module tests failed: $($result.FailedCount) failed, $($result.PassedCount) passed."
    }
}
finally {
    Remove-Item Env:PSIGN_PWSH_TEST_SKIP_BUILD -ErrorAction SilentlyContinue
    Remove-Item Env:PSIGN_PWSH_TEST_CONFIGURATION -ErrorAction SilentlyContinue
}
