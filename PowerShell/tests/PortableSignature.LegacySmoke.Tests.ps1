Describe 'Portable PowerShell module legacy smoke suite' {
    It 'passes the pre-existing end-to-end smoke checks' {
        $configuration = if ($env:PSIGN_PWSH_TEST_CONFIGURATION) {
            $env:PSIGN_PWSH_TEST_CONFIGURATION
        }
        else {
            'Release'
        }

        & (Join-Path $PSScriptRoot 'PortableSignature.LegacySmoke.ps1') -Configuration $configuration
    }
}
