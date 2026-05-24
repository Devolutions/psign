#Requires -Module Pester

<#
    .SYNOPSIS
    Tests for Test-PsignModule, Protect-PsignModule, and Unprotect-PsignSignature cmdlets.
    Requires Windows (uses New-SelfSignedCertificate and Cert:\ store).

    Cross-platform equivalents of these tests exist in TestPsignModule.Expanded.Tests.ps1
    and ProtectPsignModule.Expanded.Tests.ps1 using .NET crypto APIs.
#>

BeforeDiscovery {
    $script:SkipNonWindows = (-not $IsWindows) -and ($PSVersionTable.PSEdition -eq 'Core')
}

BeforeAll {
    if ((-not $IsWindows) -and ($PSVersionTable.PSEdition -eq 'Core')) {
        return
    }

    $ModuleDir = Join-Path $PSScriptRoot '..' 'Devolutions.Psign'
    Import-Module (Join-Path $ModuleDir 'Devolutions.Psign.psd1') -Force -ErrorAction Stop
    $env:PSIGN_NO_AUTO_TRUST = '1'

    # Create a code signing certificate for testing (exportable key required for portable signing)
    $script:TestCert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=PsignPesterTest' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddDays(1)

    # Set up a test module directory
    $script:TestModuleDir = Join-Path ([IO.Path]::GetTempPath()) "psign-module-test-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory $script:TestModuleDir | Out-Null

    $script:ModuleName = Split-Path $script:TestModuleDir -Leaf
}

AfterAll {
    if ($script:TestModuleDir -and (Test-Path $script:TestModuleDir)) {
        Remove-Item $script:TestModuleDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($script:TestCert) {
        Remove-Item "Cert:\CurrentUser\My\$($script:TestCert.Thumbprint)" -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\PSIGN_NO_AUTO_TRUST -ErrorAction SilentlyContinue
}

Describe 'Test-PsignModule' -Skip:$script:SkipNonWindows {
    BeforeAll {
        # Create a proper module structure
        $modDir = $script:TestModuleDir
        $modName = $script:ModuleName

        @"
@{
    RootModule = '$modName.psm1'
    ModuleVersion = '1.0.0'
    GUID = '12345678-aaaa-bbbb-cccc-dddddddddddd'
    ScriptsToProcess = @('init.ps1')
    FormatsToProcess = @('Format.ps1xml')
    NestedModules = @('helper.psm1')
}
"@ | Set-Content (Join-Path $modDir "$modName.psd1")

        'function Get-Main { }' | Set-Content (Join-Path $modDir "$modName.psm1")
        'Write-Verbose "init"' | Set-Content (Join-Path $modDir 'init.ps1')
        'function Get-Helper { }' | Set-Content (Join-Path $modDir 'helper.psm1')
        '<?xml version="1.0"?><Configuration><ViewDefinitions></ViewDefinitions></Configuration>' | Set-Content (Join-Path $modDir 'Format.ps1xml')
    }

    It 'reports unsigned module fails AllSigned' {
        $result = Test-PsignModule -Path $script:TestModuleDir -Policy AllSigned -SkipTrust
        $result.Valid | Should -BeFalse
        $result.FailedCount | Should -BeGreaterThan 0
        $result.Policy | Should -Be 'AllSigned'
    }

    It 'correctly classifies file roles from manifest' {
        $result = Test-PsignModule -Path $script:TestModuleDir -Policy AllSigned -SkipTrust
        $roles = $result.Files | ForEach-Object { @{ $_.RelativePath = $_.Role } }

        $rootModule = $result.Files | Where-Object { $_.RelativePath -like "*$($script:ModuleName).psm1" }
        $rootModule.Role | Should -Be 'RootModule'

        $manifest = $result.Files | Where-Object { $_.RelativePath -like '*.psd1' }
        $manifest.Role | Should -Be 'Manifest'
        $manifest.RequiredByPolicy | Should -BeFalse

        $init = $result.Files | Where-Object { $_.RelativePath -eq 'init.ps1' }
        $init.Role | Should -Be 'ScriptsToProcess'
        $init.RequiredByPolicy | Should -BeTrue
    }

    It '.psd1 is never required by policy (mirrors PowerShell engine)' {
        $result = Test-PsignModule -Path $script:TestModuleDir -Policy AllSigned -SkipTrust
        $manifest = $result.Files | Where-Object { $_.Role -eq 'Manifest' }
        $manifest.RequiredByPolicy | Should -BeFalse
    }

    It 'passes after signing with Protect-PsignModule' {
        Protect-PsignModule -Path $script:TestModuleDir -Certificate $script:TestCert | Out-Null
        $result = Test-PsignModule -Path $script:TestModuleDir -Policy AllSigned -SkipTrust
        $result.Valid | Should -BeTrue
        $result.FailedCount | Should -Be 0
    }

    It 'accepts manifest path directly' {
        $psd1 = Get-ChildItem $script:TestModuleDir -Filter '*.psd1' | Select-Object -First 1
        $result = Test-PsignModule -Path $psd1.FullName -Policy AllSigned -SkipTrust
        $result | Should -Not -BeNullOrEmpty
        $result.Valid | Should -BeTrue
    }

    It '-IncludeUnreferenced picks up extra files' {
        # Add an unreferenced script
        'Get-Process' | Set-Content (Join-Path $script:TestModuleDir 'extra.ps1')

        $without = Test-PsignModule -Path $script:TestModuleDir -Policy AllSigned -SkipTrust
        $with = Test-PsignModule -Path $script:TestModuleDir -Policy AllSigned -SkipTrust -IncludeUnreferenced

        $extraInWith = $with.Files | Where-Object { $_.RelativePath -eq 'extra.ps1' }
        $extraInWith | Should -Not -BeNullOrEmpty
        $extraInWith.Role | Should -Be 'Unreferenced'
        $with.Valid | Should -BeFalse  # extra.ps1 is unsigned

        # Clean up
        Remove-Item (Join-Path $script:TestModuleDir 'extra.ps1')
    }
}

Describe 'Protect-PsignModule' -Skip:$script:SkipNonWindows {
    BeforeAll {
        # Create a fresh unsigned module for signing tests
        $script:SignTestDir = Join-Path ([IO.Path]::GetTempPath()) "psign-sign-test-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory $script:SignTestDir | Out-Null
        $sn = Split-Path $script:SignTestDir -Leaf

        @"
@{
    RootModule = '$sn.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'eeeeeeee-aaaa-bbbb-cccc-dddddddddddd'
}
"@ | Set-Content (Join-Path $script:SignTestDir "$sn.psd1")
        'function Test-Sign { }' | Set-Content (Join-Path $script:SignTestDir "$sn.psm1")
    }

    AfterAll {
        if ($script:SignTestDir -and (Test-Path $script:SignTestDir)) {
            Remove-Item $script:SignTestDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'signs all discovered files and returns result' {
        $result = Protect-PsignModule -Path $script:SignTestDir -Certificate $script:TestCert
        $result | Should -Not -BeNullOrEmpty
        $result.Succeeded | Should -BeGreaterThan 0
        $result.Failed | Should -Be 0
        $result.TotalFiles | Should -Be 2  # .psd1 + .psm1
    }

    It 'all signed files report Valid status' {
        # Use a fresh directory to avoid re-signing issues
        $freshDir = Join-Path ([IO.Path]::GetTempPath()) "psign-fresh-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory $freshDir | Out-Null
        $fn = Split-Path $freshDir -Leaf
        @"
@{ RootModule = '$fn.psm1'; ModuleVersion = '1.0.0'; GUID = 'dddddddd-1111-2222-3333-444444444444' }
"@ | Set-Content (Join-Path $freshDir "$fn.psd1")
        'function Fresh { }' | Set-Content (Join-Path $freshDir "$fn.psm1")

        $result = Protect-PsignModule -Path $freshDir -Certificate $script:TestCert
        $result.Files | ForEach-Object {
            $_.Status | Should -Be 'Valid'
            $_.Success | Should -BeTrue
        }

        Remove-Item $freshDir -Recurse -Force
    }

    It 'supports -WhatIf without modifying files' {
        $unsigned = Join-Path ([IO.Path]::GetTempPath()) "psign-whatif-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory $unsigned | Out-Null
        'function Noop { }' | Set-Content (Join-Path $unsigned 'test.psm1')
        @"
@{ RootModule = 'test.psm1'; ModuleVersion = '1.0.0'; GUID = 'ffffffff-1111-2222-3333-444444444444' }
"@ | Set-Content (Join-Path $unsigned 'test.psd1')

        Protect-PsignModule -Path $unsigned -Certificate $script:TestCert -WhatIf

        # File should still be unsigned
        $sig = Get-PsignSignature -FilePath (Join-Path $unsigned 'test.psm1') -SkipTrust
        $sig.Status | Should -Be 'NotSigned'

        Remove-Item $unsigned -Recurse -Force
    }
}

Describe 'Unprotect-PsignSignature' -Skip:$script:SkipNonWindows {
    It 'removes script signature block' {
        $testFile = Join-Path ([IO.Path]::GetTempPath()) "psign-strip-$([Guid]::NewGuid().ToString('N').Substring(0,8)).ps1"
        @"
function Get-Test { }

# SIG # Begin signature block
# MIIFuQYJKoZIhvcNAQcCoIIFqjCCBaYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# SIG # End signature block
"@ | Set-Content $testFile

        $result = Unprotect-PsignSignature -Path $testFile
        $result.SignatureRemoved | Should -BeTrue
        $result.BytesRemoved | Should -BeGreaterThan 0

        $content = Get-Content $testFile -Raw
        $content | Should -Not -BeLike '*SIG*Begin*'
        $content | Should -BeLike '*function Get-Test*'

        Remove-Item $testFile -Force
    }

    It 'reports no change when file has no signature' {
        $testFile = Join-Path ([IO.Path]::GetTempPath()) "psign-nosig-$([Guid]::NewGuid().ToString('N').Substring(0,8)).ps1"
        'function Clean { }' | Set-Content $testFile

        $result = Unprotect-PsignSignature -Path $testFile
        $result.SignatureRemoved | Should -BeFalse

        Remove-Item $testFile -Force
    }

    It 'supports pipeline input' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) "psign-pipe-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory $dir | Out-Null
        @"
'test'
# SIG # Begin signature block
# fake
# SIG # End signature block
"@ | Set-Content (Join-Path $dir 'a.ps1')
        @"
'test2'
# SIG # Begin signature block
# fake2
# SIG # End signature block
"@ | Set-Content (Join-Path $dir 'b.ps1')

        $results = Get-ChildItem $dir -Filter '*.ps1' | Unprotect-PsignSignature -FilePath { $_.FullName }
        # Pipeline works even without binding - let's use explicit path array
        $results2 = Unprotect-PsignSignature -Path (Get-ChildItem $dir -Filter '*.ps1').FullName
        # After first run, both files are already stripped, so second run reports no change
        $results2 | ForEach-Object { $_.SignatureRemoved | Should -BeFalse }

        Remove-Item $dir -Recurse -Force
    }

    It 'rejects unsupported file types' {
        $testFile = Join-Path ([IO.Path]::GetTempPath()) "test.exe"
        [byte[]](0x4d, 0x5a) | Set-Content $testFile -AsByteStream

        { Unprotect-PsignSignature -Path $testFile -ErrorAction Stop } | Should -Throw

        Remove-Item $testFile -Force
    }
}
