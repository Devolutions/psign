Set-StrictMode -Version Latest

function script:Ensure-PsignModuleForNativeFeatureTests {
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path (Join-Path $repoRoot 'PowerShell\Devolutions.Psign') 'Devolutions.Psign.psd1'
    Import-Module $modulePath -Force
}

Describe 'Psign native signature features' {
    BeforeAll {
        Ensure-PsignModuleForNativeFeatureTests
        $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $script:TempRoot | Out-Null
        $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }

    AfterAll {
        if ($script:TempRoot) {
            Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not export compatibility command aliases' {
        foreach ($name in @('Get-OpenAuthenticodeSignature', 'Set-OpenAuthenticodeSignature', 'Add-OpenAuthenticodeSignature', 'Clear-OpenAuthenticodeSignature')) {
            Get-Command $name -Module Devolutions.Psign -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }

    It 'clears psc1 XML signature blocks through Unprotect-PsignSignature' {
        $path = Join-Path $script:TempRoot 'console.psc1'
        @'
<PSConsoleFile>
</PSConsoleFile>
<!-- SIG # Begin signature block -->
<!-- fake -->
<!-- SIG # End signature block -->
'@ | Set-Content -LiteralPath $path -Encoding UTF8

        Unprotect-PsignSignature -LiteralPath $path

        (Get-Content -LiteralPath $path -Raw) | Should -Not -Match 'SIG # Begin signature block'
    }

    It 'clears PE signatures without a provider override' {
        $source = Join-Path $script:RepoRoot 'tests\fixtures\pe-authenticode-upstream\tiny32.signed.efi'
        $path = Join-Path $script:TempRoot 'tiny32.clear.efi'
        Copy-Item -LiteralPath $source -Destination $path

        $before = Get-PsignSignature -LiteralPath $path -SkipTrust
        $before.Status | Should -Be ([System.Management.Automation.SignatureStatus]::Valid)
        $before.SignedCms | Should -Not -BeNullOrEmpty
        $before.Certificate | Should -Not -BeNullOrEmpty

        Unprotect-PsignSignature -LiteralPath $path

        $after = Get-PsignSignature -LiteralPath $path -SkipTrust
        $after.Status | Should -Be ([System.Management.Automation.SignatureStatus]::NotSigned)
    }

    It 'appends PE signatures through Set-PsignSignature -AppendSignature' {
        $source = Join-Path $script:RepoRoot 'tests\fixtures\pe-authenticode-upstream\tiny32.signed.efi'
        $pfxPath = Join-Path $script:RepoRoot 'tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx'
        $path = Join-Path $script:TempRoot 'tiny32.append.efi'
        Copy-Item -LiteralPath $source -Destination $path

        $before = Get-PsignSignature -LiteralPath $path -SkipTrust
        $before.SignatureCount | Should -Be 1

        Set-PsignSignature -LiteralPath $path -PfxPath $pfxPath -Password (ConvertTo-SecureString 'CodeSign123!' -AsPlainText -Force) -AppendSignature | Out-Null

        $after = Get-PsignSignature -LiteralPath $path -SkipTrust
        $after.SignatureCount | Should -Be 2
    }

    It 'replaces PE signatures by default through Set-PsignSignature' {
        $source = Join-Path $script:RepoRoot 'tests\fixtures\pe-authenticode-upstream\tiny32.signed.efi'
        $pfxPath = Join-Path $script:RepoRoot 'tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx'
        $path = Join-Path $script:TempRoot 'tiny32.replace.efi'
        Copy-Item -LiteralPath $source -Destination $path

        $before = Get-PsignSignature -LiteralPath $path -SkipTrust
        $before.SignatureCount | Should -Be 1

        Set-PsignSignature -LiteralPath $path -PfxPath $pfxPath -Password (ConvertTo-SecureString 'CodeSign123!' -AsPlainText -Force) | Out-Null

        $after = Get-PsignSignature -LiteralPath $path -SkipTrust
        $after.SignatureCount | Should -Be 1
        $after.SignedCms | Should -Not -BeNullOrEmpty
    }

    It 'signs unsigned PE files through Set-PsignSignature -SkipSigned' {
        $source = Join-Path $script:RepoRoot 'tests\fixtures\pe-authenticode-upstream\tiny32.efi'
        $pfxPath = Join-Path $script:RepoRoot 'tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx'
        $path = Join-Path $script:TempRoot 'tiny32.skip-signed-unsigned.efi'
        Copy-Item -LiteralPath $source -Destination $path

        $signed = Set-PsignSignature -LiteralPath $path -PfxPath $pfxPath -Password (ConvertTo-SecureString 'CodeSign123!' -AsPlainText -Force) -SkipSigned

        $signed.Status | Should -Be ([System.Management.Automation.SignatureStatus]::Valid)
        $after = Get-PsignSignature -LiteralPath $path -SkipTrust
        $after.SignatureCount | Should -Be 1
    }

    It 'skips already signed PE files through Set-PsignSignature -SkipSigned' {
        $source = Join-Path $script:RepoRoot 'tests\fixtures\pe-authenticode-upstream\tiny32.signed.efi'
        $pfxPath = Join-Path $script:RepoRoot 'tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx'
        $path = Join-Path $script:TempRoot 'tiny32.skip-signed-existing.efi'
        Copy-Item -LiteralPath $source -Destination $path

        $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $signed = Set-PsignSignature -LiteralPath $path -PfxPath $pfxPath -Password (ConvertTo-SecureString 'CodeSign123!' -AsPlainText -Force) -SkipSigned
        $after = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))

        $signed.Status | Should -Be ([System.Management.Automation.SignatureStatus]::Valid)
        $after | Should -Be $before
        $signature = Get-PsignSignature -LiteralPath $path -SkipTrust
        $signature.SignatureCount | Should -Be 1
    }
}
