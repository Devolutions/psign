Set-StrictMode -Version Latest

function script:Ensure-PortableSignatureModule {
    if (-not (Get-Command Get-PsignSignature -ErrorAction SilentlyContinue)) {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $modulePath = Join-Path (Join-Path $repoRoot 'PowerShell\Devolutions.Psign') 'Devolutions.Psign.psd1'
        Import-Module $modulePath -Force
    }
}

Describe 'Portable PowerShell Authenticode compatibility' {
    BeforeAll {
        Ensure-PortableSignatureModule
        $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $script:TempRoot | Out-Null
    }

    AfterAll {
        if ($script:TempRoot) {
            Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'matches built-in content and literal-path binding metadata where portable-safe' {
        foreach ($commandName in @('Get-PsignSignature', 'Set-PsignSignature')) {
            $command = Get-Command $commandName

            $command.Parameters['LiteralPath'].Aliases | Should -Contain 'PSPath'
            $command.Parameters['LiteralPath'].Aliases | Should -Contain 'LP'

            $contentSet = $command.ParameterSets | Where-Object Name -EQ 'Content'
            $sourceParameter = $contentSet.Parameters | Where-Object Name -EQ 'SourcePathOrExtension'
            $contentParameter = $contentSet.Parameters | Where-Object Name -EQ 'Content'

            $sourceParameter.ValueFromPipeline | Should -BeTrue
            $sourceParameter.ValueFromPipelineByPropertyName | Should -BeTrue
            $contentParameter.ValueFromPipelineByPropertyName | Should -BeTrue
            $command.Parameters['Content'].Attributes.TypeId.Name | Should -Contain 'ValidateNotNullOrEmptyAttribute'
        }
    }

    It 'preserves backward-compatible aliases Get-PortableSignature and Set-PortableSignature' {
        Get-Command Get-PortableSignature -ErrorAction Stop | Should -Not -BeNullOrEmpty
        Get-Command Set-PortableSignature -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'exposes built-in enum types on compatibility properties' {
        $scriptPath = Join-Path $script:TempRoot 'unsigned.ps1'
        Set-Content -LiteralPath $scriptPath -Value '"unsigned"' -Encoding UTF8

        $signature = Get-PsignSignature -LiteralPath $scriptPath

        $signature.Status.GetType().FullName | Should -Be 'System.Management.Automation.SignatureStatus'
        $signature.Status | Should -Be ([System.Management.Automation.SignatureStatus]::NotSigned)
        $signature.SignatureType.GetType().FullName | Should -Be 'System.Management.Automation.SignatureType'
        $signature.SignatureType | Should -Be ([System.Management.Automation.SignatureType]::None)
        $signature.IsOSBinary | Should -BeFalse
        $signature.PSObject.Properties.Name | Should -Contain 'SubjectAlternativeName'
        $signature.PSObject.Properties.Name | Should -Contain 'PortableStatus'
    }
}
