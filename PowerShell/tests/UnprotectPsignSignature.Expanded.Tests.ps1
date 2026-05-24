Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Import-Module $modulePath -Force

    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-unprotect-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Create a signing cert
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign unprotect test',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $ekuOids = [System.Security.Cryptography.OidCollection]::new()
    $null = $ekuOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false))
    $script:Cert = $request.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))

    $script:CertPath = Join-Path $script:TestDir 'signer.cer'
    $script:KeyPath = Join-Path $script:TestDir 'signer.key'
    [System.IO.File]::WriteAllBytes($script:CertPath, $script:Cert.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [System.IO.File]::WriteAllText($script:KeyPath,
        [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()))

    function script:New-SignedScript {
        param([string]$Name, [string]$Content = '"hello"', [string]$Extension = '.ps1')
        $path = Join-Path $script:TestDir "$Name$Extension"
        Set-Content -LiteralPath $path -Value $Content -Encoding UTF8
        $null = Set-PsignSignature -LiteralPath $path -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $path
    }

    function script:New-SignedXmlFile {
        param([string]$Name, [string]$Extension = '.ps1xml')
        $xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Types>
  <Type>
    <Name>System.String</Name>
    <Members>
      <ScriptProperty>
        <Name>Reversed</Name>
        <GetScriptBlock>
          `$this[-1..(-`$this.Length)] -join ''
        </GetScriptBlock>
      </ScriptProperty>
    </Members>
  </Type>
</Types>
"@
        $path = Join-Path $script:TestDir "$Name$Extension"
        Set-Content -LiteralPath $path -Value $xmlContent -Encoding UTF8
        $null = Set-PsignSignature -LiteralPath $path -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $path
    }
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir
    }
}

Describe 'Unprotect-PsignSignature basic removal' {
    It 'removes signature from .ps1 file' {
        $path = New-SignedScript -Name 'basic-removal'
        $beforeContent = Get-Content $path -Raw
        $beforeContent | Should -BeLike '*SIG*'
        Unprotect-PsignSignature -LiteralPath $path
        $afterContent = Get-Content $path -Raw
        $afterContent | Should -Not -BeLike '*SIG*'
        $afterContent.Trim() | Should -Be '"hello"'
    }

    It 'removes signature from .psm1 file' {
        $path = New-SignedScript -Name 'module-removal' -Extension '.psm1' -Content 'function Get-Thing { "thing" }'
        Unprotect-PsignSignature -LiteralPath $path
        $afterContent = Get-Content $path -Raw
        $afterContent | Should -Not -BeLike '*SIG*'
        $afterContent.Trim() | Should -Be 'function Get-Thing { "thing" }'
    }

    It 'removes signature from .psd1 file' {
        $path = New-SignedScript -Name 'data-removal' -Extension '.psd1' -Content '@{ ModuleVersion = "1.0" }'
        Unprotect-PsignSignature -LiteralPath $path
        $afterContent = Get-Content $path -Raw
        $afterContent | Should -Not -BeLike '*SIG*'
    }
}

Describe 'Unprotect-PsignSignature XML formats' {
    It 'removes signature from .ps1xml file' {
        $path = New-SignedXmlFile -Name 'xml-removal' -Extension '.ps1xml'
        $beforeContent = Get-Content $path -Raw
        $beforeContent | Should -BeLike '*Signature*'
        Unprotect-PsignSignature -LiteralPath $path
        $afterContent = Get-Content $path -Raw
        # Should not contain XML signature block
        $afterContent | Should -Not -BeLike '*<Signature*'
    }

    It 'removes signature from .cdxml file' {
        $cdxmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<PowerShellMetadata xmlns="http://schemas.microsoft.com/cmdlets-over-objects/2009/11">
  <Class ClassName="ROOT\cimv2\Win32_Process" />
</PowerShellMetadata>
"@
        $path = Join-Path $script:TestDir 'cdxml-removal.cdxml'
        Set-Content -LiteralPath $path -Value $cdxmlContent -Encoding UTF8
        $null = Set-PsignSignature -LiteralPath $path -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        Unprotect-PsignSignature -LiteralPath $path
        $afterContent = Get-Content $path -Raw
        $afterContent | Should -Not -BeLike '*<Signature*'
    }
}

Describe 'Unprotect-PsignSignature -WhatIf' {
    It 'does not modify file when -WhatIf is used' {
        $path = New-SignedScript -Name 'whatif-test'
        $beforeContent = Get-Content $path -Raw
        Unprotect-PsignSignature -LiteralPath $path -WhatIf
        $afterContent = Get-Content $path -Raw
        $afterContent | Should -Be $beforeContent
    }
}

Describe 'Unprotect-PsignSignature -FilePath with wildcards' {
    It 'processes multiple files via wildcard' {
        $null = New-SignedScript -Name 'wild-a' -Extension '.ps1'
        $null = New-SignedScript -Name 'wild-b' -Extension '.ps1'
        Unprotect-PsignSignature -FilePath (Join-Path $script:TestDir 'wild-*.ps1')
        foreach ($name in @('wild-a.ps1', 'wild-b.ps1')) {
            $content = Get-Content (Join-Path $script:TestDir $name) -Raw
            $content | Should -Not -BeLike '*SIG*'
        }
    }
}

Describe 'Unprotect-PsignSignature error handling' {
    It 'writes error for non-existent file' {
        $result = Unprotect-PsignSignature -LiteralPath (Join-Path $script:TestDir 'nope.ps1') -ErrorAction SilentlyContinue -ErrorVariable unprotErr
        $unprotErr | Should -Not -BeNullOrEmpty
    }

    It 'handles already-unsigned file gracefully' {
        $path = Join-Path $script:TestDir 'already-unsigned.ps1'
        Set-Content -LiteralPath $path -Value '"no signature"' -Encoding UTF8
        # Should not throw on unsigned file
        Unprotect-PsignSignature -LiteralPath $path -ErrorAction SilentlyContinue
        $afterContent = Get-Content $path -Raw
        $afterContent.Trim() | Should -Be '"no signature"'
    }
}

Describe 'Unprotect-PsignSignature encoding preservation' {
    It 'preserves UTF-8 BOM encoding' {
        $path = Join-Path $script:TestDir 'utf8bom.ps1'
        $encoding = [System.Text.UTF8Encoding]::new($true)
        $content = '"BOM test"'
        [System.IO.File]::WriteAllText($path, $content, $encoding)
        $null = Set-PsignSignature -LiteralPath $path -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        Unprotect-PsignSignature -LiteralPath $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        # UTF-8 BOM: EF BB BF
        $bytes[0] | Should -Be 0xEF
        $bytes[1] | Should -Be 0xBB
        $bytes[2] | Should -Be 0xBF
    }
}
