Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Import-Module $modulePath -Force

    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-protect-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Create a signing cert
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign protect test',
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

    # Create a PFX
    $script:PfxPath = Join-Path $script:TestDir 'signer.pfx'
    $script:PfxPassword = 'ProtectTest123!'
    [System.IO.File]::WriteAllBytes($script:PfxPath, $script:Cert.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $script:PfxPassword))

    function script:New-TestModule {
        param([string]$Name, [switch]$WithManifest, [int]$ExtraFiles = 0)
        $modDir = Join-Path $script:TestDir $Name
        New-Item -ItemType Directory -Path $modDir -Force | Out-Null

        Set-Content -LiteralPath (Join-Path $modDir "$Name.psm1") -Value "function Get-$Name { '$Name' }" -Encoding UTF8

        if ($WithManifest) {
            $psdContent = @"
@{
    ModuleVersion = '1.0.0'
    RootModule = '$Name.psm1'
    FunctionsToExport = @('Get-$Name')
}
"@
            Set-Content -LiteralPath (Join-Path $modDir "$Name.psd1") -Value $psdContent -Encoding UTF8
        }

        for ($i = 1; $i -le $ExtraFiles; $i++) {
            Set-Content -LiteralPath (Join-Path $modDir "helper$i.ps1") -Value "# helper $i" -Encoding UTF8
        }
        $modDir
    }
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir
    }
}

Describe 'Protect-PsignModule basic signing' {
    It 'signs all module files with -CertificatePath and -PrivateKeyPath' {
        $modDir = New-TestModule -Name 'BasicProtect' -WithManifest
        $result = Protect-PsignModule -Path $modDir -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.TotalFiles | Should -BeGreaterOrEqual 2
        $result.Succeeded | Should -Be $result.TotalFiles
        $result.Failed | Should -Be 0
    }

    It 'signs module with -PfxPath and -Password' {
        $modDir = New-TestModule -Name 'PfxProtect' -WithManifest
        $secPw = ConvertTo-SecureString $script:PfxPassword -AsPlainText -Force
        $result = Protect-PsignModule -Path $modDir -PfxPath $script:PfxPath -Password $secPw
        $result | Should -Not -BeNull
        $result.Succeeded | Should -Be $result.TotalFiles
    }
}

Describe 'Protect-PsignModule error handling' {
    It 'errors for non-existent path' {
        $err = $null
        try {
            Protect-PsignModule -Path (Join-Path $script:TestDir 'ghost-module') `
                -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath -ErrorAction Stop
        } catch { $err = $_ }
        $err | Should -Not -BeNull
    }

    It 'reports failures with no signing material' {
        $modDir = New-TestModule -Name 'NoMaterial' -WithManifest
        $result = Protect-PsignModule -Path $modDir -WarningAction SilentlyContinue
        $result | Should -Not -BeNull
        $result.Failed | Should -BeGreaterThan 0
        $result.Succeeded | Should -Be 0
    }
}

Describe 'Protect-PsignModule -IncludeUnreferenced' {
    It 'signs unreferenced files when -IncludeUnreferenced is set' {
        $modDir = New-TestModule -Name 'UnrefProtect' -WithManifest -ExtraFiles 2
        $result = Protect-PsignModule -Path $modDir -IncludeUnreferenced `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        # Should sign manifest, root module, AND the 2 extra helper files
        $result.TotalFiles | Should -BeGreaterOrEqual 4
        $result.Succeeded | Should -Be $result.TotalFiles
    }

    It 'skips unreferenced files without -IncludeUnreferenced' {
        $modDir = New-TestModule -Name 'SkipUnref' -WithManifest -ExtraFiles 2
        $result = Protect-PsignModule -Path $modDir `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        # Only manifest-referenced files: .psd1 + .psm1
        $result.TotalFiles | Should -Be 2
    }
}

Describe 'Protect-PsignModule result properties' {
    It 'returns PsignModuleSigningResult with per-file details' {
        $modDir = New-TestModule -Name 'ResultProps' -WithManifest -ExtraFiles 1
        $result = Protect-PsignModule -Path $modDir -IncludeUnreferenced `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.PSObject.Properties.Name | Should -Contain 'ModulePath'
        $result.PSObject.Properties.Name | Should -Contain 'TotalFiles'
        $result.PSObject.Properties.Name | Should -Contain 'Succeeded'
        $result.PSObject.Properties.Name | Should -Contain 'Failed'
        $result.PSObject.Properties.Name | Should -Contain 'Files'
        $result.Files | Should -Not -BeNullOrEmpty
        $result.Files[0].PSObject.Properties.Name | Should -Contain 'RelativePath'
        $result.Files[0].PSObject.Properties.Name | Should -Contain 'Status'
    }
}

Describe 'Protect-PsignModule and Test-PsignModule round-trip' {
    It 'module passes AllSigned after Protect-PsignModule' {
        $modDir = New-TestModule -Name 'RoundTrip' -WithManifest -ExtraFiles 1
        $null = Protect-PsignModule -Path $modDir -IncludeUnreferenced `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $testResult = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust -IncludeUnreferenced
        $testResult | Should -Not -BeNull
        $testResult.Valid | Should -BeTrue
    }
}
