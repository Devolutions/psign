Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Import-Module $modulePath -Force

    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-setval-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Create a valid code-signing certificate
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign validation test',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
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
    $script:PfxPassword = 'TestPassword123!'
    [System.IO.File]::WriteAllBytes($script:PfxPath, $script:Cert.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $script:PfxPassword))

    # Create a cert WITHOUT CodeSigning EKU
    $noEkuRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $noEkuRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign no-eku test',
        $noEkuRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $noEkuRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    # Add EKU for Server Auth only (not code signing)
    $serverEku = [System.Security.Cryptography.OidCollection]::new()
    $null = $serverEku.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    $noEkuRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($serverEku, $false))
    $script:NoCodeSigningCert = $noEkuRequest.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))

    # Create a cert without DigitalSignature KeyUsage
    $noKuRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $noKuRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign no-ku test',
        $noKuRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $noKuRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment, $true))
    $script:NoDigitalSigCert = $noKuRequest.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))

    function script:New-TestScript {
        param([string]$Name = 'test.ps1')
        $path = Join-Path $script:TestDir $Name
        Set-Content -LiteralPath $path -Value '"hello world"' -Encoding UTF8
        $path
    }
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir
    }
}

Describe 'Set-PsignSignature signing material validation' {
    It 'rejects when no signing material is supplied' {
        $scriptPath = New-TestScript -Name 'no-material.ps1'
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $scriptPath -ErrorAction Stop 2>&1
        } catch { $err = $_ }
        $err | Should -Not -BeNull
        $err.FullyQualifiedErrorId | Should -BeLike 'PsignSignatureSigningMaterialRequired*'
    }

    It 'rejects -CertificatePath without -PrivateKeyPath' {
        $scriptPath = New-TestScript -Name 'cert-only.ps1'
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $scriptPath -CertificatePath $script:CertPath -ErrorAction Stop 2>&1
        } catch { $err = $_ }
        $err | Should -Not -BeNull
        $err.FullyQualifiedErrorId | Should -BeLike 'PsignSignatureIncompleteKeyPair*'
    }

    It 'rejects -PrivateKeyPath without -CertificatePath' {
        $scriptPath = New-TestScript -Name 'key-only.ps1'
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $scriptPath -PrivateKeyPath $script:KeyPath -ErrorAction Stop 2>&1
        } catch { $err = $_ }
        $err | Should -Not -BeNull
        $err.FullyQualifiedErrorId | Should -BeLike 'PsignSignatureIncompleteKeyPair*'
    }

    It 'rejects certificate without CodeSigning EKU' {
        $scriptPath = New-TestScript -Name 'no-eku.ps1'
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $scriptPath -Certificate $script:NoCodeSigningCert -ErrorAction Stop 2>&1
        } catch { $err = $_ }
        $err | Should -Not -BeNull
        $err.Exception.Message | Should -BeLike '*not valid for code signing*'
    }

    It 'rejects certificate without DigitalSignature KeyUsage' {
        $scriptPath = New-TestScript -Name 'no-ku.ps1'
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $scriptPath -Certificate $script:NoDigitalSigCert -ErrorAction Stop 2>&1
        } catch { $err = $_ }
        $err | Should -Not -BeNull
        $err.Exception.Message | Should -BeLike '*not valid for digital signatures*'
    }

    It 'rejects multiple signing sources' {
        $scriptPath = New-TestScript -Name 'multi-source.ps1'
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $scriptPath -Certificate $script:Cert -PfxPath $script:PfxPath -ErrorAction Stop 2>&1
        } catch { $err = $_ }
        $err | Should -Not -BeNull
        $err.FullyQualifiedErrorId | Should -BeLike 'PsignSignatureSigningMaterialRequired*'
    }
}

Describe 'Set-PsignSignature -PfxPath signing' {
    It 'signs with -PfxPath and -Password' {
        $scriptPath = New-TestScript -Name 'pfx-sign.ps1'
        $secPw = ConvertTo-SecureString $script:PfxPassword -AsPlainText -Force
        $result = Set-PsignSignature -LiteralPath $scriptPath -PfxPath $script:PfxPath -Password $secPw
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
        $result.SignerCertificate.Thumbprint | Should -Be $script:Cert.Thumbprint
    }

    It 'fails with wrong PFX password' {
        $scriptPath = New-TestScript -Name 'pfx-bad-pw.ps1'
        $badPw = ConvertTo-SecureString 'wrong' -AsPlainText -Force
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $scriptPath -PfxPath $script:PfxPath -Password $badPw -ErrorAction Stop
        } catch { $err = $_ }
        $err | Should -Not -BeNull
    }
}

Describe 'Set-PsignSignature -OutputPath' {
    It 'writes signed output to a separate file' {
        $scriptPath = New-TestScript -Name 'output-src.ps1'
        $outPath = Join-Path $script:TestDir 'output-dest.ps1'
        $result = Set-PsignSignature -LiteralPath $scriptPath -OutputPath $outPath `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
        Test-Path $outPath | Should -BeTrue
        # Original should NOT be modified
        (Get-Content $scriptPath -Raw) | Should -Not -BeLike '*SIG*'
    }

    It 'rejects -OutputPath with multiple input files' {
        $s1 = New-TestScript -Name 'multi1.ps1'
        $s2 = New-TestScript -Name 'multi2.ps1'
        $outPath = Join-Path $script:TestDir 'multi-out.ps1'
        $err = $null
        try {
            Set-PsignSignature -LiteralPath $s1, $s2 -OutputPath $outPath `
                -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath -ErrorAction Stop
        } catch { $err = $_ }
        $err | Should -Not -BeNull
        $err.FullyQualifiedErrorId | Should -BeLike 'PsignSignatureOutputPathRequiresSingleInput*'
    }
}

Describe 'Set-PsignSignature -Force and read-only files' {
    It 'fails on read-only file without -Force' {
        $scriptPath = New-TestScript -Name 'readonly.ps1'
        Set-ItemProperty -LiteralPath $scriptPath -Name IsReadOnly -Value $true
        $result = Set-PsignSignature -LiteralPath $scriptPath `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath -ErrorAction SilentlyContinue -ErrorVariable setErr
        $setErr | Should -Not -BeNullOrEmpty
        $setErr[0].Exception.Message | Should -BeLike '*read-only*'
        # Cleanup
        Set-ItemProperty -LiteralPath $scriptPath -Name IsReadOnly -Value $false
    }

    It 'signs read-only file with -Force' {
        $scriptPath = New-TestScript -Name 'force-readonly.ps1'
        Set-ItemProperty -LiteralPath $scriptPath -Name IsReadOnly -Value $true
        $result = Set-PsignSignature -LiteralPath $scriptPath -Force `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
        # File should be read-only again after signing
        (Get-ItemProperty -LiteralPath $scriptPath).IsReadOnly | Should -BeTrue
        # Cleanup
        Set-ItemProperty -LiteralPath $scriptPath -Name IsReadOnly -Value $false
    }
}

Describe 'Set-PsignSignature -HashAlgorithm variants' {
    It 'signs with Sha384' {
        $scriptPath = New-TestScript -Name 'sha384.ps1'
        $result = Set-PsignSignature -LiteralPath $scriptPath -HashAlgorithm Sha384 `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
        # DigestAlgorithm returns OID: 2.16.840.1.101.3.4.2.2 for SHA-384
        $result.DigestAlgorithm | Should -BeIn @('2.16.840.1.101.3.4.2.2', 'sha384', 'SHA384', 'Sha384')
    }

    It 'signs with Sha512' {
        $scriptPath = New-TestScript -Name 'sha512.ps1'
        $result = Set-PsignSignature -LiteralPath $scriptPath -HashAlgorithm Sha512 `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
        # DigestAlgorithm returns OID: 2.16.840.1.101.3.4.2.3 for SHA-512
        $result.DigestAlgorithm | Should -BeIn @('2.16.840.1.101.3.4.2.3', 'sha512', 'SHA512', 'Sha512')
    }
}

Describe 'Set-PsignSignature -IncludeChain modes' {
    It 'signs with -IncludeChain Signer (no chain certs embedded)' {
        $scriptPath = New-TestScript -Name 'chain-signer.ps1'
        $result = Set-PsignSignature -LiteralPath $scriptPath -IncludeChain Signer `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
    }

    It 'signs with -IncludeChain All' {
        $scriptPath = New-TestScript -Name 'chain-all.ps1'
        $result = Set-PsignSignature -LiteralPath $scriptPath -IncludeChain All `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
    }
}
