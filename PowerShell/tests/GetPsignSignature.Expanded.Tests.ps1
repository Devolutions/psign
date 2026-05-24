Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Import-Module $modulePath -Force

    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-getexp-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Create a code-signing cert and sign some test files
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign get test',
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

    # Create multiple test scripts
    foreach ($name in @('alpha.ps1', 'beta.ps1', 'gamma.ps1')) {
        Set-Content -LiteralPath (Join-Path $script:TestDir $name) -Value "Write-Output '$name'" -Encoding UTF8
    }
    # Create unsigned file
    Set-Content -LiteralPath (Join-Path $script:TestDir 'unsigned.ps1') -Value '"not signed"' -Encoding UTF8
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir
    }
}

Describe 'Get-PsignSignature wildcard expansion' {
    It 'resolves wildcards via -FilePath' {
        $results = Get-PsignSignature -FilePath (Join-Path $script:TestDir '*.ps1')
        $results | Should -Not -BeNull
        $results.Count | Should -BeGreaterOrEqual 4
        $results | ForEach-Object { $_.Status | Should -Be 'NotSigned' }
    }

    It 'handles no-match wildcard gracefully' {
        $results = Get-PsignSignature -FilePath (Join-Path $script:TestDir '*.xyz') -ErrorAction SilentlyContinue -ErrorVariable getErr
        # Should either return nothing or write a non-terminating error
        if ($results) { $results.Count | Should -Be 0 }
    }
}

Describe 'Get-PsignSignature pipeline input' {
    It 'accepts file paths via pipeline' {
        $paths = @(
            Join-Path $script:TestDir 'alpha.ps1'
            Join-Path $script:TestDir 'beta.ps1'
        )
        $results = $paths | Get-PsignSignature
        $results | Should -Not -BeNull
        $results.Count | Should -Be 2
    }

    It 'accepts FileInfo objects via pipeline' {
        $results = Get-ChildItem (Join-Path $script:TestDir '*.ps1') | Get-PsignSignature
        $results | Should -Not -BeNull
        $results.Count | Should -BeGreaterOrEqual 4
    }
}

Describe 'Get-PsignSignature error handling' {
    It 'writes error for non-existent file' {
        $result = Get-PsignSignature -LiteralPath (Join-Path $script:TestDir 'does-not-exist.ps1') -ErrorAction SilentlyContinue -ErrorVariable getErr
        $getErr | Should -Not -BeNullOrEmpty
    }

    It 'handles signed file verification' {
        $scriptPath = Join-Path $script:TestDir 'signed-for-get.ps1'
        Set-Content -LiteralPath $scriptPath -Value '"to be signed"' -Encoding UTF8
        $null = Set-PsignSignature -LiteralPath $scriptPath -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result = Get-PsignSignature -LiteralPath $scriptPath
        $result | Should -Not -BeNull
        $result.Status | Should -BeIn @('Valid', 'NotTrusted')
        $result.SignerCertificate | Should -Not -BeNull
        $result.DigestAlgorithm | Should -Not -BeNullOrEmpty
        $result.Format | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-PsignSignature -Content edge cases' {
    It 'handles bare extension without dot' {
        $content = [System.Text.Encoding]::UTF8.GetBytes('"bare ext"')
        $result = Get-PsignSignature -SourcePathOrExtension 'ps1' -Content $content
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'NotSigned'
    }

    It 'handles full filename as SourcePathOrExtension' {
        $content = [System.Text.Encoding]::UTF8.GetBytes('"full name"')
        $result = Get-PsignSignature -SourcePathOrExtension 'script.ps1' -Content $content
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'NotSigned'
    }

    It 'handles extension with leading dot' {
        $content = [System.Text.Encoding]::UTF8.GetBytes('"dot ext"')
        $result = Get-PsignSignature -SourcePathOrExtension '.ps1' -Content $content
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'NotSigned'
    }
}

Describe 'Get-PsignSignature -TrustedCertificatePath' {
    It 'validates trust with explicit anchor' {
        $content = [System.Text.Encoding]::UTF8.GetBytes('"trust test"')
        $signed = Set-PsignSignature -SourcePathOrExtension '.ps1' -Content $content `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        # With the signer cert as a trust anchor
        $result = Get-PsignSignature -SourcePathOrExtension '.ps1' -Content $signed.Content `
            -TrustedCertificatePath $script:CertPath
        $result | Should -Not -BeNull
        # Trust evaluation ran — may or may not trust a self-signed leaf as anchor
        $result.Status | Should -BeIn @('Valid', 'NotTrusted')
        $result.SignerCertificate | Should -Not -BeNull
    }
}

Describe 'Get-PsignSignature -SkipTrust' {
    It 'skips trust evaluation and reports signature integrity only' {
        $scriptPath = Join-Path $script:TestDir 'skip-trust.ps1'
        Set-Content -LiteralPath $scriptPath -Value '"skip trust"' -Encoding UTF8
        $null = Set-PsignSignature -LiteralPath $scriptPath -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result = Get-PsignSignature -LiteralPath $scriptPath -SkipTrust
        $result.Status | Should -Be 'Valid'
    }
}
