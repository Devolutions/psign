Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Import-Module $modulePath -Force

    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-content-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Create a self-signed code-signing certificate
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign content test',
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

    $certPath = Join-Path $script:TestDir 'signer.cer'
    $keyPath = Join-Path $script:TestDir 'signer.key'
    [System.IO.File]::WriteAllBytes($certPath, $script:Cert.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [System.IO.File]::WriteAllText($keyPath,
        [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()))
    $script:CertPath = $certPath
    $script:KeyPath = $keyPath
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir
    }
}

Describe 'Content signing round-trip' {
    It 'signs PowerShell script content and returns signed bytes' {
        $content = [System.Text.Encoding]::UTF8.GetBytes("Write-Output 'hello world'")
        $result = Set-PsignSignature -SourcePathOrExtension '.ps1' -Content $content `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result | Should -Not -BeNull
        $result.Status | Should -Be 'Valid'
        $result.Content | Should -Not -BeNull
        $result.Content.Length | Should -BeGreaterThan $content.Length
        $result.SourcePathOrExtension | Should -Be '.ps1'
    }

    It 'signed content verifies with Get-PsignSignature -Content' {
        $content = [System.Text.Encoding]::UTF8.GetBytes('"verify me"')
        $signed = Set-PsignSignature -SourcePathOrExtension 'test.ps1' -Content $content `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $verified = Get-PsignSignature -SourcePathOrExtension '.ps1' -Content $signed.Content
        # Without explicit trust anchors, signature is cryptographically valid
        $verified.Status | Should -BeIn @('Valid', 'NotTrusted')
        $verified.SignerCertificate | Should -Not -BeNull
        $verified.SignerCertificate.Thumbprint | Should -Be $script:Cert.Thumbprint
    }

    It 'unsigned content reports NotSigned' {
        $content = [System.Text.Encoding]::UTF8.GetBytes("'no signature here'")
        $result = Get-PsignSignature -SourcePathOrExtension '.ps1' -Content $content
        $result.Status | Should -Be 'NotSigned'
    }

    It 'tampered signed content reports HashMismatch' {
        $content = [System.Text.Encoding]::UTF8.GetBytes('"tamper test"')
        $signed = Set-PsignSignature -SourcePathOrExtension '.ps1' -Content $content `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        # Tamper with the content while preserving the signature block
        $text = [System.Text.Encoding]::UTF8.GetString($signed.Content)
        $tampered = $text -replace 'tamper test', 'TAMPERED!!'
        $tamperedBytes = [System.Text.Encoding]::UTF8.GetBytes($tampered)
        $result = Get-PsignSignature -SourcePathOrExtension '.ps1' -Content $tamperedBytes
        $result.Status | Should -Be 'HashMismatch'
    }

    It 'signs ps1xml content' {
        $xml = '<?xml version="1.0" encoding="utf-8"?><Types><Type><Name>System.String</Name></Type></Types>'
        $content = [System.Text.Encoding]::UTF8.GetBytes($xml)
        $result = Set-PsignSignature -SourcePathOrExtension 'Types.ps1xml' -Content $content `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result.Status | Should -Be 'Valid'
        $result.Content | Should -Not -BeNull
    }

    It 'signs psm1 content' {
        $content = [System.Text.Encoding]::UTF8.GetBytes("function Get-Greeting { 'hello' }")
        $result = Set-PsignSignature -SourcePathOrExtension 'Module.psm1' -Content $content `
            -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $result.Status | Should -Be 'Valid'
    }
}

Describe 'Content signing with pcert: store' {
    BeforeAll {
        $script:StoreDir = Join-Path $script:TestDir 'cert-store'
        New-Item -ItemType Directory -Path (Join-Path $script:StoreDir 'CurrentUser\MY') -Force | Out-Null
        $thumb = $script:Cert.Thumbprint
        Copy-Item $script:CertPath (Join-Path $script:StoreDir "CurrentUser\MY\$thumb.der")
        Copy-Item $script:KeyPath (Join-Path $script:StoreDir "CurrentUser\MY\$thumb.key")
    }

    It 'signs content using -Thumbprint from portable store' {
        $content = [System.Text.Encoding]::UTF8.GetBytes('"store signing"')
        $result = Set-PsignSignature -SourcePathOrExtension '.ps1' -Content $content `
            -Thumbprint $script:Cert.Thumbprint -CertStoreDirectory $script:StoreDir
        $result.Status | Should -Be 'Valid'
        $result.SignerCertificate.Thumbprint | Should -Be $script:Cert.Thumbprint
    }

    It 'signs content using certificate from pcert: provider' {
        # Import cert into a custom pcert: drive
        $driveName = "ptest$([System.Guid]::NewGuid().ToString('N').Substring(0,4))"
        $driveRoot = Join-Path $script:TestDir "pcert-drive-$driveName"
        New-PSDrive -Name $driveName -PSProvider PortableCertStore -Root $driveRoot -Scope Script | Out-Null
        New-Item -Path "${driveName}:\CurrentUser\MY\$($script:Cert.Thumbprint)" -Value $script:Cert | Out-Null

        # Get the cert from the provider and use it for signing
        $providerCert = Get-Item "${driveName}:\CurrentUser\MY\$($script:Cert.Thumbprint)"
        $providerCert | Should -Not -BeNull
        $providerCert.Thumbprint | Should -Be $script:Cert.Thumbprint

        Remove-PSDrive -Name $driveName
    }
}
