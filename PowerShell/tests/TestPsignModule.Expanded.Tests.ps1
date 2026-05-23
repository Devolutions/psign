Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Import-Module $modulePath -Force

    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-testmod-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    # Create a signing cert
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign testmod test',
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

    function script:New-TestModule {
        param([string]$Name, [switch]$WithManifest, [switch]$Sign, [int]$ExtraFiles = 0)
        $modDir = Join-Path $script:TestDir $Name
        New-Item -ItemType Directory -Path $modDir -Force | Out-Null

        # Root module
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

        if ($Sign) {
            Get-ChildItem -LiteralPath $modDir -Filter '*.ps*' -File | ForEach-Object {
                $null = Set-PsignSignature -LiteralPath $_.FullName -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
            }
        }
        $modDir
    }
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir
    }
}

Describe 'Test-PsignModule -Policy AllSigned' {
    It 'passes for a fully signed module' {
        $modDir = New-TestModule -Name 'AllSignedPass' -WithManifest -Sign
        $result = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust
        $result | Should -Not -BeNull
        $result.Valid | Should -BeTrue
        $result.Policy | Should -Be 'AllSigned'
    }

    It 'fails for an unsigned module' {
        $modDir = New-TestModule -Name 'AllSignedFail' -WithManifest
        $result = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust
        $result | Should -Not -BeNull
        $result.Valid | Should -BeFalse
    }
}

Describe 'Test-PsignModule -Policy RemoteSigned' {
    It 'passes for signed module (RemoteSigned behaves like AllSigned for our portable use)' {
        $modDir = New-TestModule -Name 'RemoteSignedPass' -WithManifest -Sign
        $result = Test-PsignModule -Path $modDir -Policy RemoteSigned -SkipTrust
        $result | Should -Not -BeNull
        $result.Valid | Should -BeTrue
    }

    It 'fails for unsigned module under RemoteSigned' {
        $modDir = New-TestModule -Name 'RemoteSignedFail' -WithManifest
        $result = Test-PsignModule -Path $modDir -Policy RemoteSigned -SkipTrust
        $result | Should -Not -BeNull
        $result.Valid | Should -BeFalse
    }
}

Describe 'Test-PsignModule error handling' {
    It 'errors for non-existent path' {
        $err = $null
        try {
            Test-PsignModule -Path (Join-Path $script:TestDir 'ghost-module') -Policy AllSigned -ErrorAction Stop
        } catch { $err = $_ }
        $err | Should -Not -BeNull
    }

    It 'handles module without manifest (directory scan fallback)' {
        $modDir = New-TestModule -Name 'NoManifest' -Sign
        $result = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust
        $result | Should -Not -BeNull
        # Without manifest, should scan directory for signable files
        $result.Valid | Should -BeTrue
    }
}

Describe 'Test-PsignModule tamper detection' {
    It 'detects tampered file as HashMismatch' {
        $modDir = New-TestModule -Name 'Tampered' -WithManifest -Sign
        # Tamper with the .psm1
        $psm1Path = Join-Path $modDir 'Tampered.psm1'
        $content = Get-Content $psm1Path -Raw
        # Insert content before the signature block
        $content = $content -replace "function Get-Tampered", "# TAMPERED`nfunction Get-Tampered"
        Set-Content -LiteralPath $psm1Path -Value $content -NoNewline
        $result = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust
        $result | Should -Not -BeNull
        $result.Valid | Should -BeFalse
        $result.Files | Where-Object { $_.Status -eq 'HashMismatch' } | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-PsignModule -IncludeUnreferenced' {
    It 'checks unreferenced files when -IncludeUnreferenced is set' {
        $modDir = New-TestModule -Name 'Unreferenced' -WithManifest -ExtraFiles 2
        # Sign the manifest and root module but NOT the helpers
        $null = Set-PsignSignature -LiteralPath (Join-Path $modDir 'Unreferenced.psd1') -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        $null = Set-PsignSignature -LiteralPath (Join-Path $modDir 'Unreferenced.psm1') -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath
        # Without -IncludeUnreferenced, the module is compliant (only manifest-referenced checked)
        $result = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust
        $result.Valid | Should -BeTrue
        # With -IncludeUnreferenced, the extra unsigned files should be checked
        $resultAll = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust -IncludeUnreferenced
        $resultAll.Valid | Should -BeFalse
    }
}
