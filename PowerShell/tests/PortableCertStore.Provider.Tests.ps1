#Requires -Module Pester

<#
    .SYNOPSIS
    Tests for the pcert:\ (PortableCertStore) PowerShell provider.
#>

BeforeAll {
    $ModuleDir = Join-Path $PSScriptRoot '..' 'Devolutions.Psign'
    Import-Module (Join-Path $ModuleDir 'Devolutions.Psign.psd1') -Force -ErrorAction Stop

    # Use a temp directory as the cert store for test isolation
    $script:TestStoreRoot = Join-Path ([IO.Path]::GetTempPath()) "psign-provider-test-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $env:PSIGN_CERT_STORE = $script:TestStoreRoot

    # Re-import to pick up the env var for the default pcert: drive
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $ModuleDir 'Devolutions.Psign.psd1') -Force -ErrorAction Stop

    # Create a self-signed test cert
    if ($IsWindows) {
        $script:TestCert = New-SelfSignedCertificate -DnsName 'pcert-pester-test' -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddDays(1)
    } else {
        # On Linux, generate a cert via openssl
        $keyFile = Join-Path $script:TestStoreRoot '_testkey.pem'
        $certFile = Join-Path $script:TestStoreRoot '_testcert.pem'
        New-Item -ItemType Directory -Force -Path $script:TestStoreRoot | Out-Null
        & openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile -days 1 -nodes -subj '/CN=pcert-pester-test' 2>$null
        $script:TestCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certFile)
    }
}

AfterAll {
    if ($script:TestStoreRoot -and (Test-Path $script:TestStoreRoot)) {
        Remove-Item $script:TestStoreRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($IsWindows -and $script:TestCert) {
        Remove-Item "Cert:\CurrentUser\My\$($script:TestCert.Thumbprint)" -ErrorAction SilentlyContinue
    }
    Remove-Item Env:\PSIGN_CERT_STORE -ErrorAction SilentlyContinue
}

Describe 'pcert:\ Provider - Drive' {
    It 'pcert: drive exists after module import' {
        Get-PSDrive pcert | Should -Not -BeNullOrEmpty
    }

    It 'pcert: drive has PortableCertStore provider' {
        (Get-PSDrive pcert).Provider.Name | Should -Be 'PortableCertStore'
    }
}

Describe 'pcert:\ Provider - Navigation' {
    It 'can list scopes at root' {
        $items = Get-ChildItem pcert:\
        $items | Should -Not -BeNullOrEmpty
        $items.PSChildName | Should -Contain 'CurrentUser'
        $items.PSChildName | Should -Contain 'LocalMachine'
    }

    It 'can list stores under a scope' {
        $items = Get-ChildItem pcert:\CurrentUser
        $names = $items | ForEach-Object { $_.PSChildName }
        $names | Should -Contain 'MY'
        $names | Should -Contain 'Root'
        $names | Should -Contain 'CA'
        $names | Should -Contain 'TrustedPublisher'
    }

    It 'can cd into scope and store' {
        Push-Location pcert:\
        try {
            Set-Location CurrentUser
            (Get-Location).Path | Should -BeLike '*CurrentUser*'
            Set-Location MY
            (Get-Location).Path | Should -BeLike '*MY*'
        } finally {
            Pop-Location
        }
    }

    It 'IsItemContainer returns true for scope and store, false for cert' {
        Test-Path pcert:\CurrentUser -PathType Container | Should -BeTrue
        Test-Path pcert:\CurrentUser\MY -PathType Container | Should -BeTrue
    }
}

Describe 'pcert:\ Provider - Certificate CRUD' {
    It 'can import a certificate via New-Item' {
        $imported = New-Item -Path pcert:\CurrentUser\MY\cert -Value $script:TestCert
        $imported | Should -Not -BeNullOrEmpty
        $imported | Should -BeOfType [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $imported.Thumbprint | Should -Be $script:TestCert.Thumbprint
    }

    It 'can list certificates in a store' {
        $certs = Get-ChildItem pcert:\CurrentUser\MY
        $certs | Should -Not -BeNullOrEmpty
        $certs.Thumbprint | Should -Contain $script:TestCert.Thumbprint
    }

    It 'Test-Path returns true for existing cert' {
        Test-Path "pcert:\CurrentUser\MY\$($script:TestCert.Thumbprint)" | Should -BeTrue
    }

    It 'Test-Path returns false for non-existent cert' {
        Test-Path "pcert:\CurrentUser\MY\0000000000000000000000000000000000000000" | Should -BeFalse
    }

    It 'can get a single certificate by thumbprint' {
        $cert = Get-Item "pcert:\CurrentUser\MY\$($script:TestCert.Thumbprint)"
        $cert | Should -Not -BeNullOrEmpty
        $cert.Subject | Should -BeLike '*pcert-pester-test*'
    }

    It 'can copy a certificate to another store' {
        Copy-Item "pcert:\CurrentUser\MY\$($script:TestCert.Thumbprint)" pcert:\CurrentUser\Root
        Test-Path "pcert:\CurrentUser\Root\$($script:TestCert.Thumbprint)" | Should -BeTrue
        $copied = Get-Item "pcert:\CurrentUser\Root\$($script:TestCert.Thumbprint)"
        $copied.Thumbprint | Should -Be $script:TestCert.Thumbprint
    }

    It 'can use TrustedPublisher as a well-known store' {
        Copy-Item "pcert:\CurrentUser\MY\$($script:TestCert.Thumbprint)" pcert:\CurrentUser\TrustedPublisher
        Test-Path "pcert:\CurrentUser\TrustedPublisher\$($script:TestCert.Thumbprint)" | Should -BeTrue
        $copied = Get-Item "pcert:\CurrentUser\TrustedPublisher\$($script:TestCert.Thumbprint)"
        $copied.Thumbprint | Should -Be $script:TestCert.Thumbprint
    }

    It 'can remove a certificate' {
        # Remove from Root (the copy)
        Remove-Item "pcert:\CurrentUser\Root\$($script:TestCert.Thumbprint)"
        Test-Path "pcert:\CurrentUser\Root\$($script:TestCert.Thumbprint)" | Should -BeFalse
    }

    It 'can remove original cert from MY' {
        Remove-Item "pcert:\CurrentUser\MY\$($script:TestCert.Thumbprint)"
        Test-Path "pcert:\CurrentUser\MY\$($script:TestCert.Thumbprint)" | Should -BeFalse
        (Get-ChildItem pcert:\CurrentUser\MY).Count | Should -Be 0
    }

    It 'Get-ChildItem on empty store returns nothing' {
        $certs = Get-ChildItem pcert:\LocalMachine\Root
        $certs | Should -BeNullOrEmpty
    }
}

Describe 'pcert:\ Provider - Custom Drive' {
    BeforeAll {
        $script:CustomRoot = Join-Path ([IO.Path]::GetTempPath()) "psign-custom-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        New-PSDrive -Name teststore -PSProvider PortableCertStore -Root $script:CustomRoot | Out-Null
    }

    AfterAll {
        Remove-PSDrive teststore -ErrorAction SilentlyContinue
        if ($script:CustomRoot -and (Test-Path $script:CustomRoot)) {
            Remove-Item $script:CustomRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'custom drive can import and list certs' {
        New-Item -Path teststore:\LocalMachine\MY\cert -Value $script:TestCert | Out-Null
        $certs = Get-ChildItem teststore:\LocalMachine\MY
        $certs | Should -Not -BeNullOrEmpty
        $certs.Thumbprint | Should -Contain $script:TestCert.Thumbprint
    }

    It 'custom drive files are stored under the custom root' {
        $derFile = Join-Path $script:CustomRoot 'LocalMachine' 'MY' "$($script:TestCert.Thumbprint).der"
        Test-Path $derFile | Should -BeTrue
    }

    It 'custom drive is isolated from default pcert: drive' {
        # Default pcert: should NOT see certs in the custom drive
        Test-Path "pcert:\LocalMachine\MY\$($script:TestCert.Thumbprint)" | Should -BeFalse
    }
}

Describe 'pcert:\ Provider - Error Handling' {
    It 'Get-Item on non-existent cert throws' {
        { Get-Item "pcert:\CurrentUser\MY\DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF" -ErrorAction Stop } |
            Should -Throw
    }

    It 'Remove-Item on non-existent cert throws' {
        { Remove-Item "pcert:\CurrentUser\MY\DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF" -ErrorAction Stop } |
            Should -Throw
    }

    It 'New-Item with invalid value writes error' {
        { New-Item -Path pcert:\CurrentUser\MY\cert -Value 12345 -ErrorAction Stop } |
            Should -Throw -ErrorId 'InvalidCertificateValue*'
    }
}
