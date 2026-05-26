Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-testmod-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null
    $env:PSIGN_CERT_STORE = Join-Path $script:TestDir 'cert-store'

    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
    Import-Module $modulePath -Force

    function script:New-TestSerialNumber {
        $serial = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
        $serial[0] = $serial[0] -band 0x7F
        $serial
    }

    function script:New-TestCaRequest {
        param(
            [string]$Subject,
            [System.Security.Cryptography.RSA]$Key
        )

        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $Key,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign,
                $true))
        $ekuOids = [System.Security.Cryptography.OidCollection]::new()
        $null = $ekuOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false))
        $request
    }

    function script:New-TestSignerRequest {
        param(
            [string]$Subject,
            [System.Security.Cryptography.RSA]$Key
        )

        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $Key,
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
        $request
    }

    function script:Export-TestCertificate {
        param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
            [string]$CertificatePath,
            [string]$PrivateKeyPath
        )

        [System.IO.File]::WriteAllBytes($CertificatePath, $Certificate.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

        if ($PrivateKeyPath) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
            [System.IO.File]::WriteAllText(
                $PrivateKeyPath,
                [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()))
        }
    }

    # Create a self-signed signing cert
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = New-TestSignerRequest -Subject 'CN=psign testmod test' -Key $rsa
    $script:Cert = $request.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))

    $otherRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $otherRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign unrelated trust anchor',
        $otherRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $script:OtherCert = $otherRequest.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))

    $script:CertPath = Join-Path $script:TestDir 'signer.cer'
    $script:KeyPath = Join-Path $script:TestDir 'signer.key'
    Export-TestCertificate -Certificate $script:Cert -CertificatePath $script:CertPath -PrivateKeyPath $script:KeyPath

    # Create a root -> intermediate -> leaf signing chain matching Jordan's scenarios.
    $chainNotBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $chainRootNotAfter = [System.DateTimeOffset]::UtcNow.AddDays(31)
    $chainLeafNotAfter = [System.DateTimeOffset]::UtcNow.AddDays(30)

    $rootRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $rootRequest = New-TestCaRequest -Subject 'CN=psign jordan root' -Key $rootRsa
    $rootCert = $rootRequest.CreateSelfSigned(
        $chainNotBefore,
        $chainRootNotAfter)

    $intermediateRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $intermediateRequest = New-TestCaRequest -Subject 'CN=psign jordan intermediate' -Key $intermediateRsa
    $intermediatePublic = $intermediateRequest.Create(
        $rootCert,
        $chainNotBefore,
        $chainLeafNotAfter,
        (New-TestSerialNumber))
    $intermediateCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey(
        $intermediatePublic,
        $intermediateRsa)

    $leafRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $leafRequest = New-TestSignerRequest -Subject 'CN=psign jordan signer' -Key $leafRsa
    $leafPublic = $leafRequest.Create(
        $intermediateCert,
        $chainNotBefore,
        $chainLeafNotAfter,
        (New-TestSerialNumber))
    $leafCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey(
        $leafPublic,
        $leafRsa)

    $chainRootPath = Join-Path $script:TestDir 'chain-root.cer'
    $chainIntermediatePath = Join-Path $script:TestDir 'chain-intermediate.cer'
    $chainLeafPath = Join-Path $script:TestDir 'chain-leaf.cer'
    $chainLeafKeyPath = Join-Path $script:TestDir 'chain-leaf.key'
    Export-TestCertificate -Certificate $rootCert -CertificatePath $chainRootPath
    Export-TestCertificate -Certificate $intermediateCert -CertificatePath $chainIntermediatePath
    Export-TestCertificate -Certificate $leafCert -CertificatePath $chainLeafPath -PrivateKeyPath $chainLeafKeyPath

    $script:Chain = [pscustomobject]@{
        Root = $rootCert
        Intermediate = $intermediateCert
        Leaf = $leafCert
        RootPath = $chainRootPath
        IntermediatePath = $chainIntermediatePath
        LeafPath = $chainLeafPath
        LeafKeyPath = $chainLeafKeyPath
    }

    function script:New-TestModule {
        param(
            [string]$Name,
            [switch]$WithManifest,
            [switch]$Sign,
            [int]$ExtraFiles = 0,
            [string]$ModuleVersion = '1.0.0',
            [string]$Directory,
            [string]$CertificatePath = $script:CertPath,
            [string]$PrivateKeyPath = $script:KeyPath,
            [string[]]$ChainCertificatePath = @()
        )
        $modDir = if ($Directory) { $Directory } else { Join-Path $script:TestDir $Name }
        New-Item -ItemType Directory -Path $modDir -Force | Out-Null

        # Root module
        Set-Content -LiteralPath (Join-Path $modDir "$Name.psm1") -Value "function Get-$Name { '$Name' }" -Encoding UTF8

        if ($WithManifest) {
            $psdContent = @"
@{
    ModuleVersion = '$ModuleVersion'
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
                $signParams = @{
                    LiteralPath = $_.FullName
                    CertificatePath = $CertificatePath
                    PrivateKeyPath = $PrivateKeyPath
                }
                if ($ChainCertificatePath.Count -gt 0) {
                    $signParams.ChainCertificatePath = $ChainCertificatePath
                }
                $null = Set-PsignSignature @signParams
            }
        }
        $modDir
    }

    function script:Clear-TestPublisherStores {
        $thumbprints = @(
            $script:Cert.Thumbprint
            $script:Chain.Root.Thumbprint
            $script:Chain.Intermediate.Thumbprint
            $script:Chain.Leaf.Thumbprint
        )

        foreach ($store in @('Trust', 'TrustedPublisher', 'Disallowed')) {
            foreach ($scope in @('CurrentUser', 'LocalMachine')) {
                foreach ($thumbprint in $thumbprints) {
                    $path = "pcert:\$scope\$store\$thumbprint"
                    Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue
                }
            }
        }
    }

    function script:Add-TestCertificateToStore {
        param(
            [ValidateSet('CurrentUser', 'LocalMachine')]
            [string]$Scope = 'CurrentUser',
            [ValidateSet('Trust', 'TrustedPublisher', 'Disallowed')]
            [string]$Store,
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
        )

        New-Item -Path "pcert:\$Scope\$Store\$($Certificate.Thumbprint)" -Value $Certificate | Out-Null
    }

    function script:New-ChainSignedTestModule {
        param([string]$Name)

        New-TestModule `
            -Name $Name `
            -WithManifest `
            -Sign `
            -CertificatePath $script:Chain.LeafPath `
            -PrivateKeyPath $script:Chain.LeafKeyPath `
            -ChainCertificatePath @($script:Chain.IntermediatePath)
    }
}

AfterAll {
    if (Test-Path $script:TestDir) {
        Remove-Item -Recurse -Force $script:TestDir
    }
    Remove-Item Env:\PSIGN_CERT_STORE -ErrorAction SilentlyContinue
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

Describe 'Test-PsignModule pipeline input' {
    It 'accepts Get-Module output and validates the piped module version' {
        $moduleName = 'NamedModule'
        $modulePathRoot = Join-Path $script:TestDir 'psmodulepath'
        $moduleVersionRoot = Join-Path $modulePathRoot $moduleName
        $oldModuleDir = Join-Path $moduleVersionRoot '1.0.0'
        $newModuleDir = Join-Path $moduleVersionRoot '2.0.0'
        $null = New-TestModule -Name $moduleName -WithManifest -Directory $oldModuleDir
        $null = New-TestModule -Name $moduleName -WithManifest -Sign -ModuleVersion '2.0.0' -Directory $newModuleDir

        $originalPSModulePath = $env:PSModulePath
        try {
            $env:PSModulePath = "$modulePathRoot$([System.IO.Path]::PathSeparator)$originalPSModulePath"

            $modules = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version
            $results = $modules | Test-PsignModule -Policy AllSigned -SkipTrust
            $results | Should -HaveCount 2

            $oldResult = $results | Where-Object ModulePath -eq $oldModuleDir
            $oldResult.Valid | Should -BeFalse
            $oldResult.ModuleName | Should -Be $moduleName

            $newResult = $results | Where-Object ModulePath -eq $newModuleDir
            $newResult.Valid | Should -BeTrue
            $newResult.ModuleName | Should -Be $moduleName
        } finally {
            $env:PSModulePath = $originalPSModulePath
        }
    }

    It 'accepts Get-InstalledModule-style output with InstalledLocation' {
        $moduleName = 'InstalledModule'
        $modDir = New-TestModule -Name $moduleName -WithManifest -Sign -ModuleVersion '2.0.0'
        $installedModule = [pscustomobject]@{
            Name = $moduleName
            Version = '2.0.0'
            InstalledLocation = $modDir
            Repository = 'TestRepository'
        }

        $result = $installedModule | Test-PsignModule -Policy AllSigned -SkipTrust
        $result.Valid | Should -BeTrue
        $result.ModuleName | Should -Be $moduleName
        $result.ModulePath | Should -Be $modDir
    }
}

Describe 'Test-PsignModule trusted publisher parity' {
    BeforeEach {
        Clear-TestPublisherStores
    }

    It 'requires the self-signed leaf in TrustedPublisher, not Trust' {
        $modDir = New-TestModule -Name 'PublisherTrust' -WithManifest -Sign

        Add-TestCertificateToStore -Store Trust -Certificate $script:Cert
        $trustOnly = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust -RequireTrustedPublisher
        $trustOnly.Valid | Should -BeFalse
        ($trustOnly.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeFalse

        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Cert
        $trustedPublisher = Test-PsignModule -Path $modDir -Policy AllSigned -SkipTrust -RequireTrustedPublisher
        $trustedPublisher.Valid | Should -BeTrue
        ($trustedPublisher.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeTrue
    }

    It 'does not use self-signed TrustedPublisher membership to bypass chain trust' {
        $modDir = New-TestModule -Name 'PublisherNeedsRoot' -WithManifest -Sign
        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Cert

        $result = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:OtherCert -RequireTrustedPublisher
        $result.Valid | Should -BeFalse
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeTrue
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).FailureReason | Should -Not -Match 'not in TrustedPublisher store'
    }

    It 'passes a self-signed signer only when it is both a trust anchor and TrustedPublisher' {
        $modDir = New-TestModule -Name 'SelfSignedRootAndPublisher' -WithManifest -Sign
        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Cert

        $result = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Cert -RequireTrustedPublisher
        $result.Valid | Should -BeTrue
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeTrue
    }

    It 'requires the CA-signed leaf signer, not root or intermediate, in TrustedPublisher' {
        $modDir = New-ChainSignedTestModule -Name 'JordanLeafPublisher'

        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Chain.Root
        $rootPublisher = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Root -RequireTrustedPublisher
        $rootPublisher.Valid | Should -BeFalse
        $rootFile = $rootPublisher.Files | Where-Object RequiredByPolicy | Select-Object -First 1
        $rootFile.IsTrustedPublisher | Should -BeFalse
        $rootFile.FailureReason | Should -Match 'not in TrustedPublisher store'

        Clear-TestPublisherStores
        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Chain.Intermediate
        $intermediatePublisher = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Root -RequireTrustedPublisher
        $intermediatePublisher.Valid | Should -BeFalse
        $intermediateFile = $intermediatePublisher.Files | Where-Object RequiredByPolicy | Select-Object -First 1
        $intermediateFile.IsTrustedPublisher | Should -BeFalse
        $intermediateFile.FailureReason | Should -Match 'not in TrustedPublisher store'

        Clear-TestPublisherStores
        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Chain.Leaf
        $leafPublisher = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Root -RequireTrustedPublisher
        $leafPublisher.Valid | Should -BeTrue
        ($leafPublisher.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeTrue
    }

    It 'accepts TrustedPublisher from CurrentUser or LocalMachine for the leaf signer' {
        $modDir = New-ChainSignedTestModule -Name 'JordanPublisherScopes'

        Add-TestCertificateToStore -Scope LocalMachine -Store TrustedPublisher -Certificate $script:Chain.Leaf
        $result = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Root -RequireTrustedPublisher
        $result.Valid | Should -BeTrue
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeTrue
    }

    It 'does not accept the leaf signer as a root trust substitute' {
        $modDir = New-ChainSignedTestModule -Name 'JordanLeafNotRoot'
        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Chain.Leaf

        $result = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Leaf -RequireTrustedPublisher
        $result.Valid | Should -BeFalse
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeTrue
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).FailureReason | Should -Not -Match 'not in TrustedPublisher store'
    }

    It 'does not accept the intermediate as a root trust substitute' {
        $modDir = New-ChainSignedTestModule -Name 'JordanIntermediateNotRoot'
        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Chain.Leaf

        $result = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Intermediate -RequireTrustedPublisher
        $result.Valid | Should -BeFalse
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).IsTrustedPublisher | Should -BeTrue
        ($result.Files | Where-Object RequiredByPolicy | Select-Object -First 1).FailureReason | Should -Not -Match 'not in TrustedPublisher store'
    }

    It 'blocks a Disallowed leaf signer even when chain and TrustedPublisher checks pass' {
        $modDir = New-ChainSignedTestModule -Name 'JordanDisallowed'
        Add-TestCertificateToStore -Store TrustedPublisher -Certificate $script:Chain.Leaf
        Add-TestCertificateToStore -Store Disallowed -Certificate $script:Chain.Leaf

        $result = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Root -RequireTrustedPublisher
        $result.Valid | Should -BeFalse
        $file = $result.Files | Where-Object RequiredByPolicy | Select-Object -First 1
        $file.IsTrustedPublisher | Should -BeTrue
        $file.IsDisallowedPublisher | Should -BeTrue
        $file.FailureReason | Should -Match 'Disallowed store'
    }

    It 'blocks a Disallowed leaf signer even when TrustedPublisher is not required' {
        $modDir = New-ChainSignedTestModule -Name 'JordanDisallowedNoPublisher'
        Add-TestCertificateToStore -Store Disallowed -Certificate $script:Chain.Leaf

        $result = Test-PsignModule -Path $modDir -Policy AllSigned -TrustedCertificate $script:Chain.Root
        $result.Valid | Should -BeFalse
        $file = $result.Files | Where-Object RequiredByPolicy | Select-Object -First 1
        $file.IsTrustedPublisher | Should -BeFalse
        $file.IsDisallowedPublisher | Should -BeTrue
        $file.FailureReason | Should -Match 'Disallowed store'
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
