Set-StrictMode -Version Latest

# Disable auto-trust during tests — test certificates are self-signed.
$env:PSIGN_NO_AUTO_TRUST = '1'

function script:Ensure-PortableSignatureModule {
    if (-not (Get-Command Set-PsignSignature -ErrorAction SilentlyContinue)) {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $modulePath = Join-Path (Join-Path $repoRoot 'PowerShell\Devolutions.Psign') 'Devolutions.Psign.psd1'
        Import-Module $modulePath -Force
    }
}

function script:New-PortableSigningMaterial {
    param(
        [Parameter(Mandatory)]
        [string] $BasePath
    )

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $rootRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign portable root',
        $rootRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $rootRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
    $rootRequest.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign,
            $true))
    $rootCert = $rootRequest.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(31))

    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign portable test',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true))
    $ekuOids = [System.Security.Cryptography.OidCollection]::new()
    $null = $ekuOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false))
    $issuedCert = $request.Create(
        $rootCert,
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30),
        [byte[]](1, 2, 3, 4, 5, 6, 7, 8))
    $cert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issuedCert, $rsa)

    $certPath = Join-Path $BasePath 'signer.cer'
    $keyPath = Join-Path $BasePath 'signer.key'
    [System.IO.File]::WriteAllBytes($certPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [System.IO.File]::WriteAllText(
        $keyPath,
        [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()))

    [pscustomobject]@{
        Certificate = $cert
        RootCertificate = $rootCert
        CertificatePath = $certPath
        PrivateKeyPath = $keyPath
    }
}

function script:Get-ZipEntryNames {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        return @($archive.Entries | ForEach-Object FullName)
    }
    finally {
        $archive.Dispose()
    }
}

function script:New-ClickOnceDocument {
    param(
        [Parameter(Mandatory)]
        [string] $Path,
        [Parameter(Mandatory)]
        [string] $RootName
    )

    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<$RootName>
  <assemblyIdentity name="psign.$RootName" version="1.0.0.0" />
</$RootName>
"@
    Set-Content -LiteralPath $Path -Value $xml -Encoding UTF8
}

Describe 'Portable PowerShell package-native coverage' {
    BeforeAll {
        Ensure-PortableSignatureModule
        $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $script:ModulePath = Join-Path (Join-Path $script:RepoRoot 'PowerShell\Devolutions.Psign') 'Devolutions.Psign.psd1'
        $script:TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $script:TempRoot | Out-Null
        $script:Signing = New-PortableSigningMaterial -BasePath $script:TempRoot
    }

    AfterAll {
        if ($script:TempRoot) {
            Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Context 'Set-PsignSignature validation' {
    It 'requires -AzureKeyVaultCertificate when -AzureKeyVaultUrl is used' {
        $errorRecord = $null
        try {
            Set-PsignSignature -LiteralPath 'placeholder.exe' -AzureKeyVaultUrl 'https://vault.example' -ErrorAction Stop | Out-Null
        }
        catch {
            $errorRecord = $_
        }

        $errorRecord | Should -Not -BeNullOrEmpty
        $errorRecord.FullyQualifiedErrorId | Should -Be 'PsignSignatureAkvCertificateRequired,Devolutions.Psign.PowerShell.Cmdlets.SetPsignSignatureCommand'
    }

    It 'rejects mixed local and Azure Key Vault signing sources' {
        $errorRecord = $null
        try {
            Set-PsignSignature -LiteralPath 'placeholder.exe' `
                -CertificatePath 'signer.cer' `
                -PrivateKeyPath 'signer.key' `
                -AzureKeyVaultUrl 'https://vault.example' `
                -AzureKeyVaultCertificate 'signer' `
                -ErrorAction Stop | Out-Null
        }
        catch {
            $errorRecord = $_
        }

        $errorRecord | Should -Not -BeNullOrEmpty
        $errorRecord.FullyQualifiedErrorId | Should -Be 'PsignSignatureSigningMaterialRequired,Devolutions.Psign.PowerShell.Cmdlets.SetPsignSignatureCommand'
    }

    It 'rejects -OutputPath with -Content' {
        $errorRecord = $null
        try {
            Set-PsignSignature -SourcePathOrExtension '.ps1' `
                -Content ([System.Text.Encoding]::UTF8.GetBytes('"hello"')) `
                -CertificatePath $script:Signing.CertificatePath `
                -PrivateKeyPath $script:Signing.PrivateKeyPath `
                -OutputPath 'out.ps1' `
                -ErrorAction Stop | Out-Null
        }
        catch {
            $errorRecord = $_
        }

        $errorRecord | Should -Not -BeNullOrEmpty
        $errorRecord.FullyQualifiedErrorId | Should -Be 'PsignSignatureContentOutputPathUnsupported,Devolutions.Psign.PowerShell.Cmdlets.SetPsignSignatureCommand'
    }
    }

    Context 'Set-PsignSignature package-native formats' {
    It 'signs and inspects NuGet packages' {
        $work = Join-Path $script:TempRoot 'sample.nupkg'
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\package-signing\unsigned\sample.nupkg') -Destination $work -Force

        $signed = Set-PsignSignature -LiteralPath $work -CertificatePath $script:Signing.CertificatePath -PrivateKeyPath $script:Signing.PrivateKeyPath
        $signed.Format | Should -Be 'NuGet'
        $signed.Status | Should -Be 'Valid'
        (Get-ZipEntryNames -Path $work) | Should -Contain '.signature.p7s'

        $inspected = Get-PsignSignature -LiteralPath $work
        $inspected.Format | Should -Be 'NuGet'
        $inspected.Status | Should -Be 'Valid'
    }

    It 'signs and inspects symbol NuGet packages' {
        $work = Join-Path $script:TempRoot 'sample.snupkg'
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\package-signing\unsigned\sample.snupkg') -Destination $work -Force

        $signed = Set-PsignSignature -LiteralPath $work -CertificatePath $script:Signing.CertificatePath -PrivateKeyPath $script:Signing.PrivateKeyPath
        $signed.Format | Should -Be 'NuGet'
        $signed.Status | Should -Be 'Valid'
        (Get-ZipEntryNames -Path $work) | Should -Contain '.signature.p7s'
    }

    It 'signs and inspects VSIX packages' {
        $work = Join-Path $script:TempRoot 'sample.vsix'
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\package-signing\unsigned\sample.vsix') -Destination $work -Force

        $signed = Set-PsignSignature -LiteralPath $work -CertificatePath $script:Signing.CertificatePath -PrivateKeyPath $script:Signing.PrivateKeyPath
        $signed.Format | Should -Be 'Vsix'
        $signed.Status | Should -Be 'Valid'
        @(Get-ZipEntryNames -Path $work | Where-Object { $_ -like 'package/services/digital-signature/*' }).Count | Should -BeGreaterThan 0

        $inspected = Get-PsignSignature -LiteralPath $work
        $inspected.Format | Should -Be 'Vsix'
        $inspected.Status | Should -Be 'Valid'
    }

    It 'signs and inspects ClickOnce XML manifests for .manifest, .application, and .vsto' -TestCases @(
        @{ FileName = 'sample.manifest'; RootName = 'assembly' }
        @{ FileName = 'sample.application'; RootName = 'deployment' }
        @{ FileName = 'sample.vsto'; RootName = 'deployment' }
    ) {
        param($FileName, $RootName)

        $work = Join-Path $script:TempRoot $FileName
        New-ClickOnceDocument -Path $work -RootName $RootName

        $signed = Set-PsignSignature -LiteralPath $work -CertificatePath $script:Signing.CertificatePath -PrivateKeyPath $script:Signing.PrivateKeyPath
        $signed.Format | Should -Be 'ClickOnceManifest'
        $signed.Status | Should -Be 'Valid'
        (Get-Content -LiteralPath $work -Raw) | Should -Match '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'

        $inspected = Get-PsignSignature -LiteralPath $work
        $inspected.Format | Should -Be 'ClickOnceManifest'
        $inspected.Status | Should -Be 'Valid'
    }

    It 'signs App Installer descriptors and writes the detached companion' {
        $work = Join-Path $script:TempRoot 'sample.appinstaller'
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\generated-unsigned\appinstaller\sample.appinstaller') -Destination $work -Force

        $signed = Set-PsignSignature -LiteralPath $work -CertificatePath $script:Signing.CertificatePath -PrivateKeyPath $script:Signing.PrivateKeyPath
        $signed.Format | Should -Be 'AppInstaller'
        $signed.Status | Should -Be 'Valid'

        $companion = "$work.p7"
        Test-Path -LiteralPath $companion | Should -BeTrue

        $inspected = Get-PsignSignature -LiteralPath $work
        $inspected.Format | Should -Be 'AppInstaller'
        $inspected.Status | Should -Be 'Valid'
    }
    }

    Context 'Directory recursion covers newly signable PowerShell module neighbors' {
    It 'recurses into package-native and ClickOnce files in a module tree' {
        $moduleRoot = Join-Path $script:TempRoot 'PortableModuleWithPackages'
        $privateRoot = Join-Path $moduleRoot 'Private'
        New-Item -ItemType Directory -Force -Path $privateRoot | Out-Null

        Set-Content -LiteralPath (Join-Path $moduleRoot 'PortableModule.psm1') -Value 'function Get-PortableGreeting { "hello" }' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $moduleRoot 'PortableModule.psd1') -Value "@{ RootModule = 'PortableModule.psm1'; ModuleVersion = '1.0.0'; GUID = '$([System.Guid]::NewGuid())' }" -Encoding UTF8
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\package-signing\unsigned\sample.nupkg') -Destination (Join-Path $moduleRoot 'sample.nupkg')
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\package-signing\unsigned\sample.snupkg') -Destination (Join-Path $moduleRoot 'sample.snupkg')
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\package-signing\unsigned\sample.vsix') -Destination (Join-Path $moduleRoot 'sample.vsix')
        Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'tests\fixtures\generated-unsigned\appinstaller\sample.appinstaller') -Destination (Join-Path $moduleRoot 'sample.appinstaller')
        New-ClickOnceDocument -Path (Join-Path $moduleRoot 'sample.manifest') -RootName 'assembly'
        New-ClickOnceDocument -Path (Join-Path $moduleRoot 'sample.application') -RootName 'deployment'
        New-ClickOnceDocument -Path (Join-Path $privateRoot 'sample.vsto') -RootName 'deployment'
        Set-Content -LiteralPath (Join-Path $moduleRoot 'ignored.txt') -Value 'ignore me' -Encoding UTF8

        $signed = @(Set-PsignSignature -LiteralPath $moduleRoot -CertificatePath $script:Signing.CertificatePath -PrivateKeyPath $script:Signing.PrivateKeyPath)
        $formats = @($signed | ForEach-Object Format)
        $formats | Should -Contain 'PowerShellScript'
        $formats | Should -Contain 'NuGet'
        $formats | Should -Contain 'Vsix'
        $formats | Should -Contain 'ClickOnceManifest'
        $formats | Should -Contain 'AppInstaller'

        $signedPaths = @($signed | ForEach-Object Path)
        $signedPaths | Should -Not -Contain (Join-Path $moduleRoot 'ignored.txt')
        Test-Path -LiteralPath (Join-Path $moduleRoot 'sample.appinstaller.p7') | Should -BeTrue

        $validated = @(Get-PsignSignature -LiteralPath $moduleRoot)
        @($validated | Where-Object Status -ne 'Valid').Count | Should -Be 0
        @($validated | ForEach-Object Format) | Should -Contain 'NuGet'
        @($validated | ForEach-Object Format) | Should -Contain 'Vsix'
        @($validated | ForEach-Object Format) | Should -Contain 'ClickOnceManifest'
        @($validated | ForEach-Object Format) | Should -Contain 'AppInstaller'
    }
    }
}
