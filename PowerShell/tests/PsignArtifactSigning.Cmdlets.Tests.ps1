Set-StrictMode -Version Latest

$env:PSIGN_NO_AUTO_TRUST = '1'

<#
    .SYNOPSIS
    Tests for Get-PsignArtifactSigningPublisherId, Test-PsignArtifactSigning, and the
    -ArtifactSigning* parameters of Get-PsignSignature.

    A self-signed certificate carrying forged Azure Artifact Signing EKUs proves that the
    publisher ID is decoded from any certificate but only validates when the chain ends at the
    pinned Microsoft root. Set PSIGN_ARTIFACT_SIGNING_SAMPLE to a real Artifact Signing PE (and
    optionally PSIGN_ARTIFACT_SIGNING_SAMPLE_PUBLISHER_ID) to also run the positive cases.
#>

BeforeDiscovery {
    $script:HasSample = -not [string]::IsNullOrWhiteSpace($env:PSIGN_ARTIFACT_SIGNING_SAMPLE)
}

BeforeAll {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $repoRoot 'PowerShell\Devolutions.Psign\Devolutions.Psign.psd1'
    Import-Module $modulePath -Force

    $script:FixtureDir = Join-Path $repoRoot 'tests\fixtures\artifact-signing'
    $script:RealPublisherId = '285218949.549339218.252840042.443064405'
    $script:ForgedPublisherId = '111.222.333.444'

    $script:TestDir = Join-Path ([System.IO.Path]::GetTempPath()) "psign-aas-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Forged Artifact Signing',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $ekuOids = [System.Security.Cryptography.OidCollection]::new()
    foreach ($oid in @('1.3.6.1.4.1.311.97.1.0', "1.3.6.1.4.1.311.97.$script:ForgedPublisherId", '1.3.6.1.5.5.7.3.3')) {
        $null = $ekuOids.Add([System.Security.Cryptography.Oid]::new($oid))
    }
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false))
    $script:ForgedCert = $request.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))

    $certPath = Join-Path $script:TestDir 'forged.cer'
    $keyPath = Join-Path $script:TestDir 'forged.key'
    [System.IO.File]::WriteAllBytes($certPath, $script:ForgedCert.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [System.IO.File]::WriteAllText($keyPath,
        [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()))

    $script:ForgedScript = Join-Path $script:TestDir 'forged.ps1'
    Set-Content -LiteralPath $script:ForgedScript -Value "Write-Output 'forged'" -Encoding UTF8
    Set-PsignSignature -FilePath $script:ForgedScript -CertificatePath $certPath -PrivateKeyPath $keyPath | Out-Null
}

AfterAll {
    if ($script:TestDir -and (Test-Path $script:TestDir)) {
        Remove-Item -LiteralPath $script:TestDir -Recurse -Force
    }
}

Describe 'Get-PsignArtifactSigningPublisherId' {
    It 'decodes the publisher ID from a certificate' {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            (Join-Path $script:FixtureDir 'devolutions-signer.pem'))
        $id = Get-PsignArtifactSigningPublisherId -Certificate $cert
        $id.PublisherId | Should -Be $script:RealPublisherId
        $id.Kind | Should -Be 'public_trust'
        $id.HasPublicTrustMarker | Should -BeTrue
        $id.IdentityEku | Should -Be "1.3.6.1.4.1.311.97.$script:RealPublisherId"
    }

    It 'decodes the publisher ID from a signed file without validating it' {
        $id = Get-PsignArtifactSigningPublisherId -LiteralPath $script:ForgedScript
        $id.PublisherId | Should -Be $script:ForgedPublisherId
        $id.Path | Should -Be $script:ForgedScript
    }

    It 'writes an error for a certificate without an Artifact Signing identity' {
        $plain = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            (Join-Path $repoRoot 'tests\fixtures\devolutions-authenticode\authenticode-test-ca.crt'))
        $result = Get-PsignArtifactSigningPublisherId -Certificate $plain -ErrorAction SilentlyContinue -ErrorVariable err
        $result | Should -BeNullOrEmpty
        $err[0].FullyQualifiedErrorId | Should -BeLike 'NotArtifactSigningCertificate*'
    }
}

Describe 'Test-PsignArtifactSigning' {
    It 'rejects forged Artifact Signing EKUs that do not chain to the pinned Microsoft root' {
        Test-PsignArtifactSigning -LiteralPath $script:ForgedScript | Should -BeFalse
        Test-PsignArtifactSigning -LiteralPath $script:ForgedScript -PublisherId $script:ForgedPublisherId | Should -BeFalse
    }

    It 'returns the signature object with -Detailed' {
        $detail = Test-PsignArtifactSigning -LiteralPath $script:ForgedScript -Detailed
        $detail.Status | Should -Be 'NotTrusted'
        $detail.ArtifactSigningVerification | Should -BeNullOrEmpty
        $detail.ArtifactSigningPublisherId | Should -Be $script:ForgedPublisherId
    }

    It 'validates a real Artifact Signing sample with publisher pinning' -Skip:(-not $script:HasSample) {
        $sample = $env:PSIGN_ARTIFACT_SIGNING_SAMPLE
        $expected = if ($env:PSIGN_ARTIFACT_SIGNING_SAMPLE_PUBLISHER_ID) { $env:PSIGN_ARTIFACT_SIGNING_SAMPLE_PUBLISHER_ID } else { $script:RealPublisherId }
        Test-PsignArtifactSigning -LiteralPath $sample | Should -BeTrue
        Test-PsignArtifactSigning -LiteralPath $sample -PublisherId $expected | Should -BeTrue
        Test-PsignArtifactSigning -LiteralPath $sample -PublisherId '1.2.3.4' | Should -BeFalse

        $detail = Test-PsignArtifactSigning -LiteralPath $sample -PublisherId $expected -Detailed
        $detail.ArtifactSigningVerification.RootSha1 | Should -Be 'f40042e2e5f7e8ef8189fed15519aece42c3bfa2'
        $detail.ArtifactSigningVerification.Timestamped | Should -BeTrue
    }
}

Describe 'Get-PsignSignature Artifact Signing parameters' {
    It 'exposes the decoded publisher ID without validation' {
        (Get-PsignSignature -LiteralPath $script:ForgedScript -SkipTrust).ArtifactSigningPublisherId |
            Should -Be $script:ForgedPublisherId
    }

    It 'reports NotTrusted for forged EKUs under -ArtifactSigningPublisherId' {
        $signature = Get-PsignSignature -LiteralPath $script:ForgedScript -ArtifactSigningPublisherId $script:ForgedPublisherId
        $signature.Status | Should -Be 'NotTrusted'
        $signature.TrustStatus | Should -Be 'NotTrusted'
    }

    It 'rejects generic trust anchors combined with Artifact Signing' {
        $null = Get-PsignSignature -LiteralPath $script:ForgedScript -ArtifactSigning `
            -TrustedCertificate $script:ForgedCert -ErrorAction SilentlyContinue -ErrorVariable err
        $err[0].Exception.Message | Should -BeLike '*cannot be combined with Artifact Signing*'
    }
}
