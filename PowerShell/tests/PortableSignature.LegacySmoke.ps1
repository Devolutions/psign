param(
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

# Disable auto-trust during tests — test certificates are self-signed and
# won't chain to the Microsoft AuthRoot CTL.
$env:PSIGN_NO_AUTO_TRUST = '1'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$buildScript = Join-Path (Join-Path $repo 'PowerShell') 'build.ps1'
if (-not $env:PSIGN_PWSH_TEST_SKIP_BUILD) {
    # If the module is already loaded in this process, the native DLL is locked
    # and cannot be overwritten by a rebuild. Skip the build in that case.
    $alreadyLoaded = Get-Module Devolutions.Psign -ErrorAction SilentlyContinue
    if ($alreadyLoaded) {
        Write-Host "Skipping build: module already loaded in this session (native DLL locked)."
    } else {
        & $buildScript -Configuration $Configuration
    }
}

$modulePath = Join-Path (Join-Path (Join-Path $repo 'PowerShell') 'Devolutions.Psign') 'Devolutions.Psign.psd1'
Import-Module $modulePath -Force

function Assert-SignerCertificate {
    param(
        [Parameter(Mandatory)]
        $Signature,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ExpectedCertificate,
        [Parameter(Mandatory)]
        [string] $Label
    )

    if ($null -eq $Signature.SignerCertificate) {
        throw "Expected SignerCertificate for $Label."
    }
    if ($Signature.SignerCertificate.Thumbprint -ne $ExpectedCertificate.Thumbprint) {
        throw "Unexpected SignerCertificate thumbprint for $Label."
    }
    if ($Signature.EmbeddedCertificateCount -lt 1) {
        throw "Expected EmbeddedCertificateCount for $Label."
    }
}

function Start-PsignTimestampServer {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'cargo'
    foreach ($argument in @('run', '--quiet', '--bin', 'psign-server', '--', 'timestamp-server', '--max-requests', '1')) {
        $psi.ArgumentList.Add($argument)
    }
    $psi.WorkingDirectory = $repo
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $line = $process.StandardOutput.ReadLine()
    if ($line -notlike 'psign-server timestamp-server listening on *') {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
            }
        }
        catch {
        }
        throw "Failed to start psign timestamp server. First output: $line"
    }
    [pscustomobject]@{
        Process = $process
        Url = $line.Substring('psign-server timestamp-server listening on '.Length)
    }
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp | Out-Null
try {
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
    $certPath = Join-Path $temp 'signer.cer'
    $keyPath = Join-Path $temp 'signer.key'
    $pfxPath = Join-Path $temp 'signer.pfx'
    $pfxPassword = ConvertTo-SecureString -String 'portable-test' -AsPlainText -Force
    [System.IO.File]::WriteAllBytes($certPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [System.IO.File]::WriteAllText(
        $keyPath,
        [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()))
    [System.IO.File]::WriteAllBytes($pfxPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, 'portable-test'))
    $storeDir = Join-Path $temp 'cert-store'
    $storeMyDir = Join-Path (Join-Path $storeDir 'CurrentUser') 'MY'
    New-Item -ItemType Directory -Force -Path $storeMyDir | Out-Null
    $storeCertPath = Join-Path $storeMyDir "$($cert.Thumbprint.ToUpperInvariant()).der"
    $storeKeyPath = Join-Path $storeMyDir "$($cert.Thumbprint.ToUpperInvariant()).key"
    Copy-Item -LiteralPath $certPath -Destination $storeCertPath
    Copy-Item -LiteralPath $keyPath -Destination $storeKeyPath
    $chainRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $chainRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign portable chain test',
        $chainRsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $chainCert = $chainRequest.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))
    $chainCertPath = Join-Path $temp 'chain.cer'
    [System.IO.File]::WriteAllBytes($chainCertPath, $chainCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    $unsigned = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'pe') 'tiny32-pe-alias.exe'
    $work = Join-Path $temp 'tiny.exe'
    Copy-Item $unsigned $work

    if (-not (Get-Command Get-PsignSignature -ErrorAction SilentlyContinue)) {
        throw 'Get-PsignSignature was not exported.'
    }
    if (-not (Get-Command Set-PsignSignature -ErrorAction SilentlyContinue)) {
        throw 'Set-PsignSignature was not exported.'
    }
    $getParameters = (Get-Command Get-PsignSignature).Parameters
    foreach ($parameterName in @('FilePath', 'LiteralPath', 'SourcePathOrExtension', 'Content', 'TrustedCertificate', 'TrustedCertificatePath', 'AnchorDirectory', 'AuthRootCab', 'AsOf', 'PreferTimestampSigningTime', 'RequireValidTimestamp', 'OnlineAia', 'OnlineOcsp', 'RevocationMode')) {
        if (-not $getParameters.ContainsKey($parameterName)) {
            throw "Get-PsignSignature is missing expected migration parameter '$parameterName'."
        }
    }
    $setParameters = (Get-Command Set-PsignSignature).Parameters
    foreach ($parameterName in @('FilePath', 'LiteralPath', 'SourcePathOrExtension', 'Content', 'Certificate', 'CertificatePath', 'PrivateKeyPath', 'PfxPath', 'Password', 'Thumbprint', 'CertStoreDirectory', 'StoreName', 'MachineStore', 'IncludeChain', 'ChainCertificatePath', 'TimestampServer', 'TimestampHashAlgorithm', 'HashAlgorithm', 'OutputPath', 'Force')) {
        if (-not $setParameters.ContainsKey($parameterName)) {
            throw "Set-PsignSignature is missing expected migration parameter '$parameterName'."
        }
    }

    $before = Get-PsignSignature -LiteralPath $work
    if ($before.Status -ne 'NotSigned') {
        throw "Expected NotSigned before signing, got $($before.Status)."
    }

    $signed = Set-PsignSignature -LiteralPath $work -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($signed.Status -ne 'Valid') {
        throw "Expected Valid after signing, got $($signed.Status): $($signed.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $signed -ExpectedCertificate $cert -Label 'PE signing response'

    $after = Get-PsignSignature -LiteralPath $work
    if ($after.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature after signing, got $($after.Status)."
    }
    Assert-SignerCertificate -Signature $after -ExpectedCertificate $cert -Label 'PE get response'

    $trustedAfter = Get-PsignSignature -LiteralPath $work -TrustedCertificate $rootCert -AsOf ([System.DateTime]::UtcNow) -RevocationMode Off
    if ($trustedAfter.Status -ne 'Valid' -or $trustedAfter.TrustStatus -ne 'Valid') {
        throw "Expected explicit trust verification to succeed for signed PE, got status=$($trustedAfter.Status) trust=$($trustedAfter.TrustStatus): $($trustedAfter.StatusMessage)"
    }
    $untrustedAfter = Get-PsignSignature -LiteralPath $work -TrustedCertificate $chainCert
    if ($untrustedAfter.Status -ne 'NotTrusted' -or $untrustedAfter.TrustStatus -ne 'NotTrusted') {
        throw "Expected explicit trust verification to fail with wrong anchor, got status=$($untrustedAfter.Status) trust=$($untrustedAfter.TrustStatus): $($untrustedAfter.StatusMessage)"
    }

    $length = (Get-Item -LiteralPath $work).Length
    Set-PsignSignature -LiteralPath $work -CertificatePath $certPath -PrivateKeyPath $keyPath -WhatIf | Out-Null
    if ((Get-Item -LiteralPath $work).Length -ne $length) {
        throw 'Set-PsignSignature -WhatIf mutated the file.'
    }

    $readOnlyWork = Join-Path $temp 'tiny-readonly.exe'
    Copy-Item $unsigned $readOnlyWork
    Set-ItemProperty -LiteralPath $readOnlyWork -Name IsReadOnly -Value $true
    try {
        $failedWithoutForce = $false
        try {
            Set-PsignSignature -LiteralPath $readOnlyWork -CertificatePath $certPath -PrivateKeyPath $keyPath -ErrorAction Stop | Out-Null
        }
        catch {
            $failedWithoutForce = $true
        }
        if (-not $failedWithoutForce) {
            throw 'Expected Set-PsignSignature to fail on a read-only file without -Force.'
        }
        $forceSigned = Set-PsignSignature -LiteralPath $readOnlyWork -CertificatePath $certPath -PrivateKeyPath $keyPath -Force
        if ($forceSigned.Status -ne 'Valid') {
            throw "Expected Valid after read-only file signing with -Force, got $($forceSigned.Status): $($forceSigned.StatusMessage)"
        }
        if (-not (Get-Item -LiteralPath $readOnlyWork).IsReadOnly) {
            throw 'Expected Set-PsignSignature -Force to restore the read-only attribute.'
        }
    }
    finally {
        Set-ItemProperty -LiteralPath $readOnlyWork -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    }

    $storeWork = Join-Path $temp 'tiny-store.exe'
    Copy-Item $unsigned $storeWork
    $storeSigned = Set-PsignSignature -LiteralPath $storeWork -Sha1 $cert.Thumbprint -CertStoreDirectory $storeDir
    if ($storeSigned.Status -ne 'Valid') {
        throw "Expected Valid after portable cert-store signing, got $($storeSigned.Status): $($storeSigned.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $storeSigned -ExpectedCertificate $cert -Label 'portable cert-store signing response'

    $chainWork = Join-Path $temp 'tiny-chain.exe'
    Copy-Item $unsigned $chainWork
    $defaultChainWork = Join-Path $temp 'tiny-chain-default.exe'
    Copy-Item $unsigned $defaultChainWork
    $defaultChainSigned = Set-PsignSignature -LiteralPath $defaultChainWork -CertificatePath $certPath -PrivateKeyPath $keyPath -ChainCertificatePath $chainCertPath
    if ($defaultChainSigned.EmbeddedCertificateCount -ne 1) {
        throw "Expected default IncludeChain NotRoot to exclude a self-signed root certificate, got $($defaultChainSigned.EmbeddedCertificateCount) embedded certificates."
    }
    $chainSigned = Set-PsignSignature -LiteralPath $chainWork -CertificatePath $certPath -PrivateKeyPath $keyPath -IncludeChain All -ChainCertificatePath $chainCertPath
    if ($chainSigned.EmbeddedCertificateCount -lt 2) {
        throw "Expected IncludeChain All with ChainCertificatePath to embed at least 2 certificates, got $($chainSigned.EmbeddedCertificateCount)."
    }

    $unsignedCab = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'cab') 'sample.cab'
    $cabWork = Join-Path $temp 'sample.cab'
    Copy-Item $unsignedCab $cabWork
    $cabSigned = Set-PsignSignature -LiteralPath $cabWork -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($cabSigned.Status -ne 'Valid') {
        throw "Expected Valid after CAB signing, got $($cabSigned.Status): $($cabSigned.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $cabSigned -ExpectedCertificate $cert -Label 'CAB signing response'
    $cabAfter = Get-PsignSignature -LiteralPath $cabWork
    if ($cabAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature for signed CAB, got $($cabAfter.Status): $($cabAfter.StatusMessage)"
    }

    $unsignedMsi = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'installer') 'tiny.msi'
    $msiWork = Join-Path $temp 'tiny.msi'
    Copy-Item $unsignedMsi $msiWork
    $msiSigned = Set-PsignSignature -LiteralPath $msiWork -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($msiSigned.Status -ne 'Valid') {
        throw "Expected Valid after MSI signing, got $($msiSigned.Status): $($msiSigned.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $msiSigned -ExpectedCertificate $cert -Label 'MSI signing response'
    $msiAfter = Get-PsignSignature -LiteralPath $msiWork
    if ($msiAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature for signed MSI, got $($msiAfter.Status): $($msiAfter.StatusMessage)"
    }

    $zipSource = Join-Path $temp 'zip-source'
    New-Item -ItemType Directory -Force -Path $zipSource | Out-Null
    Set-Content -LiteralPath (Join-Path $zipSource 'payload.txt') -Value 'portable zip authenticode' -Encoding UTF8
    $zipWork = Join-Path $temp 'payload.zip'
    Compress-Archive -LiteralPath (Join-Path $zipSource 'payload.txt') -DestinationPath $zipWork
    $zipSigned = Set-PsignSignature -LiteralPath $zipWork -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($zipSigned.Status -ne 'Valid') {
        throw "Expected Valid after ZIP signing, got $($zipSigned.Status): $($zipSigned.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $zipSigned -ExpectedCertificate $cert -Label 'ZIP signing response'
    $zipAfter = Get-PsignSignature -LiteralPath $zipWork
    if ($zipAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature for signed ZIP, got $($zipAfter.Status): $($zipAfter.StatusMessage)"
    }

    $scriptPath = Join-Path $temp 'Invoke-Test.ps1'
    Set-Content -LiteralPath $scriptPath -Value @'
param([string] $Name = "portable")
"Hello $Name"
'@ -Encoding UTF8
    $scriptSigned = Set-PsignSignature -LiteralPath $scriptPath -Certificate $cert
    if ($scriptSigned.Status -ne 'Valid') {
        throw "Expected Valid for signed PowerShell script, got $($scriptSigned.Status): $($scriptSigned.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $scriptSigned -ExpectedCertificate $cert -Label 'script signing response'
    $scriptAfter = Get-PsignSignature -LiteralPath $scriptPath
    if ($scriptAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature for signed script, got $($scriptAfter.Status)."
    }
    $trustedScript = Get-PsignSignature -LiteralPath $scriptPath -TrustedCertificate $rootCert
    if ($trustedScript.Status -ne 'Valid' -or $trustedScript.TrustStatus -ne 'Valid') {
        throw "Expected explicit trust verification to succeed for signed script, got status=$($trustedScript.Status) trust=$($trustedScript.TrustStatus): $($trustedScript.StatusMessage)"
    }
    Add-Content -LiteralPath $scriptPath -Value '# tamper'
    $scriptTampered = Get-PsignSignature -LiteralPath $scriptPath
    if ($scriptTampered.Status -ne 'HashMismatch') {
        throw "Expected HashMismatch for tampered signed script, got $($scriptTampered.Status): $($scriptTampered.StatusMessage)"
    }

    $ps1xmlPath = Join-Path $temp 'Types.ps1xml'
    Set-Content -LiteralPath $ps1xmlPath -Value @'
<Types>
  <Type>
    <Name>Portable.Type</Name>
  </Type>
</Types>
'@ -Encoding UTF8
    $ps1xmlSigned = Set-PsignSignature -LiteralPath $ps1xmlPath -Certificate $cert
    if ($ps1xmlSigned.Status -ne 'Valid') {
        throw "Expected Valid for signed ps1xml, got $($ps1xmlSigned.Status): $($ps1xmlSigned.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $ps1xmlSigned -ExpectedCertificate $cert -Label 'ps1xml signing response'
    $ps1xmlText = Get-Content -LiteralPath $ps1xmlPath -Raw
    if ($ps1xmlText -notmatch '<!-- SIG # Begin signature block -->') {
        throw 'Expected signed ps1xml to use XML Authenticode signature markers.'
    }
    $ps1xmlAfter = Get-PsignSignature -LiteralPath $ps1xmlPath
    if ($ps1xmlAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature for signed ps1xml, got $($ps1xmlAfter.Status): $($ps1xmlAfter.StatusMessage)"
    }
    Add-Content -LiteralPath $ps1xmlPath -Value '<!-- tamper -->'
    $ps1xmlTampered = Get-PsignSignature -LiteralPath $ps1xmlPath
    if ($ps1xmlTampered.Status -ne 'HashMismatch') {
        throw "Expected HashMismatch for tampered signed ps1xml, got $($ps1xmlTampered.Status): $($ps1xmlTampered.StatusMessage)"
    }

    $scriptContent = [System.Text.Encoding]::UTF8.GetBytes("'content mode'")
    $contentSigned = Set-PsignSignature -SourcePathOrExtension '.ps1' -Content $scriptContent -Certificate $cert
    if ($contentSigned.Status -ne 'Valid') {
        throw "Expected Valid for signed PowerShell script content, got $($contentSigned.Status): $($contentSigned.StatusMessage)"
    }
    if ($null -eq $contentSigned.Content -or $contentSigned.Content.Length -le $scriptContent.Length) {
        throw 'Expected Set-PsignSignature -Content to return signed content bytes.'
    }
    Assert-SignerCertificate -Signature $contentSigned -ExpectedCertificate $cert -Label 'script content signing response'
    $contentAfter = Get-PsignSignature -SourcePathOrExtension '.ps1' -Content $contentSigned.Content
    if ($contentAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature -Content for signed script, got $($contentAfter.Status): $($contentAfter.StatusMessage)"
    }

    $timestampServer = Start-PsignTimestampServer
    try {
        $timestampScript = Join-Path $temp 'Timestamped.ps1'
        Set-Content -LiteralPath $timestampScript -Value '"timestamped"' -Encoding UTF8
        $timestamped = Set-PsignSignature -LiteralPath $timestampScript -Certificate $cert -TimestampServer $timestampServer.Url -TimestampHashAlgorithm Sha256
        if ($timestamped.Status -ne 'Valid') {
            throw "Expected Valid for timestamped script, got $($timestamped.Status): $($timestamped.StatusMessage)"
        }
        if ($timestamped.TimestampKinds.Count -eq 0) {
            throw 'Expected timestamped script to report a timestamp kind.'
        }
        if ($null -eq $timestamped.TimeStamperCertificate) {
            throw 'Expected timestamped script to expose TimeStamperCertificate.'
        }
        if (-not $timestamped.PSObject.Properties.Match('TimestampSigningTime')) {
            throw 'Expected timestamped script output to include TimestampSigningTime.'
        }
    }
    finally {
        if (-not $timestampServer.Process.HasExited) {
            $timestampServer.Process.Kill($true)
        }
        $timestampServer.Process.Dispose()
    }

    $moduleDir = Join-Path $temp 'PortableModule'
    $nestedDir = Join-Path $moduleDir 'Private'
    New-Item -ItemType Directory -Force -Path $nestedDir | Out-Null
    Set-Content -LiteralPath (Join-Path $moduleDir 'PortableModule.psm1') -Value 'function Get-PortableGreeting { "hello" }' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $moduleDir 'PortableModule.psd1') -Value "@{ RootModule = 'PortableModule.psm1'; ModuleVersion = '1.0.0'; GUID = '$([System.Guid]::NewGuid())' }" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $moduleDir 'PortableModule.Types.ps1xml') -Value '<Types />' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $nestedDir 'Helper.ps1') -Value '$script:PortableHelper = $true' -Encoding UTF8
    $moduleSigned = @(Set-PsignSignature -LiteralPath $moduleDir -CertificatePath $certPath -PrivateKeyPath $keyPath)
    if ($moduleSigned.Count -ne 4) {
        throw "Expected 4 signed PowerShell module files, got $($moduleSigned.Count)."
    }
    if (@($moduleSigned | Where-Object Status -ne 'Valid').Count -ne 0) {
        throw "Expected all signed module files to be Valid, got: $($moduleSigned | ConvertTo-Json -Depth 4)"
    }
    foreach ($moduleSignature in $moduleSigned) {
        Assert-SignerCertificate -Signature $moduleSignature -ExpectedCertificate $cert -Label "module signing response $($moduleSignature.Path)"
    }
    $moduleValidated = @(Get-PsignSignature -LiteralPath $moduleDir)
    if ($moduleValidated.Count -ne 4) {
        throw "Expected 4 validated PowerShell module files, got $($moduleValidated.Count)."
    }
    if (@($moduleValidated | Where-Object Status -ne 'Valid').Count -ne 0) {
        throw "Expected all validated module files to be Valid, got: $($moduleValidated | ConvertTo-Json -Depth 4)"
    }

    $unsignedMsix = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'msix') 'sample.msix'
    $msixWork = Join-Path $temp 'sample.msix'
    Copy-Item $unsignedMsix $msixWork
    $msixBefore = Get-PsignSignature -LiteralPath $msixWork
    if ($msixBefore.Status -notin @('NotSigned', 'Incompatible')) {
        throw "Expected unsigned MSIX preflight status before signing, got $($msixBefore.Status)."
    }
    $msixSigned = Set-PsignSignature -LiteralPath $msixWork -PfxPath $pfxPath -Password $pfxPassword
    if ($msixSigned.Status -ne 'Valid') {
        throw "Expected Valid after MSIX signing, got $($msixSigned.Status): $($msixSigned.StatusMessage)"
    }
    Assert-SignerCertificate -Signature $msixSigned -ExpectedCertificate $cert -Label 'MSIX signing response'
    $msixAfter = Get-PsignSignature -LiteralPath $msixWork
    if ($msixAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PsignSignature for signed MSIX, got $($msixAfter.Status): $($msixAfter.StatusMessage)"
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
}
