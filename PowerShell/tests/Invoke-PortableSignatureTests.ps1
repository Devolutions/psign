param(
    [string] $Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$buildScript = Join-Path (Join-Path $repo 'PowerShell') 'build.ps1'
& $buildScript -Configuration $Configuration

$modulePath = Join-Path (Join-Path (Join-Path $repo 'PowerShell') 'Devolutions.Psign') 'Devolutions.Psign.psd1'
Import-Module $modulePath -Force

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp | Out-Null
try {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=psign portable test',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert = $request.CreateSelfSigned(
        [System.DateTimeOffset]::UtcNow.AddDays(-1),
        [System.DateTimeOffset]::UtcNow.AddDays(30))
    $certPath = Join-Path $temp 'signer.cer'
    $keyPath = Join-Path $temp 'signer.key'
    $pfxPath = Join-Path $temp 'signer.pfx'
    $pfxPassword = ConvertTo-SecureString -String 'portable-test' -AsPlainText -Force
    [System.IO.File]::WriteAllBytes($certPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [System.IO.File]::WriteAllText(
        $keyPath,
        [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $rsa.ExportPkcs8PrivateKey()))
    [System.IO.File]::WriteAllBytes($pfxPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, 'portable-test'))

    $unsigned = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'pe') 'tiny32-pe-alias.exe'
    $work = Join-Path $temp 'tiny.exe'
    Copy-Item $unsigned $work

    if (-not (Get-Command Get-PortableSignature -ErrorAction SilentlyContinue)) {
        throw 'Get-PortableSignature was not exported.'
    }
    if (-not (Get-Command Set-PortableSignature -ErrorAction SilentlyContinue)) {
        throw 'Set-PortableSignature was not exported.'
    }

    $before = Get-PortableSignature -LiteralPath $work
    if ($before.Status -ne 'NotSigned') {
        throw "Expected NotSigned before signing, got $($before.Status)."
    }

    $signed = Set-PortableSignature -LiteralPath $work -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($signed.Status -ne 'Valid') {
        throw "Expected Valid after signing, got $($signed.Status): $($signed.StatusMessage)"
    }

    $after = Get-PortableSignature -LiteralPath $work
    if ($after.Status -ne 'Valid') {
        throw "Expected Valid from Get-PortableSignature after signing, got $($after.Status)."
    }

    $length = (Get-Item -LiteralPath $work).Length
    Set-PortableSignature -LiteralPath $work -CertificatePath $certPath -PrivateKeyPath $keyPath -WhatIf | Out-Null
    if ((Get-Item -LiteralPath $work).Length -ne $length) {
        throw 'Set-PortableSignature -WhatIf mutated the file.'
    }

    $unsignedCab = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'cab') 'sample.cab'
    $cabWork = Join-Path $temp 'sample.cab'
    Copy-Item $unsignedCab $cabWork
    $cabSigned = Set-PortableSignature -LiteralPath $cabWork -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($cabSigned.Status -ne 'Valid') {
        throw "Expected Valid after CAB signing, got $($cabSigned.Status): $($cabSigned.StatusMessage)"
    }
    $cabAfter = Get-PortableSignature -LiteralPath $cabWork
    if ($cabAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PortableSignature for signed CAB, got $($cabAfter.Status): $($cabAfter.StatusMessage)"
    }

    $unsignedMsi = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'installer') 'tiny.msi'
    $msiWork = Join-Path $temp 'tiny.msi'
    Copy-Item $unsignedMsi $msiWork
    $msiSigned = Set-PortableSignature -LiteralPath $msiWork -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($msiSigned.Status -ne 'Valid') {
        throw "Expected Valid after MSI signing, got $($msiSigned.Status): $($msiSigned.StatusMessage)"
    }
    $msiAfter = Get-PortableSignature -LiteralPath $msiWork
    if ($msiAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PortableSignature for signed MSI, got $($msiAfter.Status): $($msiAfter.StatusMessage)"
    }

    $zipSource = Join-Path $temp 'zip-source'
    New-Item -ItemType Directory -Force -Path $zipSource | Out-Null
    Set-Content -LiteralPath (Join-Path $zipSource 'payload.txt') -Value 'portable zip authenticode' -Encoding UTF8
    $zipWork = Join-Path $temp 'payload.zip'
    Compress-Archive -LiteralPath (Join-Path $zipSource 'payload.txt') -DestinationPath $zipWork
    $zipSigned = Set-PortableSignature -LiteralPath $zipWork -CertificatePath $certPath -PrivateKeyPath $keyPath
    if ($zipSigned.Status -ne 'Valid') {
        throw "Expected Valid after ZIP signing, got $($zipSigned.Status): $($zipSigned.StatusMessage)"
    }
    $zipAfter = Get-PortableSignature -LiteralPath $zipWork
    if ($zipAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PortableSignature for signed ZIP, got $($zipAfter.Status): $($zipAfter.StatusMessage)"
    }

    $scriptPath = Join-Path $temp 'Invoke-Test.ps1'
    Set-Content -LiteralPath $scriptPath -Value @'
param([string] $Name = "portable")
"Hello $Name"
'@ -Encoding UTF8
    $scriptSigned = Set-PortableSignature -LiteralPath $scriptPath -Certificate $cert
    if ($scriptSigned.Status -ne 'Valid') {
        throw "Expected Valid for signed PowerShell script, got $($scriptSigned.Status): $($scriptSigned.StatusMessage)"
    }
    $scriptAfter = Get-PortableSignature -LiteralPath $scriptPath
    if ($scriptAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PortableSignature for signed script, got $($scriptAfter.Status)."
    }
    Add-Content -LiteralPath $scriptPath -Value '# tamper'
    $scriptTampered = Get-PortableSignature -LiteralPath $scriptPath
    if ($scriptTampered.Status -ne 'HashMismatch') {
        throw "Expected HashMismatch for tampered signed script, got $($scriptTampered.Status): $($scriptTampered.StatusMessage)"
    }

    $moduleDir = Join-Path $temp 'PortableModule'
    $nestedDir = Join-Path $moduleDir 'Private'
    New-Item -ItemType Directory -Force -Path $nestedDir | Out-Null
    Set-Content -LiteralPath (Join-Path $moduleDir 'PortableModule.psm1') -Value 'function Get-PortableGreeting { "hello" }' -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $moduleDir 'PortableModule.psd1') -Value "@{ RootModule = 'PortableModule.psm1'; ModuleVersion = '1.0.0'; GUID = '$([System.Guid]::NewGuid())' }" -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $nestedDir 'Helper.ps1') -Value '$script:PortableHelper = $true' -Encoding UTF8
    $moduleSigned = @(Set-PortableSignature -LiteralPath $moduleDir -CertificatePath $certPath -PrivateKeyPath $keyPath)
    if ($moduleSigned.Count -ne 3) {
        throw "Expected 3 signed PowerShell module files, got $($moduleSigned.Count)."
    }
    if (@($moduleSigned | Where-Object Status -ne 'Valid').Count -ne 0) {
        throw "Expected all signed module files to be Valid, got: $($moduleSigned | ConvertTo-Json -Depth 4)"
    }
    $moduleValidated = @(Get-PortableSignature -LiteralPath $moduleDir)
    if ($moduleValidated.Count -ne 3) {
        throw "Expected 3 validated PowerShell module files, got $($moduleValidated.Count)."
    }
    if (@($moduleValidated | Where-Object Status -ne 'Valid').Count -ne 0) {
        throw "Expected all validated module files to be Valid, got: $($moduleValidated | ConvertTo-Json -Depth 4)"
    }

    $unsignedMsix = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $repo 'tests') 'fixtures') 'generated-unsigned') 'msix') 'sample.msix'
    $msixWork = Join-Path $temp 'sample.msix'
    Copy-Item $unsignedMsix $msixWork
    $msixBefore = Get-PortableSignature -LiteralPath $msixWork
    if ($msixBefore.Status -notin @('NotSigned', 'Incompatible')) {
        throw "Expected unsigned MSIX preflight status before signing, got $($msixBefore.Status)."
    }
    $msixSigned = Set-PortableSignature -LiteralPath $msixWork -PfxPath $pfxPath -Password $pfxPassword
    if ($msixSigned.Status -ne 'Valid') {
        throw "Expected Valid after MSIX signing, got $($msixSigned.Status): $($msixSigned.StatusMessage)"
    }
    $msixAfter = Get-PortableSignature -LiteralPath $msixWork
    if ($msixAfter.Status -ne 'Valid') {
        throw "Expected Valid from Get-PortableSignature for signed MSIX, got $($msixAfter.Status): $($msixAfter.StatusMessage)"
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
}
