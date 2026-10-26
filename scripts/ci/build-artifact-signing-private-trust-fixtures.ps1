#Requires -Version 7.0
# Build synthetic Azure Artifact Signing *Private Trust* fixtures for the non-PE formats.
#
# A throwaway root CA and a signer certificate carrying the Private Trust identity EKU
# (1.3.6.1.4.1.311.97.1.3.1.<id>) plus code signing are created in memory with
# CertificateRequest (no certificate store is touched), then used to sign:
#   - sample.js    (signtool, WSH SIP)
#   - sample.msix  (signtool, AppX SIP; the publisher must equal the signer subject)
#   - sample.nupkg (psign-tool portable nupkg-sign; `dotnet nuget sign` refuses untrusted roots)
#   - sample.vsix  (System.IO.Packaging.PackageDigitalSignatureManager via Windows PowerShell)
# No timestamps are applied, so verification uses --artifact-signing-allow-missing-timestamp.
#
# Requires Windows, the Windows SDK signtool.exe, Windows PowerShell 5.1, and a built psign-tool:
#   cargo build
#   pwsh -NoProfile -File .\scripts\ci\build-artifact-signing-private-trust-fixtures.ps1
param(
    [string] $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string] $PublisherId = '11.22.33.44.55.66.77.88',
    [string] $SignTool,
    [string] $PsignTool
)

$ErrorActionPreference = 'Stop'
$X509 = 'System.Security.Cryptography.X509Certificates'

$fixtures = Join-Path $WorkspaceRoot 'tests\fixtures'
$outDir = Join-Path $fixtures 'artifact-signing\private-trust'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$work = Join-Path ([IO.Path]::GetTempPath()) ("psign-aas-pt-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null

if (-not $SignTool) {
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
        Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}
if (-not $SignTool) { throw 'signtool.exe not found; pass -SignTool' }
if (-not $PsignTool) { $PsignTool = Join-Path $WorkspaceRoot 'target\debug\psign-tool.exe' }
if (-not (Test-Path $PsignTool)) { throw "psign-tool not found at $PsignTool; run cargo build or pass -PsignTool" }

$sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
$pkcs1 = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
$notBefore = [DateTimeOffset]::new(2026, 1, 1, 0, 0, 0, [TimeSpan]::Zero)

# Root CA
$rootKey = [System.Security.Cryptography.RSA]::Create(2048)
$rootReq = New-Object "$X509.CertificateRequest" 'CN=Psign Artifact Signing Private Trust Test Root', $rootKey, $sha256, $pkcs1
$rootReq.CertificateExtensions.Add((New-Object "$X509.X509BasicConstraintsExtension" $true, $false, 0, $true))
$rootReq.CertificateExtensions.Add((New-Object "$X509.X509KeyUsageExtension" ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign'), $true))
$rootReq.CertificateExtensions.Add((New-Object "$X509.X509SubjectKeyIdentifierExtension" $rootReq.PublicKey, $false))
$root = $rootReq.CreateSelfSigned($notBefore, $notBefore.AddYears(25))

# Signer: the subject must equal the MSIX fixture's Publisher.
$leafKey = [System.Security.Cryptography.RSA]::Create(2048)
$leafReq = New-Object "$X509.CertificateRequest" 'CN=Test Code Signing Certificate', $leafKey, $sha256, $pkcs1
$leafReq.CertificateExtensions.Add((New-Object "$X509.X509BasicConstraintsExtension" $false, $false, 0, $true))
$leafReq.CertificateExtensions.Add((New-Object "$X509.X509KeyUsageExtension" ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature), $true))
$ekus = [System.Security.Cryptography.OidCollection]::new()
$null = $ekus.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.4.1.311.97.1.3.1.$PublisherId"))
$null = $ekus.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
$leafReq.CertificateExtensions.Add((New-Object "$X509.X509EnhancedKeyUsageExtension" $ekus, $false))
$leafReq.CertificateExtensions.Add((New-Object "$X509.X509SubjectKeyIdentifierExtension" $leafReq.PublicKey, $false))
$serial = [byte[]](1..16 | ForEach-Object { Get-Random -Maximum 256 })
$serial[0] = $serial[0] -band 0x7f
$leafPublic = $leafReq.Create($root, $notBefore, $notBefore.AddYears(20), $serial)
$leaf = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($leafPublic, $leafKey)

$password = [Guid]::NewGuid().ToString('N')
$pfxPath = Join-Path $work 'signer.pfx'
$chain = New-Object "$X509.X509Certificate2Collection"
$null = $chain.Add($leaf)
$null = $chain.Add((New-Object "$X509.X509Certificate2" (, $root.RawData)))
[IO.File]::WriteAllBytes($pfxPath, $chain.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
$certPath = Join-Path $work 'signer.cer'
$keyPath = Join-Path $work 'signer.key'
[IO.File]::WriteAllBytes($certPath, $leafPublic.RawData)
[IO.File]::WriteAllText($keyPath, [System.Security.Cryptography.PemEncoding]::WriteString('PRIVATE KEY', $leafKey.ExportPkcs8PrivateKey()))
[IO.File]::WriteAllBytes((Join-Path $outDir 'root.cer'), $root.RawData)
$rootCertPath = Join-Path $work 'root.cer'
[IO.File]::WriteAllBytes($rootCertPath, $root.RawData)

function Invoke-SignTool([string] $Path) {
    $output = & $SignTool sign /f $pfxPath /p $password /fd SHA256 $Path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $Path`n$($output -join "`n")" }
}

# WSH script
$js = Join-Path $outDir 'sample.js'
Copy-Item -LiteralPath (Join-Path $fixtures 'unsigned-sample.js') -Destination $js -Force
Invoke-SignTool $js

# MSIX
$msix = Join-Path $outDir 'sample.msix'
Copy-Item -LiteralPath (Join-Path $fixtures 'generated-unsigned\msix\sample.msix') -Destination $msix -Force
Invoke-SignTool $msix

# NuGet
$nupkg = Join-Path $outDir 'sample.nupkg'
$output = & $PsignTool portable nupkg-sign (Join-Path $fixtures 'package-signing\unsigned\sample.nupkg') `
    --cert $certPath --key $keyPath --chain-cert $rootCertPath --output $nupkg --overwrite 2>&1
if ($LASTEXITCODE -ne 0) { throw "psign-tool nupkg-sign failed`n$($output -join "`n")" }

# VSIX: PackageDigitalSignatureManager exists only on .NET Framework.
$vsix = Join-Path $outDir 'sample.vsix'
Copy-Item -LiteralPath (Join-Path $fixtures 'package-signing\unsigned\sample.vsix') -Destination $vsix -Force
$env:PSIGN_FIXTURE_VSIX = $vsix
$env:PSIGN_FIXTURE_PFX = $pfxPath
$env:PSIGN_FIXTURE_PFX_PASSWORD = $password
try {
    $output = & powershell.exe -NoProfile -NonInteractive -Command {
        $ErrorActionPreference = 'Stop'
        Add-Type -AssemblyName WindowsBase
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($env:PSIGN_FIXTURE_PFX, $env:PSIGN_FIXTURE_PFX_PASSWORD)
        $package = [System.IO.Packaging.Package]::Open($env:PSIGN_FIXTURE_VSIX, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
        try {
            $manager = [System.IO.Packaging.PackageDigitalSignatureManager]::new($package)
            $manager.CertificateOption = [System.IO.Packaging.CertificateEmbeddingOption]::InSignaturePart
            $manager.HashAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256'
            $parts = [System.Collections.Generic.List[Uri]]::new()
            foreach ($part in $package.GetParts()) { $parts.Add($part.Uri) }
            $parts.Add([System.IO.Packaging.PackUriHelper]::GetRelationshipPartUri($manager.SignatureOrigin))
            $parts.Add($manager.SignatureOrigin)
            $parts.Add([System.IO.Packaging.PackUriHelper]::GetRelationshipPartUri([Uri]::new('/', [UriKind]::RelativeOrAbsolute)))
            $null = $manager.Sign($parts, $cert)
        }
        finally {
            $package.Close()
        }
    } 2>&1
    if ($LASTEXITCODE -ne 0) { throw "VSIX signing failed`n$($output -join "`n")" }
}
finally {
    Remove-Item Env:\PSIGN_FIXTURE_VSIX, Env:\PSIGN_FIXTURE_PFX, Env:\PSIGN_FIXTURE_PFX_PASSWORD -ErrorAction SilentlyContinue
}

Remove-Item -LiteralPath $work -Recurse -Force
Get-ChildItem $outDir | Select-Object Name, Length
"publisher_id=$PublisherId"
