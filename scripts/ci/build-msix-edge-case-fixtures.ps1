# Build comprehensive unsigned and signed MSIX/AppX-family edge-case fixtures.
#
# Requires Windows SDK (MakeAppx.exe + SignTool.exe), Cargo/psign-tool, and the
# vendored Devolutions public test certificate PFX.
#
# Regenerate from repository root:
#   pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\ci\build-msix-edge-case-fixtures.ps1 -WorkspaceRoot . -Force
param(
    [string]$WorkspaceRoot = "",
    [string]$OutputDir = "",
    [string]$SignToolPath = "",
    [string]$MakeAppxPath = "",
    [string]$PsignToolPath = "",
    [string]$PfxPath = "",
    [string]$PfxPassword = "CodeSign123!",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$WorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path $WorkspaceRoot "tests\fixtures\msix-edge-cases"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $WorkspaceRoot $OutputDir
}

if (-not $PfxPath) {
    $PfxPath = Join-Path $WorkspaceRoot "tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx"
}
elseif (-not [System.IO.Path]::IsPathRooted($PfxPath)) {
    $PfxPath = Join-Path $WorkspaceRoot $PfxPath
}
if (-not (Test-Path -LiteralPath $PfxPath)) {
    throw "PFX not found: $PfxPath"
}

function Resolve-KitTool {
    param([Parameter(Mandatory)][string]$ExeName, [string]$ExplicitPath = "")
    if ($ExplicitPath -and (Test-Path -LiteralPath $ExplicitPath)) {
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }
    foreach ($pf in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not $pf) { continue }
        $binRoot = Join-Path $pf "Windows Kits\10\bin"
        if (-not (Test-Path -LiteralPath $binRoot)) { continue }
        $hit = Get-ChildItem -LiteralPath $binRoot -Recurse -Filter $ExeName -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\|\\amd64\\' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    $cmd = Get-Command $ExeName -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "$ExeName not found under Windows Kits or PATH."
}

$MakeAppxPath = Resolve-KitTool -ExeName "makeappx.exe" -ExplicitPath $MakeAppxPath
$SignToolPath = Resolve-KitTool -ExeName "signtool.exe" -ExplicitPath $SignToolPath

if (-not $PsignToolPath) {
    $candidate = Join-Path $WorkspaceRoot "target\debug\psign-tool.exe"
    if (-not (Test-Path -LiteralPath $candidate)) {
        Push-Location $WorkspaceRoot
        try {
            & cargo build -p psign --bin psign-tool --locked
            if ($LASTEXITCODE -ne 0) { throw "cargo build psign-tool failed" }
        }
        finally {
            Pop-Location
        }
    }
    $PsignToolPath = (Resolve-Path -LiteralPath $candidate).Path
}

$pe32Source = Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny32.efi"
$pe64Source = Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny64.efi"
foreach ($pe in @($pe32Source, $pe64Source)) {
    if (-not (Test-Path -LiteralPath $pe)) { throw "PE source missing: $pe" }
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

if ((Test-Path -LiteralPath $OutputDir) -and -not $Force) {
    throw "Output directory already exists: $OutputDir. Pass -Force to replace it."
}
if (Test-Path -LiteralPath $OutputDir) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}

$unsignedDir = Join-Path $OutputDir "unsigned"
$signedDir = Join-Path $OutputDir "signed"
$workDir = Join-Path $OutputDir "_work"
$workTemp = Join-Path $workDir "tmp"
New-Item -ItemType Directory -Force -Path $unsignedDir, $signedDir, $workDir, $workTemp | Out-Null

# Keep AppxBundleSip's AXS*.tmp staging inside our writable same-volume work directory
# rather than %SystemRoot%\Temp (whose CREATOR-OWNER DACL leaves moved bundles unreadable).
$savedTemp = $env:TEMP
$savedTmp = $env:TMP
$env:TEMP = $workTemp
$env:TMP = $workTemp

$pngBytes = [Convert]::FromBase64String(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)
$publisher = "CN=Test Code Signing Certificate"
$entries = [System.Collections.Generic.List[object]]::new()

function Convert-ToRepoPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    return ([System.IO.Path]::GetRelativePath($WorkspaceRoot, $full)).Replace('\', '/')
}

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string[]]$ArgsList, [string]$Context = "")
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = & $Exe @ArgsList 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $saved
    if ($code -ne 0) {
        throw "$Context ($Exe) failed with exit $code`n$($out -join "`n")"
    }
}

function Write-Utf8NoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $normalized = ($Content -replace "`r`n", "`n").TrimStart("`n")
    [System.IO.File]::WriteAllText($Path, $normalized, [System.Text.UTF8Encoding]::new($false))
}

function New-AppManifestXml {
    param(
        [string]$Name = "Psign.EdgeTest",
        [string]$Arch = "x64",
        [string]$Version = "1.0.0.0"
    )
    return @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="uap rescap">
  <Identity
    Name="$Name"
    Publisher="$publisher"
    Version="$Version"
    ProcessorArchitecture="$Arch" />
  <Properties>
    <DisplayName>Psign Edge Test</DisplayName>
    <PublisherDisplayName>Psign Test</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Applications>
    <Application Id="App" Executable="noop.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements
        DisplayName="Psign Edge Test"
        Description="Psign MSIX fixture"
        BackgroundColor="transparent"
        Square150x150Logo="Assets\StoreLogo.png"
        Square44x44Logo="Assets\StoreLogo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
"@
}

function New-ResourceManifestXml {
    param([string]$Name = "Psign.EdgeTest", [string]$Version = "1.0.0.0")
    return @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  IgnorableNamespaces="uap">
  <Identity
    Name="$Name"
    Publisher="$publisher"
    Version="$Version"
    ResourceId="scale-200" />
  <Properties>
    <DisplayName>Psign Edge Test Resources</DisplayName>
    <PublisherDisplayName>Psign Test</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
    <ResourcePackage>true</ResourcePackage>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" />
  </Dependencies>
  <Resources>
    <Resource uap:Scale="200" />
  </Resources>
</Package>
"@
}

function New-OptionalNonExecManifestXml {
    return @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
  xmlns:uap6="http://schemas.microsoft.com/appx/manifest/uap/windows10/6"
  IgnorableNamespaces="uap uap3 uap6">
  <Identity
    Name="Psign.EdgeTest.OptionalData"
    Publisher="$publisher"
    Version="1.0.0.0"
    ProcessorArchitecture="neutral" />
  <Properties>
    <DisplayName>Psign Optional NonExec Add-on</DisplayName>
    <PublisherDisplayName>Psign Test</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
    <uap6:AllowExecution>false</uap6:AllowExecution>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22621.0" />
    <uap3:MainPackageDependency Name="Psign.EdgeTest" />
  </Dependencies>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
</Package>
"@
}

function New-BasicAppLayout {
    param([string]$Dir, [string]$Arch = "x64", [string]$PeSource = $pe64Source)
    New-Item -ItemType Directory -Force -Path (Join-Path $Dir "Assets") | Out-Null
    Write-Utf8NoBom -Path (Join-Path $Dir "AppxManifest.xml") -Content (New-AppManifestXml -Arch $Arch)
    Copy-Item -LiteralPath $PeSource -Destination (Join-Path $Dir "noop.exe") -Force
    [System.IO.File]::WriteAllBytes((Join-Path $Dir "Assets\StoreLogo.png"), $pngBytes)
}

function Add-FixtureRecord {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Extension,
        [string]$Digest = "SHA256",
        [string]$UnsignedPath = "",
        [string]$SignedPath = "",
        [string]$SignTool = "",
        [string]$ExpectedPortableVerify = "valid",
        [string]$ExpectedPortableSign = "supported",
        [string]$ExpectedWindowsVerify = "valid",
        [string]$ExpectedWindowsSign = "supported",
        [bool]$HasCodeIntegrityCat = $false,
        [bool]$IsSparseBundle = $false,
        [bool]$IsEncrypted = $false,
        [bool]$IsUploadContainer = $false,
        [string]$Notes = ""
    )
    $rec = [ordered]@{
        id                       = $Id
        category                 = $Category
        extension                = $Extension
        digest                   = $Digest
        has_code_integrity_cat   = $HasCodeIntegrityCat
        is_sparse_bundle         = $IsSparseBundle
        is_encrypted             = $IsEncrypted
        is_upload_container      = $IsUploadContainer
        expected_portable_verify = $ExpectedPortableVerify
        expected_portable_sign   = $ExpectedPortableSign
        expected_windows_verify  = $ExpectedWindowsVerify
        expected_windows_sign    = $ExpectedWindowsSign
    }
    if ($UnsignedPath) {
        $u = Get-Item -LiteralPath $UnsignedPath
        $rec.unsigned_path = Convert-ToRepoPath -Path $u.FullName
        $rec.unsigned_size_bytes = $u.Length
        $rec.unsigned_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $u.FullName).Hash.ToLowerInvariant()
    }
    if ($SignedPath) {
        $s = Get-Item -LiteralPath $SignedPath
        $rec.signed_path = Convert-ToRepoPath -Path $s.FullName
        $rec.signed_size_bytes = $s.Length
        $rec.signed_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $s.FullName).Hash.ToLowerInvariant()
    }
    if ($SignTool) { $rec.sign_tool = $SignTool }
    if ($Notes) { $rec.notes = $Notes }
    $entries.Add($rec)
}

try {
    # Base x64, arm64, and x86 app layouts + scale-200 resource layout
    $layX64 = Join-Path $workDir "lay-x64"
    $layArm64 = Join-Path $workDir "lay-arm64"
    $layX86 = Join-Path $workDir "lay-x86"
    $layRes = Join-Path $workDir "lay-res"
    New-BasicAppLayout -Dir $layX64 -Arch "x64" -PeSource $pe64Source
    New-BasicAppLayout -Dir $layArm64 -Arch "arm64" -PeSource $pe64Source
    New-BasicAppLayout -Dir $layX86 -Arch "x86" -PeSource $pe32Source
    New-Item -ItemType Directory -Force -Path (Join-Path $layRes "Assets") | Out-Null
    Write-Utf8NoBom -Path (Join-Path $layRes "AppxManifest.xml") -Content (New-ResourceManifestXml)
    [System.IO.File]::WriteAllBytes((Join-Path $layRes "Assets\StoreLogo.png"), $pngBytes)
    [System.IO.File]::WriteAllBytes((Join-Path $layRes "Assets\StoreLogo.scale-200.png"), $pngBytes)

    # 1 & 2: Flat SHA-384 and SHA-512 MSIX packages
    foreach ($hash in @("SHA384", "SHA512")) {
        $lower = $hash.ToLowerInvariant()
        $uPath = Join-Path $unsignedDir "flat-$lower.msix"
        $sPath = Join-Path $signedDir "flat-$lower.signed.msix"
        Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", $hash, "/d", $layX64, "/p", $uPath) -Context "pack flat-$lower"
        Copy-Item -LiteralPath $uPath -Destination $sPath -Force
        Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", $hash, "/f", $PfxPath, "/p", $PfxPassword, $sPath) -Context "sign flat-$lower"
        Add-FixtureRecord -Id "msix-flat-$lower" -Category "flat-msix" -Extension ".msix" -Digest $hash `
            -UnsignedPath $uPath -SignedPath $sPath -SignTool "signtool" -HasCodeIntegrityCat $true `
            -Notes "MakeAppx /h $hash + SignTool /fd $hash with CodeIntegrity.cat and AXCI."
    }

    # 3: Flat stored-only (/nc) MSIX package
    $uNoComp = Join-Path $unsignedDir "flat-nocompress.msix"
    $sNoComp = Join-Path $signedDir "flat-nocompress.signed.msix"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/nc", "/h", "SHA256", "/d", $layX64, "/p", $uNoComp) -Context "pack flat-nocompress"
    Copy-Item -LiteralPath $uNoComp -Destination $sNoComp -Force
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sNoComp) -Context "sign flat-nocompress"
    Add-FixtureRecord -Id "msix-flat-nocompress" -Category "flat-msix" -Extension ".msix" `
        -UnsignedPath $uNoComp -SignedPath $sNoComp -SignTool "signtool" -HasCodeIntegrityCat $true `
        -Notes "MakeAppx /nc stored payloads (AppxBlockMap Block elements omit Size)."

    # 4: Multi-block (>64 KiB) + b4:FileHash + nested special/UTF-8 paths + empty + incompressible payload
    $layMulti = Join-Path $workDir "lay-multiblock"
    New-BasicAppLayout -Dir $layMulti -Arch "x64" -PeSource $pe64Source
    New-Item -ItemType Directory -Force -Path (Join-Path $layMulti "Data"), (Join-Path $layMulti "Assets\Sub Dir") | Out-Null
    $sb = [System.Text.StringBuilder]::new(90000)
    for ($i = 0; $i -lt 2000; $i++) {
        [void]$sb.AppendFormat("block-line-{0:D5}-psign-multiblock-fixture`n", ($i % 37))
    }
    Write-Utf8NoBom -Path (Join-Path $layMulti "Data\large-compressible.txt") -Content $sb.ToString()
    Write-Utf8NoBom -Path (Join-Path $layMulti "Assets\Sub Dir\notes & config.xml") -Content '<?xml version="1.0" encoding="utf-8"?><Config mode="edge"/>'
    $utf8FileName = "donn" + [char]0x00E9 + "es-utf8.txt"
    Write-Utf8NoBom -Path (Join-Path $layMulti ("Assets\" + $utf8FileName)) -Content "UTF-8 part name fixture`n"
    [System.IO.File]::WriteAllBytes((Join-Path $layMulti "Assets\empty.bin"), [byte[]]@())
    $noise = New-Object byte[] 256
    for ($blk = 0; $blk -lt 8; $blk++) {
        $blockHash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes("psign-incompressible-seed-$blk"))
        [Array]::Copy($blockHash, 0, $noise, $blk * 32, 32)
    }
    [System.IO.File]::WriteAllBytes((Join-Path $layMulti "Assets\noise.bin"), $noise)

    $uMulti = Join-Path $unsignedDir "flat-multiblock-paths.msix"
    $sMulti = Join-Path $signedDir "flat-multiblock-paths.signed.msix"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", "SHA256", "/d", $layMulti, "/p", $uMulti) -Context "pack flat-multiblock-paths"
    Copy-Item -LiteralPath $uMulti -Destination $sMulti -Force
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sMulti) -Context "sign flat-multiblock-paths"
    Add-FixtureRecord -Id "msix-flat-multiblock-paths" -Category "flat-msix" -Extension ".msix" `
        -UnsignedPath $uMulti -SignedPath $sMulti -SignTool "signtool" -HasCodeIntegrityCat $true `
        -Notes "2-block (>64 KiB) deflated payload with b4:FileHash, spaces/ampersand XML path, UTF-8 filename (bit 11), 0-byte empty file, and stored incompressible blob."

    # 5: Flat MSIX signed with /ph (PE page hashes in CodeIntegrity.cat)
    $uBaseX64 = Join-Path $workDir "base-x64.msix"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", "SHA256", "/d", $layX64, "/p", $uBaseX64) -Context "pack base-x64"
    $sPageHash = Join-Path $signedDir "flat-pagehashes.signed.msix"
    Copy-Item -LiteralPath $uBaseX64 -Destination $sPageHash -Force
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/ph", "/f", $PfxPath, "/p", $PfxPassword, $sPageHash) -Context "sign flat-pagehashes"
    Add-FixtureRecord -Id "msix-flat-pagehashes" -Category "flat-msix" -Extension ".msix" `
        -SignedPath $sPageHash -SignTool "signtool /ph" -HasCodeIntegrityCat $true `
        -Notes "Signed with /ph (SPC_INC_PE_PAGE_HASHES_FLAG 0x100) embedding PE page hashes inside AppxMetadata/CodeIntegrity.cat."

    # 6: Resource packages (.msix and .appx) — no PE payload -> 4-digest SpcIndirectData without CodeIntegrity.cat / AXCI
    foreach ($ext in @(".msix", ".appx")) {
        $tag = $ext.TrimStart('.')
        $uRes = Join-Path $unsignedDir "flat-resource$ext"
        $sRes = Join-Path $signedDir "flat-resource.signed$ext"
        Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", "SHA256", "/d", $layRes, "/p", $uRes) -Context "pack flat-resource$ext"
        Copy-Item -LiteralPath $uRes -Destination $sRes -Force
        Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sRes) -Context "sign flat-resource$ext"
        Add-FixtureRecord -Id "msix-flat-resource-$tag" -Category "flat-resource" -Extension $ext `
            -UnsignedPath $uRes -SignedPath $sRes -SignTool "signtool" -HasCodeIntegrityCat $false `
            -Notes "ResourcePackage=true without PE files; produces 4-digest APPX indirect data without CodeIntegrity.cat or AXCI."
    }

    # 7: Optional non-executable package (uap10:AllowExecution=false + data.dll PE -> suppresses CodeIntegrity.cat)
    $layOpt = Join-Path $workDir "lay-optional"
    New-Item -ItemType Directory -Force -Path (Join-Path $layOpt "Assets") | Out-Null
    Write-Utf8NoBom -Path (Join-Path $layOpt "AppxManifest.xml") -Content (New-OptionalNonExecManifestXml)
    Copy-Item -LiteralPath $pe64Source -Destination (Join-Path $layOpt "data.dll") -Force
    [System.IO.File]::WriteAllBytes((Join-Path $layOpt "Assets\StoreLogo.png"), $pngBytes)
    $uOpt = Join-Path $unsignedDir "flat-optional-nonexec.msix"
    $sOpt = Join-Path $signedDir "flat-optional-nonexec.signed.msix"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", "SHA256", "/d", $layOpt, "/p", $uOpt) -Context "pack flat-optional-nonexec"
    Copy-Item -LiteralPath $uOpt -Destination $sOpt -Force
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sOpt) -Context "sign flat-optional-nonexec"
    Add-FixtureRecord -Id "msix-flat-optional-nonexec" -Category "flat-optional" -Extension ".msix" `
        -UnsignedPath $uOpt -SignedPath $sOpt -SignTool "signtool" -HasCodeIntegrityCat $false `
        -Notes "Optional package with uap10:AllowExecution=false and uap3:MainPackageDependency; suppresses CodeIntegrity.cat even with data.dll."

    # 8: Windows .pkgSignConfig SkipPackageContentHash=true (AXPC sentinel 43da04fa...)
    $sSkipAxpc = Join-Path $signedDir "flat-skip-pcontent-hash.signed.msix"
    Copy-Item -LiteralPath $uBaseX64 -Destination $sSkipAxpc -Force
    $pkgCfgPath = Join-Path $workDir "skip-axpc.pkgSignConfig"
    $pkgCfgXml = @"
<?xml version="1.0" encoding="utf-8"?>
<PackageSignConfig xmlns="http://schemas.microsoft.com/msix/signing/2018">
  <Package Uri="$sSkipAxpc" PackageType="msix" />
  <AppxSipSettings>
    <SkipPackageContentHash Value="true" />
  </AppxSipSettings>
</PackageSignConfig>
"@
    Write-Utf8NoBom -Path $pkgCfgPath -Content $pkgCfgXml
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $pkgCfgPath) -Context "sign .pkgSignConfig SkipPackageContentHash"
    Add-FixtureRecord -Id "msix-flat-skip-pcontent-hash" -Category "flat-pkgsignconfig" -Extension ".msix" `
        -SignedPath $sSkipAxpc -SignTool "signtool .pkgSignConfig" -HasCodeIntegrityCat $true `
        -Notes "Signed through AppxSip .pkgSignConfig with SkipPackageContentHash=true (AXPC carries the 43da04fa... sentinel)."

    # 9: Plain non-MakeAppx ZIP input (no AppxBlockMap.xml, no [Content_Types].xml) + portable-signed output
    $uPlainZip = Join-Path $unsignedDir "flat-plain-zip.msix"
    $sPlainZip = Join-Path $signedDir "flat-plain-zip.portable-signed.msix"
    $fs = [System.IO.File]::Open($uPlainZip, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite)
    try {
        $za = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($pair in @(
                @{ Name = "AppxManifest.xml"; Bytes = [System.Text.UTF8Encoding]::new($false).GetBytes((New-AppManifestXml -Arch "x64")) },
                @{ Name = "noop.exe"; Bytes = [System.IO.File]::ReadAllBytes($pe64Source) },
                @{ Name = "Assets/StoreLogo.png"; Bytes = $pngBytes }
            )) {
                $ze = $za.CreateEntry($pair.Name, [System.IO.Compression.CompressionLevel]::Optimal)
                $ze.LastWriteTime = [System.DateTimeOffset]::new(2024, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
                $st = $ze.Open()
                try { $st.Write($pair.Bytes, 0, $pair.Bytes.Length) }
                finally { $st.Dispose() }
            }
        }
        finally { $za.Dispose() }
    }
    finally { $fs.Dispose() }
    Copy-Item -LiteralPath $uPlainZip -Destination $sPlainZip -Force
    Invoke-Checked -Exe $PsignToolPath -ArgsList @("--mode", "portable", "sign", "--pfx", $PfxPath, "--password", $PfxPassword, "--digest", "sha256", $sPlainZip) -Context "portable sign flat-plain-zip"
    Add-FixtureRecord -Id "msix-flat-plain-zip" -Category "flat-plain-zip" -Extension ".msix" `
        -UnsignedPath $uPlainZip -SignedPath $sPlainZip -SignTool "psign portable sign" -HasCodeIntegrityCat $false `
        -ExpectedWindowsSign "unsupported-missing-blockmap" `
        -Notes "Plain generic ZIP with no AppxBlockMap.xml or [Content_Types].xml; portable sign generates full AppxPackaging ZIP64 + block map."

    # Build child packages for multi-package bundles
    $uChildArm64Msix = Join-Path $workDir "app-arm64.msix"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", "SHA256", "/d", $layArm64, "/p", $uChildArm64Msix) -Context "pack app-arm64.msix"
    $uChildX86Appx = Join-Path $workDir "app-x86.appx"
    $uChildX64Appx = Join-Path $workDir "app-x64.appx"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", "SHA256", "/d", $layX86, "/p", $uChildX86Appx) -Context "pack app-x86.appx"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("pack", "/o", "/h", "SHA256", "/d", $layX64, "/p", $uChildX64Appx) -Context "pack app-x64.appx"

    $sChildX64Msix = Join-Path $workDir "app-x64.signed.msix"
    $sChildArm64Msix = Join-Path $workDir "app-arm64.signed.msix"
    $sChildResMsix = Join-Path $signedDir "flat-resource.signed.msix"
    Copy-Item -LiteralPath $uBaseX64 -Destination $sChildX64Msix -Force
    Copy-Item -LiteralPath $uChildArm64Msix -Destination $sChildArm64Msix -Force
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sChildX64Msix) -Context "sign app-x64.msix"
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sChildArm64Msix) -Context "sign app-arm64.msix"

    # 10: Multi-package .msixbundle (unsigned children: x64 + arm64 + subdirectory resources\scale-200.msix)
    $mapMultiMsix = Join-Path $workDir "bundle-multi-msix.map.txt"
    $uResMsix = Join-Path $unsignedDir "flat-resource.msix"
    Write-Utf8NoBom -Path $mapMultiMsix -Content @"
[Files]
"$uBaseX64" "app-x64.msix"
"$uChildArm64Msix" "app-arm64.msix"
"$uResMsix" "resources\scale-200.msix"
"@
    $uBundleMultiMsix = Join-Path $unsignedDir "bundle-multi.msixbundle"
    $sBundleMultiMsix = Join-Path $signedDir "bundle-multi.signed.msixbundle"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("bundle", "/o", "/bv", "1.0.0.0", "/f", $mapMultiMsix, "/p", $uBundleMultiMsix) -Context "bundle multi msix"
    Copy-Item -LiteralPath $uBundleMultiMsix -Destination $sBundleMultiMsix -Force
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sBundleMultiMsix) -Context "sign bundle-multi.msixbundle"
    Add-FixtureRecord -Id "msixbundle-multi-unsigned-children" -Category "bundle-msix" -Extension ".msixbundle" `
        -UnsignedPath $uBundleMultiMsix -SignedPath $sBundleMultiMsix -SignTool "signtool" `
        -Notes "3-child .msixbundle (app-x64.msix, app-arm64.msix, subdirectory resources\scale-200.msix) with ZIP64 data descriptors and unsigned source children."

    # 11: Multi-package .msixbundle built from pre-signed children (pwsh-distro workflow) + portable-signed outer bundle
    $mapPresignedMsix = Join-Path $workDir "bundle-presigned-msix.map.txt"
    Write-Utf8NoBom -Path $mapPresignedMsix -Content @"
[Files]
"$sChildX64Msix" "app-x64.msix"
"$sChildArm64Msix" "app-arm64.msix"
"$sChildResMsix" "resources\scale-200.msix"
"@
    $uBundlePresigned = Join-Path $unsignedDir "bundle-multi-presigned-children.msixbundle"
    $sBundlePresigned = Join-Path $signedDir "bundle-multi-presigned-children.portable-signed.msixbundle"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("bundle", "/o", "/bv", "1.0.0.0", "/f", $mapPresignedMsix, "/p", $uBundlePresigned) -Context "bundle presigned msix"
    Copy-Item -LiteralPath $uBundlePresigned -Destination $sBundlePresigned -Force
    Invoke-Checked -Exe $PsignToolPath -ArgsList @("--mode", "portable", "sign", "--pfx", $PfxPath, "--password", $PfxPassword, "--digest", "sha256", $sBundlePresigned) -Context "portable sign presigned msixbundle"
    Add-FixtureRecord -Id "msixbundle-multi-presigned-children" -Category "bundle-msix" -Extension ".msixbundle" `
        -UnsignedPath $uBundlePresigned -SignedPath $sBundlePresigned -SignTool "psign portable sign" `
        -Notes "pwsh-distro pipeline fixture: pre-signed x64 + arm64 + subdirectory resource MSIXs bundled with MakeAppx ZIP64 descriptors, then portable-signed preserving child bytes and recalculating manifest offsets."

    # 12: Genuine multi-package .appxbundle containing genuine .appx children (x86 + x64 + resources\scale-200.appx)
    $uResAppx = Join-Path $unsignedDir "flat-resource.appx"
    $mapMultiAppx = Join-Path $workDir "bundle-multi-appx.map.txt"
    Write-Utf8NoBom -Path $mapMultiAppx -Content @"
[Files]
"$uChildX86Appx" "app-x86.appx"
"$uChildX64Appx" "app-x64.appx"
"$uResAppx" "resources\scale-200.appx"
"@
    $uBundleMultiAppx = Join-Path $unsignedDir "bundle-multi.appxbundle"
    $sBundleMultiAppx = Join-Path $signedDir "bundle-multi.signed.appxbundle"
    Invoke-Checked -Exe $MakeAppxPath -ArgsList @("bundle", "/o", "/bv", "1.0.0.0", "/f", $mapMultiAppx, "/p", $uBundleMultiAppx) -Context "bundle multi appx"
    Copy-Item -LiteralPath $uBundleMultiAppx -Destination $sBundleMultiAppx -Force
    Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sBundleMultiAppx) -Context "sign bundle-multi.appxbundle"
    Add-FixtureRecord -Id "appxbundle-multi-genuine" -Category "bundle-appx" -Extension ".appxbundle" `
        -UnsignedPath $uBundleMultiAppx -SignedPath $sBundleMultiAppx -SignTool "signtool" `
        -Notes "Genuine 3-child .appxbundle containing .appx children (app-x86.appx, app-x64.appx, resources\scale-200.appx)."

    # 13: Sparse (/fb) .msixbundle and .appxbundle (external child references without Offset/Size or ZIP entries)
    foreach ($spec in @(
        @{ Ext = ".msixbundle"; Map = $mapPresignedMsix; Id = "msixbundle-sparse-fb" },
        @{ Ext = ".appxbundle"; Map = $mapMultiAppx; Id = "appxbundle-sparse-fb" }
    )) {
        $uSparse = Join-Path $unsignedDir ("bundle-sparse" + $spec.Ext)
        $sSparse = Join-Path $signedDir ("bundle-sparse.signed" + $spec.Ext)
        Invoke-Checked -Exe $MakeAppxPath -ArgsList @("bundle", "/o", "/bv", "1.0.0.0", "/fb", "/f", $spec.Map, "/p", $uSparse) -Context "bundle sparse $($spec.Ext)"
        Copy-Item -LiteralPath $uSparse -Destination $sSparse -Force
        Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sSparse) -Context "sign sparse $($spec.Ext)"
        Add-FixtureRecord -Id $spec.Id -Category "bundle-sparse" -Extension $spec.Ext `
            -UnsignedPath $uSparse -SignedPath $sSparse -SignTool "signtool" -IsSparseBundle $true `
            -Notes "MakeAppx /fb fully sparse bundle where child packages are external references without Offset/Size attributes."
    }

    # 14: Real encrypted packages & bundles (.emsix, .eappx, .emsixbundle, .eappxbundle) via MakeAppx /kt global test key
    foreach ($encSpec in @(
        @{ Id = "encrypted-emsix"; Ext = ".emsix"; Kind = "flat"; Src = $uBaseX64 },
        @{ Id = "encrypted-eappx"; Ext = ".eappx"; Kind = "flat"; Src = $uChildX64Appx },
        @{ Id = "encrypted-emsixbundle"; Ext = ".emsixbundle"; Kind = "bundle"; Map = $mapMultiMsix },
        @{ Id = "encrypted-eappxbundle"; Ext = ".eappxbundle"; Kind = "bundle"; Map = $mapMultiAppx }
    )) {
        $uEnc = Join-Path $unsignedDir ("sample" + $encSpec.Ext)
        $sEnc = Join-Path $signedDir ("sample.signed" + $encSpec.Ext)
        if ($encSpec.Kind -eq "flat") {
            Invoke-Checked -Exe $MakeAppxPath -ArgsList @("encrypt", "/o", "/p", $encSpec.Src, "/ep", $uEnc, "/kt") -Context "encrypt $($encSpec.Ext)"
        }
        else {
            Invoke-Checked -Exe $MakeAppxPath -ArgsList @("bundle", "/o", "/bv", "1.0.0.0", "/f", $encSpec.Map, "/ep", $uEnc, "/kt") -Context "bundle encrypt $($encSpec.Ext)"
        }
        Copy-Item -LiteralPath $uEnc -Destination $sEnc -Force
        Invoke-Checked -Exe $SignToolPath -ArgsList @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, $sEnc) -Context "sign $($encSpec.Ext)"
        Add-FixtureRecord -Id $encSpec.Id -Category "encrypted-appx" -Extension $encSpec.Ext `
            -UnsignedPath $uEnc -SignedPath $sEnc -SignTool "signtool" -IsEncrypted $true `
            -ExpectedPortableVerify "reject-encrypted" -ExpectedPortableSign "reject-encrypted" `
            -ExpectedWindowsVerify "valid" -ExpectedWindowsSign "supported" `
            -Notes "Real MakeAppx /kt (global test key) encrypted package/bundle signed via Windows EappxSip / EappxBundleSip."
    }

    # 15: Store upload containers (.msixupload and .appxupload) wrapping multi-child bundle + .appxsym
    foreach ($upSpec in @(
        @{ Id = "upload-msixupload"; Ext = ".msixupload"; BundlePath = $uBundleMultiMsix; BundleName = "Psign.EdgeTest_1.0.0.0.msixbundle" },
        @{ Id = "upload-appxupload"; Ext = ".appxupload"; BundlePath = $uBundleMultiAppx; BundleName = "Psign.EdgeTest_1.0.0.0.appxbundle" }
    )) {
        $uUpload = Join-Path $unsignedDir ("sample" + $upSpec.Ext)
        $symZipPath = Join-Path $workDir ("symbols" + $upSpec.Ext + ".appxsym")
        $symFs = [System.IO.File]::Open($symZipPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite)
        try {
            $symZa = [System.IO.Compression.ZipArchive]::new($symFs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
            try {
                $se = $symZa.CreateEntry("noop.pdb", [System.IO.Compression.CompressionLevel]::Optimal)
                $se.LastWriteTime = [System.DateTimeOffset]::new(2024, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
                $st = $se.Open()
                try {
                    $pdbStub = [System.Text.Encoding]::ASCII.GetBytes("Microsoft C/C++ MSF 7.00`r`npsign symbol placeholder`r`n")
                    $st.Write($pdbStub, 0, $pdbStub.Length)
                }
                finally { $st.Dispose() }
            }
            finally { $symZa.Dispose() }
        }
        finally { $symFs.Dispose() }

        $upFs = [System.IO.File]::Open($uUpload, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite)
        try {
            $upZa = [System.IO.Compression.ZipArchive]::new($upFs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
            try {
                foreach ($item in @(
                    @{ Name = $upSpec.BundleName; Bytes = [System.IO.File]::ReadAllBytes($upSpec.BundlePath) },
                    @{ Name = "Psign.EdgeTest_1.0.0.0_x64.appxsym"; Bytes = [System.IO.File]::ReadAllBytes($symZipPath) }
                )) {
                    $ue = $upZa.CreateEntry($item.Name, [System.IO.Compression.CompressionLevel]::Optimal)
                    $ue.LastWriteTime = [System.DateTimeOffset]::new(2024, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
                    $st = $ue.Open()
                    try { $st.Write($item.Bytes, 0, $item.Bytes.Length) }
                    finally { $st.Dispose() }
                }
            }
            finally { $upZa.Dispose() }
        }
        finally { $upFs.Dispose() }

        Add-FixtureRecord -Id $upSpec.Id -Category "upload-container" -Extension $upSpec.Ext `
            -UnsignedPath $uUpload -IsUploadContainer $true `
            -ExpectedPortableVerify "reject-upload-container" -ExpectedPortableSign "reject-upload-container" `
            -ExpectedWindowsVerify "reject-upload-container" -ExpectedWindowsSign "reject-upload-container" `
            -Notes "Store upload container (.appxsym + multi-child bundle); prepared inside-out via psign-tool code."
    }

    # 16: UTF-8 BOM 2021 .appinstaller (MainBundle + OptionalPackages + third-party Dependencies) + .p7 companion
    $uAppInst = Join-Path $unsignedDir "bundle-bom.appinstaller"
    $sAppInstCopy = Join-Path $signedDir "bundle-bom.appinstaller"
    $sAppInstP7 = Join-Path $signedDir "bundle-bom.appinstaller.p7"
    $appInstXml = @"
<?xml version="1.0" encoding="utf-8"?>
<AppInstaller
  xmlns="http://schemas.microsoft.com/appx/appinstaller/2021"
  Version="1.0.0.0"
  Uri="https://example.invalid/psign/bundle-bom.appinstaller">
  <MainBundle
    Name="Psign.EdgeTest"
    Version="1.0.0.0"
    Publisher="$publisher"
    Uri="https://example.invalid/psign/bundle-multi.signed.msixbundle" />
  <OptionalPackages>
    <Package
      Name="Psign.EdgeTest.OptionalData"
      Version="1.0.0.0"
      Publisher="$publisher"
      ProcessorArchitecture="neutral"
      Uri="https://example.invalid/psign/flat-optional-nonexec.signed.msix" />
  </OptionalPackages>
  <Dependencies>
    <Package
      Name="Microsoft.WindowsAppRuntime.1.5"
      Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      Version="5001.119.156.0"
      ProcessorArchitecture="x64"
      Uri="https://example.invalid/psign/WindowsAppRuntime.msix" />
  </Dependencies>
  <UpdateSettings>
    <OnLaunch HoursBetweenUpdateChecks="0" ShowPrompt="true" />
  </UpdateSettings>
</AppInstaller>
"@
    $utf8Bom = [System.Text.UTF8Encoding]::new($true)
    $appInstNormalized = ($appInstXml -replace "`r`n", "`n").TrimStart("`n")
    [System.IO.File]::WriteAllBytes($uAppInst, ($utf8Bom.GetPreamble() + $utf8Bom.GetBytes($appInstNormalized)))
    Copy-Item -LiteralPath $uAppInst -Destination $sAppInstCopy -Force
    Invoke-Checked -Exe $PsignToolPath -ArgsList @("--mode", "portable", "sign", "--pfx", $PfxPath, "--password", $PfxPassword, "--digest", "sha256", $sAppInstCopy) -Context "sign bundle-bom.appinstaller"
    Remove-Item -LiteralPath $sAppInstCopy -Force
    Add-FixtureRecord -Id "appinstaller-bundle-bom" -Category "appinstaller" -Extension ".appinstaller" `
        -UnsignedPath $uAppInst -SignedPath $sAppInstP7 -SignTool "psign portable sign" `
        -ExpectedPortableVerify "detached-valid" -ExpectedWindowsVerify "detached-valid" `
        -ExpectedWindowsSign "unsupported-detached-companion" `
        -Notes "UTF-8-with-BOM 2021 AppInstaller descriptor with MainBundle, OptionalPackages, and third-party Dependencies plus detached .appinstaller.p7 companion."

    # 17: Standalone bundle AppxSignature.p7x (PKCX + APPXBUNDLE_UUID)
    $p7xBundle = Join-Path $signedDir "bundle-signature.p7x"
    $bz = [System.IO.Compression.ZipFile]::OpenRead($sBundleMultiMsix)
    try {
        $sigEntry = $bz.GetEntry("AppxSignature.p7x")
        if (-not $sigEntry) { throw "AppxSignature.p7x missing in $sBundleMultiMsix" }
        $inStream = $sigEntry.Open()
        try {
            $outStream = [System.IO.File]::Create($p7xBundle)
            try { $inStream.CopyTo($outStream) }
            finally { $outStream.Dispose() }
        }
        finally { $inStream.Dispose() }
    }
    finally { $bz.Dispose() }
    Add-FixtureRecord -Id "p7x-bundle-signature" -Category "p7x" -Extension ".p7x" `
        -SignedPath $p7xBundle -SignTool "extracted from signtool bundle" `
        -ExpectedPortableVerify "inspect-pkcs7" -ExpectedPortableSign "unsupported-standalone-p7x" `
        -ExpectedWindowsVerify "valid" -ExpectedWindowsSign "unsupported-standalone-p7x" `
        -Notes "Standalone PKCX-wrapped AppxSignature.p7x extracted from signed multi-package .msixbundle (APPXBUNDLE_UUID)."
}
finally {
    $env:TEMP = $savedTemp
    $env:TMP = $savedTmp
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction Continue
    }
}

$manifestPath = Join-Path $OutputDir "msix-edge-case-fixtures.json"
$manifestObj = [ordered]@{
    schema_version = 1
    generated_by   = "scripts/ci/build-msix-edge-case-fixtures.ps1"
    pfx            = Convert-ToRepoPath -Path $PfxPath
    pfx_thumbprint = "A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38"
    publisher      = $publisher
    entries        = $entries
}
$jsonText = ($manifestObj | ConvertTo-Json -Depth 6) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($manifestPath, $jsonText + "`n", [System.Text.UTF8Encoding]::new($false))

Write-Host "Generated $($entries.Count) MSIX/AppX edge-case fixture entries under $OutputDir"
