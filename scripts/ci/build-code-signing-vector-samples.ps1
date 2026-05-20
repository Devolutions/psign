# Generate small unsigned/probe inputs for the code-signing vector matrix.
# Pass -ArchivePath only when an ad hoc local zip is useful.
param(
    [string]$WorkspaceRoot = "",
    [string]$OutputDir = "",
    [string]$ArchivePath = "",
    [string]$Pe32Source = "",
    [string]$Pe64Source = "",
    [switch]$IncludeSdkPackages,
    [switch]$RequireSdkTools,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$WorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path $WorkspaceRoot "tests\fixtures\generated-unsigned"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $WorkspaceRoot $OutputDir
}

if ($ArchivePath -and -not [System.IO.Path]::IsPathRooted($ArchivePath)) {
    $ArchivePath = Join-Path $WorkspaceRoot $ArchivePath
}

if (-not $Pe32Source) {
    $Pe32Source = Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny32.efi"
}
elseif (-not [System.IO.Path]::IsPathRooted($Pe32Source)) {
    $Pe32Source = Join-Path $WorkspaceRoot $Pe32Source
}
if (-not $Pe64Source) {
    $Pe64Source = Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny64.efi"
}
elseif (-not [System.IO.Path]::IsPathRooted($Pe64Source)) {
    $Pe64Source = Join-Path $WorkspaceRoot $Pe64Source
}
foreach ($pe in @($Pe32Source, $Pe64Source)) {
    if (-not (Test-Path -LiteralPath $pe)) { throw "PE source not found: $pe" }
}

function Resolve-Tool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$Candidates = @()
    )
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$preservedWimEsd = @{}
if (Test-Path -LiteralPath $OutputDir) {
    foreach ($ext in @(".wim", ".esd")) {
        $existing = Join-Path $OutputDir ("wim-esd\tiny" + $ext)
        if (Test-Path -LiteralPath $existing) {
            $preservedWimEsd[$ext] = [System.IO.File]::ReadAllBytes($existing)
        }
    }
}

if ((Test-Path -LiteralPath $OutputDir) -and -not $Force) {
    throw "Output directory already exists: $OutputDir. Pass -Force to replace it."
}
if (Test-Path -LiteralPath $OutputDir) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$entries = New-Object System.Collections.Generic.List[object]

function Convert-ToManifestPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path.StartsWith(".\", [System.StringComparison]::Ordinal)) {
        return $Path.Substring(2)
    }
    return $Path
}

function Add-GeneratedEntry {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [Parameter(Mandatory)][string]$Path,
        [string]$Extension = "",
        [string]$Encoding = "binary",
        [string]$LineEndings = "none",
        [string]$State = "unsigned",
        [string]$ExpectedNative = "probe",
        [string]$ExpectedRustSip = "not-applicable",
        [string]$Tooling = "none"
    )
    $file = Get-Item -LiteralPath $Path
    $rel = Convert-ToManifestPath -Path (Resolve-Path -LiteralPath $file.FullName -Relative)
    $entries.Add([ordered]@{
            id                = $Id
            family            = $Family
            extension         = $Extension
            encoding          = $Encoding
            line_endings      = $LineEndings
            state             = $State
            expected_native   = $ExpectedNative
            expected_rust_sip = $ExpectedRustSip
            tooling           = $Tooling
            path              = $rel
            size_bytes        = $file.Length
            sha256            = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        })
}

function Copy-Vector {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [string]$Extension = "",
        [string]$State = "unsigned",
        [string]$ExpectedNative = "probe",
        [string]$ExpectedRustSip = "not-applicable",
        [string]$Tooling = "none"
    )
    $dest = Join-Path $OutputDir $RelativePath
    New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $dest -Force
    Add-GeneratedEntry -Id $Id -Family $Family -Path $dest -Extension $Extension -State $State -ExpectedNative $ExpectedNative -ExpectedRustSip $ExpectedRustSip -Tooling $Tooling
}

function Get-TextBytes {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Encoding
    )
    switch ($Encoding) {
        "utf8" {
            return [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        }
        "utf8-bom" {
            $enc = [System.Text.UTF8Encoding]::new($true)
            return [byte[]]($enc.GetPreamble() + $enc.GetBytes($Text))
        }
        "utf16le-bom" {
            $enc = [System.Text.UnicodeEncoding]::new($false, $true)
            return [byte[]]($enc.GetPreamble() + $enc.GetBytes($Text))
        }
        "utf16be-bom" {
            $enc = [System.Text.UnicodeEncoding]::new($true, $true)
            return [byte[]]($enc.GetPreamble() + $enc.GetBytes($Text))
        }
        default {
            throw "Unsupported text encoding: $Encoding"
        }
    }
}

function Write-BytesVector {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [string]$Extension = "",
        [string]$Encoding = "binary",
        [string]$LineEndings = "none",
        [string]$State = "unsigned",
        [string]$ExpectedNative = "probe",
        [string]$ExpectedRustSip = "not-applicable",
        [string]$Tooling = "none"
    )
    $dest = Join-Path $OutputDir $RelativePath
    New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
    [System.IO.File]::WriteAllBytes($dest, $Bytes)
    Add-GeneratedEntry -Id $Id -Family $Family -Path $dest -Extension $Extension -Encoding $Encoding -LineEndings $LineEndings -State $State -ExpectedNative $ExpectedNative -ExpectedRustSip $ExpectedRustSip -Tooling $Tooling
}

function Write-TextVector {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [Parameter(Mandatory)][string]$Extension,
        [Parameter(Mandatory)][string]$Encoding,
        [Parameter(Mandatory)][string]$LineEndings,
        [string]$State = "unsigned",
        [string]$ExpectedNative = "sign-probe",
        [string]$ExpectedRustSip = "unsigned-marker-negative",
        [string]$Tooling = "none"
    )
    $bytes = Get-TextBytes -Text $Text -Encoding $Encoding
    Write-BytesVector -RelativePath $RelativePath -Bytes $bytes -Id $Id -Family $Family -Extension $Extension -Encoding $Encoding -LineEndings $LineEndings -State $State -ExpectedNative $ExpectedNative -ExpectedRustSip $ExpectedRustSip -Tooling $Tooling
}

function Join-Lines {
    param([string[]]$Lines, [string]$LineEndings)
    $sep = if ($LineEndings -eq "lf") { "`n" } else { "`r`n" }
    return ($Lines -join $sep) + $sep
}

$peAliases = @(".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".efi", ".mui")
foreach ($sourceInfo in @(
        @{ Name = "tiny32"; Path = $Pe32Source },
        @{ Name = "tiny64"; Path = $Pe64Source }
    )) {
    foreach ($ext in $peAliases) {
        $stem = "$($sourceInfo.Name)-pe-alias$ext"
        Copy-Vector -Source $sourceInfo.Path -RelativePath "pe\$stem" -Id "generated-pe-$($sourceInfo.Name)-$($ext.TrimStart('.'))" -Family "pe" -Extension $ext -ExpectedNative "sign-ok" -ExpectedRustSip "pe-digest-source"
    }
    Copy-Vector -Source $sourceInfo.Path -RelativePath "winmd\$($sourceInfo.Name)-pe-copy.winmd" -Id "generated-winmd-$($sourceInfo.Name)" -Family "winmd" -Extension ".winmd" -ExpectedNative "sign-ok" -ExpectedRustSip "pe-digest-source"
}
Write-BytesVector -RelativePath "negative\not-pe.exe" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("not a PE image`n")) -Id "generated-negative-not-pe-exe" -Family "pe" -Extension ".exe" -State "negative" -ExpectedNative "reject" -ExpectedRustSip "negative-ok"

$scriptEncodings = @("utf8", "utf8-bom", "utf16le-bom", "utf16be-bom")
$lineEndingKinds = @("crlf", "lf")
$psExtensions = @(".ps1", ".psd1", ".psm1", ".ps1xml", ".psc1", ".cdxml", ".mof")
foreach ($ext in $psExtensions) {
    foreach ($encoding in $scriptEncodings) {
        foreach ($lineEndings in $lineEndingKinds) {
            $lines = switch ($ext) {
                ".ps1" { @("Write-Output 'psign vector ps1'") }
                ".psd1" { @("@{", "    RootModule = 'vector.psm1'", "}") }
                ".mof" { @("class Psign_Vector", "{", "  [key] string Name;", "};") }
                default { @("<?xml version=`"1.0`" encoding=`"utf-8`"?>", "<Configuration><Name>psign vector</Name></Configuration>") }
            }
            $text = Join-Lines -Lines $lines -LineEndings $lineEndings
            $safeExt = $ext.TrimStart('.')
            $rel = "scripts\powershell\$safeExt\$encoding-$lineEndings$ext"
            $id = "generated-powershell-$safeExt-$encoding-$lineEndings"
            Write-TextVector -RelativePath $rel -Text $text -Id $id -Family "powershell-script" -Extension $ext -Encoding $encoding -LineEndings $lineEndings
        }
    }
}

$wshExtensions = @(".js", ".vbs", ".wsf")
foreach ($ext in $wshExtensions) {
    foreach ($encoding in $scriptEncodings) {
        foreach ($lineEndings in $lineEndingKinds) {
            $lines = switch ($ext) {
                ".js" { @("WScript.Echo('psign vector js');") }
                ".vbs" { @("WScript.Echo ""psign vector vbs""") }
                default { @("<job id=`"psign`">", "  <script language=`"JScript`">WScript.Echo('psign vector wsf');</script>", "</job>") }
            }
            $text = Join-Lines -Lines $lines -LineEndings $lineEndings
            $safeExt = $ext.TrimStart('.')
            $rel = "scripts\wsh\$safeExt\$encoding-$lineEndings$ext"
            $id = "generated-wsh-$safeExt-$encoding-$lineEndings"
            Write-TextVector -RelativePath $rel -Text $text -Id $id -Family "wsh-script" -Extension $ext -Encoding $encoding -LineEndings $lineEndings
        }
    }
}

foreach ($ext in @(".jse", ".vbe", ".wsc")) {
    foreach ($encoding in @("utf8", "utf16le-bom")) {
        $safeExt = $ext.TrimStart('.')
        $lines = switch ($ext) {
            ".jse" { @("// optional WSH encoded JScript probe", "WScript.Echo('psign optional probe');") }
            ".vbe" { @("' optional WSH encoded VBScript probe", "WScript.Echo ""psign optional probe""") }
            default { @("<?xml version=`"1.0`"?>", "<component><registration progid=`"Psign.WscProbe`" /></component>") }
        }
        $state = if ($ext -eq ".wsc") { "native-sign-rejected" } else { "unsigned" }
        $expectedNative = if ($ext -eq ".wsc") { "reject-unrecognized-format" } else { "sign-ok" }
        $expectedRust = if ($ext -eq ".wsc") { "unsupported" } else { "wsh-digest-after-sign" }
        $text = Join-Lines -Lines $lines -LineEndings "crlf"
        Write-TextVector -RelativePath "scripts\wsh-probe\$safeExt\$encoding-crlf$ext" -Text $text -Id "generated-wsh-probe-$safeExt-$encoding" -Family "wsh-script" -Extension $ext -Encoding $encoding -LineEndings "crlf" -State $state -ExpectedNative $expectedNative -ExpectedRustSip $expectedRust
    }
}

$makecab = Get-Command makecab.exe -ErrorAction SilentlyContinue
if ($makecab) {
    $cabWork = Join-Path $OutputDir "_cab-work"
    New-Item -ItemType Directory -Force -Path $cabWork | Out-Null
    $payload = Join-Path $cabWork "hello.txt"
    [System.IO.File]::WriteAllBytes($payload, [System.Text.Encoding]::ASCII.GetBytes("psign cab unsigned fixture`r`n"))
    $ddf = Join-Path $cabWork "sample.ddf"
    $cabPath = Join-Path $OutputDir "cab\sample.cab"
    New-Item -ItemType Directory -Force -Path (Split-Path $cabPath -Parent) | Out-Null
    @"
.Set CabinetNameTemplate=$cabPath
.Set DiskDirectoryTemplate=
.Set CompressionType=MSZIP
.Set UniqueFiles=on
.Set Cabinet=on
.Set DiskDirectory1=
$payload
"@ | Set-Content -LiteralPath $ddf -Encoding ascii
    Push-Location $cabWork
    try {
        & $makecab.Source /f (Split-Path $ddf -Leaf) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "makecab.exe failed with exit $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }
    Add-GeneratedEntry -Id "generated-cab-unsigned" -Family "cab" -Path $cabPath -Extension ".cab" -State "unsigned" -ExpectedNative "sign-ok" -ExpectedRustSip "cab-digest-after-sign" -Tooling "makecab"
    Remove-Item -LiteralPath $cabWork -Recurse -Force
}
elseif ($RequireSdkTools) {
    throw "makecab.exe not found."
}

function Write-TinyInstallerWxs {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$Payload
    )
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $Directory "payload.txt"), [System.Text.Encoding]::ASCII.GetBytes($Payload))
    @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Id="Psign.Tiny.Installer" ProductCode="44444444-4444-4444-4444-444444444444" Name="Psign Tiny Installer" Manufacturer="Devolutions" Version="$Version" UpgradeCode="11111111-1111-1111-1111-111111111111">
    <MediaTemplate EmbedCab="yes" />
    <Feature Id="Main" Title="Main" Level="1">
      <ComponentGroupRef Id="Files" />
    </Feature>
  </Package>
  <Fragment>
    <StandardDirectory Id="ProgramFilesFolder">
      <Directory Id="INSTALLFOLDER" Name="PsignTiny" />
    </StandardDirectory>
  </Fragment>
  <Fragment>
    <ComponentGroup Id="Files" Directory="INSTALLFOLDER">
      <Component Id="PayloadComponent" Guid="22222222-2222-2222-2222-222222222222">
        <File Id="Payload" Source="payload.txt" KeyPath="yes" />
      </Component>
    </ComponentGroup>
  </Fragment>
</Wix>
"@ | Set-Content -LiteralPath (Join-Path $Directory "tiny.wxs") -Encoding utf8
}

function Invoke-WixBuild {
    param(
        [Parameter(Mandatory)][string]$Wix,
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Output
    )
    Push-Location $Directory
    try {
        & $Wix build tiny.wxs -out $Output -arch x64 -nologo -pdbtype none | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }
}

$wix = Resolve-Tool -Name "wix.exe" -Candidates @(
    (Join-Path $env:ProgramFiles "WiX Toolset v7.0\bin\wix.exe"),
    (Join-Path $env:ProgramFiles "WiX Toolset v6.0\bin\wix.exe")
)
$msiTran = Resolve-Tool -Name "MsiTran.exe" -Candidates @(
    (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\10.0.26100.0\x86\MsiTran.exe")
)

if ($wix -and $msiTran) {
    $installerWork = Join-Path $OutputDir "_installer-work"
    $installerOut = Join-Path $OutputDir "installer"
    $baseDir = Join-Path $installerWork "base"
    $updateDir = Join-Path $installerWork "update"
    New-Item -ItemType Directory -Force -Path $installerOut | Out-Null

    Write-TinyInstallerWxs -Directory $baseDir -Version "1.0.0.0" -Payload "x"
    Write-TinyInstallerWxs -Directory $updateDir -Version "1.0.1.0" -Payload "y"

    $baseMsi = Join-Path $baseDir "tiny.msi"
    $updateMsi = Join-Path $updateDir "tiny.msi"
    Invoke-WixBuild -Wix $wix -Directory $baseDir -Output $baseMsi
    Invoke-WixBuild -Wix $wix -Directory $updateDir -Output $updateMsi

    $mst = Join-Path $installerOut "tiny-transform.mst"
    & $msiTran -g $baseMsi $updateMsi $mst | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "MsiTran.exe failed with exit $LASTEXITCODE" }

    $patchWxs = Join-Path $installerWork "tiny-patch.wxs"
    @"
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Patch Id="33333333-3333-3333-3333-333333333333" Classification="Update" Description="Psign tiny patch" DisplayName="Psign Tiny Patch" Manufacturer="Devolutions" TargetProductName="Psign Tiny Installer" AllowRemoval="yes">
    <Media Id="1" Cabinet="tiny-patch.cab">
      <PatchBaseline Id="RTM" BaselineFile="$baseMsi" UpdateFile="$updateMsi" />
    </Media>
    <PatchFamily Id="TinyPatchFamily" Version="1.0.1.0" Supersede="yes">
      <ComponentRef Id="PayloadComponent" />
    </PatchFamily>
  </Patch>
</Wix>
"@ | Set-Content -LiteralPath $patchWxs -Encoding utf8

    $msp = Join-Path $installerOut "tiny-patch.msp"
    Push-Location $installerWork
    try {
        & $wix build $patchWxs -out $msp -arch x64 -nologo -pdbtype none | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "wix patch build failed with exit $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }

    $msi = Join-Path $installerOut "tiny.msi"
    Copy-Item -LiteralPath $baseMsi -Destination $msi -Force

    Add-GeneratedEntry -Id "generated-installer-tiny-msi" -Family "installer" -Path $msi -Extension ".msi" -State "unsigned" -ExpectedNative "sign-ok" -ExpectedRustSip "msi-digest-after-sign" -Tooling "wix"
    Add-GeneratedEntry -Id "generated-installer-tiny-msp" -Family "installer" -Path $msp -Extension ".msp" -State "unsigned" -ExpectedNative "sign-ok" -ExpectedRustSip "msi-digest-after-sign" -Tooling "wix"
    Add-GeneratedEntry -Id "generated-installer-tiny-mst" -Family "installer" -Path $mst -Extension ".mst" -State "native-pa-verify-rejected" -ExpectedNative "sign-ok-pa-verify-reject" -ExpectedRustSip "msi-trust-if-signed" -Tooling "wix-msitran"
    Remove-Item -LiteralPath $installerWork -Recurse -Force
}
elseif ($RequireSdkTools) {
    throw "WiX Toolset wix.exe and Windows SDK MsiTran.exe are required for installer fixtures."
}
else {
    $msiStub = Join-Path $WorkspaceRoot "tests\fixtures\msi-authenticode-upstream\tiny-pkcs7-stub.msi"
    foreach ($ext in @(".msi", ".msp", ".mst")) {
        if (Test-Path -LiteralPath $msiStub) {
            Copy-Vector -Source $msiStub -RelativePath "installer\synthetic-probe$ext" -Id "generated-installer-probe-$($ext.TrimStart('.'))" -Family "installer" -Extension $ext -State "synthetic-probe" -ExpectedNative "sign-probe" -ExpectedRustSip "synthetic-extract-only" -Tooling "optional-wix-or-msi-builder"
        }
    }
}

$memberPath = Join-Path $OutputDir "catalog\member.sys"
Copy-Vector -Source $Pe64Source -RelativePath "catalog\member.sys" -Id "generated-catalog-member-sys" -Family "catalog-member" -Extension ".sys" -State "unsigned" -ExpectedNative "catalog-member" -ExpectedRustSip "not-applicable"
$inf2Cat = Resolve-Tool -Name "Inf2Cat.exe" -Candidates @(
    (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\10.0.26100.0\x86\Inf2Cat.exe")
)
if ($inf2Cat) {
    $catalogDir = Join-Path $OutputDir "catalog"
    $infPath = Join-Path $catalogDir "sample.inf"
    @"
[Version]
Signature="`$Windows NT`$"
Class=Sample
ClassGuid={78A1C341-4539-11d3-B88D-00C04FAD5171}
Provider=%ProviderName%
CatalogFile=sample.cat
DriverVer=01/01/2024,1.0.0.0

[Manufacturer]
%ProviderName%=Models,NTamd64

[Models.NTamd64]
%DeviceName%=Install, ROOT\PSIGNCAT

[Install]
CopyFiles=Files

[Files]
member.sys

[DestinationDirs]
Files=12

[SourceDisksNames]
1=%DiskName%,,,.

[SourceDisksFiles]
member.sys=1

[Strings]
ProviderName="Devolutions"
DeviceName="Psign Catalog Test Device"
DiskName="Psign Catalog Test Disk"
"@ | Set-Content -LiteralPath $infPath -Encoding ascii
    & $inf2Cat /driver:$catalogDir /os:10_X64 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Inf2Cat.exe failed with exit $LASTEXITCODE" }
    $catPath = Join-Path $catalogDir "sample.cat"
    Add-GeneratedEntry -Id "generated-catalog-sample-cat" -Family "catalog" -Path $catPath -Extension ".cat" -State "unsigned" -ExpectedNative "sign-ok" -ExpectedRustSip "catalog-trust-after-sign" -Tooling "inf2cat"
}
elseif ($RequireSdkTools) {
    throw "Inf2Cat.exe not found."
}
else {
    Write-BytesVector -RelativePath "catalog\catalog-probe.cat" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("psign catalog placeholder`r`n")) -Id "generated-catalog-probe-cat" -Family "catalog" -Extension ".cat" -State "probe" -ExpectedNative "catalog-verify-probe" -ExpectedRustSip "catalog-cms-if-signed" -Tooling "windows-sdk"
}

if ($IncludeSdkPackages) {
    $makeAppx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter MakeAppx.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\|\\amd64\\' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $makeAppx) {
        if ($RequireSdkTools) { throw "MakeAppx.exe not found under Windows Kits." }
    }
    else {
        $layoutSrc = Join-Path $WorkspaceRoot "tests\fixtures\msix-minimal"
        $flatPackages = @()
        foreach ($packageExt in @(".msix", ".appx")) {
            $stage = Join-Path $OutputDir ("_appx-stage-" + $packageExt.TrimStart('.'))
            if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
            New-Item -ItemType Directory -Path $stage | Out-Null
            Get-ChildItem -LiteralPath $layoutSrc -Force | Copy-Item -Destination $stage -Recurse -Force
            Copy-Item -LiteralPath $Pe64Source -Destination (Join-Path $stage "noop.exe") -Force
            $assetsDir = Join-Path $stage "Assets"
            New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null
            $logoPath = Join-Path $assetsDir "StoreLogo.png"
            $pngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
            [IO.File]::WriteAllBytes($logoPath, [Convert]::FromBase64String($pngB64))
            $packagePath = Join-Path $OutputDir ("msix\sample" + $packageExt)
            New-Item -ItemType Directory -Force -Path (Split-Path $packagePath -Parent) | Out-Null
            & $makeAppx.FullName pack /h sha256 /d $stage /p $packagePath /o 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakeAppx pack failed for $packageExt with exit $LASTEXITCODE" }
            Add-GeneratedEntry -Id ("generated-msix-" + $packageExt.TrimStart('.')) -Family "msix" -Path $packagePath -Extension $packageExt -State "unsigned" -ExpectedNative "sign-ok" -ExpectedRustSip "msix-digest-after-sign" -Tooling "makeappx"
            $flatPackages += @{ Ext = $packageExt; Path = $packagePath }
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
        foreach ($bundleInfo in @(
                @{ Ext = ".msixbundle"; SourceExt = ".msix" },
                @{ Ext = ".appxbundle"; SourceExt = ".appx" }
            )) {
            $sourcePkg = $flatPackages | Where-Object { $_.Ext -eq $bundleInfo.SourceExt } | Select-Object -First 1
            if (-not $sourcePkg) { continue }
            $bundleStage = Join-Path $OutputDir ("_bundle-stage-" + $bundleInfo.Ext.TrimStart('.'))
            New-Item -ItemType Directory -Force -Path $bundleStage | Out-Null
            Copy-Item -LiteralPath $sourcePkg.Path -Destination (Join-Path $bundleStage (Split-Path $sourcePkg.Path -Leaf)) -Force
            $bundlePath = Join-Path $OutputDir ("msix\sample" + $bundleInfo.Ext)
            & $makeAppx.FullName bundle /d $bundleStage /p $bundlePath /o 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $bundlePath)) {
                Add-GeneratedEntry -Id ("generated-msix-" + $bundleInfo.Ext.TrimStart('.')) -Family "msix" -Path $bundlePath -Extension $bundleInfo.Ext -State "unsigned" -ExpectedNative "sign-ok" -ExpectedRustSip "msix-digest-after-sign" -Tooling "makeappx"
            }
            elseif ($RequireSdkTools) {
                throw "MakeAppx bundle failed for $($bundleInfo.Ext) with exit $LASTEXITCODE"
            }
            Remove-Item -LiteralPath $bundleStage -Recurse -Force
        }
    }
}

foreach ($ext in @(".eappx", ".eappxbundle", ".emsix", ".emsixbundle")) {
    Write-BytesVector -RelativePath "msix-encrypted-negative\placeholder$ext" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("encrypted package placeholder for extension rejection`r`n")) -Id "generated-encrypted-negative-$($ext.TrimStart('.'))" -Family "msix" -Extension $ext -State "negative" -ExpectedNative "wintrust-only-or-reject" -ExpectedRustSip "unsupported-encrypted-package"
}

foreach ($ext in @(".wim", ".esd")) {
    Write-BytesVector -RelativePath "wim-esd\bad-magic$ext" -Bytes ([byte[]](0..207 | ForEach-Object { 0x41 })) -Id "generated-wim-esd-bad-magic-$($ext.TrimStart('.'))" -Family "wim-esd" -Extension $ext -State "bad-magic-negative" -ExpectedNative "reject" -ExpectedRustSip "negative-ok"
    $h = New-Object byte[] 208
    [System.Text.Encoding]::ASCII.GetBytes("MSWIM") | ForEach-Object -Begin { $i = 0 } -Process { $h[$i] = $_; $i++ }
    Write-BytesVector -RelativePath "wim-esd\unsigned-header$ext" -Bytes $h -Id "generated-wim-esd-unsigned-header-$($ext.TrimStart('.'))" -Family "wim-esd" -Extension $ext -State "unsigned-header-negative" -ExpectedNative "reject" -ExpectedRustSip "negative-ok"
    if ($preservedWimEsd.ContainsKey($ext)) {
        Write-BytesVector -RelativePath "wim-esd\tiny$ext" -Bytes $preservedWimEsd[$ext] -Id "generated-wim-esd-tiny-$($ext.TrimStart('.'))" -Family "wim-esd" -Extension $ext -State "unsigned" -ExpectedNative "sign-ok" -ExpectedRustSip "esd-trust-after-sign" -Tooling "dism"
    }
}

Write-BytesVector -RelativePath "detached\content.bin" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("psign detached binary content fixture`r`n")) -Id "generated-detached-content-bin" -Family "detached-pkcs7" -Extension ".bin" -State "content" -ExpectedNative "detached-sign-probe" -ExpectedRustSip "trust-verify-detached-if-signed" -Tooling "signtool"
foreach ($encoding in @("utf8", "utf16le-bom")) {
    Write-TextVector -RelativePath "detached\content-$encoding.txt" -Text "psign detached text content fixture`r`n" -Id "generated-detached-content-txt-$encoding" -Family "detached-pkcs7" -Extension ".txt" -Encoding $encoding -LineEndings "crlf" -State "content" -ExpectedNative "detached-sign-probe" -ExpectedRustSip "trust-verify-detached-if-signed" -Tooling "signtool"
}
Write-BytesVector -RelativePath "detached\signature-placeholder.p7" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("CI replaces this with detached PKCS#7`r`n")) -Id "generated-detached-placeholder-p7" -Family "detached-pkcs7" -Extension ".p7" -State "ci-generated-signature" -ExpectedNative "detached-sign-probe" -ExpectedRustSip "trust-verify-detached-if-signed" -Tooling "signtool"

Write-BytesVector -RelativePath "p7x\sample.p7x" -Bytes ([System.Text.Encoding]::ASCII.GetBytes("PKCX`r`npsign P7X provider probe`r`n")) -Id "generated-p7x-sample" -Family "p7x" -Extension ".p7x" -State "unsigned" -ExpectedNative "sign-probe" -ExpectedRustSip "unsupported" -Tooling "appxsip-p7x-provider-probe"

$appInstallerXml = @'
<?xml version="1.0" encoding="utf-8"?>
<AppInstaller
  Uri="https://example.invalid/psign/sample.appinstaller"
  Version="1.0.0.0"
  xmlns="http://schemas.microsoft.com/appx/appinstaller/2018">
  <MainPackage
    Name="Psign.Sample"
    Publisher="CN=Test Code Signing Certificate"
    Version="1.0.0.0"
    ProcessorArchitecture="x64"
    Uri="https://example.invalid/psign/sample.msix" />
</AppInstaller>
'@
Write-BytesVector -RelativePath "appinstaller\sample.appinstaller" -Bytes ([System.Text.UTF8Encoding]::new($false).GetBytes($appInstallerXml)) -Id "generated-appinstaller-sample" -Family "appinstaller" -Extension ".appinstaller" -State "unsigned" -ExpectedNative "sign-probe" -ExpectedRustSip "unsupported" -Tooling "appinstaller-xml"

foreach ($ext in @(".vsix", ".vsto", ".application", ".deploy", ".manifest", ".docm", ".xlsm", ".pptm", ".xlam")) {
    $safeExt = $ext.TrimStart('.')
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("psign optional provider probe for $ext`r`n")
    Write-BytesVector -RelativePath "optional-provider\probe$ext" -Bytes $bytes -Id "generated-optional-provider-$safeExt" -Family "optional-provider" -Extension $ext -State "unsigned-probe" -ExpectedNative "provider-probe" -ExpectedRustSip "unsupported" -Tooling "machine-local-sip-or-app-tooling"
}

$generatedManifest = Join-Path $OutputDir "generated-vectors.json"
$generatedJson = @{
    generated_by = "scripts/ci/build-code-signing-vector-samples.ps1"
    source_pe32  = (Resolve-Path -LiteralPath $Pe32Source -Relative)
    source_pe64  = (Resolve-Path -LiteralPath $Pe64Source -Relative)
    vectors      = $entries
} | ConvertTo-Json -Depth 8
$generatedJson = $generatedJson -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($generatedManifest, $generatedJson + "`n", [System.Text.UTF8Encoding]::new($false))

if ($ArchivePath) {
    if (Test-Path -LiteralPath $ArchivePath) {
        Remove-Item -LiteralPath $ArchivePath -Force
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $ArchivePath -Parent) | Out-Null
    $archiveItems = Get-ChildItem -LiteralPath $OutputDir -Force
    if ($archiveItems.Count -eq 0) {
        throw "No generated vector files found under $OutputDir"
    }
    Compress-Archive -LiteralPath $archiveItems.FullName -DestinationPath $ArchivePath -Force
    Write-Host "Wrote archive: $ArchivePath"
}

Write-Host "Generated $($entries.Count) vector file(s): $OutputDir"
Write-Host "Wrote generated manifest: $generatedManifest"
