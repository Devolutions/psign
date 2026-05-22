param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [string] $OutputDirectory = (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts') 'powershell')
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$moduleRoot = Join-Path $PSScriptRoot 'Devolutions.Psign'
$localRepo = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
$installRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
$repoName = "DevolutionsPsignLocal$([System.Guid]::NewGuid().ToString('N'))"

& (Join-Path $PSScriptRoot 'build.ps1') -Configuration $Configuration

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $localRepo | Out-Null
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null

$manifestPath = Join-Path $moduleRoot 'Devolutions.Psign.psd1'
$manifest = Test-ModuleManifest -Path $manifestPath
$expectedCmdlets = @('Get-PortableSignature', 'Set-PortableSignature')
foreach ($cmdlet in $expectedCmdlets) {
    if ($manifest.ExportedCmdlets.Keys -notcontains $cmdlet) {
        throw "Module manifest does not export expected cmdlet '$cmdlet'."
    }
}

try {
    Register-PSRepository -Name $repoName -SourceLocation $localRepo -PublishLocation $localRepo -InstallationPolicy Trusted
    Publish-Module -Path $moduleRoot -Repository $repoName -NuGetApiKey 'local-package'

    $package = Get-ChildItem -Path $localRepo -Filter 'Devolutions.Psign.*.nupkg' |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $package) {
        throw "PowerShell module package was not created in $localRepo"
    }

    Copy-Item -Force -Path $package.FullName -Destination $OutputDirectory
    Save-Module -Name 'Devolutions.Psign' -RequiredVersion $manifest.Version.ToString() -Repository $repoName -Path $installRoot
    $savedManifest = Join-Path (Join-Path (Join-Path $installRoot 'Devolutions.Psign') $manifest.Version.ToString()) 'Devolutions.Psign.psd1'
    Import-Module $savedManifest -Force
    foreach ($cmdlet in $expectedCmdlets) {
        if (-not (Get-Command $cmdlet -Module 'Devolutions.Psign' -ErrorAction SilentlyContinue)) {
            throw "Installed package smoke test did not find cmdlet '$cmdlet'."
        }
    }
    $nativeProbe = New-TemporaryFile
    try {
        $null = Get-PortableSignature -LiteralPath $nativeProbe.FullName -ErrorAction Stop
    }
    finally {
        Remove-Item -LiteralPath $nativeProbe.FullName -Force -ErrorAction SilentlyContinue
    }
    Get-Item -LiteralPath (Join-Path $OutputDirectory $package.Name)
}
finally {
    Remove-Module Devolutions.Psign -Force -ErrorAction SilentlyContinue
    Unregister-PSRepository -Name $repoName -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $localRepo -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
}
