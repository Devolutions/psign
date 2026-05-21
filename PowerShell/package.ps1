param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [string] $OutputDirectory = (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts') 'powershell')
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$moduleRoot = Join-Path $PSScriptRoot 'Devolutions.Psign'
$localRepo = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString('N'))
$repoName = "DevolutionsPsignLocal$([System.Guid]::NewGuid().ToString('N'))"

& (Join-Path $PSScriptRoot 'build.ps1') -Configuration $Configuration

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $localRepo | Out-Null

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
    Get-Item -LiteralPath (Join-Path $OutputDirectory $package.Name)
}
finally {
    Unregister-PSRepository -Name $repoName -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $localRepo -Recurse -Force -ErrorAction SilentlyContinue
}
