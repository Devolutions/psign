param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [switch]$SkipCargoLock
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

if ($Version.StartsWith("v")) {
    $Version = $Version.Substring(1)
}

if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$') {
    throw "Invalid version format: $Version (expected 1.2.3 or 1.2.3-suffix)."
}

function Set-FileText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Update-RequiredRegex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Pattern,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Replacement,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $text = [System.IO.File]::ReadAllText($Path)
    $regex = [regex]::new($Pattern)
    $script:replaceCount = 0
    $updated = $regex.Replace(
        $text,
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($match)
            $script:replaceCount++
            & $Replacement $match
        },
        1
    )
    $count = $script:replaceCount
    $script:replaceCount = 0

    if ($count -ne 1) {
        throw "Expected exactly one $Description match in $Path; found $count."
    }

    if ($updated -ne $text) {
        Set-FileText -Path $Path -Text $updated
        Write-Host "Updated $Description in $Path"
    }
    else {
        Write-Host "$Description already set in $Path"
    }
}

function Update-CargoPackageVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Update-RequiredRegex `
        -Path $Path `
        -Pattern '(?ms)(^\[package\].*?^version\s*=\s*")([^"]+)(")' `
        -Description "Cargo package version" `
        -Replacement {
            param($match)
            "$($match.Groups[1].Value)$Version$($match.Groups[3].Value)"
        }
}

function Update-PowerShellModuleManifestVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Version -notmatch '^(\d+\.\d+\.\d+)([-.](.+))?$') {
        throw "Invalid PowerShell module version format: $Version"
    }

    $moduleVersion = $Matches[1]
    $prerelease = $Matches[3]

    Update-RequiredRegex `
        -Path $Path `
        -Pattern "(?m)^(\s*ModuleVersion\s*=\s*')([^']+)(')" `
        -Description "PowerShell module version" `
        -Replacement {
            param($match)
            "$($match.Groups[1].Value)$moduleVersion$($match.Groups[3].Value)"
        }

    $text = [System.IO.File]::ReadAllText($Path)
    if ($prerelease) {
        $prereleasePattern = "(?m)^(\s*Prerelease\s*=\s*')([^']*)(')"
        if ([regex]::IsMatch($text, $prereleasePattern)) {
            Update-RequiredRegex `
                -Path $Path `
                -Pattern $prereleasePattern `
                -Description "PowerShell module prerelease" `
                -Replacement {
                    param($match)
                    "$($match.Groups[1].Value)$prerelease$($match.Groups[3].Value)"
                }
            return
        }

        $regex = [regex]::new('(?m)^(\s*)PSData\s*=\s*@\{(\r?\n)')
        $script:replaceCount = 0
        $updated = $regex.Replace(
            $text,
            [System.Text.RegularExpressions.MatchEvaluator] {
                param($match)
                $script:replaceCount++
                $indent = $match.Groups[1].Value
                "$($indent)PSData = @{$($match.Groups[2].Value)$($indent)    Prerelease = '$prerelease'$($match.Groups[2].Value)"
            },
            1
        )
        $count = $script:replaceCount
        $script:replaceCount = 0

        if ($count -ne 1) {
            throw "Expected exactly one PowerShell module PSData match in $Path; found $count."
        }

        Set-FileText -Path $Path -Text $updated
        Write-Host "Added PowerShell module prerelease in $Path"
        return
    }

    $regex = [regex]::new("(?m)^\s*Prerelease\s*=\s*'[^']*'\r?\n?")
    $updated = $regex.Replace($text, '', 1)
    if ($updated -ne $text) {
        Set-FileText -Path $Path -Text $updated
        Write-Host "Removed PowerShell module prerelease in $Path"
    }
}

$cargoManifests = @((Join-Path $repoRoot "Cargo.toml"))
$cratesRoot = Join-Path $repoRoot "crates"
if (Test-Path -LiteralPath $cratesRoot) {
    $cargoManifests += Get-ChildItem -LiteralPath $cratesRoot -Directory |
        ForEach-Object { Join-Path $_.FullName "Cargo.toml" } |
        Where-Object { Test-Path -LiteralPath $_ }
}

foreach ($manifest in $cargoManifests) {
    Update-CargoPackageVersion -Path $manifest
}

$powerShellModuleManifest = Join-Path $repoRoot "PowerShell\Devolutions.Psign\Devolutions.Psign.psd1"
Update-PowerShellModuleManifestVersion -Path $powerShellModuleManifest

$toolProject = Join-Path $repoRoot "nuget\tool\Devolutions.Psign.Tool.csproj"
Update-RequiredRegex `
    -Path $toolProject `
    -Pattern '(?m)^(\s*<Version Condition="''\$\((?:Version)\)'' == ''''">)([^<]+)(</Version>)' `
    -Description "NuGet tool fallback version" `
    -Replacement {
        param($match)
        "$($match.Groups[1].Value)$Version$($match.Groups[3].Value)"
    }

$readmePath = Join-Path $repoRoot "README.md"
Update-RequiredRegex `
    -Path $readmePath `
    -Pattern '(pack-psign-dotnet-tool\.ps1 -Version )\S+' `
    -Description "README pack example version" `
    -Replacement {
        param($match)
        "$($match.Groups[1].Value)$Version"
    }

$releaseWorkflow = Join-Path $repoRoot ".github\workflows\release.yml"
Update-RequiredRegex `
    -Path $releaseWorkflow `
    -Pattern '(description: Release version to build/publish \(for example )\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?(\))' `
    -Description "release workflow example version" `
    -Replacement {
        param($match)
        "$($match.Groups[1].Value)$Version$($match.Groups[3].Value)"
    }

if (-not $SkipCargoLock) {
    Push-Location $repoRoot
    try {
        cargo metadata --format-version 1 --quiet | Out-Null
    }
    finally {
        Pop-Location
    }
    Write-Host "Refreshed Cargo.lock"
}

Write-Host "Version bumped to $Version"
