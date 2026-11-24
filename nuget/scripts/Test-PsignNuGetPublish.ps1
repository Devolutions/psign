$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$publishScript = Join-Path $PSScriptRoot 'Publish-PsignNuGetPackages.ps1'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "psign-publish-test-$([guid]::NewGuid().ToString('N'))"
$managedDir = Join-Path $testRoot 'managed'
$toolDir = Join-Path $testRoot 'tool'
$version = '0.9.0-test'
$managedIds = @(
    'Devolutions.Psign.Core'
    'Devolutions.Psign.Signing'
)
$excludedIds = @('Devolutions.Psign.Verification', 'Devolutions.Psign.Cli', 'Devolutions.Psign.Server')
$rids = @('win-x64', 'win-arm64', 'linux-x64', 'linux-arm64', 'osx-x64', 'osx-arm64', 'any')
$expected = @(
    foreach ($id in $managedIds) { "$id.$version.nupkg" }
    foreach ($rid in $rids) { "Devolutions.Psign.Tool.$rid.$version.nupkg" }
    "Devolutions.Psign.Tool.$version.nupkg"
)

$originalApiKey = $env:NUGET_API_KEY
$global:PsignPublishTestPushes = [System.Collections.Generic.List[string]]::new()
$global:PsignPublishTestFailAt = 0

function dotnet {
    if ($args.Count -lt 3 -or $args[0] -ne 'nuget' -or $args[1] -ne 'push') {
        throw 'Unexpected dotnet invocation.'
    }

    $global:PsignPublishTestPushes.Add([System.IO.Path]::GetFileName($args[2]))
    $global:LASTEXITCODE = if ($global:PsignPublishTestPushes.Count -eq $global:PsignPublishTestFailAt) { 1 } else { 0 }
}

function Test-PublishesPackagesInDependencyOrder {
    $global:PsignPublishTestPushes.Clear()
    $env:NUGET_API_KEY = 'test-key-not-for-logging'
    $output = (& $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir 6>&1 | Out-String)
    if (($global:PsignPublishTestPushes -join '|') -ne ($expected -join '|')) {
        throw 'Packages were not pushed in dependency order with the native pointer last.'
    }
    if ($output.Contains($env:NUGET_API_KEY)) {
        throw 'The API key appeared in publish output.'
    }
}

function Test-DryRunRequiresNoKeyAndDoesNotPush {
    $global:PsignPublishTestPushes.Clear()
    $env:NUGET_API_KEY = ''
    $output = (& $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir -DryRun 6>&1 | Out-String)
    if ($global:PsignPublishTestPushes.Count -ne 0) {
        throw 'Dry-run unexpectedly pushed a package.'
    }
    foreach ($name in $expected) {
        if (-not $output.Contains($name)) {
            throw "Dry-run omitted $name."
        }
    }
}

function Test-ExcludesUnpublishedManagedPackages {
    $global:PsignPublishTestPushes.Clear()
    $env:NUGET_API_KEY = 'test-key'
    $output = (& $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir -DryRun 6>&1 | Out-String)
    foreach ($id in $excludedIds) {
        if ($output.Contains("$id.$version.nupkg")) {
            throw "Dry-run included the unpublished package $id."
        }
    }

    & $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir
    foreach ($id in $excludedIds) {
        if ($global:PsignPublishTestPushes.Contains("$id.$version.nupkg")) {
            throw "Publishing included the unpublished package $id."
        }
    }
}

function Test-MissingPackageStopsBeforeAnyPush {
    $global:PsignPublishTestPushes.Clear()
    $env:NUGET_API_KEY = 'test-key'
    $missing = Join-Path $managedDir "Devolutions.Psign.Signing.$version.nupkg"
    Remove-Item -LiteralPath $missing
    try {
        $failed = $false
        try {
            & $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir
        }
        catch {
            $failed = $_.Exception.Message -like '*Devolutions.Psign.Signing*'
        }
        if (-not $failed -or $global:PsignPublishTestPushes.Count -ne 0) {
            throw 'A missing package did not stop publishing before the first push.'
        }
    }
    finally {
        New-Item -ItemType File -Path $missing | Out-Null
    }
}

function Test-MissingNativePointerStopsBeforeAnyPush {
    $global:PsignPublishTestPushes.Clear()
    $env:NUGET_API_KEY = 'test-key'
    $missing = Join-Path $toolDir "Devolutions.Psign.Tool.$version.nupkg"
    Remove-Item -LiteralPath $missing
    try {
        $failed = $false
        try {
            & $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir
        }
        catch {
            $failed = $_.Exception.Message -like '*Devolutions.Psign.Tool*'
        }
        if (-not $failed -or $global:PsignPublishTestPushes.Count -ne 0) {
            throw 'A missing native pointer did not stop publishing before the first push.'
        }
    }
    finally {
        New-Item -ItemType File -Path $missing | Out-Null
    }
}

function Test-MissingApiKeyStopsBeforeAnyPush {
    $global:PsignPublishTestPushes.Clear()
    $env:NUGET_API_KEY = ''
    $failed = $false
    try {
        & $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir
    }
    catch {
        $failed = $_.Exception.Message -like '*NUGET_API_KEY*'
    }
    if (-not $failed -or $global:PsignPublishTestPushes.Count -ne 0) {
        throw 'A missing API key did not stop publishing before the first push.'
    }
}

function Test-PushFailureStopsImmediately {
    $global:PsignPublishTestPushes.Clear()
    $global:PsignPublishTestFailAt = 2
    $env:NUGET_API_KEY = 'test-key'
    try {
        $failed = $false
        try {
            & $publishScript -Version $version -ManagedPackageDir $managedDir -ToolPackageDir $toolDir
        }
        catch {
            $failed = $_.Exception.Message -like '*Devolutions.Psign.Signing*'
        }
        if (-not $failed -or $global:PsignPublishTestPushes.Count -ne 2) {
            throw 'A failed push did not stop the remaining packages.'
        }
    }
    finally {
        $global:PsignPublishTestFailAt = 0
        $global:LASTEXITCODE = 0
    }
}

try {
    New-Item -ItemType Directory -Path $managedDir, $toolDir | Out-Null
    foreach ($id in ($managedIds + $excludedIds)) {
        New-Item -ItemType File -Path (Join-Path $managedDir "$id.$version.nupkg") | Out-Null
    }
    foreach ($rid in $rids) {
        New-Item -ItemType File -Path (Join-Path $toolDir "Devolutions.Psign.Tool.$rid.$version.nupkg") | Out-Null
    }
    New-Item -ItemType File -Path (Join-Path $toolDir "Devolutions.Psign.Tool.$version.nupkg") | Out-Null

    $tests = @(
        'Test-PublishesPackagesInDependencyOrder'
        'Test-DryRunRequiresNoKeyAndDoesNotPush'
        'Test-ExcludesUnpublishedManagedPackages'
        'Test-MissingPackageStopsBeforeAnyPush'
        'Test-MissingNativePointerStopsBeforeAnyPush'
        'Test-MissingApiKeyStopsBeforeAnyPush'
        'Test-PushFailureStopsImmediately'
    )
    foreach ($test in $tests) {
        & $test
        Write-Host "PASS $test"
    }
    Write-Host "Passed: $($tests.Count), Failed: 0, Skipped: 0"
}
finally {
    $env:NUGET_API_KEY = $originalApiKey
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Variable -Name PsignPublishTestPushes, PsignPublishTestFailAt -Scope Global -ErrorAction SilentlyContinue
}
