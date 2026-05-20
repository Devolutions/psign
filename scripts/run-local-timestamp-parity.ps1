param(
    [string]$UnsignedPe,
    [string]$NativeSigntool,
    [string[]]$RunParityArgs = @("-FailOnSemantic")
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot
try {
    if (-not $UnsignedPe) {
        $UnsignedPe = Join-Path $repoRoot "target\debug\psign-tool.exe"
    }

    cargo build --locked --features timestamp-server --bins

    . (Join-Path $repoRoot "scripts\ci\bootstrap-devolutions-authenticode.ps1") | Out-Null
    $prepareArgs = @{
        WorkspaceRoot = $repoRoot
        UnsignedPe = $UnsignedPe
        PfxPath = $env:PSIGN_TEST_PFX
        PfxPassword = $env:PSIGN_TEST_PFX_PASSWORD
    }
    if ($NativeSigntool) {
        $prepareArgs.NativeSigntool = $NativeSigntool
    }
    & (Join-Path $repoRoot "scripts\ci\prepare-parity-fixtures.ps1") @prepareArgs

    $serverExe = Join-Path $repoRoot "target\debug\psign-server.exe"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $serverExe
    foreach ($arg in @("timestamp-server", "--listen", "127.0.0.1:0", "--gen-time", "20260601000000Z")) {
        [void]$psi.ArgumentList.Add($arg)
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $server = [System.Diagnostics.Process]::Start($psi)
    try {
        $line = $server.StandardOutput.ReadLine()
        $url = ($line -split " ")[-1]
        if (-not $url.StartsWith("http://")) {
            throw "psign-server did not report a URL: $line"
        }
        Set-Item -Path Env:PSIGN_TIMESTAMP_URL -Value $url
        Write-Host "PSIGN_TIMESTAMP_URL=$url"
        & (Join-Path $repoRoot "scripts\run-parity-diff.ps1") @RunParityArgs
    }
    finally {
        if ($server -and -not $server.HasExited) {
            $server.Kill()
            $server.WaitForExit()
        }
    }
}
finally {
    Pop-Location
}
