param(
    [string]$SignToolPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
    [string[]]$CommandLines = @(
        "verify /v C:\Windows\System32\notepad.exe"
    )
)

$ErrorActionPreference = "Stop"
$outPath = Join-Path $PSScriptRoot "..\parity-output\runtime-modules.json"
$results = @()

foreach ($commandLine in $CommandLines) {
    $args = $commandLine -split " "
    $proc = Start-Process -FilePath $SignToolPath -ArgumentList $args -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 150

    $modules = @()
    try {
        $modules = $proc.Modules | Select-Object -ExpandProperty FileName
    } catch {
        # Process may already have exited; keep empty module list for this sample.
    }

    $proc.WaitForExit()
    $results += [PSCustomObject]@{
        commandLine = $commandLine
        exitCode = $proc.ExitCode
        modules = $modules
    }
}

$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $outPath -Encoding UTF8
Write-Host "Wrote runtime module trace to $outPath"
