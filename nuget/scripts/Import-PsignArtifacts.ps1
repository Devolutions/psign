Set-StrictMode -Version Latest

function Get-PsignArchivePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$ArchiveName
    )

    $match = Get-ChildItem -Path $Root -Recurse -File -Filter $ArchiveName | Select-Object -First 1
    if (-not $match) {
        throw "Archive not found under '$Root': $ArchiveName"
    }

    return $match.FullName
}

function Import-PsignArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArtifactsRoot,

        [Parameter(Mandatory = $true)]
        [string]$StagingRoot,

        [string]$ToolsRelativePath = "tools/psign-tool"
    )

    $extractRoot = Join-Path $StagingRoot "extract"
    $toolsRoot = Join-Path $StagingRoot $ToolsRelativePath

    if (Test-Path -Path $StagingRoot) {
        Remove-Item -Path $StagingRoot -Recurse -Force
    }

    New-Item -Path $extractRoot -ItemType Directory -Force | Out-Null
    New-Item -Path $toolsRoot -ItemType Directory -Force | Out-Null

    $archives = @(
        @{ Archive = "psign-tool-windows-x64.zip"; Rid = "win-x64"; Binary = "psign-tool.exe" },
        @{ Archive = "psign-tool-windows-arm64.zip"; Rid = "win-arm64"; Binary = "psign-tool.exe" },
        @{ Archive = "psign-tool-linux-x64.zip"; Rid = "linux-x64"; Binary = "psign-tool" },
        @{ Archive = "psign-tool-linux-arm64.zip"; Rid = "linux-arm64"; Binary = "psign-tool" },
        @{ Archive = "psign-tool-macos-x64.zip"; Rid = "osx-x64"; Binary = "psign-tool" },
        @{ Archive = "psign-tool-macos-arm64.zip"; Rid = "osx-arm64"; Binary = "psign-tool" }
    )

    foreach ($entry in $archives) {
        $archivePath = Get-PsignArchivePath -Root $ArtifactsRoot -ArchiveName $entry.Archive
        $extractDir = Join-Path $extractRoot $entry.Rid
        $destDir = Join-Path $toolsRoot $entry.Rid
        $destPath = Join-Path $destDir $entry.Binary

        New-Item -Path $extractDir -ItemType Directory -Force | Out-Null
        New-Item -Path $destDir -ItemType Directory -Force | Out-Null

        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

        $sourcePath = Join-Path $extractDir $entry.Binary
        if (-not (Test-Path -Path $sourcePath)) {
            $nested = Get-ChildItem -Path $extractDir -Recurse -File -Filter $entry.Binary | Select-Object -First 1
            if (-not $nested) {
                throw "Unable to find '$($entry.Binary)' in archive '$archivePath'."
            }

            $sourcePath = $nested.FullName
        }

        Copy-Item -Path $sourcePath -Destination $destPath -Force
    }
}
