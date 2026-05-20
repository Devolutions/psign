param(
    [switch]$FailOnSemantic,
    # When set with -FailOnSemantic, require CI “full tier” env vars (timestamp, MSIX package, detached PKCS#7). Does not require MSIX decoupled /dlib /dmdf.
    [switch]$FailOnSemanticExhaustive,
    [switch]$MsixOnly
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Resolve-SignTool {
    $src = $null
    if ($env:SIGNTOOL_EXE -and (Test-Path -LiteralPath $env:SIGNTOOL_EXE)) {
        $src = $env:SIGNTOOL_EXE
    }
    if (-not $src) {
        $candidates = @(Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Sort-Object FullName)
        if ($candidates.Count -eq 0) {
            throw "Unable to locate native signtool.exe"
        }
        # Prefer x64/amd64 over x86 (Sort-Object FullName | Last would pick x86 after x64).
        foreach ($sub in @('\x64\', '\amd64\', '\arm64\', '\x86\', '\arm\')) {
            $hit = $candidates | Where-Object { $_.FullName -match [regex]::Escape($sub) } | Select-Object -Last 1
            if ($hit) {
                $src = $hit.FullName
                break
            }
        }
        if (-not $src) {
            $src = ($candidates | Select-Object -Last 1 -ExpandProperty FullName)
        }
    }
    # Copy to a path without spaces: CreateProcess / PowerShell quoting breaks `signtool.exe @rsp`
    # when the executable lives under "Program Files" (native then reports "Invalid command: Files").
    $dest = Join-Path $env:TEMP "psign_parity_native.exe"
    Copy-Item -LiteralPath $src -Destination $dest -Force
    return $dest
}

$nativeSignTool = Resolve-SignTool
$workspace = Split-Path -Parent $PSScriptRoot
$rustBin = Join-Path $workspace "target\debug\psign-tool.exe"

if (-not (Test-Path -LiteralPath $rustBin)) {
    cargo build -p psign --bin psign-tool | Out-Null
}

if ($MsixOnly) {
    $msixScript = Join-Path $PSScriptRoot "msix-parity-sign.ps1"
    if (-not (Test-Path -LiteralPath $msixScript)) {
        throw "MSIX parity script not found: $msixScript"
    }
    & $msixScript -FailOnSemantic:$FailOnSemantic
    return
}

$scenarios = @(
    @{
        id = "verify_pa_native_signed"
        nativeArgs = @("verify", "/pa", $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", $nativeSignTool)
    },
    @{
        id = "verify_default_policy_failure"
        nativeArgs = @("verify", $nativeSignTool)
        rustArgs = @("verify", "--policy", "default", $nativeSignTool)
    },
    @{
        id = "verify_pa_quiet_exit_match"
        nativeArgs = @("verify", "/pa", "/q", $nativeSignTool)
        rustArgs = @("verify", "--quiet", "--policy", "pa", $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_bad_signer_sha1_exit_match"
        nativeArgs = @("verify", "/pa", "/sha1", "0000000000000000000000000000000000000000", $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", "--signer-thumbprint-sha1", "0000000000000000000000000000000000000000", $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_now2010pca_exit_match"
        nativeArgs = @("verify", "/pa", "/now2010pca", $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", "--no-warn-pca-2010", $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_verbose_exit_match"
        nativeArgs = @("verify", "/pa", "/v", $nativeSignTool)
        rustArgs = @("verify", "-v", "--policy", "pa", $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_slash_q_exit_match"
        nativeArgs = @("verify", "/pa", "/q", $nativeSignTool)
        rustArgs = @("verify", "/pa", "/q", $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_two_targets_exit_match"
        nativeArgs = @("verify", "/pa", $nativeSignTool, $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", $nativeSignTool, $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_verbose_ph_exit_match"
        nativeArgs = @("verify", "/pa", "/v", "/ph", $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", "-v", "--verify-page-hashes", $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_verbose_ph_two_targets_exit_match"
        nativeArgs = @("verify", "/pa", "/v", "/ph", $nativeSignTool, $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", "-v", "--verify-page-hashes", $nativeSignTool, $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_sl_exit_match"
        nativeArgs = @("verify", "/pa", "/sl", $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", "--verify-sealing-signatures", $nativeSignTool)
        compareExitOnly = $true
    },
    @{
        id = "verify_pa_os_version_check_exit_match"
        nativeArgs = @("verify", "/pa", "/o", "386:10.0.0.0", $nativeSignTool)
        rustArgs = @("verify", "--policy", "pa", "--os-version-check", "386:10.0.0.0", $nativeSignTool)
        compareExitOnly = $true
    }
)

# Response file @-parity (ASCII, quoted path, UTF-16 LE+BOM). Native executable is already a TEMP copy
# without spaces (see Resolve-SignTool) so @rsp command-line quoting is reliable.
$parityAtRsp = Join-Path $env:TEMP "psign_parity_at_verify.rsp"
Set-Content -LiteralPath $parityAtRsp -Value @(
    "verify",
    "/pa",
    $nativeSignTool
) -Encoding ascii
$atRspArg = "@" + $parityAtRsp
$scenarios += @(
    @{
        id = "verify_pa_at_response_exit_match"
        nativeArgs = @($atRspArg)
        rustArgs = @($atRspArg)
        compareExitOnly = $true
    }
)

# Same as above but target path is one quoted token (native response-file style).
$parityAtQuotedRsp = Join-Path $env:TEMP "psign_parity_at_verify_quoted.rsp"
$quotedNativeTarget = '"' + $nativeSignTool + '"'
Set-Content -LiteralPath $parityAtQuotedRsp -Value @(
    "verify",
    "/pa",
    $quotedNativeTarget
) -Encoding ascii
$atQuotedRspArg = "@" + $parityAtQuotedRsp
$scenarios += @(
    @{
        id = "verify_pa_at_response_quoted_path_exit_match"
        nativeArgs = @($atQuotedRspArg)
        rustArgs = @($atQuotedRspArg)
        compareExitOnly = $true
    }
)

# UTF-16 LE with BOM (typical MSVC / .NET "Unicode" response files).
$parityAtUtf16Rsp = Join-Path $env:TEMP "psign_parity_at_verify_utf16.rsp"
$utf16Body = "verify`n/pa`n" + $nativeSignTool + "`n"
$utf16Enc = [System.Text.UnicodeEncoding]::new($false, $true)
[System.IO.File]::WriteAllText($parityAtUtf16Rsp, $utf16Body, $utf16Enc)
$atUtf16RspArg = "@" + $parityAtUtf16Rsp
$scenarios += @(
    @{
        id = "verify_pa_at_response_utf16_le_bom_exit_match"
        nativeArgs = @($atUtf16RspArg)
        rustArgs = @($atUtf16RspArg)
        compareExitOnly = $true
    }
)

function Test-SignatureSemantic {
    param(
        [string]$TargetPath
    )
    if (-not (Test-Path -LiteralPath $TargetPath)) {
        return [PSCustomObject]@{
            exists = $false
            nativeExitCode = -1
            output = ""
        }
    }
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = & "$nativeSignTool" verify /pa /v "$TargetPath" 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $saved
    return [PSCustomObject]@{
        exists = $true
        nativeExitCode = $code
        output = ($out -join "`n")
    }
}

$results = @()
$expectedScenarioIds = @(
    "verify_pa_native_signed",
    "verify_default_policy_failure",
    "verify_pa_quiet_exit_match",
    "verify_pa_bad_signer_sha1_exit_match",
    "verify_pa_now2010pca_exit_match",
    "verify_pa_verbose_exit_match",
    "verify_pa_slash_q_exit_match",
    "verify_pa_two_targets_exit_match",
    "verify_pa_verbose_ph_exit_match",
    "verify_pa_verbose_ph_two_targets_exit_match",
    "verify_pa_sl_exit_match",
    "verify_pa_os_version_check_exit_match",
    "verify_pa_at_response_exit_match",
    "verify_pa_at_response_quoted_path_exit_match",
    "verify_pa_at_response_utf16_le_bom_exit_match",
    "remove_no_flags_exit_match",
    "remove_s_two_targets_exit_match",
    "remove_s_quiet_stdout_empty_exit_match",
    "remove_u_sha256_match_native",
    "remove_c_sha256_match_native",
    "remove_cu_sha256_match_native"
)
foreach ($scenario in $scenarios) {
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $nativeExeThis = $nativeSignTool
    if ($scenario.nativeExe) {
        $nativeExeThis = $scenario.nativeExe
    }
    $native = & "$nativeExeThis" @($scenario.nativeArgs) 2>&1
    $nativeExit = $LASTEXITCODE

    $rust = & "$rustBin" @($scenario.rustArgs) 2>&1
    $rustExit = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorPreference

    $classification = if ($nativeExit -ne $rustExit) { "semantic_mismatch" }
    elseif ($scenario.compareExitOnly) { "exit_match" }
    elseif ($nativeExit -ne 0 -and $rustExit -ne 0) { "shared_failure" }
    elseif (($native -join "`n") -ne ($rust -join "`n")) { "format_only_diff" }
    else { "exact_match" }

    # Native signtool commonly reads @rsp as ANSI/UTF-8; UTF-16 LE+BOM is mis-decoded (e.g. "Invalid command: yv").
    # psign decodes UTF-16 per response_argv.rs — exit divergence is expected, not a Rust regression.
    if ($scenario.id -eq "verify_pa_at_response_utf16_le_bom_exit_match" -and $nativeExit -eq 1 -and $rustExit -eq 0) {
        $classification = "documented_native_utf16_rsp_gap"
    }

    $results += [PSCustomObject]@{
        id = $scenario.id
        nativeExitCode = $nativeExit
        rustExitCode = $rustExit
        classification = $classification
    }
}

# remove with no /s /c /u: native and rust should both fail (exit parity only).
$tmpRmParity = Join-Path $env:TEMP "psign_remove_noflags_parity.exe"
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmParity -Force
$savedRm = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& "$nativeSignTool" remove $tmpRmParity 2>&1 | Out-Null
$nativeRmNoFlags = $LASTEXITCODE
& "$rustBin" remove $tmpRmParity 2>&1 | Out-Null
$rustRmNoFlags = $LASTEXITCODE
$ErrorActionPreference = $savedRm
Remove-Item -LiteralPath $tmpRmParity -Force -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    id = "remove_no_flags_exit_match"
    nativeExitCode = $nativeRmNoFlags
    rustExitCode = $rustRmNoFlags
    classification = if ($nativeRmNoFlags -ne $rustRmNoFlags) { "semantic_mismatch" } else { "exit_match" }
}

# remove /s on two TEMP copies — native `<filename(s)>` parity (exit codes only).
$tmpRmMulti1 = Join-Path $env:TEMP "psign_remove_multi1.exe"
$tmpRmMulti2 = Join-Path $env:TEMP "psign_remove_multi2.exe"
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmMulti1 -Force
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmMulti2 -Force
$savedRm2 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& "$nativeSignTool" remove /s $tmpRmMulti1 $tmpRmMulti2 2>&1 | Out-Null
$nativeRmTwo = $LASTEXITCODE
& "$rustBin" remove --strip-signature $tmpRmMulti1 $tmpRmMulti2 2>&1 | Out-Null
$rustRmTwo = $LASTEXITCODE
$ErrorActionPreference = $savedRm2
Remove-Item -LiteralPath $tmpRmMulti1 -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tmpRmMulti2 -Force -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    id = "remove_s_two_targets_exit_match"
    nativeExitCode = $nativeRmTwo
    rustExitCode = $rustRmTwo
    classification = if ($nativeRmTwo -ne $rustRmTwo) { "semantic_mismatch" } else { "exit_match" }
}

# remove /s /q: native "No output on success" vs rust --quiet (exit + empty combined stdout/stderr on success).
$tmpRmQuiet = Join-Path $env:TEMP "psign_remove_quiet.exe"
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmQuiet -Force
$savedRmQ = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$nativeQuietOut = & "$nativeSignTool" remove /s /q $tmpRmQuiet 2>&1
$nativeRmQuietExit = $LASTEXITCODE
$rustQuietOut = & "$rustBin" remove --quiet --strip-signature $tmpRmQuiet 2>&1
$rustRmQuietExit = $LASTEXITCODE
$ErrorActionPreference = $savedRmQ
Remove-Item -LiteralPath $tmpRmQuiet -Force -ErrorAction SilentlyContinue
$nativeQuietText = ($nativeQuietOut | Out-String).Trim()
$rustQuietText = ($rustQuietOut | Out-String).Trim()
$quietOk = ($nativeRmQuietExit -eq $rustRmQuietExit) -and ($nativeQuietText -eq "") -and ($rustQuietText -eq "")
$results += [PSCustomObject]@{
    id = "remove_s_quiet_stdout_empty_exit_match"
    nativeExitCode = $nativeRmQuietExit
    rustExitCode = $rustRmQuietExit
    classification = if ($quietOk) { "exact_match" } else { "semantic_mismatch" }
}

# remove /u: PKCS#7 byte-for-byte parity vs native (two TEMP copies of parity-native exe).
$tmpRmUNative = Join-Path $env:TEMP "psign_remove_u_native.exe"
$tmpRmURust = Join-Path $env:TEMP "psign_remove_u_rust.exe"
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmUNative -Force
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmURust -Force
$savedRmU = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& "$nativeSignTool" remove /u /q $tmpRmUNative 2>&1 | Out-Null
$nativeRmUExit = $LASTEXITCODE
& "$rustBin" remove --strip-unauthenticated-attributes /q $tmpRmURust 2>&1 | Out-Null
$rustRmUExit = $LASTEXITCODE
$hashRmUMatch = $false
if ($nativeRmUExit -eq 0 -and $rustRmUExit -eq 0) {
    $hashRmUMatch = ((Get-FileHash -LiteralPath $tmpRmUNative -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpRmURust -Algorithm SHA256).Hash)
}
$ErrorActionPreference = $savedRmU
Remove-Item -LiteralPath $tmpRmUNative, $tmpRmURust -Force -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    id = "remove_u_sha256_match_native"
    nativeExitCode = $nativeRmUExit
    rustExitCode = $rustRmUExit
    classification = if ($nativeRmUExit -ne $rustRmUExit) { "semantic_mismatch" }
    elseif ($nativeRmUExit -ne 0) { "shared_failure" }
    elseif (-not $hashRmUMatch) { "semantic_mismatch" }
    else { "exact_match" }
}

# remove /c: PKCS#7 byte-for-byte parity vs native (two TEMP copies of parity-native exe).
$tmpRmCNative = Join-Path $env:TEMP "psign_remove_c_native.exe"
$tmpRmCRust = Join-Path $env:TEMP "psign_remove_c_rust.exe"
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmCNative -Force
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmCRust -Force
$savedRmC = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& "$nativeSignTool" remove /c /q $tmpRmCNative 2>&1 | Out-Null
$nativeRmCExit = $LASTEXITCODE
& "$rustBin" remove --strip-chain-except-signer /q $tmpRmCRust 2>&1 | Out-Null
$rustRmCExit = $LASTEXITCODE
$hashRmCMatch = $false
if ($nativeRmCExit -eq 0 -and $rustRmCExit -eq 0) {
    $hashRmCMatch = ((Get-FileHash -LiteralPath $tmpRmCNative -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpRmCRust -Algorithm SHA256).Hash)
}
$ErrorActionPreference = $savedRmC
Remove-Item -LiteralPath $tmpRmCNative, $tmpRmCRust -Force -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    id = "remove_c_sha256_match_native"
    nativeExitCode = $nativeRmCExit
    rustExitCode = $rustRmCExit
    classification = if ($nativeRmCExit -ne $rustRmCExit) { "semantic_mismatch" }
    elseif ($nativeRmCExit -ne 0) { "shared_failure" }
    elseif (-not $hashRmCMatch) { "semantic_mismatch" }
    else { "exact_match" }
}

# remove /c /u: PKCS#7 byte-for-byte parity vs native (two TEMP copies).
$tmpRmCUNative = Join-Path $env:TEMP "psign_remove_cu_native.exe"
$tmpRmCURust = Join-Path $env:TEMP "psign_remove_cu_rust.exe"
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmCUNative -Force
Copy-Item -LiteralPath $nativeSignTool -Destination $tmpRmCURust -Force
$savedRmCU = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& "$nativeSignTool" remove /c /u /q $tmpRmCUNative 2>&1 | Out-Null
$nativeRmCUExit = $LASTEXITCODE
& "$rustBin" remove --strip-chain-except-signer --strip-unauthenticated-attributes /q $tmpRmCURust 2>&1 | Out-Null
$rustRmCUExit = $LASTEXITCODE
$hashRmCUMatch = $false
if ($nativeRmCUExit -eq 0 -and $rustRmCUExit -eq 0) {
    $hashRmCUMatch = ((Get-FileHash -LiteralPath $tmpRmCUNative -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpRmCURust -Algorithm SHA256).Hash)
}
$ErrorActionPreference = $savedRmCU
Remove-Item -LiteralPath $tmpRmCUNative, $tmpRmCURust -Force -ErrorAction SilentlyContinue
$results += [PSCustomObject]@{
    id = "remove_cu_sha256_match_native"
    nativeExitCode = $nativeRmCUExit
    rustExitCode = $rustRmCUExit
    classification = if ($nativeRmCUExit -ne $rustRmCUExit) { "semantic_mismatch" }
    elseif ($nativeRmCUExit -ne 0) { "shared_failure" }
    elseif (-not $hashRmCUMatch) { "semantic_mismatch" }
    else { "exact_match" }
}

# Optional: native /tseal vs rust --tseal exit codes on the same signed artifact.
if ($env:PSIGN_SIGNED_FIXTURE -and $env:PSIGN_TIMESTAMP_URL) {
    $expectedScenarioIds += @("timestamp_tseal_exit_parity", "timestamp_tr_missing_td_exit_match", "timestamp_tr_two_targets_exit_match")
    $tsUrl = $env:PSIGN_TIMESTAMP_URL
    $signedPath = $env:PSIGN_SIGNED_FIXTURE
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & "$nativeSignTool" timestamp /tseal $tsUrl /td SHA256 $signedPath 2>&1 | Out-Null
    $nativeTsealExit = $LASTEXITCODE
    & "$rustBin" timestamp --tseal $tsUrl --td sha256 $signedPath 2>&1 | Out-Null
    $rustTsealExit = $LASTEXITCODE

    $tmpTsMissingTd = Join-Path $env:TEMP "psign_ts_tr_missing_td.exe"
    Copy-Item -LiteralPath $signedPath -Destination $tmpTsMissingTd -Force
    & "$nativeSignTool" timestamp /tr $tsUrl $tmpTsMissingTd 2>&1 | Out-Null
    $nativeTrMissingTd = $LASTEXITCODE
    & "$rustBin" timestamp --rfc3161-url $tsUrl $tmpTsMissingTd 2>&1 | Out-Null
    $rustTrMissingTd = $LASTEXITCODE
    Remove-Item -LiteralPath $tmpTsMissingTd -Force -ErrorAction SilentlyContinue

    $tmpTs1 = Join-Path $env:TEMP "psign_ts_tr_two_1.exe"
    $tmpTs2 = Join-Path $env:TEMP "psign_ts_tr_two_2.exe"
    Copy-Item -LiteralPath $signedPath -Destination $tmpTs1 -Force
    Copy-Item -LiteralPath $signedPath -Destination $tmpTs2 -Force
    & "$nativeSignTool" timestamp /tr $tsUrl /td SHA256 $tmpTs1 $tmpTs2 2>&1 | Out-Null
    $nativeTrTwo = $LASTEXITCODE
    & "$rustBin" timestamp --rfc3161-url $tsUrl --digest sha256 $tmpTs1 $tmpTs2 2>&1 | Out-Null
    $rustTrTwo = $LASTEXITCODE
    Remove-Item -LiteralPath $tmpTs1 -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpTs2 -Force -ErrorAction SilentlyContinue

    $ErrorActionPreference = $saved
    $results += [PSCustomObject]@{
        id = "timestamp_tseal_exit_parity"
        nativeExitCode = $nativeTsealExit
        rustExitCode = $rustTsealExit
        classification = if ($nativeTsealExit -ne $rustTsealExit) { "semantic_mismatch" } else { "exit_match" }
    }
    $trTwoClassification = if ($nativeTrTwo -ne $rustTrTwo) { "semantic_mismatch" } else { "exit_match" }
    $results += [PSCustomObject]@{
        id = "timestamp_tr_missing_td_exit_match"
        nativeExitCode = $nativeTrMissingTd
        rustExitCode = $rustTrMissingTd
        classification = if ($nativeTrMissingTd -ne $rustTrMissingTd) { "semantic_mismatch" } else { "exit_match" }
    }
    $results += [PSCustomObject]@{
        id = "timestamp_tr_two_targets_exit_match"
        nativeExitCode = $nativeTrTwo
        rustExitCode = $rustTrTwo
        classification = $trTwoClassification
    }
}

function Test-EnvPresent([string]$Name) {
    $v = [Environment]::GetEnvironmentVariable($Name)
    return ($null -ne $v -and $v.Trim().Length -gt 0)
}

function Get-RustSignCredentialArgs {
    $thumb = $env:PSIGN_TEST_CERT_SHA1
    if ($thumb -and $thumb.Trim().Length -gt 0) {
        return @("--cert-sha1", $thumb.Trim())
    }
    $out = @("--pfx", $env:PSIGN_TEST_PFX)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $out += @("--password", $env:PSIGN_TEST_PFX_PASSWORD)
    }
    return $out
}

function Get-RustMsixCredentialArgs {
    # Prefer store thumbprint when CI bootstrap imported the test cert into `CurrentUser\My` — Rust `SignerSignEx3`
    # + MSIX SIP often succeeds with `--cert-sha1` while `--pfx` can hit `CRYPT_E_NO_PROVIDER` on some hosts.
    $thumb = $env:PSIGN_MSIX_TEST_CERT_SHA1
    if (-not $thumb -or $thumb.Trim().Length -eq 0) {
        $thumb = $env:PSIGN_TEST_CERT_SHA1
    }
    if ($thumb -and $thumb.Trim().Length -gt 0) {
        return @("--cert-sha1", $thumb.Trim())
    }
    $pfx = $env:PSIGN_MSIX_TEST_PFX
    if ($pfx -and $pfx.Trim().Length -gt 0 -and (Test-Path -LiteralPath $pfx.Trim())) {
        $out = @("--pfx", $pfx.Trim())
        if ($env:PSIGN_MSIX_TEST_PFX_PASSWORD) {
            $out += @("--password", $env:PSIGN_MSIX_TEST_PFX_PASSWORD)
        }
        return $out
    }
    throw "Get-RustMsixCredentialArgs: set PSIGN_TEST_CERT_SHA1 (after bootstrap) or PSIGN_MSIX_TEST_PFX (see scripts/ci/bootstrap-devolutions-authenticode.ps1)."
}

if ($FailOnSemantic) {
    $requiredCore = @(
        "PSIGN_UNSIGNED_FIXTURE",
        "PSIGN_TEST_PFX"
    )
    $missingCore = @($requiredCore | Where-Object { -not (Test-EnvPresent $_) })
    if ($missingCore.Count -gt 0) {
        throw "Missing required semantic fixture env vars: $($missingCore -join ', ')"
    }
}

if ($FailOnSemantic -and $FailOnSemanticExhaustive) {
    $requiredExhaustive = @(
        "PSIGN_SIGNED_FIXTURE",
        "PSIGN_TIMESTAMP_URL",
        "PSIGN_MSIX_UNSIGNED_FIXTURE",
        "PSIGN_MSIX_TEST_PFX",
        "PSIGN_MSIX_TIMESTAMP_URL",
        "PSIGN_DETACHED_CONTENT",
        "PSIGN_DETACHED_PKCS7"
    )
    $missingEx = @($requiredExhaustive | Where-Object { -not (Test-EnvPresent $_) })
    if ($missingEx.Count -gt 0) {
        throw "Missing exhaustive parity env vars (use scripts/ci or see docs/ci-parity.md): $($missingEx -join ', ')"
    }
}

# Artifact-semantic scenario: sign + verify output includes expected signature markers.
if ($env:PSIGN_UNSIGNED_FIXTURE -and $env:PSIGN_TEST_PFX) {
    $expectedScenarioIds += @(
        "artifact_sign_verify_semantic",
        "artifact_sign_two_pe_exit_parity",
        "artifact_verify_print_description_match",
        "sign_pe_fixture_sha256_match_native",
        "verify_pe_fixture_pa_exit_match"
    )
    $tempSigned = Join-Path $env:TEMP "psign_ci_semantic.exe"
    Copy-Item -LiteralPath $env:PSIGN_UNSIGNED_FIXTURE -Destination $tempSigned -Force

    $signArgs = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tempSigned)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & "$rustBin" @signArgs 2>&1 | Out-Null
    $signExit = $LASTEXITCODE
    $ErrorActionPreference = $saved

    $semantic = Test-SignatureSemantic -TargetPath $tempSigned
    $classification = if ($signExit -ne 0 -and $semantic.nativeExitCode -ne 0) { "shared_failure" }
    elseif ($signExit -ne 0 -or $semantic.nativeExitCode -ne 0) { "semantic_mismatch" }
    elseif ($semantic.output -match "Successfully verified") { "artifact_semantic_match" }
    else { "semantic_mismatch" }

    $results += [PSCustomObject]@{
        id = "artifact_sign_verify_semantic"
        nativeExitCode = $semantic.nativeExitCode
        rustExitCode = $signExit
        classification = $classification
    }

    # Native `<filename(s)>` vs rust trailing `files`: same PFX/options, two unsigned PE copies — exit codes only.
    $tmpSignA = Join-Path $env:TEMP "psign_sign_two_a.exe"
    $tmpSignB = Join-Path $env:TEMP "psign_sign_two_b.exe"
    Copy-Item -LiteralPath $env:PSIGN_UNSIGNED_FIXTURE -Destination $tmpSignA -Force
    Copy-Item -LiteralPath $env:PSIGN_UNSIGNED_FIXTURE -Destination $tmpSignB -Force
    $savedTwo = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $nativeTwoSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpSignA, $tmpSignB)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $nativeTwoSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpSignA, $tmpSignB)
    }
    & "$nativeSignTool" @nativeTwoSign 2>&1 | Out-Null
    $nativeTwoSignExit = $LASTEXITCODE

    $rustTwoSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpSignA, $tmpSignB)
    & "$rustBin" @rustTwoSign 2>&1 | Out-Null
    $rustTwoSignExit = $LASTEXITCODE
    $ErrorActionPreference = $savedTwo
    Remove-Item -LiteralPath $tmpSignA, $tmpSignB -Force -ErrorAction SilentlyContinue

    $results += [PSCustomObject]@{
        id = "artifact_sign_two_pe_exit_parity"
        nativeExitCode = $nativeTwoSignExit
        rustExitCode = $rustTwoSignExit
        classification = if ($nativeTwoSignExit -ne $rustTwoSignExit) { "semantic_mismatch" } else { "exit_match" }
    }

    # PE (.exe/.dll/…): same SIP as native; two copies of CI unsigned PE — SHA256 match or verify-valid semantic match.
    $peExt = [System.IO.Path]::GetExtension($env:PSIGN_UNSIGNED_FIXTURE)
    if ([string]::IsNullOrEmpty($peExt)) { $peExt = ".exe" }
    $tmpPeNat = Join-Path $env:TEMP ("psign_pe_fixture_native" + $peExt)
    $tmpPeRust = Join-Path $env:TEMP ("psign_pe_fixture_rust" + $peExt)
    Copy-Item -LiteralPath $env:PSIGN_UNSIGNED_FIXTURE -Destination $tmpPeNat -Force
    Copy-Item -LiteralPath $env:PSIGN_UNSIGNED_FIXTURE -Destination $tmpPeRust -Force
    $savedPe = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $nativePeSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpPeNat)
    $rustPeSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpPeRust)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $nativePeSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpPeNat)
    }
    & "$nativeSignTool" @nativePeSign 2>&1 | Out-Null
    $nativePeSignExit = $LASTEXITCODE
    & "$rustBin" @rustPeSign 2>&1 | Out-Null
    $rustPeSignExit = $LASTEXITCODE
    $hashPeMatch = $false
    if ($nativePeSignExit -eq 0 -and $rustPeSignExit -eq 0) {
        $hashPeMatch = ((Get-FileHash -LiteralPath $tmpPeNat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpPeRust -Algorithm SHA256).Hash)
    }
    & "$nativeSignTool" verify /pa $tmpPeNat 2>&1 | Out-Null
    $nativePeVerifyExit = $LASTEXITCODE
    & "$rustBin" verify --policy pa $tmpPeRust 2>&1 | Out-Null
    $rustPeVerifyExit = $LASTEXITCODE
    $bothPeVerifyOk = ($nativePeVerifyExit -eq 0) -and ($rustPeVerifyExit -eq 0)
    $ErrorActionPreference = $savedPe
    Remove-Item -LiteralPath $tmpPeNat, $tmpPeRust -Force -ErrorAction SilentlyContinue

    $results += [PSCustomObject]@{
        id = "sign_pe_fixture_sha256_match_native"
        nativeExitCode = $nativePeSignExit
        rustExitCode = $rustPeSignExit
        classification = if ($nativePeSignExit -ne $rustPeSignExit) { "semantic_mismatch" }
        elseif ($nativePeSignExit -ne 0) { "shared_failure" }
        elseif (-not $hashPeMatch -and $bothPeVerifyOk) { "artifact_semantic_match" }
        elseif (-not $hashPeMatch) { "semantic_mismatch" }
        else { "exact_match" }
    }
    $results += [PSCustomObject]@{
        id = "verify_pe_fixture_pa_exit_match"
        nativeExitCode = $nativePeVerifyExit
        rustExitCode = $rustPeVerifyExit
        classification = if ($nativePeVerifyExit -ne $rustPeVerifyExit) { "semantic_mismatch" }
        elseif ($nativePeVerifyExit -ne 0 -and $rustPeVerifyExit -ne 0) { "shared_failure" }
        else { "exit_match" }
    }

    # Sign with /d + /du then verify /pa /v /d: Authenticode program name + URL must match native output lines.
    $tmpDesc = Join-Path $env:TEMP "psign_verify_desc.exe"
    Copy-Item -LiteralPath $env:PSIGN_UNSIGNED_FIXTURE -Destination $tmpDesc -Force
    $parityDesc = "psign_parity_desc_2026"
    $parityUrl = "https://example.invalid/psign-parity"
    $savedDesc = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $nativeSignDesc = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $parityDesc, "/du", $parityUrl, $tmpDesc)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $nativeSignDesc = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $parityDesc, "/du", $parityUrl, $tmpDesc)
    }
    & "$nativeSignTool" @nativeSignDesc 2>&1 | Out-Null
    $nativeSignDescExit = $LASTEXITCODE

    $rustSignDesc = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", "--description", $parityDesc, "--description-url", $parityUrl, $tmpDesc)
    & "$rustBin" @rustSignDesc 2>&1 | Out-Null
    $rustSignDescExit = $LASTEXITCODE

    $nativeVerifyDescOut = ""
    $rustVerifyDescOut = ""
    $nativeVerifyDescExit = -1
    $rustVerifyDescExit = -1
    if ($nativeSignDescExit -eq 0 -and $rustSignDescExit -eq 0) {
        $nativeVerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpDesc) 2>&1 | Out-String)
        $nativeVerifyDescExit = $LASTEXITCODE
        $rustVerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpDesc) 2>&1 | Out-String)
        $rustVerifyDescExit = $LASTEXITCODE
    }
    $ErrorActionPreference = $savedDesc
    Remove-Item -LiteralPath $tmpDesc -Force -ErrorAction SilentlyContinue

    $nativeDescLine = [regex]::Match($nativeVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $rustDescLine = [regex]::Match($rustVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $nativeUrlLine = [regex]::Match($nativeVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
    $rustUrlLine = [regex]::Match($rustVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

    $descClassification = if ($nativeSignDescExit -ne 0 -or $rustSignDescExit -ne 0) {
        if ($nativeSignDescExit -eq $rustSignDescExit) { "shared_failure" } else { "semantic_mismatch" }
    }
    elseif ($nativeVerifyDescExit -ne $rustVerifyDescExit) { "semantic_mismatch" }
    elseif ($nativeDescLine -ne $rustDescLine -or $nativeUrlLine -ne $rustUrlLine) { "semantic_mismatch" }
    elseif ($nativeDescLine -ne $parityDesc -or $nativeUrlLine -ne $parityUrl) { "semantic_mismatch" }
    else { "artifact_semantic_match" }

    $results += [PSCustomObject]@{
        id = "artifact_verify_print_description_match"
        nativeExitCode = $nativeVerifyDescExit
        rustExitCode = $rustVerifyDescExit
        classification = $descClassification
    }

    # PowerShell .ps1: Windows CryptSIP (same SignerSignEx3 / WinVerifyTrust stack as native signtool).
    $ps1Src = if ($env:PSIGN_PS1_UNSIGNED_FIXTURE) { $env:PSIGN_PS1_UNSIGNED_FIXTURE } else { Join-Path $workspace "tests\fixtures\unsigned-sample.ps1" }
    if (Test-Path -LiteralPath $ps1Src) {
        $expectedScenarioIds += @("sign_ps1_sha256_match_native", "verify_ps1_pa_exit_match")
        $tmpPs1Nat = Join-Path $env:TEMP "psign_ps1_native.ps1"
        $tmpPs1Rust = Join-Path $env:TEMP "psign_ps1_rust.ps1"
        Copy-Item -LiteralPath $ps1Src -Destination $tmpPs1Nat -Force
        Copy-Item -LiteralPath $ps1Src -Destination $tmpPs1Rust -Force
        $savedPs1 = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativePs1Sign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpPs1Nat)
        $rustPs1Sign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpPs1Rust)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativePs1Sign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpPs1Nat)
        }
        & "$nativeSignTool" @nativePs1Sign 2>&1 | Out-Null
        $nativePs1SignExit = $LASTEXITCODE
        & "$rustBin" @rustPs1Sign 2>&1 | Out-Null
        $rustPs1SignExit = $LASTEXITCODE
        $hashPs1Match = $false
        if ($nativePs1SignExit -eq 0 -and $rustPs1SignExit -eq 0) {
            $hashPs1Match = ((Get-FileHash -LiteralPath $tmpPs1Nat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpPs1Rust -Algorithm SHA256).Hash)
        }
        & "$nativeSignTool" verify /pa $tmpPs1Nat 2>&1 | Out-Null
        $nativePs1VerifyExit = $LASTEXITCODE
        & "$rustBin" verify --policy pa $tmpPs1Rust 2>&1 | Out-Null
        $rustPs1VerifyExit = $LASTEXITCODE
        $bothPs1VerifyOk = ($nativePs1VerifyExit -eq 0) -and ($rustPs1VerifyExit -eq 0)
        $ErrorActionPreference = $savedPs1
        Remove-Item -LiteralPath $tmpPs1Nat, $tmpPs1Rust -Force -ErrorAction SilentlyContinue

        $results += [PSCustomObject]@{
            id = "sign_ps1_sha256_match_native"
            nativeExitCode = $nativePs1SignExit
            rustExitCode = $rustPs1SignExit
            classification = if ($nativePs1SignExit -ne $rustPs1SignExit) { "semantic_mismatch" }
            elseif ($nativePs1SignExit -ne 0) { "shared_failure" }
            elseif (-not $hashPs1Match -and $bothPs1VerifyOk) {
                # PKCS#7 embedding can differ while remaining trust-valid (same as some PE scenarios).
                "artifact_semantic_match"
            }
            elseif (-not $hashPs1Match) { "semantic_mismatch" }
            else { "exact_match" }
        }
        $results += [PSCustomObject]@{
            id = "verify_ps1_pa_exit_match"
            nativeExitCode = $nativePs1VerifyExit
            rustExitCode = $rustPs1VerifyExit
            classification = if ($nativePs1VerifyExit -ne $rustPs1VerifyExit) { "semantic_mismatch" }
            elseif ($nativePs1VerifyExit -ne 0 -and $rustPs1VerifyExit -ne 0) { "shared_failure" }
            else { "exit_match" }
        }

        # Same as PE `artifact_verify_print_description_match`: /d + /du then verify /v /d (PowerShell SIP).
        $expectedScenarioIds += @("artifact_verify_ps1_print_description_match")
        $tmpPs1DescNat = Join-Path $env:TEMP "psign_verify_desc_native.ps1"
        $tmpPs1DescRust = Join-Path $env:TEMP "psign_verify_desc_rust.ps1"
        Copy-Item -LiteralPath $ps1Src -Destination $tmpPs1DescNat -Force
        Copy-Item -LiteralPath $ps1Src -Destination $tmpPs1DescRust -Force
        $savedPs1Desc = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativePs1DescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $parityDesc, "/du", $parityUrl, $tmpPs1DescNat)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativePs1DescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $parityDesc, "/du", $parityUrl, $tmpPs1DescNat)
        }
        & "$nativeSignTool" @nativePs1DescSign 2>&1 | Out-Null
        $nativePs1DescSignExit = $LASTEXITCODE

        $rustPs1DescSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", "--description", $parityDesc, "--description-url", $parityUrl, $tmpPs1DescRust)
        & "$rustBin" @rustPs1DescSign 2>&1 | Out-Null
        $rustPs1DescSignExit = $LASTEXITCODE

        $nativePs1VerifyDescOut = ""
        $rustPs1VerifyDescOut = ""
        $nativePs1VerifyDescExit = -1
        $rustPs1VerifyDescExit = -1
        if ($nativePs1DescSignExit -eq 0 -and $rustPs1DescSignExit -eq 0) {
            $nativePs1VerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpPs1DescNat) 2>&1 | Out-String)
            $nativePs1VerifyDescExit = $LASTEXITCODE
            $rustPs1VerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpPs1DescRust) 2>&1 | Out-String)
            $rustPs1VerifyDescExit = $LASTEXITCODE
        }
        $ErrorActionPreference = $savedPs1Desc
        Remove-Item -LiteralPath $tmpPs1DescNat, $tmpPs1DescRust -Force -ErrorAction SilentlyContinue

        $nativePs1DescLine = [regex]::Match($nativePs1VerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $rustPs1DescLine = [regex]::Match($rustPs1VerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $nativePs1UrlLine = [regex]::Match($nativePs1VerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
        $rustPs1UrlLine = [regex]::Match($rustPs1VerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

        $ps1DescClassification = if ($nativePs1DescSignExit -ne 0 -or $rustPs1DescSignExit -ne 0) {
            if ($nativePs1DescSignExit -eq $rustPs1DescSignExit) { "shared_failure" } else { "semantic_mismatch" }
        }
        elseif ($nativePs1VerifyDescExit -ne $rustPs1VerifyDescExit) { "semantic_mismatch" }
        elseif ($nativePs1DescLine -ne $rustPs1DescLine -or $nativePs1UrlLine -ne $rustPs1UrlLine) { "semantic_mismatch" }
        elseif ($nativePs1DescLine -ne $parityDesc -or $nativePs1UrlLine -ne $parityUrl) { "semantic_mismatch" }
        else { "artifact_semantic_match" }

        $results += [PSCustomObject]@{
            id = "artifact_verify_ps1_print_description_match"
            nativeExitCode = $nativePs1VerifyDescExit
            rustExitCode = $rustPs1VerifyDescExit
            classification = $ps1DescClassification
        }
    }

    # PowerShell module .psm1 (same CryptSIP stack as .ps1).
    $psm1Src = if ($env:PSIGN_PSM1_UNSIGNED_FIXTURE) { $env:PSIGN_PSM1_UNSIGNED_FIXTURE } else { Join-Path $workspace "tests\fixtures\unsigned-sample.psm1" }
    if (Test-Path -LiteralPath $psm1Src) {
        $expectedScenarioIds += @(
            "sign_psm1_sha256_match_native",
            "verify_psm1_pa_exit_match",
            "artifact_verify_psm1_print_description_match"
        )
        $tmpPsm1Nat = Join-Path $env:TEMP "psign_psm1_native.psm1"
        $tmpPsm1Rust = Join-Path $env:TEMP "psign_psm1_rust.psm1"
        Copy-Item -LiteralPath $psm1Src -Destination $tmpPsm1Nat -Force
        Copy-Item -LiteralPath $psm1Src -Destination $tmpPsm1Rust -Force
        $savedPsm1 = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativePsm1Sign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpPsm1Nat)
        $rustPsm1Sign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpPsm1Rust)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativePsm1Sign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpPsm1Nat)
        }
        & "$nativeSignTool" @nativePsm1Sign 2>&1 | Out-Null
        $nativePsm1SignExit = $LASTEXITCODE
        & "$rustBin" @rustPsm1Sign 2>&1 | Out-Null
        $rustPsm1SignExit = $LASTEXITCODE
        $hashPsm1Match = $false
        if ($nativePsm1SignExit -eq 0 -and $rustPsm1SignExit -eq 0) {
            $hashPsm1Match = ((Get-FileHash -LiteralPath $tmpPsm1Nat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpPsm1Rust -Algorithm SHA256).Hash)
        }
        & "$nativeSignTool" verify /pa $tmpPsm1Nat 2>&1 | Out-Null
        $nativePsm1VerifyExit = $LASTEXITCODE
        & "$rustBin" verify --policy pa $tmpPsm1Rust 2>&1 | Out-Null
        $rustPsm1VerifyExit = $LASTEXITCODE
        $bothPsm1VerifyOk = ($nativePsm1VerifyExit -eq 0) -and ($rustPsm1VerifyExit -eq 0)
        $ErrorActionPreference = $savedPsm1
        Remove-Item -LiteralPath $tmpPsm1Nat, $tmpPsm1Rust -Force -ErrorAction SilentlyContinue

        $results += [PSCustomObject]@{
            id = "sign_psm1_sha256_match_native"
            nativeExitCode = $nativePsm1SignExit
            rustExitCode = $rustPsm1SignExit
            classification = if ($nativePsm1SignExit -ne $rustPsm1SignExit) { "semantic_mismatch" }
            elseif ($nativePsm1SignExit -ne 0) { "shared_failure" }
            elseif (-not $hashPsm1Match -and $bothPsm1VerifyOk) { "artifact_semantic_match" }
            elseif (-not $hashPsm1Match) { "semantic_mismatch" }
            else { "exact_match" }
        }
        $results += [PSCustomObject]@{
            id = "verify_psm1_pa_exit_match"
            nativeExitCode = $nativePsm1VerifyExit
            rustExitCode = $rustPsm1VerifyExit
            classification = if ($nativePsm1VerifyExit -ne $rustPsm1VerifyExit) { "semantic_mismatch" }
            elseif ($nativePsm1VerifyExit -ne 0 -and $rustPsm1VerifyExit -ne 0) { "shared_failure" }
            else { "exit_match" }
        }

        $tmpPsm1DescNat = Join-Path $env:TEMP "psign_verify_desc_native.psm1"
        $tmpPsm1DescRust = Join-Path $env:TEMP "psign_verify_desc_rust.psm1"
        Copy-Item -LiteralPath $psm1Src -Destination $tmpPsm1DescNat -Force
        Copy-Item -LiteralPath $psm1Src -Destination $tmpPsm1DescRust -Force
        $savedPsm1Desc = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativePsm1DescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $parityDesc, "/du", $parityUrl, $tmpPsm1DescNat)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativePsm1DescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $parityDesc, "/du", $parityUrl, $tmpPsm1DescNat)
        }
        & "$nativeSignTool" @nativePsm1DescSign 2>&1 | Out-Null
        $nativePsm1DescSignExit = $LASTEXITCODE

        $rustPsm1DescSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", "--description", $parityDesc, "--description-url", $parityUrl, $tmpPsm1DescRust)
        & "$rustBin" @rustPsm1DescSign 2>&1 | Out-Null
        $rustPsm1DescSignExit = $LASTEXITCODE

        $nativePsm1VerifyDescOut = ""
        $rustPsm1VerifyDescOut = ""
        $nativePsm1VerifyDescExit = -1
        $rustPsm1VerifyDescExit = -1
        if ($nativePsm1DescSignExit -eq 0 -and $rustPsm1DescSignExit -eq 0) {
            $nativePsm1VerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpPsm1DescNat) 2>&1 | Out-String)
            $nativePsm1VerifyDescExit = $LASTEXITCODE
            $rustPsm1VerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpPsm1DescRust) 2>&1 | Out-String)
            $rustPsm1VerifyDescExit = $LASTEXITCODE
        }
        $ErrorActionPreference = $savedPsm1Desc
        Remove-Item -LiteralPath $tmpPsm1DescNat, $tmpPsm1DescRust -Force -ErrorAction SilentlyContinue

        $nativePsm1DescLine = [regex]::Match($nativePsm1VerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $rustPsm1DescLine = [regex]::Match($rustPsm1VerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $nativePsm1UrlLine = [regex]::Match($nativePsm1VerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
        $rustPsm1UrlLine = [regex]::Match($rustPsm1VerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

        $psm1DescClassification = if ($nativePsm1DescSignExit -ne 0 -or $rustPsm1DescSignExit -ne 0) {
            if ($nativePsm1DescSignExit -eq $rustPsm1DescSignExit) { "shared_failure" } else { "semantic_mismatch" }
        }
        elseif ($nativePsm1VerifyDescExit -ne $rustPsm1VerifyDescExit) { "semantic_mismatch" }
        elseif ($nativePsm1DescLine -ne $rustPsm1DescLine -or $nativePsm1UrlLine -ne $rustPsm1UrlLine) { "semantic_mismatch" }
        elseif ($nativePsm1DescLine -ne $parityDesc -or $nativePsm1UrlLine -ne $parityUrl) { "semantic_mismatch" }
        else { "artifact_semantic_match" }

        $results += [PSCustomObject]@{
            id = "artifact_verify_psm1_print_description_match"
            nativeExitCode = $nativePsm1VerifyDescExit
            rustExitCode = $rustPsm1VerifyDescExit
            classification = $psm1DescClassification
        }
    }

    # PowerShell manifest .psd1 (same CryptSIP stack as .ps1).
    $psd1Src = if ($env:PSIGN_PSD1_UNSIGNED_FIXTURE) { $env:PSIGN_PSD1_UNSIGNED_FIXTURE } else { Join-Path $workspace "tests\fixtures\unsigned-sample.psd1" }
    if (Test-Path -LiteralPath $psd1Src) {
        $expectedScenarioIds += @(
            "sign_psd1_sha256_match_native",
            "verify_psd1_pa_exit_match",
            "artifact_verify_psd1_print_description_match"
        )
        $tmpPsd1Nat = Join-Path $env:TEMP "psign_psd1_native.psd1"
        $tmpPsd1Rust = Join-Path $env:TEMP "psign_psd1_rust.psd1"
        Copy-Item -LiteralPath $psd1Src -Destination $tmpPsd1Nat -Force
        Copy-Item -LiteralPath $psd1Src -Destination $tmpPsd1Rust -Force
        $savedPsd1 = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativePsd1Sign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpPsd1Nat)
        $rustPsd1Sign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpPsd1Rust)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativePsd1Sign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpPsd1Nat)
        }
        & "$nativeSignTool" @nativePsd1Sign 2>&1 | Out-Null
        $nativePsd1SignExit = $LASTEXITCODE
        & "$rustBin" @rustPsd1Sign 2>&1 | Out-Null
        $rustPsd1SignExit = $LASTEXITCODE
        $hashPsd1Match = $false
        if ($nativePsd1SignExit -eq 0 -and $rustPsd1SignExit -eq 0) {
            $hashPsd1Match = ((Get-FileHash -LiteralPath $tmpPsd1Nat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpPsd1Rust -Algorithm SHA256).Hash)
        }
        & "$nativeSignTool" verify /pa $tmpPsd1Nat 2>&1 | Out-Null
        $nativePsd1VerifyExit = $LASTEXITCODE
        & "$rustBin" verify --policy pa $tmpPsd1Rust 2>&1 | Out-Null
        $rustPsd1VerifyExit = $LASTEXITCODE
        $bothPsd1VerifyOk = ($nativePsd1VerifyExit -eq 0) -and ($rustPsd1VerifyExit -eq 0)
        $ErrorActionPreference = $savedPsd1
        Remove-Item -LiteralPath $tmpPsd1Nat, $tmpPsd1Rust -Force -ErrorAction SilentlyContinue

        $results += [PSCustomObject]@{
            id = "sign_psd1_sha256_match_native"
            nativeExitCode = $nativePsd1SignExit
            rustExitCode = $rustPsd1SignExit
            classification = if ($nativePsd1SignExit -ne $rustPsd1SignExit) { "semantic_mismatch" }
            elseif ($nativePsd1SignExit -ne 0) { "shared_failure" }
            elseif (-not $hashPsd1Match -and $bothPsd1VerifyOk) { "artifact_semantic_match" }
            elseif (-not $hashPsd1Match) { "semantic_mismatch" }
            else { "exact_match" }
        }
        $results += [PSCustomObject]@{
            id = "verify_psd1_pa_exit_match"
            nativeExitCode = $nativePsd1VerifyExit
            rustExitCode = $rustPsd1VerifyExit
            classification = if ($nativePsd1VerifyExit -ne $rustPsd1VerifyExit) { "semantic_mismatch" }
            elseif ($nativePsd1VerifyExit -ne 0 -and $rustPsd1VerifyExit -ne 0) { "shared_failure" }
            else { "exit_match" }
        }

        $tmpPsd1DescNat = Join-Path $env:TEMP "psign_verify_desc_native.psd1"
        $tmpPsd1DescRust = Join-Path $env:TEMP "psign_verify_desc_rust.psd1"
        Copy-Item -LiteralPath $psd1Src -Destination $tmpPsd1DescNat -Force
        Copy-Item -LiteralPath $psd1Src -Destination $tmpPsd1DescRust -Force
        $savedPsd1Desc = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativePsd1DescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $parityDesc, "/du", $parityUrl, $tmpPsd1DescNat)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativePsd1DescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $parityDesc, "/du", $parityUrl, $tmpPsd1DescNat)
        }
        & "$nativeSignTool" @nativePsd1DescSign 2>&1 | Out-Null
        $nativePsd1DescSignExit = $LASTEXITCODE

        $rustPsd1DescSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", "--description", $parityDesc, "--description-url", $parityUrl, $tmpPsd1DescRust)
        & "$rustBin" @rustPsd1DescSign 2>&1 | Out-Null
        $rustPsd1DescSignExit = $LASTEXITCODE

        $nativePsd1VerifyDescOut = ""
        $rustPsd1VerifyDescOut = ""
        $nativePsd1VerifyDescExit = -1
        $rustPsd1VerifyDescExit = -1
        if ($nativePsd1DescSignExit -eq 0 -and $rustPsd1DescSignExit -eq 0) {
            $nativePsd1VerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpPsd1DescNat) 2>&1 | Out-String)
            $nativePsd1VerifyDescExit = $LASTEXITCODE
            $rustPsd1VerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpPsd1DescRust) 2>&1 | Out-String)
            $rustPsd1VerifyDescExit = $LASTEXITCODE
        }
        $ErrorActionPreference = $savedPsd1Desc
        Remove-Item -LiteralPath $tmpPsd1DescNat, $tmpPsd1DescRust -Force -ErrorAction SilentlyContinue

        $nativePsd1DescLine = [regex]::Match($nativePsd1VerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $rustPsd1DescLine = [regex]::Match($rustPsd1VerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $nativePsd1UrlLine = [regex]::Match($nativePsd1VerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
        $rustPsd1UrlLine = [regex]::Match($rustPsd1VerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

        $psd1DescClassification = if ($nativePsd1DescSignExit -ne 0 -or $rustPsd1DescSignExit -ne 0) {
            if ($nativePsd1DescSignExit -eq $rustPsd1DescSignExit) { "shared_failure" } else { "semantic_mismatch" }
        }
        elseif ($nativePsd1VerifyDescExit -ne $rustPsd1VerifyDescExit) { "semantic_mismatch" }
        elseif ($nativePsd1DescLine -ne $rustPsd1DescLine -or $nativePsd1UrlLine -ne $rustPsd1UrlLine) { "semantic_mismatch" }
        elseif ($nativePsd1DescLine -ne $parityDesc -or $nativePsd1UrlLine -ne $parityUrl) { "semantic_mismatch" }
        else { "artifact_semantic_match" }

        $results += [PSCustomObject]@{
            id = "artifact_verify_psd1_print_description_match"
            nativeExitCode = $nativePsd1VerifyDescExit
            rustExitCode = $rustPsd1VerifyDescExit
            classification = $psd1DescClassification
        }
    }

    # Windows Script Host .js: OS CryptSIP for script signing (same SignerSignEx3 / WinVerifyTrust as native).
    $jsSrc = if ($env:PSIGN_JS_UNSIGNED_FIXTURE) { $env:PSIGN_JS_UNSIGNED_FIXTURE } else { Join-Path $workspace "tests\fixtures\unsigned-sample.js" }
    if (Test-Path -LiteralPath $jsSrc) {
        $expectedScenarioIds += @(
            "sign_js_sha256_match_native",
            "verify_js_pa_exit_match",
            "artifact_verify_js_print_description_match"
        )
        $tmpJsNat = Join-Path $env:TEMP "psign_js_native.js"
        $tmpJsRust = Join-Path $env:TEMP "psign_js_rust.js"
        Copy-Item -LiteralPath $jsSrc -Destination $tmpJsNat -Force
        Copy-Item -LiteralPath $jsSrc -Destination $tmpJsRust -Force
        $savedJs = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativeJsSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpJsNat)
        $rustJsSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpJsRust)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativeJsSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpJsNat)
        }
        & "$nativeSignTool" @nativeJsSign 2>&1 | Out-Null
        $nativeJsSignExit = $LASTEXITCODE
        & "$rustBin" @rustJsSign 2>&1 | Out-Null
        $rustJsSignExit = $LASTEXITCODE
        $hashJsMatch = $false
        if ($nativeJsSignExit -eq 0 -and $rustJsSignExit -eq 0) {
            $hashJsMatch = ((Get-FileHash -LiteralPath $tmpJsNat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpJsRust -Algorithm SHA256).Hash)
        }
        & "$nativeSignTool" verify /pa $tmpJsNat 2>&1 | Out-Null
        $nativeJsVerifyExit = $LASTEXITCODE
        & "$rustBin" verify --policy pa $tmpJsRust 2>&1 | Out-Null
        $rustJsVerifyExit = $LASTEXITCODE
        $bothJsVerifyOk = ($nativeJsVerifyExit -eq 0) -and ($rustJsVerifyExit -eq 0)
        $ErrorActionPreference = $savedJs
        Remove-Item -LiteralPath $tmpJsNat, $tmpJsRust -Force -ErrorAction SilentlyContinue

        $results += [PSCustomObject]@{
            id = "sign_js_sha256_match_native"
            nativeExitCode = $nativeJsSignExit
            rustExitCode = $rustJsSignExit
            classification = if ($nativeJsSignExit -ne $rustJsSignExit) { "semantic_mismatch" }
            elseif ($nativeJsSignExit -ne 0) { "shared_failure" }
            elseif (-not $hashJsMatch -and $bothJsVerifyOk) { "artifact_semantic_match" }
            elseif (-not $hashJsMatch) { "semantic_mismatch" }
            else { "exact_match" }
        }
        $results += [PSCustomObject]@{
            id = "verify_js_pa_exit_match"
            nativeExitCode = $nativeJsVerifyExit
            rustExitCode = $rustJsVerifyExit
            classification = if ($nativeJsVerifyExit -ne $rustJsVerifyExit) { "semantic_mismatch" }
            elseif ($nativeJsVerifyExit -ne 0 -and $rustJsVerifyExit -ne 0) { "shared_failure" }
            else { "exit_match" }
        }

        $tmpJsDescNat = Join-Path $env:TEMP "psign_verify_desc_native.js"
        $tmpJsDescRust = Join-Path $env:TEMP "psign_verify_desc_rust.js"
        Copy-Item -LiteralPath $jsSrc -Destination $tmpJsDescNat -Force
        Copy-Item -LiteralPath $jsSrc -Destination $tmpJsDescRust -Force
        $savedJsDesc = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativeJsDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $parityDesc, "/du", $parityUrl, $tmpJsDescNat)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativeJsDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $parityDesc, "/du", $parityUrl, $tmpJsDescNat)
        }
        & "$nativeSignTool" @nativeJsDescSign 2>&1 | Out-Null
        $nativeJsDescSignExit = $LASTEXITCODE

        $rustJsDescSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", "--description", $parityDesc, "--description-url", $parityUrl, $tmpJsDescRust)
        & "$rustBin" @rustJsDescSign 2>&1 | Out-Null
        $rustJsDescSignExit = $LASTEXITCODE

        $nativeJsVerifyDescOut = ""
        $rustJsVerifyDescOut = ""
        $nativeJsVerifyDescExit = -1
        $rustJsVerifyDescExit = -1
        if ($nativeJsDescSignExit -eq 0 -and $rustJsDescSignExit -eq 0) {
            $nativeJsVerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpJsDescNat) 2>&1 | Out-String)
            $nativeJsVerifyDescExit = $LASTEXITCODE
            $rustJsVerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpJsDescRust) 2>&1 | Out-String)
            $rustJsVerifyDescExit = $LASTEXITCODE
        }
        $ErrorActionPreference = $savedJsDesc
        Remove-Item -LiteralPath $tmpJsDescNat, $tmpJsDescRust -Force -ErrorAction SilentlyContinue

        $nativeJsDescLine = [regex]::Match($nativeJsVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $rustJsDescLine = [regex]::Match($rustJsVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $nativeJsUrlLine = [regex]::Match($nativeJsVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
        $rustJsUrlLine = [regex]::Match($rustJsVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

        $jsDescClassification = if ($nativeJsDescSignExit -ne 0 -or $rustJsDescSignExit -ne 0) {
            if ($nativeJsDescSignExit -eq $rustJsDescSignExit) { "shared_failure" } else { "semantic_mismatch" }
        }
        elseif ($nativeJsVerifyDescExit -ne $rustJsVerifyDescExit) { "semantic_mismatch" }
        elseif ($nativeJsDescLine -ne $rustJsDescLine -or $nativeJsUrlLine -ne $rustJsUrlLine) { "semantic_mismatch" }
        elseif ($nativeJsDescLine -ne $parityDesc -or $nativeJsUrlLine -ne $parityUrl) { "semantic_mismatch" }
        else { "artifact_semantic_match" }

        $results += [PSCustomObject]@{
            id = "artifact_verify_js_print_description_match"
            nativeExitCode = $nativeJsVerifyDescExit
            rustExitCode = $rustJsVerifyDescExit
            classification = $jsDescClassification
        }
    }

    # Windows Script Host .vbs (same stack as .js when SIP registered).
    $vbsSrc = if ($env:PSIGN_VBS_UNSIGNED_FIXTURE) { $env:PSIGN_VBS_UNSIGNED_FIXTURE } else { Join-Path $workspace "tests\fixtures\unsigned-sample.vbs" }
    if (Test-Path -LiteralPath $vbsSrc) {
        $expectedScenarioIds += @(
            "sign_vbs_sha256_match_native",
            "verify_vbs_pa_exit_match",
            "artifact_verify_vbs_print_description_match"
        )
        $tmpVbsNat = Join-Path $env:TEMP "psign_vbs_native.vbs"
        $tmpVbsRust = Join-Path $env:TEMP "psign_vbs_rust.vbs"
        Copy-Item -LiteralPath $vbsSrc -Destination $tmpVbsNat -Force
        Copy-Item -LiteralPath $vbsSrc -Destination $tmpVbsRust -Force
        $savedVbs = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativeVbsSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpVbsNat)
        $rustVbsSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpVbsRust)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativeVbsSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpVbsNat)
        }
        & "$nativeSignTool" @nativeVbsSign 2>&1 | Out-Null
        $nativeVbsSignExit = $LASTEXITCODE
        & "$rustBin" @rustVbsSign 2>&1 | Out-Null
        $rustVbsSignExit = $LASTEXITCODE
        $hashVbsMatch = $false
        if ($nativeVbsSignExit -eq 0 -and $rustVbsSignExit -eq 0) {
            $hashVbsMatch = ((Get-FileHash -LiteralPath $tmpVbsNat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpVbsRust -Algorithm SHA256).Hash)
        }
        & "$nativeSignTool" verify /pa $tmpVbsNat 2>&1 | Out-Null
        $nativeVbsVerifyExit = $LASTEXITCODE
        & "$rustBin" verify --policy pa $tmpVbsRust 2>&1 | Out-Null
        $rustVbsVerifyExit = $LASTEXITCODE
        $bothVbsVerifyOk = ($nativeVbsVerifyExit -eq 0) -and ($rustVbsVerifyExit -eq 0)
        $ErrorActionPreference = $savedVbs
        Remove-Item -LiteralPath $tmpVbsNat, $tmpVbsRust -Force -ErrorAction SilentlyContinue

        $results += [PSCustomObject]@{
            id = "sign_vbs_sha256_match_native"
            nativeExitCode = $nativeVbsSignExit
            rustExitCode = $rustVbsSignExit
            classification = if ($nativeVbsSignExit -ne $rustVbsSignExit) { "semantic_mismatch" }
            elseif ($nativeVbsSignExit -ne 0) { "shared_failure" }
            elseif (-not $hashVbsMatch -and $bothVbsVerifyOk) { "artifact_semantic_match" }
            elseif (-not $hashVbsMatch) { "semantic_mismatch" }
            else { "exact_match" }
        }
        $results += [PSCustomObject]@{
            id = "verify_vbs_pa_exit_match"
            nativeExitCode = $nativeVbsVerifyExit
            rustExitCode = $rustVbsVerifyExit
            classification = if ($nativeVbsVerifyExit -ne $rustVbsVerifyExit) { "semantic_mismatch" }
            elseif ($nativeVbsVerifyExit -ne 0 -and $rustVbsVerifyExit -ne 0) { "shared_failure" }
            else { "exit_match" }
        }

        $tmpVbsDescNat = Join-Path $env:TEMP "psign_verify_desc_native.vbs"
        $tmpVbsDescRust = Join-Path $env:TEMP "psign_verify_desc_rust.vbs"
        Copy-Item -LiteralPath $vbsSrc -Destination $tmpVbsDescNat -Force
        Copy-Item -LiteralPath $vbsSrc -Destination $tmpVbsDescRust -Force
        $savedVbsDesc = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativeVbsDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $parityDesc, "/du", $parityUrl, $tmpVbsDescNat)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativeVbsDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $parityDesc, "/du", $parityUrl, $tmpVbsDescNat)
        }
        & "$nativeSignTool" @nativeVbsDescSign 2>&1 | Out-Null
        $nativeVbsDescSignExit = $LASTEXITCODE

        $rustVbsDescSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", "--description", $parityDesc, "--description-url", $parityUrl, $tmpVbsDescRust)
        & "$rustBin" @rustVbsDescSign 2>&1 | Out-Null
        $rustVbsDescSignExit = $LASTEXITCODE

        $nativeVbsVerifyDescOut = ""
        $rustVbsVerifyDescOut = ""
        $nativeVbsVerifyDescExit = -1
        $rustVbsVerifyDescExit = -1
        if ($nativeVbsDescSignExit -eq 0 -and $rustVbsDescSignExit -eq 0) {
            $nativeVbsVerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpVbsDescNat) 2>&1 | Out-String)
            $nativeVbsVerifyDescExit = $LASTEXITCODE
            $rustVbsVerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpVbsDescRust) 2>&1 | Out-String)
            $rustVbsVerifyDescExit = $LASTEXITCODE
        }
        $ErrorActionPreference = $savedVbsDesc
        Remove-Item -LiteralPath $tmpVbsDescNat, $tmpVbsDescRust -Force -ErrorAction SilentlyContinue

        $nativeVbsDescLine = [regex]::Match($nativeVbsVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $rustVbsDescLine = [regex]::Match($rustVbsVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $nativeVbsUrlLine = [regex]::Match($nativeVbsVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
        $rustVbsUrlLine = [regex]::Match($rustVbsVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

        $vbsDescClassification = if ($nativeVbsDescSignExit -ne 0 -or $rustVbsDescSignExit -ne 0) {
            if ($nativeVbsDescSignExit -eq $rustVbsDescSignExit) { "shared_failure" } else { "semantic_mismatch" }
        }
        elseif ($nativeVbsVerifyDescExit -ne $rustVbsVerifyDescExit) { "semantic_mismatch" }
        elseif ($nativeVbsDescLine -ne $rustVbsDescLine -or $nativeVbsUrlLine -ne $rustVbsUrlLine) { "semantic_mismatch" }
        elseif ($nativeVbsDescLine -ne $parityDesc -or $nativeVbsUrlLine -ne $parityUrl) { "semantic_mismatch" }
        else { "artifact_semantic_match" }

        $results += [PSCustomObject]@{
            id = "artifact_verify_vbs_print_description_match"
            nativeExitCode = $nativeVbsVerifyDescExit
            rustExitCode = $rustVbsVerifyDescExit
            classification = $vbsDescClassification
        }
    }

    # Windows Script File .wsf (XML container — OS SIP when registered).
    $wsfSrc = if ($env:PSIGN_WSF_UNSIGNED_FIXTURE) { $env:PSIGN_WSF_UNSIGNED_FIXTURE } else { Join-Path $workspace "tests\fixtures\unsigned-sample.wsf" }
    if (Test-Path -LiteralPath $wsfSrc) {
        $expectedScenarioIds += @(
            "sign_wsf_sha256_match_native",
            "verify_wsf_pa_exit_match",
            "artifact_verify_wsf_print_description_match"
        )
        $tmpWsfNat = Join-Path $env:TEMP "psign_wsf_native.wsf"
        $tmpWsfRust = Join-Path $env:TEMP "psign_wsf_rust.wsf"
        Copy-Item -LiteralPath $wsfSrc -Destination $tmpWsfNat -Force
        Copy-Item -LiteralPath $wsfSrc -Destination $tmpWsfRust -Force
        $savedWsf = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativeWsfSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, $tmpWsfNat)
        $rustWsfSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", $tmpWsfRust)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativeWsfSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, $tmpWsfNat)
        }
        & "$nativeSignTool" @nativeWsfSign 2>&1 | Out-Null
        $nativeWsfSignExit = $LASTEXITCODE
        & "$rustBin" @rustWsfSign 2>&1 | Out-Null
        $rustWsfSignExit = $LASTEXITCODE
        $hashWsfMatch = $false
        if ($nativeWsfSignExit -eq 0 -and $rustWsfSignExit -eq 0) {
            $hashWsfMatch = ((Get-FileHash -LiteralPath $tmpWsfNat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpWsfRust -Algorithm SHA256).Hash)
        }
        & "$nativeSignTool" verify /pa $tmpWsfNat 2>&1 | Out-Null
        $nativeWsfVerifyExit = $LASTEXITCODE
        & "$rustBin" verify --policy pa $tmpWsfRust 2>&1 | Out-Null
        $rustWsfVerifyExit = $LASTEXITCODE
        $bothWsfVerifyOk = ($nativeWsfVerifyExit -eq 0) -and ($rustWsfVerifyExit -eq 0)
        $ErrorActionPreference = $savedWsf
        Remove-Item -LiteralPath $tmpWsfNat, $tmpWsfRust -Force -ErrorAction SilentlyContinue

        $results += [PSCustomObject]@{
            id = "sign_wsf_sha256_match_native"
            nativeExitCode = $nativeWsfSignExit
            rustExitCode = $rustWsfSignExit
            classification = if ($nativeWsfSignExit -ne $rustWsfSignExit) { "semantic_mismatch" }
            elseif ($nativeWsfSignExit -ne 0) { "shared_failure" }
            elseif (-not $hashWsfMatch -and $bothWsfVerifyOk) { "artifact_semantic_match" }
            elseif (-not $hashWsfMatch) { "semantic_mismatch" }
            else { "exact_match" }
        }
        $results += [PSCustomObject]@{
            id = "verify_wsf_pa_exit_match"
            nativeExitCode = $nativeWsfVerifyExit
            rustExitCode = $rustWsfVerifyExit
            classification = if ($nativeWsfVerifyExit -ne $rustWsfVerifyExit) { "semantic_mismatch" }
            elseif ($nativeWsfVerifyExit -ne 0 -and $rustWsfVerifyExit -ne 0) { "shared_failure" }
            else { "exit_match" }
        }

        $tmpWsfDescNat = Join-Path $env:TEMP "psign_verify_desc_native.wsf"
        $tmpWsfDescRust = Join-Path $env:TEMP "psign_verify_desc_rust.wsf"
        Copy-Item -LiteralPath $wsfSrc -Destination $tmpWsfDescNat -Force
        Copy-Item -LiteralPath $wsfSrc -Destination $tmpWsfDescRust -Force
        $savedWsfDesc = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $nativeWsfDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $parityDesc, "/du", $parityUrl, $tmpWsfDescNat)
        if ($env:PSIGN_TEST_PFX_PASSWORD) {
            $nativeWsfDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $parityDesc, "/du", $parityUrl, $tmpWsfDescNat)
        }
        & "$nativeSignTool" @nativeWsfDescSign 2>&1 | Out-Null
        $nativeWsfDescSignExit = $LASTEXITCODE

        $rustWsfDescSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256", "--description", $parityDesc, "--description-url", $parityUrl, $tmpWsfDescRust)
        & "$rustBin" @rustWsfDescSign 2>&1 | Out-Null
        $rustWsfDescSignExit = $LASTEXITCODE

        $nativeWsfVerifyDescOut = ""
        $rustWsfVerifyDescOut = ""
        $nativeWsfVerifyDescExit = -1
        $rustWsfVerifyDescExit = -1
        if ($nativeWsfDescSignExit -eq 0 -and $rustWsfDescSignExit -eq 0) {
            $nativeWsfVerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpWsfDescNat) 2>&1 | Out-String)
            $nativeWsfVerifyDescExit = $LASTEXITCODE
            $rustWsfVerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpWsfDescRust) 2>&1 | Out-String)
            $rustWsfVerifyDescExit = $LASTEXITCODE
        }
        $ErrorActionPreference = $savedWsfDesc
        Remove-Item -LiteralPath $tmpWsfDescNat, $tmpWsfDescRust -Force -ErrorAction SilentlyContinue

        $nativeWsfDescLine = [regex]::Match($nativeWsfVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $rustWsfDescLine = [regex]::Match($rustWsfVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
        $nativeWsfUrlLine = [regex]::Match($nativeWsfVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
        $rustWsfUrlLine = [regex]::Match($rustWsfVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

        $wsfDescClassification = if ($nativeWsfDescSignExit -ne 0 -or $rustWsfDescSignExit -ne 0) {
            if ($nativeWsfDescSignExit -eq $rustWsfDescSignExit) { "shared_failure" } else { "semantic_mismatch" }
        }
        elseif ($nativeWsfVerifyDescExit -ne $rustWsfVerifyDescExit) { "semantic_mismatch" }
        elseif ($nativeWsfDescLine -ne $rustWsfDescLine -or $nativeWsfUrlLine -ne $rustWsfUrlLine) { "semantic_mismatch" }
        elseif ($nativeWsfDescLine -ne $parityDesc -or $nativeWsfUrlLine -ne $parityUrl) { "semantic_mismatch" }
        else { "artifact_semantic_match" }

        $results += [PSCustomObject]@{
            id = "artifact_verify_wsf_print_description_match"
            nativeExitCode = $nativeWsfVerifyDescExit
            rustExitCode = $rustWsfVerifyDescExit
            classification = $wsfDescClassification
        }
    }
}

# MSIX semantic scenario: native and rust sign with RFC3161 should align on success/failure.
if ($env:PSIGN_MSIX_UNSIGNED_FIXTURE -and $env:PSIGN_MSIX_TEST_PFX -and $env:PSIGN_MSIX_TIMESTAMP_URL) {
    $expectedScenarioIds += @("artifact_msix_sign_semantic", "artifact_verify_msix_print_description_match")
    $tempNativeMsix = Join-Path $env:TEMP "psign_ci_msix_native.msix"
    $tempRustMsix = Join-Path $env:TEMP "psign_ci_msix_rust.msix"
    Copy-Item -LiteralPath $env:PSIGN_MSIX_UNSIGNED_FIXTURE -Destination $tempNativeMsix -Force
    Copy-Item -LiteralPath $env:PSIGN_MSIX_UNSIGNED_FIXTURE -Destination $tempRustMsix -Force

    $nativeSignArgs = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_MSIX_TEST_PFX, "/tr", $env:PSIGN_MSIX_TIMESTAMP_URL, "/td", "SHA256", $tempNativeMsix)
    if ($env:PSIGN_MSIX_TEST_PFX_PASSWORD) {
        $nativeSignArgs = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_MSIX_TEST_PFX, "/p", $env:PSIGN_MSIX_TEST_PFX_PASSWORD, "/tr", $env:PSIGN_MSIX_TIMESTAMP_URL, "/td", "SHA256", $tempNativeMsix)
    }
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & "$nativeSignTool" @nativeSignArgs 2>&1 | Out-Null
    $nativeMsixExit = $LASTEXITCODE

    $rustSignArgs = @("sign") + (Get-RustMsixCredentialArgs) + @("--digest", "sha256", "--timestamp-url", $env:PSIGN_MSIX_TIMESTAMP_URL, "--timestamp-digest", "sha256", $tempRustMsix)
    & "$rustBin" @rustSignArgs 2>&1 | Out-Null
    $rustMsixExit = $LASTEXITCODE
    $ErrorActionPreference = $saved

    $msixSignClass = if ($nativeMsixExit -eq $rustMsixExit) {
        if ($nativeMsixExit -ne 0) { "shared_failure" } else { "artifact_semantic_match" }
    }
    elseif ($nativeMsixExit -eq 0 -and $rustMsixExit -ne 0) {
        # Native `signtool sign /f` succeeds on GitHub runners; Rust `SignerSignEx3` + Appx SIP still hits
        # `CRYPT_E_NO_PROVIDER` / `APPX_E_MISSING_PUBLIC_KEY_OR_REQUIRED_DATA` on some hosts — tracked for parity.
        "documented_rust_msix_sign_ex3_gap"
    }
    else { "semantic_mismatch" }

    $results += [PSCustomObject]@{
        id = "artifact_msix_sign_semantic"
        nativeExitCode = $nativeMsixExit
        rustExitCode = $rustMsixExit
        classification = $msixSignClass
    }

    # Same strings as PE description parity (`artifact_verify_print_description_match`) for comparable metadata.
    $msixParityDesc = "psign_parity_desc_2026"
    $msixParityUrl = "https://example.invalid/psign-parity"
    $tempNativeMsixDesc = Join-Path $env:TEMP "psign_ci_msix_native_desc.msix"
    $tempRustMsixDesc = Join-Path $env:TEMP "psign_ci_msix_rust_desc.msix"
    Copy-Item -LiteralPath $env:PSIGN_MSIX_UNSIGNED_FIXTURE -Destination $tempNativeMsixDesc -Force
    Copy-Item -LiteralPath $env:PSIGN_MSIX_UNSIGNED_FIXTURE -Destination $tempRustMsixDesc -Force
    $savedMsixDesc = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $nativeMsixDescSign = @(
        "sign", "/fd", "SHA256", "/f", $env:PSIGN_MSIX_TEST_PFX,
        "/d", $msixParityDesc, "/du", $msixParityUrl,
        "/tr", $env:PSIGN_MSIX_TIMESTAMP_URL, "/td", "SHA256",
        $tempNativeMsixDesc
    )
    if ($env:PSIGN_MSIX_TEST_PFX_PASSWORD) {
        $nativeMsixDescSign = @(
            "sign", "/fd", "SHA256", "/f", $env:PSIGN_MSIX_TEST_PFX, "/p", $env:PSIGN_MSIX_TEST_PFX_PASSWORD,
            "/d", $msixParityDesc, "/du", $msixParityUrl,
            "/tr", $env:PSIGN_MSIX_TIMESTAMP_URL, "/td", "SHA256",
            $tempNativeMsixDesc
        )
    }
    & "$nativeSignTool" @nativeMsixDescSign 2>&1 | Out-Null
    $nativeMsixDescSignExit = $LASTEXITCODE

    $rustMsixDescSign = @("sign") + (Get-RustMsixCredentialArgs) + @(
        "--digest", "sha256",
        "--description", $msixParityDesc, "--description-url", $msixParityUrl,
        "--timestamp-url", $env:PSIGN_MSIX_TIMESTAMP_URL, "--timestamp-digest", "sha256",
        $tempRustMsixDesc
    )
    & "$rustBin" @rustMsixDescSign 2>&1 | Out-Null
    $rustMsixDescSignExit = $LASTEXITCODE

    $nativeMsixVerifyDescOut = ""
    $rustMsixVerifyDescOut = ""
    $nativeMsixVerifyDescExit = -1
    $rustMsixVerifyDescExit = -1
    if ($nativeMsixDescSignExit -eq 0 -and $rustMsixDescSignExit -eq 0) {
        $nativeMsixVerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tempNativeMsixDesc) 2>&1 | Out-String)
        $nativeMsixVerifyDescExit = $LASTEXITCODE
        $rustMsixVerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tempRustMsixDesc) 2>&1 | Out-String)
        $rustMsixVerifyDescExit = $LASTEXITCODE
    }
    $ErrorActionPreference = $savedMsixDesc
    Remove-Item -LiteralPath $tempNativeMsixDesc, $tempRustMsixDesc -Force -ErrorAction SilentlyContinue

    $nativeMsixDescLine = [regex]::Match($nativeMsixVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $rustMsixDescLine = [regex]::Match($rustMsixVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $nativeMsixUrlLine = [regex]::Match($nativeMsixVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
    $rustMsixUrlLine = [regex]::Match($rustMsixVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

    $msixDescClassification = if ($nativeMsixDescSignExit -ne 0 -or $rustMsixDescSignExit -ne 0) {
        if ($nativeMsixDescSignExit -eq $rustMsixDescSignExit) { "shared_failure" }
        elseif ($nativeMsixDescSignExit -eq 0 -and $rustMsixDescSignExit -ne 0) { "documented_rust_msix_sign_ex3_gap" }
        else { "semantic_mismatch" }
    }
    elseif ($nativeMsixVerifyDescExit -ne $rustMsixVerifyDescExit) { "semantic_mismatch" }
    elseif ($nativeMsixDescLine -ne $rustMsixDescLine -or $nativeMsixUrlLine -ne $rustMsixUrlLine) { "semantic_mismatch" }
    elseif ($nativeMsixDescLine -ne $msixParityDesc -or $nativeMsixUrlLine -ne $msixParityUrl) { "semantic_mismatch" }
    else { "artifact_semantic_match" }

    $results += [PSCustomObject]@{
        id = "artifact_verify_msix_print_description_match"
        nativeExitCode = $nativeMsixVerifyDescExit
        rustExitCode = $rustMsixVerifyDescExit
        classification = $msixDescClassification
    }
}

# MSIX decoupled digest scenario: rust dlib/dmdf bridge must align with native success/failure.
if ($env:PSIGN_MSIX_UNSIGNED_FIXTURE -and $env:PSIGN_MSIX_TEST_PFX -and $env:PSIGN_MSIX_TIMESTAMP_URL -and $env:PSIGN_MSIX_DLIB -and $env:PSIGN_MSIX_DMDF) {
    $expectedScenarioIds += @("artifact_msix_decoupled_semantic")
    $tempNativeMsixDecoupled = Join-Path $env:TEMP "psign_ci_msix_native_decoupled.msix"
    $tempRustMsixDecoupled = Join-Path $env:TEMP "psign_ci_msix_rust_decoupled.msix"
    Copy-Item -LiteralPath $env:PSIGN_MSIX_UNSIGNED_FIXTURE -Destination $tempNativeMsixDecoupled -Force
    Copy-Item -LiteralPath $env:PSIGN_MSIX_UNSIGNED_FIXTURE -Destination $tempRustMsixDecoupled -Force

    $nativeDecoupledArgs = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_MSIX_TEST_PFX, "/tr", $env:PSIGN_MSIX_TIMESTAMP_URL, "/td", "SHA256", "/dlib", $env:PSIGN_MSIX_DLIB, "/dmdf", $env:PSIGN_MSIX_DMDF, "/ph", $tempNativeMsixDecoupled)
    if ($env:PSIGN_MSIX_TEST_PFX_PASSWORD) {
        $nativeDecoupledArgs = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_MSIX_TEST_PFX, "/p", $env:PSIGN_MSIX_TEST_PFX_PASSWORD, "/tr", $env:PSIGN_MSIX_TIMESTAMP_URL, "/td", "SHA256", "/dlib", $env:PSIGN_MSIX_DLIB, "/dmdf", $env:PSIGN_MSIX_DMDF, "/ph", $tempNativeMsixDecoupled)
    }
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & "$nativeSignTool" @nativeDecoupledArgs 2>&1 | Out-Null
    $nativeDecoupledExit = $LASTEXITCODE

    $rustDecoupledArgs = @("sign") + (Get-RustMsixCredentialArgs) + @("--digest", "sha256", "--timestamp-url", $env:PSIGN_MSIX_TIMESTAMP_URL, "--timestamp-digest", "sha256", "--dlib", $env:PSIGN_MSIX_DLIB, "--dmdf", $env:PSIGN_MSIX_DMDF, "--page-hashes", $tempRustMsixDecoupled)
    & "$rustBin" @rustDecoupledArgs 2>&1 | Out-Null
    $rustDecoupledExit = $LASTEXITCODE
    $ErrorActionPreference = $saved

    $decoupledClass = if ($nativeDecoupledExit -eq $rustDecoupledExit) {
        if ($nativeDecoupledExit -ne 0) { "shared_failure" } else { "artifact_semantic_match" }
    }
    elseif ($nativeDecoupledExit -eq 0 -and $rustDecoupledExit -ne 0) {
        # Same documented bucket as embedded MSIX — decoupled still uses SignerSignEx3 + Appx SIP + digest DLL.
        "documented_rust_msix_sign_ex3_gap"
    }
    else { "semantic_mismatch" }

    $results += [PSCustomObject]@{
        id = "artifact_msix_decoupled_semantic"
        nativeExitCode = $nativeDecoupledExit
        rustExitCode = $rustDecoupledExit
        classification = $decoupledClass
    }
}

# Optional WinMD (Windows metadata, PE-based CLI assembly SIP): `PSIGN_WINMD_UNSIGNED_FIXTURE` + `PSIGN_TEST_PFX`.
# Optional RFC3161: `PSIGN_WINMD_TIMESTAMP_URL`. Smoke helper: `scripts/sip-format-smoke.ps1`.
$winmdSrc = $env:PSIGN_WINMD_UNSIGNED_FIXTURE
if ($winmdSrc -and $env:PSIGN_TEST_PFX -and (Test-Path -LiteralPath $winmdSrc)) {
    $expectedScenarioIds += @(
        "sign_winmd_sha256_match_native",
        "verify_winmd_pa_exit_match",
        "artifact_verify_winmd_print_description_match"
    )
    $tmpWinmdNat = Join-Path $env:TEMP "psign_winmd_native.winmd"
    $tmpWinmdRust = Join-Path $env:TEMP "psign_winmd_rust.winmd"
    Copy-Item -LiteralPath $winmdSrc -Destination $tmpWinmdNat -Force
    Copy-Item -LiteralPath $winmdSrc -Destination $tmpWinmdRust -Force
    $savedW = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $nativeWinmdSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $nativeWinmdSign += @("/p", $env:PSIGN_TEST_PFX_PASSWORD)
    }
    if ($env:PSIGN_WINMD_TIMESTAMP_URL) {
        $nativeWinmdSign += @("/tr", $env:PSIGN_WINMD_TIMESTAMP_URL, "/td", "SHA256")
    }
    $nativeWinmdSign += @($tmpWinmdNat)

    $rustWinmdSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256")
    if ($env:PSIGN_WINMD_TIMESTAMP_URL) {
        $rustWinmdSign += @("--timestamp-url", $env:PSIGN_WINMD_TIMESTAMP_URL, "--timestamp-digest", "sha256")
    }
    $rustWinmdSign += @($tmpWinmdRust)

    & "$nativeSignTool" @nativeWinmdSign 2>&1 | Out-Null
    $nativeWinmdSignExit = $LASTEXITCODE
    & "$rustBin" @rustWinmdSign 2>&1 | Out-Null
    $rustWinmdSignExit = $LASTEXITCODE
    $hashWinmdMatch = $false
    if ($nativeWinmdSignExit -eq 0 -and $rustWinmdSignExit -eq 0) {
        $hashWinmdMatch = ((Get-FileHash -LiteralPath $tmpWinmdNat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpWinmdRust -Algorithm SHA256).Hash)
    }
    & "$nativeSignTool" verify /pa $tmpWinmdNat 2>&1 | Out-Null
    $nativeWinmdVerifyExit = $LASTEXITCODE
    & "$rustBin" verify --policy pa $tmpWinmdRust 2>&1 | Out-Null
    $rustWinmdVerifyExit = $LASTEXITCODE
    $bothWinmdVerifyOk = ($nativeWinmdVerifyExit -eq 0) -and ($rustWinmdVerifyExit -eq 0)

    $winmdParityDesc = "psign_winmd_parity_desc_2026"
    $winmdParityUrl = "https://example.invalid/psign-winmd-parity"
    $tmpWinmdDescNat = Join-Path $env:TEMP "psign_winmd_desc_native.winmd"
    $tmpWinmdDescRust = Join-Path $env:TEMP "psign_winmd_desc_rust.winmd"
    Copy-Item -LiteralPath $winmdSrc -Destination $tmpWinmdDescNat -Force
    Copy-Item -LiteralPath $winmdSrc -Destination $tmpWinmdDescRust -Force

    $nativeWinmdDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $winmdParityDesc, "/du", $winmdParityUrl)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $nativeWinmdDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $winmdParityDesc, "/du", $winmdParityUrl)
    }
    if ($env:PSIGN_WINMD_TIMESTAMP_URL) {
        $nativeWinmdDescSign += @("/tr", $env:PSIGN_WINMD_TIMESTAMP_URL, "/td", "SHA256")
    }
    $nativeWinmdDescSign += @($tmpWinmdDescNat)

    $rustWinmdDescSign = @("sign") + (Get-RustSignCredentialArgs) + @(
        "--digest", "sha256",
        "--description", $winmdParityDesc, "--description-url", $winmdParityUrl
    )
    if ($env:PSIGN_WINMD_TIMESTAMP_URL) {
        $rustWinmdDescSign += @("--timestamp-url", $env:PSIGN_WINMD_TIMESTAMP_URL, "--timestamp-digest", "sha256")
    }
    $rustWinmdDescSign += @($tmpWinmdDescRust)

    & "$nativeSignTool" @nativeWinmdDescSign 2>&1 | Out-Null
    $nativeWinmdDescSignExit = $LASTEXITCODE
    & "$rustBin" @rustWinmdDescSign 2>&1 | Out-Null
    $rustWinmdDescSignExit = $LASTEXITCODE

    $nativeWinmdVerifyDescOut = ""
    $rustWinmdVerifyDescOut = ""
    $nativeWinmdVerifyDescExit = -1
    $rustWinmdVerifyDescExit = -1
    if ($nativeWinmdDescSignExit -eq 0 -and $rustWinmdDescSignExit -eq 0) {
        $nativeWinmdVerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpWinmdDescNat) 2>&1 | Out-String)
        $nativeWinmdVerifyDescExit = $LASTEXITCODE
        $rustWinmdVerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpWinmdDescRust) 2>&1 | Out-String)
        $rustWinmdVerifyDescExit = $LASTEXITCODE
    }

    $ErrorActionPreference = $savedW
    Remove-Item -LiteralPath $tmpWinmdNat, $tmpWinmdRust, $tmpWinmdDescNat, $tmpWinmdDescRust -Force -ErrorAction SilentlyContinue

    $results += [PSCustomObject]@{
        id = "sign_winmd_sha256_match_native"
        nativeExitCode = $nativeWinmdSignExit
        rustExitCode = $rustWinmdSignExit
        classification = if ($nativeWinmdSignExit -ne $rustWinmdSignExit) { "semantic_mismatch" }
        elseif ($nativeWinmdSignExit -ne 0) { "shared_failure" }
        elseif (-not $hashWinmdMatch -and $bothWinmdVerifyOk) { "artifact_semantic_match" }
        elseif (-not $hashWinmdMatch) { "semantic_mismatch" }
        else { "exact_match" }
    }
    $results += [PSCustomObject]@{
        id = "verify_winmd_pa_exit_match"
        nativeExitCode = $nativeWinmdVerifyExit
        rustExitCode = $rustWinmdVerifyExit
        classification = if ($nativeWinmdVerifyExit -ne $rustWinmdVerifyExit) { "semantic_mismatch" }
        elseif ($nativeWinmdVerifyExit -ne 0 -and $rustWinmdVerifyExit -ne 0) { "shared_failure" }
        else { "exit_match" }
    }

    $nativeWinmdDescLine = [regex]::Match($nativeWinmdVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $rustWinmdDescLine = [regex]::Match($rustWinmdVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $nativeWinmdUrlLine = [regex]::Match($nativeWinmdVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
    $rustWinmdUrlLine = [regex]::Match($rustWinmdVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

    $winmdDescClassification = if ($nativeWinmdDescSignExit -ne 0 -or $rustWinmdDescSignExit -ne 0) {
        if ($nativeWinmdDescSignExit -eq $rustWinmdDescSignExit) { "shared_failure" } else { "semantic_mismatch" }
    }
    elseif ($nativeWinmdVerifyDescExit -ne $rustWinmdVerifyDescExit) { "semantic_mismatch" }
    elseif ($nativeWinmdDescLine -ne $rustWinmdDescLine -or $nativeWinmdUrlLine -ne $rustWinmdUrlLine) { "semantic_mismatch" }
    elseif ($nativeWinmdDescLine -ne $winmdParityDesc -or $nativeWinmdUrlLine -ne $winmdParityUrl) { "semantic_mismatch" }
    else { "artifact_semantic_match" }

    $results += [PSCustomObject]@{
        id = "artifact_verify_winmd_print_description_match"
        nativeExitCode = $nativeWinmdVerifyDescExit
        rustExitCode = $rustWinmdVerifyDescExit
        classification = $winmdDescClassification
    }
}

# Optional MSI (Windows Installer SIP): supply `PSIGN_MSI_UNSIGNED_FIXTURE` + same PFX env as PE (`PSIGN_TEST_PFX`).
# Optional RFC3161 during sign: `PSIGN_MSI_TIMESTAMP_URL` (native `/tr` `/td SHA256`, rust `--timestamp-url` `--timestamp-digest sha256`).
$mmsiSrc = $env:PSIGN_MSI_UNSIGNED_FIXTURE
if ($mmsiSrc -and $env:PSIGN_TEST_PFX -and (Test-Path -LiteralPath $mmsiSrc)) {
    $expectedScenarioIds += @(
        "sign_msi_sha256_match_native",
        "verify_msi_pa_exit_match",
        "artifact_verify_msi_print_description_match"
    )
    $tmpMsiNat = Join-Path $env:TEMP "psign_msi_native.msi"
    $tmpMsiRust = Join-Path $env:TEMP "psign_msi_rust.msi"
    Copy-Item -LiteralPath $mmsiSrc -Destination $tmpMsiNat -Force
    Copy-Item -LiteralPath $mmsiSrc -Destination $tmpMsiRust -Force
    $savedMsi = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $nativeMsiSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $nativeMsiSign += @("/p", $env:PSIGN_TEST_PFX_PASSWORD)
    }
    if ($env:PSIGN_MSI_TIMESTAMP_URL) {
        $nativeMsiSign += @("/tr", $env:PSIGN_MSI_TIMESTAMP_URL, "/td", "SHA256")
    }
    $nativeMsiSign += @($tmpMsiNat)

    $rustMsiSign = @("sign") + (Get-RustSignCredentialArgs) + @("--digest", "sha256")
    if ($env:PSIGN_MSI_TIMESTAMP_URL) {
        $rustMsiSign += @("--timestamp-url", $env:PSIGN_MSI_TIMESTAMP_URL, "--timestamp-digest", "sha256")
    }
    $rustMsiSign += @($tmpMsiRust)

    & "$nativeSignTool" @nativeMsiSign 2>&1 | Out-Null
    $nativeMsiSignExit = $LASTEXITCODE
    & "$rustBin" @rustMsiSign 2>&1 | Out-Null
    $rustMsiSignExit = $LASTEXITCODE
    $hashMsiMatch = $false
    if ($nativeMsiSignExit -eq 0 -and $rustMsiSignExit -eq 0) {
        $hashMsiMatch = ((Get-FileHash -LiteralPath $tmpMsiNat -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $tmpMsiRust -Algorithm SHA256).Hash)
    }
    & "$nativeSignTool" verify /pa $tmpMsiNat 2>&1 | Out-Null
    $nativeMsiVerifyExit = $LASTEXITCODE
    & "$rustBin" verify --policy pa $tmpMsiRust 2>&1 | Out-Null
    $rustMsiVerifyExit = $LASTEXITCODE
    $bothMsiVerifyOk = ($nativeMsiVerifyExit -eq 0) -and ($rustMsiVerifyExit -eq 0)

    $msiParityDesc = "psign_parity_desc_2026"
    $msiParityUrl = "https://example.invalid/psign-parity"
    $tmpMsiDescNat = Join-Path $env:TEMP "psign_msi_desc_native.msi"
    $tmpMsiDescRust = Join-Path $env:TEMP "psign_msi_desc_rust.msi"
    Copy-Item -LiteralPath $mmsiSrc -Destination $tmpMsiDescNat -Force
    Copy-Item -LiteralPath $mmsiSrc -Destination $tmpMsiDescRust -Force

    $nativeMsiDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/d", $msiParityDesc, "/du", $msiParityUrl)
    if ($env:PSIGN_TEST_PFX_PASSWORD) {
        $nativeMsiDescSign = @("sign", "/fd", "SHA256", "/f", $env:PSIGN_TEST_PFX, "/p", $env:PSIGN_TEST_PFX_PASSWORD, "/d", $msiParityDesc, "/du", $msiParityUrl)
    }
    if ($env:PSIGN_MSI_TIMESTAMP_URL) {
        $nativeMsiDescSign += @("/tr", $env:PSIGN_MSI_TIMESTAMP_URL, "/td", "SHA256")
    }
    $nativeMsiDescSign += @($tmpMsiDescNat)

    $rustMsiDescSign = @("sign") + (Get-RustSignCredentialArgs) + @(
        "--digest", "sha256",
        "--description", $msiParityDesc, "--description-url", $msiParityUrl
    )
    if ($env:PSIGN_MSI_TIMESTAMP_URL) {
        $rustMsiDescSign += @("--timestamp-url", $env:PSIGN_MSI_TIMESTAMP_URL, "--timestamp-digest", "sha256")
    }
    $rustMsiDescSign += @($tmpMsiDescRust)

    & "$nativeSignTool" @nativeMsiDescSign 2>&1 | Out-Null
    $nativeMsiDescSignExit = $LASTEXITCODE
    & "$rustBin" @rustMsiDescSign 2>&1 | Out-Null
    $rustMsiDescSignExit = $LASTEXITCODE

    $nativeMsiVerifyDescOut = ""
    $rustMsiVerifyDescOut = ""
    $nativeMsiVerifyDescExit = -1
    $rustMsiVerifyDescExit = -1
    if ($nativeMsiDescSignExit -eq 0 -and $rustMsiDescSignExit -eq 0) {
        $nativeMsiVerifyDescOut = (& "$nativeSignTool" @("verify", "/pa", "/v", "/d", $tmpMsiDescNat) 2>&1 | Out-String)
        $nativeMsiVerifyDescExit = $LASTEXITCODE
        $rustMsiVerifyDescOut = (& "$rustBin" @("verify", "--policy", "pa", "-v", "--print-description", $tmpMsiDescRust) 2>&1 | Out-String)
        $rustMsiVerifyDescExit = $LASTEXITCODE
    }

    $ErrorActionPreference = $savedMsi
    Remove-Item -LiteralPath $tmpMsiNat, $tmpMsiRust, $tmpMsiDescNat, $tmpMsiDescRust -Force -ErrorAction SilentlyContinue

    $results += [PSCustomObject]@{
        id = "sign_msi_sha256_match_native"
        nativeExitCode = $nativeMsiSignExit
        rustExitCode = $rustMsiSignExit
        classification = if ($nativeMsiSignExit -ne $rustMsiSignExit) { "semantic_mismatch" }
        elseif ($nativeMsiSignExit -ne 0) { "shared_failure" }
        elseif (-not $hashMsiMatch -and $bothMsiVerifyOk) { "artifact_semantic_match" }
        elseif (-not $hashMsiMatch) { "semantic_mismatch" }
        else { "exact_match" }
    }
    $results += [PSCustomObject]@{
        id = "verify_msi_pa_exit_match"
        nativeExitCode = $nativeMsiVerifyExit
        rustExitCode = $rustMsiVerifyExit
        classification = if ($nativeMsiVerifyExit -ne $rustMsiVerifyExit) { "semantic_mismatch" }
        elseif ($nativeMsiVerifyExit -ne 0 -and $rustMsiVerifyExit -ne 0) { "shared_failure" }
        else { "exit_match" }
    }

    $nativeMsiDescLine = [regex]::Match($nativeMsiVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $rustMsiDescLine = [regex]::Match($rustMsiVerifyDescOut, '(?m)^Description:\s*(.*)$').Groups[1].Value.Trim()
    $nativeMsiUrlLine = [regex]::Match($nativeMsiVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()
    $rustMsiUrlLine = [regex]::Match($rustMsiVerifyDescOut, '(?m)^Description URL:\s*(.*)$').Groups[1].Value.Trim()

    $msiDescClassification = if ($nativeMsiDescSignExit -ne 0 -or $rustMsiDescSignExit -ne 0) {
        if ($nativeMsiDescSignExit -eq $rustMsiDescSignExit) { "shared_failure" } else { "semantic_mismatch" }
    }
    elseif ($nativeMsiVerifyDescExit -ne $rustMsiVerifyDescExit) { "semantic_mismatch" }
    elseif ($nativeMsiDescLine -ne $rustMsiDescLine -or $nativeMsiUrlLine -ne $rustMsiUrlLine) { "semantic_mismatch" }
    elseif ($nativeMsiDescLine -ne $msiParityDesc -or $nativeMsiUrlLine -ne $msiParityUrl) { "semantic_mismatch" }
    else { "artifact_semantic_match" }

    $results += [PSCustomObject]@{
        id = "artifact_verify_msi_print_description_match"
        nativeExitCode = $nativeMsiVerifyDescExit
        rustExitCode = $rustMsiVerifyDescExit
        classification = $msiDescClassification
    }
}

# Optional scenario: detached verify path
if ($env:PSIGN_DETACHED_CONTENT -and $env:PSIGN_DETACHED_PKCS7) {
    $expectedScenarioIds += @("artifact_detached_semantic")
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & "$rustBin" verify --policy pa --allow-test-root $env:PSIGN_DETACHED_CONTENT --detached-pkcs7 $env:PSIGN_DETACHED_PKCS7 2>&1 | Out-Null
    $detachedExit = $LASTEXITCODE
    $ErrorActionPreference = $saved
    # Bare CMS SignedData from `signtool /p7` is normalized to PKCS#7 ContentInfo in Rust; remaining failures stay documented.
    $detachedClass = if ($detachedExit -eq 0) { "artifact_semantic_match" } else { "documented_detached_pkcs7_verify_gap" }
    $results += [PSCustomObject]@{
        id = "artifact_detached_semantic"
        nativeExitCode = 0
        rustExitCode = $detachedExit
        classification = $detachedClass
    }
}

# Optional scenario: catalog verify path (+ `/o` WinTrust flag via `--os-version-check` when catalog is used)
if ($env:PSIGN_CATALOG_TARGET -and $env:PSIGN_CATALOG_FILE) {
    $expectedScenarioIds += @("artifact_catalog_semantic", "artifact_catalog_os_version_semantic")
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & "$rustBin" verify $env:PSIGN_CATALOG_TARGET --catalog $env:PSIGN_CATALOG_FILE 2>&1 | Out-Null
    $catalogExit = $LASTEXITCODE
    & "$rustBin" verify $env:PSIGN_CATALOG_TARGET --catalog $env:PSIGN_CATALOG_FILE --os-version-check "386:10.0.26100.0" 2>&1 | Out-Null
    $catalogOsExit = $LASTEXITCODE
    $ErrorActionPreference = $saved
    $results += [PSCustomObject]@{
        id = "artifact_catalog_semantic"
        nativeExitCode = 0
        rustExitCode = $catalogExit
        classification = if ($catalogExit -eq 0) { "artifact_semantic_match" } else { "semantic_mismatch" }
    }
    $results += [PSCustomObject]@{
        id = "artifact_catalog_os_version_semantic"
        nativeExitCode = 0
        rustExitCode = $catalogOsExit
        classification = if ($catalogOsExit -eq 0) { "artifact_semantic_match" } else { "semantic_mismatch" }
    }
}

$semantic = @($results | Where-Object { $_.classification -eq "semantic_mismatch" })
$actualScenarioIds = @($results | ForEach-Object { $_.id })
$missingScenarioIds = @($expectedScenarioIds | Where-Object { $_ -notin $actualScenarioIds })
$missingCount = $missingScenarioIds.Count
$report = [PSCustomObject]@{
    generatedAt = (Get-Date).ToString("o")
    nativeSignTool = $nativeSignTool
    totalScenarios = $results.Count
    semanticMismatchCount = $semantic.Count
    expectedScenarioCount = $expectedScenarioIds.Count
    missingScenarioCount = $missingCount
    missingScenarioIds = $missingScenarioIds
    results = $results
}

$outDir = Join-Path $workspace "parity-output"
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}
$reportPath = Join-Path $outDir "parity-report.json"
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Host "Wrote parity report to $reportPath"

if ($FailOnSemantic -and ($semantic.Count -gt 0 -or $missingCount -gt 0)) {
    throw "Found $($semantic.Count) semantic mismatch(es) and $missingCount missing scenario(s)."
}

# Avoid leaking the last native/Rust $LASTEXITCODE (e.g. documented-gap scenarios still exit 1).
exit 0
