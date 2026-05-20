param(
    [switch]$RunNativeParity,
    [string[]]$RunParityArgs = @("-FailOnSemantic")
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot
try {
    cargo build --locked --features timestamp-server,timestamp-http --bins

    $tests = @(
        "psign_server_pki_server_serves_certificates_for_non_admin_tests",
        "psign_server_pki_server_serves_signed_crls",
        "unified_verify_mode_portable_accepts_trusted_ca_without_os_store",
        "portable_trust_verify_detached_uses_pki_server_crl_without_admin_trust_store",
        "portable_trust_verify_detached_uses_pki_server_ocsp_without_admin_trust_store",
        "portable_trust_verify_detached_requires_trusted_rfc3161_timestamp_without_admin_trust_store"
    )

    foreach ($test in $tests) {
        cargo test -p psign --test cli_pe_digest --features timestamp-server,timestamp-http --locked $test
    }

    if ($RunNativeParity) {
        & (Join-Path $repoRoot "scripts\run-parity-diff.ps1") @RunParityArgs
    }
}
finally {
    Pop-Location
}
