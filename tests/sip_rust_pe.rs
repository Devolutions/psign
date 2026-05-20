#![cfg(windows)]

//! Integration-style checks for experimental Rust SIP PE digest logic.

#[test]
fn upstream_signed_tiny32_digest_consistency() {
    let bytes = include_bytes!("fixtures/pe-authenticode-upstream/tiny32.signed.efi");
    psign::win::sip_rust::verify_pe::verify_pe_authenticode_digest_consistency(bytes)
        .expect("tiny32.signed.efi digest should match PKCS#7 indirect digest");
}

#[test]
fn upstream_signed_tiny64_digest_consistency() {
    let bytes = include_bytes!("fixtures/pe-authenticode-upstream/tiny64.signed.efi");
    psign::win::sip_rust::verify_pe::verify_pe_authenticode_digest_consistency(bytes)
        .expect("tiny64.signed.efi digest should match PKCS#7 indirect digest");
}

#[test]
#[ignore = "set PSIGN_SIGNED_FIXTURE to a WinTrust-verifiable signed PE"]
fn signed_fixture_digest_check_after_trust() {
    let path = std::env::var_os("PSIGN_SIGNED_FIXTURE")
        .expect("PSIGN_SIGNED_FIXTURE must be set when running this ignored test");
    let path = std::path::Path::new(&path);
    let mut verify = assert_cmd::Command::cargo_bin("psign-tool").expect("binary");
    verify.args([
        "verify",
        "--policy",
        "pa",
        "--rust-sip-pe-digest-check",
        "--verbose",
    ]);
    verify.arg(path);
    verify.assert().success();
}
