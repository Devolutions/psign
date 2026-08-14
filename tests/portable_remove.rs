use assert_cmd::Command;
use predicates::prelude::*;
use psign_sip_digest::pe_embed;
use std::path::Path;

fn portable_remove(path: &Path) -> Command {
    let mut command = Command::cargo_bin("psign-tool").expect("psign-tool binary");
    command
        .args(["--mode", "portable", "remove", "--strip-signature"])
        .arg(path);
    command
}

#[test]
fn mode_portable_remove_strips_powershell_signature_block() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("module.psd1");
    std::fs::write(
        &path,
        "@{ RootModule = 'module.psm1' }\r\n# SIG # Begin signature block\r\n# YWJj\r\n# SIG # End signature block\r\n",
    )
    .expect("write signed script");

    portable_remove(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Removed embedded Authenticode data",
        ));

    assert_eq!(
        std::fs::read_to_string(&path).expect("read unsigned script"),
        "@{ RootModule = 'module.psm1' }"
    );
}

#[test]
fn mode_portable_remove_strips_pe_signature() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("signed.exe");
    let unsigned = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/generated-unsigned/pe/tiny32-pe-alias.exe"),
    )
    .expect("read unsigned PE fixture");
    let signed = pe_embed::pe_append_authenticode_pkcs7_certificate(unsigned.clone(), &[1, 2, 3])
        .expect("add certificate table row");
    std::fs::write(&path, signed).expect("write PE with certificate table row");

    portable_remove(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Removed embedded Authenticode data",
        ));

    let removed = std::fs::read(&path).expect("read unsigned PE");
    let (_, remaining) = pe_embed::pe_remove_authenticode_certificates(removed)
        .expect("inspect PE certificate table");
    assert_eq!(remaining, 0);
}

#[test]
fn mode_portable_remove_rejects_partial_cms_mutation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("module.ps1");
    std::fs::write(&path, "Write-Output test").expect("write script");

    let mut command = Command::cargo_bin("psign-tool").expect("psign-tool binary");
    command
        .args([
            "--mode",
            "portable",
            "remove",
            "--strip-chain-except-signer",
        ])
        .arg(&path);
    command.assert().failure().stderr(predicate::str::contains(
        "portable remove supports only --strip-signature",
    ));
}
