//! Azure Artifact Signing CLI surface: publisher ID extraction and `verify --artifact-signing…`
//! parity between `--mode windows` and `--mode portable`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

const PUBLISHER_ID: &str = "285218949.549339218.252840042.443064405";

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn psign() -> Command {
    let mut cmd = Command::cargo_bin("psign-tool").expect("psign-tool binary");
    cmd.env("PSIGN_NO_AUTO_TRUST", "1");
    cmd
}

/// Tool modes available on this host; Windows mode needs WinVerifyTrust.
fn modes() -> &'static [&'static str] {
    if cfg!(windows) {
        &["windows", "portable"]
    } else {
        &["portable"]
    }
}

#[test]
fn publisher_id_from_certificate_and_pkcs7() {
    for (input, path) in [
        ("cert", "artifact-signing/devolutions-signer.pem"),
        ("pkcs7", "artifact-signing/psign-tool.pkcs7.der"),
    ] {
        psign()
            .args([
                "portable",
                "artifact-signing-publisher-id",
                "--input",
                input,
            ])
            .arg(fixture(path))
            .assert()
            .success()
            .stdout(predicate::str::contains(format!(
                "\"publisher_id\": \"{PUBLISHER_ID}\""
            )))
            .stdout(predicate::str::contains("\"kind\": \"public_trust\""));
    }
}

#[test]
fn publisher_id_is_null_for_non_artifact_signing_signer() {
    psign()
        .args(["portable", "artifact-signing-publisher-id"])
        .arg(fixture("pe-authenticode-upstream/tiny64.signed.efi"))
        .assert()
        .success()
        .stdout(predicate::str::contains("\"identity\": null"));
}

#[test]
fn verify_rejects_non_artifact_signing_signer_in_every_mode() {
    for mode in modes() {
        psign()
            .args(["--mode", mode, "verify", "--artifact-signing"])
            .arg(fixture("pe-authenticode-upstream/tiny64.signed.efi"))
            .assert()
            .failure();
    }
    psign()
        .args(["--mode", "portable", "verify", "--artifact-signing"])
        .arg(fixture("pe-authenticode-upstream/tiny64.signed.efi"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no Artifact Signing identity EKU"));
}

#[test]
fn verify_rejects_generic_anchors_with_artifact_signing_in_every_mode() {
    for mode in modes() {
        psign()
            .args(["--mode", mode, "verify", "--artifact-signing-publisher-id"])
            .arg(PUBLISHER_ID)
            .arg("--trusted-ca")
            .arg(fixture("artifact-signing/devolutions-signer.pem"))
            .arg(fixture("pe-authenticode-upstream/tiny64.signed.efi"))
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "--trusted-ca cannot be combined with --artifact-signing",
            ));
    }
}

#[test]
fn portable_trust_verify_rejects_generic_anchors_with_artifact_signing() {
    psign()
        .args([
            "portable",
            "trust-verify-pe",
            "--artifact-signing",
            "--anchor-dir",
        ])
        .arg(fixture("artifact-signing"))
        .arg(fixture("pe-authenticode-upstream/tiny64.signed.efi"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--anchor-dir cannot be combined with --artifact-signing",
        ));
}

/// Real Artifact Signing PE (too large to commit): set `PSIGN_ARTIFACT_SIGNING_SAMPLE` to a PE
/// signed with publisher ID [`PUBLISHER_ID`] (or override with
/// `PSIGN_ARTIFACT_SIGNING_SAMPLE_PUBLISHER_ID`).
#[test]
#[ignore = "requires PSIGN_ARTIFACT_SIGNING_SAMPLE"]
fn verify_real_sample_identically_in_every_mode() {
    let sample = PathBuf::from(
        std::env::var("PSIGN_ARTIFACT_SIGNING_SAMPLE").expect("PSIGN_ARTIFACT_SIGNING_SAMPLE"),
    );
    let publisher_id = std::env::var("PSIGN_ARTIFACT_SIGNING_SAMPLE_PUBLISHER_ID")
        .unwrap_or_else(|_| PUBLISHER_ID.to_string());
    for mode in modes() {
        psign()
            .args(["--mode", mode, "verify", "--artifact-signing-publisher-id"])
            .arg(&publisher_id)
            .arg(&sample)
            .assert()
            .success()
            .stdout(predicate::str::contains(format!(
                "publisher_id={publisher_id}"
            )))
            .stdout(predicate::str::contains(
                "root=f40042e2e5f7e8ef8189fed15519aece42c3bfa2",
            ));
        psign()
            .args([
                "--mode",
                mode,
                "verify",
                "--artifact-signing-publisher-id",
                "1.2.3.4",
            ])
            .arg(&sample)
            .assert()
            .failure()
            .stderr(predicate::str::contains("is not one of the expected IDs"));
    }
}
