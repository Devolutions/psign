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
fn publisher_id_format_prints_only_the_id() {
    for (input, path) in [
        ("cert", "artifact-signing/devolutions-signer.pem"),
        ("pkcs7", "artifact-signing/psign-tool.pkcs7.der"),
    ] {
        psign()
            .args([
                "portable",
                "artifact-signing-publisher-id",
                "--format",
                "publisher-id",
                "--input",
                input,
            ])
            .arg(fixture(path))
            .assert()
            .success()
            .stdout(format!("{PUBLISHER_ID}\n"));
    }
    psign()
        .args([
            "portable",
            "artifact-signing-publisher-id",
            "--format",
            "publisher-id",
        ])
        .arg(fixture("pe-authenticode-upstream/tiny64.signed.efi"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no Azure Artifact Signing identity EKU",
        ));
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

const PRIVATE_TRUST_ID: &str = "11.22.33.44.55.66.77.88";
const PRIVATE_TRUST_FILES: [&str; 4] = ["sample.js", "sample.msix", "sample.nupkg", "sample.vsix"];

fn private_trust_args(cmd: &mut Command, publisher_id: &str) {
    cmd.args(["--artifact-signing-publisher-id", publisher_id])
        .arg("--artifact-signing-private-trust-root")
        .arg(fixture("artifact-signing/private-trust/root.cer"))
        .arg("--artifact-signing-allow-missing-timestamp");
}

/// Synthetic Private Trust signer (see scripts/ci/build-artifact-signing-private-trust-fixtures.ps1).
#[test]
fn private_trust_script_msix_nuget_vsix_verify_in_portable_mode() {
    for file in PRIVATE_TRUST_FILES {
        let mut cmd = psign();
        cmd.args(["--mode", "portable", "verify"]);
        private_trust_args(&mut cmd, PRIVATE_TRUST_ID);
        cmd.arg(fixture(&format!("artifact-signing/private-trust/{file}")))
            .assert()
            .success()
            .stdout(predicate::str::contains(format!(
                "publisher_id={PRIVATE_TRUST_ID} kind=private_trust"
            )));

        let mut cmd = psign();
        cmd.args(["--mode", "portable", "verify"]);
        private_trust_args(&mut cmd, "1.2.3.4");
        cmd.arg(fixture(&format!("artifact-signing/private-trust/{file}")))
            .assert()
            .failure()
            .stderr(predicate::str::contains("is not one of the expected IDs"));
    }
}

#[test]
fn private_trust_requires_the_subscriber_root() {
    psign()
        .args([
            "--mode",
            "portable",
            "verify",
            "--artifact-signing-allow-missing-timestamp",
        ])
        .arg(fixture("artifact-signing/private-trust/sample.vsix"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires the subscriber root"));
}

/// NuGet / VSIX have no Windows SIP, so Windows mode applies the shared check alone.
#[cfg(windows)]
#[test]
fn package_formats_verify_in_windows_mode() {
    for file in ["sample.nupkg", "sample.vsix"] {
        let mut cmd = psign();
        cmd.args(["--mode", "windows", "verify"]);
        private_trust_args(&mut cmd, PRIVATE_TRUST_ID);
        cmd.arg(fixture(&format!("artifact-signing/private-trust/{file}")))
            .assert()
            .success()
            .stdout(predicate::str::contains("kind=private_trust"));
    }
}

const TEST_CA: &str = "devolutions-authenticode/authenticode-test-ca.crt";

#[test]
fn portable_trust_verify_commands_cover_scripts_msix_nuget_vsix() {
    for (command, file) in [
        (
            "trust-verify-script",
            "generated-signed/scripts/wsh/js/utf8-crlf.js",
        ),
        (
            "trust-verify-script",
            "generated-signed/scripts/wsh/vbs/utf8-crlf.vbs",
        ),
        ("trust-verify-msix", "generated-signed/msix/sample.msix"),
        (
            "trust-verify-nupkg",
            "package-signing/signed/sample.signed.nupkg",
        ),
        (
            "trust-verify-vsix",
            "package-signing/signed/sample.signed.vsix",
        ),
    ] {
        psign()
            .args(["portable", command, "--as-of", "2026-06-01", "--trusted-ca"])
            .arg(fixture(TEST_CA))
            .arg(fixture(file))
            .assert()
            .success()
            .stdout(predicate::str::contains(format!("{command}: ok")));
    }
}

#[test]
fn portable_verify_routes_explicit_trust_for_new_formats() {
    for file in [
        "generated-signed/scripts/wsh/wsf/utf8-crlf.wsf",
        "generated-signed/msix/sample.appx",
        "package-signing/signed/sample.signed.snupkg",
        "package-signing/signed/nested.signed.vsix",
    ] {
        psign()
            .args([
                "--mode",
                "portable",
                "verify",
                "--as-of",
                "2026-06-01",
                "--trusted-ca",
            ])
            .arg(fixture(TEST_CA))
            .arg(fixture(file))
            .assert()
            .success();
    }
}
