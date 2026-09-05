use assert_cmd::Command;
use predicates::prelude::*;
use psign_opc_sign::nuget;
use psign_sip_digest::{pkcs7, verify_pe};
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::signature::Keypair;
use serde_json::Value;
use sha2::Sha256;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::{Encode, asn1::OctetString};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

fn psign() -> Command {
    Command::cargo_bin("psign-tool").unwrap()
}

#[test]
fn help_lists_code_orchestrator_command() {
    let mut cmd = psign();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("code"));
}

#[test]
fn code_dry_run_file_list_applies_globs_braces_ranges_and_negation() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write_file(&base.join("lib/net8.0/a1.dll"), b"pe");
    write_file(&base.join("lib/net8.0/a2.dll"), b"pe");
    write_file(&base.join("lib/net7.0/a1.dll"), b"pe");
    write_file(&base.join("tools/readme.txt"), b"text");
    let file_list = base.join("files.txt");
    std::fs::write(&file_list, "lib/net{7..8}.0/a?.dll\n!lib/net8.0/a2.dll\n").unwrap();

    let mut cmd = psign();
    let assert = cmd
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(base)
        .args(["--file-list"])
        .arg("files.txt")
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let paths = plan_paths(&json);
    assert_eq!(paths, ["lib/net7.0/a1.dll", "lib/net8.0/a1.dll"]);
}

#[test]
fn code_dry_run_recurses_nested_vsix_and_nupkg_inside_out() {
    let repo = repo_root();
    let input = "tests/fixtures/package-signing/unsigned/deep-nested.vsix";

    let mut cmd = psign();
    let assert = cmd
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(&repo)
        .arg(input)
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let paths = plan_paths(&json);
    assert!(
        paths
            .iter()
            .any(|path| path == "tests/fixtures/package-signing/unsigned/deep-nested.vsix")
    );
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("!packages/with-pe.nupkg"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("!packages/with-pe.nupkg!lib/net8.0/tiny32.dll"))
    );

    let edges = json["edges"].as_array().expect("edges");
    assert!(
        !edges.is_empty(),
        "inside-out graph should order nested entries before containers"
    );
}

#[test]
fn code_dry_run_applies_exclude_filters_inside_containers() {
    let repo = repo_root();
    let input = "tests/fixtures/package-signing/unsigned/deep-nested.vsix";
    let file_list = repo.join("target/psign-code-nested-exclude.txt");
    std::fs::write(&file_list, format!("{input}\n!**/*.dll\n")).unwrap();

    let mut cmd = psign();
    let assert = cmd
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(&repo)
        .args(["--file-list"])
        .arg(&file_list)
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let paths = plan_paths(&json);
    assert!(
        paths
            .iter()
            .any(|path| path.ends_with("!packages/with-pe.nupkg"))
    );
    assert!(
        !paths
            .iter()
            .any(|path| path.ends_with("!packages/with-pe.nupkg!lib/net8.0/tiny32.dll")),
        "nested DLL should be excluded by file-list rule"
    );
}

#[test]
fn code_without_dry_run_fails_safely() {
    let mut cmd = psign();
    cmd.args([
        "code",
        "tests/fixtures/package-signing/unsigned/sample.nupkg",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("requires exactly one signer"));
}

#[test]
fn code_signs_top_level_nupkg_with_local_cert_key() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let output = temp.path().join("signed.nupkg");
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/package-signing/unsigned/sample.nupkg");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "signed tests/fixtures/package-signing/unsigned/sample.nupkg",
        ))
        .stdout(predicate::str::contains(".signature.p7s"));

    let mut info = psign();
    info.args(["portable", "nupkg-signature-info"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"))
        .stdout(predicate::str::contains("signature_stored=yes"));

    assert_nupkg_signature_has_nuget_author_attrs(&output);
}

#[test]
fn code_signs_nupkg_with_portable_cert_store_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let store = base.join("cert-store");
    let cert = base.join("signer.der");
    let key_der = base.join("signer.pkcs8");
    let key_pem = base.join("signer.pem");
    let input = base.join("sample.nupkg");
    let output = base.join("signed-store.nupkg");
    write_test_rsa_cert_key_and_pem(&cert, &key_der, &key_pem);
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
        &input,
    )
    .unwrap();

    let import = psign()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store)
        .arg("--key")
        .arg(&key_pem)
        .arg(&cert)
        .output()
        .expect("import cert-store identity");
    assert!(
        import.status.success(),
        "cert-store import failed: {}",
        String::from_utf8_lossy(&import.stderr)
    );
    let import_stdout = String::from_utf8(import.stdout).unwrap();
    let thumbprint = import_stdout
        .lines()
        .find_map(|line| line.strip_prefix("thumbprint_sha1="))
        .expect("import reports thumbprint");

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .arg("--cert-store-dir")
        .arg(&store)
        .args(["--sha1", thumbprint, "--output"])
        .arg(&output)
        .arg("sample.nupkg");
    cmd.assert().success();

    let mut info = psign();
    info.args(["portable", "nupkg-signature-info"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"))
        .stdout(predicate::str::contains("signature_stored=yes"));

    assert_nupkg_signature_has_nuget_author_attrs(&output);
}

#[test]
fn code_signs_nupkg_with_pfx_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let pfx = base.join("signer.pfx");
    let input = base.join("sample.nupkg");
    let output = base.join("signed-pfx.nupkg");
    write_test_rsa_pfx(&pfx, "secret");
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
        &input,
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .arg("--pfx")
        .arg(&pfx)
        .args(["--password", "secret", "--output"])
        .arg(&output)
        .arg("sample.nupkg");
    cmd.assert().success();

    let mut info = psign();
    info.args(["portable", "nupkg-signature-info"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"))
        .stdout(predicate::str::contains("signature_stored=yes"));
}

#[cfg(all(feature = "timestamp-server", feature = "azure-kv-sign"))]
#[test]
fn code_signs_nupkg_with_azure_key_vault_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("sample.nupkg");
    let output = base.join("signed-kv.nupkg");
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
        &input,
    )
    .unwrap();

    let (mut guard, url, certificate) = spawn_azure_key_vault_server(2);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .arg("--azure-key-vault-url")
        .arg(&url)
        .arg("--azure-key-vault-certificate")
        .arg(&certificate)
        .args(["--azure-key-vault-accesstoken", "test-token", "--output"])
        .arg(&output)
        .arg("sample.nupkg");
    cmd.assert().success();
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut info = psign();
    info.args(["portable", "nupkg-signature-info"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"))
        .stdout(predicate::str::contains("signature_stored=yes"));
}

#[cfg(all(feature = "timestamp-server", feature = "artifact-signing-rest"))]
#[test]
fn code_signs_nupkg_with_artifact_signing_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("sample.nupkg");
    let output = base.join("signed-artifact.nupkg");
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
        &input,
    )
    .unwrap();

    let (mut guard, endpoint) = spawn_artifact_signing_server(4);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .arg("--artifact-signing-endpoint")
        .arg(&endpoint)
        .args([
            "--artifact-signing-account-name",
            "acct",
            "--artifact-signing-profile-name",
            "profile",
            "--artifact-signing-access-token",
            "test-token",
            "--output",
        ])
        .arg(&output)
        .arg("sample.nupkg");
    cmd.assert().success();
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut info = psign();
    info.args(["portable", "nupkg-signature-info"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"))
        .stdout(predicate::str::contains("signature_stored=yes"));
}

#[test]
fn code_signs_top_level_pe_with_local_cert_key() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe");
    let output = base.join("app.signed.exe");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
        &input,
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("app.exe");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Authenticode PE/WinMD"));

    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&output)
        .assert()
        .success();
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn code_signs_top_level_pe_with_rfc3161_timestamp() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe");
    let output = base.join("app.timestamped.exe");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
        &input,
    )
    .unwrap();
    let (mut guard, timestamp_url) = spawn_timestamp_server();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--timestamp-url",
            &timestamp_url,
            "--timestamp-digest",
            "sha256",
            "--output",
        ])
        .arg(&output)
        .arg("app.exe");
    cmd.assert().success();
    let status = guard.0.wait().expect("timestamp server exit");
    assert!(status.success(), "timestamp server failed with {status}");

    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&output)
        .assert()
        .success();

    let pkcs7_der =
        verify_pe::pe_nth_pkcs7_signed_data_der(&std::fs::read(&output).unwrap(), 0).unwrap();
    assert_pkcs7_has_unsigned_attr(
        &pkcs7_der,
        pkcs7::MS_RFC3161_TIMESTAMP_TOKEN_OID,
        pkcs7::PKCS9_RFC3161_TIMESTAMP_TOKEN_OID,
    );
}

#[cfg(all(feature = "timestamp-server", feature = "azure-kv-sign"))]
#[test]
fn code_signs_pe_with_azure_key_vault_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe");
    let output = base.join("app.signed-kv.exe");
    std::fs::copy(
        repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
        &input,
    )
    .unwrap();

    let (mut guard, url, certificate) = spawn_azure_key_vault_server(2);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .arg("--azure-key-vault-url")
        .arg(&url)
        .arg("--azure-key-vault-certificate")
        .arg(&certificate)
        .args(["--azure-key-vault-accesstoken", "test-token", "--output"])
        .arg(&output)
        .arg("app.exe");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Authenticode PE/WinMD"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&output)
        .assert()
        .success();
}

#[cfg(all(feature = "timestamp-server", feature = "artifact-signing-rest"))]
#[test]
fn code_signs_pe_with_artifact_signing_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe");
    let output = base.join("app.signed-artifact.exe");
    std::fs::copy(
        repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
        &input,
    )
    .unwrap();

    let (mut guard, endpoint) = spawn_artifact_signing_server(2);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .arg("--artifact-signing-endpoint")
        .arg(&endpoint)
        .args([
            "--artifact-signing-account-name",
            "acct",
            "--artifact-signing-profile-name",
            "profile",
            "--artifact-signing-access-token",
            "test-token",
            "--output",
        ])
        .arg(&output)
        .arg("app.exe");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Authenticode PE/WinMD"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&output)
        .assert()
        .success();
}

#[test]
fn code_skip_signed_copies_already_signed_pe() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe");
    let signed = base.join("app.initially-signed.exe");
    let output = base.join("app.skipped.exe");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
        &input,
    )
    .unwrap();

    let mut first = psign();
    first
        .args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&signed)
        .arg("app.exe");
    first.assert().success();

    let mut skip = psign();
    skip.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--skip-signed",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("app.initially-signed.exe");
    skip.assert()
        .success()
        .stdout(predicate::str::contains("skipped"))
        .stdout(predicate::str::contains("already signed"));

    assert_eq!(
        std::fs::read(&signed).unwrap(),
        std::fs::read(&output).unwrap()
    );
}

#[test]
fn code_signing_replaces_existing_pe_signature_by_default() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.signed.exe");
    let output = base.join("app.resigned.exe");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi"),
        &input,
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("app.signed.exe");
    cmd.assert().success();

    let resigned = std::fs::read(&output).unwrap();
    verify_pe::verify_pe_authenticode_digest_consistency(&resigned)
        .expect("resigned PE digest consistency");
    assert_eq!(
        verify_pe::pe_pkcs7_signed_data_entry_count(&resigned).expect("resigned PE entry count"),
        1
    );
}

#[test]
fn code_skip_signed_copies_already_signed_nupkg() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let output = temp.path().join("already-signed.nupkg");
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--skip-signed",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/package-signing/signed/sample.signed.nupkg");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("skipped"))
        .stdout(predicate::str::contains("already signed"));

    let mut info = psign();
    info.args(["portable", "nupkg-signature-info"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"));
}

#[test]
fn code_overwrite_resigns_already_signed_nupkg() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let output = temp.path().join("resigned.nupkg");
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--overwrite",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/package-signing/signed/sample.signed.nupkg");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "signed tests/fixtures/package-signing/signed/sample.signed.nupkg",
        ))
        .stdout(predicate::str::contains(".signature.p7s"));

    let mut verify = psign();
    verify
        .args(["portable", "nupkg-verify-signature"])
        .arg(&output)
        .args(["--trusted-ca"])
        .arg(&cert)
        .args(["--allow-loose-signing-cert"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nupkg-verify-signature: ok"));
}

#[test]
fn code_signs_appinstaller_companion_with_local_cert_key() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let output = temp.path().join("sample.appinstaller.p7");
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("detached PKCS#7 companion"));

    let mut verify = psign();
    verify
        .args([
            "portable",
            "appinstaller-verify-companion",
            "tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller",
            "--signature",
        ])
        .arg(&output)
        .args(["--trusted-ca"])
        .arg(&cert)
        .args(["--allow-loose-signing-cert"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "appinstaller-verify-companion: ok",
        ));
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn code_signs_appinstaller_companion_with_authenticode_timestamp() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let output = temp.path().join("sample.appinstaller.p7");
    write_test_rsa_cert_key(&cert, &key);
    let (mut guard, timestamp_url) = spawn_timestamp_server();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--timestamp-url",
            &timestamp_url,
            "--timestamp-digest",
            "sha256",
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller");
    cmd.assert().success();
    let status = guard.0.wait().expect("timestamp server exit");
    assert!(status.success(), "timestamp server failed with {status}");

    let signature_der = std::fs::read(&output).expect("read App Installer companion signature");
    assert_pkcs7_has_unsigned_attr(
        &signature_der,
        pkcs7::MS_RFC3161_TIMESTAMP_TOKEN_OID,
        pkcs7::PKCS9_RFC3161_TIMESTAMP_TOKEN_OID,
    );
}

#[test]
fn code_updates_appinstaller_publisher_before_signing_companion() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let descriptor = temp.path().join("updated.appinstaller");
    let signature = temp.path().join("updated.appinstaller.p7");
    let publisher = "CN=Updated App Installer Publisher, O=Example & Co";
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--publisher-name",
            publisher,
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&signature)
        .arg("tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("updated descriptor"))
        .stdout(predicate::str::contains("detached PKCS#7 companion"));

    let mut info = psign();
    info.args(["portable", "appinstaller-info"])
        .arg(&descriptor)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "publisher=CN=Updated App Installer Publisher, O=Example &amp; Co",
        ));

    let mut verify = psign();
    verify
        .args(["portable", "appinstaller-verify-companion"])
        .arg(&descriptor)
        .args(["--signature"])
        .arg(&signature)
        .args(["--trusted-ca"])
        .arg(&cert)
        .args(["--allow-loose-signing-cert"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "appinstaller-verify-companion: ok",
        ));
}

#[test]
fn code_updates_prefixed_appinstaller_main_bundle_before_signing() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("prefixed.appinstaller");
    let descriptor = base.join("prefixed.signed.appinstaller");
    let signature = base.join("prefixed.signed.appinstaller.p7");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::write(
        &input,
        r#"<AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2021" xmlns:pkg="urn:example" Version="1.0.0.0" Uri="https://example.invalid/app.appinstaller"><pkg:MainBundle Name="Example.Bundle" Publisher="CN=Old" Version="1.0.0.0" Uri="https://example.invalid/app.msixbundle"/></AppInstaller>"#,
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--publisher-name",
            "CN=Updated Bundle Publisher",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&signature)
        .arg("prefixed.appinstaller");
    cmd.assert().success();

    let xml = std::fs::read_to_string(&descriptor).unwrap();
    assert!(xml.contains(r#"<pkg:MainBundle"#));
    assert!(xml.contains(r#"Publisher="CN=Updated Bundle Publisher""#));

    let mut verify = psign();
    verify
        .args(["portable", "appinstaller-verify-companion"])
        .arg(&descriptor)
        .args(["--signature"])
        .arg(&signature)
        .args(["--trusted-ca"])
        .arg(&cert)
        .args(["--allow-loose-signing-cert"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "appinstaller-verify-companion: ok",
        ));
}

#[cfg(all(feature = "timestamp-server", feature = "azure-kv-sign"))]
#[test]
fn code_signs_appinstaller_with_azure_key_vault_identity() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("sample.appinstaller.p7");

    let (mut guard, url, certificate) = spawn_azure_key_vault_server(2);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .arg("--azure-key-vault-url")
        .arg(&url)
        .arg("--azure-key-vault-certificate")
        .arg(&certificate)
        .args(["--azure-key-vault-accesstoken", "test-token", "--output"])
        .arg(&output)
        .arg("tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("detached PKCS#7 companion"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    assert!(output.exists(), "companion .p7 not created");
}

#[test]
fn code_signs_nested_appinstaller_inside_generic_zip() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("bundle.zip");
    let output = base.join("signed-bundle.zip");
    let descriptor = base.join("nested.appinstaller");
    let signature = base.join("nested.appinstaller.p7");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &input,
        &[
            ("readme.txt", b"App Installer bundle".as_slice()),
            (
                "descriptors/app.appinstaller",
                br#"<AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2021" Version="1.0.0.0" Uri="https://example.invalid/app.appinstaller"><MainPackage Name="Example.App" Publisher="CN=Old" Version="1.0.0.0" ProcessorArchitecture="x64" Uri="https://example.invalid/app.msix"/></AppInstaller>"#.as_slice(),
            ),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--publisher-name",
            "CN=Nested App Installer Publisher",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("bundle.zip");
    cmd.assert().success();

    extract_zip_entry(&output, "descriptors/app.appinstaller", &descriptor);
    extract_zip_entry(&output, "descriptors/app.appinstaller.p7", &signature);
    let mut verify = psign();
    verify
        .args(["portable", "appinstaller-verify-companion"])
        .arg(&descriptor)
        .args(["--signature"])
        .arg(&signature)
        .args(["--trusted-ca"])
        .arg(&cert)
        .args(["--allow-loose-signing-cert"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "appinstaller-verify-companion: ok",
        ));
}

#[test]
fn code_signs_clickonce_deploy_pe_payload_with_local_cert_key() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe.deploy");
    let output = base.join("app.signed.exe.deploy");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
        &input,
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("app.exe.deploy");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ClickOnce .deploy payload"));

    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&output)
        .assert()
        .success();
}

#[test]
fn code_signs_clickonce_manifest_with_local_cert_key() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe.manifest");
    let output = base.join("app.signed.exe.manifest");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::write(&input, sample_clickonce_manifest()).unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("app.exe.manifest");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ClickOnce manifest XMLDSig"));

    let mut verify = psign();
    verify
        .args(["portable", "clickonce-verify-manifest-signature"])
        .arg(&output)
        .arg("--trusted-ca")
        .arg(&cert)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "clickonce-verify-manifest-signature: ok",
        ))
        .stdout(predicate::str::contains("signer_trust_chain=yes"));
}

#[cfg(all(feature = "timestamp-server", feature = "azure-kv-sign"))]
#[test]
fn code_signs_clickonce_manifest_with_azure_key_vault_identity() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.exe.manifest");
    let output = base.join("app.signed.exe.manifest");
    std::fs::write(&input, sample_clickonce_manifest()).unwrap();

    let (mut guard, url, certificate) = spawn_azure_key_vault_server(2);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .arg("--azure-key-vault-url")
        .arg(&url)
        .arg("--azure-key-vault-certificate")
        .arg(&certificate)
        .args(["--azure-key-vault-accesstoken", "test-token", "--output"])
        .arg(&output)
        .arg("app.exe.manifest");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ClickOnce manifest XMLDSig"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut verify = psign();
    verify
        .args(["portable", "clickonce-verify-manifest-signature"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "clickonce-verify-manifest-signature: ok",
        ));
}

#[test]
fn code_signs_nested_clickonce_manifest_inside_generic_zip() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("bundle.zip");
    let output = base.join("signed.zip");
    let nested_manifest = base.join("nested.signed.manifest");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &input,
        &[
            ("readme.txt", b"ClickOnce manifest bundle".as_slice()),
            (
                "publish/app.exe.manifest",
                sample_clickonce_manifest().as_bytes(),
            ),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("bundle.zip");
    cmd.assert().success();

    extract_zip_entry(&output, "publish/app.exe.manifest", &nested_manifest);
    let mut verify = psign();
    verify
        .args(["portable", "clickonce-verify-manifest-signature"])
        .arg(&nested_manifest)
        .arg("--trusted-ca")
        .arg(&cert)
        .assert()
        .success()
        .stdout(predicate::str::contains("signature_value_match=yes"));
}

#[test]
fn code_rejects_clickonce_manifest_timestamping_explicitly() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("app.application");
    let output = base.join("app.signed.application");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::write(&input, sample_clickonce_manifest()).unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--timestamp-url",
            "http://127.0.0.1:9/tsa",
            "--timestamp-digest",
            "sha256",
            "--output",
        ])
        .arg(&output)
        .arg("app.application");
    cmd.assert().failure().stderr(predicate::str::contains(
        "ClickOnce manifest XMLDSig timestamping is not implemented",
    ));
}

#[test]
fn code_rejects_vsix_timestamping_explicitly() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("sample.vsix");
    let output = base.join("timestamped.vsix");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.vsix"),
        &input,
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--timestamp-url",
            "http://127.0.0.1:9/tsa",
            "--timestamp-digest",
            "sha256",
            "--output",
        ])
        .arg(&output)
        .arg("sample.vsix");
    cmd.assert().failure().stderr(predicate::str::contains(
        "VSIX XMLDSig timestamping is not implemented",
    ));
}

#[test]
fn code_prepares_msix_with_nested_pe_and_publisher_update() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("sample.msix");
    let output = base.join("prepared.msix");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_pe = base.join("app.signed.exe");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &input,
        &[
            (
                "[Content_Types].xml",
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="exe" ContentType="application/octet-stream"/><Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/><Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/></Types>"#
                    .as_slice(),
            ),
            (
                "AppxManifest.xml",
                br#"<Package><Identity Name="Psign.Test" Publisher="CN=Old" Version="1.0.0.0" ProcessorArchitecture="x86"/></Package>"#
                    .as_slice(),
            ),
            (
                "AppxBlockMap.xml",
                br#"<BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"/>"#
                    .as_slice(),
            ),
            (
                "app.exe",
                &std::fs::read(
                    repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
                )
                .unwrap(),
            ),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--publisher-name",
            "CN=Updated Publisher, O=Example & Co",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("sample.msix");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("unsigned MSIX/AppX"));

    let mut info = psign();
    info.args(["portable", "msix-manifest-info"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "publisher=CN=Updated Publisher, O=Example &amp; Co",
        ));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut pe = Vec::new();
    archive
        .by_name("app.exe")
        .unwrap()
        .read_to_end(&mut pe)
        .unwrap();
    std::fs::write(&nested_pe, pe).unwrap();

    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&nested_pe)
        .assert()
        .success();

    let mut block_map = String::new();
    archive
        .by_name("AppxBlockMap.xml")
        .unwrap()
        .read_to_string(&mut block_map)
        .unwrap();
    assert!(block_map.contains("app.exe"));
    assert!(block_map.contains("AppxManifest.xml"));
}

#[test]
fn code_prepares_msixupload_nested_package_with_publisher_update() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let inner = base.join("inner.msix");
    let input = base.join("sample.msixupload");
    let output = base.join("prepared.msixupload");
    let extracted = base.join("prepared-inner.msix");
    let nested_pe = base.join("app.signed.exe");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &inner,
        &[
            (
                "[Content_Types].xml",
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="exe" ContentType="application/octet-stream"/><Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/><Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/></Types>"#
                    .as_slice(),
            ),
            (
                "AppxManifest.xml",
                br#"<Package><Identity Name="Psign.Test" Publisher="CN=Old" Version="1.0.0.0" ProcessorArchitecture="x86"/></Package>"#
                    .as_slice(),
            ),
            (
                "AppxBlockMap.xml",
                br#"<BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"/>"#
                    .as_slice(),
            ),
            (
                "app.exe",
                &std::fs::read(
                    repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
                )
                .unwrap(),
            ),
        ],
    );
    write_zip(
        &input,
        &[
            ("metadata/readme.txt", b"upload container".as_slice()),
            ("packages/inner.msix", &std::fs::read(&inner).unwrap()),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--publisher-name",
            "CN=Updated Upload Publisher",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("sample.msixupload");
    cmd.assert().success();

    extract_zip_entry(&output, "packages/inner.msix", &extracted);
    let mut info = psign();
    info.args(["portable", "msix-manifest-info"])
        .arg(&extracted)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "publisher=CN=Updated Upload Publisher",
        ));
    extract_zip_entry(&extracted, "app.exe", &nested_pe);
    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&nested_pe)
        .assert()
        .success();
}

#[test]
fn code_prepares_msixbundle_with_bundle_manifest_publisher_update() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("bundle.msixbundle");
    let output = base.join("prepared.msixbundle");
    let extracted_child = base.join("prepared-inner.msix");
    let nested_pe = base.join("app.signed.exe");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);

    // A minimal flat child package with one nested PE payload.
    let inner = base.join("inner.msix");
    write_zip(
        &inner,
        &[
            (
                "[Content_Types].xml",
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="exe" ContentType="application/octet-stream"/><Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/><Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/></Types>"#
                    .as_slice(),
            ),
            (
                "AppxManifest.xml",
                br#"<Package><Identity Name="Psign.BundleChild" Publisher="CN=Old" Version="1.0.0.0" ProcessorArchitecture="x64"/></Package>"#
                    .as_slice(),
            ),
            (
                "AppxBlockMap.xml",
                br#"<BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"/>"#
                    .as_slice(),
            ),
            (
                "app.exe",
                &std::fs::read(
                    repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi"),
                )
                .unwrap(),
            ),
        ],
    );
    write_zip(
        &input,
        &[
            (
                "AppxMetadata/AppxBundleManifest.xml",
                br#"<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="5.0"><Identity Name="Psign.Bundle" Publisher="CN=Old" Version="1.0.0.0"/><Packages><Package Type="application" Version="1.0.0.0" Architecture="x64" FileName="inner.msix" Publisher="CN=Old"/></Packages></Bundle>"#
                    .as_slice(),
            ),
            (
                "AppxBlockMap.xml",
                br#"<BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"/>"#
                    .as_slice(),
            ),
            (
                "[Content_Types].xml",
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="msix" ContentType="application/vnd.ms-appx"/><Default Extension="xml" ContentType="application/vnd.ms-appx.bundlemanifest+xml"/><Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/></Types>"#
                    .as_slice(),
            ),
            ("inner.msix", &std::fs::read(&inner).unwrap()),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--publisher-name",
            "CN=Updated Bundle Publisher",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("bundle.msixbundle");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("unsigned MSIX/AppX"));

    // Publisher must propagate to both the bundle Identity and the child Package mirror,
    // and the block map must cover only the bundle manifest (AppxBundleSip semantics).
    let mut bundle_manifest = String::new();
    {
        let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
        archive
            .by_name("AppxMetadata/AppxBundleManifest.xml")
            .unwrap()
            .read_to_string(&mut bundle_manifest)
            .unwrap();
        let mut block_map = String::new();
        archive
            .by_name("AppxBlockMap.xml")
            .unwrap()
            .read_to_string(&mut block_map)
            .unwrap();
        assert!(
            block_map.contains(r#"Name="AppxMetadata\AppxBundleManifest.xml""#),
            "bundle block map must list the bundle manifest with backslash separators:\n{block_map}"
        );
        assert!(
            !block_map.contains("inner.msix"),
            "bundle block map must not list child packages:\n{block_map}"
        );
    }
    assert!(bundle_manifest.contains(r#"Publisher="CN=Updated Bundle Publisher""#));
    let identity_publishers = bundle_manifest
        .matches(r#"Publisher="CN=Updated Bundle Publisher""#)
        .count();
    assert_eq!(
        identity_publishers, 2,
        "Identity@Publisher and Package@Publisher must both be updated:\n{bundle_manifest}"
    );

    // The nested flat child gets the same publisher and its PE payload is signed.
    extract_zip_entry(&output, "inner.msix", &extracted_child);
    let mut info = psign();
    info.args(["portable", "msix-manifest-info"])
        .arg(&extracted_child)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "publisher=CN=Updated Bundle Publisher",
        ));
    extract_zip_entry(&extracted_child, "app.exe", &nested_pe);
    let mut verify = psign();
    verify
        .args(["portable", "verify-pe"])
        .arg(&nested_pe)
        .assert()
        .success();
}

#[test]
fn code_classifies_encrypted_msix_as_os_only_and_fails_explicitly() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let output = base.join("prepared.emsix");
    write_test_rsa_cert_key(&cert, &key);
    write_file(&base.join("encrypted.emsix"), b"encrypted-placeholder");

    let mut dry = psign();
    let assert = dry
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(base)
        .arg("encrypted.emsix")
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let node = json["nodes"].as_array().unwrap().first().unwrap();
    assert_eq!(node["format"].as_str().unwrap(), "encrypted-msix");
    assert_eq!(node["signer"].as_str().unwrap(), "msix-encrypted-os-only");

    let mut sign = psign();
    sign.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("encrypted.emsix");
    sign.assert()
        .failure()
        .stderr(predicate::str::contains("encrypted MSIX/AppX package"))
        .stderr(predicate::str::contains("Windows AppxSip OS delegation"));
}

#[test]
fn code_signs_top_level_vsix_with_local_cert_key() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let output = temp.path().join("signed.vsix");
    let signature_xml = temp.path().join("signature.xml");
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/package-signing/unsigned/sample.vsix");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("psign-signature.psdsxs"));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut xml = Vec::new();
    archive
        .by_name("package/services/digital-signature/xml-signature/psign-signature.psdsxs")
        .unwrap()
        .read_to_end(&mut xml)
        .unwrap();
    std::fs::write(&signature_xml, xml).unwrap();

    let mut verify = psign();
    verify
        .args([
            "portable",
            "vsix-verify-signature-xml",
            "tests/fixtures/package-signing/unsigned/sample.vsix",
            "--signature-xml",
        ])
        .arg(&signature_xml)
        .args(["--cert"])
        .arg(&cert)
        .assert()
        .success()
        .stdout(predicate::str::contains("signature_value_match=yes"));
}

#[cfg(all(feature = "timestamp-server", feature = "azure-kv-sign"))]
#[test]
fn code_signs_vsix_with_azure_key_vault_identity() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("signed-kv.vsix");

    let (mut guard, url, certificate) = spawn_azure_key_vault_server(2);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .arg("--azure-key-vault-url")
        .arg(&url)
        .arg("--azure-key-vault-certificate")
        .arg(&certificate)
        .args(["--azure-key-vault-accesstoken", "test-token", "--output"])
        .arg(&output)
        .arg("tests/fixtures/package-signing/unsigned/sample.vsix");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("psign-signature.psdsxs"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut verify = psign();
    verify
        .args(["portable", "vsix-verify-signature"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("vsix-verify-signature: ok"));
}

#[cfg(all(feature = "timestamp-server", feature = "artifact-signing-rest"))]
#[test]
fn code_signs_vsix_with_artifact_signing_identity() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("signed-artifact.vsix");

    let (mut guard, endpoint) = spawn_artifact_signing_server(2);
    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .arg("--artifact-signing-endpoint")
        .arg(&endpoint)
        .args([
            "--artifact-signing-account-name",
            "acct",
            "--artifact-signing-profile-name",
            "profile",
            "--artifact-signing-access-token",
            "test-token",
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/package-signing/unsigned/sample.vsix");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("psign-signature.psdsxs"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut verify = psign();
    verify
        .args(["portable", "vsix-verify-signature"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("vsix-verify-signature: ok"));
}

#[test]
fn code_overwrite_resigns_already_signed_vsix() {
    let repo = repo_root();
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("signer.der");
    let key = temp.path().join("signer.pkcs8");
    let output = temp.path().join("resigned.vsix");
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(&repo)
        .args([
            "--overwrite",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("tests/fixtures/package-signing/signed/sample.signed.vsix");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "signed tests/fixtures/package-signing/signed/sample.signed.vsix",
        ))
        .stdout(predicate::str::contains("psign-signature.psdsxs"));

    let mut verify = psign();
    verify
        .args(["portable", "vsix-verify-signature"])
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("vsix-verify-signature: ok"));
}

#[test]
fn code_signs_nested_nupkg_before_outer_vsix() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("nested.vsix");
    let output = base.join("signed.vsix");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_nupkg = base.join("nested-signed.nupkg");
    let signature_xml = base.join("signature.xml");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &input,
        &[
            ("extension.vsixmanifest", b"<PackageManifest/>".as_slice()),
            ("[Content_Types].xml", b"<Types/>".as_slice()),
            (
                "packages/sample.nupkg",
                &std::fs::read(
                    repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
                )
                .unwrap(),
            ),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("nested.vsix");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signed nested.vsix"));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut nested = Vec::new();
    archive
        .by_name("packages/sample.nupkg")
        .unwrap()
        .read_to_end(&mut nested)
        .unwrap();
    std::fs::write(&nested_nupkg, nested).unwrap();
    let mut xml = Vec::new();
    archive
        .by_name("package/services/digital-signature/xml-signature/psign-signature.psdsxs")
        .unwrap()
        .read_to_end(&mut xml)
        .unwrap();
    std::fs::write(&signature_xml, xml).unwrap();
    drop(archive);

    let mut nested_info = psign();
    nested_info
        .args(["portable", "nupkg-signature-info"])
        .arg(&nested_nupkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"));

    let mut verify_outer = psign();
    verify_outer
        .args(["portable", "vsix-verify-signature-xml"])
        .arg(&output)
        .args(["--signature-xml"])
        .arg(&signature_xml)
        .args(["--cert"])
        .arg(&cert)
        .assert()
        .success()
        .stdout(predicate::str::contains("signature_value_match=yes"));
}

#[test]
fn code_signs_nested_nupkg_inside_generic_zip() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("bundle.zip");
    let output = base.join("signed.zip");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_nupkg = base.join("nested-signed.nupkg");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &input,
        &[
            ("readme.txt", b"unsigned container".as_slice()),
            (
                "packages/sample.nupkg",
                &std::fs::read(
                    repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
                )
                .unwrap(),
            ),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("bundle.zip");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("nested package entries"));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut nested = Vec::new();
    archive
        .by_name("packages/sample.nupkg")
        .unwrap()
        .read_to_end(&mut nested)
        .unwrap();
    std::fs::write(&nested_nupkg, nested).unwrap();

    let mut nested_info = psign();
    nested_info
        .args(["portable", "nupkg-signature-info"])
        .arg(&nested_nupkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"));
}

#[test]
fn code_continue_on_error_signs_remaining_top_level_inputs() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("bundle.zip");
    let unsupported = base.join("unsupported.exe");
    let output_dir = base.join("signed");
    let signed_zip = output_dir.join("bundle.zip");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_nupkg = base.join("nested-signed.nupkg");
    write_test_rsa_cert_key(&cert, &key);
    write_file(&unsupported, b"MZunsupported");
    write_zip(
        &input,
        &[(
            "packages/sample.nupkg",
            &std::fs::read(
                repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
            )
            .unwrap(),
        )],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--continue-on-error",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output_dir)
        .args(["bundle.zip", "unsupported.exe"]);
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("signed bundle.zip"))
        .stdout(predicate::str::contains("failed unsupported.exe"));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&signed_zip).unwrap()).unwrap();
    let mut nested = Vec::new();
    archive
        .by_name("packages/sample.nupkg")
        .unwrap()
        .read_to_end(&mut nested)
        .unwrap();
    std::fs::write(&nested_nupkg, nested).unwrap();

    let mut nested_info = psign();
    nested_info
        .args(["portable", "nupkg-signature-info"])
        .arg(&nested_nupkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"));
}

#[test]
fn code_max_concurrency_signs_independent_top_level_packages() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let output_dir = base.join("signed");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
        base.join("a.nupkg"),
    )
    .unwrap();
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.snupkg"),
        base.join("b.snupkg"),
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--max-concurrency",
            "2",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output_dir)
        .args(["a.nupkg", "b.snupkg"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signed a.nupkg"))
        .stdout(predicate::str::contains("signed b.snupkg"));

    for name in ["a.nupkg", "b.snupkg"] {
        let mut info = psign();
        info.args(["portable", "nupkg-signature-info"])
            .arg(output_dir.join(name))
            .assert()
            .success()
            .stdout(predicate::str::contains("signed=yes"));
    }
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn code_signs_nupkg_with_rfc3161_timestamp() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let output = base.join("timestamped.nupkg");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let signature = base.join("signature.p7s");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/sample.nupkg"),
        base.join("sample.nupkg"),
    )
    .unwrap();
    let (mut guard, timestamp_url) = spawn_timestamp_server();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--timestamp-url",
            &timestamp_url,
            "--timestamp-digest",
            "sha256",
            "--output",
        ])
        .arg(&output)
        .arg("sample.nupkg");
    cmd.assert().success();
    let status = guard.0.wait().expect("timestamp server exit");
    assert!(status.success(), "timestamp server failed with {status}");

    let signature_der = nuget::extract_signature_path(&output).expect("extract NuGet signature");
    assert_pkcs7_has_unsigned_attr(
        &signature_der,
        pkcs7::PKCS9_RFC3161_TIMESTAMP_TOKEN_OID,
        pkcs7::MS_RFC3161_TIMESTAMP_TOKEN_OID,
    );
    std::fs::write(&signature, signature_der).unwrap();
    let mut inspect = psign();
    inspect
        .args(["portable", "inspect-authenticode"])
        .arg(&signature)
        .args(["--input", "pkcs7"]);
    inspect
        .assert()
        .success()
        .stdout(predicate::str::contains("id_aa_time_stamp_token"))
        .stdout(predicate::str::contains("1.2.840.113549.1.9.16.2.14"));
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn code_signs_nupkg_nested_pe_with_rfc3161_timestamp() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("with-pe.nupkg");
    let output = base.join("with-pe.timestamped.nupkg");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_pe = base.join("tiny32.timestamped.dll");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/with-pe.nupkg"),
        &input,
    )
    .unwrap();
    let (mut guard, timestamp_url) = spawn_timestamp_server_with_max_requests(2);

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--timestamp-url",
            &timestamp_url,
            "--timestamp-digest",
            "sha256",
            "--output",
        ])
        .arg(&output)
        .arg("with-pe.nupkg");
    cmd.assert().success();
    let status = guard.0.wait().expect("timestamp server exit");
    assert!(status.success(), "timestamp server failed with {status}");

    let signature_der = nuget::extract_signature_path(&output).expect("extract NuGet signature");
    assert_pkcs7_has_unsigned_attr(
        &signature_der,
        pkcs7::PKCS9_RFC3161_TIMESTAMP_TOKEN_OID,
        pkcs7::MS_RFC3161_TIMESTAMP_TOKEN_OID,
    );

    extract_zip_entry(&output, "lib/net8.0/tiny32.dll", &nested_pe);
    let nested_pkcs7 =
        verify_pe::pe_nth_pkcs7_signed_data_der(&std::fs::read(&nested_pe).unwrap(), 0).unwrap();
    assert_pkcs7_has_unsigned_attr(
        &nested_pkcs7,
        pkcs7::MS_RFC3161_TIMESTAMP_TOKEN_OID,
        pkcs7::PKCS9_RFC3161_TIMESTAMP_TOKEN_OID,
    );
}

#[test]
fn code_rejects_zero_max_concurrency() {
    let mut cmd = psign();
    cmd.args(["code", "--dry-run", "--max-concurrency", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--max-concurrency must be greater than zero",
        ));
}

#[test]
fn code_overwrite_resigns_signed_nupkg_inside_generic_zip() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("bundle.zip");
    let output = base.join("resigned.zip");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_nupkg = base.join("nested-resigned.nupkg");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &input,
        &[
            ("readme.txt", b"signed container".as_slice()),
            (
                "packages/sample.nupkg",
                &std::fs::read(
                    repo_root().join("tests/fixtures/package-signing/signed/sample.signed.nupkg"),
                )
                .unwrap(),
            ),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--overwrite",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("bundle.zip");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("nested package entries"));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut nested = Vec::new();
    archive
        .by_name("packages/sample.nupkg")
        .unwrap()
        .read_to_end(&mut nested)
        .unwrap();
    std::fs::write(&nested_nupkg, nested).unwrap();

    let mut verify = psign();
    verify
        .args(["portable", "nupkg-verify-signature"])
        .arg(&nested_nupkg)
        .args(["--trusted-ca"])
        .arg(&cert)
        .args(["--allow-loose-signing-cert"])
        .assert()
        .success()
        .stdout(predicate::str::contains("nupkg-verify-signature: ok"));
}

#[test]
fn code_overwrite_resigns_signed_vsix_inside_generic_zip() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("bundle.zip");
    let output = base.join("resigned.zip");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_vsix = base.join("nested-resigned.vsix");
    write_test_rsa_cert_key(&cert, &key);
    write_zip(
        &input,
        &[
            ("readme.txt", b"signed container".as_slice()),
            (
                "extensions/sample.vsix",
                &std::fs::read(
                    repo_root().join("tests/fixtures/package-signing/signed/sample.signed.vsix"),
                )
                .unwrap(),
            ),
        ],
    );

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--overwrite",
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("bundle.zip");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("nested package entries"));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut nested = Vec::new();
    archive
        .by_name("extensions/sample.vsix")
        .unwrap()
        .read_to_end(&mut nested)
        .unwrap();
    std::fs::write(&nested_vsix, nested).unwrap();

    let mut verify = psign();
    verify
        .args(["portable", "vsix-verify-signature"])
        .arg(&nested_vsix)
        .assert()
        .success()
        .stdout(predicate::str::contains("vsix-verify-signature: ok"));
}

#[test]
fn code_signs_nested_package_when_excluding_unsupported_inner_payload() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("deep-nested.vsix");
    let output = base.join("signed.vsix");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let file_list = base.join("files.txt");
    let nested_nupkg = base.join("with-pe-signed.nupkg");
    let signature_xml = base.join("signature.xml");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/deep-nested.vsix"),
        &input,
    )
    .unwrap();
    std::fs::write(&file_list, "deep-nested.vsix\n!**/*.dll\n").unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args(["--file-list", "files.txt"])
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signed deep-nested.vsix"));

    let mut archive = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut nested = Vec::new();
    archive
        .by_name("packages/with-pe.nupkg")
        .unwrap()
        .read_to_end(&mut nested)
        .unwrap();
    std::fs::write(&nested_nupkg, nested).unwrap();
    let mut xml = Vec::new();
    archive
        .by_name("package/services/digital-signature/xml-signature/psign-signature.psdsxs")
        .unwrap()
        .read_to_end(&mut xml)
        .unwrap();
    std::fs::write(&signature_xml, xml).unwrap();
    drop(archive);

    let mut nested_info = psign();
    nested_info
        .args(["portable", "nupkg-signature-info"])
        .arg(&nested_nupkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"));

    let mut verify_outer = psign();
    verify_outer
        .args(["portable", "vsix-verify-signature-xml"])
        .arg(&output)
        .args(["--signature-xml"])
        .arg(&signature_xml)
        .args(["--cert"])
        .arg(&cert)
        .assert()
        .success()
        .stdout(predicate::str::contains("signature_value_match=yes"));
}

#[test]
fn code_signs_nested_pe_before_nupkg_before_vsix() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let input = base.join("deep-nested.vsix");
    let output = base.join("signed.vsix");
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let nested_nupkg = base.join("with-pe-signed.nupkg");
    let nested_pe = base.join("tiny32.signed.dll");
    let signature_xml = base.join("signature.xml");
    write_test_rsa_cert_key(&cert, &key);
    std::fs::copy(
        repo_root().join("tests/fixtures/package-signing/unsigned/deep-nested.vsix"),
        &input,
    )
    .unwrap();

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("deep-nested.vsix");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signed deep-nested.vsix"));

    let mut outer = zip::ZipArchive::new(std::fs::File::open(&output).unwrap()).unwrap();
    let mut nested = Vec::new();
    outer
        .by_name("packages/with-pe.nupkg")
        .unwrap()
        .read_to_end(&mut nested)
        .unwrap();
    std::fs::write(&nested_nupkg, nested).unwrap();
    let mut xml = Vec::new();
    outer
        .by_name("package/services/digital-signature/xml-signature/psign-signature.psdsxs")
        .unwrap()
        .read_to_end(&mut xml)
        .unwrap();
    std::fs::write(&signature_xml, xml).unwrap();
    drop(outer);

    let mut nupkg = zip::ZipArchive::new(std::fs::File::open(&nested_nupkg).unwrap()).unwrap();
    let mut pe = Vec::new();
    nupkg
        .by_name("lib/net8.0/tiny32.dll")
        .unwrap()
        .read_to_end(&mut pe)
        .unwrap();
    std::fs::write(&nested_pe, pe).unwrap();

    let mut verify_pe = psign();
    verify_pe
        .args(["portable", "verify-pe"])
        .arg(&nested_pe)
        .assert()
        .success();

    let mut nested_info = psign();
    nested_info
        .args(["portable", "nupkg-signature-info"])
        .arg(&nested_nupkg)
        .assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"));

    let mut verify_outer = psign();
    verify_outer
        .args(["portable", "vsix-verify-signature-xml"])
        .arg(&output)
        .args(["--signature-xml"])
        .arg(&signature_xml)
        .args(["--cert"])
        .arg(&cert)
        .assert()
        .success()
        .stdout(predicate::str::contains("signature_value_match=yes"));
}

#[test]
fn code_dry_run_detects_only_navx_business_central_app_files() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write_file(&base.join("valid.app"), b"NAVX\x00fixture");
    write_file(&base.join("not-business-central.app"), b"ZIP?");

    let mut cmd = psign();
    let assert = cmd
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(base)
        .args(["*.app"])
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let formats: Vec<_> = json["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .map(|node| {
            (
                node["path"].as_str().expect("path"),
                node["format"].as_str().expect("format"),
            )
        })
        .collect();
    assert!(formats.contains(&("valid.app", "business-central-app")));
    assert!(formats.contains(&("not-business-central.app", "unknown")));
}

#[test]
fn code_execution_reports_business_central_navx_gap() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let cert = base.join("signer.der");
    let key = base.join("signer.pkcs8");
    let output = base.join("signed.app");
    write_test_rsa_cert_key(&cert, &key);
    write_file(&base.join("valid.app"), b"NAVX\x00fixture");

    let mut cmd = psign();
    cmd.args(["code", "--base-directory"])
        .arg(base)
        .args([
            "--cert",
            cert.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
        ])
        .arg(&output)
        .arg("valid.app");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Business Central NAVX .app"));
}

#[test]
fn code_dry_run_classifies_clickonce_deploy_payloads() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write_file(&base.join("app.application"), b"manifest");
    write_file(&base.join("app.exe.manifest"), b"manifest");
    write_file(&base.join("app.exe.deploy"), b"pe");

    let mut cmd = psign();
    let assert = cmd
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(base)
        .args(["**/*"])
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let formats: Vec<_> = json["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .map(|node| {
            (
                node["path"].as_str().expect("path"),
                node["format"].as_str().expect("format"),
                node["signer"].as_str().expect("signer"),
            )
        })
        .collect();
    assert!(formats.contains(&(
        "app.application",
        "click-once-application",
        "clickonce-manifest"
    )));
    assert!(formats.contains(&("app.exe.manifest", "manifest", "clickonce-manifest")));
    assert!(formats.contains(&("app.exe.deploy", "deploy", "clickonce-manifest")));
}

#[test]
fn code_dry_run_plans_output_directory_layout() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    let output = base.join("signed-output");
    write_file(&base.join("lib/a.dll"), b"pe");
    write_file(&base.join("tools/b.dll"), b"pe");

    let mut cmd = psign();
    let assert = cmd
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(base)
        .args(["--output"])
        .arg(&output)
        .args(["**/*.dll"])
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let output_paths = plan_output_paths(&json);
    let root = output.display().to_string().replace('\\', "/");
    assert_eq!(
        output_paths,
        [format!("{root}/lib/a.dll"), format!("{root}/tools/b.dll")]
    );
}

#[test]
fn code_dry_run_plans_single_file_output_for_nested_container() {
    let repo = repo_root();
    let input = "tests/fixtures/package-signing/unsigned/deep-nested.vsix";
    let output = repo.join("target/signed-extension.vsix");

    let mut cmd = psign();
    let assert = cmd
        .args(["code", "--dry-run", "--plan-json", "--base-directory"])
        .arg(&repo)
        .args(["--output"])
        .arg(&output)
        .arg(input)
        .assert()
        .success();

    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let output_paths = plan_output_paths(&json);
    let root = output.display().to_string().replace('\\', "/");
    assert!(output_paths.contains(&root));
    assert!(output_paths.iter().any(|path| {
        path.ends_with("signed-extension.vsix!packages/with-pe.nupkg!lib/net8.0/tiny32.dll")
    }));
}

fn plan_paths(json: &Value) -> Vec<String> {
    let mut paths: Vec<_> = json["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .map(|node| node["path"].as_str().expect("node path").to_owned())
        .collect();
    paths.sort();
    paths
}

fn plan_output_paths(json: &Value) -> Vec<String> {
    let mut paths: Vec<_> = json["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .map(|node| {
            node["output_path"]
                .as_str()
                .expect("node output_path")
                .to_owned()
        })
        .collect();
    paths.sort();
    paths
}

fn write_file(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::default();
    for (name, bytes) in entries {
        writer.start_file(*name, options).unwrap();
        use std::io::Write as _;
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap();
}

fn extract_zip_entry(zip_path: &Path, entry_name: &str, output: &Path) {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(zip_path).unwrap()).unwrap();
    let mut entry = archive.by_name(entry_name).unwrap();
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).unwrap();
    std::fs::write(output, bytes).unwrap();
}

fn assert_nupkg_signature_has_nuget_author_attrs(path: &Path) {
    let signature_der = nuget::extract_signature_path(path).expect("extract NuGet signature");
    let signed_data =
        pkcs7::parse_pkcs7_signed_data_der(&signature_der).expect("parse NuGet signature");
    assert_eq!(
        signed_data.encap_content_info.econtent_type.to_string(),
        pkcs7::PKCS7_ID_DATA_OID
    );
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .expect("NuGet signature embeds id-data content");
    let content = econtent
        .decode_as::<OctetString>()
        .expect("NuGet id-data content OCTET STRING");
    let expected_content =
        nuget::signed_package_signature_content_path(path, nuget::NuGetHashAlgorithm::Sha256)
            .expect("expected NuGet signature content");
    assert_eq!(content.as_bytes(), expected_content.as_slice());

    let signer_infos = signed_data.signer_infos.0.as_slice();
    let signer_info = signer_infos.first().expect("NuGet signature signer info");
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .expect("NuGet signature signed attributes");
    let commitment_attr = signed_attrs
        .iter()
        .find(|attr| attr.oid == pkcs7::PKCS9_COMMITMENT_TYPE_INDICATION_OID)
        .expect("NuGet author commitment-type signed attribute");
    let commitment_values = commitment_attr.values.as_slice();
    assert_eq!(commitment_values.len(), 1);

    let proof_of_origin_oid = pkcs7::COMMITMENT_TYPE_IDENTIFIER_PROOF_OF_ORIGIN_OID
        .to_der()
        .expect("proofOfOrigin OID DER");
    let mut expected_value = vec![0x30, proof_of_origin_oid.len() as u8];
    expected_value.extend_from_slice(&proof_of_origin_oid);
    assert_eq!(
        commitment_values[0].to_der().expect("commitment value DER"),
        expected_value
    );

    assert!(
        signed_attrs
            .iter()
            .any(|attr| attr.oid == pkcs7::PKCS9_SIGNING_TIME_OID),
        "NuGet author signing-time signed attribute"
    );
    let signing_certificate_v2 = signed_attrs
        .iter()
        .find(|attr| attr.oid == pkcs7::PKCS9_SIGNING_CERTIFICATE_V2_OID)
        .expect("NuGet author signing-certificate-v2 signed attribute");
    assert_eq!(signing_certificate_v2.values.as_slice().len(), 1);
}

fn assert_pkcs7_has_unsigned_attr(
    signature_der: &[u8],
    expected: x509_cert::der::asn1::ObjectIdentifier,
    unexpected: x509_cert::der::asn1::ObjectIdentifier,
) {
    let signed_data =
        pkcs7::parse_pkcs7_signed_data_der(signature_der).expect("parse PKCS#7 signature");
    let signer_info = signed_data
        .signer_infos
        .0
        .as_slice()
        .first()
        .expect("PKCS#7 signer info");
    let unsigned_attrs = signer_info
        .unsigned_attrs
        .as_ref()
        .expect("PKCS#7 unsigned attributes");
    assert!(
        unsigned_attrs.iter().any(|attr| attr.oid == expected),
        "expected unsigned attribute {expected}"
    );
    assert!(
        unsigned_attrs.iter().all(|attr| attr.oid != unexpected),
        "unexpected unsigned attribute {unexpected}"
    );
}

fn sample_clickonce_manifest() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity name="ClickOnce.Sample" version="1.0.0.0" />
  <description asmv2:publisher="Example" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" />
</assembly>"#
}

#[cfg(feature = "timestamp-server")]
struct PsignServerGuard(std::process::Child);

#[cfg(feature = "timestamp-server")]
impl Drop for PsignServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn spawn_timestamp_server() -> (PsignServerGuard, String) {
    spawn_timestamp_server_with_max_requests(1)
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn spawn_timestamp_server_with_max_requests(max_requests: u64) -> (PsignServerGuard, String) {
    let mut server_cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("psign-server"));
    let max_requests = max_requests.to_string();
    server_cmd.args([
        "timestamp-server",
        "--listen",
        "127.0.0.1:0",
        "--gen-time",
        "20240102030405Z",
        "--max-requests",
        max_requests.as_str(),
    ]);
    server_cmd.stdout(std::process::Stdio::piped());
    server_cmd.stderr(std::process::Stdio::piped());
    let mut guard = PsignServerGuard(server_cmd.spawn().expect("spawn psign-server"));
    let stdout = guard.0.stdout.take().expect("server stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("read listening line");
    let url = line
        .trim()
        .strip_prefix("psign-server timestamp-server listening on ")
        .expect("listening URL")
        .to_string();
    (guard, url)
}

#[cfg(all(feature = "timestamp-server", feature = "azure-kv-sign"))]
fn spawn_azure_key_vault_server(max_requests: u64) -> (PsignServerGuard, String, String) {
    let mut server_cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("psign-server"));
    let max_requests = max_requests.to_string();
    server_cmd.args([
        "azure-key-vault-server",
        "--listen",
        "127.0.0.1:0",
        "--max-requests",
        max_requests.as_str(),
    ]);
    server_cmd.stdout(std::process::Stdio::piped());
    server_cmd.stderr(std::process::Stdio::piped());
    let mut guard = PsignServerGuard(server_cmd.spawn().expect("spawn psign-server"));
    let stdout = guard.0.stdout.take().expect("server stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut listen_line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut listen_line).expect("read listening line");
    let mut cert_line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut cert_line).expect("read certificate line");
    let mut ignored = String::new();
    std::io::BufRead::read_line(&mut reader, &mut ignored).expect("read leaf line");
    let url = listen_line
        .trim()
        .strip_prefix("psign-server azure-key-vault-server listening on ")
        .expect("listening URL")
        .to_string();
    let certificate = cert_line
        .trim()
        .strip_prefix("psign-server azure-key-vault-server certificate ")
        .expect("certificate name")
        .to_string();
    (guard, url, certificate)
}

#[cfg(all(feature = "timestamp-server", feature = "artifact-signing-rest"))]
fn spawn_artifact_signing_server(max_requests: u64) -> (PsignServerGuard, String) {
    let mut server_cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("psign-server"));
    let max_requests = max_requests.to_string();
    server_cmd.args([
        "artifact-signing-server",
        "--listen",
        "127.0.0.1:0",
        "--max-requests",
        max_requests.as_str(),
    ]);
    server_cmd.stdout(std::process::Stdio::piped());
    server_cmd.stderr(std::process::Stdio::piped());
    let mut guard = PsignServerGuard(server_cmd.spawn().expect("spawn psign-server"));
    let stdout = guard.0.stdout.take().expect("server stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut listen_line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut listen_line).expect("read listening line");
    let mut ignored = String::new();
    std::io::BufRead::read_line(&mut reader, &mut ignored).expect("read endpoint line");
    let url = listen_line
        .trim()
        .strip_prefix("psign-server artifact-signing-server listening on ")
        .expect("listening URL")
        .to_string();
    (guard, url)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn write_test_rsa_cert_key(cert_path: &Path, key_path: &Path) {
    write_test_rsa_cert_key_inner(cert_path, key_path, None);
}

fn write_test_rsa_cert_key_and_pem(cert_path: &Path, key_path: &Path, pem_path: &Path) {
    write_test_rsa_cert_key_inner(cert_path, key_path, Some(pem_path));
}

fn write_test_rsa_pfx(pfx_path: &Path, password: &str) {
    use picky::key::PrivateKey;
    use picky::pkcs12::{
        Pfx, Pkcs12CryptoContext, Pkcs12HashAlgorithm, Pkcs12MacAlgorithmHmac, SafeBag,
        SafeContents,
    };
    use picky::x509::Cert;

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa private key");
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let subject = Name::from_str("CN=psign code pfx orchestrator test").expect("subject name");
    let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key())
        .expect("subject public key info");
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(85u32),
        Validity::from_now(Duration::from_secs(7 * 86_400)).expect("validity"),
        subject,
        spki,
        &signing_key,
    )
    .expect("certificate builder");
    let cert = builder
        .build::<rsa::pkcs1v15::Signature>()
        .expect("self-signed certificate");
    let key_der = private_key
        .to_pkcs8_der()
        .expect("PKCS#8 private key")
        .as_bytes()
        .to_vec();
    let key = PrivateKey::from_pkcs8(&key_der).expect("picky private key");
    let cert = Cert::from_der(&cert.to_der().expect("certificate DER")).expect("picky cert");
    let cert_bag = SafeBag::new_certificate(cert, vec![]).expect("cert bag");
    let key_bag = SafeBag::new_key(key, vec![]).expect("key bag");
    let mut context = Pkcs12CryptoContext::new_with_password(password).expect("PFX context");
    let pfx = Pfx::new_with_hmac(
        vec![SafeContents::new(vec![cert_bag, key_bag])],
        Pkcs12MacAlgorithmHmac::new(Pkcs12HashAlgorithm::Sha256),
        &mut context,
    )
    .expect("PFX")
    .to_der()
    .expect("PFX DER");
    std::fs::write(pfx_path, pfx).expect("write PFX");
}

fn write_test_rsa_cert_key_inner(cert_path: &Path, key_path: &Path, pem_path: Option<&Path>) {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa private key");
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let subject = Name::from_str("CN=psign code orchestrator test").expect("subject name");
    let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key())
        .expect("subject public key info");
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(84u32),
        Validity::from_now(Duration::from_secs(7 * 86_400)).expect("validity"),
        subject,
        spki,
        &signing_key,
    )
    .expect("certificate builder");
    let cert = builder
        .build::<rsa::pkcs1v15::Signature>()
        .expect("self-signed certificate");
    std::fs::write(cert_path, cert.to_der().expect("certificate DER")).expect("write cert");
    if let Some(pem_path) = pem_path {
        std::fs::write(
            pem_path,
            private_key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("PKCS#8 private key PEM")
                .as_bytes(),
        )
        .expect("write key PEM");
    }
    std::fs::write(
        key_path,
        private_key
            .to_pkcs8_der()
            .expect("PKCS#8 private key")
            .as_bytes(),
    )
    .expect("write key");
}
