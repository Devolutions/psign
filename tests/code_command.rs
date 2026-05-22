use assert_cmd::Command;
use predicates::prelude::*;
use psign_opc_sign::nuget;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::signature::Keypair;
use serde_json::Value;
use sha2::Sha256;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
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
    .stderr(predicate::str::contains(
        "currently requires --cert and --key",
    ));
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
    std::fs::write(&signature, signature_der).unwrap();
    let mut inspect = psign();
    inspect
        .args(["portable", "inspect-authenticode"])
        .arg(&signature)
        .args(["--input", "pkcs7"]);
    inspect
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "microsoft_nested_rfc3161_attribute",
        ))
        .stdout(predicate::str::contains("1.3.6.1.4.1.311.3.3.1"));
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

fn sample_clickonce_manifest() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity name="ClickOnce.Sample" version="1.0.0.0" />
  <description asmv2:publisher="Example" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" />
</assembly>"#
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
struct PsignServerGuard(std::process::Child);

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
impl Drop for PsignServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn spawn_timestamp_server() -> (PsignServerGuard, String) {
    let mut server_cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("psign-server"));
    server_cmd.args([
        "timestamp-server",
        "--listen",
        "127.0.0.1:0",
        "--gen-time",
        "20240102030405Z",
        "--max-requests",
        "1",
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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn write_test_rsa_cert_key(cert_path: &Path, key_path: &Path) {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa private key");
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let subject = Name::from_str("CN=psign code orchestrator test").expect("subject name");
    let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key())
        .expect("subject public key info");
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(84u32),
        Validity::from_now(Duration::from_secs(86_400)).expect("validity"),
        subject,
        spki,
        &signing_key,
    )
    .expect("certificate builder");
    let cert = builder
        .build::<rsa::pkcs1v15::Signature>()
        .expect("self-signed certificate");
    std::fs::write(cert_path, cert.to_der().expect("certificate DER")).expect("write cert");
    std::fs::write(
        key_path,
        private_key
            .to_pkcs8_der()
            .expect("PKCS#8 private key")
            .as_bytes(),
    )
    .expect("write key");
}
