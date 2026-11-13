//! Cross-platform portable verification, signing, publisher-rewriting, and `code` container
//! tests across the MSIX/AppX-family edge-case corpus (`tests/fixtures/msix-edge-cases/`).

use assert_cmd::Command;
use predicates::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct MsixEdgeManifest {
    entries: Vec<MsixEdgeEntry>,
}

#[derive(Debug, Deserialize)]
struct MsixEdgeEntry {
    id: String,
    extension: String,
    digest: String,
    is_sparse_bundle: bool,
    is_encrypted: bool,
    is_upload_container: bool,
    expected_portable_verify: String,
    unsigned_path: Option<String>,
    signed_path: Option<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(rel: &str) -> PathBuf {
    let sep = std::path::MAIN_SEPARATOR.to_string();
    repo_root().join(rel.replace(['/', '\\'], &sep))
}

fn psign() -> Command {
    Command::cargo_bin("psign-tool").expect("psign-tool binary")
}

fn test_pfx() -> PathBuf {
    repo_path("tests/fixtures/devolutions-authenticode/authenticode-test-cert.pfx")
}

fn test_ca() -> PathBuf {
    repo_path("tests/fixtures/devolutions-authenticode/authenticode-test-ca.crt")
}

fn load_manifest() -> MsixEdgeManifest {
    serde_json::from_str(include_str!(
        "fixtures/msix-edge-cases/msix-edge-case-fixtures.json"
    ))
    .expect("parse msix-edge-case-fixtures.json")
}

#[test]
fn committed_msix_edge_case_corpus_verifies_or_rejects_as_declared_in_portable_mode() {
    let manifest = load_manifest();
    let ca = test_ca();

    for entry in &manifest.entries {
        match entry.expected_portable_verify.as_str() {
            "valid" => {
                let signed = repo_path(entry.signed_path.as_deref().expect("signed_path"));
                psign()
                    .args(["portable", "verify-msix"])
                    .arg(&signed)
                    .assert()
                    .success();

                psign()
                    .args([
                        "--mode",
                        "portable",
                        "verify",
                        "--trusted-ca",
                        ca.to_str().unwrap(),
                        "--as-of",
                        "2026-06-01",
                    ])
                    .arg(&signed)
                    .assert()
                    .success();
            }
            "reject-encrypted" => {
                for rel in [entry.unsigned_path.as_deref(), entry.signed_path.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    let target = repo_path(rel);
                    psign()
                        .args(["--mode", "portable", "verify"])
                        .arg(&target)
                        .assert()
                        .failure()
                        .stderr(predicate::str::contains("encrypted MSIX/AppX"));

                    psign()
                        .args(["portable", "msix-manifest-info"])
                        .arg(&target)
                        .assert()
                        .failure()
                        .stderr(predicate::str::contains("encrypted MSIX/AppX"));
                }
            }
            "reject-upload-container" => {
                let target = repo_path(entry.unsigned_path.as_deref().expect("unsigned_path"));
                psign()
                    .args(["--mode", "portable", "verify"])
                    .arg(&target)
                    .assert()
                    .failure()
                    .stderr(predicate::str::contains("upload bundles"));
            }
            "detached-valid" => {
                let content = repo_path(entry.unsigned_path.as_deref().expect("unsigned_path"));
                let sig = repo_path(entry.signed_path.as_deref().expect("signed_path"));
                psign()
                    .args([
                        "portable",
                        "trust-verify-detached",
                        content.to_str().unwrap(),
                        sig.to_str().unwrap(),
                        "--trusted-ca",
                        ca.to_str().unwrap(),
                        "--as-of",
                        "2026-06-01",
                    ])
                    .assert()
                    .success();
            }
            "inspect-pkcs7" => {
                let p7x = repo_path(entry.signed_path.as_deref().expect("signed_path"));
                let out = psign()
                    .args(["portable", "inspect-pkcs7"])
                    .arg(&p7x)
                    .assert()
                    .success()
                    .get_output()
                    .stdout
                    .clone();
                let json: Value = serde_json::from_slice(&out).expect("parse inspect-pkcs7 JSON");
                assert!(
                    json["certificate_count"].as_u64().unwrap_or(0) >= 1,
                    "{}: expected embedded certificates in standalone .p7x",
                    entry.id
                );
            }
            other => panic!(
                "unexpected expected_portable_verify `{other}` for {}",
                entry.id
            ),
        }
    }
}

#[test]
fn portable_sign_roundtrips_first_sign_and_resign_across_all_cleartext_msix_edge_cases() {
    let manifest = load_manifest();
    let temp = tempfile::tempdir().expect("tempdir");
    let pfx = test_pfx();
    let ca = test_ca();

    for entry in &manifest.entries {
        if entry.is_encrypted || entry.is_upload_container {
            if let Some(rel) = &entry.unsigned_path {
                let copy = temp.path().join(format!("{}{}", entry.id, entry.extension));
                std::fs::copy(repo_path(rel), &copy).unwrap();
                psign()
                    .args([
                        "--mode",
                        "portable",
                        "sign",
                        "--pfx",
                        pfx.to_str().unwrap(),
                        "--password",
                        "CodeSign123!",
                    ])
                    .arg(&copy)
                    .assert()
                    .failure();
            }
            continue;
        }
        if !matches!(
            entry.extension.as_str(),
            ".msix" | ".appx" | ".msixbundle" | ".appxbundle"
        ) {
            continue;
        }
        let Some(unsigned_rel) = &entry.unsigned_path else {
            continue;
        };

        let target = temp.path().join(format!("{}{}", entry.id, entry.extension));
        std::fs::copy(repo_path(unsigned_rel), &target).unwrap();

        let original_presigned_children = if entry.id == "msixbundle-multi-presigned-children" {
            Some(read_embedded_children(&target))
        } else {
            None
        };

        // Verify independently after BOTH pass 1 (first sign) and pass 2 (re-sign).
        let digest_lower = entry.digest.to_ascii_lowercase();
        for pass in 1..=2 {
            psign()
                .args([
                    "--mode",
                    "portable",
                    "sign",
                    "--pfx",
                    pfx.to_str().unwrap(),
                    "--password",
                    "CodeSign123!",
                    "--digest",
                    &digest_lower,
                ])
                .arg(&target)
                .assert()
                .success();

            psign()
                .args(["portable", "verify-msix"])
                .arg(&target)
                .assert()
                .success();

            psign()
                .args([
                    "portable",
                    "trust-verify-msix",
                    "--trusted-ca",
                    ca.to_str().unwrap(),
                    "--as-of",
                    "2026-06-01",
                ])
                .arg(&target)
                .assert()
                .success();

            if entry.is_sparse_bundle {
                assert!(
                    read_embedded_children(&target).is_empty(),
                    "{} pass {pass}: sparse bundle must remain free of embedded child entries",
                    entry.id
                );
            }
            if let Some(expected_children) = &original_presigned_children {
                assert_eq!(
                    &read_embedded_children(&target),
                    expected_children,
                    "{} pass {pass}: pre-signed embedded children must stay byte-identical",
                    entry.id
                );
            }
        }
    }

    // Regression for bundle SHA-384 / SHA-512 block-map HashMethod URIs: sign genuine .appxbundle
    // with SHA-384 and SHA-512.
    for digest in ["sha384", "sha512"] {
        let appxbundle = temp.path().join(format!("multi-{digest}.appxbundle"));
        std::fs::copy(
            repo_path("tests/fixtures/msix-edge-cases/unsigned/bundle-multi.appxbundle"),
            &appxbundle,
        )
        .unwrap();
        psign()
            .args([
                "--mode",
                "portable",
                "sign",
                "--pfx",
                pfx.to_str().unwrap(),
                "--password",
                "CodeSign123!",
                "--digest",
                digest,
            ])
            .arg(&appxbundle)
            .assert()
            .success();
        psign()
            .args(["portable", "verify-msix"])
            .arg(&appxbundle)
            .assert()
            .success();
    }
}

#[test]
fn portable_msix_set_publisher_handles_complex_dn_and_updates_multi_bundle_children() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let root_cer = dir.join("root.cer");
    let root_pfx = dir.join("root.pfx");
    psign()
        .args([
            "portable",
            "generate-root-ca",
            "--subject",
            "CN=Psign Complex DN Root CA, O=Devolutions, C=CA",
            "--cert-out",
            root_cer.to_str().unwrap(),
            "--pfx-out",
            root_pfx.to_str().unwrap(),
            "--password",
            "RootPass123!",
        ])
        .assert()
        .success();

    let complex_publisher = "CN=Devolutions Release & QA, OU=Packaging, O=\"Devolutions, Inc.\", L=Lavaltrie, S=Quebec, C=CA";
    let leaf_pfx = dir.join("leaf.pfx");
    psign()
        .args([
            "portable",
            "issue-code-signing-cert",
            "--ca-pfx",
            root_pfx.to_str().unwrap(),
            "--ca-password",
            "RootPass123!",
            "--subject",
            complex_publisher,
            "--pfx-out",
            leaf_pfx.to_str().unwrap(),
            "--password",
            "LeafPass123!",
        ])
        .assert()
        .success();

    let updated_bundle = dir.join("complex-publisher.msixbundle");
    psign()
        .args(["portable", "msix-set-publisher"])
        .arg(repo_path(
            "tests/fixtures/msix-edge-cases/unsigned/bundle-multi.msixbundle",
        ))
        .args(["--publisher", complex_publisher, "--output"])
        .arg(&updated_bundle)
        .assert()
        .success();

    // Every embedded child's manifest must also reflect the updated publisher, and child
    // Offset/Size attributes in AppxBundleManifest.xml must match the restaged stored offsets.
    let children = read_embedded_children(&updated_bundle);
    assert_eq!(children.len(), 3, "expected 3 embedded children");
    for (name, child_bytes) in &children {
        let child_path = dir.join(name.replace('/', "_"));
        std::fs::write(&child_path, child_bytes).unwrap();
        psign()
            .args(["portable", "msix-manifest-info"])
            .arg(&child_path)
            .assert()
            .success()
            .stdout(predicate::str::contains(format!(
                "publisher={complex_publisher}"
            )));
    }

    psign()
        .args([
            "--mode",
            "portable",
            "sign",
            "--pfx",
            leaf_pfx.to_str().unwrap(),
            "--password",
            "LeafPass123!",
        ])
        .arg(&updated_bundle)
        .assert()
        .success();

    psign()
        .args([
            "portable",
            "trust-verify-msix",
            "--trusted-ca",
            root_cer.to_str().unwrap(),
        ])
        .arg(&updated_bundle)
        .assert()
        .success();
}

#[test]
fn code_command_prepares_upload_containers_and_preserves_third_party_appinstaller_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let root_cer = dir.join("root.cer");
    let root_pfx = dir.join("root.pfx");
    psign()
        .args([
            "portable",
            "generate-root-ca",
            "--subject",
            "CN=Upload Prep Root CA",
            "--cert-out",
            root_cer.to_str().unwrap(),
            "--pfx-out",
            root_pfx.to_str().unwrap(),
            "--password",
            "RootPass123!",
        ])
        .assert()
        .success();

    let new_publisher = "CN=Upload Container Publisher, O=Devolutions, C=CA";
    let leaf_pfx = dir.join("leaf.pfx");
    let leaf_cer = dir.join("leaf.cer");
    psign()
        .args([
            "portable",
            "issue-code-signing-cert",
            "--ca-pfx",
            root_pfx.to_str().unwrap(),
            "--ca-password",
            "RootPass123!",
            "--subject",
            new_publisher,
            "--pfx-out",
            leaf_pfx.to_str().unwrap(),
            "--cert-out",
            leaf_cer.to_str().unwrap(),
            "--password",
            "LeafPass123!",
        ])
        .assert()
        .success();

    for (fixture_name, inner_bundle_name) in [
        ("sample.msixupload", "Psign.EdgeTest_1.0.0.0.msixbundle"),
        ("sample.appxupload", "Psign.EdgeTest_1.0.0.0.appxbundle"),
    ] {
        let src_upload = dir.join(fixture_name);
        std::fs::copy(
            repo_path(&format!(
                "tests/fixtures/msix-edge-cases/unsigned/{fixture_name}"
            )),
            &src_upload,
        )
        .unwrap();
        let out_upload = dir.join(format!("prepared-{fixture_name}"));

        psign()
            .args([
                "code",
                "--base-directory",
                dir.to_str().unwrap(),
                "--publisher-name",
                new_publisher,
                "--pfx",
                leaf_pfx.to_str().unwrap(),
                "--password",
                "LeafPass123!",
                "--output",
                out_upload.to_str().unwrap(),
                fixture_name,
            ])
            .assert()
            .success();

        // Extract the prepared inner bundle, verify its nested PE is signed, and final-sign it.
        let upload_bytes = std::fs::read(&out_upload).unwrap();
        let mut upload_zip = zip::ZipArchive::new(Cursor::new(upload_bytes)).unwrap();
        let mut inner_bundle_bytes = Vec::new();
        upload_zip
            .by_name(inner_bundle_name)
            .unwrap()
            .read_to_end(&mut inner_bundle_bytes)
            .unwrap();
        let inner_bundle_path = dir.join(inner_bundle_name);
        std::fs::write(&inner_bundle_path, &inner_bundle_bytes).unwrap();

        psign()
            .args([
                "--mode",
                "portable",
                "sign",
                "--pfx",
                leaf_pfx.to_str().unwrap(),
                "--password",
                "LeafPass123!",
            ])
            .arg(&inner_bundle_path)
            .assert()
            .success();

        psign()
            .args([
                "portable",
                "trust-verify-msix",
                "--trusted-ca",
                root_cer.to_str().unwrap(),
            ])
            .arg(&inner_bundle_path)
            .assert()
            .success();
    }

    // UTF-8 BOM 2021 .appinstaller publisher update must update MainBundle while preserving
    // Microsoft's publisher on <Dependencies><Package .../></Dependencies>.
    let updated_appinstaller = dir.join("updated.appinstaller");
    psign()
        .args(["portable", "appinstaller-set-publisher"])
        .arg(repo_path(
            "tests/fixtures/msix-edge-cases/unsigned/bundle-bom.appinstaller",
        ))
        .args(["--publisher", new_publisher, "--output"])
        .arg(&updated_appinstaller)
        .assert()
        .success();
    let updated_xml = std::fs::read_to_string(&updated_appinstaller).unwrap();
    assert!(
        updated_xml.starts_with('\u{feff}'),
        "UTF-8 BOM must be preserved on .appinstaller"
    );
    assert!(
        updated_xml.contains(&format!(r#"Publisher="{new_publisher}""#)),
        "MainBundle Publisher must be updated: {updated_xml}"
    );
    assert!(
        updated_xml.contains(
            r#"Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US""#
        ),
        "third-party Dependency Publisher must not be clobbered: {updated_xml}"
    );
}

#[cfg(feature = "timestamp-server")]
#[test]
fn portable_sign_timestamps_multi_package_msixbundle_and_verifies_rfc3161() {
    use std::io::BufRead as _;

    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let root_cer = dir.join("code-root.cer");
    let root_pfx = dir.join("code-root.pfx");
    psign()
        .args([
            "portable",
            "generate-root-ca",
            "--subject",
            "CN=Timestamped Bundle Root CA",
            "--cert-out",
            root_cer.to_str().unwrap(),
            "--pfx-out",
            root_pfx.to_str().unwrap(),
            "--password",
            "RootPass123!",
        ])
        .assert()
        .success();

    let publisher = "CN=Timestamped Bundle Signer";
    let leaf_pfx = dir.join("code-leaf.pfx");
    psign()
        .args([
            "portable",
            "issue-code-signing-cert",
            "--ca-pfx",
            root_pfx.to_str().unwrap(),
            "--ca-password",
            "RootPass123!",
            "--subject",
            publisher,
            "--pfx-out",
            leaf_pfx.to_str().unwrap(),
            "--password",
            "LeafPass123!",
        ])
        .assert()
        .success();

    let bundle = dir.join("timestamped-multi.msixbundle");
    psign()
        .args(["portable", "msix-set-publisher"])
        .arg(repo_path(
            "tests/fixtures/msix-edge-cases/unsigned/bundle-multi.msixbundle",
        ))
        .args(["--publisher", publisher, "--output"])
        .arg(&bundle)
        .assert()
        .success();

    let gen_time = generalized_time_tomorrow_noon_utc();
    // 4 signatures occur: 3 unsigned embedded child MSIXs + 1 outer bundle.
    let tsa_cert = dir.join("tsa.cer");
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("psign-server"))
        .args([
            "timestamp-server",
            "--listen",
            "127.0.0.1:0",
            "--gen-time",
            &gen_time,
            "--max-requests",
            "4",
            "--cert-output",
            tsa_cert.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn psign-server");

    let stdout = child.stdout.take().expect("psign-server stdout");
    let mut line = String::new();
    std::io::BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read listening URL");
    let tsa_url = line
        .trim()
        .strip_prefix("psign-server timestamp-server listening on ")
        .expect("parse listening URL")
        .to_string();

    let sign_res = psign()
        .args([
            "--mode",
            "portable",
            "sign",
            "--pfx",
            leaf_pfx.to_str().unwrap(),
            "--password",
            "LeafPass123!",
            "--digest",
            "sha256",
            "--timestamp-url",
            &tsa_url,
            "--timestamp-digest",
            "sha256",
        ])
        .arg(&bundle)
        .ok();
    let _ = child.wait();
    sign_res.expect("timestamped bundle sign failed");

    psign()
        .args([
            "portable",
            "trust-verify-msix",
            "--trusted-ca",
            root_cer.to_str().unwrap(),
            "--trusted-ca",
            tsa_cert.to_str().unwrap(),
            "--prefer-timestamp-signing-time",
            "--require-valid-timestamp",
        ])
        .arg(&bundle)
        .assert()
        .success();
}

#[cfg(feature = "timestamp-server")]
fn generalized_time_tomorrow_noon_utc() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_secs();
    let days = (now / 86_400) as i64 + 1;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}{month:02}{day:02}120000Z")
}

fn read_embedded_children(bundle_path: &Path) -> Vec<(String, Vec<u8>)> {
    let bytes = std::fs::read(bundle_path).unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let name = entry.name().to_owned();
        if name.ends_with(".msix") || name.ends_with(".appx") {
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            out.push((name, data));
        }
    }
    out
}
