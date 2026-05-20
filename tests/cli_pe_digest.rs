//! End-to-end CLI smoke test (runs on Linux CI).

use assert_cmd::Command;
use predicates::prelude::*;
use psign_authenticode_trust::pe_first_pkcs7_terminal_root;
use psign_authenticode_trust::{inspect_authenticode_pkcs7_der, inspect_pe_authenticode};
use psign_sip_digest::cab_digest;
use psign_sip_digest::catalog_digest;
use psign_sip_digest::msi_digest;
use psign_sip_digest::pkcs7;
use psign_sip_digest::rdp;
use psign_sip_digest::verify_pe;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::signature::Keypair;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

fn portable_cmd() -> Command {
    let mut cmd = Command::cargo_bin("psign-tool").unwrap();
    cmd.arg("portable");
    cmd
}

#[test]
fn binary_reports_name_and_version_flag() {
    let mut cmd = portable_cmd();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("psign-tool"))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_core_subcommands() {
    let mut cmd = portable_cmd();
    cmd.arg("--help");
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help output");
    for needle in [
        "pe-digest",
        "pe-checksum",
        "verify-pe",
        "trust-verify-pe",
        "trust-verify-cab",
        "trust-verify-catalog",
        "trust-verify-detached",
        "verify-cab",
        "extract-cab-pkcs7",
        "cab-signer-rs256-prehash",
        "verify-msi",
        "extract-msi-pkcs7",
        "msi-signer-rs256-prehash",
        "verify-esd",
        "verify-msix",
        "verify-catalog",
        "verify-catalog-member",
        "catalog-signer-rs256-prehash",
        "verify-script",
        "cab-digest",
        "pe-has-page-hashes",
        "pe-page-hash-info",
        "verify-pe-page-hashes",
        "pe-authenticode-ranges",
        "artifact-signing-metadata-check",
        "inspect-authenticode",
        "inspect-pe-spc-indirect",
        "extract-pe-pkcs7",
        "list-pe-pkcs7",
        "pe-signer-rs256-prehash",
        "pkcs7-signer-rs256-prehash",
        "append-pe-pkcs7",
        "sign-pe",
        "sign-cab",
        "sign-msi",
        "sign-catalog",
        "timestamp-pe-rfc3161",
        "rdp",
        "nupkg-signature-info",
        "nupkg-digest",
        "vsix-signature-info",
        "rfc3161-timestamp-req",
        "rfc3161-timestamp-resp-inspect",
    ] {
        assert!(
            out.contains(needle),
            "help output should mention subcommand {needle:?}"
        );
    }
}

#[test]
fn nupkg_signature_info_detects_root_signature_marker() {
    let package = package_fixture("signed/sample.signed.nupkg");

    let mut cmd = portable_cmd();
    cmd.arg("nupkg-signature-info").arg(&package);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"))
        .stdout(predicate::str::contains("signature_file=.signature.p7s"))
        .stdout(predicate::str::contains("signature_len="))
        .stdout(predicate::str::contains("signature_stored=yes"));
}

#[test]
fn snupkg_signature_info_detects_root_signature_marker() {
    let package = package_fixture("signed/sample.signed.snupkg");

    let mut cmd = portable_cmd();
    cmd.arg("nupkg-signature-info").arg(&package);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signed=yes"))
        .stdout(predicate::str::contains("signature_file=.signature.p7s"))
        .stdout(predicate::str::contains("signature_len="))
        .stdout(predicate::str::contains("signature_stored=yes"));
}

#[test]
fn nupkg_digest_matches_unsigned_package_bytes() {
    let package = package_fixture("unsigned/sample.nupkg");
    let expected = hex_lower(&Sha256::digest(std::fs::read(&package).unwrap()));

    let mut cmd = portable_cmd();
    cmd.arg("nupkg-digest")
        .arg(&package)
        .arg("--algorithm")
        .arg("sha256");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected));
}

#[test]
fn snupkg_digest_matches_unsigned_package_bytes() {
    let package = package_fixture("unsigned/sample.snupkg");
    let expected = hex_lower(&Sha256::digest(std::fs::read(&package).unwrap()));

    let mut cmd = portable_cmd();
    cmd.arg("nupkg-digest")
        .arg(&package)
        .arg("--algorithm")
        .arg("sha256");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(expected));
}

#[test]
fn nupkg_digest_rejects_signed_package_fixture() {
    let package = package_fixture("signed/sample.signed.nupkg");

    let mut cmd = portable_cmd();
    cmd.arg("nupkg-digest")
        .arg(&package)
        .arg("--algorithm")
        .arg("sha256");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("already contains .signature.p7s"));
}

#[test]
fn vsix_signature_info_detects_opc_signature_parts() {
    let package = package_fixture("signed/sample.signed.vsix");

    let mut cmd = portable_cmd();
    cmd.arg("vsix-signature-info").arg(&package);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("opc_signature=yes"))
        .stdout(predicate::str::contains(
            "signature_origin=package/services/digital-signature/origin.psdsor",
        ))
        .stdout(predicate::str::contains("signature_parts=1"))
        .stdout(predicate::str::contains(
            "signature_part=package/services/digital-signature/xml-signature/",
        ));
}

fn package_fixture(rel: &str) -> PathBuf {
    let separator = std::path::MAIN_SEPARATOR.to_string();
    repo_root()
        .join("tests/fixtures/package-signing")
        .join(rel.replace('/', &separator))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn rdp_embeds_external_pkcs7_signature_for_text_encodings() {
    let repo = repo_root();
    let dir = tempfile::tempdir().unwrap();
    let pkcs7 = dir.path().join("sig.p7b");
    std::fs::write(&pkcs7, b"pkcs7").unwrap();

    for name in [
        "unsigned-utf8.rdp",
        "unsigned-utf8-bom.rdp",
        "unsigned-utf16le-bom.rdp",
        "unsigned-utf16le-nobom.rdp",
        "unsigned-utf16be-bom.rdp",
        "unsigned-utf16be-nobom.rdp",
        "partial-signed-scope.rdp",
        "with-stale-signature.rdp",
        "malformed-lines.rdp",
    ] {
        let fixture = repo.join("tests/fixtures/rdp").join(name);
        let out = dir.path().join(format!("{name}.signed.rdp"));
        let mut cmd = portable_cmd();
        cmd.arg("rdp")
            .arg("--signature-pkcs7")
            .arg(&pkcs7)
            .arg("--output")
            .arg(&out)
            .arg(&fixture);
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Signed"));

        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(&bytes[..2], &[0xFF, 0xFE], "output BOM for {name}");
        let text = rdp::decode_rdp_text(&bytes);
        assert!(
            text.contains("SignScope:s:Full Address,Alternate Full Address,Server Port"),
            "SignScope in {name}: {text}"
        );
        assert!(
            text.contains("Signature:s:AQABAAEAAAAFAAAAcGtjczc="),
            "Signature in {name}: {text}"
        );
        assert!(
            !text.contains("stale"),
            "stale partial signature should be replaced in {name}: {text}"
        );
    }
}

#[test]
fn rdp_rejects_malformed_missing_full_address() {
    let repo = repo_root();
    let dir = tempfile::tempdir().unwrap();
    let pkcs7 = dir.path().join("sig.p7b");
    let out = dir.path().join("signed.rdp");
    std::fs::write(&pkcs7, b"pkcs7").unwrap();

    let mut cmd = portable_cmd();
    cmd.arg("rdp")
        .arg("--signature-pkcs7")
        .arg(&pkcs7)
        .arg("--output")
        .arg(&out)
        .arg(repo.join("tests/fixtures/rdp/missing-full-address.rdp"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Full Address"));
    assert!(!out.exists());
}

#[test]
fn rdp_portable_cert_key_signs_with_detached_pkcs7() {
    let repo = repo_root();
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.der");
    let key = dir.path().join("key.pk8");
    let out = dir.path().join("signed.rdp");
    write_test_rsa_cert_key(&cert, &key);

    let mut cmd = portable_cmd();
    cmd.arg("rdp")
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--output")
        .arg(&out)
        .arg(repo.join("tests/fixtures/rdp/unsigned-utf8.rdp"));
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Signed"));

    let bytes = std::fs::read(&out).unwrap();
    let records = rdp::parse_records(&rdp::decode_rdp_text(&bytes));
    let pkcs7_der = rdp::signature_record_pkcs7(&records).expect("Signature record");
    let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7_der).expect("PKCS#7 SignedData");
    let si = sd.signer_infos.0.as_slice().first().expect("signer info");
    let message_digest = pkcs7::signer_info_pkcs9_message_digest_octets(si).expect("messageDigest");
    let mut unsigned = records.clone();
    unsigned.retain(|r| !r.name.eq_ignore_ascii_case("Signature"));
    let sign_scope = unsigned
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case("SignScope"))
        .expect("SignScope")
        .value
        .clone();
    let secure_blob = rdp::secure_settings_blob(&unsigned, &sign_scope).expect("secure blob");
    assert_eq!(message_digest, Sha256::digest(&secure_blob).as_slice());
}

fn write_test_rsa_cert_key(cert_path: &Path, key_path: &Path) {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa private key");
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let subject = Name::from_str("CN=psign portable rdp test").expect("subject name");
    let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key())
        .expect("subject public key info");
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(42u32),
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

#[test]
fn generated_signed_corpus_verifies_with_portable_cli() {
    let repo = repo_root();
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(
            repo.join("tests/fixtures/generated-signed/generated-signed-vectors.json"),
        )
        .expect("read signed corpus manifest"),
    )
    .expect("signed corpus manifest JSON");
    let signed = manifest["signed"]
        .as_array()
        .expect("signed corpus entries");
    assert_eq!(signed.len(), 103, "signed corpus coverage changed");

    let mut verified = 0usize;
    for entry in signed {
        let id = entry["id"].as_str().expect("entry id");
        let family = entry["family"].as_str().expect("entry family");
        let state = entry["state"].as_str().expect("entry state");
        if state == "detached-signed" {
            let content = repo_path(&repo, entry["source_path"].as_str().expect("source path"));
            let signature = repo_path(&repo, entry["path"].as_str().expect("signature path"));
            let mut cmd = portable_cmd();
            cmd.arg("trust-verify-detached")
                .arg(content)
                .arg(signature)
                .arg("--anchor-dir")
                .arg(anchor_dir(&repo));
            cmd.assert().success();
            verified += 1;
            continue;
        }
        if state == "package-signature-extracted" {
            let path = repo_path(&repo, entry["path"].as_str().expect("entry path"));
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {id}: {e}"));
            assert!(
                bytes.starts_with(b"PKCX"),
                "extracted AppxSignature.p7x fixture must start with PKCX header: {id}"
            );
            continue;
        }

        let path = repo_path(&repo, entry["path"].as_str().expect("entry path"));
        let mut cmd = portable_cmd();
        match family {
            "pe" | "winmd" => {
                cmd.arg("trust-verify-pe")
                    .arg(path)
                    .arg("--anchor-dir")
                    .arg(anchor_dir(&repo));
            }
            "cab" => {
                cmd.arg("trust-verify-cab")
                    .arg(path)
                    .arg("--anchor-dir")
                    .arg(anchor_dir(&repo));
            }
            "catalog" => {
                cmd.arg("trust-verify-catalog")
                    .arg(path)
                    .arg("--anchor-dir")
                    .arg(anchor_dir(&repo));
            }
            "wim-esd" => {
                cmd.arg("trust-verify-esd")
                    .arg(path)
                    .arg("--anchor-dir")
                    .arg(anchor_dir(&repo));
            }
            "msix" => {
                cmd.arg("verify-msix").arg(path);
            }
            "powershell-script" | "wsh-script" => {
                cmd.arg("verify-script").arg(path);
            }
            "installer" => {
                cmd.arg("trust-verify-msi")
                    .arg(path)
                    .arg("--anchor-dir")
                    .arg(anchor_dir(&repo));
            }
            _ => panic!("unexpected signed corpus family for portable test: {family} ({id})"),
        }
        cmd.assert().success();
        verified += 1;
    }

    assert_eq!(
        verified, 102,
        "portable corpus verification coverage changed"
    );
}

#[test]
fn signer_rs256_prehash_help_documents_signer_index_pe_subcommand() {
    let mut cmd = portable_cmd();
    cmd.args(["pe-signer-rs256-prehash", "--help"]);
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help");
    assert!(
        out.contains("signer-index"),
        "pe-signer-rs256-prehash --help should list --signer-index; got:\n{out}"
    );
}

#[test]
fn signer_rs256_prehash_help_documents_signer_index_pkcs7_subcommand() {
    let mut cmd = portable_cmd();
    cmd.args(["pkcs7-signer-rs256-prehash", "--help"]);
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help");
    assert!(
        out.contains("signer-index"),
        "pkcs7-signer-rs256-prehash --help should list --signer-index; got:\n{out}"
    );
}

fn decode_hex_lower(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "even hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn assert_pe_signer_rs256_prehash_raw_matches_library(fixture: &std::path::Path) {
    let bytes = std::fs::read(fixture).unwrap();
    let pkcs7 = verify_pe::pe_nth_pkcs7_signed_data_der(&bytes, 0).unwrap();
    let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7).unwrap();
    let si = sd.signer_infos.0.as_slice().first().unwrap();
    let expected = pkcs7::signer_info_sha256_digest_over_signed_attrs(si).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("prehash.bin");
    let mut cmd = portable_cmd();
    cmd.args([
        "pe-signer-rs256-prehash",
        "--signer-index",
        "0",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(&out)
    .arg(fixture);
    cmd.assert().success();
    assert_eq!(std::fs::read(&out).unwrap(), expected);
}

#[test]
fn pe_signer_rs256_prehash_raw_matches_pkcs7_library_tiny32() {
    assert_pe_signer_rs256_prehash_raw_matches_library(tiny32_fixture().as_path());
}

#[test]
fn pe_signer_rs256_prehash_raw_matches_pkcs7_library_tiny64() {
    assert_pe_signer_rs256_prehash_raw_matches_library(tiny64_fixture().as_path());
}

fn assert_pkcs7_signer_rs256_prehash_matches_pe_signer_after_extract(fixture: &std::path::Path) {
    let dir = tempfile::tempdir().unwrap();
    let pkcs7_path = dir.path().join("extracted.p7");
    let mut ext = portable_cmd();
    ext.arg("extract-pe-pkcs7")
        .arg(fixture)
        .arg("--output")
        .arg(&pkcs7_path);
    ext.assert().success();

    let out_pkcs7 = dir.path().join("prehash_pkcs7.bin");
    let mut pkcs7_cmd = portable_cmd();
    pkcs7_cmd
        .args([
            "pkcs7-signer-rs256-prehash",
            "--signer-index",
            "0",
            "--encoding",
            "raw",
            "--output",
        ])
        .arg(&out_pkcs7)
        .arg(&pkcs7_path);
    pkcs7_cmd.assert().success();

    let out_pe = dir.path().join("prehash_pe.bin");
    let mut pe_cmd = portable_cmd();
    pe_cmd
        .args([
            "pe-signer-rs256-prehash",
            "--signer-index",
            "0",
            "--encoding",
            "raw",
            "--output",
        ])
        .arg(&out_pe)
        .arg(fixture);
    pe_cmd.assert().success();

    assert_eq!(
        std::fs::read(&out_pkcs7).unwrap(),
        std::fs::read(&out_pe).unwrap(),
        "pkcs7-signer-rs256-prehash on extracted PKCS#7 must match pe-signer-rs256-prehash"
    );
}

#[test]
fn pkcs7_signer_rs256_prehash_matches_pe_signer_after_extract_tiny32() {
    assert_pkcs7_signer_rs256_prehash_matches_pe_signer_after_extract(tiny32_fixture().as_path());
}

#[test]
fn pkcs7_signer_rs256_prehash_matches_pe_signer_after_extract_tiny64() {
    assert_pkcs7_signer_rs256_prehash_matches_pe_signer_after_extract(tiny64_fixture().as_path());
}

#[test]
fn pe_signer_rs256_prehash_fails_when_signer_index_out_of_range_tiny32() {
    let mut cmd = portable_cmd();
    cmd.args([
        "pe-signer-rs256-prehash",
        "--signer-index",
        "99",
        "--encoding",
        "raw",
    ])
    .arg(tiny32_fixture());
    cmd.assert().failure();
}

/// Minimal MSCF CAB without reserve / signature tail (same shape as `cab_digest` unit tests).
fn minimal_unsigned_cab_bytes() -> Vec<u8> {
    let mut data = vec![0u8; 48];
    data[0..4].copy_from_slice(b"MSCF");
    data[8..12].copy_from_slice(&100u32.to_le_bytes());
    data
}

#[test]
fn cab_rs256_extract_errors_unsigned_cab_cli() {
    let dir = tempfile::tempdir().unwrap();
    let cab = dir.path().join("unsigned.cab");
    std::fs::write(&cab, minimal_unsigned_cab_bytes()).unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("extract-cab-pkcs7").arg(&cab);
    cmd.assert().failure();
}

#[test]
fn cab_rs256_signer_errors_unsigned_cab_cli() {
    let dir = tempfile::tempdir().unwrap();
    let cab = dir.path().join("unsigned.cab");
    std::fs::write(&cab, minimal_unsigned_cab_bytes()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["cab-signer-rs256-prehash", "--encoding", "raw"])
        .arg(&cab);
    cmd.assert().failure();
}

fn tiny_signed_cab_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cab-authenticode-upstream/tiny-signed.cab")
}

#[test]
fn cab_rs256_extract_pkcs7_stdout_matches_library_tiny_signed_cab() {
    let cab_bytes = std::fs::read(tiny_signed_cab_fixture()).unwrap();
    let expected = cab_digest::cab_signature_pkcs7_der(&cab_bytes)
        .expect("cab pkcs7")
        .to_vec();
    let mut cmd = portable_cmd();
    cmd.arg("extract-cab-pkcs7").arg(tiny_signed_cab_fixture());
    let assert = cmd.assert().success();
    assert_eq!(
        assert.get_output().stdout.as_slice(),
        expected.as_slice(),
        "extract-cab-pkcs7 stdout must match cab_signature_pkcs7_der"
    );
}

#[test]
fn cab_rs256_signer_matches_library_tiny_signed_cab() {
    let cab_bytes = std::fs::read(tiny_signed_cab_fixture()).unwrap();
    let pkcs7 = cab_digest::cab_signature_pkcs7_der(&cab_bytes).expect("cab pkcs7");
    let sd = pkcs7::parse_pkcs7_signed_data_der(pkcs7).expect("SignedData");
    let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
    let expected = pkcs7::signer_info_sha256_digest_over_signed_attrs(si).expect("prehash");

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("prehash.bin");
    let mut cmd = portable_cmd();
    cmd.args([
        "cab-signer-rs256-prehash",
        "--signer-index",
        "0",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(&out)
    .arg(tiny_signed_cab_fixture());
    cmd.assert().success();
    assert_eq!(std::fs::read(&out).unwrap(), expected);
}

#[test]
fn cab_rs256_signer_matches_pkcs7_cli_after_extract_tiny_signed_cab() {
    let dir = tempfile::tempdir().unwrap();
    let pkcs7_path = dir.path().join("cab.p7");
    let mut ext = portable_cmd();
    ext.arg("extract-cab-pkcs7")
        .arg(tiny_signed_cab_fixture())
        .arg("--output")
        .arg(&pkcs7_path);
    ext.assert().success();

    let out_cab = dir.path().join("from_cab.bin");
    let mut cab_cmd = portable_cmd();
    cab_cmd
        .args(["cab-signer-rs256-prehash", "--encoding", "raw", "--output"])
        .arg(&out_cab)
        .arg(tiny_signed_cab_fixture());
    cab_cmd.assert().success();

    let out_pkcs7 = dir.path().join("from_pkcs7.bin");
    let mut pk7 = portable_cmd();
    pk7.args([
        "pkcs7-signer-rs256-prehash",
        "--signer-index",
        "0",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(&out_pkcs7)
    .arg(&pkcs7_path);
    pk7.assert().success();

    assert_eq!(
        std::fs::read(&out_cab).unwrap(),
        std::fs::read(&out_pkcs7).unwrap(),
        "cab-signer-rs256-prehash must match pkcs7-signer-rs256-prehash on extracted CAB PKCS#7"
    );
}

#[test]
fn cab_rs256_verify_cab_digest_ok_tiny_signed_cab() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-cab").arg(tiny_signed_cab_fixture());
    cmd.assert().success();
}

fn tiny_msi_pkcs7_stub_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi")
}

#[test]
fn msi_rs256_extract_errors_non_ole_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("not.msi");
    std::fs::write(&p, b"not ole").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("extract-msi-pkcs7").arg(&p);
    cmd.assert().failure();
}

fn tiny32_pe_pkcs7_as_cat_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/catalog-authenticode-upstream/tiny32-content.cat")
}

#[test]
fn cat_rs256_verify_catalog_fails_on_pe_pkcs7_as_cat() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-catalog")
        .arg(tiny32_pe_pkcs7_as_cat_fixture());
    cmd.assert().failure();
}

#[test]
fn verify_catalog_member_accepts_makecat_single_member_fixtures() {
    for (catalog, subject) in [
        ("single-pe.cat", "tiny32.efi"),
        ("single-text.cat", "hello.txt"),
        ("single-binary.cat", "blob.bin"),
    ] {
        let mut cmd = portable_cmd();
        cmd.arg("verify-catalog-member")
            .arg("--catalog")
            .arg(catalog_workflow_fixture(catalog))
            .arg(catalog_workflow_subject(subject));
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("verify-catalog-member: ok"))
            .stdout(predicate::str::contains(subject));
    }
}

#[test]
fn verify_catalog_member_accepts_makecat_multi_member_fixture() {
    for subject in ["tiny32.efi", "hello.txt", "blob.bin"] {
        let mut cmd = portable_cmd();
        cmd.arg("verify-catalog-member")
            .arg("--catalog")
            .arg(catalog_workflow_fixture("multi-member.cat"))
            .arg(catalog_workflow_subject(subject));
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("verify-catalog-member: ok"))
            .stdout(predicate::str::contains(subject));
    }
}

#[test]
fn verify_catalog_member_rejects_subject_not_in_catalog() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-catalog-member")
        .arg("--catalog")
        .arg(catalog_workflow_fixture("single-text.cat"))
        .arg(catalog_workflow_subject("blob.bin"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a member"));
}

#[test]
fn sign_catalog_creates_portable_catalog_with_members() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("signer.der");
    let key = dir.path().join("signer.pk8");
    let out_cat = dir.path().join("portable.cat");
    write_test_rsa_cert_key(&cert, &key);
    let subjects = [
        tiny32_unsigned_fixture(),
        catalog_workflow_subject("hello.txt"),
        catalog_workflow_subject("blob.bin"),
    ];

    let mut sign = portable_cmd();
    sign.arg("sign-catalog")
        .arg(subjects[0].as_path())
        .arg(subjects[1].as_path())
        .arg(subjects[2].as_path())
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--output")
        .arg(&out_cat);
    sign.assert()
        .success()
        .stdout(predicate::str::contains("sign-catalog: ok"))
        .stdout(predicate::str::contains("members=3"));

    let mut verify = portable_cmd();
    verify.arg("verify-catalog").arg(&out_cat);
    verify.assert().success();

    for subject in &subjects {
        let mut member = portable_cmd();
        member
            .arg("verify-catalog-member")
            .arg("--catalog")
            .arg(&out_cat)
            .arg(subject);
        member
            .assert()
            .success()
            .stdout(predicate::str::contains("verify-catalog-member: ok"));
    }

    let cat = std::fs::read(&out_cat).expect("read catalog");
    let members = catalog_digest::catalog_members_bytes(&cat).expect("catalog members");
    assert_eq!(members.len(), 3);
    let econtent_digest = catalog_digest::catalog_econtent_digest(&cat).expect("eContent digest");
    let sd = pkcs7::parse_pkcs7_signed_data_der(&cat).expect("catalog SignedData");
    pkcs7::verify_signed_data_pkcs9_message_digest_and_rsa_sha256_pkcs1v15_signature(
        &sd,
        0,
        &econtent_digest,
    )
    .expect("portable catalog RSA signature verifies");
}

#[test]
fn cat_rs256_signer_matches_pkcs7_cli_on_tiny32_content_cat() {
    let dir = tempfile::tempdir().unwrap();
    let out_cat = dir.path().join("from_cat.bin");
    let mut cat_cmd = portable_cmd();
    cat_cmd
        .args([
            "catalog-signer-rs256-prehash",
            "--encoding",
            "raw",
            "--output",
        ])
        .arg(&out_cat)
        .arg(tiny32_pe_pkcs7_as_cat_fixture());
    cat_cmd.assert().success();

    let out_pkcs7 = dir.path().join("from_pkcs7.bin");
    let mut pk7 = portable_cmd();
    pk7.args([
        "pkcs7-signer-rs256-prehash",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(&out_pkcs7)
    .arg(tiny32_pe_pkcs7_as_cat_fixture());
    pk7.assert().success();

    assert_eq!(
        std::fs::read(&out_cat).unwrap(),
        std::fs::read(&out_pkcs7).unwrap()
    );
}

#[test]
fn cat_rs256_signer_matches_pe_signer_tiny32() {
    let dir = tempfile::tempdir().unwrap();
    let out_pe = dir.path().join("pe.bin");
    let mut pe_cmd = portable_cmd();
    pe_cmd
        .args([
            "pe-signer-rs256-prehash",
            "--signer-index",
            "0",
            "--encoding",
            "raw",
            "--output",
        ])
        .arg(&out_pe)
        .arg(tiny32_fixture());
    pe_cmd.assert().success();

    let out_cat = dir.path().join("cat.bin");
    let mut cat_cmd = portable_cmd();
    cat_cmd
        .args([
            "catalog-signer-rs256-prehash",
            "--encoding",
            "raw",
            "--output",
        ])
        .arg(&out_cat)
        .arg(tiny32_pe_pkcs7_as_cat_fixture());
    cat_cmd.assert().success();

    assert_eq!(
        std::fs::read(&out_pe).unwrap(),
        std::fs::read(&out_cat).unwrap(),
        "catalog fixture is same PKCS#7 as first PE row — RS256 prehash must match"
    );

    let lib_cat = std::fs::read(tiny32_pe_pkcs7_as_cat_fixture()).unwrap();
    let via_lib =
        catalog_digest::catalog_rsa_sha256_signer_prehash_digest(&lib_cat, 0).expect("lib");
    assert_eq!(std::fs::read(&out_cat).unwrap(), via_lib);
}

#[test]
fn msi_rs256_verify_msi_fails_on_pkcs7_stub() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-msi").arg(tiny_msi_pkcs7_stub_fixture());
    cmd.assert().failure();
}

#[test]
fn msi_rs256_extract_pkcs7_stdout_matches_library_stub() {
    let msi_bytes = std::fs::read(tiny_msi_pkcs7_stub_fixture()).unwrap();
    let expected = msi_digest::msi_digital_signature_pkcs7_der(&msi_bytes).expect("lib");
    let mut cmd = portable_cmd();
    cmd.arg("extract-msi-pkcs7")
        .arg(tiny_msi_pkcs7_stub_fixture());
    let assert = cmd.assert().success();
    assert_eq!(assert.get_output().stdout.as_slice(), expected.as_slice());
}

#[test]
fn msi_rs256_signer_matches_pe_signer_tiny32_and_stub() {
    let dir = tempfile::tempdir().unwrap();
    let out_pe = dir.path().join("pe.bin");
    let mut pe_cmd = portable_cmd();
    pe_cmd
        .args([
            "pe-signer-rs256-prehash",
            "--signer-index",
            "0",
            "--encoding",
            "raw",
            "--output",
        ])
        .arg(&out_pe)
        .arg(tiny32_fixture());
    pe_cmd.assert().success();

    let out_msi = dir.path().join("msi.bin");
    let mut msi_cmd = portable_cmd();
    msi_cmd
        .args([
            "msi-signer-rs256-prehash",
            "--signer-index",
            "0",
            "--encoding",
            "raw",
            "--output",
        ])
        .arg(&out_msi)
        .arg(tiny_msi_pkcs7_stub_fixture());
    msi_cmd.assert().success();

    assert_eq!(
        std::fs::read(&out_pe).unwrap(),
        std::fs::read(&out_msi).unwrap(),
        "msi stub must carry same RS256 prehash as tiny32 PE (same PKCS#7 bytes)"
    );
}

#[test]
fn msi_rs256_signer_matches_pkcs7_cli_after_extract_stub() {
    let dir = tempfile::tempdir().unwrap();
    let pkcs7_path = dir.path().join("sig.p7");
    let mut ext = portable_cmd();
    ext.arg("extract-msi-pkcs7")
        .arg(tiny_msi_pkcs7_stub_fixture())
        .arg("--output")
        .arg(&pkcs7_path);
    ext.assert().success();

    let out_msi = dir.path().join("from_msi.bin");
    let mut msi_cmd = portable_cmd();
    msi_cmd
        .args(["msi-signer-rs256-prehash", "--encoding", "raw", "--output"])
        .arg(&out_msi)
        .arg(tiny_msi_pkcs7_stub_fixture());
    msi_cmd.assert().success();

    let out_pkcs7 = dir.path().join("from_pkcs7.bin");
    let mut pk7 = portable_cmd();
    pk7.args([
        "pkcs7-signer-rs256-prehash",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(&out_pkcs7)
    .arg(&pkcs7_path);
    pk7.assert().success();

    assert_eq!(
        std::fs::read(&out_msi).unwrap(),
        std::fs::read(&out_pkcs7).unwrap()
    );
}

#[test]
fn pe_digest_raw_output_file_matches_known_sha256_tiny32() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("digest.bin");
    let mut cmd = portable_cmd();
    cmd.args([
        "pe-digest",
        "--algorithm",
        "sha256",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(&out)
    .arg(tiny32_fixture());
    cmd.assert().success();
    let raw = std::fs::read(&out).unwrap();
    assert_eq!(raw.len(), 32);
    let expected_hex = "4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8";
    assert_eq!(raw, decode_hex_lower(expected_hex));
}

#[cfg(feature = "azure-kv-sign")]
#[test]
fn help_lists_azure_key_vault_sign_digest_when_feature_enabled() {
    let mut cmd = portable_cmd();
    cmd.arg("--help");
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help");
    assert!(
        out.contains("azure-key-vault-sign-digest"),
        "help should list azure-key-vault-sign-digest when built with azure-kv-sign-portable"
    );
}

#[cfg(feature = "artifact-signing-rest")]
#[test]
fn help_lists_artifact_signing_submit_when_feature_enabled() {
    let mut cmd = portable_cmd();
    cmd.arg("--help");
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help");
    assert!(
        out.contains("artifact-signing-submit"),
        "help should list artifact-signing-submit when built with artifact-signing-rest"
    );
}

fn tiny32_fixture() -> PathBuf {
    repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
}

fn tiny32_unsigned_fixture() -> PathBuf {
    repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny32.efi")
}

fn tiny64_fixture() -> PathBuf {
    repo_root().join("tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi")
}

fn catalog_workflow_fixture(name: &str) -> PathBuf {
    repo_root()
        .join("tests/fixtures/catalog-workflows")
        .join(name)
}

fn catalog_workflow_subject(name: &str) -> PathBuf {
    catalog_workflow_fixture("subjects").join(name)
}

fn minimal_unsigned_cab_fixture_bytes() -> Vec<u8> {
    let name = b"a.txt\0";
    let payload = b"hi";
    let coff_files = 44usize;
    let cfdata_offset = coff_files + 16 + name.len();
    let cb_cabinet = cfdata_offset + 8 + payload.len();
    let mut cab = vec![0u8; cb_cabinet];
    cab[0..4].copy_from_slice(b"MSCF");
    cab[8..12].copy_from_slice(&(cb_cabinet as u32).to_le_bytes());
    cab[16..20].copy_from_slice(&(coff_files as u32).to_le_bytes());
    cab[24] = 3;
    cab[25] = 1;
    cab[26..28].copy_from_slice(&1u16.to_le_bytes());
    cab[28..30].copy_from_slice(&1u16.to_le_bytes());
    cab[32..34].copy_from_slice(&1u16.to_le_bytes());
    cab[36..40].copy_from_slice(&(cfdata_offset as u32).to_le_bytes());
    cab[40..42].copy_from_slice(&1u16.to_le_bytes());
    cab[44..48].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    cab[58..60].copy_from_slice(&0x20u16.to_le_bytes());
    cab[60..60 + name.len()].copy_from_slice(name);
    cab[cfdata_offset + 4..cfdata_offset + 6]
        .copy_from_slice(&(payload.len() as u16).to_le_bytes());
    cab[cfdata_offset + 6..cfdata_offset + 8]
        .copy_from_slice(&(payload.len() as u16).to_le_bytes());
    cab[cfdata_offset + 8..cfdata_offset + 8 + payload.len()].copy_from_slice(payload);
    cab
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(repo_root: &Path, rel: &str) -> PathBuf {
    let separator = std::path::MAIN_SEPARATOR.to_string();
    repo_root.join(rel.replace('\\', &separator))
}

fn anchor_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("tests/fixtures/devolutions-authenticode")
}

#[test]
fn pe_checksum_tiny32_reports_match_and_strict_ok() {
    let fixture = tiny32_fixture();
    let mut cmd = portable_cmd();
    cmd.arg("pe-checksum").arg(&fixture);
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    assert!(
        out.contains("match=yes"),
        "expected match=yes on signed fixture, got {out:?}"
    );

    let mut strict = portable_cmd();
    strict.arg("pe-checksum").arg("--strict").arg(&fixture);
    strict.assert().success();
}

#[test]
fn pe_digest_sha256_tiny32_matches_upstream_golden_fixture() {
    let fixture = tiny32_fixture();
    let mut cmd = portable_cmd();
    cmd.args(["pe-digest", "--algorithm", "sha256"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout("4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8\n");
}

#[test]
fn pe_digest_sha256_tiny64_matches_upstream_golden_fixture() {
    let fixture = tiny64_fixture();
    let mut cmd = portable_cmd();
    cmd.args(["pe-digest", "--algorithm", "sha256"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout("a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae\n");
}

#[test]
fn trust_verify_pe_succeeds_with_extracted_embedded_root_anchor() {
    let fixture = tiny32_fixture();
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    let der = root.to_der().expect("root DER");
    std::fs::write(dir.path().join("anchor.crt"), der).expect("write anchor");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-pe")
        .arg("--anchor-dir")
        .arg(dir.path())
        .args(["--as-of", "2023-07-01"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-pe: ok"));
}

#[test]
fn unified_verify_mode_portable_accepts_trusted_ca_without_os_store() {
    let fixture = tiny32_fixture();
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    let root_path = dir.path().join("root.cer");
    std::fs::write(&root_path, root.to_der().expect("root DER")).expect("write anchor");

    let mut cmd = Command::cargo_bin("psign-tool").unwrap();
    cmd.arg("--mode")
        .arg("portable")
        .arg("verify")
        .arg("--trusted-ca")
        .arg(&root_path)
        .arg("--verbose-chain")
        .arg("--allow-loose-signing-cert")
        .arg("--prefer-timestamp-signing-time")
        .args(["--online-timeout-secs", "7"])
        .args(["--online-max-download-bytes", "2048"])
        .args(["--as-of", "2023-07-01"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-pe: ok"));
}

#[test]
fn trust_verify_pe_ok_with_prefer_timestamp_signing_time_and_as_of() {
    let fixture = tiny32_fixture();
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    let der = root.to_der().expect("root DER");
    std::fs::write(dir.path().join("anchor.crt"), der).expect("write anchor");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-pe")
        .arg("--anchor-dir")
        .arg(dir.path())
        .arg("--prefer-timestamp-signing-time")
        .args(["--as-of", "2023-07-01"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-pe: ok"));
}

/// **`--require-valid-timestamp`** now requires a cryptographically trusted RFC3161 token;
/// PKCS#9 **`signing-time`** alone remains usable only for non-required instant selection.
#[test]
fn trust_verify_pe_require_valid_timestamp_rejects_pkcs9_only_tiny32() {
    let fixture = tiny32_fixture();
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    let der = root.to_der().expect("root DER");
    std::fs::write(dir.path().join("anchor.crt"), der).expect("write anchor");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-pe")
        .arg("--anchor-dir")
        .arg(dir.path())
        .arg("--prefer-timestamp-signing-time")
        .arg("--require-valid-timestamp")
        .arg(&fixture);
    cmd.assert().failure().stderr(predicate::str::contains(
        "no cryptographically valid trusted RFC3161 timestamp token",
    ));
}

/// Same strict **`--require-valid-timestamp`** behavior as **`tiny32`**, on **`tiny64.signed.efi`**.
#[test]
fn trust_verify_pe_require_valid_timestamp_rejects_pkcs9_only_tiny64() {
    let fixture = tiny64_fixture();
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    let der = root.to_der().expect("root DER");
    std::fs::write(dir.path().join("anchor.crt"), der).expect("write anchor");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-pe")
        .arg("--anchor-dir")
        .arg(dir.path())
        .arg("--prefer-timestamp-signing-time")
        .arg("--require-valid-timestamp")
        .arg(&fixture);
    cmd.assert().failure().stderr(predicate::str::contains(
        "no cryptographically valid trusted RFC3161 timestamp token",
    ));
}

#[test]
fn trust_verify_pe_errors_without_configured_anchors() {
    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-pe").arg(tiny32_fixture());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("no trust anchors"));
}

#[test]
fn verify_pe_pkcs7_indirect_digest_matches_on_tiny32_fixture() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-pe").arg(tiny32_fixture());
    cmd.assert().success();
}

#[test]
fn inspect_authenticode_pe_outputs_json_with_signers() {
    let mut cmd = portable_cmd();
    cmd.args(["inspect-authenticode", "--input", "pe"])
        .arg(tiny32_fixture());
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    let v: Value = serde_json::from_str(out.trim()).expect("inspect JSON");
    let entries = v
        .get("entries")
        .and_then(Value::as_array)
        .expect("top-level entries[]");
    assert!(
        !entries.is_empty(),
        "expected ≥1 attribute-cert PKCS#7 on signed PE fixture"
    );
    let pkcs7 = entries[0].get("pkcs7").expect("pkcs7 object");
    let signers = pkcs7
        .get("signers")
        .and_then(Value::as_array)
        .expect("signers[]");
    assert!(
        !signers.is_empty(),
        "expected ≥1 signer in outer SignedData"
    );
    assert!(
        pkcs7.get("nested_signatures").is_some(),
        "nested_signatures field should be present"
    );
}

#[test]
fn extract_pe_pkcs7_stdout_matches_verify_pe_helper() {
    let pe = std::fs::read(tiny32_fixture()).expect("read tiny32");
    let expected =
        psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der(&pe).expect("library extract");
    let mut cmd = portable_cmd();
    cmd.arg("extract-pe-pkcs7").arg(tiny32_fixture());
    let assert = cmd.assert().success();
    assert_eq!(
        assert.get_output().stdout.as_slice(),
        expected.as_slice(),
        "CLI stdout PKCS#7 must match verify_pe::pe_first_pkcs7_signed_data_der"
    );
}

#[test]
fn extract_pe_pkcs7_output_file_matches_verify_pe_helper() {
    let pe = std::fs::read(tiny32_fixture()).expect("read tiny32");
    let expected =
        psign_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der(&pe).expect("library extract");
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("embedded.p7");
    let mut cmd = portable_cmd();
    cmd.arg("extract-pe-pkcs7")
        .arg(tiny32_fixture())
        .arg("--output")
        .arg(&out_path);
    cmd.assert().success();
    let written = std::fs::read(&out_path).expect("read output");
    assert_eq!(written.as_slice(), expected.as_slice());
}

#[test]
fn list_pe_pkcs7_reports_single_entry_on_tiny_fixture() {
    let mut cmd = portable_cmd();
    cmd.arg("list-pe-pkcs7").arg(tiny32_fixture());
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    assert!(
        out.contains("pkcs7_entries=1"),
        "expected pkcs7_entries=1, got {out:?}"
    );
    assert!(
        out.contains("index=0 byte_len="),
        "expected index=0 line, got {out:?}"
    );
}

#[test]
fn extract_pe_pkcs7_index_out_of_range_fails() {
    let mut cmd = portable_cmd();
    cmd.arg("extract-pe-pkcs7")
        .arg(tiny32_fixture())
        .arg("--index")
        .arg("1");
    cmd.assert().failure();
}

#[test]
fn append_pe_pkcs7_duplicate_row_lists_two_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pe_copy = dir.path().join("a.exe");
    let pkcs7_path = dir.path().join("sig.der");
    let out_pe = dir.path().join("b.exe");
    std::fs::copy(tiny32_fixture(), &pe_copy).expect("copy fixture");

    let mut ext = portable_cmd();
    ext.arg("extract-pe-pkcs7")
        .arg(&pe_copy)
        .arg("--output")
        .arg(&pkcs7_path);
    ext.assert().success();

    let mut app = portable_cmd();
    app.arg("append-pe-pkcs7")
        .arg("--pe")
        .arg(&pe_copy)
        .arg("--pkcs7")
        .arg(&pkcs7_path)
        .arg("--output")
        .arg(&out_pe);
    app.assert().success();

    let mut lst = portable_cmd();
    lst.arg("list-pe-pkcs7").arg(&out_pe);
    let assert = lst.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    assert!(
        out.contains("pkcs7_entries=2"),
        "expected pkcs7_entries=2, got {out:?}"
    );

    let mut chk = portable_cmd();
    chk.arg("pe-checksum").arg("--strict").arg(&out_pe);
    let chk_assert = chk.assert().success();
    let chk_out = std::str::from_utf8(&chk_assert.get_output().stdout).expect("utf8");
    assert!(
        chk_out.contains("match=yes"),
        "append-pe-pkcs7 output should satisfy pe-checksum --strict, got {chk_out:?}"
    );
}

#[test]
fn sign_pe_creates_portable_authenticode_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("signer.der");
    let key = dir.path().join("signer.pk8");
    let out_pe = dir.path().join("tiny32.signed.exe");
    write_test_rsa_cert_key(&cert, &key);

    let mut sign = portable_cmd();
    sign.arg("sign-pe")
        .arg(tiny32_unsigned_fixture())
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--output")
        .arg(&out_pe);
    sign.assert()
        .success()
        .stdout(predicate::str::contains("sign-pe: ok"));

    let mut verify = portable_cmd();
    verify.arg("verify-pe").arg(&out_pe);
    verify.assert().success();

    let signed = std::fs::read(&out_pe).expect("read signed PE");
    let pkcs7 = verify_pe::pe_nth_pkcs7_signed_data_der(&signed, 0).expect("extract PKCS#7");
    let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7).expect("parse SignedData");
    let indirect = pkcs7::signed_data_spc_indirect_message_digest_octets(&sd).expect("indirect");
    pkcs7::verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
        &sd, 0, &indirect,
    )
    .expect("portable Authenticode RSA signature verifies");
}

#[test]
fn sign_cab_creates_portable_authenticode_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("signer.der");
    let key = dir.path().join("signer.pk8");
    let in_cab = dir.path().join("tiny.cab");
    let out_cab = dir.path().join("tiny.signed.cab");
    write_test_rsa_cert_key(&cert, &key);
    let unsigned = minimal_unsigned_cab_fixture_bytes();
    std::fs::write(&in_cab, &unsigned).expect("write unsigned CAB");

    let mut sign = portable_cmd();
    sign.arg("sign-cab")
        .arg(&in_cab)
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--output")
        .arg(&out_cab);
    sign.assert()
        .success()
        .stdout(predicate::str::contains("sign-cab: ok"));

    let mut verify = portable_cmd();
    verify.arg("verify-cab").arg(&out_cab);
    verify.assert().success();

    let signed = std::fs::read(&out_cab).expect("read signed CAB");
    let pkcs7 = cab_digest::cab_signature_pkcs7_der(&signed).expect("extract CAB PKCS#7");
    let sd = pkcs7::parse_pkcs7_signed_data_der(pkcs7).expect("parse SignedData");
    let indirect = pkcs7::signed_data_spc_indirect_message_digest_octets(&sd).expect("indirect");
    let expected = cab_digest::cab_authenticode_digest_for_signing(
        &unsigned,
        psign_sip_digest::pe_digest::PeAuthenticodeHashKind::Sha256,
    )
    .expect("CAB signing digest");
    assert_eq!(indirect, expected);
    pkcs7::verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
        &sd, 0, &indirect,
    )
    .expect("portable CAB Authenticode RSA signature verifies");
}

#[test]
fn sign_msi_creates_portable_authenticode_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("signer.der");
    let key = dir.path().join("signer.pk8");
    let input = repo_root().join("tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi");
    let out_msi = dir.path().join("tiny.signed.msi");
    write_test_rsa_cert_key(&cert, &key);

    let mut sign = portable_cmd();
    sign.arg("sign-msi")
        .arg(&input)
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--output")
        .arg(&out_msi);
    sign.assert()
        .success()
        .stdout(predicate::str::contains("sign-msi: ok"));

    let mut verify = portable_cmd();
    verify.arg("verify-msi").arg(&out_msi);
    verify.assert().success();

    let signed = std::fs::read(&out_msi).expect("read signed MSI");
    let pkcs7 = msi_digest::msi_digital_signature_pkcs7_der(&signed).expect("extract MSI PKCS#7");
    let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7).expect("parse SignedData");
    let indirect = pkcs7::signed_data_spc_indirect_message_digest_octets(&sd).expect("indirect");
    let expected = msi_digest::compute_msi_authenticode_digest(
        &signed,
        psign_sip_digest::pe_digest::PeAuthenticodeHashKind::Sha256,
    )
    .expect("MSI signing digest");
    assert_eq!(indirect, expected);
    pkcs7::verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
        &sd, 0, &indirect,
    )
    .expect("portable MSI Authenticode RSA signature verifies");
}

#[test]
fn remote_rsa_signature_injection_creates_authenticode_pkcs7() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("signer.der");
    let key_path = dir.path().join("signer.pk8");
    write_test_rsa_cert_key(&cert_path, &key_path);

    let pe = std::fs::read(tiny32_unsigned_fixture()).expect("read unsigned PE");
    let pe_digest = psign_sip_digest::pe_digest::pe_authenticode_digest(
        &pe,
        pkcs7::AuthenticodeSigningDigest::Sha256.pe_hash_kind(),
    )
    .expect("PE digest");
    let indirect =
        pkcs7::pe_spc_indirect_data(pkcs7::AuthenticodeSigningDigest::Sha256, &pe_digest)
            .expect("SpcIndirectData");
    let prehash = pkcs7::authenticode_remote_rsa_signed_attrs_digest(
        &indirect,
        pkcs7::AuthenticodeSigningDigest::Sha256,
    )
    .expect("remote prehash");
    let key_bytes = std::fs::read(&key_path).expect("read key");
    let private_key = rdp::parse_rsa_private_key(&key_bytes).expect("parse key");
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature: rsa::pkcs1v15::Signature = signing_key
        .sign_prehash(&prehash)
        .expect("sign remote prehash");
    let cert_bytes = std::fs::read(&cert_path).expect("read cert");
    let signer_cert = rdp::parse_certificate(&cert_bytes).expect("parse cert");
    let pkcs7 = pkcs7::create_authenticode_pkcs7_der_with_rsa_signature(
        indirect,
        pkcs7::AuthenticodeSigningDigest::Sha256,
        signer_cert,
        Vec::new(),
        &signature.to_bytes(),
    )
    .expect("remote-injected PKCS#7");
    let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7).expect("parse SignedData");
    pkcs7::verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature(
        &sd, 0, &pe_digest,
    )
    .expect("remote injected RSA signature verifies");
}

#[test]
fn timestamp_pe_rfc3161_attaches_unsigned_timestamp_attribute() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("signer.der");
    let key = dir.path().join("signer.pk8");
    let signed_pe = dir.path().join("tiny32.signed.exe");
    let token = dir.path().join("token.der");
    let stamped_pe = dir.path().join("tiny32.timestamped.exe");
    write_test_rsa_cert_key(&cert, &key);

    let mut sign = portable_cmd();
    sign.arg("sign-pe")
        .arg(tiny32_unsigned_fixture())
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .arg("--output")
        .arg(&signed_pe);
    sign.assert().success();

    let pkcs7 = verify_pe::pe_nth_pkcs7_signed_data_der(
        &std::fs::read(&signed_pe).expect("read signed PE"),
        0,
    )
    .expect("extract PKCS#7");
    std::fs::write(&token, pkcs7).expect("write stand-in timestamp token");

    let mut stamp = portable_cmd();
    stamp
        .arg("timestamp-pe-rfc3161")
        .arg(&signed_pe)
        .arg("--token")
        .arg(&token)
        .arg("--output")
        .arg(&stamped_pe);
    stamp
        .assert()
        .success()
        .stdout(predicate::str::contains("timestamp-pe-rfc3161: ok"));

    let mut verify = portable_cmd();
    verify.arg("verify-pe").arg(&stamped_pe);
    verify.assert().success();

    let mut inspect = portable_cmd();
    inspect
        .arg("inspect-authenticode")
        .arg(&stamped_pe)
        .arg("--input")
        .arg("pe");
    inspect
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "microsoft_nested_rfc3161_attribute",
        ))
        .stdout(predicate::str::contains("1.3.6.1.4.1.311.3.3.1"));
}

#[test]
fn inspect_pe_spc_indirect_matches_sip_digest_on_tiny_fixture() {
    let mut cmd = portable_cmd();
    cmd.arg("inspect-pe-spc-indirect").arg(tiny32_fixture());
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    let v: Value = serde_json::from_str(out.trim()).expect("inspect-pe-spc-indirect JSON");
    assert_eq!(
        v.get("message_digest_matches_pe_image_digest")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        v.get("image_data_value_type_oid").and_then(Value::as_str),
        Some("1.3.6.1.4.1.311.2.1.15")
    );
    assert_eq!(
        v.get("digest_algorithm_oid").and_then(Value::as_str),
        Some("2.16.840.1.101.3.4.2.1")
    );
}

#[test]
fn inspect_pe_spc_indirect_explicit_index_zero_matches_default() {
    let mut cmd = portable_cmd();
    cmd.arg("inspect-pe-spc-indirect")
        .arg(tiny32_fixture())
        .arg("--index")
        .arg("0");
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    let v: Value = serde_json::from_str(out.trim()).expect("inspect JSON");
    assert_eq!(
        v.get("message_digest_matches_pe_image_digest")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn inspect_pe_spc_indirect_index_out_of_range_fails() {
    let mut cmd = portable_cmd();
    cmd.arg("inspect-pe-spc-indirect")
        .arg(tiny32_fixture())
        .arg("--index")
        .arg("1");
    cmd.assert().failure();
}

#[test]
fn verify_pe_pkcs7_indirect_digest_matches_on_tiny64_fixture() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-pe").arg(tiny64_fixture());
    cmd.assert().success();
}

#[test]
fn pe_has_page_hashes_is_no_on_upstream_tiny_fixtures() {
    for fixture in [tiny32_fixture(), tiny64_fixture()] {
        let mut cmd = portable_cmd();
        cmd.arg("pe-has-page-hashes").arg(&fixture);
        cmd.assert().success().stdout("no\n");
    }
}

#[test]
fn pe_page_hash_info_is_empty_on_upstream_tiny_fixtures() {
    for fixture in [tiny32_fixture(), tiny64_fixture()] {
        let mut cmd = portable_cmd();
        cmd.arg("pe-page-hash-info").arg(&fixture);
        cmd.assert().success().stdout("");
    }
}

#[test]
fn verify_pe_page_hashes_fails_when_upstream_tiny_has_no_page_hash_attrs() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-pe-page-hashes").arg(tiny32_fixture());
    cmd.assert().failure();
}

#[test]
fn pe_authenticode_ranges_prints_start_end_lines_on_tiny_fixture() {
    let mut cmd = portable_cmd();
    cmd.arg("pe-authenticode-ranges").arg(tiny32_fixture());
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    assert!(!out.trim().is_empty(), "expected non-empty range listing");
    for line in out.lines() {
        assert!(
            line.starts_with("start=") && line.contains(" end="),
            "unexpected line: {line:?}"
        );
    }
}

#[test]
fn artifact_signing_metadata_check_accepts_valid_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meta.json");
    std::fs::write(
        &path,
        r#"{"Endpoint":"https://example.test/rpcsign","CodeSigningAccountName":"acct","CertificateProfileName":"prof","ExcludeCredentials":["ManagedIdentityCredential"]}"#,
    )
    .unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["artifact-signing-metadata-check", "--path"])
        .arg(&path);
    cmd.assert().success().stdout(predicate::str::contains(
        "artifact-signing-metadata-check: ok",
    ));
}

#[test]
fn artifact_signing_metadata_check_rejects_empty_profile_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(
        &path,
        r#"{"Endpoint":"https://example.test/rpcsign","CodeSigningAccountName":"acct","CertificateProfileName":"  "}"#,
    )
    .unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["artifact-signing-metadata-check", "--path"])
        .arg(&path);
    cmd.assert().failure();
}

/// Minimal packed WIM header (`EsdSip.dll` **208**-byte prefix) with **MSWIM** magic but **no** PKCS#7 (`cb=0`).
fn minimal_unsigned_wim_header_bytes() -> Vec<u8> {
    const WIM_HEADER_PACKED_SIZE: usize = psign_sip_digest::esd_digest::WIM_HEADER_PACKED_SIZE;
    let mut h = vec![0u8; WIM_HEADER_PACKED_SIZE];
    h[0..8].copy_from_slice(b"MSWIM\0\0\0");
    h[8..12].copy_from_slice(&(WIM_HEADER_PACKED_SIZE as u32).to_le_bytes());
    h
}

#[test]
fn portable_verify_negative_pe_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("not-pe.exe");
    std::fs::write(&p, b"not-a-pe-image").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-pe").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_esd_not_wim_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nope.wim");
    std::fs::write(&p, b"not-wim-bytes").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-esd").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_esd_unsigned_minimal_header_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("unsigned.wim");
    std::fs::write(&p, minimal_unsigned_wim_header_bytes()).unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-esd").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_esd_bad_header_size_cli() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = minimal_unsigned_wim_header_bytes();
    h[8..12].copy_from_slice(&100u32.to_le_bytes());
    let p = dir.path().join("badhdr.wim");
    std::fs::write(&p, &h).unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-esd").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_msix_encrypted_extension_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("fake.emsix");
    std::fs::write(&p, b"not-a-real-package").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-msix").arg(&p);
    let assert = cmd.assert().failure();
    let err = std::str::from_utf8(&assert.get_output().stderr).expect("utf8 stderr");
    assert!(
        err.contains("encrypted") || err.contains("Eappx"),
        "stderr should mention encrypted MSIX path; got:\n{err}"
    );
}

#[test]
fn portable_verify_negative_msix_non_zip_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("garbage.msix");
    std::fs::write(&p, b"not-zip").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-msix").arg(&p);
    cmd.assert().failure();
}

fn unsigned_sample_ps1_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.ps1")
}

fn unsigned_sample_vbs_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.vbs")
}

#[test]
fn portable_verify_negative_script_unsigned_ps1_cli() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-script").arg(unsigned_sample_ps1_fixture());
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_script_unsigned_vbs_cli() {
    let mut cmd = portable_cmd();
    cmd.arg("verify-script").arg(unsigned_sample_vbs_fixture());
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_cab_unsigned_cli() {
    let dir = tempfile::tempdir().unwrap();
    let cab = dir.path().join("unsigned.cab");
    std::fs::write(&cab, minimal_unsigned_cab_bytes()).unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-cab").arg(&cab);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_trust_cab_no_anchors_cli() {
    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-cab").arg(tiny_signed_cab_fixture());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("no trust anchors"));
}

#[test]
fn inspect_pkcs7_parity_embedded_pe_reports_agree_tiny32() {
    let pe_bytes = std::fs::read(tiny32_fixture()).expect("read tiny32");
    let der = verify_pe::pe_first_pkcs7_signed_data_der(&pe_bytes).expect("extract pkcs7");
    let pe_report = inspect_pe_authenticode(&pe_bytes).expect("inspect pe");
    let pkcs7_report = inspect_authenticode_pkcs7_der(&der).expect("inspect pkcs7");
    let e0 = &pe_report.entries[0].pkcs7;
    assert_eq!(e0.signers.len(), pkcs7_report.signers.len());
    assert_eq!(
        e0.authenticode_digest
            .as_ref()
            .map(|d| d.digest_hex.as_str()),
        pkcs7_report
            .authenticode_digest
            .as_ref()
            .map(|d| d.digest_hex.as_str())
    );
}

#[test]
fn inspect_pkcs7_parity_cli_stdout_matches_library_tiny32() {
    let pe_bytes = std::fs::read(tiny32_fixture()).expect("read tiny32");
    let der = verify_pe::pe_first_pkcs7_signed_data_der(&pe_bytes).expect("extract pkcs7");
    let dir = tempfile::tempdir().expect("tempdir");
    let blob = dir.path().join("row0.p7");
    std::fs::write(&blob, &der).expect("write pkcs7");
    let mut cmd = portable_cmd();
    cmd.args(["inspect-authenticode", "--input", "pkcs7"])
        .arg(&blob);
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    let cli_json: Value = serde_json::from_str(out.trim()).expect("CLI JSON");
    let lib_json = serde_json::to_value(inspect_authenticode_pkcs7_der(&der).expect("lib"))
        .expect("serialize lib report");
    assert_eq!(
        cli_json
            .get("signers")
            .and_then(Value::as_array)
            .map(|a| a.len()),
        lib_json
            .get("signers")
            .and_then(Value::as_array)
            .map(|a| a.len())
    );
    assert_eq!(
        cli_json.get("authenticode_digest"),
        lib_json.get("authenticode_digest")
    );
}

#[test]
fn portable_verify_negative_inspect_authenticode_invalid_pkcs7_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.p7");
    std::fs::write(&p, b"not-valid-der-pkcs7").unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["inspect-authenticode", "--input", "pkcs7"])
        .arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_verify_catalog_garbage_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("noise.cat");
    std::fs::write(&p, b"not-a-catalog").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-catalog").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_trust_catalog_tiny32_content_cat_cli() {
    let fixture = tiny32_fixture();
    let bytes = std::fs::read(&fixture).expect("read tiny32");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("anchor.crt"), root.to_der().expect("der")).expect("anchor");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-catalog")
        .arg("--anchor-dir")
        .arg(dir.path())
        .args(["--as-of", "2023-07-01"])
        .arg(tiny32_pe_pkcs7_as_cat_fixture());
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_trust_detached_pe_digest_mismatch_cli() {
    let pe_path = tiny32_fixture();
    let pe_bytes = std::fs::read(&pe_path).expect("read tiny32");
    let der = verify_pe::pe_first_pkcs7_signed_data_der(&pe_bytes).expect("pkcs7");
    let root = pe_first_pkcs7_terminal_root(&pe_bytes).expect("root");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("anchor.crt"), root.to_der().expect("der")).expect("anchor");
    std::fs::write(dir.path().join("sig.p7"), &der).expect("sig");
    let work_pe = dir.path().join("subject.exe");
    std::fs::write(&work_pe, &pe_bytes).expect("copy pe");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-detached")
        .arg("--anchor-dir")
        .arg(dir.path())
        .args(["--as-of", "2023-07-01"])
        .arg(&work_pe)
        .arg(dir.path().join("sig.p7"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("detached content digest"));
}

#[test]
fn artifact_signing_metadata_check_accepts_valid_json_stdin() {
    let mut cmd = portable_cmd();
    cmd.arg("artifact-signing-metadata-check")
        .write_stdin(r#"{"Endpoint":"https://example.test/rpcsign","CodeSigningAccountName":"acct","CertificateProfileName":"prof"}"#);
    cmd.assert().success().stdout(predicate::str::contains(
        "artifact-signing-metadata-check: ok",
    ));
}

#[test]
fn artifact_signing_metadata_check_stdin_empty_fails() {
    let mut cmd = portable_cmd();
    cmd.arg("artifact-signing-metadata-check").write_stdin("");
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_pe_digest_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("not.exe");
    std::fs::write(&p, b"not-a-pe").unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["pe-digest", "--algorithm", "sha256"]).arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_pe_digest_missing_file_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("missing.exe");
    let mut cmd = portable_cmd();
    cmd.args(["pe-digest", "--algorithm", "sha256"]).arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_extract_pe_pkcs7_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("junk.exe");
    std::fs::write(&p, b"no-pe").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("extract-pe-pkcs7").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_list_pe_pkcs7_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("junk.exe");
    std::fs::write(&p, b"no-pe").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("list-pe-pkcs7").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_cab_digest_non_mscf_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nocab.cab");
    std::fs::write(&p, b"not-mscf").unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["cab-digest", "--algorithm", "sha256"]).arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_inspect_pe_spc_indirect_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nope.exe");
    std::fs::write(&p, b"x").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("inspect-pe-spc-indirect").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_trust_detached_no_anchors_cli() {
    let pe_path = tiny32_fixture();
    let pe_bytes = std::fs::read(&pe_path).expect("read tiny32");
    let der = verify_pe::pe_first_pkcs7_signed_data_der(&pe_bytes).expect("pkcs7");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("sig.p7"), &der).expect("sig");
    let work_pe = dir.path().join("subject.exe");
    std::fs::write(&work_pe, &pe_bytes).expect("copy pe");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-detached")
        .arg(&work_pe)
        .arg(dir.path().join("sig.p7"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("no trust anchors"));
}

#[test]
fn portable_verify_negative_pe_signer_rs256_prehash_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nope.exe");
    std::fs::write(&p, b"not-pe").unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["pe-signer-rs256-prehash", "--encoding", "raw", "--output"])
        .arg(dir.path().join("out.bin"))
        .arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_pkcs7_signer_rs256_prehash_invalid_der_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.p7");
    std::fs::write(&p, b"not-der").unwrap();
    let mut cmd = portable_cmd();
    cmd.args([
        "pkcs7-signer-rs256-prehash",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(dir.path().join("out.bin"))
    .arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_catalog_signer_rs256_prehash_invalid_der_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.cat");
    std::fs::write(&p, b"not-der").unwrap();
    let mut cmd = portable_cmd();
    cmd.args([
        "catalog-signer-rs256-prehash",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(dir.path().join("out.bin"))
    .arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_inspect_authenticode_pe_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("not.exe");
    std::fs::write(&p, b"not-pe-image").unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["inspect-authenticode", "--input", "pe"]).arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_trust_verify_pe_not_pe_with_anchors_cli() {
    let fixture = tiny32_fixture();
    let pe = std::fs::read(&fixture).expect("read tiny32");
    let root = pe_first_pkcs7_terminal_root(&pe).expect("root");
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("anchor.crt"), root.to_der().expect("der")).expect("anchor");
    let junk = dir.path().join("junk.exe");
    std::fs::write(&junk, b"not-pe").expect("junk");

    let mut cmd = portable_cmd();
    cmd.arg("trust-verify-pe")
        .arg("--anchor-dir")
        .arg(dir.path())
        .args(["--as-of", "2023-07-01"])
        .arg(&junk);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_msi_signer_rs256_non_ole_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("fake.msi");
    std::fs::write(&p, b"not ole").unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["msi-signer-rs256-prehash", "--encoding", "raw", "--output"])
        .arg(dir.path().join("out.bin"))
        .arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_cab_signer_rs256_non_cab_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("fake.cab");
    std::fs::write(&p, b"not-mscf-cab").unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["cab-signer-rs256-prehash", "--encoding", "raw", "--output"])
        .arg(dir.path().join("out.bin"))
        .arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_append_pe_pkcs7_pe_not_pe_cli() {
    let dir = tempfile::tempdir().expect("tempdir");
    let junk_pe = dir.path().join("junk.exe");
    std::fs::write(&junk_pe, b"not-pe").expect("junk pe");
    let pkcs7_path = dir.path().join("sig.der");
    let mut ext = portable_cmd();
    ext.arg("extract-pe-pkcs7")
        .arg(tiny32_fixture())
        .arg("--output")
        .arg(&pkcs7_path);
    ext.assert().success();

    let out_pe = dir.path().join("out.exe");
    let mut app = portable_cmd();
    app.arg("append-pe-pkcs7")
        .arg("--pe")
        .arg(&junk_pe)
        .arg("--pkcs7")
        .arg(&pkcs7_path)
        .arg("--output")
        .arg(&out_pe);
    app.assert().failure();
}

#[test]
fn portable_verify_negative_append_pe_pkcs7_missing_pkcs7_cli() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pe_copy = dir.path().join("base.exe");
    std::fs::copy(tiny32_fixture(), &pe_copy).expect("copy tiny32");
    let missing_p7 = dir.path().join("does-not-exist.der");
    let out_pe = dir.path().join("out.exe");
    let mut app = portable_cmd();
    app.arg("append-pe-pkcs7")
        .arg("--pe")
        .arg(&pe_copy)
        .arg("--pkcs7")
        .arg(&missing_p7)
        .arg("--output")
        .arg(&out_pe);
    app.assert().failure();
}

#[test]
fn portable_verify_negative_append_pe_pkcs7_missing_pe_cli() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_pe = dir.path().join("missing.exe");
    let pkcs7_path = dir.path().join("sig.der");
    let mut ext = portable_cmd();
    ext.arg("extract-pe-pkcs7")
        .arg(tiny32_fixture())
        .arg("--output")
        .arg(&pkcs7_path);
    ext.assert().success();

    let out_pe = dir.path().join("out.exe");
    let mut app = portable_cmd();
    app.arg("append-pe-pkcs7")
        .arg("--pe")
        .arg(&missing_pe)
        .arg("--pkcs7")
        .arg(&pkcs7_path)
        .arg("--output")
        .arg(&out_pe);
    app.assert().failure();
}

#[test]
fn portable_verify_negative_pe_checksum_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.exe");
    std::fs::write(&p, b"nope").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("pe-checksum").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_pe_has_page_hashes_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.exe");
    std::fs::write(&p, b"nope").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("pe-has-page-hashes").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_pe_page_hash_info_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.exe");
    std::fs::write(&p, b"nope").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("pe-page-hash-info").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_pe_authenticode_ranges_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.exe");
    std::fs::write(&p, b"nope").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("pe-authenticode-ranges").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_verify_negative_verify_pe_page_hashes_not_pe_cli() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("x.exe");
    std::fs::write(&p, b"nope").unwrap();
    let mut cmd = portable_cmd();
    cmd.arg("verify-pe-page-hashes").arg(&p);
    cmd.assert().failure();
}

#[test]
fn portable_rfc3161_timestamp_req_sha256_zeros_hex_stdout_line() {
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--algorithm",
        "sha256",
        "--digest-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--output",
        "hex",
    ]);
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = std::str::from_utf8(&out.stdout).expect("utf-8").trim();
    assert_eq!(line.len(), 112, "56-byte DER as hex");
    assert!(
        line.contains("300d06096086480165030402010500"),
        "SHA-256 AlgorithmIdentifier inside MessageImprint (hex)"
    );
}

#[test]
fn portable_rfc3161_timestamp_req_sha1_hex_contains_sha1_algorithm_identifier() {
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--algorithm",
        "sha1",
        "--digest-hex",
        "0000000000000000000000000000000000000000",
        "--output",
        "hex",
    ]);
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = std::str::from_utf8(&out.stdout).expect("utf-8").trim();
    assert_eq!(line.len(), 80, "40-byte DER as hex");
    assert!(
        line.contains("300b06052b0e03021a0500"),
        "SHA-1 AlgorithmIdentifier inside MessageImprint (hex)"
    );
}

#[test]
fn portable_rfc3161_timestamp_req_sha384_hex_contains_sha384_algorithm_identifier() {
    let digest = "00".repeat(48);
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--algorithm",
        "sha384",
        "--digest-hex",
        &digest,
        "--output",
        "hex",
    ]);
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = std::str::from_utf8(&out.stdout).expect("utf-8").trim();
    assert_eq!(line.len(), 144, "72-byte DER as hex");
    assert!(
        line.contains("300d06096086480165030402020500"),
        "SHA-384 AlgorithmIdentifier inside MessageImprint (hex)"
    );
}

#[test]
fn portable_rfc3161_timestamp_req_sha512_hex_contains_sha512_algorithm_identifier() {
    let digest = "00".repeat(64);
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--algorithm",
        "sha512",
        "--digest-hex",
        &digest,
        "--output",
        "hex",
    ]);
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = std::str::from_utf8(&out.stdout).expect("utf-8").trim();
    assert_eq!(line.len(), 176, "88-byte DER as hex");
    assert!(
        line.contains("300d06096086480165030402030500"),
        "SHA-512 AlgorithmIdentifier inside MessageImprint (hex)"
    );
}

/// **`--nonce`** and **`--cert-req`** extend **`TimeStampReq`** after **`messageImprint`** (RFC 3161 field order).
#[test]
fn portable_rfc3161_timestamp_req_nonce_and_cert_req_hex_contains_extensions() {
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--algorithm",
        "sha256",
        "--digest-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--nonce",
        "1",
        "--cert-req",
        "--output",
        "hex",
    ]);
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = std::str::from_utf8(&out.stdout).expect("utf-8").trim();
    assert_eq!(
        line.len(),
        124,
        "62-byte DER: base 56 + INTEGER 1 + BOOLEAN TRUE"
    );
    assert!(
        line.contains("020101"),
        "nonce INTEGER value 1 (minimal DER)"
    );
    assert!(line.contains("0101ff"), "certReq BOOLEAN TRUE");
}

#[test]
fn portable_rfc3161_timestamp_req_nonce_u64_max_hex_length_and_integer_tlv() {
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--algorithm",
        "sha256",
        "--digest-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--nonce",
        "18446744073709551615",
        "--output",
        "hex",
    ]);
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = std::str::from_utf8(&out.stdout).expect("utf-8").trim();
    assert_eq!(
        line.len(),
        134,
        "67-byte DER: 56-byte base + INTEGER(u64::MAX)"
    );
    assert!(
        line.contains("020900ffffffffffffffff"),
        "nonce INTEGER: tag 02 len 09 leading 00 + u64::MAX magnitude"
    );
}

#[test]
fn portable_rfc3161_timestamp_req_digest_file_matches_der_len() {
    let dir = tempfile::tempdir().unwrap();
    let df = dir.path().join("imprint.bin");
    std::fs::write(&df, [0u8; 32]).unwrap();
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--digest-file",
        df.to_str().unwrap(),
        "--output",
        "der",
    ]);
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout.len(), 56);
}

#[test]
fn portable_rfc3161_timestamp_req_sha256_zeros_der_stdout_len() {
    let mut cmd = portable_cmd();
    cmd.args([
        "rfc3161-timestamp-req",
        "--algorithm",
        "sha256",
        "--digest-hex",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--output",
        "der",
    ]);
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout.len(), 56);
}

#[test]
fn portable_rfc3161_timestamp_req_errors_without_digest_input() {
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-req", "--algorithm", "sha256"]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("exactly one of --digest-hex"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_granted_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00]).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=granted"))
        .stdout(predicate::str::contains("pki_status_int=0"))
        .stdout(predicate::str::contains("granted=yes"))
        .stdout(predicate::str::contains("time_stamp_token_len=0"))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"))
        .stdout(predicate::str::contains("status_strings_json=[]"))
        .stdout(predicate::str::contains("fail_info_tlv_hex=-"))
        .stdout(predicate::str::contains("fail_info_flags_json=[]"));
}

fn fixture_ts_resp_granted_outer_len81() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rfc3161/ts_resp_granted_outer_len81.der")
}

/// Workspace **`tests/fixtures/rfc3161/ts_resp_granted_outer_len81.der`**: granted + long **`PKIFreeText`**, root length **`0x81`**.
#[test]
fn portable_rfc3161_timestamp_resp_inspect_fixture_outer_sequence_len81() {
    let path = fixture_ts_resp_granted_outer_len81();
    assert!(path.is_file(), "missing fixture {:?}", path);
    let der = std::fs::read(&path).expect("read fixture");
    assert_eq!(der.len(), 138);
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", path.to_str().unwrap()]);
    let assert = cmd.assert().success();
    let stdout = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8");
    assert!(stdout.contains("pki_status=granted"));
    assert!(stdout.contains("pki_status_int=0"));
    assert!(stdout.contains("time_stamp_token_len=0"));
    let line = stdout
        .lines()
        .find(|l| l.starts_with("status_strings_json="))
        .expect("status_strings_json line");
    let json_s = line.trim_start_matches("status_strings_json=");
    let v: Value = serde_json::from_str(json_s).expect("json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let s = arr[0].as_str().expect("string");
    assert_eq!(s.len(), 125);
    assert!(s.chars().all(|c| c == 'y'));
}

/// **`PKIStatusInfo`** with **`rejection`** + **`statusString`** UTF-8 **`"nope"`** (no token).
#[test]
fn portable_rfc3161_timestamp_resp_inspect_granted_with_fail_info_hex() {
    let der: [u8; 11] = [
        0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x00, 0xc0,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=granted"))
        .stdout(predicate::str::contains("pki_status_int=0"))
        .stdout(predicate::str::contains("fail_info_tlv_hex=030200c0"))
        .stdout(predicate::str::contains(
            "fail_info_flags_json=[\"badAlg\",\"badMessageCheck\"]",
        ))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_granted_with_token_prefix_hex() {
    let der: [u8; 12] = [
        0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x03, 0x02, 0x01, 0x2a,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("time_stamp_token_len=5"))
        .stdout(predicate::str::contains(
            "time_stamp_token_prefix_hex=300302012a",
        ));
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
fn spawn_psign_server(extra_args: &[&str]) -> (PsignServerGuard, String) {
    spawn_psign_server_with_gen_time("20240102030405Z", extra_args)
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn spawn_psign_server_with_gen_time(
    gen_time: &str,
    extra_args: &[&str],
) -> (PsignServerGuard, String) {
    let mut server_cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("psign-server"));
    server_cmd.args([
        "timestamp-server",
        "--listen",
        "127.0.0.1:0",
        "--gen-time",
        gen_time,
        "--max-requests",
        "1",
    ]);
    server_cmd.args(extra_args);
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

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn generalized_time_tomorrow_noon_utc() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_secs();
    let days = (now / 86_400) as i64 + 1;
    let (year, month, day) = civil_from_unix_days(days);
    format!("{year:04}{month:02}{day:02}120000Z")
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn civil_from_unix_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(feature = "timestamp-server")]
fn spawn_psign_pki_server(extra_args: &[&str]) -> (PsignServerGuard, String) {
    spawn_psign_pki_server_requests(1, extra_args)
}

#[cfg(feature = "timestamp-server")]
fn spawn_psign_pki_server_requests(
    max_requests: u64,
    extra_args: &[&str],
) -> (PsignServerGuard, String) {
    let mut server_cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("psign-server"));
    let max_requests = max_requests.to_string();
    server_cmd.args([
        "pki-server",
        "--listen",
        "127.0.0.1:0",
        "--max-requests",
        max_requests.as_str(),
    ]);
    server_cmd.args(extra_args);
    server_cmd.stdout(std::process::Stdio::piped());
    server_cmd.stderr(std::process::Stdio::piped());
    let mut guard = PsignServerGuard(server_cmd.spawn().expect("spawn psign-server"));
    let stdout = guard.0.stdout.take().expect("server stdout");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("read listening line");
    for _ in 0..5 {
        let mut ignored = String::new();
        std::io::BufRead::read_line(&mut reader, &mut ignored).expect("read endpoint line");
    }
    let url = line
        .trim()
        .strip_prefix("psign-server pki-server listening on ")
        .expect("listening URL")
        .to_string();
    (guard, url)
}

#[cfg(feature = "timestamp-server")]
fn http_get_bytes(url: &str) -> Vec<u8> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let without_scheme = url.strip_prefix("http://").expect("http URL");
    let (authority, path) = without_scheme
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((without_scheme, "/".to_string()));
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(h, p)| (h, p.parse::<u16>().expect("port")))
        .unwrap_or((authority, 80));
    let mut stream = TcpStream::connect((host, port)).expect("connect test HTTP server");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .expect("write HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read HTTP response");
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP header end");
    let headers = std::str::from_utf8(&response[..header_end]).expect("headers UTF-8");
    assert!(
        headers.starts_with("HTTP/1.1 200 OK"),
        "unexpected response headers: {headers}"
    );
    response[header_end + 4..].to_vec()
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn post_timestamp_request(
    url: &str,
    digest_hex: &str,
    resp_path: &Path,
) -> assert_cmd::assert::Assert {
    let mut post = portable_cmd();
    post.args([
        "rfc3161-timestamp-http-post",
        "--url",
        url,
        "--digest-hex",
        digest_hex,
        "--nonce",
        "7",
        "--output",
        resp_path.to_str().unwrap(),
    ]);
    post.assert()
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
fn timestamp_detached_pkcs7(pkcs7_der: &[u8], tsa_url: &str, resp_path: &Path) -> Vec<u8> {
    use cms::signed_data::UnsignedAttributes;
    use der::asn1::{Any, ObjectIdentifier, OctetStringRef, SetOfVec};
    use psign_sip_digest::timestamp::parse_time_stamp_resp_der;
    use x509_cert::attr::Attribute;

    const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

    let sd = pkcs7::parse_pkcs7_signed_data_der(pkcs7_der).expect("parse detached PKCS7");
    let si0 = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .expect("SignerInfo")
        .clone();
    let digest_hex = hex_lower(&Sha256::digest(si0.signature.as_bytes()));
    post_timestamp_request(tsa_url, &digest_hex, resp_path).success();
    let resp = std::fs::read(resp_path).expect("read timestamp response");
    let parsed = parse_time_stamp_resp_der(&resp).expect("parse timestamp response");
    let token = parsed.time_stamp_token.expect("timestamp response token");

    let mut vals = SetOfVec::new();
    vals.insert(
        Any::new(
            der::Tag::OctetString,
            OctetStringRef::new(token)
                .expect("timestamp token octets")
                .as_bytes(),
        )
        .expect("timestamp token attribute value"),
    )
    .expect("timestamp token value insert");
    let attr = Attribute {
        oid: ID_AA_TIME_STAMP_TOKEN,
        values: vals,
    };
    let mut attrs: Vec<Attribute> = si0
        .unsigned_attrs
        .as_ref()
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default();
    attrs.push(attr);
    let mut si = si0;
    si.unsigned_attrs =
        Some(UnsignedAttributes::try_from(attrs).expect("unsigned attrs canonicalization"));
    let updated = pkcs7::signed_data_replace_signer_info_at(&sd, 0, si).expect("replace signer");
    pkcs7::encode_pkcs7_content_info_signed_data_der(&updated).expect("encode timestamped PKCS7")
}

#[cfg(feature = "timestamp-server")]
#[test]
fn psign_server_pki_server_serves_certificates_for_non_admin_tests() {
    let dir = tempfile::tempdir().unwrap();
    let root_path = dir.path().join("root.der");
    let leaf_path = dir.path().join("leaf.der");
    let root_arg = root_path.to_str().unwrap();
    let leaf_arg = leaf_path.to_str().unwrap();
    let (mut guard, url) = spawn_psign_pki_server(&[
        "--root-cert-output",
        root_arg,
        "--leaf-cert-output",
        leaf_arg,
    ]);

    let root_from_http = http_get_bytes(&format!("{url}root.der"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let root_from_file = std::fs::read(&root_path).expect("read root output");
    let leaf_from_file = std::fs::read(&leaf_path).expect("read leaf output");
    assert_eq!(root_from_http, root_from_file);
    assert!(root_from_file.starts_with(&[0x30]));
    assert!(leaf_from_file.starts_with(&[0x30]));
}

#[cfg(feature = "timestamp-server")]
#[test]
fn psign_server_pki_server_serves_signed_crls() {
    let (mut guard, url) = spawn_psign_pki_server(&[]);
    let crl = http_get_bytes(&format!("{url}crl.der"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");
    assert!(crl.starts_with(&[0x30]), "CRL should be DER sequence");

    let (mut guard, url) = spawn_psign_pki_server(&["--crl-revoke-leaf"]);
    let revoked_crl = http_get_bytes(&format!("{url}crl.der"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");
    assert!(
        revoked_crl.len() > crl.len(),
        "revoked CRL should include a revoked certificate entry"
    );
}

#[cfg(feature = "timestamp-server")]
fn pki_signed_rdp_material(
    dir: &Path,
    prefix: &str,
    extra_args: &[&str],
) -> (PsignServerGuard, String, PathBuf, PathBuf, PathBuf) {
    let root_path = dir.join(format!("{prefix}-root.der"));
    let leaf_path = dir.join(format!("{prefix}-leaf.der"));
    let key_path = dir.join(format!("{prefix}-leaf.key"));
    let mut args = vec![
        "--root-cert-output",
        root_path.to_str().unwrap(),
        "--leaf-cert-output",
        leaf_path.to_str().unwrap(),
        "--leaf-key-output",
        key_path.to_str().unwrap(),
    ];
    args.extend_from_slice(extra_args);
    let (guard, url) = spawn_psign_pki_server_requests(1, &args);

    let records = rdp::parse_records("full address:s:localhost\r\n");
    let prepared = rdp::prepare_for_signature(records).expect("prepare RDP");
    let leaf_cert = rdp::parse_certificate(&std::fs::read(&leaf_path).expect("read leaf cert"))
        .expect("parse leaf cert");
    let root_cert = rdp::parse_certificate(&std::fs::read(&root_path).expect("read root cert"))
        .expect("parse root cert");
    let leaf_key = rdp::parse_rsa_private_key(&std::fs::read(&key_path).expect("read leaf key"))
        .expect("parse leaf key");
    let pkcs7 = rdp::sign_secure_blob_rsa_sha256(
        &prepared.secure_blob,
        leaf_cert,
        vec![root_cert],
        leaf_key,
    )
    .expect("sign RDP secure blob");
    let sig_path = dir.join(format!("{prefix}-sig.p7"));
    let content_path = dir.join(format!("{prefix}-content.bin"));
    std::fs::write(&sig_path, pkcs7).expect("write PKCS7");
    std::fs::write(&content_path, prepared.secure_blob).expect("write detached content");
    (guard, url, root_path, content_path, sig_path)
}

#[cfg(feature = "timestamp-server")]
#[test]
fn portable_trust_verify_detached_uses_pki_server_crl_without_admin_trust_store() {
    let dir = tempfile::tempdir().unwrap();
    let (mut guard, url, root_path, content_path, sig_path) =
        pki_signed_rdp_material(dir.path(), "clear", &[]);
    let mut verify = Command::cargo_bin("psign-tool").unwrap();
    verify
        .arg("portable")
        .arg("trust-verify-detached")
        .arg(&content_path)
        .arg(&sig_path)
        .arg("--trusted-ca")
        .arg(&root_path)
        .arg("--revocation-mode")
        .arg("require")
        .arg("--crl-url-override")
        .arg(format!("{url}crl.der"));
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-detached: ok"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let (mut guard, url, root_path, content_path, sig_path) =
        pki_signed_rdp_material(dir.path(), "revoked", &["--crl-revoke-leaf"]);
    let mut verify = Command::cargo_bin("psign-tool").unwrap();
    verify
        .arg("portable")
        .arg("trust-verify-detached")
        .arg(&content_path)
        .arg(&sig_path)
        .arg("--trusted-ca")
        .arg(&root_path)
        .arg("--revocation-mode")
        .arg("require")
        .arg("--crl-url-override")
        .arg(format!("{url}crl.der"));
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("certificate is revoked"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");
}

#[cfg(feature = "timestamp-server")]
#[test]
fn portable_trust_verify_detached_uses_pki_server_ocsp_without_admin_trust_store() {
    let dir = tempfile::tempdir().unwrap();
    let (mut guard, url, root_path, content_path, sig_path) =
        pki_signed_rdp_material(dir.path(), "ocsp-good", &["--ocsp-status", "good"]);
    let mut verify = Command::cargo_bin("psign-tool").unwrap();
    verify
        .arg("portable")
        .arg("trust-verify-detached")
        .arg(&content_path)
        .arg(&sig_path)
        .arg("--trusted-ca")
        .arg(&root_path)
        .arg("--revocation-mode")
        .arg("require")
        .arg("--online-ocsp")
        .arg("--ocsp-url-override")
        .arg(format!("{url}ocsp"));
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-detached: ok"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let (mut guard, url, root_path, content_path, sig_path) =
        pki_signed_rdp_material(dir.path(), "ocsp-revoked", &["--ocsp-status", "revoked"]);
    let mut verify = Command::cargo_bin("psign-tool").unwrap();
    verify
        .arg("portable")
        .arg("trust-verify-detached")
        .arg(&content_path)
        .arg(&sig_path)
        .arg("--trusted-ca")
        .arg(&root_path)
        .arg("--revocation-mode")
        .arg("require")
        .arg("--online-ocsp")
        .arg("--ocsp-url-override")
        .arg(format!("{url}ocsp"));
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("OCSP status is revoked"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn portable_trust_verify_detached_requires_trusted_rfc3161_timestamp_without_admin_trust_store() {
    let dir = tempfile::tempdir().unwrap();
    let (_pki_guard, _pki_url, code_root_path, content_path, sig_path) =
        pki_signed_rdp_material(dir.path(), "timestamp", &[]);
    let original_pkcs7 = std::fs::read(&sig_path).expect("read detached PKCS7");
    let gen_time = generalized_time_tomorrow_noon_utc();

    let tsa_root_path = dir.path().join("tsa-root.der");
    let resp_path = dir.path().join("tsa-response.der");
    let (mut tsa_guard, tsa_url) = spawn_psign_server_with_gen_time(
        &gen_time,
        &["--cert-output", tsa_root_path.to_str().unwrap()],
    );
    let timestamped = timestamp_detached_pkcs7(&original_pkcs7, &tsa_url, &resp_path);
    let status = tsa_guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");
    let timestamped_path = dir.path().join("timestamped-sig.p7");
    std::fs::write(&timestamped_path, timestamped).expect("write timestamped PKCS7");

    let mut verify = Command::cargo_bin("psign-tool").unwrap();
    verify
        .arg("portable")
        .arg("trust-verify-detached")
        .arg(&content_path)
        .arg(&timestamped_path)
        .arg("--trusted-ca")
        .arg(&code_root_path)
        .arg("--trusted-ca")
        .arg(&tsa_root_path)
        .arg("--prefer-timestamp-signing-time")
        .arg("--require-valid-timestamp");
    verify
        .assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-detached: ok"));

    let bad_tsa_root_path = dir.path().join("bad-tsa-root.der");
    let bad_resp_path = dir.path().join("bad-tsa-response.der");
    let (mut bad_tsa_guard, bad_tsa_url) = spawn_psign_server_with_gen_time(
        &gen_time,
        &[
            "--cert-output",
            bad_tsa_root_path.to_str().unwrap(),
            "--response-mode",
            "mismatched-imprint",
        ],
    );
    let bad_timestamped = timestamp_detached_pkcs7(&original_pkcs7, &bad_tsa_url, &bad_resp_path);
    let status = bad_tsa_guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");
    let bad_timestamped_path = dir.path().join("bad-timestamped-sig.p7");
    std::fs::write(&bad_timestamped_path, bad_timestamped).expect("write bad timestamped PKCS7");

    let mut verify_bad = Command::cargo_bin("psign-tool").unwrap();
    verify_bad
        .arg("portable")
        .arg("trust-verify-detached")
        .arg(&content_path)
        .arg(&bad_timestamped_path)
        .arg("--trusted-ca")
        .arg(&code_root_path)
        .arg("--trusted-ca")
        .arg(&bad_tsa_root_path)
        .arg("--prefer-timestamp-signing-time")
        .arg("--require-valid-timestamp");
    verify_bad
        .assert()
        .failure()
        .stderr(predicate::str::contains("MessageImprint does not match"));
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn portable_rfc3161_http_post_to_psign_server_inspects_tstinfo() {
    let dir = tempfile::tempdir().unwrap();
    let resp_path = dir.path().join("ts.der");
    let (mut guard, url) = spawn_psign_server(&[]);

    let digest_hex = "11".repeat(32);
    post_timestamp_request(&url, &digest_hex, &resp_path).success();
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut inspect = portable_cmd();
    inspect.args([
        "rfc3161-timestamp-resp-inspect",
        "--expect-digest-hex",
        &digest_hex,
        "--expect-nonce",
        "7",
        resp_path.to_str().unwrap(),
    ]);
    inspect
        .assert()
        .success()
        .stdout(predicate::str::contains("pki_status=granted"))
        .stdout(predicate::str::contains("tst_info_present=yes"))
        .stdout(predicate::str::contains(
            "tst_info_policy_oid=1.3.6.1.4.1.311.97.99.1",
        ))
        .stdout(predicate::str::contains(
            "tst_info_message_imprint_digest_alg_oid=2.16.840.1.101.3.4.2.1",
        ))
        .stdout(predicate::str::contains(format!(
            "tst_info_message_imprint_hashed_message_hex={digest_hex}"
        )))
        .stdout(predicate::str::contains(
            "tst_info_gen_time=20240102030405Z",
        ))
        .stdout(predicate::str::contains("tst_info_nonce_hex=07"))
        .stdout(predicate::str::contains(
            "tst_info_message_imprint_match=yes",
        ))
        .stdout(predicate::str::contains("tst_info_nonce_match=yes"));
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn portable_rfc3161_http_post_to_psign_server_detects_mismatched_imprint() {
    let dir = tempfile::tempdir().unwrap();
    let resp_path = dir.path().join("mismatched.der");
    let (mut guard, url) = spawn_psign_server(&["--response-mode", "mismatched-imprint"]);

    let digest_hex = "11".repeat(32);
    post_timestamp_request(&url, &digest_hex, &resp_path).success();
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut inspect = portable_cmd();
    inspect.args([
        "rfc3161-timestamp-resp-inspect",
        "--expect-digest-hex",
        &digest_hex,
        "--expect-nonce",
        "7",
        resp_path.to_str().unwrap(),
    ]);
    inspect
        .assert()
        .success()
        .stdout(predicate::str::contains("pki_status=granted"))
        .stdout(predicate::str::contains("tst_info_present=yes"))
        .stdout(predicate::str::contains(
            "tst_info_message_imprint_match=no",
        ))
        .stdout(predicate::str::contains("tst_info_nonce_match=yes"));
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn portable_rfc3161_http_post_to_psign_server_bad_alg_is_inspectable() {
    let dir = tempfile::tempdir().unwrap();
    let resp_path = dir.path().join("bad-alg.der");
    let (mut guard, url) = spawn_psign_server(&["--response-mode", "bad-alg"]);

    let digest_hex = "11".repeat(32);
    post_timestamp_request(&url, &digest_hex, &resp_path).success();
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut inspect = portable_cmd();
    inspect.args([
        "rfc3161-timestamp-resp-inspect",
        resp_path.to_str().unwrap(),
    ]);
    inspect
        .assert()
        .success()
        .stdout(predicate::str::contains("pki_status=rejection"))
        .stdout(predicate::str::contains("granted=no"))
        .stdout(predicate::str::contains(
            "status_strings_json=[\"psign-server configured badAlg\"]",
        ))
        .stdout(predicate::str::contains(
            "fail_info_flags_json=[\"badAlg\"]",
        ))
        .stdout(predicate::str::contains("tst_info_present=no"));
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn portable_rfc3161_http_post_to_psign_server_malformed_der_fails_inspect() {
    let dir = tempfile::tempdir().unwrap();
    let resp_path = dir.path().join("malformed.der");
    let (mut guard, url) = spawn_psign_server(&["--response-mode", "malformed-der"]);

    let digest_hex = "11".repeat(32);
    post_timestamp_request(&url, &digest_hex, &resp_path).success();
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");

    let mut inspect = portable_cmd();
    inspect.args([
        "rfc3161-timestamp-resp-inspect",
        resp_path.to_str().unwrap(),
    ]);
    inspect.assert().failure().stderr(predicate::str::contains(
        "could not parse TimeStampResp DER",
    ));
}

#[cfg(all(feature = "timestamp-server", feature = "timestamp-http"))]
#[test]
fn portable_rfc3161_http_post_to_psign_server_http_error_fails_post() {
    let dir = tempfile::tempdir().unwrap();
    let resp_path = dir.path().join("http-error.der");
    let (mut guard, url) = spawn_psign_server(&["--response-mode", "http-error"]);

    let digest_hex = "11".repeat(32);
    post_timestamp_request(&url, &digest_hex, &resp_path)
        .failure()
        .stderr(predicate::str::contains("TSA HTTP 500"));
    let status = guard.0.wait().expect("server exit");
    assert!(status.success(), "server failed with {status}");
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_granted_long_token_prefix_hex_truncates() {
    let mut der = vec![0x30, 0x1b, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x14];
    der.extend_from_slice(&[0x41u8; 20]);
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, &der).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("time_stamp_token_len=22"))
        .stdout(predicate::str::contains(
            "time_stamp_token_prefix_hex=30144141414141414141414141414141",
        ));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_rejection_multi_status_strings_json() {
    let der: [u8; 19] = [
        0x30, 0x11, 0x30, 0x0f, 0x02, 0x01, 0x02, 0x30, 0x0a, 0x0c, 0x01, 0x61, 0x0c, 0x02, 0x62,
        0x62, 0x0c, 0x01, 0x63,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=rejection"))
        .stdout(predicate::str::contains("pki_status_int=2"))
        .stdout(predicate::str::contains(
            "status_strings_json=[\"a\",\"bb\",\"c\"]",
        ))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_rejection_empty_pkifreetext() {
    let der: [u8; 9] = [0x30, 0x07, 0x30, 0x05, 0x02, 0x01, 0x02, 0x30, 0x00];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=rejection"))
        .stdout(predicate::str::contains("pki_status_int=2"))
        .stdout(predicate::str::contains("status_strings_json=[]"))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_rejection_with_status_string() {
    let der: [u8; 15] = [
        0x30, 0x0d, 0x30, 0x0b, 0x02, 0x01, 0x02, 0x30, 0x06, 0x0c, 0x04, 0x6e, 0x6f, 0x70, 0x65,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=rejection"))
        .stdout(predicate::str::contains("pki_status_int=2"))
        .stdout(predicate::str::contains("granted=no"))
        .stdout(predicate::str::contains("status_strings_json"))
        .stdout(predicate::str::contains("nope"))
        .stdout(predicate::str::contains("fail_info_tlv_hex=-"))
        .stdout(predicate::str::contains("fail_info_flags_json=[]"))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_waiting_status() {
    let der = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x03];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=waiting"))
        .stdout(predicate::str::contains("pki_status_int=3"))
        .stdout(predicate::str::contains("granted=no"))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_unknown_pki_status_int_128() {
    let der: [u8; 8] = [0x30, 0x06, 0x30, 0x04, 0x02, 0x02, 0x00, 0x80];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=unknown"))
        .stdout(predicate::str::contains("pki_status_int=128"))
        .stdout(predicate::str::contains("granted=no"))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_unknown_pki_status_int() {
    let der = [0x30u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x63];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=unknown"))
        .stdout(predicate::str::contains("pki_status_int=99"))
        .stdout(predicate::str::contains("granted=no"))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

/// Malformed **`PKIFailureInfo`** (**`unused` bits = 8**) still parses as **`TimeStampResp`**; flags decode as **`null`**.
#[test]
fn portable_rfc3161_timestamp_resp_inspect_fail_info_flags_null_when_bit_string_invalid() {
    let der: [u8; 11] = [
        0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x08, 0x00,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("pki_status=granted"))
        .stdout(predicate::str::contains("fail_info_tlv_hex=03020800"))
        .stdout(predicate::str::contains("fail_info_flags_json=null"))
        .stdout(predicate::str::contains("time_stamp_token_prefix_hex=-"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_rejects_fail_info_before_status_string() {
    let der: [u8; 16] = [
        0x30, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x02, 0x03, 0x02, 0x00, 0xc0, 0x30, 0x03, 0x0c, 0x01,
        0x77,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("could not parse TimeStampResp"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_rejects_oversized_pki_status_integer() {
    let der: [u8; 12] = [
        0x30, 0x0a, 0x30, 0x08, 0x02, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("could not parse TimeStampResp"));
}

#[test]
fn portable_rfc3161_timestamp_resp_inspect_rejects_pkifreetext_ia5string() {
    let der: [u8; 12] = [
        0x30, 0x0a, 0x30, 0x08, 0x02, 0x01, 0x02, 0x30, 0x03, 0x16, 0x01, 0x41,
    ];
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ts.der");
    std::fs::write(&p, der.as_slice()).unwrap();
    let mut cmd = portable_cmd();
    cmd.args(["rfc3161-timestamp-resp-inspect", p.to_str().unwrap()]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("could not parse TimeStampResp"));
}
