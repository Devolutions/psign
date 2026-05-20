use assert_cmd::Command;
use base64::Engine as _;
use predicates::prelude::*;
use psign_sip_digest::{pkcs7, verify_pe};
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::signature::Keypair;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::Encode;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

struct TestCert {
    der: Vec<u8>,
    key_pem: String,
}

fn psign_tool() -> Command {
    Command::cargo_bin("psign-tool").expect("psign-tool binary")
}

fn test_cert_der(subject_cn: &str) -> Vec<u8> {
    test_cert(subject_cn).der
}

fn test_cert(subject_cn: &str) -> TestCert {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa private key");
    let key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("PKCS#8 private key PEM")
        .to_string();
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let subject = Name::from_str(&format!("CN={subject_cn}")).expect("subject name");
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
    let der = builder
        .build::<rsa::pkcs1v15::Signature>()
        .expect("self-signed certificate")
        .to_der()
        .expect("certificate DER");
    TestCert { der, key_pem }
}

fn sha1_upper(bytes: &[u8]) -> String {
    Sha1::digest(bytes)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

fn tiny32_unsigned_fixture() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pe-authenticode-upstream/tiny32.efi")
}

fn colon_lower_thumbprint(thumbprint: &str) -> String {
    thumbprint
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex utf8"))
        .collect::<Vec<_>>()
        .join(":")
        .to_ascii_lowercase()
}

#[test]
fn cert_store_e2e_import_list_print_export_remove_der() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let exported = temp.path().join("exported.der");
    let der = test_cert_der("psign cert store test");
    let thumbprint = sha1_upper(&der);
    std::fs::write(&cert_path, &der).expect("write cert");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "my"])
        .arg(&cert_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={thumbprint}"
        )));

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "MY"])
        .arg(&cert_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificate already present"))
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={thumbprint}"
        )));

    assert!(
        store_dir
            .join("CurrentUser")
            .join("MY")
            .join(format!("{thumbprint}.der"))
            .exists()
    );

    psign_tool()
        .args(["cert-store", "list", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "MY", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&thumbprint))
        .stdout(predicate::str::contains("psign cert store test"));
    let list_assert = psign_tool()
        .args(["cert-store", "list", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "MY", "--json"])
        .assert()
        .success();
    let json: serde_json::Value =
        serde_json::from_slice(&list_assert.get_output().stdout).expect("list JSON");
    assert_eq!(json["scope"], "CurrentUser");
    assert_eq!(json["store"], "MY");
    assert_eq!(json["certificates"][0]["thumbprint_sha1"], thumbprint);

    psign_tool()
        .args(["cert-store", "print", "--cert-store-dir"])
        .arg(&store_dir)
        .args([
            "--store",
            "MY",
            "--sha1",
            &colon_lower_thumbprint(&thumbprint),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(&thumbprint))
        .stdout(predicate::str::contains("subject="));

    psign_tool()
        .args(["cert-store", "export", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "MY", "--sha1", &thumbprint, "--out"])
        .arg(&exported)
        .assert()
        .success();
    assert_eq!(std::fs::read(&exported).expect("exported cert"), der);

    psign_tool()
        .args(["cert-store", "remove", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "MY", "--sha1", &thumbprint])
        .assert()
        .success();
    assert!(
        !store_dir
            .join("CurrentUser")
            .join("MY")
            .join(format!("{thumbprint}.der"))
            .exists()
    );

    psign_tool()
        .args(["cert-store", "print", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "MY", "--sha1", &thumbprint])
        .assert()
        .failure()
        .stderr(predicate::str::contains("was not found"));

    psign_tool()
        .args(["cert-store", "remove", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--store", "MY", "--sha1", &thumbprint])
        .assert()
        .failure()
        .stderr(predicate::str::contains("was not found"));
}

#[test]
fn cert_store_e2e_import_accepts_pem_and_machine_scope() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.pem");
    let der = test_cert_der("psign cert store pem test");
    let thumbprint = sha1_upper(&der);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 utf8"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    std::fs::write(&cert_path, pem).expect("write pem");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--machine-store", "--store", "root"])
        .arg(&cert_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={thumbprint}"
        )));

    assert!(
        store_dir
            .join("LocalMachine")
            .join("Root")
            .join(format!("{thumbprint}.der"))
            .exists()
    );

    let list_assert = psign_tool()
        .args(["cert-store", "list", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--machine-store", "--store", "Root", "--json"])
        .assert()
        .success();
    let json: serde_json::Value =
        serde_json::from_slice(&list_assert.get_output().stdout).expect("machine root list JSON");
    assert_eq!(json["scope"], "LocalMachine");
    assert_eq!(json["store"], "Root");
    assert_eq!(json["certificates"][0]["thumbprint_sha1"], thumbprint);
}

#[test]
fn cert_store_export_refuses_existing_output_without_force() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let exported = temp.path().join("exported.der");
    let der = test_cert_der("psign cert store force test");
    let thumbprint = sha1_upper(&der);
    std::fs::write(&cert_path, &der).expect("write cert");
    std::fs::write(&exported, b"exists").expect("write output");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .arg(&cert_path)
        .assert()
        .success();

    psign_tool()
        .args(["cert-store", "export", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint, "--out"])
        .arg(&exported)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn cert_store_e2e_import_export_private_key() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let key_path = temp.path().join("cert.key");
    let exported_cert = temp.path().join("exported.der");
    let exported_key = temp.path().join("exported.key");
    let fixture = test_cert("psign cert store key test");
    let thumbprint = sha1_upper(&fixture.der);
    std::fs::write(&cert_path, &fixture.der).expect("write cert");
    std::fs::write(&key_path, &fixture.key_pem).expect("write key");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--key"])
        .arg(&key_path)
        .arg(&cert_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={thumbprint}"
        )))
        .stdout(predicate::str::contains("Imported private key"));

    let stored_key = store_dir
        .join("CurrentUser")
        .join("MY")
        .join(format!("{thumbprint}.key"));
    assert!(stored_key.exists());

    let list_assert = psign_tool()
        .args(["cert-store", "list", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--json"])
        .assert()
        .success();
    let json: serde_json::Value =
        serde_json::from_slice(&list_assert.get_output().stdout).expect("list JSON");
    assert_eq!(json["certificates"][0]["has_private_key"], true);

    psign_tool()
        .args(["cert-store", "print", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint])
        .assert()
        .success()
        .stdout(predicate::str::contains("has_private_key=true"));

    psign_tool()
        .args(["cert-store", "export", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint, "--out"])
        .arg(&exported_cert)
        .args(["--with-key", "--key-out"])
        .arg(&exported_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("key_out="));
    assert_eq!(
        std::fs::read(&exported_cert).expect("exported cert"),
        fixture.der
    );
    let exported_key_text = std::fs::read_to_string(&exported_key).expect("exported key");
    assert!(exported_key_text.contains("-----BEGIN PRIVATE KEY-----"));

    psign_tool()
        .args(["cert-store", "remove", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint])
        .assert()
        .success()
        .stdout(predicate::str::contains("key_removed=true"));
    assert!(!stored_key.exists());
}

#[test]
fn cert_store_export_with_key_fails_when_key_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let exported_cert = temp.path().join("exported.der");
    let exported_key = temp.path().join("exported.key");
    let der = test_cert_der("psign missing key test");
    let thumbprint = sha1_upper(&der);
    std::fs::write(&cert_path, &der).expect("write cert");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .arg(&cert_path)
        .assert()
        .success();

    psign_tool()
        .args(["cert-store", "export", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint, "--out"])
        .arg(&exported_cert)
        .args(["--with-key", "--key-out"])
        .arg(&exported_key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("private key"));
}

#[test]
fn cert_store_import_rejects_private_key_for_different_cert() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let key_path = temp.path().join("wrong.key");
    let cert = test_cert("psign key mismatch cert");
    let wrong_key = test_cert("psign key mismatch other");
    std::fs::write(&cert_path, &cert.der).expect("write cert");
    std::fs::write(&key_path, &wrong_key.key_pem).expect("write wrong key");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--key"])
        .arg(&key_path)
        .arg(&cert_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("private key does not match"));
}

#[test]
fn portable_sign_sha1_uses_cert_store_identity_for_pe() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let key_path = temp.path().join("cert.key");
    let target = temp.path().join("signed.efi");
    let fixture = test_cert("psign portable sign test");
    let thumbprint = sha1_upper(&fixture.der);
    std::fs::write(&cert_path, &fixture.der).expect("write cert");
    std::fs::write(&key_path, &fixture.key_pem).expect("write key");
    std::fs::copy(tiny32_unsigned_fixture(), &target).expect("copy unsigned PE");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--key"])
        .arg(&key_path)
        .arg(&cert_path)
        .assert()
        .success();

    psign_tool()
        .args(["--mode", "portable", "sign", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["/sha1", &thumbprint, "/s", "MY", "/fd", "SHA256"])
        .arg(&target)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signed:"))
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={thumbprint}"
        )));

    let signed = std::fs::read(&target).expect("read signed PE");
    verify_pe::verify_pe_authenticode_digest_consistency(&signed).expect("PE digest consistency");
    let pkcs7_der = verify_pe::pe_first_pkcs7_signed_data_der(&signed).expect("PKCS#7");
    let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7_der).expect("SignedData");
    let signer = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
    let cert = pkcs7::signed_data_certificate_for_signer_identifier(&sd, &signer.sid)
        .expect("signer cert");
    assert_eq!(
        sha1_upper(&cert.to_der().expect("signer cert DER")),
        thumbprint
    );
}

#[test]
fn portable_sign_sha1_fails_when_private_key_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let target = temp.path().join("signed.efi");
    let der = test_cert_der("psign portable missing key");
    let thumbprint = sha1_upper(&der);
    std::fs::write(&cert_path, &der).expect("write cert");
    std::fs::copy(tiny32_unsigned_fixture(), &target).expect("copy unsigned PE");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .arg(&cert_path)
        .assert()
        .success();

    psign_tool()
        .args(["--mode", "portable", "sign", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint, "--fd", "SHA256"])
        .arg(&target)
        .assert()
        .failure()
        .stderr(predicate::str::contains("private key"));
}

#[test]
fn portable_sign_sha1_rejects_unsupported_format() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let key_path = temp.path().join("cert.key");
    let target = temp.path().join("plain.txt");
    let fixture = test_cert("psign portable unsupported format");
    let thumbprint = sha1_upper(&fixture.der);
    std::fs::write(&cert_path, &fixture.der).expect("write cert");
    std::fs::write(&key_path, &fixture.key_pem).expect("write key");
    std::fs::write(&target, b"not a PE").expect("write txt");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--key"])
        .arg(&key_path)
        .arg(&cert_path)
        .assert()
        .success();

    psign_tool()
        .args(["--mode", "portable", "sign", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint, "--fd", "SHA256"])
        .arg(&target)
        .assert()
        .failure()
        .stderr(predicate::str::contains("PE/WinMD"));
}

fn test_pfx_der(fixture: &TestCert, password: &str) -> Vec<u8> {
    use picky::key::PrivateKey;
    use picky::pkcs12::{
        Pfx, Pkcs12CryptoContext, Pkcs12HashAlgorithm, Pkcs12MacAlgorithmHmac, SafeBag,
        SafeContents,
    };
    use picky::x509::Cert;

    let pem = picky::pem::parse_pem(fixture.key_pem.as_bytes()).expect("private key PEM");
    let key = PrivateKey::from_pkcs8(pem.data()).expect("picky private key");
    let cert = Cert::from_der(&fixture.der).expect("picky cert");
    let cert_bag = SafeBag::new_certificate(cert, vec![]).expect("cert bag");
    let key_bag = SafeBag::new_key(key, vec![]).expect("key bag");
    let mut context = Pkcs12CryptoContext::new_with_password(password).expect("PFX context");
    Pfx::new_with_hmac(
        vec![SafeContents::new(vec![cert_bag, key_bag])],
        Pkcs12MacAlgorithmHmac::new(Pkcs12HashAlgorithm::Sha256),
        &mut context,
    )
    .expect("PFX")
    .to_der()
    .expect("PFX DER")
}

#[test]
fn cert_store_e2e_import_pfx_extracts_cert_and_key() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let pfx_path = temp.path().join("cert.pfx");
    let exported_cert = temp.path().join("exported-from-pfx.der");
    let exported_key = temp.path().join("exported-from-pfx.key");
    let fixture = test_cert("psign pfx import test");
    let thumbprint = sha1_upper(&fixture.der);
    let pfx = test_pfx_der(&fixture, "secret");
    std::fs::write(&pfx_path, pfx).expect("write pfx");

    psign_tool()
        .args(["cert-store", "import-pfx", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--password", "secret"])
        .arg(&pfx_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={thumbprint}"
        )))
        .stdout(predicate::str::contains("Imported private key"));

    assert!(
        store_dir
            .join("CurrentUser")
            .join("MY")
            .join(format!("{thumbprint}.der"))
            .exists()
    );
    assert!(
        store_dir
            .join("CurrentUser")
            .join("MY")
            .join(format!("{thumbprint}.key"))
            .exists()
    );

    psign_tool()
        .args(["cert-store", "export", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--sha1", &thumbprint, "--out"])
        .arg(&exported_cert)
        .args(["--with-key", "--key-out"])
        .arg(&exported_key)
        .assert()
        .success();
    assert_eq!(
        std::fs::read(&exported_cert).expect("exported PFX cert"),
        fixture.der
    );
    let exported_key_text = std::fs::read_to_string(&exported_key).expect("exported PFX key");
    assert!(exported_key_text.contains("-----BEGIN PRIVATE KEY-----"));

    psign_tool()
        .args(["cert-store", "import-pfx", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["--password", "wrong"])
        .arg(&pfx_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("parse PFX"));
}

#[test]
fn cert_store_e2e_base_dir_env_and_explicit_override() {
    let temp = tempfile::tempdir().expect("tempdir");
    let env_store_dir = temp.path().join("env-store");
    let explicit_store_dir = temp.path().join("explicit-store");
    let env_cert_path = temp.path().join("env-cert.der");
    let explicit_cert_path = temp.path().join("explicit-cert.der");
    let env_der = test_cert_der("psign env store test");
    let explicit_der = test_cert_der("psign explicit store test");
    let env_thumbprint = sha1_upper(&env_der);
    let explicit_thumbprint = sha1_upper(&explicit_der);
    std::fs::write(&env_cert_path, &env_der).expect("write env cert");
    std::fs::write(&explicit_cert_path, &explicit_der).expect("write explicit cert");

    psign_tool()
        .env("PSIGN_CERT_STORE", &env_store_dir)
        .args(["cert-store", "import"])
        .arg(&env_cert_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={env_thumbprint}"
        )));
    assert!(
        env_store_dir
            .join("CurrentUser")
            .join("MY")
            .join(format!("{env_thumbprint}.der"))
            .exists()
    );

    psign_tool()
        .env("PSIGN_CERT_STORE", &env_store_dir)
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&explicit_store_dir)
        .arg(&explicit_cert_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "thumbprint_sha1={explicit_thumbprint}"
        )));
    assert!(
        explicit_store_dir
            .join("CurrentUser")
            .join("MY")
            .join(format!("{explicit_thumbprint}.der"))
            .exists()
    );
    assert!(
        !env_store_dir
            .join("CurrentUser")
            .join("MY")
            .join(format!("{explicit_thumbprint}.der"))
            .exists()
    );
}

#[test]
fn cert_store_e2e_windows_style_aliases() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store_dir = temp.path().join("cert-store");
    let cert_path = temp.path().join("cert.der");
    let der = test_cert_der("psign slash alias store test");
    let thumbprint = sha1_upper(&der);
    std::fs::write(&cert_path, &der).expect("write cert");

    psign_tool()
        .args(["cert-store", "import", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["/sm", "/s", "Root"])
        .arg(&cert_path)
        .assert()
        .success();

    psign_tool()
        .args(["cert-store", "print", "--cert-store-dir"])
        .arg(&store_dir)
        .args(["/sm", "/s", "Root", "/sha1", &thumbprint])
        .assert()
        .success()
        .stdout(predicate::str::contains(&thumbprint))
        .stdout(predicate::str::contains("slash alias store test"));
}
