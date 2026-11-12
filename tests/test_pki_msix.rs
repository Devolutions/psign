use std::io::Read as _;
use std::path::PathBuf;

use assert_cmd::Command;
use base64::Engine as _;
use predicates::prelude::*;
use serde_json::Value;

fn psign_tool() -> Command {
    Command::cargo_bin("psign-tool").expect("psign-tool binary")
}

fn unsigned_msix_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/generated-unsigned/msix/sample.msix")
}

fn extract_zip_entry(zip_path: &std::path::Path, entry_name: &str) -> Vec<u8> {
    let file = std::fs::File::open(zip_path).expect("open ZIP");
    let mut archive = zip::ZipArchive::new(file).expect("parse ZIP");
    let mut entry = archive.by_name(entry_name).expect("find ZIP entry");
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).expect("read ZIP entry");
    bytes
}

#[test]
fn portable_test_pki_signs_msix_with_embedded_chain_and_passes_portable_verify_inspect_and_trust() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dir = temp.path();

    let root_cer = dir.join("root-ca.cer");
    let root_pem = dir.join("root-ca.pem");
    let root_pfx = dir.join("root-ca.pfx");
    let root_out = psign_tool()
        .args([
            "portable",
            "generate-root-ca",
            "--subject",
            "CN=Devolutions Static Feed Test Root CA, O=Devolutions Inc., C=CA",
            "--cert-out",
        ])
        .arg(&root_cer)
        .arg("--pem-out")
        .arg(&root_pem)
        .arg("--pfx-out")
        .arg(&root_pfx)
        .args(["--password", "RootPass123!", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let root_json: Value = serde_json::from_slice(&root_out).expect("parse root JSON");
    assert_eq!(root_json["is_ca"], true);

    let publisher = "CN=Devolutions Inc., O=Devolutions Inc., L=Lavaltrie, S=Quebec, C=CA";
    let codesign_pfx = dir.join("codesign.pfx");
    let codesign_cer = dir.join("codesign.cer");
    let codesign_out = psign_tool()
        .args(["portable", "issue-code-signing-cert", "--ca-pfx"])
        .arg(&root_pfx)
        .args([
            "--ca-password",
            "RootPass123!",
            "--subject",
            publisher,
            "--pfx-out",
        ])
        .arg(&codesign_pfx)
        .args(["--password", "SignPass123!", "--cert-out"])
        .arg(&codesign_cer)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let codesign_json: Value = serde_json::from_slice(&codesign_out).expect("parse codesign JSON");
    assert_eq!(codesign_json["subject"], publisher);
    assert_eq!(codesign_json["chain_certificate_count"], 1);
    assert_eq!(
        codesign_json["eku_oids"],
        serde_json::json!(["1.3.6.1.5.5.7.3.3"])
    );

    let tls_pfx = dir.join("tls-server.pfx");
    let tls_pem = dir.join("tls-fullchain.pem");
    let tls_key = dir.join("tls-server.key");
    let tls_out = psign_tool()
        .args(["portable", "issue-tls-server-cert", "--ca-pfx"])
        .arg(&root_pfx)
        .args([
            "--ca-password",
            "RootPass123!",
            "--dns",
            "winget.devolutions.test",
            "--dns",
            "localhost",
            "--ip",
            "127.0.0.1",
            "--pfx-out",
        ])
        .arg(&tls_pfx)
        .args(["--password", "TlsPass123!", "--pem-out"])
        .arg(&tls_pem)
        .arg("--key-out")
        .arg(&tls_key)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let tls_json: Value = serde_json::from_slice(&tls_out).expect("parse TLS JSON");
    assert_eq!(tls_json["subject"], "CN=winget.devolutions.test");
    assert_eq!(
        tls_json["eku_oids"],
        serde_json::json!(["1.3.6.1.5.5.7.3.1"])
    );
    assert_eq!(
        tls_json["dns_names"],
        serde_json::json!(["winget.devolutions.test", "localhost"])
    );
    assert_eq!(tls_json["ip_addresses"], serde_json::json!(["127.0.0.1"]));
    let tls_pem_text = std::fs::read_to_string(&tls_pem).expect("read TLS fullchain PEM");
    assert_eq!(
        tls_pem_text.matches("-----BEGIN CERTIFICATE-----").count(),
        2,
        "TLS PEM bundle must include leaf + Root CA"
    );

    // Prepare MSIX Publisher to match signer Subject DN, then sign via @response.rsp like pinget.
    let source_msix = dir.join("source2.msix");
    psign_tool()
        .args(["portable", "msix-set-publisher"])
        .arg(unsigned_msix_fixture())
        .args(["--publisher", publisher, "--output"])
        .arg(&source_msix)
        .assert()
        .success();

    let rsp_path = dir.join("sign.rsp");
    let rsp_contents = format!(
        "--mode\nportable\nsign\n--pfx\n\"{}\"\n--password=SignPass123!\n--digest\nsha256\n\"{}\"\n",
        codesign_pfx.display(),
        source_msix.display()
    );
    std::fs::write(&rsp_path, rsp_contents).expect("write response file");

    psign_tool()
        .arg(format!("@{}", rsp_path.display()))
        .assert()
        .success();

    // 1) Digest verification (`portable verify-msix`).
    psign_tool()
        .args(["portable", "verify-msix"])
        .arg(&source_msix)
        .assert()
        .success();

    // 2) AppxSignature.p7x inspection (`portable inspect-pkcs7`).
    let p7x_bytes = extract_zip_entry(&source_msix, "AppxSignature.p7x");
    let p7x_path = dir.join("AppxSignature.p7x");
    std::fs::write(&p7x_path, &p7x_bytes).expect("write AppxSignature.p7x");
    let inspect_stdout = psign_tool()
        .args(["portable", "inspect-pkcs7"])
        .arg(&p7x_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let inspect: Value = serde_json::from_slice(&inspect_stdout).expect("parse inspect-pkcs7 JSON");
    assert_eq!(
        inspect["certificate_count"], 2,
        "AppxSignature.p7x must embed both signer leaf and CA chain certificate from PFX"
    );
    let signer_b64 = inspect["signers"][0]["signer_certificate_der_base64"]
        .as_str()
        .expect("signer_certificate_der_base64");
    let signer_der = base64::engine::general_purpose::STANDARD
        .decode(signer_b64)
        .expect("decode signer DER");
    assert_eq!(
        signer_der,
        std::fs::read(&codesign_cer).expect("read codesign.cer"),
        "inspect-pkcs7 signer_certificate_der_base64 must match leaf code signing certificate"
    );

    // 3) Chain trust verification (`portable trust-verify-msix --trusted-ca` and `--mode portable verify --trusted-ca`).
    psign_tool()
        .args(["portable", "trust-verify-msix"])
        .arg(&source_msix)
        .arg("--trusted-ca")
        .arg(&root_cer)
        .assert()
        .success();

    psign_tool()
        .args(["--mode", "portable", "verify", "--trusted-ca"])
        .arg(&root_cer)
        .arg(&source_msix)
        .assert()
        .success();

    // 4) Unrelated root CA must be rejected.
    let wrong_root = dir.join("wrong-root.cer");
    psign_tool()
        .args([
            "portable",
            "generate-root-ca",
            "--subject",
            "CN=Unrelated Root CA",
            "--cert-out",
        ])
        .arg(&wrong_root)
        .assert()
        .success();
    psign_tool()
        .args(["portable", "trust-verify-msix"])
        .arg(&source_msix)
        .arg("--trusted-ca")
        .arg(&wrong_root)
        .assert()
        .failure();
}

#[test]
fn portable_test_pki_3tier_pfx_embeds_intermediate_and_verifies_against_root_only() {
    use der::Encode as _;
    use psign_authenticode_trust::test_pki::{
        CaIssuerMaterial, CodeSigningCertSpec, RootCaSpec, encode_pfx_der, generate_root_ca,
        issue_code_signing_cert, parse_distinguished_name,
    };
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{Keypair as _, SignatureEncoding as _, Signer as _};
    use sha1::Digest as _;
    use sha2::Sha256;
    use std::time::{Duration, SystemTime};
    use x509_cert::der::asn1::{Any, AnyRef, BitString, OctetString, UtcTime};
    use x509_cert::ext::AsExtension as _;
    use x509_cert::ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
    };
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, TbsCertificate, Version};

    let temp = tempfile::tempdir().expect("tempdir");
    let dir = temp.path();

    let root = generate_root_ca(&RootCaSpec {
        subject: "CN=Three-Tier Test Root CA, O=Devolutions Inc., C=CA".into(),
        validity_days: 3650,
        key_bits: 2048,
    })
    .expect("generate root");
    let root_cer = dir.join("root.cer");
    std::fs::write(&root_cer, &root.cert_der).expect("write root.cer");

    // Mint an Intermediate Sub-CA signed by Root CA.
    let sub_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("sub CA key");
    let sub_signing_key = SigningKey::<Sha256>::new(sub_key.clone());
    let sub_spki =
        SubjectPublicKeyInfoOwned::from_key(sub_signing_key.verifying_key()).expect("sub SPKI");
    let sub_subject =
        parse_distinguished_name("CN=Three-Tier Test Issuing CA, O=Devolutions Inc., C=CA")
            .expect("sub subject");
    let now = SystemTime::now();
    let validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_system_time(now - Duration::from_secs(3600)).expect("not_before"),
        ),
        not_after: Time::UtcTime(
            UtcTime::from_system_time(now + Duration::from_secs(86_400 * 365)).expect("not_after"),
        ),
    };
    let alg = AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        parameters: Some(Any::from(AnyRef::NULL)),
    };
    let sub_ski = SubjectKeyIdentifier(
        OctetString::new(sha1::Sha1::digest(sub_spki.subject_public_key.raw_bytes()).to_vec())
            .expect("sub SKI"),
    );
    let root_ski = root
        .cert
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()
        .expect("decode root SKI")
        .expect("root SKI present")
        .1
        .0;
    let sub_exts = vec![
        sub_ski.to_extension(&sub_subject, &[]).expect("ext"),
        AuthorityKeyIdentifier {
            key_identifier: Some(root_ski),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        }
        .to_extension(&sub_subject, &[])
        .expect("ext"),
        BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }
        .to_extension(&sub_subject, &[])
        .expect("ext"),
        KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
            .to_extension(&sub_subject, &[])
            .expect("ext"),
    ];
    let sub_tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(77u32),
        signature: alg.clone(),
        issuer: root.cert.tbs_certificate.subject.clone(),
        validity,
        subject: sub_subject,
        subject_public_key_info: sub_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(sub_exts),
    };
    let root_key = psign_sip_digest::rdp::parse_rsa_private_key(root.private_key_pem.as_bytes())
        .expect("root RSA key");
    let root_signer = SigningKey::<Sha256>::new(root_key);
    let sub_sig = root_signer.sign(&sub_tbs.to_der().expect("sub TBS DER"));
    let sub_cert = Certificate {
        tbs_certificate: sub_tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(&sub_sig.to_bytes()).expect("sub sig bits"),
    };
    let sub_der = sub_cert.to_der().expect("sub cert DER");

    let sub_ca_material = CaIssuerMaterial {
        cert: sub_cert,
        cert_der: sub_der,
        private_key: sub_key,
        extra_chain_certs_der: vec![root.cert_der.clone()],
    };
    let publisher = "CN=Test Code Signing Certificate";
    let leaf = issue_code_signing_cert(
        &sub_ca_material,
        &CodeSigningCertSpec {
            subject: publisher.into(),
            validity_days: 30,
            key_bits: 2048,
            extra_eku_oids: Vec::new(),
        },
    )
    .expect("issue 3-tier leaf");
    assert_eq!(leaf.chain_certs_der.len(), 2);

    let pfx_path = dir.join("three-tier.pfx");
    std::fs::write(&pfx_path, encode_pfx_der(&leaf, "Tier3Pass!").expect("PFX")).expect("write");

    let signed_msix = dir.join("three-tier.msix");
    std::fs::copy(unsigned_msix_fixture(), &signed_msix).expect("copy MSIX");
    psign_tool()
        .args(["--mode", "portable", "sign", "--pfx"])
        .arg(&pfx_path)
        .args(["--password=Tier3Pass!", "--digest", "sha256"])
        .arg(&signed_msix)
        .assert()
        .success();

    // Without --additional-cert, trust-verify-msix must still walk Leaf -> SubCA -> RootCA!
    psign_tool()
        .args(["portable", "trust-verify-msix"])
        .arg(&signed_msix)
        .arg("--trusted-ca")
        .arg(&root_cer)
        .assert()
        .success();
}

#[test]
fn portable_test_pki_rejects_non_ca_issuer_and_missing_tls_sans() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dir = temp.path();
    let root_pfx = dir.join("root.pfx");
    let leaf_pfx = dir.join("leaf.pfx");
    let bad_out = dir.join("bad.pfx");

    psign_tool()
        .args(["portable", "generate-root-ca", "--pfx-out"])
        .arg(&root_pfx)
        .args(["--password", "pw"])
        .assert()
        .success();

    psign_tool()
        .args(["portable", "issue-code-signing-cert", "--ca-pfx"])
        .arg(&root_pfx)
        .args([
            "--ca-password",
            "pw",
            "--subject",
            "CN=Leaf Not CA",
            "--pfx-out",
        ])
        .arg(&leaf_pfx)
        .args(["--password", "pw"])
        .assert()
        .success();

    // Leaf cert cannot issue child certificates.
    psign_tool()
        .args(["portable", "issue-code-signing-cert", "--ca-pfx"])
        .arg(&leaf_pfx)
        .args([
            "--ca-password",
            "pw",
            "--subject",
            "CN=Grandchild",
            "--pfx-out",
        ])
        .arg(&bad_out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a CA certificate"));

    // TLS server cert requires at least one --dns or --ip SAN.
    psign_tool()
        .args(["portable", "issue-tls-server-cert", "--ca-pfx"])
        .arg(&root_pfx)
        .args(["--ca-password", "pw", "--pfx-out"])
        .arg(&bad_out)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Subject Alternative Name"));
}

#[cfg(windows)]
#[test]
fn windows_cryptoapi_and_appxsip_accept_generated_test_pki_without_machine_store_mutation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dir = temp.path();

    let root_cer = dir.join("root-ca.cer");
    let root_pfx = dir.join("root-ca.pfx");
    psign_tool()
        .args([
            "portable",
            "generate-root-ca",
            "--subject",
            "CN=Devolutions Static Feed Test Root CA, O=Devolutions Inc., C=CA",
            "--cert-out",
        ])
        .arg(&root_cer)
        .arg("--pfx-out")
        .arg(&root_pfx)
        .args(["--password", "RootPass123!"])
        .assert()
        .success();

    let publisher = "CN=Devolutions Inc., O=Devolutions Inc., L=Lavaltrie, S=Quebec, C=CA";
    let codesign_pfx = dir.join("codesign.pfx");
    psign_tool()
        .args(["portable", "issue-code-signing-cert", "--ca-pfx"])
        .arg(&root_pfx)
        .args([
            "--ca-password",
            "RootPass123!",
            "--subject",
            publisher,
            "--pfx-out",
        ])
        .arg(&codesign_pfx)
        .args(["--password", "SignPass123!"])
        .assert()
        .success();

    let tls_pfx = dir.join("tls-server.pfx");
    psign_tool()
        .args(["portable", "issue-tls-server-cert", "--ca-pfx"])
        .arg(&root_pfx)
        .args([
            "--ca-password",
            "RootPass123!",
            "--dns",
            "winget.devolutions.test",
            "--dns",
            "localhost",
            "--ip",
            "127.0.0.1",
            "--pfx-out",
        ])
        .arg(&tls_pfx)
        .args(["--password", "TlsPass123!"])
        .assert()
        .success();

    let signed_msix = dir.join("source2.msix");
    psign_tool()
        .args(["portable", "msix-set-publisher"])
        .arg(unsigned_msix_fixture())
        .args(["--publisher", publisher, "--output"])
        .arg(&signed_msix)
        .assert()
        .success();

    psign_tool()
        .args(["--mode", "portable", "sign", "--pfx"])
        .arg(&codesign_pfx)
        .args(["--password=SignPass123!", "--digest", "sha256"])
        .arg(&signed_msix)
        .assert()
        .success();

    // Native Windows AppxSip / WinVerifyTrust check (without touching LocalMachine\Root):
    // must accept the MSIX digest, PKCS#7, and EKU, failing ONLY on CERT_E_UNTRUSTEDROOT (0x800B0109).
    let win_verify = psign_tool()
        .args(["--mode", "windows", "verify", "--policy", "pa"])
        .arg(&signed_msix)
        .output()
        .expect("run windows verify");
    let verify_text = format!(
        "{}{}",
        String::from_utf8_lossy(&win_verify.stdout),
        String::from_utf8_lossy(&win_verify.stderr)
    );
    assert!(
        !verify_text.contains("0x80096010"),
        "AppxSip rejected MSIX digest (TRUST_E_BAD_DIGEST):\n{verify_text}"
    );
    assert!(
        !verify_text.contains("0x800B0110"),
        "WinVerifyTrust rejected certificate usage (CERT_E_WRONG_USAGE):\n{verify_text}"
    );
    assert!(
        verify_text.contains("0x800B0109"),
        "Expected only CERT_E_UNTRUSTEDROOT without OS store installation:\n{verify_text}"
    );

    // Validate PFX import, Windows Subject DN order, Code Signing chain, and TLS Server chain
    // using Windows CryptoAPI / .NET X509Chain CustomRootTrust purely in memory (zero store writes!).
    let pwsh_check = format!(
        r#"
$ErrorActionPreference = 'Stop'
$X509 = 'System.Security.Cryptography.X509Certificates'
$root = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new('{root}')

$csCol = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$csCol.Import('{cs_pfx}', 'SignPass123!', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
if ($csCol.Count -ne 2) {{ throw "Expected 2 certs in codesign PFX, got $($csCol.Count)" }}
$csLeaf = $csCol | Where-Object {{ $_.HasPrivateKey }} | Select-Object -First 1
if (-not $csLeaf) {{ throw 'Code signing PFX leaf is missing private key in Windows CryptoAPI' }}
if ($csLeaf.Subject -cne '{publisher}') {{ throw "Windows Subject mismatch: '$($csLeaf.Subject)' vs '{publisher}'" }}

$csChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$csChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$csChain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
[void]$csChain.ChainPolicy.CustomTrustStore.Add($root)
[void]$csChain.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
if (-not $csChain.Build($csLeaf)) {{
    $statuses = ($csChain.ChainStatus | ForEach-Object {{ "$($_.Status): $($_.StatusInformation)" }}) -join '; '
    throw "Windows Code Signing chain failed: $statuses"
}}

$tlsCol = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
$tlsCol.Import('{tls_pfx}', 'TlsPass123!', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
if ($tlsCol.Count -ne 2) {{ throw "Expected 2 certs in TLS PFX, got $($tlsCol.Count)" }}
$tlsLeaf = $tlsCol | Where-Object {{ $_.HasPrivateKey }} | Select-Object -First 1
if (-not $tlsLeaf) {{ throw 'TLS PFX leaf is missing private key in Windows CryptoAPI' }}

$tlsChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$tlsChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$tlsChain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
[void]$tlsChain.ChainPolicy.CustomTrustStore.Add($root)
[void]$tlsChain.ChainPolicy.ApplicationPolicy.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
if (-not $tlsChain.Build($tlsLeaf)) {{
    $statuses = ($tlsChain.ChainStatus | ForEach-Object {{ "$($_.Status): $($_.StatusInformation)" }}) -join '; '
    throw "Windows TLS Server chain failed: $statuses"
}}
$sanExt = $tlsLeaf.Extensions | Where-Object {{ $_.Oid.Value -eq '2.5.29.17' }} | Select-Object -First 1
if (-not $sanExt) {{ throw 'TLS cert missing SAN extension' }}
$sanFormatted = $sanExt.Format($false)
if ($sanFormatted -notmatch 'winget\.devolutions\.test' -or $sanFormatted -notmatch '127\.0\.0\.1') {{
    throw "Unexpected SAN extension formatting: $sanFormatted"
}}
Write-Output 'WINDOWS_CRYPTOAPI_CUSTOM_TRUST_OK'
"#,
        root = root_cer.display(),
        cs_pfx = codesign_pfx.display(),
        tls_pfx = tls_pfx.display(),
        publisher = publisher,
    );

    let pwsh = std::process::Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-Command", &pwsh_check])
        .output()
        .expect("run pwsh X509Chain verification");
    let stdout = String::from_utf8_lossy(&pwsh.stdout);
    let stderr = String::from_utf8_lossy(&pwsh.stderr);
    assert!(
        pwsh.status.success() && stdout.contains("WINDOWS_CRYPTOAPI_CUSTOM_TRUST_OK"),
        "pwsh Windows CryptoAPI verification failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
