//! Generic (explicit-anchor) trust for script, MSIX, NuGet, and VSIX signatures, using fixtures
//! signed by the Devolutions test CA with native tooling.

use psign_authenticode_trust::{
    TrustVerifyPeOptions, parse_verification_date_ymd, trust_verify_path,
};
use std::path::{Path, PathBuf};

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn test_ca_opts() -> TrustVerifyPeOptions {
    TrustVerifyPeOptions {
        trusted_ca_files: vec![repo(
            "tests/fixtures/devolutions-authenticode/authenticode-test-ca.crt",
        )],
        // Inside the test certificate's validity window (2022-03-22 .. 2027-03-22).
        verification_instant_override: Some(parse_verification_date_ymd("2026-06-01").unwrap()),
        ..Default::default()
    }
}

#[test]
fn wsh_scripts_trust_verify() {
    for rel in [
        "tests/fixtures/generated-signed/scripts/wsh/js/utf8-crlf.js",
        "tests/fixtures/generated-signed/scripts/wsh/js/utf16le-bom-lf.js",
        "tests/fixtures/generated-signed/scripts/wsh/vbs/utf8-bom-crlf.vbs",
        "tests/fixtures/generated-signed/scripts/wsh/wsf/utf8-crlf.wsf",
        "tests/fixtures/generated-signed/scripts/wsh-probe/jse/utf8-crlf.jse",
        "tests/fixtures/generated-signed/scripts/wsh-probe/vbe/utf8-crlf.vbe",
    ] {
        let report = trust_verify_path(&repo(rel), &test_ca_opts())
            .unwrap_or_else(|e| panic!("{rel}: {e:#}"));
        assert_eq!(report.pkcs7_entries_verified, 1, "{rel}");
    }
}

#[test]
fn msix_packages_trust_verify() {
    for rel in [
        "tests/fixtures/generated-signed/msix/sample.msix",
        "tests/fixtures/generated-signed/msix/sample.appx",
        "tests/fixtures/generated-signed/msix/sample.msixbundle",
        "tests/fixtures/generated-signed/msix/sample.appxbundle",
        "tests/fixtures/msix-edge-cases/signed/flat-sha384.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-sha512.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-nocompress.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-multiblock-paths.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-pagehashes.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-resource.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-resource.signed.appx",
        "tests/fixtures/msix-edge-cases/signed/flat-optional-nonexec.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-skip-pcontent-hash.signed.msix",
        "tests/fixtures/msix-edge-cases/signed/flat-plain-zip.portable-signed.msix",
        "tests/fixtures/msix-edge-cases/signed/bundle-multi.signed.msixbundle",
        "tests/fixtures/msix-edge-cases/signed/bundle-multi-presigned-children.portable-signed.msixbundle",
        "tests/fixtures/msix-edge-cases/signed/bundle-multi.signed.appxbundle",
        "tests/fixtures/msix-edge-cases/signed/bundle-sparse.signed.msixbundle",
        "tests/fixtures/msix-edge-cases/signed/bundle-sparse.signed.appxbundle",
    ] {
        trust_verify_path(&repo(rel), &test_ca_opts()).unwrap_or_else(|e| panic!("{rel}: {e:#}"));
    }
}

#[test]
fn msix_integrity_returns_signer_and_rejects_modified_package() {
    use psign_authenticode_trust::trust_verify_msix::verify_msix_signature_without_trust;

    let data = std::fs::read(repo("tests/fixtures/generated-signed/msix/sample.msix")).unwrap();
    let cert = verify_msix_signature_without_trust(&data, "msix").expect("valid signature");
    let (pkcs7, _) = psign_sip_digest::msix_digest::msix_verified_signature(&data, "msix").unwrap();
    let inspection = psign_authenticode_trust::inspect_authenticode_pkcs7_der(&pkcs7).unwrap();
    use base64::Engine as _;
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(cert),
        inspection.signers[0]
            .signer_certificate_der_base64
            .as_deref()
            .unwrap()
    );

    let mut bad_package = data;
    bad_package[40] ^= 1;
    assert!(verify_msix_signature_without_trust(&bad_package, "msix").is_err());
}

#[test]
fn msix_auto_authroot_respects_explicit_anchors() {
    let opts = test_ca_opts();
    let (resolved, cache) =
        psign_authenticode_trust::trust_verify_msix::msix_options_with_auto_authroot(&opts)
            .expect("explicit anchors");
    assert!(cache.is_none());
    assert_eq!(resolved.trusted_ca_files, opts.trusted_ca_files);
    assert!(resolved.authroot_cab.is_none());
}

#[test]
fn msix_current_or_timestamp_rejects_override_and_untrusted_certificate() {
    use psign_authenticode_trust::trust_verify_msix::trust_verify_msix_current_or_timestamp;
    let data = std::fs::read(repo("tests/fixtures/generated-signed/msix/sample.msix")).unwrap();
    let opts = test_ca_opts();
    assert!(trust_verify_msix_current_or_timestamp(&data, "msix", &opts).is_err());
    let untrusted = TrustVerifyPeOptions::default();
    let error = trust_verify_msix_current_or_timestamp(&data, "msix", &untrusted).unwrap_err();
    assert!(format!("{error:#}").contains("no trust anchors configured"));
}

#[test]
fn msix_system_roots_are_loadable() {
    let (opts, cache) =
        psign_authenticode_trust::trust_verify_msix::msix_options_with_auto_authroot(
            &TrustVerifyPeOptions::default(),
        )
        .expect("load OS roots");
    assert!(cache.is_none());
    assert!(!opts.trusted_ca_der.is_empty());
    let (anchors, _) =
        psign_authenticode_trust::load_trust_material(&opts).expect("parse OS roots");
    assert!(anchors.thumbprint_count() > 0);
}

#[cfg(windows)]
#[test]
fn windows_authenticode_rejects_unsigned_and_nul_paths() {
    use std::os::windows::ffi::OsStringExt;
    let temp = tempfile::NamedTempFile::new().unwrap();
    assert!(psign_authenticode_trust::windows::verify_authenticode_path(temp.path()).is_err());
    let nul_path = std::ffi::OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]);
    assert!(
        psign_authenticode_trust::windows::verify_authenticode_path(Path::new(&nul_path)).is_err()
    );
}

#[test]
fn msix_skip_pcontent_hash_and_nested_bundle_child_tamper_are_rejected() {
    use std::io::{Cursor, Read, Write};

    // Even when AXPC uses the SkipPackageContentHash sentinel, block-map validation must
    // reject payload byte modifications without changing ZIP record lengths.
    let mut skip_axpc = std::fs::read(repo(
        "tests/fixtures/msix-edge-cases/signed/flat-skip-pcontent-hash.signed.msix",
    ))
    .unwrap();
    let archive = zip::ZipArchive::new(Cursor::new(&skip_axpc)).unwrap();
    let logo = archive
        .file_names()
        .find(|n| n.ends_with(".png"))
        .unwrap()
        .to_owned();
    drop(archive);
    let mut archive = zip::ZipArchive::new(Cursor::new(&skip_axpc)).unwrap();
    let data_start = usize::try_from(archive.by_name(&logo).unwrap().data_start()).unwrap();
    drop(archive);
    skip_axpc[data_start] ^= 0xFF;
    let err =
        psign_authenticode_trust::trust_verify_msix_bytes(&skip_axpc, "msix", &test_ca_opts())
            .unwrap_err();
    let msg = format!("{err:#}");
    let lower = msg.to_ascii_lowercase();
    assert!(
        lower.contains("checksum") || lower.contains("crc") || lower.contains("mismatch"),
        "expected checksum/block mismatch when tampering SkipPackageContentHash payload: {msg}"
    );

    // Tampering inside a subdirectory resource child of a 3-child bundle must fail verification.
    let bundle_bytes = std::fs::read(repo(
        "tests/fixtures/msix-edge-cases/signed/bundle-multi-presigned-children.portable-signed.msixbundle",
    ))
    .unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(&bundle_bytes)).unwrap();
    let child = archive.by_name("resources/scale-200.msix").unwrap();
    let child_data_start = usize::try_from(child.data_start()).unwrap();
    let mut child_bytes = Vec::new();
    let mut child = child;
    child.read_to_end(&mut child_bytes).unwrap();
    drop(child);
    drop(archive);

    // Corrupt a byte inside the nested child's AppxSignature.p7x PKCS#7 payload and keep outer CRC valid?
    // Even simpler: corrupting inside the stored child triggers either outer AXPC/CRC or child SIP failure.
    let mut tampered = bundle_bytes;
    let _ = Write::write_all(
        &mut &mut tampered[child_data_start + 40..child_data_start + 41],
        &[0xAA],
    );
    assert!(
        psign_authenticode_trust::trust_verify_msix_bytes(&tampered, "msixbundle", &test_ca_opts())
            .is_err(),
        "tampering with subdirectory bundle child must fail trust_verify_msix_bytes"
    );
}

#[test]
fn nuget_packages_trust_verify() {
    for rel in [
        "tests/fixtures/package-signing/signed/sample.signed.nupkg",
        "tests/fixtures/package-signing/signed/sample.signed.snupkg",
        "tests/fixtures/package-signing/signed/with-pe.signed.nupkg",
    ] {
        trust_verify_path(&repo(rel), &test_ca_opts()).unwrap_or_else(|e| panic!("{rel}: {e:#}"));
    }
}

#[test]
fn nuget_package_tamper_is_rejected() {
    let mut bytes = std::fs::read(repo(
        "tests/fixtures/package-signing/signed/sample.signed.nupkg",
    ))
    .unwrap();
    // Flip a byte inside the first local file entry's data (well before the signature entry).
    bytes[80] ^= 0x01;
    let err =
        psign_authenticode_trust::trust_verify_nuget_bytes(&bytes, &test_ca_opts()).unwrap_err();
    assert!(
        format!("{err:#}").to_lowercase().contains("mismatch")
            || format!("{err:#}").contains("ZIP"),
        "{err:#}"
    );
}

#[test]
fn vsix_packages_trust_verify() {
    for rel in [
        "tests/fixtures/package-signing/signed/sample.signed.vsix",
        "tests/fixtures/package-signing/signed/nested.signed.vsix",
        "tests/fixtures/package-signing/signed/deep-nested.signed.vsix",
    ] {
        trust_verify_path(&repo(rel), &test_ca_opts()).unwrap_or_else(|e| panic!("{rel}: {e:#}"));
    }
}

/// Rewrite a ZIP, letting `edit` change or add entries (name, bytes).
fn rewrite_zip(
    src: &[u8],
    edit: impl Fn(&str, Vec<u8>) -> Vec<u8>,
    extra: Option<(&str, &[u8])>,
) -> Vec<u8> {
    use std::io::{Read, Write};
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(src)).unwrap();
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let name = file.name().to_string();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        out.start_file(name.clone(), zip::write::FileOptions::default())
            .unwrap();
        out.write_all(&edit(&name, bytes)).unwrap();
    }
    if let Some((name, bytes)) = extra {
        out.start_file(name, zip::write::FileOptions::default())
            .unwrap();
        out.write_all(bytes).unwrap();
    }
    out.finish().unwrap().into_inner()
}

fn vsix_err(bytes: &[u8]) -> String {
    let err =
        psign_authenticode_trust::trust_verify_vsix_bytes(bytes, &test_ca_opts()).unwrap_err();
    format!("{err:#}")
}

#[test]
fn vsix_tampering_is_rejected() {
    let signed = std::fs::read(repo(
        "tests/fixtures/package-signing/signed/sample.signed.vsix",
    ))
    .unwrap();
    // Unmodified round trip through the rewriter still verifies.
    let same = rewrite_zip(&signed, |_, b| b, None);
    psign_authenticode_trust::trust_verify_vsix_bytes(&same, &test_ca_opts())
        .expect("rewritten zip");

    let tampered = rewrite_zip(
        &signed,
        |n, mut b| {
            if n == "payload.txt" {
                b[0] ^= 1;
            }
            b
        },
        None,
    );
    assert!(vsix_err(&tampered).contains("digest mismatch for /payload.txt"));

    let injected = rewrite_zip(&signed, |_, b| b, Some(("evil.dll", b"MZ")));
    assert!(vsix_err(&injected).contains("not covered by the signature"));

    let retyped = rewrite_zip(
        &signed,
        |n, b| {
            if n == "[Content_Types].xml" {
                String::from_utf8(b)
                    .unwrap()
                    .replace("text/plain", "application/octet-stream")
                    .into_bytes()
            } else {
                b
            }
        },
        None,
    );
    assert!(vsix_err(&retyped).contains("content type"));

    let resigned = rewrite_zip(
        &signed,
        |n, b| {
            if n.starts_with("package/services/digital-signature/xml-signature/") {
                let t = String::from_utf8(b).unwrap();
                // Change a signed byte inside SignedInfo (a DigestValue character).
                t.replacen("<DigestValue>z", "<DigestValue>Z", 1)
                    .into_bytes()
            } else {
                b
            }
        },
        None,
    );
    assert!(
        vsix_err(&resigned).contains("SignatureValue does not verify"),
        "{}",
        vsix_err(&resigned)
    );
}

fn sign_test_msix(
    signer_cert: x509_cert::Certificate,
    chain_certs: Vec<x509_cert::Certificate>,
    private_key: rsa::RsaPrivateKey,
) -> Vec<u8> {
    let unsigned = std::fs::read(repo("tests/fixtures/generated-unsigned/msix/sample.msix"))
        .expect("read unsigned sample.msix");
    let staged = psign_sip_digest::appx_package::stage_msix_family_for_signature(
        &unsigned,
        "msix",
        psign_sip_digest::pe_digest::PeAuthenticodeHashKind::Sha256,
    )
    .expect("stage msix");
    let pkcs7 = psign_sip_digest::pkcs7::create_msix_authenticode_pkcs7_der_rsa(
        &staged,
        "msix",
        psign_sip_digest::pkcs7::AuthenticodeSigningDigest::Sha256,
        signer_cert,
        chain_certs,
        private_key,
    )
    .expect("create msix pkcs7");
    let mut p7x = Vec::with_capacity(4 + pkcs7.len());
    p7x.extend_from_slice(b"PKCX");
    p7x.extend_from_slice(&pkcs7);
    psign_sip_digest::appx_package::replace_msix_signature_part(&staged, &p7x)
        .expect("embed AppxSignature.p7x")
}

fn generate_self_signed_code_signing_cert(
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
) -> (x509_cert::Certificate, Vec<u8>, rsa::RsaPrivateKey) {
    use der::asn1::{BitString, ObjectIdentifier, OctetString};
    use der::{Decode, Encode};
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{Keypair, SignatureEncoding, Signer};
    use sha2::{Digest as _, Sha256};
    use x509_cert::ext::AsExtension;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, TbsCertificate, Version};

    let mut rng = rand::rngs::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate rsa key");
    let signing_key = SigningKey::<Sha256>::new(key.clone());
    let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key()).expect("spki");
    let subject =
        psign_authenticode_trust::test_pki::parse_distinguished_name("CN=Psign Self-Signed Test")
            .expect("dn");
    let alg = AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        parameters: Some(der::Any::null()),
    };
    let eku = ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3")]);
    let ku = KeyUsage(KeyUsages::DigitalSignature.into());
    let bc = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    };
    let ski_digest = sha1::Sha1::digest(spki.subject_public_key.raw_bytes());
    let ski = x509_cert::ext::pkix::SubjectKeyIdentifier(
        OctetString::new(ski_digest.as_slice()).expect("ski"),
    );
    let extensions = vec![
        bc.to_extension(&subject, &[]).expect("bc ext"),
        ku.to_extension(&subject, &[]).expect("ku ext"),
        eku.to_extension(&subject, &[]).expect("eku ext"),
        ski.to_extension(&subject, &[]).expect("ski ext"),
    ];
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[0x01, 0x23, 0x45, 0x67]).expect("serial"),
        signature: alg.clone(),
        issuer: subject.clone(),
        validity: Validity {
            not_before: Time::try_from(not_before).expect("not_before"),
            not_after: Time::try_from(not_after).expect("not_after"),
        },
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let tbs_der = tbs.to_der().expect("tbs der");
    let sig = signing_key.sign(&tbs_der);
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(sig.to_bytes().as_ref()).expect("sig bitstring"),
    };
    let cert_der = cert.to_der().expect("cert der");
    let cert = Certificate::from_der(&cert_der).expect("redecode cert");
    (cert, cert_der, key)
}

#[test]
fn verified_signatures_and_thumbprint_helpers_are_populated() {
    use psign_authenticode_trust::{
        ArtifactSigningPolicy, cert_der_sha1_hex, cert_der_sha256_hex, cert_sha1_thumbprint,
        cert_sha256_thumbprint, trust_verify_msix_bytes, trust_verify_vsix_bytes,
    };

    // Thumbprint helpers agree on the pinned Microsoft root.
    let root =
        psign_authenticode_trust::artifact_signing::MICROSOFT_IDENTITY_VERIFICATION_ROOT_2020
            .certificate()
            .expect("pinned root");
    let root_der = root.to_der().expect("root der");
    assert_eq!(
        cert_sha256_thumbprint(&root).expect("sha256"),
        psign_authenticode_trust::artifact_signing::MICROSOFT_IDENTITY_VERIFICATION_ROOT_2020
            .sha256
    );
    assert_eq!(
        cert_sha1_thumbprint(&root).expect("sha1"),
        psign_authenticode_trust::artifact_signing::MICROSOFT_IDENTITY_VERIFICATION_ROOT_2020.sha1
    );
    assert_eq!(
        cert_der_sha256_hex(&root_der),
        "5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270"
    );
    assert_eq!(
        cert_der_sha1_hex(&root_der),
        "f40042e2e5f7e8ef8189fed15519aece42c3bfa2"
    );

    // Generic MSIX trust populates verified_signatures.
    let msix = std::fs::read(repo("tests/fixtures/generated-signed/msix/sample.msix")).unwrap();
    let report = trust_verify_msix_bytes(&msix, "msix", &test_ca_opts()).expect("verify msix");
    assert_eq!(report.verified_signatures.len(), 1);
    let sig = &report.verified_signatures[0];
    assert_eq!(sig.signature_index, 0);
    assert!(!sig.signer_certificate_der.is_empty());
    assert_eq!(
        sig.signer_sha256_hex,
        cert_der_sha256_hex(&sig.signer_certificate_der)
    );
    assert_eq!(
        sig.signer_sha1_hex,
        cert_der_sha1_hex(&sig.signer_certificate_der)
    );
    assert!(!sig.signer_subject.is_empty());
    assert!(sig.root_subject.is_some());
    assert!(sig.root_sha1_hex.as_deref().is_some_and(|h| h.len() == 40));
    assert!(
        sig.root_sha256_hex
            .as_deref()
            .is_some_and(|h| h.len() == 64)
    );
    assert!(!sig.timestamped);
    assert!(sig.artifact_signing.is_none());

    // Artifact Signing with private_trust_root_der populates both artifact_signing and verified_signatures.
    let pt_msix = std::fs::read(repo(
        "tests/fixtures/artifact-signing/private-trust/sample.msix",
    ))
    .unwrap();
    let pt_root_der = std::fs::read(repo(
        "tests/fixtures/artifact-signing/private-trust/root.cer",
    ))
    .unwrap();
    let pt_report = trust_verify_msix_bytes(
        &pt_msix,
        "msix",
        &TrustVerifyPeOptions {
            artifact_signing: Some(ArtifactSigningPolicy {
                expected_publisher_ids: vec!["11.22.33.44.55.66.77.88".into()],
                private_trust_root_der: vec![pt_root_der.clone()],
                require_timestamp: false,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .expect("private trust msix via DER root");
    assert_eq!(pt_report.artifact_signing.len(), 1);
    assert_eq!(pt_report.verified_signatures.len(), 1);
    let pt_sig = &pt_report.verified_signatures[0];
    assert_eq!(
        pt_sig
            .artifact_signing
            .as_ref()
            .map(|id| id.publisher_id.as_str()),
        Some("11.22.33.44.55.66.77.88")
    );
    assert_eq!(
        pt_sig.root_sha256_hex.as_deref(),
        Some(cert_der_sha256_hex(&pt_root_der).as_str())
    );

    // Generic VSIX trust also populates verified_signatures.
    let vsix = std::fs::read(repo(
        "tests/fixtures/package-signing/signed/sample.signed.vsix",
    ))
    .unwrap();
    let vsix_report = trust_verify_vsix_bytes(&vsix, &test_ca_opts()).expect("verify vsix");
    assert_eq!(vsix_report.verified_signatures.len(), 1);
    assert_eq!(
        vsix_report.verified_signatures[0].signer_sha256_hex.len(),
        64
    );
}

#[test]
fn msix_pinning_artifact_signing_private_and_public_trust() {
    use psign_authenticode_trust::{
        ArtifactSigningCertificateKind, MsixPinVerifyOptions, MsixRecommendedPin,
        test_pki::{
            CodeSigningCertSpec, RootCaSpec, generate_root_ca, issue_code_signing_cert,
            load_ca_issuer_from_cert_and_key,
        },
        verify_msix_for_pinning, verify_msix_with_pins,
    };
    use rsa::pkcs8::DecodePrivateKey;

    let pt_msix = std::fs::read(repo(
        "tests/fixtures/artifact-signing/private-trust/sample.msix",
    ))
    .unwrap();
    let pt_root_path = repo("tests/fixtures/artifact-signing/private-trust/root.cer");
    let pt_root_der = std::fs::read(&pt_root_path).unwrap();

    // Private Trust publisher ID pin succeeds with file or in-memory DER root.
    let verified = verify_msix_with_pins(
        &pt_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_artifact_signing_publisher_ids: vec!["11.22.33.44.55.66.77.88".into()],
            trusted_ca_files: vec![pt_root_path.clone()],
            ..Default::default()
        },
    )
    .expect("private trust pin with file root");
    assert_eq!(
        verified.recommended_pin,
        MsixRecommendedPin::ArtifactSigningPublisherId("11.22.33.44.55.66.77.88".into())
    );
    assert_eq!(
        verified.artifact_signing.as_ref().map(|id| id.kind),
        Some(ArtifactSigningCertificateKind::PrivateTrust)
    );

    let verified_der = verify_msix_with_pins(
        &pt_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_artifact_signing_publisher_ids: vec!["11.22.33.44.55.66.77.88".into()],
            trusted_ca_der: vec![pt_root_der],
            ..Default::default()
        },
    )
    .expect("private trust pin with DER root");
    assert_eq!(verified_der.signer_sha256_hex, verified.signer_sha256_hex);

    // Mismatched publisher ID fails.
    assert!(
        verify_msix_with_pins(
            &pt_msix,
            "msix",
            &MsixPinVerifyOptions {
                expected_artifact_signing_publisher_ids: vec!["99.99.99.99".into()],
                trusted_ca_files: vec![pt_root_path.clone()],
                ..Default::default()
            },
        )
        .is_err()
    );

    // Private Trust without subscriber root fails closed.
    assert!(
        verify_msix_with_pins(
            &pt_msix,
            "msix",
            &MsixPinVerifyOptions {
                expected_artifact_signing_publisher_ids: vec!["11.22.33.44.55.66.77.88".into()],
                ..Default::default()
            },
        )
        .is_err()
    );

    // verify_msix_for_pinning auto-detects Private Trust when subscriber root is supplied.
    let auto_pt = verify_msix_for_pinning(&pt_msix, "msix", std::slice::from_ref(&pt_root_path))
        .expect("auto-pin private trust");
    assert_eq!(
        auto_pt.recommended_pin,
        MsixRecommendedPin::ArtifactSigningPublisherId("11.22.33.44.55.66.77.88".into())
    );

    // Private Trust CI Policy EKU is rejected for Artifact Signing publisher pinning and never
    // recommended as an Artifact Signing pin.
    let ca = generate_root_ca(&RootCaSpec {
        subject: "CN=Psign CI Policy Test CA".into(),
        validity_days: 30,
        key_bits: 2048,
    })
    .expect("ca");
    let ca_issuer =
        load_ca_issuer_from_cert_and_key(&ca.cert_der, ca.private_key_pem.as_bytes(), Vec::new())
            .expect("ca issuer");
    let ci_leaf = issue_code_signing_cert(
        &ca_issuer,
        &CodeSigningCertSpec {
            subject: "CN=Test Code Signing Certificate".into(),
            validity_days: 30,
            key_bits: 2048,
            extra_eku_oids: vec!["1.3.6.1.4.1.311.97.1.4.1.11.22.33.44".into()],
        },
    )
    .expect("ci policy leaf");
    let ci_key = rsa::RsaPrivateKey::from_pkcs8_pem(&ci_leaf.private_key_pem).expect("ci key");
    let ci_sha256 = psign_authenticode_trust::cert_der_sha256_hex(&ci_leaf.cert_der);
    let ci_msix = sign_test_msix(ci_leaf.cert, vec![ca.cert.clone()], ci_key);
    let ci_err = verify_msix_with_pins(
        &ci_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_artifact_signing_publisher_ids: vec!["11.22.33.44".into()],
            trusted_ca_der: vec![ca.cert_der.clone()],
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        format!("{ci_err:#}").contains("Private Trust CI Policy"),
        "expected Private Trust CI Policy rejection, got: {ci_err:#}"
    );
    let ci_ca_file = tempfile::NamedTempFile::new().expect("temp ci ca");
    std::fs::write(ci_ca_file.path(), &ca.cert_der).expect("write ci ca");
    let ci_auto_err =
        verify_msix_for_pinning(&ci_msix, "msix", &[ci_ca_file.path().to_path_buf()]).unwrap_err();
    assert!(
        format!("{ci_auto_err:#}").contains("Private Trust CI Policy"),
        "expected verify_msix_for_pinning to reject Private Trust CI Policy, got: {ci_auto_err:#}"
    );
    let ci_thumb_err = verify_msix_with_pins(
        &ci_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_cert_thumbprints: vec![ci_sha256],
            allow_pinned_leaf_trust: true,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        format!("{ci_thumb_err:#}").contains("Private Trust CI Policy"),
        "expected thumbprint-pinned verify_msix_with_pins to reject Private Trust CI Policy, got: {ci_thumb_err:#}"
    );

    // Fake Public Trust EKU signed by a non-Microsoft CA must fail Public Trust verification
    // against pinned Microsoft Identity Verification Root CA 2020.
    let fake_pub_leaf = issue_code_signing_cert(
        &ca_issuer,
        &CodeSigningCertSpec {
            subject: "CN=Test Code Signing Certificate".into(),
            validity_days: 30,
            key_bits: 2048,
            extra_eku_oids: vec![
                "1.3.6.1.4.1.311.97.1.0".into(),
                "1.3.6.1.4.1.311.97.12345.67890".into(),
            ],
        },
    )
    .expect("fake public trust leaf");
    let fake_pub_key =
        rsa::RsaPrivateKey::from_pkcs8_pem(&fake_pub_leaf.private_key_pem).expect("fake key");
    let fake_pub_msix = sign_test_msix(fake_pub_leaf.cert, vec![ca.cert], fake_pub_key);
    assert!(
        verify_msix_with_pins(
            &fake_pub_msix,
            "msix",
            &MsixPinVerifyOptions {
                expected_artifact_signing_publisher_ids: vec!["12345.67890".into()],
                ..Default::default()
            },
        )
        .is_err()
    );
}

#[test]
fn msix_thumbprint_pinning_and_auto_pinning() {
    use psign_authenticode_trust::{
        MsixPinVerifyOptions, MsixRecommendedPin, cert_der_sha1_hex, cert_der_sha256_hex,
        test_pki::{
            CodeSigningCertSpec, RootCaSpec, generate_root_ca, issue_code_signing_cert,
            load_ca_issuer_from_cert_and_key,
        },
        verify_msix_for_pinning, verify_msix_with_pins,
    };
    use rsa::pkcs8::DecodePrivateKey;
    use std::time::{Duration, SystemTime};

    // 1. CA-issued regular cert: explicit CA + thumbprint pins (SHA-256 and SHA-1) + auto-pinning.
    let ca = generate_root_ca(&RootCaSpec {
        subject: "CN=Psign Pinning Test CA".into(),
        validity_days: 30,
        key_bits: 2048,
    })
    .expect("ca");
    let ca_issuer =
        load_ca_issuer_from_cert_and_key(&ca.cert_der, ca.private_key_pem.as_bytes(), Vec::new())
            .expect("ca issuer");
    let leaf = issue_code_signing_cert(
        &ca_issuer,
        &CodeSigningCertSpec {
            subject: "CN=Test Code Signing Certificate".into(),
            validity_days: 30,
            key_bits: 2048,
            extra_eku_oids: Vec::new(),
        },
    )
    .expect("leaf");
    let leaf_sha256 = cert_der_sha256_hex(&leaf.cert_der);
    let leaf_sha1 = cert_der_sha1_hex(&leaf.cert_der);
    let leaf_key = rsa::RsaPrivateKey::from_pkcs8_pem(&leaf.private_key_pem).expect("leaf key");
    let ca_msix = sign_test_msix(leaf.cert, vec![ca.cert], leaf_key);

    let ca_file = tempfile::NamedTempFile::new().expect("temp ca");
    std::fs::write(ca_file.path(), &ca.cert_der).expect("write ca");

    // SHA-256 with prefix, uppercase, and colons.
    let colon_upper = leaf_sha256
        .to_ascii_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    let pinned_sha256 = verify_msix_with_pins(
        &ca_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_cert_thumbprints: vec![format!("sha256:{colon_upper}")],
            trusted_ca_files: vec![ca_file.path().to_path_buf()],
            ..Default::default()
        },
    )
    .expect("pin by sha256 with explicit CA");
    assert_eq!(pinned_sha256.signer_sha256_hex, leaf_sha256);
    assert_eq!(pinned_sha256.signer_sha1_hex, leaf_sha1);
    assert_eq!(
        pinned_sha256.recommended_pin,
        MsixRecommendedPin::CertificateSha256(leaf_sha256.clone())
    );

    // SHA-1 pin with explicit CA DER.
    let pinned_sha1 = verify_msix_with_pins(
        &ca_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_cert_thumbprints: vec![format!("sha1:{leaf_sha1}")],
            trusted_ca_der: vec![ca.cert_der.clone()],
            ..Default::default()
        },
    )
    .expect("pin by sha1 with explicit CA DER");
    assert_eq!(pinned_sha1.signer_sha1_hex, leaf_sha1);

    // Wrong thumbprint is rejected.
    assert!(
        verify_msix_with_pins(
            &ca_msix,
            "msix",
            &MsixPinVerifyOptions {
                expected_cert_thumbprints: vec!["00".repeat(32)],
                trusted_ca_der: vec![ca.cert_der.clone()],
                ..Default::default()
            },
        )
        .is_err()
    );

    // Tampered MSIX bytes are rejected even with matching thumbprint and CA.
    let mut tampered = ca_msix.clone();
    tampered[40] ^= 0xff;
    assert!(
        verify_msix_with_pins(
            &tampered,
            "msix",
            &MsixPinVerifyOptions {
                expected_cert_thumbprints: vec![leaf_sha256.clone()],
                trusted_ca_der: vec![ca.cert_der.clone()],
                ..Default::default()
            },
        )
        .is_err()
    );

    // Private-CA-issued leaf without explicit CA succeeds when allow_pinned_leaf_trust is true.
    verify_msix_with_pins(
        &ca_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_cert_thumbprints: vec![leaf_sha256.clone()],
            allow_pinned_leaf_trust: true,
            ..Default::default()
        },
    )
    .expect("CA-issued leaf with allow_pinned_leaf_trust");

    // verify_msix_for_pinning recommends CertificateSha256 for regular cert with explicit CA,
    // and fails closed without explicit CA.
    let auto_regular = verify_msix_for_pinning(&ca_msix, "msix", &[ca_file.path().to_path_buf()])
        .expect("auto-pin regular cert");
    assert_eq!(
        auto_regular.recommended_pin,
        MsixRecommendedPin::CertificateSha256(leaf_sha256)
    );
    assert!(verify_msix_for_pinning(&ca_msix, "msix", &[]).is_err());

    // 2. Self-signed currently-valid cert: allowed only with allow_pinned_leaf_trust.
    let now = SystemTime::now();
    let (self_cert, self_der, self_key) = generate_self_signed_code_signing_cert(
        now - Duration::from_secs(3600),
        now + Duration::from_secs(86400 * 7),
    );
    let self_sha256 = cert_der_sha256_hex(&self_der);
    let self_msix = sign_test_msix(self_cert, Vec::new(), self_key);

    assert!(verify_msix_for_pinning(&self_msix, "msix", &[]).is_err());
    assert!(
        verify_msix_with_pins(
            &self_msix,
            "msix",
            &MsixPinVerifyOptions {
                expected_cert_thumbprints: vec![self_sha256.clone()],
                allow_pinned_leaf_trust: false,
                ..Default::default()
            },
        )
        .is_err()
    );
    let self_verified = verify_msix_with_pins(
        &self_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_cert_thumbprints: vec![self_sha256.clone()],
            allow_pinned_leaf_trust: true,
            ..Default::default()
        },
    )
    .expect("self-signed leaf with allow_pinned_leaf_trust");
    assert_eq!(
        self_verified.recommended_pin,
        MsixRecommendedPin::CertificateSha256(self_sha256)
    );

    // 3. Expired untimestamped self-signed cert is rejected even with allow_pinned_leaf_trust.
    let (expired_cert, expired_der, expired_key) = generate_self_signed_code_signing_cert(
        now - Duration::from_secs(86400 * 30),
        now - Duration::from_secs(3600),
    );
    let expired_sha256 = cert_der_sha256_hex(&expired_der);
    let expired_msix = sign_test_msix(expired_cert, Vec::new(), expired_key);
    let expired_err = verify_msix_with_pins(
        &expired_msix,
        "msix",
        &MsixPinVerifyOptions {
            expected_cert_thumbprints: vec![expired_sha256],
            allow_pinned_leaf_trust: true,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(
        format!("{expired_err:#}").contains("not valid at current time"),
        "expected expired untimestamped rejection, got: {expired_err:#}"
    );
}
