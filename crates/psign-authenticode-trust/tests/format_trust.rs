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
