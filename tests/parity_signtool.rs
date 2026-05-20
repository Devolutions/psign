#![cfg(windows)]

use assert_cmd::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
#[ignore = "requires native signtool.exe and local fixture"]
fn verify_matches_native_exit_code_for_known_signed_binary() {
    let fixture =
        Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe");
    if !fixture.exists() {
        return;
    }

    let native = Command::new(native_signtool())
        .arg("verify")
        .arg("/pa")
        .arg(fixture)
        .output()
        .expect("failed to execute native signtool");

    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("verify")
        .arg("--policy")
        .arg("pa")
        .arg(fixture)
        .output()
        .expect("failed to execute psign-tool");

    assert_eq!(native.status.success(), rust.status.success());
}

#[test]
#[ignore = "requires native signtool.exe and local fixture"]
fn verify_default_policy_matches_native_failure() {
    let fixture =
        Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe");
    if !fixture.exists() {
        return;
    }

    let native = Command::new(native_signtool())
        .arg("verify")
        .arg(fixture)
        .output()
        .expect("failed to execute native signtool");

    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("verify")
        .arg("--policy")
        .arg("default")
        .arg(fixture)
        .output()
        .expect("failed to execute psign-tool");

    assert_eq!(native.status.success(), rust.status.success());
}

fn env_path(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[cfg(feature = "artifact-signing-rest")]
fn env_flag_true(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

fn native_signtool() -> &'static str {
    r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
}

fn native_signtool_optional_path() -> Option<PathBuf> {
    env_path("SIGNTOOL_EXE")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .or_else(|| {
            let p = PathBuf::from(native_signtool());
            p.exists().then_some(p)
        })
}

#[test]
#[ignore = "requires PSIGN_UNSIGNED_FIXTURE,PSIGN_TEST_PFX,PSIGN_TEST_PFX_PASSWORD"]
fn sign_semantic_parity_creates_verifiable_signature() {
    let unsigned = match env_path("PSIGN_UNSIGNED_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let pfx_password = env_path("PSIGN_TEST_PFX_PASSWORD");
    let signed_out = std::env::temp_dir().join("psign_signed_semantic.exe");
    let _ = std::fs::copy(&unsigned, &signed_out).expect("copy unsigned fixture");

    let mut rust = Command::cargo_bin("psign-tool").expect("binary available");
    rust.arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&signed_out);
    if let Some(p) = pfx_password {
        rust.arg("--password").arg(p);
    }
    let rust_out = rust.output().expect("run psign-tool sign");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let native = Command::new(native_signtool())
        .arg("verify")
        .arg("/pa")
        .arg(&signed_out)
        .output()
        .expect("run native verify");
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stdout)
    );
}

#[test]
#[ignore = "requires PSIGN_SIGNED_FIXTURE and PSIGN_TIMESTAMP_URL"]
fn timestamp_semantic_parity_adds_countersignature() {
    let signed_fixture = match env_path("PSIGN_SIGNED_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let tsa = match env_path("PSIGN_TIMESTAMP_URL") {
        Some(v) => v,
        None => return,
    };
    let ts_out = std::env::temp_dir().join("psign_timestamp_semantic.exe");
    let _ = std::fs::copy(&signed_fixture, &ts_out).expect("copy signed fixture");

    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("timestamp")
        .arg("--rfc3161-url")
        .arg(&tsa)
        .arg("--digest")
        .arg("sha256")
        .arg(&ts_out)
        .output()
        .expect("run psign-tool timestamp");
    assert!(
        rust.status.success(),
        "{}",
        String::from_utf8_lossy(&rust.stderr)
    );

    let native = Command::new(native_signtool())
        .arg("verify")
        .arg("/pa")
        .arg("/v")
        .arg(&ts_out)
        .output()
        .expect("run native verify after timestamp");
    let out = String::from_utf8_lossy(&native.stdout).to_ascii_lowercase();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stdout)
    );
    assert!(out.contains("rfc3161") || out.contains("timestamp"));
}

#[test]
#[ignore = "requires PSIGN_DETACHED_CONTENT and PSIGN_DETACHED_PKCS7"]
fn detached_semantic_parity_matches_native_integrity() {
    let content = match env_path("PSIGN_DETACHED_CONTENT") {
        Some(v) => v,
        None => return,
    };
    let sig = match env_path("PSIGN_DETACHED_PKCS7") {
        Some(v) => v,
        None => return,
    };
    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .args(["verify", "--policy", "pa", "--allow-test-root"])
        .arg(&content)
        .arg("--detached-pkcs7")
        .arg(&sig)
        .output()
        .expect("run rust detached verify");
    assert!(
        rust.status.success(),
        "{}",
        String::from_utf8_lossy(&rust.stderr)
    );
}

#[test]
#[ignore = "requires PSIGN_CATALOG_TARGET and PSIGN_CATALOG_FILE"]
fn catalog_semantic_path_executes_in_rust() {
    let target = match env_path("PSIGN_CATALOG_TARGET") {
        Some(v) => v,
        None => return,
    };
    let catalog = match env_path("PSIGN_CATALOG_FILE") {
        Some(v) => v,
        None => return,
    };
    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("verify")
        .arg(&target)
        .arg("--catalog")
        .arg(&catalog)
        .output()
        .expect("run rust catalog verify");
    assert!(
        rust.status.success(),
        "{}",
        String::from_utf8_lossy(&rust.stderr)
    );

    let rust_os = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .args(["verify", "--os-version-check", "386:10.0.26100.0"])
        .arg(&target)
        .arg("--catalog")
        .arg(&catalog)
        .output()
        .expect("run rust catalog verify with os-version-check");
    assert!(
        rust_os.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_os.stderr)
    );
}

#[test]
#[ignore = "requires PSIGN_RDP_TEST_CERT_SHA256; optional PSIGN_RDP_UNSIGNED_FIXTURE"]
fn rdp_sign_writes_native_signature_records() {
    let thumbprint = match env_path("PSIGN_RDP_TEST_CERT_SHA256") {
        Some(v) => v,
        None => return,
    };
    let out = std::env::temp_dir().join("psign_rdp_signed_fixture.rdp");
    if let Some(fixture) = env_path("PSIGN_RDP_UNSIGNED_FIXTURE") {
        std::fs::copy(fixture, &out).expect("copy rdp fixture");
    } else {
        std::fs::write(
            &out,
            b"full address:s:server.example.test\r\nserver port:i:3389\r\n",
        )
        .expect("write rdp fixture");
    }

    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("rdp")
        .arg("--sha256")
        .arg(&thumbprint)
        .arg(&out)
        .output()
        .expect("run psign-tool rdp");
    assert!(
        rust.status.success(),
        "{}{}",
        String::from_utf8_lossy(&rust.stdout),
        String::from_utf8_lossy(&rust.stderr)
    );

    let text = psign::rdp::decode_rdp_text(&std::fs::read(&out).expect("read signed rdp"));
    assert!(text.contains("SignScope:s:Full Address,Alternate Full Address"));
    assert!(text.contains("Signature:s:"));
    let _ = std::fs::remove_file(out);
}

#[test]
#[ignore = "requires PSIGN_MULTISIG_FIXTURE"]
fn multisig_verify_path_executes_in_rust() {
    let fixture = match env_path("PSIGN_MULTISIG_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("verify")
        .arg(fixture)
        .arg("--all-signatures")
        .output()
        .expect("run rust multisig verify");
    assert!(
        rust.status.success(),
        "{}",
        String::from_utf8_lossy(&rust.stderr)
    );
}

#[test]
#[ignore = "requires PSIGN_REVOCATION_FIXTURE"]
fn revocation_policy_path_executes() {
    let fixture = match env_path("PSIGN_REVOCATION_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("verify")
        .arg(fixture)
        .arg("--policy")
        .arg("default")
        .arg("--revocation-check")
        .output()
        .expect("run rust verify with revocation");
    let _ = rust.status.code();
}

#[test]
#[ignore = "requires PSIGN_MSIX_UNSIGNED_FIXTURE,PSIGN_MSIX_TEST_PFX,PSIGN_MSIX_TIMESTAMP_URL"]
fn msix_sign_with_rfc3161_timestamp_executes() {
    let unsigned_msix = match env_path("PSIGN_MSIX_UNSIGNED_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let pfx = match env_path("PSIGN_MSIX_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let tsa = match env_path("PSIGN_MSIX_TIMESTAMP_URL") {
        Some(v) => v,
        None => return,
    };
    let pfx_password = env_path("PSIGN_MSIX_TEST_PFX_PASSWORD");
    let out = std::env::temp_dir().join("psign_msix_semantic.msix");
    let _ = std::fs::copy(&unsigned_msix, &out).expect("copy unsigned msix");

    let mut rust = Command::cargo_bin("psign-tool").expect("binary available");
    rust.arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg("--timestamp-url")
        .arg(&tsa)
        .arg("--timestamp-digest")
        .arg("sha256");
    if let Some(pw) = pfx_password {
        rust.arg("--password").arg(pw);
    }
    rust.arg(&out);
    let rust_out = rust.output().expect("run psign-tool msix sign");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );
}

#[test]
#[ignore = "requires PSIGN_MSIX_UNSIGNED_FIXTURE and PSIGN_MSIX_TEST_PFX"]
fn msix_sign_requires_timestamp_url() {
    let unsigned_msix = match env_path("PSIGN_MSIX_UNSIGNED_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let pfx = match env_path("PSIGN_MSIX_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let out = std::env::temp_dir().join("psign_msix_notimestamp.msix");
    let _ = std::fs::copy(&unsigned_msix, &out).expect("copy unsigned msix");
    let rust = Command::cargo_bin("psign-tool")
        .expect("binary available")
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&out)
        .output()
        .expect("run psign-tool msix sign without timestamp");
    assert!(!rust.status.success());
}

#[test]
#[ignore = "requires PSIGN_MSIX_UNSIGNED_FIXTURE,PSIGN_MSIX_TEST_PFX,PSIGN_MSIX_TIMESTAMP_URL,PSIGN_MSIX_DLIB,PSIGN_MSIX_DMDF"]
fn msix_dlib_dmdf_path_executes() {
    let unsigned_msix = match env_path("PSIGN_MSIX_UNSIGNED_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let pfx = match env_path("PSIGN_MSIX_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let tsa = match env_path("PSIGN_MSIX_TIMESTAMP_URL") {
        Some(v) => v,
        None => return,
    };
    let dlib = match env_path("PSIGN_MSIX_DLIB") {
        Some(v) => v,
        None => return,
    };
    let dmdf = match env_path("PSIGN_MSIX_DMDF") {
        Some(v) => v,
        None => return,
    };
    let pfx_password = env_path("PSIGN_MSIX_TEST_PFX_PASSWORD");
    let out = std::env::temp_dir().join("psign_msix_decoupled.msix");
    let _ = std::fs::copy(&unsigned_msix, &out).expect("copy unsigned msix");

    let mut rust = Command::cargo_bin("psign-tool").expect("binary available");
    rust.arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg("--timestamp-url")
        .arg(&tsa)
        .arg("--timestamp-digest")
        .arg("sha256")
        .arg("--dlib")
        .arg(&dlib)
        .arg("--dmdf")
        .arg(&dmdf)
        .arg("--page-hashes");
    if let Some(pw) = pfx_password {
        rust.arg("--password").arg(pw);
    }
    rust.arg(&out);
    let rust_out = rust.output().expect("run psign-tool msix dlib/dmdf sign");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );
}

#[test]
#[ignore = "requires PSIGN_ARTIFACT_SIGNING_UNSIGNED_PE,PSIGN_ARTIFACT_SIGNING_METADATA,PSIGN_ARTIFACT_SIGNING_TIMESTAMP_URL,PSIGN_ARTIFACT_SIGNING_TEST_PFX and PSIGN_ARTIFACT_SIGNING_DLIB or PSIGN_ARTIFACT_SIGNING_DLIB_ROOT"]
fn artifact_signing_decoupled_pe_executes() {
    let unsigned_pe = match env_path("PSIGN_ARTIFACT_SIGNING_UNSIGNED_PE") {
        Some(v) => v,
        None => return,
    };
    let metadata = match env_path("PSIGN_ARTIFACT_SIGNING_METADATA") {
        Some(v) => v,
        None => return,
    };
    let tsa = match env_path("PSIGN_ARTIFACT_SIGNING_TIMESTAMP_URL") {
        Some(v) => v,
        None => return,
    };
    let pfx = match env_path("PSIGN_ARTIFACT_SIGNING_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let dlib = env_path("PSIGN_ARTIFACT_SIGNING_DLIB");
    let dlib_root = env_path("PSIGN_ARTIFACT_SIGNING_DLIB_ROOT");
    if dlib.is_none() && dlib_root.is_none() {
        return;
    }
    let pfx_password = env_path("PSIGN_ARTIFACT_SIGNING_TEST_PFX_PASSWORD");
    let out = std::env::temp_dir().join("psign_artifact_signing_decoupled.exe");
    let _ = std::fs::copy(&unsigned_pe, &out).expect("copy unsigned pe");

    let mut rust = Command::cargo_bin("psign-tool").expect("binary available");
    rust.arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg("--timestamp-url")
        .arg(&tsa)
        .arg("--timestamp-digest")
        .arg("sha256")
        .arg("--dmdf")
        .arg(&metadata)
        .arg("--auto-select");
    if let Some(ref path) = dlib {
        rust.arg("--dlib").arg(path);
    } else if let Some(ref root) = dlib_root {
        rust.arg("--trusted-signing-dlib-root").arg(root);
    }
    if let Some(pw) = pfx_password {
        rust.arg("--password").arg(pw);
    }
    rust.arg(&out);
    let rust_out = rust
        .output()
        .expect("run psign-tool artifact signing decoupled sign");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );
}

#[test]
#[ignore = "requires PSIGN_UNSIGNED_FIXTURE,PSIGN_TEST_PFX,PSIGN_TIMESTAMP_URL"]
fn append_signature_pe_nested_pkcs7_visible_to_inspector() {
    let unsigned = match env_path("PSIGN_UNSIGNED_FIXTURE") {
        Some(v) => v,
        None => return,
    };
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let tsa = match env_path("PSIGN_TIMESTAMP_URL") {
        Some(v) => v,
        None => return,
    };
    let pfx_password = env_path("PSIGN_TEST_PFX_PASSWORD");
    let first = std::env::temp_dir().join("psign_append_inspect_a.exe");
    let second = std::env::temp_dir().join("psign_append_inspect_b.exe");
    let _ = std::fs::copy(&unsigned, &first).expect("copy unsigned first");
    let _ = std::fs::copy(&unsigned, &second).expect("copy unsigned second");

    let mut one = Command::cargo_bin("psign-tool").expect("binary available");
    one.arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg("--timestamp-url")
        .arg(&tsa)
        .arg("--timestamp-digest")
        .arg("sha256")
        .arg("--auto-select")
        .arg(&first);
    if let Some(p) = pfx_password.as_ref() {
        one.arg("--password").arg(p);
    }
    let o1 = one.output().expect("first sign");
    assert!(
        o1.status.success(),
        "{}",
        String::from_utf8_lossy(&o1.stderr)
    );
    let _ = std::fs::copy(&first, &second).expect("copy signed to second before append");

    let mut two = Command::cargo_bin("psign-tool").expect("binary available");
    two.arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg("--timestamp-url")
        .arg(&tsa)
        .arg("--timestamp-digest")
        .arg("sha256")
        .arg("--append-signature")
        .arg("--auto-select")
        .arg(&second);
    if let Some(p) = pfx_password.as_ref() {
        two.arg("--password").arg(p);
    }
    let o2 = two.output().expect("second sign append");
    assert!(
        o2.status.success(),
        "{}",
        String::from_utf8_lossy(&o2.stderr)
    );

    let bytes = std::fs::read(&second).expect("read double-signed pe");
    let rep = psign_authenticode_trust::inspect_pe_authenticode(&bytes).expect("inspect");
    let outer = &rep.entries[0].pkcs7;
    assert!(
        !outer.nested_signatures.is_empty(),
        "append-signature should place a nested PKCS#7 under Microsoft OID 1.3.6.1.4.1.311.2.4.1"
    );
}

/// PowerShell `.ps1`: same Windows SIP stack as native (`SignerSignEx3`). Bytes may differ (PKCS#7
/// encoding); native `verify /pa` must accept the Rust-signed file.
#[test]
#[ignore = "requires PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_PS1_UNSIGNED_FIXTURE"]
fn ps1_sign_aligns_with_native_sip_stack() {
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let ps1_src = env_path("PSIGN_PS1_UNSIGNED_FIXTURE")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.ps1")
        });
    if !ps1_src.exists() {
        return;
    }
    let tmp_nat = std::env::temp_dir().join("psign_ps1_itest_native.ps1");
    let tmp_rust = std::env::temp_dir().join("psign_ps1_itest_rust.ps1");
    let _ = std::fs::copy(&ps1_src, &tmp_nat).expect("copy native ps1 temp");
    let _ = std::fs::copy(&ps1_src, &tmp_rust).expect("copy rust ps1 temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    let native_out = native_cmd.output().expect("native sign ps1");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    let rust_out = rust_cmd.output().expect("rust sign ps1");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed ps1");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed ps1");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

/// PowerShell `.psm1`: same Windows SIP as `.ps1`.
#[test]
#[ignore = "requires PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_PSM1_UNSIGNED_FIXTURE"]
fn psm1_sign_aligns_with_native_sip_stack() {
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let src = env_path("PSIGN_PSM1_UNSIGNED_FIXTURE")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.psm1")
        });
    if !src.exists() {
        return;
    }
    let tmp_nat = std::env::temp_dir().join("psign_psm1_itest_native.psm1");
    let tmp_rust = std::env::temp_dir().join("psign_psm1_itest_rust.psm1");
    let _ = std::fs::copy(&src, &tmp_nat).expect("copy native psm1 temp");
    let _ = std::fs::copy(&src, &tmp_rust).expect("copy rust psm1 temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    let native_out = native_cmd.output().expect("native sign psm1");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    let rust_out = rust_cmd.output().expect("rust sign psm1");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed psm1");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed psm1");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

/// PowerShell manifest `.psd1`: same Windows SIP as `.ps1`.
#[test]
#[ignore = "requires PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_PSD1_UNSIGNED_FIXTURE"]
fn psd1_sign_aligns_with_native_sip_stack() {
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let src = env_path("PSIGN_PSD1_UNSIGNED_FIXTURE")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.psd1")
        });
    if !src.exists() {
        return;
    }
    let tmp_nat = std::env::temp_dir().join("psign_psd1_itest_native.psd1");
    let tmp_rust = std::env::temp_dir().join("psign_psd1_itest_rust.psd1");
    let _ = std::fs::copy(&src, &tmp_nat).expect("copy native psd1 temp");
    let _ = std::fs::copy(&src, &tmp_rust).expect("copy rust psd1 temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    let native_out = native_cmd.output().expect("native sign psd1");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    let rust_out = rust_cmd.output().expect("rust sign psd1");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed psd1");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed psd1");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

/// Windows Installer `.msi`: OS SIP (`msisip.dll`); same `SignerSignEx3` / `WinVerifyTrust` stack as native.
#[test]
#[ignore = "requires PSIGN_MSI_UNSIGNED_FIXTURE and PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_MSI_TIMESTAMP_URL"]
fn msi_sign_aligns_with_native_sip_stack() {
    let msi_src = match env_path("PSIGN_MSI_UNSIGNED_FIXTURE") {
        Some(v) => PathBuf::from(v),
        None => return,
    };
    if !msi_src.exists() {
        return;
    }
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let tmp_nat = std::env::temp_dir().join("psign_msi_itest_native.msi");
    let tmp_rust = std::env::temp_dir().join("psign_msi_itest_rust.msi");
    let _ = std::fs::copy(&msi_src, &tmp_nat).expect("copy native msi temp");
    let _ = std::fs::copy(&msi_src, &tmp_rust).expect("copy rust msi temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");
    let ts = env_path("PSIGN_MSI_TIMESTAMP_URL");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    if let Some(ref u) = ts {
        native_cmd.arg("/tr").arg(u).arg("/td").arg("SHA256");
    }
    let native_out = native_cmd.output().expect("native sign msi");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    if let Some(u) = ts {
        rust_cmd
            .arg("--timestamp-url")
            .arg(u)
            .arg("--timestamp-digest")
            .arg("sha256");
    }
    let rust_out = rust_cmd.output().expect("rust sign msi");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed msi");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed msi");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

/// Windows metadata `.winmd`: PE-based CLI assembly; OS Authenticode SIP (`SignerSignEx3` / `WinVerifyTrust`).
#[test]
#[ignore = "requires PSIGN_WINMD_UNSIGNED_FIXTURE and PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_WINMD_TIMESTAMP_URL"]
fn winmd_sign_aligns_with_native_sip_stack() {
    let winmd_src = match env_path("PSIGN_WINMD_UNSIGNED_FIXTURE") {
        Some(v) => PathBuf::from(v),
        None => return,
    };
    if !winmd_src.exists() {
        return;
    }
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let tmp_nat = std::env::temp_dir().join("psign_winmd_itest_native.winmd");
    let tmp_rust = std::env::temp_dir().join("psign_winmd_itest_rust.winmd");
    let _ = std::fs::copy(&winmd_src, &tmp_nat).expect("copy native winmd temp");
    let _ = std::fs::copy(&winmd_src, &tmp_rust).expect("copy rust winmd temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");
    let ts = env_path("PSIGN_WINMD_TIMESTAMP_URL");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    if let Some(ref u) = ts {
        native_cmd.arg("/tr").arg(u).arg("/td").arg("SHA256");
    }
    let native_out = native_cmd.output().expect("native sign winmd");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    if let Some(u) = ts {
        rust_cmd
            .arg("--timestamp-url")
            .arg(u)
            .arg("--timestamp-digest")
            .arg("sha256");
    }
    let rust_out = rust_cmd.output().expect("rust sign winmd");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed winmd");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed winmd");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed winmd");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed winmd");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

/// Windows Script Host `.js`: OS SIP when registered (same stack as native `signtool`).
#[test]
#[ignore = "requires PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_JS_UNSIGNED_FIXTURE"]
fn js_sign_aligns_with_native_sip_stack() {
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let js_src = env_path("PSIGN_JS_UNSIGNED_FIXTURE")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.js")
        });
    if !js_src.exists() {
        return;
    }
    let tmp_nat = std::env::temp_dir().join("psign_js_itest_native.js");
    let tmp_rust = std::env::temp_dir().join("psign_js_itest_rust.js");
    let _ = std::fs::copy(&js_src, &tmp_nat).expect("copy native js temp");
    let _ = std::fs::copy(&js_src, &tmp_rust).expect("copy rust js temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    let native_out = native_cmd.output().expect("native sign js");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    let rust_out = rust_cmd.output().expect("rust sign js");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed js");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed js");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

#[test]
#[ignore = "requires PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_VBS_UNSIGNED_FIXTURE"]
fn vbs_sign_aligns_with_native_sip_stack() {
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let vbs_src = env_path("PSIGN_VBS_UNSIGNED_FIXTURE")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.vbs")
        });
    if !vbs_src.exists() {
        return;
    }
    let tmp_nat = std::env::temp_dir().join("psign_vbs_itest_native.vbs");
    let tmp_rust = std::env::temp_dir().join("psign_vbs_itest_rust.vbs");
    let _ = std::fs::copy(&vbs_src, &tmp_nat).expect("copy native vbs temp");
    let _ = std::fs::copy(&vbs_src, &tmp_rust).expect("copy rust vbs temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    let native_out = native_cmd.output().expect("native sign vbs");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    let rust_out = rust_cmd.output().expect("rust sign vbs");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed vbs");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed vbs");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

#[test]
#[ignore = "requires PSIGN_TEST_PFX; native signtool.exe; optional PSIGN_TEST_PFX_PASSWORD and PSIGN_WSF_UNSIGNED_FIXTURE"]
fn wsf_sign_aligns_with_native_sip_stack() {
    let pfx = match env_path("PSIGN_TEST_PFX") {
        Some(v) => v,
        None => return,
    };
    let Some(native_exe) = native_signtool_optional_path() else {
        return;
    };
    let wsf_src = env_path("PSIGN_WSF_UNSIGNED_FIXTURE")
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/unsigned-sample.wsf")
        });
    if !wsf_src.exists() {
        return;
    }
    let tmp_nat = std::env::temp_dir().join("psign_wsf_itest_native.wsf");
    let tmp_rust = std::env::temp_dir().join("psign_wsf_itest_rust.wsf");
    let _ = std::fs::copy(&wsf_src, &tmp_nat).expect("copy native wsf temp");
    let _ = std::fs::copy(&wsf_src, &tmp_rust).expect("copy rust wsf temp");

    let pw = env_path("PSIGN_TEST_PFX_PASSWORD");

    let mut native_cmd = Command::new(&native_exe);
    native_cmd
        .arg("sign")
        .arg("/fd")
        .arg("SHA256")
        .arg("/f")
        .arg(&pfx)
        .arg(&tmp_nat);
    if let Some(ref p) = pw {
        native_cmd.arg("/p").arg(p);
    }
    let native_out = native_cmd.output().expect("native sign wsf");
    assert!(
        native_out.status.success(),
        "{}",
        String::from_utf8_lossy(&native_out.stderr)
    );

    let mut rust_cmd = Command::cargo_bin("psign-tool").expect("binary available");
    rust_cmd
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--digest")
        .arg("sha256")
        .arg(&tmp_rust);
    if let Some(p) = pw {
        rust_cmd.arg("--password").arg(p);
    }
    let rust_out = rust_cmd.output().expect("rust sign wsf");
    assert!(
        rust_out.status.success(),
        "{}",
        String::from_utf8_lossy(&rust_out.stderr)
    );

    let nat_bytes = std::fs::read(&tmp_nat).expect("read native signed");
    let rust_bytes = std::fs::read(&tmp_rust).expect("read rust signed");

    let nv_rust = Command::new(&native_exe)
        .arg("verify")
        .arg("/pa")
        .arg(&tmp_rust)
        .output()
        .expect("native verify rust-signed wsf");
    assert!(
        nv_rust.status.success(),
        "{}",
        String::from_utf8_lossy(&nv_rust.stdout)
    );

    if nat_bytes != rust_bytes {
        let nv_nat = Command::new(&native_exe)
            .arg("verify")
            .arg("/pa")
            .arg(&tmp_nat)
            .output()
            .expect("native verify native-signed wsf");
        assert!(
            nv_nat.status.success(),
            "{}",
            String::from_utf8_lossy(&nv_nat.stdout)
        );
    }
}

#[cfg(feature = "artifact-signing-rest")]
#[test]
#[ignore = "requires PSIGN_ARTIFACT_SIGNING_REST_REGION, ACCOUNT_NAME, PROFILE_NAME, DIGEST_FILE and auth (see docs/migration-artifact-signing.md#rest-hash-signing-gated-smoke-test)"]
fn artifact_signing_rest_submit_smoke() {
    let region = match env_path("PSIGN_ARTIFACT_SIGNING_REST_REGION") {
        Some(v) => v,
        None => return,
    };
    let account_name = match env_path("PSIGN_ARTIFACT_SIGNING_REST_ACCOUNT_NAME") {
        Some(v) => v,
        None => return,
    };
    let profile_name = match env_path("PSIGN_ARTIFACT_SIGNING_REST_PROFILE_NAME") {
        Some(v) => v,
        None => return,
    };
    let digest_file = match env_path("PSIGN_ARTIFACT_SIGNING_REST_DIGEST_FILE") {
        Some(v) => v,
        None => return,
    };

    let access_token = env_path("PSIGN_ARTIFACT_SIGNING_REST_ACCESS_TOKEN");
    let mi = env_flag_true("PSIGN_ARTIFACT_SIGNING_REST_MANAGED_IDENTITY");
    let tenant = env_path("PSIGN_ARTIFACT_SIGNING_REST_TENANT_ID");
    let client_id = env_path("PSIGN_ARTIFACT_SIGNING_REST_CLIENT_ID");
    let client_secret = env_path("PSIGN_ARTIFACT_SIGNING_REST_CLIENT_SECRET");

    let auth_ready = access_token.is_some()
        || mi
        || (tenant.is_some() && client_id.is_some() && client_secret.is_some());
    if !auth_ready {
        return;
    }

    let mut cmd = Command::cargo_bin("psign-tool").expect("binary available");
    cmd.arg("artifact-signing-submit")
        .arg("--region")
        .arg(&region)
        .arg("--account-name")
        .arg(&account_name)
        .arg("--profile-name")
        .arg(&profile_name)
        .arg("--digest-file")
        .arg(&digest_file);

    if let Some(alg) = env_path("PSIGN_ARTIFACT_SIGNING_REST_SIGNATURE_ALGORITHM") {
        cmd.arg("--signature-algorithm").arg(&alg);
    }

    if let Some(tok) = access_token {
        cmd.arg("--access-token").arg(&tok);
    } else if mi {
        cmd.arg("--managed-identity");
    } else {
        cmd.arg("--tenant-id").arg(tenant.as_ref().expect("tenant"));
        cmd.arg("--client-id")
            .arg(client_id.as_ref().expect("client id"));
        cmd.arg("--client-secret")
            .arg(client_secret.as_ref().expect("client secret"));
    }

    let out = cmd.output().expect("run artifact-signing-submit");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Succeeded") && stdout.contains("signature"),
        "unexpected stdout (want LRO Succeeded + signature material):\n{stdout}"
    );
}
