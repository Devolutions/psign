#![cfg(windows)]

//! Native Windows AppX validation regression test for the HRESULT **0x80080205**
//! ("The Appx package's block map is invalid") corruption reported against
//! `psign-tool --mode portable sign` for flat `.msix`/`.appx` packages.
//!
//! `psign`'s own `portable verify-msix` self-check reuses the same
//! `psign-sip-digest` code that produced the signature, so it cannot detect a
//! systematic modeling divergence from real Windows AppX semantics (such as the
//! block-map path-separator bug this test guards against). This test instead
//! shells out to the real Windows SDK `makeappx.exe unpack` tool — the same
//! validator behind `Add-AppxPackage`'s block-map check — against a package
//! freshly signed by `psign-tool --mode portable sign`.
//! Multi-package bundles are also checked with `makeappx unbundle`: their signed
//! manifest offsets must track any change to the ZIP layout during signing.
//!
//! The test is skipped (not failed) when `makeappx.exe` cannot be located,
//! since not every Windows host is guaranteed to have the Windows SDK
//! installed; `windows-latest` GitHub Actions runners do include it.

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

/// Locate `makeappx.exe` via `PATH`, then by scanning the usual Windows Kits
/// install locations (newest version first).
fn find_makeappx() -> Option<PathBuf> {
    if let Ok(path) = which_in_path("makeappx.exe") {
        return Some(path);
    }

    for program_files in ["C:\\Program Files (x86)", "C:\\Program Files"] {
        let bin_root = Path::new(program_files).join("Windows Kits\\10\\bin");
        let Ok(entries) = std::fs::read_dir(&bin_root) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        // Prefer the highest SDK version (lexicographic sort works for the
        // `10.0.XXXXX.0` naming scheme).
        versions.sort();
        for version_dir in versions.into_iter().rev() {
            for arch in ["x64", "x86", "arm64"] {
                let candidate = version_dir.join(arch).join("makeappx.exe");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn which_in_path(exe: &str) -> Result<PathBuf, ()> {
    let path_var = std::env::var_os("PATH").ok_or(())?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(exe);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(())
}

fn require_or_find_makeappx() -> Option<PathBuf> {
    let found = find_makeappx();
    if found.is_none()
        && std::env::var("PSIGN_REQUIRE_MAKEAPPX")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    {
        panic!("makeappx.exe not found while PSIGN_REQUIRE_MAKEAPPX is set");
    }
    found
}

fn find_signtool() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("SIGNTOOL_EXE") {
        let p = PathBuf::from(path);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(path) = which_in_path("signtool.exe") {
        return Some(path);
    }
    for program_files in ["C:\\Program Files (x86)", "C:\\Program Files"] {
        let bin_root = Path::new(program_files).join("Windows Kits\\10\\bin");
        let Ok(entries) = std::fs::read_dir(&bin_root) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        versions.sort();
        for version_dir in versions.into_iter().rev() {
            for arch in ["x64", "x86", "arm64"] {
                let candidate = version_dir.join(arch).join("signtool.exe");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let base = option_env!("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!(
        "psign-makeappx-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn portable_signed_flat_msix_unpacks_cleanly_with_real_makeappx() {
    let Some(makeappx) = require_or_find_makeappx() else {
        eprintln!(
            "skipping: makeappx.exe not found (Windows SDK not installed); \
             this test only runs where the real Windows AppX validator is available"
        );
        return;
    };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = manifest_dir.join("tests/fixtures/generated-unsigned/msix/sample.msix");
    let pfx =
        manifest_dir.join("tests/fixtures/devolutions-authenticode/authenticode-test-cert.pfx");
    assert!(source.is_file(), "fixture missing: {}", source.display());
    assert!(pfx.is_file(), "fixture missing: {}", pfx.display());

    let temp_dir = unique_temp_dir("flat-msix");
    let signed = temp_dir.join("sample.signed.msix");
    std::fs::copy(&source, &signed).expect("copy fixture to scratch path");

    let mut sign_cmd = Command::cargo_bin("psign-tool").expect("psign-tool binary");
    sign_cmd
        .arg("--mode")
        .arg("portable")
        .arg("sign")
        .arg("--pfx")
        .arg(&pfx)
        .arg("--password")
        .arg("CodeSign123!")
        .arg(&signed);
    sign_cmd.assert().success();

    let unpack_dir = temp_dir.join("unpacked");
    let output = StdCommand::new(&makeappx)
        .arg("unpack")
        .arg("/p")
        .arg(&signed)
        .arg("/d")
        .arg(&unpack_dir)
        .arg("/o")
        .output()
        .expect("run makeappx unpack");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "makeappx unpack failed on psign-signed MSIX (regression for HRESULT \
         0x80080205 block-map corruption):\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("0x80080205") && !stderr.contains("0x80080205"),
        "makeappx reported the block-map-invalid HRESULT despite a successful \
         exit code; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(temp_dir);
}

/// Run a Windows PowerShell script and return its trimmed stdout.
fn run_powershell(script: &str) -> String {
    // When cargo runs under PowerShell 7 (GitHub Actions `pwsh` steps), the inherited
    // PSModulePath points at PowerShell 7 module builds that Windows PowerShell 5.1
    // cannot load (`Get-AuthenticodeSignature`: CouldNotAutoloadMatchingModule).
    let output = StdCommand::new("powershell.exe")
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("run powershell.exe");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        output.status.success(),
        "powershell failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// Regression test for TRUST_E_BAD_DIGEST (**0x80096010**) on portable-signed MSIX:
/// Windows AppxSip only accepts packages in the AppxPackaging ZIP layout (ZIP64 end
/// records, "version made by" 45, zero external attributes), which the `zip` crate does
/// not write on its own. A makeappx-built package and a plain ZIP of the same layout
/// (no `AppxBlockMap.xml` / `[Content_Types].xml`, as publishers that drop makeappx
/// produce) are signed by `psign-tool --mode portable sign` with a throwaway self-signed
/// PFX created in memory (never imported into any certificate store). Windows must then
/// fail only on chain trust (CERT_E_UNTRUSTEDROOT, **0x800B0109**), never on the digest,
/// and `makeappx unpack` must accept the block map.
#[test]
fn portable_signed_makeappx_packages_and_bundle_fail_windows_verify_only_on_untrusted_root() {
    let Some(makeappx) = require_or_find_makeappx() else {
        eprintln!("skipping: makeappx.exe not found (Windows SDK not installed)");
        return;
    };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let temp_dir = unique_temp_dir("win-verify");
    let layout = temp_dir.join("layout");
    std::fs::create_dir_all(layout.join("Assets")).expect("create layout");
    std::fs::copy(
        manifest_dir.join("tests/fixtures/msix-minimal/AppxManifest.xml"),
        layout.join("AppxManifest.xml"),
    )
    .expect("copy manifest");
    // Any PE works as the package executable; a multi-block PE also makes SDK 26100+
    // makeappx emit `b4:FileHash` block-map elements.
    let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    std::fs::copy(
        Path::new(&system_root).join("System32\\whoami.exe"),
        layout.join("noop.exe"),
    )
    .expect("copy PE payload");
    std::fs::write(
        layout.join("Assets\\StoreLogo.png"),
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89\0\0\0\rIDATx\xdac\xfc\xcf\xc0P\x0f\0\x04\x85\x01\x80\x84\xa9\x8c!\0\0\0\0IEND\xaeB`\x82",
    )
    .expect("write logo");

    let unsigned = temp_dir.join("unsigned.msix");
    let pack = StdCommand::new(&makeappx)
        .args(["pack", "/h", "sha256", "/o", "/d"])
        .arg(&layout)
        .arg("/p")
        .arg(&unsigned)
        .output()
        .expect("run makeappx pack");
    assert!(
        pack.status.success(),
        "makeappx pack failed:\n{}\n{}",
        String::from_utf8_lossy(&pack.stdout),
        String::from_utf8_lossy(&pack.stderr)
    );

    let plain_zip = temp_dir.join("plain-zip.msix");
    {
        use std::io::Write as _;
        let mut writer =
            zip::ZipWriter::new(std::fs::File::create(&plain_zip).expect("create plain ZIP"));
        let deflated =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for name in ["AppxManifest.xml", "noop.exe", "Assets/StoreLogo.png"] {
            writer.start_file(name, deflated).expect("start ZIP entry");
            writer
                .write_all(&std::fs::read(layout.join(name)).expect("read layout file"))
                .expect("write ZIP entry");
        }
        writer.finish().expect("finish plain ZIP");
    }

    // Subject must match the manifest Publisher (`CN=Test Code Signing Certificate`).
    let pfx = temp_dir.join("throwaway.pfx");
    let cer = temp_dir.join("throwaway.cer");
    run_powershell(&format!(
        r#"$ErrorActionPreference = 'Stop'
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=Test Code Signing Certificate', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$eku = New-Object System.Security.Cryptography.OidCollection
[void]$eku.Add((New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.3')))
$req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($eku, $false)))
$req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($false, $false, 0, $true)))
$cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(7))
[IO.File]::WriteAllBytes('{pfx}', $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'throwaway'))
[IO.File]::WriteAllBytes('{cer}', $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))"#,
        pfx = pfx.display(),
        cer = cer.display(),
    ));

    for (input, digest) in [
        (&unsigned, "SHA256"),
        (&unsigned, "SHA384"),
        (&unsigned, "SHA512"),
        (&plain_zip, "SHA256"),
    ] {
        let label = format!(
            "{} {digest}",
            input.file_stem().unwrap_or_default().to_string_lossy()
        );
        let signed = temp_dir.join(format!("signed-{}.msix", label.replace(' ', "-")));
        std::fs::copy(input, &signed).expect("copy unsigned package");
        Command::cargo_bin("psign-tool")
            .expect("psign-tool binary")
            .args(["--mode", "portable", "sign", "--pfx"])
            .arg(&pfx)
            .args(["--password", "throwaway", "--fd", digest])
            .arg(&signed)
            .assert()
            .success();

        // WinVerifyTrust through the native psign-tool verify path reports the HRESULT.
        let verify = Command::cargo_bin("psign-tool")
            .expect("psign-tool binary")
            .args(["verify", "/pa"])
            .arg(&signed)
            .output()
            .expect("run psign-tool verify /pa");
        let verify_text = format!(
            "{}{}",
            String::from_utf8_lossy(&verify.stdout),
            String::from_utf8_lossy(&verify.stderr)
        );
        assert!(
            !verify_text.contains("0x80096010"),
            "{label}: Windows rejected the portable MSIX digest (TRUST_E_BAD_DIGEST):\n{verify_text}"
        );
        assert!(
            verify_text.contains("0x800B0109"),
            "{label}: expected only CERT_E_UNTRUSTEDROOT from WinVerifyTrust:\n{verify_text}"
        );

        let status = run_powershell(&format!(
            "Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1'); (Get-AuthenticodeSignature -LiteralPath '{}').Status",
            signed.display()
        ));
        assert_eq!(
            status, "UnknownError",
            "{label}: Get-AuthenticodeSignature must fail only on the untrusted root (HashMismatch = bad digest)"
        );

        let unpack = StdCommand::new(&makeappx)
            .args(["unpack", "/o", "/p"])
            .arg(&signed)
            .arg("/d")
            .arg(temp_dir.join(format!("unpacked-{}", label.replace(' ', "-"))))
            .output()
            .expect("run makeappx unpack");
        assert!(
            unpack.status.success(),
            "{label}: makeappx unpack rejected the signed package:
{}
{}",
            String::from_utf8_lossy(&unpack.stdout),
            String::from_utf8_lossy(&unpack.stderr)
        );

        // The portable verifier must agree with Windows on the digest.
        Command::cargo_bin("psign-tool")
            .expect("psign-tool binary")
            .args(["portable", "trust-verify-msix", "--trusted-ca"])
            .arg(&cer)
            .arg(&signed)
            .assert()
            .success();
    }

    // makeappx bundle uses ZIP64 data descriptors between child packages. Dropping
    // those without updating the manifest offsets corrupts every child after the first.
    let children = temp_dir.join("children");
    std::fs::create_dir(&children).expect("create bundle input");
    std::fs::copy(
        temp_dir.join("signed-unsigned-SHA256.msix"),
        children.join("x64.msix"),
    )
    .expect("copy signed x64 package");
    let manifest = std::fs::read_to_string(layout.join("AppxManifest.xml")).unwrap();
    std::fs::write(
        layout.join("AppxManifest.xml"),
        manifest.replace(
            "ProcessorArchitecture=\"x64\"",
            "ProcessorArchitecture=\"arm64\"",
        ),
    )
    .unwrap();
    let arm64 = children.join("arm64.msix");
    let pack = StdCommand::new(&makeappx)
        .args(["pack", "/h", "sha256", "/o", "/d"])
        .arg(&layout)
        .arg("/p")
        .arg(&arm64)
        .output()
        .expect("pack arm64 package");
    assert!(
        pack.status.success(),
        "pack arm64: {}{}",
        String::from_utf8_lossy(&pack.stdout),
        String::from_utf8_lossy(&pack.stderr)
    );
    Command::cargo_bin("psign-tool")
        .unwrap()
        .args(["--mode", "portable", "sign", "--pfx"])
        .arg(&pfx)
        .args(["--password", "throwaway"])
        .arg(&arm64)
        .assert()
        .success();

    let bundle = temp_dir.join("multi.msixbundle");
    let pack = StdCommand::new(&makeappx)
        .args(["bundle", "/o", "/d"])
        .arg(&children)
        .arg("/p")
        .arg(&bundle)
        .output()
        .expect("makeappx bundle");
    assert!(
        pack.status.success(),
        "bundle: {}{}",
        String::from_utf8_lossy(&pack.stdout),
        String::from_utf8_lossy(&pack.stderr)
    );

    // Build a genuine .appxbundle from real .appx children (not a renamed .msixbundle).
    let appx_children = temp_dir.join("appx-children");
    std::fs::create_dir(&appx_children).expect("create appx bundle input");
    for arch in ["x86", "x64"] {
        std::fs::write(
            layout.join("AppxManifest.xml"),
            manifest.replace(
                "ProcessorArchitecture=\"x64\"",
                &format!("ProcessorArchitecture=\"{arch}\""),
            ),
        )
        .unwrap();
        let child_appx = appx_children.join(format!("{arch}.appx"));
        let pack = StdCommand::new(&makeappx)
            .args(["pack", "/h", "sha256", "/o", "/d"])
            .arg(&layout)
            .arg("/p")
            .arg(&child_appx)
            .output()
            .expect("pack child .appx");
        assert!(
            pack.status.success(),
            "pack {arch}.appx: {}{}",
            String::from_utf8_lossy(&pack.stdout),
            String::from_utf8_lossy(&pack.stderr)
        );
        Command::cargo_bin("psign-tool")
            .unwrap()
            .args(["--mode", "portable", "sign", "--pfx"])
            .arg(&pfx)
            .args(["--password", "throwaway"])
            .arg(&child_appx)
            .assert()
            .success();
    }
    let appx_bundle = temp_dir.join("multi.appxbundle");
    let pack = StdCommand::new(&makeappx)
        .args(["bundle", "/o", "/d"])
        .arg(&appx_children)
        .arg("/p")
        .arg(&appx_bundle)
        .output()
        .expect("makeappx bundle .appxbundle");
    assert!(
        pack.status.success(),
        "bundle .appxbundle: {}{}",
        String::from_utf8_lossy(&pack.stdout),
        String::from_utf8_lossy(&pack.stderr)
    );

    for (extension, src_bundle, src_children_dir, expected_names) in [
        ("msixbundle", &bundle, &children, ["x64.msix", "arm64.msix"]),
        (
            "appxbundle",
            &appx_bundle,
            &appx_children,
            ["x86.appx", "x64.appx"],
        ),
    ] {
        let signed = temp_dir.join(format!("signed.{extension}"));
        std::fs::copy(src_bundle, &signed).unwrap();
        // Verify BOTH pass 1 (first sign from MakeAppx descriptor layout) AND pass 2 (re-sign).
        for pass in 1..=2 {
            Command::cargo_bin("psign-tool")
                .unwrap()
                .args(["--mode", "portable", "sign", "--pfx"])
                .arg(&pfx)
                .args(["--password", "throwaway"])
                .arg(&signed)
                .assert()
                .success();

            let extracted = temp_dir.join(format!("unbundled-{extension}-pass-{pass}"));
            let unpack = StdCommand::new(&makeappx)
                .args(["unbundle", "/o", "/p"])
                .arg(&signed)
                .arg("/d")
                .arg(&extracted)
                .output()
                .expect("makeappx unbundle");
            assert!(
                unpack.status.success(),
                "signed {extension} (pass {pass}) has invalid child offsets: {}{}",
                String::from_utf8_lossy(&unpack.stdout),
                String::from_utf8_lossy(&unpack.stderr)
            );
            for child in expected_names {
                assert_eq!(
                    std::fs::read(extracted.join(child)).unwrap(),
                    std::fs::read(src_children_dir.join(child)).unwrap(),
                    "{extension} (pass {pass}): extracted {child} must stay byte-identical"
                );
            }
            let verify = Command::cargo_bin("psign-tool")
                .unwrap()
                .args(["verify", "/pa"])
                .arg(&signed)
                .output()
                .expect("Windows bundle verification");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&verify.stdout),
                String::from_utf8_lossy(&verify.stderr)
            );
            assert!(
                text.contains("0x800B0109") && !text.contains("0x80096010"),
                "{extension} (pass {pass}): Windows must accept the digest and reject only the untrusted test root: {text}"
            );
            Command::cargo_bin("psign-tool")
                .unwrap()
                .args(["portable", "trust-verify-msix", "--trusted-ca"])
                .arg(&cer)
                .arg(&signed)
                .assert()
                .success();
        }
    }

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[derive(serde::Deserialize)]
struct EdgeManifest {
    entries: Vec<EdgeFixture>,
}

#[derive(serde::Deserialize)]
struct EdgeFixture {
    id: String,
    extension: String,
    digest: String,
    is_sparse_bundle: bool,
    is_encrypted: bool,
    is_upload_container: bool,
    expected_windows_verify: String,
    expected_windows_sign: String,
    unsigned_path: Option<String>,
    signed_path: Option<String>,
}

fn devolutions_test_ca_trusted() -> bool {
    const CA_THUMBPRINT: &str = "247E24EE83DC1A29110A2C1A2A5D4DFEFAC369B7";
    for args in [
        &["-store", "Root", CA_THUMBPRINT][..],
        &["-user", "-store", "Root", CA_THUMBPRINT][..],
    ] {
        if StdCommand::new("certutil")
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return true;
        }
    }
    false
}

fn assert_windows_verify_ok_or_untrusted_root(
    path: &Path,
    ca_trusted: bool,
    extra: &[&str],
    label: &str,
) {
    let mut cmd = Command::cargo_bin("psign-tool").expect("psign-tool");
    cmd.args(["verify", "--policy", "pa", "--allow-test-root"]);
    cmd.args(extra);
    cmd.arg(path);
    let out = cmd.output().expect("run psign verify");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if ca_trusted {
        assert!(
            out.status.success(),
            "{label}: Windows psign verify failed:\n{text}"
        );
    } else {
        assert!(
            text.contains("0x800B0109") && !text.contains("0x80096010"),
            "{label}: expected CERT_E_UNTRUSTEDROOT (not bad digest):\n{text}"
        );
    }
}

#[test]
fn msix_edge_case_corpus_verifies_and_roundtrips_across_windows_and_portable_modes() {
    let Some(makeappx) = require_or_find_makeappx() else {
        eprintln!("skipping: makeappx.exe not found");
        return;
    };
    let signtool = find_signtool();
    let ca_trusted = devolutions_test_ca_trusted();

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pfx =
        manifest_dir.join("tests/fixtures/devolutions-authenticode/authenticode-test-cert.pfx");
    let ca = manifest_dir.join("tests/fixtures/devolutions-authenticode/authenticode-test-ca.crt");
    let edge_manifest: EdgeManifest = serde_json::from_str(include_str!(
        "fixtures/msix-edge-cases/msix-edge-case-fixtures.json"
    ))
    .expect("parse msix-edge-case-fixtures.json");

    let temp_dir = unique_temp_dir("edge-cross-mode");

    // 1. Validate every committed signed fixture in Windows mode (WinVerifyTrust + MakeAppx).
    for entry in &edge_manifest.entries {
        match entry.expected_windows_verify.as_str() {
            "valid" => {
                let signed = manifest_dir.join(entry.signed_path.as_deref().unwrap());
                let extra: &[&str] = if !entry.is_encrypted
                    && matches!(
                        entry.extension.as_str(),
                        ".msix" | ".appx" | ".msixbundle" | ".appxbundle"
                    ) {
                    &["--rust-sip-msix-digest-check"]
                } else {
                    &[]
                };
                assert_windows_verify_ok_or_untrusted_root(&signed, ca_trusted, extra, &entry.id);

                if entry.is_encrypted {
                    // Forcing the cleartext Rust SIP digest check on real /kt encrypted packages
                    // must fail explicitly rather than silently passing.
                    Command::cargo_bin("psign-tool")
                        .unwrap()
                        .args([
                            "verify",
                            "--policy",
                            "pa",
                            "--allow-test-root",
                            "--rust-sip-msix-digest-check",
                        ])
                        .arg(&signed)
                        .assert()
                        .failure();
                } else if !entry.is_sparse_bundle
                    && matches!(
                        entry.extension.as_str(),
                        ".msix" | ".appx" | ".msixbundle" | ".appxbundle"
                    )
                {
                    let subcmd = if entry.extension.ends_with("bundle") {
                        "unbundle"
                    } else {
                        "unpack"
                    };
                    let out_dir = temp_dir.join(format!("committed-{subcmd}-{}", entry.id));
                    let res = StdCommand::new(&makeappx)
                        .args([subcmd, "/o", "/p"])
                        .arg(&signed)
                        .arg("/d")
                        .arg(&out_dir)
                        .output()
                        .expect("run makeappx on committed signed fixture");
                    assert!(
                        res.status.success(),
                        "{}: makeappx {subcmd} failed:\n{}{}",
                        entry.id,
                        String::from_utf8_lossy(&res.stdout),
                        String::from_utf8_lossy(&res.stderr)
                    );
                }
            }
            "detached-valid" => {
                let content = manifest_dir.join(entry.unsigned_path.as_deref().unwrap());
                let sig = manifest_dir.join(entry.signed_path.as_deref().unwrap());
                let out = Command::cargo_bin("psign-tool")
                    .unwrap()
                    .args(["verify", "--policy", "pa", "--allow-test-root"])
                    .arg(&content)
                    .arg("--detached-pkcs7")
                    .arg(&sig)
                    .output()
                    .unwrap();
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if ca_trusted {
                    assert!(
                        out.status.success(),
                        "{}: detached verify failed:\n{text}",
                        entry.id
                    );
                } else {
                    assert!(text.contains("0x800B0109"), "{}: {text}", entry.id);
                }
            }
            "reject-upload-container" => {
                let target = manifest_dir.join(entry.unsigned_path.as_deref().unwrap());
                Command::cargo_bin("psign-tool")
                    .unwrap()
                    .args(["verify", "--policy", "pa"])
                    .arg(&target)
                    .assert()
                    .failure();
            }
            other => panic!("unexpected expected_windows_verify `{other}`"),
        }
    }

    // 2. Portable sign -> Windows MakeAppx + WinVerifyTrust + signtool cross-mode validation.
    for entry in &edge_manifest.entries {
        if entry.is_encrypted || entry.is_upload_container {
            continue;
        }
        let Some(unsigned_rel) = &entry.unsigned_path else {
            continue;
        };
        if !matches!(
            entry.extension.as_str(),
            ".msix" | ".appx" | ".msixbundle" | ".appxbundle"
        ) {
            continue;
        }
        let target = temp_dir.join(format!("portable-to-win-{}{}", entry.id, entry.extension));
        std::fs::copy(manifest_dir.join(unsigned_rel), &target).unwrap();
        Command::cargo_bin("psign-tool")
            .unwrap()
            .env("TEMP", &temp_dir)
            .env("TMP", &temp_dir)
            .args([
                "--mode",
                "portable",
                "sign",
                "--pfx",
                pfx.to_str().unwrap(),
                "--password",
                "CodeSign123!",
                "--digest",
                &entry.digest.to_ascii_lowercase(),
            ])
            .arg(&target)
            .assert()
            .success();

        assert_windows_verify_ok_or_untrusted_root(
            &target,
            ca_trusted,
            &["--rust-sip-msix-digest-check"],
            &format!("portable->win {}", entry.id),
        );
        if ca_trusted && let Some(st) = &signtool {
            let st_out = StdCommand::new(st)
                .args(["verify", "/pa"])
                .arg(&target)
                .output()
                .unwrap();
            assert!(
                st_out.status.success(),
                "signtool verify /pa failed on portable-signed {}: {}{}",
                entry.id,
                String::from_utf8_lossy(&st_out.stdout),
                String::from_utf8_lossy(&st_out.stderr)
            );
        }
        if !entry.is_sparse_bundle {
            let subcmd = if entry.extension.ends_with("bundle") {
                "unbundle"
            } else {
                "unpack"
            };
            let out_dir = temp_dir.join(format!("p2w-{subcmd}-{}", entry.id));
            let res = StdCommand::new(&makeappx)
                .args([subcmd, "/o", "/p"])
                .arg(&target)
                .arg("/d")
                .arg(&out_dir)
                .output()
                .unwrap();
            assert!(
                res.status.success(),
                "makeappx {subcmd} rejected portable-signed {}: {}{}",
                entry.id,
                String::from_utf8_lossy(&res.stdout),
                String::from_utf8_lossy(&res.stderr)
            );
        }
    }

    // 3. Windows-mode `psign sign` (SignerSignEx3 + AppxSip/AppxBundleSip/EappxSip) ->
    //    MakeAppx + signtool + portable trust-verify-msix cross-mode validation.
    for entry in &edge_manifest.entries {
        if entry.expected_windows_sign != "supported" {
            continue;
        }
        let Some(unsigned_rel) = &entry.unsigned_path else {
            continue;
        };
        let target = temp_dir.join(format!("win-sign-{}{}", entry.id, entry.extension));
        std::fs::copy(manifest_dir.join(unsigned_rel), &target).unwrap();

        let mut cmd = Command::cargo_bin("psign-tool").unwrap();
        cmd.env("TEMP", &temp_dir).env("TMP", &temp_dir).args([
            "sign",
            "--pfx",
            pfx.to_str().unwrap(),
            "--password",
            "CodeSign123!",
            "--digest",
            &entry.digest.to_ascii_lowercase(),
        ]);
        if !entry.is_encrypted {
            cmd.args(["--rust-sip", "msix"]);
        }
        cmd.arg(&target).assert().success();

        assert_windows_verify_ok_or_untrusted_root(
            &target,
            ca_trusted,
            if entry.is_encrypted {
                &[]
            } else {
                &["--rust-sip-msix-digest-check"]
            },
            &format!("win-sign {}", entry.id),
        );
        if !entry.is_encrypted {
            Command::cargo_bin("psign-tool")
                .unwrap()
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
        }
    }

    // Also test Windows-mode `psign sign --page-hashes` (/ph without /dlib) on flat MSIX,
    // and `portable msix-set-publisher` + `psign-tool code` (.msixupload) -> Windows `psign sign`!
    let win_ph = temp_dir.join("win-ph.msix");
    std::fs::copy(
        manifest_dir.join("tests/fixtures/generated-unsigned/msix/sample.msix"),
        &win_ph,
    )
    .unwrap();
    Command::cargo_bin("psign-tool")
        .unwrap()
        .env("TEMP", &temp_dir)
        .env("TMP", &temp_dir)
        .args([
            "sign",
            "--pfx",
            pfx.to_str().unwrap(),
            "--password",
            "CodeSign123!",
            "--digest",
            "sha256",
            "--page-hashes",
            "--rust-sip",
            "msix",
        ])
        .arg(&win_ph)
        .assert()
        .success();
    assert_windows_verify_ok_or_untrusted_root(
        &win_ph,
        ca_trusted,
        &["--rust-sip-msix-digest-check"],
        "win-sign --page-hashes",
    );

    // `portable msix-set-publisher` -> Windows `psign sign` -> `makeappx unbundle`!
    let pub_bundle = temp_dir.join("set-pub-then-win-sign.msixbundle");
    Command::cargo_bin("psign-tool")
        .unwrap()
        .args(["portable", "msix-set-publisher"])
        .arg(manifest_dir.join("tests/fixtures/msix-edge-cases/unsigned/bundle-multi.msixbundle"))
        .args([
            "--publisher",
            "CN=Test Code Signing Certificate",
            "--output",
        ])
        .arg(&pub_bundle)
        .assert()
        .success();
    Command::cargo_bin("psign-tool")
        .unwrap()
        .env("TEMP", &temp_dir)
        .env("TMP", &temp_dir)
        .args([
            "sign",
            "--pfx",
            pfx.to_str().unwrap(),
            "--password",
            "CodeSign123!",
            "--digest",
            "sha256",
            "--rust-sip",
            "msix",
        ])
        .arg(&pub_bundle)
        .assert()
        .success();
    let pub_unbundle_dir = temp_dir.join("pub-unbundled");
    let unb = StdCommand::new(&makeappx)
        .args(["unbundle", "/o", "/p"])
        .arg(&pub_bundle)
        .arg("/d")
        .arg(&pub_unbundle_dir)
        .output()
        .unwrap();
    assert!(
        unb.status.success(),
        "makeappx unbundle after msix-set-publisher + Windows psign sign failed:\n{}{}",
        String::from_utf8_lossy(&unb.stdout),
        String::from_utf8_lossy(&unb.stderr)
    );

    // `psign-tool code` on .msixupload -> extract inner .msixbundle -> Windows `psign sign` -> `makeappx unbundle`!
    let upload_src = temp_dir.join("sample.msixupload");
    std::fs::copy(
        manifest_dir.join("tests/fixtures/msix-edge-cases/unsigned/sample.msixupload"),
        &upload_src,
    )
    .unwrap();
    let upload_prepared = temp_dir.join("prepared.msixupload");
    Command::cargo_bin("psign-tool")
        .unwrap()
        .args([
            "code",
            "--base-directory",
            temp_dir.to_str().unwrap(),
            "--publisher-name",
            "CN=Test Code Signing Certificate",
            "--pfx",
            pfx.to_str().unwrap(),
            "--password",
            "CodeSign123!",
            "--output",
            upload_prepared.to_str().unwrap(),
            "sample.msixupload",
        ])
        .assert()
        .success();
    let inner_bundle = temp_dir.join("from-upload.msixbundle");
    {
        use std::io::Read as _;
        let f = std::fs::File::open(&upload_prepared).unwrap();
        let mut z = zip::ZipArchive::new(f).unwrap();
        let mut buf = Vec::new();
        z.by_name("Psign.EdgeTest_1.0.0.0.msixbundle")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        std::fs::write(&inner_bundle, buf).unwrap();
    }
    Command::cargo_bin("psign-tool")
        .unwrap()
        .env("TEMP", &temp_dir)
        .env("TMP", &temp_dir)
        .args([
            "sign",
            "--pfx",
            pfx.to_str().unwrap(),
            "--password",
            "CodeSign123!",
            "--digest",
            "sha256",
            "--rust-sip",
            "msix",
        ])
        .arg(&inner_bundle)
        .assert()
        .success();
    let upload_unbundle_dir = temp_dir.join("upload-unbundled");
    let unb2 = StdCommand::new(&makeappx)
        .args(["unbundle", "/o", "/p"])
        .arg(&inner_bundle)
        .arg("/d")
        .arg(&upload_unbundle_dir)
        .output()
        .unwrap();
    assert!(
        unb2.status.success(),
        "makeappx unbundle after psign-tool code (.msixupload) + Windows psign sign failed:\n{}{}",
        String::from_utf8_lossy(&unb2.stdout),
        String::from_utf8_lossy(&unb2.stderr)
    );

    let _ = std::fs::remove_dir_all(temp_dir);
}
