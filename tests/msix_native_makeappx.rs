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

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
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
    let Some(makeappx) = find_makeappx() else {
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
fn portable_signed_makeappx_msix_fails_windows_verify_only_on_untrusted_root() {
    let Some(makeappx) = find_makeappx() else {
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

    let _ = std::fs::remove_dir_all(temp_dir);
}
