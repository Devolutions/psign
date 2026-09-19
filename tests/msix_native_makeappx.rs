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
