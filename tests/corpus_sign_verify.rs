#![cfg(windows)]

use assert_cmd::prelude::*;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TEST_CERT_SHA1: &str = "A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38";
const TEST_PFX_PASSWORD: &str = "CodeSign123!";

#[derive(Debug, Deserialize)]
struct SignedCorpusManifest {
    signed: Vec<SignedCorpusEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct SignedCorpusEntry {
    id: String,
    family: String,
    extension: String,
    state: String,
    source_path: String,
    path: String,
}

#[test]
fn committed_signed_corpus_verifies_with_psign() {
    let repo = repo_root();
    let manifest = signed_manifest();
    assert_eq!(manifest.signed.len(), 103, "signed corpus coverage changed");

    for entry in &manifest.signed {
        if entry.state == "detached-signed" {
            verify_detached_with_psign(
                &repo_path(&repo, &entry.source_path),
                &repo_path(&repo, &entry.path),
                &entry.id,
            );
        } else if entry.state == "package-signature-extracted" {
            assert_appx_signature_p7x(&repo_path(&repo, &entry.path), &entry.id);
        } else {
            verify_embedded_with_psign(&repo_path(&repo, &entry.path), &entry.id);
        }
    }
}

#[test]
fn committed_signed_corpus_matches_portable_supported_verification() {
    let repo = repo_root();
    let manifest = signed_manifest();
    assert_eq!(manifest.signed.len(), 103, "signed corpus coverage changed");

    let mut parity_count = 0usize;
    for entry in &manifest.signed {
        if entry.state == "detached-signed" {
            let content = repo_path(&repo, &entry.source_path);
            let signature = repo_path(&repo, &entry.path);
            verify_detached_with_psign(&content, &signature, &entry.id);
            verify_detached_with_portable(&repo, &content, &signature, &entry.id);
        } else if entry.state == "package-signature-extracted" {
            assert_appx_signature_p7x(&repo_path(&repo, &entry.path), &entry.id);
            continue;
        } else if let Some(args) =
            portable_args_for_entry(&repo, entry, &repo_path(&repo, &entry.path))
        {
            verify_embedded_with_psign(&repo_path(&repo, &entry.path), &entry.id);
            assert_success(
                portable()
                    .args(args)
                    .output()
                    .unwrap_or_else(|e| panic!("run portable verify for {}: {e}", entry.id)),
                &format!("portable verify {}", entry.id),
            );
        } else {
            continue;
        }
        parity_count += 1;
    }

    assert_eq!(parity_count, 102, "portable parity coverage changed");
}

#[test]
fn unsigned_corpus_freshly_signed_with_native_signtool_verifies_with_psign() {
    let Some(signtool) = native_signtool_optional_path() else {
        eprintln!("skipping corpus native-sign test: signtool.exe not found");
        return;
    };

    let repo = repo_root();
    let manifest = signed_manifest();
    let temp = TempDir::new("psign-native-corpus");
    let mut signed_count = 0usize;

    for entry in manifest
        .signed
        .iter()
        .filter(|entry| entry.state == "signed")
    {
        let dest = temp.path().join(format!("{}{}", entry.id, entry.extension));
        std::fs::copy(repo_path(&repo, &entry.source_path), &dest)
            .unwrap_or_else(|e| panic!("copy {}: {e}", entry.source_path));

        let sign = Command::new(&signtool)
            .args(["sign", "/fd", "SHA256", "/f"])
            .arg(test_pfx_path(&repo))
            .args(["/p", TEST_PFX_PASSWORD])
            .arg(&dest)
            .output()
            .unwrap_or_else(|e| panic!("run signtool sign for {}: {e}", entry.id));
        assert_success(sign, &format!("native signtool sign {}", entry.id));
        verify_embedded_with_psign(&dest, &entry.id);
        signed_count += 1;
    }

    for detached in manifest
        .signed
        .iter()
        .filter(|entry| entry.state == "detached-signed")
    {
        let p7_dir = temp.path().join("detached").join(&detached.id);
        std::fs::create_dir_all(&p7_dir).expect("create detached output dir");
        let content = repo_path(&repo, &detached.source_path);
        let sign = Command::new(&signtool)
            .args(["sign", "/fd", "SHA256", "/f"])
            .arg(test_pfx_path(&repo))
            .args([
                "/p",
                TEST_PFX_PASSWORD,
                "/p7",
                p7_dir.to_str().expect("p7 dir is utf-8"),
                "/p7ce",
                "DetachedSignedData",
                "/p7co",
                "1.2.840.113549.1.7.2",
            ])
            .arg(&content)
            .output()
            .expect("run signtool detached sign");
        assert_success(sign, "native signtool detached sign");
        let p7 = std::fs::read_dir(&p7_dir)
            .expect("read detached output dir")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.is_file())
            .expect("detached PKCS#7 output");
        verify_detached_with_psign(&content, &p7, &detached.id);
        signed_count += 1;
    }

    assert_eq!(signed_count, 102, "fresh native signing coverage changed");
}

#[test]
fn unsigned_corpus_freshly_signed_with_psign_verifies_with_psign() {
    let thumbprint = std::env::var("PSIGN_TEST_CERT_SHA1")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| TEST_CERT_SHA1.to_owned());
    if !current_user_my_contains_cert(&thumbprint) {
        eprintln!(
            "skipping corpus psign-sign test: certificate {thumbprint} not found in CurrentUser\\My"
        );
        return;
    }

    let repo = repo_root();
    let manifest = signed_manifest();
    let temp = TempDir::new("psign-rust-corpus");
    let signable: Vec<_> = manifest
        .signed
        .iter()
        .filter(|entry| entry.state == "signed" && entry.family != "msix")
        .collect();
    assert_eq!(signable.len(), 94, "psign fresh-sign coverage changed");

    for entry in signable {
        let dest = temp.path().join(format!("{}{}", entry.id, entry.extension));
        std::fs::copy(repo_path(&repo, &entry.source_path), &dest)
            .unwrap_or_else(|e| panic!("copy {}: {e}", entry.source_path));

        let sign = psign()
            .args(["sign", "--cert-sha1", &thumbprint, "--digest", "sha256"])
            .arg(&dest)
            .output()
            .unwrap_or_else(|e| panic!("run psign sign for {}: {e}", entry.id));
        assert_success(sign, &format!("psign sign {}", entry.id));
        verify_embedded_with_psign(&dest, &entry.id);
    }

    for entry in manifest
        .signed
        .iter()
        .filter(|entry| entry.state == "signed" && entry.family == "msix")
    {
        let dest = temp.path().join(format!("{}{}", entry.id, entry.extension));
        std::fs::copy(repo_path(&repo, &entry.source_path), &dest)
            .unwrap_or_else(|e| panic!("copy {}: {e}", entry.source_path));
        let sign = psign()
            .args(["sign", "--cert-sha1", &thumbprint, "--digest", "sha256"])
            .arg(&dest)
            .output()
            .unwrap_or_else(|e| panic!("run psign sign for {}: {e}", entry.id));
        assert!(
            !sign.status.success(),
            "MSIX corpus row unexpectedly signed without timestamp: {}\n{}",
            entry.id,
            output_text(&sign)
        );
        assert!(
            output_text(&sign).contains("must be timestamped"),
            "MSIX timestamp requirement missing for {}\n{}",
            entry.id,
            output_text(&sign)
        );
    }
}

fn verify_embedded_with_psign(path: &Path, label: &str) {
    let verify = psign()
        .args(["verify", "--policy", "pa", "--allow-test-root"])
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("run psign verify for {label}: {e}"));
    assert_success(verify, &format!("psign verify {label}"));
}

fn verify_detached_with_psign(content: &Path, p7: &Path, label: &str) {
    let verify = psign()
        .args(["verify", "--policy", "pa", "--allow-test-root"])
        .arg(content)
        .arg("--detached-pkcs7")
        .arg(p7)
        .output()
        .unwrap_or_else(|e| panic!("run psign detached verify for {label}: {e}"));
    assert_success(verify, &format!("psign detached verify {label}"));
}

fn assert_appx_signature_p7x(path: &Path, label: &str) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {label}: {e}"));
    assert!(
        bytes.starts_with(b"PKCX"),
        "extracted AppxSignature.p7x fixture must start with PKCX header: {label}"
    );
}

fn verify_detached_with_portable(repo: &Path, content: &Path, p7: &Path, label: &str) {
    let verify = portable()
        .arg("trust-verify-detached")
        .arg(content)
        .arg(p7)
        .arg("--anchor-dir")
        .arg(anchor_dir(repo))
        .output()
        .unwrap_or_else(|e| panic!("run portable detached verify for {label}: {e}"));
    assert_success(verify, &format!("portable detached verify {label}"));
}

fn psign() -> Command {
    Command::cargo_bin("psign-tool").expect("psign-tool binary")
}

fn portable() -> Command {
    let mut cmd = psign();
    cmd.arg("portable");
    cmd
}

fn portable_args_for_entry(
    repo: &Path,
    entry: &SignedCorpusEntry,
    path: &Path,
) -> Option<Vec<String>> {
    let anchor = anchor_dir(repo).display().to_string();
    let path = path.display().to_string();
    let args = match entry.family.as_str() {
        "pe" | "winmd" => vec![
            "trust-verify-pe".to_owned(),
            path,
            "--anchor-dir".to_owned(),
            anchor,
        ],
        "cab" => vec![
            "trust-verify-cab".to_owned(),
            path,
            "--anchor-dir".to_owned(),
            anchor,
        ],
        "catalog" => vec![
            "trust-verify-catalog".to_owned(),
            path,
            "--anchor-dir".to_owned(),
            anchor,
        ],
        "wim-esd" => vec![
            "trust-verify-esd".to_owned(),
            path,
            "--anchor-dir".to_owned(),
            anchor,
        ],
        "installer" => vec![
            "trust-verify-msi".to_owned(),
            path,
            "--anchor-dir".to_owned(),
            anchor,
        ],
        "msix" => vec!["verify-msix".to_owned(), path],
        "powershell-script" | "wsh-script" => vec!["verify-script".to_owned(), path],
        _ => return None,
    };
    Some(args)
}

fn assert_success(output: Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with status {}\n{}",
        output.status,
        output_text(&output)
    );
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn signed_manifest() -> SignedCorpusManifest {
    serde_json::from_str(include_str!(
        "fixtures/generated-signed/generated-signed-vectors.json"
    ))
    .expect("signed corpus manifest JSON")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(repo_root: &Path, rel: &str) -> PathBuf {
    let separator = std::path::MAIN_SEPARATOR.to_string();
    repo_root.join(rel.replace('\\', &separator))
}

fn test_pfx_path(repo_root: &Path) -> PathBuf {
    repo_root.join("tests\\fixtures\\devolutions-authenticode\\authenticode-test-cert.pfx")
}

fn anchor_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("tests\\fixtures\\devolutions-authenticode")
}

fn native_signtool_optional_path() -> Option<PathBuf> {
    std::env::var_os("SIGNTOOL_EXE")
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .or_else(|| {
            let path = PathBuf::from(
                r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
            );
            path.exists().then_some(path)
        })
        .or_else(|| {
            Command::new("signtool.exe")
                .arg("/?")
                .output()
                .is_ok()
                .then(|| PathBuf::from("signtool.exe"))
        })
}

fn current_user_my_contains_cert(thumbprint: &str) -> bool {
    Command::new("certutil")
        .args(["-user", "-store", "MY", thumbprint])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before UNIX_EPOCH")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
