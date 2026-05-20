use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

#[test]
fn code_signing_vector_manifest_committed_entries_are_current() {
    let manifest = manifest();
    assert_eq!(manifest["schema_version"], 2);

    let vectors = manifest["committed_vectors"]
        .as_array()
        .expect("committed_vectors must be an array");
    assert!(
        !vectors.is_empty(),
        "code-signing vector manifest must describe committed fixtures"
    );

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut ids = HashSet::new();

    for vector in vectors {
        let id = vector["id"].as_str().expect("vector id");
        assert!(ids.insert(id.to_owned()), "duplicate vector id: {id}");

        let family = vector["family"].as_str().expect("vector family");
        assert!(!family.trim().is_empty(), "empty family for {id}");

        let extension = vector["extension"].as_str().expect("extension");
        assert!(
            extension.starts_with('.'),
            "extension must include dot for {id}"
        );

        let operations = vector["operations"]
            .as_array()
            .expect("operations must be an array");
        assert!(!operations.is_empty(), "missing operations for {id}");

        let rel = vector["path"].as_str().expect("committed vector path");
        let path = repo_path(repo_root, rel);
        assert!(path.is_file(), "committed vector missing: {rel}");

        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let expected_size = vector["size_bytes"].as_u64().expect("size_bytes");
        assert_eq!(bytes.len() as u64, expected_size, "size mismatch for {rel}");

        let digest = Sha256::digest(&bytes);
        let actual_hash = hex_lower(&digest);
        let expected_hash = vector["sha256"].as_str().expect("sha256");
        assert_eq!(actual_hash, expected_hash, "sha256 mismatch for {rel}");
    }
}

#[test]
fn code_signing_vector_manifest_matrix_covers_required_extensions() {
    let manifest = manifest();
    let axes = &manifest["required_axes"];

    assert_group_covers(
        &manifest,
        "generated-pe-alias-matrix",
        "extensions",
        string_set(axes["pe_extensions"].as_array().expect("pe_extensions")),
    );
    assert_group_covers(
        &manifest,
        "generated-winmd-matrix",
        "extensions",
        string_set(
            axes["winmd_extensions"]
                .as_array()
                .expect("winmd_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "generated-powershell-script-encoding-matrix",
        "extensions",
        string_set(
            axes["powershell_extensions"]
                .as_array()
                .expect("powershell_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "generated-wsh-script-encoding-matrix",
        "extensions",
        string_set(axes["wsh_extensions"].as_array().expect("wsh_extensions")),
    );
    assert_group_covers(
        &manifest,
        "generated-wsh-native-probe-matrix",
        "extensions",
        string_set(
            axes["wsh_native_probe_extensions"]
                .as_array()
                .expect("wsh_native_probe_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "generated-installer-probe-matrix",
        "extensions",
        string_set(
            axes["installer_extensions"]
                .as_array()
                .expect("installer_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "generated-cleartext-package-matrix",
        "extensions",
        string_set(
            axes["cleartext_package_extensions"]
                .as_array()
                .expect("cleartext_package_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "generated-encrypted-package-negative-matrix",
        "extensions",
        string_set(
            axes["encrypted_package_extensions"]
                .as_array()
                .expect("encrypted_package_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "optional-provider-probe-matrix",
        "extensions",
        string_set(
            axes["optional_provider_extensions"]
                .as_array()
                .expect("optional_provider_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "generated-p7x-probe-matrix",
        "extensions",
        string_set(axes["p7x_extensions"].as_array().expect("p7x_extensions")),
    );
    assert_group_covers(
        &manifest,
        "generated-p7x-artifact-matrix",
        "extensions",
        string_set(axes["p7x_extensions"].as_array().expect("p7x_extensions")),
    );
    assert_group_covers(
        &manifest,
        "generated-appinstaller-probe-matrix",
        "extensions",
        string_set(
            axes["appinstaller_extensions"]
                .as_array()
                .expect("appinstaller_extensions"),
        ),
    );
    assert_group_covers(
        &manifest,
        "generated-appinstaller-signature-matrix",
        "extensions",
        string_set(
            axes["appinstaller_signature_extensions"]
                .as_array()
                .expect("appinstaller_signature_extensions"),
        ),
    );
}

#[test]
fn code_signing_vector_manifest_script_matrices_cover_encodings_and_line_endings() {
    let manifest = manifest();
    let axes = &manifest["required_axes"];
    let encodings = string_set(
        axes["script_encodings"]
            .as_array()
            .expect("script_encodings"),
    );
    let line_endings = string_set(
        axes["script_line_endings"]
            .as_array()
            .expect("script_line_endings"),
    );

    for group_id in [
        "generated-powershell-script-encoding-matrix",
        "generated-wsh-script-encoding-matrix",
    ] {
        assert_group_covers(&manifest, group_id, "encodings", encodings.clone());
        assert_group_covers(&manifest, group_id, "line_endings", line_endings.clone());
    }
}

#[test]
fn generated_unsigned_corpus_manifest_matches_files() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/generated-unsigned/generated-vectors.json"
    ))
    .expect("generated unsigned corpus manifest JSON");
    let vectors = manifest["vectors"]
        .as_array()
        .expect("generated unsigned vectors must be an array");
    assert!(
        !vectors.is_empty(),
        "generated unsigned corpus must include vectors"
    );

    assert_hash_entries(vectors);
}

#[test]
fn generated_signed_corpus_manifest_matches_files_and_has_no_failures() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/generated-signed/generated-signed-vectors.json"
    ))
    .expect("generated signed corpus manifest JSON");

    let signed = manifest["signed"]
        .as_array()
        .expect("generated signed entries must be an array");
    assert!(
        !signed.is_empty(),
        "generated signed corpus must include signed entries"
    );
    assert_hash_entries(signed);

    let failed = manifest["failed"]
        .as_array()
        .expect("generated signed failures must be an array");
    assert!(failed.is_empty(), "generated signed corpus has failures");

    let skipped = manifest["skipped"]
        .as_array()
        .expect("generated signed skipped entries must be an array");
    assert!(
        skipped
            .iter()
            .any(|entry| entry["state"] == "native-sign-rejected"),
        "generated signed corpus should record native signing rejects"
    );
    assert!(
        signed
            .iter()
            .any(|entry| entry["state"] == "package-signature-extracted"
                && entry["family"] == "p7x"
                && entry["path"]
                    .as_str()
                    .expect("p7x path")
                    .ends_with("appxsignature-from-sample-msix.p7x")),
        "generated signed corpus should include extracted AppxSignature.p7x"
    );
    assert!(
        signed
            .iter()
            .any(|entry| entry["state"] == "detached-signed"
                && entry["family"] == "appinstaller"
                && entry["path"]
                    .as_str()
                    .expect("appinstaller signature path")
                    .ends_with("sample.appinstaller.p7")),
        "generated signed corpus should include App Installer detached signature"
    );
}

#[test]
fn package_signing_fixture_manifest_matches_files() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/package-signing/package-signing-fixtures.json"
    ))
    .expect("package signing fixture manifest JSON");

    assert_eq!(
        manifest["generated_by"],
        "scripts/ci/build-package-signing-fixtures.ps1"
    );
    assert_eq!(
        manifest["pfx_thumbprint"],
        "A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38"
    );

    let entries = manifest["entries"]
        .as_array()
        .expect("package signing entries must be an array");
    assert_eq!(entries.len(), 6, "package signing fixture count");
    assert_hash_entries(entries);

    let families: HashSet<_> = entries
        .iter()
        .map(|entry| entry["family"].as_str().expect("family").to_owned())
        .collect();
    assert_eq!(
        families,
        HashSet::from([
            "nuget".to_owned(),
            "nuget-symbols".to_owned(),
            "vsix".to_owned()
        ])
    );

    let states: HashSet<_> = entries
        .iter()
        .map(|entry| entry["state"].as_str().expect("state").to_owned())
        .collect();
    assert_eq!(
        states,
        HashSet::from(["unsigned".to_owned(), "signed".to_owned()])
    );
}

fn manifest() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/code-signing-vectors.json"))
        .expect("code-signing vector manifest JSON")
}

fn assert_hash_entries(entries: &[serde_json::Value]) {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut ids = HashSet::new();

    for entry in entries {
        let id = entry["id"].as_str().expect("entry id");
        assert!(ids.insert(id.to_owned()), "duplicate generated id: {id}");

        let rel = entry["path"].as_str().expect("generated path");
        let path = repo_path(repo_root, rel);
        assert!(path.is_file(), "generated corpus file missing: {rel}");

        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let expected_size = entry["size_bytes"].as_u64().expect("size_bytes");
        assert_eq!(bytes.len() as u64, expected_size, "size mismatch for {rel}");

        let digest = Sha256::digest(&bytes);
        let actual_hash = hex_lower(&digest);
        let expected_hash = entry["sha256"].as_str().expect("sha256");
        assert_eq!(actual_hash, expected_hash, "sha256 mismatch for {rel}");
    }
}

fn repo_path(repo_root: &Path, rel: &str) -> std::path::PathBuf {
    let separator = std::path::MAIN_SEPARATOR.to_string();
    repo_root.join(rel.replace('\\', &separator))
}

fn matrix_group<'a>(manifest: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    manifest["matrix_groups"]
        .as_array()
        .expect("matrix_groups must be an array")
        .iter()
        .find(|group| group["id"] == id)
        .unwrap_or_else(|| panic!("matrix group missing: {id}"))
}

fn assert_group_covers(
    manifest: &serde_json::Value,
    group_id: &str,
    field: &str,
    expected: HashSet<String>,
) {
    let group = matrix_group(manifest, group_id);
    let actual = string_set(
        group[field]
            .as_array()
            .unwrap_or_else(|| panic!("{group_id}.{field} must be an array")),
    );
    assert_eq!(actual, expected, "{group_id}.{field} coverage mismatch");
}

fn string_set(values: &[serde_json::Value]) -> HashSet<String> {
    values
        .iter()
        .map(|value| value.as_str().expect("string array value").to_owned())
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
