use assert_cmd::Command;
use serde_json::Value;
use std::collections::BTreeSet;

fn portable_help_commands() -> BTreeSet<String> {
    let output = Command::cargo_bin("psign-tool")
        .unwrap()
        .arg("portable")
        .arg("--help")
        .output()
        .expect("run psign-tool portable --help");
    assert!(
        output.status.success(),
        "portable help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if line.starts_with("  ")
                && !trimmed.contains(' ')
                && trimmed
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && trimmed != "help"
            {
                Some(trimmed.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn matrix_portable_commands() -> BTreeSet<String> {
    let matrix: Value =
        serde_json::from_str(include_str!("../docs/psign-cli-matrix.json")).expect("matrix JSON");
    let mut commands = matrix["portable_digest_cli"]["commands"]
        .as_array()
        .expect("portable_digest_cli.commands array")
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .expect("portable command name")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();

    if !cfg!(feature = "artifact-signing-rest") {
        commands.remove("artifact-signing-submit");
    }
    if !cfg!(feature = "azure-kv-sign") {
        commands.remove("azure-key-vault-sign-digest");
    }
    if !cfg!(feature = "timestamp-http") {
        commands.remove("rfc3161-timestamp-http-post");
    }

    commands
}

#[test]
fn portable_cli_matrix_matches_help_commands() {
    let help = portable_help_commands();
    let matrix = matrix_portable_commands();

    let missing_from_matrix = help.difference(&matrix).cloned().collect::<Vec<_>>();
    let stale_in_matrix = matrix.difference(&help).cloned().collect::<Vec<_>>();

    assert!(
        missing_from_matrix.is_empty() && stale_in_matrix.is_empty(),
        "portable_digest_cli.commands drifted from psign-tool portable --help\nmissing_from_matrix={missing_from_matrix:?}\nstale_in_matrix={stale_in_matrix:?}"
    );
}
