#!/usr/bin/env bash
# Mirror portable checks useful on Linux CI (see .github/workflows/ci-unix.yml).
# Run from repository root: bash scripts/linux-portable-validation.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== rustfmt (check) =="
cargo fmt --all --check

echo "== Cargo.lock =="
cargo metadata --locked --format-version 1 >/dev/null

echo "== clippy portable crates =="
cargo clippy -p psign-sip-digest -p psign-digest-cli -p psign-authenticode-trust \
  -p psign-codesigning-rest -p psign-azure-kv-rest \
  --all-targets --locked -- -D warnings

echo "== clippy digest-cli (artifact-signing-rest) =="
cargo clippy -p psign-digest-cli --all-targets --features artifact-signing-rest --locked -- -D warnings

echo "== clippy digest-cli (azure-kv-sign-portable) =="
cargo clippy -p psign-digest-cli --all-targets --features azure-kv-sign-portable --locked -- -D warnings

echo "== clippy digest-cli (timestamp-http) =="
cargo clippy -p psign-digest-cli --all-targets --features timestamp-http --locked -- -D warnings

echo "== clippy psign lib (stub on Unix) =="
cargo clippy -p psign --lib --locked -- -D warnings

echo "== unit tests: sip-digest =="
cargo test -p psign-sip-digest --lib --locked

echo "== unit tests: authenticode-trust =="
cargo test -p psign-authenticode-trust --lib --locked

echo "== unit tests: codesigning-rest =="
cargo test -p psign-codesigning-rest --lib --locked

echo "== unit tests: azure-kv-rest =="
cargo test -p psign-azure-kv-rest --lib --locked

echo "== integration: psign-tool portable (digest-cli) =="
cargo test -p psign --test cli_pe_digest --locked

echo "== integration: psign-tool portable (artifact-signing-rest) =="
cargo test -p psign --test cli_pe_digest --features artifact-signing-rest --locked

echo "== integration: psign-tool portable (azure-kv-sign-portable) =="
cargo test -p psign --test cli_pe_digest --features azure-kv-sign --locked

echo "== integration: psign-tool portable (timestamp-http) =="
cargo test -p psign --test cli_pe_digest --features timestamp-http --locked

echo "== psign library tests (argv / response files) =="
cargo test -p psign --lib --locked

echo "== check psign binaries + lib =="
cargo check -p psign --bins --lib --locked

echo "== OK: linux portable validation complete =="
