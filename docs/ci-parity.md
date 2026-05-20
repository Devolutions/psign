# CI parity tiers

GitHub Actions exercises differential parity between native `signtool.exe` and **`psign-tool`** (crate **`psign`**). Certificate material comes from the public **Devolutions Authenticode** test PKI ([`devolutions-authenticode`](https://github.com/Devolutions/devolutions-authenticode)): `authenticode-test-ca.crt` and `authenticode-test-cert.pfx` with password `CodeSign123!` (test-only; do not use in production).

On **Linux**, the default portable gate is **`ci-unix.yml`**; locally you can run **`bash scripts/linux-portable-validation.sh`** from the repo root (same steps as that workflow’s Rust checks).

## Tier 1 — Default workflow (`windows.yml`)

Runs on every push, PR, and daily schedule.

1. **`scripts/ci/bootstrap-devolutions-authenticode.ps1`** — Uses vendored public Devolutions test CA + PFX from [`tests/fixtures/devolutions-authenticode/`](../tests/fixtures/devolutions-authenticode/) when present (hash-checked), otherwise downloads the same files from raw URLs pinned to a fixed commit SHA; imports the CA into the machine (or user) trusted root, sets `PSIGN_TEST_PFX*` and timestamp URLs.
2. **`scripts/ci/prepare-parity-fixtures.ps1`** — Native-signs a temp PE (`PSIGN_SIGNED_FIXTURE`) for timestamp scenarios; produces detached PKCS#7 via native `signtool sign /p7 …` (`PSIGN_DETACHED_*`).
   **`scripts/ci/build-catalog-workflow-fixtures.ps1`** regenerates the committed MakeCat + signtool generic catalog fixtures under [`tests/fixtures/catalog-workflows/`](../tests/fixtures/catalog-workflows/) when catalog membership fixtures need updating.
3. **`scripts/ci/pack-minimal-msix.ps1`** — Packs [`tests/fixtures/msix-minimal/`](../tests/fixtures/msix-minimal/AppxManifest.xml) + `noop.exe` (copy of the built `psign-tool.exe`) into an unsigned `.msix`.
4. **`scripts/ci/pack-minimal-winmd.ps1`** — Copies the same unsigned `psign-tool.exe` to **`PSIGN_WINMD_UNSIGNED_FIXTURE`** (`.winmd` extension) so **`run-parity-diff`** exercises WinMD SIP scenarios; **`PSIGN_WINMD_TIMESTAMP_URL`** mirrors **`PSIGN_TIMESTAMP_URL`** when set after bootstrap.
5. **`scripts/run-parity-diff.ps1 -FailOnSemantic -FailOnSemanticExhaustive`** — Static CLI matrix, remove scenarios, PE + script description parity, timestamp exits, detached verify, catalog path if env set, MSIX semantic blocks when env present, WinMD scenarios when the WinMD fixture env is set, etc. Exhaustive mode asserts that core PE, timestamp, MSIX package, and detached env vars are all set before running.
6. **`scripts/msix-parity-sign.ps1 -FailOnSemantic`** — Focused MSIX sign/verify report (`parity-output/msix-parity-sign-report.json`).

Artifacts: `parity-output/parity-report.json`, `parity-output/msix-parity-sign-report.json` (uploaded as workflow artifacts). The **`parity-output/`** directory is gitignored, so clones do not contain those JSON files until you run parity locally or download CI artifacts.

## Local `run-parity-diff.ps1` snapshot

Optional parity scenarios are gated on environment variables (`PSIGN_MSIX_*`, `PSIGN_SIGNED_FIXTURE` + timestamp URL, detached PKCS#7 paths, catalog paths, and so on). If only a **subset** is set—for example an MSIX fixture path without the matching PFX and RFC3161 URL—the script still appends those scenarios and you may see `semantic_mismatch` rows that disappear once variables are cleared or the full matrix is provided.

For deterministic timestamp experiments without a public TSA, build **`psign-server`** with **`--features timestamp-server`** and point timestamp env vars (for example **`PSIGN_TIMESTAMP_URL`**) at its local URL. Example one-shot server:

```powershell
cargo run --features timestamp-server --bin psign-server -- timestamp-server --listen 127.0.0.1:48161 --max-requests 1
```

The server returns RFC 3161 **`TimeStampResp`** DER with a generated test TSA certificate and supports **`--status rejection`** / **`--status waiting`** plus **`--response-mode bad-alg|malformed-der|http-error|mismatched-imprint|invalid-signature`** for deterministic negative paths. It is intended for local/CI tests only, not production timestamping.

For a local Windows timestamp parity run, use [`scripts/run-local-timestamp-parity.ps1`](../scripts/run-local-timestamp-parity.ps1). It builds **`psign-server`**, prepares a signed PE fixture with the Devolutions test certificate, starts a local RFC 3161 server, exports **`PSIGN_TIMESTAMP_URL`**, and runs **`scripts/run-parity-diff.ps1`**. The server can also write its generated test certificates with **`--cert-output`** (root CA) and **`--tsa-cert-output`** (TSA leaf) for manual Windows trust experiments.

For local no-admin online certificate checks, use [`scripts/run-local-online-cert-parity.ps1`](../scripts/run-local-online-cert-parity.ps1). It builds **`psign-server`** with timestamp HTTP support and runs the feature-gated loopback PKI tests for explicit **`--trusted-ca`** anchors, AIA, CRL, OCSP, and trusted RFC3161 timestamp validation. These tests intentionally exercise the portable trust backend because Windows **`WinVerifyTrust`** custom-root parity still requires either persistent user/machine store changes or deeper custom chain-policy integration.

For a **baseline** report matching the static tier (verify/remove scenarios only, no optional blocks), clear process env vars whose names start with `PSIGN_`, then run `scripts/run-parity-diff.ps1`. Expect **21** scenarios, `missingScenarioCount: 0`, and `semanticMismatchCount: 0` (UTF-16 `@rsp` remains `documented_native_utf16_rsp_gap`, not a semantic failure).

## Tier 2 — Extensions (`parity-extensions.yml`)

Manual **`workflow_dispatch`** only.

| Input | Requires secrets | Behavior |
|-------|------------------|----------|
| **MSIX decoupled** | `PSIGN_MSIX_DLIB`, `PSIGN_MSIX_DMDF` | Repacks minimal MSIX, runs `msix-parity-sign.ps1 -UseDecoupledDigest` (same **`documented_rust_msix_sign_ex3_gap`** vs **`semantic_mismatch`** rules as embedded MSIX when sign exits differ). If you run **`run-parity-diff.ps1`** with those env vars set, **`artifact_msix_decoupled_semantic`** uses the same classification. |
| **Catalog verify** | `PSIGN_CATALOG_TARGET`, `PSIGN_CATALOG_FILE` | Runs `psign-tool verify <target> --catalog <cat>`, then the same with `--os-version-check 386:10.0.26100.0`. Optional exhaustive parity records both as `artifact_catalog_*`. |
| **Artifact Signing decoupled** | `PSIGN_ARTIFACT_SIGNING_*` (see below) | Optional local-only parity: run `cargo test -p psign --test parity_signtool artifact_signing_decoupled_pe_executes -- --ignored --nocapture` when fixtures + Microsoft dlib/metadata are available. Not wired into GitHub Actions by default. |
| **Artifact Signing REST submit** | `PSIGN_ARTIFACT_SIGNING_REST_*` | Optional: build **`psign-tool`** with **`--features artifact-signing-rest`**, then run **`artifact_signing_rest_submit_smoke`** (ignored). Env vars and recipe: [`migration-artifact-signing.md`](migration-artifact-signing.md#rest-hash-signing-gated-smoke-test). |

**Artifact Signing env vars** (for the ignored test `artifact_signing_decoupled_pe_executes` and manual recipes): `PSIGN_ARTIFACT_SIGNING_UNSIGNED_PE`, `PSIGN_ARTIFACT_SIGNING_METADATA`, `PSIGN_ARTIFACT_SIGNING_TIMESTAMP_URL`, `PSIGN_ARTIFACT_SIGNING_TEST_PFX`, optional `PSIGN_ARTIFACT_SIGNING_TEST_PFX_PASSWORD`, and either `PSIGN_ARTIFACT_SIGNING_DLIB` **or** `PSIGN_ARTIFACT_SIGNING_DLIB_ROOT`. Details: [`migration-artifact-signing.md`](migration-artifact-signing.md#ci--gated-parity-recipe).

## Scheduled portable SIP / CMS (`rust-sip-parity.yml`)

Runs on **`master`/`main`** pushes, **`workflow_dispatch`**, and a weekly cron.

| Job | Runner | Role |
|-----|--------|------|
| **`portable-cms-rs256-linux`** | **`ubuntu-latest`** | **`rsa_pkcs1v15_signed_attrs_verify`**; **`signer_rs256_prehash`**; **`cab_rs256_`** / **`cab_rsa_sha256_signer_prehash`**; **`msi_rs256_`** / **`msi_pkcs7_`**; **`cat_rs256_`** / **`catalog_rsa_sha256_signer_prehash`**; **`wim_verify_rejects`**; **`_unsigned_errors_`** (script SIP); **`portable_verify_negative_`** (CLI: PE/ESD/MSIX/script/CAB/trust/catalog/detached/inspect + digest + RS256 signer prehash bad-input paths); **`inspect_pkcs7_parity_`**; **`detached_trust_`**; **`data_plane_base_url`** ([`psign-codesigning-rest`](../crates/psign-codesigning-rest/src/lib.rs)); **`psign-azure-kv-rest --lib`** ([`psign-azure-kv-rest`](../crates/psign-azure-kv-rest/src/lib.rs)) — Linux gates for Azure KV **`RS256`** plus portable verify/inspect/trust and REST URL helpers. |
| **`rust-sip-golden`** | **`windows-latest`** | Full **`psign-sip-digest`** lib tests, unified **`psign-tool portable ...`** integration tests, optional **`scripts/rust-sip-parity-pe.ps1`**. |

These checks also run under **`ci-unix.yml`** / **`scripts/linux-portable-validation.sh`**; **`rust-sip-parity`** duplicates the CMS subset so parity dashboards stay meaningful without native **`signtool.exe`**.

## Operator notes

- Quick native ↔ Rust exit-code smoke over PE (and optional WinMD when env vars are set): [`scripts/sip-format-smoke.ps1`](../scripts/sip-format-smoke.ps1).
- Reusable committed/generated fixture inventory: [`tests/fixtures/code-signing-vectors.json`](../tests/fixtures/code-signing-vectors.json). The committed corpus lives uncompressed under [`tests/fixtures/generated-unsigned/`](../tests/fixtures/generated-unsigned/) and [`tests/fixtures/generated-signed/`](../tests/fixtures/generated-signed/) so tests can reference fixture files directly. Regenerate it with [`scripts/ci/build-code-signing-vector-corpus.ps1`](../scripts/ci/build-code-signing-vector-corpus.ps1) (or unsigned-only samples with [`build-code-signing-vector-samples.ps1`](../scripts/ci/build-code-signing-vector-samples.ps1)). The matrix includes PE aliases, script encoding variants, package bundles/encrypted negatives, installer/catalog probes, WIM/ESD negatives, detached PKCS#7 inputs, optional-provider probe rows, and native SignTool reject classifications for unsupported-but-useful encoding rows.
- WinMD parity: Tier 1 CI sets `PSIGN_WINMD_UNSIGNED_FIXTURE` via [`pack-minimal-winmd.ps1`](../scripts/ci/pack-minimal-winmd.ps1) (PE bytes, `.winmd` extension). Locally, point `PSIGN_WINMD_UNSIGNED_FIXTURE` at any unsigned `.winmd` plus the same `PSIGN_TEST_PFX` / password as PE; optional `PSIGN_WINMD_TIMESTAMP_URL` for RFC3161 (CI mirrors `PSIGN_TIMESTAMP_URL`).
- To change the pinned Devolutions commit, edit `$CommitSha` in [`scripts/ci/bootstrap-devolutions-authenticode.ps1`](../scripts/ci/bootstrap-devolutions-authenticode.ps1).
- If detached PKCS#7 generation fails on a future SDK, adjust [`scripts/ci/prepare-parity-fixtures.ps1`](../scripts/ci/prepare-parity-fixtures.ps1) (`/p7` fallback flags).
- Scenario inventory and semantics are summarized in [`parity-matrix.md`](parity-matrix.md).
