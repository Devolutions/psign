# SignTool CLI parity matrix

This document summarizes native `signtool.exe` options plus the related `rdpsign.exe` RDP signing surface vs the **`psign-tool`** CLI (Rust package **`psign`**). The **machine-readable source of truth** is [`psign-cli-matrix.json`](psign-cli-matrix.json) (`commands.*`, `global_options`, `invocation`, `capability_dimensions`, `code_sign_file_formats`, `portable_digest_cli`, `top_gap_ids`).

SDK help text used for cross-checking can be captured locally under **`parity-output/`** (`signtool-help-*.txt`; gitignored). The pinned kit version is recorded in this repo’s `sdk_kit` field in the JSON (currently aligned with `10.0.26100.0`).

## Tier legend

| Tier | Meaning |
|------|---------|
| P0 | Common CLI surface aligned with native workflows where feasible |
| P1 | Split digest pipeline (`/dg` family), advanced verify modes, and auxiliary semantics — often partial by design |
| P2 | Low-volume PKCS#7 product modes (`/p7*`), certificate-template/sign-auth stubs, and rare switches |

## Invocation (`@responsefile`)

| Native | Rust | Status |
|--------|------|--------|
| `@responsefile` | `@responsefile` | Implemented |

Notes (see JSON `invocation[0].notes`): UTF-8 (optional BOM) or UTF-16 LE/BE **with** BOM; invalid UTF-8 falls back to UTF-16 LE **without** BOM; one argument per line; double-quoted lines with `""` escapes; blank line separates command blocks when `@file` is the only tail argument; inline `@path` splices one block; `@@` strips one `@` for a literal leading at-sign. Native may mis-parse `@` when `signtool.exe`’s path contains spaces — parity scripts use a TEMP copy without spaces.

## Global options

| Native | Rust | Status |
|--------|------|--------|
| `/q` | `--quiet (-q)` | Implemented |
| `/v` | `--verbose (-v)` | Implemented |
| `/debug` | `--debug` | Implemented |

Exit codes follow native conventions where applicable: `0` success, `1` failure, `2` warning (e.g. `--warn-if-not-timestamped`).

## Per-verb switch tables

Full native ↔ Rust mappings, tiers, and per-flag notes are **only** maintained in [`psign-cli-matrix.json`](psign-cli-matrix.json) to avoid drift. Highlights:

- **Verify `/o`**: Catalog WinTrust only — `--os-version-check` sets `WTD_USE_DEFAULT_OSVER_CHECK` in `verify_with_catalog`; embedded verify without `--catalog` / `--catalog-search` / `--catalog-database-guid` errors to match current signtool (see JSON `verify` entry for `/o`).
- **Detached PKCS#7 / explicit catalogs**: Windows retains native verification. `--mode portable verify --detached-pkcs7` routes once through portable detached CMS/chain trust, while `--catalog <catalog> <subjects...>` trusts the catalog once then checks every subject’s CTL membership; neither route emulates catalog-database, driver, or OS policy.
- **Verify `/bp`, `/enclave`**: CLI accepted; explicit not-implemented errors pending published WinTrust action/policy GUIDs (JSON marks partial).
- **RDP signing**: `psign-tool rdp --sha256 <thumbprint> file.rdp` ports `rdpsign.exe` by writing native `SignScope` / `Signature` records using detached PKCS#7 over the RDP secure-settings blob. `psign-tool portable rdp --cert cert.der --key key.pk8 file.rdp` uses the same RDP blob/record logic with portable RSA/SHA-256 CMS creation; fixtures cover UTF-8, UTF-16 with/without BOM, stale/partial signatures, malformed records, and a repo-test-cert signed sample.
- **Artifact Signing REST for PE/WinMD and PowerShell scripts**: `psign-tool portable sign-pe --artifact-signing-* --timestamp-url ...` and `psign-tool --mode portable sign --dmdf metadata.json --artifact-signing-* --timestamp-url ...` build, timestamp, and embed PE or PowerShell Authenticode signatures without Microsoft client DLLs. Portable script signing supports `.ps1`, `.psd1`, `.psm1`, `.ps1xml`, `.psc1`, `.cdxml`, and `.mof`; Windows dlib mode remains available for unsupported SIP formats.
- **Portable existing-PE RFC3161 timestamp**: `psign-tool --mode portable timestamp --rfc3161-url URL --digest sha256 signed.exe` posts an RFC3161 request and embeds the returned token in the primary PE/WinMD Authenticode signature. Legacy `/t`, sealing, `/p7`, and `/tp` remain Windows-only.

## Expanded capability model

The JSON now records the feature matrix across lifecycle dimensions, not just native switch spelling:

| Dimension | Meaning |
|-----------|---------|
| `argv-parity` | Response files, slash aliases, and native-shaped global behavior |
| `sign-embed` / `timestamp` / `remove-mutate` | Signature creation, timestamp attachment, and signed-content mutation |
| `verify-policy` | WinTrust/CryptoAPI policy paths |
| `digest-consistency` / `explicit-anchor-trust` | Portable SIP/CMS verification without OS trust stores |
| `inspect-extract` / `orchestrate` | Diagnostics, split-signing primitives, and nested package planning/execution |

`portable_digest_cli.commands` is checked against `psign-tool portable --help` by `tests/cli_matrix_docs.rs`, so newly-added portable subcommands must be reflected in the machine-readable matrix.

## Top 3 gaps worth filling next

The roadmap choice is maintained in [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md#top-3-gaps-worth-filling-next); the JSON stores only the stable `top_gap_ids` for machine-readable cross-reference. Current priorities:

| Gap id | Why it is high value |
|--------|----------------------|
| `portable-msix-upload-final-signing` | Closes the remaining Linux/Artifact Signing package gap now that flat and bundle MSIX/AppX signing are portable. |
| `catalog-driver-package-authoring` | Turns existing catalog signing/member verification into a fuller driver/package catalog workflow. |
| `wdac-ci-policy-signing` | Builds on detached PKCS#7/catalog primitives for a security-policy workflow that is adjacent to existing Authenticode users. |

## Gaps intentionally partial

- **Split digest `/dg`, `/ds`, `/di`, `/dxml`**: Rust accepts equivalents; execution returns a structured error — use native `signtool` or atomic signing (`sign_digest_pipeline.rs`).
- **PKCS#7 product signing `/p7*`** (non-SIP): Flags exist; differs from PE SIP signing. Portable `inspect-pkcs7` / `extract-pkcx-pkcs7` cover standalone inspection and AppX `PKCX` unwrap, but native-shaped product signing/export remains partial in JSON.
- **Sign sealing / intent-to-seal / `/force` (sign)**, **`/c` template**, **`/sa`**, **`/fdchw` / `/tdchw` / `/rmc`**, seal warn flags**: CLI surfaces exist; many return explicit not-implemented errors (`sealing.rs`).
- **Timestamp `/p7`, `/force`, `/nosealwarn`**: Explicit not-implemented errors.
- **`/ms` (`--multiple-semantics`)**: Accepted; documented compatibility shim — WinTrust defaults vary by OS.
- **`catdb` subsystem GUIDs**: Best-effort vs SDK (`catdb.rs`).

## File-format parity (summary)

Extension groups (PE, WinMD, MSI, MSIX, scripts, WSH) and parity scenario IDs are listed under `code_sign_file_formats` in the JSON.

CLI-only parity backlog (digest-split, sealing, PKCS#7 product modes, etc.) is tracked separately in [`cli-parity-backlog.md`](cli-parity-backlog.md).

## References

- [SignTool (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
