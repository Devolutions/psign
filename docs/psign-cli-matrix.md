# SignTool CLI parity matrix

This document summarizes native `signtool.exe` options plus the related `rdpsign.exe` RDP signing surface vs the **`psign-tool`** CLI (Rust package **`psign`**). The **machine-readable source of truth** is [`psign-cli-matrix.json`](psign-cli-matrix.json) (`commands.sign`, `commands.verify`, `commands.timestamp`, `commands.catdb`, `commands.remove`, `commands.rdp`, `global_options`, `invocation`, `code_sign_file_formats`).

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
- **Detached PKCS#7**: Implemented with chain policy; bare CMS `SignedData` from `signtool /p7` is normalized to PKCS#7 `ContentInfo` before `CryptVerifyDetachedMessageSignature` (`src/win/verify_detached.rs`).
- **Verify `/bp`, `/enclave`**: CLI accepted; explicit not-implemented errors pending published WinTrust action/policy GUIDs (JSON marks partial).
- **RDP signing**: `psign-tool rdp --sha256 <thumbprint> file.rdp` ports `rdpsign.exe` by writing native `SignScope` / `Signature` records using detached PKCS#7 over the RDP secure-settings blob. `psign-tool portable rdp --cert cert.der --key key.pk8 file.rdp` uses the same RDP blob/record logic with portable RSA/SHA-256 CMS creation; fixtures cover UTF-8, UTF-16 with/without BOM, stale/partial signatures, malformed records, and a repo-test-cert signed sample.

## Gaps intentionally partial

- **Split digest `/dg`, `/ds`, `/di`, `/dxml`**: Rust accepts equivalents; execution returns a structured error — use native `signtool` or atomic signing (`sign_digest_pipeline.rs`).
- **PKCS#7 product signing `/p7*`** (non-SIP): Flags exist; differs from PE SIP signing — partial in JSON.
- **Sign sealing / intent-to-seal / `/force` (sign)**, **`/c` template**, **`/sa`**, **`/fdchw` / `/tdchw` / `/rmc`**, seal warn flags**: CLI surfaces exist; many return explicit not-implemented errors (`sealing.rs`).
- **Timestamp `/p7`, `/force`, `/nosealwarn`**: Explicit not-implemented errors.
- **`/ms` (`--multiple-semantics`)**: Accepted; documented compatibility shim — WinTrust defaults vary by OS.
- **`catdb` subsystem GUIDs**: Best-effort vs SDK (`catdb.rs`).

## File-format parity (summary)

Extension groups (PE, WinMD, MSI, MSIX, scripts, WSH) and parity scenario IDs are listed under `code_sign_file_formats` in the JSON.

CLI-only parity backlog (digest-split, sealing, PKCS#7 product modes, etc.) is tracked separately in [`cli-parity-backlog.md`](cli-parity-backlog.md).

## References

- [SignTool (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
