# Agent guide — psign

This repository is a **Rust port** of the Windows SDK **`signtool.exe`** (Authenticode sign / verify / timestamp / remove, plus related flows). Portable digest logic mirrors inbox SIP hashing where implemented; the full CLI depends on Win32 (**`WinVerifyTrust`**, **`SignerSignEx3`**, CryptSIP).

## Workspace layout

| Area | Path | Notes |
|------|------|--------|
| Root package (unified CLI + lib) | `Cargo.toml` (package **`psign`**) | **`psign-tool`** dispatches to Win32 code on Windows or portable Rust paths via `--mode`; **`windows`** crate feature deps stay under **`cfg(windows)`**. |
| Portable digest library | `crates/psign-sip-digest` | No **`windows`** dependency; Linux-safe unit tests. |
| Portable Authenticode trust | `crates/psign-authenticode-trust` | Anchors + picky chain; **`psign-tool portable`** **`trust-verify-pe`**, **`trust-verify-cab`**, **`trust-verify-catalog`**, **`trust-verify-detached`** — no OS trust store. |
| Portable CLI runner | `crates/psign-digest-cli` | Library used by **`psign-tool portable ...`**; no separate portable executable is emitted. |
| Win32 implementation | `src/win/` | Verify, sign, timestamp, catalog, detached PKCS#7, etc. |
| argv / response files | `src/native_argv.rs`, `src/response_argv.rs` | Shared by unified CLI and portable-mode builds. |

**Important:** **`default-members`** include the root **`psign`** package plus the portable crates under **`crates/`**. A bare **`cargo build`** at the repo root builds the unified **`psign-tool`** executable from **`src/main.rs`**; portable functionality is invoked through **`psign-tool portable ...`**.

## Commands agents should run

**After substantive edits**

```text
cargo fmt --all
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
```

On Linux/macOS, match **`ci-unix`**: fmt check, metadata **`--locked`**, clippy **`-D warnings`** on **`psign-sip-digest`**, **`psign-digest-cli`**, **`psign-authenticode-trust`**, **`psign --lib`**, then **`cargo test -p psign-sip-digest --lib`**, **`cargo test -p psign-authenticode-trust --lib`**, **`cargo test -p psign --test cli_pe_digest`**, and **`cargo test -p psign --lib`**.

**Windows-only parity** (when changing verify/sign/timestamp behavior): build **`psign`** and run **`scripts/run-parity-diff.ps1`** or **`scripts/ci/run-exhaustive-parity-ci.ps1`** with env vars described in **`docs/ci-parity.md`**.

## Documentation map

| Doc | Purpose |
|-----|---------|
| **`docs/windows-signing-components.md`** | Reference map of **`signtool.exe`**, **`mssign32`**, **`WINTRUST`**, SIP DLLs, **`imagehlp`**; includes a mermaid relationship diagram. |
| **`docs/rust-sip-architecture.md`** | Rust SIP digest add-ons vs OS SIP. |
| **`docs/rust-sip-gaps.md`** | Known limitations (MSIX sign gap, `/ph`, PKCS#7 encode, VBA, encrypted MSIX, …). |
| **`docs/rust-sip-spec-refs.md`** | Spec links + PE page-hash / **`SignerSignEx3`** notes. |
| **`docs/ci-parity.md`** | CI steps, **`PSIGN_*`** env vars, parity gates. |
| **`docs/roadmap-authenticode-linux.md`** | Unix/portable subset and **`psign-tool portable`**. |
| **`docs/authenticode-trust-stack.md`** | Portable trust crate split (picky vs digest vs CMS). |
| **`docs/authroot-linux-verify.md`** | Anchor dir + AuthRoot CAB usage on Linux. |
| **`docs/plan-linux-authenticode-trust-verify.md`** | Technical plan (CTL, test matrix, risks). |
| **`docs/psign-cli-matrix.json`** | Machine-checked native ↔ Rust CLI mapping (with **`psign-cli-matrix.md`** summary). |

Do **not** commit **`parity-output/`** or **`reversing/`** — they are **gitignored** (local parity JSON, **`psign-depgraph`** output, optional vendor DLL copies).

## Implementation conventions

- **Edition:** Rust **2024**.
- **Portable crypto / ASN.1:** Prefer existing crates (**`cms`**, **`authenticode`**, **`sha2`**, …) and patterns in **`psign-sip-digest`**.
- **Windows API:** Use the **`windows`** crate bindings already wired in **`src/win/`**; keep new FFI narrow and documented.
- **Parity:** Prefer extending **`scripts/run-parity-diff.ps1`** scenarios and/or corpus fixtures over one-off manual checks; **`documented_*`** classifications are allowed non-fatal rows when native limitations are intentional.

## PR / commit hygiene

- Keep changes scoped to the requested behavior; avoid drive-by refactors.
- Do not add tracked binaries, third-party analysis session databases, or parity JSON under ignored dirs.
- If you add user-facing flags, update **`docs/psign-cli-matrix.json`** (and generated/summary **`psign-cli-matrix.md`** if that file is maintained by hand in sync).
