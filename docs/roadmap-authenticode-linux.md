# Roadmap: Authenticode tooling on Linux

The primary `psign-tool` binary is unified: Windows mode depends on **`windows`**, **WinVerifyTrust**, **SignerSignEx3**, and OS **CryptSIP** registration, while portable mode uses Rust digest/trust implementations. A practical Linux story is **phased**: keep Windows as the reference implementation while carving out **portable** pieces.

**Cross-tool comparison (native signtool vs AzureSignTool vs Artifact Signing vs this repo):** [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md). **Linux cookbook (verify / REST / hybrid):** [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

## Phase 0 — CI and hygiene

- **`ci-unix`**: `cargo fmt --check`, `cargo metadata --locked`, **`cargo clippy`** on portable digest + trust crates + **`psign` lib (`-D warnings`)**, **`cargo test -p psign-sip-digest --lib`**, **`cargo test -p psign-authenticode-trust --lib`**, **`cargo check -p psign`**, **`cargo test -p psign --lib`** (see `.github/workflows/ci-unix.yml`).
- **Workspace `default-members`** (root `Cargo.toml`): a bare **`cargo build`** / **`cargo test`** at the repo root includes the root **`psign`** package, so **`cargo build`** emits **`psign-tool`** from **`src/main.rs`**. Portable commands are available through **`psign-tool portable ...`**; there is no separate **`psign-tool-portable`** executable.
- **Local Linux/macOS mirror of CI** (from repo root, `--locked` optional but matches CI):  
  `cargo test -p psign-sip-digest --lib --locked`, `cargo test -p psign-authenticode-trust --lib --locked`, and `cargo test -p psign --test cli_pe_digest --locked`.
  Build the unified CLI: `cargo build -p psign --bin psign-tool --locked`; use **`psign-tool portable ...`** for portable-only diagnostics.
- The **`psign`** **CLI binary** on non-Windows dispatches to portable Rust paths where available; **`win`** is behind **`#[cfg(windows)]`** so **`windows`** is not a dependency on Linux.

## Phase 1 — Workspace split: `psign-sip-digest` (done)

- **`crates/psign-sip-digest`** holds portable digest modules (**no `windows` dependency**). The Win32 binary re-exports them from **`src/win/sip_rust/mod.rs`** and keeps thin **`sign_*`** helpers that need **`GlobalOpts`**.
- **`ci-unix`** runs **`cargo test -p psign-sip-digest --lib --locked`** (see `.github/workflows/ci-unix.yml`).
- **CLI:** **`psign-tool portable ...`** (runner in `crates/psign-digest-cli`) — `pe-digest`, `verify-pe` (digest-only PKCS#7 consistency), **`trust-verify-pe`** / **`trust-verify-cab`** / **`trust-verify-catalog`** / **`trust-verify-detached`** (explicit-anchor trust + picky chain), **`sign-pe`** (portable PE Authenticode CMS + `WIN_CERTIFICATE` embed with local RSA/SHA-2 keys), **`sign-cab`** (unsigned single-volume CAB reserve-header + tail PKCS#7 signing), **`sign-msi`** (MSI/MSP `DigitalSignature` stream signing), **`sign-catalog`** (portable generic CTL/catalog authoring + CMS signing), **`timestamp-pe-rfc3161`** (attach RFC3161 `timeStampToken` / granted `TimeStampResp` to PE `SignedData`), `pe-has-page-hashes`, `pe-page-hash-info`, `verify-pe-page-hashes`, `pe-authenticode-ranges` (Authenticode digest file segments), `verify-cab`, `verify-msi`, `verify-esd`, `verify-msix`, `verify-catalog`, `verify-script`, `cab-digest`, **`extract-cab-pkcs7`**, **`cab-signer-rs256-prehash`**, **`extract-msi-pkcs7`**, **`msi-signer-rs256-prehash`**, **`catalog-signer-rs256-prehash`**, **`inspect-pe-spc-indirect`**, **`extract-pe-pkcs7`**, **`list-pe-pkcs7`**, **`pe-signer-rs256-prehash`** (KV **`RS256`** CMS prehash; **`--signer-index`** for multi-**`SignerInfo`** **`SignedData`**), **`pkcs7-signer-rs256-prehash`**, **`append-pe-pkcs7`** (low-level append helper). Runs on Linux/macOS; does **`not`** call `WinVerifyTrust`.
- **Trust library:** **`psign-authenticode-trust`** — see **[authenticode-trust-stack.md](authenticode-trust-stack.md)** and **[authroot-linux-verify.md](authroot-linux-verify.md)**.
- Remaining Linux work: optional **revocation**, **PinRules**, and full CryptoAPI policy parity still need dedicated design; digest CLI extras (JSON output, stdin) remain optional.

### Portable lifecycle contract

Portable mode is staged by lifecycle capability rather than by native `signtool.exe` verb parity:

| Stage | Current portable support | Boundary |
|-------|--------------------------|----------|
| Digest / consistency verification | `verify-*`, `pe-digest`, `cab-digest`, page-hash diagnostics | No `WinVerifyTrust` policy decision unless a later Windows parity check is run |
| Explicit-anchor trust | `trust-verify-*` with `--trusted-ca`, `--anchor-dir`, optional AIA/OCSP/CRL, and fixed `--as-of` dates | No OS root/intermediate stores, enterprise TrustedPublisher, or PinRules |
| Remote hash signing | Artifact Signing `:sign`, Key Vault `keys/sign`, and Authenticode signer prehash helpers | Returns signatures over supplied digests only; no Authenticode embed |
| Local signing | Portable RDP, PE `sign-pe`, unsigned single-volume CAB `sign-cab`, MSI/MSP `sign-msi`, and generic catalog `sign-catalog` with RSA/SHA-2 | Cleartext MSIX Authenticode signing and CAB replacement/multivolume signing remain backlog |
| CMS creation / embedding | PE, CAB, MSI, and catalog `SignedData` creation; remote RSA signature injection helpers; PE `WIN_CERTIFICATE`, CAB reserve-header/tail PKCS#7, MSI `DigitalSignature` stream embedding, and CTL `eContent` authoring | MSIX production embedding remains backlog |
| Timestamping | RFC3161 request/response construction, POST, inspection helpers, and PE `timestamp-pe-rfc3161` token embedding | Non-PE timestamp embedding and full `SignerTimeStampEx3` policy parity remain backlog |
| Mutation / removal | None for Authenticode subjects | Requires format-specific embedders before safe remove/update support |
| Catalog workflows | Generic catalog `sign-catalog`, CMS/catalog consistency checks, and explicit `verify-catalog-member --catalog file.cat subject` for MakeCat-style or psign-authored catalogs | No OS catalog database search, driver package policy, INF metadata, or MakeCat byte-for-byte output |

Top-level **`--mode portable`** should only route native-looking verbs when the requested stage is supported. Otherwise it should fail explicitly and point to the closest **`psign-tool portable`** helper.

## Phase 2 — PKCS#7 / CMS utilities without WinTrust

- **Verify-only** paths that parse **Embedded PKCS#7**, **SPC_PE_IMAGE_DATA**, **indirect data**, and **RFC3161** timestamps can live behind **`ring`** / **`cms`** / **`x509-parser`** (already partially aligned via `cms` / `authenticode` crates).
- **Signing** on Linux without a hardware CSP or Windows SIP remains **non-parity** unless integrating **OpenSSL** / **Azure Key Vault** / **pkcs11** — document as **optional backends**, not drop-in `signtool.exe` replacement.

### Stretch: Linux-friendly replacements for AzureSignTool / Artifact Signing

Order-of-effort sketch (each step needs tests + fixtures):

1. **Portable CMS producer** — Finish **`SignedData` / `SignerInfo`** assembly for **PE** (`SpcIndirectData` + **`WIN_CERTIFICATE`** embed) using existing **`pe_digest`** / helpers in [`pkcs7.rs`](../crates/psign-sip-digest/src/pkcs7.rs). **`encode_pkcs7_content_info_signed_data_der`** already wraps an existing **`SignedData`** as PKCS#7 **`ContentInfo`** DER (fixture round-trip tests). **`pe_embed`** **`wrap`**/**append** PKCS#7 rows and recomputes **`CheckSum`** (**`pe_compute_image_checksum`**); remaining work is **full CMS signer encode** and **unsigned→signed** parity.
2. **Remote signing adapters on Unix** — Small **`reqwest`** clients mirroring **`azure_kv_sign.rs`** (KV `keys/sign`) and **`artifact_signing_rest.rs`** (codesigning `:sign` LRO) behind Cargo features, emitting **raw signature bytes** for step (1).
3. **Additional embedders** — CAB replacement/multivolume cases and MSIX ZIP manipulation (hardest: **`AppxSipCreateIndirectData`**-equivalent APPX blob + publisher binding rules).
4. **RFC3161 request/sign** — PE token embedding exists through **`timestamp-pe-rfc3161`**; remaining work is TSA policy parity, automatic sign-time request/POST integration, and CAB/MSI/MSIX timestamp mutation.

Until Phase 2 completes, **verify-first Linux CI** remains the supported story; **production signing** stays on **`psign-tool`** (or native **`signtool.exe`**).

## Phase 3 — Container formats that are OS-agnostic

Already aligned in Rust for **cleartext** subjects:

- **MSIX / APPX / bundles** (ZIP layout) — `sip_rust::msix_digest` (encrypted **Eappx** stays out of scope without Windows crypto). **`psign-tool portable verify-msix`** exercises the same portable ZIP/hash path on Linux; **manifest publisher vs PKCS#7 signer** enforcement remains **`AppxSip`** / **`SignerSignEx*`** on Windows.
- **VSIX / NuGet packages** — these are portable package-signing formats, not Windows SIP formats. **`psign-opc-sign`** starts the dedicated OPC/NuGet layer with signature marker inspection and unsigned NuGet package digests (`psign-tool portable nupkg-signature-info`, `nupkg-digest`, `vsix-signature-info`). Full VSIX XMLDSig and `dotnet nuget sign`-compatible CMS author-signature creation remain separate milestones from Authenticode SIP parity.
- **MSI** OLE tree — `sip_rust::msi_digest`.
- **ESD / WIM** prefix hash — `sip_rust::esd_digest`.
- **PE / CAB / catalog** digests — pure byte/layout algorithms; **deployment policy** still differs without WinTrust.

## Environment variables — portable CLI vs Windows binary

| Surface | `PSIGN_*` / related | Notes |
|---------|---------------------------|--------|
| **`psign-tool portable`** (Linux/macOS) | None required | Subcommands take **paths on the argv** only (`verify-pe`, **`trust-verify-pe`** + **`--anchor-dir` / `--authroot-cab`**, `verify-msix`, …). |
| **`psign-tool --mode portable`** (non-Windows) | **`PSIGN_TOOL_MODE=portable`** optional | Uses portable Rust paths where implemented; Win32-only commands fail explicitly. |
| **`psign-tool --mode windows`** (Windows) | **`PSIGN_TOOL_MODE=windows`**, **`PSIGN_RUST_SIP`**, **`SIGNTOOL_PAGE_HASHES`** (via **`--no-page-hashes`**) | Win32 backend, post-sign Rust SIP digest gates, and **`SignerSignEx3`** page-hash hint — see [`psign-cli-matrix.json`](psign-cli-matrix.json), [`rust-sip-architecture.md`](rust-sip-architecture.md). |
| **Parity scripts / CI** | **`SIGNTOOL_EXE`**, **`PSIGN_TEST_PFX`**, **`PSIGN_MSIX_*`**, … | Full matrix and semantics in [`ci-parity.md`](ci-parity.md). |

## Explicit non-goals (unless upstream specs + test vectors appear)

- **VBA / `mso.dll`** SIP.
- **Encrypted MSIX** (`.eappx`, `.emsix`, encrypted bundles).
- **ExtensionsSip** third-party DLL chains.
- Standalone **P7X/PKCX** container signing outside extracted AppX/MSIX package signatures.
- **ClickOnce / VSTO** XML manifest signing.
- **Full** `signtool.exe` argv parity on Linux without a Windows ABI shim.
- **NuGet / VSIX** package signing remains package-native OPC/CMS/XMLDSig work in `psign-opc-sign`, not Authenticode SIP parity.

## Summary

Short term: **Unix CI for fmt + lockfile** + document this split. Medium term: **extract digest library + Linux `cargo test`** for parity-heavy code. Long term: optional **verify-focused** CLI on Linux (done) plus explicitly-scoped portable signing helpers for PE, CAB, and MSI; broad native-shaped **`sign`** and provider-dependent SIPs remain Windows-first until each portable path has dedicated fixtures and policy coverage.
