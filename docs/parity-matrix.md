# Parity Matrix

Product-oriented **tool comparison** (native SignTool vs Azure vs **`psign-tool`** / **`psign-tool portable`**): [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md).

`Status` values:
- `done`: implemented in Rust and parity-tested.
- `partial`: implemented with limitations or delegated path.
- `todo`: not implemented.

## 10 Gap Tracker

| Gap ID | Gap | Status | Evidence |
|---|---|---|---|
| 1 | Verify policy selection (`/pa`, default, `/pg`) | done | `VerifyPolicy` in `src/cli.rs`; default maps to driver policy (`DRIVER_ACTION_VERIFY`) unless `/pa` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) or `/pg` with GUID; see `policy_action` in `src/win/verify.rs`. |
| 2 | Verify output shape parity | done | Native-style table/summary rendering backed by extracted provider-chain details in `src/win/verify_format.rs`. |
| 3 | Verify exit-code parity | done | Error path now preserves failure semantics and returns non-zero via process result. |
| 4 | Detached/catalog verification path | done | Detached PKCS#7 includes crypto integrity + chain-policy trust checks in `src/win/verify_detached.rs`; catalog uses Rust WinTrust catalog path in `src/win/verify_catalog.rs`. |
| 5 | Sign option coverage | done | Added mapping for `/a`, `/n`, `/sha1`, `/csp`, `/kc`, `/sm`, `/as`, `/ph`, `/fd`; system-store selection path added in `src/win/sign_core.rs`. |
| 6 | Sign Rust/Win32 core behavior | done | Rust core signing now calls `SignerSignEx3` directly in `src/win/sign_core.rs` (no native passthrough). |
| 7 | Timestamp mode parity (`/tr`+`/td`, `/t`) | done | Rust core timestamp uses `SignerTimeStampEx3` (RFC3161) and `SignerTimeStampEx2` (legacy) in `src/win/timestamp_core.rs`. |
| 8 | Timestamp AppX/sealing restrictions | done | Centralized sealing/AppX restrictions in `src/win/sealing.rs`, enforced by sign/timestamp entry points. |
| 9 | Differential fixture corpus coverage | done | Added corpus manifest at `tests/fixtures/corpus.json` and expanded semantic integration tests in `tests/parity_signtool.rs`. |
| 10 | Automated diff triage + CI regression gate | done | `scripts/run-parity-diff.ps1` now enforces required semantic fixtures when gated and CI injects fixture env vars in `.github/workflows/windows.yml`. |

## MSIX Signing Gaps Closure

| MSIX Gap | Status | Evidence |
|---|---|---|
| Native-like sign/timestamp constraints for AppX/MSIX | done | Constraint normalization in `src/win/sealing.rs` with explicit sign-time/timestamp validations and error paths. |
| Decoupled digest (`/dlib` + `/dmdf`) execution path | done | Decoupled signing via `SignerSignEx3` + `SIGNER_DIGEST_SIGN_INFO` in `src/win/sign_core.rs` (`mode=decoupled-rust-core`). |
| Sign digest parity (`/fd`) vs RFC3161 timestamp digest parity (`/td`) | done | `--timestamp-digest` added in `src/cli.rs`; OID wiring updated in `src/win/sign_core.rs`. |
| MSIX semantic fixture matrix | done | Added MSIX scenarios in `tests/fixtures/corpus.json` and ignored parity tests in `tests/parity_signtool.rs`. |
| MSIX CI semantic gate coverage | done | `scripts/run-parity-diff.ps1` includes MSIX semantic scenarios and required fixture env checks; workflow secrets injected in `.github/workflows/windows.yml`. |

## Core verbs

| Verb | Scope | Status | Notes |
|---|---|---|---|
| `verify` | Authenticode verification for signed PE files | done | WinTrust-backed with policy modes, detached PKCS#7 Rust path, catalog resolution (`--catalog-search`), optional warning exit `2` (`--warn-if-not-timestamped`). |
| `sign` | PFX-based file signing | done | Rust core uses mssign32 APIs (`SignerSignEx3`) with certificate filters, `/ac`, Authenticode description attrs, RFC3161 + legacy sign-time timestamps. |
| `timestamp` | RFC3161 and legacy timestamping | done | Rust core uses mssign32 APIs (`SignerTimeStampEx3`/`SignerTimeStampEx2`) with sealing constraints and `/tp` index for RFC3161. |
| `catdb` | Catalog database maintenance | partial | `CryptCATAdminAddCatalog` / `CryptCATAdminRemoveCatalog` in `src/win/catdb.rs`; subsystem GUIDs are best-effort vs SDK. |
| `remove` | Strip PE signatures | partial | `/s` via `ImageEnumerateCertificates` (`CERT_SECTION_TYPE_ANY`) + `ImageRemoveCertificate` loop in `src/win/remove_signature.rs`; `/u` and `/c` via PKCS#7 manipulation in `src/win/remove_unauth.rs` (`CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR`, `CMSG_CTRL_DEL_CERT`) with parity scenarios `remove_u_sha256_match_native`, `remove_c_sha256_match_native`, `remove_cu_sha256_match_native`. |

## Experimental Rust SIP (PE digest parity)

| Area | Status | Evidence |
|------|--------|----------|
| PE Authenticode image digest (SHA-256 golden vectors) | done | Upstream `tiny32.signed.efi` / `tiny64.signed.efi` in `tests/fixtures/pe-authenticode-upstream/`; unit tests in `crates/psign-sip-digest/src/pe_digest.rs`; integration in `tests/sip_rust_pe.rs`; matches **`imagehlp.dll`** **`ImageGetDigestStream`** layout via **`authenticode-rs`** — PKCS#7 side wired via **`WINTRUST`** (**`WVTAsn1SpcPeImageData*`** in **`WINTRUST.dll`**) |
| Post-sign digest gate (`--rust-sip pe`, `PSIGN_RUST_SIP=pe`) | partial | Runs after `SignerSignEx3` in `src/win/sign.rs`; PKCS#7 encode/embed still OS SIP |
| Verify add-on (`--rust-sip-pe-digest-check`) | partial | After embedded WinTrust success in `src/win/verify.rs` |
| PKCS#7 builder / WIN_CERTIFICATE embed in Rust | partial | `pkcs7.rs`: **`parse_pkcs7_signed_data_der`**, **`cms_digest_encapsulated_econtent_bytes`** / **`signer_info_pkcs9_message_digest_octets`** / **`signer_info_signed_attributes_sequence_der`** / **`signed_attributes_replace_pkcs9_message_digest`** / **`signer_info_sha256_digest_over_signed_attrs`** / **`signer_info_clone_with_signed_attrs`** / **`signer_info_clone_with_signature_octets`** (RFC 5652 §5.4 inputs + PKCS#9 refresh + **SHA-256** staging digest + **`SignerInfo`** mutation; fixture parity + **RSA** PKCS#1 v1.5 **RS256** prehash vs **`SignerInfo.signature`** — **`rsa_pkcs1v15_signed_attrs_verify`**), **`signed_data_replace_encapsulated_spc_indirect`**, **`signed_data_replace_signer_info_at`** / **`signed_data_replace_first_signer_info`**, parse/replace **`SpcIndirectDataContent`**, **`encode_pkcs7_content_info_signed_data_der`** (re-encode **`SignedData`**; encap swap + append + **`verify-pe`** mismatch regression tested) + SIP digest checks; **`pe_embed.rs`**: **`wrap_*`**, **`pe_append_*`**, **`pe_compute_image_checksum`** / **`pe_write_image_checksum`** (ImageHlp-style; **`tiny32`**/**`tiny64`** header parity tests); **`pkcs7_wire`**: **`pkcs7_outer_sequence_prefix`**; **`psign-tool portable`** extract/list/inspect/**`pe-signer-rs256-prehash`**/**`append-pe-pkcs7`**; **new** **`SignerInfo`** / digest-binding CMS production + full sign pipeline still todo; architecture in `docs/rust-sip-architecture.md` |
| Tier 1b RFC3161 countersignature construction | todo | Stub `crates/psign-sip-digest/src/timestamp.rs`; timestamp **verification** uses Win32 paths in `psign` |
| Tier 1c PE page hashes (`/ph`) | partial | Portable **CMS + table parse + experimental contiguous verify**: `page_hashes.rs`, `psign-tool portable verify-pe-page-hashes` (differs from WinTrust exclusions); strict `/ph` still `verify --verify-page-hashes` + `WinVerifyTrust` |
| Rust SIP script digest (PowerShell + WSH) | partial | `ps_script.rs`, `wsh_script.rs`, `--rust-sip script`; COM `ConvertTextToUnicode` vs UTF-8/BOM heuristic may diverge on some files |
| Rust SIP MSI digest (OLE compound) | partial | `msi_digest.rs`, `--rust-sip msi`, `verify --rust-sip-msi-digest-check`; matches Signify `SignedMsiFile` traversal over `cfb`; PKCS#7 production/embed remains OS SIP |
| Rust SIP WIM/ESD digest | partial | `esd_digest.rs`, `--rust-sip esd`, `verify --rust-sip-esd-digest-check`; prefix hash per `EsdSip.dll` (`GetHashDataOffset`, PKCS#7 tail at header **0xBC**); PKCS#7 production/embed remains OS SIP |
| Rust SIP cleartext MSIX / APPX / bundles | partial | `msix_digest.rs`, `--rust-sip msix`, `verify --rust-sip-msix-digest-check`; ZIP hash pipeline aligned with osslsigncode `appx.c` / cleartext **`AppxSip*`** (**`VerifyIndirectData`**); **`CreateIndirectData`** / PKCS#7 APPX blob emission remains **`AppxSip.dll`** / **`SignerSignEx*`**; **encrypted** `.eappx`/`.emsix` rejected explicitly |
| Rust SIP CAB | partial | `cab_digest.rs`, `--rust-sip cab`, `verify --rust-sip-cab-digest-check`; OSS CAB SIP is **`WINTRUST.dll`** dispatch (no separate **`CabSip.dll`**); digest matches osslsigncode `cab.c` |
| Rust SIP `.cat` | partial | `catalog_digest.rs`, `--rust-sip catalog`, `verify --rust-sip-catalog-digest-check`; PKCS#9 **`messageDigest`** vs **`eContent`** only (**WINTRUST** **CryptCAT**/CTL member semantics separate) |
| Verify shorthand — all Rust digest add-ons | partial | `verify --rust-sip-all-digest-checks` enables every `--rust-sip-*-digest-check` for embedded targets |

**Warning:** Rust SIP paths are for engineering parity and diagnostics — not a serviced substitute for OS SIP registration until explicitly promoted.

Remaining SIP-shaped gaps (VBA, Eappx, extension SIPs, Rust PKCS#7 encode, `/ph`) are summarized in [`rust-sip-gaps.md`](rust-sip-gaps.md).

## CLI parity inventory

Machine-checked mapping of native switches to Rust flags lives in [`psign-cli-matrix.json`](psign-cli-matrix.json) and [`psign-cli-matrix.md`](psign-cli-matrix.md).

## Differential scenarios

| Scenario | Native command | Expected result | Status |
|---|---|---|---|
| Valid signed PE verifies (`/pa`) | `signtool verify /pa <file>` | Success exit code + trust success | done |
| Verify with `/o <ver>` under `/pa` (embedded) | `signtool verify /pa /o … <file>` | Same exit code as rust `--os-version-check` without `--catalog`/`--catalog-search` (recent kits reject `/o` unless `/a`/`/c`/…) | done (`verify_pa_os_version_check_exit_match`) |
| Verify `@rsp` UTF-16 LE + BOM | `signtool @rsp` vs `psign @rsp` | Rust decodes UTF-16 in `response_argv.rs`; native often misparses lines → `documented_native_utf16_rsp_gap` when native exits 1 and rust 0 | partial (intentional; native limitation) |
| Catalog verify + `--os-version-check` | `psign-tool verify <target> --catalog <cat> --os-version-check …` | Optional when `PSIGN_CATALOG_*` set; `artifact_catalog_os_version_semantic` in `run-parity-diff.ps1` | done (optional fixture) |
| Default policy verify failure | `signtool verify <file>` | Verification error | done |
| Sign with PFX + SHA256 | `signtool sign /f <pfx> /fd SHA256 <file>` | Signature embedded | done |
| Timestamp existing signature | `signtool timestamp /tr <url> /td SHA256 <file>` | Timestamp countersignature | done |
| PowerShell `.ps1` / `.psm1` / `.psd1` description (`/d` `/du`) | Sign then `verify /pa /v /d` | Same Description / Description URL lines as `--print-description` | done (`artifact_verify_ps1_*`, `artifact_verify_psm1_*`, `artifact_verify_psd1_*` in `run-parity-diff.ps1` when PFX + fixtures) |
| WSH `.js` / `.vbs` / `.wsf` description (`/d` `/du`) | Same | Same | done (`artifact_verify_js_*`, `artifact_verify_vbs_*`, `artifact_verify_wsf_*`) |
| MSIX `.msix` (etc.) description + RFC3161 sign | Sign `/d` `/du` `/tr` … then `verify /v /d` | Rust `--description` / `--description-url` matches native lines | done (`artifact_verify_msix_print_description_match` when `PSIGN_MSIX_*` secrets set) |
| MSI `.msi` sign + `/pa` verify + description | Same as PE/ps1 pattern on user-supplied unsigned MSI | Optional env `PSIGN_MSI_UNSIGNED_FIXTURE` + PFX; scenarios `sign_msi_*`, `verify_msi_*`, `artifact_verify_msi_print_description_match` | done (optional fixture) |
| WinMD `.winmd` sign + `/pa` verify + description | Native `signtool sign /fd SHA256 /f …` vs rust | CI: `pack-minimal-winmd.ps1` copies the unsigned PE as `.winmd`; optional local `PSIGN_WINMD_UNSIGNED_FIXTURE` + PFX; `sign_winmd_*`, `artifact_verify_winmd_print_description_match`; smoke `scripts/sip-format-smoke.ps1` | done |
| Rust SIP PE digest gate | `psign sign … --rust-sip pe` vs native sign exit code | Optional fixtures + `scripts/rust-sip-parity-pe.ps1`; corpus `rust_sip_pe_sign_digest_gate_optional` | partial (experimental) |
| Rust SIP verify digest add-on | `psign-tool verify /pa --rust-sip-pe-digest-check` | Ignored test `tests/sip_rust_pe.rs` with `PSIGN_SIGNED_FIXTURE` | partial (experimental) |
| Rust SIP script digest gate | `psign sign … --rust-sip script` on `.ps1`/`.js`/… | Optional ignored parity tests in `tests/parity_signtool.rs` when PFX + fixtures | partial (experimental) |
| Rust SIP script verify add-on | `psign-tool verify /pa --rust-sip-script-digest-check` | Same fixtures as above | partial (experimental) |
| Rust SIP MSI digest gate | `psign sign … --rust-sip msi` on `.msi` | Post-sign `sip_rust::msi_digest` vs PKCS#7 after `SignerSignEx3`; optional `PSIGN_MSI_UNSIGNED_FIXTURE` parity | partial (experimental) |
| Rust SIP MSI verify add-on | `psign-tool verify /pa --rust-sip-msi-digest-check` on `.msi` | After WinTrust success, compares Rust MSI fingerprint vs indirect digest + `MsiDigitalSignatureEx` when present | partial (experimental) |
| Rust SIP WIM/ESD digest gate | `psign sign … --rust-sip esd` on `.wim`/`.esd` | Post-sign `sip_rust::esd_digest` vs PKCS#7 after `SignerSignEx3` | partial (experimental) |
| Rust SIP WIM/ESD verify add-on | `psign-tool verify /pa --rust-sip-esd-digest-check` | After WinTrust success on WIM/ESD, compares Rust prefix digest vs PKCS#7 indirect digest | partial (experimental) |

## Artifact status

The **`parity-output/`** directory is gitignored (same as CI parity JSON); paths below are local outputs or downloaded workflow artifacts, not files tracked in this repository.

- `parity-output/binary-manifest.json`: `cargo run -p psign --bin psign-depgraph -- --signtool …` (SDK `signtool.exe` plus static dependency walk).
- `parity-output/dependency-graph.json`: written alongside the manifest by `psign-depgraph`.
- `parity-output/runtime-modules.json`: `scripts/runtime-module-trace.ps1` sample capture.
- `parity-output/parity-report.json`: `scripts/run-parity-diff.ps1` (and `msix-parity-sign-report.json` from `scripts/msix-parity-sign.ps1`).
