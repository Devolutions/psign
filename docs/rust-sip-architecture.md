# Rust SIP architecture

## Goals

- Optional **Rust-backed PE Authenticode digest** and **embedded PKCS#7 parse/compare** for parity with OS signing (`SignerSignEx3`).
- Tier 1a progress: **`WIN_CERTIFICATE`** PKCS#7 wrap + append + PE **`CheckSum`** without **`SignerSignEx3`** (**`pe_embed`**). **`pkcs7::encode_pkcs7_content_info_signed_data_der`** re-encodes an existing **`SignedData`** as PKCS#7 **`ContentInfo`** (decode → encode round-trip tested); assembling a **new** **`SignedData`** / **`SignerInfo`** for remote signing remains future work.

## PE parsing strategy

Hand-rolled COFF/optional-header traversal was deferred: **`object`** + the **`authenticode`** crate’s `PeTrait` impl match upstream digest semantics and avoid maintaining parallel PE layouts (alternative crates such as `pelite` or using only `goblin` would duplicate `authenticode-rs` assumptions).

## Dependencies (`psign-sip-digest`)

| Crate | Role |
|-------|------|
| [`authenticode`](https://crates.io/crates/authenticode) | PE image digest (`authenticode_digest`), WIN_CERTIFICATE iteration, `AuthenticodeSignature` CMS parse |
| [`object`](https://crates.io/crates/object) | `PeFile32` / `PeFile64` implementing `PeTrait` |
| [`sha2`](https://crates.io/crates/sha2) | SHA-256 hasher passed into `authenticode_digest` |
| [`cms`](https://crates.io/crates/cms) / [`der`](https://crates.io/crates/der) | PKCS#7 **`SignedData`** decode + **`ContentInfo`** re-encode (`encode_pkcs7_content_info_signed_data_der`); **new** **`SignerInfo`** / countersignature production still TODO |
| **`pe_embed`** (in-tree) | **`WIN_CERTIFICATE`** PKCS#7 wrap + attribute-cert append + **`CheckSum`** refresh; exercised from **`psign-tool portable`** (**`append-pe-pkcs7`**, **`pe-checksum`**) |

**Why not hand-roll PE parsing?** The main `psign` binary still uses **`goblin`** in `psign-depgraph`; digest code standardizes on **`object`** to match `authenticode-rs` and avoid duplicate COFF logic.

## Portable crate (`crates/psign-sip-digest/src/`)

| File | Responsibility |
|------|----------------|
| `lib.rs` | Crate root; `verify_script_digest_consistency` router |
| `pe_digest.rs` | PE / WinMD Authenticode image digest + ordered **`pe_authenticode_digest_file_ranges`** (matches `authenticode-rs` segment layout) |
| `verify_pe.rs` | Compare recomputed digest vs PKCS#7 indirect data for each embedded Authenticode cert |
| `cab_digest.rs`, `catalog_digest.rs`, `msi_digest.rs`, `esd_digest.rs`, `msix_digest.rs` | Format-specific SIP digest recomputation |
| `ps_script.rs`, `wsh_script.rs` | Script strip/hash heuristics vs PKCS#7 |
| `pkcs7.rs` | **`SignedData`** decode (**`parse_pkcs7_signed_data_der`**), **`ContentInfo`** DER encode (**`encode_pkcs7_content_info_signed_data_der`**), **`cms_digest_encapsulated_econtent_bytes`** / **`signer_info_pkcs9_message_digest_octets`** / **`signer_info_signed_attributes_sequence_der`** / **`signed_attributes_replace_pkcs9_message_digest`** / **`signer_info_sha256_digest_over_signed_attrs`** / **`signer_info_clone_with_signed_attrs`** / **`signer_info_clone_with_signature_octets`** (RFC 5652 **`eContent`** + authenticated attrs + **SHA-256** staging digest + **`SignerInfo`** patches — parity-tested on fixtures), **`SpcIndirectDataContent`** parse/replace + DER encode, **`signed_data_replace_encapsulated_spc_indirect`**, **`signed_data_replace_signer_info_at`** / **`signed_data_replace_first_signer_info`**; **`encryptedDigest`** / full **`SignerInfo`** re-sign still TODO |
| `pe_embed.rs` | **`WIN_CERTIFICATE`** PKCS#7 wrap, attribute-cert **append**, optional-header **`CheckSum`** recompute (**`pe_compute_image_checksum`**) |
| `timestamp.rs` | RFC3161 embed notes — **stub** (Tier 1b) |
| `page_hashes.rs` | PE page-hash CMS extract + Authenticode payload peel / flat table parse (Tier 1c); segment verify still Win32 |

## Linux / macOS CLI (`crates/psign-digest-cli`)

The **`psign-tool portable`** binary wraps **`psign-sip-digest`** for scripting and CI (e.g. **`pe-digest`**, **`pe-checksum`**, **`verify-pe`**, **`trust-verify-*`**, **`extract-pe-pkcs7`** / **`list-pe-pkcs7`** / **`append-pe-pkcs7`**, **`inspect-pe-spc-indirect`**, **`verify-msix`**, **`pe-has-page-hashes`**, **`pe-page-hash-info`**, **`verify-pe-page-hashes`**, **`pe-authenticode-ranges`**, …). It performs **digest vs PKCS#7 indirect data** checks, **explicit-anchor trust**, **experimental PE cert-table growth**, **PE image checksum parity**, **PE Authenticode digest segment listing**, and **PE page-hash tooling** (not a full **`WinVerifyTrust`** `/ph` clone).

## Win32 adapter (`src/win/sip_rust/`)

| File | Responsibility |
|------|----------------|
| `mod.rs` | Re-exports `signtool_sip_digest::*` for existing `crate::win::sip_rust::…` call sites |
| `sign_pe.rs`, `sign_script.rs`, `sign_msi.rs`, `sign_esd.rs`, `sign_msix.rs`, `sign_cab.rs`, `sign_catalog.rs` | Post-sign digest gates (`GlobalOpts` / debug logging) |

## Routing

- **Default:** [`sign_core::sign_with_mssign32`](../src/win/sign_core.rs).
- **`--rust-sip pe`:** Still signs with **`SignerSignEx3`** today; after signing, recomputes the PE Authenticode digest in Rust and asserts it matches the PKCS#7 **indirect** digest (experimental parity gate).
- **`--rust-sip script`:** After signing, compares PKCS#7 indirect digest to Rust recomputation: PowerShell-class uses **UTF-16 range removal** (`pwrshsip.dll`); WSH uses **`wshext.dll`** strip + UTF-16 LE payload + **u32** begin-marker offset (see `wsh_script.rs`, [`windows-signing-components.md`](windows-signing-components.md)).

### SIP DLL inventory

Optional local copies of inbox DLLs: [`scripts/copy-windows-signing-binaries.ps1`](../scripts/copy-windows-signing-binaries.ps1). Roles and SIP relationships: [`windows-signing-components.md`](windows-signing-components.md); CryptSIP GUIDs: [`rust-sip-machine-registry.md`](rust-sip-machine-registry.md).

### Verify digest add-ons

After a successful **embedded** `WinVerifyTrust`, optional flags recompute the SIP digest in Rust and compare to PKCS#7 indirect data (PE, scripts, MSI, ESD, cleartext MSIX, CAB, catalog). **`verify --rust-sip-all-digest-checks`** turns on every `--rust-sip-*-digest-check` at once. Encrypted MSIX extensions (`.eappx`, `.emsix`, …) are rejected by the MSIX checker with an explicit message — see [`rust-sip-gaps.md`](rust-sip-gaps.md).

## Security

See [`rust-sip-threat-model.md`](rust-sip-threat-model.md).
