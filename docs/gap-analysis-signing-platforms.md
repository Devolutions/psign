# Feature gap analysis: native signtool, AzureSignTool, Artifact Signing vs psign

This document compares **Windows SDK `signtool.exe`**, **AzureSignTool**, **Azure Artifact Signing (Trusted Signing)**, and this repository’s **`psign-tool`** / **`psign-tool portable`**. It is the product-facing companion to the engineering-focused [`rust-sip-gaps.md`](rust-sip-gaps.md) and [`parity-matrix.md`](parity-matrix.md).

**Writable copies of Kits / System32 binaries (read-only install dirs):** [`writable-signing-binaries.md`](writable-signing-binaries.md).

**Linux hybrid pipelines (REST hash sign, verify-only, what is still Windows-only):** [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

## Format × capability matrix

Legend: **Sign** = produce/embed Authenticode; **WT verify** = `WinVerifyTrust`-style OS verify; **Digest** = recompute SIP indirect data vs PKCS#7; **Trust** = portable CMS + explicit anchors.

| Subject format | Native `signtool` | `psign-tool` | `psign-tool portable` |
|----------------|-------------------|--------------------|---------------------|
| PE / WinMD | Sign, WT verify | Sign, WT verify, optional `--rust-sip pe` | Digest, inspect, trust-verify-pe, sign-pe, timestamp-pe-rfc3161 |
| CAB | Sign, WT verify | Same | verify-cab, trust-verify-cab, cab-digest, sign-cab |
| MSI | Sign, WT verify | Same | verify-msi, sign-msi |
| ESD / WIM | Sign, WT verify | Same | verify-esd |
| MSIX / APPX (cleartext) | Sign, WT verify | Same (+ `--dlib` / `--dmdf`) | verify-msix |
| MSIX encrypted | Sign (OS) | Delegates OS | **Rejected** (explicit error) |
| Catalog `.cat` | Sign, WT verify | WT + Rust assists | sign-catalog, verify-catalog, verify-catalog-member, trust-verify-catalog |
| PS scripts | Sign, WT verify | Same | verify-script |
| WSH `.js`/`.vbs`/`.wsf` | Sign, WT verify | Same | verify-script |
| Detached PKCS#7 | Verify | Verify | trust-verify-detached |
| VBA / `mso.dll` SIP | Sign (OS) | OS | **Not portable** |
| Extension SIP DLLs | Sign (OS) | OS | **Not portable** |

**AzureSignTool** targets the same **embedding path as SignTool** (Windows): typically PE (and same SIP stack as invoked by `SignerSignEx3`). It does **not** define new subject formats—it replaces the CSP with **KV `keys/sign`**.

**Artifact Signing REST** (`:sign` LRO) returns **signature material** for a **hash**; embedding still requires **Windows `SignerSignEx3` + dlib** or **future portable PKCS#7 + embed** (see roadmap).

## Expanded signable-surface audit by mode

This inventory starts from the in-tree supported formats, then expands to inbox Windows SIP providers and adjacent Microsoft code-signing ecosystems. A **Windows-mode gap** is missing or partial behavior in **`psign-tool --mode windows`** compared with native Windows tooling. A **portable-mode gap** is missing behavior in **`psign-tool --mode portable`** / **`psign-tool portable`**, where Win32 SIP, WinTrust, CryptoAPI policy, and `SignerSignEx3` are unavailable by design.

### Inbox Authenticode / SIP subjects

| Surface | Windows mode coverage | Windows-mode gaps | Portable mode coverage | Portable-mode gaps |
|---------|-----------------------|-------------------|------------------------|--------------------|
| **PE / WinMD** (`.exe`, `.dll`, `.sys`, `.ocx`, `.efi`, `.scr`, `.cpl`, `.mui`, `.winmd`, and other PE-by-content subjects) | `sign`, `verify`, `timestamp`, PE `remove`, optional Rust PE digest gate. | Portable-style greenfield CMS is not used; `/ph` page-hash parity and extension corpus coverage need more fixtures. | PE digest, PKCS#7 extraction/inspection, explicit-anchor `trust-verify-pe`, local RSA `sign-pe`, PE RFC3161 token embedding, remote-signature CMS injection helpers, experimental PKCS#7 append helpers. | No top-level native-shaped `--mode portable sign`, WinTrust policy, OS stores, PinRules, or full `/ph` semantics. |
| **CAB** (`.cab`) | Sign/verify through OS SIP. | No first-class CAB remove; parity success fixtures are thinner than PE. | `verify-cab`, `trust-verify-cab`, `cab-digest`, local RSA `sign-cab` for unsigned single-volume CABs, PKCS#7 extraction/prehash. | No CAB signature replacement, multivolume CAB signing, timestamp embed, or WinTrust CAB policy equivalent. |
| **Catalog** (`.cat`) and driver-package catalogs | Catalog verify paths and `catdb`; can Authenticode-sign an existing `.cat`. | No catalog authoring (`MakeCat`/`Inf2Cat`/`New-FileCatalog` equivalent) or full driver-package workflow. | `sign-catalog` for portable generic CTL catalogs, `verify-catalog`, `verify-catalog-member` for explicit file + MakeCat/psign catalog inputs, `trust-verify-catalog`, catalog PKCS#7 consistency, signer prehash. | No `CryptCATAdmin` database search, driver/INF policy, OS catalog stores, catalog-store revocation policy, or MakeCat byte-for-byte output. |
| **MSI family** (`.msi`, `.msp`, `.mst`) | Sign/verify through `MSISIP.DLL`. | Generic SIP remove is not implemented; optional parity corpus depends on external fixtures. | `verify-msi`, local RSA `sign-msi` through the `DigitalSignature` stream, PKCS#7 extraction/prehash. | No timestamp embed, `MsiDigitalSignatureEx` authoring, or installer policy branches such as `DisableSizeVerification` / `DisableLegacyVerification`. |
| **WIM / ESD** (`.wim`, `.esd`) | Sign/verify through `EsdSip.dll`. | Positive parity fixtures are limited; no remove. | `verify-esd`. | No WIM/ESD signing/embed, timestamp embed, or WinTrust policy equivalent. |
| **Cleartext AppX/MSIX** (`.appx`, `.msix`, `.appxbundle`, `.msixbundle`) | Sign/verify with AppX client data and dlib bridge. | Remaining native parity failures can occur around `SignerSignEx3` AppX glue, publisher binding, sealing, and package constraints. | `verify-msix` digest consistency. | No `AppxSipCreateIndirectData` equivalent, package PKCS#7 embed, timestamp/signing, manifest publisher-vs-signer policy, or full package policy. |
| **Encrypted AppX/MSIX** (`.eappx`, `.emsix`, `.eappxbundle`, `.emsixbundle`) | Delegates to OS `EappxSip*` / `EappxBundleSip*`. | No in-tree understanding beyond OS delegation and parity fixtures. | Explicitly rejected. | Encrypted package crypto/header handling is absent; ZIP-only digest logic is insufficient. |
| **AppX extension SIP chain** | Delegates to installed `ExtensionsSip*` providers. | No bundled/provider-specific parity coverage; behavior depends on optional third-party SIP DLLs. | Not implemented. | No extension-provider discovery, DLL contract, or portable provider model. |
| **Standalone P7X / PKCX** (`.p7x`) | OS `P7xSip*` can participate when registered; real package signatures are produced as `AppxSignature.p7x` inside signed AppX/MSIX packages. | Direct standalone `.p7x` signing is rejected by current SignTool; first-class commands for extracting/interpreting PKCX remain absent. | Raw PKCS#7 inspection/trust primitives may apply after extraction. | No dedicated PKCX/P7X container command or portable PKCX header handling. |
| **PowerShell-class scripts** (`.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.psc1`, `.cdxml`, `.mof`) | Sign/verify through `pwrshsip.dll`; parity fixtures cover `.ps1`, `.psm1`, `.psd1`. | Need parity fixtures and format detection for `.ps1xml`, `.psc1`, `.cdxml`, `.mof`. | `verify-script` digest consistency for PowerShell-style markers. | No signing/embed; digest remains heuristic for every malformed block and encoding edge case. |
| **WSH scripts** (`.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`) | Sign/verify through `wshext.dll`; parity fixtures cover `.js`, `.vbs`, `.wsf`. | Need `.jse` and `.vbe` parity coverage. | `verify-script` digest consistency for WSH markers. | No signing/embed; native COM text conversion and unusual encodings may diverge. |
| **Office / VBA macro projects** | Delegates to installed `mso.dll` / `VBE7.DLL` SIP when present. | No direct Office/VBA CLI affordance or parity fixture set; depends on installed Office components. | Not implemented. | No VBA project graph hashing; likely needs VBE7/Office FFI or permanent OS delegation. |

### Adjacent Windows code-signing ecosystems, not normal Authenticode SIP parity

| Surface | Windows mode coverage | Windows-mode gaps | Portable mode coverage | Portable-mode gaps |
|---------|-----------------------|-------------------|------------------------|--------------------|
| **RDP files** (`.rdp`) | Implemented `rdp` path using Windows certificate stores. | Mostly fixture breadth and native `rdpsign.exe` output-shape parity. | Implemented `portable rdp` with local cert/key or external detached PKCS#7. | No Windows store selection or native `rdpsign.exe` integration by design. |
| **App Installer descriptors** (`.appinstaller`) | Direct embedded signing is rejected by current SignTool; descriptor signing can be represented as unsigned XML plus a PKCS#7 companion artifact generated with SignTool `/p7`. | No first-class App Installer command, XML+companion verification UX, or native parity wrapper. | Detached PKCS#7 trust primitives can verify the XML plus companion signature. | No App Installer-specific command or policy checks. |
| **NuGet packages** (`.nupkg`, `.snupkg`) | Not a `signtool`/WinTrust SIP target in this repo. | No `nuget sign`-compatible author/repository signing workflow in Windows mode. | `psign-opc-sign` groundwork: marker inspection and unsigned package digest. | No CMS author/repository signature creation, timestamping, package embed/update, or NuGet policy verification. |
| **VSIX packages** (`.vsix`) | Not a first-class Windows-mode signing surface here. | No VSIX package signing/verification workflow. | Signature marker inspection. | No XMLDSig generation, package relationship updates, timestamping, or trust verification. |
| **ClickOnce / VSTO manifests** (`.manifest`, `.application`, `.vsto`, `.deploy` workflows) | Not implemented. | No `mage.exe`/manifest XMLDSig workflow, dependency hash graph, certificate embedding, or timestamping. | Not implemented. | Same as Windows mode, plus no XMLDSig primitives or ClickOnce/VSTO policy checks. |
| **File catalog authoring** | Can sign/verify an existing `.cat` at the Authenticode layer. | No catalog creation from arbitrary file sets or INF/driver package metadata. | `sign-catalog` authors generic CTL catalogs; catalog PKCS#7 consistency/trust and explicit `verify-catalog-member` cover committed MakeCat-style and psign-authored generic catalogs. | Driver/INF policy, OS catalog database search, and MakeCat byte-for-byte output remain out of scope. |
| **WDAC / CI policy signing** | Detached PKCS#7/catalog primitives only. | No policy-specific signing/validation workflow or deployment policy checks. | Detached PKCS#7/catalog primitives only. | No policy-specific workflow, Code Integrity semantics, or Windows deployment policy checks. |

### Fixture corpus gaps

The committed corpus already includes generated unsigned and signed vectors for PE aliases, WinMD, CAB, catalog, MSI/MSP, WIM/ESD, cleartext MSIX/AppX, PowerShell and WSH scripts, detached PKCS#7, RDP, NuGet, and VSIX. The remaining fixture gaps are:

| Surface | Current fixture state | Missing fixture coverage |
|---------|-----------------------|--------------------------|
| **MST transforms** (`.mst`) | Unsigned generated transform exists; signed native output is retained in skipped corpus rows because `/pa` verification rejects it. | A verifiable signed `.mst` fixture if native Windows Installer policy supports one, or deeper tests around the documented reject. |
| **Encrypted AppX/MSIX** (`.eappx`, `.eappxbundle`, `.emsix`, `.emsixbundle`) | Unsigned/placeholder negative files exist. | Real signed encrypted package fixtures, if the project decides to test OS-only Windows delegation. |
| **WSH component scripts** (`.wsc`) | Unsigned probe files exist and native SignTool rejection is recorded; `.jse` / `.vbe` have signed generated probes. | Signed `.wsc` fixture if a supported provider/tooling path is identified. |
| **Standalone P7X / PKCX** (`.p7x`) | Unsigned direct-signing probe exists and native SignTool rejection is recorded; a real `AppxSignature.p7x` is extracted from a signed MSIX fixture. | First-class PKCX/P7X parsing/verification behavior remains an implementation gap. |
| **App Installer descriptors** (`.appinstaller`) | Unsigned descriptor exists and native direct-signing rejection is recorded; a real SignTool `/p7` companion signature is generated for detached verification coverage. | First-class App Installer XML+signature commands and policy checks remain implementation gaps. |
| **Optional-provider / XML signing surfaces** (`.application`, `.manifest`, `.vsto`, `.deploy`) | Unsigned probe files exist and native SignTool rejection/provider-unavailable outcomes are recorded. | Signed ClickOnce/VSTO-style fixtures and tool-specific signing metadata. |
| **Office macro containers** (`.docm`, `.xlsm`, `.pptm`, `.xlam`) | Unsigned probe files exist. | Signed Office/VBA macro-project fixtures generated with installed Office/VBE SIP, plus verification expectations. |
| **Symbols packages** (`.snupkg`) | Unsigned and signed fixtures now exist under `tests/fixtures/package-signing/`. | No remaining fixture gap; implementation gaps are package-signing feature work, not corpus files. |
| **PowerShell UTF-16BE variants** | Unsigned UTF-16BE fixtures exist for `.ps1`, `.psd1`, `.psm1`, `.ps1xml`, `.psc1`, `.cdxml`, `.mof`; native SignTool rejection is recorded. | Signed UTF-16BE variants only if native tooling behavior changes or an alternate supported signing path is identified. |

## Executive summary

| Goal | Today | Gap |
|------|--------|-----|
| **Drop-in Linux replacement for `signtool.exe` sign/verify** | Not supported | Signing and WinTrust-backed verify require Windows CryptAPI/SIP (`SignerSignEx3`, `WinVerifyTrust`). |
| **Drop-in Linux replacement for AzureSignTool** | Partial | **`azure-key-vault-sign-digest`** on **`psign-tool portable`** (**`--features azure-kv-sign-portable`**) performs the Key Vault **`keys/sign`** step (**digest file → signature**). Use **`pe-digest --encoding raw`** for the **PE image** hash file; use **`pe-signer-rs256-prehash --encoding raw`** (optional **`--signer-index`** for the *N*th **`SignerInfo`** inside the selected PKCS#7 row) when you need the **CMS authenticated-attribute** **SHA-256** prehash (**32** octets) for **`RS256`** on an **existing embedded PKCS#7** (see [`migration-azuresigntool.md`](migration-azuresigntool.md)). **Embedding** Authenticode still requires **`psign-tool`** (`SignerSignEx3`) or a portable **`SignedData`** rebuild. Full **`sign`** with KV callback remains Windows (**`--features azure-kv-sign`**). |
| **Drop-in Linux replacement for Artifact Signing (dlib / REST)** | Partial | **`artifact-signing-submit`** (**`--features artifact-signing-rest`**) runs on **Linux/macOS** via **`psign-tool portable`** or on Windows via **`psign-tool`** — same **`:sign`** LRO (**hash → JSON**). **Embedding** PKCS#7 still requires **`SignerSignEx3`** + dlib or future portable CMS/embed. **`psign-tool portable`** validates **`--dmdf`** JSON without network. |
| **Linux verify + digest parity for many Authenticode formats** | Supported | **`psign-tool portable`** covers PE, CAB, MSI, ESD/WIM, cleartext MSIX, catalog, scripts; **`trust-verify-*`** adds anchor-based CMS trust (see [`authenticode-trust-stack.md`](authenticode-trust-stack.md)). |
| **Maximum Windows-mode Authenticode subject formats** | Windows mode delegates most SIP-registered subjects to OS providers | Remaining gaps are first-class CLI affordances, parity fixtures, generic SIP remove, catalog authoring/member policy, Office/VBA ergonomics, extension SIP coverage, and standalone `.p7x` handling. |
| **Maximum portable-mode Authenticode subject formats** | Portable mode covers digest/trust for PE, CAB, MSI, ESD/WIM, cleartext MSIX, catalogs, scripts, and detached PKCS#7; local signing for PE/CAB/MSI/generic catalogs is explicitly scoped | Portable gaps include MSIX signing/embed, non-PE timestamp mutation, WinTrust/CryptoAPI policy, encrypted MSIX, extension SIPs, Office/VBA, standalone `.p7x`, and package-specific ecosystems. |

**Practical Linux path today:** Use **`psign-tool portable`** for **digest computation**, **local signing** of PE/CAB/MSI/generic catalogs, **Key Vault `keys/sign`** on digest files (**`azure-key-vault-sign-digest`** with **`--features azure-kv-sign-portable`**), **`:sign` REST** (**`artifact-signing-submit`** with **`--features artifact-signing-rest`**), **inspect**, and **verify/trust** across supported formats. Broader native-shaped signing and unsupported SIP embedders still require **`psign-tool`** / **`SignerSignEx3`** (or native **`signtool.exe`**). Cookbook: [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

**Long-term Linux signing** (if required): extend the portable **CMS `SignerInfo` production** (inside **`SignedData`**) + **format-specific embedding** beyond the current PE/CAB/MSI/catalog subset to MSIX `ContentTypes` / manifest glue and other package-native formats, then combine with **remote signing** (KV REST, Artifact Signing `:sign` LRO). [`pkcs7.rs`](crates/psign-sip-digest/src/pkcs7.rs) holds parse/replace helpers, **`signed_data_replace_first_signer_info`**, **`encode_pkcs7_content_info_signed_data_der`**, **RSA PKCS#1 RS256** prehash ↔ **`SignerInfo.signature`** parity tests (`rsa_pkcs1v15_signed_attrs_verify`), and **`signer_info_sha256_digest_over_signed_attrs`** (documented KV **`RS256`** input shape); [`pe_embed.rs`](crates/psign-sip-digest/src/pe_embed.rs) can **wrap PKCS#7**, **append** rows (including after signer splice experiments), and **recompute `CheckSum`**. **`psign-tool portable pe-signer-rs256-prehash`** surfaces the **32-byte** prehash for Linux KV workflows; MSIX signing/embed and non-PE timestamp mutation remain backlog (see [`rust-sip-gaps.md`](rust-sip-gaps.md)).

---

## Native Windows SDK `signtool.exe`

**Strengths:** Full Authenticode lifecycle — **sign**, **verify** (many policies), **timestamp**, **remove**, **catalog** ops, **sealing** / AppX constraints, response files, broad switch surface ([`psign-cli-matrix.json`](psign-cli-matrix.json)).

**This repo (`psign-tool`):**

| Area | Parity |
|------|--------|
| verify (embedded, detached, catalog) | High — WinTrust + Rust paths for detached/catalog |
| sign / timestamp | **`SignerSignEx3`** / **`SignerTimeStampEx3`** Rust core |
| remove | Partial (`/s`, PKCS#7 `/u`/`/c` paths — see parity matrix) |
| catdb | Partial |
| Every obscure `/switch` | See **`cli-parity-backlog.md`** |

**Portable digest-only checks** after native sign: **`verify-pe`**, **`--rust-sip-*`** family on **`psign-tool`**.

---

## AzureSignTool

**Model:** .NET tool — hash file, call **Azure Key Vault `keys/sign`**, integrate with **`SignerSignEx3`** (or equivalent) on Windows for PKCS#7 embedding.

**This repo:**

| AzureSignTool concept | `psign-tool` | `psign-tool portable` |
|-----------------------|-------------------|---------------------|
| KV URL, cert name, auth (MI / SP / token) | Yes (`--features azure-kv-sign`) | **`azure-key-vault-sign-digest`** (`--features azure-kv-sign-portable`) — digest file only |
| Batch / parallelism / exit HRESULTs | Mapped (`--input-file-list`, `--exit-codes azuresigntool`, …) | N/A |
| ECDSA keys | Supported on KV path (alg derived from cert) | Same JWS algs (**ES256**/…) inferred from certificate **`cer`** |

**Gap:** Broad native-shaped signing is still **Windows + SIP** for production compatibility. Portable local-key signing now exists for PE, unsigned single-volume CAB, and MSI/MSP; portable KV signs an **opaque digest blob** — use the correct digest for your pipeline (**image** vs **CMS signer** prehash; **`pe-signer-rs256-prehash`** for the latter on PE). Wiring KV-returned **`encryptedDigest`** into **`SignedData`** is supported by helpers/tests, but end-to-end portable remote signing and MSIX/package-specific embedding remain future work.

Details: [`migration-azuresigntool.md`](migration-azuresigntool.md).

---

## Azure Artifact Signing (Trusted Signing)

**Models:**

1. **Decoupled digest DLL** — `Azure.CodeSigning.Dlib.dll` + **`SignerSignEx3`** + **`--dmdf`** metadata (same family as native SignTool).
2. **REST** — Certificate profile **`:sign`** LRO (`*.codesigning.azure.net`), OAuth scope **`https://codesigning.azure.net/.default`**.

**This repo:**

| Surface | Implementation |
|---------|----------------|
| Decoupled sign (`--dlib`, `--trusted-signing-dlib-root`, `--dmdf`) | **`psign-tool`** only |
| REST hash signing | **`artifact-signing-submit`** (`--features artifact-signing-rest`) on **`psign-tool`** or **`psign-tool portable`** |
| Metadata validation without signing | **`psign-tool portable artifact-signing-metadata-check`** |

**Gap:** REST output is **not** wired into a portable Authenticode embedder; docs state MVP is hash signing / diagnostics. [`migration-artifact-signing.md`](migration-artifact-signing.md).

---

## `psign-tool portable` (Linux/macOS)

**Commands (verify / inspect / digest tools):** See [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) and **`psign-tool portable --help`**.

### Portable lifecycle contract

Portable support is intentionally split by lifecycle stage. This keeps Linux/macOS workflows useful today without implying that portable mode has full Win32 SIP, `WinVerifyTrust`, or `SignerSignEx3` parity.

| Lifecycle stage | `psign-tool --mode portable ...` | `psign-tool portable ...` | Support level |
|-----------------|-----------------------------------|----------------------------|---------------|
| Digest computation | Routed through `verify` only when it can infer a supported subject format | `pe-digest`, `cab-digest`, and format-specific `verify-*` commands | Supported for PE/WinMD, CAB, MSI/MSP, WIM/ESD, cleartext MSIX/AppX, catalogs, and scripts |
| PKCS#7 inspection / extraction | `inspect-signature` routes to `inspect-authenticode` | `inspect-authenticode`, `extract-pe-pkcs7`, `extract-cab-pkcs7`, `extract-msi-pkcs7`, `list-pe-pkcs7` | Supported diagnostics; no trust decision by itself |
| Explicit-anchor trust verification | `verify` routes only when portable trust inputs are present and the inferred format has a trust command | `trust-verify-pe`, `trust-verify-cab`, `trust-verify-msi`, `trust-verify-esd`, `trust-verify-catalog`, `trust-verify-detached` | Supported with explicit anchors and bounded online AIA/OCSP/CRL; not OS store policy |
| Remote hash signing | Not exposed through top-level `sign` | `artifact-signing-submit`, `azure-key-vault-sign-digest`, signer prehash commands | Supported as digest-in/signature-out helpers; no subject embed |
| Local-key signing | Top-level `sign` returns an explicit portable-not-implemented error | `sign-pe`, `sign-cab`, `sign-msi`, `sign-catalog`, `rdp` | Supported for PE, unsigned single-volume CAB, MSI/MSP, generic catalogs, and RDP local RSA signing; other Authenticode SIP subjects remain backlog |
| CMS creation from scratch | Not exposed through the native-shaped verb | PE/CAB/MSI Authenticode CMS creation through `sign-pe`, `sign-cab`, `sign-msi`, generic CTL/catalog CMS creation through `sign-catalog`, and `psign-sip-digest` helpers | Supported for PE, CAB, MSI, and generic catalog RSA/SHA-2; reusable CMS work remains to extend MSIX |
| Format-specific Authenticode embed | Not implemented | `sign-pe` for PE, `sign-cab` for unsigned single-volume CABs, `sign-msi` for MSI/MSP `DigitalSignature` streams, `sign-catalog` for CTL `eContent` authoring; `append-pe-pkcs7` remains lower-level PE append plumbing | PE supported; CAB initial signing supported; MSI stream signing supported; generic catalog authoring supported; MSIX production embedder is backlog |
| Timestamp embedding | Top-level `timestamp` returns an explicit portable-not-implemented error | `timestamp-pe-rfc3161` attaches a granted RFC3161 `timeStampToken` to PE `SignedData`; request/response helpers can prepare or inspect TSA traffic | PE token embedding supported; non-PE timestamp embedding and native-shaped routing remain backlog |
| Signature removal / mutation | Top-level `remove` returns an explicit portable-unsupported error | No remove verb | Backlog only after production embedders exist |
| Catalog database operations | Top-level `catdb` returns an explicit portable-unsupported error | `sign-catalog` authors explicit generic catalogs; `verify-catalog-member` verifies explicit file + catalog membership without a database | OS catalog database search, driver/INF policy, and catalog store mutation remain out of scope |

The compatibility rule is: **portable mode may prove digest/CMS consistency and explicit-anchor trust, but it must not silently emulate Windows policy.** When a user asks for a Windows-only lifecycle stage, the CLI should fail with an explicit unsupported/not-implemented message and point to the closest portable helper.

**Remote signing steps:** With **`--features azure-kv-sign-portable`**, **`azure-key-vault-sign-digest`** performs Azure Key Vault **`keys/sign`** on a **raw digest file** (same REST shape as AzureSignTool’s remote step). **`pe-signer-rs256-prehash`**, **`cab-signer-rs256-prehash`**, **`msi-signer-rs256-prehash`**, and **`catalog-signer-rs256-prehash`** (**`--encoding raw`**) emit the **32-byte** **`RS256`** input over **`SignerInfo.signedAttrs`** (distinct from subject-layout digests and from **`verify-catalog`**’s CTL **`eContent`** / PKCS#9 checks). With **`--features artifact-signing-rest`**, **`artifact-signing-submit`** calls Trusted Signing **`:sign`**. The PE/CAB/MSI CMS core can now inject externally produced RSA/SHA-2 signature bytes, but the packaged CLI still exposes remote signing as digest/signature helpers; MSIX embedding and broad native-shaped remote-sign routing remain future portable embedder work.

**RFC 3161 TSA helpers:** **`rfc3161-timestamp-req`** builds **`TimeStampReq`** DER from **`--digest-hex`** / **`--digest-file`** (message-imprint preimage; optional **`--nonce`**, **`--cert-req`**) for **`curl`** / OpenSSL **`ts`** against a timestamp URL. **`rfc3161-timestamp-resp-inspect`** prints **`pki_status`** / **`pki_status_int`** (raw status INTEGER) / **`granted`** / token length, **`time_stamp_token_prefix_hex`** (first **16** octets of the raw **`timeStampToken`** TLV, or **`-`** when absent — handy for **`ContentInfo`** / CMS shape checks), **`status_strings_json`** (**`PKIFreeText`**), **`fail_info_tlv_hex`**, and **`fail_info_flags_json`** (RFC 2510 Appendix A **`PKIFailureInfo`** bit names through **`badPOP`**, then **`bit_N`**; **`null`** when the **`BIT STRING`** body is not decodable). Parseable CMS **`id-ct-TSTInfo`** tokens also surface structural **`tst_info_*`** diagnostics: policy OID, message-imprint digest OID/hash, serial, **`genTime`**, and nonce. Optional **`rfc3161-timestamp-http-post`** (**`--features timestamp-http`**) performs the HTTPS POST without **`curl`**. **`timestamp-pe-rfc3161`** can then attach a raw **`timeStampToken`** or granted **`TimeStampResp`** token to an existing PE Authenticode `SignerInfo` as the Microsoft RFC3161 unsigned attribute. This still does not clone every **`SignerTimeStampEx3`** policy branch or timestamp non-PE subjects.

**Formats with portable digest + PKCS#7 consistency (and optional trust):**

- PE / WinMD-style CLI metadata (multi-signed PEs: **`list-pe-pkcs7`**, **`extract-pe-pkcs7 --index`**, **`inspect-pe-spc-indirect --index`** share the same certificate-table PKCS#7 row order)
- CAB
- MSI (OLE Signify layout)
- ESD / WIM prefix
- Cleartext MSIX / APPX / bundles (encrypted variants rejected)
- Catalog `.cat` (CMS digest consistency, explicit MakeCat-style/psign-authored file membership, and generic `sign-catalog`; not `CryptCATAdmin` database policy)
- PowerShell-class scripts, WSH `.js`/`.vbs`/`.wsf` (heuristic strip/hash — may diverge from COM Unicode conversion edge cases)

**Not full Authenticode lifecycle:** Portable **PE local signing** is available through **`sign-pe`**, unsigned single-volume **CAB local signing** through **`sign-cab`**, MSI/MSP local signing through **`sign-msi`**, and generic catalog signing through **`sign-catalog`**, but there is still no broad native-compatible **`sign`** / **`timestamp`** / **`remove`** verb, no **`--dlib`** decoupled DLL path, and no turnkey MSIX embed. **`psign-sip-digest`** supports parse/replace indirect data, PKCS#9 **`messageDigest`** refresh, **`SignerInfo`** splice + signature octets, **`ContentInfo`** re-encode, **`WIN_CERTIFICATE`** append/wrap, portable **PE/CAB/MSI/catalog CMS creation** for RSA/SHA-2, and portable **`pe-` / `cab-` / `msi-` / `catalog-signer-rs256-prehash`** for KV **`RS256`** digest extraction from embedded PKCS#7 (PE cert table, CAB tail, MSI **`DigitalSignature`** stream, catalog PKCS#7).

---

## Studying native vs managed surfaces (no vendor tooling in-repo)

Use **public documentation**, **this repo’s parity tests**, and **writable copies** of binaries (see [`writable-signing-binaries.md`](writable-signing-binaries.md) and **`scripts/prepare-writable-signing-binaries.ps1`**) when you need to inspect behavior next to a PE outside protected install paths.

| Original / surface | Mechanism | Typical study angle |
|--------------------|-----------|----------------------|
| Windows SDK **`signtool.exe`** | Native PE | Writable **`signtool.exe`**; map **`SignerSignEx3`**, **`WinVerifyTrust`** to docs and `psign-tool` paths |
| **`mssign32.dll`**, **`crypt32.dll`**, **`WINTRUST.dll`** | Native PE | Writable copies; follow **`SignerSignEx3`**, **`CryptMsg*`**, SIP glue vs [`windows-signing-components.md`](windows-signing-components.md) |
| **AzureSignTool** | .NET | **`AzureSignTool.dll`** / **`AzureSign.Core.dll`** vs [`psign-azure-kv-rest`](../crates/psign-azure-kv-rest/) and [`migration-azuresigntool.md`](migration-azuresigntool.md) |
| **Artifact Signing** managed client | .NET | **`Microsoft.ArtifactSigning.Client.dll`** vs [`psign-codesigning-rest`](../crates/psign-codesigning-rest/) |
| **`Azure.CodeSigning.Dlib.dll`** | Native PE | Decoupled digest exports vs **`SIGNER_DIGEST_SIGN_INFO`** ([`windows-signing-components.md`](windows-signing-components.md)) |

When filing issues, prefer **parity scenario IDs** from [`parity-matrix.md`](parity-matrix.md) and **gap IDs** from [`rust-sip-gaps.md`](rust-sip-gaps.md) (e.g. **`linux_trust_rfc3161_tsa_crypto_gap`**).

---

## Validation matrix (what to run)

| Tier | Command / script | Platform |
|------|-------------------|----------|
| Unix CI | workflows in **`ci-unix.yml`** | Linux |
| Unix local mirror | **`scripts/linux-portable-validation.sh`** (from repo root; bash); **`psign-tool portable append-pe-pkcs7`** / **`pe-checksum --strict`** for PE layout experiments | Linux / WSL / Git Bash |
| Pipelines narrative | [`linux-signing-pipelines.md`](linux-signing-pipelines.md) | Linux-focused |
| Windows parity | `./scripts/run-parity-diff.ps1`, `./scripts/ci/run-exhaustive-parity-ci.ps1` | Windows |
| Writable native signing binaries | **`pwsh -File scripts/prepare-writable-signing-binaries.ps1`** → **`parity-output/writable-signing-binaries`** (gitignored) | Windows |
| MSIX focus | `./scripts/msix-parity-sign.ps1` | Windows |
| Optional KV / Artifact env tests | Ignored tests in **`tests/parity_signtool.rs`** | Windows |
| Portable REST HTTP mocks | **`cargo test -p psign-azure-kv-rest`** / **`cargo test -p psign-codesigning-rest`** (mockito; no cloud) | Linux CI |
| Portable CMS **RS256** prehash parity | **`rust-sip-parity.yml`** job **`portable-cms-rs256-linux`**: **`rsa_pkcs1v15_signed_attrs_verify`** + **`signer_rs256_prehash`** + **`cab_rs256_`** + **`cab_rsa_sha256_signer_prehash`** + **`msi_rs256_`** + **`msi_pkcs7_`** + **`cat_rs256_`** + **`catalog_rsa_sha256_signer_prehash`** + **`wim_verify_rejects`** + **`_unsigned_errors_`** + **`portable_verify_negative_`** + **`inspect_pkcs7_parity_`** + **`detached_trust_`** + **`data_plane_base_url`** + **`psign-azure-kv-rest --lib`** (KV URL + JWS helpers) | Linux (also covered by **`ci-unix.yml`**) |

---

## Related documents

- [`linux-signing-pipelines.md`](linux-signing-pipelines.md) — Linux verify + hybrid Artifact REST flows.
- [`writable-signing-binaries.md`](writable-signing-binaries.md) — writable **`signtool.exe`** / **`WINTRUST.dll`** / **`mssign32.dll`** copies for local study.
- [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) — phased Linux strategy.
- [`rust-sip-gaps.md`](rust-sip-gaps.md) — SIP/Tier 1b/1c engineering backlog.
- [`parity-matrix.md`](parity-matrix.md) — scenario status.
- [`psa-interoperability.md`](psa-interoperability.md) — PowerShell OpenAuthenticode overlap.
