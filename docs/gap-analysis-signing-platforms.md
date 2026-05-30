# Feature gap analysis: native signtool, AzureSignTool, Artifact Signing vs psign

This document compares **Windows SDK `signtool.exe`**, **AzureSignTool**, **Azure Artifact Signing (Trusted Signing)**, and this repository’s **`psign-tool`** / **`psign-tool portable`**. It is the product-facing companion to the engineering-focused [`rust-sip-gaps.md`](rust-sip-gaps.md) and [`parity-matrix.md`](parity-matrix.md).

**Writable copies of Kits / System32 binaries (read-only install dirs):** [`writable-signing-binaries.md`](writable-signing-binaries.md).

**Linux hybrid pipelines (REST hash sign, verify-only, what is still Windows-only):** [`linux-signing-pipelines.md`](linux-signing-pipelines.md). **dotnet/sign migration and package orchestration roadmap:** [`migration-dotnet-sign.md`](migration-dotnet-sign.md).

## Format × capability matrix

Legend: **Sign** = produce/embed Authenticode; **WT verify** = `WinVerifyTrust`-style OS verify; **Digest** = recompute SIP indirect data vs PKCS#7; **Trust** = portable CMS + explicit anchors.

| Subject format | Native `signtool` | `psign-tool` | `psign-tool portable` |
|----------------|-------------------|--------------------|---------------------|
| PE / WinMD | Sign, WT verify | Sign, WT verify, optional `--rust-sip pe` | Digest, inspect, trust-verify-pe, sign-pe (local RSA, Azure Key Vault, or Azure Artifact Signing REST), timestamp-pe-rfc3161 |
| CAB | Sign, WT verify | Same | verify-cab, trust-verify-cab, cab-digest, sign-cab (local RSA or Azure Artifact Signing REST) |
| MSI | Sign, WT verify | Same | verify-msi, sign-msi (local RSA or Azure Artifact Signing REST) |
| ESD / WIM | Sign, WT verify | Same | verify-esd |
| MSIX / APPX (cleartext) | Sign, WT verify | Same (+ `--dlib` / `--dmdf`) | verify-msix; native-shaped flat `.msix` / `.appx` Artifact Signing REST final signing |
| MSIX encrypted | Sign (OS) | Delegates OS | **Rejected** (explicit error) |
| Catalog `.cat` | Sign, WT verify | WT + Rust assists | sign-catalog (local RSA or Azure Artifact Signing REST), verify-catalog, verify-catalog-member, trust-verify-catalog |
| PS scripts | Sign, WT verify | Same | verify-script |
| WSH `.js`/`.vbs`/`.wsf` | Sign, WT verify | Same | verify-script |
| Detached PKCS#7 | Verify | Verify | trust-verify-detached |
| VBA / `mso.dll` SIP | Sign (OS) | OS | **Not portable** |
| Extension SIP DLLs | Sign (OS) | OS | **Not portable** |

**AzureSignTool** targets the same **embedding path as SignTool** (Windows): typically PE (and same SIP stack as invoked by `SignerSignEx3`). It does **not** define new subject formats—it replaces the CSP with **KV `keys/sign`**.

**Artifact Signing REST** (`:sign` LRO) returns **signature material** for a **hash**; PE/WinMD, CAB, MSI/MSP, flat MSIX/AppX, and generic catalog portable signing now build CMS, ask the service to sign the CMS authenticated-attributes digest, and embed the PKCS#7 without Microsoft client DLLs. The portable Rust credential resolver supports bearer tokens, client-secret credentials, system- and user-assigned managed identity, workload identity federation, and metadata `ExcludeCredentials` for the non-interactive default chain. PE/WinMD, CAB, MSI/MSP, generic catalog, and flat MSIX/AppX Artifact Signing paths support sign-time RFC3161 timestamping when built with `timestamp-http`. MSIX/AppX bundles/uploads, encrypted packages, and other SIP remote-sign embedding still require **Windows `SignerSignEx3` + dlib** or future portable embedders.

## Expanded signable-surface audit by mode

This inventory starts from the in-tree supported formats, then expands to inbox Windows SIP providers and adjacent Microsoft code-signing ecosystems. A **Windows-mode gap** is missing or partial behavior in **`psign-tool --mode windows`** compared with native Windows tooling. A **portable-mode gap** is missing behavior in **`psign-tool --mode portable`** / **`psign-tool portable`**, where Win32 SIP, WinTrust, CryptoAPI policy, and `SignerSignEx3` are unavailable by design.

### Inbox Authenticode / SIP subjects

| Surface | Windows mode coverage | Windows-mode gaps | Portable mode coverage | Portable-mode gaps |
|---------|-----------------------|-------------------|------------------------|--------------------|
| **PE / WinMD** (`.exe`, `.dll`, `.sys`, `.ocx`, `.efi`, `.scr`, `.cpl`, `.mui`, `.winmd`, and other PE-by-content subjects) | `sign`, `verify`, `timestamp`, PE `remove`, optional Rust PE digest gate. | Portable-style greenfield CMS is not used; `/ph` page-hash parity and extension corpus coverage need more fixtures. | PE digest, PKCS#7 extraction/inspection, explicit-anchor `trust-verify-pe`, local RSA `sign-pe`, Azure Key Vault and Artifact Signing REST PE signing, native-shaped `--mode portable sign` for PE/WinMD, PE RFC3161 token embedding, remote-signature CMS injection helpers, experimental PKCS#7 append helpers. | No WinTrust policy, OS stores, PinRules, or full `/ph` semantics. |
| **CAB** (`.cab`) | Sign/verify through OS SIP. | No first-class CAB remove; parity success fixtures are thinner than PE. | `verify-cab`, `trust-verify-cab`, `cab-digest`, local RSA or Artifact Signing REST `sign-cab` for unsigned single-volume CABs, native-shaped `--mode portable sign --artifact-signing-*`, PKCS#7 extraction/prehash, RFC3161 timestamp embed. | No CAB signature replacement, multivolume CAB signing, or WinTrust CAB policy equivalent. |
| **Catalog** (`.cat`) and driver-package catalogs | Catalog verify paths and `catdb`; can Authenticode-sign an existing `.cat`. | No catalog authoring (`MakeCat`/`Inf2Cat`/`New-FileCatalog` equivalent) or full driver-package workflow. | `sign-catalog` for portable generic CTL catalogs with local RSA or Artifact Signing REST, RFC3161 timestamp embed, `verify-catalog`, `verify-catalog-member` for explicit file + MakeCat/psign catalog inputs, `trust-verify-catalog`, catalog PKCS#7 consistency, signer prehash. | No native-shaped in-place `.cat` Artifact Signing route, `CryptCATAdmin` database search, driver/INF policy, OS catalog stores, catalog-store revocation policy, or MakeCat byte-for-byte output. |
| **MSI family** (`.msi`, `.msp`, `.mst`) | Sign/verify through `MSISIP.DLL`. | Generic SIP remove is not implemented; optional parity corpus depends on external fixtures. | `verify-msi`, local RSA or Artifact Signing REST `sign-msi` through the `DigitalSignature` stream, native-shaped `--mode portable sign --artifact-signing-*`, PKCS#7 extraction/prehash, RFC3161 timestamp embed. | No `MsiDigitalSignatureEx` authoring or installer policy branches such as `DisableSizeVerification` / `DisableLegacyVerification`. |
| **WIM / ESD** (`.wim`, `.esd`) | Sign/verify through `EsdSip.dll`. | Positive parity fixtures are limited; no remove. | `verify-esd`. | No WIM/ESD signing/embed, timestamp embed, or WinTrust policy equivalent. |
| **Cleartext AppX/MSIX** (`.appx`, `.msix`, `.appxbundle`, `.msixbundle`, `.appxupload`, `.msixupload`) | Sign/verify with AppX client data and dlib bridge. | Remaining native parity failures can occur around `SignerSignEx3` AppX glue, publisher binding, sealing, and package constraints. | `verify-msix` digest consistency; `msix-manifest-info` / `msix-set-publisher`; native-shaped portable Artifact Signing final signing for flat `.appx` / `.msix` packages with `AppxSignature.p7x` / `PKCX` embedding and optional RFC3161 timestamping; guarded `psign-tool code` prepare execution signs nested PE/package entries, updates `AppxManifest.xml` Publisher from `--publisher-name`, regenerates `AppxBlockMap.xml`, propagates publisher updates into nested packages inside upload/bundle containers, and rejects already-final-signed `AppxSignature.p7x` packages before final AppX SIP signing. | Bundle/upload final signing, encrypted packages, manifest publisher-vs-signer policy, and full AppX package policy remain pending. |
| **Encrypted AppX/MSIX** (`.eappx`, `.emsix`, `.eappxbundle`, `.emsixbundle`) | Delegates to OS `EappxSip*` / `EappxBundleSip*`. | No in-tree understanding beyond OS delegation and parity fixtures. | Explicitly rejected by `verify-msix`, MSIX metadata helpers, and `psign-tool code` with Windows AppxSip OS-delegation diagnostics. | Encrypted package crypto/header handling is absent; ZIP-only digest logic is insufficient. |
| **AppX extension SIP chain** | Delegates to installed `ExtensionsSip*` providers. | No bundled/provider-specific parity coverage; behavior depends on optional third-party SIP DLLs. | Not implemented. | No extension-provider discovery, DLL contract, or portable provider model. |
| **Standalone P7X / PKCX** (`.p7x`) | OS `P7xSip*` can participate when registered; real package signatures are produced as `AppxSignature.p7x` inside signed AppX/MSIX packages. | Direct standalone `.p7x` signing is rejected by current SignTool. | `inspect-pkcs7` accepts raw PKCS#7, bare `SignedData`, and PKCX-wrapped `AppxSignature.p7x`; `extract-pkcx-pkcs7` strips the PKCX wrapper; detached trust remains available through `trust-verify-detached` when caller supplies the detached content. | No standalone `.p7x` signing/export flow mapped to native `/p7*` switches. |
| **PowerShell-class scripts** (`.ps1`, `.psm1`, `.psd1`, `.ps1xml`, `.psc1`, `.cdxml`, `.mof`) | Sign/verify through `pwrshsip.dll`; parity fixtures cover `.ps1`, `.psm1`, `.psd1`. | Need parity fixtures and format detection for `.ps1xml`, `.psc1`, `.cdxml`, `.mof`. | `verify-script` digest consistency for PowerShell-style markers. | No signing/embed; digest remains heuristic for every malformed block and encoding edge case. |
| **WSH scripts** (`.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`) | Sign/verify through `wshext.dll`; parity fixtures cover `.js`, `.vbs`, `.wsf`. | Need `.jse` and `.vbe` parity coverage. | `verify-script` digest consistency for WSH markers. | No signing/embed; native COM text conversion and unusual encodings may diverge. |
| **Office / VBA macro projects** | Delegates to installed `mso.dll` / `VBE7.DLL` SIP when present. | No direct Office/VBA CLI affordance or parity fixture set; depends on installed Office components. | Not implemented. | No VBA project graph hashing; likely needs VBE7/Office FFI or permanent OS delegation. |

### Adjacent Windows code-signing ecosystems, not normal Authenticode SIP parity

| Surface | Windows mode coverage | Windows-mode gaps | Portable mode coverage | Portable-mode gaps |
|---------|-----------------------|-------------------|------------------------|--------------------|
| **RDP files** (`.rdp`) | Implemented `rdp` path using Windows certificate stores. | Mostly fixture breadth and native `rdpsign.exe` output-shape parity. | Implemented `portable rdp` with local cert/key or external detached PKCS#7. | No Windows store selection or native `rdpsign.exe` integration by design. |
| **App Installer descriptors** (`.appinstaller`) | Direct embedded signing is rejected by current SignTool; descriptor signing can be represented as unsigned XML plus a PKCS#7 companion artifact generated with SignTool `/p7`. | No full XML+companion signing/verification UX or native parity wrapper. | `appinstaller-info` inspects descriptor metadata and companion `.p7`; `appinstaller-set-publisher` updates namespace-aware MainPackage/MainBundle publisher metadata; `appinstaller-sign-companion` creates a local RSA/SHA-2 detached PKCS#7 companion with optional RFC3161 timestamping; `appinstaller-sign-companion-prehash` + `appinstaller-sign-companion-from-signature` assemble companion CMS from external RSA signatures; detached trust primitives verify the XML plus companion signature; `psign-tool code` creates top-level and nested companion signatures with local cert/key, PFX, portable cert-store SHA-1, Azure Key Vault, or Artifact Signing identity, and nested ZIP orchestration writes descriptor-local `.p7` companions. | No App Installer-specific policy checks. |
| **NuGet packages** (`.nupkg`, `.snupkg`) | Not a `signtool`/WinTrust SIP target in this repo. | No `nuget sign`-compatible author/repository signing workflow in Windows mode. | `psign-opc-sign` groundwork: marker inspection, unsigned package digest, NuGet v1 signature-content generation/verification, local RSA/SHA-2 CMS generation for signature content with RFC3161 timestamp tokens, external-signer CMS assembly via `nupkg-signature-pkcs7-prehash` + `nupkg-signature-pkcs7-from-signature`, `.signature.p7s` embed/overwrite, one-step local `nupkg-sign`, embedded `.signature.p7s` package hash + explicit-anchor CMS verification, top-level `psign-tool code` execution from local cert/key, PFX, portable cert-store SHA-1, Azure Key Vault, or Artifact Signing identity, package-native nested execution when embedded in VSIX/ZIP containers, nested PE/WinMD signing before package signatures, nested exclude filters, `--skip-signed`, and `--overwrite`. | No repository signatures, full NuGet policy verification, or non-PE Authenticode nested payload signing. |
| **VSIX packages** (`.vsix`) | Not a first-class Windows-mode signing surface here. | No VSIX package signing/verification workflow. | Signature marker inspection, signature XML embed primitive with OPC signature content-type and relationship metadata, deterministic XMLDSig Reference/DigestValue generation/verification for package parts, local RSA/SHA-2 XMLDSig `SignatureValue` generation/verification, external-signer XMLDSig assembly via `vsix-signature-xml-prehash` + `vsix-signature-xml-from-signature`, one-step local `vsix-sign`, embedded OPC XMLDSig verification with optional explicit-anchor signer chain validation, top-level `psign-tool code` execution from local cert/key, PFX, portable cert-store SHA-1, Azure Key Vault, or Artifact Signing identity, package-native nested VSIX/ZIP -> NuGet/VSIX -> PE/WinMD execution, nested exclude filters, `--skip-signed`, and `--overwrite`. | No timestamping or non-PE Authenticode nested payload signing. |
| **ClickOnce / VSTO manifests** (`.manifest`, `.application`, `.vsto`, `.deploy` workflows) | Not implemented. | No `mage.exe`/manifest XMLDSig workflow, certificate embedding, or timestamping. | `psign-tool code --dry-run` classifies ClickOnce/VSTO workflow nodes; portable helpers inspect/copy `.deploy` payloads; guarded `psign-tool code` execution signs PE-like `.deploy` payloads and `.manifest` / `.application` / `.vsto` XMLDSig manifests with local cert/key; portable helpers update and verify manifest file size/digest references; `clickonce-sign-manifest` / `clickonce-sign-manifest-prehash` / `clickonce-sign-manifest-from-signature` / `clickonce-verify-manifest-signature` provide deterministic portable structural local/external XMLDSig signing with embedded signer certificate. | Full Mage-compatible canonicalization/policy, timestamping, full deployment graph orchestration, and ClickOnce/VSTO policy checks remain. |
| **Business Central `.app`** | Format-specific behavior is not implemented. | No confirmed NAVX signing/verification workflow. | `business-central-app-info` detects NAVX headers, `psign-tool code --dry-run` classifies NAVX `.app` files, and signing execution now reports a Business Central-specific unsupported diagnostic instead of silently treating them as generic files. | Actual package signing and verification policy remain pending format confirmation. |
| **File catalog authoring** | Can sign/verify an existing `.cat` at the Authenticode layer. | No catalog creation from arbitrary file sets or INF/driver package metadata. | `sign-catalog` authors generic CTL catalogs; catalog PKCS#7 consistency/trust and explicit `verify-catalog-member` cover committed MakeCat-style and psign-authored generic catalogs. | Driver/INF policy, OS catalog database search, and MakeCat byte-for-byte output remain out of scope. |
| **WDAC / CI policy signing** | Detached PKCS#7/catalog primitives only. | No policy-specific signing/validation workflow or deployment policy checks. | Detached PKCS#7/catalog primitives only. | No policy-specific workflow, Code Integrity semantics, or Windows deployment policy checks. |

### Fixture corpus gaps

The committed corpus already includes generated unsigned and signed vectors for PE aliases, WinMD, CAB, catalog, MSI/MSP, WIM/ESD, cleartext MSIX/AppX, PowerShell and WSH scripts, detached PKCS#7, RDP, NuGet, and VSIX. The remaining fixture gaps are:

| Surface | Current fixture state | Missing fixture coverage |
|---------|-----------------------|--------------------------|
| **MST transforms** (`.mst`) | Unsigned generated transform exists; signed native output is retained in skipped corpus rows because `/pa` verification rejects it. | A verifiable signed `.mst` fixture if native Windows Installer policy supports one, or deeper tests around the documented reject. |
| **Encrypted AppX/MSIX** (`.eappx`, `.eappxbundle`, `.emsix`, `.emsixbundle`) | Unsigned/placeholder negative files exist. | Real signed encrypted package fixtures, if the project decides to test OS-only Windows delegation. |
| **WSH component scripts** (`.wsc`) | Unsigned probe files exist and native SignTool rejection is recorded; `.jse` / `.vbe` have signed generated probes. | Signed `.wsc` fixture if a supported provider/tooling path is identified. |
| **Standalone P7X / PKCX** (`.p7x`) | Unsigned direct-signing probe exists and native SignTool rejection is recorded; a real `AppxSignature.p7x` is extracted from a signed MSIX fixture. | PKCX extraction and standalone PKCS#7/P7X inspection are covered by portable CLI tests; native-shaped standalone `.p7x` signing/export remains uncovered. |
| **App Installer descriptors** (`.appinstaller`) | Unsigned descriptor exists and native direct-signing rejection is recorded; a real SignTool `/p7` companion signature is generated for detached verification coverage. | Companion PKCS#7 generation and policy checks remain implementation gaps. |
| **Optional-provider / XML signing surfaces** (`.application`, `.manifest`, `.vsto`, `.deploy`) | Unsigned probe files exist and native SignTool rejection/provider-unavailable outcomes are recorded. | Signed ClickOnce/VSTO-style fixtures and tool-specific signing metadata. |
| **Office macro containers** (`.docm`, `.xlsm`, `.pptm`, `.xlam`) | Unsigned probe files exist. | Signed Office/VBA macro-project fixtures generated with installed Office/VBE SIP, plus verification expectations. |
| **Symbols packages** (`.snupkg`) | Unsigned and signed fixtures now exist under `tests/fixtures/package-signing/`. | No remaining fixture gap; implementation gaps are package-signing feature work, not corpus files. |
| **PowerShell UTF-16BE variants** | Unsigned UTF-16BE fixtures exist for `.ps1`, `.psd1`, `.psm1`, `.ps1xml`, `.psc1`, `.cdxml`, `.mof`; native SignTool rejection is recorded. | Signed UTF-16BE variants only if native tooling behavior changes or an alternate supported signing path is identified. |

## Executive summary

| Goal | Today | Gap |
|------|--------|-----|
| **Drop-in Linux replacement for `signtool.exe` sign/verify** | Not supported | Signing and WinTrust-backed verify require Windows CryptAPI/SIP (`SignerSignEx3`, `WinVerifyTrust`). |
| **Drop-in Linux replacement for AzureSignTool** | Partial | **`psign-tool portable sign-pe --azure-key-vault-* --timestamp-url ...`** and **`psign-tool --mode portable sign --azure-key-vault-* --timestamp-url ...`** can build timestamped PE Authenticode signatures with Key Vault RSA signing. **`azure-key-vault-sign-digest`** remains available for lower-level **`keys/sign`** workflows. Gaps: non-PE remote-sign embedding still requires Windows mode or future portable signer support. |
| **Drop-in Linux replacement for Artifact Signing (dlib / REST)** | Partial | PE/WinMD is supported through **`psign-tool portable sign-pe --artifact-signing-* --timestamp-url ...`** and **`psign-tool --mode portable sign --dmdf ... --artifact-signing-* --timestamp-url ...`**. CAB and MSI/MSP are supported through scoped portable commands and native-shaped in-place Artifact Signing; generic catalogs are supported through **`portable sign-catalog --artifact-signing-*`**. Native-shaped portable Artifact Signing supports input file lists, skip-signed, continue-on-error, and max parallelism for supported targets. The lower-level **`artifact-signing-submit`** helper remains available for digest → JSON workflows. Gaps: MSIX/AppX, non-PE timestamp mutation, and other SIP formats still require Windows dlib mode or future portable embedders. |
| **Linux verify + digest parity for many Authenticode formats** | Supported | **`psign-tool portable`** covers PE, CAB, MSI, ESD/WIM, cleartext MSIX, catalog, scripts; **`trust-verify-*`** adds anchor-based CMS trust (see [`authenticode-trust-stack.md`](authenticode-trust-stack.md)). |
| **Maximum Windows-mode Authenticode subject formats** | Windows mode delegates most SIP-registered subjects to OS providers | Remaining gaps are first-class CLI affordances, parity fixtures, generic SIP remove, catalog authoring/member policy, Office/VBA ergonomics, extension SIP coverage, and standalone `.p7x` handling. |
| **Maximum portable-mode Authenticode subject formats** | Portable mode covers digest/trust for PE, CAB, MSI, ESD/WIM, cleartext MSIX, catalogs, scripts, and detached PKCS#7; local signing for PE/CAB/MSI/generic catalogs is explicitly scoped; Artifact Signing REST can sign PE/WinMD, CAB, MSI/MSP, and generic catalogs | Portable gaps include MSIX signing/embed, non-PE timestamp mutation, WinTrust/CryptoAPI policy, encrypted MSIX, extension SIPs, Office/VBA, standalone `.p7x`, and package-specific ecosystems. |

**Practical Linux path today:** Use **`psign-tool portable`** for **digest computation**, **local signing** of PE/CAB/MSI/generic catalogs, **Key Vault PE signing** (`portable sign-pe` or `--mode portable sign`), **Artifact Signing REST PE signing** (`portable sign-pe --artifact-signing-*` or `--mode portable sign --dmdf ... --artifact-signing-*`), **Key Vault `keys/sign`** on digest files (**`azure-key-vault-sign-digest`** with **`--features azure-kv-sign-portable`**), low-level **`:sign` REST** (**`artifact-signing-submit`** with **`--features artifact-signing-rest`**), **inspect**, and **verify/trust** across supported formats. Broader native-shaped signing and unsupported SIP embedders still require **`psign-tool`** / **`SignerSignEx3`** (or native **`signtool.exe`**). Cookbook: [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

**Long-term Linux signing** (if required): extend the portable **CMS `SignerInfo` production** (inside **`SignedData`**) + **format-specific embedding** beyond the current PE/CAB/MSI/catalog subset to MSIX `ContentTypes` / manifest glue and other package-native formats, then combine with **remote signing** (KV REST, Artifact Signing `:sign` LRO). [`pkcs7.rs`](crates/psign-sip-digest/src/pkcs7.rs) holds parse/replace helpers, **`signed_data_replace_first_signer_info`**, **`encode_pkcs7_content_info_signed_data_der`**, **RSA PKCS#1 RS256** prehash ↔ **`SignerInfo.signature`** parity tests (`rsa_pkcs1v15_signed_attrs_verify`), and **`signer_info_sha256_digest_over_signed_attrs`** (documented KV **`RS256`** input shape); [`pe_embed.rs`](crates/psign-sip-digest/src/pe_embed.rs) can **wrap PKCS#7**, **append** rows (including after signer splice experiments), and **recompute `CheckSum`**. **`psign-tool portable pe-signer-rs256-prehash`** surfaces the **32-byte** prehash for Linux KV workflows; MSIX signing/embed and non-PE timestamp mutation remain backlog (see [`rust-sip-gaps.md`](rust-sip-gaps.md)).

---

## Top 3 gaps worth filling next

These are the highest-leverage gaps after comparing the native switch matrix, portable lifecycle coverage, package-orchestration work, and fixture corpus. The stable IDs are mirrored in `psign-cli-matrix.json` as `top_gap_ids`; implementation details should remain here to avoid overloading the CLI switch matrix with roadmap prose.

| Priority | Gap id | Current state | Fill plan |
|----------|--------|---------------|-----------|
| 1 | `portable-msix-bundle-upload-final-signing` | Flat cleartext `.appx` / `.msix` portable Artifact Signing exists; `psign-tool code` can prepare nested bundle/upload contents and regenerate manifests/block maps, but final bundle/upload signing and encrypted packages remain outside the portable embedder. | Reuse the flat MSIX signer and publisher/block-map preparation, add bundle/upload traversal that signs nested packages before the outer container, define explicit rejection for encrypted packages, and add fixtures for unsigned bundle/upload -> signed verify/tamper cases. |
| 2 | `catalog-driver-package-authoring` | Portable `sign-catalog` can author generic CTL catalogs and `verify-catalog-member` can check explicit file membership, while Windows mode can sign/verify existing catalogs and mutate catalog databases. | Extend catalog authoring toward MakeCat/Inf2Cat/New-FileCatalog-compatible member metadata, add driver/INF policy diagnostics separately from generic catalogs, and grow the corpus with psign-authored plus native-authored driver-package catalogs. |
| 3 | `wdac-ci-policy-signing` | Detached PKCS#7 and catalog primitives exist, but WDAC / Code Integrity policy signing is documented only as adjacent backlog. | Define policy-file detection and expected signature container shape, route signing through existing detached PKCS#7/catalog CMS helpers, then add verification diagnostics that distinguish CMS validity from Windows deployment/CI policy acceptance. |

These three outrank smaller parity refinements such as stricter timestamp routing or OCSP/CRL policy hardening because they unlock whole user workflows rather than polishing already-available verification paths.

## Additional gap candidates worth filling

The next tier is still worth tracking because each item either unlocks a recognizable signing workflow, removes a common Windows-only dependency, or closes an ambiguity that would otherwise make portable verification hard to trust. They are not mirrored in `psign-cli-matrix.json` yet because they are roadmap candidates rather than stable top priorities.

| Rank | Gap id | Why it is worth filling | First useful slice |
|------|--------|-------------------------|--------------------|
| 4 | `standalone-pkcx-p7x-tooling` | Native SignTool users encounter standalone PKCS#7 / PKCX artifacts through `/p7`, `/p7ce`, `/p7co`, `/p7u`, and catalog-style detached workflows. The first standalone slice is implemented: `inspect-pkcs7` and `extract-pkcx-pkcs7` make raw PKCS#7 and AppX `PKCX` files first-class portable inputs. | Grow into explicit detached verify ergonomics and signing/export flows that map cleanly to the native `/p7*` switches. |
| 5 | `office-vba-signing-verification` | Office/VBA macro signing is a real Authenticode SIP surface that remains a practical Windows-only island; even diagnostic coverage would help teams inventory and migrate signed macro assets. | Start with Windows-mode detection, verify, and remove diagnostics around the `mso.dll` SIP, then document portable rejection and fixture requirements before attempting portable embed support. |
| 6 | `split-digest-signing-pipeline` | `/dg`, `/ds`, `/di`, and `/dxml` workflows are important for HSM, air-gapped, and service-mediated signing where the machine that hashes is not the machine that applies the signature. | Normalize one portable digest -> external signature -> ingest path for PE first, then reuse it for CAB/MSI/catalog as their portable embedders mature. |
| 7 | `portable-trust-policy-hardening` | Current portable trust is intentionally anchor-directory based; production verification often also needs disallowed CTLs/STLs, EKU/application-policy rules, revocation depth, OCSP/CRL edge cases, and TrustedPublisher semantics. | Add policy switches and diagnostics without pretending to be the OS trust store, prioritizing disallowed roots/intermediates and AuthRoot-derived pin/rule fixtures. |
| 8 | `clickonce-mage-compatible-signing` | ClickOnce deployments are still common in enterprise Windows estates and have their own manifest canonicalization, timestamping, and policy expectations beyond generic XML/package handling. | Implement detect/inspect/verify parity first, then add Mage-compatible signing and timestamping only after native-vs-portable fixture parity is clear. |
| 9 | `nuget-repository-signature-policy` | NuGet packages have author signatures, repository signatures, countersignatures, timestamp policy, and package-source trust decisions that go beyond the existing package digest primitives. | Extend inspection to distinguish author vs repository signatures and add policy diagnostics before attempting repository-signature authoring. |
| 10 | `vsix-timestamping-and-policy` | VSIX signing support without timestamp/policy parity leaves long-lived extension distribution workflows incomplete. | Add timestamp mutation and verify diagnostics for existing signed VSIX packages, with tamper/expiration fixtures. |
| 11 | `appinstaller-policy-verify` | App Installer files are small but security-sensitive orchestration manifests; portable hashing alone does not answer whether an update/feed policy is safe or acceptable. | Add policy-focused inspection and verify diagnostics for signed `.appinstaller` manifests, separate from MSIX package signing. |
| 12 | `encrypted-msix-delegation-fixtures` | Encrypted MSIX/AppX packages should probably remain a Windows/decryption-bound path, but explicit fixture-backed detection prevents confusing portable failures and regression drift. | Add corpus coverage and diagnostics that distinguish encrypted-package rejection from malformed-package failures, then route Windows-mode operations to the OS where possible. |
| 13 | `cab-replacement-multivolume-mutation` | CAB support covers important single-volume signing paths, but setup media and legacy installers can require replacement/multivolume behavior and removal parity. | Add negative/diagnostic coverage for unsupported CAB layouts first, then implement replacement and remove flows for the safest subset. |
| 14 | `msi-policy-expansion` | MSI/MSP signatures have policy branches such as `MsiDigitalSignatureEx` and installer-specific verification behavior that are distinct from generic PKCS#7 validity. | Extend MSI inspection to report signature-table variants and policy-relevant metadata before adding stricter trust decisions. |
| 15 | `extension-sip-provider-model` | Windows can delegate arbitrary subject formats to installed SIP providers, while portable mode only supports built-in Rust format handlers. | Define a narrow provider interface for digest/inspect/verify experiments, but keep signing gated until deterministic fixtures and security boundaries are understood. |

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
| KV URL, cert name, auth (MI / SP / token) | Yes (`--features azure-kv-sign`) | PE signing via **`portable sign-pe`** / **`--mode portable sign`**; digest-only helper via **`azure-key-vault-sign-digest`** |
| Batch / parallelism / exit HRESULTs | Mapped (`--input-file-list`, `--exit-codes azuresigntool`, …) | N/A |
| ECDSA keys | Supported on KV path (alg derived from cert) | Same JWS algs (**ES256**/…) inferred from certificate **`cer`** |

**Gap:** Broad native-shaped signing is still **Windows + SIP** for production compatibility. Portable local-key signing now exists for PE, unsigned single-volume CAB, and MSI/MSP; portable KV PE signing can build and embed Authenticode directly. Digest-only KV helpers remain useful when you need a raw remote signature, but use the correct digest for your pipeline (**image** vs **CMS signer** prehash; **`pe-signer-rs256-prehash`** for the latter on PE). Portable Key Vault signing for CAB/MSI/catalog and MSIX/package-specific embedding remain future work.

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
| REST PE / WinMD embedding | **`psign-tool portable sign-pe --artifact-signing-*`** and **`psign-tool --mode portable sign --dmdf ... --artifact-signing-*`** build, remote-sign, optionally timestamp, and embed Authenticode |
| Metadata validation without signing | **`psign-tool portable artifact-signing-metadata-check`** |

**Gap:** REST output is wired into the portable **PE / WinMD** Authenticode embedder, but MSIX/AppX and other non-PE SIP subjects still require the Windows dlib path or future portable embedders. [`migration-artifact-signing.md`](migration-artifact-signing.md).

---

## `psign-tool portable` (Linux/macOS)

**Commands (verify / inspect / digest tools):** See [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) and **`psign-tool portable --help`**.

### Portable lifecycle contract

Portable support is intentionally split by lifecycle stage. This keeps Linux/macOS workflows useful today without implying that portable mode has full Win32 SIP, `WinVerifyTrust`, or `SignerSignEx3` parity.

| Lifecycle stage | `psign-tool --mode portable ...` | `psign-tool portable ...` | Support level |
|-----------------|-----------------------------------|----------------------------|---------------|
| Digest computation | Routed through `verify` only when it can infer a supported subject format | `pe-digest`, `cab-digest`, and format-specific `verify-*` commands | Supported for PE/WinMD, CAB, MSI/MSP, WIM/ESD, cleartext MSIX/AppX, catalogs, and scripts |
| PKCS#7 inspection / extraction | `inspect-signature` routes to `inspect-authenticode` | `inspect-authenticode`, `inspect-pkcs7`, `extract-pkcx-pkcs7`, `extract-pe-pkcs7`, `extract-cab-pkcs7`, `extract-msi-pkcs7`, `list-pe-pkcs7` | Supported diagnostics; no trust decision by itself |
| Explicit-anchor trust verification | `verify` routes only when portable trust inputs are present and the inferred format has a trust command | `trust-verify-pe`, `trust-verify-cab`, `trust-verify-msi`, `trust-verify-esd`, `trust-verify-catalog`, `trust-verify-detached` | Supported with explicit anchors and bounded online AIA/OCSP/CRL; not OS store policy |
| Remote hash/signing | PE Key Vault signing through top-level `sign`; other remote helpers are not routed | `sign-pe --azure-key-vault-*`, `artifact-signing-submit`, `azure-key-vault-sign-digest`, signer prehash commands | PE Key Vault signing embeds Authenticode; other remote helpers are digest-in/signature-out only |
| Local-key signing | Top-level `sign` returns an explicit portable-not-implemented error | `sign-pe`, `sign-cab`, `sign-msi`, `sign-catalog`, `rdp` | Supported for PE, unsigned single-volume CAB, MSI/MSP, generic catalogs, and RDP local RSA signing; other Authenticode SIP subjects remain backlog |
| CMS creation from scratch | Not exposed through the native-shaped verb | PE/CAB/MSI Authenticode CMS creation through `sign-pe`, `sign-cab`, `sign-msi`, generic CTL/catalog CMS creation through `sign-catalog`, and `psign-sip-digest` helpers | Supported for PE, CAB, MSI, and generic catalog RSA/SHA-2; reusable CMS work remains to extend MSIX |
| Format-specific Authenticode embed | Not implemented | `sign-pe` for PE, `sign-cab` for unsigned single-volume CABs, `sign-msi` for MSI/MSP `DigitalSignature` streams, `sign-catalog` for CTL `eContent` authoring; `append-pe-pkcs7` remains lower-level PE append plumbing | PE supported; CAB initial signing supported; MSI stream signing supported; generic catalog authoring supported; MSIX production embedder is backlog |
| Timestamp embedding | `sign --timestamp-url --timestamp-digest` is routed for portable PE signing; top-level standalone `timestamp` returns an explicit portable-not-implemented error | `sign-pe --timestamp-url --timestamp-digest` timestamps at sign time; NuGet `nupkg-signature-pkcs7`, `nupkg-sign`, and `psign-tool code` NuGet/App Installer companion CMS signing can attach RFC3161 tokens; `timestamp-pe-rfc3161` attaches a granted RFC3161 `timeStampToken` to existing PE `SignedData`; request/response helpers can prepare or inspect TSA traffic | PE and NuGet/App Installer local CMS sign-time timestamping supported; VSIX/ClickOnce timestamping and standalone native-shaped timestamp routing remain backlog |
| Signature removal / mutation | Top-level `remove` returns an explicit portable-unsupported error | No remove verb | Backlog only after production embedders exist |
| Catalog database operations | Top-level `catdb` returns an explicit portable-unsupported error | `sign-catalog` authors explicit generic catalogs; `verify-catalog-member` verifies explicit file + catalog membership without a database | OS catalog database search, driver/INF policy, and catalog store mutation remain out of scope |

The compatibility rule is: **portable mode may prove digest/CMS consistency and explicit-anchor trust, but it must not silently emulate Windows policy.** When a user asks for a Windows-only lifecycle stage, the CLI should fail with an explicit unsupported/not-implemented message and point to the closest portable helper.

**Remote signing steps:** With **`--features azure-kv-sign-portable`**, **`sign-pe --azure-key-vault-*`** performs full PE Authenticode signing with Key Vault RSA signatures, while **`azure-key-vault-sign-digest`** performs Azure Key Vault **`keys/sign`** on a **raw digest file** for lower-level workflows. **`pe-signer-rs256-prehash`**, **`cab-signer-rs256-prehash`**, **`msi-signer-rs256-prehash`**, and **`catalog-signer-rs256-prehash`** (**`--encoding raw`**) emit the **32-byte** **`RS256`** input over **`SignerInfo.signedAttrs`** (distinct from subject-layout digests and from **`verify-catalog`**’s CTL **`eContent`** / PKCS#9 checks). With **`--features artifact-signing-rest`**, **`artifact-signing-submit`** calls Trusted Signing **`:sign`**, and **`sign-pe --artifact-signing-*`** / top-level **`--mode portable sign --artifact-signing-*`** use that REST signature to embed PE/WinMD Authenticode. CAB/MSI/catalog remote-sign CLI routing, MSIX embedding, and broader native-shaped remote-sign routing remain future portable embedder work.

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
