# Rust SIP — specification references

Authoritative references for in-process Authenticode “SIP logic” (digest scope, PKCS#7 embedding rules). Link-only; do not paste non-open licensed SDK headers verbatim.

## PE / COFF

- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — headers, optional header checksum, **certificate table** (file offset, not RVA).
- [Windows Authenticode PE guidance](https://learn.microsoft.com/en-us/windows/win32/seccrypto/wintrust-sha256-signature-support-in-pe-files) — SHA-256 signing notes.

## PKCS#7 / Authenticode OIDs (checklist)

- `ContentType` SignedData: `1.2.840.113549.1.7.2`
- `SPC_INDIRECT_DATA_OBJID`: `1.3.6.1.4.1.311.2.1.4`
- Digest algorithms: SHA-256 `2.16.840.1.101.3.4.2.1`, SHA-1 `1.3.14.3.2.26`
- RFC3161 countersignature (Tier 1b): nested PKCS#7 / CMS timestamp token

## Implementation notes

- PE **Authenticode digest** in this repo delegates to the **`authenticode`** crate ([google/authenticode-rs](https://github.com/google/authenticode-rs)) (`authenticode_digest`), using **`object`** `PeFile32` / `PeFile64` as `PeTrait` inputs. For tooling and future **page-hash** alignment, **`pe_authenticode_digest_file_ranges`** (`psign-sip-digest` `pe_digest`) returns the ordered list of **file byte ranges** that participate in that digest (validated by unit tests against `pe_authenticode_digest`).
- **PKCS#7 encode + RSA signing** for a standalone Rust signer path is **not** complete yet; see [`rust-sip-architecture.md`](rust-sip-architecture.md).

## PE image digest vs `SPC_PE_IMAGE_PAGE_HASHES`

The **subject digest** embedded in `SpcIndirectDataContent` follows **`authenticode_digest`**: it hashes the PE in **several disjoint file ranges** — skipping the optional-header **checksum** DWORD, skipping the **security directory** slot in the data directory, hashing **sections in ascending virtual/raw start order**, then any trailing file tail **excluding the WIN_CERTIFICATE table**. See [`authenticode-rs` `authenticode_digest.rs`](https://github.com/google/authenticode-rs/blob/main/authenticode/src/authenticode_digest.rs).

**Page-hash** authenticated attributes (`1.3.6.1.4.1.311.2.3.1` / `.2`) carry a separate flat table of **`(end_offset, digest)`** pairs. Native **`WinVerifyTrust`** `/ph` validates those entries against PE bytes with rules that **do not** reduce to “hash contiguous raw slices from offset 0”. The portable CLI command **`psign-tool portable verify-pe-page-hashes`** implements an **experimental contiguous raw-file model** only — closing Tier 1c parity requires matching **`WINTRUST`/`CryptSIP`** page-boundary and exclusion semantics (or reusing their outputs via FFI on Windows).

The **subject-digest** disjoint ranges are enumerated in-code as **`pe_authenticode_digest_file_ranges`** for tooling (same segment order as **`authenticode_digest`**).

## Writable working directories

Binaries under **`Program Files`** are often not writable side-by-side with caches or databases some tools create. If a workflow fails with **access denied**, copy **`signtool.exe`** / **`WINTRUST.dll`** (or other inputs) to **`%TEMP%`** or another user-writable directory and run against that path.

## WINTRUST PE SIP: page hashes and `SPC_LINK`

[`WintrustSetDefaultIncludePEPageHashes`](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wintrustsetdefaultincludepepagehashes) controls the default inclusion of **PE page-hash** authenticated attributes (related to native **`/ph`** and **`SIGNTOOL_PAGE_HASHES`**).

[`SignerSignEx`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signersignex) **dwFlags** semantics flow through **`SIP_SUBJECTINFO.dwFlags`**. The inbox PE SIP chooses whether to emit page-hash attributes (**`CreatePageHashesAttribute`**) vs a simpler **`SPC_LINK`** encoding:

- If **`SPC_EXC_PE_PAGE_HASHES_FLAG` (`0x10`)** is **clear** **and** (**`SPC_INC_PE_PAGE_HASHES_FLAG` (`0x100`)** is **set** **or** the process default from **`WintrustSetDefaultIncludePEPageHashes`** is on), the SIP builds page-hash authenticated attributes and the encoded **`SPC_LINK`** path includes that blob (**`dwLinkChoice == 2`** in Microsoft’s layout).
- Otherwise the SIP takes the branch without that serialized page-hash payload (**`dwLinkChoice == 3`**).

Portable Rust signing needs the same precedence (**explicit exclude** wins; else **explicit include** or **process default**) to match **`signtool.exe`** / **`SignerSignEx3`** when page hashing is enabled.

## SignerSignEx3 and SIP glue

[`SignerSignEx3`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signersignex3) routes subject hashing and PKCS#7 embedding through the registered **CryptSIP** implementation for the file type.

### MSIX / APPX / bundles — **`APPX_SIP_CLIENT_DATA`**

Microsoft’s sample for [programmatic app-package signing](https://learn.microsoft.com/en-us/windows/win32/appxpkg/how-to-programmatically-sign-a-package) requires **`pSipData`** to point at **`APPX_SIP_CLIENT_DATA`**, whose **`pSignerParams`** references the same **`SIGNER_SIGN_EX2_PARAMS`**-shaped aggregate **`SignerSignEx3`** uses (with **`pSipData`** inside that aggregate pointing back at **`APPX_SIP_CLIENT_DATA`** — a deliberate cycle).

**AppxSip** expects **`SIP_SUBJECTINFO.pClientData`** to reference valid **`APPX_SIP_CLIENT_DATA`** (initialized along **`AppxSipPutSignedDataMsg`**); null or invalid client data yields **`APPX_E_MISSING_PUBLIC_KEY_OR_REQUIRED_DATA`** (**`0x80080209`**). **`mssign32`** passes **`SignerSignEx3`** **`pSipData`** through to **`pClientData`** for the SIP call chain.

**`psign`** (`src/win/sign_core.rs`) passes this **`APPX_SIP_CLIENT_DATA`** + **`SIGNER_SIGN_EX2_PARAMS`** layout for every **`CodeSignFormat::MsixFamily`** **`SignerSignEx3`** call (embedded and decoupled **`/dlib` + `/dmdf`** — digest callbacks use the separate **`pDigestSignInfo`** parameter).

### Other optional **`SignerSignEx3`** parameters

- **`pCryptoPolicy`** (`PCERT_STRONG_SIGN_PARA`) — **`NULL`** in-tree; strong-sign policy checks from [**`CERT_STRONG_SIGN_PARA`**](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_strong_sign_para) are not applied by **`psign`** on sign.
- **`pDigestSignInfo`** — used only for decoupled **`/dlib` + `/dmdf`** signing; standard embedded signing leaves this **`NULL`** except that path.
