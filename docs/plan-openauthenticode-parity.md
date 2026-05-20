# Plan: Align psign with PowerShell OpenAuthenticode (non-module features)

[PowerShell-OpenAuthenticode](https://github.com/jborean93/PowerShell-OpenAuthenticode) (`OpenAuthenticode`) is a **.NET / portable CMS** stack for Authenticode: managed **SignedCms** signing and verification, multiple **file providers** (PowerShell scripts, MOF, PS1XML, PE, APPX/bundle), **nested signatures**, **RFC3161 HTTP timestamping**, **Azure Key Vault** certificate fetch, and **Azure Trusted Signing via the `Azure.CodeSigning` REST client** (not only a decoupled dlib).

This document lists **capabilities found there that psign does not fully mirror today**, and proposes implementation phases. **Out of scope:** shipping a PowerShell module or cmdlet surface—only libraries, CLIs, and docs that belong in this repo.

## Already broadly covered here

- **PE, PowerShell-class scripts, WSH `.js`/`.vbs`/`.wsf`**, **MOF / PS1XML-style markers** — Windows signing uses `SignerSignEx3` + SIPs; portable digest checks live in `psign-sip-digest` / `psign-tool portable`.
- **MSIX / APPX** — Windows path + portable ZIP digest verification (PSA uses a pure ZIP/CMS provider; we rely on the Windows SIP for signing).
- **Azure Key Vault–backed signing** — `psign-tool` + `--features azure-kv-sign` (RSA PKCS#1 v1.5 over digest).
- **Artifact Signing via Microsoft dlib** — `--dlib` / `--trusted-signing-dlib-root` + `--dmdf` (Windows only).
- **Append signature** — `--append-signature` exists; **parity** with PSA’s nested PKCS#7 attribute (`1.3.6.1.4.1.311.2.4.1`) should be validated with fixtures.
- **Remove / clear signature** — `remove` (and related flows) vs PSA `Clear-OpenAuthenticodeSignature`.

## Gaps and proposed work

### 1. Azure Trusted Signing without the Windows dlib (REST hash signing)

**PSA:** `AzureTrustedSigner` calls `CertificateProfileClient.StartSignAsync` / `WaitForCompletionAsync` (`Azure.CodeSigning` SDK) and feeds the returned signature into managed CMS.

**psign:** Trusted Signing is integrated through **`Azure.CodeSigning.Dlib.dll`** and `SignerSignEx3` only.

**Plan:** Optional feature (e.g. `artifact-signing-rest` or extend `azure-kv-sign`):

- Rust HTTP client + auth (Azure Identity patterns consistent with KV path).
- Implement or bind to the **Artifact Signing** “sign hash” REST contract used by the official SDK (OpenAPI/spec or careful compatibility testing).
- Plumb into a **Windows-only** path that still builds PKCS#7 via **existing** `SignerSignEx3`/`mssign32` surfaces *or* a future portable CMS builder (see §5).
- Document credential flows mirroring PSA (`Get-OpenAuthenticodeAzTrustedSigner` semantics): account name, profile name, correlation ID, tenant/client options.

**Risk:** API versioning and auth parity with Microsoft’s client; treat as **advanced / optional** behind feature flags.

### 2. Structured “get signature” / inspection (multi-signer, nested, timestamps)

**PSA:** `Get-OpenAuthenticodeSignature` walks **nested** signatures (`1.3.6.1.4.1.311.2.4.1`), extracts **legacy Authenticode** and **RFC3161** counter-signatures (`SignatureHelper.GetCounterSignature`), and returns **SignedCms**-backed objects.

**psign:** `verify` is **WinVerifyTrust**-oriented; portable tools focus on digest + optional **trust-verify** with explicit anchors—not a full **CMS inspector**.

**Plan:**

- Add a **`psign-tool inspect-signature`** (or extend **`verify --dump`** if present) that prints **machine-readable** JSON: signer count, nested blobs, digest OID, **timestamp kind** (legacy vs RFC3161), signing time hints, leaf subject/thumbprint (no PowerShell dependency).
- Share parsing logic with **`psign-tool portable`** where possible (reuse `picky` / existing PKCS#7 helpers from trust crate).
- Cross-test against PSA output on shared fixtures.

### 3. Verification semantics: timestamp-grace and optional custom trust store

**PSA:** Custom **`CheckSignature`** path uses **counter-signature time** so **expired** leaf certs can still verify when timestamped; optional **`trustStore`** and **`SkipCertificateCheck`** (`verifySignatureOnly`).

**psign:** **`trust-verify-*`** already supports anchors and timestamp-related flags (`TrustVerifySharedArgs`); **WinVerifyTrust** path follows OS policy.

**Plan:**

- Audit **expired leaf + valid RFC3161** behavior vs PSA on fixed fixtures; close gaps in **`psign-authenticode-trust`** policy if needed.
- Document mapping: `-SkipCertificateCheck` ↔ **`trust-verify`** knobs / **`verify --policy`** combinations.
- Optional: **`--custom-trust-store`** (dir of PEM) for **Windows verify** path if product needs OS-adjacent parity (lower priority than portable trust-verify).

### 4. ECDsa / P-256 (and beyond) for Key Vault or file-backed signing

**PSA:** `ManagedECDsaKeyProvider` and Azure key types support non-RSA algorithms where applicable.

**psign:** Azure KV path documentation and code emphasize **RSA PKCS#1** (`RS256`/`384`/`512`).

**Plan:**

- Inventory KV key types and **`SignerSignEx3`** requirements for EC keys (CNG / certificate mapping).
- Add **ECDSA** digest signing for KV when the platform and cert support it; extend parity tests if Devolutions or internal fixtures allow.

### 5. Portable CMS signing (long-term, large scope)

**PSA:** Can **sign PE and scripts on Linux/macOS** using **managed** crypto (no `SignerSignEx3`).

**psign:** By design, **full signing** is Windows-centric.

**Plan:** Keep as **non-goal** unless a product requirement appears. If needed later: layer a **pure-Rust Authenticode PKCS#7** builder for **PE + cleartext script** formats only, then expand—duplicate effort with `authenticode-rs` ecosystem; prefer **contributing upstream** or a thin wrapper.

### 6. Certificate selection helpers for Trusted Signing profiles

**PSA:** `CertificateHelper.GetAzureTrustedSigningCertificate` selects the leaf by **EKU OID prefix** `1.3.6.1.4.1.311.97.`.

**psign:** Users rely on **`--auto-select`** / thumbprint / subject filters.

**Plan:** When profile certs land in a store alongside others, add **`--eku-azure-trusted-signing`** (name TBD) or document thumbprint workflow; optional helper for **leaf selection** matching PSA behavior.

### 7. RFC3161 via raw HTTP (interop testing only)

**PSA:** Implements **RFC3161 request POST** with **`application/timestamp-query`** response handling in managed code.

**psign:** Uses **`SignerTimeStampEx3`** / crypto API.

**Plan:** Low priority **integration test** or **`psign-tool portable`** dev-only tool that speaks RFC3161 HTTP to compare tokens with Windows timestamp pipeline—only if timestamp discrepancies appear in parity reports.

## Suggested phase order

| Phase | Focus | Effort |
|-------|--------|--------|
| **A** | **Inspect / enumerate signatures** (nested + timestamp metadata) in CLI + portable | Medium |
| **B** | **Append vs PSA nested attribute** parity tests + docs | Small |
| **C** | **Trust policy** tweaks for expired leaf + RFC3161 vs PSA fixtures | Small–medium |
| **D** | **Azure Trusted Signing REST** sign-hash path (feature-gated) | Large |
| **E** | **ECDSA** Key Vault / cert signing where supported | Medium |

## References in PowerShell-OpenAuthenticode

- Providers: `ProviderFactory.cs` (`PEBinary`, `PowerShell`, `PowerShellMof`, `PowerShellXml`, `Appx`, `AppxBundle`).
- Signing / verification: `SignatureHelper.cs` (nested OID, `DecodeCms`, `CounterSign` RFC3161 HTTP).
- Trusted Signing REST: `Keys/AzureTrustedSigner.cs` (`CertificateProfileClient`).
- Azure KV cert bridge: `Keys/AzureKey.cs`, cmdlets docs `about_AuthenticodeAzureKeys.md`.
- Profile cert EKU: `CertificateHelper.cs`.
