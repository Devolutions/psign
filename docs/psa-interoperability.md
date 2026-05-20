# Interoperability with PowerShell OpenAuthenticode

[PowerShell OpenAuthenticode](https://github.com/jborean93/PowerShell-OpenAuthenticode) (**PSA**) uses portable **.NET CMS** (`SignedCode`) for signing and verification. **`psign`** uses **`SignerSignEx3`** on Windows and **`psign-tool portable`** / **`psign-authenticode-trust`** for digest + optional anchor trust off-Windows.

This note maps PSA behaviors to this repo; see also [`plan-openauthenticode-parity.md`](plan-openauthenticode-parity.md).

## Verification and trust

| PSA | psign / portable |
|-----|-------------------------|
| **`Get-OpenAuthenticodeSignature`** (nested PKCS#7 walk + timestamp OIDs) | **`psign-tool portable inspect-authenticode`** or **`psign-tool inspect-signature`** — JSON from **`psign-authenticode-trust`** (`inspect_pe_authenticode`, `inspect_authenticode_pkcs7_der`) |
| **`-SkipCertificateCheck`** (CMS signature check without full chain policy) | **`psign-tool portable trust-verify-*`** with **`--allow-loose-signing-cert`** (`AuthenticodeTrustPolicy::ignore_signing_certificate_check`) plus explicit **`--anchor-dir`** / **`--authroot-cab`** |
| Timestamp-aware validity for **expired leaf** certs | **`--prefer-timestamp-signing-time`**, **`--require-valid-timestamp`**, **`--as-of`** on **`trust-verify-*`** |
| No revocation in PSA README | Portable trust path does **not** aim to replace OS revocation; **`psign-tool verify`** follows **`WinVerifyTrust`** |

## Signing

| PSA | psign |
|-----|-------------|
| **Azure Trusted Signing** via **`Azure.CodeSigning.Sdk`** REST | **`artifact-signing-submit`** (with **`--features artifact-signing-rest`**) — same data-plane **`CertificateProfileOperations_Sign`** LRO as swagger **`2023-06-15-preview`**; **plus** existing **`--dlib`** / **`--trusted-signing-dlib-root`** decoupled path |
| **Azure Key Vault** | **`--azure-key-vault-url`** path (**`--features azure-kv-sign`**) — RSA **and EC** leaf certs (`RS256`/`ES256`-style JWA algorithms) |
| Select Trusted Signing profile leaf by EKU prefix **`1.3.6.1.4.1.311.97.`** | **`--signing-cert-eku-prefix`** when selecting from a certificate store |

## Appendix signatures

PSA **`Add-OpenAuthenticodeSignature`** nests PKCS#7 under OID **`1.3.6.1.4.1.311.2.4.1`**. **`psign-tool sign --append-signature`** follows the same **`SIG_APPEND`**/`SignerSignEx3` behavior; the parity test **`append_signature_pe_nested_pkcs7_visible_to_inspector`** (ignored; requires fixtures) asserts nested blobs appear in **`inspect-pe`** JSON output.
