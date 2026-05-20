# MSI PKCS#7 stub (CI / RS256 parity)

- **`tiny-pkcs7-stub.msi`**: minimal **OLE compound** (CFB) whose only meaningful content is root stream **`\u{5}DigitalSignature`** = first PKCS#7 from **`tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi`**.

This is **not** a real signed Windows Installer database: **`verify-msi`** fails (SIP fingerprint ≠ PKCS#7 indirect digest). It exists so Linux CI can exercise **`extract-msi-pkcs7`**, **`msi-signer-rs256-prehash`**, and cross-check the same **32-byte** **`RS256`** prehash as **`pe-signer-rs256-prehash`** on **`tiny32.signed.efi`**.

Regenerate:

```powershell
cargo run -p psign-sip-digest --bin psign-gen-msi-signature-stub -- `
  tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi `
  tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi
```
