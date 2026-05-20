# Migrating from AzureSignTool

This project can replace **AzureSignTool** for Windows signing when built with **`--features azure-kv-sign`**. **`psign-tool portable`** covers digest checks, verification, and (with **`--features azure-kv-sign-portable`**) Key Vault **`keys/sign`** on digest files plus PE Authenticode signing through **`portable sign-pe`** or the PE subset of **`--mode portable sign`**. Windows mode remains the broader native-shaped signing path.

**Azure Artifact Signing (Trusted Signing)** via Microsoft’s decoupled **`Azure.CodeSigning.Dlib.dll`** is **not** the Key Vault path: use **`--dlib`** / **`--trusted-signing-dlib-root`** with **`--dmdf`** only (never mixed with **`--azure-key-vault-url`**). See [`migration-artifact-signing.md`](migration-artifact-signing.md). PowerShell OpenAuthenticode overlap (inspect JSON, REST submit, EKU prefix selection) is summarized in [`psa-interoperability.md`](psa-interoperability.md).

## Signing (`psign-tool`)

Build:

```text
cargo build -p psign --features azure-kv-sign --release --bin psign-tool
```

Typical Azure-shaped invocation:

```text
psign-tool.exe sign ^
  --azure-key-vault-url https://myvault.vault.azure.net ^
  --azure-key-vault-certificate my-cert ^
  --azure-key-vault-managed-identity ^
  --timestamp-url http://timestamp.digicert.com ^
  --timestamp-digest sha256 ^
  --digest sha256 ^
  -ifl files.txt ^
  path\to\*.dll ^
  other.exe
```

### Flags mapped from AzureSignTool

| AzureSignTool | psign-tool |
|---------------|------------------|
| `-kvu` / `--azure-key-vault-url` | Same |
| `-kvc` | `--azure-key-vault-certificate` |
| `-kvcv` | `--azure-key-vault-certificate-version` |
| `-kvi`, `-kvs`, `-kvt` | Client credential trio |
| `-kva` | `--azure-key-vault-accesstoken` |
| `-kvm` | `--azure-key-vault-managed-identity` |
| `-au` | `--azure-authority` |
| `-tr`, `-td`, `-t`, `-fd`, `-d`, `-du`, `-ph`, `-nph`, `-as` | Existing sign flags (`--timestamp-url`, `--legacy-timestamp-url`, …) |
| `-ac` (repeatable) | `--ac` repeatable (`Vec`) |
| `-ifl` | `--input-file-list` |
| `-coe` | `--continue-on-error` |
| `-mdop` | `--max-degree-of-parallelism` |

**`-s` (skip signed)** in AzureSignTool conflicts with native **`/s` (certificate store name)** in this tool. Use **`--skip-signed`** instead.

### Authentication notes

- **Managed identity** calls the IMDS endpoint (`169.254.169.254`) with resource `https://vault.azure.net`, matching common VM/App Service scenarios.
- **Client credentials** use the v2.0 OAuth endpoint at `{authority}/{tenant}/oauth2/v2.0/token` with scope `https://vault.azure.net/.default`.
- **Access token** bypass (`-kva`) sends the bearer token directly to Key Vault REST.

Signing uses RSA PKCS#1 v1.5 over the file digest via Key Vault **`keys/sign`** (`RS256` / `RS384` / `RS512`). SHA-1 file digest is not supported on this path.

### Exit codes

AzureSignTool documents HRESULT-style batch exits (`README` **Exit Codes**):

| Outcome | Value |
|--------|------|
| Success | `0` |
| Partial success | `0x20000001` |
| All failed | `0xA0000002` |

Enable the same behavior directly on **`psign-tool`** with:

- **`--exit-codes azuresigntool`** (alias `azure`), or  
- Environment **`PSIGN_EXIT_CODES=azure`** (or `azuresigntool`).

The old helper executable name is no longer emitted; use **`psign-tool sign --exit-codes azure ...`** as the AzureSignTool replacement invocation, or set **`PSIGN_EXIT_CODES=azure`** for scripts that need an environment-level default.

Default **`signtool`** exit codes remain **`0` / `1` / `2`**.

### Linux / CI: portable PE signing with Key Vault

For Windows PE artifacts on Linux/macOS, use the portable PE signer. This assembles Authenticode CMS locally, asks Key Vault to sign the CMS authenticated-attribute digest, embeds the resulting PKCS#7 in the PE certificate table, and recomputes the PE checksum:

```bash
psign-tool portable sign-pe ./MyApp.exe \
  --azure-key-vault-url https://myvault.vault.azure.net \
  --azure-key-vault-certificate my-cert \
  --azure-key-vault-managed-identity \
  --timestamp-url http://timestamp.digicert.com \
  --timestamp-digest sha256 \
  --digest sha256 \
  --output ./MyApp.signed.exe
```

The native-shaped PE subset also works in-place:

```bash
psign-tool --mode portable sign \
  --azure-key-vault-url https://myvault.vault.azure.net \
  --azure-key-vault-certificate my-cert \
  --azure-key-vault-managed-identity \
  --timestamp-url http://timestamp.digicert.com \
  --timestamp-digest sha256 \
  --digest sha256 \
  ./MyApp.exe
```

The portable path currently supports PE/WinMD, SHA-2 digests, Key Vault signer certificates, optional **`--ac` / `--chain-cert`** certificates, and RFC3161 sign-time timestamping. Use **`psign-tool portable timestamp-pe-rfc3161`** as a second portable step only when you already have a timestamp token/response.

### Linux / CI: Key Vault **`keys/sign`** on a raw digest

For lower-level integrations, produce **`digest.bin`** with **`pe-digest`** / **`cab-digest`** (**`--encoding raw`**), then:

```bash
psign-tool portable azure-key-vault-sign-digest \
  --azure-key-vault-url https://myvault.vault.azure.net \
  --azure-key-vault-certificate my-cert \
  --digest-file digest.bin \
  --digest-algorithm sha256 \
  --azure-key-vault-managed-identity
```

Stdout prints **standard base64** signature bytes (no PEM). **`--signature-output PATH`** writes **raw** signature. **ECDSA** certificates use **ES256** / **ES384** / **ES512** automatically for the digest-only helper. Portable PE signing currently requires an RSA Key Vault certificate because Authenticode CMS emission uses RSA PKCS#1 v1.5.

**CMS signer digest vs subject (file layout) digest:** **`pe-digest`**, **`cab-digest`**, and the MSI installer fingerprint path behind **`verify-msi`** hash **subject layout** — **not** the **32-byte** **`RS256`** input over **`SignerInfo.signedAttrs`**. AzureSignTool’s **`CryptMsg`** path signs **authenticated attributes**; for **RSA SHA-256** the Key Vault **`RS256`** **`value`** is **SHA-256** over that attribute **`SET`** — on PE use **`pe-signer-rs256-prehash --encoding raw`** (**`--index`** = PKCS#7 row, **`--signer-index`** = **`SignerInfo`**); on signed **`.cab`** use **`cab-signer-rs256-prehash`** (or **`extract-cab-pkcs7`** then **`pkcs7-signer-rs256-prehash`**); on **`.msi`** use **`msi-signer-rs256-prehash`** (or **`extract-msi-pkcs7`** then **`pkcs7-signer-rs256-prehash`**); on raw PKCS#7 **`.cat`** bodies use **`catalog-signer-rs256-prehash`** (same bytes as **`pkcs7-signer-rs256-prehash`**). If PKCS#7 is already in a file, use **`pkcs7-signer-rs256-prehash --signer-index N --encoding raw`**. Library parity is tested in **`psign-sip-digest`** (`rsa_pkcs1v15_signed_attrs_verify`).

**Experimental (Linux PE layout only):** **`psign-tool portable append-pe-pkcs7`** appends prebuilt PKCS#7 DER as a new **`WIN_CERTIFICATE`** row and recomputes **`CheckSum`**. Use **`pe-checksum --strict`** on the output to gate ImageHlp-style checksum parity.

## Verification with **`psign-tool portable`**

AzureSignTool does not verify signatures. After signing on Windows, use portable verification on Linux/macOS CI agents where helpful, for example:

```text
psign-tool portable verify-pe -- <artifact>
```

For **trust** validation with **explicit anchors** (no OS certificate store), use **`trust-verify-pe`** (or format-specific **`trust-verify-*`** commands). Short-lived signing certificates—common with Artifact Signing profiles—**need RFC3161 timestamping** at sign time so signatures remain verifiable after the leaf expires; combine digest checks with timestamp-aware trust options when applicable:

```text
psign-tool portable trust-verify-pe ./artifact.exe \
  --prefer-timestamp-signing-time \
  --require-valid-timestamp \
  --anchor-dir ./anchors \
  --authroot-cab ./authroot.stl.cab
```

Optional **`--as-of YYYY-MM-DD`** fixes the verification instant for reproducible CI. More background and flag mapping: [`migration-artifact-signing.md`](migration-artifact-signing.md#portable-post-sign-verification).

Use the appropriate portable subcommands for your format (`verify-pe`, catalog checks, **`artifact-signing-metadata-check`** for JSON templates, etc.) as documented in that crate.

## Integration testing

Automated CI uses **`psign-server azure-key-vault-server`** as a local Key Vault replacement. Non-ignored E2E tests cover both **`psign-tool portable azure-key-vault-sign-digest`** and full portable PE signing through **`portable sign-pe`** / **`--mode portable sign`** with a dummy access token, then verify the embedded Authenticode signature without contacting Azure.
