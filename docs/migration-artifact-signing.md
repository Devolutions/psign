# Azure Trusted Signing (Artifact Signing) with psign-tool

Microsoft **Artifact Signing** (often called **Trusted Signing**) integrates with native **SignTool** through a **decoupled digest DLL** (`Azure.CodeSigning.Dlib.dll`) and a **JSON metadata file** consumed via **`/dmdf`**. Official setup: [Set up signing integrations](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations) and the [Microsoft.ArtifactSigning.Client](https://www.nuget.org/packages/Microsoft.ArtifactSigning.Client) package.

**psign-tool** uses the same Win32 bridge as SignTool: **`SignerSignEx3`** with **`SIGNER_DIGEST_SIGN_INFO`** pointing at the DLL exports (this repo prefers **`AuthenticodeDigestSignExWithFileHandle`** when present, matching Microsoft’s Azure dlib).

**psign-tool portable** cannot load the mixed-mode/.NET dlib or call **`SignerSignEx3`**. For PE/WinMD, CAB, MSI/MSP, flat MSIX/AppX packages, and generic catalogs, it can now avoid Microsoft client-side signing tools entirely by building CMS locally, asking Artifact Signing REST to sign the CMS authenticated-attributes digest, and embedding the returned PKCS#7. Other SIP formats, MSIX/AppX bundles/uploads, and encrypted packages still use Windows mode or the dlib bridge until their portable embedders are implemented.

### Azure Code Signing **REST** hash signing

PowerShell OpenAuthenticode can sign via the **`Azure.CodeSigning.Sdk`** client against the same **data-plane** API documented in Azure REST specs (**`CertificateProfileOperations_Sign`**, host template **`https://{region}.codesigning.azure.net/`**, OAuth scope **`https://codesigning.azure.net/.default`**).

With **`cargo build -p psign --features artifact-signing-rest --bin psign-tool`**, the low-level helper remains available:

```powershell
psign-tool.exe artifact-signing-submit `
  --region westus `
  --account-name myAccount `
  --profile-name myProfile `
  --digest-file .\digest.sha256.bin `
  --signature-algorithm RS256 `
  --managed-identity
```

This runs the **`:sign`** LRO and prints the final JSON. The helper accepts both the current stable wrapped result shape (`result.signature`, `result.signingCertificate`) and older top-level test/service shapes.

#### Linux / CI: same REST helper from **`psign-tool portable`**

Build or install with **`--features artifact-signing-rest`**, then use **`artifact-signing-submit`** with the same flags as Windows when you need a low-level digest-to-signature call.

**Do not confuse digest roles:** **`pe-digest`** is the **PE Authenticode image** fingerprint (typical **`:sign`** subject-hash samples for **unsigned** binaries). **`pe-signer-rs256-prehash --encoding raw`** is the **CMS RFC 5652 §5.4** **SHA-256** over the signer’s authenticated-attribute **`SET`** — the raw input Azure Key Vault **`keys/sign`** uses for **`RS256`** when you are re-signing **`SignerInfo`** on an **embedded PKCS#7** (see [`migration-azuresigntool.md`](migration-azuresigntool.md)). Trusted Signing **`:sign`** contracts follow Microsoft’s profile/docs; use the digest shape your integration expects.

```bash
cargo build -p psign-digest-cli --features artifact-signing-rest --locked
./target/debug/psign-tool portable pe-signer-rs256-prehash --encoding raw --output digest.bin ./MyApp.signed-template.exe
./target/debug/psign-tool portable artifact-signing-submit \
  --region westus --account-name myAccount --profile-name myProfile \
  --digest-file digest.bin --signature-algorithm RS256 --managed-identity
```

Optional debug logs: **`SIGNTOOL_PORTABLE_DEBUG=1`**.

## Pure REST portable signing (no Microsoft client tools)

For PE/WinMD, prefer the first-class portable signer instead of manually staging a digest:

```bash
psign-tool portable sign-pe ./MyApp.exe \
  --artifact-signing-metadata ./artifact-signing-metadata.json \
  --artifact-signing-managed-identity \
  --timestamp-url http://timestamp.acs.microsoft.com/ \
  --timestamp-digest sha256 \
  --digest sha256 \
  --output ./MyApp.signed.exe
```

The native-shaped in-place form is also available:

```bash
psign-tool --mode portable sign \
  --dmdf ./artifact-signing-metadata.json \
  --artifact-signing-managed-identity \
  --timestamp-url http://timestamp.acs.microsoft.com/ \
  --timestamp-digest sha256 \
  --digest sha256 \
  ./MyApp.exe
```

Authentication choices are mutually exclusive when explicit: use **`--artifact-signing-access-token`**, **`--artifact-signing-managed-identity`** (optionally with **`--artifact-signing-client-id`** or **`--artifact-signing-managed-identity-resource-id`** for user-assigned identities), the service-principal trio **`--artifact-signing-tenant-id`**, **`--artifact-signing-client-id`**, and **`--artifact-signing-client-secret`**, or workload identity with **`--artifact-signing-credential-type workload-identity`** plus tenant/client/token-file inputs or the standard **`AZURE_TENANT_ID`**, **`AZURE_CLIENT_ID`**, and **`AZURE_FEDERATED_TOKEN_FILE`** environment variables. If no explicit credential is supplied, the in-tree Rust default chain tries environment client-secret credentials, workload identity, then managed identity while honoring metadata **`ExcludeCredentials`**. Without metadata, pass **`--artifact-signing-endpoint`** or **`--artifact-signing-region`** plus **`--artifact-signing-account-name`** and **`--artifact-signing-profile-name`**.

Artifact Signing certificates are short-lived; include **`--timestamp-url http://timestamp.acs.microsoft.com/ --timestamp-digest sha256`** for production signatures. Portable PE/WinMD, CAB, MSI/MSP, generic catalog, and flat MSIX/AppX Artifact Signing paths attach RFC3161 tokens to the generated Authenticode PKCS#7 when the `timestamp-http` feature is enabled.

CAB, MSI/MSP, and generic catalogs can use the same Artifact Signing profile through scoped portable commands:

```bash
psign-tool portable sign-cab ./setup.cab \
  --artifact-signing-metadata ./artifact-signing-metadata.json \
  --artifact-signing-managed-identity \
  --timestamp-url http://timestamp.acs.microsoft.com/ \
  --timestamp-digest sha256 \
  --digest sha256 \
  --output ./setup.signed.cab

psign-tool portable sign-msi ./installer.msi \
  --artifact-signing-metadata ./artifact-signing-metadata.json \
  --artifact-signing-managed-identity \
  --digest sha256 \
  --output ./installer.signed.msi

psign-tool portable sign-catalog \
  --artifact-signing-metadata ./artifact-signing-metadata.json \
  --artifact-signing-managed-identity \
  --digest sha256 \
  --output ./files.cat \
  ./file1.exe ./file2.txt
```

The native-shaped in-place portable `sign` route also supports CAB, MSI/MSP, and flat `.msix` / `.appx` packages with Artifact Signing options. Catalog authoring still uses `portable sign-catalog` because a `.cat` target alone does not describe the member list to author. MSIX/AppX bundle, upload, and encrypted containers remain explicitly unsupported in portable final signing.

For native-shaped batches, the portable Artifact Signing route accepts the AzureSignTool-style convenience flags:

```bash
psign-tool --mode portable sign \
  --dmdf ./artifact-signing-metadata.json \
  --artifact-signing-managed-identity \
  --digest sha256 \
  --input-file-list ./files-to-sign.txt \
  --skip-signed \
  --continue-on-error \
  --max-degree-of-parallelism 4
```

`--input-file-list` accepts one path or glob per line; blank lines and `#` comments are ignored. `--skip-signed` skips PE/WinMD files only when existing Authenticode digest verification succeeds, and also skips CAB, MSI/MSP, and flat MSIX/AppX files that already contain embedded signature material. `--continue-on-error` preserves per-file failure diagnostics and returns a non-zero batch exit code when any target fails.

## Flag mapping (Microsoft sample → psign-tool)

| SignTool / docs | psign-tool |
|-----------------|------------------|
| `/dlib` path to `Azure.CodeSigning.Dlib.dll` | `--dlib <path>` |
| Same, but NuGet extract root | `--trusted-signing-dlib-root <root>` → resolves to `<root>\bin\x64\Azure.CodeSigning.Dlib.dll` or `<root>\bin\x86\...` matching **this executable’s** architecture (`cfg!(target_pointer_width)`) |
| `/dmdf` metadata JSON | Windows dlib: `--dmdf <path>`; portable REST PE: `--dmdf <path>` or `--artifact-signing-metadata <path>` |
| `/fd SHA256` | `--digest sha256` |
| `/tr` RFC3161 URL | `--timestamp-url <url>` |
| `/td SHA256` | `--timestamp-digest sha256` |

**`--dlib` and `--trusted-signing-dlib-root` are mutually exclusive** (Clap `conflicts_with`).

### Example (PE)

Adjust paths to your extracted NuGet layout and metadata file:

```powershell
psign-tool.exe sign `
  --digest sha256 `
  --timestamp-url http://timestamp.acs.microsoft.com/ `
  --timestamp-digest sha256 `
  --trusted-signing-dlib-root "D:\pkgs\Microsoft.ArtifactSigning.Client\extracted" `
  --dmdf "D:\configs\artifact-signing-metadata.json" `
  --auto-select `
  .\MyApp.exe
```

Or pass the DLL explicitly:

```powershell
psign-tool.exe sign `
  --digest sha256 `
  --timestamp-url http://timestamp.acs.microsoft.com/ `
  --timestamp-digest sha256 `
  --dlib "D:\pkgs\...\bin\x64\Azure.CodeSigning.Dlib.dll" `
  --dmdf "D:\configs\artifact-signing-metadata.json" `
  --auto-select `
  .\MyApp.exe
```

Microsoft recommends **`http://timestamp.acs.microsoft.com/`** with **`SHA256`** timestamp digest for **short-lived profile certificates** so signatures remain verifiable after the signing certificate expires.

### Metadata JSON (`--dmdf`)

Follow Microsoft’s documented shape: regional **`Endpoint`**, **`CodeSigningAccountName`**, **`CertificateProfileName`**, and optionally **`ExcludeCredentials`** (array of credential type names to exclude from the Rust default chain, such as **`EnvironmentCredential`**, **`WorkloadIdentityCredential`**, or **`ManagedIdentityCredential`**). Keep **`Endpoint`** aligned with your Artifact Signing region.

Validate checked-in templates **without signing** using portable **`artifact-signing-metadata-check`**:

```bash
psign-tool portable artifact-signing-metadata-check --path ./artifact-signing-metadata.json
# or
cat ./artifact-signing-metadata.json | psign-tool portable artifact-signing-metadata-check
```

## Runtime layout: NuGet `bin\x64` or `bin\x86`

Deploy the **full** `bin\x64` or `bin\x86` folder from the NuGet package next to **`Azure.CodeSigning.Dlib.dll`** (dependent assemblies and loaders). The process loading the dlib must find those DLLs—typically by keeping the **working directory** or **DLL search path** consistent with how you extracted the package.

Prerequisites:

- **.NET 8** runtime where Microsoft’s tooling expects it.
- **Architecture match**: use **x64** dlib with **64-bit** `psign-tool`, **x86** with **32-bit** builds. Mismatch commonly surfaces as **`LoadLibraryW` failures** (see troubleshooting).

### Troubleshooting `LoadLibraryW` failures

When **`--dlib`** (or the path resolved from **`--trusted-signing-dlib-root`**) fails to load, verify:

1. **.NET 8** is installed and repairable on the machine.
2. The **entire** `bin\<arch>` directory from the NuGet package is deployed so dependent DLLs resolve.
3. **PE architecture** of **`Azure.CodeSigning.Dlib.dll`** matches **`psign-tool`** (x64 vs x86).

## Conflict matrix: Artifact Signing vs Azure Key Vault

**Artifact Signing** uses **decoupled digest** mode only (**`--dlib`** or **`--trusted-signing-dlib-root`** **+** **`--dmdf`**).

**Azure Key Vault** signing (**`--azure-key-vault-url`** and related flags) is a **separate** implementation path. **`psign-tool` rejects combining Key Vault options with `--dlib`, `--dmdf`, or `--trusted-signing-dlib-root`.**

If your team uses both workflows, keep them on **different invocations** or build targets—do not mix flags on one command line.

For migrating from **AzureSignTool** (KV-focused CLI), see [`migration-azuresigntool.md`](migration-azuresigntool.md).

## Portable post-sign verification

On Linux/macOS (or Windows without the dlib), use **`psign-tool portable`** after the signed artifact exists:

1. **`verify-pe`** — PKCS#7 indirect digest vs recomputed PE digest (no trust anchors).
2. **`trust-verify-pe`** — CMS validation **plus** portable trust using the automatic AuthRoot cache or explicit anchors (**`--anchor-dir`**, **`--authroot-cab`**) and policy options.

Short-lived signing certificates **require a valid RFC3161 timestamp** for verification long after profile expiry. Combine digest verification with trust verification options such as:

- **`--prefer-timestamp-signing-time`** — prefer timestamp token time for **`exact_date`**-style checks.
- **`--require-valid-timestamp`** — fail if portable extraction finds neither a nested RFC3161 **`TSTInfo.genTime`** nor PKCS#9 **`signing-time`** (use with **`--prefer-timestamp-signing-time`**). With **`--as-of`**, the verification instant is pinned and **timestamp presence is not enforced** on that path (see **`authenticode-trust-stack.md`**).
- **`--as-of YYYY-MM-DD`** — reproducible verification date.
- **`--anchor-dir`** / **`--authroot-cab`** — supply roots explicitly for enterprise anchors or reproducible pinned CABs (portable path does not use the OS store).

Example:

```bash
psign-tool portable verify-pe ./MyApp.exe
psign-tool portable trust-verify-pe ./MyApp.exe \
  --prefer-timestamp-signing-time \
  --require-valid-timestamp \
  --anchor-dir ./anchors \
  --authroot-cab ./authroot.stl.cab
```

## MSIX / APPX

MSIX uses the same **`SignerSignEx3`** SIP stack and the same decoupled **`--dlib` / `--dmdf`** bridge. **`--page-hashes`** for MSIX requires decoupled digest inputs. See also [`rust-sip-spec-refs.md`](rust-sip-spec-refs.md).

## CI / gated parity recipe

Optional integration test (ignored by default) exercises decoupled signing when environment variables point at real fixtures. See **`artifact_signing_decoupled_pe_executes`** in [`tests/parity_signtool.rs`](../tests/parity_signtool.rs) and the **Artifact Signing** row in [`ci-parity.md`](ci-parity.md).

Required-style variables when running that test locally:

| Variable | Purpose |
|----------|---------|
| `PSIGN_ARTIFACT_SIGNING_UNSIGNED_PE` | Unsigned PE to copy and sign |
| `PSIGN_ARTIFACT_SIGNING_METADATA` | Path to `--dmdf` JSON |
| `PSIGN_ARTIFACT_SIGNING_DLIB` | Explicit `--dlib` path (**or** use root below) |
| `PSIGN_ARTIFACT_SIGNING_DLIB_ROOT` | NuGet extract root for `--trusted-signing-dlib-root` |
| `PSIGN_ARTIFACT_SIGNING_TIMESTAMP_URL` | RFC3161 URL (e.g. ACS) |
| `PSIGN_ARTIFACT_SIGNING_TEST_PFX` | PFX for cert selection in this tool’s store/PFX path |
| `PSIGN_ARTIFACT_SIGNING_TEST_PFX_PASSWORD` | Optional PFX password |

Either **`PSIGN_ARTIFACT_SIGNING_DLIB`** or **`PSIGN_ARTIFACT_SIGNING_DLIB_ROOT`** must be set; the test prefers **`_DLIB`** when both are present.

<a id="rest-hash-signing-gated-smoke-test"></a>

### REST hash signing (gated smoke test)

Automated CI does not need a real Trusted Signing account for REST submit coverage. **`psign-server artifact-signing-server`** serves a local **`:sign`** endpoint and pollable operation URL; feature-gated E2E tests call **`psign-tool portable artifact-signing-submit`** and, on Windows, **`psign-tool artifact-signing-submit`** with the local endpoint override.

Build with **`--features artifact-signing-rest`**, then run the ignored test **`artifact_signing_rest_submit_smoke`** when you have a **Trusted Signing** account and a **raw digest file** (for example **32 bytes** for SHA-256):

```powershell
cargo test -p psign --features artifact-signing-rest `
  --test parity_signtool artifact_signing_rest_submit_smoke -- --ignored --nocapture
```

| Variable | Purpose |
|----------|---------|
| `PSIGN_ARTIFACT_SIGNING_REST_REGION` | Regional segment (e.g. `westus`) |
| `PSIGN_ARTIFACT_SIGNING_REST_ACCOUNT_NAME` | Code signing account name |
| `PSIGN_ARTIFACT_SIGNING_REST_PROFILE_NAME` | Certificate profile name |
| `PSIGN_ARTIFACT_SIGNING_REST_DIGEST_FILE` | Path to raw digest bytes |
| `PSIGN_ARTIFACT_SIGNING_REST_SIGNATURE_ALGORITHM` | Optional (default API/`RS256`) |

Authentication (**one** path):

| Variable | Purpose |
|----------|---------|
| `PSIGN_ARTIFACT_SIGNING_REST_ACCESS_TOKEN` | Bearer token for **`https://codesigning.azure.net/.default`** |
| `PSIGN_ARTIFACT_SIGNING_REST_MANAGED_IDENTITY` | Set to **`1`** / **`true`** / **`yes`** for IMDS (VMs/containers) |
| `PSIGN_ARTIFACT_SIGNING_REST_TENANT_ID` | With client credentials or workload identity |
| `PSIGN_ARTIFACT_SIGNING_REST_CLIENT_ID` | With client credentials, workload identity, or user-assigned managed identity |
| `PSIGN_ARTIFACT_SIGNING_REST_CLIENT_SECRET` | With client credentials |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Environment credential used by the Rust default chain |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE` | Workload identity credential used by the Rust default chain |
| `AZURE_MANAGED_IDENTITY_CLIENT_ID` | User-assigned managed identity client ID used by the Rust default chain |
