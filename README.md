# psign

`psign` is a **Rust port** of the Windows SDK **`signtool.exe`** behavior
(sign, verify, timestamp, remove, and related Authenticode flows), validated with
differential parity tests against the native tool where CI fixtures allow.

Canonical repository: <https://github.com/Devolutions/psign>.

## CLI surface

- `verify`, `remove`, `catdb`: Windows-compatible `signtool.exe` flows backed by WinTrust and CryptSIP where native APIs are required.
- `sign`: Rust mssign32 core (`SignerSignEx3`) with PFX/system-store cert selection, RFC3161 sign-time timestamping, first-class custom ZIP Authenticode support ([docs/zip-authenticode-signing.md](docs/zip-authenticode-signing.md)), and decoupled-digest bridge flow (`--dlib` or `--trusted-signing-dlib-root` + `--dmdf`) for MSIX parity and [Azure Artifact Signing / Trusted Signing](docs/migration-artifact-signing.md).
- `inspect-signature`: JSON dump of PKCS#7 signers, timestamp OIDs, and nested signatures (`1.3.6.1.4.1.311.2.4.1`) — same parser as **`psign-tool portable inspect-authenticode`** ([docs/psa-interoperability.md](docs/psa-interoperability.md)).
- `timestamp`: Rust mssign32 core (`SignerTimeStampEx3`/`SignerTimeStampEx2`) plus AppX restrictions.
- `rdp`: Rust port of **`rdpsign.exe`** for `.rdp` files (`SignScope` / `Signature` records, detached PKCS#7 over the secure-settings blob).
- `cert-store`: Portable file-backed certificate store under `~/.psign/cert-store` by default, with Windows-style store/thumbprint selection.
- `code`: dotnet/sign-style orchestration entry point. It supports `--dry-run` / `--plan-json` planning over inputs, file lists, globs, and nested ZIP/OPC containers, plus guarded local cert/key, PFX, portable cert-store SHA-1, Azure Key Vault, or Artifact Signing execution for PE/WinMD, NuGet/SNuGet, VSIX, generic ZIP nested package entries, MSIX/AppX unsigned-package prepare including nested packages inside upload/bundle containers, encrypted MSIX/AppX OS-only diagnostics, ClickOnce `.manifest` / `.application` / `.vsto` XMLDSig signing, PE-like ClickOnce `.deploy` payloads, App Installer publisher updates + top-level or nested companion signatures, `--continue-on-error`, `--skip-signed`, `--overwrite`, and inside-out VSIX/ZIP -> NuGet/VSIX -> PE/ClickOnce-manifest signing.
- `portable ...`: Cross-platform digest, verification, trust, signing, package, RFC3161, and remote-hash helpers that avoid Win32 APIs, including PE/WinMD signing through Azure Artifact Signing REST without Microsoft client DLLs.

## MSIX parity notes

- MSIX/AppX signing requires `--timestamp-url` in the current parity profile.
- Sign-time digest controls now distinguish file digest (`--digest`, native `/fd`) and RFC3161 timestamp digest (`--timestamp-digest`, native `/td`).
- Decoupled digest inputs (`--dlib` + `--dmdf`) are executed via a native-signature bridge path and parity-gated in CI scenarios.

## Build

```powershell
cargo build
```

At the repo root, **`cargo build`** targets **`default-members`**, including the unified **`psign-tool`** executable from `src\main.rs` plus the portable digest / trust / package / REST crates. On Windows, **`cargo build -p psign --bin psign-tool`** remains the explicit way to build only that executable. Default Cargo features include **`azure-kv-sign`** (Key Vault digest callback), **`artifact-signing-rest`** (**`artifact-signing-submit`** LRO against **`*.codesigning.azure.net`**), **`timestamp-http`** (portable RFC3161 HTTP POST), and **`timestamp-server`** (local RFC3161 test server); use **`--no-default-features`** for a minimal build.

## Dotnet tool package from NuGet.org (.NET 10+)

`psign-tool` is published as the RID-specific
[`Devolutions.Psign.Tool`](https://www.nuget.org/packages/Devolutions.Psign.Tool)
dotnet tool package:

```powershell
dotnet tool install -g Devolutions.Psign.Tool
psign-tool --help
```

Update an existing global install:

```powershell
dotnet tool update -g Devolutions.Psign.Tool
```

One-shot execution from NuGet.org:

```powershell
dotnet tool exec Devolutions.Psign.Tool -- --help
dnx Devolutions.Psign.Tool --help
```

For repository-local tool manifests, omit `-g`:

```powershell
dotnet new tool-manifest
dotnet tool install Devolutions.Psign.Tool
dotnet tool run psign-tool -- --help
```

Create local dotnet tool packages from prebuilt release artifacts:

```powershell
pwsh ./nuget/pack-psign-dotnet-tool.ps1 -Version 0.3.0 -ArtifactsRoot ./dist -OutputDir ./dist/nuget
```

The package is built from native `psign-tool` artifacts for `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `osx-x64`, and `osx-arm64`, plus an `any` fallback package for unsupported runtimes.

## Linux / portable tooling

The canonical **`psign-tool`** CLI (package **`psign`**) supports an optional backend selector: **`--mode auto|windows|portable`**. When omitted, **`auto`** is used; **`PSIGN_TOOL_MODE`** can set the same default for parity automation. Windows mode uses Win32 APIs and registered SIP DLLs. Portable mode and the **`psign-tool portable ...`** namespace use the cross-platform Rust implementations from **`psign-sip-digest`**, **`psign-authenticode-trust`**, **`psign-opc-sign`**, **`psign-codesigning-rest`**, and **`psign-azure-kv-rest`** without **`WinVerifyTrust`** or the OS trust store.

**Feature gaps vs native `signtool`, AzureSignTool, and Azure Artifact Signing:** [`docs/gap-analysis-signing-platforms.md`](docs/gap-analysis-signing-platforms.md). **Linux workflows (verify, REST hash sign, hybrid embed):** [`docs/linux-signing-pipelines.md`](docs/linux-signing-pipelines.md). For Key Vault **`RS256`** over CMS authenticated attributes (not the PE image hash), use **`psign-tool portable pe-signer-rs256-prehash`** — see [`docs/migration-azuresigntool.md`](docs/migration-azuresigntool.md).

From the repo root (see [`docs/roadmap-authenticode-linux.md`](docs/roadmap-authenticode-linux.md)):

```sh
cargo build -p psign --bin psign-tool --locked
# Portable RDP signing:
# psign-tool portable rdp --cert cert.der --key key.pk8 file.rdp
# Portable PE signing with a local RSA key:
# psign-tool portable sign-pe --cert cert.der --key key.pk8 --output signed.exe unsigned.exe
# Portable trust verification with explicit anchors:
# psign-tool portable trust-verify-pe signed.exe --anchor-dir anchors
# Portable custom ZIP Authenticode verification:
# psign-tool portable trust-verify-zip archive.zip --anchor-dir anchors
# Portable unsigned CAB signing with a local RSA key:
# psign-tool portable sign-cab --cert cert.der --key key.pk8 --output signed.cab unsigned.cab
# Portable MSI/MSP signing with a local RSA key:
# psign-tool portable sign-msi --cert cert.der --key key.pk8 --output signed.msi unsigned.msi
# Portable generic catalog signing with a local RSA key:
# psign-tool portable sign-catalog --cert cert.der --key key.pk8 --output files.cat file1.exe file2.txt
# Portable RFC3161 timestamp token embedding after signing:
# psign-tool portable timestamp-pe-rfc3161 signed.exe --response timestamp.tsr --output timestamped.exe
# Portable package inspection helpers:
# psign-tool portable nupkg-signature-info package.nupkg
# psign-tool portable nupkg-digest package.nupkg --algorithm sha256
# psign-tool portable nupkg-signature-content package.nupkg --output signature-content.txt
# psign-tool portable nupkg-signature-pkcs7 package.nupkg --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output signature.p7s
# psign-tool portable nupkg-signature-pkcs7-prehash package.nupkg --encoding raw --output prehash.bin
# psign-tool portable nupkg-signature-pkcs7-from-signature package.nupkg --cert signer.der --signature remote.sig --output signature.p7s
# psign-tool portable nupkg-verify-signature-content package.nupkg --content signature-content.txt
# psign-tool portable nupkg-embed-signature package.nupkg --signature signature.p7s --output signed.nupkg
# psign-tool portable nupkg-sign package.nupkg --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output signed.nupkg
# psign-tool portable nupkg-verify-signature signed.nupkg --trusted-ca signer.der --allow-loose-signing-cert
# psign-tool portable vsix-signature-info extension.vsix
# psign-tool portable vsix-signature-reference-xml extension.vsix --output signature-reference.xml
# psign-tool portable vsix-verify-signature-reference-xml extension.vsix --signature-xml signature-reference.xml
# psign-tool portable vsix-signature-xml extension.vsix --cert signer.der --key signer.pkcs8 --output signature.xml
# psign-tool portable vsix-signature-xml-prehash extension.vsix --encoding raw --output prehash.bin
# psign-tool portable vsix-signature-xml-from-signature extension.vsix --cert signer.der --signature remote.sig --output signature.xml
# psign-tool portable vsix-verify-signature-xml extension.vsix --signature-xml signature.xml --cert signer.der --trusted-ca root.der
# psign-tool portable vsix-embed-signature-xml extension.vsix --signature-xml signature.xml --output signed.vsix
# psign-tool portable vsix-sign extension.vsix --cert signer.der --key signer.pkcs8 --output signed.vsix
# psign-tool portable vsix-verify-signature signed.vsix --trusted-ca root.der
# psign-tool portable appinstaller-info app.appinstaller --signature app.appinstaller.p7
# psign-tool portable appinstaller-sign-companion app.appinstaller --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output app.appinstaller.p7
# psign-tool portable appinstaller-sign-companion-prehash app.appinstaller --encoding raw --output prehash.bin
# psign-tool portable appinstaller-sign-companion-from-signature app.appinstaller --cert signer.der --signature remote.sig --output app.appinstaller.p7
# psign-tool portable appinstaller-verify-companion app.appinstaller --signature app.appinstaller.p7 --anchor-dir anchors
# psign-tool portable appinstaller-set-publisher app.appinstaller --publisher "CN=Example" --output updated.appinstaller
# psign-tool portable business-central-app-info package.app
# psign-tool portable msix-manifest-info package.msix
# psign-tool portable msix-set-publisher package.msix --publisher "CN=Example" --output updated.msix
# psign-tool portable clickonce-deploy-info app.exe.deploy
# psign-tool portable clickonce-copy-deploy-payload app.exe.deploy --output app.exe
# psign-tool portable clickonce-update-manifest-hashes app.exe.manifest --base-directory . --output updated.manifest
# psign-tool portable clickonce-manifest-hashes updated.manifest --base-directory .
# psign-tool portable clickonce-sign-manifest updated.manifest --cert signer.der --key signer.pkcs8 --output signed.manifest
# psign-tool portable clickonce-sign-manifest-prehash updated.manifest --encoding raw --output prehash.bin
# psign-tool portable clickonce-sign-manifest-from-signature updated.manifest --cert signer.der --signature remote.sig --output signed.manifest
# psign-tool portable clickonce-verify-manifest-signature signed.manifest --trusted-ca signer.der
# dotnet/sign-style dry-run planning for nested package orchestration:
# psign-tool code --dry-run --plan-json --base-directory . --file-list files.txt
# Initial guarded code execution for PE/NuGet/VSIX/ZIP/MSIX/ClickOnce/App Installer inputs:
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.exe app.exe
# psign-tool code --base-directory . --pfx signer.pfx --password "pfx-password" --output signed.nupkg package.nupkg
# psign-tool code --base-directory . --cert-store-dir ~/.psign/cert-store --sha1 <thumbprint> --output signed.nupkg package.nupkg
# psign-tool code --base-directory . --azure-key-vault-url https://vault.vault.azure.net --azure-key-vault-certificate cert --azure-key-vault-accesstoken "$TOKEN" --output signed.nupkg package.nupkg
# psign-tool code --base-directory . --artifact-signing-endpoint https://wus2.codesigning.azure.net --artifact-signing-account-name acct --artifact-signing-profile-name profile --artifact-signing-access-token "$TOKEN" --output signed.nupkg package.nupkg
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output signed.nupkg package.nupkg
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.vsix extension.vsix
# psign-tool code --base-directory . --overwrite --cert signer.der --key signer.pkcs8 --output resigned.nupkg signed-package.nupkg
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.zip package-bundle.zip
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --publisher-name "CN=Publisher" --output prepared.msix app.msix
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.manifest app.exe.manifest
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output app.signed.exe.deploy app.exe.deploy
# psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --publisher-name "CN=Publisher" --output updated.appinstaller.p7 app.appinstaller
# Optional portable REST helpers (Linux/macOS):
# cargo build -p psign --bin psign-tool --locked --features artifact-signing-rest
# cargo build -p psign --bin psign-tool --locked --features azure-kv-sign
cargo test -p psign-sip-digest -p psign-authenticode-trust -p psign-opc-sign -p psign-codesigning-rest -p psign-azure-kv-rest -p psign-digest-cli -p psign --locked
cargo check -p psign-sip-digest -p psign-digest-cli -p psign-authenticode-trust -p psign-opc-sign -p psign-codesigning-rest -p psign-azure-kv-rest --locked
```

Unix CI (`ci-unix`) runs **`cargo fmt`**, strict **`clippy -D warnings`** on portable / REST crates plus the **`psign` library**, and the digest CLI tests. Local mirror (bash): **`scripts/linux-portable-validation.sh`** from the repo root.

## PowerShell portable Authenticode module

The repository also builds a PowerShell 7.4 / .NET 8 module, **`Devolutions.Psign`**, with portable cmdlets backed by the Rust `psign_portable` shared library through P/Invoke:

```powershell
Import-Module .\PowerShell\Devolutions.Psign\Devolutions.Psign.psd1
Set-PsignSignature -LiteralPath .\script.ps1 -Certificate $cert
Get-PsignSignature -LiteralPath .\script.ps1
Set-PsignSignature -LiteralPath .\ModuleDirectory -CertificatePath .\signer.cer -PrivateKeyPath .\signer.key
Set-PsignSignature -LiteralPath .\package.msix -PfxPath .\signer.pfx -Password $password
Set-PsignSignature -LiteralPath .\tool.exe -Sha1 $thumbprint -CertStoreDirectory .\cert-store
Get-PsignSignature -LiteralPath .\tool.exe -TrustedCertificate $rootCertificate
```

`Set-PsignSignature` and `Get-PsignSignature` avoid Win32 SIPs and support PE, CAB, MSI, ZIP Authenticode, MSIX/AppX, PowerShell scripts, whole PowerShell module directories (`.ps1`, `.psm1`, `.psd1`), content-mode signing, RFC3161 timestamping, chain embedding, portable cert-store thumbprint selection, and explicit-anchor trust verification. Their output remains portable-specific but exposes built-in-compatible `SignatureStatus` / `SignatureType` properties for migration from `Get-AuthenticodeSignature`. See [`docs/portable-powershell-module.md`](docs/portable-powershell-module.md) and [`docs/portable-core-ffi.md`](docs/portable-core-ffi.md).

## Portable certificate store

`psign-tool cert-store ...` manages a simple file-based certificate store for portable workflows. The default base directory is **`~/.psign/cert-store`**; set **`PSIGN_CERT_STORE`** or pass **`--cert-store-dir`** to override it. Certificates are stored as DER-encoded X.509 files named by Windows-style SHA-1 thumbprint over the full DER certificate. Optional local private keys live beside the certificate as PEM-encoded, unencrypted PKCS#8 **`.key`** files with the same thumbprint name.

```text
~/.psign/cert-store/
  CurrentUser/
    MY/
      ABCDEF0123456789ABCDEF0123456789ABCDEF01.der
      ABCDEF0123456789ABCDEF0123456789ABCDEF01.key
    Root/
    CA/
  LocalMachine/
    MY/
    Root/
    CA/
```

The default scope is **`CurrentUser`**; **`--machine-store`** (native alias **`/sm`** on Windows) selects **`LocalMachine`** under the same base directory. The default store is **`MY`**; use **`--store`** (native alias **`/s`**) for stores such as **`Root`** or **`CA`**.

```powershell
psign-tool cert-store import --store MY cert.pem
psign-tool cert-store import --store MY --key cert.key cert.der
psign-tool cert-store import-pfx --store MY --password "pfx-password" cert.pfx
psign-tool cert-store list --store MY
psign-tool cert-store print --store MY --sha1 ABCDEF0123456789ABCDEF0123456789ABCDEF01
psign-tool cert-store export --store MY --sha1 ABCDEF0123456789ABCDEF0123456789ABCDEF01 --out cert.der
psign-tool cert-store export --store MY --sha1 ABCDEF0123456789ABCDEF0123456789ABCDEF01 --out cert.der --with-key --key-out cert.key
psign-tool cert-store remove --store MY --sha1 ABCDEF0123456789ABCDEF0123456789ABCDEF01
```

`cert-store import-pfx` extracts the certificate and private key from a password-protected PFX/PKCS#12 file but does not store the `.pfx` itself. `cert-store list` and `cert-store print` report whether a matching private key exists; they never print private key material.

After importing a certificate and matching key, portable PE/WinMD signing can use the same store/thumbprint selection shape as native signtool:

```powershell
psign-tool cert-store import-pfx --store MY --password "pfx-password" cert.pfx
psign-tool --mode portable sign /sha1 ABCDEF0123456789ABCDEF0123456789ABCDEF01 /s MY /fd SHA256 file.exe
```

The portable signing path supports local RSA/SHA-2 Authenticode signing for PE/WinMD plus the package/script formats exposed by the portable core. Unsupported native signing options, CSP/KSP selection, auto-selection, and non-exportable local keys return explicit errors in portable mode.

Cloud-backed signing options also accept Azure.Identity-style selectors:
`--azure-key-vault-credential-type` and `--artifact-signing-credential-type`
(`default`, `managed-identity`, `access-token`, `client-secret`,
`workload-identity`). Managed identity maps to the existing managed-identity
flows; workload identity is represented in provider planning but explicit
signing execution is not wired yet.

## Generate binary manifest and dependency graph

```powershell
cargo run -p psign --bin psign-depgraph -- --signtool "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
```

Output files (gitignored **`parity-output/`**):

- `parity-output/binary-manifest.json`
- `parity-output/dependency-graph.json`

Component reference (**exe/DLL roles**, SIP map, relationship diagram): [`docs/windows-signing-components.md`](docs/windows-signing-components.md).

### Optional local copies of inbox signing binaries

```powershell
./scripts/copy-windows-signing-binaries.ps1
# Optional: amd64 + WOW64 crypt32.dll (large).
./scripts/copy-windows-signing-binaries.ps1 -IncludeCrypt32
```

Writes **`parity-output/vendor-binaries/`** (WOW64 under **`syswow64/`**): inbox SIP DLLs, **`imagehlp.dll`**, optional **`crypt32.dll`**, Office **`mso.dll`** / **`VBE7.DLL`** when found, plus SDK **`mssign32.dll`** and **`signtool.exe`** when **Windows Kits\10\bin** is installed.

## Run tests

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
cargo test --test parity_signtool -- --ignored --nocapture
./scripts/run-parity-diff.ps1 -FailOnSemantic
```

`-FailOnSemantic` requires `PSIGN_UNSIGNED_FIXTURE` and `PSIGN_TEST_PFX`. Add `-FailOnSemanticExhaustive` when timestamp, MSIX package, and detached PKCS#7 env vars are also set (see [`docs/ci-parity.md`](docs/ci-parity.md)).

## CI parity (GitHub Actions)

The **`windows`** workflow builds the repo, bootstraps the public Devolutions test CA/PFX (pinned raw URLs — no signing secrets), derives signed/detached fixtures, packs a minimal unsigned MSIX, and runs `./scripts/ci/run-exhaustive-parity-ci.ps1`. Details and extension workflows live in [`docs/ci-parity.md`](docs/ci-parity.md). The workflow fails only on `semanticMismatchCount` in the generated **`parity-output/parity-report.json`** (that directory is gitignored; the JSON is a CI artifact or local output); rows classified `documented_*` (for example UTF-16 response files native cannot parse) do not fail the gate.

Local mirror of the CI orchestrator:

```powershell
cargo build -p psign --bin psign-tool
./scripts/ci/run-exhaustive-parity-ci.ps1
```

## MSIX parity signing script

Use the dedicated local parity runner to sign the same unsigned MSIX with native `signtool.exe` and `psign-tool`, then compare verification outcomes:

```powershell
$env:PSIGN_MSIX_UNSIGNED_FIXTURE="D:\path\unsigned.msix"
$env:PSIGN_MSIX_TEST_PFX="D:\path\authenticode-test-cert.pfx"
$env:PSIGN_MSIX_TEST_PFX_PASSWORD="CodeSign123!"
$env:PSIGN_MSIX_TIMESTAMP_URL="http://timestamp.digicert.com"
./scripts/msix-parity-sign.ps1 -FailOnSemantic
```

If you already imported the Devolutions test cert into `CurrentUser\\My`, you can use thumbprint mode instead of a PFX:

```powershell
$env:PSIGN_MSIX_UNSIGNED_FIXTURE="D:\path\unsigned.msix"
$env:PSIGN_MSIX_TEST_CERT_SHA1="A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38"
$env:PSIGN_MSIX_TIMESTAMP_URL="http://timestamp.digicert.com"
./scripts/msix-parity-sign.ps1 -FailOnSemantic
```

Optional decoupled digest parity:

```powershell
$env:PSIGN_MSIX_DLIB="D:\path\provider.dll"
$env:PSIGN_MSIX_DMDF="D:\path\metadata.json"
./scripts/msix-parity-sign.ps1 -UseDecoupledDigest -FailOnSemantic
```

Report artifact:

- `parity-output/msix-parity-sign-report.json`

You can also invoke the focused path through the main harness:

```powershell
./scripts/run-parity-diff.ps1 -MsixOnly -FailOnSemantic
```
