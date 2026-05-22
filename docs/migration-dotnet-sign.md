# Migrating from dotnet/sign to psign

`dotnet/sign` is an orchestration tool: it expands globs, walks directories, opens package containers, signs nested files inside-out, and then signs package-native formats such as NuGet, VSIX, ClickOnce/VSTO, MSIX/AppX, App Installer descriptors, and Business Central `.app` packages.

`psign-tool` is historically a SignTool/AuthentiCode implementation. The dotnet/sign migration surface is additive and currently lives under `psign-tool code` for orchestration planning and initial local package execution plus `psign-tool portable ...` package helper commands.

## Command mapping

| dotnet/sign concept | psign status | psign command |
|---------------------|--------------|---------------|
| Expand files, file lists, `!` excludes, braces, ranges, and recursive globs | Implemented for dry-run planning | `psign-tool code --dry-run --plan-json --base-directory . --file-list files.txt` |
| Nested package graph / inside-out ordering | Implemented for dry-run planning across ZIP/OPC containers | `psign-tool code --dry-run --plan-json package.vsix` |
| Top-level NuGet/VSIX/App Installer execution | Implemented for local cert/key, PFX, portable cert-store SHA-1, Azure Key Vault, or Artifact Signing identity plus explicit output | `psign-tool code --cert signer.der --key signer.pkcs8 --output signed.nupkg package.nupkg`, `psign-tool code --pfx signer.pfx --password pfx-password --output signed.nupkg package.nupkg`, `psign-tool code --cert-store-dir .psign-store --sha1 <thumbprint> --output signed.nupkg package.nupkg`, `psign-tool code --azure-key-vault-url https://vault.vault.azure.net --azure-key-vault-certificate cert --azure-key-vault-accesstoken $TOKEN --output signed.nupkg package.nupkg`, `psign-tool code --artifact-signing-endpoint https://wus2.codesigning.azure.net --artifact-signing-account-name acct --artifact-signing-profile-name profile --artifact-signing-access-token $TOKEN --output signed.nupkg package.nupkg` |
| Authenticode PE/WinMD execution | Implemented for top-level and nested PE/WinMD with local cert/key, PFX, portable cert-store SHA-1, Azure Key Vault, or Artifact Signing identity | `psign-tool code --cert signer.der --key signer.pkcs8 --output signed.exe app.exe` |
| Package-native nested execution | Implemented for VSIX/ZIP -> NuGet/VSIX -> PE/WinMD inside-out signing without unsupported non-PE inner Authenticode payloads | `psign-tool code --cert signer.der --key signer.pkcs8 --output signed.vsix extension.vsix` |
| Continue after top-level errors | Implemented for `code` execution | `psign-tool code --continue-on-error --output signed-dir ...` |
| Independent top-level concurrency | Implemented for `code` execution | `psign-tool code --max-concurrency 4 --output signed-dir ...` |
| Skip already signed packages | Implemented for NuGet/SNuGet and VSIX package-native execution | `psign-tool code --skip-signed --output signed.nupkg package.nupkg` |
| Overwrite existing package signatures | Implemented for NuGet/SNuGet and VSIX package-native execution | `psign-tool code --overwrite --cert signer.der --key signer.pkcs8 --output resigned.nupkg signed-package.nupkg` |
| NuGet `.nupkg` / `.snupkg` signature marker | Implemented structural helpers | `psign-tool portable nupkg-signature-info package.nupkg` |
| NuGet package hash signature content | Implemented deterministic generation and verification | `nupkg-signature-content`, `nupkg-verify-signature-content` |
| NuGet local or external CMS signature blob | Implemented split-signing primitives over generated signature-content bytes, with optional RFC3161 timestamping | `nupkg-signature-pkcs7 --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output signature.p7s`, `nupkg-signature-pkcs7-prehash --encoding raw --output prehash.bin`, `nupkg-signature-pkcs7-from-signature --cert signer.der --signature remote.sig --output signature.p7s` |
| NuGet `.signature.p7s` embed/overwrite | Implemented split-signing primitive; local cert/key signing can run in one command with optional RFC3161 timestamping | `nupkg-embed-signature --signature signature.p7s --output signed.nupkg`, `nupkg-sign --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output signed.nupkg` |
| NuGet embedded signature verification | Implemented package hash + CMS/trust verification with explicit anchors | `nupkg-verify-signature signed.nupkg --trusted-ca signer.der --allow-loose-signing-cert` |
| VSIX OPC signature markers | Implemented structural helpers | `vsix-signature-info`, `vsix-embed-signature-xml` |
| VSIX XMLDSig package-part references | Implemented deterministic digest generation and verification | `vsix-signature-reference-xml`, `vsix-verify-signature-reference-xml` |
| VSIX local or external XMLDSig SignatureValue | Implemented deterministic local RSA/SHA-2 signing plus split external-signing over generated SignedInfo | `vsix-signature-xml --cert signer.der --key signer.pkcs8 --output signature.xml`, `vsix-signature-xml-prehash --encoding raw --output prehash.bin`, `vsix-signature-xml-from-signature --cert signer.der --signature remote.sig --output signature.xml`, `vsix-verify-signature-xml --cert signer.der --signature-xml signature.xml` |
| VSIX one-step local signing and embedded verification | Implemented deterministic local XMLDSig generation, OPC embed, embedded signature verification, and optional explicit-anchor signer trust checks | `vsix-sign --cert signer.der --key signer.pkcs8 --output signed.vsix`, `vsix-verify-signature signed.vsix --trusted-ca root.der` |
| App Installer descriptor inspection | Implemented | `appinstaller-info app.appinstaller --signature app.appinstaller.p7` |
| App Installer companion signature verification | Implemented explicit-anchor detached trust path | `appinstaller-verify-companion --signature app.appinstaller.p7 --anchor-dir anchors` |
| App Installer companion signature generation | Implemented local and external-signer RSA/SHA-2 detached PKCS#7 companion generation with optional RFC3161 timestamping | `appinstaller-sign-companion --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output app.appinstaller.p7`, `appinstaller-sign-companion-prehash --encoding raw --output prehash.bin`, `appinstaller-sign-companion-from-signature --cert signer.der --signature remote.sig --output app.appinstaller.p7` |
| App Installer publisher metadata update | Implemented in portable helper and `code` companion signing, including namespace-prefixed `MainPackage` / `MainBundle` tags | `appinstaller-set-publisher --publisher "CN=Example" --output updated.appinstaller`, `psign-tool code --publisher-name "CN=Example" --output updated.appinstaller.p7 app.appinstaller` |
| Business Central `.app` NAVX recognition | Implemented diagnostics, planner classification, and explicit execution gap diagnostic | `business-central-app-info package.app` |
| MSIX/AppX manifest Identity inspection/update | Implemented unsigned-package helper plus guarded `code` prepare execution and encrypted-package OS-only diagnostics | `msix-manifest-info`, `msix-set-publisher`, `psign-tool code --publisher-name "CN=Publisher" --output prepared.msix app.msix` |
| ClickOnce `.deploy` payload handling | Implemented copy-out primitive and guarded PE-like payload signing through `code` | `clickonce-deploy-info`, `clickonce-copy-deploy-payload`, `psign-tool code --cert signer.der --key signer.pkcs8 --output app.signed.exe.deploy app.exe.deploy` |
| ClickOnce manifest file hash graph | Implemented portable file size/digest update and verification helpers | `clickonce-update-manifest-hashes app.exe.manifest --base-directory publish --output updated.manifest`, `clickonce-manifest-hashes updated.manifest --base-directory publish` |
| ClickOnce manifest XMLDSig | Implemented deterministic portable structural local/external XMLDSig signing/verification and routed through guarded `psign-tool code` local cert/key execution for `.manifest`, `.application`, and `.vsto`; not full Mage parity | `psign-tool code --cert signer.der --key signer.pkcs8 --output signed.manifest app.exe.manifest`, `clickonce-sign-manifest app.exe.manifest --cert signer.der --key signer.pkcs8 --output signed.manifest`, `clickonce-sign-manifest-prehash app.exe.manifest --encoding raw --output prehash.bin`, `clickonce-sign-manifest-from-signature app.exe.manifest --cert signer.der --signature remote.sig --output signed.manifest`, `clickonce-verify-manifest-signature signed.manifest --trusted-ca signer.der` |
| Azure.Identity-style auth selector UX | Partially implemented | `--azure-key-vault-credential-type`, `--artifact-signing-credential-type` |

## Current gaps

The remaining dotnet/sign feature gaps are execution and policy work:

- `psign-tool code` execution supports local RSA cert/key PE/WinMD Authenticode signing, package-native NuGet/SNuGet, VSIX, generic ZIP nested package entries, unsigned MSIX/AppX prepare execution including nested MSIX/AppX packages inside upload/bundle containers, encrypted MSIX/AppX OS-only diagnostics, ClickOnce `.manifest` / `.application` / `.vsto` XMLDSig signing, PE-like ClickOnce `.deploy` payloads, App Installer descriptors including nested descriptors in ZIP containers, `--continue-on-error`, `--max-concurrency`, `--skip-signed`, `--overwrite`, and VSIX/ZIP/MSIX -> NuGet/VSIX -> PE/WinMD/ClickOnce-manifest/App-Installer-companion inside-out signing. Unsupported non-PE nested Authenticode payloads still fail explicitly unless excluded by file-list filters.
- NuGet support does not yet wrap signature content in full NuGet author/repository signature metadata or enforce NuGet trust policy; local CMS signatures can carry RFC3161 timestamp tokens, and split external CMS assembly can consume a Key Vault/Trusted Signing-style RSA signature over `nupkg-signature-pkcs7-prehash`.
- VSIX support now produces and verifies deterministic local or external-signer RSA/SHA-2 XMLDSig `SignatureValue` bytes, writes the package-level OPC signature content types and relationships, and can optionally validate the XMLDSig signer certificate chain against explicit anchors; cloud-provider signing is supported through the `code` orchestrator; timestamp options fail explicitly rather than producing an untimestamped VSIX signature.
- ClickOnce/VSTO support includes classification, `.deploy` payload copy-out helpers, guarded local signing for PE-like `.deploy` payloads, portable manifest file hash update/verification, deterministic portable structural local/external XMLDSig manifest signing/verification with embedded signer certificate, and guarded `psign-tool code` routing for top-level or nested manifest XMLDSig signing; timestamping, full Mage-compatible XML canonicalization/policy, and full deployment graph signing remain.
- MSIX/AppX `code` execution prepares unsigned cleartext packages by signing nested entries, updating `AppxManifest.xml` Publisher from `--publisher-name`, and regenerating `AppxBlockMap.xml`; encrypted `.eappx`/`.emsix` packages are classified with explicit Windows AppxSip OS-delegation diagnostics; final package signing still uses the existing Windows SignerSignEx3/AppX path.
- App Installer local/external companion generation, RFC3161 timestamping, namespace-aware publisher update before companion signing, and explicit-anchor detached verification exist; full App Installer policy checks remain.

## Migration workflow today

Use `code --dry-run --plan-json` to validate that psign sees the same files and nested ordering that dotnet/sign would process:

```sh
psign-tool code --dry-run --plan-json --base-directory . --file-list files.txt
```

Use guarded local execution for package-native inputs while broader Authenticode recursive execution is completed:

```sh
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.nupkg package.nupkg
psign-tool code --base-directory . --pfx signer.pfx --password pfx-password --output signed.nupkg package.nupkg
psign-tool code --base-directory . --cert-store-dir .psign-store --sha1 <thumbprint> --output signed.nupkg package.nupkg
psign-tool code --base-directory . --azure-key-vault-url https://vault.vault.azure.net --azure-key-vault-certificate cert --azure-key-vault-accesstoken "$TOKEN" --output signed.nupkg package.nupkg
psign-tool code --base-directory . --artifact-signing-endpoint https://wus2.codesigning.azure.net --artifact-signing-account-name acct --artifact-signing-profile-name profile --artifact-signing-access-token "$TOKEN" --output signed.nupkg package.nupkg
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.vsix extension.vsix
psign-tool code --base-directory . --overwrite --cert signer.der --key signer.pkcs8 --output resigned.nupkg signed-package.nupkg
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.zip bundle.zip
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output signed.exe app.exe
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --publisher-name "CN=Publisher" --output prepared.msix app.msix
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output app.signed.exe.deploy app.exe.deploy
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --output app.appinstaller.p7 app.appinstaller
psign-tool code --base-directory . --cert signer.der --key signer.pkcs8 --publisher-name "CN=Publisher" --output updated.appinstaller.p7 app.appinstaller
```

Use the package helpers for split-signing experiments and CI assertions:

```sh
psign-tool portable nupkg-signature-content package.nupkg --output signature-content.txt
psign-tool portable nupkg-signature-pkcs7-prehash package.nupkg --encoding raw --output prehash.bin
psign-tool portable nupkg-signature-pkcs7-from-signature package.nupkg --cert signer.der --signature remote.sig --output signature.p7s
psign-tool portable nupkg-sign package.nupkg --cert signer.der --key signer.pkcs8 --timestamp-url http://tsa --timestamp-digest sha256 --output signed.nupkg
psign-tool portable nupkg-verify-signature-content package.nupkg --content signature-content.txt
psign-tool portable vsix-signature-reference-xml extension.vsix --output signature-reference.xml
psign-tool portable vsix-verify-signature-reference-xml extension.vsix --signature-xml signature-reference.xml
psign-tool portable vsix-signature-xml extension.vsix --cert signer.der --key signer.pkcs8 --output signature.xml
psign-tool portable vsix-signature-xml-prehash extension.vsix --encoding raw --output prehash.bin
psign-tool portable vsix-signature-xml-from-signature extension.vsix --cert signer.der --signature remote.sig --output signature.xml
psign-tool portable vsix-verify-signature-xml extension.vsix --signature-xml signature.xml --cert signer.der
psign-tool portable vsix-sign extension.vsix --cert signer.der --key signer.pkcs8 --output signed.vsix
psign-tool portable msix-manifest-info package.msix
psign-tool portable msix-set-publisher package.msix --publisher "CN=Example" --output updated.msix
psign-tool portable clickonce-deploy-info app.exe.deploy
psign-tool portable clickonce-copy-deploy-payload app.exe.deploy --output app.exe
psign-tool portable clickonce-sign-manifest app.exe.manifest --cert signer.der --key signer.pkcs8 --output signed.manifest
psign-tool portable clickonce-sign-manifest-prehash app.exe.manifest --encoding raw --output prehash.bin
psign-tool portable clickonce-sign-manifest-from-signature app.exe.manifest --cert signer.der --signature remote.sig --output signed.manifest
psign-tool portable clickonce-verify-manifest-signature signed.manifest --trusted-ca signer.der
psign-tool portable appinstaller-sign-companion-prehash app.appinstaller --encoding raw --output prehash.bin
psign-tool portable appinstaller-sign-companion-from-signature app.appinstaller --cert signer.der --signature remote.sig --output app.appinstaller.p7
```

Keep production recursive/nested package signing on dotnet/sign until the remaining execution gaps above are closed.
