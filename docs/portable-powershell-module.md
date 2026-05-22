# Portable PowerShell module

`Devolutions.Psign` is a PowerShell 7.4 / .NET 8 binary module that exposes portable Authenticode cmdlets over the Rust `psign-core` shared library. The module does not call `WinVerifyTrust`, `CryptUIWizDigitalSign`, `SignerSignEx`, or registered Windows SIP DLLs.

## Cmdlets

- `Set-PortableSignature`
- `Get-PortableSignature`

Both cmdlets accept `-FilePath` and `-LiteralPath`. When the input is a directory, the module treats it as a PowerShell module tree and recursively processes `.ps1`, `.psm1`, `.psd1`, and `.ps1xml` files.

Both cmdlets also support the built-in Authenticode content parameter shape:

```powershell
$signed = Set-PortableSignature -SourcePathOrExtension '.ps1' -Content $bytes -Certificate $exportableCertificate
Get-PortableSignature -SourcePathOrExtension '.ps1' -Content $signed.Content
```

## Signing inputs

`Set-PortableSignature` supports local exportable RSA key material:

```powershell
Set-PortableSignature -LiteralPath .\tool.exe -CertificatePath .\signer.cer -PrivateKeyPath .\signer.key
Set-PortableSignature -LiteralPath .\script.ps1 -Certificate $exportableCertificate
Set-PortableSignature -LiteralPath .\package.msix -PfxPath .\signer.pfx -Password $password
Set-PortableSignature -LiteralPath .\tool.exe -Thumbprint $sha1 -CertStoreDirectory .\cert-store
```

The P/Invoke ABI also accepts in-memory DER certificate and PKCS#8 private-key material. Non-exportable local keys fail explicitly; use file-backed key material, PFX files with exportable keys, or the portable file-backed cert store.

The portable cert store follows the same layout as `psign-tool cert-store`: `<base>\<scope>\<store>\<SHA1>.der` plus `<SHA1>.key`, where scope is `CurrentUser` or `LocalMachine` and the private key is unencrypted PKCS#8 PEM. `-Thumbprint` has `-Sha1` and `-PortableStoreThumbprint` aliases. If `-CertStoreDirectory` is omitted, the module uses `PSIGN_CERT_STORE` and then `~\.psign\cert-store`.

`Set-PortableSignature` supports `-IncludeChain Signer|NotRoot|All` (default `NotRoot`), optional `-ChainCertificatePath`, `-TimestampServer`, and `-TimestampHashAlgorithm Sha1|Sha256|Sha384|Sha512`.

## Explicit trust

`Get-PortableSignature` validates digest binding by default and does not claim OS trust. Explicit portable trust can be requested with anchors:

```powershell
Get-PortableSignature -LiteralPath .\tool.exe -TrustedCertificate $rootCertificate
Get-PortableSignature -LiteralPath .\tool.exe -TrustedCertificatePath .\root.cer
Get-PortableSignature -LiteralPath .\tool.exe -AnchorDirectory .\anchors
Get-PortableSignature -LiteralPath .\tool.exe -TrustedCertificate $rootCertificate -AsOf (Get-Date) -RevocationMode Off
```

When trust is requested, the output object's `TrustStatus` is `Valid` or `NotTrusted`, while `Status` continues to report the overall portable signature result. Timestamped signatures expose `TimestampKinds`, `TimeStamperCertificate`, and `TimestampSigningTime` when the portable timestamp parser can extract the signing date.

Trust verification is offline by default. `-OnlineAia` enables issuer retrieval, `-OnlineOcsp` enables OCSP checks, and `-RevocationMode Off|BestEffort|Require` controls revocation enforcement in the portable trust engine.

## Supported portable formats

The current module tests cover signing and validation through the PowerShell surface for:

- PE files
- CAB archives
- MSI/MSP installers
- Devolutions ZIP Authenticode packages
- PowerShell scripts, including `.ps1xml` XML marker signatures
- PowerShell module directories
- MSIX/AppX packages

Signature inspection validates portable digest binding and signature structure. Explicit trust verification is currently implemented for PE, CAB, MSI/MSP, Devolutions ZIP Authenticode, and PowerShell script signatures.

## Build, test, and package

```powershell
pwsh -File .\PowerShell\build.ps1 -Configuration Release
pwsh -File .\PowerShell\tests\Invoke-PortableSignatureTests.ps1 -Configuration Release
pwsh -File .\PowerShell\package.ps1 -Configuration Release
```

The build stages the native library under the module RID layout, for example `runtimes\win-x64\native\psign-core.dll`, so .NET can load it via the module resolver. The package script validates the module manifest, publishes to a temporary local repository, saves the generated module package, imports it, and confirms both cmdlets are exported.
