# Portable PowerShell module

`Devolutions.Psign` is a PowerShell 7.4 / .NET 8 binary module that exposes portable Authenticode cmdlets over the Rust `psign-core` shared library. The module does not call `WinVerifyTrust`, `CryptUIWizDigitalSign`, `SignerSignEx`, or registered Windows SIP DLLs.

## Cmdlets

- `Set-PortableSignature`
- `Get-PortableSignature`

Both cmdlets accept `-FilePath` and `-LiteralPath`. `-LiteralPath` accepts the same `PSPath` and `LP` aliases as the built-in Authenticode cmdlets. When the input is a directory, the module treats it as a PowerShell module tree and recursively processes PowerShell files plus newly supported portable signing neighbors such as `.dll`, `.exe`, `.nupkg`, `.snupkg`, `.vsix`, `.manifest`, `.application`, `.vsto`, and `.appinstaller`.

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

The output object is portable-specific, but its compatibility properties mirror the built-in Authenticode shape: `Status` is a `System.Management.Automation.SignatureStatus`, `SignatureType` is a `System.Management.Automation.SignatureType`, and `SignerCertificate`, `TimeStamperCertificate`, `StatusMessage`, `Path`, `IsOSBinary`, and `SubjectAlternativeName` are exposed by the same names. Portable-specific details remain available through `Format`, `PortableStatus`, `TrustStatus`, `PortableTrustStatus`, `TimestampKinds`, `TimestampSigningTime`, `SignatureCount`, and `PortableDiagnostics`.

When trust is requested, the output object's `TrustStatus` is `Valid` or `NotTrusted`, while `Status` continues to report the overall portable signature result. Timestamped signatures expose `TimestampKinds`, `TimeStamperCertificate`, and `TimestampSigningTime` when the portable timestamp parser can extract the signing date.

Trust verification is offline by default. `-OnlineAia` enables issuer retrieval, `-OnlineOcsp` enables OCSP checks, and `-RevocationMode Off|BestEffort|Require` controls revocation enforcement in the portable trust engine.

## Supported portable formats

The current PowerShell test suite covers command metadata compatibility plus signing and validation through the module surface for:

- PE files
- CAB archives
- MSI/MSP installers
- Devolutions ZIP Authenticode packages
- NuGet and symbol NuGet packages (`.nupkg`, `.snupkg`)
- VSIX packages
- ClickOnce manifests (`.manifest`, `.application`, `.vsto`)
- App Installer descriptors with detached `.p7` companions
- PowerShell scripts, including `.ps1xml` XML marker signatures
- PowerShell module directories
- MSIX/AppX packages

The suite now runs under **Pester 5**, while preserving the existing end-to-end smoke coverage. Signature inspection validates portable digest binding and signature structure. Explicit trust verification is currently implemented for PE, CAB, MSI/MSP, Devolutions ZIP Authenticode, and PowerShell script signatures.

## Build, test, and package

```powershell
pwsh -File .\PowerShell\build.ps1 -Configuration Release
pwsh -File .\PowerShell\tests\Invoke-PortableSignatureTests.ps1 -Configuration Release
pwsh -File .\PowerShell\package.ps1 -Configuration Release
```

The build stages the native library under the module RID layout, for example `runtimes\win-x64\native\psign-core.dll`, so .NET can load it via the module resolver. The package script validates the module manifest, publishes to a temporary local repository, saves the generated module package, imports it, and confirms both cmdlets are exported.

Release packaging can import prebuilt `psign-core-<rid>` native artifacts instead of rebuilding the current RID locally:

```powershell
pwsh -File .\PowerShell\package.ps1 -Configuration Release -NativeArtifactsRoot .\dist\native -SkipNativeBuild
```

The native artifact root should contain directories such as `psign-core-win-x64`, `psign-core-linux-x64`, and `psign-core-osx-arm64`, each containing the packaged native library name for that RID.

## Migrating from built-in Authenticode cmdlets

The portable module cmdlets (`Get-PortableSignature`, `Set-PortableSignature`) are designed as near drop-in replacements for `Get-AuthenticodeSignature` and `Set-AuthenticodeSignature`. The following table shows common migration patterns:

| Built-in | Portable equivalent |
| --- | --- |
| `Get-AuthenticodeSignature -LiteralPath .\f.exe` | `Get-PortableSignature -LiteralPath .\f.exe` |
| `Set-AuthenticodeSignature -LiteralPath .\f.exe -Certificate $cert` | `Set-PortableSignature -LiteralPath .\f.exe -Certificate $cert` |
| `$sig.Status -eq [SignatureStatus]::Valid` | Same — `Status` is typed as `SignatureStatus` |
| `$sig.SignatureType -eq [SignatureType]::Authenticode` | Same — `SignatureType` is typed as `SignatureType` |
| `$sig.SignerCertificate.Thumbprint` | Same |
| `$sig.TimeStamperCertificate` | Same |

### Output property compatibility

| Property | Type | Notes |
| --- | --- | --- |
| `Status` | `System.Management.Automation.SignatureStatus` | Enum-typed; same values as built-in. |
| `StatusMessage` | `string` | Free-text description of the result. |
| `SignatureType` | `System.Management.Automation.SignatureType` | `None`, `Authenticode`, or `Catalog`. |
| `SignerCertificate` | `X509Certificate2?` | Decoded from CMS signer. |
| `TimeStamperCertificate` | `X509Certificate2?` | Decoded from timestamp CMS counter-signature. |
| `IsOSBinary` | `bool` | Always `false` — no OS catalog lookup. |
| `SubjectAlternativeName` | `string[]?` | Extracted from signer certificate SAN extension. |
| `Path` | `string` | Input file path. |

Scripts that test `$sig.Status -eq 'Valid'` or `$sig.Status -eq [SignatureStatus]::Valid` continue to work because PowerShell coerces between strings and enums.

### Portable-only properties

These additional properties are available on the output object and have no built-in equivalent:

- `Format` — file format string (e.g. `PE`, `Cab`, `Msi`, `Catalog`, `NuGet`).
- `PortableStatus` / `PortableTrustStatus` — string accessors for raw status values.
- `TrustStatus` — explicit trust result (`SignatureStatus?`); only populated when trust anchors are supplied.
- `SignatureCount`, `SignerIndex`, `EmbeddedCertificateCount` — multi-signature detail.
- `DigestAlgorithm` — OID or name of the Authenticode digest.
- `TimestampKinds`, `TimestampSigningTime` — timestamp protocol detail.
- `PortableDiagnostics` — diagnostic messages from the portable verification engine.
- `Content` — signed content bytes (content-mode signing only).

### Intentional behavioral differences

| Behavior | Built-in | Portable |
| --- | --- | --- |
| Trust evaluation | Delegates to `WinVerifyTrust` / OS trust store | Validates digest binding; trust is opt-in via anchors |
| Directory inputs | Rejected as containers | Recursively processed as PowerShell module trees |
| Content signing (`Set-`) | Exposes metadata but throws `NotImplementedException` | Fully implemented, returns signed bytes |
| Non-exportable private keys | Works via CNG provider | Fails; use file-backed keys, PFX, or portable cert store |
| Catalog member lookup | Reports `SignatureType = Catalog` for catalog-protected files | Reports catalog format only for `.cat` files directly |
| SHA1 signing | Accepted by Windows CryptoAPI | Not supported; minimum is SHA-256 |
| `-HashAlgorithm` values | Arbitrary string (resolved by CNG) | `Sha256`, `Sha384`, `Sha512` (validated) |

### Parameter alias compatibility

- `-LiteralPath` accepts aliases `PSPath` and `LP` (matching built-in).
- `-FilePath` accepts alias `Path` (additive, not present on built-in but commonly piped).
- `-SourcePathOrExtension` and `-Content` have the same pipeline binding and validation attributes as the built-in content parameter set.
