# Portable PowerShell module

`Devolutions.Psign` is a PowerShell 7.4 / .NET 8 binary module that exposes portable Authenticode cmdlets over the Rust `psign_portable` shared library. The module does not call `WinVerifyTrust`, `CryptUIWizDigitalSign`, `SignerSignEx`, or registered Windows SIP DLLs.

## Cmdlets

- `Set-PortableSignature`
- `Get-PortableSignature`

Both cmdlets accept `-FilePath` and `-LiteralPath`. When the input is a directory, the module treats it as a PowerShell module tree and recursively processes `.ps1`, `.psm1`, and `.psd1` files.

## Signing inputs

`Set-PortableSignature` supports local exportable RSA key material:

```powershell
Set-PortableSignature -LiteralPath .\tool.exe -CertificatePath .\signer.cer -PrivateKeyPath .\signer.key
Set-PortableSignature -LiteralPath .\script.ps1 -Certificate $exportableCertificate
Set-PortableSignature -LiteralPath .\package.msix -PfxPath .\signer.pfx -Password $password
```

The P/Invoke ABI also accepts in-memory DER certificate and PKCS#8 private-key material. Non-exportable local keys fail explicitly; use file-backed key material or a future remote signing provider for those cases.

## Supported portable formats

The current module tests cover signing and validation through the PowerShell surface for:

- PE files
- PowerShell scripts
- PowerShell module directories
- MSIX/AppX packages

The shared core also exposes local signing/inspection for CAB, MSI/MSP, and Devolutions ZIP Authenticode. Signature inspection validates portable digest binding and signature structure; it does not claim OS trust.

## Build, test, and package

```powershell
pwsh -File .\PowerShell\build.ps1 -Configuration Release
pwsh -File .\PowerShell\tests\Invoke-PortableSignatureTests.ps1 -Configuration Release
pwsh -File .\PowerShell\package.ps1 -Configuration Release
```

The build stages the native library under the module RID layout, for example `runtimes\win-x64\native\psign_portable.dll`, so .NET can load it via the module resolver.
