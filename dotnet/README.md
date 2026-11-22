# psign for .NET (pure C#)

This folder contains a pure C# implementation of the psign **portable** stack — the same Authenticode digest,
verification, trust, and signing logic as the Rust `psign-tool portable ...` / `--mode portable` paths, re-implemented in
managed code without P/Invoke or native helpers. It runs anywhere .NET 8+ runs (Windows, Linux, macOS).

The Rust implementation remains the reference: the C# port is tested differentially against the Rust `psign-tool`
(byte-identical signatures, embedded layouts, and CLI output wherever the Rust output is deterministic).

## Packages

| Package | Use it for | Depends on |
|---------|------------|------------|
| `Devolutions.Psign.Core` | Format parsing and SIP digest recomputation (PE/WinMD, CAB, MSI/MSP, MSIX/APPX and bundles, catalogs, PowerShell and WSH scripts, custom ZIP Authenticode, WIM/ESD, RDP), PKCS#7/CMS read model, OPC / NuGet / VSIX / ClickOnce / App Installer primitives, XML C14N. | `OpenMcdf` |
| `Devolutions.Psign.Verification` | **Signature validation only**: CMS signature checks, chain building to explicit anchors or the Microsoft AuthRoot CTL (downloaded and cached like the Rust tool), RFC 3161 timestamps, revocation helpers, Azure Artifact Signing identity checks, and per-format trust verifiers. Contains no signing code. | Core |
| `Devolutions.Psign.Signing` | Portable signing compatible with psign: CMS / PKCS#7 producers, per-format signers and embedding, RFC 3161 timestamp client, Azure Key Vault and Azure Artifact Signing remote signers, PFX / PEM / DER key loading, portable certificate store, test PKI generation, signature removal, `code` orchestration. | Core, Verification |
| `Devolutions.Psign.Cli` | The managed `psign-tool` dotnet tool (portable backend only). | all |

A validation-only consumer references just `Devolutions.Psign.Verification` (which brings `Devolutions.Psign.Core`).

## Layout

```
dotnet/
  Devolutions.Psign.slnx
  Directory.Build.props
  PORTING.md                      # conventions for contributors (project boundaries, parity rules)
  src/
    Devolutions.Psign.Core/
    Devolutions.Psign.Verification/
    Devolutions.Psign.Signing/
    Devolutions.Psign.Cli/          # psign-tool (managed)
    Devolutions.Psign.Tests/        # xUnit, uses ../tests/fixtures and the Rust tool for differential tests
  Devolutions.Psign.PowerShell/     # existing PowerShell module host (uses the native psign-core FFI)
```

## Build and test

```powershell
dotnet build dotnet/Devolutions.Psign.slnx
dotnet test dotnet/src/Devolutions.Psign.Tests
```

Differential tests run against the Rust `psign-tool` when it is available (`target/debug/psign-tool`,
`target/release/psign-tool`, or the path in `PSIGN_RUST_TOOL`); otherwise they are skipped:

```powershell
cargo build -p psign --bin psign-tool --locked
dotnet test dotnet/src/Devolutions.Psign.Tests
```

## Managed CLI

```powershell
dotnet run --project dotnet/src/Devolutions.Psign.Cli -- portable pe-digest app.exe
dotnet pack dotnet/src/Devolutions.Psign.Cli -c Release -o dist/nuget
dotnet tool install -g Devolutions.Psign.Cli --add-source dist/nuget
psign-tool portable trust-verify-pe app.exe
```

The managed tool accepts the same arguments as the native `psign-tool` for the portable surface (including
signtool-style `/fd sha256` switches and `@response` files). `--mode windows` is rejected because WinVerifyTrust,
SignerSignEx3, and registered CryptSIP providers are only reachable from the native tool.

## Library examples

Recompute and check a PE signature digest:

```csharp
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Pe;

byte[] image = File.ReadAllBytes("app.exe");
var result = PeAuthenticode.VerifyDigestConsistency(image);
Console.WriteLine(result.RecomputedDigestHex);
```

Sign a PE file with a local RSA key (byte-identical to `psign-tool portable sign-pe`):

```csharp
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

var kind = AuthenticodeHashKind.Sha256;
var image = PeEmbed.PrepareForAuthenticodeSigning(File.ReadAllBytes("app.exe"));
var indirect = SpcIndirectDataContent.ForPe(kind, PeAuthenticode.Digest(image, kind));
var signer = CertificateInfo.Parse(File.ReadAllBytes("signer.der"));
using var key = RSA.Create();
key.ImportPkcs8PrivateKey(File.ReadAllBytes("signer.pk8"), out _);
var pkcs7 = Pkcs7Builder.CreateAuthenticode(indirect, kind, signer, [], key);
File.WriteAllBytes("app.signed.exe", PeEmbed.AppendPkcs7Certificate(image, pkcs7));
```
