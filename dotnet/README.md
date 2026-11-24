# psign for .NET (pure C#)

This folder contains a pure C# implementation of the psign **portable** stack — the same Authenticode digest,
verification, trust, and signing logic as the Rust `psign-tool portable ...` / `--mode portable` paths, re-implemented in
managed code without P/Invoke or native helpers. It runs anywhere .NET 8+ runs (Windows, Linux, macOS).

The Rust implementation remains the reference: the C# port is tested differentially against the Rust `psign-tool`
(byte-identical signatures, embedded layouts, and CLI output wherever the Rust output is deterministic).

## Packages

| Package | Use it for | Depends on |
|---------|------------|------------|
| `Devolutions.Psign.Core` | Format parsing and SIP digest recomputation; **signature validation only** with explicit trust anchors or Microsoft AuthRoot, RFC 3161 and revocation checks, Artifact Signing identity checks, and per-format trust verifiers. Contains no signing code or private-key handling. | BCL only |
| `Devolutions.Psign.Signing` | Portable signing compatible with psign: CMS / PKCS#7 producers, per-format signers and embedding, RFC 3161 timestamp client, Azure Key Vault and Azure Artifact Signing remote signers, PFX / PEM / DER key loading, portable certificate store, test PKI generation, signature removal, `code` orchestration. | Core |
| `Devolutions.Psign.Cli` | The managed `psign-tool` dotnet tool (portable backend only). | all |
| `Devolutions.Psign.Server` | The managed `psign-server` dotnet tool: local loopback test services (RFC 3161 TSA, code-signing PKI with AIA / CRL / OCSP, Azure Key Vault-compatible signing, Azure Artifact Signing / Trusted Signing data plane). | Core |

Not packaged: `psign-depgraph` (`src/Devolutions.Psign.DepGraph`), the managed port of the Rust binary manifest /
dependency graph generator used by the parity harness (`parity-output/binary-manifest.json`,
`parity-output/dependency-graph.json`).

A validation-only consumer references just `Devolutions.Psign.Core`; it does not bring in signing code. A signing
consumer references `Devolutions.Psign.Signing`, which brings Core transitively. The release workflow packs and
smoke-tests these two library packages, attaches them to the GitHub release, and publishes them to NuGet.org when
NuGet publishing is enabled.

## Layout

```
dotnet/
  Devolutions.Psign.slnx
  Directory.Build.props
  PORTING.md                      # conventions for contributors (project boundaries, parity rules)
  src/
    Devolutions.Psign.Core/
    Devolutions.Psign.Signing/
    Devolutions.Psign.Cli/          # psign-tool (managed)
    Devolutions.Psign.Server/       # psign-server (managed local test services)
    Devolutions.Psign.DepGraph/     # psign-depgraph (managed binary manifest / dependency graph generator)
    Devolutions.Psign.Tests/        # xUnit, uses ../tests/fixtures and the Rust tool for differential tests
  Devolutions.Psign.PowerShell/     # Devolutions.Psign PowerShell module cmdlets (managed, on Devolutions.Psign.Signing)
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
cargo build -p psign --features timestamp-server --bin psign-server --locked
cargo build -p psign --bin psign-depgraph --locked
dotnet test dotnet/src/Devolutions.Psign.Tests
```

The `psign-server` / `psign-depgraph` parity tests locate the Rust binaries through `PSIGN_RUST_SERVER` /
`PSIGN_RUST_DEPGRAPH` or `target/{debug,release}` and are skipped when they are missing.

### NativeAOT

The libraries and the three tools are NativeAOT compatible (`IsAotCompatible`, no trim / AOT warnings). Publish a
native executable with:

```powershell
dotnet publish dotnet/src/Devolutions.Psign.Cli -c Release -r win-x64 -p:PublishAot=true -o out/psign-tool
```

The same differential suite can run against native builds: set `PSIGN_MANAGED_TOOL`, `PSIGN_MANAGED_SERVER` and
`PSIGN_MANAGED_DEPGRAPH` to the published executables and the tests run them out of process instead of calling the CLI
in-process. CI does this on Linux, Windows and macOS.

## Local test services (`psign-server`)

The managed `psign-server` is argv- and wire-compatible with the Rust `psign-server` (clap help / errors, startup lines,
HTTP status codes, headers and bodies). Deterministic responses are byte-identical; generated certificates, keys and
signatures use fresh RSA keys on every start, exactly like the Rust server, so they match structurally. Its NuGet tool
package is not published; the commands below build and install it locally.

```powershell
dotnet pack dotnet/src/Devolutions.Psign.Server -c Release -o dist/nuget
dotnet tool install -g Devolutions.Psign.Server --add-source dist/nuget
psign-server timestamp-server --listen 127.0.0.1:0 --gen-time 20240102030405Z --cert-output tsa-root.der
psign-server pki-server --root-cert-output root.der --leaf-cert-output leaf.der --leaf-key-output leaf.pk8 --ocsp-status revoked
psign-server azure-key-vault-server --certificate-name my-cert --root-cert-output kv-root.der
psign-server artifact-signing-server --response-mode body-id --expect-correlation-id cid-1
```

## Managed CLI

The managed CLI NuGet tool package is not published; the commands below build and install it locally.

```powershell
dotnet run --project dotnet/src/Devolutions.Psign.Cli -- portable pe-digest app.exe
dotnet pack dotnet/src/Devolutions.Psign.Cli -c Release -o dist/nuget
dotnet tool install -g Devolutions.Psign.Cli --add-source dist/nuget
psign-tool portable trust-verify-pe app.exe
psign-tool verify --trusted-ca ca.crt app.exe package.nupkg   # routes each file to the matching portable verifier
psign-tool sign /fd sha256 /f cert.pfx /p pwd /tr http://tsa /td sha256 app.exe setup.msi pkg.msix   # signs in place
psign-tool timestamp /tr http://tsa /td sha256 app.exe
```

The managed tool accepts the same arguments as the native `psign-tool` for the portable surface (including
signtool-style `/fd sha256` switches and `@response` files). `--mode windows` is rejected because WinVerifyTrust,
SignerSignEx3, and registered CryptSIP providers are only reachable from the native tool.
The managed `Devolutions.Psign.Cli` and native `Devolutions.Psign.Tool` packages both provide the `psign-tool`
command; install them into separate tool paths or uninstall one before installing the other globally.

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
