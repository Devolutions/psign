# C# port conventions

The `dotnet/` tree is a pure C# port of the Rust portable psign stack (no P/Invoke, no native helpers). These rules keep
the port consistent across contributors.

## Projects

| Project | Contents | May reference |
|---------|----------|---------------|
| `Devolutions.Psign.Core` | Format parsing, SIP digest recomputation, signature *extraction*, portable trust (anchors, chain building, AuthRoot CTL / CAB cache, RFC 3161 validation, revocation / online fetch, Artifact Signing identity checks), and `trust-verify-*` verifiers for every format. **No** private keys or CMS production. | BCL |
| `Devolutions.Psign.Signing` | CMS / PKCS#7 producers (`Cms/Pkcs7Builder.cs`), format signers, timestamp clients, remote signers (Azure Key Vault, Azure Artifact Signing), key / PFX / cert-store loading, test PKI generation, signature removal, `code` orchestration. | Core |
| `Devolutions.Psign.Cli` | `psign-tool` (managed) — argv-compatible with the Rust `psign-tool` portable surface. | all |
| `Devolutions.Psign.Server` | `psign-server` (managed) — port of `src/bin/psign-server.rs`: raw `Socket` HTTP/1.1, clap-compatible CLI, x509-cert builder / serde_json / base64 emulation for byte-identical deterministic output. | Core |
| `Devolutions.Psign.DepGraph` | `psign-depgraph` (managed, not packed) — port of `src/bin/depgraph.rs`; PE imports via `Core/Pe/PeImports` (goblin semantics). | Core |
| `Devolutions.Psign.Tests` | xUnit tests; fixtures come from `../tests/fixtures`. | all |

Namespaces generally follow folders, with `Devolutions.Psign.Verification` retained for the validation API even though
those sources now ship in the Core assembly. Mirror the Rust module name in the file / class name so reviewers can map
files 1:1 (for example `msi_digest.rs` → `Core/Msi/MsiDigest.cs`).

## Foundation types (use these, do not duplicate)

- `Hex` (`Lower`, `Upper`, `Decode`), `PsignException` (Rust `anyhow`; keep the Rust error message text where practical so CLI output matches).
- `AuthenticodeHashKind` + extensions (`DigestLength`, `Oid`, `Hash`, `CreateHasher`, `Name`) and `AuthenticodeHashKinds` (`FromDigestLength`, `FromOid`, `Parse`).
- `Oids` — add constants here rather than scattering string literals.
- `Asn1/Der` — minimal TLV reader/writer (`First`, `TlvAt`, `Children`, `EncodeTlv`, `EncodeSequence`, `EncodeSetOf` (DER-sorted), `EncodeOid`, `DecodeOid`). `System.Formats.Asn1.AsnReader/AsnWriter` are fine for higher-level structures. `Asn1/Asn1Time`.
- `Cms/CmsSignedData`, `Cms/CmsSignerInfo`, `Cms/CmsAttribute`, `Cms/AlgorithmIdentifier`, `Cms/Pkcs7Wire` — raw-preserving CMS model. `Encode()` reproduces DER byte-for-byte for DER input and sorts SET OF like the Rust `der` crate (the `certificates` set uses `CmsSignedData.CompareCertificateChoices`, the Rust `cms` crate's quirky order, not plain byte order).
- `Authenticode/SpcIndirectDataContent` (`ForPe/ForCab/ForMsi/ForScript/ForMsix`, `Parse`, `Encode`), `Authenticode/AuthenticodeSignature` (authenticode-crate validation rules).
- `X509/CertificateInfo` (raw issuer/subject/serial/SPKI/extensions; `SameIssuerAndSerial`, `IsIssuerOf`, `VerifySignatureBy`), `X509/SignatureVerifier`, `X509/X509CertificateLoaderCompat`.
- `Pe/PeFile` (offsets, sections, cert table, Authenticode digest ranges), `Pe/PeAuthenticode` (digest, consistency, nth PKCS#7), `Pe/PeEmbed` (checksum, `WIN_CERTIFICATE`, prepare/append/replace/remove).
- ZIP (Rust `zip` 0.6.6 + `miniz_oxide` 0.8.9 emulation, all under `Core/Zip`): `ZipCrateArchive` / `ZipCrateEntry` /
  `ZipFormatException` (reader: `ByName` / `RequireByName` for metadata, `ByIndex` / `OpenByName` / `TryOpenByName` for
  Rust `by_index` / `by_name` validation, `Read`, `ReadRaw`, `DataStart`), `ZipCrateWriter` (`StartFile`, `AddDirectory`,
  `Finish`, `WriteStored`), `MinizDeflater` (one-shot `Compress` or streaming with `DeflateFlush`), `ZipCrc32`,
  `ZipDateTime`. `Core/Msix/QuickXml` is the quick-xml event reader/writer used by MSIX manifest rewriting (not a DOM;
  `Core/Xml/XmlC14n` / `XmlTextScan` serve XMLDSig and text scanning).
- OLE compound files (Rust `cfb` 0.14.0 emulation): `Core/Msi/CfbFile` (`Open` permissive like `CompoundFile::open`,
  `Create`, `CreateStorage`, `CreateStream` create-or-overwrite + write, `ReadStream`, `Children`, `FindChild`,
  `CompareNames`). It edits the image in place exactly like the crate (free-sector reuse order, appended sectors, FAT /
  DIFAT / MiniFAT growth, unbalanced directory inserts, individual header field writes), so MSI / MSP / MST outputs are
  byte-identical to Rust. Do not reintroduce a third-party CFB library in `src/`; tests use OpenMcdf only as an
  independent reader.
- Text / encoding: `Text/RustText` (strict UTF-8, Rust string helpers), `Text/Base64Standard` (Rust `base64` `STANDARD`
  decode with its error texts, plus the lenient ClickOnce `DecodeXmlDsig`), `Json/RustJson` (the only serde_json-compatible
  writer: `Pretty` / `Compact` with optional `sortKeys`, `ToStringPretty<T>` for System.Text.Json models, `String`,
  `StringArray`, `SortedObject`, `CompareUtf8` / `Utf8Comparer`), `IoErrorText` (Rust `std::io::Error` display text;
  `Message`, `Inner`).
- Certificates and keys: `X509/CertificateLoader` (Rust `rdp::parse_certificate`: `ParseCertificate`, `ParseCertificates`,
  `ParsePemBundle`, `PemText`, `DecodeSinglePem`, `PemOrDerToDer`), `Signing/Keys/PrivateKeyLoader` (Rust
  `rdp::parse_rsa_private_key`: `ParseRsaPrivateKey`, `ParseRsaPrivateKeyMaterial`, `LoadPkcs8KeyPemFile`),
  `Signing/ArtifactSigning/ArtifactSigningCertificates` (Rust `parse_artifact_signing_certificates`).
- Signing: `Signing/Cms/Pkcs7Builder` (Authenticode + generic CMS producers, signed attribute profiles, timestamp-token attachment), `IDigestSigner`, `RsaDigestSigner`, `PrecomputedDigestSigner`, `Signing/Cms/Rfc3161TimestampAttribute` (which unsigned attribute carries an RFC 3161 token).
- Tests: `RustTool` (`Run` / `RunOk` / `RunBytes`, UTF-8 decoding, optional env overrides such as `RustTool.NoAutoTrust`),
  `Cli/CliHarness` (in-process managed CLI vs Rust CLI), `LocalHttpServer` (loopback mock for TSA / Key Vault / Artifact
  Signing), `Signing/PfxIdentity` (vendored test PFX), `Cli/GeneratedTestPki` (BCL-generated root + leaf on disk; the
  library generator is `Signing.Pki.TestPki`), `TempDir`, `Fixtures`.

## Behavioral parity

- Output must be byte-identical to Rust where Rust is deterministic (RSA PKCS#1 v1.5 signatures, DER, embedded layouts,
  JSON/text CLI output). Differential tests use the Rust tool through `Tests/RustTool.cs` (`[SkippableFact]` +
  `RustTool.Require()`); see `Tests/Signing/Pkcs7BuilderParityTests.cs` for the pattern. Build the Rust tool with
  `cargo build -p psign --bin psign-tool` at the repo root.
- Port the Rust unit tests that exercise fixtures under `tests/fixtures`. Use `Fixtures.Bytes("relative/path")`.
- Prefer BCL crypto (`RSA`, `ECDsa`, `IncrementalHash`, `X509Certificate2`, `CertificateRequest`). Never rely on the OS
  certificate store or `X509Chain` with the system trust: portable trust uses explicit anchors only.
- Targets: libraries `net8.0;net10.0`, CLI/tests `net10.0`. Guard newer APIs with `#if NET9_0_OR_GREATER`.
- Nullable enabled, file-scoped namespaces, 4-space indent, braces on new lines.
- NativeAOT / trimming: every project under `src/` except the tests sets `IsAotCompatible`, and the build must stay free
  of `IL2xxx` / `IL3xxx` warnings (CI publishes the three tools with `PublishAot=true -p:TreatWarningsAsErrors=true`).
  No reflection-based System.Text.Json: build output with `JsonNode` + `RustJson`, or add the model type to a
  source-generated context (`Verification/VerificationJsonContext`) and pass its `JsonTypeInfo<T>`. When adding a
  `JsonObject` to a `JsonArray`, cast to `JsonNode` so the non-generic `Add` is used. No `Type.GetType`, `Activator`,
  `dynamic`, `Reflection.Emit` or `MakeGenericType`. (The PowerShell module is exempt: it is loaded by PowerShell.)

## Build / test

```powershell
dotnet build dotnet/Devolutions.Psign.slnx
dotnet test dotnet/src/Devolutions.Psign.Tests
```
