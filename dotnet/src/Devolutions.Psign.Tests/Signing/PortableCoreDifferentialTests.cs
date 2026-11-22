using System.Formats.Asn1;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Portable;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// Differential tests of <see cref="PortableCore"/> against the Rust implementation: byte-for-byte signed outputs versus
/// <c>psign-tool --mode portable sign</c> (which drives Rust <c>portable_sign</c>), and exact JSON responses versus the Rust
/// <c>psign-portable-ffi</c> library when available. NuGet / VSIX signatures embed the signing time, so the C# side is
/// given the Rust output's time through <see cref="PortableCoreOptions"/>.
/// </summary>
public sealed class PortableCoreDifferentialTests
{
    private const string Password = "CodeSign123!";

    private static string Pfx => Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx");

    private static string TestCa => Fixtures.Path("devolutions-authenticode/authenticode-test-ca.crt");

    public static TheoryData<string, string> DeterministicFixtures()
    {
        var data = new TheoryData<string, string>();
        foreach (var f in new[]
        {
            "generated-unsigned/pe/tiny32-pe-alias.exe",
            "generated-unsigned/pe/tiny64-pe-alias.dll",
            "generated-unsigned/pe/tiny32-pe-alias.sys",
            "generated-unsigned/pe/tiny64-pe-alias.efi",
            "generated-unsigned/pe/tiny32-pe-alias.mui",
            "generated-unsigned/pe/tiny64-pe-alias.cpl",
            "generated-unsigned/winmd/tiny64-pe-copy.winmd",
            "pe-authenticode-upstream/tiny32.signed.efi",
            "generated-unsigned/cab/sample.cab",
            "generated-unsigned/msix/sample.msix",
            "generated-unsigned/msix/sample.appx",
            "generated-unsigned/msix/sample.msixbundle",
            "generated-unsigned/msix/sample.appxbundle",
            "zip-authenticode/unsigned/sample.zip",
            "generated-unsigned/appinstaller/sample.appinstaller",
            "msix-edge-cases/unsigned/bundle-bom.appinstaller",
        })
        {
            data.Add(f, "sha256");
        }

        foreach (var kind in new[] { "ps1", "psm1", "psd1", "ps1xml", "psc1", "cdxml", "mof" })
        {
            // UTF-16LE inputs are covered through the FFI (Rust portable_sign reports their self-check as HashMismatch,
            // which makes the CLI fail).
            foreach (var enc in new[] { "utf8-lf", "utf8-bom-crlf", "utf16be-bom-lf" })
            {
                data.Add($"generated-unsigned/scripts/powershell/{kind}/{enc}.{kind}", "sha256");
            }
        }

        foreach (var digest in new[] { "sha384", "sha512" })
        {
            data.Add("generated-unsigned/pe/tiny32-pe-alias.exe", digest);
            data.Add("generated-unsigned/msix/sample.msixbundle", digest);
            data.Add("generated-unsigned/cab/sample.cab", digest);
            data.Add("generated-unsigned/scripts/powershell/ps1/utf8-crlf.ps1", digest);
            data.Add("zip-authenticode/unsigned/sample.zip", digest);
            data.Add("generated-unsigned/appinstaller/sample.appinstaller", digest);
        }

        return data;
    }

    private static PortableDigestAlgorithm Digest(string name) => name switch
    {
        "sha384" => PortableDigestAlgorithm.Sha384,
        "sha512" => PortableDigestAlgorithm.Sha512,
        _ => PortableDigestAlgorithm.Sha256,
    };

    private static (string RustFile, string CsFile) TwoCopies(TempDir dir, string sourcePath, string? fileName = null)
    {
        fileName ??= Path.GetFileName(sourcePath);
        Directory.CreateDirectory(dir.File("rust"));
        Directory.CreateDirectory(dir.File("cs"));
        var rust = Path.Combine(dir.DirPath, "rust", fileName);
        var cs = Path.Combine(dir.DirPath, "cs", fileName);
        File.Copy(sourcePath, rust);
        File.Copy(sourcePath, cs);
        return (rust, cs);
    }

    private static void RustSign(string file, string digest, params string[] extra) =>
        RustTool.RunOk(["--mode", "portable", "sign", "--pfx", Pfx, "--password", Password, "--fd", digest, .. extra, file]);

    [SkippableTheory]
    [MemberData(nameof(DeterministicFixtures))]
    public void SignOutputMatchesRustCli(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, cs) = TwoCopies(dir, Fixtures.Path(fixture));
        RustSign(rust, digest);
        var response = PortableCore.PortableSign(new PortableSignRequest
        {
            Path = cs,
            HashAlgorithm = Digest(digest),
            PfxPath = Pfx,
            PfxPassword = Password,
        });

        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
        Assert.Equal(File.ReadAllBytes(rust), File.ReadAllBytes(cs));
        if (fixture.EndsWith(".appinstaller", StringComparison.Ordinal))
        {
            Assert.Equal(File.ReadAllBytes(rust + ".p7"), File.ReadAllBytes(cs + ".p7"));
        }
    }

    /// <summary>
    /// MSI / MSP: the embedded PKCS#7 (and therefore the signed digest) is byte-identical, but the compound-file sector
    /// layout written by the C# OLE writer differs from the Rust <c>cfb</c> crate, so the files are compared semantically.
    /// </summary>
    private static void AssertSameSignedFile(byte[] rust, byte[] cs, string fixture)
    {
        if (fixture.EndsWith(".msi", StringComparison.Ordinal) || fixture.EndsWith(".msp", StringComparison.Ordinal))
        {
            Assert.Equal(Devolutions.Psign.Core.Msi.MsiDigest.DigitalSignaturePkcs7Der(rust), Devolutions.Psign.Core.Msi.MsiDigest.DigitalSignaturePkcs7Der(cs));
            Devolutions.Psign.Core.Msi.MsiDigest.VerifyDigestConsistency(cs);
            Devolutions.Psign.Core.Msi.MsiDigest.VerifyDigestConsistency(rust);
            return;
        }

        Assert.Equal(rust, cs);
    }

    [SkippableTheory]
    [InlineData("generated-unsigned/installer/tiny.msi", "sha256")]
    [InlineData("generated-unsigned/installer/tiny.msi", "sha384")]
    [InlineData("generated-unsigned/installer/tiny-patch.msp", "sha512")]
    [InlineData("generated-signed/installer/tiny.msi", "sha256")]
    public void MsiSignatureMatchesRustCliAndCrossVerifies(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, cs) = TwoCopies(dir, Fixtures.Path(fixture));
        RustSign(rust, digest);
        var response = PortableCore.PortableSign(new PortableSignRequest { Path = cs, HashAlgorithm = Digest(digest), PfxPath = Pfx, PfxPassword = Password });
        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
        AssertSameSignedFile(File.ReadAllBytes(rust), File.ReadAllBytes(cs), fixture);

        // Each implementation accepts the other's output with explicit trust.
        RustTool.RunOk("portable", "trust-verify-msi", cs, "--trusted-ca", TestCa);
        if (RustPortableFfi.Available)
        {
            var request = new PortableGetSignatureRequest { Path = cs, TrustedCertificatePaths = [TestCa] }.ToJson();
            var rustView = RustPortableFfi.Invoke("get_signature", request);
            Assert.Equal(rustView, PortableCoreJson.Invoke("get_signature", request));
            Assert.Contains("\"trust_status\":\"Valid\"", rustView.Json, StringComparison.Ordinal);
        }
    }

    public static TheoryData<string> AllPowerShellScriptFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var file in Directory.EnumerateFiles(Fixtures.Path("generated-unsigned/scripts/powershell"), "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            data.Add(Path.GetRelativePath(Fixtures.Dir, file).Replace('\\', '/'));
        }

        return data;
    }

    [SkippableTheory]
    [MemberData(nameof(AllPowerShellScriptFixtures))]
    public void ScriptSignJsonAndBytesMatchRustFfi(string fixture)
    {
        RustPortableFfi.Require();
        using var dir = new TempDir();
        var output = dir.File(Path.GetFileName(fixture));
        var request = new PortableSignRequest { Path = Fixtures.Path(fixture), OutputPath = output, PfxPath = Pfx, PfxPassword = Password }.ToJson();
        var rust = RustPortableFfi.Invoke("sign", request);
        var rustBytes = File.ReadAllBytes(output);
        File.Delete(output);
        Assert.Equal(rust, PortableCoreJson.Invoke("sign", request));
        Assert.Equal(rustBytes, File.ReadAllBytes(output));
    }

    [SkippableFact]
    public void ChainCertificatesAndAppendMatchRustCli()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, cs) = TwoCopies(dir, Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"));
        RustSign(rust, "sha256", "--append-signature", "--ac", TestCa);
        PortableCore.PortableSign(new PortableSignRequest
        {
            Path = cs,
            AppendSignature = true,
            PfxPath = Pfx,
            PfxPassword = Password,
            ChainCertificatePaths = [TestCa],
        });
        Assert.Equal(File.ReadAllBytes(rust), File.ReadAllBytes(cs));
        Assert.Equal(2, PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(cs)).SignatureCount);
    }

    [SkippableFact]
    public void CertificateAndKeyFilesMatchRustCertStoreSigning()
    {
        // The Rust CLI resolves `--sha1` through the portable cert store to certificate_path / private_key_path.
        RustTool.Require();
        using var dir = new TempDir();
        var store = dir.File("store");
        RustTool.RunOk("cert-store", "import-pfx", "--cert-store-dir", store, "--password", Password, Pfx);
        using var pfx = new PfxIdentity();
        var thumbprint = pfx.Signer.Sha1ThumbprintHex;
        var identity = new Devolutions.Psign.Signing.CertStore.PortableCertStore().ResolveSigningIdentity(store, false, "MY", thumbprint);
        foreach (var fixture in new[] { "generated-unsigned/scripts/powershell/ps1/utf8-lf.ps1", "generated-unsigned/pe/tiny32-pe-alias.exe" })
        {
            using var sub = new TempDir();
            var (rust, cs) = TwoCopies(sub, Fixtures.Path(fixture));
            RustTool.RunOk("--mode", "portable", "sign", "--cert-store-dir", store, "--sha1", thumbprint, "--fd", "sha256", rust);
            PortableCore.PortableSign(new PortableSignRequest { Path = cs, CertificatePath = identity.CertPath, PrivateKeyPath = identity.KeyPath });
            Assert.Equal(File.ReadAllBytes(rust), File.ReadAllBytes(cs));
        }
    }

    [SkippableFact]
    public void ClickOnceManifestMatchesRustCli()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var source = dir.File("src.manifest");
        File.WriteAllText(
            source,
            "﻿<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<asmv1:assembly manifestVersion=\"1.0\" xmlns:asmv1=\"urn:schemas-microsoft-com:asm.v1\">\r\n  <asmv1:assemblyIdentity name=\"Portable.Diff\" version=\"1.0.0.0\" />\r\n</asmv1:assembly>\r\n",
            new UTF8Encoding(false));
        foreach (var digest in new[] { "sha256", "sha512" })
        {
            using var sub = new TempDir();
            var (rust, cs) = TwoCopies(sub, source, "app.exe.manifest");
            RustSign(rust, digest);
            PortableCore.PortableSign(new PortableSignRequest { Path = cs, HashAlgorithm = Digest(digest), PfxPath = Pfx, PfxPassword = Password });
            Assert.Equal(File.ReadAllBytes(rust), File.ReadAllBytes(cs));

            // Re-signing replaces the existing signature.
            RustSign(rust, digest);
            PortableCore.PortableSign(new PortableSignRequest { Path = cs, HashAlgorithm = Digest(digest), PfxPath = Pfx, PfxPassword = Password });
            Assert.Equal(File.ReadAllBytes(rust), File.ReadAllBytes(cs));
        }
    }

    [SkippableTheory]
    [InlineData("package-signing/unsigned/sample.nupkg", "sha256")]
    [InlineData("package-signing/unsigned/with-pe.nupkg", "sha384")]
    [InlineData("package-signing/signed/sample.signed.nupkg", "sha256")]
    public void NuGetMatchesRustCliAtTheSameSigningTime(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, cs) = TwoCopies(dir, Fixtures.Path(fixture));
        RustSign(rust, digest);
        var rustBytes = File.ReadAllBytes(rust);
        var (signingTime, zipTime) = NuGetSigningTimes(rustBytes);
        PortableCore.PortableSign(
            new PortableSignRequest { Path = cs, HashAlgorithm = Digest(digest), PfxPath = Pfx, PfxPassword = Password },
            new PortableCoreOptions { Clock = () => signingTime, ZipClock = () => zipTime });
        Assert.Equal(rustBytes, File.ReadAllBytes(cs));
    }

    [SkippableTheory]
    [InlineData("package-signing/unsigned/sample.vsix", "sha256")]
    [InlineData("package-signing/unsigned/nested.vsix", "sha384")]
    [InlineData("package-signing/unsigned/deep-nested.vsix", "sha512")]
    public void VsixMatchesRustCliAtTheSameSigningTime(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, cs) = TwoCopies(dir, Fixtures.Path(fixture));
        RustSign(rust, digest);
        var rustBytes = File.ReadAllBytes(rust);
        var signingTime = VsixSigningTime(rustBytes);
        PortableCore.PortableSign(
            new PortableSignRequest { Path = cs, HashAlgorithm = Digest(digest), PfxPath = Pfx, PfxPassword = Password },
            new PortableCoreOptions { Clock = () => signingTime });
        Assert.Equal(rustBytes, File.ReadAllBytes(cs));
    }

    private static (DateTimeOffset SigningTime, ZipDateTime ZipTime) NuGetSigningTimes(byte[] package)
    {
        var archive = ZipCrateArchive.Open(package);
        var entry = archive.RequireByName(NuGetPackage.PackageSignatureFileName);
        var sd = CmsSignedData.Parse(archive.Read(entry));
        var attr = sd.SignerInfos[0].GetSignedAttribute(Oids.Pkcs9SigningTime)!;
        var time = new AsnReader(attr.Values[0], AsnEncodingRules.DER).ReadUtcTime(2049);
        return (time, entry.LastModified);
    }

    private static DateTimeOffset VsixSigningTime(byte[] package)
    {
        var xml = Encoding.UTF8.GetString(VsixPackage.ExtractSignatureXml(package));
        const string marker = "<Value>";
        int start = xml.IndexOf(marker, xml.IndexOf("SignatureTime", StringComparison.Ordinal), StringComparison.Ordinal) + marker.Length;
        var value = xml[start..xml.IndexOf("</Value>", start, StringComparison.Ordinal)];
        var parsed = DateTimeOffset.ParseExact(value, "yyyy-MM-dd'T'HH:mm:ss.fzzz", CultureInfo.InvariantCulture);
        return parsed.ToUniversalTime();
    }

    // ------------------------------------------------------------------ Rust FFI (JSON contract)

    private static void AssertSameInvoke(string operation, string requestJson)
    {
        var rust = RustPortableFfi.Invoke(operation, requestJson);
        var cs = PortableCoreJson.Invoke(operation, requestJson);
        Assert.Equal(rust.StatusCode, cs.StatusCode);
        Assert.Equal(rust.Json, cs.Json);
    }

    public static TheoryData<string> SignedAndUnsignedInspectionFixtures()
    {
        var data = new TheoryData<string>();
        var root = Fixtures.Dir;
        foreach (var dirName in new[] { "generated-signed", "generated-unsigned", "package-signing", "zip-authenticode", "pe-authenticode-upstream", "artifact-signing" })
        {
            var dir = Path.Combine(root, dirName);
            if (!Directory.Exists(dir))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                var rel = Path.GetRelativePath(root, file).Replace('\\', '/');
                if (rel.EndsWith(".json", StringComparison.Ordinal) || rel.EndsWith(".md", StringComparison.Ordinal))
                {
                    continue;
                }

                data.Add(rel);
            }
        }

        return data;
    }

    [SkippableTheory]
    [MemberData(nameof(SignedAndUnsignedInspectionFixtures))]
    public void GetSignatureJsonMatchesRustFfi(string fixture)
    {
        RustPortableFfi.Require();
        AssertSameInvoke("get_signature", PortableGetSignatureRequest.PathOnly(Fixtures.Path(fixture)).ToJson());
    }

    [SkippableTheory]
    [InlineData("generated-unsigned/pe/tiny32-pe-alias.exe")]
    [InlineData("generated-unsigned/cab/sample.cab")]
    [InlineData("generated-unsigned/installer/tiny.msi")]
    [InlineData("generated-unsigned/msix/sample.msixbundle")]
    [InlineData("zip-authenticode/unsigned/sample.zip")]
    [InlineData("generated-unsigned/scripts/powershell/psm1/utf16le-bom-crlf.psm1")]
    [InlineData("generated-unsigned/appinstaller/sample.appinstaller")]
    public void SignAndTrustJsonMatchRustFfi(string fixture)
    {
        RustPortableFfi.Require();
        using var dir = new TempDir();
        var output = dir.File("signed-" + Path.GetFileName(fixture));
        var request = new PortableSignRequest
        {
            Path = Fixtures.Path(fixture),
            OutputPath = output,
            PfxPath = Pfx,
            PfxPassword = Password,
            ChainCertificatePaths = [TestCa],
        }.ToJson();

        var rust = RustPortableFfi.Invoke("sign", request);
        var rustBytes = File.ReadAllBytes(output);
        File.Delete(output);
        var cs = PortableCoreJson.Invoke("sign", request);
        Assert.Equal(rust, cs);
        AssertSameSignedFile(rustBytes, File.ReadAllBytes(output), fixture);

        foreach (var trust in new[]
        {
            new PortableGetSignatureRequest { Path = output, TrustedCertificatePaths = [TestCa] },
            new PortableGetSignatureRequest { Path = output, TrustedCertificatesDerBase64 = [Convert.ToBase64String(Devolutions.Psign.Verification.Anchors.ParseCertBytes(File.ReadAllBytes(TestCa)).RawData)], AsOf = "2026-01-15" },
            new PortableGetSignatureRequest { Path = output, AnchorDirectory = dir.DirPath },
            new PortableGetSignatureRequest { Path = output, TrustedCertificatePaths = [TestCa], RequireValidTimestamp = true },
            new PortableGetSignatureRequest { Path = output, ArtifactSigning = new PortableArtifactSigningOptions() },
            new PortableGetSignatureRequest { Path = output, ArtifactSigning = new PortableArtifactSigningOptions(), TrustedCertificatePaths = [TestCa] },
        })
        {
            AssertSameInvoke("get_signature", trust.ToJson());
        }
    }

    [SkippableTheory]
    [InlineData("package-signing/unsigned/sample.nupkg")]
    [InlineData("package-signing/unsigned/with-pe.nupkg")]
    [InlineData("package-signing/unsigned/sample.vsix")]
    [InlineData("package-signing/unsigned/deep-nested.vsix")]
    public void PackageTrustJsonMatchesRustFfi(string fixture)
    {
        RustPortableFfi.Require();
        using var dir = new TempDir();
        var output = dir.File(Path.GetFileName(fixture));
        PortableCore.PortableSign(new PortableSignRequest { Path = Fixtures.Path(fixture), OutputPath = output, PfxPath = Pfx, PfxPassword = Password, ChainCertificatePaths = [TestCa] });
        foreach (var request in new[]
        {
            PortableGetSignatureRequest.PathOnly(output),
            new PortableGetSignatureRequest { Path = output, TrustedCertificatePaths = [TestCa] },
            new PortableGetSignatureRequest { Path = output, TrustedCertificatePaths = [TestCa], AsOf = "2001-01-01" },
            new PortableGetSignatureRequest { Path = output, TrustedCertificatePaths = [TestCa], PreferTimestampSigningTime = true },
            new PortableGetSignatureRequest { Path = output, TrustedCertificatePaths = [TestCa], RequireValidTimestamp = true },
            new PortableGetSignatureRequest { Path = output, ArtifactSigning = new PortableArtifactSigningOptions { AllowMissingTimestamp = true } },
        })
        {
            AssertSameInvoke("get_signature", request.ToJson());
        }

        // Tampering one part breaks the digest binding the same way in both implementations.
        var tampered = dir.File("tampered-" + Path.GetFileName(fixture));
        File.Copy(output, tampered);
        using (var zip = System.IO.Compression.ZipFile.Open(tampered, System.IO.Compression.ZipArchiveMode.Update))
        {
            var victim = zip.Entries.First(e => e.Name.Length > 0 && !e.FullName.StartsWith('[') && !e.FullName.Contains("signature", StringComparison.OrdinalIgnoreCase) && !e.FullName.EndsWith(".rels", StringComparison.Ordinal));
            using var s = victim.Open();
            s.Seek(0, SeekOrigin.End);
            s.WriteByte((byte)'!');
        }

        AssertSameInvoke("get_signature", PortableGetSignatureRequest.PathOnly(tampered).ToJson());
    }

    [SkippableFact]
    public void RequestErrorsMatchRustFfi()
    {
        RustPortableFfi.Require();
        using var dir = new TempDir();
        var notPe = Fixtures.Path("generated-unsigned/negative/not-pe.exe");
        var cases = new (string Op, string Json)[]
        {
            ("get_signature", PortableGetSignatureRequest.PathOnly(dir.File("missing.exe")).ToJson()),
            ("get_signature", PortableGetSignatureRequest.PathOnly(notPe).ToJson()),
            ("get_signature", PortableGetSignatureRequest.PathOnly(Fixtures.Path("generated-unsigned/msix-encrypted-negative/placeholder.emsix")).ToJson()),
            ("sign", new PortableSignRequest { Path = dir.File("a.vbs") }.ToJson()),
            ("sign", new PortableSignRequest { Path = dir.File("a.cat") }.ToJson()),
            ("sign", new PortableSignRequest { Path = Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe"), OutputPath = dir.File("o.exe") }.ToJson()),
            ("sign", new PortableSignRequest { Path = Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe"), OutputPath = dir.File("o.exe"), PfxPath = Pfx, CertificatePath = TestCa }.ToJson()),
            ("sign", new PortableSignRequest { Path = Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe"), OutputPath = dir.File("o.exe"), PfxPath = Pfx, PfxPassword = "wrong" }.ToJson()),
            ("sign", new PortableSignRequest { Path = Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe"), OutputPath = dir.File("o.exe"), PfxPath = Pfx, PfxPassword = Password, TimestampHashAlgorithm = PortableTimestampDigestAlgorithm.Sha1 }.ToJson()),
            ("clear_signature", new PortableClearSignatureRequest { Path = Fixtures.Path("generated-unsigned/cab/sample.cab") }.ToJson()),
            ("clear_signature", new PortableClearSignatureRequest { Path = Fixtures.Path("generated-unsigned/detached/content.bin") }.ToJson()),
            ("new_file_catalog", new PortableNewFileCatalogRequest { CatalogFilePath = dir.File("c.cat"), Paths = [dir.File("nope")] }.ToJson()),
            ("new_file_catalog", new PortableNewFileCatalogRequest { CatalogFilePath = dir.File("c.cat"), Paths = [notPe], CatalogVersion = 7 }.ToJson()),
            ("validate_powershell_script", new PortableValidatePowerShellRequest { SourcePathOrExtension = ".vbs", ContentBase64 = "" }.ToJson()),
            ("validate_powershell_script", new PortableValidatePowerShellRequest { SourcePathOrExtension = ".ps1", ContentBase64 = "!!" }.ToJson()),
            ("get_artifact_signing_identity", new PortableArtifactSigningIdentityRequest { CertificateDerBase64 = "AAAA" }.ToJson()),
            ("get_signature", "{}"),
            ("sign", "[]"),
            ("get_signature", "{\"path\":null}"),
        };
        foreach (var (op, json) in cases)
        {
            var rust = RustPortableFfi.Invoke(op, json);
            var cs = PortableCoreJson.Invoke(op, json);
            Assert.True(rust.StatusCode == cs.StatusCode, $"{op} {json}: rust={rust.Json} cs={cs.Json}");
            var rustNode = JsonNode.Parse(rust.Json)!;
            var csNode = JsonNode.Parse(cs.Json)!;
            if (rust.StatusCode == PortableCoreJson.StatusOperationFailed || rust.StatusCode == PortableCoreJson.StatusOk)
            {
                Assert.True(rust.Json == cs.Json, $"{op} {json}:\nrust={rust.Json}\ncs  ={cs.Json}");
            }
            else
            {
                Assert.Equal(rustNode["code"]!.ToJsonString(), csNode["code"]!.ToJsonString());
            }
        }
    }

    [SkippableFact]
    public void CatalogAndClearJsonMatchRustFfi()
    {
        RustPortableFfi.Require();
        using var dir = new TempDir();
        var src = dir.File("src");
        Directory.CreateDirectory(Path.Combine(src, "nested"));
        File.WriteAllBytes(Path.Combine(src, "b.txt"), "bravo"u8.ToArray());
        File.WriteAllBytes(Path.Combine(src, "A.txt"), "alpha"u8.ToArray());
        File.Copy(Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.dll"), Path.Combine(src, "nested", "lib.dll"));
        foreach (var create in new[]
        {
            new PortableNewFileCatalogRequest { CatalogFilePath = dir.File("v2.cat"), Paths = [src] },
            new PortableNewFileCatalogRequest { CatalogFilePath = dir.File("v1.cat"), Paths = [src], CatalogVersion = 1 },
            new PortableNewFileCatalogRequest { CatalogFilePath = dir.File("files.cat"), Paths = [Path.Combine(src, "b.txt"), Path.Combine(src, "nested")] },
        })
        {
            var json = create.ToJson();
            var rust = RustPortableFfi.Invoke("new_file_catalog", json);
            var rustBytes = File.ReadAllBytes(create.CatalogFilePath);
            File.Delete(create.CatalogFilePath);
            var cs = PortableCoreJson.Invoke("new_file_catalog", json);
            Assert.Equal(rust, cs);
            Assert.Equal(rustBytes, File.ReadAllBytes(create.CatalogFilePath));
        }

        File.WriteAllBytes(Path.Combine(src, "b.txt"), "tampered"u8.ToArray());
        File.WriteAllBytes(Path.Combine(src, "new.txt"), "new"u8.ToArray());
        foreach (var test in new[]
        {
            new PortableTestFileCatalogRequest { CatalogFilePath = dir.File("v2.cat"), Paths = [src] },
            new PortableTestFileCatalogRequest { CatalogFilePath = dir.File("v1.cat"), Paths = [src], FilesToSkip = ["B.TXT", "nested\\lib.dll"] },
            new PortableTestFileCatalogRequest { CatalogFilePath = dir.File("files.cat"), Paths = [Path.Combine(src, "b.txt")] },
            new PortableTestFileCatalogRequest { CatalogFilePath = dir.File("v2.cat"), Paths = [src], TrustedCertificatePaths = [TestCa] },
        })
        {
            AssertSameInvoke("test_file_catalog", test.ToJson());
        }

        var target = dir.File("clear.efi");
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"), target);
        var clear = new PortableClearSignatureRequest { Path = target }.ToJson();
        var rustClear = RustPortableFfi.Invoke("clear_signature", clear);
        var rustCleared = File.ReadAllBytes(target);
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"), target, overwrite: true);
        Assert.Equal(rustClear, PortableCoreJson.Invoke("clear_signature", clear));
        Assert.Equal(rustCleared, File.ReadAllBytes(target));
        AssertSameInvoke("clear_signature", clear);
    }

    [SkippableFact]
    public void ValidatePowerShellAndIdentityJsonMatchRustFfi()
    {
        RustPortableFfi.Require();
        using var dir = new TempDir();
        var script = dir.File("s.ps1");
        File.Copy(Fixtures.Path("generated-unsigned/scripts/powershell/ps1/utf16le-bom-crlf.ps1"), script);
        PortableCore.PortableSign(new PortableSignRequest { Path = script, PfxPath = Pfx, PfxPassword = Password, ChainCertificatePaths = [TestCa] });
        var content = Convert.ToBase64String(File.ReadAllBytes(script));
        foreach (var source in new[] { ".ps1", "psm1", "module.psd1", ".PS1", "x.vbs", "unknown" })
        {
            AssertSameInvoke("validate_powershell_script", new PortableValidatePowerShellRequest { SourcePathOrExtension = source, ContentBase64 = content }.ToJson());
            AssertSameInvoke(
                "validate_powershell_script",
                new PortableValidatePowerShellRequest { SourcePathOrExtension = source, ContentBase64 = content, TrustedCertificatePaths = [TestCa] }.ToJson());
        }

        var unsigned = Convert.ToBase64String("Write-Output 1\r\n"u8.ToArray());
        AssertSameInvoke("validate_powershell_script", new PortableValidatePowerShellRequest { SourcePathOrExtension = ".ps1", ContentBase64 = unsigned }.ToJson());

        foreach (var pem in new[] { "artifact-signing/devolutions-signer.pem", "artifact-signing/microsoft-public-rsa-timestamping-ca-2020.pem" })
        {
            var der = Devolutions.Psign.Verification.Anchors.ParseCertBytes(Fixtures.Bytes(pem)).RawData;
            AssertSameInvoke("get_artifact_signing_identity", new PortableArtifactSigningIdentityRequest { CertificateDerBase64 = " " + Convert.ToBase64String(der) + "\n" }.ToJson());
        }

        var rustVersion = JsonNode.Parse(RustPortableFfi.Invoke("version", null).Json)!;
        var csVersion = JsonNode.Parse(PortableCoreJson.Invoke("version", null).Json)!;
        Assert.Equal(rustVersion["schema_version"]!.ToJsonString(), csVersion["schema_version"]!.ToJsonString());
        Assert.Equal(rustVersion["crate_name"]!.ToJsonString(), csVersion["crate_name"]!.ToJsonString());
    }

    [SkippableFact]
    public void ArtifactSigningFixturesVerifyLikeRustFfi()
    {
        RustPortableFfi.Require();
        var root = Fixtures.Path("artifact-signing");
        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            if (file.EndsWith(".pem", StringComparison.Ordinal) || file.EndsWith(".crl", StringComparison.Ordinal) || file.EndsWith(".md", StringComparison.Ordinal) || file.EndsWith(".der", StringComparison.Ordinal))
            {
                continue;
            }

            var privateRoots = Directory.EnumerateFiles(Path.Combine(root, "private-trust"), "*.pem").ToList();
            foreach (var request in new[]
            {
                new PortableGetSignatureRequest { Path = file, ArtifactSigning = new PortableArtifactSigningOptions() },
                new PortableGetSignatureRequest { Path = file, ArtifactSigning = new PortableArtifactSigningOptions { PrivateTrustRootPaths = privateRoots, AllowMissingTimestamp = true } },
                new PortableGetSignatureRequest { Path = file, ArtifactSigning = new PortableArtifactSigningOptions { PublisherIds = ["1.2.3"] } },
            })
            {
                var rust = RustPortableFfi.Invoke("get_signature", request.ToJson());
                var cs = PortableCoreJson.Invoke("get_signature", request.ToJson());
                Assert.True(rust == cs, $"{file}:\nrust={rust.Json}\ncs  ={cs.Json}");
            }
        }
    }
}
