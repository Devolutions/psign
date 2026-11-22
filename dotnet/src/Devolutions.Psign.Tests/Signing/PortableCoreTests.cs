using System.Buffers.Binary;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Portable;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>Ports of the <c>psign-portable-core</c> unit tests (<c>crates/psign-portable-core/src/lib.rs</c>).</summary>
public sealed class PortableCoreTests
{
    private const string Password = "CodeSign123!";

    private static string Pfx => Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx");

    private static string TestCa => Fixtures.Path("devolutions-authenticode/authenticode-test-ca.crt");

    private static PortableSignRequest PfxRequest(string path, string? output = null) => new()
    {
        Path = path,
        OutputPath = output,
        PfxPath = Pfx,
        PfxPassword = Password,
    };

    [Fact]
    public void DecodesArtifactSigningIdentityFromCertificate()
    {
        var der = Anchors.ParseCertBytes(Fixtures.Bytes("artifact-signing/devolutions-signer.pem")).RawData;
        var response = PortableCore.PortableGetArtifactSigningIdentity(new PortableArtifactSigningIdentityRequest
        {
            CertificateDerBase64 = Convert.ToBase64String(der),
        });
        Assert.NotNull(response.Identity);
        Assert.Equal("285218949.549339218.252840042.443064405", response.Identity!.PublisherId);
    }

    [Fact]
    public void ArtifactSigningRejectsGenericAnchorInputs()
    {
        var request = PortableGetSignatureRequest.PathOnly("x.exe");
        request.ArtifactSigning = new PortableArtifactSigningOptions();
        request.TrustedCertificatePaths = ["root.cer"];
        var e = Assert.Throws<PsignException>(() => PortableCore.TrustOptions(request));
        Assert.Contains("cannot be combined", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("tool.exe", PortableFileFormat.Pe)]
    [InlineData("driver.SYS", PortableFileFormat.Pe)]
    [InlineData("package.nupkg", PortableFileFormat.NuGet)]
    [InlineData("symbols.snupkg", PortableFileFormat.NuGet)]
    [InlineData("extension.vsix", PortableFileFormat.Vsix)]
    [InlineData("archive.zip", PortableFileFormat.Zip)]
    [InlineData("app.manifest", PortableFileFormat.ClickOnceManifest)]
    [InlineData("deploy.application", PortableFileFormat.ClickOnceManifest)]
    [InlineData("addin.vsto", PortableFileFormat.ClickOnceManifest)]
    [InlineData("installer.appinstaller", PortableFileFormat.AppInstaller)]
    [InlineData("install.msi", PortableFileFormat.Msi)]
    [InlineData("script.ps1", PortableFileFormat.PowerShellScript)]
    [InlineData("types.ps1xml", PortableFileFormat.PowerShellScript)]
    [InlineData("console.psc1", PortableFileFormat.PowerShellScript)]
    [InlineData("module.cdxml", PortableFileFormat.PowerShellScript)]
    [InlineData("config.mof", PortableFileFormat.PowerShellScript)]
    [InlineData("unknown.bin", PortableFileFormat.Unknown)]
    [InlineData("app.msix", PortableFileFormat.Msix)]
    [InlineData("app.appx", PortableFileFormat.Msix)]
    [InlineData("bundle.msixbundle", PortableFileFormat.Msix)]
    [InlineData("bundle.APPXBUNDLE", PortableFileFormat.Msix)]
    [InlineData("upload.msixupload", PortableFileFormat.MsixUpload)]
    [InlineData("upload.appxupload", PortableFileFormat.MsixUpload)]
    [InlineData("enc.emsix", PortableFileFormat.MsixEncrypted)]
    [InlineData("enc.eappxbundle", PortableFileFormat.MsixEncrypted)]
    [InlineData(".ps1", PortableFileFormat.Unknown)]
    [InlineData("dir/", PortableFileFormat.Unknown)]
    [InlineData("noext", PortableFileFormat.Unknown)]
    public void InfersExpectedFormats(string path, PortableFileFormat expected) =>
        Assert.Equal(expected, PortableCore.InferFormat(path));

    [Fact]
    public void PortableMsixFamilyExtensionsAreExactLowercase()
    {
        foreach (var ext in new[] { "msix", "appx", "msixbundle", "appxbundle" })
        {
            Assert.True(PortableCore.IsPortableMsixFamilyExtension(ext));
        }

        Assert.False(PortableCore.IsPortableMsixFamilyExtension("MSIX"));
        Assert.False(PortableCore.IsPortableMsixFamilyExtension("emsix"));
        Assert.False(PortableCore.IsPortableMsixFamilyExtension("msixupload"));
    }

    [Fact]
    public void InfersPowerShellSourceExtensions()
    {
        Assert.Equal(PortableFileFormat.PowerShellScript, PortableCore.InferPowerShellSourceFormat(".ps1"));
        Assert.Equal(PortableFileFormat.PowerShellScript, PortableCore.InferPowerShellSourceFormat("psm1"));
        Assert.Equal(PortableFileFormat.Unknown, PortableCore.InferPowerShellSourceFormat("unknown"));
    }

    [Fact]
    public void DetectsExtensionlessPeFromMagic()
    {
        var pe = Fixtures.Bytes("pe-authenticode-upstream/tiny32.efi");
        Assert.Equal(PortableFileFormat.Pe, PortableCore.InferFormatFromPathOrData("extensionless", pe));
        Assert.Equal(PortableFileFormat.Unknown, PortableCore.InferFormatFromPathOrData("extensionless", "MZ"u8.ToArray()));
    }

    [Fact]
    public void AppendsScriptSignatureBlockUsingSourceUtf16Encoding()
    {
        const string block = "\r\n# SIG # Begin signature block\r\n";
        var le = PortableCore.AppendScriptSignatureBlock([0xFF, 0xFE, (byte)'x', 0], block);
        Assert.Equal(new byte[] { 0xFF, 0xFE, (byte)'x', 0 }, le[..4]);
        Assert.Equal("x" + block, Encoding.Unicode.GetString(le, 2, le.Length - 2));

        var be = PortableCore.AppendScriptSignatureBlock([0xFE, 0xFF, 0, (byte)'x'], block);
        Assert.Equal(new byte[] { 0xFE, 0xFF, 0, (byte)'x' }, be[..4]);
        Assert.Equal("x" + block, Encoding.BigEndianUnicode.GetString(be, 2, be.Length - 2));
    }

    [Fact]
    public void FormatsScriptSignatureMarkerFamily()
    {
        var ps1 = PortableCore.FormatPowerShellSignatureBlock("abc"u8.ToArray(), "ps1");
        Assert.Contains("# SIG # Begin signature block", ps1, StringComparison.Ordinal);
        Assert.Contains("# YWJj", ps1, StringComparison.Ordinal);
        Assert.Contains("# SIG # End signature block", ps1, StringComparison.Ordinal);

        var xml = PortableCore.FormatPowerShellSignatureBlock("abc"u8.ToArray(), "ps1xml");
        Assert.Contains("<!-- SIG # Begin signature block -->", xml, StringComparison.Ordinal);
        Assert.Contains("<!-- YWJj -->", xml, StringComparison.Ordinal);
        Assert.Contains("<!-- SIG # End signature block -->", xml, StringComparison.Ordinal);

        var mof = PortableCore.FormatPowerShellSignatureBlock("abc"u8.ToArray(), "mof");
        Assert.Contains("/* SIG # Begin signature block */", mof, StringComparison.Ordinal);
        Assert.Contains("/* YWJj */", mof, StringComparison.Ordinal);
        Assert.Contains("/* SIG # End signature block */", mof, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidatesUnsignedPowerShellContentWithoutTempFile()
    {
        var response = PortableCore.PortableValidatePowerShellScript(new PortableValidatePowerShellRequest
        {
            SourcePathOrExtension = ".ps1",
            ContentBase64 = Convert.ToBase64String("Write-Output 'unsigned'\n"u8.ToArray()),
        });
        Assert.Equal(PortableSignatureStatus.NotSigned, response.Status);
        Assert.Equal(PortableFileFormat.PowerShellScript, response.Format);
    }

    [Fact]
    public void ValidatesSignedPowerShellContentWithExplicitTrust()
    {
        using var dir = new TempDir();
        var script = dir.File("trusted.ps1");
        var signedPath = dir.File("trusted.signed.ps1");
        File.WriteAllBytes(script, "Write-Output 'trusted'\r\n"u8.ToArray());
        var request = PfxRequest(script, signedPath);
        request.ChainCertificatePaths = [TestCa];
        PortableCore.PortableSign(request);

        var response = PortableCore.PortableValidatePowerShellScript(new PortableValidatePowerShellRequest
        {
            SourcePathOrExtension = ".ps1",
            ContentBase64 = Convert.ToBase64String(File.ReadAllBytes(signedPath)),
            TrustedCertificatePaths = [TestCa],
        });
        Assert.Equal(PortableSignatureStatus.Valid, response.Status);
        Assert.Equal(PortableSignatureStatus.Valid, response.TrustStatus);
        Assert.NotNull(response.SignerCertificateDerBase64);
        Assert.Contains(response.Diagnostics, d => d.StartsWith("explicit_trust=valid", StringComparison.Ordinal));

        var inline = PortableCore.PortableValidatePowerShellScript(new PortableValidatePowerShellRequest
        {
            SourcePathOrExtension = "ps1",
            ContentBase64 = Convert.ToBase64String(File.ReadAllBytes(signedPath)),
            TrustedCertificatesDerBase64 = [Convert.ToBase64String(Anchors.ParseCertBytes(File.ReadAllBytes(TestCa)).RawData)],
        });
        Assert.Equal(PortableSignatureStatus.Valid, inline.TrustStatus);
    }

    [Fact]
    public void UntrustedSignatureReportsNotTrusted()
    {
        using var dir = new TempDir();
        using var other = new TestSigner(dir, "CN=unrelated root");
        var script = dir.File("s.ps1");
        File.WriteAllBytes(script, "Write-Output 1\r\n"u8.ToArray());
        PortableCore.PortableSign(PfxRequest(script));
        var request = PortableGetSignatureRequest.PathOnly(script);
        request.TrustedCertificatePaths = [other.CertPath];
        var response = PortableCore.PortableGetSignature(request);
        Assert.Equal(PortableSignatureStatus.NotTrusted, response.Status);
        Assert.Equal(PortableSignatureStatus.NotTrusted, response.TrustStatus);
        Assert.Contains("explicit_trust=failed", response.Diagnostics);
    }

    [Fact]
    public void CreatesAndTestsPortableFileCatalogWithRelativePaths()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("sub"));
        File.WriteAllBytes(dir.File("a.txt"), "alpha"u8.ToArray());
        File.WriteAllBytes(Path.Combine(dir.DirPath, "sub", "b.txt"), "bravo"u8.ToArray());
        var catalog = dir.File("catalog.cat");

        var created = PortableCore.PortableNewFileCatalog(new PortableNewFileCatalogRequest
        {
            CatalogFilePath = catalog,
            Paths = [dir.DirPath],
            CatalogVersion = 2,
        });
        Assert.Equal(2u, created.CatalogVersion);
        Assert.Equal("SHA256", created.HashAlgorithm);
        Assert.Equal(2, created.ItemCount);
        Assert.Contains(created.CatalogItems, i => i.Path == "a.txt");
        Assert.Contains(created.CatalogItems, i => i.Path == "sub/b.txt");

        var tested = PortableCore.PortableTestFileCatalog(new PortableTestFileCatalogRequest
        {
            CatalogFilePath = catalog,
            Paths = [dir.DirPath],
        });
        Assert.Equal(PortableCatalogValidationStatus.Valid, tested.Status);
        Assert.Equal(PortableSignatureStatus.NotSigned, tested.Signature.Status);
        Assert.Equal(2, tested.PathItems.Count);
    }

    [Fact]
    public void FileCatalogReportsTamperAndSupportsSkip()
    {
        using var dir = new TempDir();
        var file = dir.File("a.txt");
        File.WriteAllBytes(file, "alpha"u8.ToArray());
        var catalog = dir.File("catalog.cat");
        PortableCore.PortableNewFileCatalog(new PortableNewFileCatalogRequest { CatalogFilePath = catalog, Paths = [dir.DirPath], CatalogVersion = 2 });
        File.WriteAllBytes(file, "tampered"u8.ToArray());

        var failed = PortableCore.PortableTestFileCatalog(new PortableTestFileCatalogRequest { CatalogFilePath = catalog, Paths = [dir.DirPath] });
        Assert.Equal(PortableCatalogValidationStatus.ValidationFailed, failed.Status);
        Assert.Contains(failed.PathItems, i => i.Path == "a.txt" && i.Status == PortableCatalogItemStatus.HashMismatch);

        var skipped = PortableCore.PortableTestFileCatalog(new PortableTestFileCatalogRequest
        {
            CatalogFilePath = catalog,
            Paths = [dir.DirPath],
            FilesToSkip = ["a.txt"],
        });
        Assert.Equal(PortableCatalogValidationStatus.Valid, skipped.Status);
        Assert.Equal(["a.txt"], skipped.SkippedItems);
    }

    [Fact]
    public void FileCatalogVersionOneUsesSha1AndRejectsUnknownVersions()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("a.txt"), "alpha"u8.ToArray());
        var created = PortableCore.PortableNewFileCatalog(new PortableNewFileCatalogRequest { CatalogFilePath = dir.DirPath, Paths = [dir.File("a.txt")], CatalogVersion = 1 });
        Assert.Equal("SHA1", created.HashAlgorithm);
        Assert.Equal(Path.Join(dir.DirPath, "catalog.cat"), created.CatalogFilePath);
        var e = Assert.Throws<PsignException>(() =>
            PortableCore.PortableNewFileCatalog(new PortableNewFileCatalogRequest { CatalogFilePath = dir.File("x.cat"), Paths = [dir.File("a.txt")], CatalogVersion = 3 }));
        Assert.Equal("catalog_version must be 1 or 2", e.Message);
    }

    [Fact]
    public void FileCatalogReportsMissingAndNotInCatalogMembers()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("src"));
        File.WriteAllBytes(Path.Combine(dir.DirPath, "src", "a.txt"), "alpha"u8.ToArray());
        File.WriteAllBytes(Path.Combine(dir.DirPath, "src", "b.txt"), "bravo"u8.ToArray());
        var catalog = dir.File("c.cat");
        PortableCore.PortableNewFileCatalog(new PortableNewFileCatalogRequest { CatalogFilePath = catalog, Paths = [dir.File("src")] });
        File.Delete(Path.Combine(dir.DirPath, "src", "b.txt"));
        File.WriteAllBytes(Path.Combine(dir.DirPath, "src", "c.txt"), "charlie"u8.ToArray());

        var tested = PortableCore.PortableTestFileCatalog(new PortableTestFileCatalogRequest { CatalogFilePath = catalog, Paths = [dir.File("src")] });
        Assert.Equal(PortableCatalogValidationStatus.ValidationFailed, tested.Status);
        Assert.Equal(["a.txt", "b.txt", "c.txt"], tested.PathItems.Select(i => i.Path));
        Assert.Equal(
            [PortableCatalogItemStatus.Valid, PortableCatalogItemStatus.Missing, PortableCatalogItemStatus.NotInCatalog],
            tested.PathItems.Select(i => i.Status));
    }

    [Fact]
    public void ReportsUnsignedPeWithoutError()
    {
        var response = PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(Fixtures.Path("pe-authenticode-upstream/tiny32.efi")));
        Assert.Equal(PortableSignatureStatus.NotSigned, response.Status);
    }

    [Fact]
    public void ReportsSignedPeAsValidDigestBinding()
    {
        var response = PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi")));
        Assert.Equal(PortableSignatureStatus.Valid, response.Status);
        Assert.True(response.SignatureCount > 0);
        Assert.NotNull(response.Pkcs7DerBase64);
    }

    [Fact]
    public void PeSignReplaceVsAppendSignatureCount()
    {
        using var dir = new TempDir();
        var source = Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi");
        var replaced = dir.File("tiny32.replaced.efi");
        var appended = dir.File("tiny32.appended.efi");
        PortableCore.PortableSign(PfxRequest(source, replaced));
        var append = PfxRequest(source, appended);
        append.AppendSignature = true;
        PortableCore.PortableSign(append);

        Assert.Equal(1, PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(replaced)).SignatureCount);
        Assert.Equal(2, PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(appended)).SignatureCount);
    }

    [Fact]
    public void PeSignAlignsCertificateTableAndHashesPaddingForEveryEofResidue()
    {
        using var dir = new TempDir();
        var fixture = Fixtures.Bytes("pe-authenticode-upstream/tiny32.efi");
        for (int overlay = 0; overlay < 8; overlay++)
        {
            var input = dir.File($"input-{overlay}.efi");
            var output = dir.File($"signed-{overlay}.efi");
            var bytes = fixture.Concat(Enumerable.Repeat((byte)0xa5, overlay)).ToArray();
            File.WriteAllBytes(input, bytes);
            PortableCore.PortableSign(PfxRequest(input, output));

            var signed = File.ReadAllBytes(output);
            var certOffset = PeCertificateTableOffset(signed);
            Assert.Equal(0, certOffset % 8);
            Assert.All(signed[bytes.Length..certOffset], b => Assert.Equal(0, b));
            Assert.NotNull(PeAuthenticode.VerifyDigestConsistencyIfSigned(signed));
        }
    }

    private static int PeCertificateTableOffset(byte[] pe)
    {
        int peOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(0x3c));
        int optionalHeader = peOffset + 24;
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(pe.AsSpan(optionalHeader));
        int firstDataDirectory = optionalHeader + magic switch
        {
            0x10b => 96,
            0x20b => 112,
            _ => throw new InvalidOperationException($"unsupported PE optional-header magic {magic:x}"),
        };
        return (int)BinaryPrimitives.ReadUInt32LittleEndian(pe.AsSpan(firstDataDirectory + (4 * 8)));
    }

    [Fact]
    public void PeSignSkipSignedSignsUnsignedAndSkipsValidPe()
    {
        using var dir = new TempDir();
        var unsigned = dir.File("tiny32.unsigned.efi");
        var alreadySigned = dir.File("tiny32.already-signed.efi");
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.efi"), unsigned);
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"), alreadySigned);

        var request = PfxRequest(unsigned);
        request.SkipSigned = true;
        var signed = PortableCore.PortableSign(request);
        Assert.False(signed.Skipped);
        Assert.Equal(1, signed.Signature.SignatureCount);

        var before = File.ReadAllBytes(alreadySigned);
        var skipRequest = PfxRequest(alreadySigned);
        skipRequest.SkipSigned = true;
        var skipped = PortableCore.PortableSign(skipRequest);
        Assert.True(skipped.Skipped);
        Assert.Equal(before, File.ReadAllBytes(alreadySigned));
        Assert.Equal(1, skipped.Signature.SignatureCount);
        Assert.Contains("\"skipped\":true", skipped.ToJson(), StringComparison.Ordinal);
        Assert.DoesNotContain("skipped", signed.ToJson(), StringComparison.Ordinal);
    }

    [Fact]
    public void PeSignSkipSignedCopiesValidPeToOutputPath()
    {
        using var dir = new TempDir();
        var source = Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi");
        var output = dir.File("tiny32.output.efi");
        var request = PfxRequest(source, output);
        request.SkipSigned = true;
        var response = PortableCore.PortableSign(request);
        Assert.True(response.Skipped);
        Assert.Equal(File.ReadAllBytes(source), File.ReadAllBytes(output));
        Assert.Equal(1, response.Signature.SignatureCount);
    }

    [Fact]
    public void PeSignSkipSignedRejectsCorruptExistingSignature()
    {
        using var dir = new TempDir();
        var target = dir.File("tiny32.corrupt-signed.efi");
        var corrupt = Fixtures.Bytes("pe-authenticode-upstream/tiny32.signed.efi");
        var ranges = PeAuthenticode.DigestFileRanges(corrupt);
        var offset = ranges.Last(r => r.End > r.Start).Start;
        corrupt[offset] ^= 0x01;
        Assert.ThrowsAny<PsignException>(() => PeAuthenticode.VerifyDigestConsistency(corrupt));
        File.WriteAllBytes(target, corrupt);

        var request = PfxRequest(target);
        request.SkipSigned = true;
        var e = Assert.Throws<PsignException>(() => PortableCore.PortableSign(request));
        var msg = e.FullMessage;
        Assert.Contains("check existing PE/WinMD Authenticode signature", msg, StringComparison.Ordinal);
        Assert.Contains("mismatch", msg, StringComparison.Ordinal);
        Assert.Equal(corrupt, File.ReadAllBytes(target));
    }

    [Fact]
    public void RejectsMixedAzureKeyVaultAndLocalMaterial()
    {
        var request = new PortableSignRequest
        {
            Path = "test.dll",
            AzureKeyVaultUrl = "https://myvault.vault.azure.net",
            AzureKeyVaultCertificate = "my-cert",
            CertificatePath = "cert.pem",
            PrivateKeyPath = "key.pem",
        };
        var e = Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(request));
        Assert.Contains("not both", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RejectsMixedAzureKeyVaultAndArtifactSigning()
    {
        var request = new PortableSignRequest
        {
            Path = "test.dll",
            AzureKeyVaultUrl = "https://myvault.vault.azure.net",
            AzureKeyVaultCertificate = "my-cert",
            ArtifactSigningEndpoint = "https://signing.example.com",
        };
        var e = Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(request));
        Assert.Contains("not both", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalMaterialLoaderRejectsCloudProviders()
    {
        var akv = Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(new PortableSignRequest
        {
            Path = "test.dll",
            AzureKeyVaultUrl = "https://myvault.vault.azure.net",
            AzureKeyVaultCertificate = "my-cert",
        }));
        Assert.Contains("Azure Key Vault", akv.Message, StringComparison.Ordinal);

        var artifact = Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(new PortableSignRequest
        {
            Path = "test.dll",
            ArtifactSigningEndpoint = "https://signing.example.com",
        }));
        Assert.Contains("Artifact Signing", artifact.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LocalMaterialValidationMessages()
    {
        Assert.Equal(
            "provide either pfx_path or certificate/private key material, not both",
            Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(new PortableSignRequest { Path = "a.exe", PfxPath = "x.pfx", CertificatePath = "c" })).Message);
        Assert.Equal(
            "portable signing requires certificate_der_base64 or certificate_path",
            Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(new PortableSignRequest { Path = "a.exe", PrivateKeyPath = "k" })).Message);
        Assert.Equal(
            "provide only one of certificate_der_base64 or certificate_path",
            Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(new PortableSignRequest { Path = "a.exe", CertificatePath = "c", CertificateDerBase64 = "AA==" })).Message);
        Assert.Equal(
            "decode certificate_der_base64",
            Assert.Throws<PsignException>(() => PortableCore.LoadSigningMaterial(new PortableSignRequest { Path = "a.exe", CertificateDerBase64 = "not base64!", PrivateKeyDerBase64 = "AA==" })).Message);
    }

    [Fact]
    public void SignsWithCertificateAndKeyMaterialInline()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var target = dir.File("a.ps1");
        File.WriteAllBytes(target, "Write-Output 1\r\n"u8.ToArray());
        var response = PortableCore.PortableSign(new PortableSignRequest
        {
            Path = target,
            CertificateDerBase64 = Convert.ToBase64String(signer.Certificate.RawData),
            PrivateKeyDerBase64 = Convert.ToBase64String(signer.Key.ExportPkcs8PrivateKey()),
            HashAlgorithm = PortableDigestAlgorithm.Sha384,
        });
        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
        Assert.Equal(Convert.ToBase64String(signer.Certificate.RawData), response.Signature.SignerCertificateDerBase64);
        Assert.Equal("2.16.840.1.101.3.4.2.2", response.Signature.DigestAlgorithm);
    }

    [Fact]
    public void SigningRejectsUnsupportedFormats()
    {
        using var dir = new TempDir();
        foreach (var (name, message) in new[]
        {
            ("a.vbs", "portable WSH script signing is not supported yet"),
            ("a.cat", "portable catalog signing requires an explicit subject list and is not available through PortableSignRequest yet"),
            ("a.msixupload", "portable signing does not support MSIX/AppX upload bundles"),
            ("a.emsix", "portable signing does not support encrypted MSIX/AppX packages"),
            ("a.bin", "unsupported portable signing format"),
        })
        {
            var e = Assert.Throws<PsignException>(() => PortableCore.PortableSign(PfxRequest(dir.File(name))));
            Assert.StartsWith(message, e.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TimestampAlgorithmRequiresServer()
    {
        using var dir = new TempDir();
        var target = dir.File("a.ps1");
        File.WriteAllBytes(target, "Write-Output 1\r\n"u8.ToArray());
        var request = PfxRequest(target);
        request.TimestampHashAlgorithm = PortableTimestampDigestAlgorithm.Sha256;
        var e = Assert.Throws<PsignException>(() => PortableCore.PortableSign(request));
        Assert.Equal("timestamp " + target, e.Message);
        Assert.Equal("timestamp_hash_algorithm requires timestamp_server", e.InnerException!.Message);
    }

    [Fact]
    public void ClearsPeSignatureAndReportsNoTable()
    {
        using var dir = new TempDir();
        var target = dir.File("tiny32.efi");
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"), target);
        var cleared = PortableCore.PortableClearSignature(new PortableClearSignatureRequest { Path = target });
        Assert.True(cleared.SignatureRemoved);
        Assert.True(cleared.BytesRemoved > 0);
        Assert.Equal("PE Authenticode certificate table removed.", cleared.Message);
        Assert.Equal(PortableSignatureStatus.NotSigned, PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(target)).Status);

        var again = PortableCore.PortableClearSignature(new PortableClearSignatureRequest { Path = target });
        Assert.False(again.SignatureRemoved);
        Assert.Equal(0, again.BytesRemoved);
        Assert.Equal("No PE Authenticode certificate table found.", again.Message);

        var script = dir.File("a.ps1");
        File.WriteAllText(script, "x");
        Assert.Equal(
            "portable signature clear is not supported for PowerShellScript; use script signature removal for PowerShell files",
            Assert.Throws<PsignException>(() => PortableCore.PortableClearSignature(new PortableClearSignatureRequest { Path = script })).Message);
    }

    [Fact]
    public void ParsesAsOfDates()
    {
        Assert.Equal(new DateTimeOffset(2024, 2, 29, 0, 0, 0, TimeSpan.Zero), PortableCore.ParseUtcDate("2024-02-29"));
        Assert.Equal(new DateTimeOffset(2024, 2, 29, 0, 0, 0, TimeSpan.Zero), PortableCore.ParseUtcDate("2024-02-29T13:00:00Z"));
        Assert.Equal("invalid as_of date '2023-02-29': expected a valid yyyy-MM-dd date", Assert.Throws<PsignException>(() => PortableCore.ParseUtcDate("2023-02-29")).Message);
        Assert.Equal("invalid as_of date '2023-02-01-1': expected yyyy-MM-dd", Assert.Throws<PsignException>(() => PortableCore.ParseUtcDate("2023-02-01-1")).Message);
        Assert.Equal("missing month in as_of date", Assert.Throws<PsignException>(() => PortableCore.ParseUtcDate("2023")).Message);
        Assert.Equal("invalid year in as_of date 'x-1-1'", Assert.Throws<PsignException>(() => PortableCore.ParseUtcDate("x-1-1")).Message);
    }

    [Fact]
    public void ArtifactSigningCredentialTypeNames()
    {
        Assert.Equal(Devolutions.Psign.Signing.ArtifactSigning.CodesigningCredentialType.ManagedIdentity, PortableCore.ParseArtifactSigningCredentialType("Managed-Identity"));
        Assert.Equal(Devolutions.Psign.Signing.ArtifactSigning.CodesigningCredentialType.AccessToken, PortableCore.ParseArtifactSigningCredentialType("bearer"));
        Assert.Equal(Devolutions.Psign.Signing.ArtifactSigning.CodesigningCredentialType.Default, PortableCore.ParseArtifactSigningCredentialType(""));
        Assert.Equal(
            "unsupported Artifact Signing credential type 'nope'",
            Assert.Throws<PsignException>(() => PortableCore.ParseArtifactSigningCredentialType("nope")).Message);
    }

    // ---------------------------------------------------------------- MSIX layout (Rust regression tests)

    [Fact]
    public void SignedFlatMsixBlockMapUsesBackslashSeparators()
    {
        using var dir = new TempDir();
        var output = dir.File("sample.signed.msix");
        PortableCore.PortableSign(PfxRequest(Fixtures.Path("generated-unsigned/msix/sample.msix"), output));

        var archive = ZipCrateArchive.Open(File.ReadAllBytes(output));
        var physical = archive.Entries.Select(e => e.Name).ToList();
        Assert.Contains("Assets/StoreLogo.png", physical);
        Assert.DoesNotContain(physical, n => n.Contains('\\', StringComparison.Ordinal));

        var blockMap = Encoding.UTF8.GetString(archive.Read(archive.RequireByName("AppxBlockMap.xml")));
        var names = new List<string>();
        const string marker = "<File Name=\"";
        int idx = 0;
        while ((idx = blockMap.IndexOf(marker, idx, StringComparison.Ordinal)) >= 0)
        {
            idx += marker.Length;
            int end = blockMap.IndexOf('"', idx);
            names.Add(blockMap[idx..end]);
            idx = end;
        }

        Assert.NotEmpty(names);
        Assert.Equal("Assets\\StoreLogo.png", names.First(n => n.Contains("StoreLogo.png", StringComparison.Ordinal)));
        Assert.DoesNotContain(names, n => n.Contains('/', StringComparison.Ordinal));
        foreach (var p in physical.Where(p => p is not ("AppxSignature.p7x" or "AppxBlockMap.xml" or "[Content_Types].xml")))
        {
            Assert.Contains(p.Replace('/', '\\'), names);
        }
    }

    private static void AssertAppxZipLayout(byte[] zip, string label)
    {
        ushort U16(int o) => BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(o));
        uint U32(int o) => BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(o));
        ulong U64(int o) => BinaryPrimitives.ReadUInt64LittleEndian(zip.AsSpan(o));

        int eocd = zip.Length - 22;
        Assert.True(U32(eocd) == 0x06054b50, $"{label}: classic EOCD at end");
        Assert.True(zip[(eocd + 4)..(eocd + 20)].All(b => b == 0xFF), $"{label}: classic EOCD fields must be ZIP64 sentinels");
        int locator = eocd - 20;
        Assert.True(U32(locator) == 0x07064b50, $"{label}: ZIP64 locator");
        Assert.True(U32(locator + 16) == 1, $"{label}: locator disk count");
        int zip64 = checked((int)U64(locator + 8));
        Assert.True(zip64 + 56 == locator, $"{label}: ZIP64 EOCD precedes locator");
        Assert.True(U32(zip64) == 0x06064b50, $"{label}: ZIP64 EOCD signature");
        Assert.True(U64(zip64 + 4) == 44, $"{label}: ZIP64 EOCD record size");
        Assert.True(U16(zip64 + 12) == 45, $"{label}: ZIP64 version made by");
        Assert.True(U16(zip64 + 14) == 45, $"{label}: ZIP64 version needed");
        ulong entries = U64(zip64 + 32);
        int cdSize = checked((int)U64(zip64 + 40));
        int cdOffset = checked((int)U64(zip64 + 48));
        Assert.True(cdOffset + cdSize == zip64, $"{label}: CD ends at ZIP64 EOCD");
        int p = cdOffset;
        ulong seen = 0;
        while (p < zip64)
        {
            Assert.True(U32(p) == 0x02014b50, $"{label}: CD entry signature");
            Assert.True(U16(p + 4) == 45, $"{label}: CD version made by");
            Assert.True(U32(p + 38) == 0, $"{label}: CD external attributes");
            p += 46 + U16(p + 28) + U16(p + 30) + U16(p + 32);
            seen++;
        }

        Assert.Equal(entries, seen);
        ZipCrateArchive.Open(zip);
    }

    [Fact]
    public void StagedBundleManifestOffsetsMatchChildPayloads()
    {
        var children = new (string Name, byte[] Data)[] { ("x64 & test.msix", "first child"u8.ToArray()), ("arm64-é.msix", "second child"u8.ToArray()) };
        var manifest = "<Bundle xmlns=\"http://schemas.microsoft.com/appx/2013/bundle\"><Packages>"
            + "<Package FileName=\"arm64-&#233;.msix\" Offset=\"9999\" Size=\"1\"/>"
            + "<Package FileName=\"x64 &amp; test.msix\" Offset=\"8888\" Size=\"2\"><Resources/></Package>"
            + "</Packages></Bundle>";
        byte[] source;
        using (var ms = new MemoryStream())
        {
            using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var (name, data) in children.Append(("AppxMetadata/AppxBundleManifest.xml", Encoding.UTF8.GetBytes(manifest))))
                {
                    using var s = zip.CreateEntry(name).Open();
                    s.Write(data);
                }
            }

            source = ms.ToArray();
        }

        var staged = AppxPackage.StageMsixFamilyForSignature(source, "msixbundle", AuthenticodeHashKind.Sha256);
        var signedLayout = AppxPackage.ReplaceMsixSignaturePart(staged, "PKCX replacement"u8.ToArray());
        foreach (var package in new[] { staged, signedLayout })
        {
            var archive = ZipCrateArchive.Open(package);
            var xml = Encoding.UTF8.GetString(archive.Read(archive.RequireByName("AppxMetadata/AppxBundleManifest.xml")));
            long expectedOffset = 0;
            foreach (var ((name, data), (opcName, escaped)) in children.Zip(new[] { ("x64%20%26%20test.msix", "x64 &amp; test.msix"), ("arm64-%C3%A9.msix", "arm64-&#233;.msix") }))
            {
                var entry = archive.RequireByName(opcName);
                expectedOffset += 30 + opcName.Length;
                Assert.Equal((ulong)expectedOffset, archive.DataStart(entry));
                Assert.Contains($"FileName=\"{escaped}\" Offset=\"{expectedOffset}\" Size=\"{data.Length}\"", xml, StringComparison.Ordinal);
                Assert.Equal(data, archive.Read(entry));
                expectedOffset += data.Length;
            }
        }

        Assert.Contains(
            "missing from ZIP",
            Assert.Throws<PsignException>(() => AppxPackage.BundleManifestForStoredChildren(Encoding.UTF8.GetBytes(manifest), [])).Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void StagedAndSignedMsixUseAppxZip64Layout()
    {
        using var dir = new TempDir();
        foreach (var name in new[] { "sample.msix", "sample.appx", "sample.msixbundle", "sample.appxbundle" })
        {
            var source = Fixtures.Path("generated-unsigned/msix/" + name);
            var ext = name[(name.LastIndexOf('.') + 1)..];
            var staged = AppxPackage.StageMsixFamilyForSignature(File.ReadAllBytes(source), ext, AuthenticodeHashKind.Sha256);
            AssertAppxZipLayout(staged, "staged " + name);

            var output = dir.File(name);
            PortableCore.PortableSign(PfxRequest(source, output));
            var signed = File.ReadAllBytes(output);
            AssertAppxZipLayout(signed, "signed " + name);
            MsixDigest.MsixVerifiedSignature(signed, ext);
        }
    }

    [Fact]
    public void SignsPlainZipPackageWithoutMakeappxMetadata()
    {
        using var dir = new TempDir();
        var manifest = Fixtures.Bytes("msix-minimal/AppxManifest.xml");
        var index = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 40_000).Select(i => $"package-{i:D6}|Contoso.App|1.{i % 97}.0\n")));
        var source = dir.File("source2.msix");
        using (var fs = File.Create(source))
        using (var zip = new System.IO.Compression.ZipArchive(fs, System.IO.Compression.ZipArchiveMode.Create))
        {
            foreach (var (name, data) in new[] { ("AppxManifest.xml", manifest), ("Public/index.db", index), ("Assets/StoreLogo.png", "\x89PNG not really"u8.ToArray()) })
            {
                using var s = zip.CreateEntry(name, System.IO.Compression.CompressionLevel.Optimal).Open();
                s.Write(data);
            }
        }

        var output = dir.File("source2.signed.msix");
        PortableCore.PortableSign(PfxRequest(source, output));
        var signed = File.ReadAllBytes(output);
        AssertAppxZipLayout(signed, "signed plain ZIP");
        MsixDigest.MsixVerifiedSignature(signed, "msix");
        Assert.True(signed.Length < index.Length / 4, $"payload must stay compressed ({signed.Length} bytes)");

        var archive = ZipCrateArchive.Open(signed);
        Assert.Equal(8, archive.RequireByName("Public/index.db").CompressionMethod);
        Assert.Equal(0, archive.RequireByName("Assets/StoreLogo.png").CompressionMethod);
        var contentTypes = Encoding.UTF8.GetString(archive.Read(archive.RequireByName("[Content_Types].xml")));
        foreach (var expected in new[]
        {
            "<Default Extension=\"db\" ContentType=\"application/octet-stream\"/>",
            "<Default Extension=\"xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/>",
            "<Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/>",
            "<Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/>",
        })
        {
            Assert.Contains(expected, contentTypes, StringComparison.Ordinal);
        }

        var blockMap = Encoding.UTF8.GetString(archive.Read(archive.RequireByName("AppxBlockMap.xml")));
        var indexFile = blockMap.Split("<File ").First(f => f.StartsWith("Name=\"Public\\index.db\"", StringComparison.Ordinal));
        var blocks = indexFile.Split("<Block ").Skip(1).ToList();
        Assert.Equal((index.Length + 65535) / 65536, blocks.Count);
        Assert.All(blocks, b => Assert.Contains(" Size=\"", b, StringComparison.Ordinal));
    }

    [Fact]
    public void SkipSignedLeavesSignedMsixUnchanged()
    {
        using var dir = new TempDir();
        var signedPath = dir.File("signed.msix");
        PortableCore.PortableSign(PfxRequest(Fixtures.Path("generated-unsigned/msix/sample.msix"), signedPath));
        var before = File.ReadAllBytes(signedPath);
        var output = dir.File("copy.msix");
        var request = PfxRequest(signedPath, output);
        request.SkipSigned = true;
        var response = PortableCore.PortableSign(request);
        Assert.True(response.Skipped);
        Assert.Equal(before, File.ReadAllBytes(output));
        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
    }

    [Fact]
    public void AppInstallerSignWritesCompanionNextToOutput()
    {
        using var dir = new TempDir();
        var output = dir.File("out.appinstaller");
        var response = PortableCore.PortableSign(PfxRequest(Fixtures.Path("generated-unsigned/appinstaller/sample.appinstaller"), output));
        Assert.True(File.Exists(output + ".p7"));
        Assert.Equal(Fixtures.Bytes("generated-unsigned/appinstaller/sample.appinstaller"), File.ReadAllBytes(output));
        Assert.Equal(PortableFileFormat.AppInstaller, response.Format);
        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
    }

    [Fact]
    public void ClickOnceSignIsInspectableAndVerifiable()
    {
        using var dir = new TempDir();
        var manifest = dir.File("app.exe.manifest");
        File.WriteAllText(manifest, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n  <assemblyIdentity name=\"Portable.Sample\" version=\"1.0.0.0\" />\n</assembly>\n");
        var response = PortableCore.PortableSign(PfxRequest(manifest));
        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
        var report = Devolutions.Psign.Core.ClickOnce.ClickOnceManifest.VerifyManifestSignaturePath(manifest, null, AuthenticodeHashKind.Sha256);
        Assert.True(report.SignatureLen > 0);

        // Re-signing replaces the first signature instead of nesting a second one.
        PortableCore.PortableSign(PfxRequest(manifest));
        var text = File.ReadAllText(manifest);
        Assert.Equal(1, text.Split("<Signature ").Length - 1);
    }

    [Fact]
    public void NuGetAndVsixSignaturesVerifyAgainstTestCa()
    {
        using var dir = new TempDir();
        var clock = new DateTimeOffset(2025, 3, 4, 5, 6, 7, TimeSpan.Zero);
        var options = new PortableCoreOptions { Clock = () => clock, ZipClock = () => ZipDateTime.FromDateAndTime(2025, 3, 4, 5, 6, 8)!.Value };
        foreach (var fixture in new[] { "package-signing/unsigned/sample.nupkg", "package-signing/unsigned/with-pe.nupkg", "package-signing/unsigned/sample.vsix", "package-signing/unsigned/nested.vsix" })
        {
            var output = dir.File(Path.GetFileName(fixture));
            var request = PfxRequest(Fixtures.Path(fixture), output);
            var response = PortableCore.PortableSign(request, options);
            Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);

            var trusted = PortableGetSignatureRequest.PathOnly(output);
            trusted.TrustedCertificatePaths = [TestCa];
            trusted.AsOf = "2025-03-04";
            var verified = PortableCore.PortableGetSignature(trusted);
            Assert.True(verified.TrustStatus == PortableSignatureStatus.Valid, $"{fixture}: {verified.StatusMessage}");

            // Deterministic with an injected clock.
            var again = dir.File("again-" + Path.GetFileName(fixture));
            PortableCore.PortableSign(PfxRequest(Fixtures.Path(fixture), again), options);
            Assert.Equal(File.ReadAllBytes(output), File.ReadAllBytes(again));
        }
    }

    [Fact]
    public void InspectsUnsupportedAndEncryptedFormats()
    {
        using var dir = new TempDir();
        var bin = dir.File("data.bin");
        File.WriteAllText(bin, "hello");
        var unknown = PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(bin));
        Assert.Equal(PortableSignatureStatus.NotSupportedFileFormat, unknown.Status);
        Assert.Equal(PortableFileFormat.Unknown, unknown.Format);

        var e = Assert.Throws<PsignException>(() =>
            PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(Fixtures.Path("generated-unsigned/msix-encrypted-negative/placeholder.emsix"))));
        Assert.StartsWith("encrypted MSIX/AppX packages require Windows AppxSip OS delegation", e.Message, StringComparison.Ordinal);

        var missing = Assert.Throws<PsignException>(() => PortableCore.PortableGetSignature(PortableGetSignatureRequest.PathOnly(dir.File("missing.exe"))));
        Assert.Equal("read " + dir.File("missing.exe"), missing.Message);
    }
}
