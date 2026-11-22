using System.Buffers.Binary;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Zip;
using Xunit;
using static Devolutions.Psign.Tests.Core.PackageTestUtil;

namespace Devolutions.Psign.Tests.Core;

public class NuGetPackageTests
{
    private const string Sig = NuGetPackage.PackageSignatureFileName;

    [Fact]
    public void SignedPackageUnsignedBytesReproducesDotnetSignedFixture()
    {
        var signed = Fixtures.Bytes("package-signing/signed/sample.signed.nupkg");
        var unsigned = Fixtures.Bytes("package-signing/unsigned/sample.nupkg");
        Assert.Equal(unsigned, NuGetPackage.SignedPackageUnsignedBytes(signed));
    }

    [Fact]
    public void SignatureFileNameIsCaseSensitive()
    {
        var info = NuGetPackage.InspectNupkg(NuZip((Sig, B("cms"))));
        Assert.True(info.Signed);
        Assert.Equal(3ul, info.SignatureLen);
        Assert.Equal(true, info.SignatureIsStored);
        Assert.Equal(false, NuGetPackage.InspectNupkg(ZipWith((Sig, B("cms")))).SignatureIsStored);
        Assert.False(NuGetPackage.InspectNupkg(NuZip((".Signature.p7s", B("cms")))).Signed);
    }

    [Fact]
    public void HashPropertyUsesNuGetOid()
    {
        Assert.Equal("2.16.840.1.101.3.4.2.1-Hash", NuGetPackage.PackageHashPropertyName(NuGetHashAlgorithm.Sha256));
    }

    [Fact]
    public void SignatureContentRoundTripsPackageHashProperty()
    {
        var bytes = NuGetPackage.SignatureContentBytes(NuGetHashAlgorithm.Sha384, B("package-digest"));
        var parsed = NuGetPackage.ParseSignatureContent(bytes);
        Assert.Equal(NuGetHashAlgorithm.Sha384, parsed.HashAlgorithm);
        Assert.Equal(B("package-digest"), parsed.PackageHash);
        Assert.Equal("Version:1\n\n2.16.840.1.101.3.4.2.2-Hash:cGFja2FnZS1kaWdlc3Q=\n\n", System.Text.Encoding.UTF8.GetString(bytes));
    }

    [Theory]
    [InlineData("Version:2\n\n2.16.840.1.101.3.4.2.1-Hash:cGFja2FnZS1kaWdlc3Q=\n\n", "unsupported")]
    [InlineData("\n\n2.16.840.1.101.3.4.2.1-Hash:cGFja2FnZS1kaWdlc3Q=\n\n", "missing Version")]
    [InlineData("Version:1", "missing package hash section")]
    [InlineData("Version:1\n\n1.2.3-Hash:AA==\n\n", "supported package hash property")]
    [InlineData("Version:1\n\n2.16.840.1.101.3.4.2.1-Hash:%%%\n\n", "not valid base64")]
    [InlineData("Version\n\nx", "invalid NuGet signature content line \"Version\"")]
    public void SignatureContentRejectsInvalidInput(string content, string expected)
    {
        var e = Assert.Throws<PsignException>(() => NuGetPackage.ParseSignatureContent(B(content)));
        Assert.Contains(expected, PsignException.Render(e));
    }

    [Fact]
    public void UnsignedPackageSignatureContentVerifiesMatchingDigest()
    {
        using var dir = new TempDir();
        var tmp = dir.File("unsigned-for-content.nupkg");
        File.WriteAllBytes(tmp, NuZip(("lib/net8.0/a.dll", B("pe"))));

        var content = NuGetPackage.UnsignedPackageSignatureContentPath(tmp, NuGetHashAlgorithm.Sha256);
        var parsed = NuGetPackage.VerifyUnsignedPackageSignatureContentPath(tmp, content);
        var canonical = NuGetPackage.CanonicalUnsignedPackageBytesPath(tmp);

        Assert.Equal(NuGetHashAlgorithm.Sha256, parsed.HashAlgorithm);
        Assert.Equal(NuGetHashAlgorithm.Sha256.Hash(canonical), parsed.PackageHash);
    }

    [Fact]
    public void UnsignedPackageSignatureContentRejectsTamperedPackage()
    {
        using var dir = new TempDir();
        var tmp = dir.File("tampered-for-content.nupkg");
        File.WriteAllBytes(tmp, NuZip(("lib/net8.0/a.dll", B("pe"))));
        var content = NuGetPackage.UnsignedPackageSignatureContentPath(tmp, NuGetHashAlgorithm.Sha256);
        File.WriteAllBytes(tmp, NuZip(("lib/net8.0/a.dll", B("changed"))));

        var e = Assert.Throws<PsignException>(() => NuGetPackage.VerifyUnsignedPackageSignatureContentPath(tmp, content));
        Assert.Contains("hash mismatch", e.Message);
    }

    [Fact]
    public void EmbedSignatureAddsStoredRootSignature()
    {
        var signed = NuGetPackage.EmbedSignature(NuZip(("lib/net8.0/a.dll", B("pe"))), B("cms"), false);
        var info = OpcPackage.InspectPackage(signed);
        Assert.Equal(3ul, info.Entry(Sig)!.UncompressedSize);
        Assert.Equal("Stored", info.Entry(Sig)!.Compression);
        AssertNoUnixCentralDirectoryMetadata(signed);
    }

    [Fact]
    public void EmbedSignaturePreservesExistingEntryTimestamps()
    {
        var original = ZipDateTime.FromDateAndTime(2001, 2, 3, 4, 5, 6)!.Value;
        var zip = ZipWithTimestamps(("lib/net8.0/a.dll", B("pe"), original));
        var archive = ZipCrateArchive.Open(NuGetPackage.EmbedSignature(zip, B("cms"), false));
        Assert.Equal(original, archive.ByName("lib/net8.0/a.dll")!.LastModified);
        Assert.NotEqual(ZipDateTime.Default, archive.ByName(Sig)!.LastModified);
    }

    [Fact]
    public void EmbedSignatureRejectsExistingSignatureWithoutOverwrite()
    {
        var e = Assert.Throws<PsignException>(() => NuGetPackage.EmbedSignature(NuZip((Sig, B("old"))), B("new"), false));
        Assert.Contains("already contains", e.Message);
    }

    [Fact]
    public void EmbedSignatureReplacesExistingSignatureWithOverwrite()
    {
        var info = OpcPackage.InspectPackage(NuGetPackage.EmbedSignature(NuZip((Sig, B("old"))), B("new-signature"), true));
        Assert.Equal(13ul, info.Entry(Sig)!.UncompressedSize);
    }

    [Fact]
    public void ExtractSignatureReturnsEmbeddedSignatureBytes()
    {
        Assert.Equal(B("cms"), NuGetPackage.ExtractSignature(NuZip(("lib/net8.0/a.dll", B("pe")), (Sig, B("cms")))));
    }

    [Fact]
    public void WritePackageWithoutSignatureRemovesRootSignature()
    {
        var info = OpcPackage.InspectPackage(NuGetPackage.WritePackageWithoutSignature(NuZip(("lib/net8.0/a.dll", B("pe")), (Sig, B("cms")))));
        Assert.Null(info.Entry(Sig));
        Assert.Equal(2ul, info.Entry("lib/net8.0/a.dll")!.UncompressedSize);
        Assert.Throws<PsignException>(() => NuGetPackage.WritePackageWithoutSignature(NuZip(("a", B("pe")))));
    }

    [Fact]
    public void WritePackageWithoutSignaturePreservesExistingEntryTimestamps()
    {
        var original = ZipDateTime.FromDateAndTime(2004, 5, 6, 7, 8, 10)!.Value;
        var zip = ZipWithTimestamps(("lib/net8.0/a.dll", B("pe"), original), (Sig, B("cms"), ZipDateTime.FromDateAndTime(2005, 6, 7, 8, 9, 10)!.Value));
        var archive = ZipCrateArchive.Open(NuGetPackage.WritePackageWithoutSignature(zip));
        Assert.Equal(original, archive.ByName("lib/net8.0/a.dll")!.LastModified);
    }

    [Fact]
    public void EmbedSignatureClearsUnixCentralDirectoryMetadata()
    {
        var zip = NuZip(("lib/net8.0/a.dll", B("pe")));
        MarkCentralDirectoryEntriesAsUnix(zip);
        Assert.Contains(CentralDirectoryEntries(zip), e => e.HostOs == 3 && e.Attrs != 0);
        AssertNoUnixCentralDirectoryMetadata(NuGetPackage.EmbedSignature(zip, B("cms"), false));
    }

    [Fact]
    public void WritePackageWithoutSignatureClearsUnixCentralDirectoryMetadata()
    {
        var zip = NuZip(("lib/net8.0/a.dll", B("pe")), (Sig, B("cms")));
        MarkCentralDirectoryEntriesAsUnix(zip);
        AssertNoUnixCentralDirectoryMetadata(NuGetPackage.WritePackageWithoutSignature(zip));
    }

    [Fact]
    public void CanonicalUnsignedPackageRejectsTruncatedCentralDirectory()
    {
        var zip = NuZip(("lib/net8.0/a.dll", B("pe")));
        int eocd = zip.Length - 22;
        BinaryPrimitives.WriteUInt32LittleEndian(zip.AsSpan(eocd + 12), uint.MaxValue);
        var e = Assert.Throws<PsignException>(() => NuGetPackage.NormalizeNuGetZipMetadata(zip));
        Assert.Contains("central directory", e.Message);
    }

    [Fact]
    public void SignedPackageUnsignedBytesRequiresLastSignature()
    {
        var e = Assert.Throws<PsignException>(() => NuGetPackage.SignedPackageUnsignedBytes(NuZip(("a", B("pe")))));
        Assert.Contains("does not contain", e.Message);
        e = Assert.Throws<PsignException>(() => NuGetPackage.SignedPackageUnsignedBytes(NuZip((Sig, B("cms")), ("a", B("pe")))));
        Assert.Contains("single, last central directory record", e.Message);
    }

    [Fact]
    public void UnsignedDigestRejectsSignedFixture()
    {
        var e = Assert.Throws<PsignException>(() => NuGetPackage.UnsignedPackageDigestPath(Fixtures.Path("package-signing/signed/sample.signed.nupkg"), NuGetHashAlgorithm.Sha256));
        Assert.Contains("already contains .signature.p7s", e.Message);
    }

    // ---------------------------------------------------------------- differential vs Rust

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void SignatureContentMatchesRust(string alg)
    {
        RustTool.Require();
        using var dir = new TempDir();
        foreach (var rel in new[] { "package-signing/unsigned/sample.nupkg", "package-signing/unsigned/with-pe.nupkg", "package-signing/signed/sample.signed.nupkg" })
        {
            var outPath = dir.File("content.txt");
            RustTool.RunOk("portable", "nupkg-signature-content", Fixtures.Path(rel), "--algorithm", alg, "--output", outPath);
            var algorithm = NuGetHashAlgorithmExtensions.FromHashKind(AuthenticodeHashKinds.Parse(alg));
            Assert.Equal(File.ReadAllBytes(outPath), NuGetPackage.UnsignedPackageSignatureContentPath(Fixtures.Path(rel), algorithm));
        }
    }

    [SkippableFact]
    public void DigestAndInfoMatchRust()
    {
        RustTool.Require();
        var unsigned = Fixtures.Path("package-signing/unsigned/sample.nupkg");
        var rust = RustTool.RunOk("portable", "nupkg-digest", unsigned, "--algorithm", "sha384").Trim();
        Assert.Equal(rust, Hex.Lower(NuGetPackage.UnsignedPackageDigestPath(unsigned, NuGetHashAlgorithm.Sha384)));

        var signed = Fixtures.Path("package-signing/signed/sample.signed.nupkg");
        var info = NuGetPackage.InspectNupkgPath(signed);
        var expected = $"signed=yes\nsignature_file={Sig}\nsignature_len={info.SignatureLen}\nsignature_stored={(info.SignatureIsStored == true ? "yes" : "no")}\nentries={info.Package.Entries.Count}\n";
        Assert.Equal(expected, RustTool.RunOk("portable", "nupkg-signature-info", signed).Replace("\r\n", "\n"));
    }

    [SkippableFact]
    public void EmbedSignatureIsByteIdenticalToRustForFixtures()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var sigPath = dir.File("sig.p7s");
        File.WriteAllBytes(sigPath, B("not-really-a-cms-but-opaque"));
        foreach (var rel in new[] { "package-signing/unsigned/sample.nupkg", "package-signing/unsigned/with-pe.nupkg", "package-signing/unsigned/sample.snupkg" })
        {
            AssertEmbedMatchesRust(dir, File.ReadAllBytes(Fixtures.Path(rel)), sigPath, overwrite: false);
        }

        AssertEmbedMatchesRust(dir, File.ReadAllBytes(Fixtures.Path("package-signing/signed/sample.signed.nupkg")), sigPath, overwrite: true);
    }

    [SkippableFact]
    public void EmbedSignatureRecompressionMatchesRustForStressPayloads()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var sigPath = dir.File("sig.p7s");
        File.WriteAllBytes(sigPath, B("cms"));
        var entries = StressPayloads().Select(p => (p.Name, p.Data, p.Name.EndsWith("zeros.bin", StringComparison.Ordinal))).ToArray();
        AssertEmbedMatchesRust(dir, BclZip(entries), sigPath, overwrite: false);
    }

    [SkippableFact]
    public void CanonicalBytesAreTheUnsignedPartOfTheRustSignedPackage()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var sigPath = dir.File("sig.p7s");
        File.WriteAllBytes(sigPath, B("cms"));
        var outPath = dir.File("out.nupkg");
        var input = Fixtures.Path("package-signing/unsigned/with-pe.nupkg");
        RustTool.RunOk("portable", "nupkg-embed-signature", input, "--signature", sigPath, "--output", outPath);
        Assert.Equal(NuGetPackage.CanonicalUnsignedPackageBytesPath(input), NuGetPackage.SignedPackageUnsignedBytes(File.ReadAllBytes(outPath)));
    }

    private static void AssertEmbedMatchesRust(TempDir dir, byte[] input, string sigPath, bool overwrite)
    {
        var inPath = dir.File("in.nupkg");
        var outPath = dir.File("rust.nupkg");
        File.WriteAllBytes(inPath, input);
        var args = new List<string> { "portable", "nupkg-embed-signature", inPath, "--signature", sigPath, "--output", outPath };
        if (overwrite)
        {
            args.Add("--overwrite");
        }

        RustTool.RunOk([.. args]);
        var rust = File.ReadAllBytes(outPath);
        var stamp = ZipCrateArchive.Open(rust).ByName(Sig)!.LastModified;
        var cs = NuGetPackage.EmbedSignature(input, File.ReadAllBytes(sigPath), overwrite, stamp);
        Assert.Equal(rust, cs);
    }

    /// <summary>Rust nuget test helper <c>zip_with</c> (signature entry stored, default timestamps).</summary>
    private static byte[] NuZip(params (string Name, byte[] Data)[] entries) =>
        ZipWithTimestamps(entries.Select(e => (e.Name, e.Data, ZipDateTime.Default)).ToArray());

    private static List<(string Name, byte HostOs, uint Attrs)> CentralDirectoryEntries(byte[] bytes)
    {
        int eocd = bytes.Length - 22;
        int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd + 12));
        int offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd + 16));
        var result = new List<(string, byte, uint)>();
        int pos = offset;
        while (pos < offset + size)
        {
            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pos + 28));
            int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pos + 30));
            int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pos + 32));
            result.Add((System.Text.Encoding.UTF8.GetString(bytes, pos + 46, nameLen), bytes[pos + 5], BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(pos + 38))));
            pos += 46 + nameLen + extraLen + commentLen;
        }

        return result;
    }

    private static void MarkCentralDirectoryEntriesAsUnix(byte[] bytes)
    {
        int eocd = bytes.Length - 22;
        int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd + 12));
        int offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd + 16));
        int pos = offset;
        while (pos < offset + size)
        {
            bytes[pos + 5] = 3;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(pos + 38), 0xa1ed_0000u);
            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pos + 28));
            int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pos + 30));
            int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(pos + 32));
            pos += 46 + nameLen + extraLen + commentLen;
        }
    }

    private static void AssertNoUnixCentralDirectoryMetadata(byte[] bytes)
    {
        foreach (var (name, hostOs, attrs) in CentralDirectoryEntries(bytes))
        {
            Assert.True(hostOs == 0, $"{name} host OS");
            Assert.True(attrs == 0, $"{name} external attributes");
        }
    }
}
