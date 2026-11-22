using System.IO.Compression;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Zip;
using Xunit;
using static Devolutions.Psign.Tests.Core.PackageTestUtil;

namespace Devolutions.Psign.Tests.Core;

public class OpcPackageTests
{
    [Fact]
    public void DetectsOpcSignatureParts()
    {
        var zip = ZipWith(
            (OpcPackage.ContentTypesPart, B("<Types/>")),
            (OpcPackage.RootRelationshipsPart, B("<Relationships/>")),
            (OpcPackage.OpcSignatureOriginPart, []),
            ("package/services/digital-signature/xml-signature/sig1.psdsxs", B("<Signature/>")));

        var summary = OpcPackage.InspectPackage(zip);

        Assert.True(summary.HasContentTypes);
        Assert.True(summary.HasRootRelationships);
        Assert.True(summary.HasOpcSignatureOrigin);
        Assert.Equal(["package/services/digital-signature/xml-signature/sig1.psdsxs"], summary.OpcSignatureParts);
    }

    [Fact]
    public void RejectsBackslashEntryNames()
    {
        var e = Assert.Throws<PsignException>(() => OpcPackage.NormalizeZipPartName("_rels\\.rels"));
        Assert.Contains("separators", e.Message);
    }

    [Theory]
    [InlineData("", "ZIP entry name is empty")]
    [InlineData("/abs", "must be relative")]
    [InlineData("a/../b", "dot segment")]
    [InlineData("./b", "dot segment")]
    public void RejectsInvalidEntryNames(string name, string expected)
    {
        var e = Assert.Throws<PsignException>(() => OpcPackage.NormalizeZipPartName(name));
        Assert.Contains(expected, e.Message);
    }

    [Fact]
    public void ZipDateTimeFromLocalClockFields()
    {
        var local = new DateTime(1999, 12, 31, 16, 0, 0);
        var dt = ZipDateTime.FromDateTime(local);
        Assert.Equal(ZipDateTime.FromDateAndTime(1999, 12, 31, 16, 0, 0), dt);
        Assert.Throws<PsignException>(() => ZipDateTime.FromDateTime(new DateTime(1979, 1, 1)));
    }

    [Fact]
    public void ZipDateTimeRoundTripsMsDosFields()
    {
        var dt = ZipDateTime.FromDateAndTime(2026, 5, 21, 12, 47, 50)!.Value;
        Assert.Equal(dt, ZipDateTime.FromMsDos(dt.DatePart, dt.TimePart));
        Assert.Equal((ushort)0x21, ZipDateTime.Default.DatePart);
        Assert.Equal((ushort)0, ZipDateTime.Default.TimePart);
    }

    [Fact]
    public void CrateWriterOutputIsReadableByBcl()
    {
        var payloads = StressPayloads().ToArray();
        var w = new ZipCrateWriter();
        foreach (var (name, data) in payloads)
        {
            w.StartFile(name, data);
        }

        w.AddDirectory("emptydir");
        var bytes = w.Finish();

        using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        foreach (var (name, data) in payloads)
        {
            using var s = zip.GetEntry(name)!.Open();
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            Assert.Equal(data, ms.ToArray());
        }

        Assert.NotNull(zip.GetEntry("emptydir/"));

        var archive = ZipCrateArchive.Open(bytes);
        Assert.Equal(payloads.Length + 1, archive.Count);
        Assert.True(archive.ByName("emptydir/")!.IsDir);
        Assert.Equal(0x41ED0000u, archive.ByName("emptydir/")!.ExternalAttributes);
        Assert.Equal(0x81A40000u, archive[0].ExternalAttributes);
        Assert.Equal((ushort)0x032E, archive[0].VersionMadeBy);
        foreach (var (name, data) in payloads)
        {
            Assert.Equal(data, archive.Read(archive.ByName(name)!));
        }
    }

    [Fact]
    public void EmptyDeflateStreamMatchesMiniz()
    {
        Assert.Equal(new byte[] { 0x03, 0x00 }, MinizDeflater.Compress([]));
    }

    [Fact]
    public void ArchiveReaderRejectsGarbage()
    {
        var e = Assert.Throws<PsignException>(() => ZipCrateArchive.Open(new byte[100]));
        Assert.Contains("Could not find central directory end", e.Message);
    }

    [Fact]
    public void ArchiveReaderReportsCrcMismatch()
    {
        var zip = ZipWith(("a.txt", B("hello")));
        // Flip a CRC byte in the central directory (Rust zip reads the central directory CRC).
        var archive = ZipCrateArchive.Open(zip);
        int cd = zip.Length - 22 - (46 + "a.txt".Length);
        zip[cd + 16] ^= 0xFF;
        archive = ZipCrateArchive.Open(zip);
        var e = Assert.Throws<PsignException>(() => archive.Read(0));
        Assert.Contains("Invalid checksum", e.Message);
    }

    [SkippableFact]
    public void InspectMatchesRustVsixSignatureInfo()
    {
        RustTool.Require();
        foreach (var rel in new[] { "package-signing/signed/sample.signed.vsix", "package-signing/unsigned/sample.vsix", "package-signing/signed/nested.signed.vsix" })
        {
            var path = Fixtures.Path(rel);
            var rust = RustTool.RunOk("portable", "vsix-signature-info", path);
            var info = Devolutions.Psign.Core.Vsix.VsixPackage.InspectVsixPath(path);
            var expected = new System.Text.StringBuilder();
            expected.Append($"opc_signature={(info.HasOpcSignature ? "yes" : "no")}\n");
            expected.Append($"signature_origin={(info.Package.HasOpcSignatureOrigin ? OpcPackage.OpcSignatureOriginPart : "-")}\n");
            expected.Append($"signature_parts={info.Package.OpcSignatureParts.Count}\n");
            foreach (var part in info.Package.OpcSignatureParts)
            {
                expected.Append($"signature_part={part}\n");
            }

            expected.Append($"entries={info.Package.Entries.Count}\n");
            Assert.Equal(expected.ToString(), rust.Replace("\r\n", "\n"));
        }
    }
}
