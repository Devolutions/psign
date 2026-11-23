using System.Buffers.Binary;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msi;
using OpenMcdf;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

/// <summary>
/// Unit tests for the C# port of the Rust <c>cfb</c> crate's write paths (<see cref="CfbFile"/>). Byte-for-byte parity
/// with Rust is covered by the MSI signing differential tests; these check the allocator behaviour directly and use
/// OpenMcdf as an independent reader.
/// </summary>
public class CfbFileTests
{
    private const uint EndOfChain = 0xFFFF_FFFE;

    private static byte[] Pattern(int length, int seed)
    {
        var data = new byte[length];
        new Random(seed).NextBytes(data);
        return data;
    }

    private static byte[] ReadWithOpenMcdf(byte[] image, params string[] path)
    {
        using var root = RootStorage.Open(new MemoryStream(image, writable: false));
        Storage storage = root;
        for (int i = 0; i < path.Length - 1; i++)
        {
            storage = storage.OpenStorage(path[i]);
        }

        using var s = storage.OpenStream(path[^1]);
        var buf = new byte[s.Length];
        s.ReadExactly(buf);
        return buf;
    }

    private static uint HeaderU32(byte[] image, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(offset));

    private static byte[] ReadWithCfbFile(byte[] image, string name)
    {
        var cfb = CfbFile.Open((byte[])image.Clone());
        var entry = cfb.FindChild(cfb.Root, name) ?? throw new InvalidOperationException($"missing {name}");
        return cfb.ReadStream(entry);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(4)]
    public void CreatedFileMatchesCfbCreateLayoutAndRoundTrips(int versionNumber)
    {
        var version = (CfbVersion)versionNumber;
        var cfb = CfbFile.Create(version);
        int sectorLen = version == CfbVersion.V3 ? 512 : 4096;
        var image = cfb.ToArray();
        Assert.Equal(3 * sectorLen, image.Length);
        Assert.Equal((uint)(version == CfbVersion.V3 ? 0 : 1), HeaderU32(image, 40));
        Assert.Equal(1u, HeaderU32(image, 44));
        Assert.Equal(1u, HeaderU32(image, 48));
        Assert.Equal(EndOfChain, HeaderU32(image, 60));
        Assert.Equal(EndOfChain, HeaderU32(image, 68));

        var reopened = CfbFile.Open(image);
        Assert.Empty(reopened.Children(reopened.Root));
        using var root = RootStorage.Open(new MemoryStream(image, writable: false));
        Assert.Empty(root.EnumerateEntries());
    }

    [Theory]
    [InlineData(3, 1)]
    [InlineData(3, 4095)]
    [InlineData(3, 4096)]
    [InlineData(3, 70_000)]
    [InlineData(4, 100)]
    [InlineData(4, 4096)]
    [InlineData(4, 20_000)]
    public void StreamsOnBothSidesOfMiniStreamCutoffRoundTrip(int versionNumber, int length)
    {
        var version = (CfbVersion)versionNumber;
        var cfb = CfbFile.Create(version);
        var content = Pattern(length, length);
        var entry = cfb.CreateStream("Data", content);
        Assert.Equal((ulong)length, entry.StreamLength);

        var image = cfb.ToArray();
        Assert.Equal(content, ReadWithOpenMcdf(image, "Data"));
        Assert.Equal(content, ReadWithCfbFile(image, "Data"));

        // Below the cutoff the data lives in the mini stream (root entry has a length); at or above it, it does not.
        var reopened = CfbFile.Open(image);
        Assert.Equal(length < CfbFile.MiniStreamCutoff ? (ulong)((length + 63) / 64 * 64) : 0UL, reopened.Root.StreamLength);
    }

    [Theory]
    [InlineData(100, 5000)]
    [InlineData(5000, 100)]
    [InlineData(4095, 4096)]
    [InlineData(4096, 4095)]
    [InlineData(5000, 9000)]
    [InlineData(9000, 5000)]
    [InlineData(300, 200)]
    public void OverwritingAStreamAcrossTheCutoffFreesAndReusesStorage(int first, int second)
    {
        var cfb = CfbFile.Create();
        var before = Pattern(64, 1);
        var after = Pattern(64, 2);
        cfb.CreateStream("A", before);
        cfb.CreateStream("Target", Pattern(first, first));
        cfb.CreateStream("Z", after);
        var replacement = Pattern(second, second + 7);
        var entry = cfb.CreateStream("target", replacement); // CFB names are case-insensitive: overwrites "Target".
        Assert.Equal("Target", entry.Name);
        Assert.Equal(3, cfb.Children(cfb.Root).Count);

        var image = cfb.ToArray();
        Assert.Equal(replacement, ReadWithOpenMcdf(image, "Target"));
        Assert.Equal(replacement, ReadWithCfbFile(image, "Target"));
        Assert.Equal(before, ReadWithOpenMcdf(image, "A"));
        Assert.Equal(after, ReadWithOpenMcdf(image, "Z"));

        // Writing the original size back reuses the sectors freed by the previous overwrite. When both sizes sit on the
        // same side of the cutoff the file stops growing; across the cutoff it keeps growing, exactly like `cfb`, which
        // shrinks the mini stream length on free but never truncates the root chain (append_mini_sector extends it again).
        cfb.CreateStream("Target", Pattern(first, first));
        var lengthAfterRestore = cfb.Length;
        cfb.CreateStream("Target", replacement);
        cfb.CreateStream("Target", Pattern(first, first));
        if ((first < CfbFile.MiniStreamCutoff) == (second < CfbFile.MiniStreamCutoff))
        {
            Assert.Equal(lengthAfterRestore, cfb.Length);
        }

        Assert.Equal(Pattern(first, first), ReadWithOpenMcdf(cfb.ToArray(), "Target"));
    }

    [Fact]
    public void EmptyStreamHasNoChain()
    {
        var cfb = CfbFile.Create();
        var entry = cfb.CreateStream("Empty", ReadOnlySpan<byte>.Empty);
        Assert.Equal(EndOfChain, entry.StartSector);
        Assert.Equal(0UL, entry.StreamLength);
        cfb.CreateStream("Empty", Pattern(10, 10));
        var shrunk = cfb.CreateStream("Empty", ReadOnlySpan<byte>.Empty);
        Assert.Equal(EndOfChain, shrunk.StartSector);
        Assert.Empty(ReadWithOpenMcdf(cfb.ToArray(), "Empty"));
    }

    [Fact]
    public void LargeStreamGrowsFatIntoDifatSectors()
    {
        // V3: one FAT sector maps 128 sectors (64 KiB); the header DIFAT holds 109 FAT sectors (~7 MiB). A 9 MiB stream
        // (written in 1 MiB Stream-buffer chunks like the Rust crate) needs a DIFAT sector.
        var cfb = CfbFile.Create(CfbVersion.V3);
        var content = Pattern(9 * 1024 * 1024 + 123, 9);
        cfb.CreateStream("Big", content);
        cfb.CreateStream("Small", Pattern(10, 10));
        var image = cfb.ToArray();

        uint numFatSectors = HeaderU32(image, 44);
        Assert.True(numFatSectors > 109, $"expected more than 109 FAT sectors, got {numFatSectors}");
        Assert.NotEqual(EndOfChain, HeaderU32(image, 68));
        Assert.Equal(1u, HeaderU32(image, 72));
        Assert.Equal(0, (image.Length - 512) % 512);

        Assert.Equal(content, ReadWithOpenMcdf(image, "Big"));
        Assert.Equal(content, ReadWithCfbFile(image, "Big"));
        Assert.Equal(Pattern(10, 10), ReadWithOpenMcdf(image, "Small"));

        // Re-opening parses the DIFAT chain back; shrinking the stream frees sectors that a regrow then reuses.
        var reopened = CfbFile.Open(image);
        reopened.CreateStream("Big", Pattern(5000, 5000));
        int shrunkLength = reopened.Length;
        reopened.CreateStream("Other", Pattern(2 * 1024 * 1024, 2));
        Assert.Equal(shrunkLength, reopened.Length);
        var final = reopened.ToArray();
        Assert.Equal(Pattern(2 * 1024 * 1024, 2), ReadWithOpenMcdf(final, "Other"));
        Assert.Equal(Pattern(5000, 5000), ReadWithOpenMcdf(final, "Big"));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(4)]
    public void ManyEntriesGrowTheDirectoryChain(int versionNumber)
    {
        var version = (CfbVersion)versionNumber;
        var cfb = CfbFile.Create(version);
        var nested = cfb.CreateStorage(cfb.Root, "Nested", 0x01D9_0000_0000_0000);
        var names = Enumerable.Range(0, 70).Select(i => $"Stream{i:D3}").ToList();
        for (int i = 0; i < names.Count; i++)
        {
            cfb.CreateStream(names[i], Pattern(i * 97, i));
        }

        cfb.CreateStream(nested, "Inner", Pattern(33, 33));
        var image = cfb.ToArray();
        if (version == CfbVersion.V4)
        {
            // cfb updates the V4 header directory-sector count (73 entries / 32 per sector = 3 sectors).
            Assert.Equal(3u, HeaderU32(image, 40));
        }

        var reopened = CfbFile.Open(image);
        var children = reopened.Children(reopened.Root).Select(c => c.Name).ToList();
        Assert.Equal(names.Append("Nested").Order(Comparer<string>.Create(CfbFile.CompareNames)), children);
        for (int i = 0; i < names.Count; i++)
        {
            Assert.Equal(Pattern(i * 97, i), ReadWithOpenMcdf(image, names[i]));
        }

        Assert.Equal(Pattern(33, 33), ReadWithOpenMcdf(image, "Nested", "Inner"));
        var nestedEntry = reopened.FindChild(reopened.Root, "NESTED")!;
        Assert.True(nestedEntry.IsStorage);
        Assert.Equal(0x01D9_0000_0000_0000UL, nestedEntry.CreationTime);
    }

    [Fact]
    public void NameOrderingIsShortlexCaseInsensitive()
    {
        Assert.True(CfbFile.CompareNames("Z", "AA") < 0);
        Assert.Equal(0, CfbFile.CompareNames("abc", "ABC"));
        Assert.True(CfbFile.CompareNames("abc", "abd") < 0);
        Assert.True(CfbFile.CompareNames("\u0005DigitalSignature", "\u0005MsiDigitalSignatureEx") < 0);
        Assert.Equal(0, CfbFile.CompareNames("été", "ÉTÉ"));
        Assert.True(CfbFile.CompareNames("䡀㬿", "䡀㭀") < 0);
    }

    [Fact]
    public void OpenRejectsNonCompoundFiles()
    {
        var e = Assert.Throws<PsignException>(() => CfbFile.Open(new byte[100]));
        Assert.Equal("Invalid CFB file (100 bytes is too small)", e.Message);
        e = Assert.Throws<PsignException>(() => CfbFile.Open(new byte[512]));
        Assert.StartsWith("Invalid CFB file (wrong magic number)", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FixtureRewriteOnlyTouchesWhatCfbTouches()
    {
        // Overwriting a one-mini-sector stream with identical content leaves an MSI byte-for-byte unchanged (cfb frees
        // and reallocates the same mini sector and rewrites the same directory entry in place).
        var msi = Fixtures.Bytes("generated-unsigned/installer/tiny.msi");
        var cfb = CfbFile.Open((byte[])msi.Clone());
        var stream = cfb.Children(cfb.Root).First(e => e.IsStream && e.StreamLength is > 0 and <= 64);
        var content = cfb.ReadStream(stream);
        cfb.CreateStream(stream.Name, content);
        Assert.Equal(msi, cfb.ToArray());
    }

    [Fact]
    public void CertificateSetOrderFollowsRustCmsCrate()
    {
        // Header (length) first, then the SEQUENCE OF INTEGER weight (bytes >= 0x80 count double), then bytes.
        byte[] shortCert = [0x30, 0x02, 0xFF, 0xFF];
        byte[] lowBytes = [0x30, 0x03, 0x7F, 0x7F, 0x7F];
        byte[] highBytes = [0x30, 0x03, 0x01, 0x80, 0x00];
        Assert.True(CmsSignedData.CompareCertificateChoices(shortCert, lowBytes) < 0);
        Assert.True(CmsSignedData.CompareCertificateChoices(lowBytes, highBytes) < 0);
        Assert.True(Der.CompareDer(highBytes, lowBytes) < 0);
        Assert.Equal(0, CmsSignedData.CompareCertificateChoices(lowBytes, (byte[])lowBytes.Clone()));
    }
}
