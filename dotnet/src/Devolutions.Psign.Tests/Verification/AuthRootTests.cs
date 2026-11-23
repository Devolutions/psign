using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Verification;
using Devolutions.Psign.Verification.AuthRoot;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>Ports of <c>authroot_ctl.rs</c>, <c>authroot_cab.rs</c>, <c>authroot_cache.rs</c> tests plus MSZIP / CAB coverage.</summary>
public class AuthRootTests
{
    [Fact]
    public void ParseSubjectListFindsSha1OctetString()
    {
        var twenty = Enumerable.Repeat((byte)7, 20).ToArray();
        var inner = Der.EncodeTlv(0x04, twenty);
        var ts = Der.EncodeTlv(0x30, inner);
        var sl = Der.EncodeTlv(0x30, ts);
        var thumbs = AuthRootCtl.ParseSubjectList(sl)!;
        Assert.Single(thumbs);
        Assert.Equal(twenty, thumbs[0]);
    }

    internal static byte[] FakeStl(params byte[][] thumbs)
    {
        var subjects = thumbs.Select(t => Der.EncodeSequence(Der.EncodeTlv(0x04, t), Der.EncodeTlv(0x31, ReadOnlySpan<byte>.Empty))).ToArray();
        var ctl = Der.EncodeSequence(
            Der.EncodeSequence(Der.EncodeOid("1.3.6.1.4.1.311.10.3.9")),
            Der.EncodeTlv(0x17, "240101000000Z"u8),
            Der.EncodeSequence(Der.EncodeOid(Oids.Sha1), Der.Null),
            Der.EncodeTlv(0x30, subjects));
        var sd = new CmsSignedData(1, [], Oids.MsCtl, ctl, null, null, []);
        return sd.Encode();
    }

    [Fact]
    public void CtlThumbprintsAreSortedAndDeduplicated()
    {
        var a = Enumerable.Repeat((byte)0xAA, 20).ToArray();
        var b = Enumerable.Repeat((byte)0x01, 20).ToArray();
        var thumbs = AuthRootCtl.CtlSubjectSha1ThumbprintsFromStlBytes(FakeStl(a, b, a));
        Assert.Equal(2, thumbs.Count);
        Assert.Equal(b, thumbs[0]);
        Assert.Equal(a, thumbs[1]);
        Assert.Empty(AuthRootCtl.CtlSubjectSha1ThumbprintsFromStlBytes([1, 2, 3]));
    }

    private static uint CabChecksum(byte[] data)
    {
        uint value = 0;
        int i = 0;
        for (; i + 4 <= data.Length; i += 4)
        {
            value ^= BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i));
        }

        uint rem = 0;
        int shift = 0;
        for (; i < data.Length; i++)
        {
            rem |= (uint)data[i] << shift;
            shift += 8;
        }

        return shift switch
        {
            0 => value,
            8 => value ^ rem,
            16 => value ^ (rem >> 8) ^ ((rem & 0xff) << 8),
            _ => value ^ (rem >> 16) ^ (rem & 0xff00) ^ ((rem & 0xff) << 16),
        };
    }

    /// <summary>Build a one-folder cabinet from (compressed block, uncompressed size) pairs.</summary>
    internal static byte[] BuildCab(ushort compression, IReadOnlyList<(byte[] Data, int Uncompressed)> blocks, IReadOnlyList<(string Name, int Size, int Offset)> files, bool checksums = true)
    {
        var fileEntries = new MemoryStream();
        foreach (var (name, size, offset) in files)
        {
            var w = new BinaryWriter(fileEntries);
            w.Write((uint)size);
            w.Write((uint)offset);
            w.Write((ushort)0);
            w.Write((ushort)0);
            w.Write((ushort)0);
            w.Write((ushort)0x20);
            w.Write(Encoding.ASCII.GetBytes(name));
            w.Write((byte)0);
        }

        int headerLen = 36;
        int folderLen = 8;
        int coffFiles = headerLen + folderLen;
        int coffData = coffFiles + (int)fileEntries.Length;
        var dataStream = new MemoryStream();
        foreach (var (data, uncompressed) in blocks)
        {
            var w = new BinaryWriter(dataStream);
            uint csum = checksums ? CabChecksum(data) ^ ((uint)data.Length | ((uint)uncompressed << 16)) : 0;
            w.Write(csum);
            w.Write((ushort)data.Length);
            w.Write((ushort)uncompressed);
            w.Write(data);
        }

        var cab = new MemoryStream();
        var bw = new BinaryWriter(cab);
        bw.Write("MSCF"u8);
        bw.Write(0u);
        bw.Write((uint)(coffData + dataStream.Length));
        bw.Write(0u);
        bw.Write((uint)coffFiles);
        bw.Write(0u);
        bw.Write((byte)3);
        bw.Write((byte)1);
        bw.Write((ushort)1);
        bw.Write((ushort)files.Count);
        bw.Write((ushort)0);
        bw.Write((ushort)0x1234);
        bw.Write((ushort)0);
        bw.Write((uint)coffData);
        bw.Write((ushort)blocks.Count);
        bw.Write(compression);
        bw.Write(fileEntries.ToArray());
        bw.Write(dataStream.ToArray());
        return cab.ToArray();
    }

    private static byte[] RawDeflate(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var d = new DeflateStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            d.Write(data);
        }

        return ms.ToArray();
    }

    [Fact]
    public void IngestsUncompressedCabWithStl()
    {
        var thumb = Enumerable.Repeat((byte)0x42, 20).ToArray();
        var stl = FakeStl(thumb);
        var readme = "hello"u8.ToArray();
        var payload = readme.Concat(stl).ToArray();
        var cab = BuildCab(0, [(payload, payload.Length)], [("readme.txt", readme.Length, 0), ("authroot.STL", stl.Length, readme.Length)]);
        var (certs, thumbs) = AuthRootCab.IngestAuthRootCabBytes(cab);
        Assert.Empty(certs);
        Assert.Single(thumbs);
        Assert.Equal(thumb, thumbs[0]);
    }

    [Fact]
    public void IngestsMszipCabAcrossBlocks()
    {
        var thumbs = Enumerable.Range(0, 2000).Select(i => Enumerable.Repeat((byte)(i % 251), 19).Append((byte)(i / 251)).ToArray()).ToArray();
        var stl = FakeStl(thumbs);
        var blocks = stl.Chunk(0x8000).Select(chunk => ("CK"u8.ToArray().Concat(RawDeflate(chunk)).ToArray(), chunk.Length)).ToList();
        Assert.True(blocks.Count > 1);
        var cab = BuildCab(1, blocks, [("authroot.stl", stl.Length, 0)]);
        var (_, got) = AuthRootCab.IngestAuthRootCabBytes(cab);
        Assert.Equal(AuthRootCtl.CtlSubjectSha1ThumbprintsFromStlBytes(stl).Count, got.Count);
        Assert.Equal(2000, got.Count);
    }

    [Fact]
    public void CabErrorsMatchRustText()
    {
        Assert.Equal("CAB open failed: Not a cabinet file (invalid file signature)",
            Assert.Throws<PsignException>(() => AuthRootCab.IngestAuthRootCabBytes([1, 2, 3, 4, 5, 6, 7, 8])).Message);
        var data = "abc"u8.ToArray();
        var cab = BuildCab(0, [(data, data.Length)], [("x.stl", 3, 0)]);
        cab[^4] ^= 0xFF; // corrupt the data so the block checksum fails
        var e = Assert.Throws<PsignException>(() => AuthRootCab.IngestAuthRootCabBytes(cab));
        Assert.StartsWith("CAB read_file x.stl: Checksum error in data block 0 (expected ", e.Message);
    }

    private sealed class BitWriter
    {
        private readonly List<byte> _out = [];
        private int _bit;

        public void Write(int value, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (_bit == 0)
                {
                    _out.Add(0);
                }

                _out[^1] |= (byte)(((value >> i) & 1) << _bit);
                _bit = (_bit + 1) & 7;
            }
        }

        public void WriteHuffman(int code, int length)
        {
            for (int i = length - 1; i >= 0; i--)
            {
                Write((code >> i) & 1, 1);
            }
        }

        public byte[] ToArray() => _out.ToArray();
    }

    [Fact]
    public void MszipBackReferenceReachesPreviousBlock()
    {
        var block1 = Enumerable.Range(0, 4000).Select(i => (byte)(i * 7)).ToArray();
        var bw = new BitWriter();
        bw.Write(1, 1); // BFINAL
        bw.Write(1, 2); // fixed Huffman
        bw.WriteHuffman(264 - 256, 7); // length 10
        bw.WriteHuffman(18, 5); // distance base 769, 8 extra bits
        bw.Write(1000 - 769, 8);
        bw.WriteHuffman(0, 7); // end of block (256)
        var block2 = "CK"u8.ToArray().Concat(bw.ToArray()).ToArray();
        var z = new MsZipInflater();
        var out1 = z.DecompressBlock("CK"u8.ToArray().Concat(RawDeflate(block1)).ToArray(), block1.Length);
        Assert.Equal(block1, out1);
        var out2 = z.DecompressBlock(block2, 10);
        Assert.Equal(block1.AsSpan(block1.Length - 1000, 10).ToArray(), out2);
    }

    [SkippableFact]
    public void ParseRealAuthRootCab()
    {
        var home = Environment.GetEnvironmentVariable("USERPROFILE") ?? Environment.GetEnvironmentVariable("HOME") ?? ".";
        var cab = Path.Combine(home, ".psign", "authroot", "authrootstl.cab");
        Skip.IfNot(File.Exists(cab), "no cached AuthRoot CAB");
        var (_, thumbs) = AuthRootCab.IngestAuthRootCabBytes(File.ReadAllBytes(cab));
        Assert.True(thumbs.Count >= 100, $"expected at least 100 CTL root thumbprints, got {thumbs.Count}");
    }

    // --- authroot_cache.rs ---
    private static AuthRootCacheOptions Options(string dir) => new()
    {
        CacheDir = dir,
        SourceUrl = "http://example.invalid/authrootstl.cab",
        MaxAge = TimeSpan.FromDays(1),
        Timeout = TimeSpan.FromSeconds(2),
        MaxDownloadBytes = 1024 * 1024,
    };

    private static void WriteMeta(string path, DateTimeOffset downloadedAt)
    {
        long secs = downloadedAt.ToUnixTimeSeconds();
        var meta = new Dictionary<string, object?>
        {
            ["downloaded_at_utc"] = DateTimeOffset.FromUnixTimeSeconds(secs).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["downloaded_at_unix_secs"] = secs,
            ["source_url"] = AuthRootCache.AuthRootCabUrl,
            ["size_bytes"] = 3,
            ["sha256"] = new string('0', 64),
        };
        File.WriteAllText(path, JsonSerializer.Serialize(meta));
    }

    [Fact]
    public void AutoTrustDisabledValuesMatchPowerShell()
    {
        Assert.True(AuthRootCache.IsAutoTrustDisabledValue("1"));
        Assert.True(AuthRootCache.IsAutoTrustDisabledValue("true"));
        Assert.True(AuthRootCache.IsAutoTrustDisabledValue("YES"));
        Assert.False(AuthRootCache.IsAutoTrustDisabledValue("0"));
        Assert.False(AuthRootCache.IsAutoTrustDisabledValue("false"));
    }

    [Fact]
    public void InvalidMaxAgeValuesAreIgnored()
    {
        Assert.Equal(7UL, AuthRootCache.MaxAgeDaysFromValue("7"));
        Assert.Null(AuthRootCache.MaxAgeDaysFromValue("0"));
        Assert.Null(AuthRootCache.MaxAgeDaysFromValue("-1"));
        Assert.Null(AuthRootCache.MaxAgeDaysFromValue("abc"));
    }

    [Fact]
    public void FreshCacheIsUsedWithoutDownload()
    {
        using var dir = new TempDir();
        var cabPath = dir.File(AuthRootCache.AuthRootCabFileName);
        File.WriteAllBytes(cabPath, "old"u8.ToArray());
        WriteMeta(dir.File(AuthRootCache.AuthRootMetaFileName), DateTimeOffset.UtcNow);
        var r = AuthRootCache.GetOrDownloadAuthRootCabWith(Options(dir.DirPath), _ => throw new InvalidOperationException("fresh cache should not download"));
        Assert.Equal(cabPath, r.Path);
        Assert.False(r.Refreshed);
        Assert.False(r.StaleFallback);
        Assert.Equal("old"u8.ToArray(), File.ReadAllBytes(r.Path));
    }

    [Fact]
    public void StaleCacheRefreshesFromSourceUrl()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File(AuthRootCache.AuthRootCabFileName), "old"u8.ToArray());
        WriteMeta(dir.File(AuthRootCache.AuthRootMetaFileName), DateTimeOffset.UtcNow.AddDays(-2));
        var r = AuthRootCache.GetOrDownloadAuthRootCabWith(Options(dir.DirPath), _ => "new"u8.ToArray());
        Assert.True(r.Refreshed);
        Assert.False(r.StaleFallback);
        Assert.Equal("new"u8.ToArray(), File.ReadAllBytes(r.Path));

        // Metadata is rewritten in the Rust (serde pretty) layout.
        var meta = File.ReadAllText(dir.File(AuthRootCache.AuthRootMetaFileName));
        Assert.StartsWith("{\n  \"downloaded_at_utc\": \"", meta);
        Assert.Contains("\"source_url\": \"http://example.invalid/authrootstl.cab\",\n  \"size_bytes\": 3,\n  \"sha256\": \"", meta);
    }

    [Fact]
    public void MalformedMetadataIsTreatedAsStale()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File(AuthRootCache.AuthRootCabFileName), "old"u8.ToArray());
        File.WriteAllText(dir.File(AuthRootCache.AuthRootMetaFileName), "not json");
        var r = AuthRootCache.GetOrDownloadAuthRootCabWith(Options(dir.DirPath), _ => "new"u8.ToArray());
        Assert.True(r.Refreshed);
        Assert.Equal("new"u8.ToArray(), File.ReadAllBytes(r.Path));
    }

    [Fact]
    public void StaleCacheFallsBackWhenRefreshFails()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File(AuthRootCache.AuthRootCabFileName), "old"u8.ToArray());
        WriteMeta(dir.File(AuthRootCache.AuthRootMetaFileName), DateTimeOffset.UtcNow.AddDays(-2));
        var r = AuthRootCache.GetOrDownloadAuthRootCabWith(Options(dir.DirPath), _ => throw new PsignException("download failed"));
        Assert.False(r.Refreshed);
        Assert.True(r.StaleFallback);
        Assert.Equal("download AuthRoot CAB from http://example.invalid/authrootstl.cab", r.RefreshError);
        Assert.Equal("old"u8.ToArray(), File.ReadAllBytes(r.Path));
    }

    [Fact]
    public void MissingCacheWithFailedDownloadErrors()
    {
        using var dir = new TempDir();
        var e = Assert.Throws<PsignException>(() => AuthRootCache.GetOrDownloadAuthRootCabWith(Options(dir.DirPath), _ => []));
        Assert.Equal("download AuthRoot CAB from http://example.invalid/authrootstl.cab returned an empty response", e.Message);
    }
}
