using System.Buffers.Binary;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Tests.Cli;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

/// <summary>
/// Malformed compound files must fail with the Rust <c>cfb</c> crate's errors without allocating memory proportional to
/// untrusted header values (declared stream lengths, repeated DIFAT entries).
/// </summary>
public sealed class CfbMalformedInputTests
{
    private const int SectorLen = 512;
    private const string StreamName = "PsignTestStream";

    /// <summary>A V3 compound file with one 5000-byte stream (stored in the regular FAT chain).</summary>
    private static byte[] BuildFile()
    {
        var cfb = CfbFile.Create();
        cfb.CreateStream(StreamName, new byte[5000]);
        return cfb.ToArray();
    }

    private static long SectorOffset(uint sector) => (sector + 1L) * SectorLen;

    /// <summary>Offset of the test stream's directory entry.</summary>
    private static int StreamEntryOffset(byte[] data)
    {
        uint firstDirSector = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0x30));
        var dir = data.AsSpan((int)SectorOffset(firstDirSector), SectorLen);
        var name = Encoding.Unicode.GetBytes(StreamName);
        int index = dir.IndexOf(name);
        Assert.True(index >= 0 && index % 128 == 0, "stream directory entry not found");
        return (int)SectorOffset(firstDirSector) + index;
    }

    private static byte[] WithHugeStreamLength()
    {
        var data = BuildFile();
        BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(StreamEntryOffset(data) + 120), 0x7FFF_0000);
        return data;
    }

    private static byte[] WithRepeatedDifat()
    {
        var data = BuildFile();
        uint fatSector = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(76));
        for (int i = 1; i < 109; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(76 + (4 * i)), fatSector);
        }

        return data;
    }

    [Fact]
    public void HugeDeclaredStreamLengthFailsWithoutAllocatingIt()
    {
        var cfb = CfbFile.Open(WithHugeStreamLength());
        var entry = cfb.FindChild(cfb.Root, StreamName)!;
        Assert.Equal(0x7FFF_0000UL, entry.StreamLength);

        long before = GC.GetAllocatedBytesForCurrentThread();
        var e = Assert.Throws<PsignException>(() => cfb.ReadStream(entry));
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal("failed to fill whole buffer", e.Message);
        Assert.True(allocated < 16 * 1024 * 1024, $"allocated {allocated} bytes for a malformed stream");
    }

    [Fact]
    public void RepeatedDifatEntriesAreRejectedAsMalformedFat()
    {
        var e = Assert.Throws<PsignException>(() => CfbFile.Open(WithRepeatedDifat()));
        Assert.StartsWith("Malformed FAT (FAT has ", e.Message);
    }

    [Fact]
    public void WellFormedFileStillReadsBack()
    {
        var cfb = CfbFile.Open(BuildFile());
        Assert.Equal(new byte[5000], cfb.ReadStream(cfb.FindChild(cfb.Root, StreamName)!));
    }

    [SkippableTheory]
    [InlineData("huge-stream")]
    [InlineData("repeated-difat")]
    public void VerifyMsiErrorsMatchRust(string kind)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var path = dir.File(kind + ".msi");
        File.WriteAllBytes(path, kind == "huge-stream" ? WithHugeStreamLength() : WithRepeatedDifat());
        CliHarness.AssertSameOutput("portable", "verify-msi", path);
    }
}
