using System.Buffers.Binary;
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Pe;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class PageHashesTests
{
    private const string Tiny32 = "pe-authenticode-upstream/tiny32.signed.efi";
    private const string Tiny64 = "pe-authenticode-upstream/tiny64.signed.efi";

    private static byte[] Flat(params (uint Offset, byte[] Digest)[] rows)
    {
        var list = new List<byte>();
        foreach (var (offset, digest) in rows)
        {
            var o = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(o, offset);
            list.AddRange(o);
            list.AddRange(digest);
        }

        return list.ToArray();
    }

    [Theory]
    [InlineData(Oids.SpcPeImagePageHashesV1, true)]
    [InlineData(Oids.SpcPeImagePageHashesV2, false)]
    public void PageHashOidTlvMatchesAsn1Der(string oid, bool v1)
    {
        var expected = v1 ? PageHashes.SpcPeImagePageHashesV1OidDer.ToArray() : PageHashes.SpcPeImagePageHashesV2OidDer.ToArray();
        Assert.Equal(expected, Der.EncodeOid(oid));
    }

    [Fact]
    public void DetectsV2OidInBuffer()
    {
        var buf = new List<byte> { 0x30, 0x82, 0x01, 0x00 };
        buf.AddRange(PageHashes.SpcPeImagePageHashesV2OidDer.ToArray());
        Assert.True(PageHashes.Pkcs7ContainsPageHashOid(buf.ToArray()));
    }

    [Fact]
    public void UpstreamTinyFixturesHaveNoPageHashOid()
    {
        foreach (var f in new[] { Tiny32, Tiny64 })
        {
            var pe = Fixtures.Bytes(f);
            Assert.False(PageHashes.PeEmbeddedPkcs7ContainsPageHashAttribute(pe));
            Assert.Empty(PageHashes.CollectPageHashAuthAttributes(pe));
        }
    }

    [Fact]
    public void ParseFlatPageHashV2StopsAtZeroDigest()
    {
        var flat = Flat((0x1000, Enumerable.Repeat((byte)0xab, 32).ToArray()), (0x2000, new byte[32]));
        var rows = PageHashes.ParseFlatPairsLe(flat, 32);
        Assert.Single(rows);
        Assert.Equal(0x1000u, rows[0].PageEndOffset);
        Assert.Equal(Enumerable.Repeat((byte)0xab, 32).ToArray(), rows[0].Digest);
    }

    [Fact]
    public void ParseFlatRejectsTrailingGarbage()
    {
        var flat = Flat((0x1000, Enumerable.Repeat((byte)0xab, 32).ToArray())).Concat(new byte[] { 1, 2 }).ToArray();
        Assert.Throws<PsignException>(() => PageHashes.ParseFlatPairsLe(flat, 32));
    }

    [Fact]
    public void ParsePageHashAttributeThroughSerializedObjectWrappedOctet()
    {
        var flat = Flat((0x400, Enumerable.Repeat((byte)0x11, 20).ToArray()), (0x800, new byte[20]));
        var guid = Enumerable.Repeat((byte)7, 16).ToArray();
        var seq = Der.EncodeSequence(Der.EncodeTlv(0x04, guid), Der.EncodeTlv(0x04, flat));
        var value = Der.EncodeTlv(0x04, seq);
        var entries = PageHashes.ParseAttributeEntries(value, PageHashAttrKind.V1);
        Assert.Single(entries);
        Assert.Equal(0x400u, entries[0].PageEndOffset);
        Assert.Equal(Enumerable.Repeat((byte)0x11, 20).ToArray(), entries[0].Digest);
    }

    [Fact]
    public void ParsePageHashAttributeThroughSetOfTypeAndOptionalValue()
    {
        var flat = Flat((0x50, Enumerable.Repeat((byte)0x22, 32).ToArray()), (0x60, new byte[32]));
        var member = Der.EncodeSequence(Der.EncodeOid(Oids.Sha256), Der.EncodeTlv(0x04, flat));
        var setWrapped = Der.EncodeTlv(0x31, member);
        var entries = PageHashes.ParseAttributeEntries(setWrapped, PageHashAttrKind.V2);
        Assert.Single(entries);
        Assert.Equal(0x50u, entries[0].PageEndOffset);
        Assert.Equal(Enumerable.Repeat((byte)0x22, 32).ToArray(), entries[0].Digest);
    }

    [Fact]
    public void ContiguousVerifyMatchesSha256Ranges()
    {
        var pe = new byte[64];
        var entries = new[]
        {
            new PageHashTableEntry(64, SHA256.HashData(pe.AsSpan(32, 32))),
            new PageHashTableEntry(32, SHA256.HashData(pe.AsSpan(0, 32))),
        };
        PageHashes.VerifyEntriesContiguousFileOffsets(pe, entries, PageHashAttrKind.V2);
    }

    [Fact]
    public void ContiguousVerifyRejectsWrongDigest()
    {
        var pe = Enumerable.Repeat((byte)1, 16).ToArray();
        var entries = new[] { new PageHashTableEntry(16, new byte[32]) };
        Assert.Throws<PsignException>(() => PageHashes.VerifyEntriesContiguousFileOffsets(pe, entries, PageHashAttrKind.V2));
    }

    [Fact]
    public void VerifyEmbeddedTablesErrorsWhenFixtureHasNoPageHashAttrs()
    {
        var e = Assert.Throws<PsignException>(() => PageHashes.VerifyPeEmbeddedTables(Fixtures.Bytes(Tiny32)));
        Assert.Contains("SPC_PE_IMAGE_PAGE_HASHES", e.Message, StringComparison.Ordinal);
    }

    [SkippableTheory]
    [InlineData(Tiny32)]
    [InlineData(Tiny64)]
    public void PageHashInfoMatchesRust(string fixture)
    {
        RustTool.Require();
        var rust = RustTool.RunOk("portable", "pe-page-hash-info", Fixtures.Path(fixture));
        Assert.Equal(string.Empty, rust.Trim());
        Assert.Empty(PageHashes.CollectPageHashAuthAttributes(Fixtures.Bytes(fixture)));
        var (code, _, _) = RustTool.Run("portable", "verify-pe-page-hashes", Fixtures.Path(fixture));
        Assert.NotEqual(0, code);
        Assert.Throws<PsignException>(() => PageHashes.VerifyPeEmbeddedTables(Fixtures.Bytes(fixture)));
    }
}
