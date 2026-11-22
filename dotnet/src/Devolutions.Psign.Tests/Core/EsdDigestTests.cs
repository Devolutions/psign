using System.Buffers.Binary;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Esd;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class EsdDigestTests
{
    private static string RenderVerifyError(byte[] image)
    {
        var e = Assert.Throws<PsignException>(() => EsdDigest.VerifyWimEsdDigestConsistency(image));
        return e.FullMessage;
    }

    [Fact]
    public void WimVerifyRejectsNonMswimMagic()
    {
        var junk = Enumerable.Repeat((byte)0xFF, EsdDigest.WimHeaderPackedSize).ToArray();
        "XXXXIM\0\0"u8.CopyTo(junk);
        var msg = RenderVerifyError(junk);
        Assert.True(msg.Contains("MSWIM", StringComparison.Ordinal) || msg.Contains("WIM", StringComparison.Ordinal), msg);
    }

    [Fact]
    public void WimVerifyRejectsBadPackedHeaderSize()
    {
        var h = new byte[EsdDigest.WimHeaderPackedSize];
        "MSWIM\0\0\0"u8.CopyTo(h);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(8), 100);
        var msg = RenderVerifyError(h);
        Assert.True(msg.Contains("packed header", StringComparison.Ordinal) || msg.Contains("208", StringComparison.Ordinal), msg);
    }

    [Fact]
    public void WimVerifyRejectsUnsignedHeaderNoPkcs7()
    {
        var h = new byte[EsdDigest.WimHeaderPackedSize];
        "MSWIM\0\0\0"u8.CopyTo(h);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(8), (uint)EsdDigest.WimHeaderPackedSize);
        var msg = RenderVerifyError(h);
        Assert.True(msg.Contains("embedded", StringComparison.Ordinal) || msg.Contains("signature", StringComparison.Ordinal), msg);
    }

    [Fact]
    public void GetHashDataOffsetMatchesSimpleRegions()
    {
        var h = new byte[EsdDigest.WimHeaderPackedSize];
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(48), 0x10);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(56), 0x20);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(72), 0);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(80), 0x50);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(124), 0x100);
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(132), 1);
        Assert.Equal(0x101UL, EsdDigest.GetHashDataOffset(h));
    }

    [Fact]
    public void WimHashByteCountUsesExplicitQword()
    {
        var h = new byte[EsdDigest.WimHeaderPackedSize];
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(0xBC), 999);
        Assert.Equal(999UL, EsdDigest.WimHashByteCount(h));
    }

    [Theory]
    [InlineData("generated-signed/wim-esd/tiny.wim")]
    [InlineData("generated-signed/wim-esd/tiny.esd")]
    public void SignedFixturesVerify(string fixture)
    {
        EsdDigest.VerifyWimEsdDigestConsistency(Fixtures.Path(fixture));
        EsdDigest.VerifyWimEsdDigestConsistency(Fixtures.Bytes(fixture));
    }

    [Theory]
    [InlineData("generated-unsigned/wim-esd/bad-magic.wim")]
    [InlineData("generated-unsigned/wim-esd/unsigned-header.esd")]
    [InlineData("generated-unsigned/wim-esd/tiny.wim")]
    public void UnsignedOrBadFixturesFail(string fixture)
    {
        Assert.Throws<PsignException>(() => EsdDigest.VerifyWimEsdDigestConsistency(Fixtures.Path(fixture)));
    }

    [SkippableTheory]
    [InlineData("generated-signed/wim-esd/tiny.wim")]
    [InlineData("generated-signed/wim-esd/tiny.esd")]
    [InlineData("generated-unsigned/wim-esd/bad-magic.esd")]
    [InlineData("generated-unsigned/wim-esd/unsigned-header.wim")]
    [InlineData("generated-unsigned/wim-esd/tiny.esd")]
    public void VerifyOutcomeMatchesRust(string fixture)
    {
        RustTool.Require();
        var (code, _, _) = RustTool.Run("portable", "verify-esd", Fixtures.Path(fixture));
        bool csOk;
        try
        {
            EsdDigest.VerifyWimEsdDigestConsistency(Fixtures.Path(fixture));
            csOk = true;
        }
        catch (PsignException)
        {
            csOk = false;
        }

        Assert.Equal(code == 0, csOk);
    }
}
