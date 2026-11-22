using System.Buffers.Binary;
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Cms;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class CabDigestTests
{
    private const string TinySigned = "cab-authenticode-upstream/tiny-signed.cab";

    private static byte[] MinimalUnsigned()
    {
        var data = new byte[48];
        "MSCF"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(8), 100);
        return data;
    }

    [Fact]
    public void RejectsNonMscf()
    {
        Assert.Throws<PsignException>(() => CabDigest.ParseContext(new byte[64]));
    }

    [Fact]
    public void UnsignedMinimalDigestStable()
    {
        var data = MinimalUnsigned();
        var ctx = CabDigest.ParseContext(data);
        Assert.Equal(0u, ctx.SigPos);
        var h = CabDigest.ComputeAuthenticodeDigest(data, ctx, AuthenticodeHashKind.Sha256);
        Assert.Equal(32, h.Length);
        Assert.Equal(SHA256.HashData([.. data[..4], .. data[8..]]), h);
    }

    [Fact]
    public void RsaSha256SignerPrehashDigestErrorsWhenUnsigned()
    {
        Assert.Throws<PsignException>(() => CabDigest.RsaSha256SignerPrehashDigest(MinimalUnsigned(), 0));
    }

    [Fact]
    public void RsaSha256SignerPrehashMatchesDirectSignerOnTinySignedFixture()
    {
        var bytes = Fixtures.Bytes(TinySigned);
        var sd = CmsSignedData.Parse(CabDigest.SignaturePkcs7Der(bytes));
        var direct = SHA256.HashData(sd.SignerInfos[0].SignedAttributesSetDer());
        Assert.Equal(direct, CabDigest.RsaSha256SignerPrehashDigest(bytes, 0));
    }

    [Fact]
    public void TinySignedCabSignedDataEmbeddedCertificateCount()
    {
        var sd = CmsSignedData.Parse(CabDigest.SignaturePkcs7Der(Fixtures.Bytes(TinySigned)));
        Assert.Equal(1, sd.Certificates?.Count ?? 0);
    }

    [Fact]
    public void TinySignedCabSpcIndirectDigestMatchesAuthenticodeDigest()
    {
        var pkcs7 = CabDigest.SignaturePkcs7Der(Fixtures.Bytes(TinySigned));
        var sig = AuthenticodeSignature.Parse(pkcs7);
        var indirect = SpcIndirectDataContent.FromSignedData(CmsSignedData.Parse(pkcs7));
        Assert.Equal(sig.Digest, indirect.Digest);
    }

    [Theory]
    [InlineData(TinySigned)]
    [InlineData("generated-signed/cab/sample.cab")]
    public void SignedFixturesVerify(string fixture)
    {
        CabDigest.VerifyDigestConsistency(Fixtures.Bytes(fixture));
        Assert.True(CabDigest.HasSignature(Fixtures.Bytes(fixture)));
    }

    [Fact]
    public void TamperedCabFailsVerification()
    {
        var bytes = Fixtures.Bytes("generated-signed/cab/sample.cab");
        var ctx = CabDigest.ParseContext(bytes);
        bytes[ctx.SigPos - 1] ^= 0xFF;
        var e = Assert.Throws<PsignException>(() => CabDigest.VerifyDigestConsistency(bytes));
        Assert.Contains("digest mismatch", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnsignedCabHasNoSignature()
    {
        var bytes = Fixtures.Bytes("generated-unsigned/cab/sample.cab");
        Assert.False(CabDigest.HasSignature(bytes));
        var e = Assert.Throws<PsignException>(() => CabDigest.VerifyDigestConsistency(bytes));
        Assert.Contains("no embedded Authenticode signature", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PreparedCabDigestMatchesDigestForSigning()
    {
        var unsigned = Fixtures.Bytes("generated-unsigned/cab/sample.cab");
        var prepared = CabDigest.PrepareUnsignedForAuthenticodeSignature(unsigned, 0);
        Assert.Equal(unsigned.Length + 24, prepared.Length);

        // A zero-length signature extent is rejected by the context parser (sigpos without siglen).
        Assert.Throws<PsignException>(() => CabDigest.ParseContext(prepared));

        var fakePkcs7 = Enumerable.Repeat((byte)0x5A, 100).ToArray();
        var withBlob = CabDigest.AppendAuthenticodePkcs7Signature(unsigned, fakePkcs7);
        var ctx = CabDigest.ParseContext(withBlob);
        Assert.Equal(CabDigest.SignedHeaderExtra, ctx.HeaderSize);
        Assert.Equal((uint)prepared.Length, ctx.SigPos);
        Assert.Equal(100u, ctx.SigLen);
        Assert.Equal(fakePkcs7, CabDigest.SignaturePkcs7Der(withBlob));
        Assert.Equal(
            CabDigest.AuthenticodeDigestForSigning(unsigned, AuthenticodeHashKind.Sha256),
            CabDigest.ComputeAuthenticodeDigest(withBlob, ctx, AuthenticodeHashKind.Sha256));
        var e = Assert.Throws<PsignException>(() => CabDigest.PrepareUnsignedForAuthenticodeSignature(withBlob, 0));
        Assert.Contains("reserve header", e.Message, StringComparison.Ordinal);
    }

    [SkippableTheory]
    [InlineData("generated-unsigned/cab/sample.cab", "sha1")]
    [InlineData("generated-unsigned/cab/sample.cab", "sha256")]
    [InlineData("generated-unsigned/cab/sample.cab", "sha384")]
    [InlineData("generated-unsigned/cab/sample.cab", "sha512")]
    [InlineData(TinySigned, "sha256")]
    [InlineData("generated-signed/cab/sample.cab", "sha256")]
    public void CabDigestMatchesRust(string fixture, string algorithm)
    {
        RustTool.Require();
        var rust = RustTool.RunOk("portable", "cab-digest", "--algorithm", algorithm, Fixtures.Path(fixture)).Trim();
        var data = Fixtures.Bytes(fixture);
        var cs = CabDigest.ComputeAuthenticodeDigest(data, CabDigest.ParseContext(data), AuthenticodeHashKinds.Parse(algorithm));
        Assert.Equal(rust, Hex.Lower(cs));
    }

    [SkippableTheory]
    [InlineData(TinySigned)]
    [InlineData("generated-signed/cab/sample.cab")]
    public void ExtractedPkcs7MatchesRust(string fixture)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var output = dir.File("sig.p7");
        RustTool.RunOk("portable", "extract-cab-pkcs7", "--output", output, Fixtures.Path(fixture));
        Assert.Equal(File.ReadAllBytes(output), CabDigest.SignaturePkcs7Der(Fixtures.Bytes(fixture)));
    }
}
