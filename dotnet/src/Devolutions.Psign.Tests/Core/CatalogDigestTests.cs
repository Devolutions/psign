using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Cms;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class CatalogDigestTests
{
    private const string Tiny32Cat = "catalog-authenticode-upstream/tiny32-content.cat";

    [Fact]
    public void OctetStringScanFindsSha256()
    {
        var digest = Enumerable.Repeat((byte)7, 32).ToArray();
        byte[] blob = [0x6c, 0x40, 0x30, 0x04, 0x20, .. digest, 0xff];
        Assert.True(CatalogDigest.BlobContainsOctetStringDigest(blob, digest));
    }

    [Fact]
    public void OctetStringScanLongLenFormSha384()
    {
        var digest = Enumerable.Repeat((byte)9, 48).ToArray();
        byte[] blob = [0x04, 0x81, 48, .. digest];
        Assert.True(CatalogDigest.BlobContainsOctetStringDigest(blob, digest));
        Assert.False(CatalogDigest.BlobContainsOctetStringDigest(blob[..^1], digest));
    }

    [Fact]
    public void RsaSha256SignerPrehashMatchesPkcs7HelperOnTiny32Cat()
    {
        var cat = Fixtures.Bytes(Tiny32Cat);
        var sd = CmsSignedData.Parse(cat);
        var expected = SHA256.HashData(sd.SignerInfos[0].SignedAttributesSetDer());
        Assert.Equal(expected, CatalogDigest.RsaSha256SignerPrehashDigest(cat, 0));
    }

    [Theory]
    [InlineData("catalog-workflows/single-pe.cat")]
    [InlineData("catalog-workflows/single-text.cat")]
    [InlineData("catalog-workflows/single-binary.cat")]
    [InlineData("catalog-workflows/multi-member.cat")]
    [InlineData("generated-signed/catalog/sample.cat")]
    public void SignedCatalogsAreConsistent(string fixture)
    {
        var cat = Fixtures.Bytes(fixture);
        CatalogDigest.VerifyDigestConsistency(cat);
        var sd = CatalogDigest.ParseSignedData(cat);
        Assert.Equal(sd.SignerInfos[0].MessageDigest(), CatalogDigest.EContentDigest(cat));
    }

    [Fact]
    public void MultiMemberCatalogMembersVerify()
    {
        var cat = Fixtures.Bytes("catalog-workflows/multi-member.cat");
        var members = CatalogDigest.Members(cat);
        Assert.True(members.Count >= 3);
        foreach (var subject in new[] { "tiny32.efi", "hello.txt", "blob.bin" })
        {
            var m = CatalogDigest.VerifyMember(cat, Fixtures.Bytes("catalog-workflows/subjects/" + subject));
            Assert.Equal(m.Member.Digest, m.ComputedDigest);
        }
    }

    [Fact]
    public void NonMemberIsRejected()
    {
        var cat = Fixtures.Bytes("catalog-workflows/single-text.cat");
        var e = Assert.Throws<PsignException>(() => CatalogDigest.VerifyMember(cat, "not a member"u8.ToArray()));
        Assert.StartsWith("subject file is not a member of the catalog", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PeAuthenticodeIsNotACatalog()
    {
        var pkcs7 = Devolutions.Psign.Core.Pe.PeAuthenticode.FirstPkcs7(Fixtures.Bytes("pe-authenticode-upstream/tiny32.signed.efi"));
        var e = Assert.Throws<PsignException>(() => CatalogDigest.VerifyDigestConsistency(pkcs7));
        Assert.Contains("not Microsoft CTL", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(new byte[] { 0x3c, 0, 0x61, 0, 0x3e, 0, 0, 0 }, "a")]
    [InlineData(new byte[] { 0x61, 0, 0x62, 0 }, "ab")]
    [InlineData(new byte[] { 0x3c, 0 }, "<")]
    [InlineData(new byte[] { 0x61 }, null)]
    [InlineData(new byte[] { 0x00, 0xD8 }, null)]
    public void DecodesSubjectIdentifiers(byte[] bytes, string? expected)
    {
        Assert.Equal(expected, CatalogDigest.DecodeUtf16LeSubjectIdentifier(bytes));
    }

    public static TheoryData<string, string> MemberCases() => new()
    {
        { "catalog-workflows/single-pe.cat", "catalog-workflows/subjects/tiny32.efi" },
        { "catalog-workflows/single-text.cat", "catalog-workflows/subjects/hello.txt" },
        { "catalog-workflows/single-binary.cat", "catalog-workflows/subjects/blob.bin" },
        { "catalog-workflows/multi-member.cat", "catalog-workflows/subjects/hello.txt" },
        { "catalog-workflows/multi-member.cat", "catalog-workflows/subjects/tiny32.efi" },
        { "catalog-workflows/single-text.cat", "catalog-workflows/subjects/blob.bin" },
    };

    [SkippableTheory]
    [MemberData(nameof(MemberCases))]
    public void VerifyMemberMatchesRust(string catalog, string subject)
    {
        RustTool.Require();
        var (code, stdout, _) = RustTool.Run("portable", "verify-catalog-member", "--catalog", Fixtures.Path(catalog), Fixtures.Path(subject));
        CatalogMemberMatch? m = null;
        try
        {
            m = CatalogDigest.VerifyMember(Fixtures.Path(catalog), Fixtures.Path(subject));
        }
        catch (PsignException)
        {
        }

        Assert.Equal(code == 0, m is not null);
        if (m is not null)
        {
            var expected =
                $"member_index={m.MemberIndex} member_name={m.Member.SubjectName ?? "-"} digest_alg_oid={m.Member.DigestAlgorithmOid} data_oid={m.Member.DataOid} digest={Hex.Lower(m.ComputedDigest)}";
            Assert.EndsWith(expected, stdout.Trim(), StringComparison.Ordinal);
        }
    }

    [SkippableTheory]
    [InlineData("catalog-workflows/multi-member.cat")]
    [InlineData("generated-signed/catalog/sample.cat")]
    [InlineData(Tiny32Cat)]
    public void VerifyCatalogOutcomeMatchesRust(string fixture)
    {
        RustTool.Require();
        var (code, _, _) = RustTool.Run("portable", "verify-catalog", Fixtures.Path(fixture));
        bool ok;
        try
        {
            CatalogDigest.VerifyDigestConsistency(Fixtures.Path(fixture));
            ok = true;
        }
        catch (PsignException)
        {
            ok = false;
        }

        Assert.Equal(code == 0, ok);
    }
}
