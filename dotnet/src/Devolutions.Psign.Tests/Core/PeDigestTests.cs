using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class PeDigestTests
{
    [Theory]
    [InlineData("pe-authenticode-upstream/tiny32.signed.efi", "4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi", "a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae")]
    public void GoldenSha256MatchesUpstream(string fixture, string expected)
    {
        Assert.Equal(expected, PeAuthenticode.DigestSha256Hex(Fixtures.Bytes(fixture)));
    }

    [Fact]
    public void RandomBytesAreNotPe()
    {
        Assert.Throws<PsignException>(() => PeFile.Parse("not a pe"u8.ToArray()));
    }

    [Theory]
    [InlineData("pe-authenticode-upstream/tiny32.signed.efi")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi")]
    public void DigestConsistencyAndCmsRoundTrip(string fixture)
    {
        var image = Fixtures.Bytes(fixture);
        var result = PeAuthenticode.VerifyDigestConsistency(image);
        Assert.Equal(1, result.Pkcs7AuthenticodeEntries);

        var pkcs7 = PeAuthenticode.FirstPkcs7(image);
        var sd = CmsSignedData.Parse(pkcs7);
        var reencoded = sd.Encode();
        Assert.Equal(Pkcs7Wire.OuterSequencePrefix(pkcs7).ToArray(), reencoded);
        var signer = sd.SignerInfos[0];
        var cert = sd.CertificateForSigner(signer);
        Assert.True(Devolutions.Psign.Core.X509.SignatureVerifier.Verify(
            cert.SubjectPublicKeyInfo, signer.SignatureAlgorithm, signer.SignedAttributesSetDer(), signer.Signature,
            AuthenticodeHashKinds.FromOid(signer.DigestAlgorithm.Oid)));
    }

    [Fact]
    public void ChecksumRoundTrip()
    {
        var image = Fixtures.Bytes("pe-authenticode-upstream/tiny64.signed.efi");
        var (stripped, removed) = PeEmbed.RemoveCertificates(image);
        Assert.True(removed > 0);
        Assert.Equal(PeEmbed.ComputeImageChecksum(stripped), PeEmbed.ReadImageChecksum(stripped));
        Assert.Null(PeAuthenticode.VerifyDigestConsistencyIfSigned(stripped));
    }
}
