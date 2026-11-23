using Devolutions.Psign.Core;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>Ports of <c>online.rs</c> and <c>trust_pkcs7.rs</c> unit tests.</summary>
public class OnlineAndEkuTests
{
    private static readonly byte[] CaIssuersOidDer = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
    private static readonly byte[] Sha256WithRsaDer = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];
    private static readonly byte[] Pkcs1Prefix = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];

    private static void PushTlv(List<byte> output, byte tag, IReadOnlyCollection<byte> body)
    {
        output.Add(tag);
        if (body.Count < 0x80)
        {
            output.Add((byte)body.Count);
        }
        else
        {
            output.Add(0x81);
            output.Add((byte)body.Count);
        }

        output.AddRange(body);
    }

    private static byte[] Tlv(byte tag, IReadOnlyCollection<byte> body)
    {
        var o = new List<byte>();
        PushTlv(o, tag, body);
        return o.ToArray();
    }

    [Fact]
    public void ParsesCaIssuersUriFromAiaDer()
    {
        var uri = Tlv(0x86, "http://127.0.0.1:1/issuer.der"u8.ToArray());
        var ad = Tlv(0x30, CaIssuersOidDer.Concat(uri).ToArray());
        var aia = Tlv(0x30, ad);
        Assert.Equal(["http://127.0.0.1:1/issuer.der"], OnlineTrust.ParseAiaCaIssuers(aia));
    }

    private static byte[] MinimalCrl(byte[] outerAlg)
    {
        var tbs = new List<byte> { 0x02, 0x01, 0x01 };
        tbs.AddRange(Sha256WithRsaDer);
        tbs.AddRange([0x30, 0x00]);
        PushTlv(tbs, 0x17, "240101000000Z"u8.ToArray());
        PushTlv(tbs, 0x17, "250101000000Z"u8.ToArray());
        var body = new List<byte>();
        PushTlv(body, 0x30, tbs);
        body.AddRange(outerAlg);
        PushTlv(body, 0x03, new byte[] { 0 }.Concat(Enumerable.Repeat((byte)0x11, 8)).ToArray());
        return Tlv(0x30, body);
    }

    [Fact]
    public void ParsesMinimalEmptyCrl()
    {
        var parsed = OnlineTrust.ParseCertificateListDer(MinimalCrl(Sha256WithRsaDer));
        Assert.Empty(parsed.RevokedSerialTlvs);
    }

    private static byte[] Pkcs1AlgorithmIdentifier(byte lastArc, byte[] parameters)
    {
        var body = new List<byte>();
        PushTlv(body, 0x06, Pkcs1Prefix.Append(lastArc).ToArray());
        body.AddRange(parameters);
        return Tlv(0x30, body);
    }

    [Fact]
    public void MapsRsaPkcs1v15SignatureAlgorithms()
    {
        Assert.Equal(OnlineTrust.RsaPkcs1v15Hash.Sha256, OnlineTrust.RsaHashFromAlgorithmIdentifierTlv(Sha256WithRsaDer));
        foreach (var (arc, hash) in new (byte, OnlineTrust.RsaPkcs1v15Hash)[] { (0x0b, OnlineTrust.RsaPkcs1v15Hash.Sha256), (0x0c, OnlineTrust.RsaPkcs1v15Hash.Sha384), (0x0d, OnlineTrust.RsaPkcs1v15Hash.Sha512) })
        {
            Assert.Equal(hash, OnlineTrust.RsaHashFromAlgorithmIdentifierTlv(Pkcs1AlgorithmIdentifier(arc, [0x05, 0x00])));
            Assert.Equal(hash, OnlineTrust.RsaHashFromAlgorithmIdentifierTlv(Pkcs1AlgorithmIdentifier(arc, [])));
        }
    }

    [Fact]
    public void RejectsUnsupportedOrMalformedSignatureAlgorithms()
    {
        Assert.Null(OnlineTrust.RsaHashFromAlgorithmIdentifierTlv(Pkcs1AlgorithmIdentifier(0x05, [0x05, 0x00])));
        Assert.Null(OnlineTrust.RsaHashFromAlgorithmIdentifierTlv(Pkcs1AlgorithmIdentifier(0x0a, [0x30, 0x00])));
        Assert.Null(OnlineTrust.RsaHashFromAlgorithmIdentifierTlv(Pkcs1AlgorithmIdentifier(0x0c, [0x04, 0x00])));
    }

    [Fact]
    public void RejectsCrlWithMismatchedInnerSignatureAlgorithm()
    {
        var e = Assert.Throws<PsignException>(() => OnlineTrust.ParseCertificateListDer(MinimalCrl(Pkcs1AlgorithmIdentifier(0x0c, [0x05, 0x00]))));
        Assert.Contains("does not match", e.Message);
    }

    [Fact]
    public void VerifiesRealSha384RsaCrlSignature()
    {
        var crl = OnlineTrust.ParseCertificateListDer(Fixtures.Bytes("artifact-signing/microsoft-public-rsa-timestamping-ca-2020.crl"));
        Assert.Equal(OnlineTrust.RsaPkcs1v15Hash.Sha384, crl.SignatureHash);
        var issuer = Anchors.ParseCertBytes(Fixtures.Bytes("artifact-signing/microsoft-public-rsa-timestamping-ca-2020.pem"));
        OnlineTrust.VerifyCrlSignature(crl, issuer);

        var tbs = crl.TbsTlv.ToArray();
        tbs[^1] ^= 0x01;
        Assert.Throws<PsignException>(() => OnlineTrust.VerifyCrlSignature(crl with { TbsTlv = tbs }, issuer));
    }

    [Fact]
    public void OcspLookupUsesStatusFromMatchingCertIdOnly()
    {
        var d1 = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var d2 = new DateTimeOffset(2049, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var parsed = new OnlineTrust.ParsedOcspResponse([], OnlineTrust.RsaPkcs1v15Hash.Sha256, [],
        [
            new([0x30, 0x01, 0x01], OnlineTrust.OcspCheckOutcome.Revoked, d1, d2),
            new([0x30, 0x01, 0x02], OnlineTrust.OcspCheckOutcome.Good, d1, d2),
        ]);
        Assert.Equal(OnlineTrust.OcspCheckOutcome.Revoked, OnlineTrust.OcspResponseForCertId(parsed, [0x30, 0x01, 0x01]).Status);
    }

    [Fact]
    public void RevocationFreshnessRejectsStaleOrFutureWindows()
    {
        var e = Assert.Throws<PsignException>(() => OnlineTrust.EnsureTimeWindowFresh("test", new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.Contains("stale", e.Message);
        var now = DateTimeOffset.UtcNow;
        var f = Assert.Throws<PsignException>(() => OnlineTrust.EnsureTimeWindowFresh("test", now.AddYears(1), now.AddYears(2)));
        Assert.Contains("future", f.Message);
    }

    [Fact]
    public void ParsesHttpUriGeneralNamesFromCrlDpShape()
    {
        var uri = Tlv(0x86, "http://127.0.0.1:1/crl.der"u8.ToArray());
        var ext = Tlv(0x30, Tlv(0x30, Tlv(0xa0, Tlv(0xa0, uri))));
        Assert.Equal(["http://127.0.0.1:1/crl.der"], OnlineTrust.ParseHttpUriGeneralNames(ext));
    }

    [Fact]
    public void RejectsNonHttpUrls()
    {
        var e = Assert.Throws<PsignException>(() => OnlineTrust.HttpGetLimited("https://example.invalid/x", new OnlineTrustOptions()));
        Assert.Equal("only http:// URLs are supported by portable online trust", e.Message);
    }

    // --- trust_pkcs7.rs EKU scanning ---
    private static byte[] EncodeBase128(ulong value)
    {
        var encoded = new List<byte> { (byte)(value & 0x7f) };
        value >>= 7;
        while (value != 0)
        {
            encoded.Add((byte)((value & 0x7f) | 0x80));
            value >>= 7;
        }

        encoded.Reverse();
        return encoded.ToArray();
    }

    private static byte[] EncodeOid(ulong[] arcs)
    {
        var value = new List<byte>(EncodeBase128((arcs[0] * 40) + arcs[1]));
        foreach (var arc in arcs.Skip(2))
        {
            value.AddRange(EncodeBase128(arc));
        }

        return Tlv(0x06, value);
    }

    internal static byte[] EncodeEku(params ulong[][] oids) => Tlv(0x30, oids.SelectMany(EncodeOid).ToArray());

    private static readonly ulong[] CodeSigning = [1, 3, 6, 1, 5, 5, 7, 3, 3];
    private static readonly ulong[] TestLifetimeSigning = [1, 3, 6, 1, 4, 1, 311, 10, 3, 13];
    private static readonly ulong[] TestIdentity = [1, 3, 6, 1, 4, 1, 311, 97, 1, 2, 548_345_392, 570_456_524, 348_779_735, 628_493_769];
    private static readonly ulong[] PublicTrust = [1, 3, 6, 1, 4, 1, 311, 97, 1, 0];
    private static readonly ulong[] ProductionIdentity = [1, 3, 6, 1, 4, 1, 311, 97, 872_172_236, 817_999_856, 585_183_201, 971_782_747];
    private static readonly byte[] CodeSigningValue = CmsTrustHelpers.OidValue(Oids.EkuCodeSigning);

    [Fact]
    public void AcceptsAzureTestAndProductionEkus()
    {
        Assert.True(CmsTrustHelpers.ExtendedKeyUsageContains(EncodeEku(TestLifetimeSigning, TestIdentity, CodeSigning), CodeSigningValue));
        Assert.True(CmsTrustHelpers.ExtendedKeyUsageContains(EncodeEku(PublicTrust, ProductionIdentity, CodeSigning), CodeSigningValue));
        Assert.False(CmsTrustHelpers.ExtendedKeyUsageContains(EncodeEku(PublicTrust, ProductionIdentity), CodeSigningValue));
        Assert.True(CmsTrustHelpers.ExtendedKeyUsageContains(EncodeEku([2, 25, (ulong)uint.MaxValue + 1], CodeSigning), CodeSigningValue));
    }

    [Fact]
    public void RejectsMalformedEkus()
    {
        Assert.Throws<PsignException>(() => CmsTrustHelpers.ExtendedKeyUsageContains([0x30, 0x03, 0x06, 0x01, 0x80], CodeSigningValue));
        Assert.Throws<PsignException>(() => CmsTrustHelpers.ExtendedKeyUsageContains([0x30, 0x04, 0x06, 0x02, 0x80, 0x01], CodeSigningValue));
        Assert.Throws<PsignException>(() => CmsTrustHelpers.ExtendedKeyUsageContains([0x30, 0x03, 0x04, 0x01, 0x00], CodeSigningValue));
        Assert.Throws<PsignException>(() => CmsTrustHelpers.ExtendedKeyUsageContains(EncodeEku(CodeSigning).Append((byte)0).ToArray(), CodeSigningValue));
        var body = EncodeOid(CodeSigning).Concat(new byte[] { 0x06, 0x01, 0x80 }).ToArray();
        Assert.Throws<PsignException>(() => CmsTrustHelpers.ExtendedKeyUsageContains(Tlv(0x30, body), CodeSigningValue));
    }
}
