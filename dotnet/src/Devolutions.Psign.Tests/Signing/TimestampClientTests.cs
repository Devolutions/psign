using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Timestamp;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>RFC 3161 TSA HTTP client tests (mock TSA; no network).</summary>
public class TimestampClientTests
{
    private const string Tsa = "http://tsa.mock.test/rfc3161";

    // A fake (unsigned) token ContentInfo: SEQUENCE { OID signedData, [0] { SEQUENCE {} } }.
    private static readonly byte[] FakeToken = Der.EncodeSequence(Der.EncodeOid("1.2.840.113549.1.7.2"), Der.EncodeTlv(0xA0, Der.EncodeSequence()));

    private static byte[] Response(int status, byte[]? token = null, string? statusText = null, byte[]? failInfo = null)
    {
        var info = new List<byte[]> { Der.EncodeTlv(0x02, [(byte)status]) };
        if (statusText is not null)
        {
            info.Add(Der.EncodeSequence(Der.EncodeTlv(0x0C, System.Text.Encoding.UTF8.GetBytes(statusText))));
        }

        if (failInfo is not null)
        {
            info.Add(failInfo);
        }

        var parts = new List<byte[]> { Der.EncodeSequence(info.ToArray()) };
        if (token is not null)
        {
            parts.Add(token);
        }

        return Der.EncodeSequence(parts.ToArray());
    }

    [Fact]
    public void RequestBuilderMatchesRustEncoding()
    {
        var imprint = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var der = TimestampRequestBuilder.Build("2.16.840.1.101.3.4.2.1", imprint, nonce: 0x80, certReq: true)!;
        Assert.Equal(
            "303d020101" + "3031300d06096086480165030402010500" + "0420" + Hex.Lower(imprint) + "02020080" + "0101ff",
            Hex.Lower(der));
        Assert.Null(TimestampRequestBuilder.Build("2.16.840.1.101.3.4.2.1", new byte[20], null, false));
        Assert.Null(TimestampRequestBuilder.Build("1.2.3", new byte[20], null, false));
        Assert.Equal(
            "302c020101" + "3021300906052b0e03021a0500" + "0414" + new string('0', 40) + "020100" + "0101ff",
            Hex.Lower(TimestampRequestBuilder.Build("1.3.14.3.2.26", new byte[20], 0, true)!));
    }

    [SkippableFact]
    public void RequestBuilderMatchesRustTool()
    {
        RustTool.Require();
        var imprint = SHA384.HashData("payload"u8);
        var hex = RustTool.RunOk("portable", "rfc3161-timestamp-req", "--algorithm", "sha384", "--digest-hex", Hex.Lower(imprint), "--nonce", "1234567", "--cert-req", "--output", "hex");
        Assert.Equal(hex.Trim(), Hex.Lower(TimestampRequestBuilder.Build("2.16.840.1.101.3.4.2.2", imprint, 1234567, true)));
    }

    [Fact]
    public void ResponseParserIsStrict()
    {
        var granted = TimestampResponseParser.Parse(Response(0, FakeToken, "ok", [0x03, 0x02, 0x00, 0x80]))!;
        Assert.True(granted.Granted);
        Assert.Equal(FakeToken, granted.TimeStampToken);
        Assert.Equal(new[] { "ok" }, granted.StatusStrings);
        Assert.NotNull(granted.FailInfoTlv);

        Assert.False(TimestampResponseParser.Parse(Response(2))!.Granted);
        Assert.Null(TimestampResponseParser.Parse([0x30, 0x00]));
        Assert.Null(TimestampResponseParser.Parse([.. Response(0, FakeToken), 0x00]));
        Assert.Null(TimestampResponseParser.Parse(Der.EncodeSequence(Der.EncodeSequence(Der.EncodeTlv(0x02, [0]), [0x03, 0x01, 0x00], Der.EncodeSequence()))));
    }

    [Fact]
    public void RequestTokenPostsQueryAndReturnsToken()
    {
        var mock = new MockHttpHandler();
        var route = mock.Map("POST", "^" + Tsa + "$")
            .MatchHeader("Content-Type", "application/timestamp-query")
            .MatchHeader("Accept", "application/timestamp-reply")
            .Respond(200, Response(0, FakeToken), ("Content-Type", "application/timestamp-reply"));
        using var client = new TimestampClient(mock);
        var stamped = new byte[] { 1, 2, 3 };

        Assert.Equal(FakeToken, client.RequestToken(Tsa, AuthenticodeHashKind.Sha256, stamped));
        Assert.Equal(1, route.Hits);
        Assert.Equal(TimestampRequestBuilder.Build("2.16.840.1.101.3.4.2.1", SHA256.HashData(stamped), null, true), mock.Requests[0].Body);
    }

    [Fact]
    public void RequestTokenErrors()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", "/rejected").Respond(200, Response(2, statusText: "bad alg"));
        mock.Map("POST", "/notoken").Respond(200, Response(0));
        mock.Map("POST", "/garbage").Respond(200, "not der");
        mock.Map("POST", "/down").Respond(503, "maintenance");
        using var client = new TimestampClient(mock);

        Assert.Equal("TimeStampResp status is not granted (status=2)", Assert.Throws<PsignException>(() => client.RequestToken("http://t/rejected", AuthenticodeHashKind.Sha256, [1])).Message);
        Assert.Equal("TimeStampResp has no timeStampToken", Assert.Throws<PsignException>(() => client.RequestToken("http://t/notoken", AuthenticodeHashKind.Sha256, [1])).Message);
        Assert.Equal("could not parse TimeStampResp DER from TSA response", Assert.Throws<PsignException>(() => client.RequestToken("http://t/garbage", AuthenticodeHashKind.Sha256, [1])).Message);
        Assert.Equal(
            "TSA returned an HTTP error from http://t/down: HTTP status server error (503 Service Unavailable) for url (http://t/down)",
            Assert.Throws<PsignException>(() => client.RequestToken("http://t/down", AuthenticodeHashKind.Sha256, [1])).FullMessage);
    }

    [Fact]
    public void PostTimestampRequestReportsHexBodyOnHttpError()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", "/err").Respond(400, new byte[] { 0xde, 0xad });
        mock.Map("POST", "/ok").MatchHeader("Accept", "application/timestamp-reply, application/timestamp-response").Respond(200, new byte[] { 1, 2 });
        using var client = new TimestampClient(mock);

        Assert.Equal(
            "TSA HTTP 400 Bad Request — first 2 body bytes (hex): dead",
            Assert.Throws<PsignException>(() => client.PostTimestampRequest(" http://t/err ", [0x30, 0x00])).Message);
        Assert.Equal(new byte[] { 1, 2 }, client.PostTimestampRequest("http://t/ok", [0x30, 0x00]));
        Assert.Equal(
            "timestamp message imprint must be exactly 32 bytes for Sha256, got 3",
            Assert.Throws<PsignException>(() => client.PostRfc3161TimestampRequest("http://t/ok", AuthenticodeHashKind.Sha256, [1, 2, 3])).Message);
    }

    [Fact]
    public void TimestampPkcs7AttachesTokenToFirstSigner()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var indirect = SpcIndirectDataContent.ForPe(AuthenticodeHashKind.Sha256, new byte[32]);
        var pkcs7 = Pkcs7Builder.CreateAuthenticode(indirect, AuthenticodeHashKind.Sha256, signer.Info, [], signer.Key);
        var signature = CmsSignedData.Parse(pkcs7).SignerInfos[0].Signature;

        var mock = new MockHttpHandler();
        mock.Map("POST", "/tsa").Respond(200, Response(0, FakeToken));
        using var client = new TimestampClient(mock);

        var stamped = CmsSignedData.Parse(client.TimestampPkcs7(pkcs7, "http://t/tsa", AuthenticodeHashKind.Sha256));
        var attr = Assert.Single(stamped.SignerInfos[0].UnsignedAttributes!);
        Assert.Equal("1.3.6.1.4.1.311.3.3.1", attr.Oid);
        Assert.Equal(TimestampRequestBuilder.Build("2.16.840.1.101.3.4.2.1", SHA256.HashData(signature), null, true), mock.Requests[0].Body);

        var cms = CmsSignedData.Parse(client.TimestampPkcs7(pkcs7, "http://t/tsa", AuthenticodeHashKind.Sha256, Devolutions.Psign.Signing.Timestamp.Rfc3161TimestampAttribute.CmsTimeStampToken));
        Assert.Equal("1.2.840.113549.1.9.16.2.14", Assert.Single(cms.SignerInfos[0].UnsignedAttributes!).Oid);
    }
}
