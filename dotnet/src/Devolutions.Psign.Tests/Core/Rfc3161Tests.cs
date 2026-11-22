using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Timestamp;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class Rfc3161Tests
{
    private static readonly byte[] TsRespGrantedNoToken = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];

    private static bool Contains(byte[] haystack, byte[] needle) => haystack.AsSpan().IndexOf(needle) >= 0;

    [Fact]
    public void BuildTimestampRequestSha256ZerosStructureAndLength()
    {
        var preimage = new byte[32];
        var got = Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan(), preimage)!;
        Assert.Equal(56, got.Length);
        Assert.Equal(new byte[] { 0x30, 0x36, 0x02, 0x01, 0x01, 0x30 }, got[..6]);
        Assert.Equal(new byte[] { 0x04, 0x20 }, got[22..24]);
        Assert.Equal(preimage, got[24..]);
    }

    [Fact]
    public void BuildTimestampRequestWithNonceAndCertReqExtendsDer()
    {
        var plan = new Rfc3161TimestampRequestPlan { DigestAlgOid = Oids.Sha256, Nonce = 0x0102_0304_0506_0708, CertReq = true };
        var got = Rfc3161.BuildTimestampRequestBytes(plan, new byte[32])!;
        Assert.True(got.Length > 56);
        Assert.True(Contains(got, [0x01, 0x01, 0xff]));
        Assert.True(Contains(got, [0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));
    }

    [Fact]
    public void BuildTimestampRequestWrongPreimageLenReturnsNull()
    {
        var plan = new Rfc3161TimestampRequestPlan();
        Assert.Null(Rfc3161.BuildTimestampRequestBytes(plan, new byte[31]));
        Assert.Null(Rfc3161.BuildTimestampRequestBytes(plan, new byte[33]));
        Assert.Equal(
            "unsupported digest OID / preimage length for RFC3161 TimeStampReq",
            Assert.Throws<PsignException>(() => Rfc3161.BuildTimestampRequest(AuthenticodeHashKind.Sha256, new byte[31])).Message);
    }

    [Fact]
    public void BuildTimestampRequestUnknownOidReturnsNull()
    {
        Assert.Null(Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = "1.2.3.4" }, new byte[32]));
    }

    [Fact]
    public void BuildTimestampRequestSha1Length20()
    {
        var v = Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = Oids.Sha1 }, Enumerable.Repeat((byte)7, 20).ToArray())!;
        Assert.Equal(40, v.Length);
        Assert.Equal(new byte[] { 0x30, 0x26 }, v[..2]);
    }

    [Theory]
    [InlineData("2.16.840.1.101.3.4.2.2", 48, 72)]
    [InlineData("2.16.840.1.101.3.4.2.3", 64, 88)]
    public void BuildTimestampRequestSha384AndSha512NonzeroPreimage(string oid, int n, int expectLen)
    {
        var p = Enumerable.Repeat((byte)0xab, n).ToArray();
        p[n - 1] = 0xcd;
        var der = Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = oid }, p)!;
        Assert.Equal(0x30, der[0]);
        Assert.True(Contains(der, p));
        Assert.Equal(expectLen, der.Length);
    }

    [Theory]
    [InlineData("1.3.14.3.2.26", 20)]
    [InlineData("2.16.840.1.101.3.4.2.1", 32)]
    [InlineData("2.16.840.1.101.3.4.2.2", 48)]
    [InlineData("2.16.840.1.101.3.4.2.3", 64)]
    public void BuildTimestampRequestEmbedsAlgorithmIdentifierInMessageImprint(string oid, int len)
    {
        var alg = Rfc3161.MessageImprintAlgorithmIdentifierDer(oid)!;
        var preimage = Enumerable.Repeat((byte)0xcd, len).ToArray();
        var der = Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = oid }, preimage)!;
        Assert.True(Contains(der, alg));
        Assert.True(Contains(der, preimage));
    }

    [Fact]
    public void ParseTstInfoExtractsCoreFieldsAndNonce()
    {
        var imprintBody = new List<byte>(Rfc3161.MessageImprintAlgorithmIdentifierDer(Oids.Sha256)!) { 0x04, 32 };
        imprintBody.AddRange(Enumerable.Repeat((byte)0x22, 32));
        var imprint = new List<byte> { 0x30, (byte)imprintBody.Count };
        imprint.AddRange(imprintBody);

        var body = new List<byte> { 0x02, 0x01, 0x01, 0x06, 0x03, 0x2a, 0x03, 0x04 };
        body.AddRange(imprint);
        body.AddRange(new byte[] { 0x02, 0x01, 0x7f });
        body.AddRange(new byte[] { 0x18, 0x0f });
        body.AddRange("20240102030405Z"u8.ToArray());
        body.AddRange(new byte[] { 0x02, 0x01, 0x09 });
        var tstinfo = new List<byte> { 0x30, (byte)body.Count };
        tstinfo.AddRange(body);

        var parsed = Rfc3161.ParseTstInfoDer(tstinfo.ToArray())!;
        Assert.Equal("1.2.3.4", parsed.PolicyOid);
        Assert.Equal(Oids.Sha256, parsed.MessageImprintDigestAlgOid);
        Assert.Equal(Enumerable.Repeat((byte)0x22, 32).ToArray(), parsed.MessageImprintHashedMessage);
        Assert.Equal("7f", parsed.SerialNumberHex);
        Assert.Equal("20240102030405Z", parsed.GenTime);
        Assert.Equal("09", parsed.NonceHex);
    }

    [Fact]
    public void ParseTimeStampRespGrantedWithStatusStringOuterSequenceLength0x81()
    {
        var der = Fixtures.Bytes("rfc3161/ts_resp_granted_outer_len81.der");
        Assert.Equal(138, der.Length);
        var p = Rfc3161.ParseTimeStampRespDer(der)!;
        Assert.Equal(Rfc3161PkiStatusKind.Granted, p.PkiStatus.Kind);
        Assert.Single(p.StatusStrings);
        Assert.Equal(125, p.StatusStrings[0].Length);
        Assert.All(p.StatusStrings[0], c => Assert.Equal('y', c));
        Assert.Null(p.TimeStampToken);
    }

    [Fact]
    public void ParseTimeStampRespGrantedWithoutToken()
    {
        var p = Rfc3161.ParseTimeStampRespDer(TsRespGrantedNoToken)!;
        Assert.Equal(Rfc3161PkiStatusKind.Granted, p.PkiStatus.Kind);
        Assert.Equal(0u, p.PkiStatus.AsRawInteger());
        Assert.True(p.PkiStatus.Granted);
        Assert.Null(p.TimeStampToken);
        Assert.Empty(p.StatusStrings);
        Assert.Null(p.FailInfoTlv);
    }

    [Fact]
    public void ParseTimeStampRespGrantedWithMods()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01])!;
        Assert.Equal(Rfc3161PkiStatusKind.GrantedWithMods, p.PkiStatus.Kind);
        Assert.Equal(1u, p.PkiStatus.AsRawInteger());
        Assert.True(p.PkiStatus.Granted);
        Assert.Empty(p.StatusStrings);
    }

    [Theory]
    [InlineData(3, Rfc3161PkiStatusKind.Waiting, "waiting")]
    [InlineData(4, Rfc3161PkiStatusKind.RevocationWarning, "revocation-warning")]
    [InlineData(5, Rfc3161PkiStatusKind.RevocationNotification, "revocation-notification")]
    [InlineData(0x63, Rfc3161PkiStatusKind.Unknown, "unknown")]
    [InlineData(2, Rfc3161PkiStatusKind.Rejection, "rejection")]
    public void ParseTimeStampRespStatusInts(byte raw, Rfc3161PkiStatusKind kind, string label)
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, raw])!;
        Assert.Equal(kind, p.PkiStatus.Kind);
        Assert.Equal(raw, p.PkiStatus.AsRawInteger());
        Assert.False(p.PkiStatus.Granted);
        Assert.Equal(label, p.PkiStatus.Label);
    }

    [Fact]
    public void ParseTimeStampRespGrantedMalformedFailInfoTlvDecodeReturnsNull()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x08, 0x00])!;
        Assert.Null(Rfc3161.PkiFailureInfoFlagLabelsFromBitStringTlv(p.FailInfoTlv!));
    }

    [Fact]
    public void ParseTimeStampRespRejectionWithPkiFreeTextStatusString()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x0d, 0x30, 0x0b, 0x02, 0x01, 0x02, 0x30, 0x06, 0x0c, 0x04, 0x6e, 0x6f, 0x70, 0x65])!;
        Assert.Equal(Rfc3161PkiStatusKind.Rejection, p.PkiStatus.Kind);
        Assert.Equal(["nope"], p.StatusStrings);
        Assert.Null(p.FailInfoTlv);
    }

    [Fact]
    public void ParseTimeStampRespRejectionWithMultiPkiFreeTextStatusStrings()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x11, 0x30, 0x0f, 0x02, 0x01, 0x02, 0x30, 0x0a, 0x0c, 0x01, 0x61, 0x0c, 0x02, 0x62, 0x62, 0x0c, 0x01, 0x63])!;
        Assert.Equal(["a", "bb", "c"], p.StatusStrings);
        Assert.Null(p.FailInfoTlv);
    }

    [Fact]
    public void ParseTimeStampRespRejectsFailInfoBeforeStatusString()
    {
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x30, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x02, 0x03, 0x02, 0x00, 0xc0, 0x30, 0x03, 0x0c, 0x01, 0x77]));
    }

    [Fact]
    public void ParseTimeStampRespGrantedWithFailInfoBitString()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x00, 0xc0])!;
        Assert.Equal(Rfc3161PkiStatusKind.Granted, p.PkiStatus.Kind);
        Assert.Equal(new byte[] { 0x03, 0x02, 0x00, 0xc0 }, p.FailInfoTlv);
    }

    [Fact]
    public void ParseTimeStampRespGrantedWithStatusStringAndFailInfo()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x00, 0x30, 0x03, 0x0c, 0x01, 0x77, 0x03, 0x02, 0x00, 0xc0])!;
        Assert.Equal(["w"], p.StatusStrings);
        Assert.Equal(new byte[] { 0x03, 0x02, 0x00, 0xc0 }, p.FailInfoTlv);
    }

    [Fact]
    public void ParseTimeStampRespGrantedWithTokenTlv()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x03, 0x02, 0x01, 0x2a])!;
        Assert.Empty(p.StatusStrings);
        Assert.Equal(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x2a }, p.TimeStampToken);
    }

    [Fact]
    public void ParseTimeStampRespAcceptsIntegerSecondTlvAsOpaqueToken()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x08, 0x30, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x2a])!;
        Assert.Equal(new byte[] { 0x02, 0x01, 0x2a }, p.TimeStampToken);
    }

    [Fact]
    public void ParseTimeStampRespRejectsMalformedInputs()
    {
        Assert.Null(Rfc3161.ParseTimeStampRespDer([.. TsRespGrantedNoToken, 0xff]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x30, 0x0a, 0x30, 0x03, 0x02, 0x01]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x31, 0x00]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x30, 0x80, 0x00, 0x00]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x30, 0x0b, 0x30, 0x03, 0x02, 0x01, 0x00, 0x04, 0x01, 0x00, 0x04, 0x01, 0x01]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x30, 0x0a, 0x30, 0x08, 0x02, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]));
        Assert.Null(Rfc3161.ParseTimeStampRespDer([0x30, 0x0a, 0x30, 0x08, 0x02, 0x01, 0x02, 0x30, 0x03, 0x16, 0x01, 0x41]));
    }

    [Fact]
    public void ParseTimeStampRespUnknownStatusIntegers()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x06, 0x30, 0x04, 0x02, 0x02, 0x00, 0x80])!;
        Assert.Equal(Rfc3161PkiStatusKind.Unknown, p.PkiStatus.Kind);
        Assert.Equal(128u, p.PkiStatus.AsRawInteger());
        p = Rfc3161.ParseTimeStampRespDer([0x30, 0x06, 0x30, 0x04, 0x02, 0x02, 0x01, 0x00])!;
        Assert.Equal(256u, p.PkiStatus.AsRawInteger());
    }

    [Fact]
    public void ParseTimeStampRespRejectionWithEmptyPkiFreeText()
    {
        var p = Rfc3161.ParseTimeStampRespDer([0x30, 0x07, 0x30, 0x05, 0x02, 0x01, 0x02, 0x30, 0x00])!;
        Assert.Equal(Rfc3161PkiStatusKind.Rejection, p.PkiStatus.Kind);
        Assert.Empty(p.StatusStrings);
        Assert.Null(p.FailInfoTlv);
    }

    [Fact]
    public void DerIntegerU64Encodings()
    {
        Assert.Equal(new byte[] { 0x02, 0x01, 0x00 }, Rfc3161.DerIntegerU64(0));
        Assert.Equal(new byte[] { 0x02, 0x01, 0x7f }, Rfc3161.DerIntegerU64(127));
        Assert.Equal(new byte[] { 0x02, 0x02, 0x00, 0x80 }, Rfc3161.DerIntegerU64(128));
        Assert.Equal(new byte[] { 0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, Rfc3161.DerIntegerU64(ulong.MaxValue));
        Assert.Equal(new byte[] { 0x02, 0x03, 0x00, 0xff, 0xff }, Rfc3161.DerIntegerU64(65535));
    }

    [Fact]
    public void BuildTimestampRequestWithNonceU64MaxExtendsOuterLength()
    {
        var got = Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { Nonce = ulong.MaxValue }, new byte[32])!;
        Assert.Equal(56 + 11, got.Length);
        Assert.True(Contains(got, Rfc3161.DerIntegerU64(ulong.MaxValue)));
    }

    [Theory]
    [InlineData(new byte[] { 0x03, 0x02, 0x00, 0xc0 }, new[] { "badAlg", "badMessageCheck" })]
    [InlineData(new byte[] { 0x03, 0x02, 0x00, 0x10 }, new[] { "badTime" })]
    [InlineData(new byte[] { 0x03, 0x02, 0x00, 0x30 }, new[] { "badRequest", "badTime" })]
    [InlineData(new byte[] { 0x03, 0x03, 0x00, 0x00, 0x20 }, new[] { "bit_10" })]
    [InlineData(new byte[] { 0x03, 0x01, 0x00 }, new string[0])]
    [InlineData(new byte[] { 0x03, 0x03, 0x07, 0x80, 0x00 }, new[] { "badAlg" })]
    public void PkiFailureInfoLabels(byte[] tlv, string[] expected)
    {
        Assert.Equal(expected, Rfc3161.PkiFailureInfoFlagLabelsFromBitStringTlv(tlv));
    }

    [Fact]
    public void PkiFailureInfoRejectsWrongTagAndUnusedOver7()
    {
        Assert.Null(Rfc3161.PkiFailureInfoFlagLabelsFromBitStringTlv([0x04, 0x01, 0x00]));
        Assert.Null(Rfc3161.PkiFailureInfoFlagLabelsFromBitStringTlv([0x03, 0x02, 0x08, 0x00]));
    }

    [Fact]
    public void CliHelpers()
    {
        Assert.Equal("00", Rfc3161.NonceHex(0));
        Assert.Equal("0080", Rfc3161.NonceHex(128));
        Assert.Equal("0102030405060708", Rfc3161.NonceHex(0x0102030405060708));
        Assert.Equal("abcd", Rfc3161.NormalizeEvenHex(" 0xABcd "));
        Assert.Throws<PsignException>(() => Rfc3161.NormalizeEvenHex("abc"));
        Assert.Throws<PsignException>(() => Rfc3161.NormalizeEvenHex("zz"));
        Assert.Equal(new byte[] { 0xab, 0x0f }, Rfc3161.ParseHexDigestFixed("0Xab+f", 2));
        Assert.Equal("expect 4 hex chars for this digest size, got 2", Assert.Throws<PsignException>(() => Rfc3161.ParseHexDigestFixed("ab", 2)).Message);
        Assert.Equal("-", Rfc3161.TimeStampTokenPrefixHex([], false));
    }

    [Fact]
    public void InspectionTextForGrantedFixture()
    {
        var text = Rfc3161.FormatTimeStampRespInspection(Fixtures.Bytes("rfc3161/ts_resp_granted_outer_len81.der"), "00", 5);
        var lines = text.Split('\n');
        Assert.Equal("pki_status=granted pki_status_int=0 granted=yes time_stamp_token_len=0", lines[0]);
        Assert.Equal("time_stamp_token_prefix_hex=-", lines[1]);
        Assert.Equal($"status_strings_json=[\"{new string('y', 125)}\"]", lines[2]);
        Assert.Equal("fail_info_tlv_hex=-", lines[3]);
        Assert.Equal("fail_info_flags_json=[]", lines[4]);
        Assert.Equal("tst_info_present=no", lines[5]);
        Assert.Equal("tst_info_message_imprint_match=no", lines[6]);
        Assert.Equal("tst_info_nonce_match=no", lines[7]);
    }
}
