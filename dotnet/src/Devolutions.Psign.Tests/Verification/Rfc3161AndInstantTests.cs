using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>Ports of <c>rfc3161_extract.rs</c> and <c>verification_instant.rs</c> unit tests.</summary>
public class Rfc3161AndInstantTests
{
    private static readonly byte[] TstInfoDerGen20230701 =
    [
        0x30, 0x58, 0x02, 0x01, 0x01, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x59, 0x0a,
        0x04, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x03, 0x01, 0xe2, 0x40, 0x18, 0x0f,
        0x32, 0x30, 0x32, 0x33, 0x30, 0x37, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a,
    ];

    private static byte[] Tiny(string name) => PeAuthenticode.FirstPkcs7(Fixtures.Bytes("pe-authenticode-upstream/" + name));

    private static (int, int, int) Ymd(DateTimeOffset d) => (d.Year, d.Month, d.Day);

    [Fact]
    public void ParseVerificationDateYmdAcceptsIsoDay()
    {
        VerificationInstant.ParseVerificationDateYmd("2023-07-01");
        Assert.Throws<PsignException>(() => VerificationInstant.ParseVerificationDateYmd("not-a-date"));
        Assert.Throws<PsignException>(() => VerificationInstant.ParseVerificationDateYmd("2023-13-01"));
        Assert.Equal("expected YYYY-MM-DD", Assert.Throws<PsignException>(() => VerificationInstant.ParseVerificationDateYmd("2023")).Message);
    }

    [Fact]
    public void ResolveRequireTimestampErrorsWithoutToken()
    {
        var policy = new AuthenticodeTrustPolicy { PreferTimestampSigningTime = true, RequireValidTimestamp = true };
        var e = Assert.Throws<PsignException>(() => VerificationInstant.ResolveVerificationUtcDate([], policy));
        Assert.Contains("timestamp required", e.Message);
    }

    [Fact]
    public void ResolveRequireTimestampOkWhenPreferOff()
    {
        var policy = new AuthenticodeTrustPolicy { PreferTimestampSigningTime = false, RequireValidTimestamp = true };
        VerificationInstant.ResolveVerificationUtcDate([], policy);
    }

    [Fact]
    public void ResolvePreferTimestampWithoutRequireDoesNotErrorOnEmpty()
    {
        var policy = new AuthenticodeTrustPolicy { PreferTimestampSigningTime = true };
        VerificationInstant.ResolveVerificationUtcDate([], policy);
    }

    [Fact]
    public void ResolveInstantOverrideSkipsTimestampRequirement()
    {
        var policy = new AuthenticodeTrustPolicy { PreferTimestampSigningTime = true, RequireValidTimestamp = true };
        var d = VerificationInstant.ParseVerificationDateYmd("2020-01-01");
        var got = VerificationInstant.ResolveVerificationInstantForPkcs7("not-valid-pkcs7"u8, policy, d);
        Assert.Equal((2020, 1, 1), Ymd(got));
    }

    [Fact]
    public void SigningTimeUtcAndGeneralizedRoundtrip()
    {
        var ut = Asn1Time.EncodeTime(new DateTimeOffset(2023, 6, 15, 12, 30, 45, TimeSpan.Zero));
        Assert.Equal((2023, 6, 15), Ymd(Rfc3161Extract.UtcDateFromSigningTimeAny(ut)!.Value));
        var gt = Asn1Time.EncodeGeneralizedTime(new DateTimeOffset(2023, 7, 1, 12, 0, 0, TimeSpan.Zero));
        Assert.Equal((2023, 7, 1), Ymd(Rfc3161Extract.UtcDateFromSigningTimeAny(gt)!.Value));
    }

    [Fact]
    public void SigningTimeRejectsTruncatedOrNonTimeDer()
    {
        Assert.Null(Rfc3161Extract.UtcDateFromSigningTimeAny([]));
        Assert.Null(Rfc3161Extract.UtcDateFromSigningTimeAny([0x30, 0x00]));
        Assert.Null(Rfc3161Extract.UtcDateFromSigningTimeAny([0x02, 0x01, 0x2a]));
    }

    [Fact]
    public void TstInfoGenTimeRejectsMalformed()
    {
        Assert.Null(Rfc3161Extract.TstInfoGenTime([0x02, 0x01, 0x00]));
        Assert.Null(Rfc3161Extract.TstInfoGenTime([0x30, 0x00]));
    }

    [Fact]
    public void GeneralizedTimeContentsForms()
    {
        Assert.Equal((2026, 8, 10), Ymd(Rfc3161Extract.UtcDateFromGeneralizedTimeContents("20260810234021.194Z"u8)!.Value));
        Assert.Equal((2023, 7, 1), Ymd(Rfc3161Extract.UtcDateFromGeneralizedTimeContents("20230701120000Z"u8)!.Value));
        Assert.Null(Rfc3161Extract.UtcDateFromGeneralizedTimeContents("20230701120000+0000"u8));
        Assert.Null(Rfc3161Extract.UtcDateFromGeneralizedTimeContents("not-a-time"u8));
        Assert.Null(Rfc3161Extract.UtcDateFromGeneralizedTimeContents("20230701120000.Z"u8));
    }

    [Fact]
    public void TstInfoGenTimeAcceptsFractionalGeneralizedTime()
    {
        var body = new List<byte>();
        body.AddRange([0x02, 0x01, 0x01]);
        body.AddRange([0x06, 0x02, 0x2a, 0x03]);
        var mi = new List<byte> { 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
        mi.AddRange(new byte[32]);
        body.Add(0x30);
        body.Add((byte)mi.Count);
        body.AddRange(mi);
        body.AddRange([0x02, 0x01, 0x01]);
        var gt = "20260810234021.194Z"u8.ToArray();
        body.Add(0x18);
        body.Add((byte)gt.Length);
        body.AddRange(gt);
        var tlv = new List<byte> { 0x30, (byte)body.Count };
        tlv.AddRange(body);
        Assert.Equal((2026, 8, 10), Ymd(Rfc3161Extract.TstInfoGenTime(tlv.ToArray())!.Value));
    }

    [Fact]
    public void TstInfoGenTimeSkipsFixedFields() =>
        Assert.Equal((2023, 7, 1), Ymd(Rfc3161Extract.TstInfoGenTime(TstInfoDerGen20230701)!.Value));

    [Theory]
    [InlineData("tiny32.signed.efi")]
    [InlineData("tiny64.signed.efi")]
    public void UpstreamPeSigningTimeExtracts(string name)
    {
        var d = Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(Tiny(name));
        Assert.Equal((2023, 6, 24), Ymd(d!.Value));
    }

    [Theory]
    [InlineData("tiny32.signed.efi")]
    [InlineData("tiny64.signed.efi")]
    public void BareSignedDataDoesNotExtract(string name)
    {
        var sd = CmsSignedData.Parse(Tiny(name));
        Assert.Null(Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(sd.EncodeSignedData()));
        Assert.NotNull(Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(sd.Encode()));
    }

    private static byte[] Tiny32WithNestedTimestamp(string attrOid, bool appendSigningTime)
    {
        var outer = CmsSignedData.Parse(Tiny("tiny32.signed.efi"));
        var inner = outer.Clone();
        inner.EncapContentType = Oids.TstInfo;
        inner.EncapContent = Der.EncodeTlv(0x04, TstInfoDerGen20230701);
        var innerCi = inner.Encode();
        var wrapped = Der.EncodeTlv(0x04, innerCi);

        var si = outer.SignerInfos[0].Clone();
        if (appendSigningTime)
        {
            si.SignedAttributes!.Add(new CmsAttribute(Oids.Pkcs9SigningTime, Asn1Time.EncodeTime(new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero))));
        }

        si.UnsignedAttributes = [new CmsAttribute(attrOid, wrapped)];
        outer.SignerInfos[0] = si;
        return outer.Encode();
    }

    private static byte[] Tiny32SigningTimeOnly(DateTimeOffset when, bool generalized)
    {
        var outer = CmsSignedData.Parse(Tiny("tiny32.signed.efi"));
        var si = outer.SignerInfos[0].Clone();
        si.UnsignedAttributes = null;
        si.SignedAttributes = si.SignedAttributes!.Where(a => a.Oid != Oids.Pkcs9SigningTime).ToList();
        si.SignedAttributes.Add(new CmsAttribute(Oids.Pkcs9SigningTime, generalized ? Asn1Time.EncodeGeneralizedTime(when) : Asn1Time.EncodeTime(when)));
        outer.SignerInfos[0] = si;
        return outer.Encode();
    }

    [Fact]
    public void IdAaNestedTstInfoGenTime() =>
        Assert.Equal((2023, 7, 1), Ymd(Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(Tiny32WithNestedTimestamp(Oids.Pkcs9Rfc3161TimestampToken, false))!.Value));

    [Fact]
    public void MsOidNestedTstInfoGenTime() =>
        Assert.Equal((2023, 7, 1), Ymd(Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(Tiny32WithNestedTimestamp(Oids.MsRfc3161TimestampToken, false))!.Value));

    [Fact]
    public void NestedTstInfoPreemptsPkcs9SigningTime() =>
        Assert.Equal((2023, 7, 1), Ymd(Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(Tiny32WithNestedTimestamp(Oids.Pkcs9Rfc3161TimestampToken, true))!.Value));

    [Fact]
    public void Pkcs9SigningTimeWhenNoUnsigned()
    {
        var pkcs7 = Tiny32SigningTimeOnly(new DateTimeOffset(2022, 11, 8, 14, 30, 0, TimeSpan.Zero), generalized: false);
        Assert.Equal((2022, 11, 8), Ymd(Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(pkcs7)!.Value));
        var policy = new AuthenticodeTrustPolicy { PreferTimestampSigningTime = true };
        Assert.Equal((2022, 11, 8), Ymd(VerificationInstant.ResolveVerificationUtcDate(pkcs7, policy)));
    }

    [Fact]
    public void Pkcs9GeneralizedSigningTime()
    {
        var pkcs7 = Tiny32SigningTimeOnly(new DateTimeOffset(2050, 3, 1, 9, 15, 30, TimeSpan.Zero), generalized: true);
        Assert.Equal((2050, 3, 1), Ymd(Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(pkcs7)!.Value));
        var policy = new AuthenticodeTrustPolicy { PreferTimestampSigningTime = true, RequireValidTimestamp = true };
        Assert.Equal((2050, 3, 1), Ymd(VerificationInstant.ResolveVerificationUtcDate(pkcs7, policy)));
    }

    [Fact]
    public void RealArtifactSigningTimestampTokenIsTrusted()
    {
        var pkcs7 = Fixtures.Bytes("artifact-signing/psign-tool.pkcs7.der");
        var (anchors, certs) = ArtifactSigning.PublicTrustAnchors();
        var trusted = Rfc3161Extract.TrustedUtcDateFromAuthenticodeTimestampToken(pkcs7, anchors, certs, new OnlineTrustOptions(), false);
        var loose = Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(pkcs7);
        Assert.NotNull(trusted);
        Assert.Equal(Ymd(loose!.Value), Ymd(trusted!.Value));

        // Wrong anchors: the TSA chain must not terminate.
        var other = AnchorStore.Empty();
        other.MergeThumbprintsOnly([new byte[20]]);
        Assert.Throws<PsignException>(() =>
            Rfc3161Extract.TrustedUtcDateFromAuthenticodeTimestampToken(pkcs7, other, [], new OnlineTrustOptions(), false));
    }

    [Fact]
    public void ParseTstInfoReadsImprint()
    {
        var parsed = Rfc3161Extract.ParseTstInfoDer(TstInfoDerGen20230701)!;
        Assert.Equal(Oids.Sha256, parsed.MessageImprintDigestAlgOid);
        Assert.Equal(32, parsed.MessageImprintHashedMessage.Length);
        Assert.Equal("20230701120000Z", parsed.GenTime);
        Assert.Equal("01e240", parsed.SerialNumberHex);
    }
}
