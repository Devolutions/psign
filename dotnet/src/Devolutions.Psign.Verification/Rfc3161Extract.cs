using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>
/// Best-effort RFC 3161 / Authenticode nested timestamp extraction for verification instant selection, plus trusted
/// timestamp token validation (Rust <c>rfc3161_extract.rs</c>).
/// </summary>
public static class Rfc3161Extract
{
    internal const string IdSignedData = "1.2.840.113549.1.7.2";
    internal const string IdCtTstInfo = "1.2.840.113549.1.9.16.1.4";
    internal const string IdSigningTime = "1.2.840.113549.1.9.5";
    internal const string IdAaTimeStampToken = "1.2.840.113549.1.9.16.2.14";
    internal const string OidMsTimestampToken = "1.3.6.1.4.1.311.3.3.1";

    /// <summary>A decoded CMS <c>ContentInfo</c> (content type + the TLV inside <c>[0] EXPLICIT</c>).</summary>
    internal sealed record ContentInfo(string ContentType, byte[] Content);

    /// <summary>
    /// Signing time from an embedded timestamp token and/or PKCS#9 <c>signing-time</c>. Precedence: nested RFC 3161
    /// <c>TSTInfo.genTime</c> from unsigned attributes on any signer, then PKCS#9 <c>signing-time</c> from the first signer
    /// that carries it. Returns <c>null</c> when nothing usable is found.
    /// </summary>
    public static DateTimeOffset? UtcDateFromAuthenticodeTimestampToken(ReadOnlySpan<byte> pkcs7Der)
    {
        var sd = SignedDataFromPkcs7(pkcs7Der);
        if (sd is null)
        {
            return null;
        }

        DateTimeOffset? signingTimeFallback = null;
        foreach (var si in sd.SignerInfos)
        {
            if (UtcDateFromSignerUnsignedAttrs(si) is { } d)
            {
                return d;
            }

            signingTimeFallback ??= UtcDateFromSignerSignedAttrs(si);
        }

        return signingTimeFallback;
    }

    /// <summary>
    /// Verify the primary signer's RFC 3161 timestamp token (signature, MessageImprint over the primary signature, TSA EKU
    /// and TSA chain to <paramref name="anchors"/>) and return its <c>genTime</c>; <c>null</c> when there is no token.
    /// </summary>
    public static DateTimeOffset? TrustedUtcDateFromAuthenticodeTimestampToken(
        ReadOnlySpan<byte> pkcs7Der,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        OnlineTrustOptions online,
        bool verboseChain,
        TextWriter? log = null)
    {
        var outer = SignedDataFromPkcs7(pkcs7Der);
        if (outer is null || outer.SignerInfos.Count == 0)
        {
            return null;
        }

        var primary = outer.SignerInfos[0];
        var found = TimestampTokenFromSignerUnsignedAttrs(primary);
        if (found is null)
        {
            return null;
        }

        var (token, tstinfoDer, genDate) = found.Value;
        return VerifyTimestampToken(token, tstinfoDer, genDate, primary.Signature, anchors, anchorCerts, online, verboseChain, log);
    }

    /// <summary>
    /// Verify a standalone RFC 3161 timestamp token (DER <c>ContentInfo</c>) whose MessageImprint covers
    /// <paramref name="timestampedBytes"/>, with the TSA chain terminating in <paramref name="anchors"/>; returns
    /// <c>TSTInfo.genTime</c>.
    /// </summary>
    public static DateTimeOffset TrustedUtcDateFromTimestampToken(
        ReadOnlySpan<byte> tokenDer,
        ReadOnlySpan<byte> timestampedBytes,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        OnlineTrustOptions online,
        bool verboseChain,
        TextWriter? log = null)
    {
        var token = DecodeContentInfoLoose(tokenDer) ?? throw new PsignException("timestamp token is not a CMS ContentInfo");
        var sd = SignedDataFromContentInfo(token) ?? throw new PsignException("timestamp token SignedData decode failed");
        if (sd.EncapContentType != IdCtTstInfo)
        {
            throw new PsignException("timestamp token does not encapsulate TSTInfo");
        }

        var tstinfo = (sd.EncapContent is null ? null : TstInfoBytesFromEncapsulatedEContent(sd.EncapContent))
            ?? throw new PsignException("timestamp token TSTInfo is missing");
        var gen = TstInfoGenTime(tstinfo) ?? throw new PsignException("timestamp token genTime missing");
        return VerifyTimestampToken(token, tstinfo, gen, timestampedBytes.ToArray(), anchors, anchorCerts, online, verboseChain, log);
    }

    private static DateTimeOffset VerifyTimestampToken(
        ContentInfo token,
        byte[] tstinfoDer,
        DateTimeOffset genDate,
        byte[] primarySignature,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        OnlineTrustOptions online,
        bool verboseChain,
        TextWriter? log)
    {
        var tsSd = SignedDataFromContentInfo(token)
            ?? throw new PsignException("timestamp token SignedData decode failed (after stripping unsupported cert choices)");
        var parsed = ParseTstInfoDer(tstinfoDer) ?? throw new PsignException("timestamp token TSTInfo parse failed");
        var expectedImprint = DigestForOid(parsed.MessageImprintDigestAlgOid, primarySignature);
        if (!parsed.MessageImprintHashedMessage.AsSpan().SequenceEqual(expectedImprint))
        {
            throw new PsignException("timestamp token MessageImprint does not match primary signer signature");
        }

        if (tsSd.SignerInfos.Count == 0)
        {
            throw new PsignException("timestamp token SignedData has no SignerInfo");
        }

        var si = tsSd.SignerInfos[0];
        var tsaDigestKind = AuthenticodeHashKinds.FromOid(si.DigestAlgorithm.Oid)
            ?? throw new PsignException($"timestamp token CMS signature: unsupported SignerInfo digestAlgorithm {si.DigestAlgorithm.Oid}");
        var tstDigest = tsaDigestKind.Hash(tstinfoDer);
        try
        {
            VerifyTimestampCmsSignature(tsSd, si, tsaDigestKind, tstDigest);
        }
        catch (PsignException e)
        {
            throw new PsignException($"timestamp token CMS signature: {e.Message}");
        }

        CertificateInfo tsa;
        try
        {
            tsa = CmsTrustHelpers.CertificateForSigner(tsSd, si);
        }
        catch (PsignException e)
        {
            throw new PsignException($"timestamp token signer certificate: {e.Message}");
        }

        if (!HasTimeStampingEku(tsa))
        {
            throw new PsignException("timestamp token signer certificate lacks timeStamping extended key usage");
        }

        var embedded = CmsTrustHelpers.EmbeddedCertificatesStrict(tsSd, "timestamp embedded certificate");
        var merged = TrustChain.MergeUniqueCerts(anchorCerts, embedded);
        var chain = TrustChain.IssuerChainExcludingLeafOnline(tsa, merged, online, anchors);
        var root = TrustChain.TerminalRootCert(tsa, chain);
        if (!anchors.Contains(root))
        {
            throw new PsignException("timestamp token TSA chain terminates at an untrusted root");
        }

        OnlineTrust.CheckRevocationChain(tsa, chain, online);
        if (verboseChain)
        {
            (log ?? Console.Error).WriteLine($"trust-verify: timestamp TSA leaf subject: {PickyCert.SubjectDisplay(tsa)}");
        }

        try
        {
            if (PickyCert.IsSelfIssued(tsa) && chain.Count == 0)
            {
                PickyCert.Verify(tsa, [], new PickyValidatorOptions { Now = PickyFormat.Truncate(genDate), RequireChainCheck = false });
            }
            else
            {
                PickyCert.VerifyExact(tsa, chain, genDate);
            }
        }
        catch (PickyException e)
        {
            throw new PsignException($"timestamp token TSA chain verification: {e.Message}");
        }

        return genDate;
    }

    private static void VerifyTimestampCmsSignature(CmsSignedData sd, CmsSignerInfo si, AuthenticodeHashKind digestKind, byte[] expectedContentDigest)
    {
        if (digestKind == AuthenticodeHashKind.Sha256)
        {
            CmsTrustHelpers.VerifyPkcs9MessageDigestAndRsaSha256(sd, 0, expectedContentDigest);
            return;
        }

        var md = CmsTrustHelpers.SignerInfoPkcs9MessageDigestOctets(si);
        if (!md.AsSpan().SequenceEqual(expectedContentDigest))
        {
            throw new PsignException("PKCS#9 messageDigest does not match expected content digest");
        }

        var cert = CmsTrustHelpers.CertificateForSigner(sd, si);
        if (si.SignedAttributes is null)
        {
            throw new PsignException("SignerInfo has no authenticated attributes");
        }

        var attrsDer = si.SignedAttributesSetDer();
        if (!SignatureVerifier.Verify(cert.SubjectPublicKeyInfo, si.SignatureAlgorithm, attrsDer, si.Signature, digestKind))
        {
            throw new PsignException($"CMS verify over signedAttrs ({digestKind.Name()}): signature error");
        }
    }

    private static readonly byte[] TimeStampingOidValue = CmsTrustHelpers.OidValue(Oids.EkuTimeStamping);

    private static bool HasTimeStampingEku(CertificateInfo cert)
    {
        foreach (var ext in cert.Extensions.Where(e => e.Oid == Oids.ExtendedKeyUsage))
        {
            try
            {
                if (CmsTrustHelpers.ExtendedKeyUsageContains(ext.Value, TimeStampingOidValue))
                {
                    return true;
                }
            }
            catch (PsignException e)
            {
                throw new PsignException($"timestamp ExtendedKeyUsage extension: {e.Message}");
            }
        }

        return false;
    }

    internal static byte[] DigestForOid(string oid, byte[] data) => oid switch
    {
        Oids.Sha1 => SHA1.HashData(data),
        Oids.Sha256 => SHA256.HashData(data),
        Oids.Sha384 => SHA384.HashData(data),
        Oids.Sha512 => SHA512.HashData(data),
        _ => throw new PsignException($"unsupported timestamp MessageImprint digest algorithm {oid}"),
    };

    /// <summary>Decode <c>ContentInfo</c> strictly (no normalization: bare <c>SignedData</c> is rejected) and return its SignedData.</summary>
    internal static CmsSignedData? SignedDataFromPkcs7(ReadOnlySpan<byte> pkcs7Der)
    {
        var ci = DecodeContentInfo(pkcs7Der);
        return ci is null ? null : SignedDataFromContentInfo(ci);
    }

    /// <summary>
    /// Decode CMS <c>SignedData</c> from a <c>ContentInfo</c>. The parser keeps non-X.509 certificate choices and CRLs
    /// as raw elements, which covers the Rust attribute-certificate stripping retry.
    /// </summary>
    internal static CmsSignedData? SignedDataFromContentInfo(ContentInfo ci)
    {
        if (ci.ContentType != IdSignedData)
        {
            return null;
        }

        try
        {
            return CmsSignedData.ParseSignedData(ci.Content);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            return null;
        }
    }

    /// <summary>Strict <c>ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }</c> (trailing octets ignored).</summary>
    internal static ContentInfo? DecodeContentInfo(ReadOnlySpan<byte> bytes)
    {
        var outer = Der.First(bytes);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            return null;
        }

        var c = Der.Children(bytes, outer.Value);
        if (c is not { Count: 2 } || c[0].Tag != 0x06 || c[1].Tag != 0xA0)
        {
            return null;
        }

        var oid = Der.DecodeOid(c[0].Encoded(bytes));
        var inner = Der.Children(bytes, c[1]);
        if (oid is null || inner is not { Count: 1 })
        {
            return null;
        }

        return new ContentInfo(oid, inner[0].Encoded(bytes).ToArray());
    }

    internal static ContentInfo? DecodeContentInfoLoose(ReadOnlySpan<byte> bytes)
    {
        if (DecodeContentInfo(bytes) is { } ci)
        {
            return ci;
        }

        var inner = PeelOctetStringOuter(bytes);
        return inner is null ? null : DecodeContentInfo(inner);
    }

    internal static byte[]? PeelOctetStringOuter(ReadOnlySpan<byte> bytes)
    {
        var t = Der.First(bytes);
        if (t is null || t.Value.Tag != 0x04)
        {
            return null;
        }

        return t.Value.Value(bytes).ToArray();
    }

    private static (ContentInfo Token, byte[] TstInfo, DateTimeOffset Gen)? TimestampTokenFromSignerUnsignedAttrs(CmsSignerInfo si)
    {
        var attrs = si.UnsignedAttributes;
        if (attrs is null)
        {
            return null;
        }

        foreach (var attr in attrs.Where(a => TimestampAttrPriority(a.Oid) is not null))
        {
            if (TimestampTokenFromAttribute(attr) is { } v)
            {
                return v;
            }
        }

        foreach (var attr in attrs.Where(a => TimestampAttrPriority(a.Oid) is null))
        {
            if (TimestampTokenFromAttribute(attr) is { } v)
            {
                return v;
            }
        }

        return null;
    }

    private static (ContentInfo Token, byte[] TstInfo, DateTimeOffset Gen)? TimestampTokenFromAttribute(CmsAttribute attr)
    {
        foreach (var val in attr.Values)
        {
            var token = TimestampContentInfoFromAttributeValue(val);
            if (token is null)
            {
                continue;
            }

            var sd = SignedDataFromContentInfo(token);
            if (sd is null || sd.EncapContentType != IdCtTstInfo || sd.EncapContent is null)
            {
                continue;
            }

            var tst = TstInfoBytesFromEncapsulatedEContent(sd.EncapContent);
            if (tst is null || TstInfoGenTime(tst) is not { } gen)
            {
                continue;
            }

            return (token, tst, gen);
        }

        return null;
    }

    private static ContentInfo? TimestampContentInfoFromAttributeValue(byte[] valueTlv) =>
        DecodeContentInfoLoose(valueTlv) ?? DecodeContentInfoLoose(AttributeValueBytes(valueTlv));

    private static byte[] AttributeValueBytes(byte[] valueTlv)
    {
        var t = Der.First(valueTlv);
        return t is null ? [] : t.Value.Value(valueTlv).ToArray();
    }

    private static int? TimestampAttrPriority(string oid) => oid switch
    {
        IdAaTimeStampToken => 0,
        OidMsTimestampToken => 1,
        _ => null,
    };

    private static DateTimeOffset? UtcDateFromSignerUnsignedAttrs(CmsSignerInfo si)
    {
        var attrs = si.UnsignedAttributes;
        if (attrs is null)
        {
            return null;
        }

        foreach (var attr in attrs.Where(a => TimestampAttrPriority(a.Oid) is not null))
        {
            if (UtcDateFromTimestampAttribute(attr) is { } d)
            {
                return d;
            }
        }

        foreach (var attr in attrs.Where(a => TimestampAttrPriority(a.Oid) is null))
        {
            if (UtcDateFromTimestampAttribute(attr) is { } d)
            {
                return d;
            }
        }

        return null;
    }

    private static DateTimeOffset? UtcDateFromTimestampAttribute(CmsAttribute attr)
    {
        foreach (var val in attr.Values)
        {
            if (TryExtractFromNestedPkcs7(val) is { } d)
            {
                return d;
            }

            if (TryExtractFromNestedPkcs7(AttributeValueBytes(val)) is { } d2)
            {
                return d2;
            }
        }

        return null;
    }

    private static DateTimeOffset? TryExtractFromNestedPkcs7(byte[] bytes)
    {
        var ci = DecodeContentInfoLoose(bytes);
        if (ci is null)
        {
            return null;
        }

        var sd = SignedDataFromContentInfo(ci);
        if (sd is null || sd.EncapContentType != IdCtTstInfo || sd.EncapContent is null)
        {
            return null;
        }

        var tst = TstInfoBytesFromEncapsulatedEContent(sd.EncapContent);
        return tst is null ? null : TstInfoGenTime(tst);
    }

    /// <summary>TSTInfo SEQUENCE from <c>eContent</c> (the TLV inside <c>[0]</c>; its value octets are peeled).</summary>
    internal static byte[]? TstInfoBytesFromEncapsulatedEContent(byte[] eContentTlv) =>
        PeelToTstInfoSequence(AttributeValueBytes(eContentTlv));

    private static byte[]? PeelToTstInfoSequence(byte[] sl)
    {
        for (int i = 0; i < 8; i++)
        {
            if (sl.Length == 0)
            {
                return null;
            }

            switch (sl[0])
            {
                case 0x30:
                    return sl;
                case 0x04:
                    var o = PeelOctetStringOuter(sl);
                    if (o is null)
                    {
                        return null;
                    }

                    sl = o;
                    break;
                case 0xa0:
                case 0xa1:
                    var t = Der.First(sl);
                    if (t is null)
                    {
                        return null;
                    }

                    sl = t.Value.Value(sl).ToArray();
                    break;
                default:
                    return null;
            }
        }

        return null;
    }

    internal static DateTimeOffset? TstInfoGenTime(byte[] tstinfoDer)
    {
        var outer = Der.First(tstinfoDer);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            return null;
        }

        int pos = outer.Value.ValueStart;
        int end = outer.Value.ValueEnd;
        for (int i = 0; i < 4; i++)
        {
            var t = Der.TlvAt(tstinfoDer, pos, end);
            if (t is null)
            {
                return null;
            }

            pos = t.Value.End;
        }

        var gt = Der.TlvAt(tstinfoDer, pos, end);
        if (gt is null || gt.Value.Tag != 0x18)
        {
            return null;
        }

        return UtcDateFromGeneralizedTimeContents(gt.Value.Value(tstinfoDer));
    }

    /// <summary>
    /// Parse <c>GeneralizedTime</c> contents, accepting fractional seconds (truncated) and only a <c>Z</c>/<c>z</c> suffix.
    /// </summary>
    internal static DateTimeOffset? UtcDateFromGeneralizedTimeContents(ReadOnlySpan<byte> body)
    {
        string s;
        try
        {
            s = new UTF8Encoding(false, true).GetString(body).Trim();
        }
        catch (DecoderFallbackException)
        {
            return null;
        }

        if (s.EndsWith('Z') || s.EndsWith('z'))
        {
            s = s[..^1];
        }
        else
        {
            return null;
        }

        string main = s;
        int dot = s.IndexOf('.');
        if (dot >= 0)
        {
            main = s[..dot];
            var frac = s[(dot + 1)..];
            if (frac.Length == 0 || !frac.All(char.IsAsciiDigit))
            {
                return null;
            }
        }

        if (!main.All(char.IsAsciiDigit))
        {
            return null;
        }

        int year, month, day, hour, minute, second;
        if (main.Length == 14 || main.Length == 12)
        {
            year = int.Parse(main[..4], CultureInfo.InvariantCulture);
            month = int.Parse(main[4..6], CultureInfo.InvariantCulture);
            day = int.Parse(main[6..8], CultureInfo.InvariantCulture);
            hour = int.Parse(main[8..10], CultureInfo.InvariantCulture);
            minute = int.Parse(main[10..12], CultureInfo.InvariantCulture);
            second = main.Length == 14 ? int.Parse(main[12..14], CultureInfo.InvariantCulture) : 0;
        }
        else
        {
            return null;
        }

        try
        {
            if (hour > 23 || minute > 59 || second > 59)
            {
                return null;
            }

            return new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static DateTimeOffset? UtcDateFromSignerSignedAttrs(CmsSignerInfo si)
    {
        if (si.SignedAttributes is null)
        {
            return null;
        }

        foreach (var attr in si.SignedAttributes.Where(a => a.Oid == IdSigningTime))
        {
            foreach (var val in Der.SortSetOf(attr.Values))
            {
                if (UtcDateFromSigningTimeAny(val) is { } d)
                {
                    return d;
                }
            }
        }

        return null;
    }

    /// <summary>Strict DER <c>Time</c> (UTCTime <c>YYMMDDHHMMSSZ</c> or GeneralizedTime <c>YYYYMMDDHHMMSSZ</c>).</summary>
    internal static DateTimeOffset? UtcDateFromSigningTimeAny(ReadOnlySpan<byte> bytes)
    {
        var t = Der.First(bytes);
        if (t is null || t.Value.End != bytes.Length)
        {
            return null;
        }

        var body = t.Value.Value(bytes);
        string s = Encoding.ASCII.GetString(body);
        int year;
        string rest;
        if (t.Value.Tag == 0x17)
        {
            if (s.Length != 13 || s[12] != 'Z' || !s[..12].All(char.IsAsciiDigit))
            {
                return null;
            }

            int yy = int.Parse(s[..2], CultureInfo.InvariantCulture);
            year = yy >= 50 ? 1900 + yy : 2000 + yy;
            rest = s[2..12];
        }
        else if (t.Value.Tag == 0x18)
        {
            if (s.Length != 15 || s[14] != 'Z' || !s[..14].All(char.IsAsciiDigit))
            {
                return null;
            }

            year = int.Parse(s[..4], CultureInfo.InvariantCulture);
            rest = s[4..14];
        }
        else
        {
            return null;
        }

        try
        {
            int month = int.Parse(rest[..2], CultureInfo.InvariantCulture);
            int day = int.Parse(rest[2..4], CultureInfo.InvariantCulture);
            int hour = int.Parse(rest[4..6], CultureInfo.InvariantCulture);
            int minute = int.Parse(rest[6..8], CultureInfo.InvariantCulture);
            int second = int.Parse(rest[8..10], CultureInfo.InvariantCulture);
            if (hour > 23 || minute > 59 || second > 59)
            {
                return null;
            }

            return new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>Fields of RFC 3161 <c>TSTInfo</c> (Rust <c>psign_sip_digest::timestamp::ParsedRfc3161TstInfo</c>).</summary>
    internal sealed record ParsedTstInfo(
        string PolicyOid,
        string MessageImprintDigestAlgOid,
        byte[] MessageImprintHashedMessage,
        string SerialNumberHex,
        string GenTime,
        string? NonceHex);

    /// <summary>Private port of <c>psign_sip_digest::timestamp::parse_tst_info_der</c>.</summary>
    internal static ParsedTstInfo? ParseTstInfoDer(byte[] der)
    {
        var outer = Der.First(der);
        if (outer is null || outer.Value.Tag != 0x30 || outer.Value.End != der.Length)
        {
            return null;
        }

        var items = new List<DerTlv>();
        int pos = outer.Value.ValueStart;
        while (pos < outer.Value.ValueEnd)
        {
            var t = Der.TlvAt(der, pos, outer.Value.ValueEnd);
            if (t is null)
            {
                return null;
            }

            items.Add(t.Value);
            pos = t.Value.End;
        }

        if (items.Count < 5 || items[0].Tag != 0x02 || items[1].Tag != 0x06 || items[2].Tag != 0x30 || items[3].Tag != 0x02 || items[4].Tag != 0x18)
        {
            return null;
        }

        var policy = Der.DecodeOid(items[1].Encoded(der));
        if (policy is null)
        {
            return null;
        }

        var mi = Der.Children(der, items[2]);
        if (mi is not { Count: 2 } || mi[0].Tag != 0x30 || mi[1].Tag != 0x04)
        {
            return null;
        }

        var alg = Der.Children(der, mi[0]);
        if (alg is not { Count: >= 1 } || alg[0].Tag != 0x06 || Der.DecodeOid(alg[0].Encoded(der)) is not { } algOid)
        {
            return null;
        }

        string genTime;
        try
        {
            genTime = new UTF8Encoding(false, true).GetString(items[4].Value(der));
        }
        catch (DecoderFallbackException)
        {
            return null;
        }

        string? nonce = null;
        foreach (var t in items.Skip(5))
        {
            switch (t.Tag)
            {
                case 0x02:
                    nonce = Hex.Lower(t.Value(der));
                    break;
                case 0x30:
                case 0x01:
                case 0xa0:
                case 0xa1:
                    break;
                default:
                    return null;
            }
        }

        return new ParsedTstInfo(
            policy,
            algOid,
            mi[1].Value(der).ToArray(),
            Hex.Lower(items[3].Value(der)),
            genTime,
            nonce);
    }
}
