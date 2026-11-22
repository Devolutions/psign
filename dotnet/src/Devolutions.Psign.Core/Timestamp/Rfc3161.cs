using System.Text;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.Timestamp;

/// <summary>Plan for a single <c>TimeStampReq</c> (Rust <c>Rfc3161TimestampRequestPlan</c>).</summary>
public sealed class Rfc3161TimestampRequestPlan
{
    /// <summary>Digest algorithm OID (default SHA-256).</summary>
    public string DigestAlgOid { get; init; } = Oids.Sha256;

    /// <summary>Optional <c>nonce</c> (minimal unsigned DER <c>INTEGER</c>).</summary>
    public ulong? Nonce { get; init; }

    /// <summary>When true, append <c>certReq BOOLEAN TRUE</c> (omitted when false, the RFC default).</summary>
    public bool CertReq { get; init; }
}

/// <summary>Named <c>PKIStatus</c> values.</summary>
public enum Rfc3161PkiStatusKind
{
    Granted,
    GrantedWithMods,
    Rejection,
    Waiting,
    RevocationWarning,
    RevocationNotification,
    Unknown,
}

/// <summary><c>PKIStatus</c> from <c>PKIStatusInfo.status</c> (Rust <c>Rfc3161PkiStatus</c>; <c>Unknown(v)</c> keeps <c>v</c>).</summary>
public readonly record struct Rfc3161PkiStatus(Rfc3161PkiStatusKind Kind, uint RawValue)
{
    /// <summary>Map a raw status integer.</summary>
    public static Rfc3161PkiStatus FromRaw(uint v) => v switch
    {
        0 => new(Rfc3161PkiStatusKind.Granted, 0),
        1 => new(Rfc3161PkiStatusKind.GrantedWithMods, 1),
        2 => new(Rfc3161PkiStatusKind.Rejection, 2),
        3 => new(Rfc3161PkiStatusKind.Waiting, 3),
        4 => new(Rfc3161PkiStatusKind.RevocationWarning, 4),
        5 => new(Rfc3161PkiStatusKind.RevocationNotification, 5),
        _ => new(Rfc3161PkiStatusKind.Unknown, v),
    };

    /// <summary><c>granted</c> or <c>grantedWithMods</c>.</summary>
    public bool Granted => Kind is Rfc3161PkiStatusKind.Granted or Rfc3161PkiStatusKind.GrantedWithMods;

    /// <summary>The <c>PKIStatusInfo.status</c> integer.</summary>
    public uint AsRawInteger() => RawValue;

    /// <summary>CLI label (<c>granted</c>, <c>granted-with-mods</c>, ..., <c>unknown</c>).</summary>
    public string Label => Kind switch
    {
        Rfc3161PkiStatusKind.Granted => "granted",
        Rfc3161PkiStatusKind.GrantedWithMods => "granted-with-mods",
        Rfc3161PkiStatusKind.Rejection => "rejection",
        Rfc3161PkiStatusKind.Waiting => "waiting",
        Rfc3161PkiStatusKind.RevocationWarning => "revocation-warning",
        Rfc3161PkiStatusKind.RevocationNotification => "revocation-notification",
        _ => "unknown",
    };
}

/// <summary>Parsed <c>TimeStampResp</c> (Rust <c>ParsedTimeStampResp</c>).</summary>
/// <param name="PkiStatus">Status.</param>
/// <param name="TimeStampToken">Raw <c>timeStampToken</c> TLV (typically a CMS <c>ContentInfo</c>), if present.</param>
/// <param name="StatusStrings"><c>PKIStatusInfo.statusString</c> UTF-8 strings.</param>
/// <param name="FailInfoTlv">Raw <c>PKIFailureInfo</c> BIT STRING TLV, if present.</param>
public sealed record ParsedTimeStampResp(Rfc3161PkiStatus PkiStatus, byte[]? TimeStampToken, List<string> StatusStrings, byte[]? FailInfoTlv);

/// <summary>Structurally parsed <c>TSTInfo</c> fields (Rust <c>ParsedRfc3161TstInfo</c>); no cryptographic validation.</summary>
public sealed record ParsedRfc3161TstInfo(
    string PolicyOid,
    string MessageImprintDigestAlgOid,
    byte[] MessageImprintHashedMessage,
    string SerialNumberHex,
    string GenTime,
    string? NonceHex);

/// <summary>
/// RFC 3161 <c>TimeStampReq</c> / <c>TimeStampResp</c> helpers (port of <c>timestamp.rs</c>). Requests are minimal §2.4.1
/// encodings; responses are parsed with a definite-length, single-byte-tag DER subset (lengths up to <c>0x82</c>).
/// </summary>
public static class Rfc3161
{
    private static readonly string[] FailureNames =
    [
        "badAlg",
        "badMessageCheck",
        "badRequest",
        "badTime",
        "badCertId",
        "badDataFormat",
        "wrongAuthority",
        "incorrectData",
        "missingTimeStamp",
        "badPOP",
    ];

    private static (byte[] AlgorithmIdentifierDer, int DigestOctetLen)? DigestAlgSpec(string oid) => oid.Trim() switch
    {
        Oids.Sha1 => ([0x30, 0x0b, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00], 20),
        Oids.Sha256 => ([0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00], 32),
        Oids.Sha384 => ([0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00], 48),
        Oids.Sha512 => ([0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00], 64),
        _ => null,
    };

    /// <summary>Full <c>AlgorithmIdentifier</c> DER (<c>SEQUENCE { OID, NULL }</c>) used in <c>MessageImprint</c>, or <c>null</c>.</summary>
    public static byte[]? MessageImprintAlgorithmIdentifierDer(string oid) => DigestAlgSpec(oid)?.AlgorithmIdentifierDer;

    private static void PushDerDefiniteLength(List<byte> output, int len)
    {
        if (len < 0x80)
        {
            output.Add((byte)len);
        }
        else if (len <= 0xff)
        {
            output.Add(0x81);
            output.Add((byte)len);
        }
        else if (len <= 0xffff)
        {
            output.Add(0x82);
            output.Add((byte)(len >> 8));
            output.Add((byte)len);
        }
        else
        {
            output.Add(0x83);
            output.Add((byte)(len >> 16));
            output.Add((byte)(len >> 8));
            output.Add((byte)len);
        }
    }

    /// <summary>Minimal non-negative DER <c>INTEGER</c> TLV (Rust <c>der_integer_u64</c>).</summary>
    public static byte[] DerIntegerU64(ulong n)
    {
        if (n == 0)
        {
            return [0x02, 0x01, 0x00];
        }

        var digits = new List<byte>();
        ulong x = n;
        while (x > 0)
        {
            digits.Insert(0, (byte)(x & 0xff));
            x >>= 8;
        }

        if ((digits[0] & 0x80) != 0)
        {
            digits.Insert(0, 0);
        }

        var output = new List<byte> { 0x02 };
        PushDerDefiniteLength(output, digits.Count);
        output.AddRange(digits);
        return output.ToArray();
    }

    /// <summary>
    /// Build DER <c>TimeStampReq</c> for <paramref name="imprintPreimage"/> (raw digest octets for
    /// <c>MessageImprint.hashedMessage</c>). Returns <c>null</c> for an unknown OID or a preimage of the wrong length
    /// (Rust <c>build_timestamp_request_bytes</c>).
    /// </summary>
    public static byte[]? BuildTimestampRequestBytes(Rfc3161TimestampRequestPlan plan, ReadOnlySpan<byte> imprintPreimage)
    {
        var spec = DigestAlgSpec(plan.DigestAlgOid);
        if (spec is null || imprintPreimage.Length != spec.Value.DigestOctetLen)
        {
            return null;
        }

        var messageImprint = new List<byte>(spec.Value.AlgorithmIdentifierDer);
        messageImprint.Add(0x04);
        PushDerDefiniteLength(messageImprint, imprintPreimage.Length);
        messageImprint.AddRange(imprintPreimage.ToArray());

        var tsReq = new List<byte> { 0x02, 0x01, 0x01, 0x30 };
        PushDerDefiniteLength(tsReq, messageImprint.Count);
        tsReq.AddRange(messageImprint);
        if (plan.Nonce is { } nonce)
        {
            tsReq.AddRange(DerIntegerU64(nonce));
        }

        if (plan.CertReq)
        {
            tsReq.AddRange([0x01, 0x01, 0xff]);
        }

        var output = new List<byte> { 0x30 };
        PushDerDefiniteLength(output, tsReq.Count);
        output.AddRange(tsReq);
        return output.ToArray();
    }

    /// <summary>
    /// Build a <c>TimeStampReq</c> for a digest kind, throwing the CLI error text when the preimage length is wrong
    /// (<c>rfc3161-timestamp-req</c>).
    /// </summary>
    public static byte[] BuildTimestampRequest(AuthenticodeHashKind kind, ReadOnlySpan<byte> imprintPreimage, ulong? nonce = null, bool certReq = false) =>
        BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = kind.Oid(), Nonce = nonce, CertReq = certReq }, imprintPreimage)
        ?? throw new PsignException("unsupported digest OID / preimage length for RFC3161 TimeStampReq");

    /// <summary>
    /// Decode a <c>PKIFailureInfo</c> BIT STRING TLV into RFC 2510 Appendix A names (<c>badAlg</c> ... <c>badPOP</c>),
    /// higher bits as <c>bit_N</c>; <c>null</c> when malformed (Rust <c>pkifailure_info_flag_labels_from_bit_string_tlv</c>).
    /// </summary>
    public static List<string>? PkiFailureInfoFlagLabelsFromBitStringTlv(ReadOnlySpan<byte> tlv)
    {
        if (tlv.IsEmpty || tlv[0] != 0x03)
        {
            return null;
        }

        var body = DerTlvBody(tlv);
        if (body is null || body.Value.Length == 0)
        {
            return null;
        }

        var b = tlv.Slice(body.Value.Start, body.Value.Length);
        int unused = b[0];
        var valueOctets = b[1..];
        if (unused > 7)
        {
            return null;
        }

        if (valueOctets.IsEmpty)
        {
            return [];
        }

        if (valueOctets.Length * 8 < unused)
        {
            return null;
        }

        int totalBits = (valueOctets.Length * 8) - unused;
        if (totalBits > 256)
        {
            return null;
        }

        var labels = new List<string>();
        for (int i = 0; i < totalBits; i++)
        {
            byte oct = valueOctets[i / 8];
            byte mask = (byte)(0x80 >> (i % 8));
            if ((oct & mask) == 0)
            {
                continue;
            }

            labels.Add(i < FailureNames.Length ? FailureNames[i] : $"bit_{i}");
        }

        return labels;
    }

    // ---------------------------------------------------------------- DER subset (Rust timestamp.rs helpers)

    private static int? DerDefiniteTlvTotalLen(ReadOnlySpan<byte> input)
    {
        if (input.Length < 2)
        {
            return null;
        }

        int pos = 2;
        byte ll = input[1];
        int bodyLen;
        if (ll < 0x80)
        {
            bodyLen = ll;
        }
        else if (ll == 0x81)
        {
            if (input.Length < 3)
            {
                return null;
            }

            bodyLen = input[2];
            pos += 1;
        }
        else if (ll == 0x82)
        {
            if (input.Length < 4)
            {
                return null;
            }

            bodyLen = (input[2] << 8) | input[3];
            pos += 2;
        }
        else
        {
            return null;
        }

        return pos + bodyLen;
    }

    private static (int Tlv, int Remaining)? DerReadTlv0(ReadOnlySpan<byte> input)
    {
        var n = DerDefiniteTlvTotalLen(input);
        if (n is null || n.Value > input.Length)
        {
            return null;
        }

        return (n.Value, input.Length - n.Value);
    }

    private static (int Start, int Length)? DerTlvBody(ReadOnlySpan<byte> tlv)
    {
        var total = DerDefiniteTlvTotalLen(tlv);
        if (total is null || total.Value > tlv.Length)
        {
            return null;
        }

        int lfs = tlv[1] < 0x80 ? 1 : tlv[1] == 0x81 ? 2 : 3;
        int start = 1 + lfs;
        if (start > total.Value)
        {
            return null;
        }

        return (start, total.Value - start);
    }

    private static ReadOnlySpan<byte> Body(ReadOnlySpan<byte> tlv, (int Start, int Length) body) => tlv.Slice(body.Start, body.Length);

    private static uint? DerDecodeSmallNonnegativeInteger(ReadOnlySpan<byte> body)
    {
        while (body.Length > 1 && body[0] == 0 && (body[1] & 0x80) == 0)
        {
            body = body[1..];
        }

        if (body.IsEmpty || body.Length > 4 || (body[0] & 0x80) != 0)
        {
            return null;
        }

        uint v = 0;
        foreach (byte b in body)
        {
            v = (v << 8) + b;
        }

        return v;
    }

    private static List<string>? ParsePkiFreeTextUtf8Strings(ReadOnlySpan<byte> seqTlv)
    {
        if (seqTlv.IsEmpty || seqTlv[0] != 0x30)
        {
            return null;
        }

        var bodyRange = DerTlvBody(seqTlv);
        if (bodyRange is null)
        {
            return null;
        }

        var sl = Body(seqTlv, bodyRange.Value);
        var result = new List<string>();
        while (!sl.IsEmpty)
        {
            var read = DerReadTlv0(sl);
            if (read is null)
            {
                return null;
            }

            var tlv = sl[..read.Value.Tlv];
            sl = sl[read.Value.Tlv..];
            if (tlv[0] != 0x0c)
            {
                return null;
            }

            var utf8 = DerTlvBody(tlv);
            if (utf8 is null)
            {
                return null;
            }

            result.Add(RustText.FromUtf8Lossy(Body(tlv, utf8.Value)));
        }

        return result;
    }

    private static (Rfc3161PkiStatus Status, List<string> StatusStrings, byte[]? FailInfo)? ParsePkiStatusInfoComplete(ReadOnlySpan<byte> statusInfoTlv)
    {
        var innerRange = DerTlvBody(statusInfoTlv);
        if (innerRange is null)
        {
            return null;
        }

        var inner = Body(statusInfoTlv, innerRange.Value);
        var first = DerReadTlv0(inner);
        if (first is null)
        {
            return null;
        }

        var intTlv = inner[..first.Value.Tlv];
        var tail = inner[first.Value.Tlv..];
        if (intTlv[0] != 0x02)
        {
            return null;
        }

        var intBody = DerTlvBody(intTlv);
        if (intBody is null)
        {
            return null;
        }

        var raw = DerDecodeSmallNonnegativeInteger(Body(intTlv, intBody.Value));
        if (raw is null)
        {
            return null;
        }

        var status = Rfc3161PkiStatus.FromRaw(raw.Value);
        var statusStrings = new List<string>();
        byte[]? failInfo = null;
        int phase = 0;
        while (!tail.IsEmpty)
        {
            var read = DerReadTlv0(tail);
            if (read is null)
            {
                return null;
            }

            var tlv = tail[..read.Value.Tlv];
            tail = tail[read.Value.Tlv..];
            if (tlv[0] == 0x30 && phase == 0)
            {
                var strings = ParsePkiFreeTextUtf8Strings(tlv);
                if (strings is null)
                {
                    return null;
                }

                statusStrings = strings;
                phase = 1;
            }
            else if (tlv[0] == 0x03 && phase <= 1)
            {
                if (failInfo is not null)
                {
                    return null;
                }

                failInfo = tlv.ToArray();
                phase = 2;
            }
            else
            {
                return null;
            }
        }

        return (status, statusStrings, failInfo);
    }

    /// <summary>
    /// Parse DER <c>TimeStampResp</c>: <c>PKIStatusInfo</c> (status, optional <c>statusString</c>, then optional
    /// <c>failInfo</c>) and an optional opaque <c>timeStampToken</c> TLV. Returns <c>null</c> for malformed input,
    /// unknown fields, wrong field order, or trailing bytes (Rust <c>parse_time_stamp_resp_der</c>).
    /// </summary>
    public static ParsedTimeStampResp? ParseTimeStampRespDer(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty || input[0] != 0x30)
        {
            return null;
        }

        var outerLen = DerDefiniteTlvTotalLen(input);
        if (outerLen is null || outerLen.Value != input.Length)
        {
            return null;
        }

        var outerRange = DerTlvBody(input);
        if (outerRange is null)
        {
            return null;
        }

        var outer = Body(input, outerRange.Value);
        var first = DerReadTlv0(outer);
        if (first is null)
        {
            return null;
        }

        var statusInfo = ParsePkiStatusInfoComplete(outer[..first.Value.Tlv]);
        if (statusInfo is null)
        {
            return null;
        }

        var rest = outer[first.Value.Tlv..];
        byte[]? token = null;
        if (!rest.IsEmpty)
        {
            var tok = DerReadTlv0(rest);
            if (tok is null || tok.Value.Remaining != 0)
            {
                return null;
            }

            token = rest[..tok.Value.Tlv].ToArray();
        }

        return new ParsedTimeStampResp(statusInfo.Value.Status, token, statusInfo.Value.StatusStrings, statusInfo.Value.FailInfo);
    }

    /// <summary>
    /// Parse a <c>timeStampToken</c> <c>ContentInfo</c> and return its encapsulated <c>TSTInfo</c> fields (structural
    /// only; Rust <c>parse_time_stamp_token_tst_info</c>).
    /// </summary>
    public static ParsedRfc3161TstInfo? ParseTimeStampTokenTstInfo(ReadOnlySpan<byte> tokenTlv)
    {
        CmsSignedData sd;
        try
        {
            var outer = Der.First(tokenTlv);
            if (outer is null || outer.Value.Tag != 0x30)
            {
                return null;
            }

            var ci = Der.Children(tokenTlv, outer.Value);
            if (ci is null || ci.Count != 2 || ci[0].Tag != 0x06 || ci[1].Tag != 0xA0)
            {
                return null;
            }

            if (Der.DecodeOid(ci[0].Encoded(tokenTlv)) != Oids.Pkcs7SignedData)
            {
                return null;
            }

            var content = Der.Children(tokenTlv, ci[1]);
            if (content is not { Count: 1 })
            {
                return null;
            }

            sd = CmsSignedData.ParseSignedData(content[0].Encoded(tokenTlv));
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException or ArgumentException)
        {
            return null;
        }

        if (sd.EncapContentType != Oids.TstInfo || sd.EncapContent is null)
        {
            return null;
        }

        var econtent = Der.First(sd.EncapContent);
        if (econtent is null)
        {
            return null;
        }

        var tstinfo = PeelToTstInfoSequence(econtent.Value.Value(sd.EncapContent));
        return tstinfo is null ? null : ParseTstInfoDer(tstinfo);
    }

    private static byte[]? PeelToTstInfoSequence(ReadOnlySpan<byte> sl)
    {
        for (int i = 0; i < 8; i++)
        {
            if (sl.IsEmpty)
            {
                return null;
            }

            switch (sl[0])
            {
                case 0x30:
                    return sl.ToArray();
                case 0x04:
                case 0xa0:
                case 0xa1:
                    var body = DerTlvBody(sl);
                    if (body is null)
                    {
                        return null;
                    }

                    sl = Body(sl, body.Value);
                    break;
                default:
                    return null;
            }
        }

        return null;
    }

    /// <summary>Parse RFC 3161 <c>TSTInfo</c> DER (Rust <c>parse_tst_info_der</c>).</summary>
    public static ParsedRfc3161TstInfo? ParseTstInfoDer(ReadOnlySpan<byte> tstinfoDer)
    {
        var outerRange = DerTlvBody(tstinfoDer);
        if (outerRange is null || tstinfoDer[0] != 0x30)
        {
            return null;
        }

        var pos = Body(tstinfoDer, outerRange.Value);

        if (!Next(ref pos, out var version) || version[0] != 0x02)
        {
            return null;
        }

        if (!Next(ref pos, out var policyTlv))
        {
            return null;
        }

        var policyOid = OidTlvToString(policyTlv);
        if (policyOid is null)
        {
            return null;
        }

        if (!Next(ref pos, out var messageImprintTlv))
        {
            return null;
        }

        var imprint = ParseMessageImprint(messageImprintTlv);
        if (imprint is null)
        {
            return null;
        }

        if (!Next(ref pos, out var serialTlv) || serialTlv[0] != 0x02)
        {
            return null;
        }

        var serialBody = DerTlvBody(serialTlv);
        if (serialBody is null)
        {
            return null;
        }

        var serialHex = Hex.Lower(Body(serialTlv, serialBody.Value));

        if (!Next(ref pos, out var genTimeTlv) || genTimeTlv[0] != 0x18)
        {
            return null;
        }

        var genBody = DerTlvBody(genTimeTlv);
        if (genBody is null)
        {
            return null;
        }

        var genTime = RustText.TryFromUtf8(Body(genTimeTlv, genBody.Value));
        if (genTime is null)
        {
            return null;
        }

        string? nonceHex = null;
        while (!pos.IsEmpty)
        {
            if (!Next(ref pos, out var tlv))
            {
                return null;
            }

            switch (tlv[0])
            {
                case 0x02:
                    var nb = DerTlvBody(tlv);
                    if (nb is null)
                    {
                        return null;
                    }

                    nonceHex = Hex.Lower(Body(tlv, nb.Value));
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

        return new ParsedRfc3161TstInfo(policyOid, imprint.Value.AlgOid, imprint.Value.Hashed, serialHex, genTime, nonceHex);
    }

    private static bool Next(ref ReadOnlySpan<byte> pos, out ReadOnlySpan<byte> tlv)
    {
        var read = DerReadTlv0(pos);
        if (read is null)
        {
            tlv = default;
            return false;
        }

        tlv = pos[..read.Value.Tlv];
        pos = pos[read.Value.Tlv..];
        return true;
    }

    private static (string AlgOid, byte[] Hashed)? ParseMessageImprint(ReadOnlySpan<byte> tlv)
    {
        if (tlv[0] != 0x30)
        {
            return null;
        }

        var bodyRange = DerTlvBody(tlv);
        if (bodyRange is null)
        {
            return null;
        }

        var body = Body(tlv, bodyRange.Value);
        if (!Next(ref body, out var algTlv) || !Next(ref body, out var hashedTlv))
        {
            return null;
        }

        if (!body.IsEmpty || hashedTlv[0] != 0x04)
        {
            return null;
        }

        var algOid = AlgorithmIdentifierOid(algTlv);
        if (algOid is null)
        {
            return null;
        }

        var hashedBody = DerTlvBody(hashedTlv);
        return hashedBody is null ? null : (algOid, Body(hashedTlv, hashedBody.Value).ToArray());
    }

    private static string? AlgorithmIdentifierOid(ReadOnlySpan<byte> algTlv)
    {
        if (algTlv[0] != 0x30)
        {
            return null;
        }

        var bodyRange = DerTlvBody(algTlv);
        if (bodyRange is null)
        {
            return null;
        }

        var body = Body(algTlv, bodyRange.Value);
        return Next(ref body, out var oidTlv) ? OidTlvToString(oidTlv) : null;
    }

    private static string? OidTlvToString(ReadOnlySpan<byte> oidTlv) =>
        oidTlv.IsEmpty || oidTlv[0] != 0x06 ? null : Der.DecodeOid(oidTlv);

    // ---------------------------------------------------------------- CLI helpers (psign-digest-cli)

    /// <summary>Digest algorithm OID used in <c>TimeStampReq</c> for a hash kind (Rust <c>hash_alg_timestamp_oid</c>).</summary>
    public static string HashAlgorithmOid(AuthenticodeHashKind kind) => kind.Oid();

    /// <summary>Lowercase hex of a nonce as it appears in <c>TSTInfo.nonce</c> (Rust <c>rfc3161_nonce_hex</c>).</summary>
    public static string NonceHex(ulong nonce)
    {
        var der = DerIntegerU64(nonce);
        return Hex.Lower(der.AsSpan(2));
    }

    /// <summary>Validate a non-empty even-length hex string (optional <c>0x</c>) and lowercase it (Rust <c>normalize_even_hex</c>).</summary>
    public static string NormalizeEvenHex(string s)
    {
        var t = s.Trim();
        var hex = t.StartsWith("0x", StringComparison.Ordinal) ? t[2..] : t;
        hex = hex.StartsWith("0X", StringComparison.Ordinal) ? hex[2..] : hex;
        if (hex.Length == 0 || hex.Length % 2 != 0)
        {
            throw new PsignException("expected a non-empty even-length hex string");
        }

        if (!hex.All(RustText.IsAsciiHexDigit))
        {
            throw new PsignException("invalid hex");
        }

        return RustText.ToAsciiLowercase(hex);
    }

    /// <summary>Parse a fixed-size hex digest with an optional <c>0x</c>/<c>0X</c> prefix (Rust <c>parse_hex_digest_fixed</c>).</summary>
    public static byte[] ParseHexDigestFixed(string s, int byteLen)
    {
        var t = s.Trim();
        var hex = t.StartsWith("0x", StringComparison.Ordinal) || t.StartsWith("0X", StringComparison.Ordinal) ? t[2..] : t;
        int byteCount = Encoding.UTF8.GetByteCount(hex);
        if (byteCount != byteLen * 2)
        {
            throw new PsignException($"expect {byteLen * 2} hex chars for this digest size, got {byteCount}");
        }

        if (hex.Length != byteCount)
        {
            throw new PsignException("invalid hex");
        }

        var result = new byte[byteLen];
        for (int i = 0; i < byteLen; i++)
        {
            result[i] = RustText.ParseHexPair(hex[2 * i], hex[(2 * i) + 1]) ?? throw new PsignException("invalid hex");
        }

        return result;
    }

    /// <summary>Lowercase hex of the first 16 octets of the token TLV, or <c>-</c> (Rust <c>time_stamp_token_prefix_hex</c>).</summary>
    public static string TimeStampTokenPrefixHex(ReadOnlySpan<byte> tokenTlv, bool present) =>
        present ? Hex.Lower(tokenTlv[..Math.Min(16, tokenTlv.Length)]) : "-";

    /// <summary>
    /// Render the stdout of <c>psign-tool portable rfc3161-timestamp-resp-inspect</c> for <paramref name="respDer"/>
    /// (newline-terminated <c>key=value</c> lines).
    /// </summary>
    public static string FormatTimeStampRespInspection(ReadOnlySpan<byte> respDer, string? expectDigestHex = null, ulong? expectNonce = null)
    {
        string? expectedDigest = null;
        if (expectDigestHex is not null)
        {
            try
            {
                expectedDigest = NormalizeEvenHex(expectDigestHex);
            }
            catch (PsignException e)
            {
                throw new PsignException("parse --expect-digest-hex", e);
            }
        }

        string? expectedNonce = expectNonce is { } n ? NonceHex(n) : null;
        var p = ParseTimeStampRespDer(respDer)
            ?? throw new PsignException("could not parse TimeStampResp DER (definite ASN.1 subset or trailing garbage)");
        var sb = new StringBuilder();
        int tokLen = p.TimeStampToken?.Length ?? 0;
        sb.Append($"pki_status={p.PkiStatus.Label} pki_status_int={p.PkiStatus.AsRawInteger()} granted={(p.PkiStatus.Granted ? "yes" : "no")} time_stamp_token_len={tokLen}\n");
        sb.Append($"time_stamp_token_prefix_hex={TimeStampTokenPrefixHex(p.TimeStampToken, p.TimeStampToken is not null)}\n");
        sb.Append($"status_strings_json={RustText.JsonStringArray(p.StatusStrings)}\n");
        sb.Append($"fail_info_tlv_hex={(p.FailInfoTlv is null ? "-" : Hex.Lower(p.FailInfoTlv))}\n");
        string flagsJson;
        if (p.FailInfoTlv is null)
        {
            flagsJson = "[]";
        }
        else
        {
            var labels = PkiFailureInfoFlagLabelsFromBitStringTlv(p.FailInfoTlv);
            flagsJson = labels is null ? "null" : RustText.JsonStringArray(labels);
        }

        sb.Append($"fail_info_flags_json={flagsJson}\n");
        var tst = p.TimeStampToken is null ? null : ParseTimeStampTokenTstInfo(p.TimeStampToken);
        if (tst is not null)
        {
            sb.Append("tst_info_present=yes\n");
            sb.Append($"tst_info_policy_oid={tst.PolicyOid}\n");
            sb.Append($"tst_info_message_imprint_digest_alg_oid={tst.MessageImprintDigestAlgOid}\n");
            sb.Append($"tst_info_message_imprint_hashed_message_hex={Hex.Lower(tst.MessageImprintHashedMessage)}\n");
            sb.Append($"tst_info_serial_hex={tst.SerialNumberHex}\n");
            sb.Append($"tst_info_gen_time={tst.GenTime}\n");
            sb.Append($"tst_info_nonce_hex={tst.NonceHex ?? "-"}\n");
            if (expectedDigest is not null)
            {
                sb.Append($"tst_info_message_imprint_match={(Hex.Lower(tst.MessageImprintHashedMessage) == expectedDigest ? "yes" : "no")}\n");
            }

            if (expectedNonce is not null)
            {
                sb.Append($"tst_info_nonce_match={(tst.NonceHex == expectedNonce ? "yes" : "no")}\n");
            }
        }
        else
        {
            sb.Append("tst_info_present=no\n");
            if (expectedDigest is not null)
            {
                sb.Append("tst_info_message_imprint_match=no\n");
            }

            if (expectedNonce is not null)
            {
                sb.Append("tst_info_nonce_match=no\n");
            }
        }

        return sb.ToString();
    }
}
