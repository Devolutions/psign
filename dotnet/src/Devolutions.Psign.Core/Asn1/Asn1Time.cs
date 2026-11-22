using System.Formats.Asn1;

namespace Devolutions.Psign.Core.Asn1;

/// <summary>UTCTime / GeneralizedTime helpers.</summary>
public static class Asn1Time
{
    /// <summary>Decode a UTCTime (0x17) or GeneralizedTime (0x18) TLV.</summary>
    public static DateTimeOffset Decode(ReadOnlySpan<byte> tlv)
    {
        if (tlv.IsEmpty)
        {
            throw new PsignException("time: empty");
        }

        try
        {
            var r = new AsnReader(tlv.ToArray(), AsnEncodingRules.BER);
            return tlv[0] switch
            {
                0x17 => r.ReadUtcTime(twoDigitYearMax: 2049),
                0x18 => r.ReadGeneralizedTime(),
                _ => throw new PsignException($"time: unexpected tag 0x{tlv[0]:x2}"),
            };
        }
        catch (AsnContentException e)
        {
            throw new PsignException($"time: {e.Message}", e);
        }
    }

    /// <summary>
    /// Encode a time as RFC 5280 / CMS <c>Time</c>: UTCTime for years 1950..2049, otherwise GeneralizedTime (whole seconds).
    /// </summary>
    public static byte[] EncodeTime(DateTimeOffset time)
    {
        var t = time.ToUniversalTime();
        t = new DateTimeOffset(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, TimeSpan.Zero);
        var w = new AsnWriter(AsnEncodingRules.DER);
        if (t.Year is >= 1950 and <= 2049)
        {
            w.WriteUtcTime(t, twoDigitYearMax: 2049);
        }
        else
        {
            w.WriteGeneralizedTime(t, omitFractionalSeconds: true);
        }

        return w.Encode();
    }

    /// <summary>Encode a GeneralizedTime (whole seconds).</summary>
    public static byte[] EncodeGeneralizedTime(DateTimeOffset time)
    {
        var t = time.ToUniversalTime();
        t = new DateTimeOffset(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, TimeSpan.Zero);
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteGeneralizedTime(t, omitFractionalSeconds: true);
        return w.Encode();
    }

    /// <summary>RFC 3339 rendering with a trailing <c>Z</c> (seconds precision), e.g. <c>2024-01-02T03:04:05Z</c>.</summary>
    public static string Rfc3339(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
}
