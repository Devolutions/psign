using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;

namespace Devolutions.Psign.Signing.Pki;

/// <summary>One <c>AttributeTypeAndValue</c> of an X.500 name (value kept as its full DER TLV).</summary>
public sealed record X500Attribute(string Oid, byte[] ValueTlv)
{
    /// <summary>Encoded <c>AttributeTypeAndValue</c> SEQUENCE.</summary>
    public byte[] Encode() => Der.EncodeSequence(Der.EncodeOid(Oid), ValueTlv);
}

/// <summary>
/// X.500 distinguished-name parsing and formatting (port of the DN helpers in Rust <c>test_pki.rs</c> plus the
/// <c>x509-cert</c> RFC 4514 <c>Display</c> used by the portable cert store).
/// </summary>
public static partial class DistinguishedName
{
    internal const string OidCommonName = "2.5.4.3";
    internal const string OidSurname = "2.5.4.4";
    internal const string OidSerialNumber = "2.5.4.5";
    internal const string OidCountryName = "2.5.4.6";
    internal const string OidLocalityName = "2.5.4.7";
    internal const string OidStateOrProvinceName = "2.5.4.8";
    internal const string OidStreetAddress = "2.5.4.9";
    internal const string OidOrganizationName = "2.5.4.10";
    internal const string OidOrganizationalUnitName = "2.5.4.11";
    internal const string OidTitle = "2.5.4.12";
    internal const string OidGivenName = "2.5.4.42";
    internal const string OidEmailAddress = "1.2.840.113549.1.9.1";
    internal const string OidUserId = "0.9.2342.19200300.100.1.1";
    internal const string OidDomainComponent = "0.9.2342.19200300.100.1.25";

    private const byte TagUtf8String = 0x0C;
    private const byte TagPrintableString = 0x13;
    private const byte TagTeletexString = 0x14;
    private const byte TagIa5String = 0x16;
    private const byte TagBmpString = 0x1E;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Parse a Windows <c>X500DistinguishedName</c> or RFC 4514 distinguished name string into DER <c>Name</c>
    /// (<c>RDNSequence</c>) bytes (Rust <c>parse_distinguished_name</c>). The RDN list is reversed so the most-specific
    /// component written first (<c>CN</c>) ends up last in ASN.1 order.
    /// </summary>
    public static byte[] Parse(string input) => Encode(ParseRdns(input));

    /// <summary>Parse into RDNs in ASN.1 order (each RDN's attributes DER-sorted like a <c>SET OF</c>).</summary>
    public static List<List<X500Attribute>> ParseRdns(string input)
    {
        var trimmed = TrimUnescapedSpaces(input);
        if (trimmed.Length == 0)
        {
            throw new PsignException("distinguished name must not be empty");
        }

        var rdns = new List<List<X500Attribute>>();
        foreach (var rawToken in SplitUnescaped(trimmed, ','))
        {
            var token = TrimUnescapedSpaces(rawToken);
            if (token.Length == 0)
            {
                throw new PsignException($"distinguished name '{input}' contains an empty RDN component");
            }

            var atvs = SplitUnescaped(token, '+').Select(a => ParseAtv(TrimUnescapedSpaces(a))).ToList();
            atvs.Sort((a, b) => Der.CompareDer(a.Encode(), b.Encode()));
            rdns.Add(atvs);
        }

        rdns.Reverse();
        return rdns;
    }

    /// <summary>Encode RDNs (ASN.1 order) as a DER <c>Name</c>.</summary>
    public static byte[] Encode(IEnumerable<IReadOnlyList<X500Attribute>> rdns) =>
        Der.EncodeTlv(0x30, rdns.Select(rdn => Der.EncodeSetOf(0x31, rdn.Select(a => a.Encode()))).ToArray());

    /// <summary>Decode a DER <c>Name</c> into RDNs (ASN.1 order).</summary>
    public static List<List<X500Attribute>> Decode(ReadOnlySpan<byte> nameDer)
    {
        var outer = Der.First(nameDer);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            throw new PsignException("X.500 Name: expected SEQUENCE");
        }

        var result = new List<List<X500Attribute>>();
        foreach (var set in Der.Children(nameDer, outer.Value) ?? throw new PsignException("X.500 Name: malformed RDNSequence"))
        {
            if (set.Tag != 0x31)
            {
                throw new PsignException("X.500 Name: expected RDN SET");
            }

            var rdn = new List<X500Attribute>();
            foreach (var atv in Der.Children(nameDer, set) ?? throw new PsignException("X.500 Name: malformed RDN"))
            {
                var parts = Der.Children(nameDer, atv);
                if (parts is not { Count: 2 } || parts[0].Tag != 0x06)
                {
                    throw new PsignException("X.500 Name: malformed AttributeTypeAndValue");
                }

                var oid = Der.DecodeOid(parts[0].Encoded(nameDer)) ?? throw new PsignException("X.500 Name: bad attribute OID");
                rdn.Add(new X500Attribute(oid, parts[1].Encoded(nameDer).ToArray()));
            }

            result.Add(rdn);
        }

        return result;
    }

    /// <summary>
    /// Format a DER <c>Name</c> in Windows <c>X500DistinguishedName</c> order (<c>CN=..., O=..., S=..., C=...</c>), matching
    /// <c>X509Certificate2.Subject</c> and MSIX <c>Identity/@Publisher</c> (Rust <c>format_windows_dn</c>).
    /// </summary>
    public static string FormatWindows(ReadOnlySpan<byte> nameDer)
    {
        var rdns = Decode(nameDer);
        var parts = new List<string>(rdns.Count);
        for (var i = rdns.Count - 1; i >= 0; i--)
        {
            parts.Add(string.Join(" + ", rdns[i].Select(FormatWindowsAtv)));
        }

        return string.Join(", ", parts);
    }

    /// <summary>
    /// Format a DER <c>Name</c> as RFC 4514 text like Rust <c>x509_cert::name::RdnSequence</c> <c>Display</c>
    /// (<c>CN=leaf,O=Example,C=CA</c>), used by the portable cert store reports.
    /// </summary>
    public static string FormatRfc4514(ReadOnlySpan<byte> nameDer)
    {
        var rdns = Decode(nameDer);
        var sb = new StringBuilder();
        for (var i = rdns.Count - 1; i >= 0; i--)
        {
            if (sb.Length > 0 || i != rdns.Count - 1)
            {
                sb.Append(',');
            }

            for (var j = 0; j < rdns[i].Count; j++)
            {
                if (j > 0)
                {
                    sb.Append('+');
                }

                AppendRfc4514Atv(sb, rdns[i][j]);
            }
        }

        return sb.ToString();
    }

    /// <summary>Quote a value for Windows DN text (Rust <c>quote_windows_dn_value</c>).</summary>
    public static string QuoteWindowsValue(string value)
    {
        var needsQuotes = value.Length == 0
            || value.StartsWith(' ')
            || value.EndsWith(' ')
            || value.StartsWith('#')
            || value.IndexOfAny([',', '+', '=', '"', '<', '>', ';', '\\', '\r', '\n']) >= 0;
        return needsQuotes ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : value;
    }

    private static string FormatWindowsAtv(X500Attribute atv)
    {
        var key = atv.Oid switch
        {
            OidCommonName => "CN",
            OidOrganizationName => "O",
            OidOrganizationalUnitName => "OU",
            OidLocalityName => "L",
            OidStateOrProvinceName => "S",
            OidCountryName => "C",
            OidStreetAddress => "STREET",
            OidEmailAddress => "E",
            OidDomainComponent => "DC",
            OidSerialNumber => "SERIALNUMBER",
            OidUserId => "UID",
            OidTitle => "T",
            OidGivenName => "G",
            OidSurname => "SN",
            var other => "OID." + other,
        };
        var decoded = DecodeStringValue(atv.ValueTlv, allowBmp: true);
        return decoded is null ? key + "=#" + Hex.Upper(atv.ValueTlv) : key + "=" + QuoteWindowsValue(decoded);
    }

    private static void AppendRfc4514Atv(StringBuilder sb, X500Attribute atv)
    {
        var value = DecodeStringValue(atv.ValueTlv, allowBmp: false);
        if (value is not null && ShortestOidNames.TryGetValue(atv.Oid, out var key))
        {
            sb.Append(key).Append('=');
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];
                var last = i == value.Length - 1;
                switch (c)
                {
                    case '#' when i == 0:
                        sb.Append("\\#");
                        break;
                    case ' ' when i == 0 || last:
                        sb.Append("\\ ");
                        break;
                    case '"' or '+' or ',' or ';' or '<' or '>' or '\\':
                        sb.Append('\\').Append(c);
                        break;
                    case <= '\x1f' or '\x7f':
                        sb.Append('\\').Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                        break;
                    default:
                        sb.Append(c);
                        break;
                }
            }
        }
        else
        {
            sb.Append(atv.Oid).Append("=#").Append(Hex.Lower(atv.ValueTlv));
        }
    }

    private static string? DecodeStringValue(byte[] tlv, bool allowBmp)
    {
        var t = Der.First(tlv);
        if (t is null)
        {
            return null;
        }

        var content = t.Value.Value(tlv);
        switch (t.Value.Tag)
        {
            case TagPrintableString:
                return IsPrintable(content) ? Encoding.ASCII.GetString(content) : null;
            case TagUtf8String:
                try
                {
                    return StrictUtf8.GetString(content);
                }
                catch (DecoderFallbackException)
                {
                    return null;
                }

            case TagIa5String:
            case TagTeletexString:
                foreach (var b in content)
                {
                    if (b > 0x7F)
                    {
                        return null;
                    }
                }

                return Encoding.ASCII.GetString(content);
            case TagBmpString when allowBmp:
                {
                    if (content.Length % 2 != 0)
                    {
                        return null;
                    }

                    var sb = new StringBuilder(content.Length / 2);
                    for (var i = 0; i < content.Length; i += 2)
                    {
                        var unit = (char)((content[i] << 8) | content[i + 1]);
                        if (char.IsSurrogate(unit))
                        {
                            return null;
                        }

                        sb.Append(unit);
                    }

                    return sb.ToString();
                }

            default:
                return null;
        }
    }

    private static bool IsPrintable(ReadOnlySpan<byte> bytes)
    {
        foreach (var c in bytes)
        {
            var ok = c is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9'
                or (byte)' ' or (byte)'\'' or (byte)'(' or (byte)')' or (byte)'+' or (byte)',' or (byte)'-' or (byte)'.'
                or (byte)'/' or (byte)':' or (byte)'=' or (byte)'?';
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiWhitespace(char c) => c is ' ' or '\t' or '\n' or '\f' or '\r';

    /// <summary>Trim surrounding ASCII whitespace while preserving an RFC 4514 escaped trailing space (<c>\ </c>).</summary>
    private static string TrimUnescapedSpaces(string raw)
    {
        var start = 0;
        var end = raw.Length;
        while (start < end && IsAsciiWhitespace(raw[start]))
        {
            start++;
        }

        while (end > start && IsAsciiWhitespace(raw[end - 1]))
        {
            var backslashes = 0;
            for (var k = end - 2; k >= start && raw[k] == '\\'; k--)
            {
                backslashes++;
            }

            if (raw[end - 1] == ' ' && backslashes % 2 == 1)
            {
                break;
            }

            end--;
        }

        return raw[start..end];
    }

    private static List<string> SplitUnescaped(string input, char delimiter)
    {
        var parts = new List<string>();
        var start = 0;
        var inQuotes = false;
        var escaped = false;
        for (var idx = 0; idx < input.Length; idx++)
        {
            var ch = input[idx];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (ch == '\\' && !inQuotes)
            {
                escaped = true;
                continue;
            }

            if (ch == '"')
            {
                if (inQuotes && idx + 1 < input.Length && input[idx + 1] == '"')
                {
                    idx++;
                    continue;
                }

                inQuotes = !inQuotes;
                continue;
            }

            if (ch == delimiter && !inQuotes)
            {
                parts.Add(input[start..idx]);
                start = idx + 1;
            }
        }

        if (inQuotes)
        {
            throw new PsignException($"unterminated double quote in distinguished name '{input}'");
        }

        if (escaped)
        {
            throw new PsignException($"trailing backslash escape in distinguished name '{input}'");
        }

        parts.Add(input[start..]);
        return parts;
    }

    private static X500Attribute ParseAtv(string token)
    {
        var eq = token.IndexOf('=');
        if (eq < 0)
        {
            throw new PsignException($"distinguished name component '{token}' must be in KEY=VALUE form (for example, CN=Example)");
        }

        var key = token[..eq].Trim();
        if (key.Length == 0)
        {
            throw new PsignException($"distinguished name component '{token}' has an empty attribute name");
        }

        var oid = ResolveAttributeOid(key);
        var valTrimmed = TrimUnescapedSpaces(token[(eq + 1)..]);
        if (valTrimmed.StartsWith('#'))
        {
            byte[] rawDer;
            try
            {
                rawDer = DecodeHex(valTrimmed[1..]);
            }
            catch (PsignException e)
            {
                throw new PsignException($"decode hex DER value in RDN '{token}'", e);
            }

            var t = Der.First(rawDer);
            if (t is null || t.Value.End != rawDer.Length)
            {
                throw new PsignException($"decode DER value in RDN '{token}': malformed DER");
            }

            return new X500Attribute(oid, rawDer);
        }

        var unescaped = UnescapeValue(valTrimmed);
        byte[] value;
        if (oid == OidCountryName)
        {
            if (unescaped.Length != 2)
            {
                throw new PsignException($"RDN '{key}' must be a 2-character ISO 3166 country code, got '{unescaped}'");
            }

            value = Printable(key, unescaped);
        }
        else if (oid == OidSerialNumber)
        {
            if (unescaped.Length == 0)
            {
                throw new PsignException($"RDN '{key}' must not be empty");
            }

            value = Printable(key, unescaped);
        }
        else if (oid is OidDomainComponent or OidEmailAddress)
        {
            if (unescaped.Length == 0)
            {
                throw new PsignException($"RDN '{key}' must not be empty");
            }

            if (unescaped.Any(c => c > 0x7F))
            {
                throw new PsignException($"RDN '{key}' must be ASCII IA5String: malformed ASN.1 DER value for IA5String");
            }

            value = Der.EncodeTlv(TagIa5String, Encoding.ASCII.GetBytes(unescaped));
        }
        else
        {
            value = Der.EncodeTlv(TagUtf8String, Encoding.UTF8.GetBytes(unescaped));
        }

        return new X500Attribute(oid, value);
    }

    private static byte[] Printable(string key, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        if (!IsPrintable(bytes))
        {
            throw new PsignException($"RDN '{key}' must be PrintableString: malformed ASN.1 DER value for PrintableString");
        }

        return Der.EncodeTlv(TagPrintableString, bytes);
    }

    private static string ResolveAttributeOid(string key)
    {
        var upper = key.ToUpperInvariant();
        switch (upper)
        {
            case "CN" or "COMMONNAME":
                return OidCommonName;
            case "O" or "ORG" or "ORGANIZATION" or "ORGANIZATIONNAME":
                return OidOrganizationName;
            case "OU" or "ORGANIZATIONALUNIT" or "ORGANIZATIONALUNITNAME":
                return OidOrganizationalUnitName;
            case "L" or "LOCALITY" or "LOCALITYNAME":
                return OidLocalityName;
            case "S" or "ST" or "STATE" or "PROVINCE" or "STATEORPROVINCENAME":
                return OidStateOrProvinceName;
            case "C" or "COUNTRY" or "COUNTRYNAME":
                return OidCountryName;
            case "STREET" or "STREETADDRESS":
                return OidStreetAddress;
            case "E" or "EMAIL" or "EMAILADDRESS":
                return OidEmailAddress;
            case "DC" or "DOMAINCOMPONENT":
                return OidDomainComponent;
            case "SERIALNUMBER":
                return OidSerialNumber;
            case "UID" or "USERID":
                return OidUserId;
            case "T" or "TITLE":
                return OidTitle;
            case "G" or "GN" or "GIVENNAME":
                return OidGivenName;
            case "SN" or "SURNAME":
                return OidSurname;
            default:
                var dotted = upper.StartsWith("OID.", StringComparison.Ordinal) ? upper[4..] : upper;
                if (!IsValidOid(dotted))
                {
                    throw new PsignException($"unsupported X.500 attribute '{key}'");
                }

                return dotted;
        }
    }

    internal static bool IsValidOid(string dotted)
    {
        if (!OidRegex().IsMatch(dotted))
        {
            return false;
        }

        var arcs = dotted.Split('.');
        if (!uint.TryParse(arcs[0], NumberStyles.None, CultureInfo.InvariantCulture, out var first) || first > 2)
        {
            return false;
        }

        if (!ulong.TryParse(arcs[1], NumberStyles.None, CultureInfo.InvariantCulture, out var second))
        {
            return false;
        }

        return first == 2 || second < 40;
    }

    [GeneratedRegex(@"^[0-9]+(\.[0-9]+)+$")]
    private static partial Regex OidRegex();

    private static string UnescapeValue(string raw)
    {
        if (raw.StartsWith('"'))
        {
            if (!raw.EndsWith('"') || raw.Length < 2)
            {
                throw new PsignException($"improperly quoted RDN value '{raw}'");
            }

            var inner = raw[1..^1];
            var sb = new StringBuilder(inner.Length);
            for (var i = 0; i < inner.Length; i++)
            {
                var ch = inner[i];
                if (ch == '"')
                {
                    if (i + 1 < inner.Length && inner[i + 1] == '"')
                    {
                        i++;
                        sb.Append('"');
                    }
                    else
                    {
                        throw new PsignException($"unescaped double quote inside quoted RDN value '{raw}'");
                    }
                }
                else
                {
                    // Inside Windows CERT_X500_NAME_STR quotes, only "" is an escape; \ is literal.
                    sb.Append(ch);
                }
            }

            return sb.ToString();
        }

        var input = Encoding.UTF8.GetBytes(raw);
        var bytes = new List<byte>(input.Length);
        for (var i = 0; i < input.Length; i++)
        {
            var b = input[i];
            if (b == (byte)'"')
            {
                throw new PsignException($"unescaped double quote in RDN value '{raw}'");
            }

            if (b != (byte)'\\')
            {
                bytes.Add(b);
                continue;
            }

            if (++i >= input.Length)
            {
                throw new PsignException($"trailing backslash in RDN value '{raw}'");
            }

            var esc = input[i];
            if (esc is (byte)' ' or (byte)'"' or (byte)'#' or (byte)'+' or (byte)',' or (byte)';' or (byte)'<' or (byte)'=' or (byte)'>' or (byte)'\\')
            {
                bytes.Add(esc);
            }
            else if (Uri.IsHexDigit((char)esc))
            {
                if (++i >= input.Length)
                {
                    throw new PsignException($"incomplete hex escape '\\{(char)esc}' in RDN value '{raw}'; escape literal backslashes as '\\\\' or quote the value");
                }

                var lo = input[i];
                if (!Uri.IsHexDigit((char)lo))
                {
                    throw new PsignException($"invalid hex escape in RDN value '{raw}'");
                }

                bytes.Add((byte)((Uri.FromHex((char)esc) << 4) | Uri.FromHex((char)lo)));
            }
            else
            {
                throw new PsignException($"invalid backslash escape '\\{(char)esc}' in RDN value '{raw}'; escape literal backslashes as '\\\\' or quote the value");
            }
        }

        try
        {
            return StrictUtf8.GetString(bytes.ToArray());
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("RDN value is not valid UTF-8", e);
        }
    }

    private static byte[] DecodeHex(string hex)
    {
        var clean = new string(hex.Where(c => !IsAsciiWhitespace(c)).ToArray());
        if (clean.Length == 0 || clean.Length % 2 != 0)
        {
            throw new PsignException("hex string must have a non-zero even number of hex digits");
        }

        var result = new byte[clean.Length / 2];
        for (var i = 0; i < result.Length; i++)
        {
            var hi = clean[2 * i];
            var lo = clean[(2 * i) + 1];
            if (!Uri.IsHexDigit(hi) || !Uri.IsHexDigit(lo))
            {
                throw new PsignException($"invalid hex digit in '{hex}'");
            }

            result[i] = (byte)((Uri.FromHex(hi) << 4) | Uri.FromHex(lo));
        }

        return result;
    }
}
