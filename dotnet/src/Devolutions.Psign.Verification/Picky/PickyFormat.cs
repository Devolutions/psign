using System.Globalization;
using System.Text;
using Devolutions.Psign.Core.Asn1;

namespace Devolutions.Psign.Verification.Picky;

/// <summary>
/// Renders values the way the Rust <c>picky</c> / <c>picky-asn1-x509</c> crates print them in error messages, so that
/// error text produced by the C# port matches the Rust tool.
/// </summary>
internal static class PickyFormat
{
    /// <summary><c>picky::x509::date::UtcDate</c> <c>Display</c>: <c>YYYY-MM-DD HH:MM:SS</c>.</summary>
    public static string Date(DateTimeOffset d) =>
        d.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    /// <summary>Truncate to whole seconds in UTC (picky <c>UtcDate</c> precision).</summary>
    public static DateTimeOffset Truncate(DateTimeOffset d)
    {
        var u = d.ToUniversalTime();
        return new DateTimeOffset(u.Year, u.Month, u.Day, u.Hour, u.Minute, u.Second, TimeSpan.Zero);
    }

    /// <summary>picky <c>UtcDate::now()</c>.</summary>
    public static DateTimeOffset Now() => Truncate(DateTimeOffset.UtcNow);

    /// <summary>Rust <c>{:?}</c> of a <c>Vec&lt;u8&gt;</c>: <c>[1, 2, 3]</c>.</summary>
    public static string ByteVecDebug(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder("[");
        for (int i = 0; i < bytes.Length; i++)
        {
            if (i > 0)
            {
                sb.Append(", ");
            }

            sb.Append(bytes[i].ToString(CultureInfo.InvariantCulture));
        }

        return sb.Append(']').ToString();
    }

    /// <summary>Rust <c>{:#?}</c> of a <c>Vec&lt;u8&gt;</c>.</summary>
    public static string ByteVecPrettyDebug(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return "[]";
        }

        var sb = new StringBuilder("[\n");
        foreach (var b in bytes)
        {
            sb.Append("    ").Append(b.ToString(CultureInfo.InvariantCulture)).Append(",\n");
        }

        return sb.Append(']').ToString();
    }

    /// <summary>Rust <c>str</c> <c>Debug</c> (quoted with escapes).</summary>
    public static string StrDebug(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var rune in s.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                case 0:
                    sb.Append("\\0");
                    break;
                default:
                    if (Rune.IsControl(rune))
                    {
                        sb.Append("\\u{").Append(rune.Value.ToString("x", CultureInfo.InvariantCulture)).Append('}');
                    }
                    else
                    {
                        sb.Append(rune.ToString());
                    }

                    break;
            }
        }

        return sb.Append('"').ToString();
    }

    /// <summary>Lossy UTF-8 decode (Rust <c>String::from_utf8_lossy</c>).</summary>
    public static string Utf8Lossy(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);

    private static bool IsValidUtf8(ReadOnlySpan<byte> bytes)
    {
        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static string RestrictedDebug(string name, ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder(name).Append('(');
        if (IsValidUtf8(data))
        {
            sb.Append(StrDebug(Encoding.UTF8.GetString(data)));
        }
        else
        {
            sb.Append("0x").Append(Convert.ToHexString(data));
        }

        return sb.Append(')').ToString();
    }

    private static string Utf16BeLossy(ReadOnlySpan<byte> data)
    {
        var chars = new char[data.Length / 2];
        for (int i = 0; i < chars.Length; i++)
        {
            chars[i] = (char)((data[2 * i] << 8) | data[(2 * i) + 1]);
        }

        // Replace unpaired surrogates like String::from_utf16_lossy.
        var sb = new StringBuilder(chars.Length);
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (char.IsHighSurrogate(c) && i + 1 < chars.Length && char.IsLowSurrogate(chars[i + 1]))
            {
                sb.Append(c).Append(chars[i + 1]);
                i++;
            }
            else if (char.IsSurrogate(c))
            {
                sb.Append('�');
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    private static readonly Dictionary<string, (string Display, string Variant)> KnownAttributes = new()
    {
        ["2.5.4.3"] = ("CN", "CommonName"),
        ["2.5.4.4"] = ("SURNAME", "Surname"),
        ["2.5.4.5"] = ("SN", "SerialNumber"),
        ["2.5.4.6"] = ("C", "CountryName"),
        ["2.5.4.7"] = ("L", "LocalityName"),
        ["2.5.4.8"] = ("ST", "StateOrProvinceName"),
        ["2.5.4.9"] = ("STREET NAME", "StreetName"),
        ["2.5.4.10"] = ("O", "OrganizationName"),
        ["2.5.4.11"] = ("OU", "OrganizationalUnitName"),
        ["1.2.840.113549.1.9.1"] = ("EMAIL", "EmailAddress"),
        ["2.5.4.42"] = ("GIVENNAME", "GivenName"),
        ["2.5.4.20"] = ("PHONE", "Phone"),
    };

    private readonly record struct NameAttr(byte[] OidTlv, string Oid, byte[] ValueTlv);

    private static List<List<NameAttr>> ParseName(ReadOnlySpan<byte> nameDer)
    {
        var result = new List<List<NameAttr>>();
        var outer = Der.First(nameDer);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            return result;
        }

        foreach (var rdn in Der.Children(nameDer, outer.Value) ?? [])
        {
            var set = new List<NameAttr>();
            foreach (var atv in Der.Children(nameDer, rdn) ?? [])
            {
                var parts = Der.Children(nameDer, atv);
                if (parts is not { Count: >= 2 } || parts[0].Tag != 0x06)
                {
                    continue;
                }

                var oidTlv = parts[0].Encoded(nameDer).ToArray();
                set.Add(new NameAttr(oidTlv, Der.DecodeOid(oidTlv) ?? string.Empty, parts[1].Encoded(nameDer).ToArray()));
            }

            result.Add(set);
        }

        return result;
    }

    private static string DirectoryStringDisplay(byte[] valueTlv)
    {
        var t = Der.First(valueTlv);
        if (t is null)
        {
            return string.Empty;
        }

        var v = t.Value.Value(valueTlv);
        return t.Value.Tag == 0x1E ? Utf16BeLossy(v) : Utf8Lossy(v);
    }

    private static string DirectoryStringDebug(byte[] valueTlv)
    {
        var t = Der.First(valueTlv);
        if (t is null)
        {
            return "Utf8String(\"\")";
        }

        var v = t.Value.Value(valueTlv);
        return t.Value.Tag switch
        {
            0x13 => $"PrintableString(PrintableStringAsn1({RestrictedDebug("PRINTABLE", v)}))",
            0x1E => $"BmpString(BmpStringAsn1({RestrictedDebug("BMP", v)}))",
            _ => $"Utf8String({StrDebug(Utf8Lossy(v))})",
        };
    }

    /// <summary>picky <c>DirectoryName</c> <c>Display</c> (<c>NamePrettyFormatter</c>): <c>CN=a,O=b</c>.</summary>
    public static string NameDisplay(ReadOnlySpan<byte> nameDer)
    {
        var sb = new StringBuilder();
        bool first = true;
        foreach (var set in ParseName(nameDer))
        {
            foreach (var attr in set)
            {
                if (!first)
                {
                    sb.Append(',');
                }

                first = false;
                if (KnownAttributes.TryGetValue(attr.Oid, out var known))
                {
                    if (attr.Oid == "1.2.840.113549.1.9.1")
                    {
                        var t = Der.First(attr.ValueTlv);
                        sb.Append("EMAIL=").Append(t is null ? string.Empty : Utf8Lossy(t.Value.Value(attr.ValueTlv)));
                    }
                    else
                    {
                        sb.Append(known.Display).Append('=').Append(DirectoryStringDisplay(attr.ValueTlv));
                    }
                }
                else
                {
                    sb.Append(attr.Oid).Append("=RawDer(0x").Append(Convert.ToHexString(attr.ValueTlv)).Append(')');
                }
            }
        }

        return sb.ToString();
    }

    private static string OidDebug(byte[] oidTlv)
    {
        var t = Der.First(oidTlv);
        if (t is null)
        {
            return "ObjectIdentifierAsn1(ObjectIdentifier { root: ItuT, first_node: 0, child_nodes: [] })";
        }

        var arcs = new List<ulong>();
        ulong cur = 0;
        foreach (var b in t.Value.Value(oidTlv))
        {
            cur = (cur << 7) | (uint)(b & 0x7F);
            if ((b & 0x80) == 0)
            {
                arcs.Add(cur);
                cur = 0;
            }
        }

        if (arcs.Count == 0)
        {
            arcs.Add(0);
        }

        ulong firstSub = arcs[0];
        string root;
        ulong firstNode;
        if (firstSub < 40)
        {
            root = "ItuT";
            firstNode = firstSub;
        }
        else if (firstSub < 80)
        {
            root = "Iso";
            firstNode = firstSub - 40;
        }
        else
        {
            root = "JointIsoItuT";
            firstNode = firstSub - 80;
        }

        var children = string.Join(", ", arcs.Skip(1).Select(a => a.ToString(CultureInfo.InvariantCulture)));
        return $"ObjectIdentifierAsn1(ObjectIdentifier {{ root: {root}, first_node: {firstNode.ToString(CultureInfo.InvariantCulture)}, child_nodes: [{children}] }})";
    }

    /// <summary>picky <c>DirectoryName</c> <c>Debug</c> (derived), as printed by <c>{:?}</c>.</summary>
    public static string NameDebug(ReadOnlySpan<byte> nameDer)
    {
        var sets = ParseName(nameDer).Select(set =>
        {
            var attrs = set.Select(attr =>
            {
                string value;
                if (KnownAttributes.TryGetValue(attr.Oid, out var known))
                {
                    if (attr.Oid == "1.2.840.113549.1.9.1")
                    {
                        var t = Der.First(attr.ValueTlv);
                        var data = t is null ? [] : t.Value.Value(attr.ValueTlv).ToArray();
                        value = $"EmailAddress(Ia5StringAsn1({RestrictedDebug("IA5", data)}))";
                    }
                    else
                    {
                        value = $"{known.Variant}({DirectoryStringDebug(attr.ValueTlv)})";
                    }
                }
                else
                {
                    value = $"Custom(RawDer(0x{Convert.ToHexString(attr.ValueTlv)}))";
                }

                return $"AttributeTypeAndValue {{ ty: {OidDebug(attr.OidTlv)}, value: {value} }}";
            });
            return $"Asn1SetOf([{string.Join(", ", attrs)}])";
        });
        return $"DirectoryName(Name(Asn1SequenceOf([{string.Join(", ", sets)}])))";
    }
}
