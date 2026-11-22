using System.Text;

namespace Devolutions.Psign.Core.Text;

/// <summary>
/// String helpers that reproduce Rust <c>std</c> text semantics where they differ from the BCL defaults
/// (<c>str::lines</c>, <c>String::from_utf8_lossy</c>, <c>String::from_utf16_lossy</c>, <c>eq_ignore_ascii_case</c>, ...).
/// </summary>
public static class RustText
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// Rust <c>str::lines</c>: split on <c>\n</c>, strip one trailing <c>\r</c> from lines terminated by <c>\n</c>, and
    /// omit the empty remainder after a final line terminator. A bare trailing <c>\r</c> on the last unterminated line is
    /// kept.
    /// </summary>
    public static IEnumerable<string> Lines(string text)
    {
        int start = 0;
        while (start < text.Length)
        {
            int nl = text.IndexOf('\n', start);
            if (nl < 0)
            {
                yield return text[start..];
                yield break;
            }

            int end = nl;
            if (end > start && text[end - 1] == '\r')
            {
                end--;
            }

            yield return text[start..end];
            start = nl + 1;
        }
    }

    /// <summary>Rust <c>String::from_utf8_lossy</c> (invalid sequences become U+FFFD; a UTF-8 BOM is preserved as U+FEFF).</summary>
    public static string FromUtf8Lossy(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);

    /// <summary>Rust <c>std::str::from_utf8</c>: strict UTF-8 decoding, or <c>null</c> when the input is not valid UTF-8.</summary>
    public static string? TryFromUtf8(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>Strict UTF-8 decoding that throws <see cref="PsignException"/> with <paramref name="context"/> on failure.</summary>
    public static string FromUtf8Strict(ReadOnlySpan<byte> bytes, string context)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException(context, e);
        }
    }

    /// <summary>Rust <c>String::from_utf16_lossy</c>: unpaired surrogates become U+FFFD.</summary>
    public static string FromUtf16Lossy(ReadOnlySpan<char> units)
    {
        var sb = new StringBuilder(units.Length);
        for (int i = 0; i < units.Length; i++)
        {
            char c = units[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < units.Length && char.IsLowSurrogate(units[i + 1]))
                {
                    sb.Append(c).Append(units[i + 1]);
                    i++;
                }
                else
                {
                    sb.Append('�');
                }
            }
            else if (char.IsLowSurrogate(c))
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

    /// <summary>Decode little-endian UTF-16 code units (an odd trailing byte is ignored, like Rust <c>as_chunks::&lt;2&gt;</c>).</summary>
    public static char[] Utf16LeUnits(ReadOnlySpan<byte> bytes)
    {
        var units = new char[bytes.Length / 2];
        for (int i = 0; i < units.Length; i++)
        {
            units[i] = (char)(bytes[2 * i] | (bytes[(2 * i) + 1] << 8));
        }

        return units;
    }

    /// <summary>Decode big-endian UTF-16 code units (an odd trailing byte is ignored).</summary>
    public static char[] Utf16BeUnits(ReadOnlySpan<byte> bytes)
    {
        var units = new char[bytes.Length / 2];
        for (int i = 0; i < units.Length; i++)
        {
            units[i] = (char)((bytes[2 * i] << 8) | bytes[(2 * i) + 1]);
        }

        return units;
    }

    /// <summary>Encode UTF-16 code units as little-endian bytes.</summary>
    public static byte[] Utf16LeBytes(ReadOnlySpan<char> units)
    {
        var bytes = new byte[units.Length * 2];
        for (int i = 0; i < units.Length; i++)
        {
            bytes[2 * i] = (byte)units[i];
            bytes[(2 * i) + 1] = (byte)(units[i] >> 8);
        }

        return bytes;
    }

    /// <summary>Encode UTF-16 code units as big-endian bytes.</summary>
    public static byte[] Utf16BeBytes(ReadOnlySpan<char> units)
    {
        var bytes = new byte[units.Length * 2];
        for (int i = 0; i < units.Length; i++)
        {
            bytes[2 * i] = (byte)(units[i] >> 8);
            bytes[(2 * i) + 1] = (byte)units[i];
        }

        return bytes;
    }

    /// <summary>Rust <c>str::eq_ignore_ascii_case</c> (only ASCII letters are case-folded).</summary>
    public static bool EqualsIgnoreAsciiCase(string a, string b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (int i = 0; i < a.Length; i++)
        {
            if (ToAsciiLower(a[i]) != ToAsciiLower(b[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Rust <c>str::to_ascii_lowercase</c>.</summary>
    public static string ToAsciiLowercase(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            chars[i] = ToAsciiLower(chars[i]);
        }

        return new string(chars);
    }

    /// <summary>ASCII-only lower-casing of one character.</summary>
    public static char ToAsciiLower(char c) => c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;

    /// <summary>Rust <c>u8::is_ascii_hexdigit</c> for a UTF-16 code unit.</summary>
    public static bool IsAsciiHexDigit(char c) => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

    /// <summary>
    /// Rust <c>u8::from_str_radix(pair, 16)</c> for a two-character pair (a leading <c>+</c> sign is accepted), or
    /// <c>null</c> when invalid.
    /// </summary>
    public static byte? ParseHexPair(char a, char b)
    {
        static int Nibble(char c) => c switch
        {
            >= '0' and <= '9' => c - '0',
            >= 'a' and <= 'f' => c - 'a' + 10,
            >= 'A' and <= 'F' => c - 'A' + 10,
            _ => -1,
        };

        int lo = Nibble(b);
        if (lo < 0)
        {
            return null;
        }

        if (a == '+')
        {
            return (byte)lo;
        }

        int hi = Nibble(a);
        return hi < 0 ? null : (byte)((hi << 4) | lo);
    }

    /// <summary>Rust <c>char::is_ascii_alphanumeric</c>.</summary>
    public static bool IsAsciiAlphanumeric(char c) => c is (>= '0' and <= '9') or (>= 'a' and <= 'z') or (>= 'A' and <= 'Z');

    /// <summary>Index of <paramref name="needle"/> in <paramref name="haystack"/> (Rust <c>windows().position()</c>), or -1.</summary>
    public static int IndexOf(ReadOnlySpan<char> haystack, ReadOnlySpan<char> needle)
    {
        if (needle.IsEmpty || needle.Length > haystack.Length)
        {
            return -1;
        }

        return haystack.IndexOf(needle);
    }

    /// <summary>Last index of <paramref name="needle"/> in <paramref name="haystack"/>, or -1.</summary>
    public static int LastIndexOf(ReadOnlySpan<char> haystack, ReadOnlySpan<char> needle)
    {
        if (needle.IsEmpty || needle.Length > haystack.Length)
        {
            return -1;
        }

        return haystack.LastIndexOf(needle);
    }

    /// <summary>
    /// Encode a string as a JSON string literal the way <c>serde_json</c> does: escape <c>"</c>, <c>\</c>, and control
    /// characters (<c>\b \f \n \r \t</c> short forms, others as <c>\u00XX</c>); non-ASCII is emitted verbatim.
    /// </summary>
    public static string JsonString(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
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
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u00").Append(((int)c).ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        sb.Append('"');
        return sb.ToString();
    }

    /// <summary>Encode a list of strings as a compact JSON array (<c>serde_json::to_string(&amp;Vec&lt;String&gt;)</c>).</summary>
    public static string JsonStringArray(IEnumerable<string> values) => "[" + string.Join(",", values.Select(JsonString)) + "]";
}
