namespace Devolutions.Psign.Core;

/// <summary>Lowercase hexadecimal helpers matching the Rust <c>hex_lower</c> conventions.</summary>
public static class Hex
{
    /// <summary>Encode bytes as lowercase hexadecimal.</summary>
    public static string Lower(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    /// <summary>Encode bytes as uppercase hexadecimal.</summary>
    public static string Upper(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);

    /// <summary>
    /// Decode hexadecimal text. Whitespace and an optional <c>0x</c> prefix are ignored; colons are accepted as separators.
    /// </summary>
    public static byte[] Decode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var s = text.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            s = s[2..];
        }

        Span<char> buffer = s.Length <= 1024 ? stackalloc char[s.Length] : new char[s.Length];
        int n = 0;
        foreach (char c in s)
        {
            if (char.IsWhiteSpace(c) || c == ':')
            {
                continue;
            }

            buffer[n++] = c;
        }

        if (n % 2 != 0)
        {
            throw new FormatException("hex string has an odd number of digits");
        }

        try
        {
            return Convert.FromHexString(buffer[..n]);
        }
        catch (FormatException e)
        {
            throw new FormatException($"invalid hex string: {e.Message}", e);
        }
    }

    /// <summary>Try to decode hexadecimal text (see <see cref="Decode"/>).</summary>
    public static bool TryDecode(string text, out byte[] bytes)
    {
        try
        {
            bytes = Decode(text);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
