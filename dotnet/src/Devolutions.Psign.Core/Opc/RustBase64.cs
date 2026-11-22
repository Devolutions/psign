namespace Devolutions.Psign.Core.Opc;

/// <summary>Base64 codecs matching the Rust implementations used by the package / XMLDSig helpers.</summary>
public static class RustBase64
{
    /// <summary>
    /// Rust <c>base64::engine::general_purpose::STANDARD.decode</c>: canonical padding required, no whitespace, no
    /// non-zero trailing bits. Throws <see cref="FormatException"/> on invalid input.
    /// </summary>
    public static byte[] DecodeStrict(string text)
    {
        if (text.Length % 4 != 0)
        {
            throw new FormatException("Invalid padding");
        }

        int pad = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            bool alpha = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '+' or '/';
            if (alpha)
            {
                if (pad > 0)
                {
                    throw new FormatException($"Invalid symbol {(int)c}, offset {i}.");
                }
            }
            else if (c == '=')
            {
                pad++;
                if (i < text.Length - 2)
                {
                    throw new FormatException($"Invalid symbol {(int)c}, offset {i}.");
                }
            }
            else
            {
                throw new FormatException($"Invalid symbol {(int)c}, offset {i}.");
            }
        }

        var bytes = Convert.FromBase64String(text);
        if (Convert.ToBase64String(bytes) != text)
        {
            throw new FormatException("Invalid last symbol");
        }

        return bytes;
    }

    /// <summary>
    /// Lenient decoder used for ClickOnce XMLDSig values (Rust <c>base64_decode</c> in <c>psign-digest-cli</c>): ASCII
    /// whitespace is skipped, <c>=</c> counts as padding within each 4-character group.
    /// </summary>
    public static byte[] DecodeXmlDsig(string text)
    {
        var output = new List<byte>(text.Length * 3 / 4);
        Span<byte> chunk = stackalloc byte[4];
        int chunkLen = 0;
        int padding = 0;
        foreach (char ch in text)
        {
            if (ch is ' ' or '\t' or '\n' or '\r' or '\f')
            {
                continue;
            }

            byte value;
            if (ch is >= 'A' and <= 'Z')
            {
                value = (byte)(ch - 'A');
            }
            else if (ch is >= 'a' and <= 'z')
            {
                value = (byte)(ch - 'a' + 26);
            }
            else if (ch is >= '0' and <= '9')
            {
                value = (byte)(ch - '0' + 52);
            }
            else if (ch == '+')
            {
                value = 62;
            }
            else if (ch == '/')
            {
                value = 63;
            }
            else if (ch == '=')
            {
                padding++;
                value = 0;
            }
            else
            {
                throw new PsignException("invalid base64 character in XMLDSig value");
            }

            chunk[chunkLen++] = value;
            if (chunkLen == 4)
            {
                output.Add((byte)((chunk[0] << 2) | (chunk[1] >> 4)));
                if (padding < 2)
                {
                    output.Add((byte)((chunk[1] << 4) | (chunk[2] >> 2)));
                }

                if (padding == 0)
                {
                    output.Add((byte)((chunk[2] << 6) | chunk[3]));
                }

                chunkLen = 0;
                padding = 0;
            }
        }

        if (chunkLen != 0)
        {
            throw new PsignException("truncated base64 XMLDSig value");
        }

        return output.ToArray();
    }
}
