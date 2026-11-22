using System.Text;

namespace Devolutions.Psign.Core.Text;

/// <summary>
/// Base64 with the semantics of the Rust <c>base64</c> crate's <c>STANDARD</c> engine (0.22): standard alphabet,
/// canonical padding required, non-zero trailing bits rejected, no whitespace tolerated. Error messages match the crate's
/// <c>DecodeError</c> display text.
/// </summary>
public static class Base64Standard
{
    private const byte Invalid = 0xFF;
    private const byte Pad = (byte)'=';
    private static readonly byte[] DecodeTable = BuildTable();

    /// <summary>Encode with padding.</summary>
    public static string Encode(ReadOnlySpan<byte> data) => Convert.ToBase64String(data);

    /// <summary>Decode the UTF-8 bytes of <paramref name="text"/>; throws <see cref="FormatException"/> with the Rust error text.</summary>
    public static byte[] Decode(string text) => Decode(Encoding.UTF8.GetBytes(text));

    /// <summary>Try to decode; returns <c>null</c> when invalid.</summary>
    public static byte[]? TryDecode(string text)
    {
        try
        {
            return Decode(text);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>Decode ASCII base64 bytes; throws <see cref="FormatException"/> with the Rust error text.</summary>
    public static byte[] Decode(ReadOnlySpan<byte> input)
    {
        int rem = input.Length % 4;
        if (rem == 1)
        {
            byte last = input[^1];
            if (last != Pad && DecodeTable[last] == Invalid)
            {
                throw InvalidByte(input.Length - 1, last);
            }
        }

        int prefixLen = Math.Max(0, input.Length - rem - (rem == 0 ? 4 : 0));
        for (int i = 0; i < prefixLen; i++)
        {
            if (DecodeTable[input[i]] == Invalid)
            {
                throw InvalidByte(i, input[i]);
            }
        }

        // decode_suffix
        int morselsInLeftover = 0;
        int paddingBytes = 0;
        int firstPaddingOffset = 0;
        byte lastSymbol = 0;
        Span<byte> morsels = stackalloc byte[4];
        for (int leftoverIndex = 0; prefixLen + leftoverIndex < input.Length; leftoverIndex++)
        {
            byte b = input[prefixLen + leftoverIndex];
            if (b == Pad)
            {
                if (leftoverIndex < 2)
                {
                    throw InvalidByte(prefixLen + leftoverIndex, b);
                }

                if (paddingBytes == 0)
                {
                    firstPaddingOffset = leftoverIndex;
                }

                paddingBytes++;
                continue;
            }

            if (paddingBytes > 0)
            {
                throw InvalidByte(prefixLen + firstPaddingOffset, Pad);
            }

            lastSymbol = b;
            byte morsel = DecodeTable[b];
            if (morsel == Invalid)
            {
                throw InvalidByte(prefixLen + leftoverIndex, b);
            }

            morsels[morselsInLeftover++] = morsel;
        }

        if (!input.IsEmpty && morselsInLeftover < 2)
        {
            throw new FormatException($"Invalid input length: {prefixLen + morselsInLeftover}");
        }

        if ((paddingBytes + morselsInLeftover) % 4 != 0)
        {
            throw new FormatException("Invalid padding");
        }

        int leftoverBytes = morselsInLeftover * 6 / 8;
        uint leftoverNum = ((uint)morsels[0] << 26) | ((uint)morsels[1] << 20) | ((uint)morsels[2] << 14) | ((uint)morsels[3] << 8);
        uint mask = leftoverBytes >= 4 ? 0 : uint.MaxValue >> (leftoverBytes * 8);
        if ((leftoverNum & mask) != 0)
        {
            throw new FormatException($"Invalid last symbol {lastSymbol}, offset {prefixLen + morselsInLeftover - 1}.");
        }

        // Input is validated; the BCL decoder produces the same bytes.
        return input.IsEmpty ? [] : Convert.FromBase64String(Encoding.ASCII.GetString(input));
    }

    /// <summary>
    /// Lenient decoder used for ClickOnce XMLDSig values (Rust <c>base64_decode</c> in <c>psign-digest-cli</c>): ASCII
    /// whitespace is skipped, <c>=</c> counts as padding within each 4-character group. Throws <see cref="PsignException"/>.
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

    private static FormatException InvalidByte(int index, byte b) => new($"Invalid symbol {b}, offset {index}.");

    private static byte[] BuildTable()
    {
        var table = new byte[256];
        Array.Fill(table, Invalid);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < alphabet.Length; i++)
        {
            table[alphabet[i]] = (byte)i;
        }

        return table;
    }
}
