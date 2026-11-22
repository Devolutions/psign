using System.Text;

namespace Devolutions.Psign.Server;

/// <summary>
/// Rust <c>base64</c> 0.22 <c>URL_SAFE_NO_PAD</c> engine: URL-safe alphabet, no padding on encode,
/// <c>DecodePaddingMode::RequireNone</c> on decode (any <c>=</c> is invalid padding), non-zero trailing bits rejected.
/// Decode errors use the crate's <c>DecodeError</c> display text.
/// </summary>
internal static class Base64UrlNoPad
{
    private const byte Invalid = 0xFF;
    private const byte Pad = (byte)'=';
    private static readonly byte[] DecodeTable = BuildTable();

    public static string Encode(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Decode; throws <see cref="FormatException"/> with the Rust error text.</summary>
    public static byte[] Decode(string text)
    {
        var input = Encoding.UTF8.GetBytes(text);
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

        if (input.Length != 0 && morselsInLeftover < 2)
        {
            throw new FormatException($"Invalid input length: {prefixLen + morselsInLeftover}");
        }

        if (paddingBytes > 0)
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

        if (input.Length == 0)
        {
            return [];
        }

        var std = Encoding.ASCII.GetString(input).Replace('-', '+').Replace('_', '/');
        std += new string('=', (4 - (std.Length % 4)) % 4);
        return Convert.FromBase64String(std);
    }

    private static FormatException InvalidByte(int offset, byte b) => new($"Invalid symbol {b}, offset {offset}.");

    private static byte[] BuildTable()
    {
        var table = new byte[256];
        Array.Fill(table, Invalid);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (int i = 0; i < alphabet.Length; i++)
        {
            table[alphabet[i]] = (byte)i;
        }

        return table;
    }
}
