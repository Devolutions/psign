using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;

namespace Devolutions.Psign.Server;

/// <summary>Minimal DER helpers ported 1:1 from <c>psign-server.rs</c> (<c>push_*</c>, <c>read_tlv</c>, <c>expect_tlv</c>).</summary>
internal static class DerPush
{
    public static void PushLen(List<byte> output, int len)
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

    public static void PushTlv(List<byte> output, byte tag, ReadOnlySpan<byte> body)
    {
        output.Add(tag);
        PushLen(output, body.Length);
        output.AddRange(body);
    }

    public static byte[] Tlv(byte tag, ReadOnlySpan<byte> body)
    {
        var o = new List<byte>(body.Length + 6);
        PushTlv(o, tag, body);
        return o.ToArray();
    }

    public static void PushSequence(List<byte> output, ReadOnlySpan<byte> body) => PushTlv(output, 0x30, body);

    public static byte[] Sequence(ReadOnlySpan<byte> body) => Tlv(0x30, body);

    public static void PushOctetString(List<byte> output, ReadOnlySpan<byte> body) => PushTlv(output, 0x04, body);

    public static byte[] OctetStringDer(ReadOnlySpan<byte> body) => Tlv(0x04, body);

    public static void PushUtf8String(List<byte> output, string body) => PushTlv(output, 0x0c, Encoding.UTF8.GetBytes(body));

    public static void PushGeneralizedTime(List<byte> output, string value)
    {
        ValidateGeneralizedTimeZ(value);
        PushTlv(output, 0x18, Encoding.UTF8.GetBytes(value));
    }

    public static void PushUtcTime(List<byte> output, string value) => PushTlv(output, 0x17, Encoding.UTF8.GetBytes(value));

    /// <summary>Rust <c>validate_generalized_time_z</c>.</summary>
    public static void ValidateGeneralizedTimeZ(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        bool ok = bytes.Length == 15 && bytes[14] == (byte)'Z';
        for (int i = 0; ok && i < 14; i++)
        {
            ok = bytes[i] is >= (byte)'0' and <= (byte)'9';
        }

        if (!ok)
        {
            throw new PsignException("--gen-time must be DER GeneralizedTime in YYYYMMDDhhmmssZ form");
        }
    }

    public static void PushIntegerU64(List<byte> output, ulong value)
    {
        Span<byte> tmp = stackalloc byte[9];
        int pos = tmp.Length;
        ulong n = value;
        if (n == 0)
        {
            tmp[--pos] = 0;
        }
        else
        {
            while (n != 0)
            {
                tmp[--pos] = (byte)(n & 0xff);
                n >>= 8;
            }

            if ((tmp[pos] & 0x80) != 0)
            {
                tmp[--pos] = 0;
            }
        }

        PushTlv(output, 0x02, tmp[pos..]);
    }

    public static void PushOid(List<byte> output, string oid) => output.AddRange(Der.EncodeOid(oid));

    /// <summary>Rust <c>expect_tlv</c>.</summary>
    public static byte[] ExpectTlv(byte[] input, byte tag)
    {
        if (input.Length == 0 || input[0] != tag)
        {
            throw new PsignException("unexpected tag");
        }

        var (bodyStart, len) = ReadLen(input, 1);
        long end = (long)bodyStart + len;
        if (end != input.Length)
        {
            throw new PsignException("TLV trailing bytes");
        }

        return input[bodyStart..(int)end];
    }

    /// <summary>Rust <c>read_tlv</c>.</summary>
    public static byte[] ReadTlv(byte[] input, ref int pos)
    {
        int start = pos;
        if (start >= input.Length)
        {
            throw new PsignException("missing TLV tag");
        }

        var (bodyStart, len) = ReadLen(input, start + 1);
        long end = (long)bodyStart + len;
        if (end > input.Length)
        {
            throw new PsignException("TLV length exceeds input");
        }

        pos = (int)end;
        return input[start..(int)end];
    }

    private static (int BodyStart, int Length) ReadLen(byte[] input, int pos)
    {
        if (pos >= input.Length)
        {
            throw new PsignException("missing length");
        }

        byte first = input[pos++];
        if (first < 0x80)
        {
            return (pos, first);
        }

        int n = first & 0x7f;
        if (n is 0 or > 3)
        {
            throw new PsignException("unsupported DER length form");
        }

        int len = 0;
        for (int i = 0; i < n; i++)
        {
            if (pos >= input.Length)
            {
                throw new PsignException("truncated length");
            }

            len = (len << 8) | input[pos++];
        }

        return (pos, len);
    }
}
