using System.Formats.Asn1;

namespace Devolutions.Psign.Core.Asn1;

/// <summary>A located DER TLV inside a buffer (Rust <c>DerTlv</c>).</summary>
/// <param name="Tag">First identifier octet (single-octet tags only).</param>
/// <param name="TagStart">Offset of the identifier octet.</param>
/// <param name="ValueStart">Offset of the first content octet.</param>
/// <param name="ValueEnd">Offset one past the last content octet.</param>
public readonly record struct DerTlv(byte Tag, int TagStart, int ValueStart, int ValueEnd)
{
    /// <summary>Offset one past the TLV.</summary>
    public int End => ValueEnd;

    /// <summary>Total encoded length.</summary>
    public int TotalLength => ValueEnd - TagStart;

    /// <summary>Content length.</summary>
    public int ValueLength => ValueEnd - ValueStart;

    /// <summary>Slice of the full encoded TLV.</summary>
    public ReadOnlySpan<byte> Encoded(ReadOnlySpan<byte> data) => data[TagStart..ValueEnd];

    /// <summary>Slice of the content octets.</summary>
    public ReadOnlySpan<byte> Value(ReadOnlySpan<byte> data) => data[ValueStart..ValueEnd];
}

/// <summary>
/// Minimal definite-length DER TLV helpers mirroring the hand-rolled readers/writers in the Rust crates
/// (<c>pkcs7_wire.rs</c>, <c>timestamp.rs</c>). Higher-level structures should prefer <see cref="AsnReader"/> /
/// <see cref="AsnWriter"/>.
/// </summary>
public static class Der
{
    /// <summary>Encode a definite length (short or long form).</summary>
    public static byte[] EncodeLength(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        if (length < 0x80)
        {
            return [(byte)length];
        }

        Span<byte> tmp = stackalloc byte[4];
        int n = 0;
        int v = length;
        while (v > 0)
        {
            tmp[3 - n] = (byte)(v & 0xFF);
            v >>= 8;
            n++;
        }

        var result = new byte[n + 1];
        result[0] = (byte)(0x80 | n);
        tmp[(4 - n)..].CopyTo(result.AsSpan(1));
        return result;
    }

    /// <summary>Encode a TLV with a single-octet tag.</summary>
    public static byte[] EncodeTlv(byte tag, ReadOnlySpan<byte> content)
    {
        var len = EncodeLength(content.Length);
        var result = new byte[1 + len.Length + content.Length];
        result[0] = tag;
        len.CopyTo(result, 1);
        content.CopyTo(result.AsSpan(1 + len.Length));
        return result;
    }

    /// <summary>Encode a TLV whose content is the concatenation of <paramref name="parts"/>.</summary>
    public static byte[] EncodeTlv(byte tag, params byte[][] parts)
    {
        int total = 0;
        foreach (var p in parts)
        {
            total += p.Length;
        }

        var content = new byte[total];
        int off = 0;
        foreach (var p in parts)
        {
            p.CopyTo(content, off);
            off += p.Length;
        }

        return EncodeTlv(tag, (ReadOnlySpan<byte>)content);
    }

    /// <summary>
    /// Parse a definite length starting at <paramref name="bytes"/>[0]. Returns (length, headerOctets) or null.
    /// Long form is limited to 4 length octets.
    /// </summary>
    public static (int Length, int HeaderLength)? ParseLength(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return null;
        }

        byte first = bytes[0];
        if ((first & 0x80) == 0)
        {
            return (first, 1);
        }

        int n = first & 0x7F;
        if (n == 0 || n > 4 || bytes.Length < 1 + n)
        {
            return null;
        }

        long len = 0;
        for (int i = 0; i < n; i++)
        {
            len = (len << 8) | bytes[1 + i];
        }

        if (len > int.MaxValue)
        {
            return null;
        }

        return ((int)len, 1 + n);
    }

    /// <summary>Locate the TLV at <paramref name="offset"/> that must end before <paramref name="limit"/>.</summary>
    public static DerTlv? TlvAt(ReadOnlySpan<byte> data, int offset, int limit)
    {
        if (offset < 0 || offset >= limit || limit > data.Length)
        {
            return null;
        }

        byte tag = data[offset];
        var parsed = ParseLength(data[(offset + 1)..limit]);
        if (parsed is null)
        {
            return null;
        }

        int valueStart = offset + 1 + parsed.Value.HeaderLength;
        long valueEnd = (long)valueStart + parsed.Value.Length;
        if (valueEnd > limit)
        {
            return null;
        }

        return new DerTlv(tag, offset, valueStart, (int)valueEnd);
    }

    /// <summary>Locate the first TLV in <paramref name="data"/>.</summary>
    public static DerTlv? First(ReadOnlySpan<byte> data) => TlvAt(data, 0, data.Length);

    /// <summary>Enumerate the child TLVs spanning exactly [<paramref name="start"/>, <paramref name="end"/>).</summary>
    public static List<DerTlv>? Children(ReadOnlySpan<byte> data, int start, int end)
    {
        var result = new List<DerTlv>();
        int offset = start;
        while (offset < end)
        {
            var tlv = TlvAt(data, offset, end);
            if (tlv is null)
            {
                return null;
            }

            offset = tlv.Value.End;
            result.Add(tlv.Value);
        }

        return offset == end ? result : null;
    }

    /// <summary>Children of a constructed TLV.</summary>
    public static List<DerTlv>? Children(ReadOnlySpan<byte> data, DerTlv parent) =>
        Children(data, parent.ValueStart, parent.ValueEnd);

    /// <summary>Total byte length of a definite-length TLV whose first octet is <c>0x30</c>.</summary>
    public static int? SequenceTotalLength(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty || data[0] != 0x30)
        {
            return null;
        }

        var parsed = ParseLength(data[1..]);
        if (parsed is null)
        {
            return null;
        }

        return 1 + parsed.Value.HeaderLength + parsed.Value.Length;
    }

    /// <summary>Total byte length of a definite-length TLV of any single-octet tag.</summary>
    public static int? TotalLength(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return null;
        }

        var parsed = ParseLength(data[1..]);
        if (parsed is null)
        {
            return null;
        }

        long total = 1L + parsed.Value.HeaderLength + parsed.Value.Length;
        return total > int.MaxValue ? null : (int)total;
    }

    /// <summary>Encode an OBJECT IDENTIFIER TLV.</summary>
    public static byte[] EncodeOid(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        w.WriteObjectIdentifier(oid);
        return w.Encode();
    }

    /// <summary>Decode an OBJECT IDENTIFIER TLV to dotted-decimal, or <c>null</c> when malformed.</summary>
    public static string? DecodeOid(ReadOnlySpan<byte> tlv)
    {
        try
        {
            var r = new AsnReader(tlv.ToArray(), AsnEncodingRules.BER);
            var s = r.ReadObjectIdentifier();
            return r.HasData ? null : s;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    /// <summary>Encode a DER NULL.</summary>
    public static readonly byte[] Null = [0x05, 0x00];

    /// <summary>
    /// Sort DER-encoded elements of a SET OF per X.690 (lexicographic byte order, shorter prefix first) — the same order
    /// as the Rust <c>der</c> crate's <c>der_sort</c> and .NET's <see cref="AsnWriter"/> DER mode.
    /// </summary>
    public static List<byte[]> SortSetOf(IEnumerable<byte[]> elements)
    {
        var list = elements.ToList();
        list.Sort(CompareDer);
        return list;
    }

    /// <summary>Lexicographic comparison of encoded DER elements.</summary>
    public static int CompareDer(byte[]? a, byte[]? b)
    {
        if (ReferenceEquals(a, b))
        {
            return 0;
        }

        if (a is null)
        {
            return -1;
        }

        if (b is null)
        {
            return 1;
        }

        return a.AsSpan().SequenceCompareTo(b);
    }

    /// <summary>Encode a SET (tag 0x31) or other tagged set whose elements are sorted in DER order.</summary>
    public static byte[] EncodeSetOf(byte tag, IEnumerable<byte[]> elements) =>
        EncodeTlv(tag, SortSetOf(elements).ToArray());

    /// <summary>Encode a SEQUENCE (tag 0x30) of the given encoded elements, preserving order.</summary>
    public static byte[] EncodeSequence(params byte[][] elements) => EncodeTlv(0x30, elements);

    /// <summary>Read all TLVs from a buffer, requiring exact consumption.</summary>
    public static List<byte[]> SplitElements(ReadOnlySpan<byte> content)
    {
        var children = Children(content, 0, content.Length)
            ?? throw new PsignException("malformed DER element sequence");
        var result = new List<byte[]>(children.Count);
        foreach (var c in children)
        {
            result.Add(c.Encoded(content).ToArray());
        }

        return result;
    }
}
