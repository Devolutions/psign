namespace Devolutions.Psign.Verification.AuthRoot;

/// <summary>
/// Raw DEFLATE (RFC 1951) decoder for CAB MSZIP folders. Each <c>CFDATA</c> block is <c>CK</c> followed by a deflate
/// stream whose back-references may reach into the previous block's output (the "preset dictionary"), which
/// <c>System.IO.Compression.DeflateStream</c> cannot express. The decoder therefore keeps the folder's output history.
/// </summary>
internal sealed class MsZipInflater
{
    private const int MaxBits = 15;
    private const int WindowSize = 0x8000;

    private static readonly ushort[] LengthBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    private static readonly byte[] LengthExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    private static readonly ushort[] DistBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    private static readonly byte[] DistExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
    private static readonly byte[] CodeLengthOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

    private static readonly Huffman FixedLit;
    private static readonly Huffman FixedDist;

    private byte[] _history = new byte[WindowSize];
    private int _historyLength;

    static MsZipInflater()
    {
        var lengths = new byte[288];
        for (int i = 0; i < 144; i++)
        {
            lengths[i] = 8;
        }

        for (int i = 144; i < 256; i++)
        {
            lengths[i] = 9;
        }

        for (int i = 256; i < 280; i++)
        {
            lengths[i] = 7;
        }

        for (int i = 280; i < 288; i++)
        {
            lengths[i] = 8;
        }

        FixedLit = Huffman.Build(lengths, 288) ?? throw new InvalidOperationException("fixed literal table");
        var d = new byte[30];
        Array.Fill(d, (byte)5);
        FixedDist = Huffman.Build(d, 30) ?? throw new InvalidOperationException("fixed distance table");
    }

    /// <summary>Forget the dictionary (start of a folder).</summary>
    public void Reset() => _historyLength = 0;

    /// <summary>Decompress one MSZIP block (<c>CK</c> + deflate) producing exactly <paramref name="uncompressedSize"/> bytes.</summary>
    public byte[] DecompressBlock(ReadOnlySpan<byte> data, int uncompressedSize)
    {
        if (data.Length < 2 || data[0] != (byte)'C' || data[1] != (byte)'K')
        {
            throw new InvalidDataException("MSZIP decompression failed: Invalid MSZIP signature");
        }

        var output = new byte[_historyLength + Math.Max(uncompressedSize, 0) + 258 + 0x10000];
        Buffer.BlockCopy(_history, 0, output, 0, _historyLength);
        int outPos = _historyLength;
        var bits = new BitReader(data[2..].ToArray());
        bool final;
        do
        {
            final = bits.Read(1) == 1;
            int type = bits.Read(2);
            switch (type)
            {
                case 0:
                    bits.AlignToByte();
                    int len = bits.Read(16);
                    int nlen = bits.Read(16);
                    if ((len ^ 0xFFFF) != nlen)
                    {
                        throw new InvalidDataException("MSZIP decompression failed: stored block length mismatch");
                    }

                    EnsureCapacity(ref output, outPos + len);
                    for (int i = 0; i < len; i++)
                    {
                        output[outPos++] = (byte)bits.Read(8);
                    }

                    break;
                case 1:
                    outPos = Codes(bits, FixedLit, FixedDist, ref output, outPos);
                    break;
                case 2:
                    var (lit, dist) = Dynamic(bits);
                    outPos = Codes(bits, lit, dist, ref output, outPos);
                    break;
                default:
                    throw new InvalidDataException("MSZIP decompression failed: invalid block type");
            }
        }
        while (!final);

        int produced = outPos - _historyLength;
        if (produced != uncompressedSize)
        {
            throw new InvalidDataException(
                $"MSZIP decompression failed: produced {produced} bytes, expected {uncompressedSize}");
        }

        var result = output.AsSpan(_historyLength, produced).ToArray();
        int keep = Math.Min(WindowSize, outPos);
        if (_history.Length < keep)
        {
            _history = new byte[WindowSize];
        }

        Buffer.BlockCopy(output, outPos - keep, _history, 0, keep);
        _historyLength = keep;
        return result;
    }

    private static void EnsureCapacity(ref byte[] buf, int needed)
    {
        if (needed > buf.Length)
        {
            Array.Resize(ref buf, Math.Max(needed, buf.Length * 2));
        }
    }

    private static int Codes(BitReader bits, Huffman lit, Huffman dist, ref byte[] output, int outPos)
    {
        while (true)
        {
            int sym = lit.Decode(bits);
            if (sym < 256)
            {
                EnsureCapacity(ref output, outPos + 1);
                output[outPos++] = (byte)sym;
            }
            else if (sym == 256)
            {
                return outPos;
            }
            else
            {
                sym -= 257;
                if (sym >= 29)
                {
                    throw new InvalidDataException("MSZIP decompression failed: invalid length symbol");
                }

                int len = LengthBase[sym] + bits.Read(LengthExtra[sym]);
                int dsym = dist.Decode(bits);
                if (dsym >= 30)
                {
                    throw new InvalidDataException("MSZIP decompression failed: invalid distance symbol");
                }

                int d = DistBase[dsym] + bits.Read(DistExtra[dsym]);
                if (d > outPos)
                {
                    throw new InvalidDataException("MSZIP decompression failed: distance too far back");
                }

                EnsureCapacity(ref output, outPos + len);
                for (int i = 0; i < len; i++)
                {
                    output[outPos] = output[outPos - d];
                    outPos++;
                }
            }
        }
    }

    private static (Huffman Lit, Huffman Dist) Dynamic(BitReader bits)
    {
        int nlen = bits.Read(5) + 257;
        int ndist = bits.Read(5) + 1;
        int ncode = bits.Read(4) + 4;
        if (nlen > 286 || ndist > 30)
        {
            throw new InvalidDataException("MSZIP decompression failed: bad dynamic counts");
        }

        var lengths = new byte[320];
        for (int i = 0; i < ncode; i++)
        {
            lengths[CodeLengthOrder[i]] = (byte)bits.Read(3);
        }

        var lencode = Huffman.Build(lengths.AsSpan(0, 19).ToArray(), 19)
            ?? throw new InvalidDataException("MSZIP decompression failed: bad code lengths code");
        Array.Clear(lengths);
        int index = 0;
        while (index < nlen + ndist)
        {
            int sym = lencode.Decode(bits);
            if (sym < 16)
            {
                lengths[index++] = (byte)sym;
                continue;
            }

            int len = 0;
            int repeat;
            if (sym == 16)
            {
                if (index == 0)
                {
                    throw new InvalidDataException("MSZIP decompression failed: repeat with no first length");
                }

                len = lengths[index - 1];
                repeat = 3 + bits.Read(2);
            }
            else if (sym == 17)
            {
                repeat = 3 + bits.Read(3);
            }
            else
            {
                repeat = 11 + bits.Read(7);
            }

            if (index + repeat > nlen + ndist)
            {
                throw new InvalidDataException("MSZIP decompression failed: too many lengths");
            }

            while (repeat-- > 0)
            {
                lengths[index++] = (byte)len;
            }
        }

        if (lengths[256] == 0)
        {
            throw new InvalidDataException("MSZIP decompression failed: no end-of-block code");
        }

        var lit = Huffman.Build(lengths.AsSpan(0, nlen).ToArray(), nlen, allowIncomplete: false)
            ?? throw new InvalidDataException("MSZIP decompression failed: bad literal/length code");
        var dist = Huffman.Build(lengths.AsSpan(nlen, ndist).ToArray(), ndist, allowIncomplete: true)
            ?? throw new InvalidDataException("MSZIP decompression failed: bad distance code");
        return (lit, dist);
    }

    private sealed class BitReader
    {
        private readonly byte[] _data;
        private int _pos;
        private int _bitBuf;
        private int _bitCount;

        public BitReader(byte[] data)
        {
            _data = data;
        }

        public int Read(int need)
        {
            int val = _bitBuf;
            while (_bitCount < need)
            {
                if (_pos >= _data.Length)
                {
                    throw new InvalidDataException("MSZIP decompression failed: unexpected end of data");
                }

                val |= _data[_pos++] << _bitCount;
                _bitCount += 8;
            }

            _bitBuf = val >> need;
            _bitCount -= need;
            return need == 0 ? 0 : val & ((1 << need) - 1);
        }

        public void AlignToByte()
        {
            _bitBuf = 0;
            _bitCount = 0;
        }
    }

    private sealed class Huffman
    {
        private readonly short[] _count = new short[MaxBits + 1];
        private readonly short[] _symbol;

        private Huffman(int n)
        {
            _symbol = new short[n];
        }

        public static Huffman? Build(byte[] lengths, int n, bool allowIncomplete = true)
        {
            var h = new Huffman(n);
            for (int s = 0; s < n; s++)
            {
                h._count[lengths[s]]++;
            }

            if (h._count[0] == n)
            {
                return h;
            }

            int left = 1;
            for (int len = 1; len <= MaxBits; len++)
            {
                left <<= 1;
                left -= h._count[len];
                if (left < 0)
                {
                    return null;
                }
            }

            if (left > 0 && !allowIncomplete && n - h._count[0] != 1)
            {
                return null;
            }

            var offs = new short[MaxBits + 1];
            for (int len = 1; len < MaxBits; len++)
            {
                offs[len + 1] = (short)(offs[len] + h._count[len]);
            }

            for (int s = 0; s < n; s++)
            {
                if (lengths[s] != 0)
                {
                    h._symbol[offs[lengths[s]]++] = (short)s;
                }
            }

            return h;
        }

        public int Decode(BitReader bits)
        {
            int code = 0;
            int first = 0;
            int index = 0;
            for (int len = 1; len <= MaxBits; len++)
            {
                code |= bits.Read(1);
                int count = _count[len];
                if (code - count < first)
                {
                    return _symbol[index + (code - first)];
                }

                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }

            throw new InvalidDataException("MSZIP decompression failed: invalid Huffman code");
        }
    }
}
