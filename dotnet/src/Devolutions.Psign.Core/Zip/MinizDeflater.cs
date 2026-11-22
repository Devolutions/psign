namespace Devolutions.Psign.Core.Zip;

/// <summary>
/// Raw DEFLATE compressor ported from <c>miniz_oxide</c> 0.8.9 (<c>deflate/core.rs</c>, <c>compress_normal</c> path),
/// the default <c>flate2</c> backend used by the Rust <c>zip</c> 0.6.6 writer. Output is byte-identical to the Rust
/// compressor for the same level, which keeps re-written OPC / NuGet / VSIX packages (and therefore package digests)
/// identical to the Rust tool.
/// </summary>
/// <remarks>
/// Only the lazy-matching levels (2-10) are implemented; the Rust zip writer always uses the default level 6. Output is
/// independent of how the input is chunked, so one-shot compression reproduces the streaming Rust writer.
/// </remarks>
public static class MinizDeflater
{
    /// <summary>Default compression level used by <c>flate2::Compression::default()</c>.</summary>
    public const int DefaultLevel = 6;

    /// <summary>Compress <paramref name="data"/> into a raw (headerless) DEFLATE stream.</summary>
    public static byte[] Compress(ReadOnlySpan<byte> data, int level = DefaultLevel)
    {
        if (level < 2 || level > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(level), "only miniz_oxide levels 2-10 are supported");
        }

        var c = new Compressor(CreateFlags(level));
        return c.CompressAll(data);
    }

    private static uint CreateFlags(int level)
    {
        // create_comp_flags_from_zip_params(level, -15, 0): raw stream, default strategy.
        uint greedy = level <= 3 ? TdeflGreedyParsingFlag : 0;
        return NumProbes[Math.Min(10, level)] | greedy;
    }

    private const uint TdeflGreedyParsingFlag = 0x0000_4000;
    private const uint TdeflRleMatches = 0x0001_0000;
    private const uint TdeflFilterMatches = 0x0002_0000;
    private const uint TdeflForceAllStaticBlocks = 0x0004_0000;

    private static readonly uint[] NumProbes = [0, 1, 6, 32, 16, 32, 128, 256, 512, 768, 1500];

    private const int MaxHuffSymbols = 288;
    private const int MaxHuffSymbols0 = 288;
    private const int MaxHuffSymbols1 = 32;
    private const int MaxHuffSymbols2 = 19;
    private const int LzDictSize = 32_768;
    private const int LzDictSizeMask = LzDictSize - 1;
    private const int MinMatchLen = 3;
    private const int MaxMatchLen = 258;
    private const int LzCodeBufSize = 64 * 1024;
    private const int LzCodeBufMask = LzCodeBufSize - 1;
    private const int OutBufSize = (LzCodeBufSize * 13) / 10;
    private const int LzDictFullSize = LzDictSize + MaxMatchLen - 1 + 1;
    private const int LzHashBits = 15;
    private const int LzHashShift = (LzHashBits + 2) / 3;
    private const int LzHashSize = 1 << LzHashBits;
    private const int MaxSupportedHuffCodeSize = 15;

    private static readonly byte[] LenSym =
    [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15,
        15, 15, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19,
        19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21,
        21, 21, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23,
        23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
        24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
        25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
        26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27,
        27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
        27, 27, 27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 29,
    ];

    private const int LenSymOffset = 256;

    private static readonly byte[] LenExtra = BuildLenExtra();
    private static readonly byte[] SmallDistSym = BuildSmallDistSym();
    private static readonly byte[] SmallDistExtra = BuildSmallDistExtra();

    private static readonly byte[] LargeDistSym =
    [
        0, 0, 18, 19, 20, 20, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23,
        24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25,
        26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
        27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
        29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
    ];

    private static readonly byte[] LargeDistExtra =
    [
        0, 0, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10,
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
        12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    ];

    private static readonly uint[] BitMasks =
    [
        0x0000, 0x0001, 0x0003, 0x0007, 0x000F, 0x001F, 0x003F, 0x007F, 0x00FF,
        0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF,
    ];

    private static readonly byte[] HuffmanLengthOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

    private static byte[] BuildLenExtra()
    {
        // 0..7 -> 0, 8..15 -> 1, 16..31 -> 2, 32..63 -> 3, 64..127 -> 4, 128..254 -> 5, 255 -> 0
        var t = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            t[i] = i switch
            {
                < 8 => 0,
                < 16 => 1,
                < 32 => 2,
                < 64 => 3,
                < 128 => 4,
                < 255 => 5,
                _ => 0,
            };
        }

        return t;
    }

    private static byte[] BuildSmallDistSym()
    {
        // Distance code for (distance - 1) < 512 (standard DEFLATE distance codes 0..17).
        var t = new byte[512];
        int[] baseDist = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513];
        for (int d = 0; d < 512; d++)
        {
            int dist = d + 1;
            int code = 0;
            while (code + 1 < baseDist.Length && baseDist[code + 1] <= dist)
            {
                code++;
            }

            t[d] = (byte)code;
        }

        return t;
    }

    private static byte[] BuildSmallDistExtra()
    {
        var t = new byte[512];
        for (int d = 0; d < 512; d++)
        {
            int code = SmallDistSymLazy(d);
            t[d] = (byte)(code < 4 ? 0 : (code / 2) - 1);
        }

        return t;
    }

    private static int SmallDistSymLazy(int d)
    {
        int[] baseDist = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513];
        int dist = d + 1;
        int code = 0;
        while (code + 1 < baseDist.Length && baseDist[code + 1] <= dist)
        {
            code++;
        }

        return code;
    }

    private static ushort UpdateHash(ushort currentHash, byte b) =>
        (ushort)(((currentHash << LzHashShift) ^ b) & (LzHashSize - 1));

    private struct SymFreq
    {
        public ushort Key;
        public ushort SymIndex;
    }

    /// <summary>Output buffer with bit accumulator (Rust <c>OutputBufferOxide</c>).</summary>
    private sealed class OutputBuffer
    {
        public readonly byte[] Inner;
        public int InnerPos;
        public uint BitBuffer;
        public uint BitsIn;

        public OutputBuffer(byte[] inner) => Inner = inner;

        public void PutBits(uint bits, uint len)
        {
            BitBuffer |= bits << (int)BitsIn;
            BitsIn += len;
            while (BitsIn >= 8)
            {
                Inner[InnerPos++] = (byte)BitBuffer;
                BitBuffer >>= 8;
                BitsIn -= 8;
            }
        }

        public void PutBitsNoFlush(uint bits, uint len)
        {
            BitBuffer |= bits << (int)BitsIn;
            BitsIn += len;
        }

        public (int Pos, uint BitBuffer, uint BitsIn) Save() => (InnerPos, BitBuffer, BitsIn);

        public void Load((int Pos, uint BitBuffer, uint BitsIn) saved)
        {
            InnerPos = saved.Pos;
            BitBuffer = saved.BitBuffer;
            BitsIn = saved.BitsIn;
        }

        public void PadToBytes()
        {
            if (BitsIn != 0)
            {
                PutBits(0, 8 - BitsIn);
            }
        }

        public void WriteBytes(ReadOnlySpan<byte> bytes)
        {
            bytes.CopyTo(Inner.AsSpan(InnerPos));
            InnerPos += bytes.Length;
        }
    }

    private struct BitBuffer64
    {
        public ulong Bits;
        public uint BitsIn;

        public void PutFast(ulong bits, uint len)
        {
            Bits |= bits << (int)BitsIn;
            BitsIn += len;
        }

        public void Flush(OutputBuffer output)
        {
            int pos = output.InnerPos;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(output.Inner.AsSpan(pos, 8), Bits);
            int n = pos + (int)(BitsIn >> 3);
            if (n > output.Inner.Length)
            {
                throw new InvalidOperationException("deflate output buffer overflow");
            }

            output.InnerPos = n;
            Bits >>= (int)(BitsIn & ~7u);
            BitsIn &= 7;
        }
    }

    private sealed class Compressor
    {
        // params
        private readonly uint _flags;
        private readonly bool _greedyParsing;
        private uint _savedMatchDist;
        private uint _savedMatchLen;
        private byte _savedLit;
        private bool _flushFinish;
        private uint _savedBitBuffer;
        private uint _savedBitsIn;

        // lz
        private readonly byte[] _codes = new byte[LzCodeBufSize];
        private int _codePosition = 1;
        private int _flagPosition;
        private uint _totalBytes;
        private uint _numFlagsLeft = 8;

        // huffman
        private readonly ushort[][] _count = [new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols]];
        private readonly ushort[][] _huffCodes = [new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols]];
        private readonly byte[][] _codeSizes = [new byte[MaxHuffSymbols], new byte[MaxHuffSymbols], new byte[MaxHuffSymbols]];

        // dict
        private readonly uint[] _maxProbes;
        private readonly byte[] _dict = new byte[LzDictFullSize];
        private readonly ushort[] _next = new ushort[LzDictSize];
        private readonly ushort[] _hash = new ushort[LzDictSize];
        private int _codeBufDictPos;
        private int _lookaheadSize;
        private int _lookaheadPos;
        private int _dictSize;
        private const int LoopLen = 32;

        private readonly byte[] _localBuf = new byte[OutBufSize - 16];
        private readonly MemoryStream _out = new();

        public Compressor(uint flags)
        {
            _flags = flags;
            _greedyParsing = (flags & TdeflGreedyParsingFlag) != 0;
            _maxProbes = [1 + (((flags & 0xFFF) + 2) / 3), 1 + ((((flags & 0xFFF) >> 2) + 2) / 3)];
        }

        public byte[] CompressAll(ReadOnlySpan<byte> input)
        {
            _flushFinish = true;
            CompressNormal(input);
            if (_lookaheadSize == 0)
            {
                FlushBlock(finish: true);
            }

            return _out.ToArray();
        }

        // ---------------------------------------------------------------- LZ code buffer

        private void WriteCode(byte val)
        {
            _codes[(ushort)_codePosition] = val;
            _codePosition++;
        }

        private void InitFlag()
        {
            if (_numFlagsLeft == 8)
            {
                _codes[(ushort)_flagPosition] = 0;
                _codePosition--;
            }
            else
            {
                _codes[(ushort)_flagPosition] = (byte)(_codes[(ushort)_flagPosition] >> (int)_numFlagsLeft);
            }
        }

        private void PlantFlag()
        {
            _flagPosition = _codePosition;
            _codePosition++;
        }

        private void ConsumeFlag()
        {
            _numFlagsLeft--;
            if (_numFlagsLeft == 0)
            {
                _numFlagsLeft = 8;
                PlantFlag();
            }
        }

        private void RecordLiteral(byte lit)
        {
            _totalBytes++;
            WriteCode(lit);
            _codes[(ushort)_flagPosition] >>= 1;
            ConsumeFlag();
            _count[0][lit]++;
        }

        private void RecordMatch(uint matchLen, uint matchDist)
        {
            _totalBytes += matchLen;
            matchDist -= 1;
            byte ml = (byte)(matchLen - MinMatchLen);
            WriteCode(ml);
            WriteCode((byte)matchDist);
            WriteCode((byte)(matchDist >> 8));

            _codes[(ushort)_flagPosition] >>= 1;
            _codes[(ushort)_flagPosition] |= 0x80;
            ConsumeFlag();

            int symbol = matchDist < 512 ? SmallDistSym[matchDist] : LargeDistSym[(matchDist >> 8) & 127];
            _count[1][symbol]++;
            _count[0][(LenSym[ml] & 31) + LenSymOffset]++;
        }

        // ---------------------------------------------------------------- huffman

        private static SymFreq[] RadixSortSymbols(SymFreq[] symbols0, SymFreq[] symbols1, int n)
        {
            var hist0 = new int[256];
            var hist1 = new int[256];
            for (int i = 0; i < n; i++)
            {
                hist0[symbols0[i].Key & 0xFF]++;
                hist1[(symbols0[i].Key >> 8) & 0xFF]++;
            }

            int nPasses = 2;
            if (n == hist1[0])
            {
                nPasses--;
            }

            var current = symbols0;
            var next = symbols1;
            for (int pass = 0; pass < nPasses; pass++)
            {
                var hist = pass == 0 ? hist0 : hist1;
                var offsets = new int[256];
                int offset = 0;
                for (int i = 0; i < 256; i++)
                {
                    offsets[i] = offset;
                    offset += hist[i];
                }

                for (int i = 0; i < n; i++)
                {
                    var sym = current[i];
                    int j = (sym.Key >> (pass * 8)) & 0xFF;
                    next[offsets[j]] = sym;
                    offsets[j]++;
                }

                (current, next) = (next, current);
            }

            return current;
        }

        private static void CalculateMinimumRedundancy(SymFreq[] symbols, int n)
        {
            switch (n)
            {
                case 0:
                    return;
                case 1:
                    symbols[0].Key = 1;
                    return;
            }

            symbols[0].Key = (ushort)(symbols[0].Key + symbols[1].Key);
            int root = 0;
            int leaf = 2;
            for (int next = 1; next < n - 1; next++)
            {
                if (leaf >= n || symbols[root].Key < symbols[leaf].Key)
                {
                    symbols[next].Key = symbols[root].Key;
                    symbols[root].Key = (ushort)next;
                    root++;
                }
                else
                {
                    symbols[next].Key = symbols[leaf].Key;
                    leaf++;
                }

                if (leaf >= n || (root < next && symbols[root].Key < symbols[leaf].Key))
                {
                    symbols[next].Key = (ushort)(symbols[next].Key + symbols[root].Key);
                    symbols[root].Key = (ushort)next;
                    root++;
                }
                else
                {
                    symbols[next].Key = (ushort)(symbols[next].Key + symbols[leaf].Key);
                    leaf++;
                }
            }

            symbols[n - 2].Key = 0;
            for (int next = n - 3; next >= 0; next--)
            {
                symbols[next].Key = (ushort)(symbols[symbols[next].Key].Key + 1);
            }

            int avbl = 1;
            int used = 0;
            int dpth = 0;
            int r = n - 2;
            int nx = n - 1;
            while (avbl > 0)
            {
                while (r >= 0 && symbols[r].Key == dpth)
                {
                    used++;
                    r--;
                }

                while (avbl > used)
                {
                    symbols[nx].Key = (ushort)dpth;
                    nx--;
                    avbl--;
                }

                avbl = 2 * used;
                dpth++;
                used = 0;
            }
        }

        private static void EnforceMaxCodeSize(int[] numCodes, int codeListLen, int maxCodeSize)
        {
            if (codeListLen <= 1)
            {
                return;
            }

            for (int i = maxCodeSize + 1; i < numCodes.Length; i++)
            {
                numCodes[maxCodeSize] += numCodes[i];
            }

            uint total = 0;
            for (int i = 0; i < maxCodeSize; i++)
            {
                // iterate num_codes[1..=max] reversed with index i
                total += (uint)numCodes[maxCodeSize - i] << i;
            }

            for (uint k = 1u << maxCodeSize; k < total; k++)
            {
                numCodes[maxCodeSize]--;
                for (int i = maxCodeSize - 1; i >= 1; i--)
                {
                    if (numCodes[i] != 0)
                    {
                        numCodes[i]--;
                        numCodes[i + 1] += 2;
                        break;
                    }
                }
            }
        }

        private void OptimizeTable(int tableNum, int tableLen, int codeSizeLimit, bool staticTable)
        {
            var numCodes = new int[32 + 1];
            var nextCode = new uint[MaxSupportedHuffCodeSize + 1];

            if (staticTable)
            {
                for (int i = 0; i < tableLen; i++)
                {
                    numCodes[_codeSizes[tableNum][i]]++;
                }
            }
            else
            {
                var symbols0 = new SymFreq[MaxHuffSymbols];
                var symbols1 = new SymFreq[MaxHuffSymbols];
                int numUsed = 0;
                for (int i = 0; i < tableLen; i++)
                {
                    if (_count[tableNum][i] != 0)
                    {
                        symbols0[numUsed] = new SymFreq { Key = _count[tableNum][i], SymIndex = (ushort)i };
                        numUsed++;
                    }
                }

                var symbols = RadixSortSymbols(symbols0, symbols1, numUsed);
                CalculateMinimumRedundancy(symbols, numUsed);

                for (int i = 0; i < numUsed; i++)
                {
                    numCodes[symbols[i].Key]++;
                }

                EnforceMaxCodeSize(numCodes, numUsed, codeSizeLimit);

                Array.Clear(_codeSizes[tableNum]);
                Array.Clear(_huffCodes[tableNum]);

                int last = numUsed;
                for (int i = 1; i <= codeSizeLimit; i++)
                {
                    int first = last - numCodes[i];
                    for (int s = first; s < last; s++)
                    {
                        _codeSizes[tableNum][symbols[s].SymIndex] = (byte)i;
                    }

                    last = first;
                }
            }

            int j = 0;
            nextCode[1] = 0;
            for (int i = 2; i <= codeSizeLimit; i++)
            {
                j = (j + numCodes[i - 1]) << 1;
                nextCode[i] = (uint)j;
            }

            for (int i = 0; i < tableLen; i++)
            {
                int codeSize = _codeSizes[tableNum][i];
                if (codeSize == 0)
                {
                    continue;
                }

                uint code = nextCode[codeSize];
                nextCode[codeSize]++;
                ushort rev = (ushort)(ReverseBits16((ushort)code) >> (16 - codeSize));
                _huffCodes[tableNum][i] = rev;
            }
        }

        private static ushort ReverseBits16(ushort v)
        {
            uint x = v;
            x = ((x & 0x5555) << 1) | ((x >> 1) & 0x5555);
            x = ((x & 0x3333) << 2) | ((x >> 2) & 0x3333);
            x = ((x & 0x0F0F) << 4) | ((x >> 4) & 0x0F0F);
            x = ((x & 0x00FF) << 8) | ((x >> 8) & 0x00FF);
            return (ushort)x;
        }

        private void StartStaticBlock(OutputBuffer output)
        {
            var ls = _codeSizes[0];
            ls.AsSpan(0, 144).Fill(8);
            ls.AsSpan(144, 112).Fill(9);
            ls.AsSpan(256, 24).Fill(7);
            ls.AsSpan(280, 8).Fill(8);
            _codeSizes[1].AsSpan(0, 32).Fill(5);

            OptimizeTable(0, 288, 15, true);
            OptimizeTable(1, 32, 15, true);

            output.PutBits(0b01, 2);
        }

        private void StartDynamicBlock(OutputBuffer output)
        {
            _count[0][256] = 1;

            OptimizeTable(0, MaxHuffSymbols0, 15, false);
            OptimizeTable(1, MaxHuffSymbols1, 15, false);

            int numLitCodes = 286;
            for (int i = 285; i >= 257 && _codeSizes[0][i] == 0; i--)
            {
                numLitCodes--;
            }

            int numDistCodes = 30;
            for (int i = 29; i >= 1 && _codeSizes[1][i] == 0; i--)
            {
                numDistCodes--;
            }

            var codeSizesToPack = new byte[MaxHuffSymbols0 + MaxHuffSymbols1];
            var packedCodeSizes = new byte[MaxHuffSymbols0 + MaxHuffSymbols1];
            int totalToPack = numLitCodes + numDistCodes;
            Array.Copy(_codeSizes[0], 0, codeSizesToPack, 0, numLitCodes);
            Array.Copy(_codeSizes[1], 0, codeSizesToPack, numLitCodes, numDistCodes);

            uint zCount = 0;
            ushort repeatCount = 0;
            byte prevCodeSize = 0xFF;
            Array.Clear(_count[2], 0, MaxHuffSymbols2);

            int packedPos = 0;
            var counts = _count[2];

            void Write(ReadOnlySpan<byte> src)
            {
                if (packedPos + src.Length > packedCodeSizes.Length)
                {
                    throw new InvalidOperationException("deflate code size packing overflow");
                }

                src.CopyTo(packedCodeSizes.AsSpan(packedPos));
                packedPos += src.Length;
            }

            void RlePrevCodeSize()
            {
                if (repeatCount != 0)
                {
                    if (repeatCount < 3)
                    {
                        counts[prevCodeSize] = (ushort)(counts[prevCodeSize] + repeatCount);
                        Span<byte> tmp = [prevCodeSize, prevCodeSize, prevCodeSize];
                        Write(tmp[..repeatCount]);
                    }
                    else
                    {
                        counts[16] = (ushort)(counts[16] + 1);
                        Write([16, (byte)(repeatCount - 3)]);
                    }

                    repeatCount = 0;
                }
            }

            void RleZeroCodeSize()
            {
                if (zCount != 0)
                {
                    if (zCount < 3)
                    {
                        counts[0] = (ushort)(counts[0] + zCount);
                        Span<byte> tmp = [0, 0, 0];
                        Write(tmp[..(int)zCount]);
                    }
                    else if (zCount <= 10)
                    {
                        counts[17] = (ushort)(counts[17] + 1);
                        Write([17, (byte)(zCount - 3)]);
                    }
                    else
                    {
                        counts[18] = (ushort)(counts[18] + 1);
                        Write([18, (byte)(zCount - 11)]);
                    }

                    zCount = 0;
                }
            }

            for (int idx = 0; idx < totalToPack; idx++)
            {
                byte codeSize = codeSizesToPack[idx];
                if (codeSize == 0)
                {
                    RlePrevCodeSize();
                    zCount++;
                    if (zCount == 138)
                    {
                        RleZeroCodeSize();
                    }
                }
                else
                {
                    RleZeroCodeSize();
                    if (codeSize != prevCodeSize)
                    {
                        RlePrevCodeSize();
                        counts[codeSize] = (ushort)(counts[codeSize] + 1);
                        Write([codeSize]);
                    }
                    else
                    {
                        repeatCount++;
                        if (repeatCount == 6)
                        {
                            RlePrevCodeSize();
                        }
                    }
                }

                prevCodeSize = codeSize;
            }

            if (repeatCount != 0)
            {
                RlePrevCodeSize();
            }
            else
            {
                RleZeroCodeSize();
            }

            OptimizeTable(2, MaxHuffSymbols2, 7, false);

            output.PutBitsNoFlush(2, 2);
            output.PutBitsNoFlush((uint)(numLitCodes - 257), 5);
            output.PutBitsNoFlush((uint)(numDistCodes - 1), 5);

            int trailingZero = 0;
            for (int i = HuffmanLengthOrder.Length - 1; i >= 0 && _codeSizes[2][HuffmanLengthOrder[i]] == 0; i--)
            {
                trailingZero++;
            }

            int numBitLengths = 18 - trailingZero;
            numBitLengths = Math.Max(4, numBitLengths + 1);
            output.PutBits((uint)numBitLengths - 4, 4);
            for (int i = 0; i < numBitLengths; i++)
            {
                output.PutBits(_codeSizes[2][HuffmanLengthOrder[i]], 3);
            }

            int packedIndex = 0;
            while (packedIndex < packedPos)
            {
                int code = packedCodeSizes[packedIndex];
                packedIndex++;
                output.PutBits(_huffCodes[2][code], _codeSizes[2][code]);
                if (code >= 16)
                {
                    uint extraBits = code switch
                    {
                        16 => 2u,
                        17 => 3u,
                        _ => 7u,
                    };
                    output.PutBits(packedCodeSizes[packedIndex], extraBits);
                    packedIndex++;
                }
            }
        }

        private void CompressLzCodes(OutputBuffer output)
        {
            uint flags = 1;
            var bb = new BitBuffer64 { Bits = output.BitBuffer, BitsIn = output.BitsIn };
            int usedLen = Math.Min(_codes.Length, _codePosition);

            int i = 0;
            while (i < usedLen)
            {
                if (flags == 1)
                {
                    flags = _codes[i] | 0x100u;
                    i++;
                }

                if ((flags & 1) == 1)
                {
                    flags >>= 1;
                    int matchLen = _codes[i & LzCodeBufMask];
                    int matchDist = _codes[(i + 1) & LzCodeBufMask] | (_codes[(i + 2) & LzCodeBufMask] << 8);
                    i += 3;

                    int lenSym = (LenSym[matchLen] & 31) + LenSymOffset;
                    bb.PutFast(_huffCodes[0][lenSym], _codeSizes[0][lenSym]);
                    bb.PutFast((ulong)matchLen & BitMasks[LenExtra[matchLen] & 7], LenExtra[matchLen]);

                    int sym;
                    int numExtraBits;
                    if (matchDist < 512)
                    {
                        sym = SmallDistSym[matchDist];
                        numExtraBits = SmallDistExtra[matchDist];
                    }
                    else
                    {
                        sym = LargeDistSym[matchDist >> 8];
                        numExtraBits = LargeDistExtra[matchDist >> 8];
                    }

                    bb.PutFast(_huffCodes[1][sym], _codeSizes[1][sym]);
                    bb.PutFast((ulong)matchDist & BitMasks[numExtraBits & 15], (uint)numExtraBits);
                }
                else
                {
                    for (int k = 0; k < 3; k++)
                    {
                        flags >>= 1;
                        byte lit = _codes[i & LzCodeBufMask];
                        i++;
                        bb.PutFast(_huffCodes[0][lit], _codeSizes[0][lit]);
                        if ((flags & 1) == 1 || i >= usedLen)
                        {
                            break;
                        }
                    }
                }

                bb.Flush(output);
            }

            output.BitsIn = 0;
            output.BitBuffer = 0;
            while (bb.BitsIn != 0)
            {
                uint n = Math.Min(bb.BitsIn, 16);
                output.PutBits((uint)bb.Bits & BitMasks[n], n);
                bb.Bits >>= (int)n;
                bb.BitsIn -= n;
            }

            output.PutBits(_huffCodes[0][256], _codeSizes[0][256]);
        }

        private void CompressBlock(OutputBuffer output, bool staticBlock)
        {
            if (staticBlock)
            {
                StartStaticBlock(output);
            }
            else
            {
                StartDynamicBlock(output);
            }

            CompressLzCodes(output);
        }

        private void FlushBlock(bool finish)
        {
            var output = new OutputBuffer(_localBuf)
            {
                BitBuffer = _savedBitBuffer,
                BitsIn = _savedBitsIn,
            };

            InitFlag();

            output.PutBits(finish ? 1u : 0u, 1);
            var savedBuffer = output.Save();

            bool useStatic = (_flags & TdeflForceAllStaticBlocks) != 0 || _totalBytes < 48;
            CompressBlock(output, useStatic);

            bool expanded = _totalBytes > 32
                && output.InnerPos - savedBuffer.Pos + 1 >= (int)_totalBytes
                && _lookaheadPos - _codeBufDictPos <= _dictSize;

            if (expanded)
            {
                output.Load(savedBuffer);
                output.PutBits(0, 2);
                output.PadToBytes();
                output.PutBits(_totalBytes & 0xFFFF, 16);
                output.PutBits(~_totalBytes & 0xFFFF, 16);

                int start = _codeBufDictPos & LzDictSizeMask;
                int end = (_codeBufDictPos + (int)_totalBytes) & LzDictSizeMask;
                if (start < end)
                {
                    output.WriteBytes(_dict.AsSpan(start, end - start));
                }
                else if (_totalBytes > 0)
                {
                    output.WriteBytes(_dict.AsSpan(start, LzDictSize - start));
                    output.WriteBytes(_dict.AsSpan(0, end));
                }
            }

            if (finish)
            {
                output.PadToBytes();
            }

            Array.Clear(_count[0], 0, MaxHuffSymbols0);
            Array.Clear(_count[1], 0, MaxHuffSymbols1);

            _codePosition = 1;
            _flagPosition = 0;
            _numFlagsLeft = 8;
            _codeBufDictPos += (int)_totalBytes;
            _totalBytes = 0;

            _savedBitBuffer = output.BitBuffer;
            _savedBitsIn = output.BitsIn;
            _out.Write(output.Inner, 0, output.InnerPos);
        }

        // ---------------------------------------------------------------- matching

        private ushort ReadU16(int pos) => (ushort)(_dict[pos] | (_dict[pos + 1] << 8));

        private ulong ReadU64(int pos)
        {
            pos &= LzDictSizeMask;
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(_dict.AsSpan(pos, 8));
        }

        private (uint Dist, uint Len) FindMatch(int lookaheadPos, int maxDist, uint maxMatchLen, uint matchDist, uint matchLen)
        {
            maxMatchLen = Math.Min(MaxMatchLen, maxMatchLen);
            matchLen = Math.Max(matchLen, 1);
            if (maxMatchLen <= matchLen)
            {
                return (matchDist, matchLen);
            }

            int pos = lookaheadPos & LzDictSizeMask;
            int probePos = pos;
            uint numProbesLeft = matchLen < 32 ? _maxProbes[0] : _maxProbes[1];

            ushort c01 = ReadU16(pos + (int)matchLen - 1);
            ushort s01 = ReadU16(pos);

            while (true)
            {
                int dist = 0;
                bool found = false;
                while (!found)
                {
                    numProbesLeft--;
                    if (numProbesLeft == 0)
                    {
                        return (matchDist, matchLen);
                    }

                    for (int k = 0; k < 3; k++)
                    {
                        int nextProbePos = _next[probePos];
                        dist = (lookaheadPos - nextProbePos) & 0xFFFF;
                        if (nextProbePos == 0 || dist > maxDist || (int)matchLen - 1 >= MaxMatchLen)
                        {
                            return (matchDist, matchLen);
                        }

                        probePos = nextProbePos & LzDictSizeMask;
                        if (ReadU16(probePos + (int)matchLen - 1) == c01)
                        {
                            found = true;
                            break;
                        }
                    }
                }

                if (dist == 0)
                {
                    return (matchDist, matchLen);
                }

                if (ReadU16(probePos) != s01)
                {
                    continue;
                }

                int p = pos + 2;
                int q = probePos + 2;
                bool continueOuter = false;
                for (int k = 0; k < LoopLen; k++)
                {
                    ulong pData = ReadU64(p);
                    ulong qData = ReadU64(q);
                    ulong xor = pData ^ qData;
                    if (xor == 0)
                    {
                        p += 8;
                        q += 8;
                    }
                    else
                    {
                        int trailing = System.Numerics.BitOperations.TrailingZeroCount(xor);
                        int probeLen = p - pos + (trailing >> 3);
                        if (probeLen > (int)matchLen)
                        {
                            matchDist = (uint)dist;
                            matchLen = Math.Min(maxMatchLen, (uint)probeLen);
                            if (matchLen >= maxMatchLen)
                            {
                                return (matchDist, matchLen);
                            }

                            c01 = ReadU16(Math.Max(0, pos + (int)matchLen - 1));
                        }

                        continueOuter = true;
                        break;
                    }
                }

                if (continueOuter)
                {
                    continue;
                }

                return ((uint)dist, Math.Min(maxMatchLen, MaxMatchLen));
            }
        }

        private void CompressNormal(ReadOnlySpan<byte> inBuf)
        {
            int srcPos = 0;
            int lookaheadSize = _lookaheadSize;
            int lookaheadPos = _lookaheadPos;
            byte savedLit = _savedLit;
            uint savedMatchDist = _savedMatchDist;
            uint savedMatchLen = _savedMatchLen;

            while (srcPos < inBuf.Length || (_flushFinish && lookaheadSize != 0))
            {
                int srcBufLeft = inBuf.Length - srcPos;
                int numBytesToProcess = Math.Min(srcBufLeft, MaxMatchLen - lookaheadSize);

                if (lookaheadSize + _dictSize >= MinMatchLen - 1 && numBytesToProcess > 0)
                {
                    int dstPos = (lookaheadPos + lookaheadSize) & LzDictSizeMask;
                    int insPos = lookaheadPos + lookaheadSize - 2;
                    ushort hash = UpdateHash(_dict[insPos & LzDictSizeMask], _dict[(insPos + 1) & LzDictSizeMask]);

                    lookaheadSize += numBytesToProcess;
                    foreach (byte c in inBuf.Slice(srcPos, numBytesToProcess))
                    {
                        _dict[dstPos] = c;
                        if (dstPos < MaxMatchLen - 1)
                        {
                            _dict[LzDictSize + dstPos] = c;
                        }

                        hash = UpdateHash(hash, c);
                        _next[insPos & LzDictSizeMask] = _hash[hash];
                        _hash[hash] = (ushort)insPos;
                        dstPos = (dstPos + 1) & LzDictSizeMask;
                        insPos++;
                    }

                    srcPos += numBytesToProcess;
                }
                else
                {
                    foreach (byte c in inBuf.Slice(srcPos, numBytesToProcess))
                    {
                        int dstPos = (lookaheadPos + lookaheadSize) & LzDictSizeMask;
                        _dict[dstPos] = c;
                        if (dstPos < MaxMatchLen - 1)
                        {
                            _dict[LzDictSize + dstPos] = c;
                        }

                        lookaheadSize++;
                        if (lookaheadSize + _dictSize >= MinMatchLen)
                        {
                            int insPos = lookaheadPos + lookaheadSize - 3;
                            uint hash = (((uint)_dict[insPos & LzDictSizeMask] << (LzHashShift * 2))
                                ^ (((uint)_dict[(insPos + 1) & LzDictSizeMask] << LzHashShift) ^ c))
                                & (LzHashSize - 1);
                            _next[insPos & LzDictSizeMask] = _hash[hash];
                            _hash[hash] = (ushort)insPos;
                        }
                    }

                    srcPos += numBytesToProcess;
                }

                _dictSize = Math.Min(LzDictSize - lookaheadSize, _dictSize);
                if (!_flushFinish && lookaheadSize < MaxMatchLen)
                {
                    break;
                }

                int lenToMove = 1;
                uint curMatchDist = 0;
                uint curMatchLen = savedMatchLen != 0 ? savedMatchLen : MinMatchLen - 1;
                int curPos = lookaheadPos & LzDictSizeMask;
                if ((_flags & TdeflRleMatches) != 0)
                {
                    if (_dictSize != 0)
                    {
                        byte c = _dict[(curPos - 1) & LzDictSizeMask];
                        uint n = 0;
                        while (n < lookaheadSize && _dict[curPos + (int)n] == c)
                        {
                            n++;
                        }

                        curMatchLen = n;
                        if (curMatchLen < MinMatchLen)
                        {
                            curMatchLen = 0;
                        }
                        else
                        {
                            curMatchDist = 1;
                        }
                    }
                }
                else
                {
                    (curMatchDist, curMatchLen) = FindMatch(lookaheadPos, _dictSize, (uint)lookaheadSize, curMatchDist, curMatchLen);
                }

                bool farAndSmall = curMatchLen == MinMatchLen && curMatchDist >= 8 * 1024;
                bool filterSmall = (_flags & TdeflFilterMatches) != 0 && curMatchLen <= 5;
                if (farAndSmall || filterSmall || curPos == (int)curMatchDist)
                {
                    curMatchDist = 0;
                    curMatchLen = 0;
                }

                if (savedMatchLen != 0)
                {
                    if (curMatchLen > savedMatchLen)
                    {
                        RecordLiteral(savedLit);
                        if (curMatchLen >= 128)
                        {
                            RecordMatch(curMatchLen, curMatchDist);
                            savedMatchLen = 0;
                            lenToMove = (int)curMatchLen;
                        }
                        else
                        {
                            savedLit = _dict[curPos];
                            savedMatchDist = curMatchDist;
                            savedMatchLen = curMatchLen;
                        }
                    }
                    else
                    {
                        RecordMatch(savedMatchLen, savedMatchDist);
                        lenToMove = (int)(savedMatchLen - 1);
                        savedMatchLen = 0;
                    }
                }
                else if (curMatchDist == 0)
                {
                    RecordLiteral(_dict[Math.Min(curPos, _dict.Length - 1)]);
                }
                else if (_greedyParsing || (_flags & TdeflRleMatches) != 0 || curMatchLen >= 128)
                {
                    RecordMatch(curMatchLen, curMatchDist);
                    lenToMove = (int)curMatchLen;
                }
                else
                {
                    savedLit = _dict[Math.Min(curPos, _dict.Length - 1)];
                    savedMatchDist = curMatchDist;
                    savedMatchLen = curMatchLen;
                }

                lookaheadPos += lenToMove;
                if (lookaheadSize < lenToMove)
                {
                    throw new InvalidOperationException("deflate lookahead underflow");
                }

                lookaheadSize -= lenToMove;
                _dictSize = Math.Min(_dictSize + lenToMove, LzDictSize);

                bool lzBufTight = _codePosition > LzCodeBufSize - 8;
                bool fat = ((_codePosition * 115) >> 7) >= (int)_totalBytes;
                bool bufFat = _totalBytes > 31 * 1024 && fat;

                if (lzBufTight || bufFat)
                {
                    _lookaheadSize = lookaheadSize;
                    _lookaheadPos = lookaheadPos;
                    FlushBlock(finish: false);
                }
            }

            _lookaheadSize = lookaheadSize;
            _lookaheadPos = lookaheadPos;
            _savedLit = savedLit;
            _savedMatchDist = savedMatchDist;
            _savedMatchLen = savedMatchLen;
        }
    }
}
