namespace Devolutions.Psign.Core.Zip;

/// <summary>Flush mode for <see cref="MinizDeflater"/> (miniz_oxide <c>TDEFLFlush</c>).</summary>
public enum DeflateFlush
{
    None = 0,
    Sync = 2,
    Full = 3,
    Finish = 4,
}

/// <summary>
/// Raw DEFLATE compressor that reproduces the byte stream of the Rust <c>miniz_oxide</c> 0.8.9 compressor
/// (<c>flate2</c> <c>rust_backend</c>, levels 2-10, default strategy, no zlib wrapper). It backs both the MSIX
/// staging path (<c>appx_package::deflate_appx_blocks</c>, streaming with full flushes per block) and the Rust
/// <c>zip</c> 0.6.6 writer used for OPC / NuGet / VSIX re-zipping (<see cref="Compress(ReadOnlySpan{byte}, int)"/>,
/// level 6). Signed packages are only byte-identical to Rust when the compressed bytes match exactly; the BCL
/// <see cref="System.IO.Compression.DeflateStream"/> (zlib) produces a different stream.
/// </summary>
/// <remarks>
/// Port of <c>compress_normal</c>, <c>find_match</c>, <c>flush_block</c>, <c>record_literal</c> /
/// <c>record_match</c> and <c>HuffmanOxide</c> from <c>miniz_oxide/src/deflate/core.rs</c>. Output is written to
/// an unbounded buffer, which yields the same stream as the Rust output-buffer chunking; without explicit flushes the
/// output is independent of how the input is chunked, so one-shot compression reproduces the streaming Rust writer.
/// </remarks>
public sealed class MinizDeflater
{
    /// <summary>Default compression level used by <c>flate2::Compression::default()</c>.</summary>
    public const int DefaultLevel = 6;

    /// <summary>Compress <paramref name="data"/> into a raw (headerless) DEFLATE stream in one shot.</summary>
    public static byte[] Compress(ReadOnlySpan<byte> data, int level = DefaultLevel)
    {
        var deflater = new MinizDeflater(level);
        deflater.Compress(data, DeflateFlush.Finish);
        return deflater.ToArray();
    }

    private const int MaxProbesMask = 0xFFF;
    private const uint GreedyParsingFlag = 0x0000_4000;
    private const int MaxSupportedHuffCodeSize = 15;
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
    private const int LzDictFullSize = LzDictSize + MaxMatchLen - 1 + 1;
    private const int LzHashBits = 15;
    private const int LzHashShift = (LzHashBits + 2) / 3;
    private const int LzHashSize = 1 << LzHashBits;
    private const int LenSymOffset = 256;

    private static readonly ushort[] NumProbes = [0, 1, 6, 32, 16, 32, 128, 256, 512, 768, 1500];

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

    // ------------------------------------------------------------------ state

    private readonly uint _flags;
    private readonly bool _greedyParsing;
    private readonly uint[] _maxProbes = new uint[2];

    // LZ code buffer
    private readonly byte[] _lzCodes = new byte[LzCodeBufSize];
    private int _lzCodePosition = 1;
    private int _lzFlagPosition;
    private uint _lzTotalBytes;
    private uint _lzNumFlagsLeft = 8;

    // dictionary
    private readonly byte[] _dict = new byte[LzDictFullSize];
    private readonly ushort[] _next = new ushort[LzDictSize];
    private readonly ushort[] _hash = new ushort[LzDictSize];
    private long _codeBufDictPos;
    private long _lookaheadSize;
    private long _lookaheadPos;
    private long _dictSize;

    // huffman
    private readonly ushort[][] _count = [new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols]];
    private readonly ushort[][] _codes = [new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols], new ushort[MaxHuffSymbols]];
    private readonly byte[][] _codeSizes = [new byte[MaxHuffSymbols], new byte[MaxHuffSymbols], new byte[MaxHuffSymbols]];

    // params
    private uint _savedMatchDist;
    private uint _savedMatchLen;
    private byte _savedLit;
    private DeflateFlush _flush = DeflateFlush.None;
    private bool _finished;
    private uint _blockIndex;

    // output
    private readonly BitWriter _out = new();

    /// <summary>Create a raw-deflate compressor for <paramref name="level"/> (miniz <c>set_format_and_level(Raw, level)</c>).</summary>
    public MinizDeflater(int level = 6)
    {
        if (level < 2 || level > 10)
        {
            throw new ArgumentOutOfRangeException(nameof(level), "only miniz_oxide levels 2-10 (compress_normal) are supported");
        }

        _flags = NumProbes[level] | (level <= 3 ? GreedyParsingFlag : 0u);
        _greedyParsing = (_flags & GreedyParsingFlag) != 0;
        _maxProbes[0] = 1 + (((_flags & MaxProbesMask) + 2) / 3);
        _maxProbes[1] = 1 + ((((_flags & MaxProbesMask) >> 2) + 2) / 3);
    }

    /// <summary>Total compressed bytes produced so far.</summary>
    public int TotalOut => _out.Length;

    /// <summary>Compressed output produced so far.</summary>
    public byte[] ToArray() => _out.ToArray();

    /// <summary>Feed <paramref name="input"/> with <paramref name="flush"/> (one <c>flate2::Compress::compress_vec</c> call).</summary>
    public void Compress(ReadOnlySpan<byte> input, DeflateFlush flush)
    {
        if (_finished)
        {
            if (flush == DeflateFlush.Finish)
            {
                return;
            }

            throw new InvalidOperationException("deflate stream already finished");
        }

        _flush = flush;
        int srcPos = CompressNormal(input);
        bool remaining = srcPos != input.Length;
        if (flush != DeflateFlush.None && _lookaheadSize == 0 && !remaining)
        {
            FlushBlock(flush);
            _finished = flush == DeflateFlush.Finish;
            if (flush == DeflateFlush.Full)
            {
                Array.Clear(_hash);
                Array.Clear(_next);
                _dictSize = 0;
            }
        }
    }

    // ------------------------------------------------------------------ LZ

    private void WriteCode(byte val)
    {
        _lzCodes[(ushort)_lzCodePosition] = val;
        _lzCodePosition++;
    }

    private void InitFlag()
    {
        if (_lzNumFlagsLeft == 8)
        {
            _lzCodes[(ushort)_lzFlagPosition] = 0;
            _lzCodePosition--;
        }
        else
        {
            _lzCodes[(ushort)_lzFlagPosition] >>= (int)_lzNumFlagsLeft;
        }
    }

    private void ConsumeFlag()
    {
        _lzNumFlagsLeft--;
        if (_lzNumFlagsLeft == 0)
        {
            _lzNumFlagsLeft = 8;
            _lzFlagPosition = _lzCodePosition;
            _lzCodePosition++;
        }
    }

    private void RecordLiteral(byte lit)
    {
        _lzTotalBytes++;
        WriteCode(lit);
        _lzCodes[(ushort)_lzFlagPosition] >>= 1;
        ConsumeFlag();
        _count[0][lit]++;
    }

    private void RecordMatch(uint matchLen, uint matchDist)
    {
        _lzTotalBytes += matchLen;
        matchDist -= 1;
        byte len = (byte)(matchLen - MinMatchLen);
        WriteCode(len);
        WriteCode((byte)matchDist);
        WriteCode((byte)(matchDist >> 8));

        _lzCodes[(ushort)_lzFlagPosition] >>= 1;
        _lzCodes[(ushort)_lzFlagPosition] |= 0x80;
        ConsumeFlag();

        int symbol = matchDist < 512 ? SmallDistSym[matchDist] : LargeDistSym[(matchDist >> 8) & 127];
        _count[1][symbol]++;
        _count[0][(LenSym[len] & 31) + LenSymOffset]++;
    }

    private static ushort UpdateHash(ushort current, byte b) => (ushort)(((current << LzHashShift) ^ b) & (LzHashSize - 1));

    private ushort ReadU16(long pos) => (ushort)(_dict[pos] | (_dict[pos + 1] << 8));

    private ulong ReadU64(long pos)
    {
        int p = (int)(pos & LzDictSizeMask);
        return BitConverter.ToUInt64(_dict, p);
    }

    private (uint Dist, uint Len) FindMatch(long lookaheadPos, long maxDist, uint maxMatchLen, uint matchDist, uint matchLen)
    {
        maxMatchLen = Math.Min(MaxMatchLen, maxMatchLen);
        matchLen = Math.Max(matchLen, 1);
        if (maxMatchLen <= matchLen)
        {
            return (matchDist, matchLen);
        }

        long pos = lookaheadPos & LzDictSizeMask;
        long probePos = pos;
        uint numProbesLeft = matchLen < 32 ? _maxProbes[0] : _maxProbes[1];
        ushort c01 = ReadU16(pos + matchLen - 1);
        ushort s01 = ReadU16(pos);

        while (true)
        {
            long dist = 0;
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
                    long nextProbePos = _next[probePos];
                    dist = (lookaheadPos - nextProbePos) & 0xFFFF;
                    if (nextProbePos == 0 || dist > maxDist || matchLen - 1 >= MaxMatchLen)
                    {
                        return (matchDist, matchLen);
                    }

                    probePos = nextProbePos & LzDictSizeMask;
                    if (ReadU16(probePos + matchLen - 1) == c01)
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

            long p = pos + 2;
            long q = probePos + 2;
            bool restart = false;
            for (int i = 0; i < 32; i++)
            {
                ulong xor = ReadU64(p) ^ ReadU64(q);
                if (xor == 0)
                {
                    p += 8;
                    q += 8;
                }
                else
                {
                    int trailing = System.Numerics.BitOperations.TrailingZeroCount(xor);
                    long probeLen = p - pos + (trailing >> 3);
                    if (probeLen > matchLen)
                    {
                        matchDist = (uint)dist;
                        matchLen = (uint)Math.Min(maxMatchLen, probeLen);
                        if (matchLen >= maxMatchLen)
                        {
                            return (matchDist, matchLen);
                        }

                        long c = pos + matchLen;
                        c01 = ReadU16(c >= 1 ? c - 1 : 0);
                    }

                    restart = true;
                    break;
                }
            }

            if (restart)
            {
                continue;
            }

            return ((uint)dist, Math.Min(maxMatchLen, MaxMatchLen));
        }
    }

    private int CompressNormal(ReadOnlySpan<byte> inBuf)
    {
        int srcPos = 0;
        while (srcPos < inBuf.Length || (_flush != DeflateFlush.None && _lookaheadSize != 0))
        {
            int srcBufLeft = inBuf.Length - srcPos;
            int numBytesToProcess = (int)Math.Min(srcBufLeft, MaxMatchLen - _lookaheadSize);

            if (_lookaheadSize + _dictSize >= MinMatchLen - 1 && numBytesToProcess > 0)
            {
                long dstPos = (_lookaheadPos + _lookaheadSize) & LzDictSizeMask;
                long insPos = _lookaheadPos + _lookaheadSize - 2;
                ushort hash = UpdateHash(_dict[insPos & LzDictSizeMask], _dict[(insPos + 1) & LzDictSizeMask]);
                _lookaheadSize += numBytesToProcess;
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
                    long dstPos = (_lookaheadPos + _lookaheadSize) & LzDictSizeMask;
                    _dict[dstPos] = c;
                    if (dstPos < MaxMatchLen - 1)
                    {
                        _dict[LzDictSize + dstPos] = c;
                    }

                    _lookaheadSize++;
                    if (_lookaheadSize + _dictSize >= MinMatchLen)
                    {
                        long insPos = _lookaheadPos + _lookaheadSize - 3;
                        uint hash = (((uint)_dict[insPos & LzDictSizeMask] << (LzHashShift * 2))
                            ^ (((uint)_dict[(insPos + 1) & LzDictSizeMask] << LzHashShift) ^ c))
                            & (LzHashSize - 1);
                        _next[insPos & LzDictSizeMask] = _hash[hash];
                        _hash[hash] = (ushort)insPos;
                    }
                }

                srcPos += numBytesToProcess;
            }

            _dictSize = Math.Min(LzDictSize - _lookaheadSize, _dictSize);
            if (_flush == DeflateFlush.None && _lookaheadSize < MaxMatchLen)
            {
                break;
            }

            long lenToMove = 1;
            uint curMatchDist = 0;
            uint curMatchLen = _savedMatchLen != 0 ? _savedMatchLen : MinMatchLen - 1;
            long curPos = _lookaheadPos & LzDictSizeMask;

            (curMatchDist, curMatchLen) = FindMatch(_lookaheadPos, _dictSize, (uint)_lookaheadSize, curMatchDist, curMatchLen);

            bool farAndSmall = curMatchLen == MinMatchLen && curMatchDist >= 8 * 1024;
            if (farAndSmall || curPos == curMatchDist)
            {
                curMatchDist = 0;
                curMatchLen = 0;
            }

            if (_savedMatchLen != 0)
            {
                if (curMatchLen > _savedMatchLen)
                {
                    RecordLiteral(_savedLit);
                    if (curMatchLen >= 128)
                    {
                        RecordMatch(curMatchLen, curMatchDist);
                        _savedMatchLen = 0;
                        lenToMove = curMatchLen;
                    }
                    else
                    {
                        _savedLit = _dict[curPos];
                        _savedMatchDist = curMatchDist;
                        _savedMatchLen = curMatchLen;
                    }
                }
                else
                {
                    RecordMatch(_savedMatchLen, _savedMatchDist);
                    lenToMove = _savedMatchLen - 1;
                    _savedMatchLen = 0;
                }
            }
            else if (curMatchDist == 0)
            {
                RecordLiteral(_dict[Math.Min(curPos, _dict.Length - 1)]);
            }
            else if (_greedyParsing || curMatchLen >= 128)
            {
                RecordMatch(curMatchLen, curMatchDist);
                lenToMove = curMatchLen;
            }
            else
            {
                _savedLit = _dict[Math.Min(curPos, _dict.Length - 1)];
                _savedMatchDist = curMatchDist;
                _savedMatchLen = curMatchLen;
            }

            _lookaheadPos += lenToMove;
            _lookaheadSize -= lenToMove;
            _dictSize = Math.Min(_dictSize + lenToMove, LzDictSize);

            bool lzBufTight = _lzCodePosition > LzCodeBufSize - 8;
            bool fat = ((_lzCodePosition * 115) >> 7) >= _lzTotalBytes;
            bool bufFat = _lzTotalBytes > 31 * 1024 && fat;
            if (lzBufTight || bufFat)
            {
                FlushBlock(DeflateFlush.None);
            }
        }

        return srcPos;
    }

    // ------------------------------------------------------------------ blocks

    private void FlushBlock(DeflateFlush flush)
    {
        InitFlag();

        _out.PutBits(flush == DeflateFlush.Finish ? 1u : 0u, 1);
        var saved = _out.Save();

        bool useStatic = _lzTotalBytes < 48;
        CompressBlock(useStatic);

        bool expanded = _lzTotalBytes > 32
            && (_out.Length - saved.Pos + 1 >= _lzTotalBytes)
            && (_lookaheadPos - _codeBufDictPos <= _dictSize);

        if (expanded)
        {
            _out.Load(saved);
            _out.PutBits(0, 2);
            _out.PadToBytes();
            _out.PutBits(_lzTotalBytes & 0xFFFF, 16);
            _out.PutBits(~_lzTotalBytes & 0xFFFF, 16);

            int start = (int)(_codeBufDictPos & LzDictSizeMask);
            int end = (int)((_codeBufDictPos + _lzTotalBytes) & LzDictSizeMask);
            if (start < end)
            {
                _out.WriteBytes(_dict.AsSpan(start, end - start));
            }
            else if (_lzTotalBytes > 0)
            {
                _out.WriteBytes(_dict.AsSpan(start, LzDictSize - start));
                _out.WriteBytes(_dict.AsSpan(0, end));
            }
        }

        if (flush != DeflateFlush.None)
        {
            if (flush == DeflateFlush.Finish)
            {
                _out.PadToBytes();
            }
            else
            {
                _out.PutBits(0, 3);
                _out.PadToBytes();
                _out.PutBits(0, 16);
                _out.PutBits(0xFFFF, 16);
            }
        }

        Array.Clear(_count[0], 0, MaxHuffSymbols0);
        Array.Clear(_count[1], 0, MaxHuffSymbols1);

        _lzCodePosition = 1;
        _lzFlagPosition = 0;
        _lzNumFlagsLeft = 8;
        _codeBufDictPos += _lzTotalBytes;
        _lzTotalBytes = 0;
        _blockIndex++;
    }

    private void CompressBlock(bool staticBlock)
    {
        if (staticBlock)
        {
            StartStaticBlock();
        }
        else
        {
            StartDynamicBlock();
        }

        CompressLzCodes();
    }

    private void CompressLzCodes()
    {
        uint flags = 1;
        int used = Math.Min(_lzCodes.Length, _lzCodePosition);
        int i = 0;
        while (i < used)
        {
            if (flags == 1)
            {
                flags = _lzCodes[i] | 0x100u;
                i++;
            }

            if ((flags & 1) == 1)
            {
                flags >>= 1;
                int matchLen = _lzCodes[i & LzCodeBufMask];
                int matchDist = _lzCodes[(i + 1) & LzCodeBufMask] | (_lzCodes[(i + 2) & LzCodeBufMask] << 8);
                i += 3;

                int lenSym = (LenSym[matchLen] & 31) + LenSymOffset;
                _out.PutBits(_codes[0][lenSym], _codeSizes[0][lenSym]);
                _out.PutBits((uint)matchLen & BitMasks[LenExtra[matchLen] & 7], LenExtra[matchLen]);

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

                _out.PutBits(_codes[1][sym], _codeSizes[1][sym]);
                _out.PutBits((uint)matchDist & BitMasks[numExtraBits & 15], numExtraBits);
            }
            else
            {
                for (int k = 0; k < 3; k++)
                {
                    flags >>= 1;
                    byte lit = _lzCodes[i & LzCodeBufMask];
                    i++;
                    _out.PutBits(_codes[0][lit], _codeSizes[0][lit]);
                    if ((flags & 1) == 1 || i >= used)
                    {
                        break;
                    }
                }
            }
        }

        _out.PutBits(_codes[0][256], _codeSizes[0][256]);
    }

    private void StartStaticBlock()
    {
        var cs0 = _codeSizes[0];
        cs0.AsSpan(0, 144).Fill(8);
        cs0.AsSpan(144, 112).Fill(9);
        cs0.AsSpan(256, 24).Fill(7);
        cs0.AsSpan(280, 8).Fill(8);
        _codeSizes[1].AsSpan(0, 32).Fill(5);

        OptimizeTable(0, 288, 15, true);
        OptimizeTable(1, 32, 15, true);
        _out.PutBits(0b01, 2);
    }

    private void StartDynamicBlock()
    {
        _count[0][256] = 1;
        OptimizeTable(0, MaxHuffSymbols0, 15, false);
        OptimizeTable(1, MaxHuffSymbols1, 15, false);

        int numLitCodes = 286;
        for (int k = 285; k >= 257 && _codeSizes[0][k] == 0; k--)
        {
            numLitCodes--;
        }

        int numDistCodes = 30;
        for (int k = 29; k >= 1 && _codeSizes[1][k] == 0; k--)
        {
            numDistCodes--;
        }

        var codeSizesToPack = new byte[MaxHuffSymbols0 + MaxHuffSymbols1];
        var packed = new byte[MaxHuffSymbols0 + MaxHuffSymbols1];
        int total = numLitCodes + numDistCodes;
        Array.Copy(_codeSizes[0], 0, codeSizesToPack, 0, numLitCodes);
        Array.Copy(_codeSizes[1], 0, codeSizesToPack, numLitCodes, numDistCodes);

        uint zCount = 0;
        ushort repeatCount = 0;
        byte prevCodeSize = 0xFF;
        Array.Clear(_count[2], 0, MaxHuffSymbols2);
        int packedPos = 0;
        var counts2 = _count[2];

        void Write(params byte[] src)
        {
            src.CopyTo(packed, packedPos);
            packedPos += src.Length;
        }

        void FlushPrev()
        {
            if (repeatCount != 0)
            {
                if (repeatCount < 3)
                {
                    counts2[prevCodeSize] = (ushort)(counts2[prevCodeSize] + repeatCount);
                    for (int r = 0; r < repeatCount; r++)
                    {
                        Write(prevCodeSize);
                    }
                }
                else
                {
                    counts2[16]++;
                    Write(16, (byte)(repeatCount - 3));
                }

                repeatCount = 0;
            }
        }

        void FlushZero()
        {
            if (zCount != 0)
            {
                if (zCount < 3)
                {
                    counts2[0] = (ushort)(counts2[0] + zCount);
                    for (int r = 0; r < zCount; r++)
                    {
                        Write(0);
                    }
                }
                else if (zCount <= 10)
                {
                    counts2[17]++;
                    Write(17, (byte)(zCount - 3));
                }
                else
                {
                    counts2[18]++;
                    Write(18, (byte)(zCount - 11));
                }

                zCount = 0;
            }
        }

        for (int k = 0; k < total; k++)
        {
            byte codeSize = codeSizesToPack[k];
            if (codeSize == 0)
            {
                FlushPrev();
                zCount++;
                if (zCount == 138)
                {
                    FlushZero();
                }
            }
            else
            {
                FlushZero();
                if (codeSize != prevCodeSize)
                {
                    FlushPrev();
                    counts2[codeSize]++;
                    Write(codeSize);
                }
                else
                {
                    repeatCount++;
                    if (repeatCount == 6)
                    {
                        FlushPrev();
                    }
                }
            }

            prevCodeSize = codeSize;
        }

        if (repeatCount != 0)
        {
            FlushPrev();
        }
        else
        {
            FlushZero();
        }

        OptimizeTable(2, MaxHuffSymbols2, 7, false);

        _out.PutBits(2, 2);
        _out.PutBits((uint)(numLitCodes - 257), 5);
        _out.PutBits((uint)(numDistCodes - 1), 5);

        int trailing = 0;
        for (int k = HuffmanLengthOrder.Length - 1; k >= 0 && _codeSizes[2][HuffmanLengthOrder[k]] == 0; k--)
        {
            trailing++;
        }

        int numBitLengths = Math.Max(4, 18 - trailing + 1);
        _out.PutBits((uint)(numBitLengths - 4), 4);
        for (int k = 0; k < numBitLengths; k++)
        {
            _out.PutBits(_codeSizes[2][HuffmanLengthOrder[k]], 3);
        }

        int idx = 0;
        while (idx < packedPos)
        {
            int code = packed[idx];
            idx++;
            _out.PutBits(_codes[2][code], _codeSizes[2][code]);
            if (code >= 16)
            {
                _out.PutBits(packed[idx], code switch { 16 => 2, 17 => 3, _ => 7 });
                idx++;
            }
        }
    }

    private struct SymFreq
    {
        public ushort Key;
        public ushort SymIndex;
    }

    private static SymFreq[] RadixSortSymbols(SymFreq[] symbols0, SymFreq[] symbols1, int n)
    {
        var hist = new int[2, 256];
        for (int i = 0; i < n; i++)
        {
            hist[0, symbols0[i].Key & 0xFF]++;
            hist[1, (symbols0[i].Key >> 8) & 0xFF]++;
        }

        int passes = 2;
        if (n == hist[1, 0])
        {
            passes--;
        }

        var current = symbols0;
        var other = symbols1;
        for (int pass = 0; pass < passes; pass++)
        {
            var offsets = new int[256];
            int offset = 0;
            for (int i = 0; i < 256; i++)
            {
                offsets[i] = offset;
                offset += hist[pass, i];
            }

            for (int i = 0; i < n; i++)
            {
                int j = (current[i].Key >> (pass * 8)) & 0xFF;
                other[offsets[j]] = current[i];
                offsets[j]++;
            }

            (current, other) = (other, current);
        }

        return current;
    }

    private static void CalculateMinimumRedundancy(SymFreq[] s, int n)
    {
        switch (n)
        {
            case 0:
                return;
            case 1:
                s[0].Key = 1;
                return;
        }

        s[0].Key = (ushort)(s[0].Key + s[1].Key);
        int root = 0;
        int leaf = 2;
        for (int next = 1; next < n - 1; next++)
        {
            if (leaf >= n || s[root].Key < s[leaf].Key)
            {
                s[next].Key = s[root].Key;
                s[root].Key = (ushort)next;
                root++;
            }
            else
            {
                s[next].Key = s[leaf].Key;
                leaf++;
            }

            if (leaf >= n || (root < next && s[root].Key < s[leaf].Key))
            {
                s[next].Key = (ushort)(s[next].Key + s[root].Key);
                s[root].Key = (ushort)next;
                root++;
            }
            else
            {
                s[next].Key = (ushort)(s[next].Key + s[leaf].Key);
                leaf++;
            }
        }

        s[n - 2].Key = 0;
        for (int next = n - 3; next >= 0; next--)
        {
            s[next].Key = (ushort)(s[s[next].Key].Key + 1);
        }

        int avbl = 1;
        int used = 0;
        int dpth = 0;
        int r = n - 2;
        int nx = n - 1;
        while (avbl > 0)
        {
            while (r >= 0 && s[r].Key == dpth)
            {
                used++;
                r--;
            }

            while (avbl > used)
            {
                s[nx].Key = (ushort)dpth;
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
        for (int i = maxCodeSize, shift = 0; i >= 1; i--, shift++)
        {
            total += (uint)numCodes[i] << shift;
        }

        for (uint t = 1u << maxCodeSize; t < total; t++)
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
                    symbols0[numUsed++] = new SymFreq { Key = _count[tableNum][i], SymIndex = (ushort)i };
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
            Array.Clear(_codes[tableNum]);

            int last = numUsed;
            for (int i = 1; i <= codeSizeLimit; i++)
            {
                int first = last - numCodes[i];
                for (int k = first; k < last; k++)
                {
                    _codeSizes[tableNum][symbols[k].SymIndex] = (byte)i;
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
            ushort rev = ReverseBits16((ushort)code);
            _codes[tableNum][i] = (ushort)(rev >> (16 - codeSize));
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

    // ------------------------------------------------------------------ tables

    private static byte[] BuildLenExtra()
    {
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
                255 => 0,
                _ => 5,
            };
        }

        return t;
    }

    private static byte[] BuildSmallDistSym()
    {
        // Distance code for (distance - 1) < 512 per RFC 1951.
        var t = new byte[512];
        for (int d = 0; d < 512; d++)
        {
            t[d] = (byte)DistCode(d);
        }

        return t;
    }

    private static byte[] BuildSmallDistExtra()
    {
        var t = new byte[512];
        for (int d = 0; d < 512; d++)
        {
            int code = DistCode(d);
            t[d] = (byte)(code < 4 ? 0 : (code / 2) - 1);
        }

        return t;
    }

    private static int DistCode(int dMinus1)
    {
        if (dMinus1 < 4)
        {
            return dMinus1;
        }

        int bits = 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)dMinus1);
        int extra = bits - 1;
        return (2 * bits) + ((dMinus1 >> extra) & 1);
    }

    // ------------------------------------------------------------------ bit writer

    private sealed class BitWriter
    {
        private byte[] _buf = new byte[4096];
        private int _pos;
        private ulong _bitBuffer;
        private int _bitsIn;

        public int Length => _pos;

        public void PutBits(uint bits, int len)
        {
            _bitBuffer |= (ulong)bits << _bitsIn;
            _bitsIn += len;
            while (_bitsIn >= 8)
            {
                Ensure(1);
                _buf[_pos++] = (byte)_bitBuffer;
                _bitBuffer >>= 8;
                _bitsIn -= 8;
            }
        }

        public void PadToBytes()
        {
            if (_bitsIn != 0)
            {
                PutBits(0, 8 - _bitsIn);
            }
        }

        public void WriteBytes(ReadOnlySpan<byte> bytes)
        {
            Ensure(bytes.Length);
            bytes.CopyTo(_buf.AsSpan(_pos));
            _pos += bytes.Length;
        }

        public (int Pos, ulong BitBuffer, int BitsIn) Save() => (_pos, _bitBuffer, _bitsIn);

        public void Load((int Pos, ulong BitBuffer, int BitsIn) saved)
        {
            _pos = saved.Pos;
            _bitBuffer = saved.BitBuffer;
            _bitsIn = saved.BitsIn;
        }

        public byte[] ToArray() => _buf.AsSpan(0, _pos).ToArray();

        private void Ensure(int extra)
        {
            if (_pos + extra > _buf.Length)
            {
                Array.Resize(ref _buf, Math.Max(_buf.Length * 2, _pos + extra));
            }
        }
    }
}
