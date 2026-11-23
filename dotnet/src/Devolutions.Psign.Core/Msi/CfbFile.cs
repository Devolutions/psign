using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Devolutions.Psign.Core.Msi;

/// <summary>Compound-file object type (MS-CFB §2.6.1).</summary>
internal enum CfbObjectType : byte
{
    Unallocated = 0,
    Storage = 1,
    Stream = 2,
    Root = 5,
}

/// <summary>Compound-file format version (Rust <c>cfb::Version</c>).</summary>
internal enum CfbVersion
{
    /// <summary>Version 3: 512-byte sectors.</summary>
    V3 = 3,

    /// <summary>Version 4: 4096-byte sectors.</summary>
    V4 = 4,
}

/// <summary>
/// One compound-file directory entry, normalized the way the Rust <c>cfb</c> crate's permissive reader normalizes it
/// (<c>DirEntry::read_from</c>): the root name is forced to <c>Root Entry</c>, stream CLSIDs and timestamps read as zero,
/// storage start sector and length read as zero, and V3 stream lengths are masked to 32 bits. Rewriting an entry
/// (<see cref="WriteTo"/>) emits the normalized values, exactly like <c>DirEntry::write_to</c>.
/// </summary>
internal sealed class CfbDirEntry
{
    internal CfbDirEntry(int id) => Id = id;

    /// <summary>Stream id (index in the directory chain).</summary>
    public int Id { get; }

    public string Name { get; internal set; } = string.Empty;

    public CfbObjectType Type { get; internal set; }

    /// <summary>Red-black tree colour byte (0 = red, 1 = black).</summary>
    public byte Color { get; internal set; }

    public uint LeftSibling { get; internal set; } = CfbFile.NoStream;

    public uint RightSibling { get; internal set; } = CfbFile.NoStream;

    public uint Child { get; internal set; } = CfbFile.NoStream;

    /// <summary>CLSID exactly as stored on disk (little-endian GUID fields, Rust <c>Uuid::to_bytes_le</c>).</summary>
    public byte[] ClsidLe { get; internal set; } = new byte[16];

    public uint StateBits { get; internal set; }

    public ulong CreationTime { get; internal set; }

    public ulong ModifiedTime { get; internal set; }

    public uint StartSector { get; internal set; }

    public ulong StreamLength { get; internal set; }

    public bool IsRoot => Type == CfbObjectType.Root;

    /// <summary>Nested storage (the root is reported through <see cref="IsRoot"/>).</summary>
    public bool IsStorage => Type == CfbObjectType.Storage;

    public bool IsStream => Type == CfbObjectType.Stream;

    internal static CfbDirEntry Unallocated(int id) => new(id)
    {
        Type = CfbObjectType.Unallocated,
        Color = CfbFile.ColorRed,
        StartSector = 0,
    };

    internal static CfbDirEntry New(int id, string name, CfbObjectType type, ulong timestamp) => new(id)
    {
        Name = name,
        Type = type,
        Color = CfbFile.ColorBlack,
        CreationTime = timestamp,
        ModifiedTime = timestamp,
        // MS-CFB §2.6.3: storage entries use start sector zero.
        StartSector = type == CfbObjectType.Storage ? 0 : CfbFile.EndOfChain,
    };

    /// <summary>Rust <c>DirEntry::write_to</c>.</summary>
    internal void WriteTo(Span<byte> d)
    {
        d[..CfbFile.DirEntryLen].Clear();
        for (int i = 0; i < Name.Length; i++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(d[(i * 2)..], Name[i]);
        }

        BinaryPrimitives.WriteUInt16LittleEndian(d[64..], (ushort)((Name.Length + 1) * 2));
        d[66] = (byte)Type;
        d[67] = Color;
        BinaryPrimitives.WriteUInt32LittleEndian(d[68..], LeftSibling);
        BinaryPrimitives.WriteUInt32LittleEndian(d[72..], RightSibling);
        BinaryPrimitives.WriteUInt32LittleEndian(d[76..], Child);
        ClsidLe.CopyTo(d[80..]);
        BinaryPrimitives.WriteUInt32LittleEndian(d[96..], StateBits);
        BinaryPrimitives.WriteUInt64LittleEndian(d[100..], CreationTime);
        BinaryPrimitives.WriteUInt64LittleEndian(d[108..], ModifiedTime);
        BinaryPrimitives.WriteUInt32LittleEndian(d[116..], StartSector);
        BinaryPrimitives.WriteUInt64LittleEndian(d[120..], StreamLength);
    }
}

/// <summary>
/// MS-CFB compound file editor: a line-by-line port of the code paths of the Rust <c>cfb</c> crate (0.14.0) that psign
/// uses — <c>CompoundFile::open</c> (permissive validation), <c>create</c>, <c>create_storage</c>,
/// <c>create_stream</c> (create or overwrite) plus stream writes, and stream reads. Like <c>cfb</c>, every mutation is
/// written straight into the underlying image (FAT / MiniFAT entries, directory entries, individual header fields); free
/// sectors are reused last-freed / highest-index first, new sectors are appended at the end, and the directory tree is
/// not rebalanced. Applying the same operations as Rust therefore yields byte-identical files.
/// </summary>
internal sealed class CfbFile
{
    internal const int HeaderLen = 512;
    internal const int DirEntryLen = 128;
    internal const int NumDifatEntriesInHeader = 109;
    internal const int MiniSectorLen = 64;
    internal const uint MiniStreamCutoff = 4096;
    internal const uint MaxRegularSector = 0xFFFF_FFFA;
    internal const uint InvalidSector = 0xFFFF_FFFB;
    internal const uint DifatSector = 0xFFFF_FFFC;
    internal const uint FatSector = 0xFFFF_FFFD;
    internal const uint EndOfChain = 0xFFFF_FFFE;
    internal const uint FreeSector = 0xFFFF_FFFF;
    internal const uint NoStream = 0xFFFF_FFFF;
    internal const uint MaxRegularStreamId = 0xFFFF_FFFA;
    internal const byte ColorRed = 0;
    internal const byte ColorBlack = 1;
    internal const string RootDirName = "Root Entry";

    /// <summary>Rust <c>DEFAULT_STREAM_MAX_BUFFER_SIZE</c>: <c>Stream</c> writes reach the file in chunks of this size.</summary>
    internal const int StreamMaxBufferSize = 1024 * 1024;

    private static ReadOnlySpan<byte> MagicNumber => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private enum SectorInit
    {
        Zero,
        Fat,
        Difat,
        Dir,
    }

    // Underlying image (Rust `Cursor<Vec<u8>>`).
    private byte[] _data;
    private int _length;

    // Sectors / Allocator.
    private readonly int _sectorLen;
    private uint _numSectors;
    private readonly List<uint> _difatSectorIds;
    private readonly List<uint> _difat;
    private readonly List<uint> _fat;
    private readonly List<uint> _freeSectors = [];

    // Directory.
    private readonly List<CfbDirEntry> _dirEntries;
    private readonly uint _dirStartSector;

    // MiniAllocator.
    private readonly List<uint> _minifat;
    private uint _minifatStartSector;
    private readonly List<uint> _freeMiniSectors = [];

    private CfbFile(
        byte[] data,
        int length,
        CfbVersion version,
        uint numSectors,
        List<uint> difatSectorIds,
        List<uint> difat,
        List<uint> fat,
        List<CfbDirEntry> dirEntries,
        uint dirStartSector,
        List<uint> minifat,
        uint minifatStartSector)
    {
        _data = data;
        _length = length;
        Version = version;
        _sectorLen = version == CfbVersion.V3 ? 512 : 4096;
        _numSectors = numSectors;
        _difatSectorIds = difatSectorIds;
        _difat = difat;
        _fat = fat;
        _dirEntries = dirEntries;
        _dirStartSector = dirStartSector;
        _minifat = minifat;
        _minifatStartSector = minifatStartSector;
    }

    /// <summary>Format version of this compound file.</summary>
    public CfbVersion Version { get; }

    /// <summary>The root storage entry (stream id 0).</summary>
    public CfbDirEntry Root => _dirEntries[0];

    /// <summary>Current image length.</summary>
    public int Length => _length;

    /// <summary>Copy of the current compound-file image (Rust <c>into_inner().into_inner()</c>).</summary>
    public byte[] ToArray() => _data.AsSpan(0, _length).ToArray();

    private static PsignException Error(string message) => new(message);

    private int DirEntriesPerSector => _sectorLen / DirEntryLen;

    private static int SectorLenOf(CfbVersion v) => v == CfbVersion.V3 ? 512 : 4096;

    // ------------------------------------------------------------------ image I/O

    private void EnsureCapacity(long needed)
    {
        if (needed > int.MaxValue)
        {
            throw Error("compound file too large");
        }

        if (needed > _data.Length)
        {
            long cap = Math.Max(needed, Math.Min(int.MaxValue, Math.Max(4096L, (long)_data.Length * 2)));
            Array.Resize(ref _data, (int)cap);
        }
    }

    /// <summary><c>Cursor&lt;Vec&lt;u8&gt;&gt;</c> write: extends (zero-filling any gap) as needed.</summary>
    private void WriteAt(long position, ReadOnlySpan<byte> bytes)
    {
        long end = position + bytes.Length;
        EnsureCapacity(end);
        if (position > _length)
        {
            _data.AsSpan(_length, (int)(position - _length)).Clear();
        }

        bytes.CopyTo(_data.AsSpan((int)position));
        if (end > _length)
        {
            _length = (int)end;
        }
    }

    private void WriteU32At(long position, uint value)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        WriteAt(position, b);
    }

    /// <summary><c>read_exact</c> on the image.</summary>
    private void ReadExactAt(long position, Span<byte> dest)
    {
        if (position < 0 || position + dest.Length > _length)
        {
            throw Error("failed to fill whole buffer");
        }

        _data.AsSpan((int)position, dest.Length).CopyTo(dest);
    }

    private uint ReadU32At(long position)
    {
        Span<byte> b = stackalloc byte[4];
        ReadExactAt(position, b);
        return BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    // ------------------------------------------------------------------ Sectors

    /// <summary>File offset of <paramref name="offsetWithinSector"/> in <paramref name="sectorId"/> (Rust <c>seek_within_sector</c>).</summary>
    private long SectorOffset(uint sectorId, long offsetWithinSector = 0)
    {
        if (sectorId >= _numSectors)
        {
            throw Error($"Tried to seek to sector {sectorId}, but sector count is only {_numSectors}");
        }

        return ((long)sectorId + 1) * _sectorLen + offsetWithinSector;
    }

    private void InitSector(uint sectorId, SectorInit init)
    {
        if (sectorId > _numSectors)
        {
            throw Error($"Tried to initialize sector {sectorId}, but sector count is only {_numSectors}");
        }

        if (sectorId == _numSectors)
        {
            _numSectors++;
        }

        long offset = SectorOffset(sectorId);
        var sector = new byte[_sectorLen];
        switch (init)
        {
            case SectorInit.Zero:
                break;
            case SectorInit.Fat:
                sector.AsSpan().Fill(0xFF);
                break;
            case SectorInit.Difat:
                sector.AsSpan().Fill(0xFF);
                BinaryPrimitives.WriteUInt32LittleEndian(sector.AsSpan(_sectorLen - 4), EndOfChain);
                break;
            case SectorInit.Dir:
                for (int i = 0; i < DirEntriesPerSector; i++)
                {
                    CfbDirEntry.Unallocated(0).WriteTo(sector.AsSpan(i * DirEntryLen, DirEntryLen));
                }

                break;
        }

        WriteAt(offset, sector);
    }

    // ------------------------------------------------------------------ open

    /// <summary>
    /// Open an existing compound file (Rust <c>CompoundFile::open</c>, permissive validation). The image is used in place:
    /// pass a copy when the original bytes must not change.
    /// </summary>
    public static CfbFile Open(byte[] data) => Open(data, data.Length);

    private static CfbFile Open(byte[] data, int innerLen)
    {
        if (innerLen < HeaderLen)
        {
            throw Error($"Invalid CFB file ({innerLen} bytes is too small)");
        }

        var h = data.AsSpan(0, HeaderLen);
        if (!h[..8].SequenceEqual(MagicNumber))
        {
            var magic = new string[8];
            for (int i = 0; i < 8; i++)
            {
                magic[i] = h[i].ToString("x", CultureInfo.InvariantCulture);
            }

            throw Error($"Invalid CFB file (wrong magic number): [{string.Join(", ", magic)}]");
        }

        ushort versionNumber = BinaryPrimitives.ReadUInt16LittleEndian(h[26..]);
        ushort byteOrderMark = BinaryPrimitives.ReadUInt16LittleEndian(h[28..]);
        if (byteOrderMark != 0xFFFE)
        {
            throw Error($"Invalid CFB byte order mark (expected 0xFFFE, found 0x{byteOrderMark:X4})");
        }

        CfbVersion version = versionNumber switch
        {
            3 => CfbVersion.V3,
            4 => CfbVersion.V4,
            _ => throw Error($"CFB version {versionNumber} is not supported"),
        };
        ushort expectedShift = (ushort)(version == CfbVersion.V3 ? 9 : 12);
        ushort sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(h[30..]);
        if (sectorShift != expectedShift)
        {
            throw Error(
                $"Incorrect sector shift for CFB version {versionNumber} (expected {expectedShift}, found {sectorShift})");
        }

        ushort miniSectorShift = BinaryPrimitives.ReadUInt16LittleEndian(h[32..]);
        if (miniSectorShift != 6)
        {
            throw Error($"Incorrect mini sector shift (expected 6, found {miniSectorShift})");
        }

        uint numFatSectors = BinaryPrimitives.ReadUInt32LittleEndian(h[44..]);
        uint firstDirSector = BinaryPrimitives.ReadUInt32LittleEndian(h[48..]);
        uint miniStreamCutoff = BinaryPrimitives.ReadUInt32LittleEndian(h[56..]);
        if (miniStreamCutoff != MiniStreamCutoff)
        {
            throw Error($"Incorrect mini stream cutoff (expected 4096, found {miniStreamCutoff})");
        }

        uint firstMinifatSector = BinaryPrimitives.ReadUInt32LittleEndian(h[60..]);
        uint firstDifatSector = BinaryPrimitives.ReadUInt32LittleEndian(h[68..]);
        if (firstDifatSector == FreeSector)
        {
            firstDifatSector = EndOfChain;
        }

        var initialDifat = new List<uint>(NumDifatEntriesInHeader);
        for (int i = 0; i < NumDifatEntriesInHeader; i++)
        {
            uint next = BinaryPrimitives.ReadUInt32LittleEndian(h[(76 + (4 * i))..]);
            if (next == FreeSector)
            {
                break;
            }

            if (next > MaxRegularSector)
            {
                throw Error($"Initial DIFAT array refers to invalid sector index 0x{next:X8}");
            }

            initialDifat.Add(next);
        }

        int sectorLen = SectorLenOf(version);
        if (innerLen < sectorLen)
        {
            throw Error($"Invalid CFB file (length of {innerLen} < sector length of {sectorLen})");
        }

        uint numSectors = (uint)(((long)innerLen + sectorLen - 1) / sectorLen) - 1;
        var file = new CfbFile(data, innerLen, version, numSectors, [], [], [], [], firstDirSector, [], firstMinifatSector);

        // DIFAT.
        var difat = new List<uint>();
        for (int i = 0; i < NumDifatEntriesInHeader; i++)
        {
            difat.Add(i < initialDifat.Count ? initialDifat[i] : FreeSector);
        }

        var seenDifat = new HashSet<uint>();
        var difatSectorIds = new List<uint>();
        uint currentDifat = firstDifatSector;
        while (currentDifat != EndOfChain && currentDifat != FreeSector)
        {
            if (currentDifat > MaxRegularSector)
            {
                throw Error($"DIFAT chain includes invalid sector index {currentDifat}");
            }

            if (currentDifat >= numSectors)
            {
                throw Error($"DIFAT chain includes sector index {currentDifat}, but sector count is only {numSectors}");
            }

            if (!seenDifat.Add(currentDifat))
            {
                throw Error($"DIFAT chain includes duplicate sector index {currentDifat}");
            }

            difatSectorIds.Add(currentDifat);
            long offset = file.SectorOffset(currentDifat);
            for (int i = 0; i < (sectorLen / 4) - 1; i++)
            {
                uint next = file.ReadU32At(offset + (4 * i));
                if (next != FreeSector && next > MaxRegularSector)
                {
                    throw Error($"DIFAT refers to invalid sector index {next}");
                }

                difat.Add(next);
            }

            currentDifat = file.ReadU32At(offset + sectorLen - 4);
        }

        while (difat.Count > NumDifatEntriesInHeader && difat.Count > numFatSectors && difat[^1] == 0)
        {
            difat.RemoveAt(difat.Count - 1);
        }

        while (difat.Count > 0 && difat[^1] == FreeSector)
        {
            difat.RemoveAt(difat.Count - 1);
        }

        // FAT. Rust concatenates every DIFAT-listed sector, strips trailing 0 / DIFAT / FAT / FREE entries beyond the
        // sector count, then rejects a FAT that is still longer than the sector count. The DIFAT may list the same
        // sector many times, so materialising that concatenation lets a small file demand gigabytes. Keep only the
        // first numSectors entries and track the last entry beyond them that the trim would keep (a duplicated sector
        // has identical content, so it is read once); the outcome and error text match the Rust crate.
        int entriesPerSector = sectorLen / 4;
        var fat = new List<uint>();
        var lastKeptEntryInSector = new Dictionary<uint, int>();
        long fatLen = 0;
        long lastKeptBeyondSectors = -1;
        foreach (uint sectorIndex in difat)
        {
            if (sectorIndex >= numSectors)
            {
                throw Error($"DIFAT refers to sector {sectorIndex}, but sector count is only {numSectors}");
            }

            if (fatLen < numSectors || !lastKeptEntryInSector.TryGetValue(sectorIndex, out int lastKept))
            {
                lastKept = -1;
                long offset = file.SectorOffset(sectorIndex);
                for (int i = 0; i < entriesPerSector; i++)
                {
                    uint entry = file.ReadU32At(offset + (4 * i));
                    if (fatLen + i < numSectors)
                    {
                        fat.Add(entry);
                    }

                    if (entry is not (0 or DifatSector or FatSector or FreeSector))
                    {
                        lastKept = i;
                    }
                }

                lastKeptEntryInSector[sectorIndex] = lastKept;
            }

            if (lastKept >= 0 && fatLen + lastKept >= numSectors)
            {
                lastKeptBeyondSectors = Math.Max(lastKeptBeyondSectors, fatLen + lastKept);
            }

            fatLen += entriesPerSector;
        }

        if (lastKeptBeyondSectors >= numSectors)
        {
            throw Error($"Malformed FAT (FAT has {lastKeptBeyondSectors + 1} entries, but file has only {numSectors} sectors)");
        }

        while (fat.Count < numSectors)
        {
            fat.Add(FreeSector);
        }

        file._difatSectorIds.AddRange(difatSectorIds);
        file._difat.AddRange(difat);
        file._fat.AddRange(fat);
        file.ValidateAllocator();

        // Directory.
        var seenDir = new HashSet<uint>();
        uint currentDir = firstDirSector;
        var entryBuf = new byte[DirEntryLen];
        while (currentDir != EndOfChain)
        {
            if (currentDir > MaxRegularSector)
            {
                throw Error($"Directory chain includes invalid sector index {currentDir}");
            }

            if (currentDir >= numSectors)
            {
                throw Error($"Directory chain includes sector index {currentDir}, but sector count is only {numSectors}");
            }

            if (!seenDir.Add(currentDir))
            {
                throw Error($"Directory chain includes duplicate sector index {currentDir}");
            }

            long offset = file.SectorOffset(currentDir);
            for (int i = 0; i < sectorLen / DirEntryLen; i++)
            {
                file.ReadExactAt(offset + (i * DirEntryLen), entryBuf);
                file._dirEntries.Add(ReadDirEntry(entryBuf, file._dirEntries.Count, version));
            }

            currentDir = file.Next(currentDir);
        }

        file.ValidateDirectory();

        // MiniFAT.
        var minifatChain = file.ChainSectors(firstMinifatSector);
        long minifatChainLen = (long)minifatChain.Count * sectorLen;
        long numMinifatEntries = minifatChainLen / 4;
        var minifat = new List<uint>((int)Math.Min(numMinifatEntries, int.MaxValue));
        for (long i = 0; i < numMinifatEntries; i++)
        {
            long byteOffset = i * 4;
            uint sector = minifatChain[(int)(byteOffset / sectorLen)];
            minifat.Add(file.ReadU32At(file.SectorOffset(sector, byteOffset % sectorLen)));
        }

        while (minifat.Count > 0 && minifat[^1] == FreeSector)
        {
            minifat.RemoveAt(minifat.Count - 1);
        }

        file._minifat.AddRange(minifat);
        file.ValidateMiniAllocator();
        return file;
    }

    private static CfbDirEntry ReadDirEntry(ReadOnlySpan<byte> e, int id, CfbVersion version)
    {
        ushort nameLenBytes = BinaryPrimitives.ReadUInt16LittleEndian(e[64..]);
        if (nameLenBytes > 64)
        {
            throw Error($"Malformed directory entry (name length too large: {nameLenBytes})");
        }

        if (nameLenBytes % 2 != 0)
        {
            throw Error($"Malformed directory entry (odd name length: {nameLenBytes})");
        }

        int nameLenChars = nameLenBytes > 0 ? (nameLenBytes / 2) - 1 : 0;
        var chars = new char[nameLenChars];
        for (int i = 0; i < nameLenChars; i++)
        {
            chars[i] = (char)BinaryPrimitives.ReadUInt16LittleEndian(e[(i * 2)..]);
        }

        if (!IsWellFormedUtf16(chars))
        {
            throw Error("Malformed directory entry (name not valid UTF-16)");
        }

        string name = new(chars);
        byte typeByte = e[66];
        if (typeByte is not (0 or 1 or 2 or 5))
        {
            throw Error($"Malformed directory entry (invalid object type: {typeByte})");
        }

        var type = (CfbObjectType)typeByte;
        if (type == CfbObjectType.Root)
        {
            name = RootDirName;
        }
        else
        {
            ValidateName(name);
        }

        byte color = e[67];
        if (color is not (ColorRed or ColorBlack))
        {
            throw Error($"Malformed directory entry (invalid color: {color})");
        }

        uint left = BinaryPrimitives.ReadUInt32LittleEndian(e[68..]);
        if (left != NoStream && left > MaxRegularStreamId)
        {
            throw Error($"Malformed directory entry (invalid left sibling: {left})");
        }

        uint right = BinaryPrimitives.ReadUInt32LittleEndian(e[72..]);
        if (right != NoStream && right > MaxRegularStreamId)
        {
            throw Error($"Malformed directory entry (invalid right sibling: {right})");
        }

        uint child = BinaryPrimitives.ReadUInt32LittleEndian(e[76..]);
        if (child != NoStream)
        {
            if (type == CfbObjectType.Stream)
            {
                throw Error($"Malformed directory entry (non-empty stream child: {child})");
            }

            if (child > MaxRegularStreamId)
            {
                throw Error($"Malformed directory entry (invalid child: {child})");
            }
        }

        var clsid = e.Slice(80, 16).ToArray();
        uint stateBits = BinaryPrimitives.ReadUInt32LittleEndian(e[96..]);
        ulong created = BinaryPrimitives.ReadUInt64LittleEndian(e[100..]);
        ulong modified = BinaryPrimitives.ReadUInt64LittleEndian(e[108..]);
        uint startSector = BinaryPrimitives.ReadUInt32LittleEndian(e[116..]);
        ulong streamLen = BinaryPrimitives.ReadUInt64LittleEndian(e[120..]);
        if (version == CfbVersion.V3)
        {
            streamLen &= 0xFFFF_FFFF;
        }

        if (type == CfbObjectType.Stream)
        {
            clsid = new byte[16];
            created = 0;
            modified = 0;
        }
        else if (type == CfbObjectType.Storage)
        {
            startSector = 0;
            streamLen = 0;
        }

        return new CfbDirEntry(id)
        {
            Name = name,
            Type = type,
            Color = color,
            LeftSibling = left,
            RightSibling = right,
            Child = child,
            ClsidLe = clsid,
            StateBits = stateBits,
            CreationTime = created,
            ModifiedTime = modified,
            StartSector = startSector,
            StreamLength = streamLen,
        };
    }

    private static bool IsWellFormedUtf16(ReadOnlySpan<char> chars)
    {
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= chars.Length || !char.IsLowSurrogate(chars[i + 1]))
                {
                    return false;
                }

                i++;
            }
            else if (char.IsLowSurrogate(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Rust <c>cfb::internal::path::validate_name</c>.</summary>
    internal static void ValidateName(string name)
    {
        if (name.Length > 31)
        {
            throw Error($"Object name cannot be more than 31 UTF-16 code units (was {name.Length})");
        }

        foreach (char c in "/\\:!")
        {
            if (name.Contains(c, StringComparison.Ordinal))
            {
                throw Error($"Object name cannot contain {c} character");
            }
        }
    }

    private void ValidateAllocator()
    {
        if (_fat.Count > _numSectors)
        {
            throw Error($"Malformed FAT (FAT has {_fat.Count} entries, but file has only {_numSectors} sectors)");
        }

        foreach (uint difatSector in _difatSectorIds)
        {
            if (difatSector >= _fat.Count)
            {
                throw Error(
                    $"Malformed FAT (FAT has {_fat.Count} entries, but DIFAT lists {difatSector} as a DIFAT sector)");
            }

            _fat[(int)difatSector] = DifatSector;
        }

        foreach (uint fatSector in _difat)
        {
            if (fatSector >= _fat.Count)
            {
                throw Error($"Malformed FAT (FAT has {_fat.Count} entries, but DIFAT lists {fatSector} as a FAT sector)");
            }

            _fat[(int)fatSector] = FatSector;
        }

        var pointees = new HashSet<uint>();
        for (int from = 0; from < _fat.Count; from++)
        {
            uint to = _fat[from];
            if (to <= MaxRegularSector)
            {
                if (to >= _fat.Count)
                {
                    throw Error($"Malformed FAT (FAT has {_fat.Count} entries, but sector {from} points to {to})");
                }

                if (!pointees.Add(to))
                {
                    throw Error($"Malformed FAT (sector {to} pointed to twice)");
                }
            }
            else if (to == InvalidSector)
            {
                throw Error($"Malformed FAT (0x{to:X8} is not a valid FAT entry)");
            }
        }

        _freeSectors.Clear();
        for (int i = 0; i < _fat.Count; i++)
        {
            if (_fat[i] == FreeSector)
            {
                _freeSectors.Add((uint)i);
            }
        }
    }

    private void ValidateDirectory()
    {
        if (_dirEntries.Count == 0)
        {
            throw Error("Malformed directory (root entry is missing)");
        }

        var root = Root;
        if (root.StreamLength % MiniSectorLen != 0)
        {
            throw Error(
                $"Malformed directory (root stream len is {root.StreamLength}, but should be multiple of {MiniSectorLen})");
        }

        var visited = new HashSet<uint>();
        var stack = new Stack<uint>();
        stack.Push(0);
        while (stack.Count > 0)
        {
            uint id = stack.Pop();
            if (!visited.Add(id))
            {
                throw Error("Malformed directory (loop in tree)");
            }

            var entry = _dirEntries[(int)id];
            if (id == 0)
            {
                if (entry.Type != CfbObjectType.Root)
                {
                    throw Error($"Malformed directory (root entry has object type {entry.Type})");
                }
            }
            else if (entry.Type is not (CfbObjectType.Storage or CfbObjectType.Stream))
            {
                throw Error($"Malformed directory (non-root entry with object type {entry.Type})");
            }

            if (entry.LeftSibling != NoStream)
            {
                if (entry.LeftSibling >= _dirEntries.Count)
                {
                    throw Error(
                        $"Malformed directory (left sibling index is {entry.LeftSibling}, but directory entry count is {_dirEntries.Count})");
                }

                var sibling = _dirEntries[(int)entry.LeftSibling];
                if (CompareNames(sibling.Name, entry.Name) >= 0)
                {
                    throw Error($"Malformed directory (name ordering, {Debug(entry.Name)} vs {Debug(sibling.Name)})");
                }

                stack.Push(entry.LeftSibling);
            }

            if (entry.RightSibling != NoStream)
            {
                if (entry.RightSibling >= _dirEntries.Count)
                {
                    throw Error(
                        $"Malformed directory (right sibling index is {entry.RightSibling}, but directory entry count is {_dirEntries.Count})");
                }

                var sibling = _dirEntries[(int)entry.RightSibling];
                if (CompareNames(entry.Name, sibling.Name) >= 0)
                {
                    throw Error($"Malformed directory (name ordering, {Debug(entry.Name)} vs {Debug(sibling.Name)})");
                }

                stack.Push(entry.RightSibling);
            }

            if (entry.Child != NoStream)
            {
                if (entry.Child >= _dirEntries.Count)
                {
                    throw Error(
                        $"Malformed directory (child index is {entry.Child}, but directory entry count is {_dirEntries.Count})");
                }

                stack.Push(entry.Child);
            }
        }
    }

    private static string Debug(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            if (c is '"' or '\\')
            {
                sb.Append('\\').Append(c);
            }
            else if (char.IsControl(c))
            {
                sb.Append("\\u{").Append(((int)c).ToString("x", CultureInfo.InvariantCulture)).Append('}');
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.Append('"').ToString();
    }

    private void ValidateMiniAllocator()
    {
        ulong rootStreamMiniSectors = Root.StreamLength / MiniSectorLen;
        if (rootStreamMiniSectors < (ulong)_minifat.Count)
        {
            _minifat.RemoveRange((int)rootStreamMiniSectors, _minifat.Count - (int)rootStreamMiniSectors);
        }

        var pointees = new HashSet<uint>();
        for (int from = 0; from < _minifat.Count; from++)
        {
            uint to = _minifat[from];
            if (to <= MaxRegularSector)
            {
                if (to >= _minifat.Count)
                {
                    throw Error(
                        $"Malformed MiniFAT (MiniFAT has {_minifat.Count} entries, but mini sector {from} points to {to})");
                }

                if (!pointees.Add(to))
                {
                    throw Error($"Malformed MiniFAT (mini sector {to} pointed to twice)");
                }
            }
        }

        _freeMiniSectors.Clear();
        for (int i = 0; i < _minifat.Count; i++)
        {
            if (_minifat[i] == FreeSector)
            {
                _freeMiniSectors.Add((uint)i);
            }
        }
    }

    // ------------------------------------------------------------------ create

    /// <summary>Create a new, empty compound file (Rust <c>CompoundFile::create_with_version</c>).</summary>
    public static CfbFile Create(CfbVersion version = CfbVersion.V3)
    {
        int sectorLen = SectorLenOf(version);
        var data = new byte[3 * sectorLen];
        var h = data.AsSpan();
        MagicNumber.CopyTo(h);
        BinaryPrimitives.WriteUInt16LittleEndian(h[24..], 0x3E);
        BinaryPrimitives.WriteUInt16LittleEndian(h[26..], (ushort)version);
        BinaryPrimitives.WriteUInt16LittleEndian(h[28..], 0xFFFE);
        BinaryPrimitives.WriteUInt16LittleEndian(h[30..], (ushort)(version == CfbVersion.V3 ? 9 : 12));
        BinaryPrimitives.WriteUInt16LittleEndian(h[32..], 6);
        BinaryPrimitives.WriteUInt32LittleEndian(h[40..], version == CfbVersion.V3 ? 0u : 1u);
        BinaryPrimitives.WriteUInt32LittleEndian(h[44..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(h[48..], 1);
        BinaryPrimitives.WriteUInt32LittleEndian(h[52..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(h[56..], MiniStreamCutoff);
        BinaryPrimitives.WriteUInt32LittleEndian(h[60..], EndOfChain);
        BinaryPrimitives.WriteUInt32LittleEndian(h[64..], 0);
        BinaryPrimitives.WriteUInt32LittleEndian(h[68..], EndOfChain);
        BinaryPrimitives.WriteUInt32LittleEndian(h[72..], 0);
        for (int i = 0; i < NumDifatEntriesInHeader; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(h[(76 + (4 * i))..], i == 0 ? 0u : FreeSector);
        }

        // FAT sector.
        var fatSector = h.Slice(sectorLen, sectorLen);
        fatSector.Fill(0xFF);
        BinaryPrimitives.WriteUInt32LittleEndian(fatSector, FatSector);
        BinaryPrimitives.WriteUInt32LittleEndian(fatSector[4..], EndOfChain);

        // Directory sector.
        var root = CfbDirEntry.New(0, RootDirName, CfbObjectType.Root, 0);
        root.StartSector = EndOfChain;
        root.WriteTo(h.Slice(2 * sectorLen, DirEntryLen));
        for (int i = 1; i < sectorLen / DirEntryLen; i++)
        {
            CfbDirEntry.Unallocated(i).WriteTo(h.Slice((2 * sectorLen) + (i * DirEntryLen), DirEntryLen));
        }

        var file = new CfbFile(data, data.Length, version, 2, [], [0], [FatSector, EndOfChain], [root], 1, [], EndOfChain);
        file.ValidateAllocator();
        file.ValidateDirectory();
        file.ValidateMiniAllocator();
        return file;
    }

    // ------------------------------------------------------------------ Allocator

    private uint Next(uint sectorId)
    {
        if (sectorId >= _fat.Count)
        {
            throw Error($"Found reference to sector {sectorId}, but FAT has only {_fat.Count} entries");
        }

        uint next = _fat[(int)sectorId];
        if (next != EndOfChain && (next > MaxRegularSector || next >= _fat.Count))
        {
            throw Error($"next_id ({next}) is invalid");
        }

        return next;
    }

    /// <summary>Rust <c>Chain::new</c> sector list.</summary>
    private List<uint> ChainSectors(uint start)
    {
        var ids = new List<uint>();
        uint current = start;
        while (current != EndOfChain)
        {
            ids.Add(current);
            current = Next(current);
            if (current == start)
            {
                throw Error($"Chain contained duplicate sector id {current}");
            }
        }

        return ids;
    }

    private uint BeginChain(SectorInit init) => AllocateSector(init);

    private uint ExtendChain(uint startSectorId, SectorInit init)
    {
        uint last = startSectorId;
        while (true)
        {
            uint next = _fat[(int)last];
            if (next == EndOfChain)
            {
                break;
            }

            last = next;
        }

        uint newSector = AllocateSector(init);
        SetFat(last, newSector);
        return newSector;
    }

    private uint AllocateSector(SectorInit init)
    {
        if (_freeSectors.Count > 0)
        {
            uint sectorId = _freeSectors[^1];
            _freeSectors.RemoveAt(_freeSectors.Count - 1);
            SetFat(sectorId, EndOfChain);
            InitSector(sectorId, init);
            return sectorId;
        }

        int fatEntriesPerSector = _sectorLen / 4;
        if (_fat.Count % fatEntriesPerSector == 0)
        {
            AppendFatSector();
        }

        uint newSector = (uint)_fat.Count;
        SetFat(newSector, EndOfChain);
        InitSector(newSector, init);
        return newSector;
    }

    private void AppendFatSector()
    {
        uint newFatSectorId = (uint)_fat.Count;
        InitSector(newFatSectorId, SectorInit.Fat);
        int difatIndex = _difat.Count;
        _difat.Add(newFatSectorId);
        SetFat(newFatSectorId, FatSector);

        if (difatIndex < NumDifatEntriesInHeader)
        {
            WriteU32At(76 + (4L * difatIndex), newFatSectorId);
        }
        else
        {
            int difatEntriesPerSector = (_sectorLen - 4) / 4;
            int difatSectorIndex = (difatIndex - NumDifatEntriesInHeader) / difatEntriesPerSector;
            if (difatSectorIndex >= _difatSectorIds.Count)
            {
                uint newDifatSectorId = (uint)_fat.Count;
                InitSector(newDifatSectorId, SectorInit.Difat);
                SetFat(newDifatSectorId, DifatSector);
                if (_difatSectorIds.Count > 0)
                {
                    WriteU32At(SectorOffset(_difatSectorIds[^1], _sectorLen - 4), newDifatSectorId);
                }

                _difatSectorIds.Add(newDifatSectorId);
                WriteU32At(68, _difatSectorIds[0]);
                WriteU32At(72, (uint)_difatSectorIds.Count);
            }

            uint difatSectorId = _difatSectorIds[difatSectorIndex];
            int indexWithin = difatIndex - NumDifatEntriesInHeader - (difatSectorIndex * difatEntriesPerSector);
            WriteU32At(SectorOffset(difatSectorId, 4L * indexWithin), newFatSectorId);
        }

        WriteU32At(44, (uint)_difat.Count);
    }

    private void FreeChainAfter(uint sectorId)
    {
        uint next = Next(sectorId);
        SetFat(sectorId, EndOfChain);
        FreeChain(next);
    }

    private void FreeChain(uint startSectorId)
    {
        uint sectorId = startSectorId;
        while (sectorId != EndOfChain)
        {
            uint next = Next(sectorId);
            FreeSectorAt(sectorId);
            sectorId = next;
        }
    }

    private void FreeSectorAt(uint sectorId)
    {
        if (sectorId < _fat.Count && _fat[(int)sectorId] == FreeSector)
        {
            throw Error($"sector {sectorId} freed twice");
        }

        SetFat(sectorId, FreeSector);
        _freeSectors.Add(sectorId);
    }

    private void SetFat(uint index, uint value)
    {
        int fatEntriesPerSector = _sectorLen / 4;
        uint fatSectorId = _difat[(int)(index / fatEntriesPerSector)];
        WriteU32At(SectorOffset(fatSectorId, 4L * (index % fatEntriesPerSector)), value);
        if (index == _fat.Count)
        {
            _fat.Add(value);
        }
        else
        {
            _fat[(int)index] = value;
        }
    }

    /// <summary>Rust <c>Chain</c>: a cursor over a FAT sector chain.</summary>
    private sealed class Chain
    {
        private readonly CfbFile _f;
        private readonly SectorInit _init;
        private readonly List<uint> _sectorIds;
        private long _offset;

        public Chain(CfbFile f, uint start, SectorInit init)
        {
            _f = f;
            _init = init;
            _sectorIds = f.ChainSectors(start);
        }

        public uint StartSectorId => _sectorIds.Count > 0 ? _sectorIds[0] : EndOfChain;

        public int NumSectors => _sectorIds.Count;

        public long Len => (long)_f._sectorLen * _sectorIds.Count;

        public void Seek(long offset)
        {
            if (offset < 0 || offset > Len)
            {
                throw Error($"Cannot seek to {offset}, chain length is {Len} bytes");
            }

            _offset = offset;
        }

        public void SetLen(long newLen)
        {
            long sectorLen = _f._sectorLen;
            int newNumSectors = (int)((sectorLen + newLen - 1) / sectorLen);
            if (newNumSectors == 0)
            {
                if (_sectorIds.Count > 0)
                {
                    _f.FreeChain(_sectorIds[0]);
                }
            }
            else if (newNumSectors <= _sectorIds.Count)
            {
                if (newNumSectors < _sectorIds.Count)
                {
                    _f.FreeChainAfter(_sectorIds[newNumSectors - 1]);
                }
            }
            else
            {
                for (int i = _sectorIds.Count; i < newNumSectors; i++)
                {
                    _sectorIds.Add(_sectorIds.Count > 0 ? _f.ExtendChain(_sectorIds[^1], _init) : _f.BeginChain(_init));
                }
            }
        }

        public void Free() => _f.FreeChain(StartSectorId);

        /// <summary><c>write_all</c>.</summary>
        public void WriteAll(ReadOnlySpan<byte> buf)
        {
            long sectorLen = _f._sectorLen;
            while (!buf.IsEmpty)
            {
                if (_offset == Len)
                {
                    _sectorIds.Add(_sectorIds.Count > 0 ? _f.ExtendChain(_sectorIds[^1], _init) : _f.BeginChain(_init));
                }

                uint sector = _sectorIds[(int)(_offset / sectorLen)];
                long within = _offset % sectorLen;
                int n = (int)Math.Min(buf.Length, sectorLen - within);
                _f.WriteAt(_f.SectorOffset(sector, within), buf[..n]);
                _offset += n;
                buf = buf[n..];
            }
        }

        /// <summary><c>read_exact</c>.</summary>
        public void ReadExact(Span<byte> buf)
        {
            long sectorLen = _f._sectorLen;
            while (!buf.IsEmpty)
            {
                if (_offset >= Len)
                {
                    throw Error("failed to fill whole buffer");
                }

                uint sector = _sectorIds[(int)(_offset / sectorLen)];
                long within = _offset % sectorLen;
                int n = (int)Math.Min(buf.Length, sectorLen - within);
                _f.ReadExactAt(_f.SectorOffset(sector, within), buf[..n]);
                _offset += n;
                buf = buf[n..];
            }
        }
    }

    // ------------------------------------------------------------------ MiniAllocator

    private uint NextMiniSector(uint sectorId)
    {
        if (sectorId >= _minifat.Count)
        {
            throw Error($"Found reference to mini sector {sectorId}, but MiniFAT has only {_minifat.Count} entries");
        }

        uint next = _minifat[(int)sectorId];
        if (next != EndOfChain && (next > MaxRegularSector || next >= _minifat.Count))
        {
            throw Error($"next_id ({next}) is invalid");
        }

        return next;
    }

    private List<uint> MiniChainSectors(uint start)
    {
        var ids = new List<uint>();
        uint current = start;
        while (current != EndOfChain)
        {
            ids.Add(current);
            current = NextMiniSector(current);
            if (current == start)
            {
                throw Error($"Minichain contained duplicate sector id {current}");
            }
        }

        return ids;
    }

    /// <summary>File offset of a byte inside a mini sector (Rust <c>seek_within_mini_sector</c>).</summary>
    private long MiniSectorOffset(uint miniSector, long offsetWithinMiniSector)
    {
        var rootChain = ChainSectors(Root.StartSector);
        int subsectorsPerSector = _sectorLen / MiniSectorLen;
        int sectorIndexWithinChain = (int)(miniSector / subsectorsPerSector);
        long subIndex = miniSector % subsectorsPerSector;
        if (sectorIndexWithinChain >= rootChain.Count)
        {
            throw Error("invalid sector id");
        }

        return SectorOffset(rootChain[sectorIndexWithinChain], (subIndex * MiniSectorLen) + offsetWithinMiniSector);
    }

    private uint BeginMiniChain() => AllocateMiniSector(EndOfChain);

    private uint ExtendMiniChain(uint startMiniSector)
    {
        uint last = startMiniSector;
        while (true)
        {
            uint next = _minifat[(int)last];
            if (next == EndOfChain)
            {
                break;
            }

            last = next;
        }

        uint newMini = AllocateMiniSector(EndOfChain);
        SetMinifat(last, newMini);
        return newMini;
    }

    private uint AllocateMiniSector(uint value)
    {
        while (_freeMiniSectors.Count > 0)
        {
            uint freeIdx = _freeMiniSectors[^1];
            _freeMiniSectors.RemoveAt(_freeMiniSectors.Count - 1);
            if (_minifat[(int)freeIdx] == FreeSector)
            {
                SetMinifat(freeIdx, value);
                return freeIdx;
            }
        }

        int minifatEntriesPerSector = _sectorLen / 4;
        if (_minifatStartSector == EndOfChain)
        {
            _minifatStartSector = BeginChain(SectorInit.Fat);
            WriteU32At(60, _minifatStartSector);
            WriteU32At(64, 1);
        }
        else if (_minifat.Count % minifatEntriesPerSector == 0)
        {
            uint start = _minifatStartSector;
            ExtendChain(start, SectorInit.Fat);
            uint numMinifatSectors = (uint)ChainSectors(start).Count;
            WriteU32At(64, numMinifatSectors);
        }

        uint newMini = (uint)_minifat.Count;
        SetMinifat(newMini, value);
        AppendMiniSector();
        return newMini;
    }

    private void AppendMiniSector()
    {
        uint miniStreamStart = Root.StartSector;
        ulong miniStreamLen = Root.StreamLength;
        uint newStart;
        if (miniStreamStart == EndOfChain)
        {
            newStart = BeginChain(SectorInit.Zero);
        }
        else
        {
            if (miniStreamLen % (ulong)_sectorLen == 0)
            {
                ExtendChain(miniStreamStart, SectorInit.Zero);
            }

            newStart = miniStreamStart;
        }

        WithDirEntryMut(0, e =>
        {
            e.StartSector = newStart;
            e.StreamLength += MiniSectorLen;
        });
    }

    private void FreeMiniSector(uint miniSector)
    {
        if (_minifat[(int)miniSector] == FreeSector)
        {
            throw Error($"sector {miniSector} freed twice");
        }

        SetMinifat(miniSector, FreeSector);
        _freeMiniSectors.Add(miniSector);
        ulong miniStreamLen = Root.StreamLength;
        while (_minifat.Count > 0 && _minifat[^1] == FreeSector)
        {
            miniStreamLen -= MiniSectorLen;
            _minifat.RemoveAt(_minifat.Count - 1);
        }

        int minifatLen = _minifat.Count;
        _freeMiniSectors.RemoveAll(idx => idx >= minifatLen);
        if (miniStreamLen != Root.StreamLength)
        {
            WithDirEntryMut(0, e => e.StreamLength = miniStreamLen);
        }
    }

    private void FreeMiniChain(uint startMiniSector)
    {
        uint mini = startMiniSector;
        while (mini != EndOfChain)
        {
            uint next = _minifat[(int)mini];
            FreeMiniSector(mini);
            mini = next;
        }
    }

    private void FreeMiniChainAfter(uint miniSector)
    {
        uint next = _minifat[(int)miniSector];
        SetMinifat(miniSector, EndOfChain);
        FreeMiniChain(next);
    }

    private void SetMinifat(uint index, uint value)
    {
        var chain = new Chain(this, _minifatStartSector, SectorInit.Fat);
        long offset = (long)index * 4;
        chain.Seek(offset);
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        chain.WriteAll(b);
        if (index == _minifat.Count)
        {
            _minifat.Add(value);
        }
        else
        {
            _minifat[(int)index] = value;
        }
    }

    /// <summary>Rust <c>MiniChain</c>: a cursor over a MiniFAT chain inside the mini stream.</summary>
    private sealed class MiniChain
    {
        private readonly CfbFile _f;
        private readonly List<uint> _sectorIds;
        private long _offset;

        public MiniChain(CfbFile f, uint start)
        {
            _f = f;
            _sectorIds = f.MiniChainSectors(start);
        }

        public uint StartSectorId => _sectorIds.Count > 0 ? _sectorIds[0] : EndOfChain;

        public long Len => (long)MiniSectorLen * _sectorIds.Count;

        public void Seek(long offset)
        {
            if (offset < 0 || offset > Len)
            {
                throw Error($"Cannot seek to {offset}, chain length is {Len} bytes");
            }

            _offset = offset;
        }

        public void SetLen(long newLen)
        {
            int newNumSectors = (int)((MiniSectorLen + newLen - 1) / MiniSectorLen);
            if (newNumSectors == 0)
            {
                if (_sectorIds.Count > 0)
                {
                    _f.FreeMiniChain(_sectorIds[0]);
                }
            }
            else if (newNumSectors <= _sectorIds.Count)
            {
                if (newNumSectors < _sectorIds.Count)
                {
                    _f.FreeMiniChainAfter(_sectorIds[newNumSectors - 1]);
                }
            }
            else
            {
                for (int i = _sectorIds.Count; i < newNumSectors; i++)
                {
                    _sectorIds.Add(_sectorIds.Count > 0 ? _f.ExtendMiniChain(_sectorIds[^1]) : _f.BeginMiniChain());
                }
            }
        }

        public void Free() => _f.FreeMiniChain(StartSectorId);

        public void WriteAll(ReadOnlySpan<byte> buf)
        {
            while (!buf.IsEmpty)
            {
                if (_offset == Len)
                {
                    _sectorIds.Add(_sectorIds.Count > 0 ? _f.ExtendMiniChain(_sectorIds[^1]) : _f.BeginMiniChain());
                }

                uint mini = _sectorIds[(int)(_offset / MiniSectorLen)];
                long within = _offset % MiniSectorLen;
                int n = (int)Math.Min(buf.Length, MiniSectorLen - within);
                _f.WriteAt(_f.MiniSectorOffset(mini, within), buf[..n]);
                _offset += n;
                buf = buf[n..];
            }
        }

        public void ReadExact(Span<byte> buf)
        {
            while (!buf.IsEmpty)
            {
                if (_offset >= Len)
                {
                    throw Error("failed to fill whole buffer");
                }

                uint mini = _sectorIds[(int)(_offset / MiniSectorLen)];
                long within = _offset % MiniSectorLen;
                int n = (int)Math.Min(buf.Length, MiniSectorLen - within);
                _f.ReadExactAt(_f.MiniSectorOffset(mini, within), buf[..n]);
                _offset += n;
                buf = buf[n..];
            }
        }
    }

    // ------------------------------------------------------------------ Directory

    /// <summary>Directory entry by stream id.</summary>
    public CfbDirEntry Entry(uint streamId)
    {
        if (streamId >= _dirEntries.Count)
        {
            throw Error($"invalid CFB stream id {streamId}");
        }

        return _dirEntries[(int)streamId];
    }

    /// <summary>Direct children of a storage in directory-tree (in-order) order (Rust <c>read_storage</c>).</summary>
    public List<CfbDirEntry> Children(CfbDirEntry storage)
    {
        var result = new List<CfbDirEntry>();
        var stack = new Stack<uint>();
        void LeftSpine(uint id)
        {
            while (id != NoStream)
            {
                stack.Push(id);
                id = Entry(id).LeftSibling;
            }
        }

        LeftSpine(storage.Child);
        while (stack.Count > 0)
        {
            var e = Entry(stack.Pop());
            LeftSpine(e.RightSibling);
            result.Add(e);
        }

        return result;
    }

    /// <summary>Look up a direct child by name with the CFB ordering (Rust <c>stream_id_for_name_chain</c>).</summary>
    public CfbDirEntry? FindChild(CfbDirEntry storage, string name)
    {
        uint id = storage.Child;
        while (id != NoStream)
        {
            var e = Entry(id);
            int c = CompareNames(name, e.Name);
            if (c == 0)
            {
                return e;
            }

            id = c < 0 ? e.LeftSibling : e.RightSibling;
        }

        return null;
    }

    /// <summary>
    /// CFB name ordering: shorter (in UTF-16 code units) first, then case-insensitive (Rust
    /// <c>cfb::internal::path::compare_names</c>).
    /// </summary>
    internal static int CompareNames(string name1, string name2)
    {
        if (System.Text.Ascii.IsValid(name1) && System.Text.Ascii.IsValid(name2))
        {
            int byLen = name1.Length.CompareTo(name2.Length);
            if (byLen != 0)
            {
                return byLen;
            }

            for (int i = 0; i < name1.Length; i++)
            {
                int l = char.ToUpperInvariant(name1[i]);
                int r = char.ToUpperInvariant(name2[i]);
                if (l != r)
                {
                    return l.CompareTo(r);
                }
            }

            return 0;
        }

        int lenCmp = name1.Length.CompareTo(name2.Length);
        if (lenCmp != 0)
        {
            return lenCmp;
        }

        var e1 = name1.EnumerateRunes();
        var e2 = name2.EnumerateRunes();
        while (true)
        {
            bool has1 = e1.MoveNext();
            bool has2 = e2.MoveNext();
            if (!has1 || !has2)
            {
                return has1.CompareTo(has2);
            }

            int c = Rune.ToUpperInvariant(e1.Current).Value.CompareTo(Rune.ToUpperInvariant(e2.Current).Value);
            if (c != 0)
            {
                return c;
            }
        }
    }

    private long DirEntryOffset(uint streamId, int offsetWithinEntry)
    {
        uint perSector = (uint)DirEntriesPerSector;
        uint indexWithinSector = streamId % perSector;
        uint dirSector = _dirStartSector;
        for (uint i = 0; i < streamId / perSector; i++)
        {
            dirSector = Next(dirSector);
        }

        return SectorOffset(dirSector, ((long)indexWithinSector * DirEntryLen) + offsetWithinEntry);
    }

    private uint InsertDirEntry(uint parentId, string name, CfbObjectType type, ulong timestamp)
    {
        uint streamId = AllocateDirEntry();
        _dirEntries[(int)streamId] = CfbDirEntry.New((int)streamId, name, type, timestamp);

        uint siblingId = _dirEntries[(int)parentId].Child;
        uint prevSiblingId = parentId;
        int ordering = 0;
        while (siblingId != NoStream)
        {
            var sibling = _dirEntries[(int)siblingId];
            prevSiblingId = siblingId;
            ordering = CompareNames(name, sibling.Name);
            siblingId = ordering switch
            {
                < 0 => sibling.LeftSibling,
                > 0 => sibling.RightSibling,
                _ => throw new InvalidOperationException("internal error: insert duplicate"),
            };
        }

        if (ordering < 0)
        {
            _dirEntries[(int)prevSiblingId].LeftSibling = streamId;
            WriteU32At(DirEntryOffset(prevSiblingId, 68), streamId);
        }
        else if (ordering > 0)
        {
            _dirEntries[(int)prevSiblingId].RightSibling = streamId;
            WriteU32At(DirEntryOffset(prevSiblingId, 72), streamId);
        }
        else
        {
            _dirEntries[(int)parentId].Child = streamId;
            WriteU32At(DirEntryOffset(parentId, 76), streamId);
        }

        WriteDirEntry(streamId);
        return streamId;
    }

    private uint AllocateDirEntry()
    {
        for (int i = 0; i < _dirEntries.Count; i++)
        {
            if (_dirEntries[i].Type == CfbObjectType.Unallocated)
            {
                return (uint)i;
            }
        }

        if (_dirEntries.Count % DirEntriesPerSector == 0)
        {
            ExtendChain(_dirStartSector, SectorInit.Dir);
            if (Version == CfbVersion.V4)
            {
                WriteU32At(40, (uint)ChainSectors(_dirStartSector).Count);
            }
        }

        uint streamId = (uint)_dirEntries.Count;
        _dirEntries.Add(CfbDirEntry.Unallocated((int)streamId));
        return streamId;
    }

    private void WithDirEntryMut(uint streamId, Action<CfbDirEntry> func)
    {
        func(_dirEntries[(int)streamId]);
        WriteDirEntry(streamId);
    }

    private void WriteDirEntry(uint streamId)
    {
        var chain = new Chain(this, _dirStartSector, SectorInit.Dir);
        chain.Seek((long)DirEntryLen * streamId);
        var buf = new byte[DirEntryLen];
        _dirEntries[(int)streamId].WriteTo(buf);
        chain.WriteAll(buf);
    }

    // ------------------------------------------------------------------ public mutations

    /// <summary>Create a storage under <paramref name="parent"/> (Rust <c>create_storage</c>).</summary>
    /// <param name="parent">Parent storage (root or nested storage).</param>
    /// <param name="name">Storage name.</param>
    /// <param name="timestamp">Creation / modification FILETIME (Rust uses <c>Timestamp::now()</c>).</param>
    public CfbDirEntry CreateStorage(CfbDirEntry parent, string name, ulong? timestamp = null)
    {
        ValidateName(name);
        if (FindChild(parent, name) is { } existing)
        {
            throw Error(existing.IsStream
                ? $"Cannot create storage at {Debug(name)} because a stream already exists there"
                : $"Cannot create storage at {Debug(name)} because a storage already exists there");
        }

        ulong ts = timestamp ?? (ulong)DateTime.UtcNow.ToFileTimeUtc();
        return Entry(InsertDirEntry((uint)parent.Id, name, CfbObjectType.Storage, ts));
    }

    /// <summary>
    /// Create (or truncate and replace) the stream <paramref name="name"/> under <paramref name="parent"/> and write
    /// <paramref name="content"/> into it: Rust <c>create_stream</c> followed by <c>write_all</c> and dropping the
    /// <c>Stream</c> (whose buffer reaches the file in <see cref="StreamMaxBufferSize"/> chunks).
    /// </summary>
    public CfbDirEntry CreateStream(CfbDirEntry parent, string name, ReadOnlySpan<byte> content)
    {
        ValidateName(name);
        uint streamId;
        if (FindChild(parent, name) is { } existing)
        {
            if (!existing.IsStream)
            {
                throw Error($"Cannot create stream at {Debug(name)} because a storage already exists there");
            }

            streamId = (uint)existing.Id;
            if (existing.StreamLength != 0)
            {
                ResizeStream(streamId, 0);
            }
        }
        else
        {
            streamId = InsertDirEntry((uint)parent.Id, name, CfbObjectType.Stream, 0);
        }

        for (int offset = 0; offset < content.Length; offset += StreamMaxBufferSize)
        {
            int n = Math.Min(StreamMaxBufferSize, content.Length - offset);
            WriteDataToStream(streamId, (ulong)offset, content.Slice(offset, n));
        }

        return Entry(streamId);
    }

    /// <summary>Root-storage convenience for <see cref="CreateStream(CfbDirEntry, string, ReadOnlySpan{byte})"/>.</summary>
    public CfbDirEntry CreateStream(string name, ReadOnlySpan<byte> content) => CreateStream(Root, name, content);

    /// <summary>
    /// Set the creation and modification FILETIMEs of a storage (Rust <c>set_created_time</c> /
    /// <c>set_modified_time</c>; no effect on streams).
    /// </summary>
    public void SetStorageTimes(CfbDirEntry entry, ulong created, ulong modified)
    {
        WithDirEntryMut((uint)entry.Id, e =>
        {
            if (e.Type != CfbObjectType.Stream)
            {
                e.CreationTime = created;
                e.ModifiedTime = modified;
            }
        });
    }

    // ------------------------------------------------------------------ stream data

    /// <summary>Read the whole content of a stream (Rust <c>open_stream</c> + <c>read_to_end</c>).</summary>
    public byte[] ReadStream(CfbDirEntry entry)
    {
        if (!entry.IsStream)
        {
            throw Error($"Not a stream: {Debug(entry.Name)}");
        }

        ulong len = entry.StreamLength;
        if (len > int.MaxValue)
        {
            throw Error($"stream {Debug(entry.Name)} is too large");
        }

        if (len == 0)
        {
            return [];
        }

        // Walk (and validate) the sector chain before allocating: the declared length is untrusted, and a chain
        // shorter than it fails exactly like the Rust read does once it runs past the last sector.
        if (len < MiniStreamCutoff)
        {
            var miniChain = new MiniChain(this, entry.StartSector);
            if ((long)len > miniChain.Len)
            {
                throw Error("failed to fill whole buffer");
            }

            var miniBuf = new byte[len];
            miniChain.ReadExact(miniBuf);
            return miniBuf;
        }

        var chain = new Chain(this, entry.StartSector, SectorInit.Zero);
        if ((long)len > chain.Len)
        {
            throw Error("failed to fill whole buffer");
        }

        var buf = new byte[len];
        chain.ReadExact(buf);
        return buf;
    }

    /// <summary>Rust <c>write_data_to_stream</c>.</summary>
    private void WriteDataToStream(uint streamId, ulong bufOffsetFromStart, ReadOnlySpan<byte> buf)
    {
        var dirEntry = _dirEntries[(int)streamId];
        uint oldStartSector = dirEntry.StartSector;
        ulong oldStreamLen = dirEntry.StreamLength;
        ulong newStreamLen = Math.Max(oldStreamLen, bufOffsetFromStart + (ulong)buf.Length);
        uint newStartSector;
        if (oldStartSector == EndOfChain)
        {
            if (newStreamLen < MiniStreamCutoff)
            {
                var chain = new MiniChain(this, EndOfChain);
                chain.WriteAll(buf);
                newStartSector = chain.StartSectorId;
            }
            else
            {
                var chain = new Chain(this, EndOfChain, SectorInit.Zero);
                chain.WriteAll(buf);
                newStartSector = chain.StartSectorId;
            }
        }
        else if (oldStreamLen < MiniStreamCutoff)
        {
            if (newStreamLen < MiniStreamCutoff)
            {
                var chain = new MiniChain(this, oldStartSector);
                chain.Seek((long)bufOffsetFromStart);
                chain.WriteAll(buf);
                newStartSector = oldStartSector;
            }
            else
            {
                var tmp = new byte[bufOffsetFromStart];
                var mini = new MiniChain(this, oldStartSector);
                mini.ReadExact(tmp);
                mini.Free();
                var chain = new Chain(this, EndOfChain, SectorInit.Zero);
                chain.WriteAll(tmp);
                chain.WriteAll(buf);
                newStartSector = chain.StartSectorId;
            }
        }
        else
        {
            var chain = new Chain(this, oldStartSector, SectorInit.Zero);
            chain.Seek((long)bufOffsetFromStart);
            chain.WriteAll(buf);
            newStartSector = oldStartSector;
        }

        WithDirEntryMut(streamId, e =>
        {
            e.StartSector = newStartSector;
            e.StreamLength = newStreamLen;
        });
    }

    /// <summary>Rust <c>resize_stream</c>.</summary>
    private void ResizeStream(uint streamId, ulong newStreamLen)
    {
        var dirEntry = _dirEntries[(int)streamId];
        uint oldStartSector = dirEntry.StartSector;
        ulong oldStreamLen = dirEntry.StreamLength;
        uint newStartSector;
        if (oldStartSector == EndOfChain)
        {
            if (newStreamLen < MiniStreamCutoff)
            {
                var chain = new MiniChain(this, EndOfChain);
                chain.SetLen((long)newStreamLen);
                newStartSector = chain.StartSectorId;
            }
            else
            {
                var chain = new Chain(this, EndOfChain, SectorInit.Zero);
                chain.SetLen((long)newStreamLen);
                newStartSector = chain.StartSectorId;
            }
        }
        else if (oldStreamLen < MiniStreamCutoff)
        {
            if (newStreamLen == 0)
            {
                FreeMiniChain(oldStartSector);
                newStartSector = EndOfChain;
            }
            else if (newStreamLen < MiniStreamCutoff)
            {
                new MiniChain(this, oldStartSector).SetLen((long)newStreamLen);
                newStartSector = oldStartSector;
            }
            else
            {
                var tmp = new byte[oldStreamLen];
                var mini = new MiniChain(this, oldStartSector);
                mini.ReadExact(tmp);
                mini.Free();
                var chain = new Chain(this, EndOfChain, SectorInit.Zero);
                chain.WriteAll(tmp);
                chain.SetLen((long)newStreamLen);
                newStartSector = chain.StartSectorId;
            }
        }
        else
        {
            if (newStreamLen == 0)
            {
                FreeChain(oldStartSector);
                newStartSector = EndOfChain;
            }
            else if (newStreamLen < MiniStreamCutoff)
            {
                var tmp = new byte[newStreamLen];
                var chain = new Chain(this, oldStartSector, SectorInit.Zero);
                chain.ReadExact(tmp);
                chain.Free();
                var mini = new MiniChain(this, EndOfChain);
                mini.WriteAll(tmp);
                newStartSector = mini.StartSectorId;
            }
            else
            {
                new Chain(this, oldStartSector, SectorInit.Zero).SetLen((long)newStreamLen);
                newStartSector = oldStartSector;
            }
        }

        WithDirEntryMut(streamId, e =>
        {
            e.StartSector = newStartSector;
            e.StreamLength = newStreamLen;
        });
    }
}
