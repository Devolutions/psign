using System.Buffers.Binary;

namespace Devolutions.Psign.Core.Msi;

/// <summary>Compound-file object type (MS-CFB §2.6.1).</summary>
internal enum CfbObjectType : byte
{
    Unallocated = 0,
    Storage = 1,
    Stream = 2,
    Root = 5,
}

/// <summary>
/// One compound-file directory entry with the fields the Rust <c>cfb</c> crate's <c>Entry</c> exposes (name, CLSID bytes,
/// state bits, FILETIMEs, stream length). Stream CLSIDs and timestamps are normalized to zero like <c>cfb</c>'s
/// permissive validation does.
/// </summary>
internal sealed record CfbDirEntry(
    int Id,
    string Name,
    CfbObjectType Type,
    uint LeftSibling,
    uint RightSibling,
    uint Child,
    byte[] ClsidLe,
    uint StateBits,
    ulong CreationTime,
    ulong ModifiedTime,
    ulong StreamLength)
{
    public bool IsRoot => Type == CfbObjectType.Root;

    public bool IsStorage => Type == CfbObjectType.Storage;

    public bool IsStream => Type == CfbObjectType.Stream;
}

/// <summary>
/// Read-only MS-CFB directory parser. <c>OpenMcdf</c> does not expose stream state bits or raw FILETIMEs, which the
/// Windows Installer SIP metadata pre-hash covers, so the directory is decoded here; stream contents are read through
/// <c>OpenMcdf</c>.
/// </summary>
internal sealed class CfbDirectory
{
    private const uint MaxRegularSector = 0xFFFF_FFFA;
    private const uint EndOfChain = 0xFFFF_FFFE;
    private const uint FreeSector = 0xFFFF_FFFF;
    private const uint NoStream = 0xFFFF_FFFF;
    private const uint MaxRegularStreamId = 0xFFFF_FFFA;

    private static ReadOnlySpan<byte> Signature => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    private readonly List<CfbDirEntry> _entries;

    private CfbDirectory(List<CfbDirEntry> entries) => _entries = entries;

    /// <summary>The root storage entry (stream id 0).</summary>
    public CfbDirEntry Root => _entries[0];

    /// <summary>Parse the header, FAT and directory chain of <paramref name="data"/>.</summary>
    public static CfbDirectory Parse(ReadOnlySpan<byte> data)
    {
        // Messages follow the Rust `cfb` crate (`{} bytes is too small`, `wrong magic number: {:x?}`).
        if (data.Length < 512)
        {
            throw new PsignException($"Invalid CFB file ({data.Length} bytes is too small)");
        }

        if (!data[..8].SequenceEqual(Signature))
        {
            var magic = new string[8];
            for (int i = 0; i < 8; i++)
            {
                magic[i] = data[i].ToString("x", System.Globalization.CultureInfo.InvariantCulture);
            }

            throw new PsignException($"Invalid CFB file (wrong magic number): [{string.Join(", ", magic)}]");
        }

        ushort major = BinaryPrimitives.ReadUInt16LittleEndian(data[0x1A..]);
        ushort sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(data[0x1E..]);
        bool v4;
        if (major == 3 && sectorShift == 9)
        {
            v4 = false;
        }
        else if (major == 4 && sectorShift == 12)
        {
            v4 = true;
        }
        else
        {
            throw new PsignException($"unsupported CFB version {major} / sector shift {sectorShift}");
        }

        int sectorSize = 1 << sectorShift;
        uint firstDirSector = BinaryPrimitives.ReadUInt32LittleEndian(data[0x30..]);
        uint numFatSectors = BinaryPrimitives.ReadUInt32LittleEndian(data[0x2C..]);
        uint firstDifatSector = BinaryPrimitives.ReadUInt32LittleEndian(data[0x44..]);
        uint numDifatSectors = BinaryPrimitives.ReadUInt32LittleEndian(data[0x48..]);
        long maxSectors = (data.Length + (long)sectorSize - 1) / sectorSize;

        byte[] ReadSector(ReadOnlySpan<byte> d, uint id)
        {
            if (id > MaxRegularSector)
            {
                throw new PsignException($"invalid CFB sector id {id}");
            }

            long offset = ((long)id + 1) << sectorShift;
            if (offset >= d.Length)
            {
                throw new PsignException($"CFB sector {id} is past end of file");
            }

            var sector = new byte[sectorSize];
            int available = (int)Math.Min(sectorSize, d.Length - offset);
            d.Slice((int)offset, available).CopyTo(sector);
            return sector;
        }

        // DIFAT: 109 header entries, then the DIFAT sector chain.
        var fatSectorIds = new List<uint>();
        for (int i = 0; i < 109; i++)
        {
            uint id = BinaryPrimitives.ReadUInt32LittleEndian(data[(0x4C + (i * 4))..]);
            if (id == FreeSector)
            {
                continue;
            }

            fatSectorIds.Add(id);
        }

        uint difat = firstDifatSector;
        int perDifat = (sectorSize / 4) - 1;
        long guard = 0;
        while (difat != EndOfChain && difat != FreeSector && guard++ < Math.Max(numDifatSectors, maxSectors))
        {
            var sector = ReadSector(data, difat);
            for (int i = 0; i < perDifat; i++)
            {
                uint id = BinaryPrimitives.ReadUInt32LittleEndian(sector.AsSpan(i * 4));
                if (id != FreeSector)
                {
                    fatSectorIds.Add(id);
                }
            }

            difat = BinaryPrimitives.ReadUInt32LittleEndian(sector.AsSpan(perDifat * 4));
        }

        if (fatSectorIds.Count > numFatSectors && numFatSectors > 0)
        {
            fatSectorIds.RemoveRange((int)numFatSectors, fatSectorIds.Count - (int)numFatSectors);
        }

        var fat = new List<uint>(fatSectorIds.Count * (sectorSize / 4));
        foreach (var id in fatSectorIds)
        {
            var sector = ReadSector(data, id);
            for (int i = 0; i < sectorSize; i += 4)
            {
                fat.Add(BinaryPrimitives.ReadUInt32LittleEndian(sector.AsSpan(i)));
            }
        }

        // Directory chain.
        var entries = new List<CfbDirEntry>();
        uint dirSector = firstDirSector;
        var visited = new HashSet<uint>();
        while (dirSector != EndOfChain)
        {
            if (!visited.Add(dirSector))
            {
                throw new PsignException("CFB directory chain contains a loop");
            }

            var sector = ReadSector(data, dirSector);
            for (int off = 0; off + 128 <= sectorSize; off += 128)
            {
                entries.Add(ParseEntry(sector.AsSpan(off, 128), entries.Count, v4));
            }

            if (dirSector >= fat.Count)
            {
                throw new PsignException($"CFB directory sector {dirSector} is outside the FAT");
            }

            dirSector = fat[(int)dirSector];
        }

        if (entries.Count == 0 || entries[0].Type != CfbObjectType.Root)
        {
            throw new PsignException("CFB root directory entry is missing");
        }

        return new CfbDirectory(entries);
    }

    private static CfbDirEntry ParseEntry(ReadOnlySpan<byte> e, int id, bool v4)
    {
        ushort nameLenBytes = BinaryPrimitives.ReadUInt16LittleEndian(e[0x40..]);
        var type = (CfbObjectType)e[0x42];
        if (type is not (CfbObjectType.Unallocated or CfbObjectType.Storage or CfbObjectType.Stream or CfbObjectType.Root))
        {
            throw new PsignException($"invalid object type: {e[0x42]}");
        }

        string name = string.Empty;
        if (type != CfbObjectType.Unallocated)
        {
            if (nameLenBytes > 64)
            {
                throw new PsignException($"name length too large: {nameLenBytes}");
            }

            if (nameLenBytes % 2 != 0)
            {
                throw new PsignException($"odd name length: {nameLenBytes}");
            }

            int nameChars = nameLenBytes > 0 ? (nameLenBytes / 2) - 1 : 0;
            var chars = new char[nameChars];
            for (int i = 0; i < nameChars; i++)
            {
                chars[i] = (char)BinaryPrimitives.ReadUInt16LittleEndian(e[(i * 2)..]);
            }

            name = type == CfbObjectType.Root ? "Root Entry" : new string(chars);
        }

        uint left = BinaryPrimitives.ReadUInt32LittleEndian(e[0x44..]);
        uint right = BinaryPrimitives.ReadUInt32LittleEndian(e[0x48..]);
        uint child = BinaryPrimitives.ReadUInt32LittleEndian(e[0x4C..]);
        var clsid = e.Slice(0x50, 16).ToArray();
        uint stateBits = BinaryPrimitives.ReadUInt32LittleEndian(e[0x60..]);
        ulong created = BinaryPrimitives.ReadUInt64LittleEndian(e[0x64..]);
        ulong modified = BinaryPrimitives.ReadUInt64LittleEndian(e[0x6C..]);
        ulong streamLen = BinaryPrimitives.ReadUInt64LittleEndian(e[0x78..]);
        if (!v4)
        {
            streamLen &= 0xFFFF_FFFF;
        }

        if (type == CfbObjectType.Stream)
        {
            // cfb (permissive): stream CLSID and timestamps are treated as zero.
            clsid = new byte[16];
            created = 0;
            modified = 0;
        }
        else if (type == CfbObjectType.Storage)
        {
            streamLen = 0;
        }

        return new CfbDirEntry(id, name, type, left, right, child, clsid, stateBits, created, modified, streamLen);
    }

    private CfbDirEntry Entry(uint id)
    {
        if (id > MaxRegularStreamId || id >= _entries.Count)
        {
            throw new PsignException($"invalid CFB stream id {id}");
        }

        return _entries[(int)id];
    }

    /// <summary>Direct children of the storage <paramref name="storage"/> (in directory tree order).</summary>
    public List<CfbDirEntry> Children(CfbDirEntry storage)
    {
        var result = new List<CfbDirEntry>();
        if (storage.Child == NoStream)
        {
            return result;
        }

        var visited = new HashSet<uint>();
        var stack = new Stack<uint>();
        uint current = storage.Child;
        while (stack.Count > 0 || current != NoStream)
        {
            while (current != NoStream)
            {
                if (!visited.Add(current))
                {
                    throw new PsignException("CFB directory tree contains a loop");
                }

                stack.Push(current);
                current = Entry(current).LeftSibling;
            }

            uint id = stack.Pop();
            var entry = Entry(id);
            if (entry.Type is CfbObjectType.Storage or CfbObjectType.Stream)
            {
                result.Add(entry);
            }
            else
            {
                throw new PsignException($"invalid CFB directory tree entry type {entry.Type}");
            }

            current = entry.RightSibling;
        }

        return result;
    }

    /// <summary>
    /// Look up a direct child of <paramref name="storage"/> by name using the CFB case-insensitive comparison (Rust
    /// <c>CompoundFile::exists</c> semantics).
    /// </summary>
    public CfbDirEntry? FindChild(CfbDirEntry storage, string name) =>
        Children(storage).FirstOrDefault(c =>
            c.Name.Length == name.Length && string.Equals(c.Name, name, StringComparison.OrdinalIgnoreCase));
}
