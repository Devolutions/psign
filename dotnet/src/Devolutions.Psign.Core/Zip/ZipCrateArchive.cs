using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Devolutions.Psign.Core.Zip;

/// <summary>Error raised by <see cref="ZipCrateArchive"/> with the Rust <c>zip</c> 0.6 <c>ZipError</c> display text.</summary>
public sealed class ZipFormatException : PsignException
{
    public ZipFormatException(string message)
        : base(message)
    {
    }

    internal static ZipFormatException Invalid(string detail) => new($"invalid Zip archive: {detail}");

    internal static ZipFormatException Unsupported(string detail) => new($"unsupported Zip archive: {detail}");

    internal static ZipFormatException Eof() => new("failed to fill whole buffer");

    internal static ZipFormatException NotFound() => new("specified file not found in archive");
}

/// <summary>Central directory entry of a <see cref="ZipCrateArchive"/> (Rust <c>zip::read::ZipFile</c> metadata).</summary>
public sealed class ZipCrateEntry
{
    internal ZipCrateEntry()
    {
    }

    /// <summary>Index in central directory order.</summary>
    public int Index { get; internal init; }

    /// <summary>Decoded name (UTF-8 lossy when general purpose bit 11 is set, CP437 otherwise), as the Rust crate decodes it.</summary>
    public string Name { get; internal init; } = string.Empty;

    /// <summary>Raw central directory file name bytes.</summary>
    public byte[] NameRaw { get; internal init; } = [];

    /// <summary>"Version made by" (full 16-bit value).</summary>
    public ushort VersionMadeBy { get; internal init; }

    /// <summary>General purpose flags from the central directory.</summary>
    public ushort Flags { get; internal init; }

    /// <summary>Whether the entry is flagged as encrypted.</summary>
    public bool Encrypted => (Flags & 1) != 0;

    /// <summary>Compression method (after a WinZip AES extra field override, like the Rust crate).</summary>
    public ushort CompressionMethod { get; internal set; }

    /// <summary>Rust <c>format!("{:?}", file.compression())</c> (<c>Stored</c>, <c>Deflated</c>, <c>Unsupported(n)</c>).</summary>
    public string CompressionName => ZipCrateArchive.CompressionMethodName(CompressionMethod);

    /// <summary>Whether the compression method is supported by the reader (Stored / Deflated).</summary>
    public bool IsSupportedCompression => CompressionMethod is 0 or 8;

    /// <summary>Whether the entry carries a valid WinZip AES extra field.</summary>
    public bool HasAesMode { get; internal set; }

    /// <summary>MS-DOS modification time from the central directory.</summary>
    public ushort DosTime { get; internal init; }

    /// <summary>MS-DOS modification date from the central directory.</summary>
    public ushort DosDate { get; internal init; }

    /// <summary>Last modification time from the central directory (Rust <c>file.last_modified()</c>).</summary>
    public ZipDateTime LastModified => ZipDateTime.FromMsDos(DosDate, DosTime);

    /// <summary>CRC-32 from the central directory.</summary>
    public uint Crc32 { get; internal init; }

    /// <summary>Compressed size (ZIP64-resolved).</summary>
    public ulong CompressedSize { get; internal set; }

    /// <summary>Uncompressed size (ZIP64-resolved).</summary>
    public ulong UncompressedSize { get; internal set; }

    /// <summary>Central directory extra field.</summary>
    public byte[] ExtraField { get; internal init; } = [];

    /// <summary>Raw central directory comment.</summary>
    public byte[] CommentRaw { get; internal init; } = [];

    /// <summary>Offset of the local file header (ZIP64-resolved, archive-offset adjusted; Rust <c>header_start</c>).</summary>
    public ulong HeaderStart { get; internal set; }

    /// <summary>Offset of the central directory record.</summary>
    public ulong CentralHeaderStart { get; internal init; }

    /// <summary>External file attributes.</summary>
    public uint ExternalAttributes { get; internal init; }

    /// <summary>Rust <c>is_dir()</c>: the name ends with <c>/</c> or <c>\</c>.</summary>
    public bool IsDir => Name.EndsWith('/') || Name.EndsWith('\\');
}

/// <summary>
/// In-memory ZIP reader with the exact semantics of the Rust <c>zip</c> 0.6.6 <c>ZipArchive</c> (deflate feature only):
/// EOCD / ZIP64 discovery, archive-offset correction, central-directory ZIP64 / AES extra parsing, local-header based
/// <c>data_start</c>, CRC validation on read, CP437 / UTF-8 name decoding, and <c>by_name</c> resolution through a name
/// map where later duplicates win. Error texts follow the crate's <c>ZipError</c> display strings
/// (<see cref="ZipFormatException"/>).
/// </summary>
/// <remarks>
/// Lookup helpers come in two flavours: <see cref="ByName"/> / <see cref="RequireByName"/> / <see cref="this[int]"/>
/// return central directory metadata without touching the entry data, while <see cref="ByIndex"/> /
/// <see cref="OpenByName"/> / <see cref="TryOpenByName"/> reproduce Rust <c>by_index</c> / <c>by_name</c>, which also
/// reject encrypted entries, invalid local headers and unsupported compression methods.
/// </remarks>
public sealed class ZipCrateArchive
{
    private const uint LocalSig = 0x0403_4b50;
    private const uint CentralSig = 0x0201_4b50;
    private const uint EocdSig = 0x0605_4b50;
    private const uint Zip64EocdSig = 0x0606_4b50;
    private const uint Zip64LocatorSig = 0x0706_4b50;
    private const uint Zip64BytesThr = uint.MaxValue;

    private readonly byte[] _buf;
    private readonly List<ZipCrateEntry> _entries;
    private readonly Dictionary<string, int> _namesMap;
    private readonly List<string> _uniqueNames;

    private ZipCrateArchive(byte[] buf, List<ZipCrateEntry> entries, Dictionary<string, int> namesMap, List<string> uniqueNames, byte[] comment)
    {
        _buf = buf;
        _entries = entries;
        _namesMap = namesMap;
        _uniqueNames = uniqueNames;
        Comment = comment;
    }

    /// <summary>Archive bytes.</summary>
    public byte[] Data => _buf;

    /// <summary>Archive comment.</summary>
    public byte[] Comment { get; }

    /// <summary>Number of central directory entries (Rust <c>archive.len()</c>).</summary>
    public int Count => _entries.Count;

    /// <summary>Entries in central directory order.</summary>
    public IReadOnlyList<ZipCrateEntry> Entries => _entries;

    /// <summary>Entry metadata by index (no data validation).</summary>
    public ZipCrateEntry this[int index] => _entries[index];

    /// <summary>Distinct entry names (Rust <c>file_names()</c>; first-occurrence order instead of hash order).</summary>
    public IReadOnlyList<string> FileNames => _uniqueNames;

    /// <summary>Rust <c>format!("{:?}", CompressionMethod::from_u16(n))</c> with only the <c>deflate</c> feature.</summary>
    public static string CompressionMethodName(ushort method) => method switch
    {
        0 => "Stored",
        8 => "Deflated",
        _ => $"Unsupported({method})",
    };

    /// <summary>Open a ZIP archive from a file.</summary>
    public static ZipCrateArchive OpenFile(string path) => Open(File.ReadAllBytes(path));

    /// <summary>Open a ZIP archive from a stream (read fully).</summary>
    public static ZipCrateArchive Open(Stream stream)
    {
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Open(ms.ToArray());
    }

    /// <summary>Open <paramref name="buf"/> (Rust <c>ZipArchive::new(Cursor::new(buf))</c>).</summary>
    public static ZipCrateArchive Open(byte[] buf)
    {
        ArgumentNullException.ThrowIfNull(buf);
        var (cdeStart, eocd) = FindAndParseEocd(buf);
        bool recordTooSmall = eocd.DiskNumber == 0xFFFF || eocd.DiskWithCd == 0xFFFF || eocd.FilesOnDisk == 0xFFFF
            || eocd.Files == 0xFFFF || eocd.CdSize == 0xFFFFFFFF || eocd.CdOffset == 0xFFFFFFFF;
        if (!recordTooSmall && eocd.DiskNumber != eocd.DiskWithCd)
        {
            throw ZipFormatException.Unsupported("Support for multi-disk files is not implemented");
        }

        var (archiveOffset, directoryStart, numberOfFiles) = GetDirectoryCounts(buf, eocd, cdeStart, recordTooSmall);

        var entries = new List<ZipCrateEntry>();
        var names = new Dictionary<string, int>(StringComparer.Ordinal);
        var unique = new List<string>();
        ulong pos = directoryStart;
        for (ulong i = 0; i < numberOfFiles; i++)
        {
            var entry = ReadCentralHeader(buf, ref pos, archiveOffset, entries.Count);
            if (!names.ContainsKey(entry.Name))
            {
                unique.Add(entry.Name);
            }

            names[entry.Name] = entries.Count;
            entries.Add(entry);
        }

        return new ZipCrateArchive(buf, entries, names, unique, eocd.Comment);
    }

    /// <summary>Whether an entry named exactly <paramref name="name"/> exists.</summary>
    public bool Contains(string name) => _namesMap.ContainsKey(name);

    /// <summary>Entry with <paramref name="name"/> (the last one when duplicated, like the Rust names map), or <c>null</c>.</summary>
    public ZipCrateEntry? ByName(string name) => _namesMap.TryGetValue(name, out int i) ? _entries[i] : null;

    /// <summary>Entry by name or a "specified file not found in archive" error (no data validation).</summary>
    public ZipCrateEntry RequireByName(string name) => ByName(name) ?? throw ZipFormatException.NotFound();

    /// <summary>Entry metadata by index (Rust <c>by_index</c> validation: encryption, local header, compression).</summary>
    public ZipCrateEntry ByIndex(int index)
    {
        var e = Get(index);
        EnsureReadable(e);
        return e;
    }

    /// <summary>Entry by exact name (Rust <c>by_name</c>, with <see cref="ByIndex"/> validation).</summary>
    public ZipCrateEntry OpenByName(string name)
    {
        if (!_namesMap.TryGetValue(name, out int index))
        {
            throw ZipFormatException.NotFound();
        }

        return ByIndex(index);
    }

    /// <summary>Whether Rust <c>by_name(name)</c> would succeed.</summary>
    public bool TryOpenByName(string name, out ZipCrateEntry? entry)
    {
        try
        {
            entry = OpenByName(name);
            return true;
        }
        catch (PsignException)
        {
            entry = null;
            return false;
        }
    }

    /// <summary>
    /// Validate that an entry can be opened for reading (Rust <c>by_index</c>): encryption, local header and
    /// compression method.
    /// </summary>
    public void EnsureReadable(ZipCrateEntry entry)
    {
        if (entry.Encrypted)
        {
            throw ZipFormatException.Unsupported("Password required to decrypt file");
        }

        DataStart(entry);
        if (!entry.IsSupportedCompression)
        {
            throw ZipFormatException.Unsupported("Compression method not supported");
        }
    }

    /// <summary>Offset of the entry data computed from the local header (Rust <c>find_content</c>).</summary>
    public ulong DataStart(ZipCrateEntry entry)
    {
        ulong hs = entry.HeaderStart;
        if (ReadU32(_buf, hs) != LocalSig)
        {
            throw ZipFormatException.Invalid("Invalid local file header");
        }

        ulong nameLen = ReadU16(_buf, hs + 26);
        ulong extraLen = ReadU16(_buf, hs + 28);
        return hs + 30 + nameLen + extraLen;
    }

    /// <summary>Read and decompress an entry, validating the CRC (Rust <c>by_index(..)?.read_to_end</c>).</summary>
    public byte[] Read(ZipCrateEntry entry)
    {
        EnsureReadable(entry);
        return Decompress(entry);
    }

    /// <summary>Read and decompress entry <paramref name="index"/>.</summary>
    public byte[] Read(int index) => Decompress(ByIndex(index));

    /// <summary>Read and decompress an entry by name (Rust <c>by_name(..)?.read_to_end</c>).</summary>
    public byte[] Read(string name) => Decompress(OpenByName(name));

    /// <summary>Raw (still compressed) entry bytes (Rust <c>by_index_raw(..)?.read_to_end</c>).</summary>
    public byte[] ReadRaw(ZipCrateEntry entry)
    {
        ulong ds = DataStart(entry);
        return Slice(ds, entry.CompressedSize);
    }

    /// <summary>Raw (still compressed) bytes of entry <paramref name="index"/>.</summary>
    public byte[] ReadRaw(int index) => ReadRaw(Get(index));

    private byte[] Decompress(ZipCrateEntry e)
    {
        ulong ds = DataStart(e);
        var compressed = Slice(ds, e.CompressedSize);
        byte[] data;
        if (e.CompressionMethod == 0)
        {
            data = compressed;
        }
        else
        {
            try
            {
                using var input = new MemoryStream(compressed, writable: false);
                using var inflate = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                inflate.CopyTo(output);
                data = output.ToArray();
            }
            catch (InvalidDataException ex)
            {
                throw new PsignException("corrupt deflate stream", ex);
            }
        }

        if (ZipCrc32.Compute(data) != e.Crc32)
        {
            throw new PsignException("Invalid checksum");
        }

        return data;
    }

    private byte[] Slice(ulong start, ulong length)
    {
        if (start >= (ulong)_buf.Length)
        {
            return [];
        }

        ulong avail = (ulong)_buf.Length - start;
        ulong n = Math.Min(avail, length);
        return _buf.AsSpan((int)start, (int)n).ToArray();
    }

    private ZipCrateEntry Get(int index)
    {
        if (index < 0 || index >= _entries.Count)
        {
            throw ZipFormatException.NotFound();
        }

        return _entries[index];
    }

    // ------------------------------------------------------------------ parsing

    private sealed record Eocd(ushort DiskNumber, ushort DiskWithCd, ushort FilesOnDisk, ushort Files, uint CdSize, uint CdOffset, byte[] Comment);

    private static (ulong CdeStart, Eocd Eocd) FindAndParseEocd(byte[] buf)
    {
        const ulong headerSize = 22;
        ulong fileLength = (ulong)buf.Length;
        ulong searchUpper = fileLength > headerSize + ushort.MaxValue ? fileLength - (headerSize + ushort.MaxValue) : 0;
        if (fileLength < headerSize)
        {
            throw ZipFormatException.Invalid("Invalid zip header");
        }

        ulong pos = fileLength - headerSize;
        while (pos >= searchUpper)
        {
            if (ReadU32(buf, pos) == EocdSig)
            {
                var d = new Eocd(
                    ReadU16(buf, pos + 4),
                    ReadU16(buf, pos + 6),
                    ReadU16(buf, pos + 8),
                    ReadU16(buf, pos + 10),
                    ReadU32(buf, pos + 12),
                    ReadU32(buf, pos + 16),
                    ReadExact(buf, pos + 22, ReadU16(buf, pos + 20)));
                return (pos, d);
            }

            if (pos == 0)
            {
                break;
            }

            pos--;
        }

        throw ZipFormatException.Invalid("Could not find central directory end");
    }

    private static (ulong ArchiveOffset, ulong DirectoryStart, ulong NumberOfFiles) GetDirectoryCounts(byte[] buf, Eocd footer, ulong cdeStart, bool recordTooSmall)
    {
        long locatorPos = buf.Length - (20 + 22 + footer.Comment.Length);
        bool haveLocator = false;
        uint locDiskWithCd = 0;
        ulong locEocdOffset = 0;
        if (locatorPos >= 0)
        {
            if (ReadU32(buf, (ulong)locatorPos) == Zip64LocatorSig)
            {
                locDiskWithCd = ReadU32(buf, (ulong)locatorPos + 4);
                locEocdOffset = ReadU64(buf, (ulong)locatorPos + 8);
                _ = ReadU32(buf, (ulong)locatorPos + 16);
                haveLocator = true;
            }
        }

        if (!haveLocator)
        {
            ulong cs = footer.CdSize;
            ulong co = footer.CdOffset;
            if (cdeStart < cs || cdeStart - cs < co)
            {
                throw ZipFormatException.Invalid("Invalid central directory size or offset");
            }

            ulong archiveOffset = cdeStart - cs - co;
            return (archiveOffset, co + archiveOffset, footer.FilesOnDisk);
        }

        if (!recordTooSmall && footer.DiskNumber != locDiskWithCd)
        {
            throw ZipFormatException.Unsupported("Support for multi-disk files is not implemented");
        }

        if (cdeStart < 60)
        {
            throw ZipFormatException.Invalid("File cannot contain ZIP64 central directory end");
        }

        ulong searchUpper = cdeStart - 60;
        ulong pos = locEocdOffset;
        while (pos <= searchUpper)
        {
            if (ReadU32(buf, pos) == Zip64EocdSig)
            {
                ulong archiveOffset = pos - locEocdOffset;
                uint diskNumber = ReadU32(buf, pos + 16);
                uint diskWithCd = ReadU32(buf, pos + 20);
                ulong files = ReadU64(buf, pos + 32);
                ulong cdOffset = ReadU64(buf, pos + 48);
                if (diskNumber != diskWithCd)
                {
                    throw ZipFormatException.Unsupported("Support for multi-disk files is not implemented");
                }

                ulong directoryStart = cdOffset + archiveOffset;
                if (directoryStart < cdOffset)
                {
                    throw ZipFormatException.Invalid("Invalid central directory size or offset");
                }

                return (archiveOffset, directoryStart, files);
            }

            pos++;
        }

        throw ZipFormatException.Invalid("Could not find ZIP64 central directory end");
    }

    private static ZipCrateEntry ReadCentralHeader(byte[] buf, ref ulong pos, ulong archiveOffset, int index)
    {
        ulong start = pos;
        if (ReadU32(buf, pos) != CentralSig)
        {
            throw ZipFormatException.Invalid("Invalid Central Directory header");
        }

        ushort versionMadeBy = ReadU16(buf, pos + 4);
        ushort flags = ReadU16(buf, pos + 8);
        ushort method = ReadU16(buf, pos + 10);
        ushort modTime = ReadU16(buf, pos + 12);
        ushort modDate = ReadU16(buf, pos + 14);
        uint crc = ReadU32(buf, pos + 16);
        uint comp = ReadU32(buf, pos + 20);
        uint uncomp = ReadU32(buf, pos + 24);
        int nameLen = ReadU16(buf, pos + 28);
        int extraLen = ReadU16(buf, pos + 30);
        int commentLen = ReadU16(buf, pos + 32);
        uint external = ReadU32(buf, pos + 38);
        uint offset = ReadU32(buf, pos + 42);
        var name = ReadExact(buf, pos + 46, nameLen);
        var extra = ReadExact(buf, pos + 46 + (ulong)nameLen, extraLen);
        var comment = ReadExact(buf, pos + 46 + (ulong)nameLen + (ulong)extraLen, commentLen);
        pos += 46 + (ulong)nameLen + (ulong)extraLen + (ulong)commentLen;

        bool utf8 = (flags & (1 << 11)) != 0;
        var entry = new ZipCrateEntry
        {
            Index = index,
            NameRaw = name,
            Name = utf8 ? Encoding.UTF8.GetString(name) : Cp437.Decode(name),
            VersionMadeBy = versionMadeBy,
            Flags = flags,
            CompressionMethod = method,
            DosTime = modTime,
            DosDate = modDate,
            Crc32 = crc,
            CompressedSize = comp,
            UncompressedSize = uncomp,
            ExtraField = extra,
            CommentRaw = comment,
            HeaderStart = offset,
            CentralHeaderStart = start,
            ExternalAttributes = external,
        };

        ParseExtraField(entry);

        if (entry.CompressionMethod == 99 && !entry.HasAesMode)
        {
            throw ZipFormatException.Invalid("AES encryption without AES extra data field");
        }

        ulong hs = entry.HeaderStart + archiveOffset;
        if (hs < entry.HeaderStart)
        {
            throw ZipFormatException.Invalid("Archive header is too large");
        }

        entry.HeaderStart = hs;
        return entry;
    }

    private static void ParseExtraField(ZipCrateEntry file)
    {
        var extra = file.ExtraField;
        long p = 0;
        try
        {
            while (p < extra.Length)
            {
                ushort kind = ExtraU16(extra, ref p);
                ushort len = ExtraU16(extra, ref p);
                long lenLeft = len;
                switch (kind)
                {
                    case 0x0001:
                        if (file.UncompressedSize == Zip64BytesThr)
                        {
                            file.UncompressedSize = ExtraU64(extra, ref p);
                            lenLeft -= 8;
                        }

                        if (file.CompressedSize == Zip64BytesThr)
                        {
                            file.CompressedSize = ExtraU64(extra, ref p);
                            lenLeft -= 8;
                        }

                        if (file.HeaderStart == Zip64BytesThr)
                        {
                            file.HeaderStart = ExtraU64(extra, ref p);
                            lenLeft -= 8;
                        }

                        break;
                    case 0x9901:
                        if (len != 7)
                        {
                            throw ZipFormatException.Unsupported("AES extra data field has an unsupported length");
                        }

                        ushort vendorVersion = ExtraU16(extra, ref p);
                        ushort vendorId = ExtraU16(extra, ref p);
                        byte aesMode = ExtraU8(extra, ref p);
                        ushort method = ExtraU16(extra, ref p);
                        if (vendorId != 0x4541)
                        {
                            throw ZipFormatException.Invalid("Invalid AES vendor");
                        }

                        if (vendorVersion is not (1 or 2))
                        {
                            throw ZipFormatException.Invalid("Invalid AES vendor version");
                        }

                        if (aesMode is not (1 or 2 or 3))
                        {
                            throw ZipFormatException.Invalid("Invalid AES encryption strength");
                        }

                        file.HasAesMode = true;
                        file.CompressionMethod = method;
                        break;
                }

                if (lenLeft > 0)
                {
                    p += lenLeft;
                }
            }
        }
        catch (EndOfStreamException)
        {
            // Rust swallows I/O errors from parse_extra_field.
        }
    }

    private static ushort ExtraU16(byte[] b, ref long p)
    {
        if (p + 2 > b.Length)
        {
            throw new EndOfStreamException();
        }

        ushort v = BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan((int)p));
        p += 2;
        return v;
    }

    private static byte ExtraU8(byte[] b, ref long p)
    {
        if (p + 1 > b.Length)
        {
            throw new EndOfStreamException();
        }

        return b[p++];
    }

    private static ulong ExtraU64(byte[] b, ref long p)
    {
        if (p + 8 > b.Length)
        {
            throw new EndOfStreamException();
        }

        ulong v = BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan((int)p));
        p += 8;
        return v;
    }

    private static byte[] ReadExact(byte[] buf, ulong pos, int len)
    {
        if (len == 0)
        {
            return [];
        }

        if (pos > (ulong)buf.Length || (ulong)buf.Length - pos < (ulong)len)
        {
            throw ZipFormatException.Eof();
        }

        return buf.AsSpan((int)pos, len).ToArray();
    }

    internal static ushort ReadU16(byte[] buf, ulong pos)
    {
        if (pos > (ulong)buf.Length || (ulong)buf.Length - pos < 2)
        {
            throw ZipFormatException.Eof();
        }

        return BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan((int)pos));
    }

    internal static uint ReadU32(byte[] buf, ulong pos)
    {
        if (pos > (ulong)buf.Length || (ulong)buf.Length - pos < 4)
        {
            throw ZipFormatException.Eof();
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan((int)pos));
    }

    internal static ulong ReadU64(byte[] buf, ulong pos)
    {
        if (pos > (ulong)buf.Length || (ulong)buf.Length - pos < 8)
        {
            throw ZipFormatException.Eof();
        }

        return BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan((int)pos));
    }
}

/// <summary>IBM code page 437 decoding as implemented by the Rust <c>zip</c> crate (<c>zip::cp437::FromCp437</c>).</summary>
internal static class Cp437
{
    private static readonly char[] High =
    [
        'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å',
        'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ',
        'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»',
        '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐',
        '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧',
        '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀',
        'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩',
        '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', ' ',
    ];

    public static string Decode(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length);
        foreach (byte b in bytes)
        {
            sb.Append(b < 0x80 ? (char)b : High[b - 0x80]);
        }

        return sb.ToString();
    }
}
