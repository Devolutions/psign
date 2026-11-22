using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Devolutions.Psign.Core.Zip;

/// <summary>Central directory entry of a <see cref="ZipCrateArchive"/> (Rust <c>zip::read::ZipFile</c> metadata).</summary>
public sealed class ZipCrateEntry
{
    internal ZipCrateEntry()
    {
    }

    /// <summary>Index in the central directory.</summary>
    public int Index { get; internal init; }

    /// <summary>Decoded name (UTF-8 when flag bit 11 is set, otherwise CP437), as the Rust crate decodes it.</summary>
    public string Name { get; internal init; } = string.Empty;

    /// <summary>Raw name octets.</summary>
    public byte[] NameRaw { get; internal init; } = [];

    public ushort VersionMadeBy { get; internal init; }

    public ushort Flags { get; internal init; }

    /// <summary>Raw compression method.</summary>
    public ushort CompressionMethod { get; internal init; }

    /// <summary>Rust <c>format!("{:?}", file.compression())</c> (<c>Stored</c>, <c>Deflated</c>, <c>Unsupported(n)</c>).</summary>
    public string CompressionName => ZipCrateArchive.CompressionMethodName(CompressionMethod);

    public ushort DosTime { get; internal init; }

    public ushort DosDate { get; internal init; }

    /// <summary>Last modification time from the central directory (Rust <c>file.last_modified()</c>).</summary>
    public ZipDateTime LastModified => ZipDateTime.FromMsDos(DosDate, DosTime);

    public uint Crc32 { get; internal init; }

    public ulong CompressedSize { get; internal init; }

    public ulong UncompressedSize { get; internal init; }

    public uint ExternalAttributes { get; internal init; }

    /// <summary>Local header offset including the archive offset (Rust <c>header_start</c>).</summary>
    public ulong HeaderStart { get; internal init; }

    public bool Encrypted => (Flags & 1) != 0;

    /// <summary>Rust <c>is_dir()</c>: the name ends with <c>/</c> or <c>\</c>.</summary>
    public bool IsDir => Name.Length > 0 && (Name[^1] == '/' || Name[^1] == '\\');
}

/// <summary>
/// Minimal ZIP reader that mirrors the Rust <c>zip</c> 0.6.6 <c>ZipArchive</c> (central directory parsing, name
/// decoding, <c>by_name</c> semantics, CRC checks). Error texts follow the crate's <c>ZipError</c> display strings.
/// </summary>
public sealed class ZipCrateArchive
{
    private const uint LocalFileHeaderSignature = 0x04034b50;
    private const uint CentralDirectoryHeaderSignature = 0x02014b50;
    private const uint CentralDirectoryEndSignature = 0x06054b50;
    private const uint Zip64CentralDirectoryEndLocatorSignature = 0x07064b50;
    private const uint Zip64CentralDirectoryEndSignature = 0x06064b50;

    private readonly byte[] _data;
    private readonly List<ZipCrateEntry> _entries;
    private readonly Dictionary<string, int> _names;

    private ZipCrateArchive(byte[] data, List<ZipCrateEntry> entries, Dictionary<string, int> names, byte[] comment)
    {
        _data = data;
        _entries = entries;
        _names = names;
        Comment = comment;
    }

    /// <summary>Archive bytes.</summary>
    public byte[] Data => _data;

    /// <summary>Archive comment.</summary>
    public byte[] Comment { get; }

    /// <summary>Number of entries (Rust <c>archive.len()</c>).</summary>
    public int Count => _entries.Count;

    /// <summary>Entries in central directory order.</summary>
    public IReadOnlyList<ZipCrateEntry> Entries => _entries;

    /// <summary>Entry by index.</summary>
    public ZipCrateEntry this[int index] => _entries[index];

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

    /// <summary>Open a ZIP archive (Rust <c>ZipArchive::new</c>).</summary>
    public static ZipCrateArchive Open(byte[] data)
    {
        const int headerSize = 22;
        if (data.Length < headerSize)
        {
            throw Invalid("Invalid zip header");
        }

        long searchUpperBound = Math.Max(0, (long)data.Length - (headerSize + ushort.MaxValue));
        long pos = data.Length - headerSize;
        long cdeStart = -1;
        while (pos >= searchUpperBound)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)pos, 4)) == CentralDirectoryEndSignature)
            {
                cdeStart = pos;
                break;
            }

            if (pos == 0)
            {
                break;
            }

            pos--;
        }

        if (cdeStart < 0)
        {
            throw Invalid("Could not find central directory end");
        }

        var cde = data.AsSpan((int)cdeStart);
        ushort diskNumber = BinaryPrimitives.ReadUInt16LittleEndian(cde[4..]);
        ushort diskWithCd = BinaryPrimitives.ReadUInt16LittleEndian(cde[6..]);
        ushort filesOnDisk = BinaryPrimitives.ReadUInt16LittleEndian(cde[8..]);
        ushort numberOfFiles = BinaryPrimitives.ReadUInt16LittleEndian(cde[10..]);
        uint cdSize = BinaryPrimitives.ReadUInt32LittleEndian(cde[12..]);
        uint cdOffset = BinaryPrimitives.ReadUInt32LittleEndian(cde[16..]);
        ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(cde[20..]);
        int commentAvail = Math.Min(commentLen, data.Length - (int)cdeStart - headerSize);
        if (commentAvail < commentLen)
        {
            throw new PsignException("failed to fill whole buffer");
        }

        var comment = data.AsSpan((int)cdeStart + headerSize, commentLen).ToArray();
        _ = filesOnDisk;

        ulong archiveOffset;
        ulong directoryStart;
        ulong fileCount;

        // ZIP64 locator directly precedes the EOCD record.
        if (cdeStart >= 20 && BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)cdeStart - 20, 4)) == Zip64CentralDirectoryEndLocatorSignature)
        {
            var loc = data.AsSpan((int)cdeStart - 20, 20);
            uint locDisk = BinaryPrimitives.ReadUInt32LittleEndian(loc[4..]);
            ulong endOffset = BinaryPrimitives.ReadUInt64LittleEndian(loc[8..]);
            uint totalDisks = BinaryPrimitives.ReadUInt32LittleEndian(loc[16..]);
            if (locDisk != 0 || totalDisks > 1)
            {
                throw Unsupported("Support for multi-disk files is not implemented");
            }

            long found = -1;
            for (long p = (long)cdeStart - 20 - 56; p >= 0 && (ulong)p >= endOffset; p--)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan((int)p, 4)) == Zip64CentralDirectoryEndSignature)
                {
                    found = p;
                    break;
                }
            }

            if (found < 0)
            {
                throw Invalid("Could not find ZIP64 central directory end");
            }

            var z = data.AsSpan((int)found);
            uint z64Disk = BinaryPrimitives.ReadUInt32LittleEndian(z[16..]);
            uint z64DiskCd = BinaryPrimitives.ReadUInt32LittleEndian(z[20..]);
            ulong z64FilesOnDisk = BinaryPrimitives.ReadUInt64LittleEndian(z[24..]);
            ulong z64Files = BinaryPrimitives.ReadUInt64LittleEndian(z[32..]);
            ulong z64CdOffset = BinaryPrimitives.ReadUInt64LittleEndian(z[48..]);
            if (z64Disk != z64DiskCd || z64FilesOnDisk != z64Files)
            {
                throw Unsupported("Support for multi-disk files is not implemented");
            }

            archiveOffset = (ulong)found - endOffset;
            directoryStart = z64CdOffset + archiveOffset;
            fileCount = z64Files;
        }
        else
        {
            if (diskNumber != diskWithCd)
            {
                throw Unsupported("Support for multi-disk files is not implemented");
            }

            long ao = cdeStart - (long)cdSize - (long)cdOffset;
            if (ao < 0)
            {
                throw Invalid("Invalid central directory size or offset");
            }

            archiveOffset = (ulong)ao;
            directoryStart = cdOffset + archiveOffset;
            fileCount = numberOfFiles;
        }

        if (fileCount > (ulong)data.Length)
        {
            throw Invalid("Number of files is larger than the archive");
        }

        var entries = new List<ZipCrateEntry>((int)fileCount);
        var names = new Dictionary<string, int>(StringComparer.Ordinal);
        long cursor = (long)directoryStart;
        for (int i = 0; i < (int)fileCount; i++)
        {
            var entry = ReadCentralHeader(data, ref cursor, archiveOffset, i);
            names[entry.Name] = i;
            entries.Add(entry);
        }

        return new ZipCrateArchive(data, entries, names, comment);
    }

    private static ZipCrateEntry ReadCentralHeader(byte[] data, ref long cursor, ulong archiveOffset, int index)
    {
        if (cursor < 0 || cursor + 46 > data.Length)
        {
            throw new PsignException("failed to fill whole buffer");
        }

        var h = data.AsSpan((int)cursor);
        if (BinaryPrimitives.ReadUInt32LittleEndian(h) != CentralDirectoryHeaderSignature)
        {
            throw Invalid("Invalid Central Directory header");
        }

        ushort versionMadeBy = BinaryPrimitives.ReadUInt16LittleEndian(h[4..]);
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(h[8..]);
        ushort method = BinaryPrimitives.ReadUInt16LittleEndian(h[10..]);
        ushort time = BinaryPrimitives.ReadUInt16LittleEndian(h[12..]);
        ushort date = BinaryPrimitives.ReadUInt16LittleEndian(h[14..]);
        uint crc = BinaryPrimitives.ReadUInt32LittleEndian(h[16..]);
        ulong compressed = BinaryPrimitives.ReadUInt32LittleEndian(h[20..]);
        ulong uncompressed = BinaryPrimitives.ReadUInt32LittleEndian(h[24..]);
        int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(h[28..]);
        int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(h[30..]);
        int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(h[32..]);
        uint external = BinaryPrimitives.ReadUInt32LittleEndian(h[38..]);
        ulong offset = BinaryPrimitives.ReadUInt32LittleEndian(h[42..]);
        if (cursor + 46 + nameLen + extraLen + commentLen > data.Length)
        {
            throw new PsignException("failed to fill whole buffer");
        }

        var nameRaw = h.Slice(46, nameLen).ToArray();
        var extra = h.Slice(46 + nameLen, extraLen);
        bool isUtf8 = (flags & (1 << 11)) != 0;
        string name = isUtf8 ? Encoding.UTF8.GetString(nameRaw) : Cp437.Decode(nameRaw);

        // ZIP64 extended information extra field.
        int ep = 0;
        while (ep + 4 <= extra.Length)
        {
            ushort kind = BinaryPrimitives.ReadUInt16LittleEndian(extra[ep..]);
            int len = BinaryPrimitives.ReadUInt16LittleEndian(extra[(ep + 2)..]);
            int body = ep + 4;
            if (kind == 0x0001)
            {
                int bp = body;
                if (uncompressed == 0xFFFFFFFF && bp + 8 <= extra.Length)
                {
                    uncompressed = BinaryPrimitives.ReadUInt64LittleEndian(extra[bp..]);
                    bp += 8;
                }

                if (compressed == 0xFFFFFFFF && bp + 8 <= extra.Length)
                {
                    compressed = BinaryPrimitives.ReadUInt64LittleEndian(extra[bp..]);
                    bp += 8;
                }

                if (offset == 0xFFFFFFFF && bp + 8 <= extra.Length)
                {
                    offset = BinaryPrimitives.ReadUInt64LittleEndian(extra[bp..]);
                }
            }

            ep = body + len;
        }

        cursor += 46 + nameLen + extraLen + commentLen;
        return new ZipCrateEntry
        {
            Index = index,
            Name = name,
            NameRaw = nameRaw,
            VersionMadeBy = versionMadeBy,
            Flags = flags,
            CompressionMethod = method,
            DosTime = time,
            DosDate = date,
            Crc32 = crc,
            CompressedSize = compressed,
            UncompressedSize = uncompressed,
            ExternalAttributes = external,
            HeaderStart = offset + archiveOffset,
        };
    }

    /// <summary>Entry with <paramref name="name"/> (the last one when duplicated, like the Rust names map), or <c>null</c>.</summary>
    public ZipCrateEntry? ByName(string name) => _names.TryGetValue(name, out int i) ? _entries[i] : null;

    /// <summary>Entry by name or a "specified file not found in archive" error.</summary>
    public ZipCrateEntry RequireByName(string name) =>
        ByName(name) ?? throw new PsignException("specified file not found in archive");

    /// <summary>Offset of the entry data (after the local header).</summary>
    public long DataStart(ZipCrateEntry entry)
    {
        long hs = (long)entry.HeaderStart;
        if (hs < 0 || hs + 30 > _data.Length)
        {
            throw new PsignException("failed to fill whole buffer");
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(_data.AsSpan((int)hs)) != LocalFileHeaderSignature)
        {
            throw Invalid("Invalid local file header");
        }

        int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan((int)hs + 26));
        int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan((int)hs + 28));
        return hs + 30 + nameLen + extraLen;
    }

    /// <summary>Compressed entry bytes (Rust <c>by_index_raw</c> data).</summary>
    public byte[] ReadRaw(ZipCrateEntry entry)
    {
        long start = DataStart(entry);
        long end = start + (long)entry.CompressedSize;
        if (end > _data.Length)
        {
            end = _data.Length;
        }

        return _data.AsSpan((int)start, (int)(end - start)).ToArray();
    }

    /// <summary>
    /// Validate that an entry can be opened for reading (Rust <c>by_index</c>): encryption and compression method.
    /// </summary>
    public void EnsureReadable(ZipCrateEntry entry)
    {
        if (entry.Encrypted)
        {
            throw Unsupported("Password required to decrypt file");
        }

        DataStart(entry);

        if (entry.CompressionMethod != 0 && entry.CompressionMethod != 8)
        {
            throw Unsupported("Compression method not supported");
        }
    }

    /// <summary>Decompressed entry bytes with CRC verification (Rust <c>by_index(..).read_to_end</c>).</summary>
    public byte[] Read(ZipCrateEntry entry)
    {
        EnsureReadable(entry);
        var raw = ReadRaw(entry);
        byte[] plain;
        if (entry.CompressionMethod == 0)
        {
            plain = raw;
        }
        else
        {
            try
            {
                using var input = new MemoryStream(raw);
                using var inflater = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                inflater.CopyTo(output);
                plain = output.ToArray();
            }
            catch (InvalidDataException e)
            {
                throw new PsignException("corrupt deflate stream", e);
            }
        }

        if (ZipCrc32.Compute(plain) != entry.Crc32)
        {
            throw new PsignException("Invalid checksum");
        }

        return plain;
    }

    /// <summary>Decompressed bytes of entry <paramref name="index"/>.</summary>
    public byte[] Read(int index) => Read(_entries[index]);

    private static PsignException Invalid(string message) => new($"invalid Zip archive: {message}");

    private static PsignException Unsupported(string message) => new($"unsupported Zip archive: {message}");
}

/// <summary>IBM code page 437 decoding (Rust <c>zip::cp437::FromCp437</c>).</summary>
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
        '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', ' ',
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
