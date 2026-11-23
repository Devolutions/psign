using System.Buffers.Binary;
using System.Text;

namespace Devolutions.Psign.Core.Pe;

/// <summary>
/// PE import directory reader with the semantics of the <c>goblin</c> crate (0.9) <c>pe::import::ImportData</c>:
/// RVAs are mapped with goblin's <c>find_offset</c> (512-byte aligned raw pointers, file-alignment / 4 KiB rounded read
/// sizes), the directory ends at the first null or not-possibly-valid entry, and each entry's lookup / address tables are
/// walked so that structurally broken tables fail like goblin does. Error texts follow goblin / scroll display strings.
/// </summary>
public static class PeImports
{
    private const int ImageDirectoryEntryImport = 1;
    private const int ImportDirectoryEntrySize = 20;

    /// <summary>
    /// Imported library names in goblin's <c>PE::libraries</c> order (sorted ordinally and deduplicated), or an empty list
    /// when the image has no import directory. Throws <see cref="PsignException"/> for malformed import data.
    /// </summary>
    public static List<string> ImportedLibraries(this PeFile pe)
    {
        var data = pe.Data;
        if (ImageDirectoryEntryImport >= pe.NumberOfRvaAndSizes)
        {
            return [];
        }

        int dirOffset = pe.DataDirectoriesOffset + (8 * ImageDirectoryEntryImport);
        uint va = BinaryPrimitives.ReadUInt32LittleEndian(data[dirOffset..]);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(data[(dirOffset + 4)..]);
        if (va == 0 && size == 0)
        {
            return [];
        }

        uint fileAlignment = BinaryPrimitives.ReadUInt32LittleEndian(data[(pe.OptionalHeaderOffset + 36)..]);
        bool is64 = pe.IsPe32Plus;
        long offset = FindOffset(va, pe.Sections, fileAlignment)
            ?? throw Malformed($"Cannot create ImportData; cannot map import_directory_table_rva {Hex(va)} into offset");

        var names = new List<string>();
        while (true)
        {
            var entry = ReadDirectoryEntry(data, ref offset);
            bool isNull = entry.Ilt == 0 && entry.TimeDateStamp == 0 && entry.ForwarderChain == 0 && entry.NameRva == 0 && entry.Iat == 0;
            bool possiblyValid = entry.NameRva != 0 && entry.Iat != 0;
            if (isNull || !possiblyValid)
            {
                break;
            }

            names.Add(ParseEntry(data, entry, pe.Sections, fileAlignment, is64));
        }

        names.Sort(string.CompareOrdinal);
        var result = new List<string>(names.Count);
        foreach (var n in names)
        {
            if (result.Count == 0 || result[^1] != n)
            {
                result.Add(n);
            }
        }

        return result;
    }

    private readonly record struct DirectoryEntry(uint Ilt, uint TimeDateStamp, uint ForwarderChain, uint NameRva, uint Iat);

    private static DirectoryEntry ReadDirectoryEntry(ReadOnlySpan<byte> data, ref long offset)
    {
        if (offset >= data.Length)
        {
            throw Scroll($"bad offset {offset}");
        }

        var src = data[(int)offset..];
        int local = 0;
        uint ReadField(ReadOnlySpan<byte> s)
        {
            if (local >= s.Length)
            {
                throw Scroll($"bad offset {local}");
            }

            if (s.Length - local < 4)
            {
                throw Scroll($"type is too big (4) for {s.Length - local}");
            }

            uint v = BinaryPrimitives.ReadUInt32LittleEndian(s[local..]);
            local += 4;
            return v;
        }

        var e = new DirectoryEntry(ReadField(src), ReadField(src), ReadField(src), ReadField(src), ReadField(src));
        offset += ImportDirectoryEntrySize;
        return e;
    }

    private static string ParseEntry(ReadOnlySpan<byte> data, DirectoryEntry entry, IReadOnlyList<PeSection> sections, uint fileAlignment, bool is64)
    {
        string name = TryName(data, entry.NameRva, sections, fileAlignment);

        // Synthesized lookup table (ILT, else IAT): walked for its validation side effects.
        if (FindOffset(entry.Ilt, sections, fileAlignment) is { } iltOffset)
        {
            WalkLookupTable(data, iltOffset, sections, fileAlignment, is64);
        }
        else if (FindOffset(entry.Iat, sections, fileAlignment) is { } iatOffset)
        {
            WalkLookupTable(data, iatOffset, sections, fileAlignment, is64);
        }

        uint rva = entry.Iat == 0 ? entry.Ilt : entry.Iat;
        long addressOffset = FindOffset(rva, sections, fileAlignment)
            ?? throw Malformed($"Cannot map {(entry.Iat == 0 ? "import_lookup_table_rva" : "import_address_table_rva")} {Hex(rva)} into offset for {name}");
        while (ReadThunk(data, ref addressOffset, is64) != 0)
        {
        }

        return name;
    }

    private static void WalkLookupTable(ReadOnlySpan<byte> data, long offset, IReadOnlyList<PeSection> sections, uint fileAlignment, bool is64)
    {
        while (true)
        {
            ulong thunk = ReadThunk(data, ref offset, is64);
            if (thunk == 0)
            {
                return;
            }

            bool ordinal = is64 ? (thunk & 0x8000_0000_0000_0000UL) != 0 : (thunk & 0x8000_0000UL) != 0;
            if (ordinal)
            {
                continue;
            }

            uint hintRva = (uint)(thunk & 0x7fff_ffffUL);
            if (FindOffset(hintRva, sections, fileAlignment) is not { } hintOffset)
            {
                continue;
            }

            // HintNameTableEntry::parse: u16 hint followed by a NUL-delimited UTF-8 name.
            long o = hintOffset;
            ReadU16(data, ref o);
            ReadCStr(data, o);
        }
    }

    private static ulong ReadThunk(ReadOnlySpan<byte> data, ref long offset, bool is64)
    {
        int size = is64 ? 8 : 4;
        if (offset >= data.Length)
        {
            throw Scroll($"bad offset {offset}");
        }

        long remaining = data.Length - offset;
        if (remaining < size)
        {
            throw Scroll($"type is too big ({size}) for {remaining}");
        }

        ulong v = is64
            ? BinaryPrimitives.ReadUInt64LittleEndian(data[(int)offset..])
            : BinaryPrimitives.ReadUInt32LittleEndian(data[(int)offset..]);
        offset += size;
        return v;
    }

    private static void ReadU16(ReadOnlySpan<byte> data, ref long offset)
    {
        if (offset >= data.Length)
        {
            throw Scroll($"bad offset {offset}");
        }

        long remaining = data.Length - offset;
        if (remaining < 2)
        {
            throw Scroll($"type is too big (2) for {remaining}");
        }

        offset += 2;
    }

    private static string ReadCStr(ReadOnlySpan<byte> data, long offset)
    {
        if (offset >= data.Length)
        {
            throw Scroll($"bad offset {offset}");
        }

        var src = data[(int)offset..];
        int nul = src.IndexOf((byte)0);
        var bytes = nul >= 0 ? src[..nul] : src;
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw Scroll($"bad input invalid utf8 ({src.Length})");
        }
    }

    private static string TryName(ReadOnlySpan<byte> data, uint rva, IReadOnlyList<PeSection> sections, uint fileAlignment)
    {
        if (FindOffset(rva, sections, fileAlignment) is not { } offset)
        {
            throw Malformed($"Cannot find name from rva {Hex(rva)} in sections");
        }

        return ReadCStr(data, offset);
    }

    /// <summary>goblin <c>pe::utils::find_offset</c> (with <c>resolve_rva</c> enabled).</summary>
    public static long? FindOffset(uint rva, IReadOnlyList<PeSection> sections, uint fileAlignment)
    {
        if (fileAlignment == 0 || (fileAlignment & (fileAlignment - 1)) != 0)
        {
            return null;
        }

        foreach (var s in sections)
        {
            ulong start = s.VirtualAddress;
            ulong end = start + SectionReadSize(s, fileAlignment);
            if (start <= rva && rva < end)
            {
                return (long)(rva - s.VirtualAddress) + (long)AlignedPointerToRawData(s.PointerToRawData);
            }
        }

        return null;
    }

    private static ulong AlignedPointerToRawData(uint pointer) => pointer & ~0x1ffUL;

    private static ulong SectionReadSize(PeSection s, uint fileAlignment)
    {
        static ulong RoundSize(ulong size) => (size + 0xfff) & ~0xfffUL;

        ulong fa = fileAlignment;
        ulong sizeOfRaw = s.SizeOfRawData;
        ulong virtualSize = s.VirtualSize;
        ulong readSize = ((s.PointerToRawData + sizeOfRaw + fa - 1) & ~(fa - 1)) - AlignedPointerToRawData(s.PointerToRawData);
        readSize = Math.Min(readSize, RoundSize(sizeOfRaw));
        if (virtualSize == 0)
        {
            return readSize;
        }

        return readSize == 0 ? virtualSize : Math.Min(readSize, RoundSize(virtualSize));
    }

    private static string Hex(uint v) => "0x" + v.ToString("x", System.Globalization.CultureInfo.InvariantCulture);

    private static PsignException Malformed(string message) => new($"Malformed entity: {message}");

    private static PsignException Scroll(string message) => new(message);
}
