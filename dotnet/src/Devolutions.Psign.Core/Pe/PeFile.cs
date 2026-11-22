using System.Buffers.Binary;

namespace Devolutions.Psign.Core.Pe;

/// <summary>A half-open byte range [Start, End).</summary>
public readonly record struct ByteRange(int Start, int End)
{
    public int Length => End - Start;

    public override string ToString() => $"{Start}..{End}";
}

/// <summary>PE <c>WIN_CERTIFICATE</c> attribute certificate entry.</summary>
public sealed record AttributeCertificate(ushort Revision, ushort CertificateType, int DataOffset, int DataLength)
{
    public const ushort WinCertRevision20 = 0x0200;
    public const ushort WinCertTypePkcsSignedData = 0x0002;
}

/// <summary>
/// Read-only PE32 / PE32+ view providing the offsets used by Authenticode hashing. Mirrors the <c>object</c> crate's
/// <c>PeFile</c> validation plus the <c>authenticode</c> crate's <c>PeTrait</c> offsets.
/// </summary>
public sealed class PeFile
{
    public const ushort Pe32Magic = 0x10b;
    public const ushort Pe32PlusMagic = 0x20b;
    public const int ImageDirectoryEntrySecurity = 4;

    private readonly byte[] _data;

    private PeFile(byte[] data)
    {
        _data = data;
        ReadOnlySpan<byte> d = data;
        if (d.Length < 64)
        {
            throw new PsignException("not a PE image: file too small for DOS header");
        }

        if (d[0] != (byte)'M' || d[1] != (byte)'Z')
        {
            throw new PsignException("not a PE image: missing MZ signature");
        }

        uint lfanew = BinaryPrimitives.ReadUInt32LittleEndian(d[0x3C..]);
        if (lfanew > (uint)d.Length || lfanew + 4L + 20 > d.Length)
        {
            throw new PsignException("not a PE image: invalid e_lfanew");
        }

        NtHeadersOffset = (int)lfanew;
        if (!d.Slice(NtHeadersOffset, 4).SequenceEqual("PE\0\0"u8))
        {
            throw new PsignException("not a PE image: missing PE signature");
        }

        int fileHeader = NtHeadersOffset + 4;
        Machine = BinaryPrimitives.ReadUInt16LittleEndian(d[fileHeader..]);
        NumberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(d[(fileHeader + 2)..]);
        SizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(d[(fileHeader + 16)..]);
        Characteristics = BinaryPrimitives.ReadUInt16LittleEndian(d[(fileHeader + 18)..]);
        OptionalHeaderOffset = fileHeader + 20;
        if (OptionalHeaderOffset + 2 > d.Length)
        {
            throw new PsignException("not a PE image: truncated optional header");
        }

        Magic = BinaryPrimitives.ReadUInt16LittleEndian(d[OptionalHeaderOffset..]);
        int fixedSize = Magic switch
        {
            Pe32Magic => 96,
            Pe32PlusMagic => 112,
            _ => throw new PsignException($"expected PE32 or PE32+ file, got optional header magic 0x{Magic:x}"),
        };
        OptionalHeaderFixedSize = fixedSize;
        if (SizeOfOptionalHeader < fixedSize || OptionalHeaderOffset + (long)SizeOfOptionalHeader > d.Length)
        {
            throw new PsignException("PE parse failed: invalid SizeOfOptionalHeader");
        }

        SizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(d[(OptionalHeaderOffset + 60)..]);
        CheckSum = BinaryPrimitives.ReadUInt32LittleEndian(d[(OptionalHeaderOffset + 64)..]);
        uint numRva = BinaryPrimitives.ReadUInt32LittleEndian(d[(OptionalHeaderOffset + fixedSize - 4)..]);
        int maxDirs = (SizeOfOptionalHeader - fixedSize) / 8;
        if (numRva > maxDirs)
        {
            throw new PsignException("PE parse failed: NumberOfRvaAndSizes exceeds optional header size");
        }

        NumberOfRvaAndSizes = (int)numRva;
        DataDirectoriesOffset = OptionalHeaderOffset + fixedSize;

        SectionTableOffset = OptionalHeaderOffset + SizeOfOptionalHeader;
        if (SectionTableOffset + (long)NumberOfSections * 40 > d.Length)
        {
            throw new PsignException("PE parse failed: section table out of bounds");
        }

        var sections = new List<PeSection>(NumberOfSections);
        for (int i = 0; i < NumberOfSections; i++)
        {
            int o = SectionTableOffset + (i * 40);
            var nameBytes = d.Slice(o, 8);
            int nul = nameBytes.IndexOf((byte)0);
            string name = System.Text.Encoding.UTF8.GetString(nul >= 0 ? nameBytes[..nul] : nameBytes);
            sections.Add(new PeSection(
                name,
                BinaryPrimitives.ReadUInt32LittleEndian(d[(o + 8)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(d[(o + 12)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(d[(o + 16)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(d[(o + 20)..]),
                BinaryPrimitives.ReadUInt32LittleEndian(d[(o + 36)..])));
        }

        Sections = sections;
    }

    /// <summary>Underlying image bytes (not copied).</summary>
    public ReadOnlySpan<byte> Data => _data;

    public int NtHeadersOffset { get; }

    public ushort Machine { get; }

    public ushort NumberOfSections { get; }

    public ushort SizeOfOptionalHeader { get; }

    public ushort Characteristics { get; }

    public int OptionalHeaderOffset { get; }

    /// <summary>Size of the fixed optional header (96 for PE32, 112 for PE32+), excluding data directories.</summary>
    public int OptionalHeaderFixedSize { get; }

    public ushort Magic { get; }

    public bool IsPe32Plus => Magic == Pe32PlusMagic;

    public uint SizeOfHeaders { get; }

    public uint CheckSum { get; }

    public int NumberOfRvaAndSizes { get; }

    public int DataDirectoriesOffset { get; }

    public int SectionTableOffset { get; }

    public IReadOnlyList<PeSection> Sections { get; }

    /// <summary>File offset of the optional header <c>CheckSum</c> field.</summary>
    public int CheckSumOffset => OptionalHeaderOffset + 64;

    /// <summary>File offset of the security data directory entry (even when beyond NumberOfRvaAndSizes).</summary>
    public int SecurityDirectoryOffset => DataDirectoriesOffset + (8 * ImageDirectoryEntrySecurity);

    /// <summary>Parse a PE image (the buffer is referenced, not copied).</summary>
    public static PeFile Parse(byte[] image) => new(image);

    /// <summary>Try to parse a PE image.</summary>
    public static PeFile? TryParse(byte[] image)
    {
        try
        {
            return new PeFile(image);
        }
        catch (PsignException)
        {
            return null;
        }
    }

    /// <summary>Data directory entry (VirtualAddress, Size) or <c>null</c> when absent or zero (object crate semantics).</summary>
    public (uint VirtualAddress, uint Size)? DataDirectory(int index)
    {
        if (index >= NumberOfRvaAndSizes)
        {
            return null;
        }

        int o = DataDirectoriesOffset + (8 * index);
        uint va = BinaryPrimitives.ReadUInt32LittleEndian(Data[o..]);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(Data[(o + 4)..]);
        if (va == 0)
        {
            return null;
        }

        return (va, size);
    }

    /// <summary>Certificate table file range from the security directory, or <c>null</c>.</summary>
    public ByteRange? CertificateTableRange()
    {
        var dir = DataDirectory(ImageDirectoryEntrySecurity);
        if (dir is null)
        {
            return null;
        }

        long end = (long)dir.Value.VirtualAddress + dir.Value.Size;
        if (end > int.MaxValue)
        {
            throw new PsignException("an offset within the PE is invalid");
        }

        return new ByteRange((int)dir.Value.VirtualAddress, (int)end);
    }

    /// <summary>
    /// File byte ranges hashed by Authenticode, in order (Rust <c>pe_authenticode_digest_file_ranges</c>).
    /// </summary>
    public List<ByteRange> AuthenticodeDigestRanges()
    {
        var err = new PsignException("PE layout invalid for Authenticode digest ranges (checksum/security-directory offsets)");
        int checkSum = CheckSumOffset;
        int afterCheckSum = checkSum + 4;
        int secDir = SecurityDirectoryOffset;
        int afterSecDir = secDir + 8;
        long afterHeader = SizeOfHeaders;
        int len = _data.Length;
        if (checkSum > len || afterCheckSum > secDir || secDir > len || afterSecDir > afterHeader || afterHeader > len)
        {
            throw err;
        }

        var ranges = new List<ByteRange>
        {
            new(0, checkSum),
            new(afterCheckSum, secDir),
            new(afterSecDir, (int)afterHeader),
        };

        long sum = afterHeader;
        var sectionRanges = new List<ByteRange>();
        foreach (var s in Sections)
        {
            long start = s.PointerToRawData;
            long end = start + s.SizeOfRawData;
            if (end > len)
            {
                throw err;
            }

            sectionRanges.Add(new ByteRange((int)start, (int)end));
        }

        sectionRanges.Sort((a, b) => a.Start.CompareTo(b.Start));
        foreach (var r in sectionRanges)
        {
            sum += r.Length;
            ranges.Add(r);
        }

        long extra = len - sum;
        if (extra < 0)
        {
            throw err;
        }

        var cert = CertificateTableRange();
        if (cert is not null)
        {
            extra -= cert.Value.Length;
            if (extra < 0)
            {
                throw err;
            }
        }

        long tailEnd = sum + extra;
        if (tailEnd > len)
        {
            throw err;
        }

        ranges.Add(new ByteRange((int)sum, (int)tailEnd));
        return ranges;
    }

    /// <summary>Authenticode image digest (excludes checksum, security directory, and certificate table).</summary>
    public byte[] AuthenticodeDigest(AuthenticodeHashKind kind)
    {
        List<ByteRange> ranges;
        try
        {
            ranges = AuthenticodeDigestRanges();
        }
        catch (PsignException e)
        {
            throw new PsignException("authenticode_digest failed", e);
        }

        using var h = kind.CreateHasher();
        foreach (var r in ranges)
        {
            h.AppendData(_data, r.Start, r.Length);
        }

        return h.GetHashAndReset();
    }

    /// <summary>
    /// Enumerate the attribute certificate table (Rust <c>AttributeCertificateIterator</c>). Returns <c>null</c> when
    /// there is no certificate table.
    /// </summary>
    public List<AttributeCertificate>? AttributeCertificates()
    {
        var range = CertificateTableRange();
        if (range is null)
        {
            return null;
        }

        var r = range.Value;
        if (r.Start < 0 || r.End > _data.Length || r.Start > r.End)
        {
            throw new PsignException("certificate table invalid: certificate table range is out of bounds");
        }

        var (entries, remaining, error) = Iterate(r.Start, r.End);
        if (error is null && remaining != 0)
        {
            throw new PsignException(
                "certificate table invalid: certificate table size does not match the sum of the certificate entry's aligned sizes");
        }

        if (error is not null)
        {
            // check_total_size_valid consumes errors as terminal entries; Rust surfaces them during iteration.
            throw new PsignException($"attribute certificate entry invalid: {error}");
        }

        return entries;
    }

    private (List<AttributeCertificate> Entries, int Remaining, string? Error) Iterate(int start, int end)
    {
        var list = new List<AttributeCertificate>();
        int pos = start;
        while (end - pos >= 8)
        {
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(Data[pos..]);
            ushort rev = BinaryPrimitives.ReadUInt16LittleEndian(Data[(pos + 4)..]);
            ushort type = BinaryPrimitives.ReadUInt16LittleEndian(Data[(pos + 6)..]);
            if (size < 8 || size > (uint)(end - pos))
            {
                return (list, 0, $"certificate table contains an entry with an invalid size: {size}");
            }

            list.Add(new AttributeCertificate(rev, type, pos + 8, (int)size - 8));
            long rounded = (size + 7L) & ~7L;
            if (pos + rounded > end)
            {
                // Rust: remaining_data.get(size_rounded_up..) returns None -> iteration ends, remaining unchanged.
                return (list, end - pos, null);
            }

            pos += (int)rounded;
        }

        return (list, end - pos, null);
    }

    /// <summary>Data of an attribute certificate.</summary>
    public ReadOnlySpan<byte> CertificateData(AttributeCertificate cert) => Data.Slice(cert.DataOffset, cert.DataLength);
}

/// <summary>PE section header subset.</summary>
public sealed record PeSection(string Name, uint VirtualSize, uint VirtualAddress, uint SizeOfRawData, uint PointerToRawData, uint Characteristics);
