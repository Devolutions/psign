using System.Buffers.Binary;
using System.Text;

namespace Devolutions.Psign.Verification.AuthRoot;

/// <summary>
/// Minimal read-only Microsoft Cabinet (<c>MSCF</c>) parser with uncompressed and MSZIP folders, following the Rust
/// <c>cab</c> crate behaviour (header validation, per-block checksums, error texts).
/// </summary>
internal sealed class CabinetReader
{
    private const uint FileSignature = 0x4643534D; // "MSCF"
    private const uint MaxTotalCabSize = 0x7FFF8000;
    private const ushort FlagPrevCabinet = 0x0001;
    private const ushort FlagNextCabinet = 0x0002;
    private const ushort FlagReservePresent = 0x0004;
    private const int MaxStringSize = 255;

    private readonly byte[] _data;
    private readonly byte _dataReserveSize;

    private sealed record Folder(uint FirstDataOffset, ushort NumDataBlocks, ushort CompressionType);

    internal sealed record FileEntry(string Name, uint UncompressedSize, uint UncompressedOffset, ushort FolderIndex);

    private readonly List<Folder> _folders = [];

    private CabinetReader(byte[] data, byte dataReserveSize)
    {
        _data = data;
        _dataReserveSize = dataReserveSize;
    }

    /// <summary>File entries in header order.</summary>
    public List<FileEntry> Files { get; } = [];

    private sealed class Cursor(byte[] data, int pos)
    {
        public int Pos { get; set; } = pos;

        private ReadOnlySpan<byte> Take(int n)
        {
            if (Pos < 0 || Pos + n > data.Length)
            {
                throw new EndOfStreamException("failed to fill whole buffer");
            }

            var s = data.AsSpan(Pos, n);
            Pos += n;
            return s;
        }

        public byte U8() => Take(1)[0];

        public ushort U16() => BinaryPrimitives.ReadUInt16LittleEndian(Take(2));

        public uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));

        public byte[] Bytes(int n) => Take(n).ToArray();

        public string NullTerminated()
        {
            var bytes = new List<byte>();
            while (true)
            {
                byte b = U8();
                if (b == 0)
                {
                    break;
                }

                if (bytes.Count == MaxStringSize)
                {
                    throw new InvalidDataException($"String longer than maximum of {MaxStringSize} bytes");
                }

                bytes.Add(b);
            }

            return Encoding.UTF8.GetString(bytes.ToArray());
        }
    }

    /// <summary>Open a cabinet (Rust <c>Cabinet::new</c>).</summary>
    public static CabinetReader Open(byte[] data)
    {
        var r = new Cursor(data, 0);
        if (r.U32() != FileSignature)
        {
            throw new InvalidDataException("Not a cabinet file (invalid file signature)");
        }

        r.U32();
        uint totalSize = r.U32();
        if (totalSize > MaxTotalCabSize)
        {
            throw new InvalidDataException($"Cabinet total size field is too large ({totalSize} bytes; max is {MaxTotalCabSize} bytes)");
        }

        r.U32();
        uint firstFileOffset = r.U32();
        r.U32();
        byte minor = r.U8();
        byte major = r.U8();
        if (major > 1 || (major == 1 && minor > 3))
        {
            throw new InvalidDataException($"Version {major}.{minor} cabinet files are not supported");
        }

        int numFolders = r.U16();
        int numFiles = r.U16();
        ushort flags = r.U16();
        r.U16();
        r.U16();
        ushort headerReserve = 0;
        byte folderReserve = 0;
        byte dataReserve = 0;
        if ((flags & FlagReservePresent) != 0)
        {
            headerReserve = r.U16();
            folderReserve = r.U8();
            dataReserve = r.U8();
        }

        if (headerReserve > 0)
        {
            r.Bytes(headerReserve);
        }

        if ((flags & FlagPrevCabinet) != 0)
        {
            r.NullTerminated();
            r.NullTerminated();
        }

        if ((flags & FlagNextCabinet) != 0)
        {
            r.NullTerminated();
            r.NullTerminated();
        }

        var cab = new CabinetReader(data, dataReserve);
        for (int i = 0; i < numFolders; i++)
        {
            uint firstData = r.U32();
            ushort blocks = r.U16();
            ushort compression = r.U16();
            ValidateCompression(compression);
            if (folderReserve > 0)
            {
                r.Bytes(folderReserve);
            }

            cab._folders.Add(new Folder(firstData, blocks, compression));
        }

        if (firstFileOffset > (uint)data.Length)
        {
            throw new EndOfStreamException("failed to fill whole buffer");
        }

        r.Pos = (int)firstFileOffset;
        for (int i = 0; i < numFiles; i++)
        {
            uint size = r.U32();
            uint offset = r.U32();
            ushort folderIndex = r.U16();
            r.U16();
            r.U16();
            r.U16();
            string name = r.NullTerminated();
            if (folderIndex >= cab._folders.Count)
            {
                throw new InvalidDataException("File entry folder index out of bounds");
            }

            cab.Files.Add(new FileEntry(name, size, offset, folderIndex));
        }

        return cab;
    }

    private static void ValidateCompression(ushort bits)
    {
        switch (bits & 0x000F)
        {
            case 0:
            case 1:
                return;
            case 2:
                int level = (bits & 0x00F0) >> 4;
                int memory = (bits & 0x1F00) >> 8;
                if (level is < 1 or > 7)
                {
                    throw new InvalidDataException($"Invalid Quantum level: 0x{level:x2}");
                }

                if (memory is < 10 or > 21)
                {
                    throw new InvalidDataException($"Invalid Quantum memory: 0x{memory:x2}");
                }

                return;
            case 3:
                int window = (bits & 0x1F00) >> 8;
                if (window is < 15 or > 21)
                {
                    throw new InvalidDataException($"Invalid LZX window: 0x{window:x2}");
                }

                return;
            default:
                throw new InvalidDataException($"Invalid compression type: 0x{bits:x4}");
        }
    }

    private static uint Checksum(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        uint value = 0;
        uint remainder = 0;
        int shift = 0;
        void Update(ReadOnlySpan<byte> buf)
        {
            foreach (var by in buf)
            {
                remainder |= (uint)by << shift;
                if (shift == 24)
                {
                    value ^= remainder;
                    remainder = 0;
                    shift = 0;
                }
                else
                {
                    shift += 8;
                }
            }
        }

        Update(a);
        Update(b);
        return shift switch
        {
            0 => value,
            8 => value ^ remainder,
            16 => value ^ (remainder >> 8) ^ ((remainder & 0xff) << 8),
            _ => value ^ (remainder >> 16) ^ (remainder & 0xff00) ^ ((remainder & 0xff) << 16),
        };
    }

    /// <summary>Decompress the folder holding <paramref name="name"/> and return the file's bytes.</summary>
    public byte[] ReadFile(string name)
    {
        var entry = Files.FirstOrDefault(f => f.Name == name)
            ?? throw new FileNotFoundException($"No such file in cabinet: \"{name}\"");
        var folder = _folders[entry.FolderIndex];
        long need = (long)entry.UncompressedOffset + entry.UncompressedSize;
        using var output = new MemoryStream();
        var inflater = new MsZipInflater();
        if (folder.FirstDataOffset > (uint)_data.Length)
        {
            throw new EndOfStreamException("failed to fill whole buffer");
        }

        var r = new Cursor(_data, (int)folder.FirstDataOffset);
        int ctype = folder.CompressionType & 0x000F;
        for (int i = 0; i < folder.NumDataBlocks && output.Length < need; i++)
        {
            uint csum = r.U32();
            ushort cbData = r.U16();
            ushort cbUncomp = r.U16();
            var reserve = _dataReserveSize > 0 ? r.Bytes(_dataReserveSize) : [];
            var compressed = r.Bytes(cbData);
            if (csum != 0)
            {
                uint actual = Checksum(reserve, compressed) ^ (cbData | ((uint)cbUncomp << 16));
                if (actual != csum)
                {
                    throw new InvalidDataException($"Checksum error in data block {i} (expected {csum:x8}, actual {actual:x8})");
                }
            }

            byte[] block = ctype switch
            {
                0 => compressed.Length == cbUncomp
                    ? compressed
                    : throw new InvalidDataException(
                        $"Uncompressed block has data size {compressed.Length}, but uncompressed size {cbUncomp}"),
                1 => inflater.DecompressBlock(compressed, cbUncomp),
                2 => throw new InvalidDataException("Quantum decompression is not yet supported."),
                _ => throw new InvalidDataException("LZX decompression is not supported by the portable C# cabinet reader."),
            };
            output.Write(block);
        }

        if (output.Length < need)
        {
            throw new EndOfStreamException("failed to fill whole buffer");
        }

        var all = output.GetBuffer();
        return all.AsSpan((int)entry.UncompressedOffset, (int)entry.UncompressedSize).ToArray();
    }
}
