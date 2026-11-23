using System.Buffers.Binary;
using System.Text;

namespace Devolutions.Psign.Core.Zip;

/// <summary>
/// ZIP writer that reproduces the byte layout of the Rust <c>zip</c> 0.6.6 <c>ZipWriter</c> (with the <c>deflate</c>
/// feature and <c>flate2</c>'s <c>miniz_oxide</c> backend): local headers without data descriptors or extra fields,
/// version made by <c>0x032E</c> (Unix, 4.6), version needed 20, external attributes <c>0o100644 &lt;&lt; 16</c>
/// (files) / <c>0o40755 &lt;&lt; 16</c> (directories), DEFLATE level 6 via <see cref="MinizDeflater"/>, and a plain
/// end-of-central-directory record (preceded by the ZIP64 end record + locator when more than 65535 entries are written).
/// </summary>
public sealed class ZipCrateWriter
{
    /// <summary>Rust <c>CompressionMethod::Stored</c>.</summary>
    public const ushort Stored = 0;

    /// <summary>Rust <c>CompressionMethod::Deflated</c> (the <c>FileOptions</c> default).</summary>
    public const ushort Deflated = 8;

    private const ushort DefaultVersion = 46;
    private const byte SystemUnix = 3;

    private readonly MemoryStream _out = new();
    private readonly List<CentralRecord> _files = [];
    private bool _finished;

    private sealed record CentralRecord(
        byte[] Name,
        bool NonAscii,
        ushort Method,
        ZipDateTime Modified,
        uint Crc,
        ulong CompressedSize,
        ulong UncompressedSize,
        uint ExternalAttributes,
        ulong HeaderStart);

    /// <summary>Number of entries written so far.</summary>
    public int Count => _files.Count;

    /// <summary>
    /// Write a file entry (Rust <c>start_file</c> + <c>write_all</c>). <paramref name="compression"/> is the raw
    /// compression method; only <see cref="Stored"/> and <see cref="Deflated"/> are supported, like the Rust crate.
    /// </summary>
    public void StartFile(string name, ReadOnlySpan<byte> data, ushort compression = Deflated, ZipDateTime? modified = null, uint? unixPermissions = null)
    {
        uint permissions = (unixPermissions ?? 0x1A4) | 0x8000 /* 0o644 | 0o100000 */;
        byte[] payload = compression switch
        {
            Stored => data.ToArray(),
            Deflated => MinizDeflater.Compress(data),
            _ => throw new PsignException("unsupported Zip archive: Unsupported compression"),
        };
        WriteEntry(name, compression, modified ?? ZipDateTime.Default, permissions, ZipCrc32.Compute(data), (ulong)data.Length, payload);
    }

    /// <summary>Write a directory entry (Rust <c>add_directory</c>): stored, trailing <c>/</c> appended when missing.</summary>
    public void AddDirectory(string name, ZipDateTime? modified = null, uint? unixPermissions = null)
    {
        uint permissions = (unixPermissions ?? 0x1ED) | 0x4000 /* 0o755 | 0o40000 */;
        string withSlash = name.Length > 0 && (name[^1] == '/' || name[^1] == '\\') ? name : name + "/";
        WriteEntry(withSlash, Stored, modified ?? ZipDateTime.Default, permissions, 0, 0, []);
    }

    private void WriteEntry(string name, ushort method, ZipDateTime modified, uint permissions, uint crc, ulong uncompressedSize, byte[] payload)
    {
        if (_finished)
        {
            throw new InvalidOperationException("ZIP writer already finished");
        }

        if (uncompressedSize >= 0xFFFFFFFF || (ulong)payload.Length >= 0xFFFFFFFF)
        {
            throw new PsignException("Large file option has not been set");
        }

        var nameBytes = Encoding.UTF8.GetBytes(name);
        bool nonAscii = nameBytes.Any(b => b >= 0x80);
        ulong headerStart = (ulong)_out.Position;

        Span<byte> h = stackalloc byte[30];
        BinaryPrimitives.WriteUInt32LittleEndian(h, 0x04034b50);
        BinaryPrimitives.WriteUInt16LittleEndian(h[4..], 20);
        BinaryPrimitives.WriteUInt16LittleEndian(h[6..], (ushort)(nonAscii ? 1 << 11 : 0));
        BinaryPrimitives.WriteUInt16LittleEndian(h[8..], method);
        BinaryPrimitives.WriteUInt16LittleEndian(h[10..], modified.TimePart);
        BinaryPrimitives.WriteUInt16LittleEndian(h[12..], modified.DatePart);
        BinaryPrimitives.WriteUInt32LittleEndian(h[14..], crc);
        BinaryPrimitives.WriteUInt32LittleEndian(h[18..], (uint)payload.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(h[22..], (uint)uncompressedSize);
        BinaryPrimitives.WriteUInt16LittleEndian(h[26..], (ushort)nameBytes.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(h[28..], 0);
        _out.Write(h);
        _out.Write(nameBytes);
        _out.Write(payload);

        _files.Add(new CentralRecord(nameBytes, nonAscii, method, modified, crc, (ulong)payload.Length, uncompressedSize, permissions << 16, headerStart));
    }

    /// <summary>Write the central directory and end record (Rust <c>finish</c>) and return the archive bytes.</summary>
    public byte[] Finish()
    {
        if (!_finished)
        {
            _finished = true;
            ulong centralStart = (ulong)_out.Position;
            Span<byte> c = stackalloc byte[46];
            foreach (var f in _files)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(c, 0x02014b50);
                BinaryPrimitives.WriteUInt16LittleEndian(c[4..], (ushort)((SystemUnix << 8) | DefaultVersion));
                BinaryPrimitives.WriteUInt16LittleEndian(c[6..], 20);
                BinaryPrimitives.WriteUInt16LittleEndian(c[8..], (ushort)(f.NonAscii ? 1 << 11 : 0));
                BinaryPrimitives.WriteUInt16LittleEndian(c[10..], f.Method);
                BinaryPrimitives.WriteUInt16LittleEndian(c[12..], f.Modified.TimePart);
                BinaryPrimitives.WriteUInt16LittleEndian(c[14..], f.Modified.DatePart);
                BinaryPrimitives.WriteUInt32LittleEndian(c[16..], f.Crc);
                BinaryPrimitives.WriteUInt32LittleEndian(c[20..], (uint)Math.Min(f.CompressedSize, 0xFFFFFFFF));
                BinaryPrimitives.WriteUInt32LittleEndian(c[24..], (uint)Math.Min(f.UncompressedSize, 0xFFFFFFFF));
                BinaryPrimitives.WriteUInt16LittleEndian(c[28..], (ushort)f.Name.Length);
                BinaryPrimitives.WriteUInt16LittleEndian(c[30..], 0);
                BinaryPrimitives.WriteUInt16LittleEndian(c[32..], 0);
                BinaryPrimitives.WriteUInt16LittleEndian(c[34..], 0);
                BinaryPrimitives.WriteUInt16LittleEndian(c[36..], 0);
                BinaryPrimitives.WriteUInt32LittleEndian(c[38..], f.ExternalAttributes);
                BinaryPrimitives.WriteUInt32LittleEndian(c[42..], (uint)Math.Min(f.HeaderStart, 0xFFFFFFFF));
                _out.Write(c);
                _out.Write(f.Name);
            }

            ulong centralSize = (ulong)_out.Position - centralStart;
            if (_files.Count > ushort.MaxValue || Math.Max(centralSize, centralStart) > 0xFFFFFFFF)
            {
                // Rust write_central_and_footer: ZIP64 end record + locator before the classic EOCD.
                ulong zip64Start = (ulong)_out.Position;
                Span<byte> z = stackalloc byte[56 + 20];
                BinaryPrimitives.WriteUInt32LittleEndian(z, 0x06064b50);
                BinaryPrimitives.WriteUInt64LittleEndian(z[4..], 44);
                BinaryPrimitives.WriteUInt16LittleEndian(z[12..], DefaultVersion);
                BinaryPrimitives.WriteUInt16LittleEndian(z[14..], DefaultVersion);
                BinaryPrimitives.WriteUInt32LittleEndian(z[16..], 0);
                BinaryPrimitives.WriteUInt32LittleEndian(z[20..], 0);
                BinaryPrimitives.WriteUInt64LittleEndian(z[24..], (ulong)_files.Count);
                BinaryPrimitives.WriteUInt64LittleEndian(z[32..], (ulong)_files.Count);
                BinaryPrimitives.WriteUInt64LittleEndian(z[40..], centralSize);
                BinaryPrimitives.WriteUInt64LittleEndian(z[48..], centralStart);
                BinaryPrimitives.WriteUInt32LittleEndian(z[56..], 0x07064b50);
                BinaryPrimitives.WriteUInt32LittleEndian(z[60..], 0);
                BinaryPrimitives.WriteUInt64LittleEndian(z[64..], zip64Start);
                BinaryPrimitives.WriteUInt32LittleEndian(z[72..], 1);
                _out.Write(z);
            }

            ushort count = (ushort)Math.Min(_files.Count, ushort.MaxValue);
            Span<byte> e = stackalloc byte[22];
            BinaryPrimitives.WriteUInt32LittleEndian(e, 0x06054b50);
            BinaryPrimitives.WriteUInt16LittleEndian(e[4..], 0);
            BinaryPrimitives.WriteUInt16LittleEndian(e[6..], 0);
            BinaryPrimitives.WriteUInt16LittleEndian(e[8..], count);
            BinaryPrimitives.WriteUInt16LittleEndian(e[10..], count);
            BinaryPrimitives.WriteUInt32LittleEndian(e[12..], (uint)Math.Min(centralSize, 0xFFFFFFFF));
            BinaryPrimitives.WriteUInt32LittleEndian(e[16..], (uint)Math.Min(centralStart, 0xFFFFFFFF));
            BinaryPrimitives.WriteUInt16LittleEndian(e[20..], 0);
            _out.Write(e);
        }

        return _out.ToArray();
    }

    /// <summary>
    /// Write <paramref name="entries"/> as stored files with default options (1980-01-01, <c>0o100644</c>) and return the
    /// finished archive (Rust <c>ZipWriter</c> + <c>FileOptions::default().compression_method(Stored)</c>). Used where the
    /// Rust MSIX code re-zips bundle children before restaging and by tests that build ZIPs.
    /// </summary>
    public static byte[] WriteStored(IEnumerable<(string Name, byte[] Data)> entries)
    {
        var writer = new ZipCrateWriter();
        foreach (var (name, data) in entries)
        {
            writer.StartFile(name, data, Stored);
        }

        return writer.Finish();
    }
}
