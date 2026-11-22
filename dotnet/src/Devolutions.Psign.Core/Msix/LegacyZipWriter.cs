using System.Text;

namespace Devolutions.Psign.Core.Msix;

/// <summary>
/// Stored-entry ZIP writer reproducing the Rust <c>zip</c> 0.6.6 <c>ZipWriter</c> layout with
/// <c>FileOptions::default().compression_method(Stored)</c>: Unix "version made by" 0x032e, <c>0o100644</c>
/// external attributes, 1980-01-01 timestamps, no data descriptors and a classic EOCD (ZIP64 records only when
/// required). Used where the Rust code re-zips bundle children before restaging and by tests that build ZIPs.
/// </summary>
internal static class LegacyZipWriter
{
    public static byte[] WriteStored(IEnumerable<(string Name, byte[] Data)> entries)
    {
        using var output = new MemoryStream();
        var w = new BinaryWriter(output);
        var files = new List<(byte[] Name, bool Ascii, uint Crc, ulong Size, ulong HeaderStart)>();
        foreach (var (name, data) in entries)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name);
            bool ascii = nameBytes.All(b => b < 0x80);
            ulong headerStart = (ulong)output.Length;
            uint crc = ZipCrc32.Compute(data);
            ulong size = (ulong)data.Length;
            bool zip64 = size > uint.MaxValue || headerStart > uint.MaxValue;
            w.Write(0x0403_4b50u);
            w.Write((ushort)(zip64 ? 45 : 20));
            w.Write((ushort)(ascii ? 0 : 1 << 11));
            w.Write((ushort)0);
            w.Write((ushort)0);
            w.Write((ushort)0x21);
            w.Write(crc);
            w.Write((uint)size);
            w.Write((uint)size);
            w.Write((ushort)nameBytes.Length);
            w.Write((ushort)0);
            w.Write(nameBytes);
            w.Write(data);
            files.Add((nameBytes, ascii, crc, size, headerStart));
        }

        ulong centralStart = (ulong)output.Length;
        foreach (var f in files)
        {
            var extra = new List<byte>();
            if (f.Size >= uint.MaxValue)
            {
                extra.AddRange(BitConverter.GetBytes(f.Size));
                extra.AddRange(BitConverter.GetBytes(f.Size));
            }

            if (f.HeaderStart >= uint.MaxValue)
            {
                extra.AddRange(BitConverter.GetBytes(f.HeaderStart));
            }

            var zip64Extra = new List<byte>();
            if (extra.Count > 0)
            {
                zip64Extra.AddRange(BitConverter.GetBytes((ushort)1));
                zip64Extra.AddRange(BitConverter.GetBytes((ushort)extra.Count));
                zip64Extra.AddRange(extra);
            }

            bool zip64 = f.Size > uint.MaxValue || f.HeaderStart > uint.MaxValue;
            w.Write(0x0201_4b50u);
            w.Write((ushort)((3 << 8) | 46));
            w.Write((ushort)(zip64 ? 45 : 20));
            w.Write((ushort)(f.Ascii ? 0 : 1 << 11));
            w.Write((ushort)0);
            w.Write((ushort)0);
            w.Write((ushort)0x21);
            w.Write(f.Crc);
            w.Write((uint)Math.Min(f.Size, uint.MaxValue));
            w.Write((uint)Math.Min(f.Size, uint.MaxValue));
            w.Write((ushort)f.Name.Length);
            w.Write((ushort)zip64Extra.Count);
            w.Write((ushort)0);
            w.Write((ushort)0);
            w.Write((ushort)0);
            w.Write(0x81A4u << 16); // 0o100644 << 16
            w.Write((uint)Math.Min(f.HeaderStart, uint.MaxValue));
            w.Write(f.Name);
            w.Write(zip64Extra.ToArray());
        }

        ulong centralSize = (ulong)output.Length - centralStart;
        if (files.Count > ushort.MaxValue || Math.Max(centralSize, centralStart) > uint.MaxValue)
        {
            ulong zip64Start = (ulong)output.Length;
            w.Write(0x0606_4b50u);
            w.Write(44UL);
            w.Write((ushort)46);
            w.Write((ushort)46);
            w.Write(0u);
            w.Write(0u);
            w.Write((ulong)files.Count);
            w.Write((ulong)files.Count);
            w.Write(centralSize);
            w.Write(centralStart);
            w.Write(0x0706_4b50u);
            w.Write(0u);
            w.Write(zip64Start);
            w.Write(1u);
        }

        ushort count = (ushort)Math.Min(files.Count, ushort.MaxValue);
        w.Write(0x0605_4b50u);
        w.Write((ushort)0);
        w.Write((ushort)0);
        w.Write(count);
        w.Write(count);
        w.Write((uint)Math.Min(centralSize, uint.MaxValue));
        w.Write((uint)Math.Min(centralStart, uint.MaxValue));
        w.Write((ushort)0);
        w.Flush();
        return output.ToArray();
    }
}
