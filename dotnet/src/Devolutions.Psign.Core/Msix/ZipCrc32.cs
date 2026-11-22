namespace Devolutions.Psign.Core.Msix;

/// <summary>IEEE CRC-32 (ZIP / <c>flate2::Crc</c>).</summary>
public static class ZipCrc32
{
    private static readonly uint[] Table = BuildTable();

    /// <summary>Compute the CRC-32 of <paramref name="data"/>.</summary>
    public static uint Compute(ReadOnlySpan<byte> data) => Update(0, data);

    /// <summary>Continue a CRC-32 computation.</summary>
    public static uint Update(uint crc, ReadOnlySpan<byte> data)
    {
        uint c = ~crc;
        foreach (byte b in data)
        {
            c = Table[(c ^ b) & 0xFF] ^ (c >> 8);
        }

        return ~c;
    }

    private static uint[] BuildTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
            {
                c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            }

            t[i] = c;
        }

        return t;
    }
}
