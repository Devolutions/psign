using System.Buffers.Binary;

namespace Devolutions.Psign.Core.Pe;

/// <summary>
/// PE attribute certificate table layout helpers (port of <c>pe_embed.rs</c>): checksum, <c>WIN_CERTIFICATE</c> wrapping,
/// alignment preparation, append / replace / remove.
/// </summary>
public static class PeEmbed
{
    private const int PeOffset = 0x3C;
    private const int AttributeCertificateAlignment = 8;
    private const int OptionalHeaderChecksumOffset = 64;

    private static int ChecksumFieldOffset(ReadOnlySpan<byte> pe)
    {
        var (optionalStart, _) = OptionalHeaderStart(pe);
        int off = optionalStart + OptionalHeaderChecksumOffset;
        if (off + 4 > pe.Length)
        {
            throw new PsignException("PE image truncated before Optional Header CheckSum");
        }

        return off;
    }

    /// <summary>Compute the PE image checksum (<c>CheckSumMappedFile</c> algorithm).</summary>
    public static uint ComputeImageChecksum(ReadOnlySpan<byte> image)
    {
        int checkOff = ChecksumFieldOffset(image);
        ulong sum = 0;
        int i = 0;
        while (i < image.Length)
        {
            if (i >= checkOff && i < checkOff + 4)
            {
                i = checkOff + 4;
                continue;
            }

            if (i + 1 < image.Length)
            {
                sum += BinaryPrimitives.ReadUInt16LittleEndian(image[i..]);
            }
            else
            {
                sum += image[i];
            }

            sum = (sum >> 16) + (sum & 0xFFFF);
            i += 2;
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        return unchecked((uint)sum + (uint)image.Length);
    }

    /// <summary>Write the optional header <c>CheckSum</c> field.</summary>
    public static void WriteImageChecksum(Span<byte> image, uint checksum)
    {
        int off = ChecksumFieldOffset(image);
        BinaryPrimitives.WriteUInt32LittleEndian(image[off..], checksum);
    }

    /// <summary>Read the optional header <c>CheckSum</c> field.</summary>
    public static uint ReadImageChecksum(ReadOnlySpan<byte> image)
    {
        int off = ChecksumFieldOffset(image);
        return BinaryPrimitives.ReadUInt32LittleEndian(image[off..]);
    }

    private static void RefreshImageChecksum(byte[] image) => WriteImageChecksum(image, ComputeImageChecksum(image));

    /// <summary>Wrap PKCS#7 DER in a <c>WIN_CERTIFICATE</c> record padded to 8 bytes.</summary>
    public static byte[] WrapPkcs7InWinCertificate(ReadOnlySpan<byte> pkcs7)
    {
        int len = 8 + pkcs7.Length;
        int padded = (len + 7) & ~7;
        var body = new byte[padded];
        BinaryPrimitives.WriteUInt32LittleEndian(body, (uint)padded);
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(4), AttributeCertificate.WinCertRevision20);
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(6), AttributeCertificate.WinCertTypePkcsSignedData);
        pkcs7.CopyTo(body.AsSpan(8));
        return body;
    }

    private static (int OptionalStart, ushort Magic) OptionalHeaderStart(ReadOnlySpan<byte> pe)
    {
        if (pe.Length < PeOffset + 4)
        {
            throw new PsignException("PE image too small");
        }

        if (pe[0] != 0x4D || pe[1] != 0x5A)
        {
            throw new PsignException("missing MZ DOS stub");
        }

        long peOff = BinaryPrimitives.ReadUInt32LittleEndian(pe[PeOffset..]);
        if (peOff + 24 > pe.Length)
        {
            throw new PsignException("invalid e_lfanew");
        }

        if (!pe.Slice((int)peOff, 4).SequenceEqual("PE\0\0"u8))
        {
            throw new PsignException("missing PE signature");
        }

        int optionalStart = (int)peOff + 4 + 20;
        if (optionalStart + 2 > pe.Length)
        {
            throw new PsignException("truncated optional header");
        }

        return (optionalStart, BinaryPrimitives.ReadUInt16LittleEndian(pe[optionalStart..]));
    }

    private static int DataDirectoryEntryOffset(int optionalStart, ushort magic)
    {
        int dir0 = magic switch
        {
            PeFile.Pe32Magic => optionalStart + 96,
            PeFile.Pe32PlusMagic => optionalStart + 112,
            _ => throw new PsignException($"unsupported optional header magic 0x{magic:x}"),
        };
        return dir0 + (PeFile.ImageDirectoryEntrySecurity * 8);
    }

    private static int NumberOfRvaAndSizesOffset(int optionalStart, ushort magic) => magic switch
    {
        PeFile.Pe32Magic => optionalStart + 92,
        PeFile.Pe32PlusMagic => optionalStart + 108,
        _ => throw new PsignException($"unsupported optional header magic 0x{magic:x}"),
    };

    /// <summary>Read the raw security data directory (file pointer, size).</summary>
    public static (uint FilePointer, uint Size) ReadSecurityDataDirectory(ReadOnlySpan<byte> pe)
    {
        var (optionalStart, magic) = OptionalHeaderStart(pe);
        int numRvaOff = NumberOfRvaAndSizesOffset(optionalStart, magic);
        if (numRvaOff + 4 > pe.Length)
        {
            throw new PsignException("truncated NumberOfRvaAndSizes");
        }

        uint num = BinaryPrimitives.ReadUInt32LittleEndian(pe[numRvaOff..]);
        if (num <= PeFile.ImageDirectoryEntrySecurity)
        {
            throw new PsignException($"PE optional header has only {num} data directories (need security slot)");
        }

        int ddOff = DataDirectoryEntryOffset(optionalStart, magic);
        if (ddOff + 8 > pe.Length)
        {
            throw new PsignException("truncated security data directory");
        }

        return (BinaryPrimitives.ReadUInt32LittleEndian(pe[ddOff..]), BinaryPrimitives.ReadUInt32LittleEndian(pe[(ddOff + 4)..]));
    }

    private static void WriteSecurityDataDirectory(Span<byte> pe, uint filePointer, uint size)
    {
        var (optionalStart, magic) = OptionalHeaderStart(pe);
        int ddOff = DataDirectoryEntryOffset(optionalStart, magic);
        if (ddOff + 8 > pe.Length)
        {
            throw new PsignException("truncated security data directory (write)");
        }

        BinaryPrimitives.WriteUInt32LittleEndian(pe[ddOff..], filePointer);
        BinaryPrimitives.WriteUInt32LittleEndian(pe[(ddOff + 4)..], size);
    }

    private static void ValidateAlignment(uint filePointer, uint size)
    {
        if (filePointer == 0 && size == 0)
        {
            return;
        }

        if (filePointer == 0 || size == 0)
        {
            throw new PsignException($"incomplete PE certificate table directory: offset {filePointer}, size {size}");
        }

        if (filePointer % AttributeCertificateAlignment != 0)
        {
            throw new PsignException($"PE certificate table offset {filePointer} is not 8-byte aligned");
        }

        if (size % AttributeCertificateAlignment != 0)
        {
            throw new PsignException($"PE certificate table size {size} is not 8-byte aligned");
        }
    }

    /// <summary>Validate that the certificate table directory is complete and 8-byte aligned.</summary>
    public static void ValidateAttributeCertificateTableAlignment(ReadOnlySpan<byte> pe)
    {
        var (ptr, size) = ReadSecurityDataDirectory(pe);
        ValidateAlignment(ptr, size);
    }

    /// <summary>
    /// Prepare an unsigned image for Authenticode signing: pad the file to an 8-byte boundary when there is no
    /// certificate table yet. Call before computing the digest.
    /// </summary>
    public static byte[] PrepareForAuthenticodeSigning(byte[] image)
    {
        var (ptr, size) = ReadSecurityDataDirectory(image);
        ValidateAlignment(ptr, size);
        if (ptr != 0)
        {
            return image;
        }

        int remainder = image.Length % AttributeCertificateAlignment;
        int padding = (AttributeCertificateAlignment - remainder) % AttributeCertificateAlignment;
        if (padding == 0)
        {
            return image;
        }

        var padded = new byte[image.Length + padding];
        image.CopyTo(padded, 0);
        return padded;
    }

    /// <summary>Append a PKCS#7 signature as a new <c>WIN_CERTIFICATE</c> and refresh the checksum.</summary>
    public static byte[] AppendPkcs7Certificate(byte[] image, ReadOnlySpan<byte> pkcs7)
    {
        var wrapped = WrapPkcs7InWinCertificate(pkcs7);
        var (va, size) = ReadSecurityDataDirectory(image);
        ValidateAlignment(va, size);
        byte[] result;
        if (va == 0 && size == 0)
        {
            if (image.Length % AttributeCertificateAlignment != 0)
            {
                throw new PsignException(
                    $"PE image length {image.Length} is not 8-byte aligned; prepare it before computing the Authenticode digest");
            }

            result = new byte[image.Length + wrapped.Length];
            image.CopyTo(result, 0);
            wrapped.CopyTo(result, image.Length);
            WriteSecurityDataDirectory(result, (uint)image.Length, (uint)wrapped.Length);
            RefreshImageChecksum(result);
            return result;
        }

        long start = va;
        long end = start + size;
        if (start > image.Length)
        {
            throw new PsignException($"security directory pointer {start} past EOF {image.Length}");
        }

        if (end > image.Length)
        {
            throw new PsignException($"security directory end {end} beyond EOF {image.Length}");
        }

        result = new byte[end + wrapped.Length];
        image.AsSpan(0, (int)end).CopyTo(result);
        wrapped.CopyTo(result, (int)end);
        WriteSecurityDataDirectory(result, va, checked(size + (uint)wrapped.Length));
        RefreshImageChecksum(result);
        return result;
    }

    /// <summary>Replace the <paramref name="pkcs7Index"/>-th PKCS#7 <c>WIN_CERTIFICATE</c> and refresh the checksum.</summary>
    public static byte[] ReplacePkcs7CertificateAt(byte[] image, int pkcs7Index, ReadOnlySpan<byte> pkcs7)
    {
        var replacement = WrapPkcs7InWinCertificate(pkcs7);
        var (va, size) = ReadSecurityDataDirectory(image);
        if (va == 0 || size == 0)
        {
            throw new PsignException("PE has no certificate table");
        }

        long start = va;
        long end = start + size;
        if (start > image.Length || end > image.Length)
        {
            throw new PsignException($"security directory range {start}..{end} is outside PE length {image.Length}");
        }

        var table = image.AsSpan((int)start, (int)size);
        using var rebuilt = new MemoryStream();
        int offset = 0;
        int seen = 0;
        bool replaced = false;
        while (offset < table.Length)
        {
            if (offset + 8 > table.Length)
            {
                throw new PsignException($"truncated WIN_CERTIFICATE header at table offset {offset}");
            }

            int len = (int)BinaryPrimitives.ReadUInt32LittleEndian(table[offset..]);
            if (len < 8 || offset + (long)len > table.Length)
            {
                throw new PsignException($"invalid WIN_CERTIFICATE length {len} at table offset {offset}");
            }

            ushort type = BinaryPrimitives.ReadUInt16LittleEndian(table[(offset + 6)..]);
            if (type == AttributeCertificate.WinCertTypePkcsSignedData)
            {
                if (seen == pkcs7Index)
                {
                    rebuilt.Write(replacement);
                    replaced = true;
                }
                else
                {
                    rebuilt.Write(table.Slice(offset, len));
                }

                seen++;
            }
            else
            {
                rebuilt.Write(table.Slice(offset, len));
            }

            offset += len;
        }

        if (!replaced)
        {
            throw new PsignException($"no PKCS#7 Authenticode entry at index {pkcs7Index} (found {seen})");
        }

        var rebuiltBytes = rebuilt.ToArray();
        var result = new byte[start + rebuiltBytes.Length];
        image.AsSpan(0, (int)start).CopyTo(result);
        rebuiltBytes.CopyTo(result, (int)start);
        WriteSecurityDataDirectory(result, va, (uint)rebuiltBytes.Length);
        RefreshImageChecksum(result);
        return result;
    }

    /// <summary>Remove the whole certificate table. Returns the new image and the removed byte count.</summary>
    public static (byte[] Image, int Removed) RemoveCertificates(byte[] image)
    {
        var (va, size) = ReadSecurityDataDirectory(image);
        if (va == 0 || size == 0)
        {
            return (image, 0);
        }

        long start = va;
        long end = start + size;
        if (start > image.Length || end > image.Length)
        {
            throw new PsignException($"security directory range {start}..{end} is outside PE length {image.Length}");
        }

        var result = new byte[image.Length - size];
        image.AsSpan(0, (int)start).CopyTo(result);
        image.AsSpan((int)end).CopyTo(result.AsSpan((int)start));
        WriteSecurityDataDirectory(result, 0, 0);
        RefreshImageChecksum(result);
        return (result, (int)size);
    }
}
