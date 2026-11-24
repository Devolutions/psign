using System.Buffers.Binary;
using Devolutions.Psign.Core.Authenticode;

namespace Devolutions.Psign.Core.Esd;

/// <summary>
/// ESD / WIM Authenticode digest (<c>EsdSip.dll</c>): hash a byte prefix of the file, then PKCS#7 + signature tail
/// (port of <c>esd_digest.rs</c>).
/// <list type="bullet">
/// <item><c>GetHashDataOffset</c> walks three 16-byte regions in the packed WIM header at offsets 48, 72 and 124 (the
/// region at 96 is skipped).</item>
/// <item><c>WimFileHashReadLoop</c> hashes from file offset 0 for <c>total</c> bytes: the QWORD at header offset 188
/// (<c>0xBC</c>) when non-zero, otherwise <c>GetHashDataOffset</c>.</item>
/// <item><c>EsdSipGetSignature</c> reads PKCS#7 bytes at file offset QWORD 188, length DWORD 180 (<c>0xB4</c>).</item>
/// <item><c>EsdSipCreateHash</c> hashes the signed prefix with the 8-byte region <c>0xB4..0xBC</c> zeroed.</item>
/// <item><c>EsdSipIsMyFileType</c> requires the <c>MSWIM\0\0\0</c> magic and <c>dwHeaderSize</c> 208 (<c>0xD0</c>).</item>
/// </list>
/// </summary>
public static class EsdDigest
{
    /// <summary>Packed WIM header size used by <c>EsdSipCreateHash</c> / <c>EsdSipVerifyHash</c>.</summary>
    public const int WimHeaderPackedSize = 0xD0;

    private static readonly ulong WimMagicQwordLe = BinaryPrimitives.ReadUInt64LittleEndian("MSWIM\0\0\0"u8);

    /// <summary>DWORD at <c>0xB4</c>: PKCS#7 byte length (when signed).</summary>
    private const int OffPkcs7Cb = 0xB4;

    /// <summary>QWORD at <c>0xBC</c>: hashed-prefix length (and PKCS#7 file offset when signed).</summary>
    private const int OffHashEndOrSigOff = 0xBC;

    private static readonly int[] HashExtentRegionBases = [48, 72, 124];

    private static ulong ReadU64(ReadOnlySpan<byte> slice, int off)
    {
        if (off < 0 || off > slice.Length - 8)
        {
            throw new PsignException($"WIM header slice too small at offset {off}");
        }

        return BinaryPrimitives.ReadUInt64LittleEndian(slice[off..]);
    }

    private static uint ReadU32(ReadOnlySpan<byte> slice, int off)
    {
        if (off < 0 || off > slice.Length - 4)
        {
            throw new PsignException($"WIM header slice too small at offset {off}");
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(slice[off..]);
    }

    private static void RequireHeader(ReadOnlySpan<byte> header)
    {
        if (header.Length != WimHeaderPackedSize)
        {
            throw new ArgumentException($"WIM packed header must be exactly {WimHeaderPackedSize} bytes", nameof(header));
        }
    }

    /// <summary>Mirrors <c>GetHashDataOffset</c>: maximum end offset from the selected header regions.</summary>
    public static ulong GetHashDataOffset(ReadOnlySpan<byte> header)
    {
        RequireHeader(header);
        ulong maxEnd = 0;
        foreach (int b in HashExtentRegionBases)
        {
            ulong offsetMasked = ReadU64(header, b) & 0x00FF_FFFF_FFFF_FFFFUL;
            ulong length = ReadU64(header, b + 8);
            ulong end = offsetMasked + length;
            if (end < offsetMasked)
            {
                throw new PsignException($"WIM header region at 0x{b:x}: offset/length overflow");
            }

            maxEnd = Math.Max(maxEnd, end);
        }

        return maxEnd;
    }

    /// <summary>Bytes to hash from the start of the file (<c>WimFileHashReadLoop</c> total).</summary>
    public static ulong WimHashByteCount(ReadOnlySpan<byte> header)
    {
        RequireHeader(header);
        ulong explicitCount = ReadU64(header, OffHashEndOrSigOff);
        return explicitCount != 0 ? explicitCount : GetHashDataOffset(header);
    }

    private static void ValidateHeaderPrefix(ReadOnlySpan<byte> header)
    {
        RequireHeader(header);
        if (ReadU64(header, 0) != WimMagicQwordLe)
        {
            throw new PsignException("not a WIM/ESD image (missing MSWIM magic at offset 0)");
        }

        uint hdrCb = ReadU32(header, 8);
        if (hdrCb != WimHeaderPackedSize)
        {
            throw new PsignException($"unexpected WIM packed header size {hdrCb} (expected {WimHeaderPackedSize})");
        }
    }

    private static void ReadExact(Stream s, Span<byte> buffer)
    {
        while (!buffer.IsEmpty)
        {
            int n = s.Read(buffer);
            if (n == 0)
            {
                throw new PsignException("failed to fill whole buffer", new EndOfStreamException());
            }

            buffer = buffer[n..];
        }
    }

    /// <summary>Read the 208-byte packed header from the start of <paramref name="image"/>.</summary>
    public static byte[] ReadHeader(Stream image)
    {
        var head = new byte[WimHeaderPackedSize];
        image.Seek(0, SeekOrigin.Begin);
        ReadExact(image, head);
        return head;
    }

    /// <summary>
    /// Recompute the ESD SIP image digest for <paramref name="image"/> using the given packed header (Rust
    /// <c>compute_wim_image_digest_from_header</c>).
    /// </summary>
    public static byte[] ComputeWimImageDigestFromHeader(Stream image, ReadOnlySpan<byte> header, AuthenticodeHashKind kind)
    {
        ValidateHeaderPrefix(header);
        ulong total = WimHashByteCount(header);
        var hashHeader = header.ToArray();
        hashHeader.AsSpan(OffPkcs7Cb, OffHashEndOrSigOff - OffPkcs7Cb).Clear();
        using var h = kind.CreateHasher();
        if (total <= WimHeaderPackedSize)
        {
            h.AppendData(hashHeader, 0, (int)total);
            return h.GetHashAndReset();
        }

        h.AppendData(hashHeader);
        image.Seek(WimHeaderPackedSize, SeekOrigin.Begin);
        ulong remaining = total - WimHeaderPackedSize;
        var buf = new byte[0x10000];
        while (remaining > 0)
        {
            int n = (int)Math.Min(remaining, (ulong)buf.Length);
            ReadExact(image, buf.AsSpan(0, n));
            h.AppendData(buf, 0, n);
            remaining -= (ulong)n;
        }

        return h.GetHashAndReset();
    }

    /// <summary>File-path overload of <see cref="ComputeWimImageDigestFromHeader(Stream, ReadOnlySpan{byte}, AuthenticodeHashKind)"/>.</summary>
    public static byte[] ComputeWimImageDigestFromHeader(string path, ReadOnlySpan<byte> header, AuthenticodeHashKind kind)
    {
        ValidateHeaderPrefix(header);
        using var f = File.OpenRead(path);
        return ComputeWimImageDigestFromHeader(f, header, kind);
    }

    /// <summary>In-memory overload of <see cref="ComputeWimImageDigestFromHeader(Stream, ReadOnlySpan{byte}, AuthenticodeHashKind)"/>.</summary>
    public static byte[] ComputeWimImageDigestFromHeader(byte[] image, ReadOnlySpan<byte> header, AuthenticodeHashKind kind)
    {
        using var ms = new MemoryStream(image, writable: false);
        return ComputeWimImageDigestFromHeader(ms, header, kind);
    }

    /// <summary>PKCS#7 blob embedded after the hashed prefix (Rust <c>read_embedded_pkcs7</c>, <c>EsdSipGetSignature</c>).</summary>
    public static byte[] ReadEmbeddedPkcs7(Stream image, ReadOnlySpan<byte> header)
    {
        ValidateHeaderPrefix(header);
        ulong cb = ReadU32(header, OffPkcs7Cb);
        ulong off = ReadU64(header, OffHashEndOrSigOff);
        if (cb == 0 || off == 0)
        {
            throw new PsignException(
                "WIM/ESD file has no embedded Authenticode signature (cb=0 or offset=0 in header)");
        }

        ulong len = (ulong)image.Length;
        ulong end = off + cb;
        if (end < off)
        {
            throw new PsignException("signature extent overflow");
        }

        if (end > len)
        {
            throw new PsignException(
                $"embedded PKCS#7 extent exceeds file size (offset={off}, cb={cb}, file_len={len})");
        }

        var output = new byte[cb];
        image.Seek((long)off, SeekOrigin.Begin);
        ReadExact(image, output);
        return output;
    }

    /// <summary>File-path overload of <see cref="ReadEmbeddedPkcs7(Stream, ReadOnlySpan{byte})"/>.</summary>
    public static byte[] ReadEmbeddedPkcs7(string path, ReadOnlySpan<byte> header)
    {
        ValidateHeaderPrefix(header);
        using var f = File.OpenRead(path);
        return ReadEmbeddedPkcs7(f, header);
    }

    /// <summary>In-memory overload of <see cref="ReadEmbeddedPkcs7(Stream, ReadOnlySpan{byte})"/>.</summary>
    public static byte[] ReadEmbeddedPkcs7(byte[] image, ReadOnlySpan<byte> header)
    {
        using var ms = new MemoryStream(image, writable: false);
        return ReadEmbeddedPkcs7(ms, header);
    }

    /// <summary>
    /// Compare the PKCS#7 indirect digest with the ESD/WIM SIP prefix hash (Rust
    /// <c>verify_wim_esd_digest_consistency</c>, <c>EsdSipVerifyHash</c> semantics).
    /// </summary>
    public static void VerifyWimEsdDigestConsistency(Stream image)
    {
        var head = ReadHeader(image);
        var pkcs7 = ReadEmbeddedPkcs7(image, head);
        AuthenticodeSignature sig;
        try
        {
            sig = AuthenticodeSignature.Parse(pkcs7);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            throw new PsignException($"WIM/ESD PKCS#7 parse failed: {e.Message}", e);
        }

        var embedded = sig.Digest;
        var kind = sig.IndirectData.HashKind
            ?? throw new PsignException($"unsupported Authenticode digest algorithm OID {sig.IndirectData.DigestAlgorithm.Oid}");
        if (embedded.Length != kind.DigestLength())
        {
            throw new PsignException(
                $"Authenticode digest length {embedded.Length} does not match algorithm {kind.Name()} ({kind.DigestLength()} bytes)");
        }
        var computed = ComputeWimImageDigestFromHeader(image, head, kind);
        if (!computed.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException(
                "WIM/ESD Authenticode digest mismatch (Rust SIP prefix hash vs PKCS#7 indirect digest)");
        }
    }

    /// <summary>File-path overload of <see cref="VerifyWimEsdDigestConsistency(Stream)"/>.</summary>
    public static void VerifyWimEsdDigestConsistency(string path)
    {
        using var f = File.OpenRead(path);
        VerifyWimEsdDigestConsistency(f);
    }

    /// <summary>In-memory overload of <see cref="VerifyWimEsdDigestConsistency(Stream)"/>.</summary>
    public static void VerifyWimEsdDigestConsistency(byte[] image)
    {
        using var ms = new MemoryStream(image, writable: false);
        VerifyWimEsdDigestConsistency(ms);
    }
}
