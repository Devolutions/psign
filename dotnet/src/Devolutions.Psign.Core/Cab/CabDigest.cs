using System.Buffers.Binary;
using System.Security.Cryptography;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.Cab;

/// <summary>Parsed CAB layout relevant to Authenticode hashing (Rust <c>CabCtx</c> / osslsigncode <c>CAB_CTX</c>).</summary>
/// <param name="HeaderSize">Additional header size (<c>cbCFHeader</c>; 20 when signed, 0 without a reserve area).</param>
/// <param name="SigPos">PKCS#7 file offset (0 when unsigned).</param>
/// <param name="SigLen">PKCS#7 length (0 when unsigned).</param>
/// <param name="FileEnd">File length.</param>
/// <param name="Flags">CFHEADER <c>flags</c>.</param>
public sealed record CabCtx(uint HeaderSize, uint SigPos, uint SigLen, uint FileEnd, ushort Flags);

/// <summary>
/// Windows CAB Authenticode digest (<c>WINTRUST.DLL</c> SIP for <c>.cab</c>) vs PKCS#7 indirect digest (port of
/// <c>cab_digest.rs</c>).
/// <para>
/// Algorithm follows osslsigncode <c>cab.c</c> (<c>cab_digest_calc</c> / <c>cab_ctx_get</c>): MSCF header with selective
/// fields, optional chained-cabinet name strings, <c>CFFOLDER</c> table, then raw cabinet bytes up to the PKCS#7 blob.
/// </para>
/// </summary>
public static class CabDigest
{
    public const ushort FlagPrevCabinet = 0x0001;
    public const ushort FlagNextCabinet = 0x0002;
    public const ushort FlagReservePresent = 0x0004;

    private const uint AbReserveExpected = 0x0010_0000;

    /// <summary>Size of the Authenticode CAB reserve header (<c>cbCFHeader</c>).</summary>
    public const uint SignedHeaderExtra = 20;

    private static ushort ReadU16(ReadOnlySpan<byte> buf, int off)
    {
        if (off < 0 || off > buf.Length - 2)
        {
            throw new PsignException($"read past end at {off}");
        }

        return BinaryPrimitives.ReadUInt16LittleEndian(buf[off..]);
    }

    private static uint ReadU32(ReadOnlySpan<byte> buf, int off)
    {
        if (off < 0 || off > buf.Length - 4)
        {
            throw new PsignException($"read past end at {off}");
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(buf[off..]);
    }

    private static void WriteU16(Span<byte> buf, int off, ushort value)
    {
        if (off < 0 || off > buf.Length - 2)
        {
            throw new PsignException($"write past end at {off}");
        }

        BinaryPrimitives.WriteUInt16LittleEndian(buf[off..], value);
    }

    private static void WriteU32(Span<byte> buf, int off, uint value)
    {
        if (off < 0 || off > buf.Length - 4)
        {
            throw new PsignException($"write past end at {off}");
        }

        BinaryPrimitives.WriteUInt32LittleEndian(buf[off..], value);
    }

    private static uint CheckedU32Add(uint a, uint b, string what)
    {
        ulong sum = (ulong)a + b;
        if (sum > uint.MaxValue)
        {
            throw new PsignException($"{what} exceeds CAB u32 range");
        }

        return (uint)sum;
    }

    private static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> data, long start, long end)
    {
        if (start < 0 || end < start || end > data.Length)
        {
            throw new PsignException($"read past end at {start}");
        }

        return data[(int)start..(int)end];
    }

    private static int SkipCabSz(ReadOnlySpan<byte> data, int idx)
    {
        while (idx < data.Length)
        {
            byte b = data[idx];
            idx++;
            if (b == 0)
            {
                return idx;
            }
        }

        throw new PsignException("truncated CAB sz field");
    }

    private static int CfFolderTableOffset(ReadOnlySpan<byte> data, ushort flags)
    {
        int idx = 36;
        if ((flags & FlagPrevCabinet) != 0)
        {
            throw new PsignException("multivolume CAB (FLAG_PREV_CABINET) is unsupported for portable signing");
        }

        if ((flags & FlagNextCabinet) != 0)
        {
            idx = SkipCabSz(data, idx);
            idx = SkipCabSz(data, idx);
        }

        return idx;
    }

    /// <summary>Validate CAB layout and signature extents (Rust <c>parse_cab_context</c>, osslsigncode <c>cab_ctx_get</c>).</summary>
    public static CabCtx ParseContext(ReadOnlySpan<byte> data)
    {
        if (data.Length < 44)
        {
            throw new PsignException("CAB file too short");
        }

        if (!data[..4].SequenceEqual("MSCF"u8))
        {
            throw new PsignException("not a CAB file (missing MSCF signature)");
        }

        if (ReadU32(data, 4) != 0)
        {
            throw new PsignException("CAB reserved1 must be zero");
        }

        ushort flags = ReadU16(data, 30);
        if ((flags & FlagPrevCabinet) != 0)
        {
            throw new PsignException("multivolume CAB (FLAG_PREV_CABINET) is unsupported for Rust SIP digest");
        }

        uint fileEnd = (uint)data.Length;
        uint headerSize = 0;
        uint sigpos = 0;
        uint siglen = 0;

        if ((flags & FlagReservePresent) != 0)
        {
            headerSize = ReadU32(data, 36);
            if (headerSize != SignedHeaderExtra)
            {
                throw new PsignException(
                    $"unsupported CAB additional header size {headerSize} (expected {SignedHeaderExtra})");
            }

            uint abReserved = ReadU32(data, 40);
            if (abReserved != AbReserveExpected)
            {
                throw new PsignException($"unexpected CAB abReserve value 0x{abReserved:x8} (expected 0x00100000)");
            }

            sigpos = ReadU32(data, 44);
            siglen = ReadU32(data, 48);
            if ((sigpos > 0 && siglen == 0) || (sigpos == 0 && siglen > 0))
            {
                throw new PsignException("corrupt CAB signature extent (sigpos/siglen)");
            }

            ulong saturated = Math.Min((ulong)sigpos + siglen, uint.MaxValue);
            if (sigpos < fileEnd && saturated != fileEnd)
            {
                throw new PsignException(
                    $"CAB signature extent does not match file size (sigpos={sigpos}, siglen={siglen}, file={fileEnd})");
            }

            if (sigpos >= fileEnd)
            {
                throw new PsignException("CAB sigpos past end of file");
            }
        }

        return new CabCtx(headerSize, sigpos, siglen, fileEnd, flags);
    }

    /// <summary>
    /// Add the Authenticode reserve header required before appending a CAB PKCS#7 signature (Rust
    /// <c>prepare_unsigned_cab_for_authenticode_signature</c>).
    /// <para>
    /// Supports only unsigned, single-volume CABs with no pre-existing reserve area. Header offsets shifted by the new
    /// 24-byte reserve block are updated; the caller appends the PKCS#7 blob at the returned image's end (<c>sigpos</c>).
    /// </para>
    /// </summary>
    public static byte[] PrepareUnsignedForAuthenticodeSignature(ReadOnlySpan<byte> data, int signatureLength)
    {
        var ctx = ParseContext(data);
        if ((ctx.Flags & FlagReservePresent) != 0)
        {
            throw new PsignException("CAB already has a reserve header; replacing CAB signatures is not implemented");
        }

        if (ctx.SigPos != 0 || ctx.SigLen != 0)
        {
            throw new PsignException("CAB already has an embedded signature");
        }

        if (signatureLength < 0)
        {
            throw new PsignException("CAB signature too large");
        }

        uint sigLen = (uint)signatureLength;
        uint originalLen = (uint)data.Length;
        uint sigpos = CheckedU32Add(originalLen, 24, "signed CAB header");
        uint originalCbCabinet = ReadU32(data, 8);
        if (originalCbCabinet != originalLen)
        {
            throw new PsignException(
                $"unsupported CAB cbCabinet {originalCbCabinet} (expected unsigned file size {originalLen})");
        }

        uint originalCoffFiles = ReadU32(data, 16);
        int folderCount = ReadU16(data, 26);
        int originalFolderTable = CfFolderTableOffset(data, ctx.Flags);
        long folderTableEnd = originalFolderTable + ((long)folderCount * 8);
        if (folderTableEnd > originalCoffFiles)
        {
            throw new PsignException(
                $"CFFOLDER table extends past coffFiles (end={folderTableEnd}, coffFiles={originalCoffFiles})");
        }

        var output = new byte[data.Length + 24];
        data[..36].CopyTo(output);
        ReadOnlySpan<byte> reserve =
        [
            0x14, 0x00, 0x00, 0x00, // cbCFHeader=20, cbCFFolder=0, cbCFData=0
            0x00, 0x00, 0x10, 0x00, // abReserve=0x00100000 (Authenticode CAB signature block)
            0x00, 0x00, 0x00, 0x00, // sigpos
            0x00, 0x00, 0x00, 0x00, // siglen
            0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, // reserved
        ];
        reserve.CopyTo(output.AsSpan(36));
        data[36..].CopyTo(output.AsSpan(60));

        ushort newFlags = (ushort)(ctx.Flags | FlagReservePresent);
        WriteU32(output, 8, sigpos);
        WriteU32(output, 16, CheckedU32Add(originalCoffFiles, 24, "coffFiles"));
        WriteU16(output, 30, newFlags);
        WriteU32(output, 44, sigpos);
        WriteU32(output, 48, sigLen);

        int newFolderTable = originalFolderTable + 24;
        for (int folderIndex = 0; folderIndex < folderCount; folderIndex++)
        {
            int entry = newFolderTable + (folderIndex * 8);
            uint coffCabStart = ReadU32(output, entry);
            WriteU32(output, entry, CheckedU32Add(coffCabStart, 24, "CFFOLDER coffCabStart"));
        }

        return output;
    }

    /// <summary>Prepare an unsigned CAB and append a PKCS#7 Authenticode signature blob (Rust <c>cab_append_authenticode_pkcs7_signature</c>).</summary>
    public static byte[] AppendAuthenticodePkcs7Signature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> pkcs7)
    {
        var prepared = PrepareUnsignedForAuthenticodeSignature(data, pkcs7.Length);
        var output = new byte[prepared.Length + pkcs7.Length];
        prepared.CopyTo(output, 0);
        pkcs7.CopyTo(output.AsSpan(prepared.Length));
        return output;
    }

    /// <summary>
    /// Compute the CAB Authenticode digest over the post-reserve, pre-signature byte layout (Rust
    /// <c>cab_authenticode_digest_for_signing</c>).
    /// </summary>
    public static byte[] AuthenticodeDigestForSigning(ReadOnlySpan<byte> unsignedCab, AuthenticodeHashKind kind)
    {
        var prepared = PrepareUnsignedForAuthenticodeSignature(unsignedCab, 0);
        uint sigpos = (uint)prepared.Length;
        ushort flags = ReadU16(prepared, 30);
        var ctx = new CabCtx(SignedHeaderExtra, sigpos, 0, sigpos, flags);
        return ComputeAuthenticodeDigest(prepared, ctx, kind);
    }

    private static int HashSzField(IncrementalHash hasher, ReadOnlySpan<byte> data, int idx, int fileEnd)
    {
        while (idx < fileEnd)
        {
            byte b = data[idx];
            hasher.AppendData([b]);
            idx++;
            if (b == 0)
            {
                break;
            }
        }

        return idx;
    }

    /// <summary>Recompute the CAB image digest (Rust <c>compute_cab_authenticode_digest</c>, osslsigncode <c>cab_digest_calc</c>).</summary>
    public static byte[] ComputeAuthenticodeDigest(ReadOnlySpan<byte> data, CabCtx ctx, AuthenticodeHashKind kind)
    {
        using var hasher = kind.CreateHasher();
        long fileEnd = ctx.FileEnd;

        hasher.AppendData(Slice(data, 0, 4));

        if (ctx.SigPos != 0)
        {
            int sigpos = checked((int)ctx.SigPos);
            long coffFiles = ReadU32(data, 16);
            int nfolders = ReadU16(data, 26);
            ushort flags = ReadU16(data, 30);

            hasher.AppendData(Slice(data, 8, 16));
            hasher.AppendData(Slice(data, 16, 20));
            hasher.AppendData(Slice(data, 20, 26));
            hasher.AppendData(Slice(data, 26, 28));
            hasher.AppendData(Slice(data, 28, 30));
            hasher.AppendData(Slice(data, 30, 32));
            hasher.AppendData(Slice(data, 32, 34));
            hasher.AppendData(Slice(data, 56, 60));

            int idx = 60;
            if ((flags & FlagNextCabinet) != 0)
            {
                int limit = Math.Min(sigpos, data.Length);
                idx = HashSzField(hasher, data, idx, limit);
                idx = HashSzField(hasher, data, idx, limit);
            }

            int remaining = nfolders;
            while (remaining > 0 && idx < sigpos)
            {
                int end = idx + 8;
                if (end > sigpos)
                {
                    throw new PsignException("CFFOLDER entries overflow signature offset");
                }

                hasher.AppendData(Slice(data, idx, end));
                idx = end;
                remaining--;
            }

            if (remaining != 0)
            {
                throw new PsignException("truncated CFFOLDER table");
            }

            if (idx != coffFiles)
            {
                throw new PsignException(
                    $"corrupt CAB coffFiles: expected header to end at 0x{coffFiles:x}, got 0x{idx:x}");
            }

            if (sigpos > fileEnd)
            {
                throw new PsignException("sigpos past file");
            }

            hasher.AppendData(Slice(data, idx, sigpos));
        }
        else
        {
            hasher.AppendData(Slice(data, 8, fileEnd));
        }

        return hasher.GetHashAndReset();
    }

    /// <summary>
    /// RS256 prehash (SHA-256 over authenticated <c>signedAttrs</c>) from embedded CAB PKCS#7 (Rust
    /// <c>cab_rsa_sha256_signer_prehash_digest</c>).
    /// </summary>
    public static byte[] RsaSha256SignerPrehashDigest(ReadOnlySpan<byte> data, int signerIndex)
    {
        var pkcs7 = SignaturePkcs7Der(data);
        var sd = CmsSignedData.Parse(pkcs7);
        return Rs256SignerPrehash.Compute(sd, signerIndex);
    }

    /// <summary>PKCS#7 <c>SignedData</c> bytes embedded at the tail of a signed CAB (Rust <c>cab_signature_pkcs7_der</c>).</summary>
    public static byte[] SignaturePkcs7Der(ReadOnlySpan<byte> data)
    {
        var (start, length) = SignatureExtent(data);
        return data.Slice(start, length).ToArray();
    }

    private static (int Start, int Length) SignatureExtent(ReadOnlySpan<byte> data)
    {
        var ctx = ParseContext(data);
        if (ctx.HeaderSize != SignedHeaderExtra || ctx.SigPos == 0 || ctx.SigLen == 0)
        {
            throw new PsignException("CAB has no embedded Authenticode signature (expected reserve header + PKCS#7)");
        }

        long sigEnd = (long)ctx.SigPos + ctx.SigLen;
        if (sigEnd > data.Length)
        {
            throw new PsignException("PKCS#7 extent out of range");
        }

        return ((int)ctx.SigPos, (int)ctx.SigLen);
    }

    /// <summary>True when <paramref name="data"/> carries an embedded CAB Authenticode signature.</summary>
    public static bool HasSignature(ReadOnlySpan<byte> data)
    {
        try
        {
            SignatureExtent(data);
            return true;
        }
        catch (PsignException)
        {
            return false;
        }
    }

    /// <summary>PKCS#7 indirect digest vs osslsigncode-style CAB hash (Rust <c>verify_cab_digest_consistency</c> / <c>cab_verify_digests</c>).</summary>
    public static void VerifyDigestConsistency(ReadOnlySpan<byte> data)
    {
        var ctx = ParseContext(data);
        if (ctx.HeaderSize != SignedHeaderExtra || ctx.SigPos == 0 || ctx.SigLen == 0)
        {
            throw new PsignException(
                "CAB has no embedded Authenticode signature (expected 20-byte reserve header + PKCS#7)");
        }

        var pkcs7 = SignaturePkcs7Der(data);
        AuthenticodeSignature sig;
        try
        {
            sig = AuthenticodeSignature.Parse(pkcs7);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            throw new PsignException($"CAB PKCS#7 parse failed: {e.Message}", e);
        }

        var embedded = sig.Digest;
        var kind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
        var computed = ComputeAuthenticodeDigest(data, ctx, kind);
        if (!computed.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException("CAB Authenticode digest mismatch (Rust SIP vs PKCS#7 indirect digest)");
        }
    }

    /// <summary>File-path overload of <see cref="VerifyDigestConsistency(ReadOnlySpan{byte})"/>.</summary>
    public static void VerifyDigestConsistency(string path) => VerifyDigestConsistency(File.ReadAllBytes(path));
}
