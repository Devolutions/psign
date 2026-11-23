using System.Buffers.Binary;
using System.Security.Cryptography;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.Msi;

/// <summary>
/// MSI / MSP image staged for Authenticode signing, including the root <c>\u0005MsiDigitalSignatureEx</c> metadata
/// digest stream required by the Windows Installer SIP (Rust <c>PreparedMsiAuthenticode</c>).
/// </summary>
public sealed class PreparedMsiAuthenticode
{
    internal PreparedMsiAuthenticode(byte[] image, byte[] digest)
    {
        Image = image;
        Digest = digest;
    }

    /// <summary>Compound-file bytes containing the root <c>MsiDigitalSignatureEx</c> stream.</summary>
    public byte[] Image { get; }

    /// <summary>Authenticode digest of <see cref="Image"/>.</summary>
    public byte[] Digest { get; }
}

/// <summary>
/// Windows Installer Authenticode digest (<c>MSISIP.DLL</c>) vs PKCS#7 <c>SpcIndirectData</c> (port of
/// <c>msi_digest.rs</c>).
/// <para>
/// The traversal matches Signify <c>SignedMsiFile</c>: sibling names sorted by UTF-16LE byte order (longer prefix first),
/// root <c>\u0005DigitalSignature</c> and <c>\u0005MsiDigitalSignatureEx</c> skipped, an optional metadata pre-hash when
/// <c>MsiDigitalSignatureEx</c> exists, then recursive stream hashing plus each storage's CLSID at storage close.
/// </para>
/// </summary>
public static class MsiDigest
{
    /// <summary>Root stream holding the PKCS#7 signature.</summary>
    public const string DigitalSignatureEntry = "\u0005DigitalSignature";

    /// <summary>Root stream holding the metadata (pre-hash) digest.</summary>
    public const string ExtendedSignatureEntry = "\u0005MsiDigitalSignatureEx";

    /// <summary>Rust <c>escape_debug</c> rendering used in error messages.</summary>
    private const string DigitalSignatureEntryDebug = "\\u{5}DigitalSignature";

    private const string ExtendedSignatureEntryDebug = "\\u{5}MsiDigitalSignatureEx";

    /// <summary>
    /// SIP sibling order: compare UTF-16LE encoded names byte-wise over the common prefix, then longer names first
    /// (Rust <c>cmp_utf16_name</c>).
    /// </summary>
    internal static int CompareUtf16Name(string a, string b)
    {
        int common = Math.Min(a.Length, b.Length);
        for (int i = 0; i < common; i++)
        {
            char ca = a[i];
            char cb = b[i];
            int lo = (ca & 0xFF).CompareTo(cb & 0xFF);
            if (lo != 0)
            {
                return lo;
            }

            int hi = (ca >> 8).CompareTo(cb >> 8);
            if (hi != 0)
            {
                return hi;
            }
        }

        return b.Length.CompareTo(a.Length);
    }

    private static void HashUtf16Name(IncrementalHash h, string name)
    {
        Span<byte> buf = stackalloc byte[2];
        foreach (char c in name)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(buf, c);
            h.AppendData(buf);
        }
    }

    private static void HashU32(IncrementalHash h, uint v)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, v);
        h.AppendData(buf);
    }

    private static void HashU64(IncrementalHash h, ulong v)
    {
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(buf, v);
        h.AppendData(buf);
    }

    private static void PrehashEntry(CfbDirEntry entry, IncrementalHash h)
    {
        if (!entry.IsRoot)
        {
            HashUtf16Name(h, entry.Name);
        }

        if (entry.IsRoot || entry.IsStorage)
        {
            h.AppendData(entry.ClsidLe);
        }

        if (entry.IsStream)
        {
            // MSISIP hashes the low DWORD of the stream size.
            HashU32(h, (uint)entry.StreamLength);
        }

        HashU32(h, entry.StateBits);
        if (!entry.IsRoot)
        {
            HashU64(h, entry.CreationTime);
            HashU64(h, entry.ModifiedTime);
        }
    }

    private static bool IsRootSignatureEntry(CfbDirEntry storage, CfbDirEntry e) =>
        storage.IsRoot && (e.Name == DigitalSignatureEntry || e.Name == ExtendedSignatureEntry);

    private static List<CfbDirEntry> SortedChildren(CfbFile cfb, CfbDirEntry storage)
    {
        var entries = cfb.Children(storage);
        entries.Sort((x, y) => CompareUtf16Name(x.Name, y.Name));
        return entries;
    }

    private static void PrehashStorageRecursive(CfbFile cfb, CfbDirEntry storage, IncrementalHash h)
    {
        PrehashEntry(storage, h);
        foreach (var e in SortedChildren(cfb, storage))
        {
            if (IsRootSignatureEntry(storage, e))
            {
                continue;
            }

            if (e.IsStorage)
            {
                PrehashStorageRecursive(cfb, e, h);
            }
            else
            {
                PrehashEntry(e, h);
            }
        }
    }

    private static void HashStorageContentRecursive(CfbFile cfb, CfbDirEntry storage, IncrementalHash h)
    {
        foreach (var e in SortedChildren(cfb, storage))
        {
            if (IsRootSignatureEntry(storage, e))
            {
                continue;
            }

            if (e.IsStorage)
            {
                HashStorageContentRecursive(cfb, e, h);
            }
            else if (e.IsStream)
            {
                h.AppendData(cfb.ReadStream(e));
            }
        }

        h.AppendData(storage.ClsidLe);
    }

    /// <summary>Opened compound file (Rust <c>CompoundFile</c> over a cursor), ported from the <c>cfb</c> crate.</summary>
    private sealed class Package
    {
        private Package(CfbFile cfb) => Cfb = cfb;

        public CfbFile Cfb { get; }

        public CfbDirEntry Root => Cfb.Root;

        /// <summary>
        /// Open <paramref name="data"/>; <paramref name="writable"/> works on a private copy of the bytes. A <c>null</c>
        /// <paramref name="errorPrefix"/> reports the compound-file error without context (Rust <c>CompoundFile::open(..)?</c>).
        /// </summary>
        public static Package Open(byte[] data, bool writable = false, string? errorPrefix = "open as OLE compound file")
        {
            try
            {
                return new Package(CfbFile.Open(writable ? (byte[])data.Clone() : data));
            }
            catch (Exception e) when (e is PsignException or ArgumentException or IndexOutOfRangeException or OverflowException)
            {
                var inner = e as PsignException ?? new PsignException(e.Message);
                if (errorPrefix is null)
                {
                    throw inner;
                }

                throw new PsignException(errorPrefix, inner);
            }
        }

        public CfbDirEntry? FindRootChild(string name) => Cfb.FindChild(Cfb.Root, name);

        public bool HasExtended => FindRootChild(ExtendedSignatureEntry) is not null;

        public byte[] ReadRootStream(string name) =>
            Cfb.ReadStream(FindRootChild(name) ?? throw new PsignException($"No such stream: \"/{name}\""));
    }

    private static byte[] ComputePrehash(Package pkg, AuthenticodeHashKind kind)
    {
        using var h = kind.CreateHasher();
        PrehashStorageRecursive(pkg.Cfb, pkg.Root, h);
        return h.GetHashAndReset();
    }

    private static byte[] ComputeFingerprint(Package pkg, AuthenticodeHashKind kind)
    {
        using var h = kind.CreateHasher();
        if (pkg.HasExtended)
        {
            h.AppendData(ComputePrehash(pkg, kind));
        }

        HashStorageContentRecursive(pkg.Cfb, pkg.Root, h);
        return h.GetHashAndReset();
    }

    /// <summary>
    /// Metadata pre-hash stored in <c>\u0005MsiDigitalSignatureEx</c> (Rust <c>compute_prehash</c>, MSISIP
    /// <c>DigestStorageMetadataHelper</c>).
    /// </summary>
    public static byte[] ComputeMetadataDigest(byte[] data, AuthenticodeHashKind kind)
    {
        var pkg = Package.Open(data);
        return ComputePrehash(pkg, kind);
    }

    /// <summary>Compute the Windows Installer Authenticode SIP fingerprint for MSI-like OLE packages (Rust <c>compute_msi_authenticode_digest</c>).</summary>
    public static byte[] ComputeAuthenticodeDigest(byte[] data, AuthenticodeHashKind kind)
    {
        var pkg = Package.Open(data);
        return ComputeFingerprint(pkg, kind);
    }

    /// <summary>
    /// Compute the signing digest for an MSI / MSP that already carries a valid metadata digest stream (Rust
    /// <c>compute_prepared_msi_authenticode_digest</c>).
    /// </summary>
    public static byte[] ComputePreparedAuthenticodeDigest(byte[] data, AuthenticodeHashKind kind)
    {
        var pkg = Package.Open(data);
        if (!pkg.HasExtended)
        {
            throw new PsignException(
                $"MSI signing requires the root {ExtendedSignatureEntryDebug} stream; stage the image with prepare_msi_for_authenticode_signing");
        }

        var extended = pkg.ReadRootStream(ExtendedSignatureEntry);
        var expected = ComputePrehash(pkg, kind);
        if (!extended.AsSpan().SequenceEqual(expected))
        {
            throw new PsignException($"MSI {ExtendedSignatureEntryDebug} stream does not match its metadata digest");
        }

        return ComputeFingerprint(pkg, kind);
    }

    /// <summary>
    /// Create or replace a root stream and return the updated compound-file bytes (Rust <c>cfb</c>
    /// <c>create_stream</c> + <c>write_all</c>; the file is edited in place exactly like the crate does).
    /// </summary>
    internal static byte[] WriteRootStream(byte[] data, string name, ReadOnlySpan<byte> content, string openErrorPrefix = "open as OLE compound file")
    {
        var pkg = Package.Open(data, writable: true, openErrorPrefix);
        pkg.Cfb.CreateStream(name, content);
        return pkg.Cfb.ToArray();
    }

    /// <summary>
    /// Stage an MSI / MSP for signing and compute the Windows Installer SIP digest (Rust
    /// <c>prepare_msi_for_authenticode_signing</c>). The root <c>MsiDigitalSignatureEx</c> stream receives the package
    /// metadata digest before the final Authenticode digest is computed.
    /// </summary>
    public static PreparedMsiAuthenticode PrepareForAuthenticodeSigning(byte[] data, AuthenticodeHashKind kind)
    {
        var pkg = Package.Open(data, writable: true);
        var metadataDigest = ComputePrehash(pkg, kind);
        pkg.Cfb.CreateStream(ExtendedSignatureEntry, metadataDigest);
        var digest = ComputeFingerprint(pkg, kind);
        return new PreparedMsiAuthenticode(pkg.Cfb.ToArray(), digest);
    }

    /// <summary>
    /// PKCS#7 <c>SignedData</c> bytes from the root <c>\u0005DigitalSignature</c> stream (Rust
    /// <c>msi_digital_signature_pkcs7_der</c>).
    /// </summary>
    public static byte[] DigitalSignaturePkcs7Der(byte[] data)
    {
        var pkg = Package.Open(data);
        if (pkg.FindRootChild(DigitalSignatureEntry) is null)
        {
            throw new PsignException($"MSI is missing {DigitalSignatureEntryDebug} stream");
        }

        return pkg.ReadRootStream(DigitalSignatureEntry);
    }

    /// <summary>True when <paramref name="data"/> is a compound file with a root <c>\u0005DigitalSignature</c> stream.</summary>
    public static bool HasDigitalSignature(byte[] data)
    {
        try
        {
            DigitalSignaturePkcs7Der(data);
            return true;
        }
        catch (PsignException)
        {
            return false;
        }
    }

    /// <summary>Create or replace the root <c>\u0005DigitalSignature</c> stream in memory.</summary>
    public static byte[] EmbedPkcs7Signature(byte[] image, ReadOnlySpan<byte> pkcs7) =>
        WriteRootStream(image, DigitalSignatureEntry, pkcs7, "open OLE compound file read/write");

    /// <summary>Create or replace the root <c>\u0005DigitalSignature</c> stream in an MSI / MSP file (Rust <c>write_msi_digital_signature_pkcs7</c>).</summary>
    public static void WriteDigitalSignaturePkcs7(string path, ReadOnlySpan<byte> pkcs7)
    {
        var updated = EmbedPkcs7Signature(File.ReadAllBytes(path), pkcs7);
        File.WriteAllBytes(path, updated);
    }

    /// <summary>Copy an MSI / MSP file and write the root <c>\u0005DigitalSignature</c> PKCS#7 stream (Rust <c>msi_embed_authenticode_pkcs7_signature</c>).</summary>
    public static void EmbedAuthenticodePkcs7Signature(string input, string output, ReadOnlySpan<byte> pkcs7)
    {
        var updated = EmbedPkcs7Signature(File.ReadAllBytes(input), pkcs7);
        File.WriteAllBytes(output, updated);
    }

    /// <summary>
    /// Write a staged MSI / MSP image and its root <c>\u0005DigitalSignature</c> PKCS#7 stream (Rust
    /// <c>msi_embed_prepared_authenticode_pkcs7_signature</c>).
    /// </summary>
    public static void EmbedPreparedAuthenticodePkcs7Signature(PreparedMsiAuthenticode prepared, string output, ReadOnlySpan<byte> pkcs7) =>
        File.WriteAllBytes(output, EmbedPkcs7Signature(prepared.Image, pkcs7));

    /// <summary>
    /// RS256 prehash over <c>SignerInfo</c> authenticated attributes for MSI-embedded PKCS#7 (Rust
    /// <c>msi_rsa_sha256_signer_prehash_digest</c>).
    /// </summary>
    public static byte[] RsaSha256SignerPrehashDigest(byte[] data, int signerIndex)
    {
        var pkcs7 = DigitalSignaturePkcs7Der(data);
        return SignerPrehash.Rs256(CmsSignedData.Parse(pkcs7), signerIndex);
    }

    /// <summary>
    /// Compare the PKCS#7 indirect digest with the MSI SIP fingerprint and, when present, the
    /// <c>MsiDigitalSignatureEx</c> metadata digest (Rust <c>verify_msi_digest_consistency</c>).
    /// </summary>
    public static void VerifyDigestConsistency(byte[] data)
    {
        // Rust `verify_msi_digest_consistency` opens with a bare `?`: no "open as OLE compound file" context.
        var pkg = Package.Open(data, errorPrefix: null);
        if (pkg.FindRootChild(DigitalSignatureEntry) is null)
        {
            throw new PsignException($"MSI is missing {DigitalSignatureEntryDebug} stream");
        }

        var pkcs7 = pkg.ReadRootStream(DigitalSignatureEntry);
        AuthenticodeSignature sig;
        try
        {
            sig = AuthenticodeSignature.Parse(pkcs7);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            throw new PsignException($"MSI Authenticode PKCS#7 parse failed: {e.Message}", e);
        }

        var embedded = sig.Digest;
        var kind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
        var computed = ComputeFingerprint(pkg, kind);
        if (!computed.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException(
                "MSI Authenticode digest mismatch (Rust SIP fingerprint vs PKCS#7 indirect digest)");
        }

        if (pkg.HasExtended)
        {
            var expected = pkg.ReadRootStream(ExtendedSignatureEntry);
            var pre = ComputePrehash(pkg, kind);
            if (!pre.AsSpan().SequenceEqual(expected))
            {
                throw new PsignException(
                    "MSI extended metadata digest mismatch (MsiDigitalSignatureEx stream vs Rust pre-hash)");
            }
        }
    }

    /// <summary>File-path overload of <see cref="VerifyDigestConsistency(byte[])"/>.</summary>
    public static void VerifyDigestConsistency(string path) => VerifyDigestConsistency(File.ReadAllBytes(path));
}
