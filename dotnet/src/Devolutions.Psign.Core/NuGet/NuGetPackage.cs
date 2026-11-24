using System.Buffers.Binary;
using System.Text;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Core.NuGet;

/// <summary>NuGet package hash algorithm (Rust <c>nuget::NuGetHashAlgorithm</c>).</summary>
public enum NuGetHashAlgorithm
{
    Sha256,
    Sha384,
    Sha512,
}

/// <summary>Helpers for <see cref="NuGetHashAlgorithm"/>.</summary>
public static class NuGetHashAlgorithmExtensions
{
    /// <summary>Digest algorithm OID.</summary>
    public static string Oid(this NuGetHashAlgorithm algorithm) => algorithm.ToHashKind().Oid();

    /// <summary>One-shot digest.</summary>
    public static byte[] Hash(this NuGetHashAlgorithm algorithm, ReadOnlySpan<byte> bytes) => algorithm.ToHashKind().Hash(bytes);

    /// <summary>Equivalent <see cref="AuthenticodeHashKind"/>.</summary>
    public static AuthenticodeHashKind ToHashKind(this NuGetHashAlgorithm algorithm) => algorithm switch
    {
        NuGetHashAlgorithm.Sha256 => AuthenticodeHashKind.Sha256,
        NuGetHashAlgorithm.Sha384 => AuthenticodeHashKind.Sha384,
        NuGetHashAlgorithm.Sha512 => AuthenticodeHashKind.Sha512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>CLI label (<c>sha256</c>, <c>sha384</c>, <c>sha512</c>; Rust <c>nuget_hash_alg_label</c>).</summary>
    public static string Label(this NuGetHashAlgorithm algorithm) => algorithm.ToHashKind().Name();

    /// <summary>Map an OID to an algorithm (Rust <c>NuGetHashAlgorithm::from_oid</c>).</summary>
    public static NuGetHashAlgorithm? FromOid(string oid) => oid switch
    {
        Oids.Sha256 => NuGetHashAlgorithm.Sha256,
        Oids.Sha384 => NuGetHashAlgorithm.Sha384,
        Oids.Sha512 => NuGetHashAlgorithm.Sha512,
        _ => null,
    };

    /// <summary>Map a SHA-2 hash kind (SHA-1 is rejected).</summary>
    public static NuGetHashAlgorithm FromHashKind(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha256 => NuGetHashAlgorithm.Sha256,
        AuthenticodeHashKind.Sha384 => NuGetHashAlgorithm.Sha384,
        AuthenticodeHashKind.Sha512 => NuGetHashAlgorithm.Sha512,
        _ => throw new PsignException("NuGet package signing supports SHA-256, SHA-384, and SHA-512 only"),
    };
}

/// <summary>NuGet package signature marker info (Rust <c>nuget::NuGetPackageInfo</c>).</summary>
public sealed record NuGetPackageInfo(PackageSummary Package, bool Signed, ulong? SignatureLen, bool? SignatureIsStored);

/// <summary>Parsed NuGet signature content (Rust <c>nuget::NuGetSignatureContent</c>).</summary>
public sealed record NuGetSignatureContent(NuGetHashAlgorithm HashAlgorithm, byte[] PackageHash);

/// <summary>
/// Portable NuGet package signing primitives (port of Rust <c>psign-opc-sign/src/nuget.rs</c>): signature marker
/// inspection, canonical unsigned package bytes, signature content, extraction and embedding of an already-built
/// <c>.signature.p7s</c>.
/// </summary>
public static class NuGetPackage
{
    public const string PackageSignatureFileName = ".signature.p7s";
    public const string SignatureContentVersion = "1";

    // ---------------------------------------------------------------- inspection

    /// <summary>Rust <c>inspect_nupkg_path</c>.</summary>
    public static NuGetPackageInfo InspectNupkgPath(string path) => FromSummary(OpcPackage.InspectPackagePath(path));

    /// <summary>Inspect package bytes.</summary>
    public static NuGetPackageInfo InspectNupkg(byte[] package) => FromSummary(OpcPackage.InspectPackage(package));

    private static NuGetPackageInfo FromSummary(PackageSummary package)
    {
        var entry = package.Entry(PackageSignatureFileName);
        return new NuGetPackageInfo(package, entry is not null, entry?.UncompressedSize, entry is null ? null : entry.Compression == "Stored");
    }

    /// <summary>Digest of the package file bytes; fails when already signed (Rust <c>unsigned_package_digest_path</c>).</summary>
    public static byte[] UnsignedPackageDigestPath(string path, NuGetHashAlgorithm algorithm)
    {
        var info = InspectNupkgPath(path);
        if (info.Signed)
        {
            throw new PsignException(
                $"{path} already contains {PackageSignatureFileName}; remove or overwrite the signature before computing the unsigned package digest");
        }

        return algorithm.Hash(ReadFile(path));
    }

    // ---------------------------------------------------------------- canonical bytes

    /// <summary>Rust <c>canonical_unsigned_package_bytes_path</c>.</summary>
    public static byte[] CanonicalUnsignedPackageBytesPath(string path)
    {
        var bytes = ReadFileForOpen(path);
        try
        {
            return CanonicalUnsignedPackageBytes(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"canonicalize unsigned NuGet package {path}", e);
        }
    }

    /// <summary>
    /// Package re-written by the Rust <c>zip</c> writer without <c>.signature.p7s</c> and with normalized central
    /// directory metadata (Rust <c>canonical_unsigned_package_bytes</c>).
    /// </summary>
    public static byte[] CanonicalUnsignedPackageBytes(byte[] package) => WritePackageWithoutSignatureImpl(package, requireSignature: false);

    /// <summary>Rust <c>signed_package_unsigned_bytes_path</c>.</summary>
    public static byte[] SignedPackageUnsignedBytesPath(string path)
    {
        var bytes = ReadFile(path);
        try
        {
            return SignedPackageUnsignedBytes(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"remove NuGet signature from {path}", e);
        }
    }

    /// <summary>
    /// Reconstruct the exact unsigned package bytes a NuGet author signature covers by cutting the last
    /// <c>.signature.p7s</c> entry and adjusting the end-of-central-directory record (Rust
    /// <c>signed_package_unsigned_bytes</c>).
    /// </summary>
    public static byte[] SignedPackageUnsignedBytes(byte[] bytes)
    {
        int eocd = FindValidEocd(bytes);
        if (eocd < 0)
        {
            int anyEocd = LastIndexOf(bytes, Math.Max(0, bytes.Length - (22 + ushort.MaxValue)), [0x50, 0x4b, 0x05, 0x06]);
            if (anyEocd >= 0)
            {
                throw new PsignException("ZIP end of central directory has trailing data");
            }

            throw new PsignException("ZIP end of central directory not found");
        }

        int diskEntries = Le16(bytes, eocd + 8);
        int totalEntries = Le16(bytes, eocd + 10);
        long cdSize = Le32(bytes, eocd + 12);
        long cdOffset = Le32(bytes, eocd + 16);
        if (diskEntries != totalEntries || totalEntries == 0xffff || cdOffset == 0xffff_ffff)
        {
            throw new PsignException("multi-disk or ZIP64 NuGet packages are not supported for signature verification");
        }

        if (cdOffset + cdSize != eocd)
        {
            throw new PsignException("ZIP central directory does not end at the EOCD record");
        }

        var records = new List<(int Pos, int Len, bool IsSignature, long LocalOffset)>(totalEntries);
        long pos = cdOffset;
        for (int i = 0; i < totalEntries; i++)
        {
            if (pos + 4 > bytes.Length || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)pos)) != 0x02014b50)
            {
                throw new PsignException("invalid ZIP central directory record");
            }

            int nameLen = Le16(bytes, (int)pos + 28);
            int len = 46 + nameLen + Le16(bytes, (int)pos + 30) + Le16(bytes, (int)pos + 32);
            if (pos + len > bytes.Length)
            {
                throw new PsignException("truncated ZIP central directory record");
            }

            bool isSig = bytes.AsSpan((int)pos + 46, nameLen).SequenceEqual(Encoding.ASCII.GetBytes(PackageSignatureFileName));
            records.Add(((int)pos, len, isSig, Le32(bytes, (int)pos + 42)));
            pos += len;
        }

        if (pos != eocd)
        {
            throw new PsignException("ZIP central directory size mismatch");
        }

        int signatureIndex = records.FindIndex(r => r.IsSignature);
        if (signatureIndex < 0)
        {
            throw new PsignException($"package does not contain {PackageSignatureFileName}");
        }

        if (records.Count(r => r.IsSignature) != 1 || signatureIndex + 1 != records.Count)
        {
            throw new PsignException($"{PackageSignatureFileName} must be the single, last central directory record");
        }

        long signatureLocalOffset = records[signatureIndex].LocalOffset;
        if (signatureLocalOffset > cdOffset || records.Take(signatureIndex).Any(r => r.LocalOffset >= signatureLocalOffset))
        {
            throw new PsignException($"{PackageSignatureFileName} must be the last local file entry");
        }

        int keptCdSize = records[signatureIndex].Pos - (int)cdOffset;
        using var output = new MemoryStream();
        output.Write(bytes, 0, (int)signatureLocalOffset);
        output.Write(bytes, (int)cdOffset, keptCdSize);
        var end = bytes.AsSpan(eocd).ToArray();
        ushort entries = (ushort)(totalEntries - 1);
        BinaryPrimitives.WriteUInt16LittleEndian(end.AsSpan(8), entries);
        BinaryPrimitives.WriteUInt16LittleEndian(end.AsSpan(10), entries);
        BinaryPrimitives.WriteUInt32LittleEndian(end.AsSpan(12), (uint)keptCdSize);
        BinaryPrimitives.WriteUInt32LittleEndian(end.AsSpan(16), (uint)signatureLocalOffset);
        output.Write(end);
        return output.ToArray();
    }

    // ---------------------------------------------------------------- signature content

    /// <summary>Signature content reconstructed from a signed package (Rust <c>signed_package_signature_content_path</c>).</summary>
    public static byte[] SignedPackageSignatureContentPath(string path, NuGetHashAlgorithm algorithm)
    {
        var unsigned = SignedPackageUnsignedBytesPath(path);
        return SignatureContentBytes(algorithm, algorithm.Hash(unsigned));
    }

    /// <summary>Signature content reconstructed from signed package bytes.</summary>
    public static byte[] SignedPackageSignatureContent(byte[] package, NuGetHashAlgorithm algorithm)
    {
        var unsigned = SignedPackageUnsignedBytes(package);
        return SignatureContentBytes(algorithm, algorithm.Hash(unsigned));
    }

    /// <summary><c>{oid}-Hash</c> (Rust <c>package_hash_property_name</c>).</summary>
    public static string PackageHashPropertyName(NuGetHashAlgorithm algorithm) => $"{algorithm.Oid()}-Hash";

    /// <summary>Signature content for the canonical unsigned package (Rust <c>unsigned_package_signature_content_path</c>).</summary>
    public static byte[] UnsignedPackageSignatureContentPath(string path, NuGetHashAlgorithm algorithm)
    {
        var unsigned = CanonicalUnsignedPackageBytesPath(path);
        return SignatureContentBytes(algorithm, algorithm.Hash(unsigned));
    }

    /// <summary>Signature content for canonical unsigned package bytes derived from <paramref name="package"/>.</summary>
    public static byte[] UnsignedPackageSignatureContent(byte[] package, NuGetHashAlgorithm algorithm)
    {
        var unsigned = CanonicalUnsignedPackageBytes(package);
        return SignatureContentBytes(algorithm, algorithm.Hash(unsigned));
    }

    /// <summary><c>Version:1\n\n{oid}-Hash:{base64}\n\n</c> (Rust <c>signature_content_bytes</c>).</summary>
    public static byte[] SignatureContentBytes(NuGetHashAlgorithm algorithm, ReadOnlySpan<byte> packageHash) =>
        Encoding.UTF8.GetBytes($"Version:{SignatureContentVersion}\n\n{PackageHashPropertyName(algorithm)}:{Convert.ToBase64String(packageHash)}\n\n");

    /// <summary>Parse NuGet signature content (Rust <c>parse_signature_content</c>).</summary>
    public static NuGetSignatureContent ParseSignatureContent(byte[] bytes)
    {
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("NuGet signature content is not UTF-8", e);
        }

        var sections = text.Split("\n\n");
        string header = sections[0];
        if (sections.Length < 2)
        {
            throw new PsignException("NuGet signature content is missing package hash section");
        }

        string hashSection = sections[1];

        string? version = null;
        foreach (var line in RustLines(header).Where(l => l.Length > 0))
        {
            var (key, value) = SplitSignatureContentPair(line);
            if (key == "Version")
            {
                version = value;
            }
        }

        if (version is null)
        {
            throw new PsignException("NuGet signature content is missing Version");
        }

        if (version != SignatureContentVersion)
        {
            throw new PsignException($"unsupported NuGet signature content version {version}; expected {SignatureContentVersion}");
        }

        foreach (var line in RustLines(hashSection).Where(l => l.Length > 0))
        {
            var (key, value) = SplitSignatureContentPair(line);
            if (key.EndsWith("-Hash", StringComparison.Ordinal)
                && NuGetHashAlgorithmExtensions.FromOid(key[..^"-Hash".Length]) is { } hashAlgorithm)
            {
                byte[] packageHash;
                try
                {
                    packageHash = Base64Standard.Decode(value);
                }
                catch (FormatException e)
                {
                    throw new PsignException("NuGet signature content package hash is not valid base64", e);
                }

                if (packageHash.Length == 0)
                {
                    throw new PsignException("NuGet signature content package hash is empty");
                }

                return new NuGetSignatureContent(hashAlgorithm, packageHash);
            }
        }

        throw new PsignException("NuGet signature content does not contain a supported package hash property");
    }

    /// <summary>Rust <c>verify_unsigned_package_signature_content_path</c>.</summary>
    public static NuGetSignatureContent VerifyUnsignedPackageSignatureContentPath(string path, byte[] content)
    {
        var parsed = ParseSignatureContent(content);
        var unsigned = CanonicalUnsignedPackageBytesPath(path);
        var actual = parsed.HashAlgorithm.Hash(unsigned);
        if (!actual.AsSpan().SequenceEqual(parsed.PackageHash))
        {
            throw new PsignException(
                $"NuGet package hash mismatch for {path}; signature content records a different unsigned package digest");
        }

        return parsed;
    }

    // ---------------------------------------------------------------- extraction / embedding

    /// <summary>Rust <c>extract_signature_path</c>.</summary>
    public static byte[] ExtractSignaturePath(string path)
    {
        var bytes = ReadFileForOpen(path);
        try
        {
            return ExtractSignature(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"extract NuGet signature from {path}", e);
        }
    }

    /// <summary>Embedded <c>.signature.p7s</c> bytes (Rust <c>extract_signature</c>).</summary>
    public static byte[] ExtractSignature(byte[] package)
    {
        var input = OpenZip(package, "open NuGet ZIP");
        var file = input.ByName(PackageSignatureFileName)
            ?? throw new PsignException($"package does not contain {PackageSignatureFileName}", new PsignException("specified file not found in archive"));
        byte[] signature;
        try
        {
            signature = input.Read(file);
        }
        catch (PsignException e)
        {
            throw new PsignException("read NuGet package signature", e);
        }

        if (signature.Length == 0)
        {
            throw new PsignException("NuGet package signature payload is empty");
        }

        return signature;
    }

    /// <summary>Re-write the package without <c>.signature.p7s</c>, requiring it to be present (Rust <c>write_package_without_signature</c>).</summary>
    public static byte[] WritePackageWithoutSignature(byte[] package) => WritePackageWithoutSignatureImpl(package, requireSignature: true);

    private static byte[] WritePackageWithoutSignatureImpl(byte[] package, bool requireSignature)
    {
        var input = OpenZip(package, "open NuGet ZIP");
        var output = new ZipCrateWriter();
        bool hadSignature = false;
        foreach (var file in input.Entries)
        {
            string name = NormalizeEntry(input, file);
            if (name == PackageSignatureFileName)
            {
                hadSignature = true;
                continue;
            }

            CopyEntry(input, file, name, output);
        }

        if (requireSignature && !hadSignature)
        {
            throw new PsignException($"package does not contain {PackageSignatureFileName}");
        }

        var bytes = output.Finish();
        NormalizeNuGetZipMetadata(bytes);
        return bytes;
    }

    /// <summary>Rust <c>embed_signature_path</c>.</summary>
    public static void EmbedSignaturePath(string input, string output, byte[] signatureDer, bool overwrite, ZipDateTime? signatureTimestamp = null)
    {
        if (signatureDer.Length == 0)
        {
            throw new PsignException("NuGet package signature payload is empty");
        }

        var info = InspectNupkgPath(input);
        if (info.Signed && !overwrite)
        {
            throw new PsignException($"{input} already contains {PackageSignatureFileName}; pass overwrite to replace it");
        }

        var bytes = ReadFileForOpen(input);
        byte[] signed;
        try
        {
            signed = EmbedSignature(bytes, signatureDer, overwrite, signatureTimestamp);
        }
        catch (PsignException e)
        {
            throw new PsignException($"embed NuGet signature into {output}", e);
        }

        try
        {
            File.WriteAllBytes(output, signed);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"create {output}", e);
        }
    }

    /// <summary>
    /// Re-write the package and append a stored <c>.signature.p7s</c> as the last entry (Rust <c>embed_signature</c>).
    /// <paramref name="signatureTimestamp"/> defaults to the current local time (the Rust behavior); pass a fixed value
    /// for reproducible output.
    /// </summary>
    public static byte[] EmbedSignature(byte[] package, byte[] signatureDer, bool overwrite, ZipDateTime? signatureTimestamp = null)
    {
        if (signatureDer.Length == 0)
        {
            throw new PsignException("NuGet package signature payload is empty");
        }

        var input = OpenZip(package, "open NuGet ZIP");
        ZipDateTime timestamp;
        try
        {
            timestamp = signatureTimestamp ?? OpcPackage.CurrentZipDateTime();
        }
        catch (PsignException e)
        {
            throw new PsignException("determine local ZIP timestamp for NuGet signature", e);
        }

        var output = new ZipCrateWriter();
        bool hadSignature = false;
        foreach (var file in input.Entries)
        {
            string name = NormalizeEntry(input, file);
            if (name == PackageSignatureFileName)
            {
                hadSignature = true;
                if (overwrite)
                {
                    continue;
                }

                throw new PsignException($"package already contains {PackageSignatureFileName}; pass overwrite to replace it");
            }

            CopyEntry(input, file, name, output);
        }

        if (!hadSignature || overwrite)
        {
            output.StartFile(PackageSignatureFileName, signatureDer, ZipCrateWriter.Stored, timestamp);
        }

        var bytes = output.Finish();
        NormalizeNuGetZipMetadata(bytes);
        return bytes;
    }

    /// <summary>
    /// Clear the central directory "version made by" host byte and external attributes (Rust
    /// <c>normalize_nuget_zip_metadata</c>).
    /// </summary>
    public static void NormalizeNuGetZipMetadata(byte[] bytes)
    {
        int eocd = FindValidEocd(bytes);
        if (eocd < 0)
        {
            throw new PsignException("ZIP central directory end not found");
        }

        if (eocd + 22 > bytes.Length)
        {
            throw new PsignException("truncated ZIP central directory end");
        }

        long centralDirSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd + 12));
        long centralDirOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(eocd + 16));
        long centralDirEnd = centralDirOffset + centralDirSize;
        if (centralDirEnd > bytes.Length)
        {
            throw new PsignException("ZIP central directory extends past end of file");
        }

        long pos = centralDirOffset;
        while (pos < centralDirEnd)
        {
            if (pos + 46 > bytes.Length || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)pos)) != 0x02014b50)
            {
                throw new PsignException("invalid ZIP central directory entry");
            }

            bytes[pos + 5] = 0;
            bytes.AsSpan((int)pos + 38, 4).Clear();
            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan((int)pos + 28));
            int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan((int)pos + 30));
            int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan((int)pos + 32));
            pos += 46L + nameLen + extraLen + commentLen;
        }

        if (pos != centralDirEnd)
        {
            throw new PsignException("ZIP central directory entry length mismatch");
        }
    }

    // ---------------------------------------------------------------- helpers

    internal static ZipCrateArchive OpenZip(byte[] package, string context)
    {
        try
        {
            return ZipCrateArchive.Open(package);
        }
        catch (PsignException e)
        {
            throw new PsignException(context, e);
        }
    }

    private static string NormalizeEntry(ZipCrateArchive input, ZipCrateEntry file)
    {
        try
        {
            input.EnsureReadable(file);
        }
        catch (PsignException e)
        {
            throw new PsignException("read NuGet ZIP entry", e);
        }

        return OpcPackage.NormalizeZipPartName(file.Name);
    }

    private static void CopyEntry(ZipCrateArchive input, ZipCrateEntry file, string name, ZipCrateWriter output)
    {
        if (file.IsDir)
        {
            output.AddDirectory(name, file.LastModified);
        }
        else
        {
            output.StartFile(name, input.Read(file), file.CompressionMethod, file.LastModified);
        }
    }

    private static (string Key, string Value) SplitSignatureContentPair(string line)
    {
        int idx = line.IndexOf(':');
        if (idx < 0)
        {
            throw new PsignException($"invalid NuGet signature content line {RustDebugString(line)}");
        }

        string key = line[..idx];
        string value = line[(idx + 1)..];
        if (key.Length == 0 || value.Length == 0)
        {
            throw new PsignException($"invalid NuGet signature content line {RustDebugString(line)}");
        }

        return (key, value);
    }

    /// <summary>Rust <c>str::lines</c>: split on <c>\n</c>, strip one trailing <c>\r</c>, no trailing empty line.</summary>
    private static IEnumerable<string> RustLines(string text)
    {
        int start = 0;
        while (start < text.Length)
        {
            int nl = text.IndexOf('\n', start);
            string line = nl < 0 ? text[start..] : text[start..nl];
            if (line.EndsWith('\r'))
            {
                line = line[..^1];
            }

            yield return line;
            if (nl < 0)
            {
                break;
            }

            start = nl + 1;
        }
    }

    private static string RustDebugString(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    if (char.IsControl(c))
                    {
                        sb.Append($"\\u{{{(int)c:x}}}");
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        return sb.Append('"').ToString();
    }

    private static int FindValidEocd(byte[] bytes)
    {
        if (bytes.Length < 22)
        {
            return -1;
        }

        int searchFrom = Math.Max(0, bytes.Length - (22 + ushort.MaxValue));
        for (int i = bytes.Length - 22; i >= searchFrom; i--)
        {
            if (bytes[i] == 0x50 && bytes[i + 1] == 0x4b && bytes[i + 2] == 0x05 && bytes[i + 3] == 0x06)
            {
                int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i + 20));
                if (i + 22 + commentLen == bytes.Length)
                {
                    return i;
                }
            }
        }

        return -1;
    }

    private static int LastIndexOf(byte[] bytes, int from, ReadOnlySpan<byte> pattern)
    {
        for (int i = bytes.Length - pattern.Length; i >= from; i--)
        {
            if (bytes.AsSpan(i, pattern.Length).SequenceEqual(pattern))
            {
                return i;
            }
        }

        return -1;
    }

    private static int Le16(byte[] bytes, int at)
    {
        if (at < 0 || at + 2 > bytes.Length)
        {
            throw new PsignException("truncated ZIP structure");
        }

        return BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(at));
    }

    private static long Le32(byte[] bytes, int at)
    {
        if (at < 0 || at + 4 > bytes.Length)
        {
            throw new PsignException("truncated ZIP structure");
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at));
    }

    internal static byte[] ReadFile(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read {path}", e);
        }
    }

    internal static byte[] ReadFileForOpen(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"open {path}", e);
        }
    }
}
