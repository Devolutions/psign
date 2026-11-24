using System.Text;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Core.Msix;

/// <summary>
/// One entry of an AppxPackaging-layout ZIP written by <see cref="AppxPackage.WriteAppxZip"/> (Rust
/// <c>AppxZipEntry</c>).
/// </summary>
internal sealed class AppxZipEntry
{
    private AppxZipEntry(string name, ushort method, uint crc32, ulong uncompressedSize, byte[] data, List<ulong>? blockSizes)
    {
        Name = name;
        Method = method;
        Crc32 = crc32;
        UncompressedSize = uncompressedSize;
        Data = data;
        BlockSizes = blockSizes;
    }

    public string Name { get; }

    public ushort Method { get; }

    public uint Crc32 { get; }

    public ulong UncompressedSize { get; }

    public byte[] Data { get; }

    /// <summary>Compressed size of each 64 KiB block of a deflated entry (<c>Block/@Size</c>).</summary>
    public List<ulong>? BlockSizes { get; }

    /// <summary>Uncompressed stored entry.</summary>
    public static AppxZipEntry Stored(string name, byte[] data) =>
        new(name, AppxPackage.MethodStored, ZipCrc32.Compute(data), (ulong)data.Length, data, null);

    /// <summary>Payload entry deflated in 64 KiB AppX blocks unless storing is smaller or required.</summary>
    public static AppxZipEntry Payload(string name, byte[] data)
    {
        int slash = name.LastIndexOf('/');
        var leaf = slash >= 0 ? name[(slash + 1)..] : name;
        int dot = leaf.LastIndexOf('.');
        var extension = dot >= 0 ? MsixDigest.AsciiLower(leaf[(dot + 1)..]) : string.Empty;
        if (data.Length == 0 || AppxPackage.StoredExtensions.Contains(extension))
        {
            return Stored(name, (byte[])data.Clone());
        }

        var (compressed, blockSizes) = AppxPackage.DeflateAppxBlocks(data);
        if (compressed.Length >= data.Length)
        {
            return Stored(name, (byte[])data.Clone());
        }

        return new AppxZipEntry(name, AppxPackage.MethodDeflated, ZipCrc32.Compute(data), (ulong)data.Length, compressed, blockSizes);
    }

    /// <summary>Entry copied verbatim (already compressed with <paramref name="method"/>) from a staged package.</summary>
    public static AppxZipEntry Raw(string name, ushort method, uint crc32, ulong uncompressedSize, byte[] data)
    {
        if (method is not (AppxPackage.MethodStored or AppxPackage.MethodDeflated))
        {
            throw new PsignException($"unsupported ZIP compression method {method} in staged MSIX package");
        }

        return new AppxZipEntry(name, method, crc32, uncompressedSize, data, null);
    }

    /// <summary>Local file header byte size, matching <c>File/@LfhSize</c>.</summary>
    public int LocalHeaderSize => 30 + Encoding.UTF8.GetByteCount(Name);
}

/// <summary>
/// AppxPackaging-compatible ZIP layout, block-map authoring, bundle offset rewriting and unsigned / signing staging
/// for cleartext MSIX/AppX packages and bundles (port of <c>psign-sip-digest/src/appx_package.rs</c>).
/// </summary>
public static class AppxPackage
{
    /// <summary>Uncompressed bytes per <c>AppxBlockMap.xml</c> <c>&lt;Block&gt;</c> element.</summary>
    public const int AppxBlockSize = 64 * 1024;

    internal const ushort MethodStored = 0;
    internal const ushort MethodDeflated = 8;
    private const uint LocalHeaderSig = 0x0403_4b50;
    private const uint CentralHeaderSig = 0x0201_4b50;
    private const uint EocdSig = 0x0605_4b50;
    private const ushort DosDate1980 = 0x21;

    /// <summary>Extensions <c>makeappx</c> stores without compression because they are already compressed.</summary>
    internal static readonly HashSet<string> StoredExtensions = new(StringComparer.Ordinal)
    {
        "png", "jpg", "jpeg", "gif", "zip", "gz", "7z", "cab", "appx", "msix", "appxbundle", "msixbundle",
        "eappx", "emsix", "eappxbundle", "emsixbundle", "mp3", "mp4", "wma", "wmv", "m4a",
    };

    /// <summary><c>true</c> for <c>msixbundle</c> / <c>appxbundle</c> (lowercase, no dot).</summary>
    public static bool IsMsixBundleExtension(string ext) => ext is "msixbundle" or "appxbundle";

    /// <summary><c>true</c> for a cleartext MSIX/AppX package or bundle extension (lowercase, no dot).</summary>
    public static bool IsCleartextMsixFamilyExtension(string ext) => ext is "msix" or "appx" or "msixbundle" or "appxbundle";

    /// <summary>Raw-deflate <paramref name="data"/> with a full flush after every 64 KiB block (Rust <c>deflate_appx_blocks</c>).</summary>
    internal static (byte[] Compressed, List<ulong> BlockSizes) DeflateAppxBlocks(byte[] data)
    {
        var compress = new MinizDeflater(6);
        var blockSizes = new List<ulong>((data.Length + AppxBlockSize - 1) / AppxBlockSize);
        for (int offset = 0; offset < data.Length; offset += AppxBlockSize)
        {
            int len = Math.Min(AppxBlockSize, data.Length - offset);
            int start = compress.TotalOut;
            compress.Compress(data.AsSpan(offset, len), DeflateFlush.Full);
            blockSizes.Add((ulong)(compress.TotalOut - start));
        }

        compress.Compress([], DeflateFlush.Finish);
        return (compress.ToArray(), blockSizes);
    }

    internal static uint U32Field(ulong value, string what)
    {
        if (value >= uint.MaxValue)
        {
            throw new PsignException($"{what} exceeds 4 GiB; portable MSIX signing does not write ZIP64 entries");
        }

        return (uint)value;
    }

    /// <summary>Serialize <paramref name="entries"/> in order into an AppxPackaging-layout ZIP archive (Rust <c>write_appx_zip</c>).</summary>
    internal static byte[] WriteAppxZip(IReadOnlyList<AppxZipEntry> entries)
    {
        using var output = new MemoryStream();
        using var central = new MemoryStream();
        var o = new BinaryWriter(output);
        var c = new BinaryWriter(central);
        foreach (var entry in entries)
        {
            var name = Encoding.UTF8.GetBytes(entry.Name);
            if (name.Length > ushort.MaxValue)
            {
                throw new PsignException("out of range integral type conversion attempted");
            }

            ushort nameLen = (ushort)name.Length;
            ushort flags = IsAscii(entry.Name) ? (ushort)0 : (ushort)(1 << 11);
            uint offset = U32Field((ulong)output.Length, "MSIX package size");
            uint compressedSize = U32Field((ulong)entry.Data.Length, "MSIX entry size");
            uint uncompressedSize = U32Field(entry.UncompressedSize, "MSIX entry size");

            o.Write(LocalHeaderSig);
            o.Write((ushort)20);
            o.Write(flags);
            o.Write(entry.Method);
            o.Write((ushort)0);
            o.Write(DosDate1980);
            o.Write(entry.Crc32);
            o.Write(compressedSize);
            o.Write(uncompressedSize);
            o.Write(nameLen);
            o.Write((ushort)0);
            o.Write(name);
            o.Write(entry.Data);
            o.Flush();

            c.Write(CentralHeaderSig);
            c.Write((ushort)45);
            c.Write((ushort)20);
            c.Write(flags);
            c.Write(entry.Method);
            c.Write((ushort)0);
            c.Write(DosDate1980);
            c.Write(entry.Crc32);
            c.Write(compressedSize);
            c.Write(uncompressedSize);
            c.Write(nameLen);
            c.Write(new byte[8]);
            c.Write(0u);
            c.Write(offset);
            c.Write(name);
        }

        c.Flush();
        if (entries.Count >= ushort.MaxValue)
        {
            throw new PsignException("too many MSIX package entries");
        }

        ushort entryCount = (ushort)entries.Count;
        uint cdOffset = U32Field((ulong)output.Length, "MSIX package size");
        uint cdSize = U32Field((ulong)central.Length, "MSIX central directory size");
        central.Position = 0;
        central.CopyTo(output);
        o.Write(EocdSig);
        o.Write(new byte[4]);
        o.Write(entryCount);
        o.Write(entryCount);
        o.Write(cdSize);
        o.Write(cdOffset);
        o.Write((ushort)0);
        o.Flush();
        return MsixDigest.NormalizeZipForAppxSigning(output.ToArray());
    }

    private static bool IsAscii(string s)
    {
        foreach (char ch in s)
        {
            if (ch > 0x7F)
            {
                return false;
            }
        }

        return true;
    }

    private static string BlockMapHashMethodUri(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha256 => MsixDigest.HashSha256,
        AuthenticodeHashKind.Sha384 => MsixDigest.HashSha384,
        AuthenticodeHashKind.Sha512 => MsixDigest.HashSha512,
        _ => throw new PsignException("MSIX/AppX AppxBlockMap.xml requires SHA-256, SHA-384, or SHA-512; got SHA-1"),
    };

    private static byte[] HashBlock(ReadOnlySpan<byte> chunk, AuthenticodeHashKind kind)
    {
        _ = BlockMapHashMethodUri(kind);
        return kind.Hash(chunk);
    }

    private static string XmlEscapeAttr(string value) =>
        value.Replace("&", "&amp;").Replace("\"", "&quot;").Replace("<", "&lt;").Replace(">", "&gt;");

    internal static string BuildFlatMsixBlockMap(IReadOnlyList<(string Name, byte[] Data)> payloads, IReadOnlyList<AppxZipEntry> entries, AuthenticodeHashKind kind)
    {
        var hashMethod = BlockMapHashMethodUri(kind);
        var xml = new StringBuilder($"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"{hashMethod}\">");
        int n = Math.Min(payloads.Count, entries.Count);
        for (int i = 0; i < n; i++)
        {
            var (name, data) = payloads[i];
            var entry = entries[i];
            var escaped = XmlEscapeAttr(name.Replace('/', '\\'));
            xml.Append($"<File Name=\"{escaped}\" Size=\"{data.Length}\" LfhSize=\"{entry.LocalHeaderSize}\">");
            var blockSizes = entry.BlockSizes ?? [];
            int index = 0;
            for (int offset = 0; offset < data.Length; offset += AppxBlockSize, index++)
            {
                int len = Math.Min(AppxBlockSize, data.Length - offset);
                var encoded = Convert.ToBase64String(HashBlock(data.AsSpan(offset, len), kind));
                if (index < blockSizes.Count)
                {
                    xml.Append($"<Block Hash=\"{encoded}\" Size=\"{blockSizes[index]}\"/>");
                }
                else
                {
                    xml.Append($"<Block Hash=\"{encoded}\"/>");
                }
            }

            xml.Append("</File>");
        }

        xml.Append("</BlockMap>");
        return xml.ToString();
    }

    internal static string BuildMsixBundleBlockMap(byte[] manifest, AuthenticodeHashKind kind)
    {
        var hashMethod = BlockMapHashMethodUri(kind);
        var xml = new StringBuilder($"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"{hashMethod}\"><File Name=\"AppxMetadata\\AppxBundleManifest.xml\" Size=\"{manifest.Length}\" LfhSize=\"65\">");
        for (int offset = 0; offset < manifest.Length; offset += AppxBlockSize)
        {
            int len = Math.Min(AppxBlockSize, manifest.Length - offset);
            var encoded = Convert.ToBase64String(HashBlock(manifest.AsSpan(offset, len), kind));
            xml.Append($"<Block Hash=\"{encoded}\" Size=\"{len}\"/>");
        }

        xml.Append("</File></BlockMap>");
        return xml.ToString();
    }

    private static XmlEvent ReadEvent(QuickXmlReader reader, string context)
    {
        try
        {
            return reader.Read();
        }
        catch (QuickXmlException e)
        {
            throw new PsignException(context, new PsignException(e.Message));
        }
    }

    private static List<XmlAttribute> CollectAttributes(XmlEvent element, string context)
    {
        try
        {
            return element.Attributes().ToList();
        }
        catch (QuickXmlException e)
        {
            throw new PsignException(context, new PsignException(e.Message));
        }
    }

    private static string DecodeAttr(XmlAttribute attr)
    {
        try
        {
            return attr.DecodeAndUnescape();
        }
        catch (QuickXmlException e)
        {
            throw new PsignException(e.Message);
        }
    }

    /// <summary>
    /// Rewrite <c>&lt;Package&gt;</c> child <c>Offset</c> / <c>Size</c> attributes in <c>AppxBundleManifest.xml</c> to
    /// match the stored local headers of <paramref name="children"/>, preserving external sparse / flat-bundle
    /// references (Rust <c>bundle_manifest_for_stored_children</c>).
    /// </summary>
    public static byte[] BundleManifestForStoredChildren(byte[] manifest, IReadOnlyList<(string Name, byte[] Data)> children)
    {
        var locations = new Dictionary<string, (ulong Offset, ulong Size)>(StringComparer.Ordinal);
        ulong offset = 0;
        foreach (var (name, data) in children)
        {
            var logical = MsixDigest.DecodeOpcZipPartName(name);
            var opc = MsixDigest.EncodeOpcPartName(logical);
            var entry = AppxZipEntry.Stored(opc, []);
            offset = checked(offset + (ulong)entry.LocalHeaderSize);
            locations[logical] = (offset, (ulong)data.Length);
            offset = checked(offset + (ulong)data.Length);
        }

        var reader = new QuickXmlReader(manifest, trimText: false);
        var writer = new QuickXmlWriter();
        while (true)
        {
            var e = ReadEvent(reader, "read MSIX bundle manifest");
            if (e.Kind == XmlEventKind.Eof)
            {
                break;
            }

            if (e.Kind is XmlEventKind.Start or XmlEventKind.Empty && e.LocalName == "Package")
            {
                string? fileName = null;
                (byte[] Key, byte[] RawValue, string Value)? declaredOffset = null;
                (byte[] Key, byte[] RawValue, string Value)? declaredSize = null;
                var replacement = e.CloneWithoutAttributes();
                foreach (var attr in CollectAttributes(e, "read bundle Package attribute"))
                {
                    if (attr.KeyIs("FileName"))
                    {
                        fileName = DecodeAttr(attr).Replace('\\', '/');
                        replacement.PushRawAttribute(attr.Key, attr.Value);
                    }
                    else if (attr.KeyIs("Offset"))
                    {
                        declaredOffset = (attr.Key, attr.Value, DecodeAttr(attr));
                    }
                    else if (attr.KeyIs("Size"))
                    {
                        declaredSize = (attr.Key, attr.Value, DecodeAttr(attr));
                    }
                    else
                    {
                        replacement.PushRawAttribute(attr.Key, attr.Value);
                    }
                }

                if (fileName is null)
                {
                    throw new PsignException("bundle Package is missing FileName");
                }

                if (locations.TryGetValue(fileName, out var loc))
                {
                    replacement.PushAttribute("Offset", loc.Offset.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    replacement.PushAttribute("Size", loc.Size.ToString(System.Globalization.CultureInfo.InvariantCulture));
                }
                else
                {
                    bool expectsEmbedded = declaredOffset is { } d && d.Value.Trim().Length != 0 && d.Value.Trim() != "0";
                    if (expectsEmbedded)
                    {
                        throw new PsignException($"bundle child `{fileName}` is missing from ZIP");
                    }

                    if (declaredOffset is { } o)
                    {
                        replacement.PushRawAttribute(o.Key, o.RawValue);
                    }

                    if (declaredSize is { } s)
                    {
                        replacement.PushRawAttribute(s.Key, s.RawValue);
                    }
                }

                writer.Write(replacement);
                continue;
            }

            writer.Write(e);
        }

        return writer.ToArray();
    }

    /// <summary>
    /// Stage a cleartext package or bundle for signing, inserting a <c>PKCX</c> placeholder <c>AppxSignature.p7x</c>
    /// as the final ZIP entry (Rust <c>stage_msix_family_for_signature</c>).
    /// </summary>
    public static byte[] StageMsixFamilyForSignature(byte[] package, string ext, AuthenticodeHashKind hashKind)
    {
        var lower = MsixDigest.AsciiLower(ext);
        return IsMsixBundleExtension(lower)
            ? StageMsixBundleInternal(package, hashKind, true)
            : StageFlatMsixInternal(package, hashKind, true);
    }

    /// <summary>
    /// Restage an unsigned package or bundle into AppxPackaging ZIP64 layout with regenerated block map, content types
    /// and bundle offsets, without <c>AppxSignature.p7x</c>. A <c>null</c> <paramref name="hashKind"/> preserves an
    /// existing block-map hash method (default SHA-256) (Rust <c>restage_unsigned_msix_family_bytes</c>).
    /// </summary>
    public static byte[] RestageUnsignedMsixFamilyBytes(byte[] package, string ext, AuthenticodeHashKind? hashKind)
    {
        var lower = MsixDigest.AsciiLower(ext);
        if (MsixDigest.IsEncryptedMsixExtension(lower))
        {
            throw new PsignException($"encrypted MSIX/AppX packages (.{lower}) require Windows AppxSip OS delegation; portable cleartext package helpers cannot restage encrypted stores");
        }

        if (MsixDigest.MsixSignaturePartPresent(package))
        {
            throw new PsignException("MSIX/AppX package already contains AppxSignature.p7x; update the unsigned package before final signing");
        }

        var resolved = hashKind ?? MsixDigest.DetectBlockMapHashKind(package) ?? AuthenticodeHashKind.Sha256;
        return DetectIsBundleArchive(package, lower)
            ? StageMsixBundleInternal(package, resolved, false)
            : StageFlatMsixInternal(package, resolved, false);
    }

    /// <summary>
    /// Update <c>Identity/@Publisher</c> (and bundle <c>Package/@Publisher</c> plus unsigned embedded children) on an
    /// unsigned package or bundle and restage it (Rust <c>set_unsigned_msix_family_publisher_bytes</c>).
    /// </summary>
    public static byte[] SetUnsignedMsixFamilyPublisherBytes(byte[] package, string ext, string publisher)
    {
        var lower = MsixDigest.AsciiLower(ext);
        if (MsixDigest.IsEncryptedMsixExtension(lower))
        {
            throw new PsignException("encrypted MSIX/AppX packages (.eappx/.emsix) require Windows AppxSip OS delegation; portable cleartext package helpers cannot inspect or update encrypted stores");
        }

        if (publisher.Length == 0)
        {
            throw new PsignException("MSIX/AppX publisher cannot be empty");
        }

        if (MsixDigest.MsixSignaturePartPresent(package))
        {
            throw new PsignException("MSIX/AppX package already contains AppxSignature.p7x; update the unsigned package before final signing");
        }

        var hashKind = MsixDigest.DetectBlockMapHashKind(package) ?? AuthenticodeHashKind.Sha256;
        return DetectIsBundleArchive(package, lower)
            ? SetBundlePublisherAndRestage(package, publisher, hashKind)
            : SetFlatPublisherAndRestage(package, publisher, hashKind);
    }

    /// <summary>
    /// Replace <c>AppxSignature.p7x</c> in a staged archive with <paramref name="p7x"/>, copying every other entry's
    /// compressed bytes verbatim (Rust <c>replace_msix_signature_part</c>).
    /// </summary>
    public static byte[] ReplaceMsixSignaturePart(byte[] package, byte[] p7x)
    {
        var source = OpenZip(package, "open staged MSIX ZIP");
        var entries = new List<AppxZipEntry>(source.Count);
        bool replaced = false;
        for (int i = 0; i < source.Count; i++)
        {
            ZipCrateEntry entry;
            byte[] raw;
            try
            {
                entry = source.Entries[i];
                raw = source.ReadRaw(i);
            }
            catch (PsignException e)
            {
                throw new PsignException("read staged MSIX ZIP entry", e);
            }

            var name = entry.Name;
            if (name == MsixDigest.AppSignature)
            {
                entries.Add(AppxZipEntry.Stored(name, (byte[])p7x.Clone()));
                replaced = true;
                continue;
            }

            if (!entry.IsSupportedCompression)
            {
                throw new PsignException($"unsupported compression Unsupported({entry.CompressionMethod}) in staged MSIX entry `{name}`");
            }

            entries.Add(AppxZipEntry.Raw(name, entry.CompressionMethod, entry.Crc32, entry.UncompressedSize, raw));
        }

        if (!replaced)
        {
            throw new PsignException($"staged MSIX package is missing {MsixDigest.AppSignature} placeholder");
        }

        return WriteAppxZip(entries);
    }

    private static ZipCrateArchive OpenZip(byte[] package, string context)
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

    private static ZipCrateEntry ByIndex(ZipCrateArchive source, int i, string context)
    {
        try
        {
            return source.ByIndex(i);
        }
        catch (PsignException e)
        {
            throw new PsignException(context, e);
        }
    }

    private static bool DetectIsBundleArchive(byte[] package, string extLower)
    {
        var archive = OpenZip(package, "open MSIX/AppX ZIP");
        bool hasFlat = archive.TryOpenByName(MsixDigest.AppManifest, out _);
        bool hasBundle = archive.TryOpenByName(MsixDigest.BundleManifest, out _);
        if (IsMsixBundleExtension(extLower))
        {
            if (!hasBundle)
            {
                throw new PsignException("MSIX bundle is missing AppxMetadata/AppxBundleManifest.xml");
            }

            return true;
        }

        if (extLower is "msix" or "appx")
        {
            if (!hasFlat)
            {
                throw new PsignException("flat MSIX package is missing AppxManifest.xml");
            }

            return false;
        }

        if (hasFlat)
        {
            return false;
        }

        if (hasBundle)
        {
            return true;
        }

        throw new PsignException("MSIX/AppX package is missing AppxManifest.xml (or AppxMetadata/AppxBundleManifest.xml for bundles)");
    }

    private static byte[] FinishFlat(List<(string Name, byte[] Data)> payloads, string contentTypes, AuthenticodeHashKind hashKind, bool includeSignaturePlaceholder)
    {
        var entries = payloads.Select(p => AppxZipEntry.Payload(MsixDigest.EncodeOpcPartName(p.Name), p.Data)).ToList();
        var blockMap = BuildFlatMsixBlockMap(payloads, entries, hashKind);
        entries.Add(AppxZipEntry.Payload(MsixDigest.BlockMap, Encoding.UTF8.GetBytes(blockMap)));
        entries.Add(AppxZipEntry.Payload(MsixDigest.ContentTypes, Encoding.UTF8.GetBytes(contentTypes)));
        if (includeSignaturePlaceholder)
        {
            entries.Add(AppxZipEntry.Stored(MsixDigest.AppSignature, "PKCX"u8.ToArray()));
        }

        return WriteAppxZip(entries);
    }

    private static byte[] FinishBundle(byte[] manifest, List<(string Name, byte[] Data)> childPayloads, string contentTypes, AuthenticodeHashKind hashKind, bool includeSignaturePlaceholder)
    {
        var updated = BundleManifestForStoredChildren(manifest, childPayloads);
        var blockMap = BuildMsixBundleBlockMap(updated, hashKind);
        var entries = childPayloads.Select(c => AppxZipEntry.Stored(MsixDigest.EncodeOpcPartName(c.Name), c.Data)).ToList();
        entries.Add(AppxZipEntry.Stored(MsixDigest.BundleManifest, updated));
        entries.Add(AppxZipEntry.Payload(MsixDigest.BlockMap, Encoding.UTF8.GetBytes(blockMap)));
        entries.Add(AppxZipEntry.Payload(MsixDigest.ContentTypes, Encoding.UTF8.GetBytes(contentTypes)));
        if (includeSignaturePlaceholder)
        {
            entries.Add(AppxZipEntry.Stored(MsixDigest.AppSignature, "PKCX"u8.ToArray()));
        }

        return WriteAppxZip(entries);
    }

    private static byte[] StageFlatMsixInternal(byte[] package, AuthenticodeHashKind hashKind, bool includeSignaturePlaceholder)
    {
        var source = OpenZip(package, "open MSIX ZIP");
        var payloads = new List<(string Name, byte[] Data)>();
        var seenPayloads = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        byte[]? contentTypes = null;
        for (int i = 0; i < source.Count; i++)
        {
            var entry = ByIndex(source, i, "read MSIX ZIP entry");
            var name = entry.Name.Replace('\\', '/');
            if (name.EndsWith('/'))
            {
                continue;
            }

            switch (name)
            {
                case MsixDigest.ContentTypes:
                    contentTypes = source.Read(i);
                    break;
                case MsixDigest.BlockMap:
                case MsixDigest.AppSignature:
                case MsixDigest.CodeIntegrity:
                    break;
                default:
                    var logical = MsixDigest.DecodeOpcZipPartName(name);
                    if (!seenPayloads.Add(logical))
                    {
                        throw new PsignException($"duplicate MSIX payload part `{logical}`");
                    }

                    payloads.Add((logical, source.Read(i)));
                    break;
            }
        }

        if (!payloads.Any(p => p.Name == MsixDigest.AppManifest))
        {
            throw new PsignException("flat MSIX package is missing AppxManifest.xml");
        }

        var parts = payloads.Select(p => p.Name).ToList();
        var ct = includeSignaturePlaceholder
            ? MsixDigest.AppxContentTypesForSigning(contentTypes, parts, false)
            : MsixDigest.AppxContentTypesForUnsignedPackage(contentTypes, parts, AppxPackageLayout.Flat);
        return FinishFlat(payloads, ct, hashKind, includeSignaturePlaceholder);
    }

    private static byte[] StageMsixBundleInternal(byte[] package, AuthenticodeHashKind hashKind, bool includeSignaturePlaceholder)
    {
        var source = OpenZip(package, "open MSIX bundle ZIP");
        var children = new List<(string Name, byte[] Data)>();
        var seenChildren = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        byte[]? manifest = null;
        byte[]? contentTypes = null;
        for (int i = 0; i < source.Count; i++)
        {
            var entry = ByIndex(source, i, "read MSIX bundle ZIP entry");
            var name = entry.Name.Replace('\\', '/');
            if (name.EndsWith('/'))
            {
                continue;
            }

            switch (name)
            {
                case MsixDigest.BundleManifest:
                    manifest = source.Read(i);
                    break;
                case MsixDigest.ContentTypes:
                    contentTypes = source.Read(i);
                    break;
                case MsixDigest.BlockMap:
                case MsixDigest.AppSignature:
                case MsixDigest.AppManifest:
                case MsixDigest.CodeIntegrity:
                    break;
                default:
                    var logical = MsixDigest.DecodeOpcZipPartName(name);
                    if (!seenChildren.Add(logical))
                    {
                        throw new PsignException($"duplicate MSIX bundle child part `{logical}`");
                    }

                    children.Add((logical, source.Read(i)));
                    break;
            }
        }

        if (manifest is null)
        {
            throw new PsignException("MSIX bundle is missing AppxMetadata/AppxBundleManifest.xml");
        }

        var parts = children.Select(c => c.Name).ToList();
        parts.Add(MsixDigest.BundleManifest);
        var ct = includeSignaturePlaceholder
            ? MsixDigest.AppxContentTypesForSigning(contentTypes, parts, true)
            : MsixDigest.AppxContentTypesForUnsignedPackage(contentTypes, parts, AppxPackageLayout.Bundle);
        foreach (var (name, _) in children)
        {
            int dot = name.LastIndexOf('.');
            var childExt = dot >= 0 ? MsixDigest.AsciiLower(name[(dot + 1)..]) : string.Empty;
            if (MsixDigest.IsEncryptedMsixExtension(childExt))
            {
                throw new PsignException($"cleartext MSIX bundle contains encrypted child package `{name}`; encrypted children require Windows AppxSip OS delegation");
            }
        }

        return FinishBundle(manifest, children, ct, hashKind, includeSignaturePlaceholder);
    }

    private static byte[] SetFlatPublisherAndRestage(byte[] package, string publisher, AuthenticodeHashKind hashKind)
    {
        var source = OpenZip(package, "open MSIX/AppX ZIP");
        var payloads = new List<(string Name, byte[] Data)>();
        byte[]? contentTypes = null;
        bool updatedManifest = false;
        for (int i = 0; i < source.Count; i++)
        {
            var entry = ByIndex(source, i, "read MSIX/AppX ZIP entry");
            var name = entry.Name.Replace('\\', '/');
            if (name.EndsWith('/'))
            {
                continue;
            }

            switch (name)
            {
                case MsixDigest.ContentTypes:
                    contentTypes = source.Read(i);
                    break;
                case MsixDigest.BlockMap:
                case MsixDigest.AppSignature:
                case MsixDigest.CodeIntegrity:
                    break;
                case MsixDigest.AppManifest:
                    {
                        var data = source.Read(i);
                        byte[] rewritten;
                        try
                        {
                            rewritten = RewriteXmlPublisher(data, ["Identity"], publisher);
                        }
                        catch (PsignException e)
                        {
                            throw new PsignException("rewrite AppxManifest.xml Publisher", e);
                        }

                        payloads.Add((name, rewritten));
                        updatedManifest = true;
                        break;
                    }

                default:
                    var logical = MsixDigest.DecodeOpcZipPartName(name);
                    payloads.Add((logical, source.Read(i)));
                    break;
            }
        }

        if (!updatedManifest)
        {
            throw new PsignException("flat MSIX package is missing AppxManifest.xml");
        }

        var ct = MsixDigest.AppxContentTypesForUnsignedPackage(contentTypes, payloads.Select(p => p.Name).ToList(), AppxPackageLayout.Flat);
        return FinishFlat(payloads, ct, hashKind, false);
    }

    private static byte[] SetBundlePublisherAndRestage(byte[] package, string publisher, AuthenticodeHashKind hashKind)
    {
        var source = OpenZip(package, "open MSIX/AppX bundle ZIP");
        var children = new List<(string Name, byte[] Data)>();
        byte[]? manifest = null;
        byte[]? contentTypes = null;
        for (int i = 0; i < source.Count; i++)
        {
            var entry = ByIndex(source, i, "read MSIX bundle ZIP entry");
            var name = entry.Name.Replace('\\', '/');
            if (name.EndsWith('/'))
            {
                continue;
            }

            switch (name)
            {
                case MsixDigest.BundleManifest:
                    {
                        var data = source.Read(i);
                        try
                        {
                            manifest = RewriteXmlPublisher(data, ["Identity", "Package"], publisher);
                        }
                        catch (PsignException e)
                        {
                            throw new PsignException("rewrite AppxBundleManifest.xml Publisher", e);
                        }

                        break;
                    }

                case MsixDigest.ContentTypes:
                    contentTypes = source.Read(i);
                    break;
                case MsixDigest.BlockMap:
                case MsixDigest.AppSignature:
                case MsixDigest.AppManifest:
                case MsixDigest.CodeIntegrity:
                    break;
                default:
                    {
                        var logical = MsixDigest.DecodeOpcZipPartName(name);
                        var data = source.Read(i);
                        int dot = logical.LastIndexOf('.');
                        var childExt = dot >= 0 ? MsixDigest.AsciiLower(logical[(dot + 1)..]) : string.Empty;
                        if (MsixDigest.IsEncryptedMsixExtension(childExt))
                        {
                            throw new PsignException($"cleartext MSIX bundle contains encrypted child package `{logical}`; encrypted children require Windows AppxSip OS delegation");
                        }

                        if (IsCleartextMsixFamilyExtension(childExt))
                        {
                            if (MsixDigest.MsixSignaturePartPresent(data))
                            {
                                throw new PsignException($"bundle child `{logical}` already contains AppxSignature.p7x; update unsigned children before changing bundle publisher");
                            }

                            byte[] updated;
                            try
                            {
                                updated = SetUnsignedMsixFamilyPublisherBytes(data, childExt, publisher);
                            }
                            catch (PsignException e)
                            {
                                throw new PsignException($"update Publisher in bundle child `{logical}`", e);
                            }

                            children.Add((logical, updated));
                        }
                        else
                        {
                            children.Add((logical, data));
                        }

                        break;
                    }
            }
        }

        if (manifest is null)
        {
            throw new PsignException("MSIX bundle is missing AppxMetadata/AppxBundleManifest.xml");
        }

        var parts = children.Select(c => c.Name).ToList();
        parts.Add(MsixDigest.BundleManifest);
        var ct = MsixDigest.AppxContentTypesForUnsignedPackage(contentTypes, parts, AppxPackageLayout.Bundle);
        return FinishBundle(manifest, children, ct, hashKind, false);
    }

    internal static byte[] RewriteXmlPublisher(byte[] xml, IReadOnlyList<string> targetLocalNames, string publisher)
    {
        var reader = new QuickXmlReader(xml, trimText: false);
        var writer = new QuickXmlWriter();
        bool sawIdentity = false;
        while (true)
        {
            var e = ReadEvent(reader, "parse manifest XML");
            if (e.Kind == XmlEventKind.Eof)
            {
                break;
            }

            if (e.Kind is XmlEventKind.Start or XmlEventKind.Empty && targetLocalNames.Contains(e.LocalName))
            {
                if (e.LocalName == "Identity")
                {
                    sawIdentity = true;
                }

                writer.Write(ReplaceElementPublisher(e, publisher));
                continue;
            }

            writer.Write(e);
        }

        if (targetLocalNames.Contains("Identity") && !sawIdentity)
        {
            throw new PsignException("manifest XML is missing an <Identity> element");
        }

        return writer.ToArray();
    }

    private static XmlEvent ReplaceElementPublisher(XmlEvent element, string publisher)
    {
        bool insertIfMissing = element.LocalName == "Identity";
        var replacement = element.CloneWithoutAttributes();
        bool replaced = false;
        foreach (var attr in CollectAttributes(element, "read XML attribute"))
        {
            if (attr.KeyIs("Publisher"))
            {
                replacement.PushAttribute("Publisher", publisher);
                replaced = true;
            }
            else
            {
                replacement.PushRawAttribute(attr.Key, attr.Value);
            }
        }

        if (!replaced && insertIfMissing)
        {
            replacement.PushAttribute("Publisher", publisher);
        }

        return replacement;
    }
}
