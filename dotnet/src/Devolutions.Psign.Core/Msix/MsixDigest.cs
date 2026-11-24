using System.Buffers.Binary;
using System.Text;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Core.Msix;

/// <summary>Package topology when generating <c>[Content_Types].xml</c> (Rust <c>AppxPackageLayout</c>).</summary>
public enum AppxPackageLayout
{
    /// <summary>Flat <c>.msix</c> / <c>.appx</c> package carrying root <c>AppxManifest.xml</c>.</summary>
    Flat,

    /// <summary>Bundle <c>.msixbundle</c> / <c>.appxbundle</c> carrying <c>AppxMetadata/AppxBundleManifest.xml</c>.</summary>
    Bundle,
}

/// <summary>Individual digests of an APPX <c>SpcIndirectData</c> blob (Rust <c>AppxDigestParts</c>).</summary>
public sealed record AppxDigestParts(byte[] Axpc, byte[] Axcd, byte[] Axct, byte[] Axbm, byte[]? Axci);

/// <summary>
/// MSIX / APPX flat package and bundle digest (<c>AppxSip.dll</c>) vs PKCS#7 <c>SpcIndirectData</c> APPX blob
/// (port of <c>psign-sip-digest/src/msix_digest.rs</c>). The digest layout follows osslsigncode <c>appx.c</c>:
/// <c>APPX + AXPC + AXCD + AXCT + AXBM [+ AXCI]</c>.
/// </summary>
public static class MsixDigest
{
    internal const string AppSignature = "AppxSignature.p7x";
    internal const string ContentTypes = "[Content_Types].xml";
    internal const string BlockMap = "AppxBlockMap.xml";
    internal const string AppManifest = "AppxManifest.xml";
    internal const string BundleManifest = "AppxMetadata/AppxBundleManifest.xml";
    internal const string CodeIntegrity = "AppxMetadata/CodeIntegrity.cat";

    internal static readonly byte[] SigAppx = "APPX"u8.ToArray();
    internal static readonly byte[] TagAxpc = "AXPC"u8.ToArray();
    internal static readonly byte[] TagAxcd = "AXCD"u8.ToArray();
    internal static readonly byte[] TagAxct = "AXCT"u8.ToArray();
    internal static readonly byte[] TagAxbm = "AXBM"u8.ToArray();
    internal static readonly byte[] TagAxci = "AXCI"u8.ToArray();

    internal const string HashSha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    internal const string HashSha384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
    internal const string HashSha512 = "http://www.w3.org/2001/04/xmlenc#sha512";

    internal const ushort Zip64ExtraId = 0x0001;
    internal const uint LhSig = 0x0403_4b50;
    internal const uint CdSig = 0x0201_4b50;
    internal const uint EocdSig = 0x0605_4b50;
    internal const uint Zip64EocdSig = 0x0606_4b50;
    internal const uint Zip64LocSig = 0x0706_4b50;
    internal const ulong Zip64EocdRecordSize = 44;
    internal const ushort Zip64Version = 45;
    internal const ushort DataDescriptorBit = 1 << 3;
    internal const uint DdSig = 0x0807_4b50;
    internal const int AppxBlockSize = 64 * 1024;

    internal const string ContentTypeManifest = "application/vnd.ms-appx.manifest+xml";
    internal const string ContentTypeBundleManifest = "application/vnd.ms-appx.bundlemanifest+xml";
    internal const string ContentTypeBlockMap = "application/vnd.ms-appx.blockmap+xml";
    internal const string ContentTypeSignature = "application/vnd.ms-appx.signature";

    /// <summary>
    /// Fixed 64-byte <c>AXPC</c> sentinel emitted by Windows <c>AppxSip.dll</c> when signing via
    /// <c>.pkgSignConfig</c> with <c>&lt;SkipPackageContentHash&gt;true&lt;/SkipPackageContentHash&gt;</c>. The
    /// prefix of the digest width is compared; the other digests and block hashes are still verified.
    /// </summary>
    public static ReadOnlySpan<byte> SkipPackageContentHashSentinel =>
    [
        0x43, 0xda, 0x04, 0xfa, 0xfe, 0xa9, 0x5d, 0xf4, 0x29, 0xd0, 0xf9, 0xfe, 0x86, 0x59, 0x75, 0xd8,
        0x37, 0x51, 0xe4, 0x93, 0x03, 0x25, 0x4a, 0xe9, 0x99, 0x9d, 0x89, 0x5b, 0xe2, 0x6f, 0xf4, 0x18,
        0x43, 0xda, 0x04, 0xfa, 0xfe, 0xa9, 0x5d, 0xf4, 0x29, 0xd0, 0xf9, 0xfe, 0x86, 0x59, 0x75, 0xd8,
        0x37, 0x51, 0xe4, 0x93, 0x03, 0x25, 0x4a, 0xe9, 0x99, 0x9d, 0x89, 0x5b, 0xe2, 0x6f, 0xf4, 0x18,
    ];

    // ================================================================== model types

    internal sealed record ClassicEocd(
        ushort DiskNumber,
        ushort DiskWithCentralDirectory,
        ushort NumberOfFilesOnThisDisk,
        ushort NumberOfFiles,
        uint CentralDirectorySize,
        uint CentralDirectoryOffset,
        byte[] ZipFileComment);

    internal sealed record Zip64Locator(uint DiskWithCentralDirectory, ulong EndOfCentralDirectoryOffset, uint NumberOfDisks);

    internal sealed record Zip64Eocd(
        ulong RecordSize,
        ushort VersionMadeBy,
        ushort VersionNeededToExtract,
        uint DiskNumber,
        uint DiskWithCentralDirectory,
        ulong NumberOfFilesOnThisDisk,
        ulong NumberOfFiles,
        ulong CentralDirectorySize,
        ulong CentralDirectoryOffset,
        byte[] TailAfterFixed);

    internal sealed record ZipTail(
        ClassicEocd Classic,
        Zip64Eocd? Zip64Eocd,
        Zip64Locator? Locator,
        ulong? Zip64EocdOffset,
        int EocdOffset,
        ulong CentralDirectoryOffset,
        ulong CentralDirectorySize);

    internal sealed class AppxBlockMapFile
    {
        public required string Name { get; init; }

        public required string NormalizedName { get; init; }

        public ulong DeclaredSize { get; init; }

        public ulong? LfhSize { get; init; }

        public List<AppxBlockMapBlock> Blocks { get; } = [];

        public byte[]? FileHash { get; set; }
    }

    internal sealed record AppxBlockMapBlock(byte[] Hash, ulong? CompressedSize);

    internal readonly record struct AppxPackageInventory(bool HasCodeIntegrity);

    internal sealed class AppxContentTypes
    {
        public Dictionary<string, string> Defaults { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, string> Overrides { get; } = new(StringComparer.Ordinal);
    }

    // ================================================================== little endian helpers

    private static ushort ReadU16(byte[] buf, long off)
    {
        if (off < 0 || off + 2 > buf.Length)
        {
            throw new PsignException($"read past end at {off}");
        }

        return BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan((int)off));
    }

    private static uint ReadU32(byte[] buf, long off)
    {
        if (off < 0 || off + 4 > buf.Length)
        {
            throw new PsignException($"read past end at {off}");
        }

        return BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan((int)off));
    }

    private static ulong ReadU64(byte[] buf, long off)
    {
        if (off < 0 || off + 8 > buf.Length)
        {
            throw new PsignException($"read past end at {off}");
        }

        return BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan((int)off));
    }

    private static void Le(IncrementalHashWrapper h, ushort v)
    {
        Span<byte> b = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(b, v);
        h.Update(b);
    }

    private static void Le(IncrementalHashWrapper h, uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, v);
        h.Update(b);
    }

    private static void Le(IncrementalHashWrapper h, ulong v)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, v);
        h.Update(b);
    }

    private sealed class IncrementalHashWrapper : IDisposable
    {
        private readonly System.Security.Cryptography.IncrementalHash _h;

        public IncrementalHashWrapper(AuthenticodeHashKind kind) => _h = kind.CreateHasher();

        public void Update(ReadOnlySpan<byte> data) => _h.AppendData(data);

        public byte[] Finish() => _h.GetHashAndReset();

        public void Dispose() => _h.Dispose();
    }

    // ================================================================== PKCX / hash URIs

    /// <summary>Strip the <c>PKCX</c> prefix of <c>AppxSignature.p7x</c> (Rust <c>strip_pkcx</c>).</summary>
    public static byte[] StripPkcx(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4 || !data.StartsWith("PKCX"u8))
        {
            throw new PsignException("AppxSignature.p7x did not start with PKCX (Windows P7X wrapper)");
        }

        return data[4..].ToArray();
    }

    /// <summary>Strip a <c>PKCX</c> wrapper or return <c>null</c> (Rust <c>pkcs7_wire::strip_pkcx_p7x_wrapper</c>).</summary>
    public static byte[]? TryStripPkcxWrapper(ReadOnlySpan<byte> data) =>
        data.StartsWith("PKCX"u8) ? data[4..].ToArray() : null;

    internal static AuthenticodeHashKind HashKindFromBlockMapUri(string uri)
    {
        uri = uri.Trim();
        return uri switch
        {
            HashSha256 => AuthenticodeHashKind.Sha256,
            HashSha384 => AuthenticodeHashKind.Sha384,
            HashSha512 => AuthenticodeHashKind.Sha512,
            _ => throw new PsignException($"unsupported AppxBlockMap HashMethod URI `{uri}` (expected SHA256/384/512 URIs)"),
        };
    }

    // ================================================================== part names

    /// <summary>
    /// Decode an OPC/AppxPackaging ZIP entry name (such as <c>Assets/Sub%20Dir/notes%20%26%20config.xml</c>) into its
    /// logical forward-slash path, rejecting percent-encoded separators, NULs, drive colons or traversal segments.
    /// </summary>
    public static string DecodeOpcZipPartName(string name)
    {
        if (name == ContentTypes)
        {
            return name;
        }

        if (name.Length == 0 || name.Contains('\0'))
        {
            throw new PsignException("APPX/MSIX ZIP contains an empty or NUL part name");
        }

        var slashName = name.Replace('\\', '/');
        if (slashName.StartsWith('/') || slashName.EndsWith('/'))
        {
            throw new PsignException($"APPX/MSIX part `{name}` has leading or trailing `/`");
        }

        var decoded = new List<string>();
        var strict = new UTF8Encoding(false, true);
        foreach (var rawSeg in slashName.Split('/'))
        {
            if (rawSeg.Length == 0)
            {
                throw new PsignException($"APPX/MSIX part `{name}` has an empty path segment");
            }

            var bytes = Encoding.UTF8.GetBytes(rawSeg);
            var outBytes = new List<byte>(bytes.Length);
            int i = 0;
            while (i < bytes.Length)
            {
                if (bytes[i] == '%' && i + 2 < bytes.Length && HexNibble(bytes[i + 1]) is int hi && HexNibble(bytes[i + 2]) is int lo)
                {
                    byte decodedByte = (byte)((hi << 4) | lo);
                    if (decodedByte is 0 or (byte)'/' or (byte)'\\' or (byte)':')
                    {
                        throw new PsignException($"APPX/MSIX part `{name}` percent-encodes a forbidden path separator or NUL");
                    }

                    outBytes.Add(decodedByte);
                    i += 3;
                    continue;
                }

                outBytes.Add(bytes[i]);
                i++;
            }

            string seg;
            try
            {
                seg = strict.GetString(outBytes.ToArray());
            }
            catch (DecoderFallbackException)
            {
                throw new PsignException($"APPX/MSIX part `{name}` percent-decodes to invalid UTF-8");
            }

            if (seg == "." || seg == ".." || seg.Contains(':'))
            {
                throw new PsignException($"APPX/MSIX part `{name}` decodes to an invalid path segment `{seg}`");
            }

            decoded.Add(seg);
        }

        return string.Join('/', decoded);
    }

    /// <summary>
    /// Encode a logical forward-slash package path into the OPC Part URI form emitted by <c>AppxPackaging.dll</c>,
    /// preserving <c>[Content_Types].xml</c> verbatim.
    /// </summary>
    public static string EncodeOpcPartName(string logicalName)
    {
        if (logicalName == ContentTypes)
        {
            return logicalName;
        }

        const string hex = "0123456789ABCDEF";
        var sb = new StringBuilder(logicalName.Length);
        var segments = logicalName.Split('/');
        for (int s = 0; s < segments.Length; s++)
        {
            if (s > 0)
            {
                sb.Append('/');
            }

            foreach (byte b in Encoding.UTF8.GetBytes(segments[s]))
            {
                if (b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9'
                    or (byte)'-' or (byte)'.' or (byte)'_' or (byte)'~' or (byte)'!')
                {
                    sb.Append((char)b);
                }
                else
                {
                    sb.Append('%').Append(hex[b >> 4]).Append(hex[b & 0x0F]);
                }
            }
        }

        return sb.ToString();
    }

    private static int? HexNibble(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => null,
    };

    internal static string NormalizeAppxPartName(string name)
    {
        if (name.Length == 0 || name.Contains('\0'))
        {
            throw new PsignException("AppxBlockMap.xml contains an empty or NUL part name");
        }

        var normalized = name.Replace('\\', '/');
        if (normalized.StartsWith('/') || normalized.Contains(':'))
        {
            throw new PsignException($"AppxBlockMap.xml part `{name}` is absolute or drive-qualified");
        }

        foreach (var segment in normalized.Split('/'))
        {
            if (segment.Length == 0 || segment == "." || segment == "..")
            {
                throw new PsignException($"AppxBlockMap.xml part `{name}` contains an invalid path segment");
            }
        }

        return normalized;
    }

    // ================================================================== XML helpers

    private static string? XmlAttr(XmlEvent e, string name)
    {
        // The Rust helpers hard-code "AppxBlockMap.xml" in their messages for every document.
        const string doc = "AppxBlockMap.xml";
        try
        {
            foreach (var attr in e.Attributes())
            {
                if (attr.KeyIs(name))
                {
                    try
                    {
                        return attr.DecodeAndUnescape();
                    }
                    catch (QuickXmlException ex)
                    {
                        throw new PsignException($"{doc} attribute decode failed: {ex.Message}");
                    }
                }
            }
        }
        catch (QuickXmlException ex)
        {
            throw new PsignException($"{doc} attribute parse failed: {ex.Message}");
        }

        return null;
    }

    private static string RequiredXmlAttr(XmlEvent e, string name) =>
        XmlAttr(e, name) ?? throw new PsignException($"AppxBlockMap.xml `{e.LocalName}` element missing `{name}` attribute");

    private static ulong? OptionalU64XmlAttr(XmlEvent e, string name)
    {
        var v = XmlAttr(e, name);
        if (v is null)
        {
            return null;
        }

        if (!TryParseRustU64(v, out ulong r))
        {
            throw new PsignException($"AppxBlockMap.xml `{e.LocalName}` element has invalid `{name}` value");
        }

        return r;
    }

    /// <summary>Rust <c>str::parse::&lt;u64&gt;</c> (optional leading <c>+</c>, ASCII digits only).</summary>
    internal static bool TryParseRustU64(string s, out ulong value)
    {
        value = 0;
        var span = s.AsSpan();
        if (span.StartsWith("+"))
        {
            span = span[1..];
        }

        if (span.IsEmpty)
        {
            return false;
        }

        foreach (char c in span)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }
        }

        return ulong.TryParse(span, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out value);
    }

    private static byte[] DecodeBase64Strict(string encoded, string what)
    {
        try
        {
            return Base64Standard.Decode(encoded);
        }
        catch (FormatException e)
        {
            throw new PsignException($"{what} is not base64: {e.Message}");
        }
    }

    private static XmlEvent ReadXml(QuickXmlReader reader, string doc)
    {
        try
        {
            return reader.Read();
        }
        catch (QuickXmlException e)
        {
            throw new PsignException($"{doc} parse failed: {e.Message}");
        }
    }

    // ================================================================== AppxBlockMap.xml

    internal static (AuthenticodeHashKind Kind, List<AppxBlockMapFile> Files) ParseBlockMapXml(byte[] xml)
    {
        const string doc = "AppxBlockMap.xml";
        var reader = new QuickXmlReader(xml, trimText: true);
        AuthenticodeHashKind? kind = null;
        var files = new List<AppxBlockMapFile>();
        AppxBlockMapFile? current = null;
        var seenNames = new HashSet<string>(StringComparer.Ordinal);
        bool inBlockMap = false;

        while (true)
        {
            var e = ReadXml(reader, doc);
            if (e.Kind == XmlEventKind.Eof)
            {
                break;
            }

            bool startOrEmpty = e.Kind is XmlEventKind.Start or XmlEventKind.Empty;
            string local = startOrEmpty || e.Kind == XmlEventKind.End ? e.LocalName : string.Empty;

            if (startOrEmpty && local == "BlockMap")
            {
                if (kind is not null)
                {
                    throw new PsignException("duplicate AppxBlockMap.xml BlockMap root");
                }

                kind = HashKindFromBlockMapUri(RequiredXmlAttr(e, "HashMethod"));
                if (e.Kind == XmlEventKind.Start)
                {
                    inBlockMap = true;
                }
            }
            else if (startOrEmpty && local == "File")
            {
                if (!inBlockMap)
                {
                    throw new PsignException("AppxBlockMap.xml File outside BlockMap");
                }

                if (current is not null)
                {
                    throw new PsignException("nested AppxBlockMap.xml File elements are invalid");
                }

                var name = RequiredXmlAttr(e, "Name");
                var normalized = NormalizeAppxPartName(name);
                if (!seenNames.Add(normalized))
                {
                    throw new PsignException($"duplicate AppxBlockMap.xml File entry `{name}`");
                }

                if (!TryParseRustU64(RequiredXmlAttr(e, "Size"), out ulong declaredSize))
                {
                    throw new PsignException($"AppxBlockMap.xml File `{name}` has invalid Size");
                }

                var lfh = OptionalU64XmlAttr(e, "LfhSize");
                var file = new AppxBlockMapFile { Name = name, NormalizedName = normalized, DeclaredSize = declaredSize, LfhSize = lfh };
                if (e.Kind == XmlEventKind.Start)
                {
                    current = file;
                }
                else
                {
                    files.Add(file);
                }
            }
            else if (startOrEmpty && local == "Block")
            {
                if (current is null)
                {
                    throw new PsignException("AppxBlockMap.xml Block outside File");
                }

                var hash = DecodeBase64Strict(RequiredXmlAttr(e, "Hash"), "AppxBlockMap.xml Block Hash");
                var compressed = OptionalU64XmlAttr(e, "Size");
                current.Blocks.Add(new AppxBlockMapBlock(hash, compressed));
            }
            else if (startOrEmpty && local == "FileHash")
            {
                if (current is null)
                {
                    throw new PsignException("AppxBlockMap.xml FileHash outside File");
                }

                if (current.FileHash is not null)
                {
                    throw new PsignException($"AppxBlockMap.xml File `{current.Name}` has duplicate FileHash elements");
                }

                current.FileHash = DecodeBase64Strict(RequiredXmlAttr(e, "Hash"), "AppxBlockMap.xml FileHash Hash");
            }
            else if (e.Kind == XmlEventKind.End && local == "BlockMap")
            {
                if (current is not null)
                {
                    throw new PsignException("AppxBlockMap.xml BlockMap ended inside File");
                }

                inBlockMap = false;
            }
            else if (e.Kind == XmlEventKind.End && local == "File")
            {
                files.Add(current ?? throw new PsignException("AppxBlockMap.xml unexpected File end"));
                current = null;
            }
            else if (startOrEmpty)
            {
                throw new PsignException($"unexpected AppxBlockMap.xml element `{local}`");
            }
        }

        if (current is not null)
        {
            throw new PsignException("unterminated AppxBlockMap.xml File element");
        }

        var k = kind ?? throw new PsignException("AppxBlockMap.xml missing HashMethod");
        int expected = k.DigestLength();
        foreach (var file in files)
        {
            if (file.FileHash is { } fh && fh.Length != expected)
            {
                throw new PsignException($"AppxBlockMap.xml File `{file.Name}` has {fh.Length}-byte FileHash, expected {expected}");
            }

            foreach (var block in file.Blocks)
            {
                if (block.Hash.Length != expected)
                {
                    throw new PsignException($"AppxBlockMap.xml File `{file.Name}` has {block.Hash.Length}-byte block hash, expected {expected}");
                }
            }
        }

        return (k, files);
    }

    // ================================================================== [Content_Types].xml

    internal static AppxContentTypes ValidateContentTypesXml(byte[] xml)
    {
        const string doc = "[Content_Types].xml";
        var reader = new QuickXmlReader(xml, trimText: true);
        bool inTypes = false;
        bool sawTypes = false;
        var ct = new AppxContentTypes();

        while (true)
        {
            var e = ReadXml(reader, doc);
            if (e.Kind == XmlEventKind.Eof)
            {
                break;
            }

            bool startOrEmpty = e.Kind is XmlEventKind.Start or XmlEventKind.Empty;
            string local = startOrEmpty || e.Kind == XmlEventKind.End ? e.LocalName : string.Empty;
            if (startOrEmpty && local == "Types")
            {
                if (sawTypes)
                {
                    throw new PsignException("duplicate [Content_Types].xml Types root");
                }

                sawTypes = true;
                if (e.Kind == XmlEventKind.Start)
                {
                    inTypes = true;
                }
            }
            else if (startOrEmpty && local == "Default")
            {
                if (!inTypes)
                {
                    throw new PsignException("[Content_Types].xml Default outside Types");
                }

                var extension = RequiredXmlAttr(e, "Extension");
                var contentType = RequiredXmlAttr(e, "ContentType");
                if (extension.Length == 0 || extension.Contains('/') || extension.Contains('\\'))
                {
                    throw new PsignException($"[Content_Types].xml Default has invalid Extension `{extension}`");
                }

                if (contentType.Length == 0)
                {
                    throw new PsignException($"[Content_Types].xml Default `{extension}` has empty ContentType");
                }

                if (!ct.Defaults.TryAdd(AsciiLower(extension), contentType))
                {
                    throw new PsignException($"duplicate [Content_Types].xml Default for extension `{extension}`");
                }
            }
            else if (startOrEmpty && local == "Override")
            {
                if (!inTypes)
                {
                    throw new PsignException("[Content_Types].xml Override outside Types");
                }

                var partName = RequiredXmlAttr(e, "PartName");
                var contentType = RequiredXmlAttr(e, "ContentType");
                if (!partName.StartsWith('/'))
                {
                    throw new PsignException($"[Content_Types].xml Override PartName `{partName}` is not absolute");
                }

                if (contentType.Length == 0)
                {
                    throw new PsignException($"[Content_Types].xml Override `{partName}` has empty ContentType");
                }

                var decodedPart = DecodeOpcZipPartName(partName[1..]);
                var normalized = NormalizeAppxPartName(decodedPart);
                if (!ct.Overrides.TryAdd(AsciiLower(normalized), contentType))
                {
                    throw new PsignException($"duplicate [Content_Types].xml Override for part `{partName}`");
                }
            }
            else if (e.Kind == XmlEventKind.End && local == "Types")
            {
                inTypes = false;
            }
            else if (e.Kind == XmlEventKind.End && local is "Default" or "Override")
            {
            }
            else if (startOrEmpty)
            {
                throw new PsignException($"unexpected [Content_Types].xml element `{local}`");
            }
            else if (e.Kind == XmlEventKind.Text)
            {
                string text;
                try
                {
                    text = QuickXml.DecodeUtf8(e.Content);
                }
                catch (QuickXmlException ex)
                {
                    throw new PsignException($"[Content_Types].xml text decode failed: {ex.Message}");
                }

                if (text.Trim().Length != 0)
                {
                    throw new PsignException("[Content_Types].xml contains non-whitespace text");
                }
            }
        }

        if (!sawTypes)
        {
            throw new PsignException("[Content_Types].xml missing Types root");
        }

        if (inTypes)
        {
            throw new PsignException("unterminated [Content_Types].xml Types root");
        }

        return ct;
    }

    internal static string AsciiLower(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            if (chars[i] is >= 'A' and <= 'Z')
            {
                chars[i] = (char)(chars[i] + 32);
            }
        }

        return new string(chars);
    }

    internal static bool AsciiEqualsIgnoreCase(string a, string b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (int i = 0; i < a.Length; i++)
        {
            char x = a[i];
            char y = b[i];
            if (x is >= 'A' and <= 'Z')
            {
                x = (char)(x + 32);
            }

            if (y is >= 'A' and <= 'Z')
            {
                y = (char)(y + 32);
            }

            if (x != y)
            {
                return false;
            }
        }

        return true;
    }

    internal static string? ContentTypeForPart(AppxContentTypes contentTypes, string part)
    {
        string normalized;
        try
        {
            normalized = NormalizeAppxPartName(part);
        }
        catch (PsignException)
        {
            return null;
        }

        if (contentTypes.Overrides.TryGetValue(AsciiLower(normalized), out var o))
        {
            return o;
        }

        int dot = normalized.LastIndexOf('.');
        if (dot < 0)
        {
            return null;
        }

        return contentTypes.Defaults.TryGetValue(AsciiLower(normalized[(dot + 1)..]), out var d) ? d : null;
    }

    private static void RequireContentType(AppxContentTypes contentTypes, string part, string expected)
    {
        var actual = ContentTypeForPart(contentTypes, part)
            ?? throw new PsignException($"[Content_Types].xml does not declare a content type for `{part}`");
        if (!AsciiEqualsIgnoreCase(actual, expected))
        {
            throw new PsignException($"[Content_Types].xml content type for `{part}` is `{actual}`, expected `{expected}`");
        }
    }

    internal static void ValidateReservedContentTypes(AppxContentTypes contentTypes, AppxPackageInventory inventory, string ext)
    {
        RequireContentType(contentTypes, BlockMap, ContentTypeBlockMap);
        RequireContentType(contentTypes, AppSignature, ContentTypeSignature);
        if (inventory.HasCodeIntegrity)
        {
            RequireContentType(contentTypes, CodeIntegrity, "application/vnd.ms-pkiseccat");
        }

        if (ext is "msixbundle" or "appxbundle")
        {
            RequireContentType(contentTypes, BundleManifest, ContentTypeBundleManifest);
        }
        else
        {
            RequireContentType(contentTypes, AppManifest, ContentTypeManifest);
        }
    }

    // ================================================================== APPX blob

    /// <summary>Parse an APPX indirect digest blob into its pieces; returns the per-piece digest width.</summary>
    public static (int DigestLength, AppxDigestParts Parts) ParseSignedAppxBlob(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4 || !data.StartsWith(SigAppx))
        {
            throw new PsignException("PKCS#7 indirect digest is not an APPX blob (missing APPX prefix)");
        }

        (int Len, bool Ci)? found = null;
        foreach (int candidate in new[] { 20, 32, 48, 64 })
        {
            int pos = 4;
            bool ok = true;
            foreach (var t in new[] { TagAxpc, TagAxcd, TagAxct, TagAxbm })
            {
                if (pos + 4 + candidate > data.Length || !data.Slice(pos, 4).SequenceEqual(t))
                {
                    ok = false;
                    break;
                }

                pos += 4 + candidate;
            }

            if (!ok)
            {
                continue;
            }

            if (pos == data.Length)
            {
                found = (candidate, false);
                break;
            }

            if (pos + 4 + candidate <= data.Length && data.Slice(pos, 4).SequenceEqual(TagAxci))
            {
                pos += 4 + candidate;
                if (pos == data.Length)
                {
                    found = (candidate, true);
                    break;
                }
            }
        }

        var (mdLen, hasCi) = found ?? throw new PsignException("could not parse APPX indirect digest blob (expected AXPC..AXBM [+ AXCI])");
        int p = 4;
        byte[] Take(ReadOnlySpan<byte> d, byte[] tag)
        {
            if (p + 4 + mdLen > d.Length || !d.Slice(p, 4).SequenceEqual(tag))
            {
                throw new PsignException("unexpected APPX digest tag");
            }

            p += 4;
            var r = d.Slice(p, mdLen).ToArray();
            p += mdLen;
            return r;
        }

        var axpc = Take(data, TagAxpc);
        var axcd = Take(data, TagAxcd);
        var axct = Take(data, TagAxct);
        var axbm = Take(data, TagAxbm);
        var axci = hasCi ? Take(data, TagAxci) : null;
        if (p != data.Length)
        {
            throw new PsignException("trailing bytes in APPX indirect digest blob");
        }

        return (mdLen, new AppxDigestParts(axpc, axcd, axct, axbm, axci));
    }

    // ================================================================== ZIP tail

    private static (int Offset, ClassicEocd Eocd) FindClassicEocd(byte[] buf)
    {
        const long headerSize = 22;
        long fileLength = buf.Length;
        if (fileLength < headerSize)
        {
            throw new PsignException("buffer too small for EOCD");
        }

        long searchUpper = Math.Max(0, fileLength - (headerSize + ushort.MaxValue));
        long pos = fileLength - headerSize;
        while (pos >= searchUpper)
        {
            int p = (int)pos;
            if (ReadU32(buf, p) == EocdSig)
            {
                ushort diskNumber = ReadU16(buf, p + 4);
                ushort diskWithCd = ReadU16(buf, p + 6);
                ushort filesOnDisk = ReadU16(buf, p + 8);
                ushort files = ReadU16(buf, p + 10);
                uint cdSize = ReadU32(buf, p + 12);
                uint cdOffset = ReadU32(buf, p + 16);
                int commentLen = ReadU16(buf, p + 20);
                long cstart = p + 22;
                long cend = cstart + commentLen;
                if (cend != buf.Length)
                {
                    if (pos == 0)
                    {
                        break;
                    }

                    pos--;
                    continue;
                }

                return (p, new ClassicEocd(diskNumber, diskWithCd, filesOnDisk, files, cdSize, cdOffset, buf.AsSpan((int)cstart, commentLen).ToArray()));
            }

            if (pos == 0)
            {
                break;
            }

            pos--;
        }

        throw new PsignException("could not find ZIP end-of-central-directory");
    }

    private static Zip64Locator ParseZip64Locator(byte[] buf, int off)
    {
        if (ReadU32(buf, off) != Zip64LocSig)
        {
            throw new PsignException("invalid ZIP64 locator signature");
        }

        var loc = new Zip64Locator(ReadU32(buf, off + 4), ReadU64(buf, off + 8), ReadU32(buf, off + 16));
        if (loc.DiskWithCentralDirectory != 0 || loc.NumberOfDisks != 1)
        {
            throw new PsignException("multi-disk ZIP64 archives are not valid APPX/MSIX packages");
        }

        return loc;
    }

    private static (long Pos, Zip64Eocd Eocd) FindZip64Eocd(byte[] buf, ulong nominalOffset, long searchUpper, long limitEnd)
    {
        if (nominalOffset > long.MaxValue)
        {
            throw new PsignException("could not find ZIP64 end-of-central-directory");
        }

        long pos = (long)nominalOffset;
        while (pos <= searchUpper)
        {
            if (ReadU32(buf, pos) == Zip64EocdSig)
            {
                ulong recordSize = ReadU64(buf, pos + 4);
                if (recordSize < 44)
                {
                    throw new PsignException("ZIP64 end-of-central-directory record is too small");
                }

                ushort versionMadeBy = ReadU16(buf, pos + 12);
                ushort versionNeeded = ReadU16(buf, pos + 14);
                uint diskNumber = ReadU32(buf, pos + 16);
                uint diskWithCd = ReadU32(buf, pos + 20);
                if (diskNumber != 0 || diskWithCd != 0)
                {
                    throw new PsignException("multi-disk ZIP64 archives are not valid APPX/MSIX packages");
                }

                ulong filesOnDisk = ReadU64(buf, pos + 24);
                ulong files = ReadU64(buf, pos + 32);
                ulong cdSize = ReadU64(buf, pos + 40);
                ulong cdOffset = ReadU64(buf, pos + 48);
                ulong tailLen = recordSize - 44;
                long tailStart = pos + 12 + 44;
                if (tailLen > (ulong)limitEnd || tailStart + (long)tailLen > limitEnd)
                {
                    throw new PsignException("zip64 tail out of range");
                }

                var tail = buf.AsSpan((int)tailStart, (int)tailLen).ToArray();
                return (pos, new Zip64Eocd(recordSize, versionMadeBy, versionNeeded, diskNumber, diskWithCd, filesOnDisk, files, cdSize, cdOffset, tail));
            }

            pos++;
        }

        throw new PsignException("could not find ZIP64 end-of-central-directory");
    }

    internal static ZipTail ParseZipTail(byte[] buf)
    {
        var (cdePos, classic) = FindClassicEocd(buf);
        bool sentinels = classic.DiskNumber == ushort.MaxValue && classic.DiskWithCentralDirectory == ushort.MaxValue;
        if (!sentinels && (classic.DiskNumber != 0 || classic.DiskWithCentralDirectory != 0))
        {
            throw new PsignException("multi-disk ZIP archives are not valid APPX/MSIX packages");
        }

        int fileLen = buf.Length;
        int commentLen = classic.ZipFileComment.Length;
        Zip64Locator? locator = null;
        Zip64Eocd? zip64 = null;
        ulong? zip64Offset = null;
        ulong cdOffset = classic.CentralDirectoryOffset;
        ulong cdSize = classic.CentralDirectorySize;

        long locatorSeek = fileLen - (20L + 22 + commentLen);
        if (locatorSeek >= 0 && locatorSeek + 20 <= buf.Length && ReadU32(buf, locatorSeek) == Zip64LocSig)
        {
            var loc = ParseZip64Locator(buf, (int)locatorSeek);
            locator = loc;
            if (locatorSeek < 56)
            {
                throw new PsignException("could not find ZIP64 end-of-central-directory");
            }

            long searchUpper = locatorSeek - 56;
            var (zpos, z64) = FindZip64Eocd(buf, loc.EndOfCentralDirectoryOffset, searchUpper, locatorSeek);
            if (z64.NumberOfFilesOnThisDisk != z64.NumberOfFiles)
            {
                throw new PsignException("multi-disk ZIP64 entry counts are not valid APPX/MSIX packages");
            }

            cdOffset = classic.CentralDirectoryOffset == uint.MaxValue ? z64.CentralDirectoryOffset : classic.CentralDirectoryOffset;
            cdSize = classic.CentralDirectorySize == uint.MaxValue ? z64.CentralDirectorySize : classic.CentralDirectorySize;
            zip64Offset = (ulong)zpos;
            zip64 = z64;
        }

        if (locator is null)
        {
            if (classic.NumberOfFilesOnThisDisk == ushort.MaxValue || classic.NumberOfFiles == ushort.MaxValue
                || classic.CentralDirectorySize == uint.MaxValue || classic.CentralDirectoryOffset == uint.MaxValue)
            {
                throw new PsignException("classic EOCD uses ZIP64 sentinel values but ZIP64 locator is missing");
            }

            ulong cde = (ulong)cdePos;
            if (cde < classic.CentralDirectorySize || cde - classic.CentralDirectorySize < classic.CentralDirectoryOffset)
            {
                throw new PsignException("invalid EOCD central directory size/offset");
            }
        }

        ulong cdEnd = cdOffset + cdSize;
        if (cdEnd < cdOffset)
        {
            throw new PsignException("central directory extent overflow");
        }

        ulong expectedCdEnd = zip64Offset ?? (ulong)cdePos;
        if (cdEnd != expectedCdEnd)
        {
            throw new PsignException($"central directory extent does not end at EOCD/ZIP64 EOCD (offset={cdOffset}, size={cdSize}, expected_end={expectedCdEnd})");
        }

        return new ZipTail(classic, zip64, locator, zip64Offset, cdePos, cdOffset, cdSize);
    }

    // ================================================================== local header / data hashing

    private static (bool Uncomp, bool Comp, bool Off, bool Disk, uint DiskValue) ParseZip64CdExtra(byte[] extra, uint fixedComp, uint fixedUncomp, uint fixedOff, ushort fixedDisk)
    {
        bool needsUncomp = fixedUncomp == uint.MaxValue;
        bool needsComp = fixedComp == uint.MaxValue;
        bool needsOff = fixedOff == uint.MaxValue;
        bool needsDisk = fixedDisk == ushort.MaxValue;
        uint disk = fixedDisk;
        int i = 0;
        while (i + 4 <= extra.Length)
        {
            ushort id = BinaryPrimitives.ReadUInt16LittleEndian(extra.AsSpan(i));
            int sz = BinaryPrimitives.ReadUInt16LittleEndian(extra.AsSpan(i + 2));
            i += 4;
            if (i + sz > extra.Length)
            {
                break;
            }

            var chunk = extra.AsSpan(i, sz);
            if (id == Zip64ExtraId)
            {
                int r = 0;
                if (needsUncomp && r + 8 <= chunk.Length)
                {
                    r += 8;
                    needsUncomp = false;
                }

                if (needsComp && r + 8 <= chunk.Length)
                {
                    r += 8;
                    needsComp = false;
                }

                if (needsOff && r + 8 <= chunk.Length)
                {
                    r += 8;
                    needsOff = false;
                }

                if (needsDisk && r + 4 <= chunk.Length)
                {
                    disk = BinaryPrimitives.ReadUInt32LittleEndian(chunk[r..]);
                    needsDisk = false;
                }
            }

            i += sz;
        }

        return (fixedUncomp == uint.MaxValue, fixedComp == uint.MaxValue, fixedOff == uint.MaxValue, fixedDisk == ushort.MaxValue, disk);
    }

    private static void WriteLocalHeaderNormalized(IncrementalHashWrapper hasher, byte[] buf, ZipCrateEntry zf)
    {
        long hs = checked((long)zf.HeaderStart);
        if (ReadU32(buf, hs) != LhSig)
        {
            throw new PsignException("bad local file header signature");
        }

        ushort version = ReadU16(buf, hs + 4);
        ushort flags = ReadU16(buf, hs + 6);
        ushort compression = ReadU16(buf, hs + 8);
        ushort modTime = ReadU16(buf, hs + 10);
        ushort modDate = ReadU16(buf, hs + 12);

        Le(hasher, LhSig);
        Le(hasher, version);
        Le(hasher, flags);
        Le(hasher, compression);
        Le(hasher, modTime);
        Le(hasher, modDate);
        if ((flags & DataDescriptorBit) != 0)
        {
            hasher.Update(new byte[12]);
        }
        else
        {
            Le(hasher, zf.Crc32);
            Le(hasher, zf.CompressedSize > uint.MaxValue ? uint.MaxValue : (uint)zf.CompressedSize);
            Le(hasher, zf.UncompressedSize > uint.MaxValue ? uint.MaxValue : (uint)zf.UncompressedSize);
        }

        Le(hasher, (ushort)zf.NameRaw.Length);
        Le(hasher, (ushort)zf.ExtraField.Length);
        hasher.Update(zf.NameRaw);
        hasher.Update(zf.ExtraField);
    }

    private static void AppendDataDescriptor(IncrementalHashWrapper hasher, byte[] buf, ZipCrateEntry zf, bool packageZip64)
    {
        long hs = checked((long)zf.HeaderStart);
        ushort flags = ReadU16(buf, hs + 6);
        if ((flags & DataDescriptorBit) == 0)
        {
            return;
        }

        Le(hasher, DdSig);
        Le(hasher, zf.Crc32);
        if (packageZip64)
        {
            Le(hasher, zf.CompressedSize);
            Le(hasher, zf.UncompressedSize);
        }
        else
        {
            if (zf.CompressedSize > uint.MaxValue)
            {
                throw new PsignException("ZIP64 package flag required for large data descriptor");
            }

            if (zf.UncompressedSize > uint.MaxValue)
            {
                throw new PsignException("ZIP64 package flag required");
            }

            Le(hasher, (uint)zf.CompressedSize);
            Le(hasher, (uint)zf.UncompressedSize);
        }
    }

    private static ulong PayloadAndDescriptorLen(byte[] buf, ZipCrateEntry zf, bool packageZip64)
    {
        long hs = checked((long)zf.HeaderStart);
        ushort flags = ReadU16(buf, hs + 6);
        ulong ddExtra = (flags & DataDescriptorBit) != 0 ? (packageZip64 ? 24u : 16u) : 0u;
        ulong cs = zf.CompressedSize;
        return cs > ulong.MaxValue - ddExtra ? ulong.MaxValue : cs + ddExtra;
    }

    private static (byte[] Hash, ulong CdCursor) HashZipFileData(byte[] buf, ZipCrateArchive archive, ZipTail tail, AuthenticodeHashKind kind)
    {
        bool packageZip64 = tail.Locator is not null;
        using var hasher = new IncrementalHashWrapper(kind);
        ulong cdCursor = 0;
        for (int i = 0; i < archive.Count; i++)
        {
            var zf = archive.ByIndex(i);
            if (zf.NameRaw.AsSpan().SequenceEqual("AppxSignature.p7x"u8))
            {
                continue;
            }

            if (zf.IsDir)
            {
                continue;
            }

            if (!zf.IsSupportedCompression)
            {
                throw new PsignException($"unsupported ZIP compression Unsupported({zf.CompressionMethod}) for MSIX digest (need Stored/Deflated)");
            }

            WriteLocalHeaderNormalized(hasher, buf, zf);
            cdCursor = checked(cdCursor + (ulong)(30 + zf.NameRaw.Length + zf.ExtraField.Length));

            ulong ds = archive.DataStart(zf);
            ulong cs = zf.CompressedSize;
            if (ds > (ulong)buf.Length || cs > (ulong)buf.Length - ds)
            {
                throw new PsignException("compressed payload out of range");
            }

            hasher.Update(buf.AsSpan((int)ds, (int)cs));
            AppendDataDescriptor(hasher, buf, zf, packageZip64);
            ulong inc = PayloadAndDescriptorLen(buf, zf, packageZip64);
            cdCursor = cdCursor + inc < cdCursor ? throw new PsignException("cursor overflow") : cdCursor + inc;
        }

        return (hasher.Finish(), cdCursor);
    }

    internal static byte[] HashCdAndEocd(byte[] buf, ZipCrateArchive archive, ZipTail tail, AuthenticodeHashKind kind, ulong cdOffsetVirtual)
    {
        using var hasher = new IncrementalHashWrapper(kind);
        ulong cdSize = 0;
        ushort noEntries = 0;
        Span<byte> leBuf = stackalloc byte[8];

        for (int i = 0; i < archive.Count; i++)
        {
            var zf = archive.ByIndex(i);
            if (zf.NameRaw.AsSpan().SequenceEqual("AppxSignature.p7x"u8))
            {
                continue;
            }

            if (zf.IsDir)
            {
                continue;
            }

            long c = checked((long)zf.CentralHeaderStart);
            if (ReadU32(buf, c) != CdSig)
            {
                throw new PsignException("bad central directory signature");
            }

            ushort versionMadeBy = ReadU16(buf, c + 4);
            ushort versionNeeded = ReadU16(buf, c + 6);
            ushort flags = ReadU16(buf, c + 8);
            ushort compression = ReadU16(buf, c + 10);
            ushort modTime = ReadU16(buf, c + 12);
            ushort modDate = ReadU16(buf, c + 14);
            uint crc32 = ReadU32(buf, c + 16);
            uint comp32 = ReadU32(buf, c + 20);
            uint uncomp32 = ReadU32(buf, c + 24);
            int nameLen = ReadU16(buf, c + 28);
            int extraLen = ReadU16(buf, c + 30);
            int commentLen = ReadU16(buf, c + 32);
            ushort diskStart = ReadU16(buf, c + 34);
            ushort internalAttr = ReadU16(buf, c + 36);
            uint externalAttr = ReadU32(buf, c + 38);
            uint localOff32 = ReadU32(buf, c + 42);

            long b = c + 46;
            long recordEnd = b + nameLen + extraLen + commentLen;
            if (recordEnd > buf.Length)
            {
                throw new PsignException("central directory entry out of range");
            }

            var fname = buf.AsSpan((int)b, nameLen).ToArray();
            var extra = buf.AsSpan((int)b + nameLen, extraLen).ToArray();
            var fcomment = buf.AsSpan((int)b + nameLen + extraLen, commentLen).ToArray();

            var (uncompZ64, compZ64, offZ64, diskZ64, diskU32) = ParseZip64CdExtra(extra, comp32, uncomp32, localOff32, diskStart);
            ulong uncompU64 = zf.UncompressedSize;
            ulong compU64 = zf.CompressedSize;
            ulong offU64 = zf.HeaderStart;
            uncompZ64 = uncompZ64 || uncompU64 > uint.MaxValue;
            compZ64 = compZ64 || compU64 > uint.MaxValue;
            offZ64 = offZ64 || offU64 > uint.MaxValue;

            var pay = new List<byte>();
            if (uncompZ64)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(leBuf, uncompU64);
                pay.AddRange(leBuf);
            }

            if (compZ64)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(leBuf, compU64);
                pay.AddRange(leBuf);
            }

            if (offZ64)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(leBuf, offU64);
                pay.AddRange(leBuf);
            }

            if (diskZ64)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(leBuf, diskU32);
                pay.AddRange(leBuf[..4]);
            }

            var syn = new List<byte>();
            if (pay.Count > 0)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(leBuf, Zip64ExtraId);
                syn.AddRange(leBuf[..2]);
                BinaryPrimitives.WriteUInt16LittleEndian(leBuf, (ushort)pay.Count);
                syn.AddRange(leBuf[..2]);
                syn.AddRange(pay);
            }

            if (versionMadeBy != Zip64Version || externalAttr != 0)
            {
                throw new PsignException(
                    $"MSIX/AppX central directory entry `{zf.Name}` has version made by 0x{versionMadeBy:x4} and external attributes 0x{externalAttr:x8}; Windows AppxSip only accepts the AppxPackaging layout (0x{Zip64Version:x4}, 0x00000000)");
            }

            Le(hasher, CdSig);
            Le(hasher, versionMadeBy);
            Le(hasher, versionNeeded);
            Le(hasher, flags);
            Le(hasher, compression);
            Le(hasher, modTime);
            Le(hasher, modDate);
            Le(hasher, crc32);
            Le(hasher, compZ64 ? uint.MaxValue : checked((uint)compU64));
            Le(hasher, uncompZ64 ? uint.MaxValue : checked((uint)uncompU64));
            Le(hasher, (ushort)fname.Length);
            if (syn.Count > ushort.MaxValue)
            {
                throw new PsignException("synthetic extra too large");
            }

            Le(hasher, (ushort)syn.Count);
            Le(hasher, (ushort)fcomment.Length);
            Le(hasher, diskZ64 ? ushort.MaxValue : diskStart);
            Le(hasher, internalAttr);
            Le(hasher, externalAttr);
            Le(hasher, offZ64 ? uint.MaxValue : checked((uint)offU64));
            hasher.Update(fname);
            hasher.Update(syn.ToArray());
            hasher.Update(fcomment);

            cdSize = checked(cdSize + 46UL + (ulong)fname.Length + (ulong)syn.Count + (ulong)fcomment.Length);
            if (noEntries == ushort.MaxValue)
            {
                throw new PsignException("too many entries");
            }

            noEntries++;
        }

        ulong noEntries64 = noEntries;
        var z = tail.Zip64Eocd ?? throw new PsignException(
            "MSIX/AppX package has no ZIP64 end-of-central-directory record; Windows AppxSip rejects the signature digest of such packages");
        var loc = tail.Locator ?? throw new PsignException("ZIP64 EOCD without locator");
        Le(hasher, Zip64EocdSig);
        Le(hasher, z.RecordSize);
        Le(hasher, z.VersionMadeBy);
        Le(hasher, z.VersionNeededToExtract);
        Le(hasher, z.DiskNumber);
        Le(hasher, z.DiskWithCentralDirectory);
        Le(hasher, noEntries64);
        Le(hasher, noEntries64);
        Le(hasher, cdSize);
        Le(hasher, cdOffsetVirtual);
        hasher.Update(z.TailAfterFixed);

        Le(hasher, Zip64LocSig);
        Le(hasher, loc.DiskWithCentralDirectory);
        ulong locOff = cdOffsetVirtual + cdSize;
        Le(hasher, locOff < cdOffsetVirtual ? ulong.MaxValue : locOff);
        Le(hasher, loc.NumberOfDisks);

        var cl = tail.Classic;
        Le(hasher, EocdSig);
        Le(hasher, (ushort)0);
        Le(hasher, (ushort)0);
        Le(hasher, cl.NumberOfFilesOnThisDisk != ushort.MaxValue ? noEntries : ushort.MaxValue);
        Le(hasher, cl.NumberOfFiles != ushort.MaxValue ? noEntries : ushort.MaxValue);
        if (cl.CentralDirectorySize != uint.MaxValue)
        {
            if (cdSize > uint.MaxValue)
            {
                throw new PsignException("cd_size does not fit u32");
            }

            Le(hasher, (uint)cdSize);
        }
        else
        {
            Le(hasher, uint.MaxValue);
        }

        if (cl.CentralDirectoryOffset != uint.MaxValue)
        {
            if (cdOffsetVirtual > uint.MaxValue)
            {
                throw new PsignException("cd_offset does not fit u32");
            }

            Le(hasher, (uint)cdOffsetVirtual);
        }
        else
        {
            Le(hasher, uint.MaxValue);
        }

        Le(hasher, (ushort)cl.ZipFileComment.Length);
        hasher.Update(cl.ZipFileComment);
        return hasher.Finish();
    }

    private static byte[] ReadZipEntryRaw(ZipCrateArchive archive, string name) => archive.Read(name);

    // ================================================================== inventory / layout validation

    private static string? CanonicalReservedPart(string normalized)
    {
        foreach (var reserved in new[] { ContentTypes, BlockMap, AppSignature, AppManifest, BundleManifest, CodeIntegrity })
        {
            if (AsciiEqualsIgnoreCase(normalized, reserved))
            {
                return reserved;
            }
        }

        return null;
    }

    internal static AppxPackageInventory ValidatePackagePartInventory(ZipCrateArchive archive, string ext)
    {
        bool isBundle = ext is "msixbundle" or "appxbundle";
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var seenFolded = new Dictionary<string, string>(StringComparer.Ordinal);
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var entry in archive.Entries)
        {
            var name = entry.Name;
            if (name.EndsWith('/') || name.EndsWith('\\'))
            {
                continue;
            }

            if (name.Contains('\\'))
            {
                throw new PsignException($"APPX/MSIX ZIP entry `{name}` uses backslashes; package part names must use `/`");
            }

            var decoded = DecodeOpcZipPartName(name);
            var normalized = NormalizeAppxPartName(decoded);
            if (!seen.Add(normalized))
            {
                throw new PsignException($"duplicate APPX/MSIX ZIP part `{normalized}`");
            }

            var folded = AsciiLower(normalized);
            if (seenFolded.TryGetValue(folded, out var previous))
            {
                throw new PsignException($"duplicate APPX/MSIX ZIP part after case-insensitive normalization: `{previous}` / `{normalized}`");
            }

            seenFolded[folded] = normalized;
            if (CanonicalReservedPart(normalized) is { } canonical)
            {
                if (normalized != canonical)
                {
                    throw new PsignException($"reserved APPX/MSIX part `{normalized}` must use canonical path `{canonical}`");
                }

                counts[canonical] = counts.GetValueOrDefault(canonical) + 1;
            }

            if (isBundle)
            {
                int dot = normalized.LastIndexOf('.');
                if (dot >= 0 && IsEncryptedMsixExtension(AsciiLower(normalized[(dot + 1)..])))
                {
                    throw new PsignException($"cleartext APPX/MSIX bundle contains encrypted child package `{normalized}`");
                }
            }
        }

        foreach (var required in new[] { ContentTypes, BlockMap, AppSignature })
        {
            if (counts.GetValueOrDefault(required) != 1)
            {
                throw new PsignException($"APPX/MSIX package must contain exactly one required part `{required}`");
            }
        }

        if (isBundle)
        {
            if (counts.GetValueOrDefault(BundleManifest) != 1)
            {
                throw new PsignException($"APPX/MSIX bundle must contain exactly one required part `{BundleManifest}`");
            }

            if (counts.GetValueOrDefault(AppManifest) != 0)
            {
                throw new PsignException($"APPX/MSIX bundle must not contain top-level `{AppManifest}`");
            }
        }
        else
        {
            if (counts.GetValueOrDefault(AppManifest) != 1)
            {
                throw new PsignException($"APPX/MSIX package must contain exactly one required part `{AppManifest}`");
            }

            if (counts.GetValueOrDefault(BundleManifest) != 0)
            {
                throw new PsignException($"flat APPX/MSIX package must not contain bundle part `{BundleManifest}`");
            }
        }

        int ci = counts.GetValueOrDefault(CodeIntegrity);
        if (ci > 1)
        {
            throw new PsignException($"APPX/MSIX package must contain at most one `{CodeIntegrity}`");
        }

        return new AppxPackageInventory(ci == 1);
    }

    internal static byte[] HashBytes(AuthenticodeHashKind kind, ReadOnlySpan<byte> bytes) => kind.Hash(bytes);

    /// <summary>
    /// Validate a ZIP data descriptor using <c>AppxSip.dll</c>'s rule: <paramref name="isZip64"/>
    /// (<c>version_needed_to_extract &gt;= 45</c>) selects 8-byte sizes. Returns the descriptor length.
    /// </summary>
    internal static ulong DataDescriptorLenAndValidate(byte[] buf, long off, bool isZip64, ZipCrateEntry zf)
    {
        bool hasSig = off >= 0 && off + 4 <= buf.Length && BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan((int)off)) == DdSig;
        long cursor = off + (hasSig ? 4 : 0);
        uint crc = ReadU32(buf, cursor);
        if (crc != zf.Crc32)
        {
            throw new PsignException("ZIP data descriptor CRC does not match central directory");
        }

        ulong compressed;
        ulong uncompressed;
        if (isZip64)
        {
            compressed = ReadU64(buf, cursor + 4);
            uncompressed = ReadU64(buf, cursor + 12);
        }
        else
        {
            compressed = ReadU32(buf, cursor + 4);
            uncompressed = ReadU32(buf, cursor + 8);
        }

        if (compressed != zf.CompressedSize || uncompressed != zf.UncompressedSize)
        {
            throw new PsignException($"ZIP data descriptor sizes do not match central directory (compressed={compressed}, uncompressed={uncompressed})");
        }

        return isZip64 ? (hasSig ? 24UL : 20UL) : (hasSig ? 16UL : 12UL);
    }

    private static (ulong Start, ulong End) LocalFileRecordExtent(byte[] buf, ZipCrateArchive archive, ZipCrateEntry zf)
    {
        ulong headerStart = zf.HeaderStart;
        long hs = checked((long)headerStart);
        if (ReadU32(buf, hs) != LhSig)
        {
            throw new PsignException("bad local file header signature");
        }

        ushort versionNeeded = ReadU16(buf, hs + 4);
        ushort flags = ReadU16(buf, hs + 6);
        if ((flags & 0x2041) != 0)
        {
            throw new PsignException("encrypted ZIP local file records are not valid cleartext APPX/MSIX packages");
        }

        ushort compression = ReadU16(buf, hs + 8);
        if (compression is not (0 or 8))
        {
            throw new PsignException($"unsupported ZIP compression method {compression} in APPX/MSIX local file record");
        }

        if (!zf.IsSupportedCompression)
        {
            throw new PsignException($"unsupported ZIP compression method Unsupported({zf.CompressionMethod}) in APPX/MSIX central directory");
        }

        ulong nameLen = ReadU16(buf, hs + 26);
        ulong extraLen = ReadU16(buf, hs + 28);
        long nameStart = hs + 30;
        long nameEnd = nameStart + (long)nameLen;
        if (nameEnd > buf.Length)
        {
            throw new PsignException("local file name out of range");
        }

        if (!buf.AsSpan((int)nameStart, (int)nameLen).SequenceEqual(zf.NameRaw))
        {
            throw new PsignException($"ZIP local file name does not match central directory for `{zf.Name}`");
        }

        ulong expectedDataStart = headerStart + 30 + nameLen + extraLen;
        ulong dataStart = archive.DataStart(zf);
        if (dataStart != expectedDataStart)
        {
            throw new PsignException($"local file header/data offset mismatch for `{zf.Name}`");
        }

        ulong compressedEnd = dataStart + zf.CompressedSize;
        if (compressedEnd < dataStart)
        {
            throw new PsignException("compressed payload extent overflow");
        }

        if ((flags & DataDescriptorBit) == 0)
        {
            uint crc = ReadU32(buf, hs + 14);
            ulong compressedSize = ReadU32(buf, hs + 18);
            ulong uncompressedSize = ReadU32(buf, hs + 22);
            if (crc != zf.Crc32)
            {
                throw new PsignException($"ZIP local file CRC does not match central directory for `{zf.Name}`");
            }

            if (compressedSize != uint.MaxValue && compressedSize != zf.CompressedSize)
            {
                throw new PsignException($"ZIP local compressed size does not match central directory for `{zf.Name}`");
            }

            if (uncompressedSize != uint.MaxValue && uncompressedSize != zf.UncompressedSize)
            {
                throw new PsignException($"ZIP local uncompressed size does not match central directory for `{zf.Name}`");
            }
        }

        ulong descriptorLen = 0;
        if ((flags & DataDescriptorBit) != 0)
        {
            if (compressedEnd > long.MaxValue)
            {
                throw new PsignException("compressed end");
            }

            descriptorLen = DataDescriptorLenAndValidate(buf, (long)compressedEnd, versionNeeded >= Zip64Version, zf);
        }

        ulong end = compressedEnd + descriptorLen;
        if (end < compressedEnd)
        {
            throw new PsignException("local file record extent overflow");
        }

        return (headerStart, end);
    }

    internal static void ValidateCentralDirectoryRecords(byte[] buf, ZipTail tail)
    {
        ulong count = tail.Zip64Eocd?.NumberOfFiles ?? tail.Classic.NumberOfFiles;
        if (count > 0xA00000)
        {
            throw new PsignException("APPX/MSIX ZIP has too many central directory entries");
        }

        long cursor = checked((long)tail.CentralDirectoryOffset);
        long cdEnd = checked((long)(tail.CentralDirectoryOffset + tail.CentralDirectorySize));
        ulong seen = 0;
        while (cursor < cdEnd)
        {
            if (ReadU32(buf, cursor) != CdSig)
            {
                throw new PsignException("bad central directory signature");
            }

            ushort flags = ReadU16(buf, cursor + 8);
            if ((flags & 0x2041) != 0)
            {
                throw new PsignException("encrypted ZIP central directory records are not valid cleartext APPX/MSIX packages");
            }

            ushort compression = ReadU16(buf, cursor + 10);
            if (compression is not (0 or 8))
            {
                throw new PsignException($"unsupported ZIP compression method {compression} in APPX/MSIX central directory");
            }

            int nameLen = ReadU16(buf, cursor + 28);
            int extraLen = ReadU16(buf, cursor + 30);
            int commentLen = ReadU16(buf, cursor + 32);
            ushort diskStart = ReadU16(buf, cursor + 34);
            if (diskStart != 0)
            {
                throw new PsignException("central directory entry starts on a non-zero disk");
            }

            if (commentLen != 0)
            {
                throw new PsignException("central directory file comments are not valid in APPX/MSIX packages");
            }

            cursor += 46 + nameLen + extraLen + commentLen;
            if (cursor > cdEnd)
            {
                throw new PsignException("central directory record extends past directory");
            }

            seen++;
        }

        if (seen != count)
        {
            throw new PsignException($"central directory entry count {seen} does not match EOCD count {count}");
        }
    }

    internal static void ValidateZipFileLayout(byte[] buf, ZipCrateArchive archive, ZipTail tail)
    {
        ValidateCentralDirectoryRecords(buf, tail);
        var extents = new List<(ulong Start, ulong End, string Name)>();
        for (int i = 0; i < archive.Count; i++)
        {
            var zf = archive.ByIndex(i);
            var (start, end) = LocalFileRecordExtent(buf, archive, zf);
            extents.Add((start, end, zf.Name));
        }

        // Stable sort by start (Rust sort_by_key is stable).
        extents = extents.Select((e, idx) => (e, idx)).OrderBy(t => t.e.Start).ThenBy(t => t.idx).Select(t => t.e).ToList();
        if (extents.Count == 0)
        {
            throw new PsignException("APPX/MSIX ZIP has no local file records");
        }

        if (extents[0].Start != 0)
        {
            throw new PsignException($"APPX/MSIX ZIP has leading bytes before first local file `{extents[0].Name}`");
        }

        for (int i = 0; i + 1 < extents.Count; i++)
        {
            var prev = extents[i];
            var next = extents[i + 1];
            if (next.Start < prev.End)
            {
                throw new PsignException($"APPX/MSIX ZIP local file records overlap (`{prev.Name}` / `{next.Name}`)");
            }

            if (next.Start > prev.End)
            {
                throw new PsignException($"APPX/MSIX ZIP has a gap between local file records `{prev.Name}` and `{next.Name}`");
            }
        }

        var last = extents[^1];
        if (last.End != tail.CentralDirectoryOffset)
        {
            throw new PsignException($"APPX/MSIX ZIP has a gap before the central directory after `{last.Name}`");
        }

        ulong cdEnd = tail.CentralDirectoryOffset + tail.CentralDirectorySize;
        ulong expected = tail.Zip64EocdOffset ?? (ulong)tail.EocdOffset;
        if (cdEnd != expected)
        {
            throw new PsignException("APPX/MSIX ZIP central directory does not end at EOCD/ZIP64 EOCD");
        }
    }

    private static Dictionary<string, int> ArchiveFileIndexByNormalizedName(ZipCrateArchive archive)
    {
        var files = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < archive.Count; i++)
        {
            var zf = archive.ByIndex(i);
            if (zf.IsDir)
            {
                continue;
            }

            var normalized = NormalizeAppxPartName(DecodeOpcZipPartName(zf.Name));
            if (files.ContainsKey(normalized))
            {
                throw new PsignException($"duplicate ZIP entry after APPX path normalization: `{normalized}`");
            }

            files[normalized] = i;
        }

        return files;
    }

    internal static void ValidateBlockMapFileHashes(byte[] buf, AuthenticodeHashKind kind, IReadOnlyList<AppxBlockMapFile> blockMapFiles)
    {
        var archive = ZipCrateArchive.Open(buf);
        var fileIndex = ArchiveFileIndexByNormalizedName(archive);

        foreach (var bf in blockMapFiles)
        {
            if (bf.NormalizedName is "AppxBlockMap.xml" or "[Content_Types].xml" or "AppxSignature.p7x")
            {
                throw new PsignException($"AppxBlockMap.xml must not list metadata part `{bf.Name}` as payload");
            }

            if (!fileIndex.TryGetValue(bf.NormalizedName, out int index))
            {
                throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` is missing from package ZIP");
            }

            var zf = archive.ByIndex(index);
            if (bf.LfhSize is { } lfh)
            {
                ulong ds = archive.DataStart(zf);
                if (ds < zf.HeaderStart)
                {
                    throw new PsignException("local file header size underflow");
                }

                ulong actual = ds - zf.HeaderStart;
                if (lfh != actual)
                {
                    throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` LfhSize {lfh} does not match ZIP local header size {actual}");
                }
            }

            var data = archive.Read(index);
            ulong dataLen = (ulong)data.Length;
            if (dataLen != bf.DeclaredSize)
            {
                throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` Size {bf.DeclaredSize} does not match uncompressed size {dataLen}");
            }

            if (data.Length == 0)
            {
                if (bf.Blocks.Count != 0)
                {
                    throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` is empty but has block hashes");
                }

                continue;
            }

            if (bf.Blocks.Count == 0)
            {
                throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` has content but no block hashes");
            }

            int offset = 0;
            for (int bi = 0; bi < bf.Blocks.Count; bi++)
            {
                var block = bf.Blocks[bi];
                if (offset >= data.Length)
                {
                    throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` has too many block hashes");
                }

                int end = Math.Min(offset + AppxBlockSize, data.Length);
                var actual = HashBytes(kind, data.AsSpan(offset, end - offset));
                if (!actual.AsSpan().SequenceEqual(block.Hash))
                {
                    throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` block {bi} hash mismatch");
                }

                if (block.CompressedSize == 0)
                {
                    throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` block {bi} has zero Size");
                }

                offset = end;
            }

            if (offset != data.Length)
            {
                throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` has too few block hashes");
            }

            if (bf.FileHash is { } fh && !HashBytes(kind, data).AsSpan().SequenceEqual(fh))
            {
                throw new PsignException($"AppxBlockMap.xml File `{bf.Name}` FileHash mismatch");
            }
        }
    }

    private static string? CleartextMsixExtensionForName(string name)
    {
        int slash = name.LastIndexOf('/');
        var lower = AsciiLower(slash >= 0 ? name[(slash + 1)..] : name);
        if (lower.EndsWith(".msix", StringComparison.Ordinal))
        {
            return "msix";
        }

        if (lower.EndsWith(".appx", StringComparison.Ordinal))
        {
            return "appx";
        }

        if (lower.EndsWith(".msixbundle", StringComparison.Ordinal))
        {
            return "msixbundle";
        }

        if (lower.EndsWith(".appxbundle", StringComparison.Ordinal))
        {
            return "appxbundle";
        }

        return null;
    }

    internal static void VerifyBundleChildPackages(byte[] buf)
    {
        var archive = ZipCrateArchive.Open(buf);
        var children = new List<(string Name, string Ext, byte[] Data)>();
        for (int i = 0; i < archive.Count; i++)
        {
            var zf = archive.ByIndex(i);
            if (zf.IsDir)
            {
                continue;
            }

            var normalized = NormalizeAppxPartName(DecodeOpcZipPartName(zf.Name));
            if (CleartextMsixExtensionForName(normalized) is not { } ext)
            {
                continue;
            }

            children.Add((normalized, ext, archive.Read(i)));
        }

        foreach (var (name, ext, child) in children)
        {
            try
            {
                VerifyMsixDigestConsistencyBytes(child, ext);
            }
            catch (PsignException e)
            {
                throw new PsignException($"bundle child package `{name}` failed MSIX SIP validation: {e.Message}");
            }
        }
    }

    // ================================================================== public entry points

    /// <summary>Encrypted package extensions (<c>.eappx</c>, <c>.eappxbundle</c>, <c>.emsix</c>, <c>.emsixbundle</c>); <paramref name="ext"/> is lowercase without dot.</summary>
    public static bool IsEncryptedMsixExtension(string ext) => ext is "eappx" or "eappxbundle" or "emsix" or "emsixbundle";

    private static string PathExtensionLower(string path)
    {
        var ext = System.IO.Path.GetExtension(path);
        return AsciiLower(string.IsNullOrEmpty(ext) ? string.Empty : ext[1..]);
    }

    /// <summary>Compare the PKCS#7 APPX indirect blob with recomputed ZIP hashes (Rust <c>verify_msix_digest_consistency</c>).</summary>
    public static void VerifyMsixDigestConsistency(string path)
    {
        var ext = PathExtensionLower(path);
        if (IsEncryptedMsixExtension(ext))
        {
            throw new PsignException(
                "Rust MSIX SIP digest parity applies only to cleartext OPC/ZIP packages (.msix, .appx, bundles); "
                + "encrypted packages (.eappx, .emsix, …) use AppxSip `EappxSip*` / Windows crypto — rely on WinVerifyTrust");
        }

        if (ext is not ("msix" or "appx" or "msixbundle" or "appxbundle"))
        {
            throw new PsignException("Rust MSIX SIP digest check applies only to `.msix` / `.appx` / `.msixbundle` / `.appxbundle` files");
        }

        VerifyMsixDigestConsistencyBytes(File.ReadAllBytes(path), ext);
    }

    /// <summary>
    /// Verify the APPX digest binding of a cleartext package and return its PKCS#7 (without <c>PKCX</c>) and the
    /// verified APPX <c>messageDigest</c> blob (Rust <c>msix_verified_signature</c>).
    /// </summary>
    public static (byte[] Pkcs7, byte[] Digest) MsixVerifiedSignature(byte[] buf, string ext)
    {
        ext = AsciiLower(ext);
        if (ext is not ("msix" or "appx" or "msixbundle" or "appxbundle"))
        {
            throw new PsignException("Rust MSIX SIP digest check applies only to cleartext `.msix` / `.appx` / `.msixbundle` / `.appxbundle` files");
        }

        return VerifyMsixDigestConsistencyBytes(buf, ext);
    }

    /// <summary>
    /// Rewrite a ZIP archive into the layout AppxPackaging writes: central directory "version made by" 45 and zero
    /// external attributes, plus ZIP64 EOCD / locator and an all-sentinel classic EOCD. Local headers and data keep
    /// their offsets (Rust <c>normalize_zip_for_appx_signing</c>).
    /// </summary>
    public static byte[] NormalizeZipForAppxSigning(byte[] zip)
    {
        var tail = ParseZipTail(zip);
        ulong cdOffset = tail.CentralDirectoryOffset;
        ulong cdSize = tail.CentralDirectorySize;
        long cdStart = checked((long)cdOffset);
        long cdEnd = checked((long)(cdOffset + cdSize));

        var output = (byte[])zip.Clone();
        ulong entries = 0;
        long p = cdStart;
        while (p < cdEnd)
        {
            if (ReadU32(output, p) != CdSig || p + 46 > output.Length)
            {
                throw new PsignException("bad central directory entry");
            }

            int nameLen = ReadU16(output, p + 28);
            int extraLen = ReadU16(output, p + 30);
            int commentLen = ReadU16(output, p + 32);
            BinaryPrimitives.WriteUInt16LittleEndian(output.AsSpan((int)p + 4), Zip64Version);
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan((int)p + 38), 0);
            p += 46 + nameLen + extraLen + commentLen;
            entries++;
        }

        if (p != cdEnd)
        {
            throw new PsignException("central directory entries overrun the declared size");
        }

        if (tail.Zip64Eocd is not null)
        {
            return output;
        }

        ulong zip64EocdOffset = (ulong)tail.EocdOffset;
        var comment = tail.Classic.ZipFileComment;
        using var ms = new MemoryStream();
        ms.Write(output, 0, tail.EocdOffset);
        var w = new BinaryWriter(ms);
        w.Write(Zip64EocdSig);
        w.Write(Zip64EocdRecordSize);
        w.Write(Zip64Version);
        w.Write(Zip64Version);
        w.Write(0u);
        w.Write(0u);
        w.Write(entries);
        w.Write(entries);
        w.Write(cdSize);
        w.Write(cdOffset);

        w.Write(Zip64LocSig);
        w.Write(0u);
        w.Write(zip64EocdOffset);
        w.Write(1u);

        w.Write(EocdSig);
        for (int i = 0; i < 4; i++)
        {
            w.Write(ushort.MaxValue);
        }

        w.Write(uint.MaxValue);
        w.Write(uint.MaxValue);
        if (comment.Length > ushort.MaxValue)
        {
            throw new PsignException("ZIP comment is too long");
        }

        w.Write((ushort)comment.Length);
        w.Write(comment);
        w.Flush();
        return ms.ToArray();
    }

    /// <summary>makeappx-style <c>Default</c> content type for a payload extension without one.</summary>
    internal static string DefaultContentTypeForExtension(string extension) => extension switch
    {
        "xml" => ContentTypeManifest,
        "png" => "image/png",
        "jpg" or "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "ico" => "image/vnd.microsoft.icon",
        "svg" => "image/svg+xml",
        "exe" or "dll" or "sys" => "application/x-msdownload",
        "json" => "application/json",
        "txt" => "text/plain",
        "htm" or "html" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "cat" => "application/vnd.ms-pkiseccat",
        "appx" => "application/vnd.ms-appx",
        "msix" => "application/msix",
        "appxbundle" => "application/vnd.ms-appx.bundle",
        "msixbundle" => "application/msixbundle",
        _ => "application/octet-stream",
    };

    /// <summary>Build the <c>[Content_Types].xml</c> for a package staged for signing (Rust <c>appx_content_types_for_signing</c>).</summary>
    public static string AppxContentTypesForSigning(byte[]? existing, IReadOnlyList<string> payloadParts, bool bundle) =>
        BuildAppxContentTypesXml(existing, payloadParts, bundle ? AppxPackageLayout.Bundle : AppxPackageLayout.Flat, true);

    /// <summary>Build <c>[Content_Types].xml</c> for an unsigned package without an <c>AppxSignature.p7x</c> override.</summary>
    public static string AppxContentTypesForUnsignedPackage(byte[]? existing, IReadOnlyList<string> payloadParts, AppxPackageLayout layout) =>
        BuildAppxContentTypesXml(existing, payloadParts, layout, false);

    /// <summary>Inspect <c>AppxBlockMap.xml</c> inside <paramref name="package"/> and return its declared hash kind, if present.</summary>
    public static AuthenticodeHashKind? DetectBlockMapHashKind(byte[] package)
    {
        var archive = ZipCrateArchive.Open(package);
        if (!archive.TryOpenByName(BlockMap, out _))
        {
            return null;
        }

        var (kind, _) = ParseBlockMapXml(ReadZipEntryRaw(archive, BlockMap));
        return kind;
    }

    private static string BuildAppxContentTypesXml(byte[]? existing, IReadOnlyList<string> payloadParts, AppxPackageLayout layout, bool includeSignatureOverride)
    {
        var input = existing is null ? new AppxContentTypes() : ValidateContentTypesXml(existing);
        var defaults = new SortedDictionary<string, string>(input.Defaults, StringComparer.Ordinal);
        var overrides = new List<(string Part, string ContentType)>();
        var (manifestPart, manifestType) = layout == AppxPackageLayout.Bundle
            ? (BundleManifest, ContentTypeBundleManifest)
            : (AppManifest, ContentTypeManifest);

        foreach (var part in payloadParts)
        {
            var normalized = NormalizeAppxPartName(DecodeOpcZipPartName(part));
            int slash = normalized.LastIndexOf('/');
            var leaf = slash >= 0 ? normalized[(slash + 1)..] : normalized;
            int dot = leaf.LastIndexOf('.');
            var extension = dot >= 0 ? AsciiLower(leaf[(dot + 1)..]) : string.Empty;
            input.Overrides.TryGetValue(AsciiLower(normalized), out var explicitType);
            if (AsciiEqualsIgnoreCase(normalized, manifestPart))
            {
                if (explicitType is null && extension.Length != 0 && !defaults.ContainsKey(extension))
                {
                    defaults[extension] = manifestType;
                }

                string? resolved = explicitType ?? (defaults.TryGetValue(extension, out var d) ? d : null);
                if (explicitType is not null || resolved is null || !AsciiEqualsIgnoreCase(resolved, manifestType))
                {
                    overrides.Add((normalized, manifestType));
                }
            }
            else if (explicitType is not null)
            {
                overrides.Add((normalized, explicitType));
            }
            else if (extension.Length == 0)
            {
                overrides.Add((normalized, "application/octet-stream"));
            }
            else
            {
                var contentType = DefaultContentTypeForExtension(extension);
                defaults.TryAdd(extension, contentType);
            }
        }

        overrides.Add((BlockMap, ContentTypeBlockMap));
        if (includeSignatureOverride)
        {
            overrides.Add((AppSignature, ContentTypeSignature));
        }

        static string Esc(string v) => v.Replace("&", "&amp;").Replace("\"", "&quot;").Replace("<", "&lt;").Replace(">", "&gt;");

        var xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");
        foreach (var (extension, contentType) in defaults)
        {
            xml.Append("<Default Extension=\"").Append(Esc(extension)).Append("\" ContentType=\"").Append(Esc(contentType)).Append("\"/>");
        }

        foreach (var (part, contentType) in overrides)
        {
            xml.Append("<Override PartName=\"/").Append(Esc(EncodeOpcPartName(part))).Append("\" ContentType=\"").Append(Esc(contentType)).Append("\"/>");
        }

        xml.Append("</Types>");
        return xml.ToString();
    }

    /// <summary>
    /// Read <c>AppxSignature.p7x</c> and return the inner PKCS#7 DER without verifying digests (port of the portable
    /// signer's <c>msix_signature_pkcs7_der</c>).
    /// </summary>
    public static byte[] MsixSignaturePkcs7Der(byte[] package)
    {
        ZipCrateArchive archive;
        try
        {
            archive = ZipCrateArchive.Open(package);
        }
        catch (PsignException e)
        {
            throw new PsignException("open MSIX ZIP", e);
        }

        byte[] p7x;
        try
        {
            p7x = archive.Read(AppSignature);
        }
        catch (PsignException e)
        {
            throw new PsignException("read AppxSignature.p7x", e);
        }

        return TryStripPkcxWrapper(p7x) ?? throw new PsignException("AppxSignature.p7x missing PKCX prefix");
    }

    /// <summary>Fast <c>--skip-signed</c> preflight: does this package carry an <c>AppxSignature.p7x</c> part?</summary>
    public static bool MsixSignaturePartPresent(byte[] package)
    {
        var archive = ZipCrateArchive.Open(package);
        return archive.FileNames.Any(n => n == AppSignature);
    }

    /// <summary>
    /// Compute the APPX Authenticode <c>messageDigest</c> blob for a cleartext package that already contains
    /// <c>AppxSignature.p7x</c> and its content-type declaration (Rust <c>msix_authenticode_digest_blob</c>).
    /// </summary>
    public static (AuthenticodeHashKind Kind, byte[] Blob) MsixAuthenticodeDigestBlob(byte[] buf, string ext)
    {
        ext = AsciiLower(ext);
        if (IsEncryptedMsixExtension(ext))
        {
            throw new PsignException("Rust MSIX SIP digest parity applies only to cleartext OPC/ZIP packages (.msix, .appx, bundles)");
        }

        if (ext is not ("msix" or "appx" or "msixbundle" or "appxbundle"))
        {
            throw new PsignException("Rust MSIX SIP digest applies only to `.msix` / `.appx` / `.msixbundle` / `.appxbundle` files");
        }

        var tail = ParseZipTail(buf);
        ValidateZipFileLayout(buf, ZipCrateArchive.Open(buf), tail);
        var archive = ZipCrateArchive.Open(buf);
        var inventory = ValidatePackagePartInventory(archive, ext);

        var blockMapBytes = ReadZipEntryRaw(archive, BlockMap);
        var (kind, blockMapFiles) = ParseBlockMapXml(blockMapBytes);
        var ctRaw = ReadZipEntryRaw(archive, ContentTypes);
        var contentTypes = ValidateContentTypesXml(ctRaw);
        ValidateReservedContentTypes(contentTypes, inventory, ext);

        var ciRaw = inventory.HasCodeIntegrity ? ReadZipEntryRaw(archive, CodeIntegrity) : null;
        var ctHash = HashBytes(kind, ctRaw);
        var bmHash = HashBytes(kind, blockMapBytes);
        var ciHash = ciRaw is null ? null : HashBytes(kind, ciRaw);

        var (dataHash, cdOffVirt) = HashZipFileData(buf, ZipCrateArchive.Open(buf), tail, kind);
        var cdHash = HashCdAndEocd(buf, ZipCrateArchive.Open(buf), tail, kind, cdOffVirt);

        ValidateBlockMapFileHashes(buf, kind, blockMapFiles);
        if (ext is "msixbundle" or "appxbundle")
        {
            VerifyBundleChildPackages(buf);
        }

        using var blob = new MemoryStream();
        blob.Write(SigAppx);
        foreach (var (tag, digest) in new[] { (TagAxpc, dataHash), (TagAxcd, cdHash), (TagAxct, ctHash), (TagAxbm, bmHash) })
        {
            blob.Write(tag);
            blob.Write(digest);
        }

        if (ciHash is not null)
        {
            blob.Write(TagAxci);
            blob.Write(ciHash);
        }

        return (kind, blob.ToArray());
    }

    internal static (byte[] Pkcs7, byte[] Digest) VerifyMsixDigestConsistencyBytes(byte[] buf, string ext)
    {
        var tail = ParseZipTail(buf);
        ValidateZipFileLayout(buf, ZipCrateArchive.Open(buf), tail);
        var archive = ZipCrateArchive.Open(buf);
        var inventory = ValidatePackagePartInventory(archive, ext);

        var p7x = ReadZipEntryRaw(archive, AppSignature);
        var pkcs7 = StripPkcx(p7x);
        AuthenticodeSignature sig;
        try
        {
            sig = AuthenticodeSignature.Parse(pkcs7);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException or ArgumentException or IndexOutOfRangeException or InvalidOperationException)
        {
            throw new PsignException($"MSIX PKCS#7 parse failed: {e.Message}");
        }

        var embedded = sig.Digest;
        var (pieceLen, parts) = ParseSignedAppxBlob(embedded);

        var blockMapBytes = ReadZipEntryRaw(archive, BlockMap);
        var (kind, blockMapFiles) = ParseBlockMapXml(blockMapBytes);
        var ctRaw = ReadZipEntryRaw(archive, ContentTypes);
        var contentTypes = ValidateContentTypesXml(ctRaw);
        ValidateReservedContentTypes(contentTypes, inventory, ext);
        int expectedPiece = kind.DigestLength();
        if (pieceLen != expectedPiece)
        {
            throw new PsignException($"PKCS#7 APPX digest width {pieceLen} does not match AppxBlockMap HashMethod ({expectedPiece})");
        }

        if (sig.IndirectData.HashKind is { } sigHashKind && sigHashKind != kind)
        {
            throw new PsignException(
                $"PKCS#7 Authenticode DigestInfo algorithm ({sigHashKind.Name()}) does not match AppxBlockMap HashMethod ({kind.Name()})");
        }

        var bmRaw = ReadZipEntryRaw(archive, BlockMap);
        var ciRaw = inventory.HasCodeIntegrity ? ReadZipEntryRaw(archive, CodeIntegrity) : null;
        if (inventory.HasCodeIntegrity != (parts.Axci is not null))
        {
            throw new PsignException("CodeIntegrity.cat presence does not match PKCS#7 AXCI block");
        }

        var ctHash = HashBytes(kind, ctRaw);
        var bmHash = HashBytes(kind, bmRaw);
        var ciHash = ciRaw is null ? null : HashBytes(kind, ciRaw);

        var (dataHash, cdOffVirt) = HashZipFileData(buf, ZipCrateArchive.Open(buf), tail, kind);
        var cdHash = HashCdAndEocd(buf, ZipCrateArchive.Open(buf), tail, kind, cdOffVirt);

        static void Check(string label, byte[] a, byte[] b)
        {
            if (!a.AsSpan().SequenceEqual(b))
            {
                throw new PsignException($"MSIX Authenticode {label} mismatch (Rust SIP vs PKCS#7 APPX blob)");
            }
        }

        bool axpcSentinel = parts.Axpc.AsSpan().SequenceEqual(SkipPackageContentHashSentinel[..Math.Min(expectedPiece, 64)]);
        if (!axpcSentinel)
        {
            Check("AXPC (payload)", dataHash, parts.Axpc);
        }

        Check("AXCD (central directory)", cdHash, parts.Axcd);
        Check("AXCT ([Content_Types].xml)", ctHash, parts.Axct);
        Check("AXBM (AppxBlockMap.xml)", bmHash, parts.Axbm);
        if (ciHash is not null && parts.Axci is not null)
        {
            Check("AXCI (CodeIntegrity.cat)", ciHash, parts.Axci);
        }
        else if (ciHash is not null || parts.Axci is not null)
        {
            throw new PsignException("MSIX Authenticode AXCI presence mismatch (CodeIntegrity.cat vs PKCS#7 APPX blob)");
        }

        ValidateBlockMapFileHashes(buf, kind, blockMapFiles);
        if (ext is "msixbundle" or "appxbundle")
        {
            VerifyBundleChildPackages(buf);
        }

        return (pkcs7, embedded.ToArray());
    }
}
