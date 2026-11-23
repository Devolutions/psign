using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Core.Opc;

/// <summary>ZIP entry metadata (Rust <c>opc::PackageEntry</c>).</summary>
public sealed record PackageEntry(string Name, ulong CompressedSize, ulong UncompressedSize, bool IsDir, string Compression);

/// <summary>OPC package summary (Rust <c>opc::PackageSummary</c>).</summary>
public sealed class PackageSummary
{
    public PackageSummary(
        IReadOnlyList<PackageEntry> entries,
        bool hasContentTypes,
        bool hasRootRelationships,
        bool hasOpcSignatureOrigin,
        IReadOnlyList<string> opcSignatureParts)
    {
        Entries = entries;
        HasContentTypes = hasContentTypes;
        HasRootRelationships = hasRootRelationships;
        HasOpcSignatureOrigin = hasOpcSignatureOrigin;
        OpcSignatureParts = opcSignatureParts;
    }

    public IReadOnlyList<PackageEntry> Entries { get; }

    public bool HasContentTypes { get; }

    public bool HasRootRelationships { get; }

    public bool HasOpcSignatureOrigin { get; }

    /// <summary>Signature parts under <see cref="OpcPackage.OpcSignaturesPrefix"/>, sorted ordinally.</summary>
    public IReadOnlyList<string> OpcSignatureParts { get; }

    public bool ContainsEntry(string name) => Entries.Any(e => e.Name == name);

    /// <summary>First entry named <paramref name="name"/> (Rust <c>entry</c>).</summary>
    public PackageEntry? Entry(string name) => Entries.FirstOrDefault(e => e.Name == name);
}

/// <summary>
/// Portable OPC package primitives shared by VSIX and NuGet signing (port of Rust <c>psign-opc-sign/src/opc.rs</c>).
/// </summary>
public static class OpcPackage
{
    public const string ContentTypesPart = "[Content_Types].xml";
    public const string RootRelationshipsPart = "_rels/.rels";
    public const string OpcSignatureOriginPart = "package/services/digital-signature/origin.psdsor";
    public const string OpcSignaturesPrefix = "package/services/digital-signature/xml-signature/";

    /// <summary>Inspect a package on disk (Rust <c>inspect_package_path</c>).</summary>
    public static PackageSummary InspectPackagePath(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"open {path}", e);
        }

        try
        {
            return InspectPackage(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"inspect OPC ZIP {path}", e);
        }
    }

    /// <summary>Inspect package bytes (Rust <c>inspect_package_reader</c>).</summary>
    public static PackageSummary InspectPackage(byte[] bytes)
    {
        ZipCrateArchive archive;
        try
        {
            archive = ZipCrateArchive.Open(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException("open ZIP archive", e);
        }

        return InspectPackage(archive);
    }

    /// <summary>Inspect an opened archive.</summary>
    public static PackageSummary InspectPackage(ZipCrateArchive archive)
    {
        var entries = new List<PackageEntry>(archive.Count);
        bool hasContentTypes = false;
        bool hasRootRelationships = false;
        bool hasOrigin = false;
        var signatureParts = new List<string>();

        foreach (var file in archive.Entries)
        {
            try
            {
                archive.EnsureReadable(file);
            }
            catch (PsignException e)
            {
                throw new PsignException("read ZIP central directory entry", e);
            }

            string name = NormalizeZipPartName(file.Name);
            hasContentTypes |= name == ContentTypesPart;
            hasRootRelationships |= name == RootRelationshipsPart;
            hasOrigin |= name == OpcSignatureOriginPart;
            if (name.StartsWith(OpcSignaturesPrefix, StringComparison.Ordinal) && name != OpcSignatureOriginPart && !file.IsDir)
            {
                signatureParts.Add(name);
            }

            entries.Add(new PackageEntry(name, file.CompressedSize, file.UncompressedSize, file.IsDir, file.CompressionName));
        }

        signatureParts.Sort(Utf8Ordinal.Comparer);
        return new PackageSummary(entries, hasContentTypes, hasRootRelationships, hasOrigin, signatureParts);
    }

    /// <summary>Validate a ZIP part name (Rust <c>normalize_zip_part_name</c>).</summary>
    public static string NormalizeZipPartName(string name)
    {
        if (name.Length == 0)
        {
            throw new PsignException("ZIP entry name is empty");
        }

        if (name.StartsWith('/'))
        {
            throw new PsignException($"ZIP entry name must be relative: {name}");
        }

        if (name.Contains('\\'))
        {
            throw new PsignException($"ZIP entry name must use '/' separators: {name}");
        }

        if (name.Split('/').Any(segment => segment == "." || segment == ".."))
        {
            throw new PsignException($"ZIP entry name contains dot segment: {name}");
        }

        return name;
    }

    /// <summary>Current local time as a ZIP DOS timestamp (Rust <c>current_zip_datetime</c>).</summary>
    public static ZipDateTime CurrentZipDateTime() => ZipDateTime.FromDateTime(DateTime.Now);
}

/// <summary>Ordinal comparison of strings by their UTF-8 octets (Rust <c>str</c> / <c>String</c> ordering).</summary>
public sealed class Utf8Ordinal : IComparer<string>
{
    public static Utf8Ordinal Comparer { get; } = new();

    public int Compare(string? x, string? y)
    {
        if (ReferenceEquals(x, y))
        {
            return 0;
        }

        if (x is null)
        {
            return -1;
        }

        if (y is null)
        {
            return 1;
        }

        // UTF-16 ordinal order matches UTF-8 order except for surrogates vs U+E000..U+FFFF; compare by code point.
        int i = 0;
        int j = 0;
        while (i < x.Length && j < y.Length)
        {
            int cx = CodePointAt(x, i, out int lx);
            int cy = CodePointAt(y, j, out int ly);
            if (cx != cy)
            {
                return cx < cy ? -1 : 1;
            }

            i += lx;
            j += ly;
        }

        return (x.Length - i).CompareTo(y.Length - j);
    }

    private static int CodePointAt(string s, int index, out int length)
    {
        if (char.IsHighSurrogate(s[index]) && index + 1 < s.Length && char.IsLowSurrogate(s[index + 1]))
        {
            length = 2;
            return char.ConvertToUtf32(s[index], s[index + 1]);
        }

        length = 1;
        return s[index];
    }
}
