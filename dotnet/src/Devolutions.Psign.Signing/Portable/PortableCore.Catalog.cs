using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Signing.Catalog;

namespace Devolutions.Psign.Signing.Portable;

public static partial class PortableCore
{
    /// <summary>
    /// Create an unsigned Windows file catalog over files / directories (Rust <c>portable_new_file_catalog</c>). A single
    /// directory root records relative member names joined with <c>/</c>; otherwise members use file names.
    /// </summary>
    public static PortableNewFileCatalogResponse PortableNewFileCatalog(PortableNewFileCatalogRequest request)
    {
        var catalogFilePath = ResolveCatalogOutputPath(request.CatalogFilePath);
        var catalogVersion = EffectiveCatalogVersion(request.CatalogVersion);
        var hashAlgorithm = CatalogHashAlgorithmForVersion(catalogVersion);
        var subjects = CollectCatalogSubjects(request.Paths, catalogFilePath);
        var inputs = subjects
            .Select(s => new CatalogSubjectInput(s.MemberName, ReadFile(s.Path, $"read catalog subject {s.Path}")))
            .ToList();
        var catalog = WithContext($"create file catalog {catalogFilePath}", () => CatalogSigning.CreateUnsigned(inputs, hashAlgorithm));
        WriteFile(catalogFilePath, catalog.Pkcs7Der);
        var items = catalog.Members.Select(PortableCatalogItemFromMember).ToList();
        return new PortableNewFileCatalogResponse
        {
            CatalogFilePath = catalogFilePath,
            CatalogVersion = catalogVersion,
            HashAlgorithm = CatalogHashAlgorithmLabel(hashAlgorithm),
            ItemCount = items.Count,
            CatalogItems = items,
        };
    }

    /// <summary>
    /// Validate files against a catalog (Rust <c>portable_test_file_catalog</c>): per-path hash checks, catalog members
    /// missing on disk, skip lists, and the catalog's own signature (with optional explicit trust).
    /// </summary>
    public static PortableTestFileCatalogResponse PortableTestFileCatalog(PortableTestFileCatalogRequest request, PortableCoreOptions? options = null)
    {
        var catalogFilePath = request.CatalogFilePath;
        var catalogBytes = ReadFile(catalogFilePath, $"read catalog {catalogFilePath}");
        var members = WithContext($"parse catalog members {catalogFilePath}", () => CatalogDigest.Members(catalogBytes));
        var catalogItems = members.Select(PortableCatalogItemFromMember).ToList();
        var hashAlgorithm = members.Count > 0 ? CatalogHashAlgorithmLabelForOid(members[0].DigestAlgorithmOid) : "Unknown";
        var memberByName = new Dictionary<string, CatalogMember>(StringComparer.Ordinal);
        foreach (var member in members)
        {
            if (member.SubjectName is { } name)
            {
                memberByName[NormalizeCatalogMemberKey(name)] = member;
            }
        }

        var skipKeys = new HashSet<string>(request.FilesToSkip.SelectMany(CatalogSkipKeys), StringComparer.Ordinal);
        var subjects = CollectCatalogSubjects(request.Paths, catalogFilePath);
        var seenPathKeys = new HashSet<string>(StringComparer.Ordinal);
        var skippedItems = new List<string>();
        var pathItems = new List<PortableCatalogPathItem>();

        foreach (var subject in subjects)
        {
            var memberKey = NormalizeCatalogMemberKey(subject.MemberName);
            if (skipKeys.Contains(memberKey)
                || skipKeys.Contains(NormalizeCatalogMemberKey(subject.Path))
                || (RustPath.FileName(subject.Path) is { } fileName && skipKeys.Contains(NormalizeCatalogMemberKey(fileName))))
            {
                skippedItems.Add(subject.MemberName);
                continue;
            }

            seenPathKeys.Add(memberKey);
            if (!memberByName.TryGetValue(memberKey, out var catalogMember))
            {
                pathItems.Add(new PortableCatalogPathItem(subject.MemberName, null, PortableCatalogItemStatus.NotInCatalog, "File is not listed in the catalog."));
                continue;
            }

            var bytes = ReadFile(subject.Path, $"read catalog validation subject {subject.Path}");
            var actual = WithContext($"hash catalog validation subject {subject.Path}", () => CatalogDigest.MemberDigestForSubject(catalogMember, bytes));
            var status = actual.AsSpan().SequenceEqual(catalogMember.Digest) ? PortableCatalogItemStatus.Valid : PortableCatalogItemStatus.HashMismatch;
            pathItems.Add(new PortableCatalogPathItem(
                subject.MemberName,
                Hex.Lower(actual),
                status,
                status == PortableCatalogItemStatus.HashMismatch ? "File hash does not match the catalog." : null));
        }

        foreach (var (key, member) in memberByName)
        {
            if (seenPathKeys.Contains(key) || skipKeys.Contains(key))
            {
                continue;
            }

            pathItems.Add(new PortableCatalogPathItem(
                member.SubjectName ?? Hex.Lower(member.SubjectIdentifier),
                null,
                PortableCatalogItemStatus.Missing,
                "Catalog member was not found under the supplied path."));
        }

        pathItems = pathItems.OrderBy(i => CatalogPathSortKey(i.Path), RustJson.Utf8Comparer).ToList();
        skippedItems = skippedItems.OrderBy(CatalogPathSortKey, RustJson.Utf8Comparer).ToList();
        var signature = PortableGetSignature(request.ToSignatureRequest(catalogFilePath), options);
        var overall = pathItems.All(i => i.Status == PortableCatalogItemStatus.Valid)
            ? PortableCatalogValidationStatus.Valid
            : PortableCatalogValidationStatus.ValidationFailed;

        return new PortableTestFileCatalogResponse
        {
            CatalogFilePath = catalogFilePath,
            Status = overall,
            HashAlgorithm = hashAlgorithm,
            CatalogItems = catalogItems,
            PathItems = pathItems,
            SkippedItems = skippedItems,
            Signature = signature,
        };
    }

    private sealed record CatalogSubjectPlan(string Path, string MemberName);

    private static string ResolveCatalogOutputPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new PsignException("catalog file path must not be empty");
        }

        return Directory.Exists(path) ? Path.Join(path, "catalog.cat") : path;
    }

    private static uint EffectiveCatalogVersion(uint version) => version switch
    {
        0 => 2,
        1 or 2 => version,
        _ => throw new PsignException("catalog_version must be 1 or 2"),
    };

    private static AuthenticodeHashKind CatalogHashAlgorithmForVersion(uint version) => version switch
    {
        1 => AuthenticodeHashKind.Sha1,
        2 => AuthenticodeHashKind.Sha256,
        _ => throw new PsignException("catalog_version must be 1 or 2"),
    };

    private static string CatalogHashAlgorithmLabel(AuthenticodeHashKind algorithm) => algorithm switch
    {
        AuthenticodeHashKind.Sha1 => "SHA1",
        AuthenticodeHashKind.Sha256 => "SHA256",
        AuthenticodeHashKind.Sha384 => "SHA384",
        _ => "SHA512",
    };

    private static string CatalogHashAlgorithmLabelForOid(string oid) => oid switch
    {
        "1.3.14.3.2.26" => "SHA1",
        "2.16.840.1.101.3.4.2.1" => "SHA256",
        "2.16.840.1.101.3.4.2.2" => "SHA384",
        "2.16.840.1.101.3.4.2.3" => "SHA512",
        _ => "Unknown",
    };

    private static PortableCatalogItem PortableCatalogItemFromMember(CatalogMember member) =>
        new(member.SubjectName ?? Hex.Lower(member.SubjectIdentifier), Hex.Lower(member.Digest));

    private static List<CatalogSubjectPlan> CollectCatalogSubjects(IReadOnlyList<string> paths, string? catalogFilePath)
    {
        List<string> effectivePaths;
        if (paths.Count == 0)
        {
            try
            {
                effectivePaths = [Directory.GetCurrentDirectory()];
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                throw new PsignException("resolve current directory for catalog paths", e);
            }
        }
        else
        {
            effectivePaths = [.. paths];
        }

        var subjects = new List<CatalogSubjectPlan>();
        if (effectivePaths.Count == 1 && Directory.Exists(effectivePaths[0]))
        {
            CollectCatalogDirectorySubjects(effectivePaths[0], effectivePaths[0], catalogFilePath, subjects);
        }
        else
        {
            foreach (var path in effectivePaths)
            {
                if (Directory.Exists(path))
                {
                    CollectCatalogDirectorySubjects(path, null, catalogFilePath, subjects);
                }
                else if (File.Exists(path))
                {
                    if (IsSameExistingPath(path, catalogFilePath))
                    {
                        continue;
                    }

                    subjects.Add(new CatalogSubjectPlan(path, CatalogFileName(path)));
                }
                else
                {
                    throw new PsignException($"catalog path does not exist or is not a file/directory: {path}");
                }
            }
        }

        subjects = subjects
            .OrderBy(s => CatalogPathSortKey(s.MemberName), RustJson.Utf8Comparer)
            .ThenBy(s => s.Path, RustJson.Utf8Comparer)
            .ToList();
        RejectDuplicateCatalogMemberNames(subjects);
        if (subjects.Count == 0)
        {
            throw new PsignException("catalog requires at least one subject file");
        }

        return subjects;
    }

    private static void CollectCatalogDirectorySubjects(string directory, string? relativeBase, string? catalogFilePath, List<CatalogSubjectPlan> subjects)
    {
        List<FileSystemInfo> entries;
        try
        {
            entries = new DirectoryInfo(directory).EnumerateFileSystemInfos().ToList();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new PsignException($"read directory {directory}", e);
        }

        foreach (var entry in entries.OrderBy(e => e.Name, RustJson.Utf8Comparer))
        {
            var path = Path.Join(directory, entry.Name);
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                // Rust `DirEntry::file_type` does not follow symlinks: links are neither files nor directories.
                continue;
            }

            if ((entry.Attributes & FileAttributes.Directory) != 0)
            {
                CollectCatalogDirectorySubjects(path, relativeBase, catalogFilePath, subjects);
            }
            else
            {
                if (IsSameExistingPath(path, catalogFilePath))
                {
                    continue;
                }

                var memberName = relativeBase is null ? CatalogFileName(path) : CatalogRelativeName(relativeBase, path);
                subjects.Add(new CatalogSubjectPlan(path, memberName));
            }
        }
    }

    private static string CatalogFileName(string path) =>
        RustPath.FileName(path) ?? throw new PsignException($"catalog subject path has no UTF-8 file name: {path}");

    private static string CatalogRelativeName(string basePath, string path)
    {
        if (!path.StartsWith(basePath, StringComparison.Ordinal))
        {
            throw new PsignException($"make {path} relative to {basePath}");
        }

        var parts = path[basePath.Length..]
            .Split(OperatingSystem.IsWindows() ? ['\\', '/'] : ['/'])
            .Where(p => p.Length > 0 && p != ".")
            .ToList();
        if (parts.Count == 0)
        {
            throw new PsignException($"catalog relative path is empty for {path}");
        }

        return string.Join('/', parts);
    }

    private static void RejectDuplicateCatalogMemberNames(List<CatalogSubjectPlan> subjects)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var subject in subjects)
        {
            if (!seen.Add(NormalizeCatalogMemberKey(subject.MemberName)))
            {
                throw new PsignException($"catalog contains duplicate subject file name {subject.MemberName}");
            }
        }
    }

    private static bool IsSameExistingPath(string path, string? other)
    {
        if (other is null || !(File.Exists(path) || Directory.Exists(path)) || !(File.Exists(other) || Directory.Exists(other)))
        {
            return false;
        }

        try
        {
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return string.Equals(Canonical(path), Canonical(other), comparison);
        }
        catch (Exception e) when (e is IOException or ArgumentException or NotSupportedException or UnauthorizedAccessException)
        {
            return false;
        }

        static string Canonical(string p)
        {
            var info = new FileInfo(Path.GetFullPath(p));
            var target = info.LinkTarget is not null ? info.ResolveLinkTarget(returnFinalTarget: true)?.FullName : null;
            return target ?? info.FullName;
        }
    }

    private static string NormalizeCatalogMemberKey(string path) => RustText.ToAsciiLowercase(path.Replace('\\', '/'));

    private static IEnumerable<string> CatalogSkipKeys(string skip)
    {
        var normalized = NormalizeCatalogMemberKey(skip);
        int slash = normalized.LastIndexOf('/');
        var fileName = slash >= 0 ? normalized[(slash + 1)..] : normalized;
        return fileName.Length > 0 && fileName != normalized ? [normalized, fileName] : [normalized];
    }

    private static string CatalogPathSortKey(string path) => NormalizeCatalogMemberKey(path);
}
