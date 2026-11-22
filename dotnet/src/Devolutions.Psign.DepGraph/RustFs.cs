namespace Devolutions.Psign.DepGraph;

/// <summary>
/// Rust <c>std::path</c> / <c>std::fs</c> behaviour needed by <c>psign-depgraph</c>: <c>fs::canonicalize</c> (Windows
/// verbatim <c>\\?\</c> paths with on-disk casing and resolved links, <c>realpath</c> elsewhere), <c>Path::parent</c>,
/// <c>PathBuf::join</c> and <c>Path::exists</c>.
/// </summary>
internal static class RustFs
{
    private static bool Windows => OperatingSystem.IsWindows();

    private static bool IsSep(char c) => c == '/' || (Windows && c == '\\');

    /// <summary><c>Path::exists</c> (any file system entry, following links).</summary>
    public static bool Exists(string path)
    {
        try
        {
            return File.Exists(path) || Directory.Exists(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary><c>PathBuf::join</c> of a relative single-component <paramref name="name"/>.</summary>
    public static string Join(string basePath, string name)
    {
        if (name.Length > 0 && (IsSep(name[0]) || (Windows && name.Length >= 2 && name[1] == ':')))
        {
            return name;
        }

        bool needSep = basePath.Length > 0 && !IsSep(basePath[^1]);
        if (Windows && basePath.Length == 2 && basePath[1] == ':' && char.IsAsciiLetter(basePath[0]))
        {
            needSep = false;
        }

        return needSep ? basePath + (Windows ? "\\" : "/") + name : basePath + name;
    }

    /// <summary><c>Path::parent</c> (<c>null</c> for a root or prefix-only path).</summary>
    public static string? Parent(string path)
    {
        int prefixLen = PrefixLength(path);
        bool verbatim = path.StartsWith(@"\\?\", StringComparison.Ordinal);
        bool Sep(char c) => verbatim ? c == '\\' : IsSep(c);
        int rootEnd = prefixLen;
        if (rootEnd < path.Length && Sep(path[rootEnd]))
        {
            rootEnd++;
        }

        int end = path.Length;
        while (end > rootEnd && Sep(path[end - 1]))
        {
            end--;
        }

        if (end <= rootEnd)
        {
            return null;
        }

        int lastSep = -1;
        for (int i = end - 1; i >= rootEnd; i--)
        {
            if (Sep(path[i]))
            {
                lastSep = i;
                break;
            }
        }

        if (lastSep < 0)
        {
            return path[..rootEnd];
        }

        int parentEnd = lastSep;
        while (parentEnd > rootEnd && Sep(path[parentEnd - 1]))
        {
            parentEnd--;
        }

        return path[..Math.Max(parentEnd, rootEnd)];
    }

    private static int PrefixLength(string path)
    {
        if (!Windows)
        {
            return 0;
        }

        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return UncPrefixEnd(path, 8, verbatim: true);
        }

        if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            int sep = path.IndexOf('\\', 4);
            return sep < 0 ? path.Length : sep;
        }

        if (path.Length >= 2 && IsSep(path[0]) && IsSep(path[1]))
        {
            return UncPrefixEnd(path, 2, verbatim: false);
        }

        if (path.Length >= 2 && path[1] == ':' && char.IsAsciiLetter(path[0]))
        {
            return 2;
        }

        return 0;
    }

    private static int UncPrefixEnd(string path, int start, bool verbatim)
    {
        bool Sep(char c) => verbatim ? c == '\\' : IsSep(c);
        int i = start;
        while (i < path.Length && !Sep(path[i]))
        {
            i++;
        }

        if (i >= path.Length)
        {
            return path.Length;
        }

        i++;
        while (i < path.Length && !Sep(path[i]))
        {
            i++;
        }

        return i;
    }

    /// <summary>
    /// <c>std::fs::canonicalize</c>: absolute path with links resolved and the on-disk spelling of every component; on
    /// Windows the result carries the <c>\\?\</c> (or <c>\\?\UNC\</c>) verbatim prefix like <c>GetFinalPathNameByHandleW</c>.
    /// Throws <see cref="FileNotFoundException"/> / <see cref="DirectoryNotFoundException"/> when the path does not exist.
    /// </summary>
    public static string Canonicalize(string path)
    {
        string full = Path.GetFullPath(StripVerbatim(path));
        return Windows ? CanonicalizeWindows(full, 0) : CanonicalizeUnix(full, 0);
    }

    private static string StripVerbatim(string path)
    {
        if (!Windows)
        {
            return path;
        }

        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[8..];
        }

        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
    }

    private static string CanonicalizeWindows(string full, int depth)
    {
        if (depth > 40)
        {
            throw new IOException("The name of the file cannot be resolved by the system. (os error 1921)");
        }

        string root = Path.GetPathRoot(full) ?? throw new DirectoryNotFoundException();
        var components = full[root.Length..].Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        string normalizedRoot = root.Length >= 2 && root[1] == ':'
            ? char.ToUpperInvariant(root[0]) + @":\"
            : root.TrimEnd('\\', '/') + "\\";
        string current = normalizedRoot;
        for (int i = 0; i < components.Length; i++)
        {
            var info = FindEntry(current, components[i], last: i == components.Length - 1);
            if (info.LinkTarget is not null)
            {
                var target = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName
                    ?? throw new FileNotFoundException();
                var rest = string.Join('\\', components[(i + 1)..]);
                var combined = rest.Length == 0 ? target : Path.Combine(target, rest);
                return CanonicalizeWindows(Path.GetFullPath(StripVerbatim(combined)), depth + 1);
            }

            current = Path.Combine(current, info.Name);
        }

        if (current.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return @"\\?\UNC\" + current[2..];
        }

        return @"\\?\" + current;
    }

    private static string CanonicalizeUnix(string full, int depth)
    {
        if (depth > 40)
        {
            throw new IOException("Too many levels of symbolic links (os error 40)");
        }

        var components = full.Split('/', StringSplitOptions.RemoveEmptyEntries);
        string current = "/";
        for (int i = 0; i < components.Length; i++)
        {
            var info = FindEntry(current, components[i], last: i == components.Length - 1);
            if (info.LinkTarget is not null)
            {
                var target = info.ResolveLinkTarget(returnFinalTarget: true)?.FullName
                    ?? throw new FileNotFoundException();
                var rest = string.Join('/', components[(i + 1)..]);
                return CanonicalizeUnix(Path.GetFullPath(rest.Length == 0 ? target : Path.Combine(target, rest)), depth + 1);
            }

            current = Path.Combine(current, info.Name);
        }

        return current;
    }

    private static FileSystemInfo FindEntry(string directory, string name, bool last)
    {
        var dir = new DirectoryInfo(directory);
        FileSystemInfo? found = null;
        try
        {
            if (dir.Exists)
            {
                var options = new EnumerationOptions
                {
                    MatchCasing = Windows ? MatchCasing.CaseInsensitive : MatchCasing.CaseSensitive,
                    MatchType = MatchType.Simple,
                    AttributesToSkip = 0,
                    IgnoreInaccessible = true,
                    RecurseSubdirectories = false,
                };
                found = dir.EnumerateFileSystemInfos(name, options)
                    .FirstOrDefault(e => string.Equals(e.Name, name, Windows ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                    ?? dir.EnumerateFileSystemInfos(name, options).FirstOrDefault();
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            found = null;
        }

        if (found is null)
        {
            // Fall back to direct probing (entries hidden from enumeration, e.g. inaccessible parents).
            var probe = Path.Combine(directory, name);
            if (File.Exists(probe))
            {
                found = new FileInfo(probe);
            }
            else if (Directory.Exists(probe))
            {
                found = new DirectoryInfo(probe);
            }
        }

        return found ?? (last ? throw new FileNotFoundException() : throw new DirectoryNotFoundException());
    }
}
