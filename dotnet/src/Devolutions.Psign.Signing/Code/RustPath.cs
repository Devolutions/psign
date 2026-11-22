using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Code;

/// <summary>
/// Rust <c>std::path</c> / <c>std::fs</c> semantics needed by the <c>code</c> orchestrator so planned paths, display
/// strings and error messages match the Rust tool: <c>canonicalize</c> (Windows verbatim <c>\\?\</c> prefix with on-disk
/// casing), <c>Path::join</c> (including verbatim-path normalization), <c>file_name</c> / <c>extension</c> /
/// <c>file_stem</c> / <c>parent</c> / <c>set_file_name</c>, and <c>std::io::Error</c> display text.
/// </summary>
internal static class RustPath
{
    private const int MaxLinkDepth = 40;

    internal static bool IsWindows => OperatingSystem.IsWindows();

    internal static char MainSeparator => IsWindows ? '\\' : '/';

    internal static bool IsSeparator(char c) => c == '/' || (IsWindows && c == '\\');

    // ------------------------------------------------------------------ prefix / root parsing

    /// <summary>Length of the Windows path prefix (<c>C:</c>, <c>\\server\share</c>, <c>\\?\...</c>) or 0.</summary>
    private static int PrefixLength(string p, out bool verbatim, out bool bareDrive)
    {
        verbatim = false;
        bareDrive = false;
        if (!IsWindows)
        {
            return 0;
        }

        if (p.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            verbatim = true;
            var rest = p[4..];
            if (rest.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
            {
                int server = rest.IndexOf('\\', 4);
                if (server < 0)
                {
                    return p.Length;
                }

                int share = rest.IndexOf('\\', server + 1);
                return share < 0 ? p.Length : 4 + share;
            }

            if (rest.Length >= 2 && char.IsAsciiLetter(rest[0]) && rest[1] == ':')
            {
                return 6;
            }

            int end = rest.IndexOf('\\');
            return end < 0 ? p.Length : 4 + end;
        }

        if (p.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            int end = p.IndexOfAny(['\\', '/'], 4);
            return end < 0 ? p.Length : end;
        }

        if (p.Length >= 2 && IsSeparator(p[0]) && IsSeparator(p[1]) && p.Length > 2 && !IsSeparator(p[2]))
        {
            int server = p.IndexOfAny(['\\', '/'], 2);
            if (server < 0)
            {
                return p.Length;
            }

            int share = p.IndexOfAny(['\\', '/'], server + 1);
            return share < 0 ? p.Length : share;
        }

        if (p.Length >= 2 && char.IsAsciiLetter(p[0]) && p[1] == ':')
        {
            bareDrive = true;
            return 2;
        }

        return 0;
    }

    private static int PrefixLength(string p) => PrefixLength(p, out _, out _);

    /// <summary>Rust <c>Path::is_absolute</c>.</summary>
    internal static bool IsAbsolute(string p)
    {
        if (!IsWindows)
        {
            return p.StartsWith('/');
        }

        int prefix = PrefixLength(p, out bool verbatim, out bool bareDrive);
        if (prefix == 0)
        {
            return false;
        }

        if (verbatim || !bareDrive)
        {
            return true;
        }

        return p.Length > 2 && IsSeparator(p[2]);
    }

    private static bool HasRootAfterPrefix(string p, int prefix) => prefix < p.Length && IsSeparator(p[prefix]);

    /// <summary>Normal components of <paramref name="p"/> after the prefix / root (<c>.</c> dropped; <c>..</c> kept).</summary>
    internal static List<string> NormalComponents(string p)
    {
        int prefix = PrefixLength(p);
        var list = new List<string>();
        foreach (var part in SplitSeparators(p[prefix..]))
        {
            if (part.Length == 0 || part == ".")
            {
                continue;
            }

            list.Add(part);
        }

        return list;
    }

    private static IEnumerable<string> SplitSeparators(string s)
    {
        int start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (IsSeparator(s[i]))
            {
                yield return s[start..i];
                start = i + 1;
            }
        }

        yield return s[start..];
    }

    // ------------------------------------------------------------------ file name helpers

    /// <summary>Rust <c>Path::file_name</c>.</summary>
    internal static string? FileName(string p)
    {
        var comps = NormalComponents(p);
        if (comps.Count == 0)
        {
            return null;
        }

        var last = comps[^1];
        return last == ".." ? null : last;
    }

    /// <summary>Rust <c>Path::extension</c>.</summary>
    internal static string? Extension(string p)
    {
        var name = FileName(p);
        if (name is null || name == "..")
        {
            return null;
        }

        int dot = name.LastIndexOf('.');
        return dot <= 0 ? null : name[(dot + 1)..];
    }

    /// <summary>Rust <c>Path::file_stem</c>.</summary>
    internal static string? FileStem(string p)
    {
        var name = FileName(p);
        if (name is null)
        {
            return null;
        }

        int dot = name.LastIndexOf('.');
        return dot <= 0 ? name : name[..dot];
    }

    /// <summary>Case-insensitive (ASCII) extension check (Rust <c>is_extension</c>).</summary>
    internal static bool IsExtension(string p, string expected) =>
        Extension(p) is { } ext && string.Equals(CodeFormats.AsciiLower(ext), CodeFormats.AsciiLower(expected), StringComparison.Ordinal);

    /// <summary>Rust <c>Path::parent</c> (<c>null</c> for a root / prefix-only path).</summary>
    internal static string? Parent(string p)
    {
        int prefix = PrefixLength(p);
        bool hasRoot = HasRootAfterPrefix(p, prefix) || (!IsWindows && p.StartsWith('/'));
        int rootEnd = prefix + (hasRoot ? 1 : 0);
        int end = p.Length;
        while (end > rootEnd && IsSeparator(p[end - 1]))
        {
            end--;
        }

        if (end <= rootEnd)
        {
            return null;
        }

        int sep = -1;
        for (int i = end - 1; i >= rootEnd; i--)
        {
            if (IsSeparator(p[i]))
            {
                sep = i;
                break;
            }
        }

        if (sep < 0)
        {
            return p[..rootEnd];
        }

        int parentEnd = sep;
        while (parentEnd > rootEnd && IsSeparator(p[parentEnd - 1]))
        {
            parentEnd--;
        }

        return p[..Math.Max(parentEnd, rootEnd)];
    }

    /// <summary>Rust <c>PathBuf::push</c> for a relative component string.</summary>
    internal static string Push(string buf, string component)
    {
        if (component.Length > 0 && IsAbsolute(component))
        {
            return component;
        }

        bool needSep = buf.Length > 0 && !IsSeparator(buf[^1]);
        int prefix = PrefixLength(buf, out _, out bool bareDrive);
        if (bareDrive && prefix == buf.Length)
        {
            needSep = false;
        }

        return needSep ? buf + MainSeparator + component : buf + component;
    }

    /// <summary>Rust <c>PathBuf::set_file_name</c>.</summary>
    internal static string SetFileName(string p, string name)
    {
        var buf = FileName(p) is not null ? Parent(p) ?? string.Empty : p;
        return Push(buf, name);
    }

    /// <summary>Rust <c>display_to_path</c>: replace <c>/</c> with the platform separator.</summary>
    internal static string DisplayToPath(string display) => display.Replace('/', MainSeparator);

    /// <summary>
    /// Rust <c>base.join(rel)</c>. Verbatim (<c>\\?\</c>) bases normalize the pushed components like
    /// <c>PathBuf::push</c> does (skip <c>.</c>, pop on <c>..</c>).
    /// </summary>
    internal static string Join(string basePath, string rel)
    {
        if (rel.Length == 0)
        {
            return Push(basePath, rel);
        }

        if (IsAbsolute(rel))
        {
            return rel;
        }

        int relPrefix = PrefixLength(rel);
        if (relPrefix > 0)
        {
            return rel;
        }

        int basePrefix = PrefixLength(basePath, out bool verbatim, out _);
        bool relRooted = IsSeparator(rel[0]);
        if (verbatim)
        {
            var comps = relRooted ? new List<string>() : NormalComponents(basePath);
            foreach (var part in SplitSeparators(rel))
            {
                if (part.Length == 0 || part == ".")
                {
                    continue;
                }

                if (part == "..")
                {
                    if (comps.Count > 0)
                    {
                        comps.RemoveAt(comps.Count - 1);
                    }

                    continue;
                }

                comps.Add(part);
            }

            var sb = new StringBuilder(basePath[..basePrefix]);
            sb.Append('\\');
            sb.Append(string.Join('\\', comps));
            return sb.ToString();
        }

        if (relRooted)
        {
            return basePath[..basePrefix] + rel;
        }

        return Push(basePath, rel);
    }

    // ------------------------------------------------------------------ canonicalize

    /// <summary>Rust <c>std::fs::canonicalize</c>.</summary>
    internal static string Canonicalize(string path)
    {
        string full;
        try
        {
            full = Path.GetFullPath(path.Length == 0 ? "." : path);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new PsignException(IsWindows ? "The filename, directory name, or volume label syntax is incorrect. (os error 123)" : "No such file or directory (os error 2)");
        }

        if (!File.Exists(full) && !Directory.Exists(full))
        {
            throw new PsignException(NotFoundMessage(full));
        }

        return IsWindows ? CanonicalizeWindows(full, 0) : CanonicalizeUnix(full, 0);
    }

    private static string NotFoundMessage(string full)
    {
        if (!IsWindows)
        {
            return "No such file or directory (os error 2)";
        }

        var parent = Path.GetDirectoryName(full);
        return parent is null || Directory.Exists(parent)
            ? "The system cannot find the file specified. (os error 2)"
            : "The system cannot find the path specified. (os error 3)";
    }

    private static string CanonicalizeWindows(string full, int depth)
    {
        if (depth > MaxLinkDepth)
        {
            throw new PsignException("The name of the file cannot be resolved by the system. (os error 1921)");
        }

        if (full.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            full = @"\\" + full[8..];
        }
        else if (full.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            full = full[4..];
        }

        string root = Path.GetPathRoot(full) ?? string.Empty;
        bool unc = root.StartsWith(@"\\", StringComparison.Ordinal);
        string current = unc ? root.TrimEnd('\\', '/') + "\\" : char.ToUpperInvariant(root[0]) + root[1..].Replace('/', '\\');
        var parts = full[root.Length..].Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length; i++)
        {
            var part = parts[i];
            FileSystemInfo? match = null;
            try
            {
                match = new DirectoryInfo(current).EnumerateFileSystemInfos(part).FirstOrDefault();
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
            }

            string next = Path.Combine(current, match?.Name ?? part);
            match ??= Directory.Exists(next) ? new DirectoryInfo(next) : new FileInfo(next);
            if (match.LinkTarget is not null)
            {
                var target = match.ResolveLinkTarget(returnFinalTarget: true);
                if (target is not null)
                {
                    var rest = string.Join('\\', parts.Skip(i + 1));
                    var resolved = rest.Length == 0 ? target.FullName : Path.Combine(target.FullName, rest);
                    return CanonicalizeWindows(Path.GetFullPath(resolved), depth + 1);
                }
            }

            current = next;
        }

        return unc ? @"\\?\UNC\" + current[2..].TrimEnd('\\') : @"\\?\" + (current.Length > 3 ? current.TrimEnd('\\') : current);
    }

    private static string CanonicalizeUnix(string full, int depth)
    {
        if (depth > MaxLinkDepth)
        {
            throw new PsignException("Too many levels of symbolic links (os error 40)");
        }

        var parts = full.Split('/', StringSplitOptions.RemoveEmptyEntries);
        string current = "/";
        for (int i = 0; i < parts.Length; i++)
        {
            string next = Path.Combine(current, parts[i]);
            FileSystemInfo info = Directory.Exists(next) ? new DirectoryInfo(next) : new FileInfo(next);
            if (info.LinkTarget is not null)
            {
                var target = info.ResolveLinkTarget(returnFinalTarget: true);
                if (target is not null)
                {
                    var rest = string.Join('/', parts.Skip(i + 1));
                    var resolved = rest.Length == 0 ? target.FullName : Path.Combine(target.FullName, rest);
                    return CanonicalizeUnix(Path.GetFullPath(resolved), depth + 1);
                }
            }

            current = next;
        }

        return current;
    }
}

/// <summary>Rust <c>std::io::Error</c> display text and <c>std::fs</c> wrappers with anyhow-style context.</summary>
internal static class RustIo
{
    /// <summary>Approximate Rust <c>std::io::Error</c> display text for a .NET exception.</summary>
    internal static string Message(Exception e) => e switch
    {
        FileNotFoundException => RustPath.IsWindows ? "The system cannot find the file specified. (os error 2)" : "No such file or directory (os error 2)",
        DirectoryNotFoundException => RustPath.IsWindows ? "The system cannot find the path specified. (os error 3)" : "No such file or directory (os error 2)",
        UnauthorizedAccessException => RustPath.IsWindows ? "Access is denied. (os error 5)" : "Permission denied (os error 13)",
        PathTooLongException => RustPath.IsWindows ? "The filename or extension is too long. (os error 206)" : "File name too long (os error 36)",
        ArgumentException or NotSupportedException => RustPath.IsWindows ? "The filename, directory name, or volume label syntax is incorrect. (os error 123)" : "invalid filename",
        _ => e.Message,
    };

    internal static bool IsIo(Exception e) =>
        e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException;

    /// <summary><c>std::fs::read(path).with_context(|| context)</c>.</summary>
    internal static byte[] Read(string path, string context)
    {
        try
        {
            if (Directory.Exists(path))
            {
                throw new UnauthorizedAccessException();
            }

            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (IsIo(e))
        {
            throw new PsignException(context, new PsignException(Message(e)));
        }
    }

    /// <summary><c>std::fs::write(path, data).with_context(|| context)</c>.</summary>
    internal static void Write(string path, byte[] data, string context)
    {
        try
        {
            File.WriteAllBytes(path, data);
        }
        catch (Exception e) when (IsIo(e))
        {
            throw new PsignException(context, new PsignException(Message(e)));
        }
    }

    /// <summary><c>std::fs::read_to_string(path).with_context(|| context)</c> (UTF-8, BOM preserved).</summary>
    internal static string ReadToString(string path, string context)
    {
        var bytes = Read(path, context);
        var text = Devolutions.Psign.Core.Text.RustText.TryFromUtf8(bytes);
        return text ?? throw new PsignException(context, new PsignException("stream did not contain valid UTF-8"));
    }

    /// <summary><c>std::fs::create_dir_all(path).with_context(|| context)</c>.</summary>
    internal static void CreateDirAll(string path, string context)
    {
        try
        {
            Directory.CreateDirectory(path);
        }
        catch (Exception e) when (IsIo(e))
        {
            throw new PsignException(context, new PsignException(Message(e)));
        }
    }

    /// <summary>Rust <c>std::str::from_utf8</c> with the <c>Utf8Error</c> display text on failure.</summary>
    internal static string Utf8(byte[] bytes, string context)
    {
        var text = Devolutions.Psign.Core.Text.RustText.TryFromUtf8(bytes);
        return text ?? throw new PsignException(context, new PsignException(Utf8ErrorMessage(bytes)));
    }

    /// <summary>Rust <c>Utf8Error</c> display: <c>invalid utf-8 sequence of N bytes from index I</c> / <c>incomplete utf-8 byte sequence from index I</c>.</summary>
    internal static string Utf8ErrorMessage(ReadOnlySpan<byte> bytes)
    {
        int i = 0;
        while (i < bytes.Length)
        {
            byte b = bytes[i];
            if (b < 0x80)
            {
                i++;
                continue;
            }

            int width = b switch
            {
                >= 0xC2 and <= 0xDF => 2,
                >= 0xE0 and <= 0xEF => 3,
                >= 0xF0 and <= 0xF4 => 4,
                _ => 0,
            };
            if (width == 0)
            {
                return $"invalid utf-8 sequence of 1 bytes from index {i}";
            }

            int valid = 1;
            for (int k = 1; k < width; k++)
            {
                if (i + k >= bytes.Length)
                {
                    return $"incomplete utf-8 byte sequence from index {i}";
                }

                byte c = bytes[i + k];
                bool ok = k == 1
                    ? b switch
                    {
                        0xE0 => c is >= 0xA0 and <= 0xBF,
                        0xED => c is >= 0x80 and <= 0x9F,
                        0xF0 => c is >= 0x90 and <= 0xBF,
                        0xF4 => c is >= 0x80 and <= 0x8F,
                        _ => c is >= 0x80 and <= 0xBF,
                    }
                    : c is >= 0x80 and <= 0xBF;
                if (!ok)
                {
                    return $"invalid utf-8 sequence of {valid} bytes from index {i}";
                }

                valid++;
            }

            i += width;
        }

        return "invalid utf-8";
    }
}
