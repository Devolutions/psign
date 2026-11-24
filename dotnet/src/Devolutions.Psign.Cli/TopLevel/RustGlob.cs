using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>
/// Port of the Rust <c>glob</c> crate (0.3) <c>glob(pattern)</c> with the default <c>MatchOptions</c> (case-sensitive,
/// <c>*</c> may match a leading dot): same pattern syntax and errors (<c>?</c>, <c>*</c>, <c>**</c> path components,
/// <c>[...]</c> / <c>[!...]</c> classes), the same depth-first, name-ordered traversal, and the same result path spelling
/// (the literal root of the pattern followed by <c>\</c>-joined components on Windows).
/// </summary>
internal static class RustGlob
{
    private const int Done = -1;

    private const string ErrorWildcards = "wildcards are either regular `*` or recursive `**`";
    private const string ErrorRecursiveWildcards = "recursive wildcards must form a single path component";
    private const string ErrorInvalidRange = "invalid range pattern";

    private enum TokenKind
    {
        Char,
        AnyChar,
        AnySequence,
        AnyRecursiveSequence,
        AnyWithin,
        AnyExcept,
    }

    private readonly record struct CharSpecifier(int Start, int End);

    private sealed record Token(TokenKind Kind, int Char = 0, CharSpecifier[]? Specifiers = null);

    private sealed class Pattern
    {
        public Pattern(List<Token> tokens, bool isRecursive)
        {
            Tokens = tokens;
            IsRecursive = isRecursive;
        }

        public List<Token> Tokens { get; }

        public bool IsRecursive { get; }

        /// <summary>Rust <c>pattern_as_str</c>: the literal text when the pattern has no metacharacters.</summary>
        public string? AsLiteral()
        {
            var sb = new StringBuilder();
            foreach (var t in Tokens)
            {
                if (t.Kind != TokenKind.Char)
                {
                    return null;
                }

                sb.Append(char.ConvertFromUtf32(t.Char));
            }

            return sb.ToString();
        }

        public bool Matches(string name)
        {
            var chars = CodePoints(name);
            var memo = new sbyte[(chars.Length + 1) * (Tokens.Count + 1)];
            return MatchFrom(chars, 0, 0, memo);
        }

        private bool MatchFrom(int[] file, int fi, int ti, sbyte[] memo)
        {
            int key = (fi * (Tokens.Count + 1)) + ti;
            if (memo[key] != 0)
            {
                return memo[key] > 0;
            }

            bool matched = MatchFromCore(file, fi, ti, memo);
            memo[key] = matched ? (sbyte)1 : (sbyte)-1;
            return matched;
        }

        private bool MatchFromCore(int[] file, int fi, int ti, sbyte[] memo)
        {
            for (; ti < Tokens.Count; ti++)
            {
                var token = Tokens[ti];
                switch (token.Kind)
                {
                    case TokenKind.AnySequence:
                    case TokenKind.AnyRecursiveSequence:
                        // `**` can only end right after a separator.
                        for (int k = fi; k <= file.Length; k++)
                        {
                            if (k > fi && token.Kind == TokenKind.AnyRecursiveSequence && !IsSeparator(file[k - 1]))
                            {
                                continue;
                            }

                            if (MatchFrom(file, k, ti + 1, memo))
                            {
                                return true;
                            }
                        }

                        return false;
                    default:
                        if (fi >= file.Length)
                        {
                            return false;
                        }

                        int c = file[fi];
                        bool ok = token.Kind switch
                        {
                            TokenKind.AnyChar => true,
                            TokenKind.AnyWithin => InSpecifiers(token.Specifiers!, c),
                            TokenKind.AnyExcept => !InSpecifiers(token.Specifiers!, c),
                            _ => c == token.Char || (OperatingSystem.IsWindows() && IsSeparator(c) && IsSeparator(token.Char)),
                        };
                        if (!ok)
                        {
                            return false;
                        }

                        fi++;
                        break;
                }
            }

            return fi == file.Length;
        }

        private static bool InSpecifiers(CharSpecifier[] specifiers, int c)
        {
            foreach (var s in specifiers)
            {
                if (s.Start <= c && c <= s.End)
                {
                    return true;
                }
            }

            return false;
        }
    }

    private sealed record PathEntry(string Path, string? Name, bool IsDirectory);

    /// <summary>A pending traversal item, or a deferred I/O error (Rust <c>GlobError</c>).</summary>
    private sealed record TodoItem(PathEntry? Entry, int Index, PsignException? Error);

    /// <summary>
    /// Expand <paramref name="pattern"/>; pattern syntax errors and directory read errors throw <see cref="PsignException"/>
    /// with the Rust <c>PatternError</c> / <c>GlobError</c> display text.
    /// </summary>
    public static List<string> Expand(string pattern)
    {
        var results = new List<string>();
        foreach (var path in Enumerate(pattern))
        {
            results.Add(path);
        }

        return results;
    }

    /// <summary>Lazily enumerate matches (errors surface when the failing item is reached, like the Rust iterator).</summary>
    public static IEnumerable<string> Enumerate(string pattern)
    {
        // Validate the whole pattern first (Rust `glob_with`).
        Compile(pattern);

        int rootLen = RootLength(pattern);
        if (rootLen > 0 && IsUnsupportedVerbatim(pattern[..rootLen]))
        {
            yield break;
        }

        string scopePath = rootLen > 0 ? pattern[..rootLen] : ".";
        var dirPatterns = new List<Pattern>();
        foreach (var component in SplitTerminator(pattern[Math.Min(rootLen, pattern.Length)..]))
        {
            dirPatterns.Add(Compile(component));
        }

        bool requireDir = pattern.Length > 0 && IsSeparator(pattern[^1]);
        if (dirPatterns.Count == 0)
        {
            yield break;
        }

        var todo = new List<TodoItem>();
        var visitedRecursiveDirs = new HashSet<string>(
            OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        FillTodo(todo, dirPatterns, 0, FromPath(scopePath));

        while (todo.Count > 0)
        {
            var item = todo[^1];
            todo.RemoveAt(todo.Count - 1);
            if (item.Error is { } error)
            {
                throw error;
            }

            var entry = item.Entry!;
            int idx = item.Index;
            if (idx == Done)
            {
                if (requireDir && !entry.IsDirectory)
                {
                    continue;
                }

                yield return entry.Path;
                continue;
            }

            if (dirPatterns[idx].IsRecursive)
            {
                int next = idx;
                while (next + 1 < dirPatterns.Count && dirPatterns[next + 1].IsRecursive)
                {
                    next++;
                }

                if (entry.IsDirectory)
                {
                    var canonical = CanonicalDirKey(entry.Path);
                    if (visitedRecursiveDirs.Add($"{next}:{canonical}"))
                    {
                        FillTodo(todo, dirPatterns, next, entry);
                    }

                    if (next == dirPatterns.Count - 1)
                    {
                        yield return entry.Path;
                        continue;
                    }

                    idx = next + 1;
                }
                else if (next == dirPatterns.Count - 1)
                {
                    continue;
                }
                else
                {
                    idx = next + 1;
                }
            }

            if (entry.Name is not { } name)
            {
                continue;
            }

            if (dirPatterns[idx].Matches(name))
            {
                if (idx == dirPatterns.Count - 1)
                {
                    if (!requireDir || entry.IsDirectory)
                    {
                        yield return entry.Path;
                    }
                }
                else
                {
                    FillTodo(todo, dirPatterns, idx + 1, entry);
                }
            }
        }
    }

    private static void FillTodo(List<TodoItem> todo, List<Pattern> patterns, int idx, PathEntry path)
    {
        void Add(PathEntry nextPath)
        {
            if (idx + 1 == patterns.Count)
            {
                todo.Add(new TodoItem(nextPath, Done, null));
            }
            else
            {
                FillTodo(todo, patterns, idx + 1, nextPath);
            }
        }

        var pattern = patterns[idx];
        bool isDir = path.IsDirectory;
        bool curdir = path.Path == ".";
        if (pattern.AsLiteral() is { } literal)
        {
            bool special = literal is "." or "..";
            var nextPath = curdir ? literal : Join(path.Path, literal);
            if ((special && isDir) || (!special && Exists(nextPath)))
            {
                Add(FromPath(nextPath));
            }

            return;
        }

        if (!isDir)
        {
            return;
        }

        List<PathEntry> children;
        try
        {
            children = ReadDir(path.Path, curdir);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException or ArgumentException or NotSupportedException)
        {
            todo.Add(new TodoItem(null, 0, new PsignException($"attempting to read `{path.Path}` resulted in an error: {IoErrorText.Message(e)}")));
            return;
        }

        children.Sort((a, b) => CompareUtf8(b.Name!, a.Name!));
        foreach (var child in children)
        {
            todo.Add(new TodoItem(child, idx, null));
        }

        if (pattern.Tokens.Count > 0 && pattern.Tokens[0].Kind == TokenKind.Char && pattern.Tokens[0].Char == '.')
        {
            foreach (var special in new[] { ".", ".." })
            {
                if (pattern.Matches(special))
                {
                    Add(FromPath(Join(path.Path, special)));
                }
            }
        }
    }

    private static List<PathEntry> ReadDir(string dir, bool curdir)
    {
        var options = new EnumerationOptions
        {
            AttributesToSkip = 0,
            IgnoreInaccessible = false,
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false,
            MatchType = MatchType.Simple,
        };
        var list = new List<PathEntry>();
        foreach (var info in new DirectoryInfo(dir).EnumerateFileSystemInfos("*", options))
        {
            var childPath = curdir ? info.Name : Join(dir, info.Name);
            bool isDirectory = (info.Attributes & FileAttributes.ReparsePoint) != 0
                ? Directory.Exists(childPath)
                : (info.Attributes & FileAttributes.Directory) != 0;
            list.Add(new PathEntry(childPath, info.Name, isDirectory));
        }

        return list;
    }

    private static string CanonicalDirKey(string path)
    {
        try
        {
            var di = new DirectoryInfo(path);
            if (di.LinkTarget is not null && di.ResolveLinkTarget(returnFinalTarget: true) is { } target)
            {
                return Path.GetFullPath(target.FullName);
            }

            return Path.GetFullPath(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return path;
        }
    }

    private static PathEntry FromPath(string path) => new(path, Devolutions.Psign.Signing.Portable.RustPath.FileName(path), Directory.Exists(path));

    private static bool Exists(string path)
    {
        if (File.Exists(path) || Directory.Exists(path))
        {
            return true;
        }

        try
        {
            return new FileInfo(path).LinkTarget is not null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>Rust <c>PathBuf::push</c> for a relative component (separator <c>\</c> on Windows).</summary>
    internal static string Join(string basePath, string component)
    {
        if (basePath.Length == 0)
        {
            return component;
        }

        bool needSep = !IsSeparator(basePath[^1]);
        if (OperatingSystem.IsWindows() && basePath.Length == 2 && basePath[1] == ':' && char.IsAsciiLetter(basePath[0]))
        {
            needSep = false;
        }

        return needSep ? basePath + Path.DirectorySeparatorChar + component : basePath + component;
    }

    private static bool IsSeparator(char c) => c == '/' || (OperatingSystem.IsWindows() && c == '\\');

    private static bool IsSeparator(int c) => c == '/' || (OperatingSystem.IsWindows() && c == '\\');

    /// <summary>Length of the leading prefix (<c>C:</c>, <c>\\server\share</c>, <c>\\?\...</c>) plus root separator.</summary>
    private static int RootLength(string pattern)
    {
        int i = 0;
        if (OperatingSystem.IsWindows())
        {
            if (pattern.Length >= 2 && pattern[1] == ':' && char.IsAsciiLetter(pattern[0]))
            {
                i = 2;
            }
            else if (pattern.StartsWith(@"\\?\", StringComparison.Ordinal) || pattern.StartsWith(@"\\.\", StringComparison.Ordinal))
            {
                // Verbatim / device prefix: up to the next backslash.
                int end = pattern.IndexOf('\\', 4);
                i = end < 0 ? pattern.Length : end;
            }
            else if (pattern.Length > 2 && IsSeparator(pattern[0]) && IsSeparator(pattern[1]) && !IsSeparator(pattern[2]))
            {
                // UNC \\server\share.
                int server = IndexOfSeparator(pattern, 2);
                if (server > 2)
                {
                    int share = IndexOfSeparator(pattern, server + 1);
                    i = share < 0 ? pattern.Length : share;
                }
            }
        }

        if (i < pattern.Length && IsSeparator(pattern[i]))
        {
            i++;
        }

        return i;
    }

    private static int IndexOfSeparator(string s, int start)
    {
        for (int i = start; i < s.Length; i++)
        {
            if (IsSeparator(s[i]))
            {
                return i;
            }
        }

        return -1;
    }

    private static bool IsUnsupportedVerbatim(string root) =>
        OperatingSystem.IsWindows()
        && root.StartsWith(@"\\?\", StringComparison.Ordinal)
        && !(root.Length >= 6 && char.IsAsciiLetter(root[4]) && root[5] == ':');

    /// <summary>Rust <c>str::split_terminator(path::is_separator)</c>.</summary>
    private static List<string> SplitTerminator(string s)
    {
        var parts = new List<string>();
        int start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (IsSeparator(s[i]))
            {
                parts.Add(s[start..i]);
                start = i + 1;
            }
        }

        if (start < s.Length)
        {
            parts.Add(s[start..]);
        }

        return parts;
    }

    private static int[] CodePoints(string s)
    {
        var list = new List<int>(s.Length);
        foreach (var rune in s.EnumerateRunes())
        {
            list.Add(rune.Value);
        }

        return [.. list];
    }

    private static int CompareUtf8(string a, string b)
    {
        var x = Encoding.UTF8.GetBytes(a);
        var y = Encoding.UTF8.GetBytes(b);
        return x.AsSpan().SequenceCompareTo(y);
    }

    private static PsignException PatternError(int pos, string msg) => new($"Pattern syntax error near position {pos}: {msg}");

    /// <summary>Rust <c>Pattern::new</c>.</summary>
    private static Pattern Compile(string pattern)
    {
        var chars = CodePoints(pattern);
        var tokens = new List<Token>();
        bool isRecursive = false;
        int i = 0;
        while (i < chars.Length)
        {
            switch (chars[i])
            {
                case '?':
                    tokens.Add(new Token(TokenKind.AnyChar));
                    i++;
                    break;
                case '*':
                    {
                        int old = i;
                        while (i < chars.Length && chars[i] == '*')
                        {
                            i++;
                        }

                        int count = i - old;
                        if (count > 2)
                        {
                            throw PatternError(old + 2, ErrorWildcards);
                        }

                        if (count == 2)
                        {
                            if (i == 2 || IsSeparator(chars[i - count - 1]))
                            {
                                if (i < chars.Length && IsSeparator(chars[i]))
                                {
                                    i++;
                                }
                                else if (i != chars.Length)
                                {
                                    throw PatternError(i, ErrorRecursiveWildcards);
                                }
                            }
                            else
                            {
                                throw PatternError(old - 1, ErrorRecursiveWildcards);
                            }

                            if (!(tokens.Count > 0 && tokens[^1].Kind == TokenKind.AnyRecursiveSequence))
                            {
                                isRecursive = true;
                                tokens.Add(new Token(TokenKind.AnyRecursiveSequence));
                            }
                        }
                        else
                        {
                            tokens.Add(new Token(TokenKind.AnySequence));
                        }

                        break;
                    }

                case '[':
                    {
                        if (i + 4 <= chars.Length && chars[i + 1] == '!')
                        {
                            int j = IndexOfClose(chars, i + 3);
                            if (j >= 0)
                            {
                                tokens.Add(new Token(TokenKind.AnyExcept, Specifiers: ParseSpecifiers(chars, i + 2, i + 3 + j)));
                                i += j + 4;
                                break;
                            }
                        }
                        else if (i + 3 <= chars.Length && chars[i + 1] != '!')
                        {
                            int j = IndexOfClose(chars, i + 2);
                            if (j >= 0)
                            {
                                tokens.Add(new Token(TokenKind.AnyWithin, Specifiers: ParseSpecifiers(chars, i + 1, i + 2 + j)));
                                i += j + 3;
                                break;
                            }
                        }

                        throw PatternError(i, ErrorInvalidRange);
                    }

                default:
                    tokens.Add(new Token(TokenKind.Char, chars[i]));
                    i++;
                    break;
            }
        }

        return new Pattern(tokens, isRecursive);
    }

    /// <summary>Position of the first <c>]</c> at or after <paramref name="start"/>, relative to <paramref name="start"/>.</summary>
    private static int IndexOfClose(int[] chars, int start)
    {
        for (int k = start; k < chars.Length; k++)
        {
            if (chars[k] == ']')
            {
                return k - start;
            }
        }

        return -1;
    }

    private static CharSpecifier[] ParseSpecifiers(int[] chars, int start, int end)
    {
        var cs = new List<CharSpecifier>();
        int i = start;
        while (i < end)
        {
            if (i + 3 <= end && chars[i + 1] == '-')
            {
                cs.Add(new CharSpecifier(chars[i], chars[i + 2]));
                i += 3;
            }
            else
            {
                cs.Add(new CharSpecifier(chars[i], chars[i]));
                i++;
            }
        }

        return [.. cs];
    }
}
