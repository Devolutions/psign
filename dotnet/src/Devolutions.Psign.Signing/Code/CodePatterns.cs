using System.Globalization;
using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Code;

/// <summary>Include (or <c>!</c> exclude) selection rule (Rust <c>PatternRule</c>).</summary>
public sealed record CodePatternRule(bool Include, string Pattern);

/// <summary>
/// dotnet/sign-style input selection patterns (ported from <c>pattern_rules</c>, <c>unescape_pattern</c>,
/// <c>expand_braces</c>, <c>glob_match</c> and <c>validate_relative_pattern</c> in Rust <c>src/code.rs</c>): <c>!</c>
/// negation, <c>\!</c> literal bang, brace lists and numeric ranges, <c>*</c> / <c>?</c> within a path segment and
/// <c>**</c> across segments (ASCII case-insensitive).
/// </summary>
public static class CodePatterns
{
    /// <summary>Parse one input / file-list line into rules (Rust <c>pattern_rules</c>).</summary>
    public static List<CodePatternRule> PatternRules(string input)
    {
        bool include = true;
        string pattern;
        if (input.StartsWith("\\!", StringComparison.Ordinal))
        {
            pattern = "!" + UnescapePattern(input[2..]);
        }
        else if (input.StartsWith('!'))
        {
            include = false;
            pattern = UnescapePattern(input[1..]);
        }
        else
        {
            pattern = UnescapePattern(input);
        }

        if (pattern.Length == 0)
        {
            throw new PsignException("empty pattern");
        }

        ValidateRelativePattern(pattern);
        return ExpandBraces(pattern).Select(p => new CodePatternRule(include, p)).ToList();
    }

    /// <summary>Rust <c>unescape_pattern</c>: <c>\!</c>, <c>\{</c>, <c>\}</c>, <c>\\</c> become literals.</summary>
    public static string UnescapePattern(string input)
    {
        var sb = new StringBuilder(input.Length);
        var runes = input.EnumerateRunes().ToList();
        for (int i = 0; i < runes.Count; i++)
        {
            var ch = runes[i];
            if (ch.Value == '\\')
            {
                if (i + 1 >= runes.Count)
                {
                    throw new PsignException("trailing escape");
                }

                var next = runes[++i];
                if (next.Value is '!' or '{' or '}' or '\\')
                {
                    sb.Append(next.ToString());
                }
                else
                {
                    sb.Append('\\').Append(next.ToString());
                }
            }
            else
            {
                sb.Append(ch.ToString());
            }
        }

        return sb.ToString();
    }

    /// <summary>Rust <c>expand_braces</c>: nested <c>{a,b}</c> lists and <c>{01..10}</c> numeric ranges.</summary>
    public static List<string> ExpandBraces(string pattern)
    {
        if (FirstBrace(pattern) is not { } span)
        {
            return [pattern];
        }

        string before = pattern[..span.Start];
        string body = pattern[(span.Start + 1)..span.End];
        string after = pattern[(span.End + 1)..];
        var output = new List<string>();
        foreach (var choice in BraceChoices(body))
        {
            output.AddRange(ExpandBraces(before + choice + after));
        }

        return output;
    }

    private static (int Start, int End)? FirstBrace(string pattern)
    {
        int? start = null;
        int depth = 0;
        bool escaped = false;
        for (int idx = 0; idx < pattern.Length; idx++)
        {
            char ch = pattern[idx];
            if (escaped)
            {
                escaped = false;
                continue;
            }

            switch (ch)
            {
                case '\\':
                    escaped = true;
                    break;
                case '{':
                    if (depth == 0)
                    {
                        start = idx;
                    }

                    depth++;
                    break;
                case '}':
                    if (depth == 0)
                    {
                        throw new PsignException($"unmatched closing brace in pattern: {pattern}");
                    }

                    depth--;
                    if (depth == 0)
                    {
                        return (start!.Value, idx);
                    }

                    break;
            }
        }

        if (depth != 0)
        {
            throw new PsignException($"unmatched opening brace in pattern: {pattern}");
        }

        return null;
    }

    private static List<string> BraceChoices(string body)
    {
        int dots = body.IndexOf("..", StringComparison.Ordinal);
        if (dots >= 0)
        {
            string startText = body[..dots];
            string endText = body[(dots + 2)..];
            if (TryParseI64(startText, out long first) && TryParseI64(endText, out long last))
            {
                int width = Math.Max(Encoding.UTF8.GetByteCount(startText), Encoding.UTF8.GetByteCount(endText));
                var range = new List<string>();
                if (first <= last)
                {
                    for (long n = first; ; n++)
                    {
                        range.Add(FormatRange(n, width));
                        if (n == last)
                        {
                            break;
                        }
                    }
                }
                else
                {
                    for (long n = first; ; n--)
                    {
                        range.Add(FormatRange(n, width));
                        if (n == last)
                        {
                            break;
                        }
                    }
                }

                return range;
            }
        }

        var choices = new List<string>();
        var current = new StringBuilder();
        int depth = 0;
        foreach (char ch in body)
        {
            switch (ch)
            {
                case '{':
                    depth++;
                    current.Append(ch);
                    break;
                case '}':
                    if (depth == 0)
                    {
                        throw new PsignException($"unmatched closing brace in {body}");
                    }

                    depth--;
                    current.Append(ch);
                    break;
                case ',' when depth == 0:
                    choices.Add(current.ToString());
                    current.Clear();
                    break;
                default:
                    current.Append(ch);
                    break;
            }
        }

        choices.Add(current.ToString());
        return choices;
    }

    /// <summary>Rust <c>str::parse::&lt;i64&gt;</c> (optional sign, ASCII digits).</summary>
    private static bool TryParseI64(string s, out long value)
    {
        value = 0;
        if (s.Length == 0)
        {
            return false;
        }

        int i = s[0] is '+' or '-' ? 1 : 0;
        if (i == s.Length)
        {
            return false;
        }

        for (int k = i; k < s.Length; k++)
        {
            if (s[k] is < '0' or > '9')
            {
                return false;
            }
        }

        return long.TryParse(s, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>Rust <c>format!("{n:0width$}")</c> (the sign counts toward the width) or plain <c>n</c> when width is 1.</summary>
    private static string FormatRange(long n, int width)
    {
        string digits = n < 0 ? (-(decimal)n).ToString(CultureInfo.InvariantCulture) : n.ToString(CultureInfo.InvariantCulture);
        if (width <= 1)
        {
            return n < 0 ? "-" + digits : digits;
        }

        int padTo = n < 0 ? width - 1 : width;
        string padded = digits.Length < padTo ? new string('0', padTo - digits.Length) + digits : digits;
        return n < 0 ? "-" + padded : padded;
    }

    /// <summary>Whether a pattern contains glob metacharacters (Rust <c>has_glob_meta</c>).</summary>
    public static bool HasGlobMeta(string pattern) => pattern.Contains('*') || pattern.Contains('?');

    /// <summary>
    /// Rust <c>glob_match</c>: byte-wise, ASCII case-insensitive; <c>*</c> and <c>?</c> stay within a <c>/</c> segment,
    /// <c>**</c> (optionally followed by <c>/</c>) crosses segments.
    /// </summary>
    public static bool GlobMatch(string pattern, string text)
    {
        var p = Encoding.UTF8.GetBytes(pattern);
        var t = Encoding.UTF8.GetBytes(text);
        var memo = new sbyte[(p.Length + 1) * (t.Length + 1)];
        return GlobMatchInner(p, t, 0, 0, memo);
    }

    private static bool GlobMatchInner(byte[] pattern, byte[] text, int pi, int ti, sbyte[] memo)
    {
        int key = (pi * (text.Length + 1)) + ti;
        if (memo[key] != 0)
        {
            return memo[key] > 0;
        }

        bool result;
        if (pi == pattern.Length)
        {
            result = ti == text.Length;
        }
        else if (pattern[pi] == (byte)'*')
        {
            if (pi + 1 < pattern.Length && pattern[pi + 1] == (byte)'*')
            {
                result = (pi + 2 < pattern.Length && pattern[pi + 2] == (byte)'/' && GlobMatchInner(pattern, text, pi + 3, ti, memo))
                    || GlobMatchInner(pattern, text, pi + 2, ti, memo)
                    || (ti < text.Length && GlobMatchInner(pattern, text, pi, ti + 1, memo));
            }
            else
            {
                result = GlobMatchInner(pattern, text, pi + 1, ti, memo)
                    || (ti < text.Length && text[ti] != (byte)'/' && GlobMatchInner(pattern, text, pi, ti + 1, memo));
            }
        }
        else if (pattern[pi] == (byte)'?')
        {
            result = ti < text.Length && text[ti] != (byte)'/' && GlobMatchInner(pattern, text, pi + 1, ti + 1, memo);
        }
        else
        {
            result = ti < text.Length && AsciiLower(pattern[pi]) == AsciiLower(text[ti]) && GlobMatchInner(pattern, text, pi + 1, ti + 1, memo);
        }

        memo[key] = result ? (sbyte)1 : (sbyte)-1;
        return result;
    }

    private static byte AsciiLower(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;

    /// <summary>Rust <c>pattern_to_native_path</c>: <c>pattern.split('/').collect::&lt;PathBuf&gt;()</c>.</summary>
    internal static string PatternToNativePath(string pattern)
    {
        string buf = string.Empty;
        foreach (var segment in pattern.Split('/'))
        {
            buf = PushSegment(buf, segment);
        }

        return buf;
    }

    private static string PushSegment(string buf, string segment)
    {
        if (segment.Length > 0 && RustPath.IsWindows)
        {
            bool hasDrive = segment.Length >= 2 && char.IsAsciiLetter(segment[0]) && segment[1] == ':';
            if (RustPath.IsAbsolute(segment) || hasDrive)
            {
                return segment;
            }

            if (RustPath.IsSeparator(segment[0]))
            {
                bool bufDrive = buf.Length >= 2 && char.IsAsciiLetter(buf[0]) && buf[1] == ':';
                return (bufDrive ? buf[..2] : string.Empty) + segment;
            }
        }

        return RustPath.Push(buf, segment);
    }

    /// <summary>Reject absolute patterns and traversal outside the base directory (Rust <c>validate_relative_pattern</c>).</summary>
    public static void ValidateRelativePattern(string pattern)
    {
        var path = PatternToNativePath(pattern);
        if (RustPath.IsAbsolute(path))
        {
            throw new PsignException($"absolute patterns are not supported: {pattern}");
        }

        bool traversal;
        if (RustPath.IsWindows)
        {
            bool hasPrefix = path.Length >= 2 && ((char.IsAsciiLetter(path[0]) && path[1] == ':') || (RustPath.IsSeparator(path[0]) && RustPath.IsSeparator(path[1])));
            bool hasRoot = path.Length >= 1 && RustPath.IsSeparator(path[0]);
            traversal = hasPrefix || hasRoot || path.Split(['\\', '/']).Any(p => p == "..");
        }
        else
        {
            traversal = path.StartsWith('/') || path.Split('/').Any(p => p == "..");
        }

        if (traversal)
        {
            throw new PsignException($"pattern may not traverse outside the base directory: {pattern}");
        }
    }
}
