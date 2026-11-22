using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.Framework;

/// <summary>Expand native <c>signtool @responsefile</c> argument lists (port of <c>src/response_argv.rs</c>).</summary>
public static class ResponseArgv
{
    private const int MaxResponseDepth = 8;
    private const int MaxResponseLines = 4096;

    /// <summary>Azure-style partial success exit code (<c>0x20000001</c>).</summary>
    public const int AzureSignExitPartialSuccess = 0x2000_0001;

    /// <summary>Azure-style all-failed exit code (<c>0xA0000002</c>).</summary>
    public const int AzureSignExitAllFailed = unchecked((int)0xA000_0002);

    private static string? ResponsePath(string arg)
    {
        if (!arg.StartsWith('@') || arg.Length == 1 || arg.StartsWith("@@", StringComparison.Ordinal))
        {
            return null;
        }

        return arg[1..];
    }

    private static string Utf16(ReadOnlySpan<byte> bytes, bool bigEndian)
    {
        if (bytes.Length % 2 != 0)
        {
            throw new PsignException($"response file UTF-16 payload has odd length ({bytes.Length} bytes)");
        }

        try
        {
            var enc = new UnicodeEncoding(bigEndian, byteOrderMark: false, throwOnInvalidBytes: true);
            return enc.GetString(bytes);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException($"response file UTF-16 decode failed: {e.Message}");
        }
    }

    private static string ReadText(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"reading response file {path}", new PsignException(Output.IoMessage(e)));
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            try
            {
                return new UTF8Encoding(false, true).GetString(bytes, 3, bytes.Length - 3);
            }
            catch (DecoderFallbackException e)
            {
                throw new PsignException($"response file {path} is not valid UTF-8 after BOM strip: {e.Message}");
            }
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return Utf16(bytes.AsSpan(2), false);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return Utf16(bytes.AsSpan(2), true);
        }

        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException e)
        {
            try
            {
                return Utf16(bytes, false);
            }
            catch (PsignException e2)
            {
                throw new PsignException($"response file {path}: invalid UTF-8 ({e.Message}); UTF-16-LE fallback failed: {e2.Message}");
            }
        }
    }

    private static IEnumerable<string> Lines(string text)
    {
        // Rust str::lines: split on \n, strip a trailing \r, no final empty line.
        var parts = text.Split('\n');
        int count = parts.Length;
        if (count > 0 && parts[^1].Length == 0)
        {
            count--;
        }

        for (int i = 0; i < count; i++)
        {
            var l = parts[i];
            yield return l.EndsWith('\r') ? l[..^1] : l;
        }
    }

    private static string NormalizedLine(string line) => line.TrimEnd('\r').Trim();

    private static string DecodeToken(string line)
    {
        var t = line.Trim();
        if (t.Length >= 2 && t[0] == '"' && t[^1] == '"')
        {
            return t[1..^1].Replace("\"\"", "\"", StringComparison.Ordinal);
        }

        return t;
    }

    private static void AppendLine(List<string> output, string rawLine, int depth)
    {
        var t = NormalizedLine(rawLine);
        if (t.Length == 0)
        {
            return;
        }

        var decoded = DecodeToken(t);
        if (decoded.Length > 1 && decoded[0] == '@')
        {
            output.AddRange(ReadFlat(decoded[1..], depth + 1));
        }
        else
        {
            output.Add(decoded);
        }
    }

    private static List<string> ReadFlat(string path, int depth)
    {
        if (depth > MaxResponseDepth)
        {
            throw new PsignException($"response file nesting exceeds {MaxResponseDepth} (@-includes are too deep)");
        }

        var text = ReadText(path);
        var output = new List<string>();
        int seen = 0;
        foreach (var line in Lines(text))
        {
            if (++seen > MaxResponseLines)
            {
                throw new PsignException($"response file {path} exceeds {MaxResponseLines} lines");
            }

            AppendLine(output, line, depth);
        }

        return output;
    }

    private static List<List<string>> ParseBlocks(string text)
    {
        var blocks = new List<List<string>>();
        var current = new List<string>();
        int seen = 0;
        foreach (var line in Lines(text))
        {
            if (++seen > MaxResponseLines)
            {
                throw new PsignException($"response file exceeds {MaxResponseLines} lines");
            }

            if (NormalizedLine(line).Length == 0)
            {
                if (current.Count > 0)
                {
                    blocks.Add(current);
                    current = [];
                }

                continue;
            }

            AppendLine(current, line, 0);
        }

        if (current.Count > 0)
        {
            blocks.Add(current);
        }

        if (blocks.Count == 0)
        {
            throw new PsignException("response file is empty (no arguments)");
        }

        return blocks;
    }

    /// <summary>Build one or more argv lists (without the executable).</summary>
    public static List<List<string>> ExpandInvocations(IReadOnlyList<string> tail)
    {
        if (tail.Count == 1 && ResponsePath(tail[0]) is { } p)
        {
            return ParseBlocks(ReadText(p));
        }

        var output = new List<string>(tail.Count);
        foreach (var arg in tail)
        {
            if (arg.StartsWith("@@", StringComparison.Ordinal))
            {
                output.Add(arg.Length == 2 ? "@" : arg[1..]);
                continue;
            }

            if (ResponsePath(arg) is { } path)
            {
                output.AddRange(ReadFlat(path, 0));
            }
            else
            {
                output.Add(arg);
            }
        }

        return [output];
    }

    /// <summary>Combine exit codes like a batch.</summary>
    public static int CombineBatchExitCodes(int acc, int next)
    {
        if (acc == 1 || next == 1)
        {
            return 1;
        }

        if (acc == AzureSignExitAllFailed || next == AzureSignExitAllFailed)
        {
            return AzureSignExitAllFailed;
        }

        if (acc == AzureSignExitPartialSuccess || next == AzureSignExitPartialSuccess)
        {
            return AzureSignExitPartialSuccess;
        }

        return acc == 2 || next == 2 ? 2 : 0;
    }
}
