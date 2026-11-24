using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Pe;

namespace Devolutions.Psign.Signing.Remove;

/// <summary>Portable signature removal (port of <c>src/portable_remove.rs</c>).</summary>
public static class PortableRemove
{
    private static readonly string[] PeWinmdExtensions = ["exe", "dll", "sys", "ocx", "efi", "winmd"];
    private static readonly string[] PowerShellExtensions = ["ps1", "psd1", "psm1", "ps1xml", "psc1", "cdxml", "mof"];

    /// <summary>
    /// Run the portable <c>remove</c> command. Only <c>--strip-signature</c> (<c>/s</c>) is supported. Returns the stdout text
    /// (empty when <paramref name="quiet"/>).
    /// </summary>
    public static string RemoveCommand(IEnumerable<string> files, bool stripSignature, bool stripChainExceptSigner, bool stripUnauthenticatedAttributes, bool quiet)
    {
        if (!stripSignature || stripChainExceptSigner || stripUnauthenticatedAttributes)
        {
            throw new PsignException(
                "portable remove supports only --strip-signature (/s); partial embedded CMS removal (/c or /u) requires Windows mode");
        }

        var output = new StringBuilder();
        foreach (var path in files)
        {
            var ext = ExtensionLower(path);
            bool removed;
            if (PeWinmdExtensions.Contains(ext))
            {
                removed = RemovePeSignature(path);
            }
            else if (PowerShellExtensions.Contains(ext))
            {
                removed = RemovePowerShellSignature(path, ext);
            }
            else
            {
                throw new PsignException(
                    $"portable remove supports PE/WinMD and PowerShell Authenticode scripts (.ps1, .psd1, .psm1, .ps1xml, .psc1, .cdxml, .mof); got {path}");
            }

            if (!quiet)
            {
                output.Append(removed
                    ? $"Removed embedded Authenticode data from {path}\n"
                    : $"No embedded Authenticode data found in {path}\n");
            }
        }

        return output.ToString();
    }

    /// <summary>Remove all PE/WinMD Authenticode certificates in place. Returns true when something was removed.</summary>
    public static bool RemovePeSignature(string path)
    {
        var bytes = ReadFile(path);
        byte[] unsigned;
        int removed;
        try
        {
            (unsigned, removed) = PeEmbed.RemoveCertificates(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"remove PE/WinMD Authenticode signature from '{path}'", e);
        }

        if (removed > 0)
        {
            WriteFile(path, unsigned, $"write unsigned PE/WinMD '{path}'");
        }

        return removed > 0;
    }

    /// <summary>Remove a PowerShell-class signature block in place, preserving the file encoding.</summary>
    public static bool RemovePowerShellSignature(string path, string ext)
    {
        var bytes = ReadFile(path);
        (string content, ScriptEncoding encoding) decoded;
        try
        {
            decoded = ScriptEncodingExtensions.Decode(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"decode PowerShell script '{path}'", e);
        }

        var unsigned = RemoveScriptSignatureBlock(decoded.content, ext);
        if (unsigned is null)
        {
            return false;
        }

        WriteFile(path, decoded.encoding.Encode(unsigned), $"write unsigned PowerShell script '{path}'");
        return true;
    }

    /// <summary>Remove the trailing signature block (and its surrounding newline) or return <c>null</c>.</summary>
    public static string? RemoveScriptSignatureBlock(string content, string ext)
    {
        ext = ext.TrimStart('.').ToLowerInvariant();
        var (begin, end) = ext switch
        {
            "ps1xml" or "psc1" or "cdxml" => ("<!-- SIG # Begin signature block -->", "<!-- SIG # End signature block -->"),
            "mof" => ("/* SIG # Begin signature block */", "/* SIG # End signature block */"),
            _ => ("# SIG # Begin signature block", "# SIG # End signature block"),
        };
        int beginAt = content.LastIndexOf(begin, StringComparison.Ordinal);
        if (beginAt < 0 || (beginAt > 0 && content[beginAt - 1] is not ('\n' or '\r')))
        {
            return null;
        }

        int bodyStart = beginAt + begin.Length;
        int rel = content.IndexOf(end, bodyStart, StringComparison.Ordinal);
        if (rel < 0)
        {
            return null;
        }

        int endAt = rel;
        int afterEnd = endAt + end.Length;
        if (content[afterEnd..].Trim().Length != 0 || !IsAuthenticodeSignatureBlock(content[bodyStart..endAt], ext))
        {
            return null;
        }

        int removeStart = beginAt;
        if (content[..beginAt].EndsWith("\r\n", StringComparison.Ordinal))
        {
            removeStart -= 2;
        }
        else if (content[..beginAt].EndsWith('\n'))
        {
            removeStart -= 1;
        }

        int removeEnd = afterEnd;
        if (content[removeEnd..].StartsWith("\r\n", StringComparison.Ordinal))
        {
            removeEnd += 2;
        }
        else if (content[removeEnd..].StartsWith('\n'))
        {
            removeEnd += 1;
        }

        return string.Concat(content.AsSpan(0, removeStart), content.AsSpan(removeEnd));
    }

    /// <summary>True when every non-empty line is a comment wrapping base64 and the payload decodes.</summary>
    public static bool IsAuthenticodeSignatureBlock(string body, string ext)
    {
        ext = ext.TrimStart('.').ToLowerInvariant();
        var payload = new StringBuilder();
        foreach (var raw in body.Split('\n'))
        {
            var line = raw.TrimEnd('\r').Trim();
            if (line.Length == 0)
            {
                continue;
            }

            string? encoded = ext switch
            {
                "ps1xml" or "psc1" or "cdxml" => line.StartsWith("<!-- ", StringComparison.Ordinal) && line.EndsWith(" -->", StringComparison.Ordinal) && line.Length >= 9 ? line[5..^4] : null,
                "mof" => line.StartsWith("/* ", StringComparison.Ordinal) && line.EndsWith(" */", StringComparison.Ordinal) && line.Length >= 6 ? line[3..^3] : null,
                _ => line.StartsWith("# ", StringComparison.Ordinal) ? line[2..] : null,
            };
            if (encoded is null)
            {
                return false;
            }

            payload.Append(encoded);
        }

        if (payload.Length == 0)
        {
            return false;
        }

        var s = payload.ToString();
        if (s.Any(char.IsWhiteSpace))
        {
            return false;
        }

        var buffer = new byte[s.Length];
        return Convert.TryFromBase64String(s, buffer, out _);
    }

    private static string ExtensionLower(string path)
    {
        var ext = Path.GetExtension(path);
        return string.IsNullOrEmpty(ext) ? string.Empty : ext[1..].ToLowerInvariant();
    }

    private static byte[] ReadFile(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"read '{path}'", e);
        }
    }

    private static void WriteFile(string path, byte[] bytes, string context)
    {
        try
        {
            File.WriteAllBytes(path, bytes);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException(context, e);
        }
    }
}

/// <summary>Script text encoding detected from a BOM.</summary>
public enum ScriptEncoding
{
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
}

/// <summary>Decode / encode helpers for <see cref="ScriptEncoding"/>.</summary>
public static class ScriptEncodingExtensions
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static (string Content, ScriptEncoding Encoding) Decode(byte[] bytes)
    {
        try
        {
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            {
                return (StrictUtf8.GetString(bytes, 3, bytes.Length - 3), ScriptEncoding.Utf8Bom);
            }
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("invalid UTF-8 with BOM", e);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return (DecodeUtf16(bytes.AsSpan(2), littleEndian: true), ScriptEncoding.Utf16Le);
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return (DecodeUtf16(bytes.AsSpan(2), littleEndian: false), ScriptEncoding.Utf16Be);
        }

        try
        {
            return (StrictUtf8.GetString(bytes), ScriptEncoding.Utf8);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("invalid UTF-8 script", e);
        }
    }

    public static byte[] Encode(this ScriptEncoding encoding, string content) => encoding switch
    {
        ScriptEncoding.Utf8 => Encoding.UTF8.GetBytes(content),
        ScriptEncoding.Utf8Bom => [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes(content)],
        ScriptEncoding.Utf16Le => [0xFF, 0xFE, .. Encoding.Unicode.GetBytes(content)],
        _ => [0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes(content)],
    };

    private static string DecodeUtf16(ReadOnlySpan<byte> bytes, bool littleEndian)
    {
        if (bytes.Length % 2 != 0)
        {
            throw new PsignException("UTF-16 script has an odd byte length");
        }

        try
        {
            return new UnicodeEncoding(!littleEndian, false, true).GetString(bytes);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("invalid UTF-16 script", e);
        }
    }
}
