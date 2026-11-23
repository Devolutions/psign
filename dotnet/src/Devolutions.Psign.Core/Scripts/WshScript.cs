using System.Text;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.Scripts;

/// <summary>Windows Script Host subject kind (Rust <c>WshKind</c>).</summary>
public enum WshKind
{
    /// <summary><c>.vbs</c> / <c>.vbe</c> — <c>OID_VBSSIP</c>.</summary>
    Vbs,

    /// <summary><c>.js</c> / <c>.jse</c> — <c>OID_JSSIP</c>.</summary>
    Js,

    /// <summary><c>.wsf</c>.</summary>
    Wsf,
}

/// <summary>
/// Windows Script Host Authenticode (<c>wshext.dll</c>) — PKCS#7 indirect digest vs recomputed hash (port of
/// <c>wsh_script.rs</c>). <c>HashFile</c> hashes the UTF-16LE bytes of the stripped script followed by a little-endian
/// <c>u32</c> equal to the UTF-16 index of the begin marker in the original subject.
/// </summary>
public static class WshScript
{
    /// <summary>Classify a WSH extension (case-insensitive), or <c>null</c>.</summary>
    public static WshKind? WshKindFromExt(string ext) => RustText.ToAsciiLowercase(ext) switch
    {
        "vbs" or "vbe" => WshKind.Vbs,
        "js" or "jse" => WshKind.Js,
        "wsf" => WshKind.Wsf,
        _ => null,
    };

    /// <summary>Begin marker (<c>BegSigBlock</c>).</summary>
    public static string BeginMarker(WshKind kind) => kind switch
    {
        WshKind.Vbs => "\r\n'' SIG '' Begin signature block",
        WshKind.Js => "\r\n// SIG // Begin signature block",
        _ => "\r\n<signature>",
    };

    /// <summary>End marker (<c>EndSigBlock</c>).</summary>
    public static string EndMarker(WshKind kind) => kind switch
    {
        WshKind.Vbs => "\r\n'' SIG '' End signature block\r\n",
        WshKind.Js => "\r\n// SIG // End signature block\r\n",
        _ => "\r\n</signature>\r\n",
    };

    /// <summary>Line-local prefix inside the signature block (<c>Comment</c> without the leading CRLF).</summary>
    public static string SigLinePrefix(WshKind kind) => kind switch
    {
        WshKind.Vbs => "'' SIG '' ",
        WshKind.Js => "// SIG // ",
        _ => "** SIG ** ",
    };

    private static ReadOnlySpan<char> TrimCr(ReadOnlySpan<char> line)
    {
        while (!line.IsEmpty && line[0] == '\r')
        {
            line = line[1..];
        }

        while (!line.IsEmpty && line[^1] == '\r')
        {
            line = line[..^1];
        }

        return line;
    }

    private static List<(int Start, int Length)> SplitLinesUtf16(ReadOnlySpan<char> region)
    {
        var lines = new List<(int, int)>();
        int pos = 0;
        while (pos < region.Length)
        {
            int i = region[pos..].IndexOf('\n');
            if (i >= 0)
            {
                lines.Add((pos, i));
                pos += i + 1;
            }
            else
            {
                lines.Add((pos, region.Length - pos));
                pos = region.Length;
            }
        }

        return lines;
    }

    /// <summary>Collect the ASCII base64 payload of the signature region (Rust <c>extract_base64_ascii</c>).</summary>
    public static byte[] ExtractBase64Ascii(ReadOnlySpan<char> region, WshKind kind)
    {
        var prefix = SigLinePrefix(kind);
        var ascii = new StringBuilder();
        foreach (var (start, length) in SplitLinesUtf16(region))
        {
            var line = TrimCr(region.Slice(start, length));
            if (line.IsEmpty)
            {
                continue;
            }

            if (!line.StartsWith(prefix, StringComparison.Ordinal))
            {
                throw new PsignException($"WSH signature region line missing {DebugString(prefix)} prefix");
            }

            foreach (char cu in line[prefix.Length..])
            {
                if (cu < 128)
                {
                    ascii.Append(cu);
                }
                else
                {
                    throw new PsignException("non-ASCII in WSH base64 payload");
                }
            }
        }

        var trimmed = new StringBuilder();
        foreach (char c in ascii.ToString())
        {
            if (!char.IsWhiteSpace(c))
            {
                trimmed.Append(c);
            }
        }

        if (trimmed.Length == 0)
        {
            throw new PsignException("empty WSH base64 payload");
        }

        return Encoding.ASCII.GetBytes(trimmed.ToString());
    }

    /// <summary>
    /// Strip the last WSH signature block; returns the remaining units and the UTF-16 index of the begin marker (Rust
    /// <c>strip_wsh_signature_units</c>).
    /// </summary>
    public static (char[] Stripped, uint BeginOffset) StripWshSignatureUnits(ReadOnlySpan<char> units, WshKind kind)
    {
        var beg = BeginMarker(kind);
        int last = RustText.LastIndexOf(units, beg);
        if (last < 0)
        {
            throw new PsignException($"WSH begin signature marker not found ({DebugString(beg)})");
        }

        var tail = units[last..];
        var end = EndMarker(kind);
        int er = RustText.IndexOf(tail, end);
        if (er < 0)
        {
            throw new PsignException("WSH end signature marker not found");
        }

        int after = last + er + end.Length;
        var result = new char[last + (units.Length - after)];
        units[..last].CopyTo(result);
        units[after..].CopyTo(result.AsSpan(last));
        return (result, (uint)last);
    }

    /// <summary>Extract PKCS#7 DER from the last WSH signature block (Rust <c>extract_pkcs7_der</c>).</summary>
    public static byte[] ExtractPkcs7Der(ReadOnlySpan<char> units, WshKind kind)
    {
        var beg = BeginMarker(kind);
        int last = RustText.LastIndexOf(units, beg);
        if (last < 0)
        {
            throw new PsignException("WSH begin marker not found");
        }

        var tail = units[(last + beg.Length)..];
        int er = RustText.IndexOf(tail, EndMarker(kind));
        if (er < 0)
        {
            throw new PsignException("WSH end marker not found");
        }

        var ascii = ExtractBase64Ascii(tail[..er], kind);
        try
        {
            return Base64Standard.Decode(ascii);
        }
        catch (FormatException e)
        {
            throw new PsignException($"WSH base64 decode: {e.Message}", e);
        }
    }

    /// <summary>Verify the WSH digest binding (Rust <c>verify_wsh_digest_consistency</c>).</summary>
    public static void VerifyWshDigestConsistency(ReadOnlySpan<byte> raw, string ext) => WshDigestReport(raw, ext);

    /// <summary>
    /// Decode file bytes for WSH processing: <see cref="PsScript.FileUtf16Units"/> with a leading UTF-8 BOM removed.
    /// </summary>
    public static char[] SubjectUnits(ReadOnlySpan<byte> raw)
    {
        var units = PsScript.FileUtf16Units(raw);
        if (raw.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]) && units.Length > 0 && units[0] == '﻿')
        {
            return units[1..];
        }

        return units;
    }

    /// <summary>Verify the WSH digest binding and return the PKCS#7 with embedded and recomputed digests (Rust <c>wsh_digest_report</c>).</summary>
    public static ScriptAuthenticodeDigestReport WshDigestReport(ReadOnlySpan<byte> raw, string ext)
    {
        var kind = WshKindFromExt(ext) ?? throw new PsignException($"not a WSH script extension .{ext}");
        var units = SubjectUnits(raw);
        var pkcs7 = ExtractPkcs7Der(units, kind);
        AuthenticodeSignature sig;
        try
        {
            sig = AuthenticodeSignature.Parse(pkcs7);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            throw new PsignException($"Authenticode PKCS#7 parse failed: {e.Message}", e);
        }

        var embedded = sig.Digest;
        var hkind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
        var (stripped, beginOff) = StripWshSignatureUnits(units, kind);
        var payload = new byte[(stripped.Length * 2) + 4];
        RustText.Utf16LeBytes(stripped).CopyTo(payload, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(payload.AsSpan(stripped.Length * 2), beginOff);
        var computed = PsScript.HashPayload(hkind, payload);
        if (!computed.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException("WSH Authenticode digest mismatch (wshext strip + offset dword vs PKCS#7)");
        }

        return new ScriptAuthenticodeDigestReport(pkcs7, embedded.ToArray(), computed);
    }

    /// <summary>Rust <c>{:?}</c> rendering of a <c>&amp;str</c> (quoted; CR, LF, TAB, double quote and backslash escaped).</summary>
    internal static string DebugString(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (char c in s)
        {
            sb.Append(c switch
            {
                '\r' => "\\r",
                '\n' => "\\n",
                '\t' => "\\t",
                '"' => "\\\"",
                '\\' => "\\\\",
                _ => c.ToString(),
            });
        }

        sb.Append('"');
        return sb.ToString();
    }
}
