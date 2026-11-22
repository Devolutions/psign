using System.Text;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.Scripts;

/// <summary>Verified script digest binding: the embedded PKCS#7 plus embedded and recomputed digests (Rust <c>ScriptAuthenticodeDigestReport</c>).</summary>
public sealed record ScriptAuthenticodeDigestReport(byte[] Pkcs7Der, byte[] EmbeddedDigest, byte[] ComputedDigest);

/// <summary>Signature-block marker family used by <c>pwrshsip.dll</c> (Rust <c>MarkerFamily</c>).</summary>
public enum PowerShellMarkerFamily
{
    /// <summary><c># SIG # ...</c> (<c>.ps1</c>, <c>.psd1</c>, <c>.psm1</c>).</summary>
    Hash,

    /// <summary><c>&lt;!-- SIG # ... --&gt;</c> (<c>.ps1xml</c>, <c>.psc1</c>, <c>.cdxml</c>).</summary>
    Xml,

    /// <summary><c>/* SIG # ... */</c> (<c>.mof</c>).</summary>
    Mof,
}

/// <summary>
/// PowerShell-class Authenticode (<c>pwrshsip.dll</c>) digest parity vs PKCS#7 indirect data (port of
/// <c>ps_script.rs</c>). Hashing is a UTF-16 range-removal heuristic: the signature block is stripped from the UTF-16
/// view of the file and the remaining code units are hashed as little-endian bytes.
/// </summary>
public static class PsScript
{
    private static readonly string[] SupportedExtensions = ["ps1", "psd1", "psm1", "ps1xml", "psc1", "cdxml", "mof"];
    private static readonly string[] WshExtensions = ["js", "jse", "vbs", "vbe", "wsf"];

    /// <summary>Marker family for an extension (Rust <c>marker_family</c>).</summary>
    public static PowerShellMarkerFamily MarkerFamily(string ext) => RustText.ToAsciiLowercase(ext) switch
    {
        "ps1" or "psd1" or "psm1" => PowerShellMarkerFamily.Hash,
        "ps1xml" or "psc1" or "cdxml" => PowerShellMarkerFamily.Xml,
        "mof" => PowerShellMarkerFamily.Mof,
        _ => throw new PsignException($"extension .{ext} is not handled by pwrshsip-style markers"),
    };

    /// <summary>Extensions whose digest logic is implemented via <c>pwrshsip</c>-style markers.</summary>
    public static bool ExtensionSupported(string ext) => SupportedExtensions.Contains(RustText.ToAsciiLowercase(ext));

    /// <summary>True for Windows Script Host extensions (<c>js</c>, <c>jse</c>, <c>vbs</c>, <c>vbe</c>, <c>wsf</c>).</summary>
    public static bool IsWshExtension(string ext) => WshExtensions.Contains(RustText.ToAsciiLowercase(ext));

    /// <summary>
    /// Decode file bytes to UTF-16 code units (BOM-aware LE/BE, BOM excluded; otherwise lossy UTF-8 → UTF-16 with a UTF-8
    /// BOM preserved as U+FEFF). Rust <c>file_utf16_units</c>.
    /// </summary>
    public static char[] FileUtf16Units(ReadOnlySpan<byte> raw)
    {
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        {
            return RustText.Utf16LeUnits(raw[2..]);
        }

        if (raw.Length >= 2 && raw[0] == 0xFE && raw[1] == 0xFF)
        {
            return RustText.Utf16BeUnits(raw[2..]);
        }

        return RustText.FromUtf8Lossy(raw).ToCharArray();
    }

    /// <summary>UTF-16 code units as little-endian bytes (Rust <c>utf16le_bytes</c>).</summary>
    public static byte[] Utf16LeBytes(ReadOnlySpan<char> units) => RustText.Utf16LeBytes(units);

    /// <summary>Hash <paramref name="payload"/> with <paramref name="kind"/> (Rust <c>hash_payload</c>).</summary>
    public static byte[] HashPayload(AuthenticodeHashKind kind, ReadOnlySpan<byte> payload) => kind.Hash(payload);

    /// <summary>The four marker strings (begin with CRLF, begin, end with CRLF, end) for a family.</summary>
    internal static (string BeginCr, string Begin, string EndCr, string End) Markers(PowerShellMarkerFamily family) => family switch
    {
        PowerShellMarkerFamily.Hash => (
            "\r\n# SIG # Begin signature block\r\n",
            "# SIG # Begin signature block",
            "# SIG # End signature block\r\n",
            "# SIG # End signature block"),
        PowerShellMarkerFamily.Xml => (
            "\r\n<!-- SIG # Begin signature block -->\r\n",
            "<!-- SIG # Begin signature block -->",
            "<!-- SIG # End signature block -->\r\n",
            "<!-- SIG # End signature block -->"),
        _ => (
            "\r\n/* SIG # Begin signature block */\r\n",
            "/* SIG # Begin signature block */",
            "/* SIG # End signature block */\r\n",
            "/* SIG # End signature block */"),
    };

    /// <summary>Remove the signature block from a UTF-16 view of the file (Rust <c>strip_signature_region_utf16</c>).</summary>
    public static char[] StripSignatureRegionUtf16(ReadOnlySpan<char> units, PowerShellMarkerFamily family)
    {
        var (beginCr, begin, endCr, end) = Markers(family);
        int start = RustText.IndexOf(units, beginCr);
        if (start < 0)
        {
            start = RustText.IndexOf(units, begin);
        }

        if (start < 0)
        {
            throw new PsignException("signature begin marker not found when interpreting file as UTF-16");
        }

        var tail = units[start..];
        int endRel;
        int patLen;
        int i = RustText.IndexOf(tail, endCr);
        if (i >= 0)
        {
            endRel = i;
            patLen = endCr.Length;
        }
        else if ((i = RustText.IndexOf(tail, end)) >= 0)
        {
            endRel = i;
            patLen = end.Length;
        }
        else
        {
            throw new PsignException("signature end marker not found when interpreting file as UTF-16");
        }

        int endExclusive = start + endRel + patLen;
        var result = new char[start + (units.Length - endExclusive)];
        units[..start].CopyTo(result);
        units[endExclusive..].CopyTo(result.AsSpan(start));
        return result;
    }

    private static bool LooksLikeB64Token(string s) =>
        s.Length >= 4 && s.All(c => RustText.IsAsciiAlphanumeric(c) || c == '+' || c == '/' || c == '=');

    private static char[] VerifierUnits(ReadOnlySpan<byte> raw)
    {
        var units = FileUtf16Units(raw);
        if (raw.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE]))
        {
            var withBom = new char[units.Length + 1];
            withBom[0] = '﻿';
            units.CopyTo(withBom, 1);
            return withBom;
        }

        return units;
    }

    /// <summary>Extract PKCS#7 DER from the signature block of a PowerShell-class script (Rust <c>extract_pkcs7_der_from_script</c>).</summary>
    public static byte[] ExtractPkcs7Der(ReadOnlySpan<byte> raw, PowerShellMarkerFamily family)
    {
        var text = RustText.FromUtf16Lossy(VerifierUnits(raw));
        var (beginPat, endPat) = family switch
        {
            PowerShellMarkerFamily.Hash => ("# SIG # Begin signature block", "# SIG # End signature block"),
            PowerShellMarkerFamily.Xml => ("<!-- SIG # Begin signature block -->", "<!-- SIG # End signature block -->"),
            _ => ("/* SIG # Begin signature block */", "/* SIG # End signature block */"),
        };
        int start = text.IndexOf(beginPat, StringComparison.Ordinal);
        if (start < 0)
        {
            throw new PsignException("signature begin not found (UTF-8 lossy view)");
        }

        var tail = text[start..];
        int endRel = tail.IndexOf(endPat, StringComparison.Ordinal);
        if (endRel < 0)
        {
            throw new PsignException("signature end not found (UTF-8 lossy view)");
        }

        var block = tail[..(endRel + endPat.Length)];
        var b64 = new StringBuilder();
        foreach (var line in RustText.Lines(block))
        {
            var t = line.Trim();
            string? token = null;
            switch (family)
            {
                case PowerShellMarkerFamily.Hash:
                    if (t.StartsWith("# ", StringComparison.Ordinal))
                    {
                        token = t[2..].Trim();
                    }

                    break;
                case PowerShellMarkerFamily.Xml:
                    if (t.StartsWith("<!--", StringComparison.Ordinal) && t.Length >= 7 && t.EndsWith("-->", StringComparison.Ordinal))
                    {
                        token = t[4..^3].Trim();
                    }

                    break;
                default:
                    if (t.StartsWith("/*", StringComparison.Ordinal) && t.Length >= 4 && t.EndsWith("*/", StringComparison.Ordinal))
                    {
                        token = t[2..^2].Trim();
                    }

                    break;
            }

            if (token is not null && LooksLikeB64Token(token))
            {
                b64.Append(token);
            }
        }

        if (b64.Length == 0)
        {
            throw new PsignException("no base64 tokens parsed inside signature block");
        }

        try
        {
            return Base64Standard.Decode(b64.ToString().Trim());
        }
        catch (FormatException e)
        {
            throw new PsignException($"base64 decode: {e.Message}", e);
        }
    }

    /// <summary>
    /// Compare the PKCS#7 indirect digest with a UTF-16 hash over the file excluding the signature block (Rust
    /// <c>powershell_class_digest_report</c>).
    /// </summary>
    public static ScriptAuthenticodeDigestReport PowerShellClassDigestReport(ReadOnlySpan<byte> raw, string ext)
    {
        var extL = RustText.ToAsciiLowercase(ext);
        if (!ExtensionSupported(extL))
        {
            throw new PsignException($"Rust SIP script digest does not support extension .{extL}");
        }

        var family = MarkerFamily(extL);
        var pkcs7 = ExtractPkcs7Der(raw, family);
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
        var kind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
        var stripped = StripSignatureRegionUtf16(VerifierUnits(raw), family);
        var computed = HashPayload(kind, Utf16LeBytes(stripped));
        if (!computed.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException("script Authenticode digest mismatch (experimental UTF-16 strip heuristic vs PKCS#7)");
        }

        return new ScriptAuthenticodeDigestReport(pkcs7, embedded.ToArray(), computed);
    }

    /// <summary>Verify the PowerShell-class digest binding (Rust <c>verify_powershell_class_digest</c>).</summary>
    public static void VerifyPowerShellClassDigest(ReadOnlySpan<byte> raw, string ext) => PowerShellClassDigestReport(raw, ext);

    /// <summary>
    /// Digest that a signer embeds for a PowerShell-class script: hash of the UTF-16LE bytes of
    /// <see cref="FileUtf16Units"/> (the whole unsigned file). Used by
    /// <c>script_authenticode_spc_indirect_data</c>.
    /// </summary>
    public static byte[] SigningDigest(ReadOnlySpan<byte> script, AuthenticodeHashKind kind) =>
        HashPayload(kind, Utf16LeBytes(FileUtf16Units(script)));
}
