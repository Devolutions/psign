using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.Zip;

/// <summary>Located ZIP end-of-central-directory record (Rust <c>ZipEocd</c>).</summary>
public readonly record struct ZipEocd(int Offset, int CommentOffset, int CommentLength);

/// <summary>Parsed <c>ZipAuthenticode=</c> comment payload (Rust <c>ZipAuthenticodeSignature</c>).</summary>
public sealed record ZipAuthenticodeSignature(string Digest, string Pkcs7Base64);

/// <summary>
/// Devolutions ZIP Authenticode convention (port of <c>zip_authenticode.rs</c>; see <c>docs/zip-authenticode-signing.md</c>).
/// Not a Windows SIP: the ZIP EOCD comment stores a single <c>ZipAuthenticode=&lt;zip digest&gt;,&lt;PowerShell
/// Authenticode PKCS#7&gt;</c> line.
/// </summary>
public static class ZipAuthenticode
{
    private const int EocdLen = 22;
    private const int EocdCommentLenOffset = 20;

    /// <summary>Maximum ZIP comment length.</summary>
    public const int MaxZipCommentLen = 65_535;

    /// <summary>Comment line prefix.</summary>
    public const string ZipAuthenticodePrefix = "ZipAuthenticode=";

    /// <summary>Digest string prefix.</summary>
    public const string Sha256DigestPrefix = "sha256:";

    /// <summary>PowerShell signature block begin marker.</summary>
    public const string BeginSigBlock = "# SIG # Begin signature block";

    /// <summary>PowerShell signature block end marker.</summary>
    public const string EndSigBlock = "# SIG # End signature block";

    private static ReadOnlySpan<byte> EocdSig => [0x50, 0x4b, 0x05, 0x06];

    /// <summary>
    /// Locate the EOCD record whose comment ends exactly at EOF, scanning backwards over the last
    /// <c>22 + 65535</c> bytes (Rust <c>find_eocd</c>).
    /// </summary>
    public static ZipEocd FindEocd(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < EocdLen)
        {
            throw new PsignException("ZIP file is too short to contain an EOCD record");
        }

        int lastPossible = bytes.Length - EocdLen;
        int firstPossible = Math.Max(0, bytes.Length - (EocdLen + MaxZipCommentLen));
        for (int offset = lastPossible; offset >= firstPossible; offset--)
        {
            if (!bytes.Slice(offset, 4).SequenceEqual(EocdSig))
            {
                continue;
            }

            int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(offset + EocdCommentLenOffset, 2));
            int commentOffset = offset + EocdLen;
            if (commentOffset + commentLen == bytes.Length)
            {
                return new ZipEocd(offset, commentOffset, commentLen);
            }
        }

        throw new PsignException("could not find a valid ZIP end-of-central-directory record");
    }

    /// <summary>The ZIP comment bytes (Rust <c>zip_comment</c>).</summary>
    public static byte[] ZipComment(ReadOnlySpan<byte> bytes)
    {
        var eocd = FindEocd(bytes);
        return bytes.Slice(eocd.CommentOffset, eocd.CommentLength).ToArray();
    }

    /// <summary>
    /// SHA-256 over the ZIP bytes through the EOCD record with the comment-length field zeroed and the comment excluded
    /// (Rust <c>compute_zip_authenticode_digest</c>).
    /// </summary>
    public static byte[] ComputeZipAuthenticodeDigest(ReadOnlySpan<byte> bytes)
    {
        var eocd = FindEocd(bytes);
        var tbs = bytes[..eocd.CommentOffset].ToArray();
        tbs[eocd.Offset + EocdCommentLenOffset] = 0;
        tbs[eocd.Offset + EocdCommentLenOffset + 1] = 0;
        return SHA256.HashData(tbs);
    }

    /// <summary><c>sha256:&lt;64 lowercase hex&gt;</c> digest string (Rust <c>zip_authenticode_digest_string</c>).</summary>
    public static string ZipAuthenticodeDigestString(ReadOnlySpan<byte> bytes) =>
        Sha256DigestPrefix + Hex.Lower(ComputeZipAuthenticodeDigest(bytes));

    /// <summary>First trimmed comment line starting with <c>ZipAuthenticode=</c> (Rust <c>signature_comment_line</c>).</summary>
    public static string SignatureCommentLine(ReadOnlySpan<byte> bytes)
    {
        var comment = ZipComment(bytes);
        var text = RustText.FromUtf8Strict(comment, "ZIP comment is not UTF-8");
        foreach (var line in RustText.Lines(text))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(ZipAuthenticodePrefix, StringComparison.Ordinal))
            {
                return trimmed;
            }
        }

        throw new PsignException("ZIP Authenticode signature comment not found");
    }

    /// <summary>True for <c>sha256:</c> followed by exactly 64 ASCII hex digits (either case).</summary>
    public static bool IsSha256DigestString(string value) =>
        value.Length == Sha256DigestPrefix.Length + 64
        && value.StartsWith(Sha256DigestPrefix, StringComparison.Ordinal)
        && value[Sha256DigestPrefix.Length..].All(RustText.IsAsciiHexDigit);

    /// <summary>Parse and validate a <c>ZipAuthenticode=</c> comment line (Rust <c>parse_signature_comment_line</c>).</summary>
    public static ZipAuthenticodeSignature ParseSignatureCommentLine(string line)
    {
        var t = line.Trim();
        if (!t.StartsWith(ZipAuthenticodePrefix, StringComparison.Ordinal))
        {
            throw new PsignException($"ZIP signature comment must start with {ZipAuthenticodePrefix}");
        }

        var rest = t[ZipAuthenticodePrefix.Length..];
        int comma = rest.IndexOf(',');
        if (comma < 0)
        {
            throw new PsignException("ZIP signature comment is missing PKCS#7 separator");
        }

        var digest = rest[..comma];
        var pkcs7Base64 = rest[(comma + 1)..];
        if (!IsSha256DigestString(digest))
        {
            throw new PsignException("ZIP signature digest must use sha256:<64 hex chars>");
        }

        if (pkcs7Base64.Trim().Length == 0)
        {
            throw new PsignException("ZIP signature PKCS#7 payload is empty");
        }

        DecodePkcs7Base64(pkcs7Base64);
        return new ZipAuthenticodeSignature(RustText.ToAsciiLowercase(digest), pkcs7Base64.Trim());
    }

    /// <summary>Decode the PKCS#7 DER of a parsed signature (Rust <c>signature_pkcs7_der</c>).</summary>
    public static byte[] SignaturePkcs7Der(ZipAuthenticodeSignature sig) => DecodePkcs7Base64(sig.Pkcs7Base64);

    private static byte[] DecodePkcs7Base64(string b64)
    {
        try
        {
            return Base64Standard.Decode(b64.Trim());
        }
        catch (FormatException e)
        {
            throw new PsignException("ZIP signature PKCS#7 base64 decode", e);
        }
    }

    /// <summary>
    /// Reconstruct the signed <c>.sig.ps1</c> script: digest line, CRLF, then a <c># SIG #</c> block with 64-character
    /// base64 lines (Rust <c>signature_script_from_parts</c>).
    /// </summary>
    public static string SignatureScriptFromParts(string digest, string pkcs7Base64)
    {
        var sb = new StringBuilder();
        sb.Append(digest).Append("\r\n");
        sb.Append(BeginSigBlock).Append("\r\n");
        var bytes = Encoding.UTF8.GetBytes(pkcs7Base64);
        for (int i = 0; i < bytes.Length; i += 64)
        {
            sb.Append("# ");
            sb.Append(Encoding.UTF8.GetString(bytes, i, Math.Min(64, bytes.Length - i)));
            sb.Append("\r\n");
        }

        sb.Append(EndSigBlock).Append("\r\n");
        return sb.ToString();
    }

    /// <summary>Build a validated comment line from a digest string and PKCS#7 DER (Rust <c>signature_comment_line_from_pkcs7_der</c>).</summary>
    public static string SignatureCommentLineFromPkcs7Der(string digest, ReadOnlySpan<byte> pkcs7Der)
    {
        if (!IsSha256DigestString(digest))
        {
            throw new PsignException("ZIP signature digest must use sha256:<64 hex chars>");
        }

        var line = $"{ZipAuthenticodePrefix}{RustText.ToAsciiLowercase(digest)},{Base64Standard.Encode(pkcs7Der)}";
        ParseSignatureCommentLine(line);
        return line;
    }

    /// <summary>Reconstruct the signed script from a comment line (Rust <c>signature_script_from_comment_line</c>).</summary>
    public static string SignatureScriptFromCommentLine(string line)
    {
        var sig = ParseSignatureCommentLine(line);
        return SignatureScriptFromParts(sig.Digest, sig.Pkcs7Base64);
    }

    /// <summary>The unsigned <c>.sig.ps1</c> bytes: the digest string as UTF-8 with no BOM and no newline.</summary>
    public static byte[] UnsignedSignatureScriptBytes(string digest) => Encoding.UTF8.GetBytes(digest);

    /// <summary>Recover the comment line from a signed <c>.sig.ps1</c> (Rust <c>signature_comment_line_from_script</c>).</summary>
    public static string SignatureCommentLineFromScript(ReadOnlySpan<byte> script)
    {
        var text = RustText.FromUtf8Strict(script, "signed ZIP .sig.ps1 is not UTF-8");
        using var lines = RustText.Lines(text).GetEnumerator();
        if (!lines.MoveNext())
        {
            throw new PsignException("signed ZIP .sig.ps1 is empty");
        }

        var digest = lines.Current.Trim();
        if (!IsSha256DigestString(digest))
        {
            throw new PsignException("signed ZIP .sig.ps1 first line must be sha256:<64 hex chars>");
        }

        bool inBlock = false;
        var pkcs7Base64 = new StringBuilder();
        while (lines.MoveNext())
        {
            var trimmed = lines.Current.Trim();
            if (trimmed == BeginSigBlock)
            {
                inBlock = true;
                continue;
            }

            if (trimmed == EndSigBlock)
            {
                break;
            }

            if (inBlock && trimmed.StartsWith("# ", StringComparison.Ordinal))
            {
                pkcs7Base64.Append(trimmed[2..].Trim());
            }
        }

        var line = $"{ZipAuthenticodePrefix}{RustText.ToAsciiLowercase(digest)},{pkcs7Base64}";
        ParseSignatureCommentLine(line);
        return line;
    }

    /// <summary>Replace the ZIP comment (Rust <c>set_zip_comment</c>).</summary>
    public static byte[] SetZipComment(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> comment)
    {
        if (comment.Length > MaxZipCommentLen)
        {
            throw new PsignException(
                $"ZIP comment is too large for EOCD comment field ({comment.Length} > {MaxZipCommentLen})");
        }

        var eocd = FindEocd(bytes);
        var result = new byte[eocd.CommentOffset + comment.Length];
        bytes[..eocd.CommentOffset].CopyTo(result);
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(eocd.Offset + EocdCommentLenOffset, 2), (ushort)comment.Length);
        comment.CopyTo(result.AsSpan(eocd.CommentOffset));
        return result;
    }

    /// <summary>Validate and embed a comment line, replacing any existing comment (Rust <c>embed_signature_comment_line</c>).</summary>
    public static byte[] EmbedSignatureCommentLine(ReadOnlySpan<byte> bytes, string line)
    {
        ParseSignatureCommentLine(line);
        return SetZipComment(bytes, Encoding.UTF8.GetBytes(line));
    }

    /// <summary>Check that the embedded digest matches the current ZIP bytes (Rust <c>verify_zip_digest_binding</c>).</summary>
    public static ZipAuthenticodeSignature VerifyZipDigestBinding(ReadOnlySpan<byte> bytes)
    {
        var line = SignatureCommentLine(bytes);
        var sig = ParseSignatureCommentLine(line);
        var computed = ZipAuthenticodeDigestString(bytes);
        if (sig.Digest != computed)
        {
            throw new PsignException($"ZIP Authenticode digest mismatch: embedded {sig.Digest} computed {computed}");
        }

        return sig;
    }

    /// <summary>
    /// Full portable ZIP check used by <c>verify-zip</c> / <c>trust-verify-zip</c>: digest binding, then the
    /// reconstructed <c>.sig.ps1</c> PowerShell digest binding. Returns the comment signature and the script report
    /// (whose <see cref="Scripts.ScriptAuthenticodeDigestReport.Pkcs7Der"/> is the signature to chain-validate).
    /// </summary>
    public static (ZipAuthenticodeSignature Signature, Scripts.ScriptAuthenticodeDigestReport ScriptReport) VerifyZipSignature(ReadOnlySpan<byte> bytes)
    {
        var sig = VerifyZipDigestBinding(bytes);
        var script = SignatureScriptFromParts(sig.Digest, sig.Pkcs7Base64);
        var report = Scripts.PsScript.PowerShellClassDigestReport(Encoding.UTF8.GetBytes(script), "ps1");
        return (sig, report);
    }
}
