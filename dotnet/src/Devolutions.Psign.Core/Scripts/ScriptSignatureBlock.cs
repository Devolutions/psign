using System.Text;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.Scripts;

/// <summary>
/// Embedding of an already-built PKCS#7 into PowerShell-class scripts (port of <c>format_powershell_signature_block</c>
/// and <c>append_script_signature_block</c> in <c>psign-portable-core</c>).
/// </summary>
public static class ScriptSignatureBlock
{
    /// <summary>Base64 characters per signature-block line.</summary>
    public const int LineWidth = 64;

    /// <summary>
    /// Format the PowerShell signature block for <paramref name="pkcs7Der"/> using the marker family implied by
    /// <paramref name="extension"/> (<c>ps1xml</c>/<c>psc1</c>/<c>cdxml</c> → XML comments, <c>mof</c> → C comments,
    /// anything else → <c>#</c> comments). The block starts with CRLF and every line ends with CRLF.
    /// </summary>
    public static string FormatPowerShellSignatureBlock(ReadOnlySpan<byte> pkcs7Der, string extension)
    {
        var b64 = Base64Standard.Encode(pkcs7Der);
        var (begin, linePrefix, lineSuffix, end) = RustText.ToAsciiLowercase(extension) switch
        {
            "ps1xml" or "psc1" or "cdxml" => (
                "\r\n<!-- SIG # Begin signature block -->\r\n",
                "<!-- ",
                " -->\r\n",
                "<!-- SIG # End signature block -->\r\n"),
            "mof" => (
                "\r\n/* SIG # Begin signature block */\r\n",
                "/* ",
                " */\r\n",
                "/* SIG # End signature block */\r\n"),
            _ => (
                "\r\n# SIG # Begin signature block\r\n",
                "# ",
                "\r\n",
                "# SIG # End signature block\r\n"),
        };
        var block = new StringBuilder(begin);
        for (int i = 0; i < b64.Length; i += LineWidth)
        {
            block.Append(linePrefix);
            block.Append(b64, i, Math.Min(LineWidth, b64.Length - i));
            block.Append(lineSuffix);
        }

        block.Append(end);
        return block.ToString();
    }

    /// <summary>
    /// Append <paramref name="block"/> to <paramref name="script"/> in the script's own encoding: UTF-16LE after an
    /// <c>FF FE</c> BOM, UTF-16BE after <c>FE FF</c>, UTF-8 otherwise.
    /// </summary>
    public static byte[] AppendSignatureBlock(ReadOnlySpan<byte> script, string block)
    {
        byte[] encoded;
        if (script.Length >= 2 && script[0] == 0xFF && script[1] == 0xFE)
        {
            encoded = RustText.Utf16LeBytes(block);
        }
        else if (script.Length >= 2 && script[0] == 0xFE && script[1] == 0xFF)
        {
            encoded = RustText.Utf16BeBytes(block);
        }
        else
        {
            encoded = Encoding.UTF8.GetBytes(block);
        }

        var result = new byte[script.Length + encoded.Length];
        script.CopyTo(result);
        encoded.CopyTo(result, script.Length);
        return result;
    }

    /// <summary>Format and append a signature block for <paramref name="pkcs7Der"/> to <paramref name="script"/>.</summary>
    public static byte[] Embed(ReadOnlySpan<byte> script, ReadOnlySpan<byte> pkcs7Der, string extension) =>
        AppendSignatureBlock(script, FormatPowerShellSignatureBlock(pkcs7Der, extension));
}
