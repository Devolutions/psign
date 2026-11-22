using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Internal;

/// <summary>Minimal PEM helpers matching the Rust <c>picky::pem</c> / <c>pem-rfc7468</c> text forms used by psign.</summary>
internal static class Pem
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Encode <paramref name="der"/> as a PEM block with 64-column base64 lines and a trailing newline.</summary>
    public static string Encode(string label, ReadOnlySpan<byte> der)
    {
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).Append("-----\n");
        var b64 = Convert.ToBase64String(der);
        for (var i = 0; i < b64.Length; i += 64)
        {
            sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
        }

        sb.Append("-----END ").Append(label).Append("-----\n");
        return sb.ToString();
    }

    /// <summary>Strict UTF-8 decode, or <c>null</c> when <paramref name="bytes"/> are not valid UTF-8.</summary>
    public static string? TryUtf8(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>
    /// Rust <c>rdp::pem_text</c>: return the PEM text (BOM and leading whitespace trimmed) when <paramref name="bytes"/>
    /// look like PEM, <c>null</c> for binary (DER) input.
    /// </summary>
    public static string? PemText(ReadOnlySpan<byte> bytes)
    {
        var text = TryUtf8(bytes);
        if (text is not null)
        {
            var trimmed = text.TrimStart('\uFEFF').TrimStart();
            return trimmed.StartsWith("-----BEGIN ", StringComparison.Ordinal) ? trimmed : null;
        }

        if (bytes.StartsWith("-----BEGIN "u8) || bytes.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }))
        {
            throw new PsignException("PEM input is not valid UTF-8");
        }

        return null;
    }

    /// <summary>A decoded PEM block.</summary>
    public readonly record struct Block(string Label, byte[] Data, int End);

    /// <summary>Find the first PEM block at or after <paramref name="start"/> (optionally with a specific label).</summary>
    public static Block? Find(string text, string? label = null, int start = 0)
    {
        var pos = start;
        while (true)
        {
            var begin = text.IndexOf("-----BEGIN ", pos, StringComparison.Ordinal);
            if (begin < 0)
            {
                return null;
            }

            var labelStart = begin + "-----BEGIN ".Length;
            var labelEnd = text.IndexOf("-----", labelStart, StringComparison.Ordinal);
            if (labelEnd < 0)
            {
                throw new PsignException("PEM BEGIN line is not terminated");
            }

            var found = text[labelStart..labelEnd];
            var bodyStart = labelEnd + 5;
            var endMarker = "-----END " + found + "-----";
            var end = text.IndexOf(endMarker, bodyStart, StringComparison.Ordinal);
            if (end < 0)
            {
                throw new PsignException($"PEM block '{found}' is missing its END marker");
            }

            if (label is null || found == label)
            {
                var b64 = new StringBuilder();
                foreach (var c in text.AsSpan(bodyStart, end - bodyStart))
                {
                    if (!char.IsWhiteSpace(c))
                    {
                        b64.Append(c);
                    }
                }

                byte[] data;
                try
                {
                    data = Convert.FromBase64String(b64.ToString());
                }
                catch (FormatException e)
                {
                    throw new PsignException($"PEM block '{found}' contains invalid base64", e);
                }

                return new Block(found, data, end + endMarker.Length);
            }

            pos = end + endMarker.Length;
        }
    }

    /// <summary>Every PEM block with <paramref name="label"/> in <paramref name="text"/>.</summary>
    public static List<byte[]> FindAll(string text, string label)
    {
        var list = new List<byte[]>();
        var pos = 0;
        while (Find(text, label, pos) is { } block)
        {
            list.Add(block.Data);
            pos = block.End;
        }

        return list;
    }
}
