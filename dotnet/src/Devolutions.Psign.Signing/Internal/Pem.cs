using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Internal;

/// <summary>Minimal PEM helpers matching the Rust <c>picky::pem</c> / <c>pem-rfc7468</c> text forms used by psign.</summary>
internal static class Pem
{
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
            if (found.Length == 0 || found.IndexOfAny(['\r', '\n']) >= 0)
            {
                throw new PsignException("PEM BEGIN line is not terminated");
            }
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
}
