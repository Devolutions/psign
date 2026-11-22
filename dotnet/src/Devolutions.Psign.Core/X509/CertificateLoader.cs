using System.Text;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Core.X509;

/// <summary>One decoded PEM block.</summary>
/// <param name="Label">Type label (for example <c>CERTIFICATE</c>).</param>
/// <param name="Der">Decoded payload.</param>
public sealed record PemBlock(string Label, byte[] Der);

/// <summary>
/// General certificate loading: a single DER or PEM certificate (port of Rust <c>rdp::parse_certificate</c>, which is
/// reused across psign for <c>--cert</c> / <c>--chain-cert</c> inputs) and PEM bundles.
/// </summary>
public static class CertificateLoader
{
    private const string PreBoundary = "-----BEGIN ";
    private const string PostBoundary = "-----END ";
    private const string Dashes = "-----";

    /// <summary>
    /// Return the PEM text when <paramref name="bytes"/> is UTF-8 that starts (after BOMs and leading whitespace) with
    /// <c>-----BEGIN </c>; <c>null</c> for non-PEM input. Throws when the input looks like PEM but is not valid UTF-8
    /// (Rust <c>pem_text</c>).
    /// </summary>
    public static string? PemText(ReadOnlySpan<byte> bytes)
    {
        var text = RustText.TryFromUtf8(bytes);
        if (text is not null)
        {
            var trimmed = text.TrimStart('﻿').TrimStart();
            return trimmed.StartsWith(PreBoundary, StringComparison.Ordinal) ? trimmed : null;
        }

        if (bytes.StartsWith("-----BEGIN "u8) || bytes.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
        {
            throw new PsignException("PEM input is not valid UTF-8");
        }

        return null;
    }

    /// <summary>
    /// Parse one certificate from DER or PEM bytes (Rust <c>rdp::parse_certificate</c>). PEM input must contain exactly one
    /// <c>CERTIFICATE</c> block; DER input must be exactly one certificate.
    /// </summary>
    public static CertificateInfo ParseCertificate(ReadOnlySpan<byte> bytes)
    {
        var pem = PemText(bytes);
        if (pem is not null)
        {
            try
            {
                var block = DecodeSinglePem(pem);
                if (block.Label != "CERTIFICATE")
                {
                    throw new PsignException($"PEM type label mismatch: expected CERTIFICATE, got {block.Label}");
                }

                return CertificateInfo.Parse(block.Der);
            }
            catch (Exception e) when (e is PsignException or FormatException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException)
            {
                throw new PsignException("parse PEM certificate", e);
            }
        }

        try
        {
            return CertificateInfo.Parse(bytes);
        }
        catch (Exception e) when (e is PsignException or FormatException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException)
        {
            throw new PsignException("parse DER certificate", e);
        }
    }

    /// <summary>
    /// Parse every <c>CERTIFICATE</c> block of a PEM bundle (other labels are skipped). Throws when no certificate block is
    /// present.
    /// </summary>
    public static List<CertificateInfo> ParsePemBundle(string pem)
    {
        var result = new List<CertificateInfo>();
        foreach (var block in DecodePemBlocks(pem))
        {
            if (block.Label == "CERTIFICATE")
            {
                try
                {
                    result.Add(CertificateInfo.Parse(block.Der));
                }
                catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
                {
                    throw new PsignException($"parse PEM certificate #{result.Count + 1}", e);
                }
            }
        }

        if (result.Count == 0)
        {
            throw new PsignException("PEM input contains no CERTIFICATE blocks");
        }

        return result;
    }

    /// <summary>Load one or more certificates: a PEM bundle (all <c>CERTIFICATE</c> blocks) or a single DER certificate.</summary>
    public static List<CertificateInfo> ParseCertificates(ReadOnlySpan<byte> bytes)
    {
        var pem = PemText(bytes);
        if (pem is not null)
        {
            return ParsePemBundle(pem);
        }

        return [ParseCertificate(bytes)];
    }

    /// <summary>Read and parse a single certificate file (DER or PEM).</summary>
    public static CertificateInfo LoadCertificateFile(string path) => ParseCertificate(File.ReadAllBytes(path));

    /// <summary>
    /// Cert-store certificate loading (Rust <c>cert_store::pem_or_der_to_der</c>): extract the first <c>CERTIFICATE</c>
    /// PEM block when present, otherwise return the bytes unchanged.
    /// </summary>
    public static byte[] PemOrDerToDer(byte[] bytes)
    {
        var text = RustText.TryFromUtf8(bytes);
        if (text is null)
        {
            return bytes;
        }

        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        var start = text.IndexOf(begin, StringComparison.Ordinal);
        if (start < 0)
        {
            return bytes;
        }

        var bodyStart = start + begin.Length;
        var bodyEnd = text.IndexOf(end, bodyStart, StringComparison.Ordinal);
        if (bodyEnd < 0)
        {
            throw new PsignException("PEM certificate is missing END CERTIFICATE marker");
        }

        var encoded = new string(text.AsSpan(bodyStart, bodyEnd - bodyStart).ToArray().Where(c => c is not (' ' or '\t' or '\n' or '\r' or '\f')).ToArray());
        try
        {
            return Convert.FromBase64String(encoded);
        }
        catch (FormatException e)
        {
            throw new PsignException("decode PEM certificate base64", e);
        }
    }

    /// <summary>
    /// Decode a document that holds exactly one PEM block (RFC 7468 strict: only an optional preamble before the
    /// pre-encapsulation boundary, matching labels, and at most one line break after the post-encapsulation boundary).
    /// </summary>
    public static PemBlock DecodeSinglePem(string pem)
    {
        int begin = FindPreBoundary(pem, 0);
        if (begin < 0)
        {
            throw new PsignException("PEM pre-encapsulation boundary not found");
        }

        var (label, bodyStart) = ParseLabel(pem, begin);
        var tail = StripTrailingEol(pem.AsSpan(bodyStart));
        var expectedEnd = PostBoundary + label + Dashes;
        if (!tail.EndsWith(expectedEnd, StringComparison.Ordinal))
        {
            throw new PsignException("PEM post-encapsulation boundary error");
        }

        var body = tail[..^expectedEnd.Length];
        return new PemBlock(label, DecodeBody(body));
    }

    /// <summary>Decode every PEM block in <paramref name="pem"/> (text outside blocks is ignored).</summary>
    public static List<PemBlock> DecodePemBlocks(string pem)
    {
        var blocks = new List<PemBlock>();
        int pos = 0;
        while (true)
        {
            int begin = FindPreBoundary(pem, pos);
            if (begin < 0)
            {
                return blocks;
            }

            var (label, bodyStart) = ParseLabel(pem, begin);
            var expectedEnd = PostBoundary + label + Dashes;
            int end = pem.IndexOf(expectedEnd, bodyStart, StringComparison.Ordinal);
            if (end < 0)
            {
                throw new PsignException($"PEM block '{label}' has no matching post-encapsulation boundary");
            }

            blocks.Add(new PemBlock(label, DecodeBody(pem.AsSpan(bodyStart, end - bodyStart))));
            pos = end + expectedEnd.Length;
        }
    }

    private static int FindPreBoundary(string pem, int from)
    {
        int pos = from;
        while (pos < pem.Length)
        {
            int i = pem.IndexOf(PreBoundary, pos, StringComparison.Ordinal);
            if (i < 0)
            {
                return -1;
            }

            if (i == 0 || pem[i - 1] == '\n' || pem[i - 1] == '\r' || i == from)
            {
                return i;
            }

            pos = i + 1;
        }

        return -1;
    }

    private static (string Label, int BodyStart) ParseLabel(string pem, int begin)
    {
        int labelStart = begin + PreBoundary.Length;
        int labelEnd = pem.IndexOf(Dashes, labelStart, StringComparison.Ordinal);
        if (labelEnd < 0)
        {
            throw new PsignException("PEM type label error");
        }

        var label = pem[labelStart..labelEnd];
        if (label.Contains('\n') || label.Contains('\r') || label.StartsWith(' ') || label.EndsWith(' ') ||
            label.StartsWith('-') || label.EndsWith('-') || label.Contains("  ", StringComparison.Ordinal) ||
            label.Contains("--", StringComparison.Ordinal))
        {
            throw new PsignException("PEM type label error");
        }

        int bodyStart = labelEnd + Dashes.Length;
        if (bodyStart < pem.Length && pem[bodyStart] == '\r')
        {
            bodyStart++;
        }

        if (bodyStart < pem.Length && pem[bodyStart] == '\n')
        {
            bodyStart++;
        }

        return (label, bodyStart);
    }

    private static ReadOnlySpan<char> StripTrailingEol(ReadOnlySpan<char> s)
    {
        if (s.EndsWith("\r\n", StringComparison.Ordinal))
        {
            return s[..^2];
        }

        if (s.EndsWith("\n", StringComparison.Ordinal) || s.EndsWith("\r", StringComparison.Ordinal))
        {
            return s[..^1];
        }

        return s;
    }

    private static byte[] DecodeBody(ReadOnlySpan<char> body)
    {
        var sb = new StringBuilder(body.Length);
        foreach (char c in body)
        {
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                continue;
            }

            if (c == ':')
            {
                throw new PsignException("PEM headers are not allowed (RFC 7468)");
            }

            sb.Append(c);
        }

        try
        {
            return Base64Standard.Decode(sb.ToString());
        }
        catch (FormatException e)
        {
            throw new PsignException($"PEM Base64 error: {e.Message}", e);
        }
    }
}
