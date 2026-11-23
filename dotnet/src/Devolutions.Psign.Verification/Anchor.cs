using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Verification;

/// <summary>
/// Trust anchor set keyed by SHA-1 certificate thumbprint (Rust <c>anchor::AnchorStore</c>). Thumbprints may come from
/// full certificates or from AuthRoot CTL subject identifiers.
/// </summary>
public sealed class AnchorStore
{
    private readonly HashSet<string> _sha1Thumbs = new(StringComparer.Ordinal);

    /// <summary>Empty store.</summary>
    public static AnchorStore Empty() => new();

    /// <summary>Add the SHA-1 thumbprints of <paramref name="certs"/>.</summary>
    public void MergeCertThumbprints(IEnumerable<CertificateInfo> certs)
    {
        foreach (var c in certs)
        {
            _sha1Thumbs.Add(Anchors.CertSha1ThumbprintHex(c));
        }
    }

    /// <summary>Merge raw SHA-1 subject identifiers (for example from AuthRoot CTL entries) without full certificates.</summary>
    public void MergeThumbprintsOnly(IEnumerable<byte[]> thumbs)
    {
        foreach (var t in thumbs)
        {
            _sha1Thumbs.Add(Hex.Lower(t));
        }
    }

    /// <summary>True when the SHA-1 thumbprint is trusted.</summary>
    public bool ContainsThumbprint(ReadOnlySpan<byte> thumb) => _sha1Thumbs.Contains(Hex.Lower(thumb));

    /// <summary>True when the certificate's SHA-1 thumbprint is trusted.</summary>
    public bool Contains(CertificateInfo cert) => _sha1Thumbs.Contains(Anchors.CertSha1ThumbprintHex(cert));

    /// <summary>Number of distinct trusted thumbprints.</summary>
    public int ThumbprintCount => _sha1Thumbs.Count;

    /// <summary>Parse every <c>*.crt</c>, <c>*.cer</c>, and <c>*.pem</c> under <paramref name="dir"/> (non-recursive).</summary>
    public static (AnchorStore Store, List<CertificateInfo> Certs) LoadDir(string dir)
    {
        string[] paths;
        try
        {
            paths = Directory.GetFiles(dir);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw PsignException.Context($"read anchor dir {dir}", e);
        }

        Array.Sort(paths, StringComparer.Ordinal);
        var certs = new List<CertificateInfo>();
        foreach (var path in paths)
        {
            var ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
            if (ext is not ("crt" or "cer" or "pem"))
            {
                continue;
            }

            byte[] raw;
            try
            {
                raw = File.ReadAllBytes(path);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw PsignException.Context($"read anchor {path}", e);
            }

            try
            {
                certs.Add(Anchors.ParseCertBytes(raw));
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"parse anchor certificate {path}", e);
            }
        }

        if (certs.Count == 0)
        {
            throw new PsignException($"no certificates loaded from anchor dir {dir} (expected .crt/.cer/.pem)");
        }

        var store = Empty();
        store.MergeCertThumbprints(certs);
        return (store, certs);
    }

    /// <summary>Parse explicitly supplied certificate files and use them as trust anchors.</summary>
    public static (AnchorStore Store, List<CertificateInfo> Certs) LoadFiles(IEnumerable<string> paths)
    {
        var certs = new List<CertificateInfo>();
        foreach (var path in paths)
        {
            byte[] raw;
            try
            {
                raw = File.ReadAllBytes(path);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
            {
                throw PsignException.Context($"read anchor {path}", e);
            }

            try
            {
                certs.Add(Anchors.ParseCertBytes(raw));
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"parse anchor certificate {path}", e);
            }
        }

        if (certs.Count == 0)
        {
            throw new PsignException("no trusted CA files were supplied");
        }

        var store = Empty();
        store.MergeCertThumbprints(certs);
        return (store, certs);
    }
}

/// <summary>Certificate helpers from Rust <c>anchor.rs</c>.</summary>
public static class Anchors
{
    private static readonly string[] CertPemLabels = ["CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"];

    /// <summary>SHA-1 over the certificate DER (Windows-style certificate hash).</summary>
    public static byte[] CertSha1Thumbprint(CertificateInfo cert) => SHA1.HashData(cert.RawData);

    /// <summary>Lowercase hex SHA-1 thumbprint.</summary>
    public static string CertSha1ThumbprintHex(CertificateInfo cert) => Hex.Lower(SHA1.HashData(cert.RawData));

    /// <summary>Parse a PEM (<c>-----BEGIN …</c>) or DER certificate (Rust <c>anchor::parse_cert_bytes</c>).</summary>
    public static CertificateInfo ParseCertBytes(ReadOnlySpan<byte> raw)
    {
        int start = 0;
        while (start < raw.Length && raw[start] is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\r' or 0x0C)
        {
            start++;
        }

        var trimmed = raw[start..];
        if (trimmed.StartsWith("-----BEGIN "u8))
        {
            string text;
            try
            {
                text = new UTF8Encoding(false, true).GetString(trimmed);
            }
            catch (DecoderFallbackException e)
            {
                throw new PsignException($"anchor PEM is not UTF-8: {e.Message}");
            }

            return ParsePemCertificate(text, "PEM parse failed: ");
        }

        return ParseDerCertificate(trimmed, "DER parse failed: ");
    }

    internal static CertificateInfo ParseDerCertificate(ReadOnlySpan<byte> der, string errorPrefix)
    {
        var tlv = Der.First(der);
        if (tlv is null || tlv.Value.Tag != 0x30)
        {
            // picky_asn1_der::Asn1DerError's Display is its Debug form.
            throw new PsignException(errorPrefix + "(ASN1) couldn't deserialize x509 certificate: InvalidData");
        }

        try
        {
            return CertificateInfo.Parse(der[..tlv.Value.End]);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException or CryptographicException)
        {
            throw new PsignException(errorPrefix + "(ASN1) couldn't deserialize x509 certificate: " + e.Message);
        }
    }

    internal static CertificateInfo ParsePemCertificate(string text, string errorPrefix)
    {
        const string begin = "-----BEGIN ";
        int b = text.IndexOf(begin, StringComparison.Ordinal);
        if (b < 0)
        {
            throw new PsignException(errorPrefix + "invalid PEM provided: pem header not found");
        }

        int labelEnd = text.IndexOf("-----", b + begin.Length, StringComparison.Ordinal);
        if (labelEnd < 0)
        {
            throw new PsignException(errorPrefix + "invalid PEM provided: pem header not found");
        }

        string label = text[(b + begin.Length)..labelEnd];
        string endMarker = "-----END " + label + "-----";
        int bodyStart = labelEnd + 5;
        int e = text.IndexOf(endMarker, bodyStart, StringComparison.Ordinal);
        if (e < 0)
        {
            throw new PsignException(errorPrefix + "invalid PEM provided: pem footer not found");
        }

        if (!CertPemLabels.Contains(label))
        {
            throw new PsignException(errorPrefix + $"invalid PEM label: {label}");
        }

        byte[] der;
        try
        {
            var body = new string(text[bodyStart..e].Where(c => !char.IsWhiteSpace(c)).ToArray());
            der = Convert.FromBase64String(body);
        }
        catch (FormatException ex)
        {
            throw new PsignException(errorPrefix + $"invalid PEM provided: couldn't decode base64: {ex.Message}");
        }

        return ParseDerCertificate(der, errorPrefix);
    }
}
