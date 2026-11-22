using System.Formats.Asn1;
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Internal;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>
/// Loaders for signing certificates and RSA private keys (Rust <c>rdp::parse_certificate</c>,
/// <c>rdp::parse_rsa_private_key</c>, and the cert-store PEM / DER helpers).
/// </summary>
public static class SigningMaterialLoader
{
    /// <summary>Parse a DER or PEM certificate (Rust <c>rdp::parse_certificate</c>).</summary>
    public static CertificateInfo ParseCertificate(byte[] bytes)
    {
        var pem = Pem.PemText(bytes);
        if (pem is not null)
        {
            try
            {
                var block = Pem.Find(pem, "CERTIFICATE") ?? throw new PsignException("no CERTIFICATE PEM block found");
                return CertificateInfo.Parse(block.Data);
            }
            catch (Exception e) when (e is PsignException or AsnContentException or CryptographicException or FormatException)
            {
                throw new PsignException("parse PEM certificate", e);
            }
        }

        try
        {
            return CertificateInfo.Parse(bytes);
        }
        catch (Exception e) when (e is PsignException or AsnContentException or CryptographicException)
        {
            throw new PsignException("parse DER certificate", e);
        }
    }

    /// <summary>Parse every certificate in a PEM bundle, or a single DER certificate.</summary>
    public static List<CertificateInfo> ParseCertificates(byte[] bytes)
    {
        var pem = Pem.PemText(bytes);
        if (pem is null)
        {
            return [ParseCertificate(bytes)];
        }

        var list = Pem.FindAll(pem, "CERTIFICATE").Select(d => CertificateInfo.Parse(d)).ToList();
        if (list.Count == 0)
        {
            throw new PsignException("parse PEM certificate", new PsignException("no CERTIFICATE PEM block found"));
        }

        return list;
    }

    /// <summary>
    /// Cert-store certificate loading (Rust <c>pem_or_der_to_der</c>): extract the first <c>CERTIFICATE</c> PEM block
    /// when present, otherwise return the bytes unchanged.
    /// </summary>
    public static byte[] PemOrDerToDer(byte[] bytes)
    {
        var text = Pem.TryUtf8(bytes);
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

        var encoded = new string(text.AsSpan(bodyStart, bodyEnd - bodyStart).ToArray().Where(c => !IsAsciiWhitespace(c)).ToArray());
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
    /// Parse an RSA private key as PKCS#8 / PKCS#1, DER or unencrypted PEM (Rust <c>rdp::parse_rsa_private_key</c>).
    /// </summary>
    public static PrivateKeyMaterial ParseRsaPrivateKeyMaterial(byte[] bytes)
    {
        var pem = Pem.PemText(bytes);
        if (pem is not null)
        {
            if (pem.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal))
            {
                return Wrap("parse PKCS#1 RSA private key PEM", () =>
                {
                    var block = Pem.Find(pem, "RSA PRIVATE KEY") ?? throw new PsignException("no RSA PRIVATE KEY PEM block found");
                    return FromPkcs1(block.Data);
                });
            }

            return Wrap("parse PKCS#8 RSA private key PEM", () =>
            {
                var block = Pem.Find(pem, "PRIVATE KEY") ?? throw new PsignException("no PRIVATE KEY PEM block found");
                return RequireRsa(PrivateKeyMaterial.FromPkcs8Der(block.Data));
            });
        }

        return Wrap("parse DER RSA private key", () =>
        {
            try
            {
                return RequireRsa(PrivateKeyMaterial.FromPkcs8Der(bytes));
            }
            catch (Exception e) when (e is PsignException or AsnContentException or CryptographicException)
            {
                return FromPkcs1(bytes);
            }
        });
    }

    /// <summary>Parse an RSA private key (see <see cref="ParseRsaPrivateKeyMaterial"/>) into an <see cref="RSA"/> instance.</summary>
    public static RSA ParseRsaPrivateKey(byte[] bytes) => ParseRsaPrivateKeyMaterial(bytes).CreateRsa();

    /// <summary>
    /// Read a PEM unencrypted PKCS#8 key file (Rust <c>cert_store::load_pkcs8_key_pem</c>); errors mention the expected
    /// <c>BEGIN PRIVATE KEY</c> format.
    /// </summary>
    public static PrivateKeyMaterial LoadPkcs8KeyPemFile(string path)
    {
        string pem;
        try
        {
            pem = File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read private key '{path}'", e);
        }

        try
        {
            return PrivateKeyMaterial.FromPkcs8Pem(pem);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse private key '{path}'; expected PEM unencrypted PKCS#8 (BEGIN PRIVATE KEY)", e);
        }
    }

    private static PrivateKeyMaterial FromPkcs1(byte[] der)
    {
        using var rsa = RSA.Create();
        try
        {
            rsa.ImportRSAPrivateKey(der, out var read);
            if (read != der.Length)
            {
                throw new PsignException("trailing data after PKCS#1 RSA private key");
            }
        }
        catch (CryptographicException e)
        {
            throw new PsignException("invalid PKCS#1 RSAPrivateKey", e);
        }

        return PrivateKeyMaterial.FromRsa(rsa);
    }

    private static PrivateKeyMaterial RequireRsa(PrivateKeyMaterial key)
    {
        if (key.Algorithm != PrivateKeyAlgorithm.Rsa)
        {
            throw new PsignException($"PKCS#8 private key algorithm {key.AlgorithmOid} is not RSA");
        }

        // Validate that the key material is well-formed.
        using var rsa = key.CreateRsa();
        return key;
    }

    private static PrivateKeyMaterial Wrap(string context, Func<PrivateKeyMaterial> action)
    {
        try
        {
            return action();
        }
        catch (Exception e) when (e is PsignException or AsnContentException or CryptographicException or FormatException)
        {
            throw new PsignException(context, e);
        }
    }

    private static bool IsAsciiWhitespace(char c) => c is ' ' or '\t' or '\n' or '\r' or '\f';
}
