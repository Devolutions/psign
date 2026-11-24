using System.Formats.Asn1;
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>
/// Private key loading. <see cref="ParseRsaPrivateKeyMaterial"/> ports Rust <c>rdp::parse_rsa_private_key</c>, which psign
/// reuses for every <c>--key</c> input (PKCS#8 or PKCS#1, DER or unencrypted single-block PEM);
/// <see cref="LoadPkcs8KeyPemFile"/> ports <c>cert_store::load_pkcs8_key_pem</c>. Certificates are loaded with
/// <see cref="CertificateLoader"/>.
/// </summary>
public static class PrivateKeyLoader
{
    /// <summary>
    /// Parse an RSA private key. PEM containing <c>BEGIN RSA PRIVATE KEY</c> is PKCS#1, other PEM is PKCS#8 (both RFC 7468
    /// strict single-block PEM); DER is tried as PKCS#8 first and then PKCS#1.
    /// </summary>
    public static PrivateKeyMaterial ParseRsaPrivateKeyMaterial(ReadOnlySpan<byte> bytes)
    {
        var pem = CertificateLoader.PemText(bytes);
        if (pem is not null)
        {
            if (pem.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal))
            {
                return Wrap("parse PKCS#1 RSA private key PEM", () => FromPkcs1(DecodePem(pem, "RSA PRIVATE KEY")));
            }

            return Wrap("parse PKCS#8 RSA private key PEM", () => RequireRsa(PrivateKeyMaterial.FromPkcs8Der(DecodePem(pem, "PRIVATE KEY"))));
        }

        var der = bytes.ToArray();
        return Wrap("parse DER RSA private key", () =>
        {
            try
            {
                return RequireRsa(PrivateKeyMaterial.FromPkcs8Der(der));
            }
            catch (Exception e) when (e is PsignException or AsnContentException or CryptographicException)
            {
                return FromPkcs1(der);
            }
        });
    }

    /// <summary>Parse an RSA private key (see <see cref="ParseRsaPrivateKeyMaterial"/>) into an <see cref="RSA"/> instance.</summary>
    public static RSA ParseRsaPrivateKey(ReadOnlySpan<byte> bytes) => ParseRsaPrivateKeyMaterial(bytes).CreateRsa();

    /// <summary>Read and parse an RSA private key file.</summary>
    public static RSA LoadRsaPrivateKeyFile(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"read private key '{path}'", e);
        }

        return ParseRsaPrivateKey(bytes);
    }

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
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
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

    private static byte[] DecodePem(string pem, string label)
    {
        var block = CertificateLoader.DecodeSinglePem(pem);
        if (block.Label != label)
        {
            throw new PsignException($"PEM type label mismatch: expected {label}, got {block.Label}");
        }

        return block.Der;
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
}
