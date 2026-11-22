using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>
/// RSA private key loading (port of Rust <c>rdp::parse_rsa_private_key</c>, which psign reuses for every <c>--key</c>
/// input): PKCS#8 or PKCS#1, DER or unencrypted PEM.
/// </summary>
public static class RsaPrivateKeyLoader
{
    /// <summary>
    /// Parse an RSA private key. PEM containing <c>BEGIN RSA PRIVATE KEY</c> is PKCS#1, other PEM is PKCS#8; DER is tried
    /// as PKCS#8 first and then PKCS#1.
    /// </summary>
    public static RSA ParseRsaPrivateKey(ReadOnlySpan<byte> bytes)
    {
        var pem = CertificateLoader.PemText(bytes);
        if (pem is not null)
        {
            if (pem.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal))
            {
                return FromPem(pem, "RSA PRIVATE KEY", pkcs1: true, "parse PKCS#1 RSA private key PEM");
            }

            return FromPem(pem, "PRIVATE KEY", pkcs1: false, "parse PKCS#8 RSA private key PEM");
        }

        var der = bytes.ToArray();
        if (TryImport(der, pkcs1: false, out var key) || TryImport(der, pkcs1: true, out key))
        {
            return key!;
        }

        throw new PsignException("parse DER RSA private key", new PsignException("not a PKCS#8 or PKCS#1 RSA private key"));
    }

    /// <summary>Read and parse an RSA private key file.</summary>
    public static RSA LoadRsaPrivateKeyFile(string path) => ParseRsaPrivateKey(File.ReadAllBytes(path));

    private static RSA FromPem(string pem, string label, bool pkcs1, string context)
    {
        try
        {
            var block = CertificateLoader.DecodeSinglePem(pem);
            if (block.Label != label)
            {
                throw new PsignException($"PEM type label mismatch: expected {label}, got {block.Label}");
            }

            if (!TryImport(block.Der, pkcs1, out var key, out var error))
            {
                throw new PsignException(error ?? "invalid RSA private key");
            }

            return key!;
        }
        catch (PsignException e)
        {
            throw new PsignException(context, e);
        }
    }

    private static bool TryImport(byte[] der, bool pkcs1, out RSA? key) => TryImport(der, pkcs1, out key, out _);

    private static bool TryImport(byte[] der, bool pkcs1, out RSA? key, out string? error)
    {
        var rsa = RSA.Create();
        try
        {
            int read;
            if (pkcs1)
            {
                rsa.ImportRSAPrivateKey(der, out read);
            }
            else
            {
                rsa.ImportPkcs8PrivateKey(der, out read);
            }

            if (read != der.Length)
            {
                rsa.Dispose();
                key = null;
                error = "trailing data after private key";
                return false;
            }

            key = rsa;
            error = null;
            return true;
        }
        catch (CryptographicException e)
        {
            rsa.Dispose();
            key = null;
            error = e.Message;
            return false;
        }
    }
}
