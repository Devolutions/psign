using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Internal;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>Private key algorithm family (from the PKCS#8 <c>privateKeyAlgorithm</c> OID).</summary>
public enum PrivateKeyAlgorithm
{
    Rsa,
    Ec,
    Other,
}

/// <summary>
/// An unencrypted PKCS#8 private key in the canonical form psign writes (Rust <c>picky::key::PrivateKey</c>
/// <c>to_pem_str</c>): attributes are dropped and RSA keys use <c>rsaEncryption</c> with <c>NULL</c> parameters.
/// </summary>
public sealed class PrivateKeyMaterial
{
    private readonly byte[] _privateKeyOctets;

    private PrivateKeyMaterial(byte[] pkcs8Der, string algorithmOid, byte[] privateKeyOctets)
    {
        Pkcs8Der = pkcs8Der;
        AlgorithmOid = algorithmOid;
        _privateKeyOctets = privateKeyOctets;
    }

    /// <summary>Canonical PKCS#8 <c>PrivateKeyInfo</c> DER.</summary>
    public byte[] Pkcs8Der { get; }

    /// <summary><c>privateKeyAlgorithm</c> OID.</summary>
    public string AlgorithmOid { get; }

    /// <summary>Algorithm family.</summary>
    public PrivateKeyAlgorithm Algorithm => AlgorithmOid switch
    {
        KeyOids.RsaEncryption => PrivateKeyAlgorithm.Rsa,
        KeyOids.EcPublicKey => PrivateKeyAlgorithm.Ec,
        _ => PrivateKeyAlgorithm.Other,
    };

    /// <summary>Parse an unencrypted PKCS#8 <c>PrivateKeyInfo</c> and canonicalize it.</summary>
    public static PrivateKeyMaterial FromPkcs8Der(ReadOnlySpan<byte> der)
    {
        try
        {
            var reader = new AsnReader(der.ToArray(), AsnEncodingRules.BER);
            var seq = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            var version = seq.ReadEncodedValue().ToArray();
            var algId = seq.ReadEncodedValue().ToArray();
            var algReader = new AsnReader(algId, AsnEncodingRules.BER).ReadSequence();
            var oid = algReader.ReadObjectIdentifier();
            var privateKey = seq.ReadOctetString();
            byte[]? publicKeyTlv = null;
            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                var tlv = seq.ReadEncodedValue().ToArray();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 1)
                {
                    publicKeyTlv = tlv;
                }
            }

            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteEncodedValue(version);
                if (oid == KeyOids.RsaEncryption)
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(oid);
                        writer.WriteNull();
                    }
                }
                else
                {
                    writer.WriteEncodedValue(algId);
                }

                writer.WriteOctetString(privateKey);
                if (publicKeyTlv is not null)
                {
                    writer.WriteEncodedValue(publicKeyTlv);
                }
            }

            return new PrivateKeyMaterial(writer.Encode(), oid, privateKey);
        }
        catch (AsnContentException e)
        {
            throw new PsignException("parse unencrypted PKCS#8 private key", e);
        }
    }

    /// <summary>
    /// Parse PEM unencrypted PKCS#8 (<c>BEGIN PRIVATE KEY</c>); Rust <c>cert_store::validate_pkcs8_key_pem</c>.
    /// </summary>
    public static PrivateKeyMaterial FromPkcs8Pem(string pem)
    {
        Pem.Block? block;
        try
        {
            block = Pem.Find(pem);
        }
        catch (PsignException e)
        {
            throw new PsignException("parse private key PEM", e);
        }

        if (block is null)
        {
            throw new PsignException("parse private key PEM", new PsignException("no PEM block found"));
        }

        if (block.Value.Label != "PRIVATE KEY")
        {
            throw new PsignException($"private key PEM label must be PRIVATE KEY, got {block.Value.Label}");
        }

        return FromPkcs8Der(block.Value.Data);
    }

    /// <summary>Export an RSA key as canonical PKCS#8.</summary>
    public static PrivateKeyMaterial FromRsa(RSA key) => FromPkcs8Der(key.ExportPkcs8PrivateKey());

    /// <summary>PKCS#8 PEM text (<c>-----BEGIN PRIVATE KEY-----</c>, 64-column base64, trailing newline).</summary>
    public string ToPkcs8Pem() => Pem.Encode("PRIVATE KEY", Pkcs8Der);

    /// <summary>Create an <see cref="RSA"/> instance (RSA keys only).</summary>
    public RSA CreateRsa()
    {
        if (Algorithm != PrivateKeyAlgorithm.Rsa)
        {
            throw new PsignException($"private key algorithm {AlgorithmOid} is not RSA");
        }

        var rsa = RSA.Create();
        try
        {
            rsa.ImportPkcs8PrivateKey(Pkcs8Der, out _);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>Create an <see cref="ECDsa"/> instance (EC keys only).</summary>
    public ECDsa CreateECDsa()
    {
        if (Algorithm != PrivateKeyAlgorithm.Ec)
        {
            throw new PsignException($"private key algorithm {AlgorithmOid} is not EC");
        }

        var ec = ECDsa.Create();
        try
        {
            ec.ImportPkcs8PrivateKey(Pkcs8Der, out _);
            return ec;
        }
        catch
        {
            ec.Dispose();
            throw;
        }
    }

    /// <summary>RSA PKCS#1 v1.5 digest signer for this key (portable Authenticode signing supports RSA keys only).</summary>
    public IDigestSigner CreateDigestSigner()
    {
        if (Algorithm != PrivateKeyAlgorithm.Rsa)
        {
            throw new PsignException($"portable signing supports RSA private keys only (got {AlgorithmOid})");
        }

        return new RsaDigestSigner(CreateRsa(), ownsKey: true);
    }

    /// <summary>Whether this key's public half matches <paramref name="cert"/>'s subject public key.</summary>
    public bool MatchesCertificate(CertificateInfo cert)
    {
        try
        {
            switch (Algorithm)
            {
                case PrivateKeyAlgorithm.Rsa:
                    {
                        if (cert.PublicKeyAlgorithm.Oid != KeyOids.RsaEncryption)
                        {
                            return false;
                        }

                        var (keyN, keyE) = RsaPrivateModulusExponent(_privateKeyOctets);
                        var (certN, certE) = RsaPublicModulusExponent(cert.PublicKey);
                        return keyN.AsSpan().SequenceEqual(certN) && keyE.AsSpan().SequenceEqual(certE);
                    }

                case PrivateKeyAlgorithm.Ec:
                    {
                        if (cert.PublicKeyAlgorithm.Oid != KeyOids.EcPublicKey)
                        {
                            return false;
                        }

                        using var key = CreateECDsa();
                        using var pub = cert.X509.GetECDsaPublicKey();
                        if (pub is null)
                        {
                            return false;
                        }

                        var a = key.ExportParameters(false);
                        var b = pub.ExportParameters(false);
                        return a.Curve.Oid?.Value == b.Curve.Oid?.Value
                            && a.Q.X.AsSpan().SequenceEqual(b.Q.X)
                            && a.Q.Y.AsSpan().SequenceEqual(b.Q.Y);
                    }

                default:
                    return false;
            }
        }
        catch (Exception e) when (e is CryptographicException or AsnContentException or PsignException)
        {
            return false;
        }
    }

    /// <summary>Rust <c>key_matches_cert</c> / <c>ensure_key_matches_cert</c>.</summary>
    public void EnsureMatchesCertificate(CertificateInfo cert)
    {
        if (!MatchesCertificate(cert))
        {
            throw new PsignException("private key does not match certificate public key");
        }
    }

    private static (byte[] N, byte[] E) RsaPrivateModulusExponent(byte[] rsaPrivateKey)
    {
        var seq = new AsnReader(rsaPrivateKey, AsnEncodingRules.BER).ReadSequence();
        _ = seq.ReadIntegerBytes();
        var n = seq.ReadIntegerBytes().ToArray();
        var e = seq.ReadIntegerBytes().ToArray();
        return (TrimInteger(n), TrimInteger(e));
    }

    private static (byte[] N, byte[] E) RsaPublicModulusExponent(byte[] rsaPublicKey)
    {
        var seq = new AsnReader(rsaPublicKey, AsnEncodingRules.BER).ReadSequence();
        var n = seq.ReadIntegerBytes().ToArray();
        var e = seq.ReadIntegerBytes().ToArray();
        return (TrimInteger(n), TrimInteger(e));
    }

    private static byte[] TrimInteger(byte[] value)
    {
        var i = 0;
        while (i < value.Length - 1 && value[i] == 0)
        {
            i++;
        }

        return value[i..];
    }
}

/// <summary>Key-related OIDs used by the signing key loaders.</summary>
internal static class KeyOids
{
    public const string RsaEncryption = "1.2.840.113549.1.1.1";
    public const string EcPublicKey = "1.2.840.10045.2.1";
}
