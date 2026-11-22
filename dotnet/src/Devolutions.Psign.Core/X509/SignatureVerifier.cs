using System.Formats.Asn1;
using System.Security.Cryptography;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.X509;

/// <summary>Signature verification over raw data using a <c>SubjectPublicKeyInfo</c>.</summary>
public static class SignatureVerifier
{
    /// <summary>
    /// Verify <paramref name="signature"/> over <paramref name="data"/> with the algorithm from
    /// <paramref name="signatureAlgorithm"/>. Supports RSA PKCS#1 v1.5 (with explicit sha*WithRSA or bare rsaEncryption
    /// plus <paramref name="digestHint"/>), RSA-PSS, and ECDSA.
    /// </summary>
    public static bool Verify(byte[] spkiDer, AlgorithmIdentifier signatureAlgorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, AuthenticodeHashKind? digestHint = null)
    {
        try
        {
            var hash = ResolveHash(signatureAlgorithm, digestHint);
            if (hash is null)
            {
                return false;
            }

            var spkiAlg = SpkiAlgorithm(spkiDer);
            if (spkiAlg == Oids.RsaEncryption || spkiAlg == Oids.RsaPss)
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
                var padding = signatureAlgorithm.Oid == Oids.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(data, signature, hash.Value.HashAlgorithmName(), padding);
            }

            if (spkiAlg == Oids.EcPublicKey)
            {
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(spkiDer, out _);
                return ec.VerifyData(data, signature, hash.Value.HashAlgorithmName(), DSASignatureFormat.Rfc3279DerSequence);
            }

            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Verify a signature over a precomputed digest. RSA PKCS#1 v1.5 / PSS and ECDSA are supported.
    /// </summary>
    public static bool VerifyHash(byte[] spkiDer, AlgorithmIdentifier signatureAlgorithm, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature, AuthenticodeHashKind hash)
    {
        try
        {
            var spkiAlg = SpkiAlgorithm(spkiDer);
            if (spkiAlg == Oids.RsaEncryption || spkiAlg == Oids.RsaPss)
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
                var padding = signatureAlgorithm.Oid == Oids.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyHash(digest, signature, hash.HashAlgorithmName(), padding);
            }

            if (spkiAlg == Oids.EcPublicKey)
            {
                using var ec = ECDsa.Create();
                ec.ImportSubjectPublicKeyInfo(spkiDer, out _);
                return ec.VerifyHash(digest, signature, DSASignatureFormat.Rfc3279DerSequence);
            }

            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Public key algorithm OID from a SubjectPublicKeyInfo.</summary>
    public static string SpkiAlgorithm(byte[] spkiDer)
    {
        var r = new AsnReader(spkiDer, AsnEncodingRules.BER).ReadSequence();
        var alg = r.ReadSequence();
        return alg.ReadObjectIdentifier();
    }

    /// <summary>Hash algorithm implied by a signature algorithm identifier.</summary>
    public static AuthenticodeHashKind? ResolveHash(AlgorithmIdentifier signatureAlgorithm, AuthenticodeHashKind? digestHint = null)
    {
        switch (signatureAlgorithm.Oid)
        {
            case Oids.Sha1WithRsa:
            case Oids.EcdsaWithSha1:
                return AuthenticodeHashKind.Sha1;
            case Oids.Sha256WithRsa:
            case Oids.EcdsaWithSha256:
                return AuthenticodeHashKind.Sha256;
            case Oids.Sha384WithRsa:
            case Oids.EcdsaWithSha384:
                return AuthenticodeHashKind.Sha384;
            case Oids.Sha512WithRsa:
            case Oids.EcdsaWithSha512:
                return AuthenticodeHashKind.Sha512;
            case Oids.RsaPss:
                return PssHash(signatureAlgorithm) ?? digestHint;
            case Oids.RsaEncryption:
            case Oids.EcPublicKey:
                return digestHint;
            default:
                return null;
        }
    }

    private static AuthenticodeHashKind? PssHash(AlgorithmIdentifier alg)
    {
        if (alg.Parameters is null)
        {
            return AuthenticodeHashKind.Sha1;
        }

        try
        {
            var r = new AsnReader(alg.Parameters, AsnEncodingRules.BER).ReadSequence();
            var tag0 = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
            if (r.HasData && r.PeekTag().HasSameClassAndValue(tag0))
            {
                var hashAlg = r.ReadSequence(tag0).ReadSequence();
                return AuthenticodeHashKinds.FromOid(hashAlg.ReadObjectIdentifier());
            }

            return AuthenticodeHashKind.Sha1;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
