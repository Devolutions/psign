using System.Formats.Asn1;
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Verification.Picky;

/// <summary>
/// Port of <c>picky::signature::SignatureAlgorithm::{from_algorithm_identifier, verify}</c> used for X.509 certificate
/// signatures. Returns <c>picky</c>'s <c>SignatureError</c> text on failure.
/// </summary>
internal static class PickySignature
{
    private const string Sha224WithRsa = "1.2.840.113549.1.1.14";
    private const string Sha3_384WithRsa = "2.16.840.1.101.3.4.3.15";
    private const string Sha3_512WithRsa = "2.16.840.1.101.3.4.3.16";
    private const string Ed25519 = "1.3.101.112";
    private const string P256 = "1.2.840.10045.3.1.7";
    private const string P384 = "1.3.132.0.34";
    private const string P521 = "1.3.132.0.35";

    private enum Kind
    {
        Rsa,
        Ecdsa,
        Ed25519,
    }

    private static (Kind Kind, HashAlgorithmName Hash)? FromOid(string oid) => oid switch
    {
        Oids.Md5WithRsa => (Kind.Rsa, HashAlgorithmName.MD5),
        Oids.Sha1WithRsa => (Kind.Rsa, HashAlgorithmName.SHA1),
        Sha224WithRsa => (Kind.Rsa, new HashAlgorithmName("SHA224")),
        Oids.Sha256WithRsa => (Kind.Rsa, HashAlgorithmName.SHA256),
        Oids.Sha384WithRsa => (Kind.Rsa, HashAlgorithmName.SHA384),
        Oids.Sha512WithRsa => (Kind.Rsa, HashAlgorithmName.SHA512),
#if NET8_0_OR_GREATER
        Sha3_384WithRsa => (Kind.Rsa, HashAlgorithmName.SHA3_384),
        Sha3_512WithRsa => (Kind.Rsa, HashAlgorithmName.SHA3_512),
#endif
        Oids.EcdsaWithSha256 => (Kind.Ecdsa, HashAlgorithmName.SHA256),
        Oids.EcdsaWithSha384 => (Kind.Ecdsa, HashAlgorithmName.SHA384),
        Ed25519 => (Kind.Ed25519, default),
        _ => null,
    };

    /// <summary>RSA PKCS#1 v1.5 algorithm for a digest OID (picky <c>AlgorithmIdentifier::new_rsa_encryption_with_sha</c>).</summary>
    public static string? RsaSignatureOidForDigest(string digestOid) => digestOid switch
    {
        Oids.Sha1 => Oids.Sha1WithRsa,
        "2.16.840.1.101.3.4.2.4" => Sha224WithRsa,
        Oids.Sha256 => Oids.Sha256WithRsa,
        Oids.Sha384 => Oids.Sha384WithRsa,
        Oids.Sha512 => Oids.Sha512WithRsa,
        "2.16.840.1.101.3.4.2.9" => Sha3_384WithRsa,
        "2.16.840.1.101.3.4.2.10" => Sha3_512WithRsa,
        _ => null,
    };

    /// <summary>Verify; returns <c>null</c> on success or picky's <c>SignatureError</c> display text.</summary>
    public static string? Verify(string signatureAlgorithmOid, byte[] spkiDer, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        var alg = FromOid(signatureAlgorithmOid);
        if (alg is null)
        {
            return $"unsupported algorithm: {signatureAlgorithmOid}";
        }

        string keyAlg;
        try
        {
            keyAlg = SignatureVerifier.SpkiAlgorithm(spkiDer);
        }
        catch (AsnContentException e)
        {
            return $"Key error: {e.Message}";
        }

        try
        {
            switch (alg.Value.Kind)
            {
                case Kind.Rsa:
                {
                    if (keyAlg != Oids.RsaEncryption)
                    {
                        return "Key error: public key is not an RSA key";
                    }

                    using var rsa = RSA.Create();
                    rsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
                    return rsa.VerifyData(data, signature, alg.Value.Hash, RSASignaturePadding.Pkcs1) ? null : "invalid signature";
                }

                case Kind.Ecdsa:
                {
                    if (keyAlg != Oids.EcPublicKey)
                    {
                        return "Key error: public key is not an EC key";
                    }

                    var curve = EcCurveOid(spkiDer);
                    var (wantCurve, hashName, curveName) = alg.Value.Hash == HashAlgorithmName.SHA256
                        ? (P256, "SHA256", CurveDisplay(curve))
                        : (P384, "SHA384", CurveDisplay(curve));
                    if (curve is not (P256 or P384 or P521))
                    {
                        return $"Key error: unsupported curve {curve} for verifying";
                    }

                    if (curve != wantCurve)
                    {
                        return $"unsupported algorithm: {hashName} hash algorithm can't be used with `{curveName}` curve";
                    }

                    using var ec = ECDsa.Create();
                    ec.ImportSubjectPublicKeyInfo(spkiDer, out _);
                    return ec.VerifyData(data, signature, alg.Value.Hash, DSASignatureFormat.Rfc3279DerSequence) ? null : "invalid signature";
                }

                default:
                    // Ed25519 is not available in the BCL; report it as unsupported (documented gap).
                    return $"unsupported algorithm: {signatureAlgorithmOid}";
            }
        }
        catch (Exception e) when (e is CryptographicException or PlatformNotSupportedException)
        {
            return alg.Value.Kind == Kind.Rsa ? $"RSA error: {e.Message}" : $"EC error: {e.Message}";
        }
    }

    private static string CurveDisplay(string? oid) => oid switch
    {
        P256 => "NIST P-256",
        P384 => "NIST P-384",
        P521 => "NIST P-521",
        _ => oid ?? string.Empty,
    };

    private static string? EcCurveOid(byte[] spkiDer)
    {
        try
        {
            var r = new AsnReader(spkiDer, AsnEncodingRules.BER).ReadSequence();
            var alg = r.ReadSequence();
            alg.ReadObjectIdentifier();
            return alg.HasData && alg.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier) ? alg.ReadObjectIdentifier() : null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
