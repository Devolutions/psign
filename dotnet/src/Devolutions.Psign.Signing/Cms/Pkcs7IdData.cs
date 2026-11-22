using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Signing.Cms;

/// <summary>Unsigned attribute used to attach an RFC 3161 token (Rust <c>Rfc3161TimestampAttribute</c>).</summary>
public enum Rfc3161TimestampAttribute
{
    /// <summary>Microsoft Authenticode <c>1.3.6.1.4.1.311.3.3.1</c> (Authenticode / App Installer companion signatures).</summary>
    MicrosoftAuthenticode,

    /// <summary>CMS / PKCS#9 <c>id-aa-timeStampToken</c> <c>1.2.840.113549.1.9.16.2.14</c> (NuGet signatures).</summary>
    CmsTimeStampToken,
}

/// <summary>
/// CMS <c>SignedData</c> over <c>id-data</c> content (ported from <c>sign_pkcs7_id_data</c>,
/// <c>pkcs7_id_data_remote_prehash</c>, <c>sign_pkcs7_id_data_with_external_signature</c> and
/// <c>timestamp_pkcs7_der_rfc3161</c> in Rust <c>psign-digest-cli/src/main.rs</c>). Used by NuGet author signatures and
/// App Installer companion signatures.
/// </summary>
public static class Pkcs7IdData
{
    /// <summary>DER <c>OCTET STRING</c> wrapping <paramref name="content"/> (Rust <c>id_data_econtent_der</c>).</summary>
    public static byte[] EContentDer(ReadOnlySpan<byte> content) => Der.EncodeTlv(0x04, content);

    /// <summary>Signed attributes for <paramref name="content"/> (Rust <c>pkcs7::pkcs7_signed_attrs</c>).</summary>
    public static List<CmsAttribute> SignedAttributes(
        byte[] content,
        AuthenticodeHashKind digest,
        Pkcs7SignedAttributeProfile profile,
        CertificateInfo? signerCert,
        DateTimeOffset? signingTime = null) =>
        Pkcs7Builder.SignedAttributes(Oids.Pkcs7Data, EContentDer(content), digest, profile, signerCert, signingTime);

    /// <summary>Digest of the DER signed attributes a remote RSA signer must sign (Rust <c>pkcs7_id_data_remote_prehash</c>).</summary>
    public static byte[] RemotePrehash(byte[] content, AuthenticodeHashKind digest, Pkcs7SignedAttributeProfile profile, CertificateInfo? signerCert)
    {
        Pkcs7Builder.RequireSigningDigest(digest);
        return Pkcs7Builder.SignedAttributesDigest(SignedAttributes(content, digest, profile, signerCert), digest);
    }

    /// <summary>
    /// Create <c>SignedData</c> with <paramref name="signer"/> producing the RSA signature over the signed-attributes
    /// digest (Rust <c>sign_pkcs7_id_data</c>).
    /// </summary>
    public static byte[] Sign(
        byte[] content,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        AuthenticodeHashKind digest,
        Pkcs7ContentMode contentMode,
        Pkcs7SignedAttributeProfile profile,
        DateTimeOffset? signingTime = null)
    {
        Pkcs7Builder.RequireSigningDigest(digest);
        var attrs = SignedAttributes(content, digest, profile, signerCert, signingTime);
        return Pkcs7Builder.CreateSignedData(Oids.Pkcs7Data, EContentDer(content), digest, signerCert, chainCerts, signer, contentMode, attrs);
    }

    /// <summary>Create <c>SignedData</c> with a local RSA key.</summary>
    public static byte[] Sign(
        byte[] content,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key,
        AuthenticodeHashKind digest,
        Pkcs7ContentMode contentMode,
        Pkcs7SignedAttributeProfile profile,
        DateTimeOffset? signingTime = null) =>
        Sign(content, signerCert, chainCerts, new RsaDigestSigner(key), digest, contentMode, profile, signingTime);

    /// <summary>
    /// Create <c>SignedData</c> from an externally produced RSA signature over <see cref="RemotePrehash"/> (Rust
    /// <c>sign_pkcs7_id_data_with_external_signature</c>).
    /// </summary>
    public static byte[] SignWithExternalSignature(
        byte[] content,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        AuthenticodeHashKind digest,
        byte[] signature,
        Pkcs7ContentMode contentMode,
        Pkcs7SignedAttributeProfile profile) =>
        Sign(content, signerCert, chainCerts, new PrecomputedDigestSigner(signature), digest, contentMode, profile);

    /// <summary>Octets an RFC 3161 imprint is computed over: the first signer's signature value.</summary>
    public static byte[] TimestampImprintInput(byte[] pkcs7Der)
    {
        CmsSignedData sd;
        try
        {
            sd = CmsSignedData.Parse(pkcs7Der);
        }
        catch (Exception e) when (e is not PsignException)
        {
            throw new PsignException("parse PKCS#7 SignedData", e);
        }

        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("PKCS#7 SignedData has no SignerInfo to timestamp");
        }

        return sd.SignerInfos[0].Signature;
    }

    /// <summary>Attach an RFC 3161 <c>timeStampToken</c> to the first signer (Rust <c>timestamp_pkcs7_der_rfc3161</c> tail).</summary>
    public static byte[] AttachTimestampToken(byte[] pkcs7Der, byte[] token, Rfc3161TimestampAttribute attribute)
    {
        var sd = CmsSignedData.Parse(pkcs7Der);
        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("PKCS#7 SignedData has no SignerInfo to timestamp");
        }

        CmsSignedData stamped;
        try
        {
            stamped = attribute == Rfc3161TimestampAttribute.MicrosoftAuthenticode
                ? Pkcs7Builder.AddTimestampToken(sd, 0, token)
                : Pkcs7Builder.AddPkcs9TimestampToken(sd, 0, token);
        }
        catch (PsignException e)
        {
            throw new PsignException("attach RFC3161 timestamp token", e);
        }

        return stamped.Encode();
    }

    /// <summary>
    /// Timestamp <paramref name="pkcs7Der"/> through <paramref name="timestampToken"/>, which receives the first signer's
    /// signature value (hash it with the timestamp digest to form the imprint) and returns the RFC 3161 token DER.
    /// </summary>
    public static byte[] Timestamp(byte[] pkcs7Der, Func<byte[], byte[]> timestampToken, Rfc3161TimestampAttribute attribute) =>
        AttachTimestampToken(pkcs7Der, timestampToken(TimestampImprintInput(pkcs7Der)), attribute);
}
