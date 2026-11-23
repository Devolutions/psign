using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Signing.Cms;

/// <summary>Signed-attribute profile for generic CMS <c>SignedData</c> (Rust <c>Pkcs7SignedAttributeProfile</c>).</summary>
public enum Pkcs7SignedAttributeProfile
{
    /// <summary>RFC 5652 minimum: <c>contentType</c> and <c>messageDigest</c>.</summary>
    Basic,

    /// <summary>NuGet author signature attributes (includes <c>signingTime</c>).</summary>
    NuGetAuthor,

    /// <summary>NuGet author attributes without <c>signingTime</c> (stable across split prehash / from-signature steps).</summary>
    NuGetAuthorWithoutSigningTime,
}

/// <summary>Whether <c>encapContentInfo</c> embeds the signed content (Rust <c>Pkcs7ContentMode</c>).</summary>
public enum Pkcs7ContentMode
{
    Attached,
    Detached,
}

/// <summary>
/// Produces a raw signature over a digest of the DER signed attributes (RSA PKCS#1 v1.5). Implemented by local keys and
/// remote signers (Azure Key Vault, Azure Artifact Signing, precomputed signatures).
/// </summary>
public interface IDigestSigner
{
    /// <summary>Sign <paramref name="digest"/> (already hashed with <paramref name="hash"/>).</summary>
    byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash);
}

/// <summary>Local RSA PKCS#1 v1.5 signer.</summary>
public sealed class RsaDigestSigner : IDigestSigner
{
    private readonly RSA _key;

    public RsaDigestSigner(RSA key) => _key = key;

    public byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash) =>
        _key.SignHash(digest, hash.HashAlgorithmName(), RSASignaturePadding.Pkcs1);
}

/// <summary>Signer that returns a precomputed signature (split prehash / from-signature workflows).</summary>
public sealed class PrecomputedDigestSigner : IDigestSigner
{
    private readonly byte[] _signature;

    public PrecomputedDigestSigner(byte[] signature) => _signature = signature;

    public byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash) => _signature;
}

/// <summary>
/// CMS / PKCS#7 <c>SignedData</c> producers (port of the producer half of Rust <c>pkcs7.rs</c>). Output is
/// byte-identical to the Rust implementation for the same inputs (deterministic RSA PKCS#1 v1.5, sorted DER sets).
/// </summary>
public static class Pkcs7Builder
{
    /// <summary>Ensure <paramref name="kind"/> is a SHA-2 algorithm supported by the portable producer.</summary>
    public static void RequireSigningDigest(AuthenticodeHashKind kind)
    {
        if (kind == AuthenticodeHashKind.Sha1)
        {
            throw new PsignException("portable signing supports SHA-256, SHA-384, and SHA-512 digests only");
        }
    }

    /// <summary>Digest algorithm identifier without parameters (generic CMS profile).</summary>
    public static AlgorithmIdentifier DigestAlgorithm(AuthenticodeHashKind kind) => AlgorithmIdentifier.Absent(kind.Oid());

    /// <summary>Digest algorithm identifier with NULL parameters (Authenticode profile).</summary>
    public static AlgorithmIdentifier AuthenticodeDigestAlgorithm(AuthenticodeHashKind kind) => AlgorithmIdentifier.WithNull(kind.Oid());

    /// <summary><c>shaNNNWithRSAEncryption</c> with NULL parameters.</summary>
    public static AlgorithmIdentifier RsaDigestSignatureAlgorithm(AuthenticodeHashKind kind) => AlgorithmIdentifier.WithNull(kind.RsaSignatureOid());

    /// <summary><c>rsaEncryption</c> with NULL parameters (Authenticode <c>SignerInfo.signatureAlgorithm</c>).</summary>
    public static AlgorithmIdentifier AuthenticodeRsaSignatureAlgorithm() => AlgorithmIdentifier.WithNull(Oids.RsaEncryption);

    // ---------------------------------------------------------------- attributes

    /// <summary>PKCS#9 <c>messageDigest</c>.</summary>
    public static CmsAttribute MessageDigestAttribute(byte[] digest) =>
        new(Oids.Pkcs9MessageDigest, Der.EncodeTlv(0x04, digest));

    /// <summary>PKCS#9 <c>contentType</c>.</summary>
    public static CmsAttribute ContentTypeAttribute(string contentType) =>
        new(Oids.Pkcs9ContentType, Der.EncodeOid(contentType));

    /// <summary>Empty <c>SpcSpOpusInfo</c> (<c>SEQUENCE {}</c>).</summary>
    public static CmsAttribute SpcSpOpusInfoAttribute() => new(Oids.SpcSpOpusInfo, [0x30, 0x00]);

    /// <summary><c>SpcStatementType</c> = individual code signing.</summary>
    public static CmsAttribute SpcStatementTypeAttribute() =>
        new(Oids.SpcStatementType, Der.EncodeSequence(Der.EncodeOid(Oids.SpcIndividualCodeSigning)));

    /// <summary>PKCS#9 <c>signingTime</c> encoded as UTCTime (Rust <c>UtcTime::from_system_time</c>).</summary>
    public static CmsAttribute SigningTimeAttribute(DateTimeOffset now)
    {
        var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        var t = now.ToUniversalTime();
        w.WriteUtcTime(new DateTimeOffset(t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second, TimeSpan.Zero), twoDigitYearMax: 2049);
        return new CmsAttribute(Oids.Pkcs9SigningTime, w.Encode());
    }

    /// <summary>CAdES <c>commitmentTypeIndication</c> with only a commitment type identifier.</summary>
    public static CmsAttribute CommitmentTypeIndicationAttribute(string commitmentType) =>
        new(Oids.Pkcs9CommitmentTypeIndication, Der.EncodeSequence(Der.EncodeOid(commitmentType)));

    /// <summary>ESS <c>signingCertificateV2</c> with an explicit SHA-256 hash algorithm and issuer/serial.</summary>
    public static CmsAttribute SigningCertificateV2Attribute(CertificateInfo signerCert)
    {
        var hashAlgorithm = DigestAlgorithm(AuthenticodeHashKind.Sha256).Encode();
        var certHash = Der.EncodeTlv(0x04, SHA256.HashData(signerCert.RawData));
        var directoryName = Der.EncodeTlv(0xA4, signerCert.Issuer);
        var generalNames = Der.EncodeSequence(directoryName);
        var issuerSerial = Der.EncodeSequence(generalNames, signerCert.SerialNumberEncoded);
        var essCertIdV2 = Der.EncodeSequence(hashAlgorithm, certHash, issuerSerial);
        var certs = Der.EncodeSequence(essCertIdV2);
        return new CmsAttribute(Oids.Pkcs9SigningCertificateV2, Der.EncodeSequence(certs));
    }

    /// <summary>RFC 5652 §5.4 <c>eContent</c> digest: hash the value octets of <paramref name="econtentDer"/>.</summary>
    public static byte[] EncapsulatedContentDigest(byte[] econtentDer, AuthenticodeHashKind kind)
    {
        var t = Der.First(econtentDer);
        if (t is null || t.Value.End != econtentDer.Length)
        {
            throw new PsignException("trailing octets after encapsulated content DER");
        }

        return kind.Hash(t.Value.Value(econtentDer));
    }

    /// <summary>Authenticode signed attributes for <paramref name="indirect"/>.</summary>
    public static List<CmsAttribute> AuthenticodeSignedAttributes(SpcIndirectDataContent indirect, AuthenticodeHashKind kind)
    {
        var digest = EncapsulatedContentDigest(indirect.Encode(), kind);
        return
        [
            SpcSpOpusInfoAttribute(),
            ContentTypeAttribute(Oids.SpcIndirectData),
            SpcStatementTypeAttribute(),
            MessageDigestAttribute(digest),
        ];
    }

    /// <summary>Generic CMS signed attributes for a profile (Rust <c>pkcs7_signed_attrs</c>).</summary>
    public static List<CmsAttribute> SignedAttributes(
        string econtentType,
        byte[] econtentDer,
        AuthenticodeHashKind kind,
        Pkcs7SignedAttributeProfile profile,
        CertificateInfo? signerCert,
        DateTimeOffset? signingTime = null)
    {
        var digest = EncapsulatedContentDigest(econtentDer, kind);
        var attrs = new List<CmsAttribute>
        {
            ContentTypeAttribute(econtentType),
            MessageDigestAttribute(digest),
        };
        if (profile != Pkcs7SignedAttributeProfile.Basic)
        {
            if (signerCert is null)
            {
                throw new PsignException("NuGet author signed attributes require the signer certificate");
            }

            if (profile == Pkcs7SignedAttributeProfile.NuGetAuthor)
            {
                attrs.Add(SigningTimeAttribute(signingTime ?? DateTimeOffset.UtcNow));
            }

            attrs.Add(CommitmentTypeIndicationAttribute(Oids.CommitmentTypeProofOfOrigin));
            attrs.Add(SigningCertificateV2Attribute(signerCert));
        }

        return attrs;
    }

    /// <summary>DER <c>SET OF Attribute</c> (tag 0x31) — the octets signed per RFC 5652 §5.4.</summary>
    public static byte[] SignedAttributesDer(IEnumerable<CmsAttribute> attributes) => CmsAttribute.EncodeSet(0x31, attributes);

    /// <summary>Digest of the DER signed attributes that a (remote) RSA signer must sign.</summary>
    public static byte[] SignedAttributesDigest(IEnumerable<CmsAttribute> attributes, AuthenticodeHashKind kind) =>
        kind.Hash(SignedAttributesDer(attributes));

    /// <summary>Replace the PKCS#9 <c>messageDigest</c> value.</summary>
    public static List<CmsAttribute> ReplaceMessageDigest(IEnumerable<CmsAttribute> attributes, byte[] newDigest)
    {
        bool found = false;
        var result = new List<CmsAttribute>();
        foreach (var a in attributes)
        {
            if (a.Oid == Oids.Pkcs9MessageDigest)
            {
                found = true;
                result.Add(MessageDigestAttribute(newDigest));
            }
            else
            {
                result.Add(a);
            }
        }

        if (!found)
        {
            throw new PsignException($"authenticated attributes contain no PKCS#9 messageDigest ({Oids.Pkcs9MessageDigest})");
        }

        return result;
    }

    // ---------------------------------------------------------------- Authenticode

    /// <summary>Digest a remote signer must sign for an Authenticode payload.</summary>
    public static byte[] AuthenticodeRemoteSignedAttributesDigest(SpcIndirectDataContent indirect, AuthenticodeHashKind kind) =>
        SignedAttributesDigest(AuthenticodeSignedAttributes(indirect, kind), kind);

    /// <summary>
    /// Create Authenticode PKCS#7 <c>ContentInfo(SignedData)</c> DER. <paramref name="signer"/> receives the digest of the
    /// DER signed attributes.
    /// </summary>
    public static byte[] CreateAuthenticode(
        SpcIndirectDataContent indirect,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer)
    {
        RequireSigningDigest(kind);
        var attrs = AuthenticodeSignedAttributes(indirect, kind);
        var signature = signer.SignDigest(SignedAttributesDigest(attrs, kind), kind);
        var signerInfo = new CmsSignerInfo(
            1,
            CmsSignerInfo.IssuerAndSerialSid(signerCert),
            AuthenticodeDigestAlgorithm(kind),
            attrs,
            AuthenticodeRsaSignatureAlgorithm(),
            signature,
            null);
        return Assemble(Oids.SpcIndirectData, indirect.Encode(), AuthenticodeDigestAlgorithm(kind), signerCert, chainCerts, signerInfo, attached: true);
    }

    /// <summary>Create Authenticode PKCS#7 DER with a local RSA key.</summary>
    public static byte[] CreateAuthenticode(
        SpcIndirectDataContent indirect,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) => CreateAuthenticode(indirect, kind, signerCert, chainCerts, new RsaDigestSigner(key));

    /// <summary>Create Authenticode PKCS#7 DER from an externally produced RSA signature over the signed-attributes digest.</summary>
    public static byte[] CreateAuthenticodeWithSignature(
        SpcIndirectDataContent indirect,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        byte[] encryptedDigest) =>
        CreateAuthenticode(indirect, kind, signerCert, chainCerts, new PrecomputedDigestSigner(encryptedDigest));

    // ---------------------------------------------------------------- generic CMS

    /// <summary>Digest a remote signer must sign for a generic CMS document.</summary>
    public static byte[] RemoteSignedAttributesDigest(
        string econtentType,
        byte[] econtentDer,
        AuthenticodeHashKind kind,
        Pkcs7SignedAttributeProfile profile = Pkcs7SignedAttributeProfile.Basic,
        CertificateInfo? signerCert = null) =>
        SignedAttributesDigest(SignedAttributes(econtentType, econtentDer, kind, profile, signerCert), kind);

    /// <summary>
    /// Create generic CMS <c>SignedData</c> (Rust <c>create_pkcs7_signed_data_der_rsa</c> /
    /// <c>create_pkcs7_signed_data_der_with_signed_attrs_and_rsa_signature</c>).
    /// </summary>
    public static byte[] CreateSignedData(
        string econtentType,
        byte[] econtentDer,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        Pkcs7ContentMode contentMode = Pkcs7ContentMode.Attached,
        List<CmsAttribute>? signedAttributes = null)
    {
        RequireSigningDigest(kind);
        var attrs = signedAttributes ?? SignedAttributes(econtentType, econtentDer, kind, Pkcs7SignedAttributeProfile.Basic, null);
        var signature = signer.SignDigest(SignedAttributesDigest(attrs, kind), kind);
        var signerInfo = new CmsSignerInfo(
            1,
            CmsSignerInfo.IssuerAndSerialSid(signerCert),
            DigestAlgorithm(kind),
            attrs,
            RsaDigestSignatureAlgorithm(kind),
            signature,
            null);
        return Assemble(econtentType, econtentDer, DigestAlgorithm(kind), signerCert, chainCerts, signerInfo, contentMode == Pkcs7ContentMode.Attached);
    }

    /// <summary>Create generic CMS <c>SignedData</c> with a local RSA key (attached content, basic attributes).</summary>
    public static byte[] CreateSignedData(
        string econtentType,
        byte[] econtentDer,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) =>
        CreateSignedData(econtentType, econtentDer, kind, signerCert, chainCerts, new RsaDigestSigner(key));

    /// <summary>Create unsigned CMS <c>SignedData</c> (no signer infos, no certificates) for catalogs prepared for later signing.</summary>
    public static byte[] CreateUnsignedSignedData(string econtentType, byte[] econtentDer, AlgorithmIdentifier digestAlgorithm)
    {
        var t = Der.First(econtentDer);
        if (t is null || t.Value.End != econtentDer.Length)
        {
            throw new PsignException("trailing octets after encapsulated content DER");
        }

        var sd = new CmsSignedData(1, [digestAlgorithm], econtentType, econtentDer, null, null, []);
        return sd.Encode();
    }

    private static byte[] Assemble(
        string econtentType,
        byte[] econtentDer,
        AlgorithmIdentifier digestAlgorithm,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        CmsSignerInfo signerInfo,
        bool attached)
    {
        var t = Der.First(econtentDer);
        if (t is null || t.Value.End != econtentDer.Length)
        {
            throw new PsignException("trailing octets after encapsulated content DER");
        }

        var certs = new List<byte[]> { signerCert.RawData };
        foreach (var c in DedupChain(signerCert, chainCerts))
        {
            certs.Add(c.RawData);
        }

        var sd = new CmsSignedData(1, [digestAlgorithm], econtentType, attached ? econtentDer : null, certs, null, [signerInfo]);
        return sd.Encode();
    }

    /// <summary>Remove certificates equal to the signer or duplicated in the chain (Rust <c>dedup_chain_certs</c>).</summary>
    public static List<CertificateInfo> DedupChain(CertificateInfo signerCert, IEnumerable<CertificateInfo> chainCerts)
    {
        var seen = new List<byte[]> { signerCert.RawData };
        var unique = new List<CertificateInfo>();
        foreach (var c in chainCerts)
        {
            if (seen.Any(s => s.AsSpan().SequenceEqual(c.RawData)))
            {
                continue;
            }

            seen.Add(c.RawData);
            unique.Add(c);
        }

        return unique;
    }

    // ---------------------------------------------------------------- timestamps / mutation

    /// <summary>
    /// Attach a raw RFC 3161 <c>timeStampToken</c> <c>ContentInfo</c> as an unsigned attribute with
    /// <paramref name="attributeOid"/> (default Microsoft <c>1.3.6.1.4.1.311.3.3.1</c>), replacing any existing one.
    /// </summary>
    public static CmsSignedData AddTimestampToken(CmsSignedData sd, int signerIndex, ReadOnlySpan<byte> timestampToken, string attributeOid = Oids.MsRfc3161TimestampToken)
    {
        if (signerIndex < 0 || signerIndex >= sd.SignerInfos.Count)
        {
            throw new PsignException($"SignerInfo index {signerIndex} out of range (len {sd.SignerInfos.Count})");
        }

        var token = Pkcs7Wire.TryOuterSequencePrefix(timestampToken) ?? timestampToken.ToArray();
        var t = Der.First(token);
        if (t is null || t.Value.End != token.Length)
        {
            throw new PsignException("timestamp token ContentInfo: malformed DER");
        }

        var result = sd.Clone();
        var si = result.SignerInfos[signerIndex];
        var attrs = si.UnsignedAttributes?.Where(a => a.Oid != attributeOid).ToList() ?? [];
        attrs.Add(new CmsAttribute(attributeOid, token));
        si.UnsignedAttributes = attrs;
        return result;
    }

    /// <summary>Attach an RFC 3161 token using the CMS / PKCS#9 <c>id-aa-timeStampToken</c> attribute OID.</summary>
    public static CmsSignedData AddPkcs9TimestampToken(CmsSignedData sd, int signerIndex, ReadOnlySpan<byte> timestampToken) =>
        AddTimestampToken(sd, signerIndex, timestampToken, Oids.Pkcs9Rfc3161TimestampToken);

    /// <summary>Replace <c>encapContentInfo.eContent</c> with a new <c>SpcIndirectDataContent</c>.</summary>
    public static CmsSignedData ReplaceEncapsulatedSpcIndirect(CmsSignedData template, SpcIndirectDataContent indirect)
    {
        if (template.EncapContentType != Oids.SpcIndirectData)
        {
            throw new PsignException($"SignedData encap content type is not SPC_INDIRECT_DATA (got {template.EncapContentType})");
        }

        var result = template.Clone();
        result.EncapContent = indirect.Encode();
        return result;
    }

    /// <summary>Replace the signer info at <paramref name="index"/>.</summary>
    public static CmsSignedData ReplaceSignerInfo(CmsSignedData sd, int index, CmsSignerInfo signerInfo)
    {
        if (index < 0 || index >= sd.SignerInfos.Count)
        {
            throw new PsignException($"SignerInfo index {index} out of range (len {sd.SignerInfos.Count})");
        }

        var result = sd.Clone();
        result.SignerInfos[index] = signerInfo;
        return result;
    }
}
