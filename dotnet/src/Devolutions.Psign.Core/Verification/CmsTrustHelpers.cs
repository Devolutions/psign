using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Verification;

/// <summary>
/// CMS helpers from Rust <c>psign_sip_digest::pkcs7</c> used by the portable trust fallback paths (RSA / SHA-256
/// <c>SignerInfo</c> verification over <c>signedAttrs</c>, digest bindings, signer certificate resolution).
/// </summary>
internal static class CmsTrustHelpers
{
    /// <summary><c>parse_pkcs7_signed_data_der</c>.</summary>
    public static CmsSignedData ParsePkcs7SignedDataDer(ReadOnlySpan<byte> pkcs7)
    {
        try
        {
            return CmsSignedData.Parse(pkcs7);
        }
        catch (Exception e) when (e is System.Formats.Asn1.AsnContentException or FormatException)
        {
            throw new PsignException($"SignedData: {e.Message}");
        }
    }

    /// <summary><c>signed_data_certificate_for_signer_identifier</c>.</summary>
    public static CertificateInfo CertificateForSigner(CmsSignedData sd, CmsSignerInfo si) => sd.CertificateForSigner(si);

    /// <summary><c>signed_data_spc_indirect_message_digest_octets</c>.</summary>
    public static byte[] SpcIndirectMessageDigestOctets(CmsSignedData sd)
    {
        if (sd.EncapContent is null)
        {
            throw new PsignException("SignedData missing encapsulated content");
        }

        try
        {
            return SpcIndirectDataContent.Parse(sd.EncapContent).Digest;
        }
        catch (PsignException e)
        {
            throw new PsignException($"SpcIndirectDataContent: {e.Message}");
        }
    }

    /// <summary><c>signer_info_pkcs9_message_digest_octets</c>.</summary>
    public static byte[] SignerInfoPkcs9MessageDigestOctets(CmsSignerInfo si)
    {
        if (si.SignedAttributes is null)
        {
            throw new PsignException("SignerInfo has no authenticated attributes");
        }

        foreach (var attr in si.SignedAttributes)
        {
            if (attr.Oid != Oids.Pkcs9MessageDigest)
            {
                continue;
            }

            var values = Der.SortSetOf(attr.Values);
            if (values.Count == 0)
            {
                throw new PsignException("messageDigest attribute has empty SET");
            }

            var v = values[0];
            var t = Der.First(v);
            if (t is null || t.Value.Tag != 0x04 || t.Value.End != v.Length)
            {
                throw new PsignException("messageDigest attribute OCTET STRING: unexpected ASN.1 DER tag");
            }

            return t.Value.Value(v).ToArray();
        }

        throw new PsignException("PKCS#9 messageDigest attribute not found");
    }

    /// <summary><c>verify_signed_data_authenticode_indirect_digest_and_rsa_sha256_pkcs1v15_signature</c>.</summary>
    public static void VerifyAuthenticodeIndirectDigestAndRsaSha256(CmsSignedData sd, int signerIndex, ReadOnlySpan<byte> expectedSubjectDigest)
    {
        var indirect = SpcIndirectMessageDigestOctets(sd);
        if (!indirect.AsSpan().SequenceEqual(expectedSubjectDigest))
        {
            throw new PsignException("SpcIndirectData messageDigest does not match expected subject digest");
        }

        var econtentDigest = SHA256.HashData(sd.EncapContentDigestInput());
        VerifyPkcs9MessageDigestAndRsaSha256(sd, signerIndex, econtentDigest);
    }

    /// <summary><c>verify_signed_data_pkcs9_message_digest_and_rsa_sha256_pkcs1v15_signature</c>.</summary>
    public static void VerifyPkcs9MessageDigestAndRsaSha256(CmsSignedData sd, int signerIndex, ReadOnlySpan<byte> expectedContentDigest)
    {
        if (signerIndex >= sd.SignerInfos.Count)
        {
            throw new PsignException($"SignerInfo index {signerIndex} out of range (len {sd.SignerInfos.Count})");
        }

        var md = SignerInfoPkcs9MessageDigestOctets(sd.SignerInfos[signerIndex]);
        if (!md.AsSpan().SequenceEqual(expectedContentDigest))
        {
            throw new PsignException("PKCS#9 messageDigest does not match expected content digest");
        }

        VerifyRsaSha256Signature(sd, signerIndex);
    }

    private static void VerifyRsaSha256Signature(CmsSignedData sd, int signerIndex)
    {
        if (signerIndex >= sd.SignerInfos.Count)
        {
            throw new PsignException($"SignerInfo index {signerIndex} out of range (len {sd.SignerInfos.Count})");
        }

        var si = sd.SignerInfos[signerIndex];
        if (si.DigestAlgorithm.Oid != Oids.Sha256)
        {
            throw new PsignException($"CMS fallback trust requires SignerInfo digestAlgorithm SHA-256 (got {si.DigestAlgorithm.Oid})");
        }

        var cert = CertificateForSigner(sd, si);
        string spkiAlg = cert.PublicKeyAlgorithm.Oid;
        if (spkiAlg != Oids.RsaEncryption)
        {
            throw new PsignException($"CMS fallback trust requires RSA public key (got algorithm OID {spkiAlg})");
        }

        using var rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(cert.SubjectPublicKeyInfo, out _);
        }
        catch (CryptographicException e)
        {
            throw new PsignException($"RSA public key from certificate: {e.Message}");
        }

        if (si.SignedAttributes is null)
        {
            throw new PsignException("SignerInfo has no authenticated attributes");
        }

        var prehash = SHA256.HashData(si.SignedAttributesSetDer());
        bool ok;
        try
        {
            ok = rsa.VerifyHash(prehash, si.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            ok = false;
        }

        if (!ok)
        {
            throw new PsignException("RSA PKCS#1 v1.5 verify over signedAttrs (SHA-256): signature error");
        }
    }

    /// <summary>Validate canonical base-128 sub-identifiers without decoding them into fixed-width integers.</summary>
    internal static bool OidValueIsCanonical(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            return false;
        }

        bool startsSubidentifier = true;
        foreach (var b in value)
        {
            if (startsSubidentifier && b == 0x80)
            {
                return false;
            }

            startsSubidentifier = (b & 0x80) == 0;
        }

        return startsSubidentifier;
    }

    /// <summary>
    /// Search an EKU SEQUENCE for <paramref name="expectedOidValue"/> (OID content octets) without decoding unrelated
    /// OIDs into fixed-width arcs (Rust <c>trust_pkcs7::extended_key_usage_contains</c>).
    /// </summary>
    internal static bool ExtendedKeyUsageContains(ReadOnlySpan<byte> der, ReadOnlySpan<byte> expectedOidValue)
    {
        var outer = Der.First(der) ?? throw new PsignException("ExtendedKeyUsage extension header: malformed DER");
        if (outer.Tag != 0x30)
        {
            throw new PsignException("ExtendedKeyUsage extension is not a SEQUENCE");
        }

        if (outer.End != der.Length)
        {
            throw new PsignException("ExtendedKeyUsage extension trailing data: trailing data");
        }

        bool found = false;
        int pos = outer.ValueStart;
        while (pos < outer.ValueEnd)
        {
            var entry = Der.TlvAt(der, pos, outer.ValueEnd) ?? throw new PsignException("ExtendedKeyUsage OID header: malformed DER");
            if (entry.Tag != 0x06)
            {
                throw new PsignException("ExtendedKeyUsage entry is not an OBJECT IDENTIFIER");
            }

            var value = entry.Value(der);
            if (!OidValueIsCanonical(value))
            {
                throw new PsignException("ExtendedKeyUsage contains a non-canonical or truncated OID");
            }

            found |= value.SequenceEqual(expectedOidValue);
            pos = entry.End;
        }

        return found;
    }

    private static readonly byte[] CodeSigningOidValue = OidValue(Oids.EkuCodeSigning);

    internal static byte[] OidValue(string oid)
    {
        var tlv = Der.EncodeOid(oid);
        var t = Der.First(tlv)!.Value;
        return t.Value(tlv).ToArray();
    }

    /// <summary><c>x509_cert_has_code_signing_eku</c>.</summary>
    public static bool HasCodeSigningEku(CertificateInfo cert)
    {
        foreach (var ext in cert.Extensions.Where(e => e.Oid == Oids.ExtendedKeyUsage))
        {
            if (ExtendedKeyUsageContains(ext.Value, CodeSigningOidValue))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Embedded X.509 certificates (non-certificate choices skipped; malformed ones are an error).</summary>
    public static List<CertificateInfo> EmbeddedCertificatesStrict(CmsSignedData sd, string errorPrefix)
    {
        var output = new List<CertificateInfo>();
        if (sd.Certificates is null)
        {
            return output;
        }

        foreach (var c in sd.Certificates)
        {
            if (c.Length == 0 || c[0] != 0x30)
            {
                continue;
            }

            try
            {
                output.Add(CertificateInfo.Parse(c));
            }
            catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException or CryptographicException)
            {
                throw new PsignException($"{errorPrefix}: {e.Message}");
            }
        }

        return output;
    }
}
