using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Cab;

/// <summary>
/// CAB Authenticode producers (port of Rust <c>pkcs7::create_cab_authenticode_pkcs7_der_rsa</c> and the
/// <c>portable sign-cab</c> flow).
/// </summary>
public static class CabSigning
{
    /// <summary>
    /// Authenticode <c>SpcIndirectDataContent</c> for an unsigned CAB: the digest is computed over the image as it will
    /// look after the reserve header is inserted (Rust <c>cab_spc_indirect_data</c> over
    /// <c>cab_authenticode_digest_for_signing</c>).
    /// </summary>
    public static SpcIndirectDataContent IndirectData(ReadOnlySpan<byte> unsignedCab, AuthenticodeHashKind kind) =>
        SpcIndirectDataContent.ForCab(kind, CabDigest.AuthenticodeDigestForSigning(unsignedCab, kind));

    /// <summary>Digest a remote signer must sign for <paramref name="unsignedCab"/>.</summary>
    public static byte[] RemoteSignedAttributesDigest(ReadOnlySpan<byte> unsignedCab, AuthenticodeHashKind kind)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return Pkcs7Builder.AuthenticodeRemoteSignedAttributesDigest(IndirectData(unsignedCab, kind), kind);
    }

    /// <summary>Create PKCS#7 <c>ContentInfo(SignedData)</c> DER for a CAB Authenticode signature.</summary>
    public static byte[] CreateAuthenticodePkcs7(
        ReadOnlySpan<byte> unsignedCab,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return Pkcs7Builder.CreateAuthenticode(IndirectData(unsignedCab, kind), kind, signerCert, chainCerts, signer);
    }

    /// <summary>Create PKCS#7 DER for a CAB Authenticode signature using an RSA private key.</summary>
    public static byte[] CreateAuthenticodePkcs7(
        ReadOnlySpan<byte> unsignedCab,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) =>
        CreateAuthenticodePkcs7(unsignedCab, kind, signerCert, chainCerts, new RsaDigestSigner(key));

    /// <summary>
    /// Sign an unsigned CAB: create the PKCS#7 signature and embed it after inserting the reserve header (same output as
    /// <c>psign-tool portable sign-cab</c> without a timestamp).
    /// </summary>
    public static byte[] Sign(
        ReadOnlySpan<byte> unsignedCab,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer)
    {
        var pkcs7 = CreateAuthenticodePkcs7(unsignedCab, kind, signerCert, chainCerts, signer);
        return CabDigest.AppendAuthenticodePkcs7Signature(unsignedCab, pkcs7);
    }

    /// <summary>Sign an unsigned CAB with a local RSA key.</summary>
    public static byte[] Sign(
        ReadOnlySpan<byte> unsignedCab,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) =>
        Sign(unsignedCab, kind, signerCert, chainCerts, new RsaDigestSigner(key));
}
