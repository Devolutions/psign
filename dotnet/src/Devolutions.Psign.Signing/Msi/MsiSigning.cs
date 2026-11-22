using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Msi;

/// <summary>
/// MSI / MSP Authenticode producers (port of Rust <c>pkcs7::create_msi_authenticode_pkcs7_der_rsa</c> and the
/// <c>portable sign-msi</c> flow).
/// </summary>
public static class MsiSigning
{
    /// <summary>
    /// Authenticode <c>SpcIndirectDataContent</c> for an image staged with
    /// <see cref="MsiDigest.PrepareForAuthenticodeSigning"/> (Rust <c>msi_spc_indirect_data</c> over
    /// <c>compute_prepared_msi_authenticode_digest</c>).
    /// </summary>
    public static SpcIndirectDataContent IndirectData(byte[] preparedImage, AuthenticodeHashKind kind) =>
        SpcIndirectDataContent.ForMsi(kind, MsiDigest.ComputePreparedAuthenticodeDigest(preparedImage, kind));

    /// <summary>Digest a remote signer must sign for a prepared MSI image.</summary>
    public static byte[] RemoteSignedAttributesDigest(byte[] preparedImage, AuthenticodeHashKind kind)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return Pkcs7Builder.AuthenticodeRemoteSignedAttributesDigest(IndirectData(preparedImage, kind), kind);
    }

    /// <summary>
    /// Create PKCS#7 <c>ContentInfo(SignedData)</c> DER for a prepared MSI / MSP image. Embed the result into that same
    /// staged image.
    /// </summary>
    public static byte[] CreateAuthenticodePkcs7(
        byte[] preparedImage,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return Pkcs7Builder.CreateAuthenticode(IndirectData(preparedImage, kind), kind, signerCert, chainCerts, signer);
    }

    /// <summary>Create PKCS#7 DER for a prepared MSI / MSP image using an RSA private key.</summary>
    public static byte[] CreateAuthenticodePkcs7(
        byte[] preparedImage,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) =>
        CreateAuthenticodePkcs7(preparedImage, kind, signerCert, chainCerts, new RsaDigestSigner(key));

    /// <summary>
    /// Sign an MSI / MSP: stage the metadata digest stream, create the PKCS#7 signature and write the root
    /// <c>\u0005DigitalSignature</c> stream (same flow as <c>psign-tool portable sign-msi</c> without a timestamp).
    /// </summary>
    public static byte[] Sign(
        byte[] msi,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        var prepared = MsiDigest.PrepareForAuthenticodeSigning(msi, kind);
        var pkcs7 = CreateAuthenticodePkcs7(prepared.Image, kind, signerCert, chainCerts, signer);
        return MsiDigest.EmbedPkcs7Signature(prepared.Image, pkcs7);
    }

    /// <summary>Sign an MSI / MSP with a local RSA key.</summary>
    public static byte[] Sign(
        byte[] msi,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) =>
        Sign(msi, kind, signerCert, chainCerts, new RsaDigestSigner(key));
}
