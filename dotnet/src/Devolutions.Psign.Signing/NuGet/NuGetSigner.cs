using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.NuGet;

/// <summary>Result of <see cref="NuGetSigner.SignPackage(byte[], NuGetHashAlgorithm, CertificateInfo, IEnumerable{CertificateInfo}, IDigestSigner, bool, DateTimeOffset?, ZipDateTime?, Func{byte[], byte[]}?)"/>.</summary>
public sealed record NuGetSignResult(byte[] SignedPackage, byte[] SignatureDer, byte[] SignatureContent);

/// <summary>
/// NuGet author signing (ported from the <c>nupkg-signature-pkcs7*</c> / <c>nupkg-sign</c> handlers in Rust
/// <c>psign-digest-cli/src/main.rs</c> and <c>sign_nuget_bytes</c> in <c>src/code.rs</c>): attached CMS over the
/// signature content with the NuGet author signed-attribute profile, embedded as <c>.signature.p7s</c>.
/// </summary>
public static class NuGetSigner
{
    /// <summary>
    /// CMS for the canonical unsigned package's signature content (Rust <c>nupkg-signature-pkcs7</c>; profile
    /// <see cref="Pkcs7SignedAttributeProfile.NuGetAuthor"/>, attached content).
    /// </summary>
    public static byte[] CreateSignaturePkcs7(
        byte[] package,
        NuGetHashAlgorithm algorithm,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        DateTimeOffset? signingTime = null)
    {
        var content = NuGetPackage.UnsignedPackageSignatureContent(package, algorithm);
        return SignContent(content, algorithm, signerCert, chainCerts, signer, signingTime);
    }

    /// <summary><see cref="CreateSignaturePkcs7(byte[], NuGetHashAlgorithm, CertificateInfo, IEnumerable{CertificateInfo}, IDigestSigner, DateTimeOffset?)"/> with a local RSA key.</summary>
    public static byte[] CreateSignaturePkcs7(
        byte[] package,
        NuGetHashAlgorithm algorithm,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key,
        DateTimeOffset? signingTime = null) =>
        CreateSignaturePkcs7(package, algorithm, signerCert, chainCerts, new RsaDigestSigner(key), signingTime);

    /// <summary>CMS over already computed signature content (Rust <c>sign_pkcs7_id_data</c> with <c>NuGetAuthor</c>).</summary>
    public static byte[] SignContent(
        byte[] content,
        NuGetHashAlgorithm algorithm,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        DateTimeOffset? signingTime = null) =>
        Pkcs7IdData.Sign(content, signerCert, chainCerts, signer, algorithm.ToHashKind(), Pkcs7ContentMode.Attached, Pkcs7SignedAttributeProfile.NuGetAuthor, signingTime);

    /// <summary>
    /// Signed-attributes digest for remote signing (Rust <c>nupkg-signature-pkcs7-prehash</c>; profile
    /// <see cref="Pkcs7SignedAttributeProfile.NuGetAuthorWithoutSigningTime"/>).
    /// </summary>
    public static byte[] SignaturePkcs7Prehash(byte[] package, NuGetHashAlgorithm algorithm, CertificateInfo signerCert)
    {
        var content = NuGetPackage.UnsignedPackageSignatureContent(package, algorithm);
        return Pkcs7IdData.RemotePrehash(content, algorithm.ToHashKind(), Pkcs7SignedAttributeProfile.NuGetAuthorWithoutSigningTime, signerCert);
    }

    /// <summary>CMS assembled from an external RSA signature over <see cref="SignaturePkcs7Prehash"/> (Rust <c>nupkg-signature-pkcs7-from-signature</c>).</summary>
    public static byte[] SignaturePkcs7FromSignature(
        byte[] package,
        NuGetHashAlgorithm algorithm,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        byte[] signature)
    {
        var content = NuGetPackage.UnsignedPackageSignatureContent(package, algorithm);
        return Pkcs7IdData.SignWithExternalSignature(
            content,
            signerCert,
            chainCerts,
            algorithm.ToHashKind(),
            signature,
            Pkcs7ContentMode.Attached,
            Pkcs7SignedAttributeProfile.NuGetAuthorWithoutSigningTime);
    }

    /// <summary>Attach an RFC 3161 token as <c>id-aa-timeStampToken</c> (NuGet's timestamp attribute).</summary>
    public static byte[] AttachTimestampToken(byte[] pkcs7Der, byte[] token) =>
        Pkcs7IdData.AttachTimestampToken(pkcs7Der, token, Rfc3161TimestampAttribute.CmsTimeStampToken);

    /// <summary>
    /// Sign a package end-to-end (Rust <c>nupkg-sign</c>): signature content of the canonical unsigned package, CMS,
    /// optional RFC 3161 timestamp through <paramref name="timestampToken"/> (receives the signature value, returns
    /// the token DER), and embedding as the last stored entry.
    /// </summary>
    public static NuGetSignResult SignPackage(
        byte[] package,
        NuGetHashAlgorithm algorithm,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        bool overwrite,
        DateTimeOffset? signingTime = null,
        ZipDateTime? zipTimestamp = null,
        Func<byte[], byte[]>? timestampToken = null)
    {
        var info = NuGetPackage.InspectNupkg(package);
        if (info.Signed && !overwrite)
        {
            throw new PsignException($"package already contains {NuGetPackage.PackageSignatureFileName}; pass overwrite to replace it");
        }

        var content = NuGetPackage.UnsignedPackageSignatureContent(package, algorithm);
        var pkcs7 = SignContent(content, algorithm, signerCert, chainCerts, signer, signingTime);
        if (timestampToken is not null)
        {
            pkcs7 = Pkcs7IdData.Timestamp(pkcs7, timestampToken, Rfc3161TimestampAttribute.CmsTimeStampToken);
        }

        var signed = NuGetPackage.EmbedSignature(package, pkcs7, overwrite, zipTimestamp);
        return new NuGetSignResult(signed, pkcs7, content);
    }

    /// <summary>Path form of <c>nupkg-sign</c>; returns the CMS written into the package.</summary>
    public static byte[] SignPackagePath(
        string path,
        string output,
        NuGetHashAlgorithm algorithm,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        bool overwrite,
        DateTimeOffset? signingTime = null,
        ZipDateTime? zipTimestamp = null,
        Func<byte[], byte[]>? timestampToken = null)
    {
        var content = NuGetPackage.UnsignedPackageSignatureContentPath(path, algorithm);
        byte[] pkcs7;
        try
        {
            pkcs7 = SignContent(content, algorithm, signerCert, chainCerts, signer, signingTime);
        }
        catch (PsignException e)
        {
            throw new PsignException($"nupkg-sign create CMS for {path}", e);
        }

        if (timestampToken is not null)
        {
            pkcs7 = Pkcs7IdData.Timestamp(pkcs7, timestampToken, Rfc3161TimestampAttribute.CmsTimeStampToken);
        }

        try
        {
            NuGetPackage.EmbedSignaturePath(path, output, pkcs7, overwrite, zipTimestamp);
        }
        catch (PsignException e)
        {
            throw new PsignException($"nupkg-sign embed signature into {output}", e);
        }

        return pkcs7;
    }
}
