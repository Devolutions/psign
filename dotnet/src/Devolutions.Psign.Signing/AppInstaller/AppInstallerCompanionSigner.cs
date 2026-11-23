using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.AppInstaller;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.AppInstaller;

/// <summary>
/// App Installer companion signatures (ported from the <c>appinstaller-sign-companion*</c> handlers in Rust
/// <c>psign-digest-cli/src/main.rs</c>): detached CMS over the descriptor UTF-8 octets with the basic signed-attribute
/// profile. RFC 3161 tokens use the Microsoft <c>1.3.6.1.4.1.311.3.3.1</c> attribute.
/// </summary>
public static class AppInstallerCompanionSigner
{
    /// <summary>Detached CMS over <paramref name="descriptorText"/> (Rust <c>appinstaller-sign-companion</c>).</summary>
    public static byte[] SignCompanion(
        string descriptorText,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        AuthenticodeHashKind digest)
    {
        AppInstallerDescriptor.Parse(descriptorText);
        return Pkcs7IdData.Sign(
            AppInstallerDescriptor.CompanionSignedContent(descriptorText),
            signerCert,
            chainCerts,
            signer,
            digest,
            Pkcs7ContentMode.Detached,
            Pkcs7SignedAttributeProfile.Basic);
    }

    /// <summary><see cref="SignCompanion(string, CertificateInfo, IEnumerable{CertificateInfo}, IDigestSigner, AuthenticodeHashKind)"/> with a local RSA key.</summary>
    public static byte[] SignCompanion(string descriptorText, CertificateInfo signerCert, IEnumerable<CertificateInfo> chainCerts, RSA key, AuthenticodeHashKind digest) =>
        SignCompanion(descriptorText, signerCert, chainCerts, new RsaDigestSigner(key), digest);

    /// <summary>Signed-attributes digest for remote signing (Rust <c>appinstaller-sign-companion-prehash</c>).</summary>
    public static byte[] CompanionPrehash(string descriptorText, AuthenticodeHashKind digest)
    {
        AppInstallerDescriptor.Parse(descriptorText);
        return Pkcs7IdData.RemotePrehash(AppInstallerDescriptor.CompanionSignedContent(descriptorText), digest, Pkcs7SignedAttributeProfile.Basic, null);
    }

    /// <summary>Detached CMS from an external signature over <see cref="CompanionPrehash"/> (Rust <c>appinstaller-sign-companion-from-signature</c>).</summary>
    public static byte[] SignCompanionFromSignature(
        string descriptorText,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        AuthenticodeHashKind digest,
        byte[] signature)
    {
        AppInstallerDescriptor.Parse(descriptorText);
        return Pkcs7IdData.SignWithExternalSignature(
            AppInstallerDescriptor.CompanionSignedContent(descriptorText),
            signerCert,
            chainCerts,
            digest,
            signature,
            Pkcs7ContentMode.Detached,
            Pkcs7SignedAttributeProfile.Basic);
    }

    /// <summary>Attach an RFC 3161 token with the Microsoft timestamp attribute.</summary>
    public static byte[] AttachTimestampToken(byte[] pkcs7Der, byte[] token) =>
        Pkcs7IdData.AttachTimestampToken(pkcs7Der, token, Rfc3161TimestampAttribute.MicrosoftAuthenticode);
}
