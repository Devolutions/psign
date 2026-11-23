using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.ClickOnce;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Signing.ClickOnce;

/// <summary>
/// ClickOnce manifest XMLDSig signing (ported from <c>sign_clickonce_manifest_path</c> /
/// <c>sign_clickonce_signed_info</c> in Rust <c>psign-digest-cli/src/main.rs</c> and
/// <c>sign_clickonce_manifest_bytes</c> in <c>src/code.rs</c>).
/// </summary>
public static class ClickOnceSigner
{
    /// <summary>RSA PKCS#1 v1.5 signature over the <c>SignedInfo</c> octets (Rust <c>sign_clickonce_signed_info</c>).</summary>
    public static byte[] SignSignedInfo(AuthenticodeHashKind digest, RSA key, byte[] signedInfo) =>
        key.SignData(signedInfo, ClickOnceManifest.RequireSignDigest(digest).HashAlgorithmName(), RSASignaturePadding.Pkcs1);

    /// <summary>
    /// Sign manifest text: strip any existing signature, build <c>SignedInfo</c>, sign it with
    /// <paramref name="signSignedInfo"/>, and insert the <c>Signature</c> before the root end tag.
    /// </summary>
    public static (string SignedManifest, ClickOnceManifestSignatureReport Report) SignManifest(
        string manifestText,
        AuthenticodeHashKind digest,
        byte[] certBytes,
        Func<byte[], byte[]> signSignedInfo,
        string certLabel = "certificate")
    {
        string unsigned = ClickOnceManifest.UnsignedManifestText(manifestText);
        try
        {
            CertificateLoader.ParseCertificate(certBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse signer certificate {certLabel}", e);
        }

        byte[] signedInfo = ClickOnceManifest.SignedInfoXml(unsigned, digest);
        byte[] signature = signSignedInfo(signedInfo);
        string signatureXml = ClickOnceManifest.SignatureXml(signedInfo, signature, certBytes);
        string signed = ClickOnceManifest.InsertSignatureXml(unsigned, signatureXml);
        return (signed, new ClickOnceManifestSignatureReport(digest, Convert.ToBase64String(ClickOnceManifest.ManifestDigest(unsigned, digest)), signature.Length));
    }

    /// <summary><see cref="SignManifest(string, AuthenticodeHashKind, byte[], Func{byte[], byte[]}, string)"/> with a local RSA key.</summary>
    public static (string SignedManifest, ClickOnceManifestSignatureReport Report) SignManifest(
        string manifestText,
        AuthenticodeHashKind digest,
        byte[] certBytes,
        RSA key,
        string certLabel = "certificate") =>
        SignManifest(manifestText, digest, certBytes, si => SignSignedInfo(digest, key, si), certLabel);

    /// <summary>Rust <c>sign_clickonce_manifest_path</c> (the caller loads the RSA key).</summary>
    public static ClickOnceManifestSignatureReport SignManifestPath(string path, string certPath, RSA key, AuthenticodeHashKind digest, string output)
    {
        string text = ClickOnceManifest.ReadManifestText(path);
        byte[] certBytes = ClickOnceManifest.ReadFile(certPath);
        var (signed, report) = SignManifest(text, digest, certBytes, key, certPath);
        ClickOnceManifest.WriteManifest(output, signed);
        return report;
    }
}
