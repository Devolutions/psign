using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Scripts;

namespace Devolutions.Psign.Signing.Zip;

/// <summary>
/// Devolutions ZIP Authenticode signing (port of <c>sign_zip</c> in <c>psign-portable-core</c>): compute the
/// <c>sha256:</c> ZIP digest, Authenticode-sign it as an unsigned UTF-8 <c>.sig.ps1</c>, and store
/// <c>ZipAuthenticode=&lt;digest&gt;,&lt;base64 PKCS#7&gt;</c> as the ZIP comment. Byte-identical to Rust for the same key.
/// </summary>
public static class ZipAuthenticodeSigner
{
    /// <summary>Create the PKCS#7 for a ZIP digest string (the Authenticode signature of the <c>.sig.ps1</c> bridge script).</summary>
    public static byte[] CreateSignaturePkcs7(
        string digest,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer) =>
        ScriptSigner.CreateScriptAuthenticodePkcs7(ZipAuthenticode.UnsignedSignatureScriptBytes(digest), kind, signerCert, chainCerts, signer);

    /// <summary>Digest of the Authenticode signed attributes that a remote signer must sign for <paramref name="zip"/>.</summary>
    public static byte[] RemoteSignedAttributesDigest(ReadOnlySpan<byte> zip, AuthenticodeHashKind kind) =>
        ScriptSigner.RemoteSignedAttributesDigest(ZipAuthenticode.UnsignedSignatureScriptBytes(ZipAuthenticode.ZipAuthenticodeDigestString(zip)), kind);

    /// <summary>Sign ZIP bytes and return the signed ZIP (the existing comment is replaced).</summary>
    public static byte[] SignZip(
        ReadOnlySpan<byte> zip,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        Func<byte[], byte[]>? timestamp = null)
    {
        var digest = ZipAuthenticode.ZipAuthenticodeDigestString(zip);
        var pkcs7 = CreateSignaturePkcs7(digest, kind, signerCert, chainCerts, signer);
        if (timestamp is not null)
        {
            pkcs7 = timestamp(pkcs7);
        }

        var line = ZipAuthenticode.SignatureCommentLineFromPkcs7Der(digest, pkcs7);
        return ZipAuthenticode.EmbedSignatureCommentLine(zip, line);
    }

    /// <summary>Sign ZIP bytes with a local RSA key.</summary>
    public static byte[] SignZip(
        ReadOnlySpan<byte> zip,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key,
        Func<byte[], byte[]>? timestamp = null) =>
        SignZip(zip, kind, signerCert, chainCerts, new RsaDigestSigner(key), timestamp);

    /// <summary>File-based <see cref="SignZip(ReadOnlySpan{byte}, AuthenticodeHashKind, CertificateInfo, IEnumerable{CertificateInfo}, IDigestSigner, Func{byte[], byte[]})"/> with the Rust error contexts.</summary>
    public static void SignZipFile(
        string inputPath,
        string outputPath,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        Func<byte[], byte[]>? timestamp = null)
    {
        var zip = ScriptSigner.ReadFile(inputPath);
        string digest;
        try
        {
            digest = ZipAuthenticode.ZipAuthenticodeDigestString(zip);
        }
        catch (PsignException e)
        {
            throw new PsignException($"compute ZIP Authenticode digest for {inputPath}", e);
        }

        byte[] pkcs7;
        try
        {
            pkcs7 = CreateSignaturePkcs7(digest, kind, signerCert, chainCerts, signer);
        }
        catch (Exception e) when (e is PsignException or CryptographicException)
        {
            throw new PsignException($"create portable ZIP signature script Authenticode signature for {inputPath}", e);
        }

        if (timestamp is not null)
        {
            try
            {
                pkcs7 = timestamp(pkcs7);
            }
            catch (PsignException e)
            {
                throw new PsignException($"timestamp {inputPath}", e);
            }
        }

        var line = ZipAuthenticode.SignatureCommentLineFromPkcs7Der(digest, pkcs7);
        byte[] signed;
        try
        {
            signed = ZipAuthenticode.EmbedSignatureCommentLine(zip, line);
        }
        catch (PsignException e)
        {
            throw new PsignException($"embed ZIP Authenticode comment in {inputPath}", e);
        }

        ScriptSigner.WriteFile(outputPath, signed);
    }
}
