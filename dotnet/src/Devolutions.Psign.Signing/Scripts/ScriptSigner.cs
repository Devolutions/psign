using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Scripts;

/// <summary>
/// PowerShell-class script Authenticode signing (port of <c>script_spc_indirect_data</c>,
/// <c>script_authenticode_spc_indirect_data</c>, <c>create_script_authenticode_pkcs7_der_rsa</c> in <c>pkcs7.rs</c> and
/// <c>sign_script</c> in <c>psign-portable-core</c>). Output is byte-identical to the Rust signer for the same key.
/// </summary>
public static class ScriptSigner
{
    private static readonly string[] SignableExtensions = ["ps1", "psd1", "psm1", "ps1xml", "psc1", "cdxml", "mof"];

    /// <summary><c>SpcIndirectDataContent</c> for a precomputed script digest (Rust <c>script_spc_indirect_data</c>).</summary>
    public static SpcIndirectDataContent ScriptSpcIndirectData(AuthenticodeHashKind kind, byte[] scriptDigest)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return SpcIndirectDataContent.ForScript(kind, scriptDigest);
    }

    /// <summary>
    /// <c>SpcIndirectDataContent</c> for an unsigned PowerShell-class script: hash of the UTF-16LE bytes of the decoded
    /// file (Rust <c>script_authenticode_spc_indirect_data</c>).
    /// </summary>
    public static SpcIndirectDataContent ScriptAuthenticodeSpcIndirectData(ReadOnlySpan<byte> script, AuthenticodeHashKind kind)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return SpcIndirectDataContent.ForScript(kind, PsScript.SigningDigest(script, kind));
    }

    /// <summary>Digest of the Authenticode signed attributes that a remote signer must sign for <paramref name="script"/>.</summary>
    public static byte[] RemoteSignedAttributesDigest(ReadOnlySpan<byte> script, AuthenticodeHashKind kind) =>
        Pkcs7Builder.AuthenticodeRemoteSignedAttributesDigest(ScriptAuthenticodeSpcIndirectData(script, kind), kind);

    /// <summary>Create the PKCS#7 <c>ContentInfo(SignedData)</c> for a PowerShell-class script (Rust <c>create_script_authenticode_pkcs7_der_rsa</c>).</summary>
    public static byte[] CreateScriptAuthenticodePkcs7(
        ReadOnlySpan<byte> script,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer) =>
        Pkcs7Builder.CreateAuthenticode(ScriptAuthenticodeSpcIndirectData(script, kind), kind, signerCert, chainCerts, signer);

    /// <summary>Create the script PKCS#7 with a local RSA key.</summary>
    public static byte[] CreateScriptAuthenticodePkcs7(
        ReadOnlySpan<byte> script,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) =>
        CreateScriptAuthenticodePkcs7(script, kind, signerCert, chainCerts, new RsaDigestSigner(key));

    /// <summary>True for extensions the portable script signer accepts.</summary>
    public static bool IsSignableExtension(string extension) => SignableExtensions.Contains(RustText.ToAsciiLowercase(extension));

    /// <summary>
    /// Sign a PowerShell-class script: build the Authenticode PKCS#7 over the unsigned bytes, optionally pass it through
    /// <paramref name="timestamp"/> (for an RFC 3161 countersignature), and append the signature block in the script's
    /// own encoding (Rust <c>sign_script</c>).
    /// </summary>
    public static byte[] SignScript(
        ReadOnlySpan<byte> script,
        string extension,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        Func<byte[], byte[]>? timestamp = null)
    {
        var ext = RustText.ToAsciiLowercase(extension);
        if (!IsSignableExtension(ext))
        {
            throw new PsignException("portable script signing supports ps1, psd1, psm1, ps1xml, psc1, cdxml, and mof scripts");
        }

        var pkcs7 = CreateScriptAuthenticodePkcs7(script, kind, signerCert, chainCerts, signer);
        if (timestamp is not null)
        {
            pkcs7 = timestamp(pkcs7);
        }

        return ScriptSignatureBlock.Embed(script, pkcs7, ext);
    }

    /// <summary>Sign a script with a local RSA key.</summary>
    public static byte[] SignScript(
        ReadOnlySpan<byte> script,
        string extension,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key,
        Func<byte[], byte[]>? timestamp = null) =>
        SignScript(script, extension, kind, signerCert, chainCerts, new RsaDigestSigner(key), timestamp);

    /// <summary>
    /// File-based <see cref="SignScript(ReadOnlySpan{byte}, string, AuthenticodeHashKind, CertificateInfo, IEnumerable{CertificateInfo}, IDigestSigner, Func{byte[], byte[]})"/>
    /// with the Rust error contexts. The extension comes from <paramref name="inputPath"/> (default <c>ps1</c>).
    /// </summary>
    public static void SignScriptFile(
        string inputPath,
        string outputPath,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer,
        Func<byte[], byte[]>? timestamp = null)
    {
        var ext = Path.GetExtension(inputPath).TrimStart('.');
        if (ext.Length == 0)
        {
            ext = "ps1";
        }

        ext = RustText.ToAsciiLowercase(ext);
        if (!IsSignableExtension(ext))
        {
            throw new PsignException("portable script signing supports ps1, psd1, psm1, ps1xml, psc1, cdxml, and mof scripts");
        }

        var script = ReadFile(inputPath);
        byte[] pkcs7;
        try
        {
            pkcs7 = CreateScriptAuthenticodePkcs7(script, kind, signerCert, chainCerts, signer);
        }
        catch (Exception e) when (e is PsignException or CryptographicException)
        {
            throw new PsignException($"create portable script Authenticode signature for {inputPath}", e);
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

        WriteFile(outputPath, ScriptSignatureBlock.Embed(script, pkcs7, ext));
    }

    internal static byte[] ReadFile(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read {path}", e);
        }
    }

    internal static void WriteFile(string path, byte[] data)
    {
        try
        {
            File.WriteAllBytes(path, data);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"write {path}", e);
        }
    }
}
