using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Rdp;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Keys;

namespace Devolutions.Psign.Signing.Rdp;

/// <summary>Local signing identity for RDP files: signer certificate, extra certificates, and the signer.</summary>
public sealed class RdpSigningIdentity
{
    public RdpSigningIdentity(CertificateInfo signerCertificate, IReadOnlyList<CertificateInfo> chainCertificates, IDigestSigner signer)
    {
        SignerCertificate = signerCertificate;
        ChainCertificates = chainCertificates;
        Signer = signer;
    }

    public CertificateInfo SignerCertificate { get; }

    public IReadOnlyList<CertificateInfo> ChainCertificates { get; }

    public IDigestSigner Signer { get; }

    /// <summary>
    /// Load <c>--cert</c> / <c>--key</c> / <c>--chain-cert</c> files with the Rust error contexts
    /// (<c>read …</c>, <c>parse signer certificate …</c>, <c>parse RSA private key …</c>, <c>parse chain certificate …</c>).
    /// </summary>
    public static RdpSigningIdentity FromFiles(string certPath, string keyPath, IEnumerable<string> chainCertPaths)
    {
        var certBytes = RdpSigner.ReadFile(certPath);
        CertificateInfo signerCert;
        try
        {
            signerCert = CertificateLoader.ParseCertificate(certBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse signer certificate {certPath}", e);
        }

        var keyBytes = RdpSigner.ReadFile(keyPath);
        RSA key;
        try
        {
            key = PrivateKeyLoader.ParseRsaPrivateKey(keyBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse RSA private key {keyPath}", e);
        }

        var chain = new List<CertificateInfo>();
        foreach (var path in chainCertPaths)
        {
            var bytes = RdpSigner.ReadFile(path);
            try
            {
                chain.Add(CertificateLoader.ParseCertificate(bytes));
            }
            catch (PsignException e)
            {
                throw new PsignException($"parse chain certificate {path}", e);
            }
        }

        return new RdpSigningIdentity(signerCert, chain, new RsaDigestSigner(key));
    }
}

/// <summary>Result of signing one RDP document.</summary>
/// <param name="Prepared">Records (with <c>SignScope</c> and <c>Signature</c>), scope, and secure blob.</param>
/// <param name="Pkcs7">Detached PKCS#7 placed in the <c>Signature</c> record.</param>
/// <param name="Output">Native UTF-16LE (BOM) <c>.rdp</c> bytes.</param>
public sealed record RdpSignedContent(PreparedRdpSignature Prepared, byte[] Pkcs7, byte[] Output);

/// <summary>Options for <see cref="RdpSigner.Run"/> (mirror of <c>psign-tool portable rdp</c> arguments).</summary>
public sealed class RdpPortableSignOptions
{
    /// <summary>Signer certificate (DER or PEM).</summary>
    public string? CertPath { get; init; }

    /// <summary>RSA private key (PKCS#8 / PKCS#1, DER or PEM).</summary>
    public string? KeyPath { get; init; }

    /// <summary>Additional certificates for the PKCS#7 certificate set.</summary>
    public IReadOnlyList<string> ChainCertPaths { get; init; } = [];

    /// <summary>Externally created detached PKCS#7 to embed (single input only).</summary>
    public string? SignaturePkcs7Path { get; init; }

    /// <summary>Build and validate without writing files.</summary>
    public bool DryRun { get; init; }

    /// <summary>Output path (single input only).</summary>
    public string? OutputPath { get; init; }

    /// <summary>Input <c>.rdp</c> files.</summary>
    public IReadOnlyList<string> Files { get; init; } = [];
}

/// <summary>
/// Portable RDP signing (port of <c>parse_rsa_private_key</c> / <c>sign_secure_blob_rsa_sha256</c> in
/// <c>psign-sip-digest/src/rdp.rs</c>, the portable <c>rdp</c> command flow in <c>psign-digest-cli</c>, and the
/// platform-independent checks of <c>src/win/rdp.rs</c>).
/// </summary>
public static class RdpSigner
{
    /// <summary>Default hash algorithm OID used by <c>mstsc</c> RDP signing (SHA-256).</summary>
    public const string DefaultRdpHashOid = Oids.Sha256;

    /// <summary>EKUs accepted by the native RDP signer (serverAuth, codeSigning, RDP signing).</summary>
    public static IReadOnlyList<string> RdpSigningEkus { get; } = [Oids.EkuServerAuth, Oids.EkuCodeSigning, "1.3.6.1.4.1.311.54.1.1"];

    /// <summary>Parse an RSA private key (Rust <c>rdp::parse_rsa_private_key</c>).</summary>
    public static RSA ParseRsaPrivateKey(ReadOnlySpan<byte> bytes) => PrivateKeyLoader.ParseRsaPrivateKey(bytes);

    /// <summary>Parse a DER or PEM certificate (Rust <c>rdp::parse_certificate</c>).</summary>
    public static CertificateInfo ParseCertificate(ReadOnlySpan<byte> bytes) => CertificateLoader.ParseCertificate(bytes);

    /// <summary>
    /// Create the detached CMS <c>SignedData</c> over <paramref name="secureBlob"/> that the <c>cms</c> crate builder
    /// produces in Rust <c>sign_secure_blob_rsa_sha256</c>: <c>id-data</c> without eContent, SHA-256 (absent parameters),
    /// signed attributes <c>contentType</c> + <c>messageDigest</c>, <c>sha256WithRSAEncryption</c>, and the signer
    /// certificate followed by <paramref name="chainCerts"/> (no de-duplication; duplicates are rejected).
    /// </summary>
    public static byte[] SignSecureBlobRsaSha256(byte[] secureBlob, CertificateInfo signerCert, IEnumerable<CertificateInfo> chainCerts, IDigestSigner signer)
    {
        const AuthenticodeHashKind kind = AuthenticodeHashKind.Sha256;
        var attrs = new List<CmsAttribute>
        {
            Pkcs7Builder.MessageDigestAttribute(SHA256.HashData(secureBlob)),
            Pkcs7Builder.ContentTypeAttribute(Oids.Pkcs7Data),
        };
        byte[] signature;
        try
        {
            signature = signer.SignDigest(Pkcs7Builder.SignedAttributesDigest(attrs, kind), kind);
        }
        catch (CryptographicException e)
        {
            throw new PsignException("sign PKCS#7 signed attributes", e);
        }

        var signerInfo = new CmsSignerInfo(
            1,
            CmsSignerInfo.IssuerAndSerialSid(signerCert),
            Pkcs7Builder.DigestAlgorithm(kind),
            attrs,
            Pkcs7Builder.RsaDigestSignatureAlgorithm(kind),
            signature,
            null);

        var certs = new List<byte[]> { signerCert.RawData };
        foreach (var c in chainCerts)
        {
            if (certs.Any(existing => existing.AsSpan().SequenceEqual(c.RawData)))
            {
                throw new PsignException("build PKCS#7 SignedData", new PsignException("duplicate certificate in SET OF"));
            }

            certs.Add(c.RawData);
        }

        var sd = new CmsSignedData(1, [Pkcs7Builder.DigestAlgorithm(kind)], Oids.Pkcs7Data, null, certs, null, [signerInfo]);
        return sd.Encode();
    }

    /// <summary><see cref="SignSecureBlobRsaSha256(byte[], CertificateInfo, IEnumerable{CertificateInfo}, IDigestSigner)"/> with a local RSA key.</summary>
    public static byte[] SignSecureBlobRsaSha256(byte[] secureBlob, CertificateInfo signerCert, IEnumerable<CertificateInfo> chainCerts, RSA key) =>
        SignSecureBlobRsaSha256(secureBlob, signerCert, chainCerts, new RsaDigestSigner(key));

    /// <summary>
    /// Decode, prepare, sign and re-encode one RDP document. <paramref name="pkcs7Producer"/> receives the secure-settings
    /// blob and returns the detached PKCS#7 to embed.
    /// </summary>
    public static RdpSignedContent SignContent(ReadOnlySpan<byte> input, Func<byte[], byte[]> pkcs7Producer)
    {
        var text = RdpFile.DecodeRdpText(input);
        var records = RdpFile.ParseRecords(text);
        var prepared = RdpFile.PrepareForSignature(records);
        var pkcs7 = pkcs7Producer(prepared.SecureBlob);
        RdpFile.ApplyPkcs7Signature(prepared.Records, pkcs7);
        var output = RdpFile.EncodeNativeUnicode(RdpFile.RecordsToText(prepared.Records));
        return new RdpSignedContent(prepared, pkcs7, output);
    }

    /// <summary>Sign one RDP document with a local identity.</summary>
    public static RdpSignedContent SignContent(ReadOnlySpan<byte> input, RdpSigningIdentity identity) =>
        SignContent(input, blob => SignSecureBlobRsaSha256(blob, identity.SignerCertificate, identity.ChainCertificates, identity.Signer));

    /// <summary>
    /// Run the portable <c>rdp</c> command flow (Rust <c>run_rdp_portable</c>): validate options, load the identity or
    /// external PKCS#7, then sign each file. Progress lines (<c>Test signed …</c> / <c>Signed …</c>) are passed to
    /// <paramref name="writeLine"/>. Errors carry the Rust context chain.
    /// </summary>
    public static void Run(RdpPortableSignOptions options, Action<string> writeLine)
    {
        var files = options.Files;
        if (files.Count == 0)
        {
            throw new PsignException("rdp requires at least one input file");
        }

        if (options.OutputPath is not null && files.Count != 1)
        {
            throw new PsignException("--output is only valid with one input file");
        }

        if (options.DryRun && options.OutputPath is not null)
        {
            throw new PsignException("--dry-run cannot be combined with --output");
        }

        if (options.SignaturePkcs7Path is not null && files.Count != 1)
        {
            throw new PsignException("--signature-pkcs7 is only valid with one input file because it signs one secure blob");
        }

        byte[]? externalPkcs7 = options.SignaturePkcs7Path is null ? null : ReadFile(options.SignaturePkcs7Path);

        RdpSigningIdentity? identity;
        if (options.CertPath is not null && options.KeyPath is not null)
        {
            identity = RdpSigningIdentity.FromFiles(options.CertPath, options.KeyPath, options.ChainCertPaths);
        }
        else if (options.CertPath is null && options.KeyPath is null && externalPkcs7 is not null)
        {
            identity = null;
        }
        else
        {
            throw new PsignException("rdp requires either --cert and --key, or --signature-pkcs7");
        }

        foreach (var path in files)
        {
            var input = ReadFile(path);
            var text = RdpFile.DecodeRdpText(input);
            var records = RdpFile.ParseRecords(text);
            PreparedRdpSignature prepared;
            try
            {
                prepared = RdpFile.PrepareForSignature(records);
            }
            catch (PsignException e)
            {
                throw new PsignException($"prepare RDP signature scope for {path}", e);
            }

            byte[] pkcs7;
            if (externalPkcs7 is not null)
            {
                pkcs7 = externalPkcs7;
            }
            else
            {
                try
                {
                    pkcs7 = SignSecureBlobRsaSha256(prepared.SecureBlob, identity!.SignerCertificate, identity.ChainCertificates, identity.Signer);
                }
                catch (PsignException e)
                {
                    throw new PsignException($"sign {path}", e);
                }
            }

            RdpFile.ApplyPkcs7Signature(prepared.Records, pkcs7);
            if (options.DryRun)
            {
                writeLine($"Test signed {path}");
                continue;
            }

            var destination = options.OutputPath ?? path;
            var output = RdpFile.EncodeNativeUnicode(RdpFile.RecordsToText(prepared.Records));
            try
            {
                File.WriteAllBytes(destination, output);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new PsignException($"write {destination}", e);
            }

            writeLine($"Signed {destination}");
        }
    }

    /// <summary>
    /// Parse a certificate thumbprint for the native <c>rdp --sha256/--sha1</c> selection: colons, spaces and LRM/RLM
    /// marks are removed and exactly <paramref name="length"/> bytes of hex are required (Rust <c>win::rdp::parse_hex</c>).
    /// </summary>
    public static byte[] ParseThumbprint(string input, int length, string label)
    {
        var clean = input.Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("‎", string.Empty, StringComparison.Ordinal)
            .Replace("‏", string.Empty, StringComparison.Ordinal);
        if (System.Text.Encoding.UTF8.GetByteCount(clean) != length * 2)
        {
            throw new PsignException($"{label} thumbprint must be {length * 2} hex characters");
        }

        var result = new byte[length];
        for (int i = 0; i < length; i++)
        {
            byte? b = clean.Length == length * 2 ? RustText.ParseHexPair(clean[2 * i], clean[(2 * i) + 1]) : null;
            result[i] = b ?? throw new PsignException($"{label} thumbprint contains invalid hex");
        }

        return result;
    }

    /// <summary>True when <paramref name="cert"/>'s SHA-1 (20-byte) or SHA-256 (32-byte) thumbprint equals <paramref name="thumbprint"/>.</summary>
    public static bool ThumbprintMatches(CertificateInfo cert, ReadOnlySpan<byte> thumbprint) => thumbprint.Length switch
    {
        20 => SHA1.HashData(cert.RawData).AsSpan().SequenceEqual(thumbprint),
        32 => SHA256.HashData(cert.RawData).AsSpan().SequenceEqual(thumbprint),
        _ => false,
    };

    /// <summary>
    /// Native RDP signing certificate checks (Rust <c>validate_rdp_signing_cert</c>): when an EKU extension is present it
    /// must contain serverAuth, codeSigning, or the RDP signing EKU, and <paramref name="now"/> must be within the
    /// validity period.
    /// </summary>
    public static void ValidateSigningCertificate(CertificateInfo cert, DateTimeOffset now)
    {
        var usages = cert.ExtendedKeyUsages;
        if (usages is { Count: > 0 } && !RdpSigningEkus.Any(oid => usages.Contains(oid)))
        {
            throw new PsignException("certificate is not valid for RDP signing; expected serverAuth, codeSigning, or RDP signing EKU");
        }

        if (now < cert.NotBefore || now > cert.NotAfter)
        {
            throw new PsignException("certificate is outside its validity period");
        }
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
}
