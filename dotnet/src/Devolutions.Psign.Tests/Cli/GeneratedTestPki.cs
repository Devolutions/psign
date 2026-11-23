using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>
/// Generated two-level PKI (root CA + RSA-2048 code signing leaf) written to <see cref="TempDir"/> with the BCL
/// <see cref="CertificateRequest"/> (test-only; the ported Rust generator is <see cref="Devolutions.Psign.Signing.Pki.TestPki"/>).
/// </summary>
internal sealed class GeneratedTestPki : IDisposable
{
    public GeneratedTestPki(TempDir dir, string prefix = "pki")
    {
        var now = DateTimeOffset.UtcNow;
        RootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest($"CN=psign {prefix} Root, O=Devolutions", RootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        Root = rootReq.CreateSelfSigned(now.AddYears(-2), now.AddYears(10));

        LeafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest($"CN=psign {prefix} Leaf", LeafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
        leafReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafReq.PublicKey, false));
        leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Root, true, false));
        Leaf = leafReq.Create(Root.SubjectName, X509SignatureGenerator.CreateForRSA(RootKey, RSASignaturePadding.Pkcs1), now.AddDays(-1), now.AddYears(2), [4, 2]);

        RootPath = dir.File($"{prefix}-root.cer");
        LeafPath = dir.File($"{prefix}-leaf.cer");
        LeafPemPath = dir.File($"{prefix}-leaf.pem");
        LeafKeyPath = dir.File($"{prefix}-leaf.pk8");
        LeafKeyPemPath = dir.File($"{prefix}-leaf-pkcs1.pem");
        File.WriteAllBytes(RootPath, Root.RawData);
        File.WriteAllBytes(LeafPath, Leaf.RawData);
        File.WriteAllText(LeafPemPath, PemEncoding.WriteString("CERTIFICATE", Leaf.RawData) + "\n");
        File.WriteAllBytes(LeafKeyPath, LeafKey.ExportPkcs8PrivateKey());
        File.WriteAllText(LeafKeyPemPath, PemEncoding.WriteString("RSA PRIVATE KEY", LeafKey.ExportRSAPrivateKey()) + "\n");
    }

    /// <summary>UTC date (YYYY-MM-DD) inside every generated validity window.</summary>
    public static string Today => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    public RSA RootKey { get; }

    public RSA LeafKey { get; }

    public X509Certificate2 Root { get; }

    public X509Certificate2 Leaf { get; }

    public string RootPath { get; }

    public string LeafPath { get; }

    public string LeafPemPath { get; }

    public string LeafKeyPath { get; }

    public string LeafKeyPemPath { get; }

    public void Dispose()
    {
        RootKey.Dispose();
        LeafKey.Dispose();
        Root.Dispose();
        Leaf.Dispose();
    }
}
