using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>
/// Differential trust tests over PE files signed by the Rust tool with C#-generated PKI (root → intermediate → leaf),
/// covering EKU rules, validity windows, CA constraints, self-signed leaves, SHA-384/512 and nested (appended) signatures.
/// </summary>
public class GeneratedPkiDifferentialTests
{
    private sealed class Pki : IDisposable
    {
        public Pki(TempDir dir, string? leafEku = Oids.EkuCodeSigning, bool intermediateIsCa = true, int leafValidDays = 365, int leafStartOffsetDays = -1)
        {
            var now = DateTimeOffset.UtcNow;
            RootKey = RSA.Create(2048);
            var rootReq = new CertificateRequest("CN=psign C# Root, O=Devolutions", RootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
            Root = rootReq.CreateSelfSigned(now.AddYears(-2), now.AddYears(10));

            InterKey = RSA.Create(2048);
            var interReq = new CertificateRequest("CN=psign C# Intermediate", InterKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            interReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(intermediateIsCa, false, 0, true));
            interReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(interReq.PublicKey, false));
            interReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Root, true, false));
            Inter = interReq.Create(Root.SubjectName, X509SignatureGenerator.CreateForRSA(RootKey, RSASignaturePadding.Pkcs1), now.AddYears(-1), now.AddYears(5), [5, 6, 7]);

            LeafKey = RSA.Create(2048);
            var leafReq = new CertificateRequest("CN=psign C# Leaf", LeafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            if (leafEku is not null)
            {
                leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(leafEku) }, false));
            }

            leafReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafReq.PublicKey, false));
            leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Inter, true, false));
            var start = now.AddDays(leafStartOffsetDays);
            Leaf = leafReq.Create(Inter.SubjectName, X509SignatureGenerator.CreateForRSA(InterKey, RSASignaturePadding.Pkcs1), start, start.AddDays(leafValidDays), [9, 9, 1]);

            RootPath = dir.File("root.cer");
            InterPath = dir.File("inter.cer");
            LeafPath = dir.File("leaf.cer");
            LeafKeyPath = dir.File("leaf.pk8");
            File.WriteAllBytes(RootPath, Root.RawData);
            File.WriteAllBytes(InterPath, Inter.RawData);
            File.WriteAllBytes(LeafPath, Leaf.RawData);
            File.WriteAllBytes(LeafKeyPath, LeafKey.ExportPkcs8PrivateKey());
        }

        public RSA RootKey { get; }

        public RSA InterKey { get; }

        public RSA LeafKey { get; }

        public X509Certificate2 Root { get; }

        public X509Certificate2 Inter { get; }

        public X509Certificate2 Leaf { get; }

        public string RootPath { get; }

        public string InterPath { get; }

        public string LeafPath { get; }

        public string LeafKeyPath { get; }

        public void Dispose()
        {
            RootKey.Dispose();
            InterKey.Dispose();
            LeafKey.Dispose();
            Root.Dispose();
            Inter.Dispose();
            Leaf.Dispose();
        }
    }

    private static string UnsignedPe() =>
        Directory.GetFiles(Fixtures.Path("generated-unsigned/pe")).OrderBy(p => p, StringComparer.Ordinal).First(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

    private static string Sign(TempDir dir, Pki pki, string name, string input, string digest = "sha256", bool append = false, bool includeRoot = false)
    {
        var output = dir.File(name);
        var args = new List<string> { "portable", "sign-pe", "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--chain-cert", pki.InterPath, "--digest", digest, "--output", output };
        if (includeRoot)
        {
            args.AddRange(["--chain-cert", pki.RootPath]);
        }

        if (append)
        {
            args.Add("--append-signature");
        }

        args.Add(input);
        RustTool.RunOk(RustTool.NoAutoTrust, args.ToArray());
        return output;
    }

    private static void Compare(string pe, params string[] trustArgs)
    {
        var rust = RustTool.Run(RustTool.NoAutoTrust, ["portable", "trust-verify-pe", pe, .. trustArgs]);
        string csText;
        bool csOk;
        try
        {
            var opts = ParseArgs(trustArgs).ToOptions();
            var report = TrustVerifyPe.TrustVerifyPeBytes(File.ReadAllBytes(pe), opts);
            csOk = true;
            csText = string.Join("\n", report.FormatOkLines("trust-verify-pe"));
        }
        catch (PsignException e)
        {
            csOk = false;
            csText = $"trust-verify-pe {pe}: {e.FullMessage}";
        }

        if (rust.ExitCode == 0)
        {
            Assert.True(csOk, $"Rust ok, C# failed ({string.Join(' ', trustArgs)}): {csText}");
            Assert.Equal(rust.Stdout.TrimEnd('\r', '\n'), csText);
        }
        else
        {
            Assert.False(csOk, $"Rust failed, C# ok ({string.Join(' ', trustArgs)}): {rust.Stderr}");
            Assert.Equal(rust.Stderr.Trim(), csText);
        }
    }

    private static TrustVerifySharedArgs ParseArgs(string[] a)
    {
        var r = new TrustVerifySharedArgs();
        var trusted = new List<string>();
        for (int i = 0; i < a.Length; i++)
        {
            r = a[i] switch
            {
                "--trusted-ca" => r with { TrustedCa = [.. r.TrustedCa, a[++i]] },
                "--as-of" => r with { AsOf = a[++i] },
                "--allow-loose-signing-cert" => r with { AllowLooseSigningCert = true },
                "--prefer-timestamp-signing-time" => r with { PreferTimestampSigningTime = true },
                "--require-valid-timestamp" => r with { RequireValidTimestamp = true },
                _ => throw new ArgumentException(a[i]),
            };
        }

        return r;
    }

    private static readonly string Today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd");

    private static void CompareMatrix(string pe, Pki pki)
    {
        foreach (var asOf in new[] { Today, DateTimeOffset.UtcNow.AddYears(3).ToString("yyyy-MM-dd"), DateTimeOffset.UtcNow.AddYears(-3).ToString("yyyy-MM-dd") })
        {
            Compare(pe, "--trusted-ca", pki.RootPath, "--as-of", asOf);
            Compare(pe, "--trusted-ca", pki.RootPath, "--as-of", asOf, "--allow-loose-signing-cert");
            Compare(pe, "--trusted-ca", pki.InterPath, "--as-of", asOf);
        }

        Compare(pe, "--trusted-ca", pki.RootPath, "--prefer-timestamp-signing-time");
        Compare(pe, "--trusted-ca", pki.RootPath, "--prefer-timestamp-signing-time", "--require-valid-timestamp");
        Compare(pe, "--trusted-ca", pki.LeafPath, "--as-of", Today);
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void ThreeTierChainMatchesRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var pki = new Pki(dir);
        CompareMatrix(Sign(dir, pki, "signed.exe", UnsignedPe(), digest), pki);
        CompareMatrix(Sign(dir, pki, "signed-root.exe", UnsignedPe(), digest, includeRoot: true), pki);
    }

    [SkippableTheory]
    [InlineData(null)]
    [InlineData("1.3.6.1.5.5.7.3.1")]
    public void LeafEkuVariantsMatchRust(string? eku)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var pki = new Pki(dir, leafEku: eku);
        CompareMatrix(Sign(dir, pki, "signed.exe", UnsignedPe()), pki);
    }

    [SkippableFact]
    public void NonCaIntermediateMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var pki = new Pki(dir, intermediateIsCa: false);
        CompareMatrix(Sign(dir, pki, "signed.exe", UnsignedPe()), pki);
    }

    [SkippableFact]
    public void ExpiredLeafMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var pki = new Pki(dir, leafValidDays: 30, leafStartOffsetDays: -60);
        CompareMatrix(Sign(dir, pki, "signed.exe", UnsignedPe()), pki);
    }

    [SkippableFact]
    public void AppendedNestedSignatureMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var pki = new Pki(dir);
        var first = Sign(dir, pki, "first.exe", UnsignedPe());
        var nested = Sign(dir, pki, "nested.exe", first, "sha384", append: true);
        CompareMatrix(nested, pki);

        var inspectRust = RustTool.RunOk(RustTool.NoAutoTrust, "portable", "inspect-authenticode", nested);
        var inspectCs = RustJson.ToStringPretty(AuthenticodeInspector.InspectPeAuthenticode(File.ReadAllBytes(nested)));
        Assert.Equal(inspectRust.TrimEnd('\r', '\n').Replace("\r\n", "\n"), inspectCs);
    }

    [SkippableFact]
    public void NestedSignatureAttributeMatchesRust()
    {
        // Build a PE whose primary SignerInfo carries a Microsoft nested signature (1.3.6.1.4.1.311.2.4.1) unsigned
        // attribute: picky cannot model that attribute, so Rust takes its CMS fallback path.
        RustTool.Require();
        using var dir = new TempDir();
        using var pki = new Pki(dir);
        var first = Sign(dir, pki, "first.exe", UnsignedPe());
        var both = Sign(dir, pki, "both.exe", first, "sha384", append: true);
        var blobs = Devolutions.Psign.Core.Pe.PeAuthenticode.Pkcs7Blobs(File.ReadAllBytes(both));
        var outer = Devolutions.Psign.Core.Cms.CmsSignedData.Parse(blobs[0]);
        var si = outer.SignerInfos[0].Clone();
        si.UnsignedAttributes = [new Devolutions.Psign.Core.Cms.CmsAttribute(Oids.SpcNestedSignature, Devolutions.Psign.Core.Cms.CmsSignedData.Parse(blobs[1]).Encode())];
        outer.SignerInfos[0] = si;
        var image = Devolutions.Psign.Core.Pe.PeEmbed.ReplacePkcs7CertificateAt(File.ReadAllBytes(first), 0, outer.Encode());
        var nested = dir.File("nested-attr.exe");
        File.WriteAllBytes(nested, image);
        CompareMatrix(nested, pki);

        var inspectRust = RustTool.RunOk(RustTool.NoAutoTrust, "portable", "inspect-authenticode", nested);
        var inspectCs = RustJson.ToStringPretty(AuthenticodeInspector.InspectPeAuthenticode(image));
        Assert.Equal(inspectRust.TrimEnd('\r', '\n').Replace("\r\n", "\n"), inspectCs);
    }

    [SkippableFact]
    public void SelfSignedLeafMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("self.exe");
        RustTool.RunOk(RustTool.NoAutoTrust, "portable", "sign-pe", "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", output, UnsignedPe());
        Compare(output, "--trusted-ca", signer.CertPath, "--as-of", Today);
        Compare(output, "--trusted-ca", signer.CertPath, "--as-of", "2000-01-01");
        Compare(output, "--trusted-ca", signer.CertPath, "--as-of", "2000-01-01", "--allow-loose-signing-cert");
    }
}
