using System.Net;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.CertStore;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Signing.Pki;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// Differential tests against the Rust <c>psign-tool</c>: PFX / key / certificate interchange in both directions,
/// certificate profile (extensions) parity and DN encoding parity. Rust RSA key generation is slow in debug builds, so
/// the Rust-generated material is created once and shared.
/// </summary>
public class TestPkiRustParityTests
{
    private const string RootSubject = "CN=Root \\\"Q\\\" T, O=\"Dev, Inc.\", OU=R\\+D, L=Lavaltrie, S=Quebec, E=ops@devolutions.net, DC=devolutions, SERIALNUMBER=ABC-1, C=CA";
    private const string LeafSubject = "SN=Doe, G=Jane, T=Signer, CN=  \\ Jane Doe\\ , O=Devolutions Inc., STREET=\"1 Main, Suite 2\", UID=jdoe, C=CA";

    private static readonly object Gate = new();
    private static RustMaterial? _material;

    private sealed record RustMaterial(TempDir Dir, string RootPfx, byte[] RootDer, JsonNode RootJson, string LeafPfx, byte[] LeafDer, string LeafKeyPem, JsonNode LeafJson, byte[] TlsDer, JsonNode TlsJson);

    private static RustMaterial Material()
    {
        RustTool.Require();
        lock (Gate)
        {
            if (_material is not null)
            {
                return _material;
            }

            var dir = new TempDir();
            var rootJson = JsonNode.Parse(RustTool.RunOk(
                "portable", "generate-root-ca", "--subject", RootSubject, "--validity-days", "30",
                "--cert-out", dir.File("root.der"), "--pfx-out", dir.File("root.pfx"), "--password", "RootPw!", "--json"))!;
            var leafJson = JsonNode.Parse(RustTool.RunOk(
                "portable", "issue-code-signing-cert", "--ca-pfx", dir.File("root.pfx"), "--ca-password", "RootPw!",
                "--subject", LeafSubject, "--eku-oid", "1.3.6.1.4.1.311.10.3.13",
                "--cert-out", dir.File("leaf.der"), "--key-out", dir.File("leaf.key"), "--pfx-out", dir.File("leaf.pfx"), "--password", "LeafPw!", "--json"))!;
            var tlsJson = JsonNode.Parse(RustTool.RunOk(
                "portable", "issue-tls-server-cert", "--ca-pfx", dir.File("root.pfx"), "--ca-password", "RootPw!",
                "--dns", "a.devolutions.test", "--dns", "localhost", "--ip", "127.0.0.1", "--ip", "::1",
                "--cert-out", dir.File("tls.der"), "--json"))!;
            _material = new RustMaterial(
                dir,
                dir.File("root.pfx"),
                File.ReadAllBytes(dir.File("root.der")),
                rootJson,
                dir.File("leaf.pfx"),
                File.ReadAllBytes(dir.File("leaf.der")),
                File.ReadAllText(dir.File("leaf.key")),
                leafJson,
                File.ReadAllBytes(dir.File("tls.der")),
                tlsJson);
            return _material;
        }
    }

    [SkippableFact]
    public void RustPfxIsParsedByCSharp()
    {
        var m = Material();
        var leaf = Pkcs12Identity.Parse(File.ReadAllBytes(m.LeafPfx), "LeafPw!");
        Assert.Equal(m.LeafDer, leaf.SignerCertificateDer);
        Assert.Equal(new[] { m.RootDer }, leaf.ChainCertificatesDer);
        Assert.Equal(m.LeafKeyPem, leaf.PrivateKeyPem);

        var root = Pkcs12Identity.Parse(File.ReadAllBytes(m.RootPfx), "RootPw!");
        Assert.Equal(m.RootDer, root.SignerCertificateDer);
        Assert.Empty(root.ChainCertificatesDer);
    }

    [SkippableFact]
    public void RustDistinguishedNamesMatchCSharpEncodingAndFormatting()
    {
        var m = Material();
        var root = CertificateInfo.Parse(m.RootDer);
        var leaf = CertificateInfo.Parse(m.LeafDer);
        Assert.Equal(root.Subject, DistinguishedName.Parse(RootSubject));
        Assert.Equal(leaf.Subject, DistinguishedName.Parse(LeafSubject));
        Assert.Equal(m.RootJson["subject"]!.GetValue<string>(), DistinguishedName.FormatWindows(root.Subject));
        Assert.Equal(m.LeafJson["subject"]!.GetValue<string>(), DistinguishedName.FormatWindows(leaf.Subject));
        Assert.Equal(m.LeafJson["issuer"]!.GetValue<string>(), DistinguishedName.FormatWindows(leaf.Issuer));
        Assert.Equal(m.TlsJson["subject"]!.GetValue<string>(), DistinguishedName.FormatWindows(CertificateInfo.Parse(m.TlsDer).Subject));
    }

    [SkippableFact]
    public void CSharpCertificateProfileMatchesRust()
    {
        var m = Material();
        var issuer = TestPki.LoadCaIssuerFromPfx(File.ReadAllBytes(m.RootPfx), "RootPw!");
        var csRoot = TestPki.GenerateRootCa(new RootCaSpec(RootSubject, 30));
        var csLeaf = TestPki.IssueCodeSigningCert(issuer, new CodeSigningCertSpec(LeafSubject, 365, 2048, ["1.3.6.1.4.1.311.10.3.13"]));
        var csTls = TestPki.IssueTlsServerCert(issuer, new TlsServerCertSpec(null, ["a.devolutions.test", "localhost"], [IPAddress.Parse("127.0.0.1"), IPAddress.Parse("::1")]));

        AssertSameProfile(CertificateInfo.Parse(m.RootDer), csRoot.Certificate);
        AssertSameProfile(CertificateInfo.Parse(m.LeafDer), csLeaf.Certificate);
        AssertSameProfile(CertificateInfo.Parse(m.TlsDer), csTls.Certificate);

        // Summary JSON (minus the CLI-only output path fields and per-certificate values) has the same shape and text.
        AssertSameSummary(m.RootJson, csRoot.Summary);
        AssertSameSummary(m.LeafJson, csLeaf.Summary);
        AssertSameSummary(m.TlsJson, csTls.Summary);
    }

    [SkippableFact]
    public void CSharpPfxIsConsumedByRust()
    {
        var m = Material();
        using var dir = new TempDir();
        var issuer = TestPki.LoadCaIssuerFromPfx(File.ReadAllBytes(m.RootPfx), "RootPw!");
        var leaf = TestPki.IssueCodeSigningCert(issuer, new CodeSigningCertSpec("CN=C# leaf for Rust", 30));
        File.WriteAllBytes(dir.File("cs-leaf.pfx"), TestPki.EncodePfxDer(leaf, "Pw é!"));

        // Rust imports the C# PFX into a portable store; the stored files must equal what C# writes.
        var rustStore = dir.File("rust-store");
        var csStore = dir.File("cs-store");
        RustTool.RunOk("cert-store", "import-pfx", "--cert-store-dir", rustStore, "--password", "Pw é!", dir.File("cs-leaf.pfx"));
        var report = new PortableCertStore(_ => null).ImportPfx(new CertStoreSelection(csStore), dir.File("cs-leaf.pfx"), "Pw é!");
        var thumb = report.ThumbprintSha1;
        Assert.Equal(
            File.ReadAllBytes(Path.Combine(rustStore, "CurrentUser", "MY", thumb + ".der")),
            File.ReadAllBytes(Path.Combine(csStore, "CurrentUser", "MY", thumb + ".der")));
        Assert.Equal(
            File.ReadAllText(Path.Combine(rustStore, "CurrentUser", "MY", thumb + ".key")),
            File.ReadAllText(Path.Combine(csStore, "CurrentUser", "MY", thumb + ".key")));
        Assert.Equal(leaf.PrivateKeyPem, File.ReadAllText(Path.Combine(rustStore, "CurrentUser", "MY", thumb + ".key")));
    }

    [SkippableFact]
    public void CSharpRootCanIssueInRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=C# Root For Rust, O=Devolutions", 30));
        File.WriteAllBytes(dir.File("cs-root.der"), root.CertificateDer);
        File.WriteAllText(dir.File("cs-root.key"), root.PrivateKeyPem);
        var json = JsonNode.Parse(RustTool.RunOk(
            "portable", "issue-code-signing-cert", "--ca-cert", dir.File("cs-root.der"), "--ca-key", dir.File("cs-root.key"),
            "--subject", "CN=Rust leaf from C# root", "--cert-out", dir.File("leaf.der"), "--pfx-out", dir.File("leaf.pfx"), "--json"))!;
        Assert.Equal("CN=C# Root For Rust, O=Devolutions", json["issuer"]!.GetValue<string>());

        var leaf = CertificateInfo.Parse(File.ReadAllBytes(dir.File("leaf.der")));
        Assert.True(leaf.VerifySignatureBy(root.Certificate));
        Assert.Equal(root.Certificate.SubjectKeyIdentifier, leaf.AuthorityKeyIdentifier);
        var parsed = Pkcs12Identity.Parse(File.ReadAllBytes(dir.File("leaf.pfx")), string.Empty);
        Assert.Equal(leaf.RawData, parsed.SignerCertificateDer);
        Assert.Equal(new[] { root.CertificateDer }, parsed.ChainCertificatesDer);
        TestPkiTests.AssertWindowsChainBuilds(leaf.RawData, root.CertificateDer, "1.3.6.1.5.5.7.3.3");
    }

    private static void AssertSameProfile(CertificateInfo rust, CertificateInfo cs)
    {
        Assert.Equal(rust.Version, cs.Version);
        Assert.Equal(rust.SignatureAlgorithm, cs.SignatureAlgorithm);
        Assert.Equal(rust.TbsSignatureAlgorithm, cs.TbsSignatureAlgorithm);
        Assert.Equal(rust.PublicKeyAlgorithm, cs.PublicKeyAlgorithm);
        Assert.Equal(rust.SerialNumber.Length, cs.SerialNumber.Length);
        Assert.Equal(rust.SerialNumber[0] & 0xC0, cs.SerialNumber[0] & 0xC0);
        Assert.Equal(rust.Issuer, cs.Issuer);
        Assert.Equal(rust.Extensions.Select(e => (e.Oid, e.Critical)), cs.Extensions.Select(e => (e.Oid, e.Critical)));
        foreach (var (r, c) in rust.Extensions.Zip(cs.Extensions))
        {
            if (r.Oid is "2.5.29.14" or "2.5.29.35")
            {
                Assert.Equal(r.Value.Length, c.Value.Length);
                continue;
            }

            Assert.Equal(r.Value, c.Value);
        }

        Assert.Equal(rust.AuthorityKeyIdentifier, cs.AuthorityKeyIdentifier);
    }

    private static void AssertSameSummary(JsonNode rust, GeneratedCertSummary cs)
    {
        var csJson = cs.ToJsonObject();
        var rustKeys = rust.AsObject().Select(p => p.Key).Where(k => !k.EndsWith("_out", StringComparison.Ordinal)).ToList();
        Assert.Equal(rustKeys, csJson.Select(p => p.Key).ToList());
        foreach (var key in new[] { "subject", "issuer", "is_ca", "chain_certificate_count", "eku_oids", "dns_names", "ip_addresses" })
        {
            if (rust[key] is { } value)
            {
                Assert.Equal(value.ToJsonString(), csJson[key]!.ToJsonString());
            }
        }

        foreach (var key in new[] { "not_before", "not_after" })
        {
            Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", csJson[key]!.GetValue<string>());
        }
    }
}
