using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Signing.CertStore;
using Devolutions.Psign.Signing.Pki;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>Port of the <c>cert_store.rs</c> unit tests and the store behaviours from <c>tests/cert_store_cli.rs</c>.</summary>
public class PortableCertStoreTests
{
    private static PortableCertStore Store(Dictionary<string, string>? env = null) => new(n => env?.GetValueOrDefault(n));

    [Fact]
    public void NormalizesSha1Thumbprints() =>
        Assert.Equal("AABBCCDDEEFF00112233445566778899AABBCCDD", PortableCertStore.NormalizeSha1Hex("aa:bb ccdd eeff 0011 2233 4455 6677 8899 aabb ccdd"));

    [Fact]
    public void RejectsBadThumbprints()
    {
        Assert.Equal("SHA1 thumbprint must be 40 hex characters", Assert.Throws<PsignException>(() => PortableCertStore.NormalizeSha1Hex("abc")).Message);
        Assert.Equal("SHA1 thumbprint contains invalid hex", Assert.Throws<PsignException>(() => PortableCertStore.NormalizeSha1Hex(new string('z', 40))).Message);
    }

    [Fact]
    public void RejectsStorePathSeparators()
    {
        Assert.Throws<PsignException>(() => PortableCertStore.NormalizeStoreName("MY/Other"));
        Assert.Throws<PsignException>(() => PortableCertStore.NormalizeStoreName("MY\\Other"));
        Assert.Equal("certificate store name must not be empty", Assert.Throws<PsignException>(() => PortableCertStore.NormalizeStoreName(" ")).Message);
    }

    [Fact]
    public void CanonicalizesKnownStoreNames()
    {
        Assert.Equal("MY", PortableCertStore.NormalizeStoreName("my"));
        Assert.Equal("Root", PortableCertStore.NormalizeStoreName("root"));
        Assert.Equal("CA", PortableCertStore.NormalizeStoreName("ca"));
        Assert.Equal("Trust", PortableCertStore.NormalizeStoreName("TRUST"));
        Assert.Equal("Disallowed", PortableCertStore.NormalizeStoreName("disallowed"));
        Assert.Equal("Custom", PortableCertStore.NormalizeStoreName(" Custom "));
    }

    [Fact]
    public void DerivesKeyPathFromThumbprint()
    {
        var loc = new CertStoreLocation("CurrentUser", "MY", Path.Combine("store", "CurrentUser", "MY"));
        Assert.Equal("ABCDEF.key", Path.GetFileName(loc.KeyPath("ABCDEF")));
        Assert.Equal("ABCDEF.der", Path.GetFileName(loc.CertPath("ABCDEF")));
    }

    [Fact]
    public void BaseDirectoryResolutionOrder()
    {
        Assert.Equal("explicit", Store(new() { ["PSIGN_CERT_STORE"] = "env" }).ResolveBaseDir("explicit"));
        Assert.Equal("env", Store(new() { ["PSIGN_CERT_STORE"] = "env", ["HOME"] = "h" }).ResolveBaseDir(null));
        Assert.Equal(Path.Combine("h", ".psign", "cert-store"), Store(new() { ["HOME"] = "h", ["USERPROFILE"] = "u" }).ResolveBaseDir(null));
        Assert.Equal(Path.Combine("u", ".psign", "cert-store"), Store(new() { ["USERPROFILE"] = "u" }).ResolveBaseDir(null));
        Assert.Equal(Path.Combine("C:", "\\Users\\x", ".psign", "cert-store"), Store(new() { ["HOMEDRIVE"] = "C:", ["HOMEPATH"] = "\\Users\\x" }).ResolveBaseDir(null));
        Assert.Equal(
            "cannot resolve default cert-store path: set PSIGN_CERT_STORE or --cert-store-dir",
            Assert.Throws<PsignException>(() => Store().ResolveBaseDir(null)).Message);
    }

    [Fact]
    public void ImportListPrintExportRemoveDer()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir, "CN=psign cert store test");
        var der = signer.Certificate.RawData;
        var thumbprint = Hex.Upper(SHA1.HashData(der));
        var storeDir = dir.File("cert-store");
        var store = Store();

        var first = store.Import(new CertStoreSelection(storeDir, StoreName: "my"), signer.CertPath);
        Assert.True(first.Imported);
        Assert.Contains("thumbprint_sha1=" + thumbprint, first.Format(), StringComparison.Ordinal);
        Assert.StartsWith("Imported certificate\n", first.Format(), StringComparison.Ordinal);

        var second = store.Import(new CertStoreSelection(storeDir, StoreName: "MY"), signer.CertPath);
        Assert.False(second.Imported);
        Assert.StartsWith("Certificate already present certificate\n", second.Format(), StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(storeDir, "CurrentUser", "MY", thumbprint + ".der")));

        var list = store.List(new CertStoreSelection(storeDir));
        var json = JsonNode.Parse(list.ToJson())!;
        Assert.Equal("CurrentUser", json["scope"]!.GetValue<string>());
        Assert.Equal("MY", json["store"]!.GetValue<string>());
        Assert.Equal(thumbprint, json["certificates"]![0]!["thumbprint_sha1"]!.GetValue<string>());
        Assert.Equal("CN=psign cert store test", json["certificates"]![0]!["subject"]!.GetValue<string>());
        Assert.False(json["certificates"]![0]!["has_private_key"]!.GetValue<bool>());
        Assert.Null(json["certificates"]![0]!["key_path"]);

        var colonLower = string.Join(':', Enumerable.Range(0, 20).Select(i => thumbprint.Substring(i * 2, 2).ToLowerInvariant()));
        var printed = store.Print(new CertStoreSelection(storeDir), colonLower);
        Assert.Contains("psign cert store test", printed.Format(), StringComparison.Ordinal);

        var exported = dir.File("exported.der");
        store.Export(new CertStoreSelection(storeDir), thumbprint, exported);
        Assert.Equal(der, File.ReadAllBytes(exported));

        var e = Assert.Throws<PsignException>(() => store.Export(new CertStoreSelection(storeDir), thumbprint, exported));
        Assert.Equal($"output file '{exported}' already exists; use --force to replace it", e.Message);
        store.Export(new CertStoreSelection(storeDir), thumbprint, exported, force: true);

        var removed = store.Remove(new CertStoreSelection(storeDir), thumbprint);
        Assert.Contains("key_removed=false", removed, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(storeDir, "CurrentUser", "MY", thumbprint + ".der")));
        Assert.Equal(
            $"certificate with SHA1 thumbprint {thumbprint} was not found in CurrentUser\\MY",
            Assert.Throws<PsignException>(() => store.Remove(new CertStoreSelection(storeDir), thumbprint)).Message);
        Assert.Equal("No certificates found\n", store.List(new CertStoreSelection(storeDir)).Format().Split('\n', 3)[2]);
    }

    [Fact]
    public void ImportAcceptsPemAndMachineScope()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir, "CN=psign pem machine test");
        File.WriteAllText(dir.File("cert.pem"), TestPki.EncodePemCertificateBundle([signer.Certificate.RawData]));
        var storeDir = dir.File("cert-store");
        var store = Store();
        var report = store.Import(new CertStoreSelection(storeDir, MachineStore: true, StoreName: "root"), dir.File("cert.pem"));
        Assert.Equal("LocalMachine", report.Scope);
        Assert.Equal("Root", report.Store);
        var list = store.List(new CertStoreSelection(storeDir, true, "Root"));
        Assert.Equal(report.ThumbprintSha1, Assert.Single(list.Certificates).ThumbprintSha1);
    }

    [Fact]
    public void ImportExportPrivateKeyAndResolveSigningIdentity()
    {
        using var dir = new TempDir();
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Store Root"));
        var leaf = TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=Store Leaf, O=Devolutions"));
        File.WriteAllBytes(dir.File("leaf.der"), leaf.CertificateDer);
        File.WriteAllText(dir.File("leaf.key"), leaf.PrivateKeyPem);
        var storeDir = dir.File("store");
        var store = Store();

        var report = store.Import(new CertStoreSelection(storeDir), dir.File("leaf.der"), dir.File("leaf.key"));
        Assert.True(report.KeyImported);
        Assert.EndsWith("Imported private key\nkey_path=" + report.KeyPath + "\n", report.Format(), StringComparison.Ordinal);
        Assert.True(store.List(new CertStoreSelection(storeDir)).Certificates[0].HasPrivateKey);
        Assert.False(store.Import(new CertStoreSelection(storeDir), dir.File("leaf.der"), dir.File("leaf.key")).KeyImported);

        var identity = store.ResolveSigningIdentity(storeDir, false, "my", report.ThumbprintSha1.ToLowerInvariant());
        Assert.Equal(leaf.CertificateDer, identity.CertDer);
        Assert.Equal(leaf.PrivateKeyPem, System.Text.Encoding.ASCII.GetString(identity.KeyPem));
        using var signerIdentity = identity.ToSignerIdentity();
        Assert.Equal(leaf.CertificateDer, signerIdentity.Certificate.RawData);

        Assert.Equal(
            "--key-out is required when exporting with --with-key",
            Assert.Throws<PsignException>(() => store.Export(new CertStoreSelection(storeDir), report.ThumbprintSha1, dir.File("o.der"), withKey: true)).Message);
        var output = store.Export(new CertStoreSelection(storeDir), report.ThumbprintSha1, dir.File("o.der"), withKey: true, keyOut: dir.File("o.key"));
        Assert.Contains("key_out=" + dir.File("o.key"), output, StringComparison.Ordinal);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", File.ReadAllText(dir.File("o.key")), StringComparison.Ordinal);

        var removed = store.Remove(new CertStoreSelection(storeDir), report.ThumbprintSha1);
        Assert.EndsWith("key_removed=true\n", removed, StringComparison.Ordinal);
        Assert.False(File.Exists(report.KeyPath));
    }

    [Fact]
    public void ExportWithKeyFailsWhenKeyMissingAndImportRejectsMismatchedKey()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir, "CN=no key");
        using var other = new TestSigner(new TempDir(), "CN=other key");
        File.WriteAllText(dir.File("other.key"), new string(System.Security.Cryptography.PemEncoding.Write("PRIVATE KEY", other.Key.ExportPkcs8PrivateKey())));
        var storeDir = dir.File("store");
        var store = Store();
        var report = store.Import(new CertStoreSelection(storeDir), signer.CertPath);

        var e = Assert.Throws<PsignException>(() => store.Export(new CertStoreSelection(storeDir), report.ThumbprintSha1, dir.File("x.der"), withKey: true, keyOut: dir.File("x.key")));
        Assert.Equal($"private key for SHA1 thumbprint {report.ThumbprintSha1} was not found in CurrentUser\\MY", e.Message);

        var mismatch = Assert.Throws<PsignException>(() => store.Import(new CertStoreSelection(storeDir), signer.CertPath, dir.File("other.key")));
        Assert.Equal("private key does not match certificate public key", mismatch.Message);

        var resolve = Assert.Throws<PsignException>(() => store.ResolveSigningIdentity(storeDir, false, "MY", report.ThumbprintSha1));
        Assert.StartsWith($"resolve private key for SHA1 {report.ThumbprintSha1} in CurrentUser\\MY", resolve.Message, StringComparison.Ordinal);

        File.WriteAllText(dir.File("rsa.key"), "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n");
        var label = Assert.Throws<PsignException>(() => store.Import(new CertStoreSelection(storeDir), signer.CertPath, dir.File("rsa.key")));
        Assert.Equal(
            $"parse private key '{dir.File("rsa.key")}'; expected PEM unencrypted PKCS#8 (BEGIN PRIVATE KEY): private key PEM label must be PRIVATE KEY, got RSA PRIVATE KEY",
            label.FullMessage);
    }

    [Fact]
    public void ImportPfxExtractsCertAndKeyAndBaseDirEnvOverride()
    {
        using var dir = new TempDir();
        var envStore = dir.File("env-store");
        var store = Store(new() { ["PSIGN_CERT_STORE"] = envStore });
        var report = store.ImportPfx(new CertStoreSelection(), Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx"), "CodeSign123!");
        Assert.Equal("A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38", report.ThumbprintSha1);
        Assert.True(File.Exists(Path.Combine(envStore, "CurrentUser", "MY", report.ThumbprintSha1 + ".der")));
        Assert.True(File.Exists(Path.Combine(envStore, "CurrentUser", "MY", report.ThumbprintSha1 + ".key")));

        var bad = Assert.Throws<PsignException>(() => store.ImportPfx(new CertStoreSelection(dir.File("x")), Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx"), "wrong"));
        Assert.StartsWith("parse PFX '", bad.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- shared store with the Rust tool

    [SkippableFact]
    public void RustAndCSharpShareTheSameStore()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var storeDir = dir.File("shared-store");
        var pfx = Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx");
        var store = Store();

        // Rust writes, C# reads.
        var rustImport = RustTool.RunOk("cert-store", "import-pfx", "--cert-store-dir", storeDir, "--password", "CodeSign123!", pfx);
        var csImportReport = store.ImportPfx(new CertStoreSelection(storeDir), pfx, "CodeSign123!");
        Assert.False(csImportReport.Imported);
        Assert.False(csImportReport.KeyImported);
        Assert.Equal(rustImport.Replace("Imported certificate", "Certificate already present certificate", StringComparison.Ordinal)
            .Replace("Imported private key", "Private key already present private key", StringComparison.Ordinal), csImportReport.Format());
        var identity = store.ResolveSigningIdentity(storeDir, false, "MY", csImportReport.ThumbprintSha1);
        Assert.Equal("A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38", identity.ThumbprintSha1);

        // C# writes a second certificate (cert + key) into the same store, Rust reads.
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Shared \\\"Root\\\", O=\"Devolutions, Inc.\", C=CA"));
        File.WriteAllBytes(dir.File("root.der"), root.CertificateDer);
        File.WriteAllText(dir.File("root.key"), root.PrivateKeyPem);
        store.Import(new CertStoreSelection(storeDir), dir.File("root.der"), dir.File("root.key"));

        Assert.Equal(RustTool.RunOk("cert-store", "list", "--cert-store-dir", storeDir, "--json"), store.List(new CertStoreSelection(storeDir)).ToJson());
        Assert.Equal(RustTool.RunOk("cert-store", "list", "--cert-store-dir", storeDir), store.List(new CertStoreSelection(storeDir)).Format());
        var thumb = PortableCertStore.Sha1ThumbprintUpper(root.CertificateDer);
        Assert.Equal(RustTool.RunOk("cert-store", "print", "--cert-store-dir", storeDir, "--sha1", thumb), store.Print(new CertStoreSelection(storeDir), thumb).Format());
        Assert.Equal(RustTool.RunOk("cert-store", "print", "--cert-store-dir", storeDir, "--sha1", thumb, "--json"), store.Print(new CertStoreSelection(storeDir), thumb).ToJson());

        // Rust exports the C#-written key unchanged.
        RustTool.RunOk("cert-store", "export", "--cert-store-dir", storeDir, "--sha1", thumb, "--with-key", "--key-out", dir.File("rust.key"), "--out", dir.File("rust.der"));
        Assert.Equal(root.PrivateKeyPem, File.ReadAllText(dir.File("rust.key")));
        Assert.Equal(root.CertificateDer, File.ReadAllBytes(dir.File("rust.der")));

        // Rust removal is visible to C#.
        var rustRemove = RustTool.RunOk("cert-store", "remove", "--cert-store-dir", storeDir, "--sha1", thumb);
        Assert.Contains("key_removed=true", rustRemove, StringComparison.Ordinal);
        Assert.Single(store.List(new CertStoreSelection(storeDir)).Certificates);
    }

    [SkippableFact]
    public void RemoveAndExportTextMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir, "CN=text parity");
        var rustStore = dir.File("rust");
        var csStore = dir.File("cs");
        var store = Store();
        var rustOut = RustTool.RunOk("cert-store", "import", "--cert-store-dir", rustStore, "--store", "ca", signer.CertPath);
        var csOut = store.Import(new CertStoreSelection(csStore, StoreName: "ca"), signer.CertPath).Format();
        Assert.Equal(rustOut.Replace(rustStore, "<store>", StringComparison.Ordinal), csOut.Replace(csStore, "<store>", StringComparison.Ordinal));

        var thumb = PortableCertStore.Sha1ThumbprintUpper(signer.Certificate.RawData);
        var rustExport = RustTool.RunOk("cert-store", "export", "--cert-store-dir", rustStore, "--store", "CA", "--sha1", thumb, "--out", dir.File("r.der"));
        var csExport = store.Export(new CertStoreSelection(csStore, StoreName: "CA"), thumb, dir.File("c.der"));
        Assert.Equal(
            rustExport.Replace(rustStore, "<store>", StringComparison.Ordinal).Replace(dir.File("r.der"), "<out>", StringComparison.Ordinal),
            csExport.Replace(csStore, "<store>", StringComparison.Ordinal).Replace(dir.File("c.der"), "<out>", StringComparison.Ordinal));

        var rustRemove = RustTool.RunOk("cert-store", "remove", "--cert-store-dir", rustStore, "--store", "CA", "--sha1", thumb);
        var csRemove = store.Remove(new CertStoreSelection(csStore, StoreName: "CA"), thumb);
        Assert.Equal(rustRemove.Replace(rustStore, "<store>", StringComparison.Ordinal), csRemove.Replace(csStore, "<store>", StringComparison.Ordinal));
    }
}
