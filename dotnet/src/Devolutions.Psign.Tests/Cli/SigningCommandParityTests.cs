using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Cli.Portable;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Pki;
using Devolutions.Psign.Tests.Signing;
using OpenMcdf;
using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>Shared test PKI (root CA, code-signing leaf, TSA) written to disk for both CLIs.</summary>
public sealed class SigningCliPki : IDisposable
{
    public const string PfxPassword = "pw";

    private readonly TempDir _dir = new();

    public SigningCliPki()
    {
        var root = Devolutions.Psign.Signing.Pki.TestPki.GenerateRootCa(new RootCaSpec("CN=psign CLI Test Root, O=Devolutions Inc., C=CA"));
        var leaf = Devolutions.Psign.Signing.Pki.TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=psign CLI Test Signer, O=Devolutions Inc."));
        var tsa = Devolutions.Psign.Signing.Pki.TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=psign CLI Test TSA", ExtraEkuOids: [Oids.EkuTimeStamping]));
        CaCert = Write("ca.der", root.CertificateDer);
        CaKey = Write("ca.key", Encoding.ASCII.GetBytes(root.PrivateKeyPem));
        CaPfx = Write("ca.pfx", Devolutions.Psign.Signing.Pki.TestPki.EncodePfxDer(root, PfxPassword));
        LeafCert = Write("leaf.der", leaf.CertificateDer);
        LeafKey = Write("leaf.key", Encoding.ASCII.GetBytes(leaf.PrivateKeyPem));
        LeafPfx = Write("leaf.pfx", Devolutions.Psign.Signing.Pki.TestPki.EncodePfxDer(leaf, PfxPassword));
        LeafDer = leaf.CertificateDer;
        CaDer = root.CertificateDer;
        LeafRsa = leaf.PrivateKey.CreateRsa();
        TsaRsa = tsa.PrivateKey.CreateRsa();
        TsaInfo = tsa.Certificate;
        LeafThumbprint = Convert.ToHexString(SHA1.HashData(leaf.CertificateDer));
        PemBundle = Devolutions.Psign.Signing.Pki.TestPki.EncodePemCertificateBundle([leaf.CertificateDer, root.CertificateDer]);
    }

    public string CaCert { get; }

    public string CaKey { get; }

    public string CaPfx { get; }

    public string LeafCert { get; }

    public string LeafKey { get; }

    public string LeafPfx { get; }

    public byte[] LeafDer { get; }

    public byte[] CaDer { get; }

    public RSA LeafRsa { get; }

    public RSA TsaRsa { get; }

    public CertificateInfo TsaInfo { get; }

    public string LeafThumbprint { get; }

    public string PemBundle { get; }

    private string Write(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public void Dispose()
    {
        LeafRsa.Dispose();
        TsaRsa.Dispose();
        _dir.Dispose();
    }
}

/// <summary>
/// Differential tests for the managed signing / timestamp / remote-signer / test-PKI / cert-store commands against the
/// Rust <c>psign-tool</c>. Remote services (TSA, Azure Key Vault, Artifact Signing) are served by a local mock HTTP server
/// shared by both tools; no real network access is used.
/// </summary>
public class SigningCommandParityTests : IClassFixture<SigningCliPki>
{
    private const string UnsignedCab = "generated-unsigned/cab/sample.cab";
    private const string UnsignedMsi = "generated-unsigned/installer/tiny.msi";
    private const string SignedPe = "pe-authenticode-upstream/tiny64.signed.efi";
    private const string UnsignedPe = "generated-unsigned/pe/tiny64-pe-alias.dll";

    private static readonly string[] CatalogSubjects =
    [
        "catalog-workflows/subjects/tiny32.efi",
        "catalog-workflows/subjects/hello.txt",
        "catalog-workflows/subjects/blob.bin",
    ];

    private readonly SigningCliPki _pki;

    public SigningCommandParityTests(SigningCliPki pki) => _pki = pki;

    // ------------------------------------------------------------------ helpers

    private static CliResult RunRust(params string[] args) => RunRustEnv(null, args);

    private static CliResult RunRustEnv(IReadOnlyDictionary<string, string>? env, params string[] args)
    {
        var psi = new ProcessStartInfo(RustTool.Require())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment["PSIGN_TOOL_MODE"] = "portable";
        psi.Environment["NO_PROXY"] = "127.0.0.1,localhost";
        psi.Environment.Remove("SIGNTOOL_PORTABLE_DEBUG");
        if (env is not null)
        {
            foreach (var (k, v) in env)
            {
                psi.Environment[k] = v;
            }
        }

        using var p = Process.Start(psi)!;
        p.StandardInput.Close();
        using var ms = new MemoryStream();
        var copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        copy.Wait();
        return new CliResult(p.ExitCode, ms.ToArray(), stderr);
    }

    private static string Norm(string s) => s.Replace("\r\n", "\n", StringComparison.Ordinal);

    /// <summary>
    /// Run both tools with an output file (<paramref name="args"/> receives the output path); assert success, identical
    /// stdout (modulo the output path) and return the two output paths.
    /// </summary>
    private static (string Rust, string Managed) RunBothToFiles(TempDir dir, string ext, Func<string, string[]> args, string tag = "")
    {
        var rustOut = dir.File($"rust{tag}{ext}");
        var managedOut = dir.File($"managed{tag}{ext}");
        var rust = RunRust(args(rustOut));
        var managed = CliHarness.RunManaged(args(managedOut));
        Assert.True(rust.ExitCode == 0, $"rust failed ({rust.ExitCode}): {rust.Stderr}");
        Assert.True(managed.ExitCode == 0, $"managed failed ({managed.ExitCode}): {managed.Stderr}");
        Assert.Equal(rust.Stdout.Replace(rustOut, "{out}", StringComparison.Ordinal), managed.Stdout.Replace(managedOut, "{out}", StringComparison.Ordinal));
        Assert.Equal(Norm(rust.Stderr), Norm(managed.Stderr));
        return (rustOut, managedOut);
    }

    private static void AssertSameFile(string rust, string managed) =>
        Assert.True(File.ReadAllBytes(rust).AsSpan().SequenceEqual(File.ReadAllBytes(managed)), $"{rust} and {managed} differ");

    /// <summary>Same exit code, stdout and stderr.</summary>
    private static void AssertSameError(params string[] args)
    {
        var rust = RunRust(args);
        var managed = CliHarness.RunManaged(args);
        Assert.True(rust.ExitCode == managed.ExitCode, $"exit code mismatch for {string.Join(' ', args)}: rust={rust.ExitCode} managed={managed.ExitCode}\nrust: {rust.Stderr}\nmanaged: {managed.Stderr}");
        Assert.NotEqual(0, rust.ExitCode);
        Assert.Equal(rust.Stdout, managed.Stdout);
        Assert.Equal(Norm(rust.Stderr), Norm(managed.Stderr));
    }

    /// <summary>clap usage errors: same exit code (2) and same first stderr line (the usage line format differs).</summary>
    private static void AssertSameUsageError(params string[] args)
    {
        var rust = RunRust(args);
        var managed = CliHarness.RunManaged(args);
        Assert.Equal(2, rust.ExitCode);
        Assert.Equal(2, managed.ExitCode);
        Assert.Equal(Norm(rust.Stderr).Split('\n')[0], Norm(managed.Stderr).Split('\n')[0]);
    }

    private string[] LocalSigner(params string[] extra) => ["--cert", _pki.LeafCert, "--key", _pki.LeafKey, .. extra];

    private static byte[] ReadRootStream(byte[] image, string name)
    {
        using var root = RootStorage.Open(new MemoryStream(image, writable: false));
        using var s = root.OpenStream(name);
        var buf = new byte[s.Length];
        s.ReadExactly(buf);
        return buf;
    }

    // ------------------------------------------------------------------ local-key signing

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void SignPeMatchesRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        foreach (var fixture in new[] { UnsignedPe, SignedPe })
        {
            var (rust, managed) = RunBothToFiles(dir, ".efi", o =>
                ["portable", "sign-pe", Fixtures.Path(fixture), .. LocalSigner("--chain-cert", _pki.CaCert, "--digest", digest), "--output", o]);
            AssertSameFile(rust, managed);
            PeAuthenticode.VerifyDigestConsistency(File.ReadAllBytes(managed));
            Assert.Equal(0, RunRust("portable", "verify-pe", managed).ExitCode);
        }
    }

    [SkippableFact]
    public void SignPeAppendAndAliasesMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, managed) = RunBothToFiles(dir, ".efi", o => ["portable", "sign-pe", Fixtures.Path(SignedPe), .. LocalSigner(), "--as", "--output", o]);
        AssertSameFile(rust, managed);
        Assert.Equal(2, PeAuthenticode.Pkcs7ByteLengths(File.ReadAllBytes(managed)).Count);

        var (rust2, managed2) = RunBothToFiles(dir, ".efi", o => ["portable", "sign-pe", managed, .. LocalSigner("--digest", "sha384"), "--append-signature", "--chain-cert", _pki.CaCert, "--output", o], "2");
        AssertSameFile(rust2, managed2);
        CliHarness.AssertSameOutput("portable", "list-pe-pkcs7", managed2);

        // Default mode replaces existing signatures.
        var (rust3, managed3) = RunBothToFiles(dir, ".efi", o => ["portable", "sign-pe", managed2, .. LocalSigner(), "--output", o], "3");
        AssertSameFile(rust3, managed3);
        Assert.Single(PeAuthenticode.Pkcs7ByteLengths(File.ReadAllBytes(managed3)));
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void SignCabMatchesRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, managed) = RunBothToFiles(dir, ".cab", o =>
            ["portable", "sign-cab", Fixtures.Path(UnsignedCab), .. LocalSigner("--chain-cert", _pki.CaCert, "--digest", digest), "--output", o]);
        AssertSameFile(rust, managed);
        CabDigest.VerifyDigestConsistency(File.ReadAllBytes(managed));
    }

    [SkippableTheory]
    [InlineData("generated-unsigned/installer/tiny.msi", "sha256")]
    [InlineData("generated-unsigned/installer/tiny-patch.msp", "sha384")]
    [InlineData("generated-signed/installer/tiny.msi", "sha512")]
    public void SignMsiSignatureStreamsMatchRust(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, managed) = RunBothToFiles(dir, ".msi", o =>
            ["portable", "sign-msi", Fixtures.Path(fixture), .. LocalSigner("--chain-cert", _pki.CaCert, "--digest", digest), "--output", o]);
        var rustSigned = File.ReadAllBytes(rust);
        var managedSigned = File.ReadAllBytes(managed);
        Assert.Equal(MsiDigest.DigitalSignaturePkcs7Der(rustSigned), MsiDigest.DigitalSignaturePkcs7Der(managedSigned));
        Assert.Equal(ReadRootStream(rustSigned, MsiDigest.ExtendedSignatureEntry), ReadRootStream(managedSigned, MsiDigest.ExtendedSignatureEntry));
        Assert.Equal(0, RunRust("portable", "verify-msi", managed).ExitCode);
        MsiDigest.VerifyDigestConsistency(rustSigned);
        MsiDigest.VerifyDigestConsistency(managedSigned);
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void SignCatalogMatchesRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var (rust, managed) = RunBothToFiles(dir, ".cat", o =>
            ["portable", "sign-catalog", .. LocalSigner("--chain-cert", _pki.CaCert, "--digest", digest), "--output", o, .. CatalogSubjects.Select(Fixtures.Path)]);
        AssertSameFile(rust, managed);
        CatalogDigest.VerifyDigestConsistency(File.ReadAllBytes(managed));
        Assert.Equal(0, RunRust("portable", "verify-catalog-member", "--catalog", managed, Fixtures.Path(CatalogSubjects[1])).ExitCode);
    }

    // ------------------------------------------------------------------ RFC 3161

    /// <summary>Deterministic TSA token over <paramref name="messageImprintTlv"/> (fixed genTime / serial, Basic CMS attributes).</summary>
    private byte[] TsaToken(byte[] messageImprintTlv, byte[]? nonceTlv)
    {
        var parts = new List<byte[]>
        {
            new byte[] { 0x02, 0x01, 0x01 },
            Der.EncodeOid("1.3.6.1.4.1.601.10.3.1"),
            messageImprintTlv,
            new byte[] { 0x02, 0x03, 0x00, 0xbe, 0xef },
            Der.EncodeTlv(0x18, "20251122103000Z"u8),
        };
        if (nonceTlv is not null)
        {
            parts.Add(nonceTlv);
        }

        var tstinfo = Der.EncodeSequence([.. parts]);
        return Pkcs7Builder.CreateSignedData(Oids.TstInfo, Der.EncodeTlv(0x04, tstinfo), AuthenticodeHashKind.Sha256, _pki.TsaInfo, [], _pki.TsaRsa);
    }

    private static byte[] GrantedResponse(byte[] token) => Der.EncodeSequence(Der.EncodeSequence([0x02, 0x01, 0x00]), token);

    private LocalHttpResponse TsaHandler(LocalHttpRequest req)
    {
        Assert.Equal("POST", req.Method);
        Assert.Equal("application/timestamp-query", req.Headers["Content-Type"]);
        var der = req.Body;
        var outer = Der.First(der)!.Value;
        var kids = Der.Children(der, outer)!;
        var imprint = kids[1].Encoded(der).ToArray();
        byte[]? nonce = kids.Count > 2 && kids[2].Tag == 0x02 ? kids[2].Encoded(der).ToArray() : null;
        return new LocalHttpResponse(200, GrantedResponse(TsaToken(imprint, nonce)), "application/timestamp-reply");
    }

    [SkippableFact]
    public void TimestampPeTokenAndResponseMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var signed = dir.File("signed.efi");
        Assert.Equal(0, CliHarness.RunManaged(["portable", "sign-pe", Fixtures.Path(UnsignedPe), .. LocalSigner(), "--output", signed]).ExitCode);
        var sd = CmsSignedData.Parse(PeAuthenticode.NthPkcs7(File.ReadAllBytes(signed), 0));
        var hashed = SHA256.HashData(sd.SignerInfos[0].Signature);
        var imprint = Der.EncodeSequence(Rfc3161ImprintAlgorithm(), Der.EncodeTlv(0x04, hashed));
        var token = TsaToken(imprint, null);
        var tokenPath = dir.File("token.der");
        File.WriteAllBytes(tokenPath, token);
        var respPath = dir.File("resp.der");
        File.WriteAllBytes(respPath, GrantedResponse(token));

        var (r1, m1) = RunBothToFiles(dir, ".efi", o => ["portable", "timestamp-pe-rfc3161", signed, "--token", tokenPath, "--output", o], "token");
        AssertSameFile(r1, m1);
        var (r2, m2) = RunBothToFiles(dir, ".efi", o => ["portable", "timestamp-pe-rfc3161", signed, "--response", respPath, "--index", "0", "--signer-index", "0", "--output", o], "resp");
        AssertSameFile(r2, m2);
        AssertSameFile(m1, m2);
        var stamped = CmsSignedData.Parse(PeAuthenticode.NthPkcs7(File.ReadAllBytes(m1), 0));
        Assert.NotNull(stamped.SignerInfos[0].GetUnsignedAttribute(Oids.MsRfc3161TimestampToken));
        PeAuthenticode.VerifyDigestConsistency(File.ReadAllBytes(m1));

        // Error paths: rejected response, wrong signer index, missing row.
        var rejected = dir.File("rejected.der");
        File.WriteAllBytes(rejected, Der.EncodeSequence(Der.EncodeSequence([0x02, 0x01, 0x02])));
        AssertSameError("portable", "timestamp-pe-rfc3161", signed, "--response", rejected, "--output", dir.File("x.efi"));
        AssertSameError("portable", "timestamp-pe-rfc3161", signed, "--response", tokenPath, "--output", dir.File("x.efi"));
        AssertSameError("portable", "timestamp-pe-rfc3161", signed, "--token", tokenPath, "--signer-index", "3", "--output", dir.File("x.efi"));
        AssertSameError("portable", "timestamp-pe-rfc3161", signed, "--token", tokenPath, "--index", "1", "--output", dir.File("x.efi"));
        AssertSameError("portable", "timestamp-pe-rfc3161", Fixtures.Path(UnsignedPe), "--token", tokenPath, "--output", dir.File("x.efi"));
    }

    private static byte[] Rfc3161ImprintAlgorithm() => Devolutions.Psign.Core.Timestamp.Rfc3161.MessageImprintAlgorithmIdentifierDer(Oids.Sha256)!;

    [SkippableFact]
    public void TimestampOverHttpMatchesRust()
    {
        RustTool.Require();
        using var server = new LocalHttpServer(TsaHandler);
        using var dir = new TempDir();
        var tsa = server.BaseUrl + "/tsa";

        var (r1, m1) = RunBothToFiles(dir, ".efi", o => ["portable", "sign-pe", Fixtures.Path(UnsignedPe), .. LocalSigner(), "--tr", tsa, "--td", "sha256", "--output", o], "pe");
        AssertSameFile(r1, m1);
        var (r2, m2) = RunBothToFiles(dir, ".cab", o => ["portable", "sign-cab", Fixtures.Path(UnsignedCab), .. LocalSigner(), "--timestamp-url", tsa, "--timestamp-digest", "sha384", "--output", o], "cab");
        AssertSameFile(r2, m2);
        var (r3, m3) = RunBothToFiles(dir, ".cat", o => ["portable", "sign-catalog", .. LocalSigner(), "--tr", tsa, "--td", "sha512", "--output", o, Fixtures.Path(CatalogSubjects[1])], "cat");
        AssertSameFile(r3, m3);
        var (r4, m4) = RunBothToFiles(dir, ".msi", o => ["portable", "sign-msi", Fixtures.Path(UnsignedMsi), .. LocalSigner(), "--tr", tsa, "--td", "sha256", "--output", o], "msi");
        Assert.Equal(MsiDigest.DigitalSignaturePkcs7Der(File.ReadAllBytes(r4)), MsiDigest.DigitalSignaturePkcs7Der(File.ReadAllBytes(m4)));

        var unstamped = dir.File("unstamped.efi");
        Assert.Equal(0, CliHarness.RunManaged(["portable", "sign-pe", Fixtures.Path(UnsignedPe), .. LocalSigner(), "--output", unstamped]).ExitCode);
        var (r5, m5) = RunBothToFiles(dir, ".efi", o => ["portable", "timestamp-pe-rfc3161", unstamped, "--rfc3161-url", tsa, "--digest", "sha256", "--output", o], "ts");
        AssertSameFile(r5, m5);
        AssertSameFile(r1, m5);

        var digestHex = Hex.Lower(SHA256.HashData("payload"u8));
        var (r6, m6) = RunBothToFiles(dir, ".tsr", o => ["portable", "rfc3161-timestamp-http-post", "--url", tsa, "--digest-hex", digestHex, "--nonce", "4660", "--cert-req", "--output", o], "post");
        AssertSameFile(r6, m6);
        var rustStdout = RunRust("portable", "rfc3161-timestamp-http-post", "--url", tsa, "--digest-hex", digestHex);
        var managedStdout = CliHarness.RunManaged("portable", "rfc3161-timestamp-http-post", "--url", tsa, "--digest-hex", digestHex);
        Assert.Equal(0, rustStdout.ExitCode);
        Assert.Equal(rustStdout.StdoutBytes, managedStdout.StdoutBytes);

        // Request bodies posted by both tools are identical.
        var bodies = server.Requests.Select(r => Hex.Lower(r.Body)).ToList();
        Assert.Equal(14, bodies.Count);
        for (int i = 0; i < bodies.Count; i += 2)
        {
            Assert.Equal(bodies[i], bodies[i + 1]);
        }
    }

    [SkippableFact]
    public void TimestampHttpErrorsMatchRust()
    {
        RustTool.Require();
        using var server = new LocalHttpServer(req => req.Path switch
        {
            "/fail" => new LocalHttpResponse(500, "tsa down"u8.ToArray(), "text/plain"),
            "/rejected" => new LocalHttpResponse(200, Der.EncodeSequence(Der.EncodeSequence([0x02, 0x01, 0x02], Der.EncodeSequence(Der.EncodeTlv(0x0c, "nope"u8)))), "application/timestamp-reply"),
            _ => new LocalHttpResponse(200, [0x30, 0x03, 0x02, 0x01], "application/timestamp-reply"),
        });
        using var dir = new TempDir();
        var x = dir.File("x.out");
        AssertSameError(["portable", "sign-pe", Fixtures.Path(UnsignedPe), .. LocalSigner(), "--tr", server.BaseUrl + "/fail", "--td", "sha256", "--output", x]);
        AssertSameError(["portable", "sign-cab", Fixtures.Path(UnsignedCab), .. LocalSigner(), "--tr", server.BaseUrl + "/rejected", "--td", "sha256", "--output", x]);
        AssertSameError(["portable", "sign-catalog", .. LocalSigner(), "--tr", server.BaseUrl + "/garbage", "--td", "sha256", "--output", x, Fixtures.Path(CatalogSubjects[1])]);
        AssertSameError("portable", "rfc3161-timestamp-http-post", "--url", server.BaseUrl + "/fail", "--digest-hex", new string('0', 64));
        AssertSameError("portable", "rfc3161-timestamp-http-post", "--url", server.BaseUrl + "/fail", "--digest-hex", "00");
        AssertSameError("portable", "rfc3161-timestamp-http-post", "--url", server.BaseUrl + "/fail");
        Assert.False(File.Exists(x));
    }

    // ------------------------------------------------------------------ Azure Key Vault (local mock)

    private LocalHttpResponse KeyVaultHandler(LocalHttpServer server, LocalHttpRequest req)
    {
        Assert.Equal("Bearer kv-token", req.Headers["Authorization"]);
        var kid = server.BaseUrl + "/keys/signer/0123456789abcdef";
        if (req.Method == "GET" && req.Path == "/certificates/signer" && req.Target.EndsWith("api-version=7.4", StringComparison.Ordinal))
        {
            return LocalHttpResponse.Json(new JsonObject { ["kid"] = kid, ["cer"] = Convert.ToBase64String(_pki.LeafDer) }.ToJsonString());
        }

        if (req.Method == "POST" && req.Path == "/keys/signer/0123456789abcdef/sign")
        {
            var body = JsonNode.Parse(req.Body)!;
            var alg = body["alg"]!.GetValue<string>();
            var digest = Base64UrlDecode(body["value"]!.GetValue<string>());
            var hash = alg switch
            {
                "RS256" => HashAlgorithmName.SHA256,
                "RS384" => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA512,
            };
            var sig = _pki.LeafRsa.SignHash(digest, hash, RSASignaturePadding.Pkcs1);
            return LocalHttpResponse.Json(new JsonObject { ["kid"] = kid, ["value"] = Base64UrlEncode(sig) }.ToJsonString());
        }

        return LocalHttpResponse.Json("{\"error\":{\"code\":\"NotFound\"}}", 404);
    }

    private static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t + new string('=', (4 - (t.Length % 4)) % 4));
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    public void SignPeWithKeyVaultMatchesRust(string digest)
    {
        RustTool.Require();
        LocalHttpServer? server = null;
        server = new LocalHttpServer(req => KeyVaultHandler(server!, req));
        using (server)
        {
            using var dir = new TempDir();
            var (rust, managed) = RunBothToFiles(dir, ".efi", o =>
            [
                "portable", "sign-pe", Fixtures.Path(UnsignedPe), "--kvu", server.BaseUrl + "/", "--kvc", " signer ",
                "--azure-key-vault-accesstoken", "kv-token", "--digest", digest, "--chain-cert", _pki.CaCert, "--output", o,
            ]);
            AssertSameFile(rust, managed);

            // The Key Vault signature equals a local signature with the same key.
            var (local, _) = RunBothToFiles(dir, ".efi", o => ["portable", "sign-pe", Fixtures.Path(UnsignedPe), .. LocalSigner("--digest", digest, "--chain-cert", _pki.CaCert), "--output", o], "local");
            AssertSameFile(local, managed);

            var digestFile = dir.File("digest.bin");
            File.WriteAllBytes(digestFile, SHA256.HashData("kv"u8));
            string[] signDigest = ["portable", "azure-key-vault-sign-digest", "--azure-key-vault-url", server.BaseUrl, "--azure-key-vault-certificate", "signer", "--digest-file", digestFile, "--azure-key-vault-accesstoken", "kv-token"];
            var rustB64 = RunRust(signDigest);
            var managedB64 = CliHarness.RunManaged(signDigest);
            Assert.True(rustB64.ExitCode == 0, rustB64.Stderr);
            Assert.Equal(rustB64.Stdout, managedB64.Stdout);
            var (rs, ms) = RunBothToFiles(dir, ".sig", o => [.. signDigest, "--signature-output", o], "sig");
            AssertSameFile(rs, ms);

            AssertSameError("portable", "azure-key-vault-sign-digest", "--kvu", server.BaseUrl, "--kvc", "missing", "--digest-file", digestFile, "--azure-key-vault-accesstoken", "kv-token");
        }
    }

    [SkippableFact]
    public void KeyVaultValidationErrorsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var digestFile = dir.File("digest.bin");
        File.WriteAllBytes(digestFile, new byte[32]);
        var empty = dir.File("empty.bin");
        File.WriteAllBytes(empty, []);
        var x = dir.File("x.efi");
        var pe = Fixtures.Path(UnsignedPe);
        AssertSameError("portable", "sign-pe", pe, "--kvu", "https://kv.example", "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--kvc", "c", "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--kvu", "https://kv.example", "--kvc", "c", "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--kvu", "https://kv.example", "--kvc", "c", "--azure-key-vault-tenant-id", "t", "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--kvu", "https://kv.example", "--kvc", "c", "--azure-key-vault-accesstoken", "t", "--azure-key-vault-managed-identity", "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--kvu", "https://kv.example", "--kvc", "c", "--azure-key-vault-managed-identity", "--azure-key-vault-tenant-id", "t", "--azure-key-vault-client-id", "c", "--azure-key-vault-client-secret", "s", "--output", x);
        AssertSameError(["portable", "sign-pe", pe, .. LocalSigner(), "--kvu", "https://kv.example", "--output", x]);
        AssertSameError(["portable", "sign-pe", pe, .. LocalSigner(), "--artifact-signing-account-name", "a", "--output", x]);
        AssertSameError("portable", "sign-pe", pe, "--kvu", "https://kv.example", "--artifact-signing-region", "r", "--output", x);
        AssertSameError("portable", "azure-key-vault-sign-digest", "--kvu", "https://kv.example", "--kvc", "c", "--digest-file", digestFile);
        AssertSameError("portable", "azure-key-vault-sign-digest", "--kvu", "https://kv.example", "--kvc", "c", "--digest-file", empty, "--azure-key-vault-accesstoken", "t");
        AssertSameError("portable", "azure-key-vault-sign-digest", "--kvu", "https://kv.example", "--kvc", "c", "--digest-file", dir.File("missing.bin"), "--azure-key-vault-accesstoken", "t");
        AssertSameError("portable", "azure-key-vault-sign-digest", "--kvu", " ", "--kvc", "c", "--digest-file", digestFile, "--azure-key-vault-accesstoken", "t");
    }

    // ------------------------------------------------------------------ Artifact Signing (local mock)

    private sealed class ArtifactSigningMock
    {
        private readonly SigningCliPki _pki;
        private readonly bool _pemBundle;
        private byte[]? _lastSignature;

        public ArtifactSigningMock(SigningCliPki pki, bool pemBundle)
        {
            _pki = pki;
            _pemBundle = pemBundle;
        }

        public LocalHttpResponse Handle(LocalHttpRequest req)
        {
            Assert.Equal("Bearer as-token", req.Headers["Authorization"]);
            const string prefix = "/codesigningaccounts/acct/certificateprofiles/prof";
            if (req.Method == "POST" && req.Path == prefix + ":sign")
            {
                var body = JsonNode.Parse(req.Body)!;
                var digest = Convert.FromBase64String(body["digest"]!.GetValue<string>());
                var hash = body["signatureAlgorithm"]!.GetValue<string>() switch
                {
                    "RS256" => HashAlgorithmName.SHA256,
                    "RS384" => HashAlgorithmName.SHA384,
                    _ => HashAlgorithmName.SHA512,
                };
                _lastSignature = _pki.LeafRsa.SignHash(digest, hash, RSASignaturePadding.Pkcs1);
                return LocalHttpResponse.Json("{\"id\":\"op-1\",\"status\":\"InProgress\"}", 202, ("Operation-Location", prefix + "/sign/op-1?api-version=2024-06-15"));
            }

            if (req.Method == "GET" && req.Path == prefix + "/sign/op-1" && _lastSignature is not null)
            {
                var cert = _pemBundle ? Encoding.ASCII.GetBytes(_pki.PemBundle) : _pki.LeafDer;
                var json = new JsonObject
                {
                    ["status"] = "Succeeded",
                    ["id"] = "op-1",
                    ["result"] = new JsonObject
                    {
                        ["signature"] = Convert.ToBase64String(_lastSignature),
                        ["signingCertificate"] = Convert.ToBase64String(cert),
                    },
                };
                return LocalHttpResponse.Json(json.ToJsonString());
            }

            return LocalHttpResponse.Json("{\"error\":\"not found\"}", 404);
        }
    }

    private static string[] ArtifactOptions(LocalHttpServer server) =>
    [
        "--artifact-signing-endpoint-base-url", server.BaseUrl,
        "--artifact-signing-account-name", "acct",
        "--artifact-signing-profile-name", "prof",
        "--artifact-signing-access-token", "as-token",
    ];

    [SkippableFact]
    public void ArtifactSigningSubmitMatchesRust()
    {
        RustTool.Require();
        var mock = new ArtifactSigningMock(_pki, pemBundle: false);
        using var server = new LocalHttpServer(mock.Handle);
        using var dir = new TempDir();
        var digestFile = dir.File("digest.bin");
        File.WriteAllBytes(digestFile, SHA256.HashData("artifact"u8));
        string[] args = ["portable", "artifact-signing-submit", "--region", "unused", "--account-name", "acct", "--profile-name", "prof", "--digest-file", digestFile, "--access-token", "as-token", "--endpoint-base-url", server.BaseUrl, "--correlation-id", "corr-1"];
        CliHarness.AssertSameOutput(args);
        Assert.Contains(server.Requests, r => r.Headers.TryGetValue("x-ms-correlation-id", out var c) && c == "corr-1");

        var empty = dir.File("empty.bin");
        File.WriteAllBytes(empty, []);
        AssertSameError("portable", "artifact-signing-submit", "--region", "r", "--account-name", "acct", "--profile-name", "prof", "--digest-file", empty, "--access-token", "t");
        AssertSameError("portable", "artifact-signing-submit", "--region", "r", "--account-name", "acct", "--profile-name", "prof", "--digest-file", dir.File("missing"), "--access-token", "t");
        AssertSameError("portable", "artifact-signing-submit", "--region", "r", "--account-name", "acct", "--profile-name", "prof", "--digest-file", digestFile, "--access-token", "t", "--managed-identity");
        AssertSameError("portable", "artifact-signing-submit", "--region", "r", "--account-name", "nope", "--profile-name", "prof", "--digest-file", digestFile, "--access-token", "as-token", "--endpoint-base-url", server.BaseUrl);
        AssertSameError("artifact-signing-submit", "--region", "r", "--account-name", "acct", "--profile-name", "prof", "--digest-file", digestFile);
        AssertSameUsageError("artifact-signing-submit", "--region", "r");
        AssertSameUsageError("portable", "artifact-signing-submit", "--region", "r");
    }

    [SkippableTheory]
    [InlineData(false)]
    [InlineData(true)]
    public void SignWithArtifactSigningMatchesRust(bool pemBundle)
    {
        RustTool.Require();
        var mock = new ArtifactSigningMock(_pki, pemBundle);
        using var server = new LocalHttpServer(mock.Handle);
        using var dir = new TempDir();
        var asOptions = ArtifactOptions(server);
        var chain = pemBundle ? Array.Empty<string>() : ["--chain-cert", _pki.CaCert];

        var (r1, m1) = RunBothToFiles(dir, ".efi", o => ["portable", "sign-pe", Fixtures.Path(UnsignedPe), .. asOptions, .. chain, "--output", o], "pe");
        AssertSameFile(r1, m1);
        var (local, _) = RunBothToFiles(dir, ".efi", o => ["portable", "sign-pe", Fixtures.Path(UnsignedPe), .. LocalSigner("--chain-cert", _pki.CaCert), "--output", o], "local");
        AssertSameFile(local, m1);

        var (r2, m2) = RunBothToFiles(dir, ".cab", o => ["portable", "sign-cab", Fixtures.Path(UnsignedCab), .. asOptions, .. chain, "--digest", "sha384", "--output", o], "cab");
        AssertSameFile(r2, m2);
        var (r3, m3) = RunBothToFiles(dir, ".msi", o => ["portable", "sign-msi", Fixtures.Path(UnsignedMsi), .. asOptions, .. chain, "--output", o], "msi");
        Assert.Equal(MsiDigest.DigitalSignaturePkcs7Der(File.ReadAllBytes(r3)), MsiDigest.DigitalSignaturePkcs7Der(File.ReadAllBytes(m3)));
        var (r4, m4) = RunBothToFiles(dir, ".cat", o => ["portable", "sign-catalog", .. asOptions, .. chain, "--digest", "sha512", "--output", o, .. CatalogSubjects.Select(Fixtures.Path)], "cat");
        AssertSameFile(r4, m4);

        // Metadata JSON supplies account / profile.
        var metadata = dir.File("metadata.json");
        File.WriteAllText(metadata, "{\"Endpoint\":\"https://ignored.codesigning.azure.net\",\"CodeSigningAccountName\":\"acct\",\"CertificateProfileName\":\"prof\"}");
        var (r5, m5) = RunBothToFiles(dir, ".efi", o =>
            ["portable", "sign-pe", Fixtures.Path(UnsignedPe), "--artifact-signing-metadata", metadata, "--artifact-signing-endpoint-base-url", server.BaseUrl, "--artifact-signing-access-token", "as-token", .. chain, "--output", o], "meta");
        AssertSameFile(r5, m5);
    }

    [SkippableFact]
    public void ArtifactSigningValidationErrorsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var x = dir.File("x.out");
        var metadata = dir.File("metadata.json");
        var cab = Fixtures.Path(UnsignedCab);
        AssertSameError("portable", "sign-cab", cab, "--artifact-signing-region", "r", "--output", x);
        AssertSameError("portable", "sign-cab", cab, "--artifact-signing-account-name", "a", "--output", x);
        AssertSameError("portable", "sign-cab", cab, "--cert", _pki.LeafCert, "--artifact-signing-account-name", "a", "--output", x);
        AssertSameError("portable", "sign-msi", Fixtures.Path(UnsignedMsi), "--key", _pki.LeafKey, "--artifact-signing-account-name", "a", "--output", x);
        AssertSameError("portable", "sign-catalog", "--artifact-signing-account-name", "a", "--artifact-signing-profile-name", "p", "--artifact-signing-access-token", "t", "--artifact-signing-managed-identity", "--output", x, Fixtures.Path(CatalogSubjects[1]));
        AssertSameError("portable", "sign-pe", Fixtures.Path(UnsignedPe), "--artifact-signing-metadata", dir.File("missing.json"), "--output", x);

        File.WriteAllText(metadata, "{\"Endpoint\":\"e\",\"CodeSigningAccountName\":\"a\",\"CertificateProfileName\":\"p\",\"ExcludeCredentials\":[\"\"]}");
        CliHarness.AssertSameOutput("portable", "artifact-signing-metadata-check", "--path", metadata);
        File.WriteAllText(metadata, "{\"Endpoint\":\"e\",\"CodeSigningAccountName\":\" \",\"CertificateProfileName\":\"p\"}");
        CliHarness.AssertSameOutput("portable", "artifact-signing-metadata-check", "--path", metadata);
        File.WriteAllText(metadata, "{\"Endpoint\":\"e\",\"CodeSigningAccountName\":\"a\",\"CertificateProfileName\":\"p\",\"ExcludeCredentials\":[\"AzureCliCredential\"]}");
        CliHarness.AssertSameOutput("portable", "artifact-signing-metadata-check", "--path", metadata);
        File.WriteAllBytes(metadata, []);
        CliHarness.AssertSameOutput("portable", "artifact-signing-metadata-check", "--path", metadata);
        CliHarness.AssertSameOutput("portable", "artifact-signing-metadata-check", "--path", dir.File("missing.json"));

        AssertSameError("portable", "artifact-signing-root", "--endpoint", "http://wus.codesigning.azure.net", "--account-name", "a", "--profile-name", "p", "--output", x, "--access-token", "t");
        AssertSameError("portable", "artifact-signing-root", "--endpoint", "https://example.com", "--account-name", "a", "--profile-name", "p", "--output", x, "--access-token", "t");
        AssertSameError("portable", "artifact-signing-root", "--endpoint", "https://wus.codesigning.azure.net/path", "--account-name", "a", "--profile-name", "p", "--output", x, "--access-token", "t");
        AssertSameError("portable", "artifact-signing-root", "--endpoint", "https://wus.codesigning.azure.net", "--account-name", "a", "--profile-name", "p", "--output", x, "--access-token", "t", "--managed-identity");
    }

    [Fact]
    public void ArtifactSigningRootUsesMockTransport()
    {
        var mock = new MockHttpHandler();
        mock.Map("GET", "^https://wus\\.codesigning\\.azure\\.net/codesigningaccounts/acct/certificateprofiles/prof/sign/rootcert\\?api-version=2022-06-15-preview$")
            .MatchHeader("Authorization", "Bearer root-token")
            .Respond(200, _pki.CaDer, ("Content-Type", "application/x-x509-ca-cert"));
        using var dir = new TempDir();
        var output = dir.File("root.cer");
        SigningCommands.HttpHandlerFactory = () => mock;
        try
        {
            var r = CliHarness.RunManaged("portable", "artifact-signing-root", "--endpoint", "https://wus.codesigning.azure.net", "--account-name", "acct", "--profile-name", "prof", "--output", output, "--access-token", "root-token");
            Assert.True(r.ExitCode == 0, r.Stderr);
            Assert.Equal($"output={output}\n", r.Stdout);
            Assert.Equal(_pki.CaDer, File.ReadAllBytes(output));

            var bad = new MockHttpHandler();
            bad.Map("GET", ".*").Respond(200, "not a cert"u8.ToArray(), ("Content-Type", "application/octet-stream"));
            SigningCommands.HttpHandlerFactory = () => bad;
            var e = CliHarness.RunManaged("portable", "artifact-signing-root", "--endpoint", "https://wus.codesigning.azure.net", "--account-name", "acct", "--profile-name", "prof", "--output", dir.File("bad.cer"), "--access-token", "root-token");
            Assert.Equal(1, e.ExitCode);
            Assert.StartsWith("parse Artifact Signing root certificate", e.Stderr, StringComparison.Ordinal);
        }
        finally
        {
            SigningCommands.HttpHandlerFactory = null;
        }
    }

    // ------------------------------------------------------------------ test PKI

    private static JsonObject ParseJson(CliResult r)
    {
        Assert.True(r.ExitCode == 0, r.Stderr);
        return JsonNode.Parse(r.Stdout)!.AsObject();
    }

    private static readonly string[] NondeterministicPkiKeys = ["thumbprint_sha1", "thumbprint_sha256", "serial_hex", "not_before", "not_after", "cert_out", "pem_out", "key_out", "pfx_out"];

    private static void AssertSamePkiJson(JsonObject rust, JsonObject managed)
    {
        Assert.Equal(rust.Select(kv => kv.Key), managed.Select(kv => kv.Key));
        foreach (var (key, value) in rust)
        {
            if (!NondeterministicPkiKeys.Contains(key))
            {
                Assert.Equal(value!.ToJsonString(), managed[key]!.ToJsonString());
            }
        }

        var span = DateTimeOffset.Parse(rust["not_after"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture) - DateTimeOffset.Parse(rust["not_before"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);
        var mspan = DateTimeOffset.Parse(managed["not_after"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture) - DateTimeOffset.Parse(managed["not_before"]!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal(span, mspan);
        Assert.Equal(rust["serial_hex"]!.GetValue<string>().Length, managed["serial_hex"]!.GetValue<string>().Length);
    }

    private static string ExtensionProfile(string certPath)
    {
        var cert = CertificateInfo.Parse(File.ReadAllBytes(certPath));
        return string.Join(";", cert.Extensions.Select(e => $"{e.Oid}:{e.Critical}")) + $"|{cert.Version}|{cert.SignatureAlgorithm.Oid}|{Hex.Lower(cert.Subject)}|{Hex.Lower(cert.Issuer)}";
    }

    [SkippableFact]
    public void GenerateRootCaMatchesRustStructure()
    {
        RustTool.Require();
        using var dir = new TempDir();
        CliResult Run(bool rust, string tag, params string[] extra)
        {
            string[] args = ["portable", "generate-root-ca", "--subject", "CN=Root, O=Devolutions Inc., C=CA", "--validity-days", "30",
                "--cert-out", dir.File($"{tag}.der"), "--pem-out", dir.File($"{tag}.pem"), "--key-out", dir.File(Path.Combine(tag, "k.key")),
                "--pfx-out", dir.File($"{tag}.pfx"), "--password", "secret", .. extra];
            return rust ? RunRust(args) : CliHarness.RunManaged(args);
        }

        var rustJson = ParseJson(Run(true, "r", "--json"));
        var managedJson = ParseJson(Run(false, "m", "--json"));
        AssertSamePkiJson(rustJson, managedJson);
        Assert.Equal(dir.File("m.der"), managedJson["cert_out"]!.GetValue<string>());
        Assert.Equal(ExtensionProfile(dir.File("r.der")), ExtensionProfile(dir.File("m.der")));
        Assert.Equal(File.ReadAllText(dir.File("r.pem")).Length, File.ReadAllText(dir.File("m.pem")).Length);

        var rustText = Run(true, "rt");
        var managedText = Run(false, "mt");
        string Mask(string s, string tag) => string.Join('\n', Norm(s).Split('\n').Select(l => l.Split('=')[0] is "thumbprint_sha1" or "thumbprint_sha256" or "serial_hex" or "not_before" or "not_after" ? l.Split('=')[0] : l.Replace(dir.File(tag), "{tag}", StringComparison.Ordinal)));
        Assert.Equal(Mask(rustText.Stdout, "rt"), Mask(managedText.Stdout, "mt"));

        // Each tool can issue from the other's CA (PFX with password and cert + key).
        var leafRust = ParseJson(RunRust("portable", "issue-code-signing-cert", "--ca-pfx", dir.File("m.pfx"), "--ca-password", "secret", "--subject", "CN=Leaf", "--eku-oid", "1.3.6.1.4.1.311.10.3.13", "--cert-out", dir.File("lr.der"), "--json"));
        var leafManaged = ParseJson(CliHarness.RunManaged("portable", "issue-code-signing-cert", "--ca-pfx", dir.File("r.pfx"), "--ca-password", "secret", "--subject", "CN=Leaf", "--eku-oid", "1.3.6.1.4.1.311.10.3.13", "--cert-out", dir.File("lm.der"), "--json"));
        AssertSamePkiJson(leafRust, leafManaged);
        Assert.Equal(ExtensionProfile(dir.File("lr.der")).Split('|')[0], ExtensionProfile(dir.File("lm.der")).Split('|')[0]);

        var fromKeyRust = ParseJson(RunRust("portable", "issue-code-signing-cert", "--ca-cert", dir.File("m.pem"), "--ca-key", Path.Combine(dir.DirPath, "m", "k.key"), "--ca-chain-cert", _pki.CaCert, "--subject", "CN=Leaf2", "--pfx-out", dir.File("l2r.pfx"), "--json"));
        var fromKeyManaged = ParseJson(CliHarness.RunManaged("portable", "issue-code-signing-cert", "--ca-cert", dir.File("r.pem"), "--ca-key", Path.Combine(dir.DirPath, "r", "k.key"), "--ca-chain-cert", _pki.CaCert, "--subject", "CN=Leaf2", "--pfx-out", dir.File("l2m.pfx"), "--json"));
        AssertSamePkiJson(fromKeyRust, fromKeyManaged);
        Assert.Equal(2, fromKeyManaged["chain_certificate_count"]!.GetValue<int>());
    }

    [SkippableFact]
    public void IssueTlsServerCertMatchesRustStructure()
    {
        RustTool.Require();
        using var dir = new TempDir();
        string[] Args(string tag) =>
        [
            "portable", "issue-tls-server-cert", "--ca-cert", _pki.CaCert, "--ca-key", _pki.CaKey,
            "--dns", "winget.devolutions.test", "--dns", "localhost", "--ip", "127.0.0.1", "--ip", "::1", "--ip", "2001:db8:0:0:0:0:0:1",
            "--validity-days", "+10", "--cert-out", dir.File($"{tag}.der"),
        ];
        var rust = RunRust(Args("r"));
        var managed = CliHarness.RunManaged(Args("m"));
        Assert.True(rust.ExitCode == 0, rust.Stderr);
        Assert.True(managed.ExitCode == 0, managed.Stderr);
        var rl = Norm(rust.Stdout).Split('\n');
        var ml = Norm(managed.Stdout).Split('\n');
        Assert.Equal(rl.Length, ml.Length);
        foreach (var key in new[] { "subject", "issuer", "is_ca", "eku_oids", "dns_names", "ip_addresses", "chain_certificate_count" })
        {
            Assert.Equal(rl.Single(l => l.StartsWith(key + "=", StringComparison.Ordinal)), ml.Single(l => l.StartsWith(key + "=", StringComparison.Ordinal)));
        }

        Assert.Equal(ExtensionProfile(dir.File("r.der")).Split('|')[0], ExtensionProfile(dir.File("m.der")).Split('|')[0]);
        var rj = ParseJson(RunRust([.. Args("rj"), "--json", "--subject", "CN=Server, O=Test"]));
        var mj = ParseJson(CliHarness.RunManaged([.. Args("mj"), "--json", "--subject", "CN=Server, O=Test"]));
        AssertSamePkiJson(rj, mj);
    }

    [SkippableFact]
    public void TestPkiErrorsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var z = dir.File("z.der");
        AssertSameError("portable", "generate-root-ca");
        AssertSameError("portable", "generate-root-ca", "--key-bits", "1024", "--cert-out", z);
        AssertSameError("portable", "generate-root-ca", "--validity-days", "0", "--cert-out", z);
        AssertSameError("portable", "generate-root-ca", "--key-bits", "abc", "--cert-out", z);
        AssertSameError("portable", "generate-root-ca", "--validity-days", "99999999999", "--cert-out", z);
        AssertSameError("portable", "issue-code-signing-cert", "--subject", "CN=x", "--cert-out", z);
        AssertSameError("portable", "issue-code-signing-cert", "--ca-cert", _pki.LeafCert, "--ca-key", _pki.LeafKey, "--subject", "CN=x", "--cert-out", z);
        AssertSameError("portable", "issue-code-signing-cert", "--ca-pfx", _pki.CaPfx, "--subject", "CN=x", "--cert-out", z);
        AssertSameError("portable", "issue-code-signing-cert", "--ca-pfx", dir.File("missing.pfx"), "--subject", "CN=x", "--cert-out", z);
        AssertSameError("portable", "issue-code-signing-cert", "--ca-cert", _pki.CaCert, "--ca-key", _pki.CaKey, "--ca-chain-cert", dir.File("missing.der"), "--subject", "CN=x", "--cert-out", z);
        AssertSameError("portable", "issue-tls-server-cert", "--ca-cert", _pki.CaCert, "--ca-key", _pki.CaKey, "--ip", "1.2.3", "--cert-out", z);
        AssertSameError("portable", "issue-tls-server-cert", "--ca-cert", _pki.CaCert, "--ca-key", _pki.CaKey, "--ip", "01.2.3.4", "--cert-out", z);
        AssertSameError("portable", "issue-tls-server-cert", "--ca-cert", _pki.CaCert, "--ca-key", _pki.CaKey, "--cert-out", z);
        AssertSameUsageError("portable", "issue-code-signing-cert", "--ca-pfx", _pki.CaPfx, "--ca-cert", _pki.CaCert, "--subject", "CN=x", "--cert-out", z);
        AssertSameUsageError("portable", "issue-code-signing-cert", "--ca-password", "x", "--subject", "CN=x", "--cert-out", z);
        AssertSameUsageError("portable", "issue-code-signing-cert", "--ca-cert", _pki.CaCert, "--subject", "CN=x", "--cert-out", z);
        AssertSameUsageError("portable", "generate-root-ca", "--password", "x", "--cert-out", z);
        AssertSameUsageError("portable", "issue-code-signing-cert", "--cert-out", z);
        Assert.False(File.Exists(z));
    }

    // ------------------------------------------------------------------ cert-store

    [SkippableFact]
    public void CertStoreMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var rustStore = dir.File("rust-store");
        var managedStore = dir.File("managed-store");

        void Same(Func<string, string[]> args, bool expectSuccess = true)
        {
            var rust = RunRust(args(rustStore));
            var managed = CliHarness.RunManaged(args(managedStore));
            Assert.True(rust.ExitCode == managed.ExitCode, $"rust={rust.ExitCode} {rust.Stderr} managed={managed.ExitCode} {managed.Stderr}");
            Assert.Equal(expectSuccess ? 0 : 1, rust.ExitCode);
            Assert.Equal(rust.Stdout.Replace(rustStore, "{store}", StringComparison.Ordinal).Replace(JsonEscape(rustStore), "{store}", StringComparison.Ordinal),
                managed.Stdout.Replace(managedStore, "{store}", StringComparison.Ordinal).Replace(JsonEscape(managedStore), "{store}", StringComparison.Ordinal));
            Assert.Equal(Norm(rust.Stderr).Replace(rustStore, "{store}", StringComparison.Ordinal), Norm(managed.Stderr).Replace(managedStore, "{store}", StringComparison.Ordinal));
        }

        void SameOnSharedStore(params string[] args)
        {
            var rust = RunRust(["cert-store", .. args, "--cert-store-dir", rustStore]);
            var managed = CliHarness.RunManaged(["cert-store", .. args, "--cert-store-dir", rustStore]);
            Assert.Equal(rust.ExitCode, managed.ExitCode);
            Assert.Equal(rust.Stdout, managed.Stdout);
            Assert.Equal(Norm(rust.Stderr), Norm(managed.Stderr));
        }

        var leafPem = dir.File("leaf.pem");
        File.WriteAllText(leafPem, Devolutions.Psign.Signing.Pki.TestPki.EncodePemCertificateBundle([_pki.LeafDer]));
        Same(s => ["cert-store", "list", "--cert-store-dir", s]);
        Same(s => ["cert-store", "list", "--cert-store-dir", s, "--json"]);
        Same(s => ["cert-store", "import", "--cert-store-dir", s, "--key", _pki.LeafKey, leafPem]);
        Same(s => ["cert-store", "import", "--cert-store-dir", s, _pki.LeafCert]);
        Same(s => ["cert-store", "import-pfx", "--cert-store-dir", s, "--sm", "--s", "root", "--p", SigningCliPki.PfxPassword, _pki.CaPfx]);
        Same(s => ["cert-store", "import-pfx", "--cert-store-dir", s, "--machine-store", "--store", "Root", "--password", SigningCliPki.PfxPassword, _pki.CaPfx]);
        Same(s => ["cert-store", "import", "--cert-store-dir", s, "--store", "CA", _pki.CaCert]);
        foreach (var store in new[] { "MY", "CA" })
        {
            Assert.Equal(
                Directory.GetFiles(Path.Combine(rustStore, "CurrentUser", store)).Select(Path.GetFileName).Order(),
                Directory.GetFiles(Path.Combine(managedStore, "CurrentUser", store)).Select(Path.GetFileName).Order());
        }

        var thumb = _pki.LeafThumbprint;
        AssertSameFile(Path.Combine(rustStore, "CurrentUser", "MY", thumb + ".key"), Path.Combine(managedStore, "CurrentUser", "MY", thumb + ".key"));
        AssertSameFile(Path.Combine(rustStore, "LocalMachine", "Root", Convert.ToHexString(SHA1.HashData(_pki.CaDer)) + ".key"), Path.Combine(managedStore, "LocalMachine", "Root", Convert.ToHexString(SHA1.HashData(_pki.CaDer)) + ".key"));

        SameOnSharedStore("list");
        SameOnSharedStore("list", "--json");
        SameOnSharedStore("list", "--sm", "--store", "root");
        SameOnSharedStore("list", "--store", "Trust");
        var colonThumb = string.Join(':', Enumerable.Range(0, 20).Select(i => thumb.Substring(i * 2, 2).ToLowerInvariant()));
        SameOnSharedStore("print", "--sha1", colonThumb);
        SameOnSharedStore("print", "--sha1", thumb, "--json");
        SameOnSharedStore("print", "--sha1", "00");
        SameOnSharedStore("print", "--sha1", new string('Z', 40));
        SameOnSharedStore("print", "--sha1", new string('0', 40));
        SameOnSharedStore("list", "--store", "a/b");
        SameOnSharedStore("list", "--store", " ");

        // Quiet mode suppresses stdout on success.
        var quietRust = RunRust("-q", "cert-store", "list", "--cert-store-dir", rustStore);
        var quietManaged = CliHarness.RunManaged("-q", "cert-store", "list", "--cert-store-dir", rustStore);
        Assert.Equal(0, quietRust.ExitCode);
        Assert.Equal(quietRust.Stdout, quietManaged.Stdout);
        Assert.Empty(quietManaged.Stdout);

        Same(s => ["cert-store", "export", "--cert-store-dir", s, "--sha1", thumb, "--out", s + ".out.der", "--with-key", "--key-out", s + ".out.key"]);
        AssertSameFile(rustStore + ".out.der", managedStore + ".out.der");
        AssertSameFile(rustStore + ".out.key", managedStore + ".out.key");
        Same(s => ["cert-store", "export", "--cert-store-dir", s, "--sha1", thumb, "--out", s + ".out.der"], expectSuccess: false);
        Same(s => ["cert-store", "export", "--cert-store-dir", s, "--sha1", thumb, "--out", s + ".out.der", "--force"]);
        Same(s => ["cert-store", "export", "--cert-store-dir", s, "--store", "CA", "--sha1", Convert.ToHexString(SHA1.HashData(_pki.CaDer)), "--out", s + ".ca.der", "--with-key"], expectSuccess: false);
        Same(s => ["cert-store", "export", "--cert-store-dir", s, "--sha1", thumb, "--out", s + ".x.der", "--with-key"], expectSuccess: false);
        AssertSameUsageError("cert-store", "export", "--sha1", thumb, "--out", dir.File("x.der"), "--key-out", dir.File("x.key"));
        AssertSameUsageError("cert-store", "import-pfx", _pki.CaPfx);
        Same(s => ["cert-store", "import", "--cert-store-dir", s, "--key", _pki.CaKey, _pki.LeafCert], expectSuccess: false);
        Same(s => ["cert-store", "import", "--cert-store-dir", s, dir.File("missing.der")], expectSuccess: false);
        Same(s => ["cert-store", "import-pfx", "--cert-store-dir", s, "--password", "wrong", _pki.LeafPfx], expectSuccess: false);
        Same(s => ["cert-store", "remove", "--cert-store-dir", s, "--sha1", thumb]);
        Same(s => ["cert-store", "remove", "--cert-store-dir", s, "--sha1", thumb], expectSuccess: false);
        Same(s => ["cert-store", "remove", "--cert-store-dir", s, "--store", "ca", "--sha1", Convert.ToHexString(SHA1.HashData(_pki.CaDer))]);
    }

    private static string JsonEscape(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal);

    // ------------------------------------------------------------------ generic error parity

    [SkippableFact]
    public void SigningErrorsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var x = dir.File("x.out");
        var pe = Fixtures.Path(UnsignedPe);
        var cab = Fixtures.Path(UnsignedCab);
        var msi = Fixtures.Path(UnsignedMsi);
        AssertSameError("portable", "sign-pe", pe, "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--cert", _pki.LeafCert, "--output", x);
        AssertSameError("portable", "sign-pe", dir.File("missing.efi"), "--cert", _pki.LeafCert, "--key", _pki.LeafKey, "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--cert", dir.File("missing.der"), "--key", _pki.LeafKey, "--output", x);
        AssertSameError("portable", "sign-pe", pe, "--cert", _pki.LeafCert, "--key", dir.File("missing.key"), "--output", x);
        AssertSameError(["portable", "sign-pe", pe, .. LocalSigner(), "--chain-cert", dir.File("missing.der"), "--output", x]);
        AssertSameError(["portable", "sign-pe", pe, .. LocalSigner(), "--tr", "http://127.0.0.1:9/tsa", "--output", x]);
        AssertSameError(["portable", "sign-pe", pe, .. LocalSigner(), "--td", "sha256", "--output", x]);
        AssertSameError(["portable", "sign-pe", Fixtures.Path(CatalogSubjects[1]), .. LocalSigner(), "--output", x]);
        AssertSameError("portable", "sign-cab", cab, "--output", x);
        AssertSameError(["portable", "sign-cab", cab, .. LocalSigner(), "--tr", "http://127.0.0.1:9/tsa", "--output", x]);
        AssertSameError(["portable", "sign-cab", cab, .. LocalSigner(), "--td", "sha1", "--output", x]);
        AssertSameError(["portable", "sign-cab", pe, .. LocalSigner(), "--output", x]);
        AssertSameError("portable", "sign-msi", msi, "--cert", _pki.LeafCert, "--output", x);
        AssertSameError(["portable", "sign-msi", pe, .. LocalSigner(), "--output", x]);
        AssertSameError(["portable", "sign-msi", msi, .. LocalSigner(), "--td", "sha384", "--output", x]);
        AssertSameError("portable", "sign-catalog", "--output", x, Fixtures.Path(CatalogSubjects[1]));
        AssertSameError(["portable", "sign-catalog", .. LocalSigner(), "--output", x, dir.File("missing.txt")]);
        AssertSameError(["portable", "sign-catalog", .. LocalSigner(), "--output", x, Fixtures.Path(CatalogSubjects[1]), Fixtures.Path(CatalogSubjects[1])]);
        AssertSameError(["portable", "sign-catalog", .. LocalSigner(), "--tr", "http://127.0.0.1:9", "--output", x, Fixtures.Path(CatalogSubjects[1])]);
        AssertSameError("portable", "timestamp-pe-rfc3161", Fixtures.Path(SignedPe), "--output", x);
        AssertSameError("portable", "timestamp-pe-rfc3161", Fixtures.Path(SignedPe), "--tr", "http://127.0.0.1:9", "--output", x);
        AssertSameError("portable", "timestamp-pe-rfc3161", Fixtures.Path(SignedPe), "--tr", "http://127.0.0.1:9", "--td", "sha256", "--signer-index", "1", "--output", x);
        AssertSameError("portable", "timestamp-pe-rfc3161", Fixtures.Path(SignedPe), "--token", dir.File("missing.der"), "--output", x);
        AssertSameUsageError("portable", "sign-pe", pe, "--cert", _pki.LeafCert);
        AssertSameUsageError("portable", "sign-pe", pe, "--output", x, "--digest", "sha1");
        AssertSameUsageError("portable", "sign-catalog", "--output", x);
        AssertSameUsageError("portable", "timestamp-pe-rfc3161", Fixtures.Path(SignedPe), "--token", "a", "--response", "b", "--output", x);
        AssertSameUsageError("portable", "timestamp-pe-rfc3161", Fixtures.Path(SignedPe), "--digest", "sha256", "--output", x);
        AssertSameUsageError("portable", "rfc3161-timestamp-http-post", "--digest-hex", "00");
        AssertSameUsageError("portable", "azure-key-vault-sign-digest", "--kvu", "https://x");
        AssertSameUsageError("portable", "artifact-signing-root", "--endpoint", "https://x");
        Assert.False(File.Exists(x));
    }
}
