using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.Timestamp;
using Devolutions.Psign.Tests.Cli;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Server;

/// <summary>
/// The existing managed clients (and the Rust <c>psign-tool</c>) pointed at the managed <c>psign-server</c>: RFC 3161
/// timestamping, Azure Key Vault and Artifact Signing remote signing, online AIA / OCSP / CRL trust, and a full
/// sign + timestamp + verify round trip. Loopback only.
/// </summary>
public sealed class ServerClientEndToEndTests
{
    private static ServerProcess Managed(int lines, params string[] args) => ServerProcess.Start(RustBinaries.ManagedServer, lines, args);

    private static readonly IReadOnlyDictionary<string, string?> PortableEnv = new Dictionary<string, string?>
    {
        ["PSIGN_TOOL_MODE"] = "portable",
        ["PSIGN_NO_AUTO_TRUST"] = "1",
    };

    [Fact]
    public void TimestampClientGetsGrantedTokenFromManagedServer()
    {
        using var server = Managed(1, "timestamp-server", "--gen-time", "20260102030405Z");
        using var client = new TimestampClient();
        var data = "payload"u8.ToArray();
        var token = client.RequestToken(server.BaseUrl, AuthenticodeHashKind.Sha256, data);
        var tst = Rfc3161.ParseTimeStampTokenTstInfo(token)!;
        Assert.Equal("20260102030405Z", tst.GenTime);
        Assert.Equal(SHA256.HashData(data), tst.MessageImprintHashedMessage);
        Assert.Equal("1.3.6.1.4.1.311.97.99.1", tst.PolicyOid);

        var token2 = client.RequestToken(server.BaseUrl, AuthenticodeHashKind.Sha384, data);
        var tst2 = Rfc3161.ParseTimeStampTokenTstInfo(token2)!;
        Assert.Equal(SHA384.HashData(data), tst2.MessageImprintHashedMessage);
        Assert.Equal("02", tst2.SerialNumberHex);
    }

    [Theory]
    [InlineData("--status", "rejection")]
    [InlineData("--response-mode", "http-error")]
    [InlineData("--response-mode", "malformed-der")]
    public void TimestampClientRejectsNegativeModes(string flag, string value)
    {
        using var server = Managed(1, "timestamp-server", flag, value);
        using var client = new TimestampClient();
        Assert.ThrowsAny<PsignException>(() => client.RequestToken(server.BaseUrl, AuthenticodeHashKind.Sha256, [1, 2, 3]));
    }

    [Fact]
    public void AzureKeyVaultClientSignsWithManagedServer()
    {
        using var dir = new TempDir();
        var leafPath = dir.File("leaf.der");
        using var server = Managed(3, "azure-key-vault-server", "--leaf-cert-output", leafPath, "--certificate-name", "c1", "--key-name", "k1", "--version", "v9");
        using var client = new AzureKeyVaultClient();
        var signer = AzureKeyVaultDigestSigner.Create(client, server.BaseUrl, "c1", "v9", new KvAuthParams { AccessToken = "tok" });
        Assert.Equal(File.ReadAllBytes(leafPath), signer.Certificate.RawData);
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(CertificateInfo.Parse(signer.Certificate.RawData).SubjectPublicKeyInfo, out _);
        foreach (var kind in new[] { AuthenticodeHashKind.Sha256, AuthenticodeHashKind.Sha384, AuthenticodeHashKind.Sha512 })
        {
            var digest = kind.Hash("kv"u8.ToArray());
            var sig = signer.SignDigest(digest, kind);
            var name = kind switch
            {
                AuthenticodeHashKind.Sha256 => HashAlgorithmName.SHA256,
                AuthenticodeHashKind.Sha384 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA512,
            };
            Assert.True(rsa.VerifyHash(digest, sig, name, RSASignaturePadding.Pkcs1));
        }
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("sync-success")]
    [InlineData("body-id")]
    [InlineData("body-operation-id")]
    [InlineData("pem-chain")]
    public async Task ArtifactSigningClientSignsWithManagedServer(string mode)
    {
        using var dir = new TempDir();
        var leafPath = dir.File("leaf.der");
        using var server = Managed(2, "artifact-signing-server", "--response-mode", mode, "--leaf-cert-output", leafPath, "--expect-signature-algorithm", "RS256");
        using var client = new ArtifactSigningClient(environment: _ => null) { PollInterval = TimeSpan.FromMilliseconds(10) };
        var template = new CodesigningSubmitParams
        {
            Region = "local",
            AccountName = "acct",
            ProfileName = "prof",
            EndpointBaseUrl = server.BaseUrl,
            Auth = new CodesigningAuth.Bearer("tok"),
        };
        var digest = SHA256.HashData("artifact"u8);
        var result = await client.SubmitCodesignHashSignatureAsync(template.WithDigest(digest, "RS256"));
        var (leaf, _) = ArtifactSigningCertificates.Parse(result.SigningCertificate);
        Assert.Equal(File.ReadAllBytes(leafPath), leaf.RawData);
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(leaf.SubjectPublicKeyInfo, out _);
        Assert.True(rsa.VerifyHash(digest, result.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Theory]
    [InlineData("failed")]
    [InlineData("canceled")]
    [InlineData("http-error")]
    [InlineData("poll-http-error")]
    [InlineData("malformed-json")]
    [InlineData("poll-malformed-json")]
    public async Task ArtifactSigningClientReportsNegativeModes(string mode)
    {
        using var server = Managed(2, "artifact-signing-server", "--response-mode", mode);
        using var client = new ArtifactSigningClient(environment: _ => null) { PollInterval = TimeSpan.FromMilliseconds(10), MaxPollAttempts = 3 };
        var p = new CodesigningSubmitParams
        {
            Region = "local",
            AccountName = "acct",
            ProfileName = "prof",
            EndpointBaseUrl = server.BaseUrl,
            Auth = new CodesigningAuth.Bearer("tok"),
            Digest = new byte[32],
        };
        await Assert.ThrowsAnyAsync<PsignException>(() => client.SubmitCodesignHashSignatureAsync(p));
    }

    private static OnlineTrustOptions Online(ServerProcess pki, bool ocsp, RevocationMode mode = RevocationMode.Require) => new()
    {
        EnableOcsp = ocsp,
        OcspUrlOverride = ocsp ? pki.BaseUrl + "ocsp" : null,
        CrlUrlOverride = pki.BaseUrl + "crl.der",
        AiaUrlOverride = pki.BaseUrl + "issuer.der",
        RevocationMode = mode,
    };

    [Fact]
    public void OnlineTrustAgainstManagedPkiServer()
    {
        using var dir = new TempDir();
        string root = dir.File("root.der"), leaf = dir.File("leaf.der");
        using (var pki = Managed(6, "pki-server", "--root-cert-output", root, "--leaf-cert-output", leaf))
        {
            var rootCert = CertificateInfo.Parse(File.ReadAllBytes(root));
            var leafCert = CertificateInfo.Parse(File.ReadAllBytes(leaf));
            var issuers = OnlineTrust.IssuerCandidatesFromAia(leafCert, Online(pki, true));
            Assert.Equal(rootCert.RawData, Assert.Single(issuers).RawData);
            OnlineTrust.CheckRevocationChain(leafCert, [rootCert], Online(pki, ocsp: true));
            OnlineTrust.CheckRevocationChain(leafCert, [rootCert], Online(pki, ocsp: false));
        }

        using (var pki = Managed(6, "pki-server", "--root-cert-output", root, "--leaf-cert-output", leaf, "--ocsp-status", "revoked"))
        {
            var e = Assert.Throws<PsignException>(() => OnlineTrust.CheckRevocationChain(CertificateInfo.Parse(File.ReadAllBytes(leaf)), [CertificateInfo.Parse(File.ReadAllBytes(root))], Online(pki, ocsp: true)));
            Assert.Equal("OCSP status is revoked", e.Message);
        }

        using (var pki = Managed(6, "pki-server", "--root-cert-output", root, "--leaf-cert-output", leaf, "--ocsp-status", "unknown", "--crl-revoke-leaf"))
        {
            var leafCert = CertificateInfo.Parse(File.ReadAllBytes(leaf));
            var rootCert = CertificateInfo.Parse(File.ReadAllBytes(root));
            Assert.Equal("OCSP status is unknown", Assert.Throws<PsignException>(() => OnlineTrust.CheckRevocationChain(leafCert, [rootCert], Online(pki, ocsp: true))).Message);
            Assert.StartsWith("certificate is revoked by CRL ", Assert.Throws<PsignException>(() => OnlineTrust.CheckRevocationChain(leafCert, [rootCert], Online(pki, ocsp: false))).Message);
        }
    }

    /// <summary>
    /// Sign a PE with the managed PKI server's leaf, timestamp it with the managed TSA, then verify with both the managed
    /// and the Rust <c>psign-tool</c> using online OCSP / CRL checks against the managed PKI server.
    /// </summary>
    [SkippableFact]
    public void SignTimestampAndVerifyRoundTripWithManagedServers()
    {
        using var dir = new TempDir();
        string pkiRoot = dir.File("pki-root.der"), leaf = dir.File("leaf.der"), key = dir.File("leaf.pk8"), tsaRoot = dir.File("tsa-root.der");
        using var pki = Managed(6, "pki-server", "--root-cert-output", pkiRoot, "--leaf-cert-output", leaf, "--leaf-key-output", key);
        using var tsa = Managed(1, "timestamp-server", "--cert-output", tsaRoot, "--gen-time", DateTime.UtcNow.ToString("yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture) + "Z");
        var signed = dir.File("signed.exe");
        var sign = CliHarness.RunManaged(PortableEnv, "portable", "sign-pe", Fixtures.Path("generated-unsigned/pe/tiny64-pe-alias.exe"), "--cert", leaf, "--key", key, "--timestamp-url", tsa.BaseUrl, "--timestamp-digest", "sha256", "--output", signed);
        Assert.True(sign.ExitCode == 0, sign.Stderr);

        string[] verify =
        [
            "portable", "trust-verify-pe", signed, "--trusted-ca", pkiRoot, "--trusted-ca", tsaRoot,
            "--online-ocsp", "--ocsp-url-override", pki.BaseUrl + "ocsp",
            "--revocation-mode", "require", "--crl-url-override", pki.BaseUrl + "crl.der",
        ];
        var managed = CliHarness.RunManaged(PortableEnv, verify);
        Assert.True(managed.ExitCode == 0, managed.Stderr);
        Assert.StartsWith("trust-verify-pe: ok", managed.Stdout);

        RustTool.Require();
        var rust = RustTool.Run(PortableEnv, verify);
        Assert.True(rust.ExitCode == 0, rust.Stderr);
        Assert.Equal(rust.Stdout, managed.Stdout);
    }

    /// <summary>Remote signing through the managed CLI against the managed Key Vault and Artifact Signing servers.</summary>
    [Fact]
    public void RemoteSigningThroughCliWithManagedServers()
    {
        using var dir = new TempDir();
        string kvRoot = dir.File("kv-root.der"), asRoot = dir.File("as-root.der");
        using var kv = Managed(3, "azure-key-vault-server", "--root-cert-output", kvRoot);
        using var artifact = Managed(2, "artifact-signing-server", "--root-cert-output", asRoot, "--expect-correlation-id", "cid-1");
        var input = Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe");

        var kvOut = dir.File("kv.exe");
        var kvSign = CliHarness.RunManaged(PortableEnv, "portable", "sign-pe", input, "--azure-key-vault-url", kv.BaseUrl, "--azure-key-vault-certificate", "psign-test-cert", "--azure-key-vault-accesstoken", "tok", "--output", kvOut);
        Assert.True(kvSign.ExitCode == 0, kvSign.Stderr);
        var kvVerify = CliHarness.RunManaged(PortableEnv, "portable", "trust-verify-pe", kvOut, "--trusted-ca", kvRoot);
        Assert.True(kvVerify.ExitCode == 0, kvVerify.Stderr);

        var asOut = dir.File("as.exe");
        var asSign = CliHarness.RunManaged(
            PortableEnv,
            "portable", "sign-pe", input,
            "--artifact-signing-endpoint-base-url", artifact.BaseUrl.TrimEnd('/'),
            "--artifact-signing-region", "local",
            "--artifact-signing-account-name", "acct",
            "--artifact-signing-profile-name", "prof",
            "--artifact-signing-access-token", "tok",
            "--artifact-signing-correlation-id", "cid-1",
            "--output", asOut);
        Assert.True(asSign.ExitCode == 0, asSign.Stderr);
        var asVerify = CliHarness.RunManaged(PortableEnv, "portable", "trust-verify-pe", asOut, "--trusted-ca", asRoot);
        Assert.True(asVerify.ExitCode == 0, asVerify.Stderr);
    }
}
