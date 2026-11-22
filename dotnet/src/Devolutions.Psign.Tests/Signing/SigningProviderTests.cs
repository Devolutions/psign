using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.CertStore;
using Devolutions.Psign.Signing.Internal;
using Devolutions.Psign.Signing.Pki;
using Devolutions.Psign.Signing.Providers;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>Port of the <c>signing_provider.rs</c> unit tests plus provider instantiation.</summary>
public class SigningProviderTests
{
    [Fact]
    public void SelectsPortableStoreFromSha1()
    {
        var provider = SigningProviderConfig.FromSignOptions(new SigningProviderOptions { CertSha1 = "ABC" });
        Assert.Equal(SigningProviderKind.PortableStore, provider.Kind);
        Assert.Equal(new SigningProviderIdentity.PortableStore("ABC", false, "MY", null), provider.Identity);
    }

    [Fact]
    public void RejectsMixedCloudProviderOptions()
    {
        var e = Assert.Throws<PsignException>(() => SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            AzureKeyVaultUrl = "https://vault.example",
            AzureKeyVaultCertificate = "cert",
            ArtifactSigningProfileName = "profile",
        }));
        Assert.Contains("ambiguous", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ArtifactSigningUsesClientSecretAuthShape()
    {
        var provider = SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            ArtifactSigningEndpoint = "https://westus.codesigning.azure.net",
            ArtifactSigningAccountName = "acct",
            ArtifactSigningProfileName = "profile",
            ArtifactSigningTenantId = "tenant",
            ArtifactSigningClientId = "client",
            ArtifactSigningClientSecret = "secret",
        });
        Assert.Equal(SigningProviderKind.ArtifactSigning, provider.Kind);
        var identity = Assert.IsType<SigningProviderIdentity.ArtifactSigning>(provider.Identity);
        var auth = Assert.IsType<AzureAuthConfig.ClientSecret>(identity.Auth);
        Assert.Equal("client", auth.ClientId);
    }

    [Fact]
    public void AzureCredentialTypeManagedIdentityMapsToManagedIdentityAuth()
    {
        var provider = SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            AzureKeyVaultUrl = "https://vault.example",
            AzureKeyVaultCertificate = "cert",
            AzureKeyVaultCredentialType = AzureCredentialType.ManagedIdentity,
            AzureKeyVaultClientId = "user-assigned-client",
        });
        var identity = Assert.IsType<SigningProviderIdentity.AzureKeyVault>(provider.Identity);
        Assert.Equal(new AzureAuthConfig.ManagedIdentity("user-assigned-client", null, null), identity.Auth);
    }

    [Fact]
    public void AzureCredentialTypeWorkloadIdentityIsRepresentedForPlanning()
    {
        var provider = SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            ArtifactSigningEndpoint = "https://westus.codesigning.azure.net",
            ArtifactSigningAccountName = "acct",
            ArtifactSigningProfileName = "profile",
            ArtifactSigningCredentialType = AzureCredentialType.WorkloadIdentity,
            ArtifactSigningTenantId = "tenant",
            ArtifactSigningClientId = "client",
        });
        var identity = Assert.IsType<SigningProviderIdentity.ArtifactSigning>(provider.Identity);
        Assert.Equal(new AzureAuthConfig.WorkloadIdentity("tenant", "client", null, null), identity.Auth);
    }

    [Fact]
    public void ProviderSelectionErrorsAndPrecedence()
    {
        Assert.Equal(
            "no signing provider selected; specify --sha1, --pfx, Windows store selection, Azure Key Vault, or Artifact Signing options",
            Assert.Throws<PsignException>(() => SigningProviderConfig.FromSignOptions(new SigningProviderOptions())).Message);
        Assert.Equal(
            "signing provider options are ambiguous: do not combine --pfx with certificate store selection options",
            Assert.Throws<PsignException>(() => SigningProviderConfig.FromSignOptions(new SigningProviderOptions { Pfx = "a.pfx", SubjectName = "x" })).Message);
        Assert.Equal(
            "Azure Key Vault supports only SHA256, SHA384, or SHA512 file digests",
            Assert.Throws<PsignException>(() => SigningProviderConfig.FromSignOptions(new SigningProviderOptions { AzureKeyVaultUrl = "u", Digest = SignDigestAlgorithm.Sha1 })).Message);
        Assert.Equal(
            "--azure-key-vault-certificate is required for the selected signing provider",
            Assert.Throws<PsignException>(() => SigningProviderConfig.FromSignOptions(new SigningProviderOptions { AzureKeyVaultUrl = "u" })).Message);

        var windows = SigningProviderConfig.FromSignOptions(new SigningProviderOptions { SubjectName = " Contoso ", MachineStore = true });
        Assert.Equal(new SigningProviderIdentity.WindowsStore(false, "Contoso", null, null, true, "MY"), windows.Identity);

        var pfx = SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            Pfx = "a.pfx",
            Digest = SignDigestAlgorithm.CertHash,
            SealTimestampUrl = "http://seal",
            LegacyTimestampUrl = "http://legacy",
            TimestampDigest = SignDigestAlgorithm.Sha384,
        });
        Assert.Equal("cert-hash", pfx.DigestAlgorithm);
        Assert.Equal("http://seal", pfx.TimestampUrl);
        Assert.Equal("sha384", pfx.TimestampDigestAlgorithm);

        var ambient = SigningProviderConfig.FromSignOptions(new SigningProviderOptions { Dmdf = "metadata.json", ArtifactSigningAuthority = " https://login.test " });
        Assert.Equal(new AzureAuthConfig.Ambient("https://login.test"), Assert.IsType<SigningProviderIdentity.ArtifactSigning>(ambient.Identity).Auth);
    }

    [Fact]
    public void ConfigJsonMatchesSerdeShape()
    {
        var config = SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            AzureKeyVaultUrl = "https://vault.example",
            AzureKeyVaultCertificate = "cert",
            AzureKeyVaultAccessToken = "secret-token",
            TimestampUrl = "http://ts",
            TimestampDigest = SignDigestAlgorithm.Sha256,
        });
        Assert.Equal(
            """
            {
              "kind": "azure-key-vault",
              "digest_algorithm": "sha256",
              "timestamp_url": "http://ts",
              "timestamp_digest_algorithm": "sha256",
              "identity": {
                "type": "azure-key-vault",
                "vault_url": "https://vault.example",
                "certificate": "cert",
                "certificate_version": null,
                "auth": {
                  "mode": "access-token",
                  "authority": null
                }
              }
            }
            """.ReplaceLineEndings("\n"),
            config.ToJson());
        Assert.DoesNotContain("secret-token", config.ToJson(), StringComparison.Ordinal);
    }

    [Fact]
    public void FactoryCreatesLocalKeyProviders()
    {
        using var dir = new TempDir();
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Provider Root"));
        var leaf = TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=Provider Leaf"));
        File.WriteAllBytes(dir.File("leaf.pfx"), TestPki.EncodePfxDer(leaf, "pw"));
        var digest = SHA256.HashData("data"u8);

        var pfxConfig = SigningProviderConfig.FromSignOptions(new SigningProviderOptions { Pfx = dir.File("leaf.pfx") });
        using (var provider = (LocalKeySigningProvider)SigningProviderFactory.Create(pfxConfig, new SigningProviderSecrets { PfxPassword = "pw" }))
        {
            Assert.Equal(SigningProviderKind.Pfx, provider.Kind);
            Assert.Equal(new[] { leaf.CertificateDer, root.CertificateDer }, provider.CertificateChainDer());
            using var pub = leaf.Certificate.X509.GetRSAPublicKey()!;
            Assert.True(pub.VerifyHash(digest, provider.SignDigest(digest, AuthenticodeHashKind.Sha256), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        new PortableCertStore(_ => null).ImportPfx(new CertStoreSelection(dir.File("store")), dir.File("leaf.pfx"), "pw");
        var storeConfig = SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            CertSha1 = PortableCertStore.Sha1ThumbprintUpper(leaf.CertificateDer).ToLowerInvariant(),
            CertStoreDir = dir.File("store"),
        });
        using (var provider = (LocalKeySigningProvider)SigningProviderFactory.Create(storeConfig))
        {
            Assert.Equal(SigningProviderKind.PortableStore, provider.Kind);
            Assert.Equal(leaf.CertificateDer, SigningProviderFactory.SignerCertificate(provider).RawData);
        }

        var windows = SigningProviderConfig.FromSignOptions(new SigningProviderOptions { AutoSelect = true });
        Assert.Throws<PsignException>(() => SigningProviderFactory.Create(windows));
    }

    [Fact]
    public void FactoryCreatesArtifactSigningProvider()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", @"^https://eus\.codesigning\.azure\.net/codesigningaccounts/acct/certificateprofiles/prof:sign\?api-version=2024-06-15$")
            .MatchHeader("Authorization", "Bearer as-token")
            .Respond(200, SerdeJson.Compact(new JsonObject
            {
                ["status"] = "Succeeded",
                ["signature"] = Convert.ToBase64String([9, 9]),
                ["signingCertificate"] = Convert.ToBase64String([0x30, 0x00]),
            }));
        var config = SigningProviderConfig.FromSignOptions(new SigningProviderOptions
        {
            Digest = SignDigestAlgorithm.Sha512,
            ArtifactSigningEndpoint = "https://eus.codesigning.azure.net",
            ArtifactSigningAccountName = "acct",
            ArtifactSigningProfileName = "prof",
            ArtifactSigningAccessToken = "ignored-in-config",
        });
        using var provider = (ArtifactSigningSigningProvider)SigningProviderFactory.Create(config, new SigningProviderSecrets
        {
            ArtifactSigningAccessToken = "as-token",
            HttpHandler = mock,
            Environment = _ => null,
        });
        Assert.Throws<PsignException>(() => provider.CertificateChainDer());
        Assert.Equal(new byte[] { 9, 9 }, provider.SignDigest(new byte[64], AuthenticodeHashKind.Sha512));
        Assert.Equal(new byte[] { 0x30, 0x00 }, Assert.Single(provider.CertificateChainDer()));
        Assert.Contains("\"signatureAlgorithm\":\"RS512\"", mock.Requests[0].BodyText, StringComparison.Ordinal);
    }
}
