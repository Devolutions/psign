using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.Internal;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// Port of <c>crates/psign-azure-kv-rest/tests/kv_rest_mock.rs</c> and the unit tests in
/// <c>crates/psign-azure-kv-rest/src/lib.rs</c>.
/// </summary>
public class AzureKeyVaultTests
{
    private const string VaultBase = "http://kv.mock.test";

    private static byte[] EcLeafDer()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=KV mock leaf", key, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return cert.RawData;
    }

    [Fact]
    public void FetchCertificateAndSignDigestAgainstMockKv()
    {
        var cerB64 = Convert.ToBase64String(EcLeafDer());
        var kid = VaultBase + "/keys/mykey/versions/v1";
        var mock = new MockHttpHandler();
        var certRoute = mock.Map("GET", @"/certificates/my-cert(\?.*)?$")
            .MatchHeader("Authorization", "Bearer test-bearer-token")
            .Respond(200, SerdeJson.Compact(new JsonObject { ["kid"] = kid, ["cer"] = cerB64 }), ("Content-Type", "application/json"));
        byte[] sigBytes = [0xde, 0xad, 0xbe, 0xef];
        var signRoute = mock.Map("POST", @"/keys/mykey/versions/v1/sign(\?.*)?$")
            .Respond(200, SerdeJson.Compact(new JsonObject { ["value"] = AzureKeyVaultClient.Base64UrlEncode(sigBytes) }), ("Content-Type", "application/json"));

        using var client = new AzureKeyVaultClient(mock);
        const string token = "test-bearer-token";
        var certMeta = client.FetchCertificate(VaultBase, "my-cert", null, token);
        Assert.Equal(kid, certMeta.Kid);

        var digest = Enumerable.Repeat((byte)0xab, 32).ToArray();
        var output = client.SignDigestFromCertificate(token, certMeta, KvHashAlg.Sha256, digest);
        Assert.Equal(sigBytes, output);
        Assert.Equal(1, certRoute.Hits);
        Assert.Equal(1, signRoute.Hits);

        Assert.Equal(VaultBase + "/certificates/my-cert?api-version=7.4", mock.Requests[0].Uri.AbsoluteUri);
        Assert.Equal(VaultBase + "/keys/mykey/versions/v1/sign?api-version=7.4", mock.Requests[1].Uri.AbsoluteUri);
        Assert.Equal("{\"alg\":\"ES256\",\"value\":\"" + AzureKeyVaultClient.Base64UrlEncode(digest) + "\"}", mock.Requests[1].BodyText);
        Assert.Equal("Bearer test-bearer-token", mock.Requests[1].Headers["Authorization"]);
    }

    [Fact]
    public void JwsAlgRsaSha256() => Assert.Equal("RS256", AzureKeyVaultClient.JwsAlg(KvPublicKeyKind.Rsa, KvHashAlg.Sha256));

    [Fact]
    public void JwsAlgEcSha384() => Assert.Equal("ES384", AzureKeyVaultClient.JwsAlg(KvPublicKeyKind.Ec, KvHashAlg.Sha384));

    [Fact]
    public void JwsAlgRsaSha384Sha512AndEcSha256Sha512()
    {
        Assert.Equal("RS384", AzureKeyVaultClient.JwsAlg(KvPublicKeyKind.Rsa, KvHashAlg.Sha384));
        Assert.Equal("RS512", AzureKeyVaultClient.JwsAlg(KvPublicKeyKind.Rsa, KvHashAlg.Sha512));
        Assert.Equal("ES256", AzureKeyVaultClient.JwsAlg(KvPublicKeyKind.Ec, KvHashAlg.Sha256));
        Assert.Equal("ES512", AzureKeyVaultClient.JwsAlg(KvPublicKeyKind.Ec, KvHashAlg.Sha512));
    }

    [Fact]
    public void NormalizeVaultBaseRejectsEmpty()
    {
        Assert.Throws<PsignException>(() => AzureKeyVaultClient.NormalizeVaultBase(string.Empty));
        Assert.Throws<PsignException>(() => AzureKeyVaultClient.NormalizeVaultBase("   "));
    }

    [Fact]
    public void NormalizeVaultBaseTrimsWhitespaceAndTrailingSlashes() =>
        Assert.Equal("https://ex.vault.azure.net", AzureKeyVaultClient.NormalizeVaultBase("  https://ex.vault.azure.net/  "));

    [Fact]
    public void NormalizeVaultBasePreservesExplicitPort() =>
        Assert.Equal("https://kv-test.vault.azure.net:8443", AzureKeyVaultClient.NormalizeVaultBase("https://kv-test.vault.azure.net:8443/"));

    [Fact]
    public void SignUrlFromKidAppendsSignAndApiVersion()
    {
        var u = AzureKeyVaultClient.SignUrlFromKid("https://contoso.vault.azure.net/keys/mycert/versions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        Assert.EndsWith("/sign?api-version=7.4", u, StringComparison.Ordinal);
        Assert.Contains("/keys/mycert/versions/", u, StringComparison.Ordinal);
        Assert.Equal("https://contoso.vault.azure.net/keys/k/versions/v/sign?api-version=7.4", AzureKeyVaultClient.SignUrlFromKid("https://contoso.vault.azure.net/keys/k/versions/v/"));
    }

    [Fact]
    public void SignUrlFromKidRejectsInvalidUrl() => Assert.Throws<PsignException>(() => AzureKeyVaultClient.SignUrlFromKid("not-a-url"));

    [Fact]
    public void CertificateUrlEncodesSegmentsAndVersion()
    {
        Assert.Equal(
            "https://kv-test.vault.azure.net:8443/certificates/my%20cert/v2?api-version=7.4",
            AzureKeyVaultClient.CertificateUrl("https://kv-test.vault.azure.net:8443/", " my cert ", " v2 "));
        Assert.Equal(
            "https://ex.vault.azure.net/certificates/c?api-version=7.4",
            AzureKeyVaultClient.CertificateUrl("https://ex.vault.azure.net", "c", "  "));
    }

    [Fact]
    public void KeyVaultSignatureValueUsesBase64UrlWithoutPadding()
    {
        byte[] raw = [0xff, 0xee, 0xdd, 0xcc, 0xbb];
        var encoded = AzureKeyVaultClient.Base64UrlEncode(raw);
        Assert.Equal("_-7dzLs", encoded);
        Assert.Equal(raw, AzureKeyVaultClient.Base64UrlDecode(encoded));
        Assert.Throws<PsignException>(() => AzureKeyVaultClient.Base64UrlDecode("_-7dzLs="));
    }

    [Fact]
    public void PublicKeyKindFromCertificates()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        Assert.Equal(KvPublicKeyKind.Rsa, AzureKeyVaultClient.PublicKeyKindFromCerDer(signer.Certificate.RawData));
        Assert.Equal(KvPublicKeyKind.Ec, AzureKeyVaultClient.PublicKeyKindFromCerDer(EcLeafDer()));
        Assert.StartsWith("certificate DER (public key):", Assert.Throws<PsignException>(() => AzureKeyVaultClient.PublicKeyKindFromCerDer([1, 2, 3])).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ClientCredentialsAndManagedIdentityTokens()
    {
        var mock = new MockHttpHandler();
        var cc = mock.Map("POST", @"^https://login\.microsoftonline\.com/tenant/oauth2/v2\.0/token$").Respond(200, """{"access_token":"kv-token"}""");
        var mi = mock.Map("GET", @"^http://imds\.test/token\?api-version=2018-02-01&resource=https%3A%2F%2Fvault\.azure\.net$")
            .MatchHeader("Metadata", "true")
            .Respond(200, """{"access_token":"mi-token"}""");
        using var client = new AzureKeyVaultClient(mock) { ImdsEndpoint = "http://imds.test/token" };

        Assert.Equal("kv-token", client.AcquireAccessToken(new KvAuthParams { TenantId = "tenant", ClientId = "client", ClientSecret = "secret" }));
        Assert.Equal(
            "client_id=client&client_secret=secret&scope=https%3A%2F%2Fvault.azure.net%2F.default&grant_type=client_credentials",
            mock.Requests[0].BodyText);
        Assert.Equal("mi-token", client.AcquireAccessToken(new KvAuthParams { ManagedIdentity = true }));
        Assert.Equal(" tok ".Trim(), client.AcquireAccessToken(new KvAuthParams { AccessToken = " tok ", ManagedIdentity = true }));
        Assert.Equal(1, cc.Hits);
        Assert.Equal(1, mi.Hits);

        Assert.Equal("access token must not be empty", Assert.Throws<PsignException>(() => client.AcquireAccessToken(new KvAuthParams { AccessToken = " " })).Message);
        Assert.Equal("client credentials require tenant id", Assert.Throws<PsignException>(() => client.AcquireAccessToken(new KvAuthParams())).Message);
        Assert.Equal("client credentials require client secret", Assert.Throws<PsignException>(() => client.AcquireAccessToken(new KvAuthParams { TenantId = "t", ClientId = "c", ClientSecret = "  " })).Message);
    }

    [Fact]
    public void HttpErrorsIncludeStatusAndBody()
    {
        var mock = new MockHttpHandler();
        mock.Map("GET", "/certificates/missing").Respond(404, """{"error":{"code":"CertificateNotFound"}}""");
        mock.Map("POST", "/sign").Respond(403, "forbidden");
        using var client = new AzureKeyVaultClient(mock);

        Assert.Equal(
            "Key Vault certificate HTTP 404 Not Found: {\"error\":{\"code\":\"CertificateNotFound\"}}",
            Assert.Throws<PsignException>(() => client.FetchCertificate(VaultBase, "missing", null, "t")).Message);
        Assert.Equal(
            "Key Vault sign HTTP 403 Forbidden: forbidden",
            Assert.Throws<PsignException>(() => client.SignDigest("t", VaultBase + "/keys/k/v/sign?api-version=7.4", "RS256", [1])).Message);
    }

    [Fact]
    public void DigestSignerUsesCertificateKeyKind()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var mock = new MockHttpHandler();
        mock.Map("GET", "/certificates/rsa").Respond(200, SerdeJson.Compact(new JsonObject
        {
            ["kid"] = VaultBase + "/keys/rsa/versions/1",
            ["cer"] = Convert.ToBase64String(signer.Certificate.RawData),
        }));
        mock.Map("POST", "/keys/rsa/versions/1/sign").Respond(200, """{"value":"AQID"}""");
        using var client = new AzureKeyVaultClient(mock);

        var kvSigner = AzureKeyVaultDigestSigner.Create(client, VaultBase + "/", "rsa", null, new KvAuthParams { AccessToken = "tok" });
        Assert.Equal(signer.Certificate.RawData, kvSigner.Certificate.RawData);
        Assert.Equal(new byte[] { 1, 2, 3 }, kvSigner.SignDigest(new byte[64], AuthenticodeHashKind.Sha512));
        Assert.Contains("\"alg\":\"RS512\"", mock.Requests[1].BodyText, StringComparison.Ordinal);
        Assert.Throws<PsignException>(() => kvSigner.SignDigest(new byte[20], AuthenticodeHashKind.Sha1));
    }
}
