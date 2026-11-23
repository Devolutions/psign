using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.Internal;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// Port of <c>crates/psign-codesigning-rest/tests/codesign_rest_mock.rs</c> and the unit tests in
/// <c>crates/psign-codesigning-rest/src/lib.rs</c> (mockito replaced by <see cref="MockHttpHandler"/>).
/// </summary>
public class ArtifactSigningTests
{
    private const string Base = "http://mock.codesigning.test";

    private static CodesigningSubmitParams Params(string account, string profile, byte[] digest, string alg = "RS256", string? correlationId = null, string api = "2023-06-15-preview") => new()
    {
        Region = "unused-for-mock",
        AccountName = account,
        ProfileName = profile,
        Digest = digest,
        SignatureAlgorithm = alg,
        ApiVersion = api,
        CorrelationId = correlationId,
        Auth = new CodesigningAuth.Bearer("tok"),
        EndpointBaseUrl = Base,
    };

    private static ArtifactSigningClient Client(MockHttpHandler handler) => new(handler, _ => null) { PollInterval = TimeSpan.Zero };

    [Fact]
    public void SubmitPollViaOperationLocationHeader()
    {
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/theacct/certificateprofiles/theprof:sign(\?.*)?$")
            .MatchHeader("Authorization", "Bearer fake-token")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/abc123"));
        var poll = mock.Map("GET", @"/operations/abc123(\?.*)?$")
            .Respond(200, """{"status":"Succeeded","signature":"mock-sig-field"}""", ("Content-Type", "application/json"));

        var p = Params("theacct", "theprof", [1, 2, 3]);
        p.Auth = new CodesigningAuth.Bearer("fake-token");
        using var client = Client(mock);
        var outJson = client.SubmitCodesignHash(p)!;

        Assert.Equal("Succeeded", outJson["status"]!.GetValue<string>());
        Assert.Equal("mock-sig-field", outJson["signature"]!.GetValue<string>());
        Assert.Equal(1, post.Hits);
        Assert.Equal(1, poll.Hits);
    }

    [Fact]
    public void SubmitPollViaAcceptBodyIdField()
    {
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/acct/certificateprofiles/prof:sign(\?.*)?$")
            .Respond(200, """{"id":"job-from-body"}""", ("Content-Type", "application/json"));
        var poll = mock.Map("GET", @"/codesigningaccounts/acct/certificateprofiles/prof/sign/job-from-body(\?.*)?$")
            .Respond(200, """{"status":"Succeeded","done":true}""", ("Content-Type", "application/json"));

        using var client = Client(mock);
        var debug = new List<string>();
        var outJson = client.SubmitCodesignHash(Params("acct", "prof", [0xff]), debug.Add)!;

        Assert.Equal("Succeeded", outJson["status"]!.GetValue<string>());
        Assert.True(outJson["done"]!.GetValue<bool>());
        Assert.Equal(1, post.Hits);
        Assert.Equal(1, poll.Hits);
        Assert.Equal(
            "artifact-signing poll URL=" + Base + "/codesigningaccounts/acct/certificateprofiles/prof/sign/job-from-body?api-version=2023-06-15-preview",
            Assert.Single(debug));
    }

    [Fact]
    public void SubmitSignPostBodyBase64DigestAndSignatureAlgorithm()
    {
        var digest = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var b64 = Convert.ToBase64String(digest);
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/acct2/certificateprofiles/prof2:sign(\?.*)?$")
            .MatchBody(b =>
            {
                var j = JsonNode.Parse(b)!;
                return j["signatureAlgorithm"]!.GetValue<string>() == "ES256" && j["digest"]!.GetValue<string>() == b64;
            })
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/body-check"));
        var poll = mock.Map("GET", @"/operations/body-check(\?.*)?$").Respond(200, """{"status":"Succeeded"}""");

        using var client = Client(mock);
        client.SubmitCodesignHash(Params("acct2", "prof2", digest, "ES256"));

        Assert.Equal(1, post.Hits);
        Assert.Equal(1, poll.Hits);

        // serde_json::json! serializes a BTreeMap: keys sorted, compact.
        var request = mock.Requests[0];
        Assert.Equal("{\"digest\":\"" + b64 + "\",\"signatureAlgorithm\":\"ES256\"}", request.BodyText);
        Assert.StartsWith("application/json", request.Headers["Content-Type"], StringComparison.Ordinal);
        Assert.Equal(Base + "/codesigningaccounts/acct2/certificateprofiles/prof2:sign?api-version=2023-06-15-preview", request.Uri.AbsoluteUri);
    }

    [Fact]
    public void SubmitSignSendsXMsCorrelationIdWhenSet()
    {
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/c/certificateprofiles/p:sign(\?.*)?$")
            .MatchHeader("x-ms-correlation-id", "trace-abc-123")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/corr"));
        var poll = mock.Map("GET", @"/operations/corr(\?.*)?$").Respond(200, """{"status":"Succeeded"}""");

        using var client = Client(mock);
        client.SubmitCodesignHash(Params("c", "p", [1, 2, 3], correlationId: "  trace-abc-123  "));
        Assert.Equal(1, post.Hits);
        Assert.Equal(1, poll.Hits);
    }

    [Fact]
    public void SubmitSignSendsStableXCorrelationIdWhenSet()
    {
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/c/certificateprofiles/p:sign(\?.*)?$")
            .MatchHeader("x-correlation-id", "trace-stable")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/corr-stable"));
        var poll = mock.Map("GET", @"/operations/corr-stable(\?.*)?$").Respond(200, """{"status":"Succeeded"}""");

        using var client = Client(mock);
        client.SubmitCodesignHash(Params("c", "p", [1, 2, 3], correlationId: "trace-stable", api: ArtifactSigningClient.DefaultApiVersion));
        Assert.Equal(1, post.Hits);
        Assert.Equal(1, poll.Hits);
        Assert.Contains("api-version=2024-06-15", mock.Requests[0].Uri.Query, StringComparison.Ordinal);
    }

    [Fact]
    public void TypedSignatureResultAcceptsStableResultWrapper()
    {
        var sig = Enumerable.Repeat((byte)0xab, 256).ToArray();
        byte[] cert = [0x30, 0x82, 0x01, 0x23];
        var json = new JsonObject
        {
            ["status"] = "Succeeded",
            ["result"] = new JsonObject
            {
                ["signature"] = Convert.ToBase64String(sig),
                ["signingCertificate"] = Convert.ToBase64String(cert),
            },
        };
        var parsed = ArtifactSigningClient.SignatureResultFromJson(json);
        Assert.Equal(sig, parsed.Signature);
        Assert.Equal(cert, parsed.SigningCertificate);
    }

    [Fact]
    public void TypedSignatureResultAcceptsLegacyTopLevelFields()
    {
        var sig = Enumerable.Repeat((byte)0xcd, 256).ToArray();
        byte[] cert = [0x30, 0x82, 0x02, 0x34];
        var json = new JsonObject
        {
            ["status"] = "Succeeded",
            ["signature"] = Convert.ToBase64String(sig),
            ["signingCertificate"] = Convert.ToBase64String(cert),
        };
        var parsed = ArtifactSigningClient.SignatureResultFromJson(json);
        Assert.Equal(sig, parsed.Signature);
        Assert.Equal(cert, parsed.SigningCertificate);
    }

    [Fact]
    public void TypedSignatureResultReportsMissingField()
    {
        var e = Assert.Throws<PsignException>(() => ArtifactSigningClient.SignatureResultFromJson(new JsonObject { ["status"] = "Succeeded" }));
        Assert.Equal("codesign result missing signature", e.Message);
    }

    [Fact]
    public void SubmitPollFailedStatusReturnsError()
    {
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/f/certificateprofiles/g:sign(\?.*)?$")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/fail1"));
        var poll = mock.Map("GET", @"/operations/fail1(\?.*)?$").Respond(200, """{"status":"Failed","error":{"code":"bad"}}""");

        using var client = Client(mock);
        var e = Assert.Throws<PsignException>(() => client.SubmitCodesignHash(Params("f", "g", [9])));
        Assert.Equal("codesign operation failed: {\"error\":{\"code\":\"bad\"},\"status\":\"Failed\"}", e.Message);
        Assert.Equal(1, post.Hits);
        Assert.Equal(1, poll.Hits);
    }

    [Fact]
    public void SubmitSignPostTrimsSignatureAlgorithmInJsonBody()
    {
        var digest = Enumerable.Repeat((byte)0xab, 32).ToArray();
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/trim/certificateprofiles/alg:sign(\?.*)?$")
            .MatchBody(b => JsonNode.Parse(b)!["signatureAlgorithm"]!.GetValue<string>() == "RS256")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/trim-alg"));
        var poll = mock.Map("GET", @"/operations/trim-alg(\?.*)?$").Respond(200, """{"status":"Succeeded"}""");

        using var client = Client(mock);
        client.SubmitCodesignHash(Params("trim", "alg", digest, "  RS256  \t"));
        Assert.Equal(1, post.Hits);
        Assert.Equal(1, poll.Hits);
    }

    [Fact]
    public void SubmitPollCanceledStatusReturnsError()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", @"/codesigningaccounts/can/certificateprofiles/celed:sign(\?.*)?$")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/canceled-op"));
        var poll = mock.Map("GET", @"/operations/canceled-op(\?.*)?$").Respond(200, """{"status":"Canceled"}""");

        using var client = Client(mock);
        var e = Assert.Throws<PsignException>(() => client.SubmitCodesignHash(Params("can", "celed", [8])));
        Assert.Contains("codesign operation canceled", e.Message, StringComparison.Ordinal);
        Assert.Equal(1, poll.Hits);
    }

    [Fact]
    public void SubmitSignNonSuccessHttpIncludesStatusAndBody()
    {
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/bad/certificateprofiles/http:sign(\?.*)?$")
            .Respond(403, """{"error":"nope"}""", ("Content-Type", "application/json"));

        using var client = Client(mock);
        var e = Assert.Throws<PsignException>(() => client.SubmitCodesignHash(Params("bad", "http", [1])));
        Assert.Equal(":sign HTTP 403 Forbidden: {\"error\":\"nope\"}", e.Message);
        Assert.Equal(1, post.Hits);
    }

    [Fact]
    public void SubmitSignSuccessWithoutLroReturnsPostBody()
    {
        var mock = new MockHttpHandler();
        var post = mock.Map("POST", @"/codesigningaccounts/sync/certificateprofiles/now:sign(\?.*)?$")
            .Respond(200, """{"status":"Succeeded","inline":true}""");

        using var client = Client(mock);
        var outJson = client.SubmitCodesignHash(Params("sync", "now", [2]))!;
        Assert.Equal("Succeeded", outJson["status"]!.GetValue<string>());
        Assert.True(outJson["inline"]!.GetValue<bool>());
        Assert.Equal(1, post.Hits);
        Assert.Single(mock.Requests);
    }

    [Fact]
    public void SubmitPollNonSuccessHttpReturnsError()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", @"/codesigningaccounts/poll/certificateprofiles/http500:sign(\?.*)?$")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/poll-503"));
        var poll = mock.Map("GET", @"/operations/poll-503(\?.*)?$").Respond(503, "upstream unavailable");

        using var client = Client(mock);
        var e = Assert.Throws<PsignException>(() => client.SubmitCodesignHash(Params("poll", "http500", [3])));
        Assert.Equal("poll HTTP 503 Service Unavailable: upstream unavailable", e.Message);
        Assert.Equal(1, poll.Hits);
    }

    [Fact]
    public void SubmitPollNonJsonSuccessBodyReturnsError()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", @"/codesigningaccounts/plain/certificateprofiles/badjson:sign(\?.*)?$")
            .Respond(202, "{}", ("Operation-Location", Base + "/operations/poll-plain"));
        var poll = mock.Map("GET", @"/operations/poll-plain(\?.*)?$").Respond(200, "not-json", ("Content-Type", "text/plain"));

        using var client = Client(mock);
        var e = Assert.Throws<PsignException>(() => client.SubmitCodesignHash(Params("plain", "badjson", [4])));
        Assert.Equal("poll JSON", e.Message);
        Assert.Equal(1, poll.Hits);
    }

    [Fact]
    public void PollKeepsPollingUntilTerminalStatus()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", @":sign").Respond(202, "{}", ("Operation-Location", "/operations/slow"));
        var calls = 0;
        var inProgress = mock.Map("GET", @"/operations/slow").MatchBody(_ => ++calls < 3).Respond(200, """{"status":"InProgress"}""");
        var done = mock.Map("GET", @"/operations/slow").Respond(200, """{"status":"Succeeded","n":3}""");

        using var client = Client(mock);
        var outJson = client.SubmitCodesignHash(Params("a", "p", [1]))!;
        Assert.Equal(3, outJson["n"]!.GetValue<int>());
        Assert.Equal(2, inProgress.Hits);
        Assert.Equal(1, done.Hits);
        Assert.Equal(Base + "/operations/slow", mock.Requests[1].Uri.AbsoluteUri);
    }

    [Fact]
    public void PollTimesOutAfterMaxAttempts()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", @":sign").Respond(202, "{}", ("Operation-Location", Base + "/operations/forever"));
        mock.Map("GET", @"/operations/forever").Respond(200, """{"status":"Running"}""");

        using var client = Client(mock);
        client.MaxPollAttempts = 3;
        var e = Assert.Throws<PsignException>(() => client.SubmitCodesignHash(Params("a", "p", [1])));
        Assert.Equal("codesign operation timed out polling " + Base + "/operations/forever", e.Message);
    }

    // ---------------------------------------------------------------- lib.rs unit tests

    private static CodesigningProfileParams ProfileParams(string endpoint) => new()
    {
        AccountName = "the account",
        ProfileName = "the/profile",
        ApiVersion = ArtifactSigningClient.DefaultProfileRootApiVersion,
        Auth = new CodesigningAuth.Bearer("fake-token"),
        EndpointBaseUrl = endpoint,
    };

    [Theory]
    [InlineData("https://wus.codesigning.azure.net")]
    [InlineData("https://wus.artifactsigning.azure.net/")]
    public void ProfileRootUrlAcceptsSupportedAzureOriginsAndEncodesNames(string endpoint)
    {
        var url = ArtifactSigningClient.ProfileRootCertificateUrl(ProfileParams(endpoint));
        Assert.Equal(
            endpoint.TrimEnd('/') + "/codesigningaccounts/the%20account/certificateprofiles/the%2Fprofile/sign/rootcert?api-version=2022-06-15-preview",
            url);
    }

    [Theory]
    [InlineData("http://wus.codesigning.azure.net")]
    [InlineData("https://example.com")]
    [InlineData("https://codesigning.azure.net")]
    [InlineData("https://user@wus.codesigning.azure.net")]
    [InlineData("https://wus.codesigning.azure.net:444")]
    [InlineData("https://wus.codesigning.azure.net/path")]
    [InlineData("https://wus.codesigning.azure.net?query=value")]
    [InlineData("https://wus.codesigning.azure.net#fragment")]
    public void ProfileRootUrlRejectsUntrustedOrNonOriginEndpoints(string endpoint)
    {
        Assert.Throws<PsignException>(() => ArtifactSigningClient.ProfileRootCertificateUrl(ProfileParams(endpoint)));
    }

    [Fact]
    public void EndpointIsValidatedBeforeCredentialsAreAcquired()
    {
        var p = ProfileParams("http://example.com");
        p.Auth = new CodesigningAuth.Bearer(" ");
        using var client = new ArtifactSigningClient(new MockHttpHandler(), _ => null);
        var e = Assert.Throws<PsignException>(() => client.GetRootCertificate(p));
        Assert.Contains("must use HTTPS", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FetchesAndValidatesProfileRootCertificate()
    {
        var root = Fixtures.Bytes("devolutions-authenticode/authenticode-test-ca.crt");
        var mock = new MockHttpHandler();
        var route = mock.Map("GET", @"^https://wus\.codesigning\.azure\.net/codesigningaccounts/theacct/certificateprofiles/theprof/sign/rootcert\?api-version=2022-06-15-preview$")
            .MatchHeader("Authorization", "Bearer fake-token")
            .MatchHeader("Accept", "application/x-x509-ca-cert")
            .Respond(200, root, ("Content-Type", "application/x-x509-ca-cert"));
        using var client = new ArtifactSigningClient(mock, _ => null);
        var p = ProfileParams("https://wus.codesigning.azure.net");
        p.AccountName = "theacct";
        p.ProfileName = "theprof";

        Assert.Equal(root, client.GetRootCertificate(p));
        Assert.Equal(1, route.Hits);
    }

    [Fact]
    public void RootCertificateResponseRejectsJsonAndInvalidDer()
    {
        var jsonError = Assert.Throws<PsignException>(() =>
            ArtifactSigningClient.ValidateRootCertificateResponse("application/json; charset=utf-8", Encoding.UTF8.GetBytes("""{"error":"not a certificate"}""")));
        Assert.Contains("unexpected", jsonError.Message, StringComparison.Ordinal);

        var derError = Assert.Throws<PsignException>(() =>
            ArtifactSigningClient.ValidateRootCertificateResponse("application/x-x509-ca-cert", Encoding.ASCII.GetBytes("not DER")));
        Assert.Contains("certificate DER", derError.Message, StringComparison.Ordinal);

        var emptyError = Assert.Throws<PsignException>(() => ArtifactSigningClient.ValidateRootCertificateResponse(null, []));
        Assert.Contains("empty", emptyError.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RootCertificateResponseAcceptsCaseInsensitiveMediaType()
    {
        ArtifactSigningClient.ValidateRootCertificateResponse(
            "Application/X-X509-CA-Cert; charset=binary",
            Fixtures.Bytes("devolutions-authenticode/authenticode-test-ca.crt"));
    }

    [Fact]
    public void RootCertificateResponseRejectsNonCaCertificate()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var e = Assert.Throws<PsignException>(() => ArtifactSigningClient.ValidateRootCertificateResponse("application/x-x509-ca-cert", signer.Certificate.RawData));
        Assert.Contains("not a CA", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResponseBodyReaderEnforcesTheByteLimit()
    {
        Assert.Equal("1234"u8.ToArray(), await HttpTransport.ReadBoundedAsync(new MemoryStream("1234"u8.ToArray()), 4, default));
        var e = await Assert.ThrowsAsync<PsignException>(() => HttpTransport.ReadBoundedAsync(new MemoryStream("12345"u8.ToArray()), 4, default));
        Assert.Contains("exceeds 4 bytes", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ProfileRootHttpErrorIncludesStatusAndBody()
    {
        var mock = new MockHttpHandler();
        var route = mock.Map("GET", "/rootcert").Respond(403, """{"error":"forbidden"}""", ("Content-Type", "application/json"));
        using var client = new ArtifactSigningClient(mock, _ => null);
        var p = ProfileParams("https://wus.codesigning.azure.net");

        var e = Assert.Throws<PsignException>(() => client.GetRootCertificate(p));
        var message = e.FullMessage;
        Assert.Contains("403", message, StringComparison.Ordinal);
        Assert.Contains("forbidden", message, StringComparison.Ordinal);
        Assert.Equal(1, route.Hits);
    }

    [Fact]
    public void ProfileRootOversizedResponseIsRejected()
    {
        var mock = new MockHttpHandler();
        mock.Map("GET", "/rootcert").Respond(500, new byte[(64 * 1024) + 1]);
        using var client = new ArtifactSigningClient(mock, _ => null);
        var e = Assert.Throws<PsignException>(() => client.GetRootCertificate(ProfileParams("https://wus.codesigning.azure.net")));
        Assert.Equal("read Artifact Signing root certificate HTTP 500 Internal Server Error response: Artifact Signing root certificate response exceeds 65536 bytes", e.FullMessage);
    }

    [Fact]
    public void BearerEmptyRejected()
    {
        using var client = new ArtifactSigningClient(new MockHttpHandler(), _ => null);
        var e = Assert.Throws<PsignException>(() => client.AcquireToken(new CodesigningAuth.Bearer("  ")));
        Assert.Equal("access token must not be empty", e.Message);
    }

    [Fact]
    public void DataPlaneBaseUrlDefaultFromRegion()
    {
        var p = new CodesigningSubmitParams { Region = "westus2" };
        Assert.Equal("https://westus2.codesigning.azure.net", ArtifactSigningClient.DataPlaneBaseUrl(p));
    }

    [Fact]
    public void DataPlaneBaseUrlOverrideTrimsSlash()
    {
        var p = new CodesigningSubmitParams { Region = "ignored", EndpointBaseUrl = "https://mock.codesigning.test/" };
        Assert.Equal("https://mock.codesigning.test", ArtifactSigningClient.DataPlaneBaseUrl(p));
    }

    [Fact]
    public void DataPlaneBaseUrlOverrideEmptyFallsBackToRegion()
    {
        var p = new CodesigningSubmitParams { Region = "eastus", EndpointBaseUrl = "   " };
        Assert.Equal("https://eastus.codesigning.azure.net", ArtifactSigningClient.DataPlaneBaseUrl(p));
    }

    [Fact]
    public void SubmitRejectsEmptyDigest()
    {
        using var client = new ArtifactSigningClient(new MockHttpHandler(), _ => null);
        var e = Assert.Throws<PsignException>(() => client.SubmitCodesignHash(new CodesigningSubmitParams { Region = "westus2", Auth = new CodesigningAuth.Bearer("tok") }));
        Assert.Contains("digest is empty", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolverAcceptsUserAssignedManagedIdentity()
    {
        const string resourceId = "/subscriptions/s/resourceGroups/g/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id";
        var auth = CodesigningAuthResolver.Resolve(new CodesigningAuthInput { ManagedIdentity = true, ClientId = "client-id", ManagedIdentityResourceId = resourceId });
        Assert.Equal(new CodesigningAuth.ManagedIdentity("client-id", resourceId), auth);
    }

    [Fact]
    public void ResolverAcceptsWorkloadIdentityInputs()
    {
        var auth = CodesigningAuthResolver.Resolve(new CodesigningAuthInput
        {
            TenantId = "tenant",
            ClientId = "client",
            FederatedTokenFile = "token.jwt",
            CredentialType = CodesigningCredentialType.WorkloadIdentity,
        });
        Assert.Equal(new CodesigningAuth.WorkloadIdentity("tenant", "client", "token.jwt"), auth);
    }

    [Fact]
    public void ResolverWorkloadIdentityFallsBackToEnvironment()
    {
        var env = new Dictionary<string, string> { ["AZURE_TENANT_ID"] = "t", ["AZURE_CLIENT_ID"] = "c", ["AZURE_FEDERATED_TOKEN_FILE"] = "f" };
        var auth = CodesigningAuthResolver.Resolve(new CodesigningAuthInput { CredentialType = CodesigningCredentialType.WorkloadIdentity }, n => env.GetValueOrDefault(n));
        Assert.Equal(new CodesigningAuth.WorkloadIdentity("t", "c", "f"), auth);
    }

    [Fact]
    public void ResolverKeepsMetadataExcludesOnDefaultChain()
    {
        var auth = CodesigningAuthResolver.Resolve(new CodesigningAuthInput { ExcludeCredentials = ["EnvironmentCredential", "ManagedIdentityCredential"] });
        var chain = Assert.IsType<CodesigningAuth.DefaultChain>(auth);
        Assert.Equal(["EnvironmentCredential", "ManagedIdentityCredential"], chain.ExcludeCredentials);
    }

    [Fact]
    public void ResolverRejectsMixedExplicitCredentials()
    {
        var e = Assert.Throws<PsignException>(() => CodesigningAuthResolver.Resolve(new CodesigningAuthInput
        {
            AccessToken = "token",
            TenantId = "tenant",
            ClientId = "client",
            ClientSecret = "secret",
        }));
        Assert.Contains("not multiple", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ResolverRejectsPartialClientCredentials()
    {
        var e = Assert.Throws<PsignException>(() => CodesigningAuthResolver.Resolve(new CodesigningAuthInput { TenantId = "t", ClientId = "c" }));
        Assert.Equal("Artifact Signing client credentials require all of tenant-id, client-id, and client-secret", e.Message);
        Assert.Equal(new CodesigningAuth.ClientCredentials("t", "c", "s"), CodesigningAuthResolver.Resolve(new CodesigningAuthInput { TenantId = "t", ClientId = "c", ClientSecret = " s " }));
    }

    [Fact]
    public void CredentialExclusionIgnoresCaseAndSeparators()
    {
        Assert.True(CodesigningAuthResolver.CredentialExcluded(["managed-identity_credential"], "ManagedIdentityCredential"));
        Assert.False(CodesigningAuthResolver.CredentialExcluded(["Environment"], "EnvironmentCredential"));
    }

    // ---------------------------------------------------------------- tokens

    [Fact]
    public void ClientCredentialsTokenIsRequestedWithFormBody()
    {
        var mock = new MockHttpHandler();
        var token = mock.Map("POST", @"^https://login\.example\.test/tenant1/oauth2/v2\.0/token$").Respond(200, """{"access_token":"cc-token","expires_in":3600}""");
        var post = mock.Map("POST", ":sign").MatchHeader("Authorization", "Bearer cc-token").Respond(200, """{"status":"Succeeded"}""");
        using var client = Client(mock);
        var p = Params("a", "p", [1]);
        p.Auth = new CodesigningAuth.ClientCredentials("tenant1", "client1", "s3cret");
        p.Authority = "https://login.example.test/";

        client.SubmitCodesignHash(p);
        Assert.Equal(1, token.Hits);
        Assert.Equal(1, post.Hits);
        Assert.Equal(
            "client_id=client1&client_secret=s3cret&grant_type=client_credentials&scope=https%3A%2F%2Fcodesigning.azure.net%2F.default",
            mock.Requests[0].BodyText);
        Assert.Equal("application/x-www-form-urlencoded", mock.Requests[0].Headers["Content-Type"]);
    }

    [Fact]
    public void ManagedIdentityTokenUsesImdsEndpointOverride()
    {
        var mock = new MockHttpHandler();
        var imds = mock.Map("GET", @"^http://imds\.test/token\?api-version=2018-02-01&resource=https%3A%2F%2Fcodesigning\.azure\.net&client_id=cid&mi_res_id=%2Fsub%2Fid$")
            .MatchHeader("Metadata", "true")
            .Respond(200, """{"access_token":"mi-token"}""");
        var env = new Dictionary<string, string> { ["PSIGN_CODESIGNING_IMDS_ENDPOINT"] = "http://imds.test/token" };
        using var client = new ArtifactSigningClient(mock, n => env.GetValueOrDefault(n));
        Assert.Equal("mi-token", client.AcquireToken(new CodesigningAuth.ManagedIdentity("cid", "/sub/id")));
        Assert.Equal(1, imds.Hits);
    }

    [Fact]
    public void WorkloadIdentityTokenPostsClientAssertion()
    {
        using var dir = new TempDir();
        File.WriteAllText(dir.File("token.jwt"), "  header.payload.sig \n");
        var mock = new MockHttpHandler();
        var token = mock.Map("POST", "/tenant/oauth2/v2.0/token").Respond(200, """{"access_token":"wi-token"}""");
        using var client = Client(mock);

        Assert.Equal("wi-token", client.AcquireToken(new CodesigningAuth.WorkloadIdentity("tenant", "client", dir.File("token.jwt"))));
        Assert.Equal(
            "client_id=client&client_assertion=header.payload.sig&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&grant_type=client_credentials&scope=https%3A%2F%2Fcodesigning.azure.net%2F.default",
            mock.Requests[0].BodyText);
        Assert.StartsWith("https://login.microsoftonline.com/tenant/", mock.Requests[0].Uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public void TokenHttpErrorAndMissingField()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", "/bad/oauth2").Respond(401, "denied");
        mock.Map("POST", "/nofield/oauth2").Respond(200, """{"token":"x"}""");
        using var client = Client(mock);

        var e1 = Assert.Throws<PsignException>(() => client.AcquireToken(new CodesigningAuth.ClientCredentials("bad", "c", "s")));
        Assert.Equal("OAuth HTTP 401 Unauthorized: denied", e1.Message);
        var e2 = Assert.Throws<PsignException>(() => client.AcquireToken(new CodesigningAuth.ClientCredentials("nofield", "c", "s")));
        Assert.Equal("OAuth JSON: missing field `access_token`", e2.FullMessage);
    }

    [Fact]
    public void DefaultChainUsesEnvironmentThenReportsFailures()
    {
        var mock = new MockHttpHandler();
        mock.Map("POST", "/envtenant/oauth2/v2.0/token").Respond(200, """{"access_token":"env-token"}""");
        var env = new Dictionary<string, string> { ["AZURE_TENANT_ID"] = "envtenant", ["AZURE_CLIENT_ID"] = "c", ["AZURE_CLIENT_SECRET"] = "s" };
        using (var client = new ArtifactSigningClient(mock, n => env.GetValueOrDefault(n)))
        {
            Assert.Equal("env-token", client.AcquireToken(new CodesigningAuth.DefaultChain([])));
        }

        using (var client = new ArtifactSigningClient(mock, n => env.GetValueOrDefault(n)))
        {
            var e = Assert.Throws<PsignException>(() => client.AcquireToken(new CodesigningAuth.DefaultChain(["EnvironmentCredential", "ManagedIdentityCredential"])));
            Assert.Equal("no Artifact Signing credential was available in the Rust default chain", e.Message);
        }

        var failing = new MockHttpHandler();
        failing.Map("POST", "/oauth2").Respond(500, "boom");
        failing.Map("GET", "imds").Respond(400, "no identity");
        env["PSIGN_CODESIGNING_IMDS_ENDPOINT"] = "http://imds.test/token";
        using (var client = new ArtifactSigningClient(failing, n => env.GetValueOrDefault(n)))
        {
            var e = Assert.Throws<PsignException>(() => client.AcquireToken(new CodesigningAuth.DefaultChain([])));
            Assert.Equal(
                "Artifact Signing Rust default credential chain failed: EnvironmentCredential: OAuth HTTP 500 Internal Server Error: boom; ManagedIdentityCredential: managed identity token HTTP 400 Bad Request: no identity",
                e.Message);
        }
    }

    // ---------------------------------------------------------------- metadata / options / adapter

    [Fact]
    public void MetadataParsingAndCheck()
    {
        var doc = ArtifactSigningMetadata.Check(Encoding.UTF8.GetBytes(
            """{"Endpoint":"https://wus.codesigning.azure.net","CodeSigningAccountName":"acct","CertificateProfileName":"prof","ExcludeCredentials":["ManagedIdentityCredential"],"Extra":1}"""));
        Assert.Equal("acct", doc.CodeSigningAccountName);
        Assert.Equal(["ManagedIdentityCredential"], doc.ExcludeCredentials!);
        Assert.Null(doc.CorrelationId);

        Assert.Equal("metadata JSON is empty", Assert.Throws<PsignException>(() => ArtifactSigningMetadata.Check([])).Message);
        Assert.Equal(
            "parse Artifact Signing metadata JSON: missing field `CertificateProfileName`",
            Assert.Throws<PsignException>(() => ArtifactSigningMetadata.Check(Encoding.UTF8.GetBytes("""{"Endpoint":"e","CodeSigningAccountName":"a"}"""))).FullMessage);
        Assert.Equal(
            "Endpoint must be a non-empty string",
            Assert.Throws<PsignException>(() => ArtifactSigningMetadata.Check(Encoding.UTF8.GetBytes("""{"Endpoint":" ","CodeSigningAccountName":"a","CertificateProfileName":"p"}"""))).Message);
        Assert.Equal(
            "ExcludeCredentials[1] must be a non-empty string",
            Assert.Throws<PsignException>(() => ArtifactSigningMetadata.Check(Encoding.UTF8.GetBytes("""{"Endpoint":"e","CodeSigningAccountName":"a","CertificateProfileName":"p","ExcludeCredentials":["x",""]}"""))).Message);
    }

    [Fact]
    public void OptionsMergeMetadataAndExplicitValues()
    {
        using var dir = new TempDir();
        File.WriteAllText(dir.File("metadata.json"), """{"Endpoint":"https://eus.codesigning.azure.net","CodeSigningAccountName":"meta-acct","CertificateProfileName":"meta-prof","CorrelationId":"corr","ExcludeCredentials":["EnvironmentCredential"]}""");
        var options = new ArtifactSigningOptions { Metadata = dir.File("metadata.json"), ProfileName = "cli-prof" };
        Assert.True(options.IsRequested);
        var p = options.ToSubmitParams([1, 2], "RS384", _ => null);
        Assert.Equal("meta-acct", p.AccountName);
        Assert.Equal("cli-prof", p.ProfileName);
        Assert.Equal("https://eus.codesigning.azure.net", p.EndpointBaseUrl);
        Assert.Equal("unused", p.Region);
        Assert.Equal("RS384", p.SignatureAlgorithm);
        Assert.Equal(ArtifactSigningClient.DefaultApiVersion, p.ApiVersion);
        Assert.Equal("corr", p.CorrelationId);
        Assert.Equal(new CodesigningAuth.DefaultChain(["EnvironmentCredential"]), p.Auth);

        Assert.False(new ArtifactSigningOptions().IsRequested);
        var e = Assert.Throws<PsignException>(() => new ArtifactSigningOptions { ProfileName = "p" }.ToSubmitParams([1], "RS256", _ => null));
        Assert.Equal("Artifact Signing requires --artifact-signing-account-name or metadata CodeSigningAccountName", e.Message);
    }

    [Fact]
    public void DigestSignerSubmitsDigestAndCapturesCertificate()
    {
        var sig = Enumerable.Repeat((byte)0x5a, 256).ToArray();
        byte[] cert = [0x30, 0x03, 0x02, 0x01, 0x01];
        var mock = new MockHttpHandler();
        mock.Map("POST", ":sign").Respond(200, RustJson.Compact(new JsonObject
        {
            ["status"] = "Succeeded",
            ["result"] = new JsonObject { ["signature"] = Convert.ToBase64String(sig), ["signingCertificate"] = Convert.ToBase64String(cert) },
        }));
        using var client = Client(mock);
        var signer = new ArtifactSigningDigestSigner(client, Params("a", "p", []));
        var digest = Enumerable.Repeat((byte)7, 48).ToArray();

        Assert.Equal(sig, signer.SignDigest(digest, AuthenticodeHashKind.Sha384));
        Assert.Equal(cert, signer.LastResult!.SigningCertificate);
        var body = JsonNode.Parse(mock.Requests[0].BodyText)!;
        Assert.Equal("RS384", body["signatureAlgorithm"]!.GetValue<string>());
        Assert.Equal(Convert.ToBase64String(digest), body["digest"]!.GetValue<string>());
    }
}
