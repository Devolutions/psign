using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Portable;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>In-process <see cref="HttpMessageHandler"/> that routes to a <see cref="LocalHttpServer"/>-style handler function.</summary>
internal sealed class FuncHttpHandler : HttpMessageHandler
{
    private readonly Func<LocalHttpRequest, LocalHttpResponse> _handler;

    public FuncHttpHandler(Func<LocalHttpRequest, LocalHttpResponse> handler) => _handler = handler;

    public List<LocalHttpRequest> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in request.Headers)
        {
            headers[h.Key] = string.Join(", ", h.Value);
        }

        if (request.Content is not null)
        {
            foreach (var h in request.Content.Headers)
            {
                headers[h.Key] = string.Join(", ", h.Value);
            }
        }

        var captured = new LocalHttpRequest(request.Method.Method, request.RequestUri!.PathAndQuery, headers, body);
        Requests.Add(captured);
        var response = _handler(captured);
        var message = new HttpResponseMessage((HttpStatusCode)response.Status) { Content = new ByteArrayContent(response.Body) };
        if (response.ContentType is not null)
        {
            message.Content.Headers.TryAddWithoutValidation("Content-Type", response.ContentType);
        }

        foreach (var (name, value) in response.Headers)
        {
            if (!message.Headers.TryAddWithoutValidation(name, value))
            {
                message.Content.Headers.TryAddWithoutValidation(name, value);
            }
        }

        return message;
    }
}

/// <summary>
/// Deterministic mock of an RFC 3161 TSA, Azure Key Vault (<c>certificates</c> / <c>keys/sign</c>) and Azure Artifact
/// Signing (<c>:sign</c>, answered synchronously), all signing with the vendored test PFX key.
/// </summary>
internal sealed class CloudMock : IDisposable
{
    public const string KvCertificateName = "kvcert";
    public const string Account = "acct";
    public const string Profile = "prof";

    private readonly PfxIdentity _pfx = new();

    public CloudMock(string baseUrl)
    {
        BaseUrl = baseUrl;
        Token = CreateTimestampToken();
    }

    public string BaseUrl { get; set; }

    public byte[] Token { get; }

    public CertificateInfo Signer => _pfx.Signer;

    public List<CertificateInfo> Chain => _pfx.Chain;

    public LocalHttpResponse Handle(LocalHttpRequest request)
    {
        var path = request.Path;
        if (request.Method == "POST" && path == "/tsa")
        {
            var response = Der.EncodeSequence(Der.EncodeSequence(Der.EncodeTlv(0x02, [0])), Token);
            return new LocalHttpResponse(200, response, ("Content-Type", "application/timestamp-reply"));
        }

        if (request.Method == "GET" && path.StartsWith("/certificates/" + KvCertificateName, StringComparison.Ordinal))
        {
            return LocalHttpResponse.Json(new JsonObject
            {
                ["kid"] = $"{BaseUrl}/keys/{KvCertificateName}/v1",
                ["cer"] = Convert.ToBase64String(_pfx.Signer.RawData),
            }.ToJsonString());
        }

        if (request.Method == "POST" && path == $"/keys/{KvCertificateName}/v1/sign")
        {
            var body = JsonNode.Parse(request.BodyText)!;
            var digest = AzureKeyVaultClient.Base64UrlDecode(body["value"]!.GetValue<string>());
            var signature = _pfx.Key.SignHash(digest, HashFor(body["alg"]!.GetValue<string>()), RSASignaturePadding.Pkcs1);
            return LocalHttpResponse.Json(new JsonObject
            {
                ["kid"] = $"{BaseUrl}/keys/{KvCertificateName}/v1",
                ["value"] = AzureKeyVaultClient.Base64UrlEncode(signature),
            }.ToJsonString());
        }

        if (request.Method == "POST" && path == $"/codesigningaccounts/{Account}/certificateprofiles/{Profile}:sign")
        {
            var body = JsonNode.Parse(request.BodyText)!;
            var digest = Convert.FromBase64String(body["digest"]!.GetValue<string>());
            var signature = _pfx.Key.SignHash(digest, HashFor(body["signatureAlgorithm"]!.GetValue<string>()), RSASignaturePadding.Pkcs1);

            // CA-first PEM bag, base64-wrapped: exercises the signer selection of parse_artifact_signing_certificates.
            var pem = string.Concat(_pfx.Chain.Append(_pfx.Signer).Select(c =>
                "-----BEGIN CERTIFICATE-----\n" + string.Concat(Convert.ToBase64String(c.RawData).Chunk(64).Select(l => new string(l) + "\n")) + "-----END CERTIFICATE-----\n"));
            return LocalHttpResponse.Json(new JsonObject
            {
                ["status"] = "Succeeded",
                ["signature"] = Convert.ToBase64String(signature),
                ["signingCertificate"] = Convert.ToBase64String(Encoding.ASCII.GetBytes(pem)),
            }.ToJsonString());
        }

        return new LocalHttpResponse(404, Encoding.UTF8.GetBytes("no mock route for " + request.Method + " " + request.Target));
    }

    private static HashAlgorithmName HashFor(string alg) => alg switch
    {
        "RS384" => HashAlgorithmName.SHA384,
        "RS512" => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256,
    };

    private byte[] CreateTimestampToken()
    {
        // A CMS SignedData over a TSTInfo (genTime 2025-01-02T03:04:05Z) signed by the test key.
        var tstInfo = Der.EncodeSequence(
            Der.EncodeTlv(0x02, [1]),
            Der.EncodeOid("1.2.3.4.1"),
            Der.EncodeSequence(Pkcs7Builder.DigestAlgorithm(AuthenticodeHashKind.Sha256).Encode(), Der.EncodeTlv(0x04, new byte[32])),
            Der.EncodeTlv(0x02, [0x2a]),
            Der.EncodeTlv(0x18, Encoding.ASCII.GetBytes("20250102030405Z")));
        return Pkcs7Builder.CreateSignedData("1.2.840.113549.1.9.16.1.4", Der.EncodeTlv(0x04, tstInfo), AuthenticodeHashKind.Sha256, _pfx.Signer, [], _pfx.Key);
    }

    public void Dispose() => _pfx.Dispose();
}

/// <summary>
/// Portable signing with remote providers (Azure Key Vault, Azure Artifact Signing) and RFC 3161 timestamping over mocked
/// HTTP, plus differential checks against the Rust FFI (built with <c>azure-kv-sign</c> / <c>artifact-signing-rest</c>)
/// through a loopback server.
/// </summary>
public sealed class PortableCoreRemoteSigningTests
{
    private const string Password = "CodeSign123!";
    private const string MockBase = "http://cloud.mock.test";

    private static string Pfx => Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx");

    private static PortableSignRequest KeyVault(string path, string output, string baseUrl) => new()
    {
        Path = path,
        OutputPath = output,
        AzureKeyVaultUrl = baseUrl + "/",
        AzureKeyVaultCertificate = CloudMock.KvCertificateName,
        AzureKeyVaultAccessToken = "kv-token",
    };

    private static PortableSignRequest ArtifactSigning(string path, string output, string baseUrl) => new()
    {
        Path = path,
        OutputPath = output,
        ArtifactSigningEndpoint = baseUrl + "/",
        ArtifactSigningAccountName = CloudMock.Account,
        ArtifactSigningProfileName = CloudMock.Profile,
        ArtifactSigningAccessToken = "as-token",
        ArtifactSigningCorrelationId = "corr-1",
    };

    private static PortableSignRequest Local(string path, string output) => new() { Path = path, OutputPath = output, PfxPath = Pfx, PfxPassword = Password };

    public static TheoryData<string> RemoteFixtures() => new()
    {
        "generated-unsigned/pe/tiny64-pe-alias.dll",
        "generated-unsigned/cab/sample.cab",
        "generated-unsigned/installer/tiny.msi",
        "generated-unsigned/msix/sample.msixbundle",
        "zip-authenticode/unsigned/sample.zip",
        "generated-unsigned/scripts/powershell/ps1/utf8-crlf.ps1",
        "generated-unsigned/appinstaller/sample.appinstaller",
        "package-signing/unsigned/sample.vsix",
    };

    [Theory]
    [MemberData(nameof(RemoteFixtures))]
    public void KeyVaultAndArtifactSigningMatchLocalPfxSignatures(string fixture)
    {
        // The mock signs with the PFX key; Key Vault embeds only the signer certificate, Artifact Signing the returned
        // chain, so a local request with the same chain must produce identical bytes.
        using var mock = new CloudMock(MockBase);
        var options = new PortableCoreOptions { HttpHandler = new FuncHttpHandler(mock.Handle), Clock = () => new DateTimeOffset(2025, 1, 2, 3, 4, 5, TimeSpan.Zero) };
        using var dir = new TempDir();
        var source = Fixtures.Path(fixture);
        var name = Path.GetFileName(fixture);

        var kv = PortableCore.PortableSign(KeyVault(source, dir.File("kv-" + name), MockBase), options);
        var artifact = PortableCore.PortableSign(ArtifactSigning(source, dir.File("as-" + name), MockBase), options);
        Assert.Equal(PortableSignatureStatus.Valid, kv.Signature.Status);
        Assert.Equal(PortableSignatureStatus.Valid, artifact.Signature.Status);

        var certDer = Convert.ToBase64String(mock.Signer.RawData);
        var kvLocal = Local(source, dir.File("kv-local-" + name));
        kvLocal.CertificateDerBase64 = certDer;
        kvLocal.PrivateKeyPath = WriteKey(dir);
        kvLocal.PfxPath = null;
        PortableCore.PortableSign(kvLocal, options);
        var asLocal = Local(source, dir.File("as-local-" + name));
        PortableCore.PortableSign(asLocal, options);
        Assert.Equal(File.ReadAllBytes(kvLocal.OutputPath!), File.ReadAllBytes(kv.OutputPath));
        Assert.Equal(File.ReadAllBytes(asLocal.OutputPath!), File.ReadAllBytes(artifact.OutputPath));
        Assert.Equal(certDer, kv.Signature.SignerCertificateDerBase64);
    }

    private static string WriteKey(TempDir dir)
    {
        using var pfx = new PfxIdentity();
        var path = dir.File("key.pk8");
        if (!File.Exists(path))
        {
            File.WriteAllBytes(path, pfx.Key.ExportPkcs8PrivateKey());
        }

        return path;
    }

    [Fact]
    public void NuGetRemoteSignatureUsesBasicAttributes()
    {
        using var mock = new CloudMock(MockBase);
        var handler = new FuncHttpHandler(mock.Handle);
        var options = new PortableCoreOptions { HttpHandler = handler, ZipClock = () => Devolutions.Psign.Core.Zip.ZipDateTime.Default };
        using var dir = new TempDir();
        var output = dir.File("p.nupkg");
        var response = PortableCore.PortableSign(KeyVault(Fixtures.Path("package-signing/unsigned/sample.nupkg"), output, MockBase), options);
        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
        var sd = CmsSignedData.Parse(Convert.FromBase64String(response.Signature.Pkcs7DerBase64!));
        Assert.Equal([Oids.Pkcs9ContentType, Oids.Pkcs9MessageDigest], sd.SignerInfos[0].SignedAttributes!.Select(a => a.Oid));
        Assert.NotNull(sd.EncapContent);
        Assert.Contains(handler.Requests, r => r.Headers.TryGetValue("Authorization", out var a) && a == "Bearer kv-token");
    }

    [Fact]
    public void ArtifactSigningSendsCorrelationIdAndAlgorithm()
    {
        using var mock = new CloudMock(MockBase);
        var handler = new FuncHttpHandler(mock.Handle);
        using var dir = new TempDir();
        var request = ArtifactSigning(Fixtures.Path("generated-unsigned/scripts/powershell/ps1/utf8-lf.ps1"), dir.File("s.ps1"), MockBase);
        request.HashAlgorithm = PortableDigestAlgorithm.Sha512;
        PortableCore.PortableSign(request, new PortableCoreOptions { HttpHandler = handler });
        var sign = Assert.Single(handler.Requests);
        Assert.Equal("RS512", JsonNode.Parse(sign.BodyText)!["signatureAlgorithm"]!.GetValue<string>());
        Assert.Equal("corr-1", sign.Headers["x-correlation-id"]);
        Assert.Equal("Bearer as-token", sign.Headers["Authorization"]);
        Assert.StartsWith("/codesigningaccounts/acct/certificateprofiles/prof:sign?api-version=2024-06-15", sign.Target, StringComparison.Ordinal);
    }

    [Fact]
    public void TimestampTokenIsAttachedWithTheMicrosoftAttribute()
    {
        using var mock = new CloudMock(MockBase);
        var handler = new FuncHttpHandler(mock.Handle);
        using var dir = new TempDir();
        var request = Local(Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe"), dir.File("t.exe"));
        request.TimestampServer = MockBase + "/tsa";
        request.TimestampHashAlgorithm = PortableTimestampDigestAlgorithm.Sha384;
        var response = PortableCore.PortableSign(request, new PortableCoreOptions { HttpHandler = handler });
        var tsa = Assert.Single(handler.Requests);
        Assert.Equal("application/timestamp-query", tsa.Headers["Content-Type"]);
        var sd = CmsSignedData.Parse(Convert.FromBase64String(response.Signature.Pkcs7DerBase64!));
        var attr = sd.SignerInfos[0].GetUnsignedAttribute(Oids.MsRfc3161TimestampToken);
        Assert.NotNull(attr);
        Assert.Equal(mock.Token, attr!.Values[0]);
        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
    }

    [Fact]
    public void TimestampErrorsAreReported()
    {
        using var dir = new TempDir();
        var handler = new FuncHttpHandler(_ => new LocalHttpResponse(503, "busy"u8.ToArray()));
        var request = Local(Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe"), dir.File("t.exe"));
        request.TimestampServer = MockBase + "/tsa";
        var e = Assert.Throws<PsignException>(() => PortableCore.PortableSign(request, new PortableCoreOptions { HttpHandler = handler }));
        Assert.Equal("timestamp " + request.Path, e.Message);
        Assert.Contains("TSA returned an HTTP error", e.FullMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, null, null, false, "choose Azure Key Vault authentication: access token, managed identity, or client id/secret/tenant")]
    [InlineData("tok", null, null, true, "use either Azure Key Vault access token or managed identity / client credentials, not multiple")]
    [InlineData(null, "id", null, false, "Azure AD client credentials require azure_key_vault_client_id, azure_key_vault_client_secret, and azure_key_vault_tenant_id")]
    public void KeyVaultAuthValidation(string? token, string? clientId, string? secret, bool managedIdentity, string expected)
    {
        using var dir = new TempDir();
        var target = dir.File("a.ps1");
        File.WriteAllText(target, "x");
        var request = new PortableSignRequest
        {
            Path = target,
            AzureKeyVaultUrl = MockBase,
            AzureKeyVaultCertificate = "c",
            AzureKeyVaultAccessToken = token,
            AzureKeyVaultClientId = clientId,
            AzureKeyVaultClientSecret = secret,
            AzureKeyVaultManagedIdentity = managedIdentity,
        };
        Assert.Equal(expected, Assert.Throws<PsignException>(() => PortableCore.PortableSign(request)).Message);

        request.AzureKeyVaultCertificate = " ";
        Assert.Equal("Azure Key Vault signing requires azure_key_vault_certificate", Assert.Throws<PsignException>(() => PortableCore.PortableSign(request)).Message);
    }

    [Fact]
    public void ArtifactSigningRequiresAccountAndProfile()
    {
        using var dir = new TempDir();
        var target = dir.File("a.ps1");
        File.WriteAllText(target, "x");
        Assert.Equal(
            "Artifact Signing requires artifact_signing_endpoint",
            Assert.Throws<PsignException>(() => PortableCore.PortableSign(new PortableSignRequest { Path = target, ArtifactSigningAccountName = "a" })).Message);
        Assert.Equal(
            "Artifact Signing requires artifact_signing_profile_name",
            Assert.Throws<PsignException>(() => PortableCore.PortableSign(new PortableSignRequest { Path = target, ArtifactSigningEndpoint = "https://x", ArtifactSigningAccountName = "a" })).Message);
        Assert.Equal(
            "unsupported Artifact Signing credential type 'magic'",
            Assert.Throws<PsignException>(() => PortableCore.PortableSign(new PortableSignRequest
            {
                Path = target,
                ArtifactSigningEndpoint = "https://x",
                ArtifactSigningAccountName = "a",
                ArtifactSigningProfileName = "p",
                ArtifactSigningCredentialType = "magic",
            })).Message);
    }

    [Fact]
    public void ArtifactSigningSupportsMetadataRegionAuthorityApiVersionAndAlgorithmOnMsix()
    {
        using var mock = new CloudMock(MockBase);
        var handler = new FuncHttpHandler(req =>
        {
            if (req.Method == "POST" && req.Path == "/tenant-as/oauth2/v2.0/token")
            {
                return LocalHttpResponse.Json("""{"access_token":"as-oauth-token"}""");
            }

            return mock.Handle(req);
        });
        using var dir = new TempDir();
        var metaPath = dir.File("metadata.json");
        File.WriteAllText(
            metaPath,
            $$"""{"Endpoint":"{{MockBase}}","CodeSigningAccountName":"{{CloudMock.Account}}","CertificateProfileName":"{{CloudMock.Profile}}","CorrelationId":"meta-corr"}""");
        var msix = dir.File("sample.msix");
        File.Copy(Fixtures.Path("generated-unsigned/msix/sample.msix"), msix);

        var response = PortableCore.PortableSignFileVerified(
            new PortableSignRequest
            {
                Path = msix,
                ArtifactSigningMetadata = metaPath,
                ArtifactSigningAuthority = "http://auth.mock.test",
                ArtifactSigningApiVersion = "2024-09-01",
                ArtifactSigningSignatureAlgorithm = "RS256",
                ArtifactSigningTenantId = "tenant-as",
                ArtifactSigningClientId = "client-as",
                ArtifactSigningClientSecret = "secret-as",
            },
            new PortableCoreOptions { HttpHandler = handler });

        Assert.Equal(PortableSignatureStatus.Valid, response.Signature.Status);
        Assert.Equal(msix, response.OutputPath);
        Assert.Contains(handler.Requests, r => r.Method == "POST" && r.Path == "/tenant-as/oauth2/v2.0/token");
        var signReq = Assert.Single(handler.Requests, r => r.Path.EndsWith(":sign", StringComparison.Ordinal));
        Assert.Contains("api-version=2024-09-01", signReq.Target, StringComparison.Ordinal);
        Assert.Equal("meta-corr", signReq.Headers["x-correlation-id"]);
        Assert.Equal("Bearer as-oauth-token", signReq.Headers["Authorization"]);
    }

    [Fact]
    public void KeyVaultSupportsAzureEnvironmentFallbackForClientSecretWorkloadIdentityAndManagedIdentity()
    {
        using var mock = new CloudMock(MockBase);
        var handler = new FuncHttpHandler(req =>
        {
            if (req.Method == "POST" && req.Path == "/env-tenant/oauth2/v2.0/token")
            {
                return LocalHttpResponse.Json("""{"access_token":"kv-env-token"}""");
            }

            if (req.Method == "GET" && req.Path == "/imds")
            {
                Assert.Contains("client_id=mi-env-client", req.Target, StringComparison.Ordinal);
                return LocalHttpResponse.Json("""{"access_token":"kv-mi-token"}""");
            }

            return mock.Handle(req);
        });
        using var dir = new TempDir();
        var source = Fixtures.Path("generated-unsigned/msix/sample.msix");

        // 1. Client credentials fallback via AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET.
        var envSp = new Dictionary<string, string?>
        {
            ["AZURE_TENANT_ID"] = "env-tenant",
            ["AZURE_CLIENT_ID"] = "env-client",
            ["AZURE_CLIENT_SECRET"] = "env-secret",
        };
        var outSp = dir.File("sp.msix");
        var resSp = PortableCore.PortableSign(
            new PortableSignRequest
            {
                Path = source,
                OutputPath = outSp,
                AzureKeyVaultUrl = MockBase,
                AzureKeyVaultCertificate = CloudMock.KvCertificateName,
                AzureAuthority = "http://auth.mock.test",
            },
            new PortableCoreOptions { HttpHandler = handler, Environment = k => envSp.GetValueOrDefault(k) });
        Assert.Equal(PortableSignatureStatus.Valid, resSp.Signature.Status);
        Assert.Contains(handler.Requests, r => r.Path == "/env-tenant/oauth2/v2.0/token" && r.BodyText.Contains("client_secret=env-secret", StringComparison.Ordinal));

        // 2. Workload identity fallback via AZURE_FEDERATED_TOKEN_FILE.
        var tokenFile = dir.File("fed.jwt");
        File.WriteAllText(tokenFile, "fed-jwt-token");
        var envWi = new Dictionary<string, string?>
        {
            ["AZURE_TENANT_ID"] = "env-tenant",
            ["AZURE_CLIENT_ID"] = "env-client",
            ["AZURE_FEDERATED_TOKEN_FILE"] = tokenFile,
        };
        var outWi = dir.File("wi.msix");
        var resWi = PortableCore.PortableSign(
            new PortableSignRequest
            {
                Path = source,
                OutputPath = outWi,
                AzureKeyVaultUrl = MockBase,
                AzureKeyVaultCertificate = CloudMock.KvCertificateName,
                AzureAuthority = "http://auth.mock.test",
            },
            new PortableCoreOptions { HttpHandler = handler, Environment = k => envWi.GetValueOrDefault(k) });
        Assert.Equal(PortableSignatureStatus.Valid, resWi.Signature.Status);
        Assert.Contains(handler.Requests, r => r.Path == "/env-tenant/oauth2/v2.0/token" && r.BodyText.Contains("client_assertion=fed-jwt-token", StringComparison.Ordinal));

        // 3. Managed identity client_id fallback via AZURE_MANAGED_IDENTITY_CLIENT_ID.
        var envMi = new Dictionary<string, string?>
        {
            ["AZURE_MANAGED_IDENTITY_CLIENT_ID"] = "mi-env-client",
            ["PSIGN_AZURE_KV_IMDS_ENDPOINT"] = MockBase + "/imds",
        };
        var outMi = dir.File("mi.msix");
        var resMi = PortableCore.PortableSign(
            new PortableSignRequest
            {
                Path = source,
                OutputPath = outMi,
                AzureKeyVaultUrl = MockBase,
                AzureKeyVaultCertificate = CloudMock.KvCertificateName,
                AzureKeyVaultManagedIdentity = true,
            },
            new PortableCoreOptions { HttpHandler = handler, Environment = k => envMi.GetValueOrDefault(k) });
        Assert.Equal(PortableSignatureStatus.Valid, resMi.Signature.Status);
    }

    [Fact]
    public void PortableSignFileVerifiedSupportsCertStoreAndPreservesTargetOnError()
    {
        using var dir = new TempDir();
        var storeDir = dir.File("store");
        var store = new Devolutions.Psign.Signing.CertStore.PortableCertStore();
        var imported = store.ImportPfx(new Devolutions.Psign.Signing.CertStore.CertStoreSelection(storeDir), Pfx, Password);

        var target = dir.File("sample.msix");
        File.Copy(Fixtures.Path("generated-unsigned/msix/sample.msix"), target);

        var signed = PortableCore.PortableSignFileVerified(new PortableSignRequest
        {
            Path = target,
            CertSha1 = imported.ThumbprintSha1,
            CertStoreDir = storeDir,
        });
        Assert.Equal(PortableSignatureStatus.Valid, signed.Signature.Status);
        Assert.Equal(target, signed.OutputPath);
        Assert.Equal(target, signed.Signature.Path);
        Assert.False(signed.Skipped);

        var signedBytes = File.ReadAllBytes(target);
        var skipped = PortableCore.PortableSignFileVerified(new PortableSignRequest
        {
            Path = target,
            SkipSigned = true,
            CertSha1 = imported.ThumbprintSha1,
            CertStoreDir = storeDir,
        });
        Assert.True(skipped.Skipped);
        Assert.Equal(signedBytes, File.ReadAllBytes(target));

        Assert.Throws<PsignException>(() => PortableCore.PortableSignFileVerified(new PortableSignRequest
        {
            Path = target,
            CertSha1 = new string('0', 40),
            CertStoreDir = storeDir,
        }));
        Assert.Equal(signedBytes, File.ReadAllBytes(target));
        Assert.DoesNotContain(Directory.EnumerateFiles(dir.DirPath), f => Path.GetFileName(f).Contains(".psign-", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------ Rust FFI over a loopback server

    public static TheoryData<string, string> RemoteDifferentialCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var fixture in new[]
        {
            "generated-unsigned/pe/tiny64-pe-alias.dll",
            "generated-unsigned/cab/sample.cab",
            "generated-unsigned/msix/sample.msixbundle",
            "zip-authenticode/unsigned/sample.zip",
            "generated-unsigned/scripts/powershell/psd1/utf16be-bom-lf.psd1",
            "generated-unsigned/appinstaller/sample.appinstaller",
        })
        {
            foreach (var mode in new[] { "kv", "as", "tsa" })
            {
                data.Add(fixture, mode);
            }
        }

        data.Add("package-signing/unsigned/with-pe.nupkg", "tsa");
        return data;
    }

    [SkippableTheory]
    [MemberData(nameof(RemoteDifferentialCases))]
    public void RemoteSigningMatchesRustFfi(string fixture, string mode)
    {
        RustPortableFfi.Require();
        using var mock = new CloudMock(string.Empty);
        using var server = new LocalHttpServer(mock.Handle);
        mock.BaseUrl = server.BaseUrl;
        using var dir = new TempDir();
        var output = dir.File(Path.GetFileName(fixture));
        var request = mode switch
        {
            "kv" => KeyVault(Fixtures.Path(fixture), output, server.BaseUrl),
            "as" => ArtifactSigning(Fixtures.Path(fixture), output, server.BaseUrl),
            _ => Local(Fixtures.Path(fixture), output),
        };
        request.HashAlgorithm = PortableDigestAlgorithm.Sha384;
        if (mode == "tsa")
        {
            request.TimestampServer = server.BaseUrl + "/tsa";
            request.TimestampHashAlgorithm = PortableTimestampDigestAlgorithm.Sha1;
        }

        var json = request.ToJson();
        var rust = RustPortableFfi.Invoke("sign", json);
        Skip.If(rust.Json.Contains("not compiled into this build", StringComparison.Ordinal), "Rust FFI built without azure-kv-sign / artifact-signing-rest");
        Assert.True(rust.StatusCode == PortableCoreJson.StatusOk, rust.Json);
        var rustBytes = File.ReadAllBytes(output);
        var rustCompanion = File.Exists(output + ".p7") ? File.ReadAllBytes(output + ".p7") : null;
        File.Delete(output);

        var zipTime = fixture.EndsWith(".nupkg", StringComparison.Ordinal)
            ? Devolutions.Psign.Core.Zip.ZipCrateArchive.Open(rustBytes).RequireByName(Devolutions.Psign.Core.NuGet.NuGetPackage.PackageSignatureFileName).LastModified
            : Devolutions.Psign.Core.Zip.ZipDateTime.Default;
        var signingTime = fixture.EndsWith(".nupkg", StringComparison.Ordinal) ? NuGetSigningTime(rustBytes) : DateTimeOffset.UtcNow;
        var cs = PortableCoreJson.Invoke("sign", json, new PortableCoreOptions { Clock = () => signingTime, ZipClock = () => zipTime });
        Assert.True(rust == cs, $"rust={rust.Json}\ncs  ={cs.Json}");
        Assert.Equal(rustBytes, File.ReadAllBytes(output));
        if (rustCompanion is not null)
        {
            Assert.Equal(rustCompanion, File.ReadAllBytes(output + ".p7"));
        }
    }

    private static DateTimeOffset NuGetSigningTime(byte[] package)
    {
        var archive = Devolutions.Psign.Core.Zip.ZipCrateArchive.Open(package);
        var sd = CmsSignedData.Parse(archive.Read(archive.RequireByName(Devolutions.Psign.Core.NuGet.NuGetPackage.PackageSignatureFileName)));
        var attr = sd.SignerInfos[0].GetSignedAttribute(Oids.Pkcs9SigningTime)!;
        return new System.Formats.Asn1.AsnReader(attr.Values[0], System.Formats.Asn1.AsnEncodingRules.DER).ReadUtcTime(2049);
    }

    [SkippableFact]
    public void RemoteErrorsMatchRustFfi()
    {
        RustPortableFfi.Require();
        using var server = new LocalHttpServer(r => new LocalHttpResponse(403, Encoding.UTF8.GetBytes("forbidden " + r.Path)));
        using var dir = new TempDir();
        var target = Fixtures.Path("generated-unsigned/pe/tiny32-pe-alias.exe");
        foreach (var request in new[]
        {
            KeyVault(target, dir.File("a.exe"), server.BaseUrl),
            ArtifactSigning(target, dir.File("b.exe"), server.BaseUrl),
            new PortableSignRequest { Path = target, OutputPath = dir.File("c.exe"), AzureKeyVaultUrl = server.BaseUrl, AzureKeyVaultCertificate = "c" },
            new PortableSignRequest { Path = target, OutputPath = dir.File("d.exe"), ArtifactSigningEndpoint = server.BaseUrl, ArtifactSigningAccountName = "a" },
            new PortableSignRequest { Path = target, OutputPath = dir.File("e.exe"), PfxPath = Pfx, PfxPassword = Password, TimestampServer = server.BaseUrl + "/tsa" },
        })
        {
            var json = request.ToJson();
            var rust = RustPortableFfi.Invoke("sign", json);
            Skip.If(rust.Json.Contains("not compiled into this build", StringComparison.Ordinal), "Rust FFI built without azure-kv-sign / artifact-signing-rest");
            var cs = PortableCoreJson.Invoke("sign", json);
            Assert.Equal(rust.StatusCode, cs.StatusCode);
            Assert.True(rust.Json == cs.Json, $"rust={rust.Json}\ncs  ={cs.Json}");
        }
    }
}
