using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Internal;
using Devolutions.Psign.Signing.Pki;

namespace Devolutions.Psign.Signing.ArtifactSigning;

/// <summary>Parameters for <c>…/certificateprofiles/{profile}:sign</c> (Rust <c>CodesigningSubmitParams</c>).</summary>
public sealed class CodesigningSubmitParams
{
    public string Region { get; set; } = string.Empty;

    public string AccountName { get; set; } = string.Empty;

    public string ProfileName { get; set; } = string.Empty;

    public byte[] Digest { get; set; } = [];

    public string SignatureAlgorithm { get; set; } = "RS256";

    public string ApiVersion { get; set; } = ArtifactSigningClient.DefaultApiVersion;

    public string? CorrelationId { get; set; }

    public string? Authority { get; set; }

    public CodesigningAuth Auth { get; set; } = new CodesigningAuth.DefaultChain([]);

    /// <summary>
    /// Override data-plane origin (scheme + host and optional port), no trailing slash. Default:
    /// <c>https://{region}.codesigning.azure.net</c>.
    /// </summary>
    public string? EndpointBaseUrl { get; set; }

    /// <summary>Shallow copy with a different digest.</summary>
    public CodesigningSubmitParams WithDigest(byte[] digest, string? signatureAlgorithm = null)
    {
        var copy = (CodesigningSubmitParams)MemberwiseClone();
        copy.Digest = digest;
        if (signatureAlgorithm is not null)
        {
            copy.SignatureAlgorithm = signatureAlgorithm;
        }

        return copy;
    }
}

/// <summary>Parameters for authenticated certificate-profile reads (Rust <c>CodesigningProfileParams</c>).</summary>
public sealed class CodesigningProfileParams
{
    public string AccountName { get; set; } = string.Empty;

    public string ProfileName { get; set; } = string.Empty;

    public string ApiVersion { get; set; } = ArtifactSigningClient.DefaultProfileRootApiVersion;

    public string? Authority { get; set; }

    public CodesigningAuth Auth { get; set; } = new CodesigningAuth.DefaultChain([]);

    /// <summary>HTTPS data-plane origin in the public Azure cloud, without path, query, or fragment.</summary>
    public string EndpointBaseUrl { get; set; } = string.Empty;
}

/// <summary>Decoded <c>:sign</c> result (Rust <c>CodesigningSignatureResult</c>).</summary>
public sealed record CodesigningSignatureResult(byte[] Signature, byte[] SigningCertificate, JsonNode? FinalJson);

/// <summary>
/// Azure Artifact Signing / Trusted Signing data-plane REST client (port of Rust <c>psign-codesigning-rest</c>):
/// token acquisition, <c>:sign</c> LRO submit + polling, and the profile root-certificate operation.
/// </summary>
public sealed class ArtifactSigningClient : IDisposable
{
    public const string DefaultApiVersion = "2024-06-15";

    /// <summary>Preview API version used by the profile root-certificate operation.</summary>
    public const string DefaultProfileRootApiVersion = "2022-06-15-preview";

    internal const string DefaultScope = "https://codesigning.azure.net/.default";
    internal const string ManagedIdentityResource = "https://codesigning.azure.net";
    internal const int MaxProfileRootBytes = 1024 * 1024;
    internal const int MaxProfileRootErrorBytes = 64 * 1024;
    internal const string DefaultImdsEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token";

    private static readonly string[] ProfileRootContentTypes = ["application/x-x509-ca-cert", "application/pkix-cert", "application/octet-stream"];
    private static readonly string[] AzureDataPlaneSuffixes = [".codesigning.azure.net", ".artifactsigning.azure.net"];

    private readonly HttpTransport _http;
    private readonly Func<string, string?> _environment;

    /// <param name="handler">Optional HTTP handler (tests inject an in-memory handler); not disposed by the client.</param>
    /// <param name="environment">Environment variable lookup (defaults to the process environment).</param>
    public ArtifactSigningClient(HttpMessageHandler? handler = null, Func<string, string?>? environment = null)
    {
        _http = new HttpTransport(handler);
        _environment = environment ?? Environment.GetEnvironmentVariable;
    }

    /// <summary>Delay between LRO polls (Rust: 2 seconds).</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Maximum LRO poll attempts (Rust: 90).</summary>
    public int MaxPollAttempts { get; set; } = 90;

    /// <summary>Data-plane origin for <paramref name="p"/> (Rust <c>data_plane_base_url</c>).</summary>
    public static string DataPlaneBaseUrl(CodesigningSubmitParams p)
    {
        if (p.EndpointBaseUrl is { } u)
        {
            var t = u.Trim().TrimEnd('/');
            if (t.Length > 0)
            {
                return t;
            }
        }

        return $"https://{p.Region.Trim()}.codesigning.azure.net";
    }

    /// <summary>Resolve an <c>Operation-Location</c> value against the data-plane base (Rust <c>operation_location_url</c>).</summary>
    public static string OperationLocationUrl(string baseUrl, string location)
    {
        var trimmed = location.Trim();
        if (trimmed.StartsWith("http://", StringComparison.Ordinal) || trimmed.StartsWith("https://", StringComparison.Ordinal))
        {
            return trimmed;
        }

        return trimmed.StartsWith('/') ? baseUrl.TrimEnd('/') + trimmed : baseUrl.TrimEnd('/') + "/" + trimmed;
    }

    /// <summary>Signature algorithm (JWS name) for an RSA Authenticode digest.</summary>
    public static string SignatureAlgorithmForDigest(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha256 => "RS256",
        AuthenticodeHashKind.Sha384 => "RS384",
        AuthenticodeHashKind.Sha512 => "RS512",
        _ => throw new PsignException("Artifact Signing supports only SHA256, SHA384, or SHA512 digests"),
    };

    // ------------------------------------------------------------------ tokens

    /// <summary>Acquire a bearer token for <c>codesigning.azure.net</c> (Rust <c>acquire_codesigning_token</c>).</summary>
    public string AcquireToken(CodesigningAuth auth, string? authority = null) =>
        HttpTransport.RunSync(() => AcquireTokenAsync(auth, authority));

    /// <inheritdoc cref="AcquireToken"/>
    public async Task<string> AcquireTokenAsync(CodesigningAuth auth, string? authority = null, CancellationToken cancellationToken = default)
    {
        switch (auth)
        {
            case CodesigningAuth.Bearer bearer:
                {
                    var t = bearer.Token.Trim();
                    return t.Length == 0 ? throw new PsignException("access token must not be empty") : t;
                }

            case CodesigningAuth.ManagedIdentity mi:
                return await AcquireManagedIdentityTokenAsync(mi.ClientId, mi.ResourceId, cancellationToken).ConfigureAwait(false);
            case CodesigningAuth.ClientCredentials cc:
                return await AcquireClientCredentialsTokenAsync(authority, cc.TenantId, cc.ClientId, cc.ClientSecret, cancellationToken).ConfigureAwait(false);
            case CodesigningAuth.WorkloadIdentity wi:
                return await AcquireWorkloadIdentityTokenAsync(authority, wi.TenantId, wi.ClientId, wi.FederatedTokenFile, cancellationToken).ConfigureAwait(false);
            case CodesigningAuth.DefaultChain chain:
                {
                    var errors = new List<string>();
                    var exclude = chain.ExcludeCredentials;
                    if (!CodesigningAuthResolver.CredentialExcluded(exclude, "EnvironmentCredential", "ClientSecretCredential")
                        && Env("AZURE_TENANT_ID") is { } t1 && Env("AZURE_CLIENT_ID") is { } c1 && Env("AZURE_CLIENT_SECRET") is { } s1)
                    {
                        try
                        {
                            return await AcquireClientCredentialsTokenAsync(authority, t1, c1, s1, cancellationToken).ConfigureAwait(false);
                        }
                        catch (PsignException e)
                        {
                            errors.Add("EnvironmentCredential: " + PsignException.Render(e));
                        }
                    }

                    if (!CodesigningAuthResolver.CredentialExcluded(exclude, "WorkloadIdentityCredential")
                        && Env("AZURE_TENANT_ID") is { } t2 && Env("AZURE_CLIENT_ID") is { } c2 && Env("AZURE_FEDERATED_TOKEN_FILE") is { } f2)
                    {
                        try
                        {
                            return await AcquireWorkloadIdentityTokenAsync(authority, t2, c2, f2, cancellationToken).ConfigureAwait(false);
                        }
                        catch (PsignException e)
                        {
                            errors.Add("WorkloadIdentityCredential: " + PsignException.Render(e));
                        }
                    }

                    if (!CodesigningAuthResolver.CredentialExcluded(exclude, "ManagedIdentityCredential"))
                    {
                        var clientId = Env("AZURE_MANAGED_IDENTITY_CLIENT_ID") ?? Env("AZURE_CLIENT_ID");
                        try
                        {
                            return await AcquireManagedIdentityTokenAsync(clientId, null, cancellationToken).ConfigureAwait(false);
                        }
                        catch (PsignException e)
                        {
                            errors.Add("ManagedIdentityCredential: " + PsignException.Render(e));
                        }
                    }

                    throw errors.Count == 0
                        ? new PsignException("no Artifact Signing credential was available in the Rust default chain")
                        : new PsignException("Artifact Signing Rust default credential chain failed: " + string.Join("; ", errors));
                }

            default:
                throw new PsignException("unsupported Artifact Signing credential");
        }
    }

    private string? Env(string name) => CodesigningAuthResolver.TextOpt(_environment(name));

    private static string NormalizeAuthority(string? authority) => (authority ?? "https://login.microsoftonline.com").TrimEnd('/');

    private async Task<string> AcquireManagedIdentityTokenAsync(string? clientId, string? resourceId, CancellationToken ct)
    {
        var endpoint = _environment("PSIGN_CODESIGNING_IMDS_ENDPOINT") ?? DefaultImdsEndpoint;
        var query = new List<KeyValuePair<string, string>>
        {
            new("api-version", "2018-02-01"),
            new("resource", ManagedIdentityResource),
        };
        if (CodesigningAuthResolver.TextOpt(clientId) is { } cid)
        {
            query.Add(new("client_id", cid));
        }

        if (CodesigningAuthResolver.TextOpt(resourceId) is { } rid)
        {
            query.Add(new("mi_res_id", rid));
        }

        var url = endpoint + (endpoint.Contains('?', StringComparison.Ordinal) ? "&" : "?") + HttpText.FormEncode(query);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Metadata", "true");
        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(120), "managed identity token (IMDS) for codesigning.azure.net", ct).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"managed identity token HTTP {rsp.StatusText}: {rsp.Text}");
        }

        return HttpTransport.RequiredString(rsp.Body, "access_token", "managed identity JSON");
    }

    private async Task<string> AcquireClientCredentialsTokenAsync(string? authority, string tenantId, string clientId, string clientSecret, CancellationToken ct)
    {
        var tenant = tenantId.Trim();
        var cid = clientId.Trim();
        var sec = clientSecret.Trim();
        if (tenant.Length == 0 || cid.Length == 0 || sec.Length == 0)
        {
            throw new PsignException("client credentials require non-empty tenant_id, client_id, client_secret");
        }

        var tokenUrl = $"{NormalizeAuthority(authority)}/{tenant}/oauth2/v2.0/token";
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
        {
            Content = FormContent(
                new("client_id", cid),
                new("client_secret", sec),
                new("grant_type", "client_credentials"),
                new("scope", DefaultScope)),
        };
        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(120), "OAuth token request (codesigning.azure.net)", ct).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"OAuth HTTP {rsp.StatusText}: {rsp.Text}");
        }

        return HttpTransport.RequiredString(rsp.Body, "access_token", "OAuth JSON");
    }

    private async Task<string> AcquireWorkloadIdentityTokenAsync(string? authority, string tenantId, string clientId, string federatedTokenFile, CancellationToken ct)
    {
        string assertion;
        try
        {
            assertion = await File.ReadAllTextAsync(federatedTokenFile, ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw new PsignException($"read federated token file {federatedTokenFile}", e);
        }

        var tenant = tenantId.Trim();
        var cid = clientId.Trim();
        assertion = assertion.Trim();
        if (tenant.Length == 0 || cid.Length == 0 || assertion.Length == 0)
        {
            throw new PsignException("workload identity requires non-empty tenant_id, client_id, and federated token file");
        }

        var tokenUrl = $"{NormalizeAuthority(authority)}/{tenant}/oauth2/v2.0/token";
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
        {
            Content = FormContent(
                new("client_id", cid),
                new("client_assertion", assertion),
                new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("grant_type", "client_credentials"),
                new("scope", DefaultScope)),
        };
        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(120), "OAuth workload identity token request (codesigning.azure.net)", ct).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"OAuth workload identity HTTP {rsp.StatusText}: {rsp.Text}");
        }

        return HttpTransport.RequiredString(rsp.Body, "access_token", "OAuth workload identity JSON");
    }

    internal static ByteArrayContent FormContent(params KeyValuePair<string, string>[] pairs)
    {
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(HttpText.FormEncode(pairs)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
        return content;
    }

    // ------------------------------------------------------------------ :sign

    /// <summary>Submit a hash to <c>…:sign</c>, poll the LRO and return the final JSON (Rust <c>submit_codesign_hash_blocking</c>).</summary>
    public JsonNode? SubmitCodesignHash(CodesigningSubmitParams p, Action<string>? debug = null) =>
        HttpTransport.RunSync(() => SubmitCodesignHashAsync(p, debug));

    /// <inheritdoc cref="SubmitCodesignHash"/>
    public async Task<JsonNode?> SubmitCodesignHashAsync(CodesigningSubmitParams p, Action<string>? debug = null, CancellationToken cancellationToken = default)
    {
        if (p.Digest.Length == 0)
        {
            throw new PsignException("digest is empty");
        }

        var token = await AcquireTokenAsync(p.Auth, p.Authority, cancellationToken).ConfigureAwait(false);
        var baseUrl = DataPlaneBaseUrl(p);
        var account = p.AccountName.Trim();
        var profile = p.ProfileName.Trim();
        var api = p.ApiVersion.Trim();
        var submitUrl = $"{baseUrl}/codesigningaccounts/{account}/certificateprofiles/{profile}:sign?api-version={api}";

        // serde_json::json! builds a BTreeMap, so the body keys are sorted.
        var body = SerdeJson.Compact(new JsonObject
        {
            ["digest"] = Convert.ToBase64String(p.Digest),
            ["signatureAlgorithm"] = p.SignatureAlgorithm.Trim(),
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, submitUrl)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        if (CodesigningAuthResolver.TextOpt(p.CorrelationId) is { } correlation)
        {
            request.Headers.TryAddWithoutValidation("x-correlation-id", correlation);
            request.Headers.TryAddWithoutValidation("x-ms-correlation-id", correlation);
        }

        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(300), "codesign :sign POST", cancellationToken).ConfigureAwait(false);
        var opLocation = rsp.Header("Operation-Location");
        if (!rsp.IsSuccess)
        {
            throw new PsignException($":sign HTTP {rsp.StatusText}: {rsp.Text}");
        }

        var acceptJson = rsp.Body.Length == 0 ? null : HttpTransport.ParseJson(rsp.Body, ":sign JSON");

        string pollUrl;
        if (opLocation is not null)
        {
            pollUrl = OperationLocationUrl(baseUrl, opLocation);
        }
        else if (StringMember(acceptJson, "status") == "Succeeded")
        {
            return acceptJson;
        }
        else if ((StringMember(acceptJson, "id") ?? StringMember(acceptJson, "operationId")) is { } id)
        {
            pollUrl = $"{baseUrl}/codesigningaccounts/{account}/certificateprofiles/{profile}/sign/{id}?api-version={api}";
        }
        else
        {
            return acceptJson;
        }

        debug?.Invoke($"artifact-signing poll URL={pollUrl}");
        return await PollOperationAsync(token, pollUrl, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Submit and decode the signature result (Rust <c>submit_codesign_hash_signature_blocking</c>).</summary>
    public CodesigningSignatureResult SubmitCodesignHashSignature(CodesigningSubmitParams p, Action<string>? debug = null) =>
        SignatureResultFromJson(SubmitCodesignHash(p, debug));

    /// <inheritdoc cref="SubmitCodesignHashSignature"/>
    public async Task<CodesigningSignatureResult> SubmitCodesignHashSignatureAsync(CodesigningSubmitParams p, Action<string>? debug = null, CancellationToken cancellationToken = default) =>
        SignatureResultFromJson(await SubmitCodesignHashAsync(p, debug, cancellationToken).ConfigureAwait(false));

    private async Task<JsonNode?> PollOperationAsync(string token, string pollUrl, CancellationToken ct)
    {
        for (var attempt = 0; attempt < MaxPollAttempts; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, pollUrl);
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
            var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(300), "poll codesign operation", ct).ConfigureAwait(false);
            if (!rsp.IsSuccess)
            {
                throw new PsignException($"poll HTTP {rsp.StatusText}: {rsp.Text}");
            }

            var v = HttpTransport.ParseJson(rsp.Body, "poll JSON");
            switch (StringMember(v, "status") ?? string.Empty)
            {
                case "Succeeded":
                    return v;
                case "Failed":
                    throw new PsignException("codesign operation failed: " + SerdeJson.Compact(v, sortKeys: true));
                case "Canceled":
                    throw new PsignException("codesign operation canceled");
                default:
                    await Task.Delay(PollInterval, ct).ConfigureAwait(false);
                    break;
            }
        }

        throw new PsignException($"codesign operation timed out polling {pollUrl}");
    }

    private static string? StringMember(JsonNode? node, string name) =>
        node is JsonObject obj && obj.TryGetPropertyValue(name, out var v) && v is JsonValue jv && jv.GetValueKind() == JsonValueKind.String
            ? jv.GetValue<string>()
            : null;

    /// <summary>Decode <c>signature</c> / <c>signingCertificate</c> from a final JSON (optionally under <c>result</c>).</summary>
    public static CodesigningSignatureResult SignatureResultFromJson(JsonNode? finalJson)
    {
        var result = finalJson is JsonObject o && o.TryGetPropertyValue("result", out var r) && r is not null ? r : finalJson;
        return new CodesigningSignatureResult(
            DecodeStandardBase64Field(result, "signature"),
            DecodeStandardBase64Field(result, "signingCertificate"),
            finalJson);
    }

    private static byte[] DecodeStandardBase64Field(JsonNode? obj, string field)
    {
        var s = StringMember(obj, field) ?? throw new PsignException($"codesign result missing {field}");
        try
        {
            return Convert.FromBase64String(s.Trim());
        }
        catch (FormatException e)
        {
            throw new PsignException($"decode codesign result {field}", e);
        }
    }

    // ------------------------------------------------------------------ profile root certificate

    /// <summary>Retrieve the root certificate associated with an Artifact Signing profile (Rust <c>get_codesigning_root_certificate_blocking</c>).</summary>
    public byte[] GetRootCertificate(CodesigningProfileParams p) => HttpTransport.RunSync(() => GetRootCertificateAsync(p));

    /// <inheritdoc cref="GetRootCertificate"/>
    public async Task<byte[]> GetRootCertificateAsync(CodesigningProfileParams p, CancellationToken cancellationToken = default)
    {
        var url = ProfileRootCertificateUrl(p);
        var token = await AcquireTokenAsync(p.Auth, p.Authority, cancellationToken).ConfigureAwait(false);
        return await FetchProfileRootCertificateAsync(token, url, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Build and validate the root-certificate URL (Rust <c>profile_root_certificate_url</c>).</summary>
    public static string ProfileRootCertificateUrl(CodesigningProfileParams p)
    {
        var account = p.AccountName.Trim();
        var profile = p.ProfileName.Trim();
        var api = p.ApiVersion.Trim();
        if (account.Length == 0 || profile.Length == 0 || api.Length == 0)
        {
            throw new PsignException("Artifact Signing account, profile, and API version must not be empty");
        }

        var origin = ValidatedArtifactSigningOrigin(p.EndpointBaseUrl);
        var path = string.Join('/', new[] { "codesigningaccounts", account, "certificateprofiles", profile, "sign", "rootcert" }.Select(HttpText.EncodePathSegment));
        return HttpText.AppendQueryPair(origin + "/" + path, "api-version", api);
    }

    private static string ValidatedArtifactSigningOrigin(string endpoint)
    {
        if (!Uri.TryCreate(endpoint.Trim(), UriKind.Absolute, out var url))
        {
            throw new PsignException("parse Artifact Signing endpoint", new PsignException("relative URL without a base"));
        }

        if (url.Scheme != "https")
        {
            throw new PsignException("Artifact Signing endpoint must use HTTPS");
        }

        if (url.UserInfo.Length > 0)
        {
            throw new PsignException("Artifact Signing endpoint must not contain user information");
        }

        if (url.Port != 443)
        {
            throw new PsignException("Artifact Signing endpoint must use the default HTTPS port");
        }

        if (url.AbsolutePath != "/" || url.Query.Length > 0 || url.Fragment.Length > 0 || endpoint.Trim().EndsWith('?') || endpoint.Trim().EndsWith('#'))
        {
            throw new PsignException("Artifact Signing endpoint must be an origin without a path, query, or fragment");
        }

        var host = url.Host;
        if (host.Length == 0)
        {
            throw new PsignException("Artifact Signing endpoint must include a host");
        }

        if (!AzureDataPlaneSuffixes.Any(s => host.EndsWith(s, StringComparison.Ordinal) && host.Length > s.Length))
        {
            throw new PsignException("Artifact Signing endpoint host must be a public Azure Artifact Signing data-plane host");
        }

        return "https://" + host;
    }

    internal async Task<byte[]> FetchProfileRootCertificateAsync(string token, string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        request.Headers.TryAddWithoutValidation("Accept", "application/x-x509-ca-cert");
        var rsp = await _http.SendAsync(
            request,
            TimeSpan.FromSeconds(30),
            "Artifact Signing root certificate GET",
            ct,
            followRedirects: false,
            bodyLimit: status =>
            {
                var ok = (int)status is >= 200 and <= 299;
                return (ok ? MaxProfileRootBytes : MaxProfileRootErrorBytes, $"read Artifact Signing root certificate HTTP {HttpText.Status(status)} response");
            }).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"Artifact Signing root certificate HTTP {rsp.StatusText}: {rsp.Text}");
        }

        ValidateRootCertificateResponse(rsp.Message.Content.Headers.ContentType?.ToString(), rsp.Body);
        return rsp.Body;
    }

    /// <summary>Validate the root-certificate response (Rust <c>validate_root_certificate_response</c>).</summary>
    public static void ValidateRootCertificateResponse(string? contentType, byte[] body)
    {
        if (body.Length == 0)
        {
            throw new PsignException("Artifact Signing returned an empty root certificate");
        }

        if (contentType is not null)
        {
            var mediaType = contentType.Split(';')[0].Trim();
            if (!ProfileRootContentTypes.Any(a => string.Equals(mediaType, a, StringComparison.OrdinalIgnoreCase)))
            {
                throw new PsignException($"Artifact Signing returned unexpected root certificate content type {mediaType}");
            }
        }

        CertificateInfo cert;
        try
        {
            cert = CertificateInfo.Parse(body);
        }
        catch (PsignException e)
        {
            throw new PsignException("parse Artifact Signing root certificate DER", e);
        }

        if (!TestPki.IsCa(cert))
        {
            throw new PsignException("Artifact Signing returned a certificate that is not a CA");
        }
    }

    public void Dispose() => _http.Dispose();
}
