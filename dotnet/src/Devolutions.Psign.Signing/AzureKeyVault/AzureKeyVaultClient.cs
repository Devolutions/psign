using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.Internal;

namespace Devolutions.Psign.Signing.AzureKeyVault;

/// <summary>Key Vault certificate metadata (<c>kid</c> + base64 <c>cer</c>) (Rust <c>KeyVaultCertificate</c>).</summary>
public sealed record KeyVaultCertificate(string Kid, string Cer)
{
    /// <summary>Decoded DER certificate.</summary>
    public byte[] CerDer => AzureKeyVaultClient.DecodeCerBase64(Cer);
}

/// <summary>Certificate public-key family (Rust <c>KvPublicKeyKind</c>).</summary>
public enum KvPublicKeyKind
{
    Rsa,
    Ec,
}

/// <summary>Digest algorithm for <c>keys/sign</c> (Rust <c>KvHashAlg</c>).</summary>
public enum KvHashAlg
{
    Sha256,
    Sha384,
    Sha512,
}

/// <summary>Authentication inputs (Rust <c>KvAuthParams</c>).</summary>
public sealed class KvAuthParams
{
    public string? AccessToken { get; set; }

    public bool ManagedIdentity { get; set; }

    public string? TenantId { get; set; }

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public string? Authority { get; set; }
}

/// <summary>
/// Azure Key Vault REST client (port of Rust <c>psign-azure-kv-rest</c>): OAuth token, certificate GET (<c>kid</c> +
/// <c>cer</c>), and <c>keys/sign</c> POST.
/// </summary>
public sealed class AzureKeyVaultClient : IDisposable
{
    public const string ApiVersion = "7.4";

    private readonly HttpTransport _http;

    /// <param name="handler">Optional HTTP handler (tests inject an in-memory handler); not disposed by the client.</param>
    public AzureKeyVaultClient(HttpMessageHandler? handler = null)
    {
        _http = new HttpTransport(handler);
    }

    /// <summary>Managed identity (IMDS) token endpoint.</summary>
    public string ImdsEndpoint { get; set; } = "http://169.254.169.254/metadata/identity/oauth2/token";

    /// <summary>Trim whitespace and trailing slashes (Rust <c>normalize_vault_base</c>).</summary>
    public static string NormalizeVaultBase(string url)
    {
        var u = url.Trim();
        if (u.Length == 0)
        {
            throw new PsignException("Azure Key Vault URL must not be empty");
        }

        return u.TrimEnd('/');
    }

    /// <summary>Map an Authenticode digest to a Key Vault hash algorithm.</summary>
    public static KvHashAlg HashAlgFor(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha256 => KvHashAlg.Sha256,
        AuthenticodeHashKind.Sha384 => KvHashAlg.Sha384,
        AuthenticodeHashKind.Sha512 => KvHashAlg.Sha512,
        _ => throw new PsignException("Azure Key Vault supports only SHA256, SHA384, or SHA512 file digests"),
    };

    // ------------------------------------------------------------------ tokens

    /// <summary>Acquire a <c>vault.azure.net</c> access token (Rust <c>acquire_kv_access_token</c>).</summary>
    public string AcquireAccessToken(KvAuthParams p) => HttpTransport.RunSync(() => AcquireAccessTokenAsync(p));

    /// <inheritdoc cref="AcquireAccessToken"/>
    public async Task<string> AcquireAccessTokenAsync(KvAuthParams p, CancellationToken cancellationToken = default)
    {
        if (p.AccessToken is { } raw)
        {
            var tok = raw.Trim();
            return tok.Length == 0 ? throw new PsignException("access token must not be empty") : tok;
        }

        if (p.ManagedIdentity)
        {
            var query = new List<KeyValuePair<string, string>>
            {
                new("api-version", "2018-02-01"),
                new("resource", "https://vault.azure.net"),
            };
            if (NonBlank(p.ClientId) is { } miClientId)
            {
                query.Add(new("client_id", miClientId));
            }

            var url = ImdsEndpoint + (ImdsEndpoint.Contains('?', StringComparison.Ordinal) ? "&" : "?") + HttpText.FormEncode(query);
            using var miRequest = new HttpRequestMessage(HttpMethod.Get, url);
            miRequest.Headers.TryAddWithoutValidation("Metadata", "true");
            var mi = await _http.SendAsync(miRequest, TimeSpan.FromSeconds(120), "managed identity token request (IMDS)", cancellationToken).ConfigureAwait(false);
            if (!mi.IsSuccess)
            {
                throw new PsignException($"managed identity token HTTP {mi.StatusText}: {mi.Text}");
            }

            return HttpTransport.RequiredString(mi.Body, "access_token", "managed identity token JSON");
        }

        var tenant = NonBlank(p.TenantId) ?? throw new PsignException("client credentials require tenant id");
        var clientId = NonBlank(p.ClientId) ?? throw new PsignException("client credentials require client id");
        var secret = NonBlank(p.ClientSecret) ?? throw new PsignException("client credentials require client secret");
        var authority = (NonBlank(p.Authority) ?? "https://login.microsoftonline.com").TrimEnd('/');
        var tokenUrl = $"{authority}/{HttpText.EncodePathSegment(tenant)}/oauth2/v2.0/token";
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
        {
            Content = ArtifactSigningClient.FormContent(
                new("client_id", clientId),
                new("client_secret", secret),
                new("scope", "https://vault.azure.net/.default"),
                new("grant_type", "client_credentials")),
        };
        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(120), "Azure AD token request", cancellationToken).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"Azure AD token HTTP {rsp.StatusText}: {rsp.Text}");
        }

        return HttpTransport.RequiredString(rsp.Body, "access_token", "Azure AD token JSON");
    }

    /// <summary>Acquire a <c>vault.azure.net</c> access token using workload identity federation (Rust <c>acquire_kv_workload_identity_token</c>).</summary>
    public string AcquireWorkloadIdentityToken(string? authority, string tenantId, string clientId, string federatedTokenFile) =>
        HttpTransport.RunSync(() => AcquireWorkloadIdentityTokenAsync(authority, tenantId, clientId, federatedTokenFile));

    /// <inheritdoc cref="AcquireWorkloadIdentityToken"/>
    public async Task<string> AcquireWorkloadIdentityTokenAsync(
        string? authority,
        string tenantId,
        string clientId,
        string federatedTokenFile,
        CancellationToken cancellationToken = default)
    {
        string rawAssertion;
        try
        {
            rawAssertion = await File.ReadAllTextAsync(federatedTokenFile, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"read federated token file {federatedTokenFile}", IoErrorText.Inner(e));
        }

        var tenant = tenantId.Trim();
        var cid = clientId.Trim();
        var assertion = rawAssertion.Trim();
        if (tenant.Length == 0 || cid.Length == 0 || assertion.Length == 0)
        {
            throw new PsignException("workload identity requires non-empty tenant_id, client_id, and federated token file");
        }

        var authBase = (NonBlank(authority) ?? "https://login.microsoftonline.com").TrimEnd('/');
        var tokenUrl = $"{authBase}/{HttpText.EncodePathSegment(tenant)}/oauth2/v2.0/token";
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
        {
            Content = ArtifactSigningClient.FormContent(
                new("client_id", cid),
                new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new("client_assertion", assertion),
                new("scope", "https://vault.azure.net/.default"),
                new("grant_type", "client_credentials")),
        };
        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(120), "Azure AD workload identity token request", cancellationToken).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"Azure AD workload identity token HTTP {rsp.StatusText}: {rsp.Text}");
        }

        return HttpTransport.RequiredString(rsp.Body, "access_token", "Azure AD workload identity token JSON");
    }

    private static string? NonBlank(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }

    // ------------------------------------------------------------------ certificate

    /// <summary>GET <c>{vault}/certificates/{name}[/{version}]?api-version=7.4</c> (Rust <c>fetch_kv_certificate</c>).</summary>
    public KeyVaultCertificate FetchCertificate(string vaultBase, string certName, string? certVersion, string token) =>
        HttpTransport.RunSync(() => FetchCertificateAsync(vaultBase, certName, certVersion, token));

    /// <inheritdoc cref="FetchCertificate"/>
    public async Task<KeyVaultCertificate> FetchCertificateAsync(string vaultBase, string certName, string? certVersion, string token, CancellationToken cancellationToken = default)
    {
        var url = CertificateUrl(vaultBase, certName, certVersion);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(300), "Key Vault GET certificate", cancellationToken).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"Key Vault certificate HTTP {rsp.StatusText}: {rsp.Text}");
        }

        var kid = HttpTransport.RequiredString(rsp.Body, "kid", "Key Vault certificate JSON");
        var cer = HttpTransport.RequiredString(rsp.Body, "cer", "Key Vault certificate JSON");
        return new KeyVaultCertificate(kid, cer);
    }

    /// <summary>Certificate metadata URL (Rust <c>fetch_kv_certificate</c> URL construction).</summary>
    public static string CertificateUrl(string vaultBase, string certName, string? certVersion)
    {
        var baseUrl = NormalizeVaultBase(vaultBase);
        var name = certName.Trim();
        if (name.Length == 0)
        {
            throw new PsignException("Azure Key Vault certificate name must not be empty");
        }

        var uri = ParseHierarchical(baseUrl, "invalid vault URL", "vault URL must be hierarchical https");
        var segments = new List<string> { "certificates", name };
        if (certVersion?.Trim() is { Length: > 0 } v)
        {
            segments.Add(v);
        }

        return HttpText.AppendQueryPair(AppendSegments(uri, segments, popIfEmpty: false), "api-version", ApiVersion);
    }

    /// <summary>Build <c>…/keys/…/versions/…/sign?api-version=7.4</c> from a certificate <c>kid</c> (Rust <c>kv_sign_url_from_kid</c>).</summary>
    public static string SignUrlFromKid(string kid)
    {
        var uri = ParseHierarchical(kid.Trim(), "invalid certificate kid URL", "kid URL cannot be a base");
        return HttpText.AppendQueryPair(AppendSegments(uri, ["sign"], popIfEmpty: true), "api-version", ApiVersion);
    }

    private static Uri ParseHierarchical(string text, string invalidContext, string notBaseMessage)
    {
        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri))
        {
            throw new PsignException($"{invalidContext}: relative URL without a base");
        }

        if (string.IsNullOrEmpty(uri.Host) && !uri.IsFile)
        {
            throw new PsignException(notBaseMessage);
        }

        return uri;
    }

    private static string AppendSegments(Uri uri, IEnumerable<string> segments, bool popIfEmpty)
    {
        var path = uri.AbsolutePath;
        if (popIfEmpty && path.Length > 1 && path.EndsWith('/'))
        {
            path = path[..^1];
        }

        if (path == "/")
        {
            path = string.Empty;
        }

        var sb = new StringBuilder(uri.GetLeftPart(UriPartial.Authority)).Append(path);
        foreach (var s in segments)
        {
            sb.Append('/').Append(HttpText.EncodePathSegment(s));
        }

        sb.Append(uri.Query);
        sb.Append(uri.Fragment);
        return sb.ToString();
    }

    /// <summary>Decode the standard base64 <c>cer</c> field (Rust <c>kv_decode_cer_b64</c>).</summary>
    public static byte[] DecodeCerBase64(string cerB64)
    {
        try
        {
            return Base64Standard.Decode(cerB64.Trim());
        }
        catch (FormatException e)
        {
            throw new PsignException("decode certificate cer (base64)", e);
        }
    }

    /// <summary>Public-key family of a DER certificate (Rust <c>kv_public_key_kind_from_cer_der</c>).</summary>
    public static KvPublicKeyKind PublicKeyKindFromCerDer(byte[] cerDer)
    {
        CertificateInfo cert;
        try
        {
            cert = CertificateInfo.Parse(cerDer);
        }
        catch (PsignException e)
        {
            throw new PsignException($"certificate DER (public key): {e.Message}", e);
        }

        return cert.PublicKeyAlgorithm.Oid switch
        {
            "1.2.840.113549.1.1.1" => KvPublicKeyKind.Rsa,
            "1.2.840.10045.2.1" => KvPublicKeyKind.Ec,
            var other => throw new PsignException($"Key Vault signing is not implemented for certificate public key OID {other}"),
        };
    }

    /// <summary>JWS algorithm name (Rust <c>kv_jws_alg</c>).</summary>
    public static string JwsAlg(KvPublicKeyKind kind, KvHashAlg hash) => (kind, hash) switch
    {
        (KvPublicKeyKind.Rsa, KvHashAlg.Sha256) => "RS256",
        (KvPublicKeyKind.Rsa, KvHashAlg.Sha384) => "RS384",
        (KvPublicKeyKind.Rsa, KvHashAlg.Sha512) => "RS512",
        (KvPublicKeyKind.Ec, KvHashAlg.Sha256) => "ES256",
        (KvPublicKeyKind.Ec, KvHashAlg.Sha384) => "ES384",
        _ => "ES512",
    };

    // ------------------------------------------------------------------ sign

    /// <summary>POST <c>keys/sign</c> (Rust <c>kv_sign_digest</c>).</summary>
    public byte[] SignDigest(string token, string signUrl, string jwsAlg, byte[] digest) =>
        HttpTransport.RunSync(() => SignDigestAsync(token, signUrl, jwsAlg, digest));

    /// <inheritdoc cref="SignDigest"/>
    public async Task<byte[]> SignDigestAsync(string token, string signUrl, string jwsAlg, byte[] digest, CancellationToken cancellationToken = default)
    {
        var body = RustJson.Compact(new JsonObject
        {
            ["alg"] = jwsAlg,
            ["value"] = Base64UrlEncode(digest),
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, signUrl)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        var rsp = await _http.SendAsync(request, TimeSpan.FromSeconds(300), "Key Vault POST sign", cancellationToken).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            throw new PsignException($"Key Vault sign HTTP {rsp.StatusText}: {rsp.Text}");
        }

        var value = HttpTransport.RequiredString(rsp.Body, "value", "Key Vault sign JSON");
        return Base64UrlDecode(value);
    }

    /// <summary>Resolve <c>kid</c>, infer the JWS algorithm from <c>cer</c>, and POST <c>sign</c> (Rust <c>kv_sign_digest_from_certificate</c>).</summary>
    public byte[] SignDigestFromCertificate(string token, KeyVaultCertificate cert, KvHashAlg hash, byte[] digest) =>
        HttpTransport.RunSync(() => SignDigestFromCertificateAsync(token, cert, hash, digest));

    /// <inheritdoc cref="SignDigestFromCertificate"/>
    public Task<byte[]> SignDigestFromCertificateAsync(string token, KeyVaultCertificate cert, KvHashAlg hash, byte[] digest, CancellationToken cancellationToken = default)
    {
        var signUrl = SignUrlFromKid(cert.Kid.Trim());
        var kind = PublicKeyKindFromCerDer(DecodeCerBase64(cert.Cer));
        return SignDigestAsync(token, signUrl, JwsAlg(kind, hash), digest, cancellationToken);
    }

    /// <summary>Base64url without padding.</summary>
    public static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Strict base64url-without-padding decode (Rust <c>URL_SAFE_NO_PAD</c>).</summary>
    public static byte[] Base64UrlDecode(string value)
    {
        var v = value.Trim();
        if (v.Length % 4 == 1 || v.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
        {
            throw new PsignException("signature base64url decode", new PsignException("invalid base64url input"));
        }

        var b64 = v.Replace('-', '+').Replace('_', '/');
        b64 = b64.PadRight(b64.Length + ((4 - (b64.Length % 4)) % 4), '=');
        try
        {
            return Base64Standard.Decode(b64);
        }
        catch (FormatException e)
        {
            throw new PsignException("signature base64url decode", e);
        }
    }

    public void Dispose() => _http.Dispose();
}
