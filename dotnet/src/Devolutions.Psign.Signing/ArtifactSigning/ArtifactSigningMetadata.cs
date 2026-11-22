using System.Text.Json;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Signing.Internal;

namespace Devolutions.Psign.Signing.ArtifactSigning;

/// <summary>
/// Microsoft Artifact Signing metadata JSON (<c>metadata.json</c> / <c>/dmdf</c>): <c>Endpoint</c>,
/// <c>CodeSigningAccountName</c>, <c>CertificateProfileName</c>, optional <c>CorrelationId</c> and
/// <c>ExcludeCredentials</c> (Rust <c>ArtifactSigningMetadataDoc</c>).
/// </summary>
public sealed record ArtifactSigningMetadata(
    string Endpoint,
    string CodeSigningAccountName,
    string CertificateProfileName,
    string? CorrelationId,
    IReadOnlyList<string>? ExcludeCredentials)
{
    private const string ParseContext = "parse Artifact Signing metadata JSON";

    /// <summary>Parse metadata JSON (serde semantics: required string fields, unknown fields ignored).</summary>
    public static ArtifactSigningMetadata Parse(byte[] json)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(json);
        }
        catch (JsonException e)
        {
            throw new PsignException(ParseContext, e);
        }

        if (node is not JsonObject obj)
        {
            throw new PsignException(ParseContext, new PsignException("invalid type: expected struct ArtifactSigningMetadataDoc"));
        }

        return new ArtifactSigningMetadata(
            RequiredString(obj, "Endpoint"),
            RequiredString(obj, "CodeSigningAccountName"),
            RequiredString(obj, "CertificateProfileName"),
            OptionalString(obj, "CorrelationId"),
            OptionalStringArray(obj, "ExcludeCredentials"));
    }

    /// <summary>Read and parse a metadata file.</summary>
    public static ArtifactSigningMetadata Load(string path)
    {
        byte[] raw;
        try
        {
            raw = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read {path}", IoErrorText.Inner(e));
        }

        return Parse(raw);
    }

    /// <summary>
    /// Validate metadata shape without network access (Rust <c>run_artifact_signing_metadata_check</c>); returns the
    /// parsed document.
    /// </summary>
    public static ArtifactSigningMetadata Check(byte[] json)
    {
        if (json.Length == 0)
        {
            throw new PsignException("metadata JSON is empty");
        }

        var doc = Parse(json);
        if (doc.Endpoint.Trim().Length == 0)
        {
            throw new PsignException("Endpoint must be a non-empty string");
        }

        if (doc.CodeSigningAccountName.Trim().Length == 0)
        {
            throw new PsignException("CodeSigningAccountName must be a non-empty string");
        }

        if (doc.CertificateProfileName.Trim().Length == 0)
        {
            throw new PsignException("CertificateProfileName must be a non-empty string");
        }

        if (doc.ExcludeCredentials is { } exclude)
        {
            for (var i = 0; i < exclude.Count; i++)
            {
                if (exclude[i].Trim().Length == 0)
                {
                    throw new PsignException($"ExcludeCredentials[{i}] must be a non-empty string");
                }
            }
        }

        return doc;
    }

    private static string RequiredString(JsonObject obj, string name)
    {
        if (!obj.TryGetPropertyValue(name, out var value))
        {
            throw new PsignException(ParseContext, new PsignException($"missing field `{name}`"));
        }

        return AsString(value, name) ?? throw new PsignException(ParseContext, new PsignException($"invalid type: null, expected a string for `{name}`"));
    }

    private static string? OptionalString(JsonObject obj, string name) =>
        obj.TryGetPropertyValue(name, out var value) ? AsString(value, name) : null;

    private static List<string>? OptionalStringArray(JsonObject obj, string name)
    {
        if (!obj.TryGetPropertyValue(name, out var value) || value is null)
        {
            return null;
        }

        if (value is not JsonArray arr)
        {
            throw new PsignException(ParseContext, new PsignException($"invalid type: expected a sequence for `{name}`"));
        }

        return arr.Select(e => AsString(e, name) ?? throw new PsignException(ParseContext, new PsignException($"invalid type: null, expected a string in `{name}`"))).ToList();
    }

    private static string? AsString(JsonNode? value, string name)
    {
        if (value is null)
        {
            return null;
        }

        if (value is JsonValue v && v.GetValueKind() == JsonValueKind.String)
        {
            return v.GetValue<string>();
        }

        throw new PsignException(ParseContext, new PsignException($"invalid type: {RustJson.Compact(value)}, expected a string for `{name}`"));
    }
}

/// <summary>
/// Artifact Signing command-line style options (Rust <c>ArtifactSigningPortableOptions</c>) and their resolution into
/// <see cref="CodesigningSubmitParams"/> (Rust <c>artifact_signing_params_for_digest</c>).
/// </summary>
public sealed class ArtifactSigningOptions
{
    public string? Metadata { get; set; }

    public string? Region { get; set; }

    public string? Endpoint { get; set; }

    public string? AccountName { get; set; }

    public string? ProfileName { get; set; }

    public string? SignatureAlgorithm { get; set; }

    public string? ApiVersion { get; set; }

    public string? CorrelationId { get; set; }

    public string? AccessToken { get; set; }

    public bool ManagedIdentity { get; set; }

    public string? ManagedIdentityResourceId { get; set; }

    public CodesigningCredentialType? CredentialType { get; set; }

    public string? TenantId { get; set; }

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public string? FederatedTokenFile { get; set; }

    public string? Authority { get; set; }

    public string? EndpointBaseUrl { get; set; }

    /// <summary>Whether any Artifact Signing option is set (Rust <c>artifact_signing_requested</c>).</summary>
    public bool IsRequested =>
        Metadata is not null
        || Present(Region) || Present(Endpoint) || Present(AccountName) || Present(ProfileName) || Present(SignatureAlgorithm)
        || Present(ApiVersion) || Present(CorrelationId) || Present(AccessToken) || ManagedIdentity || Present(ManagedIdentityResourceId)
        || CredentialType is not null || Present(TenantId) || Present(ClientId) || Present(ClientSecret) || Present(FederatedTokenFile)
        || Present(Authority) || Present(EndpointBaseUrl);

    /// <summary>
    /// Build submit parameters for <paramref name="digest"/>: explicit options override metadata JSON; the signature
    /// algorithm defaults to <paramref name="defaultSignatureAlgorithm"/> and the API version to
    /// <see cref="ArtifactSigningClient.DefaultApiVersion"/>.
    /// </summary>
    public CodesigningSubmitParams ToSubmitParams(byte[] digest, string defaultSignatureAlgorithm, Func<string, string?>? environment = null)
    {
        var metadata = Metadata is { } path ? ArtifactSigningMetadata.Load(path) : null;
        var endpoint = Text(EndpointBaseUrl) ?? Text(Endpoint) ?? Text(metadata?.Endpoint);
        var region = Text(Region) ?? "unused";
        var account = Text(AccountName) ?? Text(metadata?.CodeSigningAccountName)
            ?? throw new PsignException("Artifact Signing requires --artifact-signing-account-name or metadata CodeSigningAccountName");
        var profile = Text(ProfileName) ?? Text(metadata?.CertificateProfileName)
            ?? throw new PsignException("Artifact Signing requires --artifact-signing-profile-name or metadata CertificateProfileName");
        var auth = CodesigningAuthResolver.Resolve(
            new CodesigningAuthInput
            {
                AccessToken = Text(AccessToken),
                ManagedIdentity = ManagedIdentity,
                ManagedIdentityResourceId = Text(ManagedIdentityResourceId),
                TenantId = Text(TenantId),
                ClientId = Text(ClientId),
                ClientSecret = Text(ClientSecret),
                FederatedTokenFile = Text(FederatedTokenFile),
                CredentialType = CredentialType,
                ExcludeCredentials = metadata?.ExcludeCredentials?.ToList() ?? [],
            },
            environment);
        return new CodesigningSubmitParams
        {
            Region = region,
            AccountName = account,
            ProfileName = profile,
            Digest = digest,
            SignatureAlgorithm = Text(SignatureAlgorithm) ?? defaultSignatureAlgorithm,
            ApiVersion = Text(ApiVersion) ?? ArtifactSigningClient.DefaultApiVersion,
            CorrelationId = Text(CorrelationId) ?? Text(metadata?.CorrelationId),
            Authority = Text(Authority),
            Auth = auth,
            EndpointBaseUrl = endpoint,
        };
    }

    private static bool Present(string? value) => Text(value) is not null;

    private static string? Text(string? value) => CodesigningAuthResolver.TextOpt(value);
}
