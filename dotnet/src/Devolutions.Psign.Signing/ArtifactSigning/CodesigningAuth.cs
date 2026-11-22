using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.ArtifactSigning;

/// <summary>Authentication mode for <c>codesigning.azure.net</c> (Rust <c>CodesigningAuth</c>).</summary>
public abstract record CodesigningAuth
{
    private CodesigningAuth()
    {
    }

    /// <summary>Managed identity via IMDS (optional user-assigned client id / resource id).</summary>
    public sealed record ManagedIdentity(string? ClientId, string? ResourceId) : CodesigningAuth;

    /// <summary>Pre-acquired bearer access token.</summary>
    public sealed record Bearer(string Token) : CodesigningAuth;

    /// <summary>Service principal client secret.</summary>
    public sealed record ClientCredentials(string TenantId, string ClientId, string ClientSecret) : CodesigningAuth
    {
        /// <summary>Redact the secret from <c>ToString</c>.</summary>
        protected override bool PrintMembers(System.Text.StringBuilder builder)
        {
            builder.Append("TenantId = ").Append(TenantId).Append(", ClientId = ").Append(ClientId).Append(", ClientSecret = ***");
            return true;
        }
    }

    /// <summary>Workload identity federation (client assertion from a federated token file).</summary>
    public sealed record WorkloadIdentity(string TenantId, string ClientId, string FederatedTokenFile) : CodesigningAuth;

    /// <summary>Rust default credential chain: environment client secret, workload identity, then managed identity.</summary>
    public sealed record DefaultChain(IReadOnlyList<string> ExcludeCredentials) : CodesigningAuth
    {
        public bool Equals(DefaultChain? other) => other is not null && ExcludeCredentials.SequenceEqual(other.ExcludeCredentials);

        public override int GetHashCode() => ExcludeCredentials.Count;
    }
}

/// <summary>Explicit Artifact Signing credential type (Rust <c>CodesigningCredentialType</c>).</summary>
public enum CodesigningCredentialType
{
    Default,
    ManagedIdentity,
    AccessToken,
    ClientSecret,
    WorkloadIdentity,
}

/// <summary>Raw credential inputs (Rust <c>CodesigningAuthInput</c>).</summary>
public sealed class CodesigningAuthInput
{
    public string? AccessToken { get; set; }

    public bool ManagedIdentity { get; set; }

    public string? ManagedIdentityResourceId { get; set; }

    public string? TenantId { get; set; }

    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    public string? FederatedTokenFile { get; set; }

    public CodesigningCredentialType? CredentialType { get; set; }

    public List<string> ExcludeCredentials { get; set; } = [];
}

/// <summary>Credential resolution (Rust <c>resolve_codesigning_auth</c>).</summary>
public static class CodesigningAuthResolver
{
    /// <summary>Resolve inputs into a single authentication mode, rejecting ambiguous combinations.</summary>
    public static CodesigningAuth Resolve(CodesigningAuthInput input, Func<string, string?>? environment = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        var token = TextOpt(input.AccessToken);
        var tenant = TextOpt(input.TenantId);
        var client = TextOpt(input.ClientId);
        var secret = TextOpt(input.ClientSecret);
        var federatedTokenFile = TextOpt(input.FederatedTokenFile);
        var resourceId = TextOpt(input.ManagedIdentityResourceId);
        var clientParts = (tenant is null ? 0 : 1) + (client is null ? 0 : 1) + (secret is null ? 0 : 1);

        switch (input.CredentialType ?? CodesigningCredentialType.Default)
        {
            case CodesigningCredentialType.AccessToken:
                if (clientParts != 0 || input.ManagedIdentity || federatedTokenFile is not null)
                {
                    throw new PsignException("Artifact Signing access-token credential cannot be combined with managed identity, workload identity, or client credentials");
                }

                return token is null
                    ? throw new PsignException("Artifact Signing access-token credential requires access-token")
                    : new CodesigningAuth.Bearer(token);

            case CodesigningCredentialType.ClientSecret:
                if (token is not null || input.ManagedIdentity || federatedTokenFile is not null)
                {
                    throw new PsignException("Artifact Signing client-secret credential cannot be combined with access token, managed identity, or workload identity");
                }

                if (clientParts != 3)
                {
                    throw new PsignException("Artifact Signing client-secret credential requires tenant-id, client-id, and client-secret");
                }

                return new CodesigningAuth.ClientCredentials(tenant!, client!, secret!);

            case CodesigningCredentialType.ManagedIdentity:
                if (token is not null || tenant is not null || secret is not null || federatedTokenFile is not null)
                {
                    throw new PsignException("Artifact Signing managed identity credential cannot be combined with access token, tenant/client-secret, or workload identity");
                }

                return new CodesigningAuth.ManagedIdentity(client, resourceId);

            case CodesigningCredentialType.WorkloadIdentity:
                {
                    if (token is not null || secret is not null || input.ManagedIdentity || resourceId is not null)
                    {
                        throw new PsignException("Artifact Signing workload identity credential cannot be combined with access token, client secret, or managed identity");
                    }

                    var tenantId = tenant ?? TextOpt(environment("AZURE_TENANT_ID"))
                        ?? throw new PsignException("Artifact Signing workload identity requires tenant-id or AZURE_TENANT_ID");
                    var clientId = client ?? TextOpt(environment("AZURE_CLIENT_ID"))
                        ?? throw new PsignException("Artifact Signing workload identity requires client-id or AZURE_CLIENT_ID");
                    var tokenFile = federatedTokenFile ?? TextOpt(environment("AZURE_FEDERATED_TOKEN_FILE"))
                        ?? throw new PsignException("Artifact Signing workload identity requires federated-token-file or AZURE_FEDERATED_TOKEN_FILE");
                    return new CodesigningAuth.WorkloadIdentity(tenantId, clientId, tokenFile);
                }

            case CodesigningCredentialType.Default:
                break;
        }

        if (input.ManagedIdentity)
        {
            if (token is not null || tenant is not null || secret is not null || federatedTokenFile is not null)
            {
                throw new PsignException("use either Artifact Signing managed identity, access token, workload identity, or client credentials, not multiple");
            }

            return new CodesigningAuth.ManagedIdentity(client, resourceId);
        }

        if (token is not null)
        {
            if (clientParts != 0 || federatedTokenFile is not null)
            {
                throw new PsignException("use either Artifact Signing access token, workload identity, or client credentials, not multiple");
            }

            return new CodesigningAuth.Bearer(token);
        }

        if (federatedTokenFile is not null)
        {
            if (secret is not null)
            {
                throw new PsignException("use either Artifact Signing workload identity or client credentials, not both");
            }

            if (tenant is null || client is null)
            {
                throw new PsignException("Artifact Signing workload identity requires tenant-id, client-id, and federated-token-file");
            }

            return new CodesigningAuth.WorkloadIdentity(tenant, client, federatedTokenFile);
        }

        if (clientParts is not (0 or 3))
        {
            throw new PsignException("Artifact Signing client credentials require all of tenant-id, client-id, and client-secret");
        }

        if (clientParts == 3)
        {
            return new CodesigningAuth.ClientCredentials(tenant!, client!, secret!);
        }

        return new CodesigningAuth.DefaultChain(input.ExcludeCredentials.ToList());
    }

    /// <summary>Whether <paramref name="names"/> are excluded (case-insensitive, ignoring <c>-</c>, <c>_</c>, spaces).</summary>
    public static bool CredentialExcluded(IEnumerable<string> excludeCredentials, params string[] names) =>
        excludeCredentials.Any(value =>
        {
            var normalized = Normalize(value.Trim());
            return names.Any(n => string.Equals(normalized, Normalize(n), StringComparison.OrdinalIgnoreCase));
        });

    internal static string? TextOpt(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }

    private static string Normalize(string value) => value.Replace("-", string.Empty, StringComparison.Ordinal)
        .Replace("_", string.Empty, StringComparison.Ordinal)
        .Replace(" ", string.Empty, StringComparison.Ordinal);
}
