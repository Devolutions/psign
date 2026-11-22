using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.CertStore;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Keys;

namespace Devolutions.Psign.Signing.Providers;

/// <summary>A resolved signer (Rust <c>SigningProvider</c> trait).</summary>
public interface ISigningProvider : IDigestSigner
{
    /// <summary>Provider family.</summary>
    SigningProviderKind Kind { get; }

    /// <summary>Signer certificate first, then chain certificates (DER).</summary>
    IReadOnlyList<byte[]> CertificateChainDer();
}

/// <summary>Secrets and transport needed to instantiate a provider from a <see cref="SigningProviderConfig"/>.</summary>
public sealed class SigningProviderSecrets
{
    /// <summary>PFX password (defaults to empty).</summary>
    public string PfxPassword { get; set; } = string.Empty;

    public string? AzureKeyVaultAccessToken { get; set; }

    public string? AzureKeyVaultClientSecret { get; set; }

    public string? ArtifactSigningAccessToken { get; set; }

    public string? ArtifactSigningClientSecret { get; set; }

    /// <summary>Artifact Signing options not captured by the config (signature algorithm, API version, correlation id, endpoint override).</summary>
    public ArtifactSigningOptions? ArtifactSigningExtra { get; set; }

    /// <summary>Optional HTTP handler for the remote providers (tests).</summary>
    public HttpMessageHandler? HttpHandler { get; set; }

    /// <summary>Environment lookup (defaults to the process environment).</summary>
    public Func<string, string?>? Environment { get; set; }
}

/// <summary>Provider backed by a local key (PFX or portable cert store).</summary>
public sealed class LocalKeySigningProvider : ISigningProvider, IDisposable
{
    public LocalKeySigningProvider(SigningProviderKind kind, SignerIdentity identity)
    {
        Kind = kind;
        Identity = identity;
    }

    public SigningProviderKind Kind { get; }

    public SignerIdentity Identity { get; }

    public IReadOnlyList<byte[]> CertificateChainDer() => Identity.CertificateChainDer();

    public byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash) => Identity.Signer.SignDigest(digest, hash);

    public void Dispose() => Identity.Dispose();
}

/// <summary>Provider backed by Azure Key Vault.</summary>
public sealed class AzureKeyVaultSigningProvider : ISigningProvider, IDisposable
{
    private readonly AzureKeyVaultClient? _ownedClient;

    public AzureKeyVaultSigningProvider(AzureKeyVaultDigestSigner signer, AzureKeyVaultClient? ownedClient = null)
    {
        Signer = signer;
        _ownedClient = ownedClient;
    }

    public SigningProviderKind Kind => SigningProviderKind.AzureKeyVault;

    public AzureKeyVaultDigestSigner Signer { get; }

    public IReadOnlyList<byte[]> CertificateChainDer() => [Signer.Certificate.RawData];

    public byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash) => Signer.SignDigest(digest, hash);

    public void Dispose() => _ownedClient?.Dispose();
}

/// <summary>
/// Provider backed by Azure Artifact Signing. The service issues the signing certificate with each signature, so
/// <see cref="CertificateChainDer"/> is available only after <see cref="SignDigest"/>.
/// </summary>
public sealed class ArtifactSigningSigningProvider : ISigningProvider, IDisposable
{
    private readonly ArtifactSigningClient? _ownedClient;

    public ArtifactSigningSigningProvider(ArtifactSigningDigestSigner signer, ArtifactSigningClient? ownedClient = null)
    {
        Signer = signer;
        _ownedClient = ownedClient;
    }

    public SigningProviderKind Kind => SigningProviderKind.ArtifactSigning;

    public ArtifactSigningDigestSigner Signer { get; }

    public IReadOnlyList<byte[]> CertificateChainDer() =>
        Signer.LastResult is { } r
            ? [r.SigningCertificate]
            : throw new PsignException("Artifact Signing certificate chain is only known after a signing request");

    public byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash) => Signer.SignDigest(digest, hash);

    public void Dispose() => _ownedClient?.Dispose();
}

/// <summary>Instantiates <see cref="ISigningProvider"/>s from a <see cref="SigningProviderConfig"/> (identity resolution).</summary>
public static class SigningProviderFactory
{
    public static ISigningProvider Create(SigningProviderConfig config, SigningProviderSecrets? secrets = null)
    {
        secrets ??= new SigningProviderSecrets();
        switch (config.Identity)
        {
            case SigningProviderIdentity.Pfx pfx:
                {
                    byte[] bytes;
                    try
                    {
                        bytes = File.ReadAllBytes(pfx.PfxPath);
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    {
                        throw new PsignException($"read PFX '{pfx.PfxPath}'", e);
                    }

                    return new LocalKeySigningProvider(SigningProviderKind.Pfx, SignerIdentity.FromPfx(bytes, secrets.PfxPassword));
                }

            case SigningProviderIdentity.PortableStore store:
                {
                    var identity = new PortableCertStore(secrets.Environment)
                        .ResolveSigningIdentity(store.CertStoreDir, store.MachineStore, store.StoreName, store.ThumbprintSha1);
                    return new LocalKeySigningProvider(SigningProviderKind.PortableStore, identity.ToSignerIdentity());
                }

            case SigningProviderIdentity.WindowsStore:
                throw new PsignException("Windows certificate store selection (/a, /n, /i) is not available in the portable C# implementation; use --sha1 with the portable cert store or --pfx");

            case SigningProviderIdentity.AzureKeyVault kv:
                {
                    var client = new AzureKeyVaultClient(secrets.HttpHandler);
                    try
                    {
                        var auth = new KvAuthParams
                        {
                            Authority = kv.Auth.Authority,
                            AccessToken = kv.Auth is AzureAuthConfig.AccessToken ? secrets.AzureKeyVaultAccessToken ?? string.Empty : null,
                            ManagedIdentity = kv.Auth is AzureAuthConfig.ManagedIdentity,
                            TenantId = (kv.Auth as AzureAuthConfig.ClientSecret)?.TenantId,
                            ClientId = (kv.Auth as AzureAuthConfig.ClientSecret)?.ClientId,
                            ClientSecret = secrets.AzureKeyVaultClientSecret,
                        };
                        var signer = AzureKeyVaultDigestSigner.Create(client, kv.VaultUrl, kv.Certificate, kv.CertificateVersion, auth);
                        return new AzureKeyVaultSigningProvider(signer, client);
                    }
                    catch
                    {
                        client.Dispose();
                        throw;
                    }
                }

            case SigningProviderIdentity.ArtifactSigning a:
                {
                    var extra = secrets.ArtifactSigningExtra ?? new ArtifactSigningOptions();
                    var options = new ArtifactSigningOptions
                    {
                        Metadata = a.Metadata,
                        Endpoint = a.Endpoint,
                        Region = a.Region,
                        AccountName = a.AccountName,
                        ProfileName = a.ProfileName,
                        SignatureAlgorithm = extra.SignatureAlgorithm,
                        ApiVersion = extra.ApiVersion,
                        CorrelationId = extra.CorrelationId,
                        EndpointBaseUrl = extra.EndpointBaseUrl,
                        Authority = a.Auth.Authority,
                        AccessToken = secrets.ArtifactSigningAccessToken,
                        ClientSecret = secrets.ArtifactSigningClientSecret,
                    };
                    switch (a.Auth)
                    {
                        case AzureAuthConfig.AccessToken:
                            options.CredentialType = CodesigningCredentialType.AccessToken;
                            break;
                        case AzureAuthConfig.ClientSecret cs:
                            options.CredentialType = CodesigningCredentialType.ClientSecret;
                            options.TenantId = cs.TenantId;
                            options.ClientId = cs.ClientId;
                            break;
                        case AzureAuthConfig.ManagedIdentity mi:
                            options.CredentialType = CodesigningCredentialType.ManagedIdentity;
                            options.ClientId = mi.ClientId;
                            options.ManagedIdentityResourceId = mi.ResourceId;
                            break;
                        case AzureAuthConfig.WorkloadIdentity wi:
                            options.CredentialType = CodesigningCredentialType.WorkloadIdentity;
                            options.TenantId = wi.TenantId;
                            options.ClientId = wi.ClientId;
                            options.FederatedTokenFile = wi.FederatedTokenFile;
                            break;
                    }

                    var kind = AuthenticodeHashKinds.Parse(config.DigestAlgorithm);
                    var template = options.ToSubmitParams([], ArtifactSigningClient.SignatureAlgorithmForDigest(kind), secrets.Environment);
                    var client = new ArtifactSigningClient(secrets.HttpHandler, secrets.Environment);
                    var explicitAlg = CodesigningAuthResolver.TextOpt(extra.SignatureAlgorithm);
                    return new ArtifactSigningSigningProvider(new ArtifactSigningDigestSigner(client, template, explicitAlg), client);
                }

            default:
                throw new PsignException("unsupported signing provider");
        }
    }

    /// <summary>Signer certificate of a local-key provider (convenience for callers building PKCS#7).</summary>
    public static CertificateInfo SignerCertificate(ISigningProvider provider) => CertificateInfo.Parse(provider.CertificateChainDer()[0]);
}
