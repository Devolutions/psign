using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.AzureKeyVault;

/// <summary>
/// <see cref="IDigestSigner"/> backed by Azure Key Vault <c>keys/sign</c> (AzureSignTool-style remote signing step).
/// </summary>
public sealed class AzureKeyVaultDigestSigner : IDigestSigner
{
    private readonly AzureKeyVaultClient _client;
    private readonly string _token;

    public AzureKeyVaultDigestSigner(AzureKeyVaultClient client, string token, KeyVaultCertificate certificate)
    {
        _client = client;
        _token = token;
        KeyVaultCertificate = certificate;
        Certificate = CertificateInfo.Parse(certificate.CerDer);
    }

    /// <summary>Key Vault certificate metadata (<c>kid</c>, <c>cer</c>).</summary>
    public KeyVaultCertificate KeyVaultCertificate { get; }

    /// <summary>Signer certificate decoded from <c>cer</c>.</summary>
    public CertificateInfo Certificate { get; }

    /// <summary>
    /// Acquire a token, fetch the certificate (<paramref name="certificateVersion"/> optional) and create a signer.
    /// </summary>
    public static AzureKeyVaultDigestSigner Create(AzureKeyVaultClient client, string vaultUrl, string certificateName, string? certificateVersion, KvAuthParams auth)
    {
        var token = client.AcquireAccessToken(auth);
        var cert = client.FetchCertificate(vaultUrl, certificateName, certificateVersion, token);
        return new AzureKeyVaultDigestSigner(client, token, cert);
    }

    public byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash) =>
        _client.SignDigestFromCertificate(_token, KeyVaultCertificate, AzureKeyVaultClient.HashAlgFor(hash), digest);
}
