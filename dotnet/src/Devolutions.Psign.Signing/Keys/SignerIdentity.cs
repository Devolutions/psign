using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Keys;

/// <summary>
/// A signing identity: the signer certificate, additional chain certificates to embed, and an <see cref="IDigestSigner"/>
/// that produces the raw signature (local key, Azure Key Vault, Artifact Signing, precomputed signature, ...).
/// </summary>
public sealed class SignerIdentity : IDisposable
{
    private readonly IDisposable? _owned;

    public SignerIdentity(CertificateInfo certificate, IReadOnlyList<CertificateInfo> chain, IDigestSigner signer, IDisposable? owned = null)
    {
        Certificate = certificate;
        Chain = chain;
        Signer = signer;
        _owned = owned;
    }

    /// <summary>Signer certificate.</summary>
    public CertificateInfo Certificate { get; }

    /// <summary>Additional certificates to embed (issuers / roots), excluding the signer certificate.</summary>
    public IReadOnlyList<CertificateInfo> Chain { get; }

    /// <summary>Signature producer.</summary>
    public IDigestSigner Signer { get; }

    /// <summary>Signer identity from a PKCS#12 archive (RSA keys only).</summary>
    public static SignerIdentity FromPfx(byte[] pfx, string password)
    {
        var parsed = Pkcs12Identity.Parse(pfx, password);
        return FromKey(parsed.SignerCertificate, parsed.ChainCertificates, parsed.PrivateKey);
    }

    /// <summary>
    /// Signer identity from certificate bytes (DER / PEM; a PEM bundle's first certificate is the signer and the rest are
    /// chain certificates), RSA private key bytes (PKCS#8 / PKCS#1, DER / PEM) and optional extra chain certificate files.
    /// </summary>
    public static SignerIdentity FromCertificateAndKey(byte[] certificateBytes, byte[] keyBytes, IEnumerable<byte[]>? chainCertificateBytes = null)
    {
        var certs = SigningMaterialLoader.ParseCertificates(certificateBytes);
        var key = SigningMaterialLoader.ParseRsaPrivateKeyMaterial(keyBytes);
        var chain = certs.Skip(1).ToList();
        if (chainCertificateBytes is not null)
        {
            foreach (var extra in chainCertificateBytes)
            {
                chain.AddRange(SigningMaterialLoader.ParseCertificates(extra));
            }
        }

        return FromKey(certs[0], chain, key);
    }

    /// <summary>Signer identity from a parsed certificate and PKCS#8 key; verifies the key matches the certificate.</summary>
    public static SignerIdentity FromKey(CertificateInfo certificate, IEnumerable<CertificateInfo> chain, PrivateKeyMaterial key)
    {
        key.EnsureMatchesCertificate(certificate);
        var rsa = key.CreateRsa();
        return new SignerIdentity(certificate, chain.ToList(), new RsaDigestSigner(rsa), rsa);
    }

    /// <summary>Signer identity backed by an arbitrary (for example remote) digest signer.</summary>
    public static SignerIdentity FromSigner(CertificateInfo certificate, IEnumerable<CertificateInfo> chain, IDigestSigner signer) =>
        new(certificate, chain.ToList(), signer);

    /// <summary>Certificate chain as DER, signer first (Rust <c>SigningProvider::certificate_chain_der</c>).</summary>
    public List<byte[]> CertificateChainDer()
    {
        var list = new List<byte[]> { Certificate.RawData };
        list.AddRange(Chain.Select(c => c.RawData));
        return list;
    }

    public void Dispose() => _owned?.Dispose();
}
