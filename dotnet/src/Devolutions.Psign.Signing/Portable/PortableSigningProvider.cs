using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Portable;

/// <summary>
/// Signing backend selected by a <see cref="PortableSignRequest"/> (Rust portable-core <c>SigningProvider</c>): a local
/// RSA key (PFX or certificate + key), Azure Key Vault, or Azure Artifact Signing. Remote providers learn the signer
/// certificate only when signing, so they sign the signed-attributes prehash and assemble the CMS afterwards.
/// </summary>
internal abstract class PortableSigningProvider : IDisposable
{
    /// <summary>Authenticode <c>SignedData</c> over <paramref name="indirect"/>.</summary>
    public abstract byte[] CreateAuthenticodePkcs7(SpcIndirectDataContent indirect, AuthenticodeHashKind digest);

    /// <summary>
    /// NuGet author signature: <c>id-data</c> CMS embedding the signature content. Local keys add the NuGet author
    /// attributes (signing time, commitment type, signing-certificate-v2); remote signers keep the basic attribute set.
    /// </summary>
    public abstract byte[] CreateNuGetAuthorSignature(byte[] content, AuthenticodeHashKind digest, DateTimeOffset signingTime);

    /// <summary>Generic CMS <c>SignedData</c> with basic signed attributes.</summary>
    public abstract byte[] CreatePkcs7SignedData(string econtentType, byte[] econtentDer, AuthenticodeHashKind digest, Pkcs7ContentMode contentMode);

    /// <summary>RSA PKCS#1 v1.5 signature over XMLDSig <c>SignedInfo</c> octets and the signer certificate DER.</summary>
    public abstract (byte[] Signature, byte[] CertificateDer) SignXmlSignedInfo(VsixHashAlgorithm algorithm, byte[] signedInfo);

    public virtual void Dispose()
    {
    }
}

/// <summary>Local RSA key (Rust <c>LocalSigningProvider</c>).</summary>
internal sealed class LocalPortableSigningProvider : PortableSigningProvider
{
    private readonly RSA _key;

    public LocalPortableSigningProvider(CertificateInfo signerCert, RSA key, List<CertificateInfo> chain)
    {
        SignerCert = signerCert;
        _key = key;
        Chain = chain;
    }

    public CertificateInfo SignerCert { get; }

    public List<CertificateInfo> Chain { get; }

    public override byte[] CreateAuthenticodePkcs7(SpcIndirectDataContent indirect, AuthenticodeHashKind digest) =>
        Pkcs7Builder.CreateAuthenticode(indirect, digest, SignerCert, Chain, new RsaDigestSigner(_key));

    public override byte[] CreateNuGetAuthorSignature(byte[] content, AuthenticodeHashKind digest, DateTimeOffset signingTime) =>
        Pkcs7IdData.Sign(content, SignerCert, Chain, new RsaDigestSigner(_key), digest, Pkcs7ContentMode.Attached, Pkcs7SignedAttributeProfile.NuGetAuthor, signingTime);

    public override byte[] CreatePkcs7SignedData(string econtentType, byte[] econtentDer, AuthenticodeHashKind digest, Pkcs7ContentMode contentMode) =>
        Pkcs7Builder.CreateSignedData(econtentType, econtentDer, digest, SignerCert, Chain, new RsaDigestSigner(_key), contentMode);

    public override (byte[] Signature, byte[] CertificateDer) SignXmlSignedInfo(VsixHashAlgorithm algorithm, byte[] signedInfo) =>
        (_key.SignData(signedInfo, algorithm.ToHashKind().HashAlgorithmName(), RSASignaturePadding.Pkcs1), SignerCert.RawData);

    public override void Dispose() => _key.Dispose();
}

/// <summary>A remote signature and the certificates the remote signer reported.</summary>
internal sealed record RemoteSignature(byte[] Signature, CertificateInfo SignerCert, List<CertificateInfo> Chain);

/// <summary>Remote signer base: prehash → remote signature → CMS assembly.</summary>
internal abstract class RemotePortableSigningProvider : PortableSigningProvider
{
    public abstract RemoteSignature SignRemoteDigest(AuthenticodeHashKind digest, byte[] prehash);

    public override byte[] CreateAuthenticodePkcs7(SpcIndirectDataContent indirect, AuthenticodeHashKind digest)
    {
        var prehash = Pkcs7Builder.AuthenticodeRemoteSignedAttributesDigest(indirect, digest);
        var signed = SignRemoteDigest(digest, prehash);
        return Pkcs7Builder.CreateAuthenticodeWithSignature(indirect, digest, signed.SignerCert, signed.Chain, signed.Signature);
    }

    public override byte[] CreateNuGetAuthorSignature(byte[] content, AuthenticodeHashKind digest, DateTimeOffset signingTime) =>
        CreatePkcs7SignedData(Oids.Pkcs7Data, Pkcs7IdData.EContentDer(content), digest, Pkcs7ContentMode.Attached);

    public override byte[] CreatePkcs7SignedData(string econtentType, byte[] econtentDer, AuthenticodeHashKind digest, Pkcs7ContentMode contentMode)
    {
        var prehash = Pkcs7Builder.RemoteSignedAttributesDigest(econtentType, econtentDer, digest);
        var signed = SignRemoteDigest(digest, prehash);
        return Pkcs7Builder.CreateSignedData(econtentType, econtentDer, digest, signed.SignerCert, signed.Chain, new PrecomputedDigestSigner(signed.Signature), contentMode);
    }

    public override (byte[] Signature, byte[] CertificateDer) SignXmlSignedInfo(VsixHashAlgorithm algorithm, byte[] signedInfo)
    {
        var digest = algorithm.ToHashKind();
        var signed = SignRemoteDigest(digest, algorithm.Hash(signedInfo));
        return (signed.Signature, signed.SignerCert.RawData);
    }
}

/// <summary>Azure Key Vault <c>keys/sign</c> (Rust <c>AzureKeyVaultSigningProvider</c>).</summary>
internal sealed class AzureKeyVaultPortableSigningProvider : RemotePortableSigningProvider
{
    private readonly AzureKeyVaultClient _client;
    private readonly string _token;
    private readonly KeyVaultCertificate _certificate;
    private readonly CertificateInfo _signerCert;
    private readonly List<CertificateInfo> _chain;

    public AzureKeyVaultPortableSigningProvider(AzureKeyVaultClient client, string token, KeyVaultCertificate certificate, CertificateInfo signerCert, List<CertificateInfo> chain)
    {
        _client = client;
        _token = token;
        _certificate = certificate;
        _signerCert = signerCert;
        _chain = chain;
    }

    public override RemoteSignature SignRemoteDigest(AuthenticodeHashKind digest, byte[] prehash)
    {
        var signature = _client.SignDigestFromCertificate(_token, _certificate, AzureKeyVaultClient.HashAlgFor(digest), prehash);
        return new RemoteSignature(signature, _signerCert, [.. _chain]);
    }

    public override void Dispose() => _client.Dispose();
}

/// <summary>Azure Artifact Signing <c>:sign</c> (Rust <c>ArtifactSigningProvider</c>).</summary>
internal sealed class ArtifactSigningPortableSigningProvider : RemotePortableSigningProvider
{
    private readonly ArtifactSigningClient _client;
    private readonly CodesigningSubmitParams _template;
    private readonly List<CertificateInfo> _chain;
    private readonly Action<string>? _debug;

    public ArtifactSigningPortableSigningProvider(ArtifactSigningClient client, CodesigningSubmitParams template, List<CertificateInfo> chain, Action<string>? debug)
    {
        _client = client;
        _template = template;
        _chain = chain;
        _debug = debug;
    }

    public override RemoteSignature SignRemoteDigest(AuthenticodeHashKind digest, byte[] prehash)
    {
        var p = _template.WithDigest(prehash, ArtifactSigningClient.SignatureAlgorithmForDigest(digest));
        var signed = _client.SubmitCodesignHashSignature(p, _debug);
        var (signer, returnedChain) = ArtifactSigningCertificates.Parse(signed.SigningCertificate);
        returnedChain.AddRange(_chain);
        return new RemoteSignature(signed.Signature, signer, returnedChain);
    }

    public override void Dispose() => _client.Dispose();
}
