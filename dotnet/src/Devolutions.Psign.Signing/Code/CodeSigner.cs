using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.CertStore;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Keys;

namespace Devolutions.Psign.Signing.Code;

/// <summary>Result of a remote digest signature (Rust <c>RemoteCodeSignature</c>).</summary>
internal sealed record RemoteCodeSignature(byte[] Signature, byte[] SignerCertDer, CertificateInfo SignerCert, List<CertificateInfo> Chain);

/// <summary>
/// Signer used by the <c>code</c> orchestrator (Rust <c>CodeSigner</c>): local certificate + RSA key material (from
/// <c>--cert</c>/<c>--key</c> files, a PFX or the portable cert store), Azure Key Vault, or Artifact Signing.
/// </summary>
internal sealed class CodeSigner : IDisposable
{
    private readonly LocalMaterial? _local;
    private readonly AkvBackend? _akv;
    private readonly ArtifactBackend? _artifact;

    private CodeSigner(LocalMaterial? local, AkvBackend? akv, ArtifactBackend? artifact, List<CertificateInfo> chainCerts)
    {
        _local = local;
        _akv = akv;
        _artifact = artifact;
        ChainCerts = chainCerts;
    }

    /// <summary>Signer-scoped chain certificates (PFX chain + <c>--chain-cert</c>).</summary>
    public List<CertificateInfo> ChainCerts { get; }

    /// <summary>
    /// Local signer material read on every use like the Rust signer (which re-reads its certificate / key paths), so
    /// file errors surface with the same context during execution.
    /// </summary>
    private sealed class LocalMaterial
    {
        private readonly byte[]? _certBytes;
        private readonly byte[]? _keyBytes;

        public LocalMaterial(string certLabel, string keyLabel, byte[]? certBytes = null, byte[]? keyBytes = null)
        {
            CertLabel = certLabel;
            KeyLabel = keyLabel;
            _certBytes = certBytes;
            _keyBytes = keyBytes;
        }

        public string CertLabel { get; }

        public string KeyLabel { get; }

        public byte[] ReadCert() => _certBytes ?? RustIo.Read(CertLabel, $"read {CertLabel}");

        public byte[] ReadKey() => _keyBytes ?? RustIo.Read(KeyLabel, $"read {KeyLabel}");
    }

    private sealed record AkvBackend(AzureKeyVaultClient Client, string Token, KeyVaultCertificate Certificate, byte[] CertDer);

    private sealed record ArtifactBackend(ArtifactSigningClient Client, ArtifactSigningOptions Options, Func<string, string?>? Environment);

    // ------------------------------------------------------------------ resolution

    /// <summary>Rust <c>resolve_code_signer</c>.</summary>
    public static CodeSigner Resolve(CodeOptions o)
    {
        bool localFiles = o.Cert is not null || o.Key is not null;
        bool pfx = o.Pfx is not null;
        bool portableStore = o.CertSha1 is { } s && s.Trim().Length > 0;
        bool azureKeyVault = AzureKeyVaultRequested(o);
        bool artifactSigning = ArtifactSigningRequested(o);
        int providers = (localFiles ? 1 : 0) + (pfx ? 1 : 0) + (portableStore ? 1 : 0) + (azureKeyVault ? 1 : 0) + (artifactSigning ? 1 : 0);
        if (providers != 1)
        {
            throw new PsignException("`psign-tool code` signing execution requires exactly one signer: --cert/--key, --pfx, --sha1, Azure Key Vault, or Artifact Signing");
        }

        var cliChain = LoadChainCerts(o.ChainCerts);
        if (localFiles)
        {
            var cert = o.Cert ?? throw new PsignException("`psign-tool code` signing execution requires --cert with --key");
            var key = o.Key ?? throw new PsignException("`psign-tool code` signing execution requires --key with --cert");
            return new CodeSigner(new LocalMaterial(cert, key), null, null, cliChain);
        }

        if (o.Pfx is { } pfxPath)
        {
            byte[] bytes;
            try
            {
                bytes = File.ReadAllBytes(pfxPath);
            }
            catch (Exception e) when (RustIo.IsIo(e))
            {
                throw new PsignException($"read PFX '{pfxPath}'", new PsignException(RustIo.Message(e)));
            }

            ParsedPfxIdentity parsed;
            try
            {
                parsed = Pkcs12Identity.Parse(bytes, o.Password ?? string.Empty);
            }
            catch (Exception e) when (e is PsignException or CryptographicException or System.Formats.Asn1.AsnContentException)
            {
                throw new PsignException($"extract signer identity from PFX '{pfxPath}'", e);
            }

            var chain = new List<CertificateInfo>();
            for (int i = 0; i < parsed.ChainCertificatesDer.Count; i++)
            {
                try
                {
                    chain.Add(SigningMaterialLoader.ParseCertificate(parsed.ChainCertificatesDer[i]));
                }
                catch (PsignException e)
                {
                    throw new PsignException($"parse PFX chain certificate[{i}]", e);
                }
            }

            chain.AddRange(cliChain);
            return new CodeSigner(
                new LocalMaterial("signer.der", "signer.key", parsed.SignerCertificateDer, Encoding.ASCII.GetBytes(parsed.PrivateKeyPem)),
                null,
                null,
                chain);
        }

        if (portableStore)
        {
            var identity = new PortableCertStore(o.Environment).ResolveSigningIdentity(o.CertStoreDir, o.MachineStore, o.StoreName, o.CertSha1!);
            return new CodeSigner(new LocalMaterial(identity.CertPath, identity.KeyPath, identity.CertDer, identity.KeyPem), null, null, cliChain);
        }

        if (azureKeyVault)
        {
            return ResolveAzureKeyVault(o, cliChain);
        }

        return ResolveArtifactSigning(o, cliChain);
    }

    private static CodeSigner ResolveAzureKeyVault(CodeOptions o, List<CertificateInfo> chain)
    {
        if (o.AzureKeyVaultCredentialType == CodeAzureCredentialType.WorkloadIdentity)
        {
            throw new PsignException("`psign-tool code` Azure Key Vault execution does not support workload identity yet");
        }

        var vaultUrl = RequiredText("--azure-key-vault-url", o.AzureKeyVaultUrl);
        var certificateName = RequiredText("--azure-key-vault-certificate", o.AzureKeyVaultCertificate);
        var auth = new KvAuthParams
        {
            AccessToken = o.AzureKeyVaultAccessToken,
            ManagedIdentity = o.AzureKeyVaultManagedIdentity || o.AzureKeyVaultCredentialType == CodeAzureCredentialType.ManagedIdentity,
            TenantId = o.AzureKeyVaultTenantId,
            ClientId = o.AzureKeyVaultClientId,
            ClientSecret = o.AzureKeyVaultClientSecret,
            Authority = o.AzureAuthority,
        };
        var client = new AzureKeyVaultClient(o.HttpHandler);
        try
        {
            var token = client.AcquireAccessToken(auth);
            var certificate = client.FetchCertificate(vaultUrl, certificateName, o.AzureKeyVaultCertificateVersion, token);
            var certDer = AzureKeyVaultClient.DecodeCerBase64(certificate.Cer);
            if (AzureKeyVaultClient.PublicKeyKindFromCerDer(certDer) != KvPublicKeyKind.Rsa)
            {
                throw new PsignException("`psign-tool code` Azure Key Vault package orchestration requires an RSA signing certificate");
            }

            return new CodeSigner(null, new AkvBackend(client, token, certificate, certDer), null, chain);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static CodeSigner ResolveArtifactSigning(CodeOptions o, List<CertificateInfo> chain)
    {
        var options = new ArtifactSigningOptions
        {
            Metadata = o.ArtifactSigningMetadata,
            Region = o.ArtifactSigningRegion,
            Endpoint = o.ArtifactSigningEndpoint,
            AccountName = o.ArtifactSigningAccountName,
            ProfileName = o.ArtifactSigningProfileName,
            SignatureAlgorithm = o.ArtifactSigningSignatureAlgorithm,
            ApiVersion = o.ArtifactSigningApiVersion,
            CorrelationId = o.ArtifactSigningCorrelationId,
            AccessToken = o.ArtifactSigningAccessToken,
            ManagedIdentity = o.ArtifactSigningManagedIdentity || o.ArtifactSigningCredentialType == CodeAzureCredentialType.ManagedIdentity,
            ManagedIdentityResourceId = o.ArtifactSigningManagedIdentityResourceId,
            CredentialType = o.ArtifactSigningCredentialType switch
            {
                null => null,
                CodeAzureCredentialType.Default => CodesigningCredentialType.Default,
                CodeAzureCredentialType.ManagedIdentity => CodesigningCredentialType.ManagedIdentity,
                CodeAzureCredentialType.AccessToken => CodesigningCredentialType.AccessToken,
                CodeAzureCredentialType.ClientSecret => CodesigningCredentialType.ClientSecret,
                _ => CodesigningCredentialType.WorkloadIdentity,
            },
            TenantId = o.ArtifactSigningTenantId,
            ClientId = o.ArtifactSigningClientId,
            ClientSecret = o.ArtifactSigningClientSecret,
            FederatedTokenFile = o.ArtifactSigningFederatedTokenFile,
            Authority = o.ArtifactSigningAuthority,
            EndpointBaseUrl = o.ArtifactSigningEndpointBaseUrl,
        };
        return new CodeSigner(null, null, new ArtifactBackend(new ArtifactSigningClient(o.HttpHandler, o.Environment), options, o.Environment), chain);
    }

    internal static bool AzureKeyVaultRequested(CodeOptions o) =>
        TextOpt(o.AzureKeyVaultUrl) is not null || TextOpt(o.AzureKeyVaultCertificate) is not null
        || TextOpt(o.AzureKeyVaultCertificateVersion) is not null || TextOpt(o.AzureKeyVaultClientId) is not null
        || TextOpt(o.AzureKeyVaultClientSecret) is not null || TextOpt(o.AzureKeyVaultTenantId) is not null
        || TextOpt(o.AzureKeyVaultAccessToken) is not null || o.AzureKeyVaultManagedIdentity
        || o.AzureKeyVaultCredentialType is not null || TextOpt(o.AzureAuthority) is not null;

    internal static bool ArtifactSigningRequested(CodeOptions o) =>
        o.ArtifactSigningMetadata is not null || TextOpt(o.ArtifactSigningRegion) is not null
        || TextOpt(o.ArtifactSigningEndpoint) is not null || TextOpt(o.ArtifactSigningAccountName) is not null
        || TextOpt(o.ArtifactSigningProfileName) is not null || TextOpt(o.ArtifactSigningSignatureAlgorithm) is not null
        || TextOpt(o.ArtifactSigningApiVersion) is not null || TextOpt(o.ArtifactSigningCorrelationId) is not null
        || TextOpt(o.ArtifactSigningAccessToken) is not null || o.ArtifactSigningManagedIdentity
        || TextOpt(o.ArtifactSigningManagedIdentityResourceId) is not null || o.ArtifactSigningCredentialType is not null
        || TextOpt(o.ArtifactSigningTenantId) is not null || TextOpt(o.ArtifactSigningClientId) is not null
        || TextOpt(o.ArtifactSigningClientSecret) is not null || TextOpt(o.ArtifactSigningFederatedTokenFile) is not null
        || TextOpt(o.ArtifactSigningAuthority) is not null || TextOpt(o.ArtifactSigningEndpointBaseUrl) is not null;

    private static string RequiredText(string name, string? value) =>
        TextOpt(value) ?? throw new PsignException($"{name} is required for the selected signing provider");

    private static string? TextOpt(string? value) => value?.Trim() is { Length: > 0 } t ? t : null;

    /// <summary>Rust <c>load_chain_certs</c>.</summary>
    internal static List<CertificateInfo> LoadChainCerts(IEnumerable<string> paths)
    {
        var chain = new List<CertificateInfo>();
        foreach (var path in paths)
        {
            var bytes = RustIo.Read(path, $"read {path}");
            try
            {
                chain.Add(SigningMaterialLoader.ParseCertificate(bytes));
            }
            catch (PsignException e)
            {
                throw new PsignException($"parse chain certificate {path}", e);
            }
        }

        return chain;
    }

    // ------------------------------------------------------------------ CMS

    /// <summary>Generic CMS over <paramref name="econtentDer"/> (Rust <c>CodeSigner::sign_pkcs7</c>).</summary>
    public byte[] SignPkcs7(
        string econtentType,
        byte[] econtentDer,
        AuthenticodeHashKind digest,
        List<CertificateInfo> chain,
        Pkcs7ContentMode contentMode,
        Pkcs7SignedAttributeProfile profile)
    {
        if (_local is { } local)
        {
            var certBytes = local.ReadCert();
            var signerCert = ParseSignerCertificate(certBytes, local.CertLabel);
            var keyBytes = local.ReadKey();
            using var key = ParseKey(keyBytes, local.KeyLabel);
            var attrs = Pkcs7Builder.SignedAttributes(econtentType, econtentDer, digest, profile, signerCert);
            var prehash = Pkcs7Builder.SignedAttributesDigest(attrs, digest);
            var signature = key.SignHash(prehash, digest.HashAlgorithmName(), RSASignaturePadding.Pkcs1);
            var fullChain = new List<CertificateInfo>(ChainCerts);
            fullChain.AddRange(chain);
            return Pkcs7Builder.CreateSignedData(econtentType, econtentDer, digest, signerCert, fullChain, new PrecomputedDigestSigner(signature), contentMode, attrs);
        }

        return SignPkcs7Remote(econtentType, econtentDer, digest, chain, contentMode, profile);
    }

    private byte[] SignPkcs7Remote(
        string econtentType,
        byte[] econtentDer,
        AuthenticodeHashKind digest,
        List<CertificateInfo> chain,
        Pkcs7ContentMode contentMode,
        Pkcs7SignedAttributeProfile profile)
    {
        CertificateInfo? hint = null;
        if (profile != Pkcs7SignedAttributeProfile.Basic)
        {
            hint = RemoteSignerCertificateHint() ?? ProbeRemoteSignerCertificate(digest);
        }

        for (int attempt = 0; attempt < 2; attempt++)
        {
            var attrs = Pkcs7Builder.SignedAttributes(econtentType, econtentDer, digest, profile, hint);
            var prehash = Pkcs7Builder.SignedAttributesDigest(attrs, digest);
            var remote = SignRemoteDigest(digest, prehash);
            if (hint is not null && !hint.Equals(remote.SignerCert))
            {
                if (attempt == 0)
                {
                    hint = remote.SignerCert;
                    continue;
                }

                throw new PsignException("remote signer certificate changed while building NuGet signing-certificate-v2");
            }

            var fullChain = new List<CertificateInfo>(remote.Chain);
            fullChain.AddRange(ChainCerts);
            fullChain.AddRange(chain);
            return Pkcs7Builder.CreateSignedData(econtentType, econtentDer, digest, remote.SignerCert, fullChain, new PrecomputedDigestSigner(remote.Signature), contentMode, attrs);
        }

        throw new InvalidOperationException("remote PKCS#7 signing loop returns or errors");
    }

    private CertificateInfo ProbeRemoteSignerCertificate(AuthenticodeHashKind digest) =>
        SignRemoteDigest(digest, new byte[digest.DigestLength()]).SignerCert;

    private CertificateInfo? RemoteSignerCertificateHint()
    {
        if (_akv is { } akv)
        {
            try
            {
                return SigningMaterialLoader.ParseCertificate(akv.CertDer);
            }
            catch (PsignException e)
            {
                throw new PsignException("parse Azure Key Vault signer certificate", e);
            }
        }

        return null;
    }

    // ------------------------------------------------------------------ XMLDSig

    /// <summary>RSA signature over XMLDSig <c>SignedInfo</c> plus the signer certificate bytes (Rust <c>sign_xml_signed_info</c>).</summary>
    public (byte[] Signature, byte[] CertBytes) SignXmlSignedInfo(AuthenticodeHashKind algorithm, byte[] signedInfo)
    {
        if (_local is { } local)
        {
            var certBytes = local.ReadCert();
            var keyBytes = local.ReadKey();
            using var key = ParseKey(keyBytes, local.KeyLabel);
            return (key.SignData(signedInfo, algorithm.HashAlgorithmName(), RSASignaturePadding.Pkcs1), certBytes);
        }

        var remote = SignRemoteDigest(algorithm, algorithm.Hash(signedInfo));
        return (remote.Signature, remote.SignerCertDer);
    }

    // ------------------------------------------------------------------ PE

    /// <summary>Embed an Authenticode signature into a PE image (Rust <c>CodeSigner::sign_pe_bytes</c>).</summary>
    public byte[] SignPeBytes(byte[] input, AuthenticodeHashKind digest)
    {
        if (_local is { } local)
        {
            var certBytes = local.ReadCert();
            var keyBytes = local.ReadKey();
            if (ChainCerts.Count == 0)
            {
                return SignPeImageRsaSha256(input, certBytes, keyBytes);
            }

            var preparedLocal = Ctx("prepare PE certificate table alignment", () => PeEmbed.PrepareForAuthenticodeSigning(input));
            var signerCert = ParseSignerCertificate(certBytes, local.CertLabel);
            using var key = ParseKey(keyBytes, local.KeyLabel);
            var indirectLocal = SpcIndirectDataContent.ForPe(digest, PeAuthenticode.Digest(preparedLocal, digest));
            var pkcs7Local = Pkcs7Builder.CreateAuthenticode(indirectLocal, digest, signerCert, ChainCerts, key);
            return Ctx("embed Authenticode PKCS#7", () => PeEmbed.AppendPkcs7Certificate(preparedLocal, pkcs7Local));
        }

        var prepared = Ctx("prepare PE certificate table alignment", () => PeEmbed.PrepareForAuthenticodeSigning(input));
        var peDigest = Ctx("compute PE/WinMD Authenticode digest", () => PeAuthenticode.Digest(prepared, digest));
        var indirect = SpcIndirectDataContent.ForPe(digest, peDigest);
        var prehash = Pkcs7Builder.AuthenticodeRemoteSignedAttributesDigest(indirect, digest);
        var remote = SignRemoteDigest(digest, prehash);
        var fullChain = new List<CertificateInfo>(remote.Chain);
        fullChain.AddRange(ChainCerts);
        var pkcs7 = Pkcs7Builder.CreateAuthenticodeWithSignature(indirect, digest, remote.SignerCert, fullChain, remote.Signature);
        return Ctx("embed Authenticode PKCS#7", () => PeEmbed.AppendPkcs7Certificate(prepared, pkcs7));
    }

    /// <summary>
    /// Port of Rust <c>pe_sign::sign_pe_image_rsa_sha256</c> (RustCrypto <c>cms</c> builder profile): SHA-256 PE digest,
    /// signed attributes <c>contentType</c> + <c>messageDigest</c> only, <c>sha256WithRSAEncryption</c> signature algorithm,
    /// signer certificate only.
    /// </summary>
    internal static byte[] SignPeImageRsaSha256(byte[] image, byte[] certBytes, byte[] keyBytes)
    {
        var prepared = Ctx("prepare PE certificate table alignment", () => PeEmbed.PrepareForAuthenticodeSigning(image));
        var digest = Ctx("compute PE Authenticode SHA-256 digest", () => PeAuthenticode.Digest(prepared, AuthenticodeHashKind.Sha256));
        var pkcs7 = BuildPeAuthenticodePkcs7RsaSha256(digest, certBytes, keyBytes);
        return Ctx("embed Authenticode PKCS#7", () => PeEmbed.AppendPkcs7Certificate(prepared, pkcs7));
    }

    /// <summary>Rust <c>pe_sign::build_pe_authenticode_pkcs7_rsa_sha256</c>.</summary>
    internal static byte[] BuildPeAuthenticodePkcs7RsaSha256(byte[] peDigestSha256, byte[] certBytes, byte[] keyBytes)
    {
        if (peDigestSha256.Length != 32)
        {
            throw new PsignException($"PE SHA-256 digest must be 32 bytes, got {peDigestSha256.Length}");
        }

        var signerCert = Ctx("parse signer certificate", () => SigningMaterialLoader.ParseCertificate(certBytes));
        using var key = Ctx("parse RSA private key", () => SigningMaterialLoader.ParseRsaPrivateKey(keyBytes));
        var indirect = SpcIndirectDataContent.ForPe(AuthenticodeHashKind.Sha256, peDigestSha256);
        var econtent = indirect.Encode();
        var attrs = new List<CmsAttribute>
        {
            Pkcs7Builder.MessageDigestAttribute(Pkcs7Builder.EncapsulatedContentDigest(econtent, AuthenticodeHashKind.Sha256)),
            Pkcs7Builder.ContentTypeAttribute(Oids.SpcIndirectData),
        };
        var signature = key.SignData(Pkcs7Builder.SignedAttributesDer(attrs), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var digestAlgorithm = Pkcs7Builder.AuthenticodeDigestAlgorithm(AuthenticodeHashKind.Sha256);
        var signerInfo = new CmsSignerInfo(
            1,
            CmsSignerInfo.IssuerAndSerialSid(signerCert),
            digestAlgorithm,
            attrs,
            Pkcs7Builder.RsaDigestSignatureAlgorithm(AuthenticodeHashKind.Sha256),
            signature,
            null);
        var sd = new CmsSignedData(1, [digestAlgorithm], Oids.SpcIndirectData, econtent, [signerCert.RawData], null, [signerInfo]);
        return sd.Encode();
    }

    // ------------------------------------------------------------------ remote

    private RemoteCodeSignature SignRemoteDigest(AuthenticodeHashKind algorithm, byte[] digest)
    {
        if (_akv is { } akv)
        {
            var signature = akv.Client.SignDigestFromCertificate(akv.Token, akv.Certificate, AzureKeyVaultClient.HashAlgFor(algorithm), digest);
            CertificateInfo signerCert;
            try
            {
                signerCert = SigningMaterialLoader.ParseCertificate(akv.CertDer);
            }
            catch (PsignException e)
            {
                throw new PsignException("parse Azure Key Vault signer certificate", e);
            }

            return new RemoteCodeSignature(signature, akv.CertDer, signerCert, []);
        }

        if (_artifact is { } artifact)
        {
            var defaultAlgorithm = algorithm switch
            {
                AuthenticodeHashKind.Sha384 => "RS384",
                AuthenticodeHashKind.Sha512 => "RS512",
                _ => "RS256",
            };
            var parameters = artifact.Options.ToSubmitParams(digest, defaultAlgorithm, artifact.Environment);
            var signed = artifact.Client.SubmitCodesignHashSignature(parameters);
            var (signer, chain) = ArtifactSigningCertificates.Parse(signed.SigningCertificate);
            return new RemoteCodeSignature(signed.Signature, signer.RawData, signer, chain);
        }

        throw new PsignException("local signer cannot remote-sign a digest");
    }

    // ------------------------------------------------------------------ helpers

    private static CertificateInfo ParseSignerCertificate(byte[] bytes, string label)
    {
        try
        {
            return SigningMaterialLoader.ParseCertificate(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse signer certificate {label}", e);
        }
    }

    private static RSA ParseKey(byte[] bytes, string label)
    {
        try
        {
            return SigningMaterialLoader.ParseRsaPrivateKey(bytes);
        }
        catch (Exception e) when (e is PsignException or CryptographicException)
        {
            throw new PsignException($"parse RSA private key {label}", e);
        }
    }

    internal static T Ctx<T>(string context, Func<T> action)
    {
        try
        {
            return action();
        }
        catch (Exception e) when (e is PsignException or CryptographicException or System.Formats.Asn1.AsnContentException or InvalidDataException)
        {
            throw new PsignException(context, e);
        }
    }

    public void Dispose()
    {
        _akv?.Client.Dispose();
        _artifact?.Client.Dispose();
    }
}
