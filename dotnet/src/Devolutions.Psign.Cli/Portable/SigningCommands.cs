using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.Catalog;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Signing.Msi;
using Devolutions.Psign.Signing.Pki;
using Devolutions.Psign.Signing.Timestamp;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>
/// Portable signing, timestamping, remote-signer, and test PKI commands (port of the matching <c>psign-digest-cli</c>
/// handlers: <c>sign-pe</c>, <c>sign-cab</c>, <c>sign-msi</c>, <c>sign-catalog</c>, <c>timestamp-pe-rfc3161</c>,
/// <c>rfc3161-timestamp-http-post</c>, <c>artifact-signing-*</c>, <c>azure-key-vault-sign-digest</c>,
/// <c>generate-root-ca</c>, <c>issue-code-signing-cert</c>, <c>issue-tls-server-cert</c>). The Rust cargo features
/// <c>artifact-signing-rest</c>, <c>azure-kv-sign-portable</c>, and <c>timestamp-http</c> are always enabled.
/// </summary>
internal static class SigningCommands
{
    internal static readonly string[] SignDigestValues = ["sha256", "sha384", "sha512"];
    internal static readonly string[] CredentialTypeValues = ["default", "managed-identity", "access-token", "client-secret", "workload-identity"];

    /// <summary>Test hook: HTTP handler used by remote commands (TSA, Key Vault, Artifact Signing). <c>null</c> = real network.</summary>
    internal static Func<HttpMessageHandler?>? HttpHandlerFactory { get; set; }

    /// <summary>Test hook: environment lookup for Artifact Signing credential resolution.</summary>
    internal static Func<string, string?>? Environment { get; set; }

    public static void Register(CommandSpec portable)
    {
        RegisterSignPe(portable);
        RegisterSignCab(portable);
        RegisterSignMsi(portable);
        RegisterSignCatalog(portable);
        RegisterTimestampPe(portable);
        RegisterRfc3161HttpPost(portable);
        RegisterArtifactSigning(portable);
        RegisterAzureKeyVaultSignDigest(portable);
        RegisterTestPki(portable);
    }

    // ------------------------------------------------------------------ sign-pe / sign-cab / sign-msi / sign-catalog

    private static void AddLocalSignerOptions(CommandSpec c, bool artifactNote)
    {
        var suffix = artifactNote ? " Omit when using --artifact-signing-*." : string.Empty;
        c.Value("cert", "PATH", "Signer certificate as DER or PEM." + suffix);
        c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM." + suffix);
        c.Multi("chain-cert", "PATH", "Additional certificate to include in the PKCS#7 certificate set.");
    }

    private static void AddTimestampOptions(CommandSpec c, string what)
    {
        c.Value("timestamp-url", null, $"RFC3161 timestamp URL to timestamp {what} after signing.").Alias("tr");
        c.Choice("timestamp-digest", PeCommands.HashAlgValues, null, "RFC3161 timestamp digest algorithm.").Alias("td");
    }

    private static void AddArtifactSigningOptions(CommandSpec c)
    {
        c.Value("artifact-signing-metadata", "PATH", "Artifact Signing metadata JSON (same shape as Microsoft's dlib /dmdf file).");
        c.Value("artifact-signing-region", null, "Regional hostname segment, e.g. `westus`, when not using metadata Endpoint.");
        c.Value("artifact-signing-endpoint", null, "Explicit data-plane endpoint, e.g. `https://wus2.codesigning.azure.net`.");
        c.Value("artifact-signing-account-name");
        c.Value("artifact-signing-profile-name");
        c.Value("artifact-signing-signature-algorithm");
        c.Value("artifact-signing-api-version");
        c.Value("artifact-signing-correlation-id");
        c.Value("artifact-signing-access-token");
        c.Flag("artifact-signing-managed-identity");
        c.Value("artifact-signing-managed-identity-resource-id");
        c.Choice("artifact-signing-credential-type", CredentialTypeValues);
        c.Value("artifact-signing-tenant-id");
        c.Value("artifact-signing-client-id");
        c.Value("artifact-signing-client-secret");
        c.Value("artifact-signing-federated-token-file");
        c.Value("artifact-signing-authority");
        c.Value("artifact-signing-endpoint-base-url", null, "Override data-plane origin for deterministic local tests.").Hide();
    }

    private static ArtifactSigningOptions ArtifactOptions(ParsedCommand p) => new()
    {
        Metadata = p.Value("artifact-signing-metadata"),
        Region = p.Value("artifact-signing-region"),
        Endpoint = p.Value("artifact-signing-endpoint"),
        AccountName = p.Value("artifact-signing-account-name"),
        ProfileName = p.Value("artifact-signing-profile-name"),
        SignatureAlgorithm = p.Value("artifact-signing-signature-algorithm"),
        ApiVersion = p.Value("artifact-signing-api-version"),
        CorrelationId = p.Value("artifact-signing-correlation-id"),
        AccessToken = p.Value("artifact-signing-access-token"),
        ManagedIdentity = p.Flag("artifact-signing-managed-identity"),
        ManagedIdentityResourceId = p.Value("artifact-signing-managed-identity-resource-id"),
        CredentialType = CredentialType(p.Value("artifact-signing-credential-type")),
        TenantId = p.Value("artifact-signing-tenant-id"),
        ClientId = p.Value("artifact-signing-client-id"),
        ClientSecret = p.Value("artifact-signing-client-secret"),
        FederatedTokenFile = p.Value("artifact-signing-federated-token-file"),
        Authority = p.Value("artifact-signing-authority"),
        EndpointBaseUrl = p.Value("artifact-signing-endpoint-base-url"),
    };

    internal static CodesigningCredentialType? CredentialType(string? value) => value switch
    {
        null => null,
        "default" => CodesigningCredentialType.Default,
        "managed-identity" => CodesigningCredentialType.ManagedIdentity,
        "access-token" => CodesigningCredentialType.AccessToken,
        "client-secret" => CodesigningCredentialType.ClientSecret,
        _ => CodesigningCredentialType.WorkloadIdentity,
    };

    /// <summary>clap <c>{:?}</c> of <c>PortableSignDigest</c>.</summary>
    private static string DigestDebug(AuthenticodeHashKind kind) => ScriptCommands.SpcName(kind);

    private static void RegisterSignPe(CommandSpec portable)
    {
        portable.Sub("sign-pe", "Sign a PE image with portable Authenticode CMS + `WIN_CERTIFICATE` embedding.", c =>
        {
            c.Positional("path", valueName: "PATH", help: "Input PE path.");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.");
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.");
            c.Multi("chain-cert", "PATH", "Additional certificate to include in the PKCS#7 certificate set.");
            c.Choice("digest", SignDigestValues, "sha256", "File digest algorithm for the PE Authenticode indirect digest and CMS signer.");
            AddTimestampOptions(c, "the primary PE signature");
            c.Flag("append-signature", "Append a signature instead of replacing existing embedded Authenticode signatures.").Alias("as");
            c.Value("azure-key-vault-url", null, "Azure Key Vault URL for remote RSA signing.").Alias("kvu");
            c.Value("azure-key-vault-certificate", null, "Azure Key Vault certificate name for remote RSA signing.").Alias("kvc");
            c.Value("azure-key-vault-certificate-version", null, "Optional Azure Key Vault certificate version.").Alias("kvcv");
            c.Value("azure-key-vault-accesstoken");
            c.Flag("azure-key-vault-managed-identity");
            c.Value("azure-key-vault-tenant-id");
            c.Value("azure-key-vault-client-id");
            c.Value("azure-key-vault-client-secret");
            c.Value("azure-authority");
            AddArtifactSigningOptions(c);
            c.Value("output", "PATH", "Output signed PE path.").Req();
            c.Handler = SignPe;
        });
    }

    private static int SignPe(ParsedCommand p)
    {
        var path = p.Pos("path")!;
        var output = p.Required("output");
        var kind = AuthenticodeHashKinds.Parse(p.Required("digest"));
        var pe = Output.ReadFile(path);
        if (!p.Flag("append-signature"))
        {
            pe = Ctx($"remove existing PE Authenticode signatures from {path}", () => PeEmbed.RemoveCertificates(pe).Image);
        }

        pe = Ctx($"prepare PE certificate table alignment for {path}", () => PeEmbed.PrepareForAuthenticodeSigning(pe));
        var cert = p.Value("cert");
        var key = p.Value("key");
        bool hasLocal = cert is not null || key is not null;
        var kv = new KvOptions(
            p.Value("azure-key-vault-url"),
            p.Value("azure-key-vault-certificate"),
            p.Value("azure-key-vault-certificate-version"),
            p.Value("azure-key-vault-accesstoken"),
            p.Flag("azure-key-vault-managed-identity"),
            p.Value("azure-key-vault-tenant-id"),
            p.Value("azure-key-vault-client-id"),
            p.Value("azure-key-vault-client-secret"),
            p.Value("azure-authority"));
        bool hasKv = NonBlank(kv.VaultUrl) || NonBlank(kv.Certificate) || NonBlank(kv.CertificateVersion) || NonBlank(kv.AccessToken)
            || kv.ManagedIdentity || NonBlank(kv.TenantId) || NonBlank(kv.ClientId) || NonBlank(kv.ClientSecret) || NonBlank(kv.Authority);
        var artifact = ArtifactOptions(p);
        bool hasArtifact = artifact.IsRequested;
        if ((hasLocal ? 1 : 0) + (hasKv ? 1 : 0) + (hasArtifact ? 1 : 0) > 1)
        {
            throw new PsignException("portable sign-pe accepts only one signing source: --cert/--key, --azure-key-vault-*, or --artifact-signing-*");
        }

        var url = p.Value("timestamp-url");
        var tsDigest = p.Value("timestamp-digest");
        if (url is not null && tsDigest is null)
        {
            throw new PsignException("portable sign-pe requires --timestamp-digest with --timestamp-url");
        }

        if (url is null && tsDigest is not null)
        {
            throw new PsignException("portable sign-pe requires --timestamp-url with --timestamp-digest");
        }

        var chainCerts = p.Values("chain-cert");
        byte[] pkcs7;
        if (hasArtifact)
        {
            pkcs7 = Ctx($"create portable Azure Artifact Signing Authenticode signature for {path}", () =>
                AuthenticodeWithArtifactSigning(SpcIndirectDataContent.ForPe(kind, PeAuthenticode.Digest(pe, kind)), kind, chainCerts, artifact));
        }
        else if (hasKv)
        {
            pkcs7 = Ctx($"create portable Azure Key Vault Authenticode signature for {path}", () => PeAuthenticodeWithKeyVault(pe, kind, chainCerts, kv));
        }
        else
        {
            if (cert is null || key is null)
            {
                throw new PsignException("portable sign-pe requires --cert and --key, --azure-key-vault-url and --azure-key-vault-certificate, or --artifact-signing-* options");
            }

            var (signerCert, privateKey, chain) = LoadLocalSigner(cert, key, chainCerts);
            using (privateKey)
            {
                pkcs7 = Ctx($"create portable Authenticode signature for {path}", () =>
                    Pkcs7Builder.CreateAuthenticode(SpcIndirectDataContent.ForPe(kind, PeAuthenticode.Digest(pe, kind)), kind, signerCert, chain, privateKey));
            }
        }

        if (url is not null && tsDigest is not null)
        {
            pkcs7 = Ctx($"RFC3161 timestamp portable Authenticode signature for {path}", () => TimestampPkcs7(pkcs7, url, AuthenticodeHashKinds.Parse(tsDigest)));
        }
        var signed = Ctx($"embed Authenticode signature in {path}", () => PeEmbed.AppendPkcs7Certificate(pe, pkcs7));
        Output.WriteFile(output, signed);
        Output.Line($"sign-pe: ok output={output} digest={DigestDebug(kind)} pkcs7_len={pkcs7.Length}");
        return 0;
    }

    private static void RegisterSignCab(CommandSpec portable)
    {
        portable.Sub("sign-cab", "Sign an unsigned CAB file with portable Authenticode CMS and CAB reserve-header embedding.", c =>
        {
            c.Positional("path", valueName: "PATH", help: "Input CAB path.");
            AddLocalSignerOptions(c, artifactNote: true);
            c.Choice("digest", SignDigestValues, "sha256", "File digest algorithm for the CAB Authenticode indirect digest and CMS signer.");
            AddTimestampOptions(c, "the CAB Authenticode signature");
            AddArtifactSigningOptions(c);
            c.Value("output", "PATH", "Output signed CAB path.").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var kind = AuthenticodeHashKinds.Parse(p.Required("digest"));
                var cab = Output.ReadFile(path);
                var artifact = ArtifactOptions(p);
                var pkcs7 = SignWithSource(
                    p,
                    "portable sign-cab",
                    artifact,
                    () => Ctx($"create portable Artifact Signing CAB Authenticode signature for {path}", () =>
                        AuthenticodeWithArtifactSigning(SpcIndirectDataContent.ForCab(kind, CabDigest.AuthenticodeDigestForSigning(cab, kind)), kind, p.Values("chain-cert"), artifact)),
                    (signerCert, chain, privateKey) => Ctx($"create portable CAB Authenticode signature for {path}", () =>
                        Pkcs7Builder.CreateAuthenticode(SpcIndirectDataContent.ForCab(kind, CabDigest.AuthenticodeDigestForSigning(cab, kind)), kind, signerCert, chain, privateKey)));
                pkcs7 = TimestampIfRequested(pkcs7, p, "portable sign-cab");
                var signed = Ctx($"embed Authenticode signature in {path}", () => CabDigest.AppendAuthenticodePkcs7Signature(cab, pkcs7));
                Output.WriteFile(output, signed);
                Output.Line($"sign-cab: ok output={output} digest={DigestDebug(kind)} pkcs7_len={pkcs7.Length}");
                return 0;
            };
        });
    }

    private static void RegisterSignMsi(CommandSpec portable)
    {
        portable.Sub("sign-msi", "Sign an MSI/MSP OLE package with portable Authenticode CMS and the required MSI signature streams.", c =>
        {
            c.Positional("path", valueName: "PATH", help: "Input MSI/MSP path.");
            AddLocalSignerOptions(c, artifactNote: true);
            c.Choice("digest", SignDigestValues, "sha256", "File digest algorithm for the MSI Authenticode indirect digest and CMS signer.");
            AddTimestampOptions(c, "the MSI Authenticode signature");
            AddArtifactSigningOptions(c);
            c.Value("output", "PATH", "Output signed MSI/MSP path.").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var kind = AuthenticodeHashKinds.Parse(p.Required("digest"));
                var msi = Output.ReadFile(path);
                var prepared = MsiDigest.PrepareForAuthenticodeSigning(msi, kind);
                var artifact = ArtifactOptions(p);
                var pkcs7 = SignWithSource(
                    p,
                    "portable sign-msi",
                    artifact,
                    () => Ctx($"create portable Artifact Signing MSI Authenticode signature for {path}", () =>
                        AuthenticodeWithArtifactSigning(SpcIndirectDataContent.ForMsi(kind, prepared.Digest), kind, p.Values("chain-cert"), artifact)),
                    (signerCert, chain, privateKey) => Ctx($"create portable MSI Authenticode signature for {path}", () =>
                        MsiSigning.CreateAuthenticodePkcs7(prepared.Image, kind, signerCert, chain, privateKey)));
                pkcs7 = TimestampIfRequested(pkcs7, p, "portable sign-msi");
                Ctx($"embed Authenticode signature in {path}", () => MsiDigest.EmbedPreparedAuthenticodePkcs7Signature(prepared, output, pkcs7));
                Output.Line($"sign-msi: ok output={output} digest={DigestDebug(kind)} pkcs7_len={pkcs7.Length}");
                return 0;
            };
        });
    }

    private static void RegisterSignCatalog(CommandSpec portable)
    {
        portable.Sub("sign-catalog", "Sign a portable generic file catalog (`.cat`) with CTL members and CMS `SignedData`.", c =>
        {
            c.Positionals.Add(new PositionalSpec("files", required: true, multiple: true) { ValueName = "PATH", Help = "Subject file(s) to include as catalog members." });
            AddLocalSignerOptions(c, artifactNote: true);
            c.Choice("digest", SignDigestValues, "sha256", "File digest algorithm for catalog member digests and CMS signer.");
            AddTimestampOptions(c, "the catalog signature");
            AddArtifactSigningOptions(c);
            c.Value("output", "PATH", "Output signed catalog path.").Req();
            c.Handler = p =>
            {
                var output = p.Required("output");
                var kind = AuthenticodeHashKinds.Parse(p.Required("digest"));
                var subjects = new List<CatalogSubjectInput>();
                foreach (var file in p.PosAll("files"))
                {
                    var name = Path.GetFileName(file.TrimEnd('/', '\\'));
                    if (string.IsNullOrEmpty(name) || name is "." or "..")
                    {
                        throw new PsignException($"catalog subject path has no UTF-8 file name: {file}");
                    }

                    subjects.Add(new CatalogSubjectInput(name, Output.ReadFile(file)));
                }

                var artifact = ArtifactOptions(p);
                CatalogSignResult catalog = SignCatalogWithSource(p, artifact, subjects, kind, output);
                var pkcs7 = TimestampIfRequested(catalog.Pkcs7Der, p, "portable sign-catalog");
                Output.WriteFile(output, pkcs7);
                Output.Line($"sign-catalog: ok output={output} digest={DigestDebug(kind)} members={catalog.Members.Count} pkcs7_len={pkcs7.Length}");
                return 0;
            };
        });
    }

    private static CatalogSignResult SignCatalogWithSource(ParsedCommand p, ArtifactSigningOptions artifact, List<CatalogSubjectInput> subjects, AuthenticodeHashKind kind, string output)
    {
        var cert = p.Value("cert");
        var key = p.Value("key");
        if (artifact.IsRequested && (cert is not null || key is not null))
        {
            throw new PsignException("portable sign-catalog accepts either --cert/--key or --artifact-signing-*, not both");
        }

        if (artifact.IsRequested)
        {
            return Ctx($"create portable Artifact Signing catalog {output}", () =>
            {
                var (econtent, members) = CatalogSigning.CreateCtlEContentDer(subjects, kind);
                var prehash = CatalogSigning.RemoteSignedAttributesDigest(econtent, kind);
                var (signature, signer, chain) = SubmitArtifactSigning(prehash, kind, p.Values("chain-cert"), artifact);
                var der = Pkcs7Builder.CreateSignedData(Oids.MsCtl, econtent, kind, signer, chain, new PrecomputedDigestSigner(signature));
                return new CatalogSignResult(der, members);
            });
        }

        if (cert is null || key is null)
        {
            throw new PsignException("portable sign-catalog requires --cert and --key, or --artifact-signing-* options");
        }

        var (signerCert, privateKey, chainCerts) = LoadLocalSigner(cert, key, p.Values("chain-cert"));
        using (privateKey)
        {
            return Ctx($"create portable catalog {output}", () => CatalogSigning.Create(subjects, kind, signerCert, chainCerts, privateKey));
        }
    }

    /// <summary>Shared CAB / MSI source selection: <c>--cert/--key</c> or <c>--artifact-signing-*</c>.</summary>
    private static byte[] SignWithSource(
        ParsedCommand p,
        string command,
        ArtifactSigningOptions artifact,
        Func<byte[]> artifactSign,
        Func<CertificateInfo, List<CertificateInfo>, System.Security.Cryptography.RSA, byte[]> localSign)
    {
        var cert = p.Value("cert");
        var key = p.Value("key");
        if (artifact.IsRequested && (cert is not null || key is not null))
        {
            throw new PsignException($"{command} accepts either --cert/--key or --artifact-signing-*, not both");
        }

        if (artifact.IsRequested)
        {
            return artifactSign();
        }

        if (cert is null || key is null)
        {
            throw new PsignException($"{command} requires --cert and --key, or --artifact-signing-* options");
        }

        var (signerCert, privateKey, chain) = LoadLocalSigner(cert, key, p.Values("chain-cert"));
        using (privateKey)
        {
            return localSign(signerCert, chain, privateKey);
        }
    }

    /// <summary>Read and parse <c>--cert</c>, <c>--key</c>, and <c>--chain-cert</c> in the Rust order.</summary>
    private static (CertificateInfo Cert, System.Security.Cryptography.RSA Key, List<CertificateInfo> Chain) LoadLocalSigner(string cert, string key, IReadOnlyList<string> chainCerts)
    {
        var certBytes = Output.ReadFile(cert);
        var signerCert = Ctx($"parse signer certificate {cert}", () => CertificateLoader.ParseCertificate(certBytes));
        var keyBytes = Output.ReadFile(key);
        var privateKey = Ctx($"parse RSA private key {key}", () => PrivateKeyLoader.ParseRsaPrivateKey(keyBytes));
        try
        {
            return (signerCert, privateKey, LoadChainCerts(chainCerts));
        }
        catch
        {
            privateKey.Dispose();
            throw;
        }
    }

    /// <summary>Rust <c>load_chain_certs</c>.</summary>
    private static List<CertificateInfo> LoadChainCerts(IReadOnlyList<string> chainCerts)
    {
        var chain = new List<CertificateInfo>(chainCerts.Count);
        foreach (var path in chainCerts)
        {
            var bytes = Output.ReadFile(path);
            chain.Add(Ctx($"parse chain certificate {path}", () => CertificateLoader.ParseCertificate(bytes)));
        }

        return chain;
    }

    // ------------------------------------------------------------------ remote signers

    private sealed record KvOptions(
        string? VaultUrl,
        string? Certificate,
        string? CertificateVersion,
        string? AccessToken,
        bool ManagedIdentity,
        string? TenantId,
        string? ClientId,
        string? ClientSecret,
        string? Authority);

    private static bool NonBlank(string? s) => s is not null && s.Trim().Length > 0;

    /// <summary>Rust <c>text_opt</c>: trimmed, non-empty text.</summary>
    private static string? TextOpt(string? s) => s?.Trim() is { Length: > 0 } t ? t : null;

    /// <summary>Rust <c>validate_kv_portable_auth_inputs</c>.</summary>
    private static void ValidateKvAuth(string? accessToken, bool managedIdentity, string? tenantId, string? clientId, string? clientSecret)
    {
        bool hasSp = NonBlank(clientSecret);
        bool hasTenant = NonBlank(tenantId);
        bool hasClient = NonBlank(clientId);
        bool hasToken = NonBlank(accessToken);
        int spCount = (hasSp ? 1 : 0) + (hasTenant ? 1 : 0) + (hasClient ? 1 : 0);
        if (spCount != 0 && spCount != 3)
        {
            throw new PsignException("Azure AD client credentials require all of --azure-key-vault-client-id, --azure-key-vault-client-secret, and --azure-key-vault-tenant-id");
        }

        if (hasToken && (managedIdentity || spCount == 3))
        {
            throw new PsignException("use either --azure-key-vault-accesstoken or managed identity / client credentials, not multiple");
        }

        if (managedIdentity && (hasToken || spCount == 3))
        {
            throw new PsignException("--azure-key-vault-managed-identity cannot be combined with access tokens or client secrets");
        }

        if (!hasToken && !managedIdentity && spCount != 3)
        {
            throw new PsignException("choose authentication: --azure-key-vault-accesstoken, --azure-key-vault-managed-identity, or client id/secret/tenant");
        }
    }

    private static AzureKeyVaultClient NewKeyVaultClient() => new(HttpHandlerFactory?.Invoke());

    private static ArtifactSigningClient NewArtifactSigningClient() => new(HttpHandlerFactory?.Invoke(), Environment);

    private static TimestampClient NewTimestampClient() => new(HttpHandlerFactory?.Invoke());

    /// <summary>Rust <c>create_pe_authenticode_pkcs7_der_azure_kv</c>.</summary>
    private static byte[] PeAuthenticodeWithKeyVault(byte[] pe, AuthenticodeHashKind kind, IReadOnlyList<string> chainCerts, KvOptions kv)
    {
        var vaultUrl = TextOpt(kv.VaultUrl) ?? throw new PsignException("portable sign-pe Azure Key Vault signing requires --azure-key-vault-url");
        var certificate = TextOpt(kv.Certificate) ?? throw new PsignException("portable sign-pe Azure Key Vault signing requires --azure-key-vault-certificate");
        ValidateKvAuth(kv.AccessToken, kv.ManagedIdentity, kv.TenantId, kv.ClientId, kv.ClientSecret);
        using var client = NewKeyVaultClient();
        var token = client.AcquireAccessToken(new KvAuthParams
        {
            AccessToken = kv.AccessToken,
            ManagedIdentity = kv.ManagedIdentity,
            TenantId = kv.TenantId,
            ClientId = kv.ClientId,
            ClientSecret = kv.ClientSecret,
            Authority = kv.Authority,
        });
        var kvCert = client.FetchCertificate(vaultUrl, certificate, TextOpt(kv.CertificateVersion), token);
        var signerCertDer = AzureKeyVaultClient.DecodeCerBase64(kvCert.Cer);
        var signerCert = Ctx("parse Key Vault signer certificate", () => CertificateLoader.ParseCertificate(signerCertDer));
        var chain = LoadChainCerts(chainCerts);
        var indirect = SpcIndirectDataContent.ForPe(kind, PeAuthenticode.Digest(pe, kind));
        var prehash = Pkcs7Builder.AuthenticodeRemoteSignedAttributesDigest(indirect, kind);
        var signature = client.SignDigestFromCertificate(token, kvCert, AzureKeyVaultClient.HashAlgFor(kind), prehash);
        return Pkcs7Builder.CreateAuthenticodeWithSignature(indirect, kind, signerCert, chain, signature);
    }

    /// <summary>Rust <c>create_authenticode_pkcs7_der_artifact_signing_from_indirect</c>.</summary>
    private static byte[] AuthenticodeWithArtifactSigning(SpcIndirectDataContent indirect, AuthenticodeHashKind kind, IReadOnlyList<string> chainCerts, ArtifactSigningOptions options)
    {
        var prehash = Pkcs7Builder.AuthenticodeRemoteSignedAttributesDigest(indirect, kind);
        var (signature, signer, chain) = SubmitArtifactSigning(prehash, kind, chainCerts, options);
        return Pkcs7Builder.CreateAuthenticodeWithSignature(indirect, kind, signer, chain, signature);
    }

    private static (byte[] Signature, CertificateInfo Signer, List<CertificateInfo> Chain) SubmitArtifactSigning(byte[] prehash, AuthenticodeHashKind kind, IReadOnlyList<string> chainCerts, ArtifactSigningOptions options)
    {
        var parameters = options.ToSubmitParams(prehash, ArtifactSigningClient.SignatureAlgorithmForDigest(kind), Environment);
        using var client = NewArtifactSigningClient();
        var signed = client.SubmitCodesignHashSignature(parameters, DebugSink());
        var (signer, chain) = ArtifactSigningCertificates.Parse(signed.SigningCertificate);
        chain.AddRange(LoadChainCerts(chainCerts));
        return (signed.Signature, signer, chain);
    }

    private static Action<string>? DebugSink() =>
        (Environment ?? System.Environment.GetEnvironmentVariable)("SIGNTOOL_PORTABLE_DEBUG") is not null
            ? msg => Output.ErrorLine($"[debug] {msg}")
            : null;

    // ------------------------------------------------------------------ RFC 3161

    private static byte[] TimestampPkcs7(byte[] pkcs7, string url, AuthenticodeHashKind digest)
    {
        using var client = NewTimestampClient();
        return client.TimestampPkcs7(pkcs7, url, digest);
    }

    /// <summary>Rust <c>timestamp_authenticode_pkcs7_der_if_requested</c>.</summary>
    private static byte[] TimestampIfRequested(byte[] pkcs7, ParsedCommand p, string command)
    {
        var url = p.Value("timestamp-url");
        var digest = p.Value("timestamp-digest");
        return (url, digest) switch
        {
            ({ } u, { } d) => Ctx($"{command}: RFC3161 timestamp signature", () => TimestampPkcs7(pkcs7, u, AuthenticodeHashKinds.Parse(d))),
            (not null, null) => throw new PsignException($"{command} requires --timestamp-digest with --timestamp-url"),
            (null, not null) => throw new PsignException($"{command} requires --timestamp-url with --timestamp-digest"),
            _ => pkcs7,
        };
    }

    private static void RegisterTimestampPe(CommandSpec portable)
    {
        portable.Sub("timestamp-pe-rfc3161", "Attach an RFC3161 timestamp token to an existing embedded PE Authenticode signature.", c =>
        {
            c.Positional("path", valueName: "PATH", help: "Signed PE path to mutate.");
            c.Value("index", null, "Embedded PKCS#7 row index in the PE certificate table.", "0");
            c.Value("signer-index", null, "SignerInfo index inside the selected PKCS#7 SignedData.", "0");
            c.Value("token", "PATH", "Raw RFC3161 timeStampToken ContentInfo DER.").Conflicts("response", "rfc3161-url");
            c.Value("response", "PATH", "RFC3161 TimeStampResp DER containing a granted timeStampToken.").Conflicts("token", "rfc3161-url");
            c.Value("rfc3161-url", null, "RFC3161 TSA endpoint. Requires `--digest`.").Alias("tr").Conflicts("token", "response");
            c.Choice("digest", PeCommands.HashAlgValues, null, "RFC3161 timestamp message-imprint digest. Required with `--rfc3161-url`.").Alias("td").Requiring("rfc3161-url");
            c.Value("output", "PATH", "Output PE path.").Req();
            c.Handler = TimestampPe;
        });
    }

    private static int TimestampPe(ParsedCommand p)
    {
        var path = p.Pos("path")!;
        int index = p.Int("index");
        int signerIndex = p.Int("signer-index");
        if (index < 0)
        {
            throw new PsignException($"--index must be non-negative, got {index}");
        }

        if (signerIndex < 0)
        {
            throw new PsignException($"--signer-index must be non-negative, got {signerIndex}");
        }

        var output = p.Required("output");
        var pe = Output.ReadFile(path);
        var pkcs7Der = Ctx($"extract PE PKCS#7 row {index} from {path}", () => PeAuthenticode.NthPkcs7(pe, index));
        var token = p.Value("token");
        var response = p.Value("response");
        var url = p.Value("rfc3161-url");
        byte[] stamped;
        if (token is not null && response is null && url is null)
        {
            var tokenDer = Output.ReadFile(token);
            stamped = AttachToken(pkcs7Der, tokenDer, path, index, signerIndex);
        }
        else if (token is null && response is not null && url is null)
        {
            var bytes = Output.ReadFile(response);
            var parsed = Rfc3161.ParseTimeStampRespDer(bytes)
                ?? throw new PsignException($"could not parse TimeStampResp DER from {response}");
            if (!parsed.PkiStatus.Granted)
            {
                throw new PsignException($"TimeStampResp status is not granted (status={parsed.PkiStatus.AsRawInteger()})");
            }

            var tokenDer = parsed.TimeStampToken ?? throw new PsignException("TimeStampResp has no timeStampToken");
            stamped = AttachToken(pkcs7Der, tokenDer, path, index, signerIndex);
        }
        else if (token is null && response is null && url is not null)
        {
            if (signerIndex != 0)
            {
                throw new PsignException("timestamp-pe-rfc3161 RFC3161 HTTP timestamping supports only signer_index 0");
            }

            var digest = p.Value("digest") ?? throw new PsignException("timestamp-pe-rfc3161 requires --digest with --rfc3161-url");
            stamped = Ctx("request and attach RFC3161 timestamp", () => TimestampPkcs7(pkcs7Der, url, AuthenticodeHashKinds.Parse(digest)));
        }
        else
        {
            throw new PsignException("provide exactly one of --token, --response, or --rfc3161-url with --digest");
        }

        var outImage = Ctx($"replace PE PKCS#7 row {index} in {path}", () => PeEmbed.ReplacePkcs7CertificateAt(pe, index, stamped));
        Output.WriteFile(output, outImage);
        Output.Line($"timestamp-pe-rfc3161: ok output={output} index={index} signer_index={signerIndex}");
        return 0;
    }

    private static byte[] AttachToken(byte[] pkcs7Der, byte[] tokenDer, string path, int index, int signerIndex)
    {
        var sd = Ctx($"parse PE PKCS#7 row {index} from {path}", () => CmsSignedData.Parse(pkcs7Der));
        var stamped = Ctx($"attach RFC3161 timestamp to {path} row {index} signer {signerIndex}", () => Pkcs7Builder.AddTimestampToken(sd, signerIndex, tokenDer));
        return stamped.Encode();
    }

    private static void RegisterRfc3161HttpPost(CommandSpec portable)
    {
        portable.Sub("rfc3161-timestamp-http-post", "POST TimeStampReq DER to a TSA and write TimeStampResp DER to stdout or --output.", c =>
        {
            c.Value("url", "URL", "TSA endpoint (HTTPS URL; POST body is raw TimeStampReq DER).").Req();
            c.Choice("algorithm", PeCommands.HashAlgValues, "sha256");
            c.Value("digest-file", "PATH");
            c.Value("digest-hex", "HEX");
            c.Value("nonce");
            c.Flag("cert-req");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var url = p.Required("url");
                var kind = AuthenticodeHashKinds.Parse(p.Required("algorithm"));
                var preimage = ScriptCommands.LoadTimestampImprintPreimage(p.Value("digest-hex"), p.Value("digest-file"), kind);
                ulong? nonce = ScriptCommands.ParseOptionalNonce(p.Value("nonce"), "--nonce");
                var der = Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = kind.Oid(), Nonce = nonce, CertReq = p.Flag("cert-req") }, preimage)
                    ?? throw new PsignException("unsupported digest OID / preimage length for RFC3161 TimeStampReq");
                byte[] body;
                using (var client = NewTimestampClient())
                {
                    body = client.PostTimestampRequest(url, der);
                }

                if (p.Value("output") is { } output)
                {
                    Output.WriteFile(output, body);
                }
                else
                {
                    Output.Raw(body);
                }

                return 0;
            };
        });
    }

    // ------------------------------------------------------------------ Artifact Signing

    private static void AddArtifactAuthOptions(CommandSpec c)
    {
        c.Value("access-token");
        c.Flag("managed-identity");
        c.Value("managed-identity-resource-id");
        c.Choice("credential-type", CredentialTypeValues);
        c.Value("tenant-id");
        c.Value("client-id");
        c.Value("client-secret");
        c.Value("federated-token-file");
        c.Value("authority");
    }

    /// <summary>Rust <c>portable_artifact_signing_auth</c>.</summary>
    internal static CodesigningAuth ResolveArtifactAuth(ParsedCommand p, Func<string, string?>? environment) =>
        CodesigningAuthResolver.Resolve(
            new CodesigningAuthInput
            {
                AccessToken = TextOpt(p.Value("access-token")),
                ManagedIdentity = p.Flag("managed-identity"),
                ManagedIdentityResourceId = TextOpt(p.Value("managed-identity-resource-id")),
                TenantId = TextOpt(p.Value("tenant-id")),
                ClientId = TextOpt(p.Value("client-id")),
                ClientSecret = TextOpt(p.Value("client-secret")),
                FederatedTokenFile = TextOpt(p.Value("federated-token-file")),
                CredentialType = CredentialType(p.Value("credential-type")),
                ExcludeCredentials = [],
            },
            environment);

    private static void RegisterArtifactSigning(CommandSpec portable)
    {
        portable.Sub("artifact-signing-metadata-check", "Validate JSON metadata shape for Microsoft Artifact Signing. No network / no signing.", c =>
        {
            c.Value("path", "PATH");
            c.Handler = p =>
            {
                var raw = ReadJsonInput(p.Value("path"));
                ArtifactSigningMetadata.Check(raw);
                Output.Line("artifact-signing-metadata-check: ok");
                return 0;
            };
        });

        portable.Sub("artifact-signing-submit", "Azure Code Signing `…:sign` LRO (same REST contract as `psign-tool artifact-signing-submit`).", c =>
        {
            c.Value("region").Req();
            c.Value("account-name").Req();
            c.Value("profile-name").Req();
            c.Value("digest-file").Req();
            c.Value("signature-algorithm", null, null, "RS256");
            c.Value("api-version", null, null, ArtifactSigningClient.DefaultApiVersion);
            c.Value("correlation-id");
            AddArtifactAuthOptions(c);
            c.Value("endpoint-base-url", null, "Override data-plane origin for deterministic local tests.").Hide();
            c.Handler = p =>
            {
                ResolveArtifactAuth(p, Environment);
                var digestFile = p.Required("digest-file");
                var digest = Output.ReadFile(digestFile, $"read digest file {digestFile}");
                if (digest.Length == 0)
                {
                    throw new PsignException("digest file is empty");
                }

                var parameters = new CodesigningSubmitParams
                {
                    Region = p.Required("region"),
                    AccountName = p.Required("account-name"),
                    ProfileName = p.Required("profile-name"),
                    Digest = digest,
                    SignatureAlgorithm = p.Required("signature-algorithm"),
                    ApiVersion = p.Required("api-version"),
                    CorrelationId = p.Value("correlation-id"),
                    Authority = p.Value("authority"),
                    Auth = ResolveArtifactAuth(p, Environment),
                    EndpointBaseUrl = p.Value("endpoint-base-url"),
                };
                using var client = NewArtifactSigningClient();
                var json = client.SubmitCodesignHash(parameters, DebugSink());
                Output.Line(RustJson.Pretty(RustJson.SortKeysDeep(json)));
                return 0;
            };
        });

        portable.Sub("artifact-signing-root", "Retrieve the root certificate currently associated with an authenticated Artifact Signing profile.", c =>
        {
            c.Value("endpoint", null, "Public Azure Artifact Signing data-plane origin, for example `https://wus.artifactsigning.azure.net`.").Req();
            c.Value("account-name").Req();
            c.Value("profile-name").Req();
            c.Value("api-version", null, "Preview API used by the profile root-certificate operation.", ArtifactSigningClient.DefaultProfileRootApiVersion);
            c.Value("output").Req();
            AddArtifactAuthOptions(c);
            c.Handler = p =>
            {
                var auth = ResolveArtifactAuth(p, Environment);
                var parameters = new CodesigningProfileParams
                {
                    AccountName = p.Required("account-name"),
                    ProfileName = p.Required("profile-name"),
                    ApiVersion = p.Required("api-version"),
                    Authority = p.Value("authority"),
                    Auth = auth,
                    EndpointBaseUrl = p.Required("endpoint"),
                };
                byte[] root;
                using (var client = NewArtifactSigningClient())
                {
                    root = client.GetRootCertificate(parameters);
                }

                Ctx("parse Artifact Signing root certificate", () => Devolutions.Psign.Verification.Anchors.ParseCertBytes(root));
                var output = p.Required("output");
                Output.WriteFile(output, root);
                Output.Line($"output={output}");
                return 0;
            };
        });
    }

    /// <summary>Rust <c>read_json_input</c>: a path, or stdin when omitted / <c>-</c>.</summary>
    private static byte[] ReadJsonInput(string? path)
    {
        if (path is null or "-")
        {
            try
            {
                using var stdin = Console.OpenStandardInput();
                using var ms = new MemoryStream();
                stdin.CopyTo(ms);
                return ms.ToArray();
            }
            catch (IOException e)
            {
                throw new PsignException("read JSON from stdin", new PsignException(e.Message));
            }
        }

        return Output.ReadFile(path);
    }

    // ------------------------------------------------------------------ Azure Key Vault

    private static void RegisterAzureKeyVaultSignDigest(CommandSpec portable)
    {
        portable.Sub("azure-key-vault-sign-digest", "Azure Key Vault `keys/sign` over a precomputed digest file (RSA PKCS#1 or ECDSA).", c =>
        {
            c.Value("azure-key-vault-url").Alias("kvu").Req();
            c.Value("azure-key-vault-certificate").Alias("kvc").Req();
            c.Value("azure-key-vault-certificate-version").Alias("kvcv");
            c.Value("digest-file").Req();
            c.Choice("digest-algorithm", SignDigestValues, "sha256");
            c.Value("azure-key-vault-accesstoken");
            c.Flag("azure-key-vault-managed-identity");
            c.Value("azure-key-vault-tenant-id");
            c.Value("azure-key-vault-client-id");
            c.Value("azure-key-vault-client-secret");
            c.Value("azure-authority");
            c.Value("signature-output", "PATH", "Write raw signature bytes to this path. If omitted, prints standard base64 (one line, no PEM).");
            c.Handler = p =>
            {
                var accessToken = p.Value("azure-key-vault-accesstoken");
                bool managedIdentity = p.Flag("azure-key-vault-managed-identity");
                var tenantId = p.Value("azure-key-vault-tenant-id");
                var clientId = p.Value("azure-key-vault-client-id");
                var clientSecret = p.Value("azure-key-vault-client-secret");
                ValidateKvAuth(accessToken, managedIdentity, tenantId, clientId, clientSecret);
                var digestFile = p.Required("digest-file");
                var digest = Output.ReadFile(digestFile, $"read digest file {digestFile}");
                if (digest.Length == 0)
                {
                    throw new PsignException("digest file is empty");
                }

                byte[] signature;
                using (var client = NewKeyVaultClient())
                {
                    var token = client.AcquireAccessToken(new KvAuthParams
                    {
                        AccessToken = accessToken,
                        ManagedIdentity = managedIdentity,
                        TenantId = tenantId,
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        Authority = p.Value("azure-authority"),
                    });
                    var cert = client.FetchCertificate(
                        p.Required("azure-key-vault-url").Trim(),
                        p.Required("azure-key-vault-certificate").Trim(),
                        TextOpt(p.Value("azure-key-vault-certificate-version")),
                        token);
                    var hash = AzureKeyVaultClient.HashAlgFor(AuthenticodeHashKinds.Parse(p.Required("digest-algorithm")));
                    signature = client.SignDigestFromCertificate(token, cert, hash, digest);
                }

                if (p.Value("signature-output") is { } path)
                {
                    Output.WriteFile(path, signature);
                }
                else
                {
                    Output.Line(Convert.ToBase64String(signature));
                }

                return 0;
            };
        });
    }

    // ------------------------------------------------------------------ test PKI

    private static void AddTestPkiOutputs(CommandSpec c)
    {
        c.Value("cert-out", "PATH", "Write the generated certificate as DER (`.cer` / `.der`).");
        c.Value("pem-out", "PATH", "Write the generated certificate (plus issuer chain for issued leaves) as PEM (`.pem` / `.crt`).");
        c.Value("key-out", "PATH", "Write the generated RSA private key as unencrypted PKCS#8 PEM (`.key`).");
        c.Value("pfx-out", "PATH", "Write a PKCS#12 (`.pfx`) bundle containing the certificate, private key, and issuer chain.");
        c.Value("password", null, "Password for `--pfx-out` (defaults to empty password when `--pfx-out` is set).").Requiring("pfx-out");
        c.Flag("json", "Emit machine-readable JSON metadata to stdout.");
    }

    private static void AddTestPkiCaInputs(CommandSpec c)
    {
        c.Value("ca-pfx", "PATH", "Issuing CA PKCS#12 (`.pfx`) file.").Conflicts("ca-cert", "ca-key", "ca-chain-cert");
        c.Value("ca-password", null, "Password for `--ca-pfx` (defaults to empty password).").Requiring("ca-pfx");
        c.Value("ca-cert", "PATH", "Issuing CA certificate file (DER or PEM); requires `--ca-key`.").Requiring("ca-key").Conflicts("ca-pfx");
        c.Value("ca-key", "PATH", "Issuing CA RSA private key file (DER or unencrypted PEM); requires `--ca-cert`.").Requiring("ca-cert").Conflicts("ca-pfx");
        c.Multi("ca-chain-cert", "PATH", "Optional higher-level CA certificate(s) to append to the issued chain when using `--ca-cert`.").Requiring("ca-cert").Conflicts("ca-pfx");
    }

    private static void RegisterTestPki(CommandSpec portable)
    {
        portable.Sub("generate-root-ca", "Generate a self-signed X.509 v3 Root CA for local/test environments (no OS trust-store writes).", c =>
        {
            c.Value("subject", null, "Root CA Subject DN in Windows or RFC 4514 order.", "CN=psign Test Root CA");
            c.Value("validity-days", null, "Certificate validity period in days.", "3650");
            c.Value("key-bits", null, "RSA key size in bits (2048, 3072, or 4096).", "2048");
            AddTestPkiOutputs(c);
            c.Handler = p =>
            {
                if (!TryParseU32(p, "validity-days", out uint validity) || !TryParseUsize(p, "key-bits", out ulong bits))
                {
                    return 2;
                }

                EnsureTestPkiOutputs(p, "generate-root-ca");
                var material = Ctx("generate-root-ca", () => TestPki.GenerateRootCa(new RootCaSpec(p.Required("subject"), validity, KeyBits(bits))));
                WriteAndPrintTestPkiMaterial(p, material);
                return 0;
            };
        });

        portable.Sub("issue-code-signing-cert", "Issue an X.509 v3 Code Signing leaf certificate (`1.3.6.1.5.5.7.3.3`) chained to a test CA.", c =>
        {
            AddTestPkiCaInputs(c);
            c.Value("subject", null, "Signer Subject DN in Windows or RFC 4514 order.").Req();
            c.Value("validity-days", null, "Certificate validity period in days (clamped to the CA's `notAfter`).", "365");
            c.Value("key-bits", null, "RSA key size in bits (2048, 3072, or 4096).", "2048");
            c.Multi("eku-oid", "OID", "Additional Extended Key Usage OID to include alongside Code Signing (`1.3.6.1.5.5.7.3.3`).");
            AddTestPkiOutputs(c);
            c.Handler = p =>
            {
                if (!TryParseU32(p, "validity-days", out uint validity) || !TryParseUsize(p, "key-bits", out ulong bits))
                {
                    return 2;
                }

                EnsureTestPkiOutputs(p, "issue-code-signing-cert");
                var ca = Ctx("load issuing CA", () => LoadTestPkiCa(p));
                var material = Ctx("issue-code-signing-cert", () => TestPki.IssueCodeSigningCert(
                    ca,
                    new CodeSigningCertSpec(p.Required("subject"), validity, KeyBits(bits), p.Values("eku-oid").ToList())));
                WriteAndPrintTestPkiMaterial(p, material);
                return 0;
            };
        });

        portable.Sub("issue-tls-server-cert", "Issue an X.509 v3 TLS Server leaf certificate (`1.3.6.1.5.5.7.3.1`) with DNS/IP SANs chained to a test CA.", c =>
        {
            AddTestPkiCaInputs(c);
            c.Value("subject", null, "Optional Subject DN; defaults to `CN=<first --dns or --ip>`.");
            c.Multi("dns", "HOSTNAME", "DNS Subject Alternative Name (repeatable).");
            c.Multi("ip", "IP", "IPv4 or IPv6 Subject Alternative Name (repeatable).");
            c.Value("validity-days", null, "Certificate validity period in days (clamped to the CA's `notAfter`).", "365");
            c.Value("key-bits", null, "RSA key size in bits (2048, 3072, or 4096).", "2048");
            AddTestPkiOutputs(c);
            c.Handler = p =>
            {
                var ips = new List<IPAddress>();
                foreach (var raw in p.Values("ip"))
                {
                    if (!TryParseRustIp(raw, out var ip))
                    {
                        ValueError(raw, "--ip <IP>", "invalid IP address syntax");
                        return 2;
                    }

                    ips.Add(ip);
                }

                if (!TryParseU32(p, "validity-days", out uint validity) || !TryParseUsize(p, "key-bits", out ulong bits))
                {
                    return 2;
                }

                EnsureTestPkiOutputs(p, "issue-tls-server-cert");
                var ca = Ctx("load issuing CA", () => LoadTestPkiCa(p));
                var material = Ctx("issue-tls-server-cert", () => TestPki.IssueTlsServerCert(
                    ca,
                    new TlsServerCertSpec(p.Value("subject"), p.Values("dns").ToList(), ips, validity, KeyBits(bits))));
                WriteAndPrintTestPkiMaterial(p, material);
                return 0;
            };
        });
    }

    private static void EnsureTestPkiOutputs(ParsedCommand p, string command)
    {
        if (p.Value("cert-out") is null && p.Value("pem-out") is null && p.Value("key-out") is null && p.Value("pfx-out") is null)
        {
            throw new PsignException($"{command} requires at least one output flag (--cert-out, --pem-out, --key-out, or --pfx-out)");
        }
    }

    /// <summary>Rust <c>load_test_pki_ca_input</c>.</summary>
    private static CaIssuerMaterial LoadTestPkiCa(ParsedCommand p)
    {
        if (p.Value("ca-pfx") is { } pfxPath)
        {
            var pfx = Output.ReadFile(pfxPath);
            var password = p.Value("ca-password") ?? string.Empty;
            return Ctx($"load CA PFX {pfxPath}", () => TestPki.LoadCaIssuerFromPfx(pfx, password));
        }

        var certPath = p.Value("ca-cert");
        var keyPath = p.Value("ca-key");
        if (certPath is null || keyPath is null)
        {
            throw new PsignException("specify either --ca-pfx <PATH> [--ca-password <PW>] or --ca-cert <PATH> --ca-key <PATH>");
        }

        var certBytes = Output.ReadFile(certPath);
        var keyBytes = Output.ReadFile(keyPath);
        var extra = new List<byte[]>();
        foreach (var extraPath in p.Values("ca-chain-cert"))
        {
            var raw = Output.ReadFile(extraPath);
            extra.Add(Ctx($"parse CA chain certificate {extraPath}", () => CertificateLoader.ParseCertificate(raw)).RawData);
        }

        return TestPki.LoadCaIssuerFromCertAndKey(certBytes, keyBytes, extra);
    }

    private static void EnsureParentDirectory(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(parent))
        {
            try
            {
                Directory.CreateDirectory(parent);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new PsignException($"create parent directory {parent}", new PsignException(IoErrorText.Message(e)));
            }
        }
    }

    private static void WriteRestrictedFile(string path, byte[] bytes)
    {
        EnsureParentDirectory(path);
        if (OperatingSystem.IsWindows())
        {
            Output.WriteFile(path, bytes);
            return;
        }

        try
        {
            var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite };
            using var fs = new FileStream(path, options);
            fs.Write(bytes);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"write {path}", new PsignException(IoErrorText.Message(e)));
        }
    }

    /// <summary>Rust <c>write_and_print_test_pki_material</c>.</summary>
    private static void WriteAndPrintTestPkiMaterial(ParsedCommand p, GeneratedCertMaterial material)
    {
        var certOut = p.Value("cert-out");
        var pemOut = p.Value("pem-out");
        var keyOut = p.Value("key-out");
        var pfxOut = p.Value("pfx-out");
        if (certOut is not null)
        {
            EnsureParentDirectory(certOut);
            Output.WriteFile(certOut, material.CertificateDer);
        }

        if (pemOut is not null)
        {
            EnsureParentDirectory(pemOut);
            var bundle = new List<byte[]> { material.CertificateDer };
            bundle.AddRange(material.ChainCertificatesDer);
            Output.WriteFile(pemOut, System.Text.Encoding.ASCII.GetBytes(TestPki.EncodePemCertificateBundle(bundle)));
        }

        if (keyOut is not null)
        {
            WriteRestrictedFile(keyOut, System.Text.Encoding.ASCII.GetBytes(material.PrivateKeyPem));
        }

        if (pfxOut is not null)
        {
            var password = p.Value("password") ?? string.Empty;
            var pfx = Ctx($"encode PFX {pfxOut}", () => TestPki.EncodePfxDer(material, password));
            WriteRestrictedFile(pfxOut, pfx);
        }

        var s = material.Summary;
        if (p.Flag("json"))
        {
            var report = s.ToJsonObject();
            if (certOut is not null)
            {
                report["cert_out"] = certOut;
            }

            if (pemOut is not null)
            {
                report["pem_out"] = pemOut;
            }

            if (keyOut is not null)
            {
                report["key_out"] = keyOut;
            }

            if (pfxOut is not null)
            {
                report["pfx_out"] = pfxOut;
            }

            Output.Line(RustJson.Pretty(report));
            return;
        }

        Output.Line($"subject={s.Subject}");
        Output.Line($"issuer={s.Issuer}");
        Output.Line($"thumbprint_sha1={s.ThumbprintSha1}");
        Output.Line($"thumbprint_sha256={s.ThumbprintSha256}");
        Output.Line($"serial_hex={s.SerialHex}");
        Output.Line($"not_before={s.NotBefore}");
        Output.Line($"not_after={s.NotAfter}");
        Output.Line($"is_ca={(s.IsCa ? "yes" : "no")}");
        if (s.EkuOids.Count > 0)
        {
            Output.Line($"eku_oids={string.Join(',', s.EkuOids)}");
        }

        if (s.DnsNames.Count > 0)
        {
            Output.Line($"dns_names={string.Join(',', s.DnsNames)}");
        }

        if (s.IpAddresses.Count > 0)
        {
            Output.Line($"ip_addresses={string.Join(',', s.IpAddresses)}");
        }

        Output.Line($"chain_certificate_count={s.ChainCertificateCount}");
        if (certOut is not null)
        {
            Output.Line($"cert_out={certOut}");
        }

        if (pemOut is not null)
        {
            Output.Line($"pem_out={pemOut}");
        }

        if (keyOut is not null)
        {
            Output.Line($"key_out={keyOut}");
        }

        if (pfxOut is not null)
        {
            Output.Line($"pfx_out={pfxOut}");
        }
    }

    // ------------------------------------------------------------------ clap value parsing

    /// <summary>clap value-parser error (exit status 2, no usage line).</summary>
    private static void ValueError(string value, string display, string reason)
    {
        Output.ErrorLine($"error: invalid value '{value}' for '{display}': {reason}");
        Output.ErrorLine();
        Output.ErrorLine("For more information, try '--help'.");
    }

    private static string ValueDisplay(string id) => $"--{id} <{id.ToUpperInvariant().Replace('-', '_')}>";

    /// <summary>clap <c>value_parser!(u32)</c> (ranged <c>i64</c> parser): integer syntax first, then the range.</summary>
    private static bool TryParseU32(ParsedCommand p, string id, out uint value)
    {
        var raw = p.Required(id);
        value = 0;
        if (!TryParseRustInteger(raw, out var reason, out var big))
        {
            ValueError(raw, ValueDisplay(id), reason);
            return false;
        }

        if (big < 0 || big > uint.MaxValue)
        {
            ValueError(raw, ValueDisplay(id), $"{big} is not in 0..={uint.MaxValue}");
            return false;
        }

        value = (uint)big;
        return true;
    }

    /// <summary>clap <c>usize</c> (<c>FromStr</c>) value parser.</summary>
    private static bool TryParseUsize(ParsedCommand p, string id, out ulong value)
    {
        var raw = p.Required(id);
        var digits = raw.StartsWith('+') ? raw[1..] : raw;
        if (digits.Length > 0 && digits.All(char.IsAsciiDigit) && ulong.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out value))
        {
            return true;
        }

        value = 0;
        var reason = raw.Length == 0
            ? "cannot parse integer from empty string"
            : digits.Length > 0 && digits.All(char.IsAsciiDigit) ? "number too large to fit in target type" : "invalid digit found in string";
        ValueError(raw, ValueDisplay(id), reason);
        return false;
    }

    /// <summary>Rust <c>i64::from_str</c>.</summary>
    private static bool TryParseRustInteger(string raw, out string reason, out long value)
    {
        value = 0;
        reason = string.Empty;
        if (raw.Length == 0)
        {
            reason = "cannot parse integer from empty string";
            return false;
        }

        bool negative = raw[0] == '-';
        var digits = raw[0] is '+' or '-' ? raw[1..] : raw;
        if (digits.Length == 0 || !digits.All(char.IsAsciiDigit))
        {
            reason = "invalid digit found in string";
            return false;
        }

        if (!long.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value))
        {
            reason = negative ? "number too small to fit in target type" : "number too large to fit in target type";
            return false;
        }

        return true;
    }

    /// <summary>RSA key size from a <c>usize</c> option (sizes beyond <see cref="int"/> fail like the Rust validation).</summary>
    private static int KeyBits(ulong bits) => bits <= int.MaxValue
        ? (int)bits
        : throw new PsignException($"unsupported RSA key size {bits}; supported values are 2048, 3072, or 4096");

    /// <summary>Rust <c>IpAddr::from_str</c>: strict dotted-quad IPv4 or IPv6 text.</summary>
    internal static bool TryParseRustIp(string raw, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (raw.Contains(':', StringComparison.Ordinal))
        {
            if (raw.IndexOfAny(['%', '[', ']', '/']) >= 0 || !IPAddress.TryParse(raw, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }

            ip = v6;
            return true;
        }

        var parts = raw.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        var octets = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            var part = parts[i];
            if (part.Length is 0 or > 3 || !part.All(char.IsAsciiDigit) || (part.Length > 1 && part[0] == '0'))
            {
                return false;
            }

            int v = int.Parse(part, CultureInfo.InvariantCulture);
            if (v > 255)
            {
                return false;
            }

            octets[i] = (byte)v;
        }

        ip = new IPAddress(octets);
        return true;
    }

    // ------------------------------------------------------------------ error context

    /// <summary>Run <paramref name="f"/> and wrap failures with a Rust-style <c>.context(..)</c>.</summary>
    internal static T Ctx<T>(string context, Func<T> f)
    {
        try
        {
            return f();
        }
        catch (Exception e) when (e is PsignException or IOException or UnauthorizedAccessException or FormatException
            or System.Security.Cryptography.CryptographicException or System.Formats.Asn1.AsnContentException or InvalidDataException
            or ArgumentException or HttpRequestException or OverflowException or InvalidOperationException)
        {
            throw new PsignException(context, e);
        }
    }

    internal static void Ctx(string context, Action f) => Ctx<object?>(context, () =>
    {
        f();
        return null;
    });
}
