using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.ArtifactSigning;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Signing.Msix;
using Devolutions.Psign.Signing.Scripts;
using Devolutions.Psign.Signing.Timestamp;
using Devolutions.Psign.Signing.Vsix;

namespace Devolutions.Psign.Signing.Portable;

public static partial class PortableCore
{
    /// <summary>
    /// Sign <see cref="PortableSignRequest.Path"/> (Rust <c>portable_sign</c>): PE/WinMD, CAB, MSI/MSP, MSIX/AppX packages
    /// and bundles, NuGet, VSIX, ClickOnce manifests, App Installer companions, ZIP and PowerShell scripts, with a local
    /// key, Azure Key Vault or Azure Artifact Signing, optional RFC 3161 timestamping, then a digest-only self-inspection
    /// of the output.
    /// </summary>
    public static PortableSignResponse PortableSign(PortableSignRequest request, PortableCoreOptions? options = null)
    {
        options ??= PortableCoreOptions.Default;
        var format = InferFormat(request.Path);
        var outputPath = request.OutputPath ?? request.Path;

        bool skipped = format switch
        {
            PortableFileFormat.Pe => SignPe(request, outputPath, options),
            PortableFileFormat.Cab => Done(() => SignCab(request, outputPath, options)),
            PortableFileFormat.Msi => Done(() => SignMsi(request, outputPath, options)),
            PortableFileFormat.Msix => SignMsix(request, outputPath, options),
            PortableFileFormat.MsixUpload => throw new PsignException(
                "portable signing does not support MSIX/AppX upload bundles (.appxupload/.msixupload); they are dotnet/SignTool packaging containers whose nested flat packages should be prepared and signed individually"),
            PortableFileFormat.MsixEncrypted => throw new PsignException(
                "portable signing does not support encrypted MSIX/AppX packages (.eappx/.eappxbundle/.emsix/.emsixbundle); encrypted packages require Windows AppxSip OS delegation"),
            PortableFileFormat.NuGet => Done(() => SignNuGet(request, outputPath, options)),
            PortableFileFormat.Vsix => Done(() => SignVsix(request, outputPath, options)),
            PortableFileFormat.ClickOnceManifest => Done(() => SignClickOnceManifest(request, outputPath, options)),
            PortableFileFormat.AppInstaller => Done(() => SignAppInstaller(request, outputPath, options)),
            PortableFileFormat.Zip => Done(() => SignZip(request, outputPath, options)),
            PortableFileFormat.PowerShellScript => Done(() => SignScript(request, outputPath, options)),
            PortableFileFormat.WshScript => throw new PsignException("portable WSH script signing is not supported yet"),
            PortableFileFormat.Catalog => throw new PsignException(
                "portable catalog signing requires an explicit subject list and is not available through PortableSignRequest yet"),
            _ => throw new PsignException($"unsupported portable signing format: {request.Path}"),
        };

        var signature = PortableGetSignature(PortableGetSignatureRequest.PathOnly(outputPath), options);
        return new PortableSignResponse
        {
            InputPath = request.Path,
            OutputPath = outputPath,
            Format = format,
            Signature = signature,
            Skipped = skipped,
        };
    }

    private static bool Done(Action action)
    {
        action();
        return false;
    }

    private static T WithContext<T>(string context, Func<T> action)
    {
        try
        {
            return action();
        }
        catch (Exception e) when (IsOperationError(e))
        {
            throw new PsignException(context, e);
        }
    }

    private static void WithContext(string context, Action action)
    {
        try
        {
            action();
        }
        catch (Exception e) when (IsOperationError(e))
        {
            throw new PsignException(context, e);
        }
    }

    /// <summary>Errors the Rust implementation reports as <c>anyhow</c> errors (as opposed to programming errors).</summary>
    internal static bool IsOperationError(Exception e) => e is not (NullReferenceException or InvalidCastException or OutOfMemoryException or StackOverflowException);

    // ------------------------------------------------------------------ PE

    private static bool SignPe(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var pe = ReadFile(request.Path);
        if (request.SkipSigned
            && WithContext($"check existing PE/WinMD Authenticode signature for {request.Path}", () => PeAuthenticode.VerifyDigestConsistencyIfSigned(pe)) is not null)
        {
            if (!SamePath(outputPath, request.Path))
            {
                CopyFile(request.Path, outputPath);
            }

            return true;
        }

        if (!request.AppendSignature)
        {
            pe = WithContext($"remove existing PE Authenticode signatures from {request.Path}", () => PeEmbed.RemoveCertificates(pe).Image);
        }

        pe = WithContext($"prepare PE certificate table alignment for {request.Path}", () => PeEmbed.PrepareForAuthenticodeSigning(pe));
        using var provider = LoadSigningProvider(request, options);
        var digest = request.HashAlgorithm.ToHashKind();
        var peDigest = PeAuthenticode.Digest(pe, digest);
        var indirect = SpcIndirectDataContent.ForPe(digest, peDigest);
        var pkcs7 = WithContext($"create portable PE Authenticode signature for {request.Path}", () => provider.CreateAuthenticodePkcs7(indirect, digest));
        pkcs7 = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, pkcs7, options));
        var signed = WithContext($"embed Authenticode signature in {request.Path}", () => PeEmbed.AppendPkcs7Certificate(pe, pkcs7));
        WriteFile(outputPath, signed);
        return false;
    }

    // ------------------------------------------------------------------ CAB / MSI

    private static void SignCab(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var cab = ReadFile(request.Path);
        using var provider = LoadSigningProvider(request, options);
        var digest = request.HashAlgorithm.ToHashKind();
        var cabDigest = CabDigest.AuthenticodeDigestForSigning(cab, digest);
        var indirect = SpcIndirectDataContent.ForCab(digest, cabDigest);
        var pkcs7 = WithContext($"create portable CAB Authenticode signature for {request.Path}", () => provider.CreateAuthenticodePkcs7(indirect, digest));
        pkcs7 = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, pkcs7, options));
        var signed = WithContext($"embed Authenticode signature in {request.Path}", () => CabDigest.AppendAuthenticodePkcs7Signature(cab, pkcs7));
        WriteFile(outputPath, signed);
    }

    private static void SignMsi(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var msi = ReadFile(request.Path);
        using var provider = LoadSigningProvider(request, options);
        var digest = request.HashAlgorithm.ToHashKind();
        var prepared = MsiDigest.PrepareForAuthenticodeSigning(msi, digest);
        var indirect = SpcIndirectDataContent.ForMsi(digest, prepared.Digest);
        var pkcs7 = WithContext($"create portable MSI Authenticode signature for {request.Path}", () => provider.CreateAuthenticodePkcs7(indirect, digest));
        pkcs7 = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, pkcs7, options));
        WithContext($"embed Authenticode signature in {request.Path}", () => MsiDigest.EmbedPreparedAuthenticodePkcs7Signature(prepared, outputPath, pkcs7));
    }

    // ------------------------------------------------------------------ MSIX

    private static bool SignMsix(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var ext = RustText.ToAsciiLowercase(RustPath.Extension(request.Path) ?? string.Empty);
        if (MsixDigest.IsEncryptedMsixExtension(ext))
        {
            throw new PsignException(
                $"portable MSIX signing does not support encrypted packages (.{ext}); encrypted packages require Windows AppxSip OS delegation");
        }

        if (!IsPortableMsixFamilyExtension(ext))
        {
            throw new PsignException($"portable MSIX signing supports flat .msix/.appx packages and .msixbundle/.appxbundle bundles; got .{ext}");
        }

        var package = ReadFile(request.Path);
        if (request.SkipSigned && MsixDigest.MsixSignaturePartPresent(package))
        {
            if (!SamePath(outputPath, request.Path))
            {
                CopyFile(request.Path, outputPath);
            }

            return true;
        }

        using var provider = LoadSigningProvider(request, options);
        var signed = WithContext($"sign MSIX/AppX {request.Path}", () => SignMsixBytesWithProvider(package, ext, request, provider, options));
        WriteFile(outputPath, signed);
        return false;
    }

    private static byte[] SignMsixBytesWithProvider(byte[] package, string ext, PortableSignRequest request, PortableSigningProvider provider, PortableCoreOptions options)
    {
        var source = IsMsixBundleExtension(ext) && MsixSigner.BundleHasUnsignedEmbeddedChildren(package)
            ? SignUnsignedBundleChildren(package, request, provider, options)
            : package;

        var digest = request.HashAlgorithm.ToHashKind();
        var staged = WithContext($"stage {request.Path} for MSIX signing", () => AppxPackage.StageMsixFamilyForSignature(source, ext, digest));
        var indirect = MsixSigner.SpcIndirectData(staged, ext, digest);
        var pkcs7 = WithContext($"create portable MSIX Authenticode signature for {request.Path}", () => provider.CreateAuthenticodePkcs7(indirect, digest));
        pkcs7 = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, pkcs7, options));
        return WithContext($"embed AppxSignature.p7x in {request.Path}", () => AppxPackage.ReplaceMsixSignaturePart(staged, MsixSigner.ToP7x(pkcs7)));
    }

    private static byte[] SignUnsignedBundleChildren(byte[] package, PortableSignRequest request, PortableSigningProvider provider, PortableCoreOptions options)
    {
        var archive = WithContext("open MSIX bundle ZIP", () => ZipArchiveReader.Open(package));
        var entries = new List<(string Name, byte[] Data)>();
        for (int i = 0; i < archive.Count; i++)
        {
            var entry = WithContext("read MSIX bundle ZIP entry", () => archive.ByIndex(i));
            var name = entry.Name.Replace('\\', '/');
            if (name.EndsWith('/'))
            {
                continue;
            }

            var data = archive.ReadAll(i);
            int dot = name.LastIndexOf('.');
            var childExt = dot >= 0 ? RustText.ToAsciiLowercase(name[(dot + 1)..]) : string.Empty;
            if (childExt is "msix" or "appx" && !MsixDigest.MsixSignaturePartPresent(data))
            {
                var child = data;
                data = WithContext($"sign unsigned bundle child `{name}`", () => SignMsixBytesWithProvider(child, childExt, request, provider, options));
            }

            entries.Add((name, data));
        }

        return LegacyZipWriter.WriteStored(entries);
    }

    // ------------------------------------------------------------------ ZIP / scripts

    private static void SignZip(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var zip = ReadFile(request.Path);
        var digestString = WithContext($"compute ZIP Authenticode digest for {request.Path}", () => ZipAuthenticode.ZipAuthenticodeDigestString(zip));
        var script = ZipAuthenticode.UnsignedSignatureScriptBytes(digestString);
        using var provider = LoadSigningProvider(request, options);
        var digest = request.HashAlgorithm.ToHashKind();
        var pkcs7 = WithContext(
            $"create portable ZIP signature script Authenticode signature for {request.Path}",
            () => provider.CreateAuthenticodePkcs7(ScriptSigner.ScriptAuthenticodeSpcIndirectData(script, digest), digest));
        pkcs7 = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, pkcs7, options));
        var line = ZipAuthenticode.SignatureCommentLineFromPkcs7Der(digestString, pkcs7);
        var signed = WithContext($"embed ZIP Authenticode comment in {request.Path}", () => ZipAuthenticode.EmbedSignatureCommentLine(zip, line));
        WriteFile(outputPath, signed);
    }

    private static void SignScript(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var ext = ScriptExtensionFor(request.Path);
        if (ext is not ("ps1" or "psd1" or "psm1" or "ps1xml" or "psc1" or "cdxml" or "mof"))
        {
            throw new PsignException("portable script signing supports ps1, psd1, psm1, ps1xml, psc1, cdxml, and mof scripts");
        }

        var script = ReadFile(request.Path);
        using var provider = LoadSigningProvider(request, options);
        var digest = request.HashAlgorithm.ToHashKind();
        var pkcs7 = WithContext(
            $"create portable script Authenticode signature for {request.Path}",
            () => provider.CreateAuthenticodePkcs7(ScriptSigner.ScriptAuthenticodeSpcIndirectData(script, digest), digest));
        pkcs7 = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, pkcs7, options));
        var block = FormatPowerShellSignatureBlock(pkcs7, ext);
        WriteFile(outputPath, AppendScriptSignatureBlock(script, block));
    }

    /// <summary>PowerShell signature block (Rust <c>format_powershell_signature_block</c>).</summary>
    internal static string FormatPowerShellSignatureBlock(byte[] pkcs7Der, string extension) =>
        ScriptSignatureBlock.FormatPowerShellSignatureBlock(pkcs7Der, extension);

    /// <summary>Append a block in the script's own encoding (Rust <c>append_script_signature_block</c>).</summary>
    internal static byte[] AppendScriptSignatureBlock(byte[] script, string block) =>
        ScriptSignatureBlock.AppendSignatureBlock(script, block);

    // ------------------------------------------------------------------ NuGet / VSIX

    private static void SignNuGet(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var data = ReadFile(request.Path);
        using var provider = LoadSigningProvider(request, options);
        var nugetAlg = NuGetHashAlgorithmExtensions.FromHashKind(request.HashAlgorithm.ToHashKind());
        var unsigned = WithContext($"canonicalize NuGet package for signing {request.Path}", () => NuGetPackage.CanonicalUnsignedPackageBytes(data));
        var content = NuGetPackage.SignatureContentBytes(nugetAlg, nugetAlg.Hash(unsigned));
        var pkcs7 = WithContext(
            $"create NuGet CMS signature for {request.Path}",
            () => provider.CreateNuGetAuthorSignature(content, request.HashAlgorithm.ToHashKind(), options.Now()));
        var pkcs7Final = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, pkcs7, options));
        var signed = WithContext(
            $"embed NuGet signature into {request.Path}",
            () => NuGetPackage.EmbedSignature(unsigned, pkcs7Final, overwrite: false, options.ZipClock?.Invoke()));
        WriteFile(outputPath, signed);
    }

    private static void SignVsix(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var data = ReadFile(request.Path);
        using var provider = LoadSigningProvider(request, options);
        var vsixAlg = VsixHashAlgorithmExtensions.FromHashKind(request.HashAlgorithm.ToHashKind());
        var template = WithContext(
            $"create VSIX signature for {request.Path}",
            () => VsixPackage.SignatureTemplate(data, vsixAlg, VsixSigningTime.Now, options.Now()));
        var (signature, certDer) = provider.SignXmlSignedInfo(vsixAlg, template.SignedInfo);
        var xml = template.SignatureXmlBytes(signature, certDer);
        if (request.TimestampServer is { } server)
        {
            var alg = request.TimestampHashAlgorithm ?? PortableTimestampDigestAlgorithm.Sha256;
            var signatureValue = VsixPackage.SignatureValueFromSignatureXml(xml);
            var token = WithContext($"timestamp {request.Path}", () => RequestRfc3161Token(server, alg, signatureValue, options));
            xml = VsixSigner.AddSignatureTimestamp(xml, token);
        }
        else if (request.TimestampHashAlgorithm is not null)
        {
            throw new PsignException("timestamp_hash_algorithm requires timestamp_server");
        }

        var signed = WithContext($"embed VSIX signature XML into {request.Path}", () => VsixPackage.EmbedSignatureXml(data, xml, overwrite: false));
        WriteFile(outputPath, signed);
    }

    // ------------------------------------------------------------------ ClickOnce / App Installer

    private static void SignClickOnceManifest(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var data = ReadFile(request.Path);
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(data);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException($"read ClickOnce manifest {request.Path} as UTF-8", e);
        }

        using var provider = LoadSigningProvider(request, options);
        var vsixAlg = VsixHashAlgorithmExtensions.FromHashKind(request.HashAlgorithm.ToHashKind());
        var unsigned = RemoveClickOnceXmlSignature(text);
        var signedInfo = ClickOnceManifestSignedInfoXmlBytes(unsigned, vsixAlg);
        var (signature, certDer) = provider.SignXmlSignedInfo(vsixAlg, signedInfo);
        var signatureXml = BuildClickOnceSignatureXml(signedInfo, signature, certDer);
        var signed = InsertClickOnceSignatureInManifest(unsigned, signatureXml);
        WriteFile(outputPath, Encoding.UTF8.GetBytes(signed));
    }

    /// <summary>Remove the first <c>&lt;Signature …&lt;/Signature&gt;</c> span (Rust <c>remove_clickonce_xml_signature</c>).</summary>
    internal static string RemoveClickOnceXmlSignature(string text)
    {
        const string end = "</Signature>";
        int start = text.IndexOf("<Signature", StringComparison.Ordinal);
        if (start >= 0)
        {
            int rel = text.IndexOf(end, start, StringComparison.Ordinal);
            if (rel >= 0)
            {
                return text[..start] + text[(rel + end.Length)..];
            }
        }

        return text;
    }

    /// <summary>Enveloped-signature <c>SignedInfo</c> for a ClickOnce manifest (Rust <c>clickonce_manifest_signed_info_xml_bytes</c>).</summary>
    internal static byte[] ClickOnceManifestSignedInfoXmlBytes(string unsignedManifestText, VsixHashAlgorithm algorithm)
    {
        var digestB64 = Convert.ToBase64String(algorithm.Hash(Encoding.UTF8.GetBytes(unsignedManifestText)));
        return Encoding.UTF8.GetBytes(
            "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            + $"<SignatureMethod Algorithm=\"{algorithm.SignatureUri()}\"/>"
            + "<Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>"
            + $"<DigestMethod Algorithm=\"{algorithm.DigestUri()}\"/><DigestValue>{digestB64}</DigestValue></Reference></SignedInfo>");
    }

    /// <summary><c>Signature</c> element (Rust <c>build_clickonce_signature_xml</c>).</summary>
    internal static string BuildClickOnceSignatureXml(byte[] signedInfo, byte[] signature, byte[] certDer) =>
        $"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{Encoding.UTF8.GetString(signedInfo)}<SignatureValue>{Convert.ToBase64String(signature)}</SignatureValue>"
        + $"<KeyInfo><X509Data><X509Certificate>{Convert.ToBase64String(certDer)}</X509Certificate></X509Data></KeyInfo></Signature>";

    /// <summary>Insert before the last <c>&lt;/</c> (Rust <c>insert_clickonce_signature_in_manifest</c>).</summary>
    internal static string InsertClickOnceSignatureInManifest(string text, string signatureXml)
    {
        int close = text.LastIndexOf("</", StringComparison.Ordinal);
        if (close < 0)
        {
            throw new PsignException("ClickOnce manifest does not have a closing root element tag");
        }

        return text[..close] + signatureXml + text[close..];
    }

    private static void SignAppInstaller(PortableSignRequest request, string outputPath, PortableCoreOptions options)
    {
        var data = ReadFile(request.Path);
        using var provider = LoadSigningProvider(request, options);
        var econtentDer = Pkcs7IdData.EContentDer(data);
        var detached = WithContext(
            $"create detached PKCS#7 companion signature for {request.Path}",
            () => provider.CreatePkcs7SignedData(Oids.Pkcs7Data, econtentDer, request.HashAlgorithm.ToHashKind(), Pkcs7ContentMode.Detached));
        var final = WithContext($"timestamp {request.Path}", () => MaybeTimestampPkcs7(request, detached, options));
        var companion = AppInstallerCompanionPath(outputPath);
        if (!SamePath(outputPath, request.Path))
        {
            CopyFile(request.Path, outputPath);
        }

        WriteFile(companion, final, $"write companion {companion}");
    }

    // ------------------------------------------------------------------ timestamping

    private static byte[] MaybeTimestampPkcs7(PortableSignRequest request, byte[] pkcs7Der, PortableCoreOptions options)
    {
        if (request.TimestampServer is not { } server)
        {
            if (request.TimestampHashAlgorithm is not null)
            {
                throw new PsignException("timestamp_hash_algorithm requires timestamp_server");
            }

            return pkcs7Der;
        }

        var alg = request.TimestampHashAlgorithm ?? PortableTimestampDigestAlgorithm.Sha256;
        CmsSignedData sd;
        try
        {
            sd = CmsSignedData.Parse(pkcs7Der);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            throw new PsignException("parse PKCS#7 SignedData", e);
        }

        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("PKCS#7 SignedData has no SignerInfo to timestamp");
        }

        var token = RequestRfc3161Token(server, alg, sd.SignerInfos[0].Signature, options);
        var stamped = WithContext("attach RFC3161 timestamp token", () => Pkcs7Builder.AddTimestampToken(sd, 0, token));
        return stamped.Encode();
    }

    /// <summary>RFC 3161 token (DER <c>ContentInfo</c>) whose imprint covers <paramref name="stamped"/> (Rust <c>request_rfc3161_token</c>).</summary>
    private static byte[] RequestRfc3161Token(string server, PortableTimestampDigestAlgorithm alg, byte[] stamped, PortableCoreOptions options)
    {
        using var client = new TimestampClient(options.HttpHandler);
        return client.RequestToken(server, alg.ToHashKind(), stamped);
    }

    // ------------------------------------------------------------------ provider selection

    private static bool HasAzureKeyVaultProvider(PortableSignRequest r) => r.AzureKeyVaultUrl is not null;

    private static bool HasArtifactSigningProvider(PortableSignRequest r) => r.ArtifactSigningEndpoint is not null || r.ArtifactSigningAccountName is not null;

    private static bool HasLocalSigningMaterial(PortableSignRequest r) =>
        r.CertificatePath is not null || r.CertificateDerBase64 is not null || r.PfxPath is not null || r.PrivateKeyPath is not null || r.PrivateKeyDerBase64 is not null;

    private static void ValidateSigningProviderSelection(PortableSignRequest request)
    {
        var akv = HasAzureKeyVaultProvider(request);
        var artifact = HasArtifactSigningProvider(request);
        var local = HasLocalSigningMaterial(request);
        if (akv && artifact)
        {
            throw new PsignException("provide only one cloud signing provider (Azure Key Vault or Artifact Signing), not both");
        }

        if (akv && local)
        {
            throw new PsignException("provide either Azure Key Vault cloud signing or local certificate/key material, not both");
        }

        if (artifact && local)
        {
            throw new PsignException("provide either Artifact Signing cloud signing or local certificate/key material, not both");
        }
    }

    private static void EnsureLocalSigningProvider(PortableSignRequest request)
    {
        ValidateSigningProviderSelection(request);
        if (HasAzureKeyVaultProvider(request))
        {
            throw new PsignException("Azure Key Vault cloud signing is not wired for this portable signing format yet");
        }

        if (HasArtifactSigningProvider(request))
        {
            throw new PsignException("Artifact Signing cloud signing is not wired for this portable signing format yet");
        }
    }

    internal static PortableSigningProvider LoadSigningProvider(PortableSignRequest request, PortableCoreOptions options)
    {
        ValidateSigningProviderSelection(request);
        if (HasAzureKeyVaultProvider(request))
        {
            return LoadAzureKeyVaultSigningProvider(request, options);
        }

        if (HasArtifactSigningProvider(request))
        {
            return LoadArtifactSigningProvider(request, options);
        }

        var (cert, key, chain) = LoadSigningMaterial(request);
        return new LocalPortableSigningProvider(cert, key, chain);
    }

    private static string? TextOpt(string? value)
    {
        var t = value?.Trim();
        return string.IsNullOrEmpty(t) ? null : t;
    }

    private static PortableSigningProvider LoadAzureKeyVaultSigningProvider(PortableSignRequest request, PortableCoreOptions options)
    {
        var vaultUrl = TextOpt(request.AzureKeyVaultUrl) ?? throw new PsignException("Azure Key Vault signing requires azure_key_vault_url");
        var certificate = TextOpt(request.AzureKeyVaultCertificate) ?? throw new PsignException("Azure Key Vault signing requires azure_key_vault_certificate");
        ValidateKvAuthInputs(request);

        var client = new AzureKeyVaultClient(options.HttpHandler);
        try
        {
            var auth = new KvAuthParams
            {
                AccessToken = request.AzureKeyVaultAccessToken,
                ManagedIdentity = request.AzureKeyVaultManagedIdentity ?? false,
                TenantId = request.AzureKeyVaultTenantId,
                ClientId = request.AzureKeyVaultClientId,
                ClientSecret = request.AzureKeyVaultClientSecret,
                Authority = request.AzureAuthority,
            };
            var token = client.AcquireAccessToken(auth);
            var kvCertificate = client.FetchCertificate(vaultUrl, certificate, request.AzureKeyVaultCertificateVersion, token);
            var signerDer = AzureKeyVaultClient.DecodeCerBase64(kvCertificate.Cer);
            CertificateInfo signerCert;
            try
            {
                signerCert = SigningMaterialLoader.ParseCertificate(signerDer);
            }
            catch (PsignException e)
            {
                throw new PsignException("parse Key Vault signer certificate", e);
            }

            var chain = LoadChainCertificates(request);
            return new AzureKeyVaultPortableSigningProvider(client, token, kvCertificate, signerCert, chain);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static void ValidateKvAuthInputs(PortableSignRequest request)
    {
        var hasSp = TextOpt(request.AzureKeyVaultClientSecret) is not null;
        var hasTenant = TextOpt(request.AzureKeyVaultTenantId) is not null;
        var hasClient = TextOpt(request.AzureKeyVaultClientId) is not null;
        var hasToken = TextOpt(request.AzureKeyVaultAccessToken) is not null;
        var managedIdentity = request.AzureKeyVaultManagedIdentity ?? false;
        var spCount = (hasSp ? 1 : 0) + (hasTenant ? 1 : 0) + (hasClient ? 1 : 0);
        if (spCount != 0 && spCount != 3)
        {
            throw new PsignException(
                "Azure AD client credentials require azure_key_vault_client_id, azure_key_vault_client_secret, and azure_key_vault_tenant_id");
        }

        if (hasToken && (managedIdentity || spCount == 3))
        {
            throw new PsignException("use either Azure Key Vault access token or managed identity / client credentials, not multiple");
        }

        if (managedIdentity && (hasToken || spCount == 3))
        {
            throw new PsignException("Azure Key Vault managed identity cannot be combined with access tokens or client secrets");
        }

        if (!hasToken && !managedIdentity && spCount != 3)
        {
            throw new PsignException("choose Azure Key Vault authentication: access token, managed identity, or client id/secret/tenant");
        }
    }

    private static PortableSigningProvider LoadArtifactSigningProvider(PortableSignRequest request, PortableCoreOptions options)
    {
        var endpoint = TextOpt(request.ArtifactSigningEndpoint) ?? throw new PsignException("Artifact Signing requires artifact_signing_endpoint");
        var accountName = TextOpt(request.ArtifactSigningAccountName) ?? throw new PsignException("Artifact Signing requires artifact_signing_account_name");
        var profileName = TextOpt(request.ArtifactSigningProfileName) ?? throw new PsignException("Artifact Signing requires artifact_signing_profile_name");
        var auth = CodesigningAuthResolver.Resolve(
            new CodesigningAuthInput
            {
                AccessToken = request.ArtifactSigningAccessToken,
                ManagedIdentity = request.ArtifactSigningManagedIdentity ?? false,
                ManagedIdentityResourceId = request.ArtifactSigningManagedIdentityResourceId,
                TenantId = request.ArtifactSigningTenantId,
                ClientId = request.ArtifactSigningClientId,
                ClientSecret = request.ArtifactSigningClientSecret,
                FederatedTokenFile = request.ArtifactSigningFederatedTokenFile,
                CredentialType = request.ArtifactSigningCredentialType is { } ct ? ParseArtifactSigningCredentialType(ct) : null,
                ExcludeCredentials = [.. request.ArtifactSigningExcludeCredentials],
            },
            options.Environment);
        var chain = LoadChainCertificates(request);
        var template = new CodesigningSubmitParams
        {
            Region = "unused",
            AccountName = accountName,
            ProfileName = profileName,
            ApiVersion = ArtifactSigningClient.DefaultApiVersion,
            CorrelationId = TextOpt(request.ArtifactSigningCorrelationId),
            Authority = null,
            Auth = auth,
            EndpointBaseUrl = endpoint.TrimEnd('/'),
        };
        var client = new ArtifactSigningClient(options.HttpHandler, options.Environment);
        if (options.ArtifactSigningPollInterval is { } interval)
        {
            client.PollInterval = interval;
        }

        Action<string>? debug = options.GetEnvironment("SIGNTOOL_PORTABLE_DEBUG") is not null
            ? msg => (options.DebugLog ?? Console.Error).WriteLine($"[debug] {msg}")
            : null;
        return new ArtifactSigningPortableSigningProvider(client, template, chain, debug);
    }

    /// <summary>Credential type names accepted by the request (Rust <c>parse_artifact_signing_credential_type</c>).</summary>
    internal static CodesigningCredentialType ParseArtifactSigningCredentialType(string value)
    {
        var normalized = new string(value.Where(RustText.IsAsciiAlphanumeric).Select(RustText.ToAsciiLower).ToArray());
        return normalized switch
        {
            "" or "default" or "defaultazurecredential" => CodesigningCredentialType.Default,
            "managedidentity" or "managedidentitycredential" => CodesigningCredentialType.ManagedIdentity,
            "accesstoken" or "bearer" => CodesigningCredentialType.AccessToken,
            "clientsecret" or "clientsecretcredential" => CodesigningCredentialType.ClientSecret,
            "workloadidentity" or "workloadidentitycredential" => CodesigningCredentialType.WorkloadIdentity,
            _ => throw new PsignException($"unsupported Artifact Signing credential type '{value}'"),
        };
    }

    /// <summary>Local signer certificate, RSA key and chain (Rust <c>load_signing_material</c>).</summary>
    internal static (CertificateInfo Cert, RSA Key, List<CertificateInfo> Chain) LoadSigningMaterial(PortableSignRequest request)
    {
        EnsureLocalSigningProvider(request);
        if (request.PfxPath is not null
            && (request.CertificateDerBase64 is not null || request.CertificatePath is not null || request.PrivateKeyDerBase64 is not null || request.PrivateKeyPath is not null))
        {
            throw new PsignException("provide either pfx_path or certificate/private key material, not both");
        }

        byte[] certBytes;
        byte[] keyBytes;
        IReadOnlyList<byte[]> pfxChain = [];
        if (request.PfxPath is { } pfxPath)
        {
            var pfx = ReadFile(pfxPath);
            var parsed = WithContext($"parse PFX {pfxPath}", () => Pkcs12Identity.Parse(pfx, request.PfxPassword ?? string.Empty));
            certBytes = parsed.SignerCertificateDer;
            keyBytes = Encoding.ASCII.GetBytes(parsed.PrivateKeyPem);
            pfxChain = parsed.ChainCertificatesDer;
        }
        else
        {
            certBytes = (request.CertificateDerBase64, request.CertificatePath) switch
            {
                (not null, not null) => throw new PsignException("provide only one of certificate_der_base64 or certificate_path"),
                ({ } b64, null) => DecodeBase64(b64, "decode certificate_der_base64"),
                (null, { } path) => ReadFile(path),
                _ => throw new PsignException("portable signing requires certificate_der_base64 or certificate_path"),
            };
            keyBytes = (request.PrivateKeyDerBase64, request.PrivateKeyPath) switch
            {
                (not null, not null) => throw new PsignException("provide only one of private_key_der_base64 or private_key_path"),
                ({ } b64, null) => DecodeBase64(b64, "decode private_key_der_base64"),
                (null, { } path) => ReadFile(path),
                _ => throw new PsignException("portable signing requires private_key_der_base64 or private_key_path"),
            };
        }

        var signerCert = WithContext("parse signer certificate", () => SigningMaterialLoader.ParseCertificate(certBytes));
        var key = WithContext("parse RSA private key", () => SigningMaterialLoader.ParseRsaPrivateKey(keyBytes));
        var chain = new List<CertificateInfo>(pfxChain.Count + request.ChainCertificatePaths.Count);
        for (int i = 0; i < pfxChain.Count; i++)
        {
            var der = pfxChain[i];
            chain.Add(WithContext($"parse PFX chain certificate[{i}]", () => SigningMaterialLoader.ParseCertificate(der)));
        }

        chain.AddRange(LoadChainCertificates(request));
        return (signerCert, key, chain);
    }

    private static List<CertificateInfo> LoadChainCertificates(PortableSignRequest request)
    {
        var chain = new List<CertificateInfo>();
        foreach (var path in request.ChainCertificatePaths)
        {
            var bytes = ReadFile(path);
            chain.Add(WithContext($"parse chain certificate {path}", () => SigningMaterialLoader.ParseCertificate(bytes)));
        }

        for (int i = 0; i < request.ChainCertificatesDerBase64.Count; i++)
        {
            var bytes = DecodeBase64(request.ChainCertificatesDerBase64[i], $"decode chain_certificates_der_base64[{i}]");
            chain.Add(WithContext($"parse chain certificate {i}", () => SigningMaterialLoader.ParseCertificate(bytes)));
        }

        return chain;
    }

    private static byte[] DecodeBase64(string text, string context)
    {
        try
        {
            return Base64Standard.Decode(text);
        }
        catch (FormatException e)
        {
            throw new PsignException(context, e);
        }
    }
}
