using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.ClickOnce;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Code;

/// <summary>
/// Signing execution of a <see cref="CodePlan"/> (ported from <c>execute_code_plan</c> and the <c>sign_*_bytes</c> /
/// <c>prepare_msix_family_bytes</c> / <c>sign_nested_package_entries</c> helpers in Rust <c>src/code.rs</c>). Only
/// top-level nodes are executed; nested ZIP/OPC entries are signed inside-out while their container is processed.
/// </summary>
internal sealed class CodeExecutor
{
    private const string MsixSignaturePart = "AppxSignature.p7x";

    private readonly CodeSigner _signer;
    private readonly IReadOnlyList<string> _chainPaths;
    private readonly IReadOnlyList<string> _nestedExcludes;
    private readonly bool _skipSigned;
    private readonly bool _overwrite;
    private readonly CodeTimestamp _timestamp;
    private readonly AuthenticodeHashKind _digest;

    private CodeExecutor(CodeSigner signer, CodeOptions options, IReadOnlyList<string> nestedExcludes, AuthenticodeHashKind digest)
    {
        _signer = signer;
        _chainPaths = options.ChainCerts;
        _nestedExcludes = nestedExcludes;
        _skipSigned = options.SkipSigned;
        _overwrite = options.Overwrite;
        _timestamp = new CodeTimestamp(options.TimestampUrl, options.TimestampDigest, options.HttpHandler);
        _digest = digest;
    }

    /// <summary>Rust <c>execute_code_plan</c>.</summary>
    public static CodeCommandResult Execute(CodeOptions options, CodePlan plan)
    {
        using var signer = CodeSigner.Resolve(options);
        if (options.Output is null)
        {
            throw new PsignException("`psign-tool code` signing execution currently requires --output to avoid in-place package mutation");
        }

        var digest = PackageDigest(options.FileDigest);
        var baseDir = plan.BaseDirectory;
        var nestedExcludes = CodePlanner.NestedExcludePatterns(baseDir, options);
        var executor = new CodeExecutor(signer, options, nestedExcludes, digest);

        var lines = new List<string>();
        int exitCode = 0;
        var topNodes = plan.Nodes.Where(n => n.Depth == 0).ToList();
        int maxConcurrency = Math.Max(options.MaxConcurrency ?? 1, 1);
        if (maxConcurrency == 1)
        {
            foreach (var node in topNodes)
            {
                try
                {
                    lines.Add(executor.ExecuteNode(baseDir, node, options.PublisherName));
                }
                catch (Exception e) when (options.ContinueOnError && IsExecutionError(e))
                {
                    exitCode = 1;
                    lines.Add($"failed {node.Path}: {PsignException.Render(e)}");
                }
            }
        }
        else
        {
            foreach (var chunk in topNodes.Chunk(maxConcurrency))
            {
                var results = new (string? Line, Exception? Error)[chunk.Length];
                Parallel.For(0, chunk.Length, new ParallelOptions { MaxDegreeOfParallelism = chunk.Length }, i =>
                {
                    try
                    {
                        results[i] = (executor.ExecuteNode(baseDir, chunk[i], options.PublisherName), null);
                    }
                    catch (Exception e) when (IsExecutionError(e))
                    {
                        results[i] = (null, e);
                    }
                });

                for (int i = 0; i < chunk.Length; i++)
                {
                    var (line, error) = results[i];
                    if (error is null)
                    {
                        lines.Add(line!);
                    }
                    else if (options.ContinueOnError)
                    {
                        exitCode = 1;
                        lines.Add($"failed {chunk[i].Path}: {PsignException.Render(error)}");
                    }
                    else
                    {
                        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
                    }
                }
            }
        }

        return new CodeCommandResult(string.Join("\n", lines) + "\n", exitCode);
    }

    private static bool IsExecutionError(Exception e) =>
        e is PsignException or IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException
            or System.Formats.Asn1.AsnContentException or InvalidDataException or HttpRequestException or FormatException;

    /// <summary>Rust <c>nuget_hash_algorithm</c> / <c>signing_digest_algorithm</c> / <c>vsix_hash_algorithm</c> (identical mapping).</summary>
    private static AuthenticodeHashKind PackageDigest(CodeDigestAlgorithm digest) => digest switch
    {
        CodeDigestAlgorithm.Sha256 => AuthenticodeHashKind.Sha256,
        CodeDigestAlgorithm.Sha384 => AuthenticodeHashKind.Sha384,
        CodeDigestAlgorithm.Sha512 => AuthenticodeHashKind.Sha512,
        _ => throw new PsignException("`psign-tool code` package signing supports SHA-256, SHA-384, or SHA-512 file digests"),
    };

    // ------------------------------------------------------------------ top-level nodes

    private string ExecuteNode(string baseDir, CodePlanNode node, string? publisher)
    {
        var input = RustPath.Join(baseDir, RustPath.DisplayToPath(node.Path));
        switch (node.Format)
        {
            case CodeFormat.Pe or CodeFormat.Winmd:
                {
                    var output = OutputPathForNode(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    if (_skipSigned && PeHasSignature(bytes))
                    {
                        RustIo.Write(output, bytes, $"write skipped Authenticode payload {output}");
                        return $"skipped {node.Path} -> {output} (already signed)";
                    }

                    var signed = Ctx($"sign Authenticode payload {input}", () => SignPeBytes(bytes, node.Path, skipSigned: false));
                    RustIo.Write(output, signed, $"write signed Authenticode payload {output}");
                    return $"signed {node.Path} -> {output} (Authenticode PE/WinMD)";
                }

            case CodeFormat.Nuget or CodeFormat.Snupkg:
                {
                    var output = OutputPathForNode(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    if (_skipSigned && PackageHasSignature(bytes, node.Format))
                    {
                        RustIo.Write(output, bytes, $"write skipped NuGet package {output}");
                        return $"skipped {node.Path} -> {output} (already signed)";
                    }

                    var signed = Ctx($"create NuGet package signature for {input}", () => SignNuGetBytes(bytes, node.Path, null));
                    RustIo.Write(output, signed, $"write signed NuGet package {output}");
                    return $"signed {node.Path} -> {output} ({NuGetPackage.PackageSignatureFileName})";
                }

            case CodeFormat.AppInstaller:
                {
                    var output = AppInstallerCompanionOutputPath(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    Ctx($"validate App Installer descriptor {input}", () =>
                    {
                        CodeXml.ValidateAppInstallerDescriptor(bytes);
                        return 0;
                    });
                    string? descriptorOutput = null;
                    if (publisher is not null)
                    {
                        bytes = Ctx($"update App Installer publisher for {input}", () => CodeXml.UpdateAppInstallerPublisherBytes(bytes, publisher));
                        descriptorOutput = AppInstallerDescriptorOutputPath(node);
                        EnsureParentDir(descriptorOutput);
                        RustIo.Write(descriptorOutput, bytes, $"write updated App Installer descriptor {descriptorOutput}");
                    }

                    var descriptor = bytes;
                    var pkcs7 = Ctx($"create App Installer companion signature for {input}", () => SignPkcs7IdData(
                        descriptor, Pkcs7ContentMode.Detached, Rfc3161TimestampAttribute.MicrosoftAuthenticode, Pkcs7SignedAttributeProfile.Basic));
                    RustIo.Write(output, pkcs7, $"write {output}");
                    return descriptorOutput is not null
                        ? $"signed {node.Path} -> {output} (updated descriptor {descriptorOutput}; detached PKCS#7 companion)"
                        : $"signed {node.Path} -> {output} (detached PKCS#7 companion)";
                }

            case CodeFormat.Vsix:
                {
                    var output = OutputPathForNode(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    if (_skipSigned && PackageHasSignature(bytes, node.Format))
                    {
                        RustIo.Write(output, bytes, $"write skipped VSIX package {output}");
                        return $"skipped {node.Path} -> {output} (already signed)";
                    }

                    var signed = Ctx($"create VSIX signature for {input}", () => SignVsixBytes(bytes, node.Path, _digest, null));
                    RustIo.Write(output, signed, $"write signed VSIX package {output}");
                    return $"signed {node.Path} -> {output} ({VsixPackage.DefaultVsixSignaturePart})";
                }

            case CodeFormat.Zip:
                {
                    var output = OutputPathForNode(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    var signed = Ctx($"sign nested package entries in {input}", () => SignNestedPackageEntries(bytes, node.Path, _digest, publisher));
                    RustIo.Write(output, signed, $"write signed ZIP container {output}");
                    return $"signed {node.Path} -> {output} (nested package entries)";
                }

            case CodeFormat.Msix or CodeFormat.Appx or CodeFormat.MsixBundle or CodeFormat.AppxBundle or CodeFormat.AppxUpload or CodeFormat.MsixUpload:
                {
                    var output = OutputPathForNode(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    var prepared = Ctx($"prepare MSIX/AppX package {input}", () => PrepareMsixFamilyBytes(bytes, node.Path, _digest, node.Format, publisher));
                    RustIo.Write(output, prepared, $"write prepared MSIX/AppX package {output}");
                    return $"prepared {node.Path} -> {output} (unsigned MSIX/AppX; final AppX SIP signing pending)";
                }

            case CodeFormat.EncryptedMsix:
                throw new PsignException($"`psign-tool code` recognized {node.Path} as an encrypted MSIX/AppX package; encrypted .eappx/.emsix packages require Windows AppxSip OS delegation and are not supported by the portable package prepare path");

            case CodeFormat.ClickOnceApplication or CodeFormat.Vsto or CodeFormat.Manifest:
                {
                    var output = OutputPathForNode(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    if (_skipSigned && ClickOnceManifest.HasSignature(bytes))
                    {
                        RustIo.Write(output, bytes, $"write skipped ClickOnce manifest {output}");
                        return $"skipped {node.Path} -> {output} (already signed)";
                    }

                    var signed = Ctx($"sign ClickOnce manifest {input}", () => SignClickOnceManifestBytes(bytes, node.Path, _digest));
                    RustIo.Write(output, signed, $"write signed ClickOnce manifest {output}");
                    return $"signed {node.Path} -> {output} (ClickOnce manifest XMLDSig)";
                }

            case CodeFormat.Deploy:
                {
                    var output = OutputPathForNode(node);
                    EnsureParentDir(output);
                    var bytes = RustIo.Read(input, $"read {input}");
                    var signed = Ctx($"sign ClickOnce deploy payload {input}", () => SignClickOnceDeployBytes(bytes, node.Path));
                    RustIo.Write(output, signed, $"write signed ClickOnce deploy payload {output}");
                    return $"signed {node.Path} -> {output} (ClickOnce .deploy payload)";
                }

            case CodeFormat.BusinessCentralApp:
                throw new PsignException($"`psign-tool code` recognized {node.Path} as a Business Central NAVX .app package, but Business Central package signing is not implemented yet");

            default:
                throw new PsignException($"`psign-tool code` signing execution currently supports top-level PE/WinMD, NuGet/SNuGet, VSIX, ZIP, MSIX/AppX prepare, ClickOnce manifests, ClickOnce .deploy PE payloads, and App Installer descriptors only ({node.Path} is {node.Format.DebugName()})");
        }
    }

    // ------------------------------------------------------------------ package signers

    /// <summary>Rust <c>sign_nuget_bytes</c>.</summary>
    private byte[] SignNuGetBytes(byte[] input, string label, string? publisher)
    {
        if (_skipSigned && PackageHasSignature(input, CodeFormat.Nuget))
        {
            return input;
        }

        var updated = SignNestedPackageEntries(input, label, AuthenticodeHashKind.Sha256, publisher);
        if (!_overwrite)
        {
            EnsureNuGetUnsigned(updated, label);
        }

        var unsigned = Ctx($"canonicalize NuGet package before signing {label}", () => NuGetPackage.CanonicalUnsignedPackageBytes(updated));
        var algorithm = NuGetHashAlgorithmExtensions.FromHashKind(_digest);
        var content = NuGetPackage.SignatureContentBytes(algorithm, algorithm.Hash(unsigned));
        var pkcs7 = SignPkcs7IdData(content, Pkcs7ContentMode.Attached, Rfc3161TimestampAttribute.CmsTimeStampToken, Pkcs7SignedAttributeProfile.NuGetAuthor);
        return Ctx($"embed NuGet signature into {label}", () => NuGetPackage.EmbedSignature(unsigned, pkcs7, overwrite: false));
    }

    /// <summary>Rust <c>sign_vsix_bytes</c>.</summary>
    private byte[] SignVsixBytes(byte[] input, string label, AuthenticodeHashKind vsixDigest, string? publisher)
    {
        if (_skipSigned && PackageHasSignature(input, CodeFormat.Vsix))
        {
            return input;
        }

        var updated = SignNestedPackageEntries(input, label, vsixDigest, publisher);
        var algorithm = VsixHashAlgorithmExtensions.FromHashKind(vsixDigest);
        var template = Ctx($"create VSIX signature for {label}", () => VsixPackage.SignatureTemplate(updated, algorithm, VsixSigningTime.Now));
        var (signature, certBytes) = _signer.SignXmlSignedInfo(vsixDigest, template.SignedInfo);
        var xml = template.SignatureXmlBytes(signature, certBytes);
        xml = Ctx($"timestamp VSIX signature for {label}", () => _timestamp.VsixIfRequested(xml));
        return Ctx($"embed VSIX signature XML into {label}", () => VsixPackage.EmbedSignatureXml(updated, xml, _overwrite));
    }

    /// <summary>Rust <c>sign_clickonce_manifest_bytes</c>.</summary>
    private byte[] SignClickOnceManifestBytes(byte[] input, string label, AuthenticodeHashKind digest)
    {
        if (_timestamp.Requested)
        {
            throw new PsignException("ClickOnce manifest XMLDSig timestamping is not implemented in `psign-tool code` yet");
        }

        var text = RustIo.Utf8(input, $"read ClickOnce manifest {label} as UTF-8 XML");
        var unsigned = ClickOnceManifest.UnsignedManifestText(text);
        var signedInfo = ClickOnceManifest.SignedInfoXml(unsigned, digest);
        var (signature, certBytes) = _signer.SignXmlSignedInfo(digest, signedInfo);
        var signatureXml = ClickOnceManifest.SignatureXml(signedInfo, signature, certBytes);
        return Encoding.UTF8.GetBytes(ClickOnceManifest.InsertSignatureXml(unsigned, signatureXml));
    }

    /// <summary>Rust <c>sign_clickonce_deploy_bytes</c>.</summary>
    private byte[] SignClickOnceDeployBytes(byte[] input, string label)
    {
        if (_digest != AuthenticodeHashKind.Sha256)
        {
            throw new PsignException("ClickOnce .deploy payload signing currently supports only SHA-256");
        }

        var contentName = ClickOnceDeployContentName(label) ?? throw new PsignException($"{label} is not a ClickOnce .deploy payload path");
        var ext = RustPath.Extension(contentName) is { } e ? CodeFormats.AsciiLower(e) : string.Empty;
        if (!IsPeLikeExtension(ext))
        {
            throw new PsignException($"ClickOnce .deploy payload {label} maps to unsupported content name {contentName}");
        }

        return Ctx($"sign ClickOnce .deploy PE payload {label}", () => SignPeBytes(input, label, skipSigned: false));
    }

    /// <summary>Rust <c>clickonce_deploy_content_name</c>.</summary>
    internal static string? ClickOnceDeployContentName(string label)
    {
        int bang = label.LastIndexOf('!');
        var name = bang >= 0 ? label[(bang + 1)..] : label;
        return name.EndsWith(".deploy", StringComparison.Ordinal) ? name[..^".deploy".Length] : null;
    }

    private static bool IsPeLikeExtension(string ext) => ext is "exe" or "dll" or "sys" or "ocx" or "efi" or "scr" or "cpl" or "mui" or "winmd";

    /// <summary>Rust <c>sign_pe_bytes</c>.</summary>
    private byte[] SignPeBytes(byte[] input, string label, bool skipSigned)
    {
        if (skipSigned && PeHasSignature(input))
        {
            return input;
        }

        if (_digest != AuthenticodeHashKind.Sha256)
        {
            throw new PsignException("PE/WinMD signing currently supports only SHA-256");
        }

        var (stripped, _) = Ctx($"remove existing PE/WinMD Authenticode signatures from {label}", () => PeEmbed.RemoveCertificates(input));
        var signed = Ctx($"sign PE/WinMD payload {label}", () => _signer.SignPeBytes(stripped, _digest));
        return Ctx($"timestamp PE/WinMD payload {label}", () => _timestamp.PeIfRequested(signed));
    }

    /// <summary>Rust <c>prepare_msix_family_bytes</c>.</summary>
    private byte[] PrepareMsixFamilyBytes(byte[] input, string label, AuthenticodeHashKind vsixDigest, CodeFormat format, string? publisher)
    {
        if (CodeZip.ContainsEntry(input, MsixSignaturePart))
        {
            throw new PsignException($"{label} already contains {MsixSignaturePart}; update the unsigned package before final AppX signing");
        }

        bool isTrueBundle = format is CodeFormat.MsixBundle or CodeFormat.AppxBundle;
        var updated = SignNestedPackageEntries(input, label, vsixDigest, publisher);
        bool hasFlatManifest = CodeZip.ContainsEntry(updated, "AppxManifest.xml");
        bool hasBundleManifest = CodeZip.ContainsEntry(updated, "AppxMetadata/AppxBundleManifest.xml");
        var extHint = format switch
        {
            CodeFormat.Msix => "msix",
            CodeFormat.Appx => "appx",
            CodeFormat.MsixBundle => "msixbundle",
            CodeFormat.AppxBundle => "appxbundle",
            _ => string.Empty,
        };
        if (format is CodeFormat.Msix or CodeFormat.Appx && !hasFlatManifest)
        {
            throw new PsignException($"{label} is missing AppxManifest.xml");
        }

        if (isTrueBundle && !hasBundleManifest)
        {
            throw new PsignException($"{label} is missing AppxMetadata/AppxBundleManifest.xml");
        }

        if (hasFlatManifest || hasBundleManifest)
        {
            var current = updated;
            updated = publisher is not null
                ? Ctx($"update MSIX/AppX publisher for {label}", () => AppxPackage.SetUnsignedMsixFamilyPublisherBytes(current, extHint, publisher))
                : Ctx($"restage unsigned MSIX/AppX layout for {label}", () => AppxPackage.RestageUnsignedMsixFamilyBytes(current, extHint, null));
        }

        return updated;
    }

    /// <summary>Rust <c>sign_nested_package_entries</c> (also <c>sign_zip_container_bytes</c>).</summary>
    private byte[] SignNestedPackageEntries(byte[] input, string label, AuthenticodeHashKind vsixDigest, string? publisher)
    {
        var archive = CodeZip.Open(input, $"open {label} as ZIP while signing nested package entries");
        var updates = new List<ZipEntryUpdate>();
        foreach (var file in archive.Entries)
        {
            try
            {
                archive.EnsureReadable(file);
            }
            catch (PsignException e)
            {
                throw new PsignException($"read ZIP entry in {label}", e);
            }

            if (file.IsDir)
            {
                continue;
            }

            var name = CodeZip.NormalizeZipName(file.Name);
            var compression = file.CompressionMethod;
            var format = CodeFormats.Detect(name);
            var bytes = archive.Read(file);
            var nestedLabel = $"{label}!{name}";
            var slashLabel = nestedLabel.Replace('!', '/');
            if (_nestedExcludes.Any(p => CodePatterns.GlobMatch(p, name) || CodePatterns.GlobMatch(p, slashLabel)))
            {
                continue;
            }

            switch (format)
            {
                case CodeFormat.Nuget or CodeFormat.Snupkg:
                    updates.Add(new ZipEntryUpdate(name, SignNuGetBytes(bytes, nestedLabel, null), compression));
                    break;
                case CodeFormat.Vsix:
                    updates.Add(new ZipEntryUpdate(name, SignVsixBytes(bytes, nestedLabel, vsixDigest, null), compression));
                    break;
                case CodeFormat.AppInstaller:
                    {
                        Ctx($"validate nested App Installer {nestedLabel}", () =>
                        {
                            CodeXml.ValidateAppInstallerDescriptor(bytes);
                            return 0;
                        });
                        var descriptor = bytes;
                        if (publisher is not null)
                        {
                            descriptor = Ctx($"update nested App Installer publisher for {nestedLabel}", () => CodeXml.UpdateAppInstallerPublisherBytes(bytes, publisher));
                            updates.Add(new ZipEntryUpdate(name, descriptor, compression));
                        }

                        var companionName = name + ".p7";
                        if (!_overwrite && CodeZip.ContainsEntry(input, companionName))
                        {
                            throw new PsignException($"{nestedLabel} already has companion signature {companionName}; use --overwrite to replace it");
                        }

                        var signedDescriptor = descriptor;
                        var pkcs7 = Ctx($"create nested App Installer companion signature for {nestedLabel}", () => SignPkcs7IdData(
                            signedDescriptor, Pkcs7ContentMode.Detached, Rfc3161TimestampAttribute.MicrosoftAuthenticode, Pkcs7SignedAttributeProfile.Basic));
                        updates.Add(new ZipEntryUpdate(companionName, pkcs7, Devolutions.Psign.Core.Zip.ZipCrateWriter.Stored));
                        break;
                    }

                case CodeFormat.ClickOnceApplication or CodeFormat.Vsto or CodeFormat.Manifest
                    when !(_skipSigned && ClickOnceManifest.HasSignature(bytes)):
                    updates.Add(new ZipEntryUpdate(name, SignClickOnceManifestBytes(bytes, nestedLabel, vsixDigest), compression));
                    break;
                case CodeFormat.Deploy:
                    updates.Add(new ZipEntryUpdate(name, SignClickOnceDeployBytes(bytes, nestedLabel), compression));
                    break;
                case CodeFormat.Pe or CodeFormat.Winmd:
                    updates.Add(new ZipEntryUpdate(name, SignPeBytes(bytes, nestedLabel, _skipSigned), compression));
                    break;
                case CodeFormat.Msix or CodeFormat.Appx or CodeFormat.MsixBundle or CodeFormat.AppxBundle or CodeFormat.AppxUpload or CodeFormat.MsixUpload:
                    updates.Add(new ZipEntryUpdate(name, PrepareMsixFamilyBytes(bytes, nestedLabel, vsixDigest, format, publisher), compression));
                    break;
                case var f when f.IsUnsupportedNestedSignable():
                    throw new PsignException($"`psign-tool code` nested execution cannot sign {nestedLabel} yet ({format.DebugName()})");
            }
        }

        if (updates.Count == 0)
        {
            return input;
        }

        return Ctx($"repack {label} with signed nested package entries", () => CodeZip.RepackWithUpdates(input, updates));
    }

    private static void EnsureNuGetUnsigned(byte[] bytes, string label)
    {
        var archive = CodeZip.Open(bytes, $"open NuGet package {label}");
        if (archive.ByName(NuGetPackage.PackageSignatureFileName) is not null)
        {
            throw new PsignException($"{label} already contains {NuGetPackage.PackageSignatureFileName}; nested re-sign overwrite is not wired yet");
        }
    }

    /// <summary>Rust <c>sign_pkcs7_id_data</c>.</summary>
    private byte[] SignPkcs7IdData(byte[] content, Pkcs7ContentMode mode, Rfc3161TimestampAttribute timestampAttribute, Pkcs7SignedAttributeProfile profile)
    {
        var chain = CodeSigner.LoadChainCerts(_chainPaths);
        var econtent = Pkcs7IdData.EContentDer(content);
        var pkcs7 = _signer.SignPkcs7(Oids.Pkcs7Data, econtent, _digest, chain, mode, profile);
        return _timestamp.Pkcs7IfRequested(pkcs7, timestampAttribute);
    }

    // ------------------------------------------------------------------ inspection helpers

    /// <summary>Rust <c>pe_has_signature</c>.</summary>
    internal static bool PeHasSignature(byte[] bytes)
    {
        try
        {
            return PeAuthenticode.Pkcs7Blobs(bytes).Count > 0;
        }
        catch (Exception e) when (e is PsignException or ArgumentException or IndexOutOfRangeException or InvalidDataException)
        {
            return false;
        }
    }

    /// <summary>Rust <c>package_has_signature</c>.</summary>
    internal static bool PackageHasSignature(byte[] bytes, CodeFormat format)
    {
        var archive = CodeZip.Open(bytes, "open package to inspect signature");
        foreach (var file in archive.Entries)
        {
            archive.EnsureReadable(file);
            if (file.IsDir)
            {
                continue;
            }

            var name = CodeZip.NormalizeZipName(file.Name);
            bool signed = format switch
            {
                CodeFormat.Nuget or CodeFormat.Snupkg => name == NuGetPackage.PackageSignatureFileName,
                CodeFormat.Vsix => name == OpcPackage.OpcSignatureOriginPart
                    || name == VsixPackage.DefaultVsixSignaturePart
                    || name.StartsWith(OpcPackage.OpcSignaturesPrefix, StringComparison.Ordinal),
                _ => false,
            };
            if (signed)
            {
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------------ output paths

    /// <summary>Rust <c>output_path_for_node</c>.</summary>
    private static string OutputPathForNode(CodePlanNode node)
    {
        if (node.OutputPath.Contains('!'))
        {
            throw new PsignException($"`psign-tool code` signing execution cannot write nested output path {node.OutputPath} yet");
        }

        return RustPath.DisplayToPath(node.OutputPath);
    }

    /// <summary>Rust <c>appinstaller_companion_output_path</c>.</summary>
    private static string AppInstallerCompanionOutputPath(CodePlanNode node)
    {
        var output = OutputPathForNode(node);
        if (RustPath.IsExtension(output, "p7"))
        {
            return output;
        }

        var name = RustPath.FileName(output) ?? throw new PsignException($"invalid App Installer output path {output}");
        return RustPath.SetFileName(output, name + ".p7");
    }

    /// <summary>Rust <c>appinstaller_descriptor_output_path</c>.</summary>
    private static string AppInstallerDescriptorOutputPath(CodePlanNode node)
    {
        var output = OutputPathForNode(node);
        if (RustPath.IsExtension(output, "p7"))
        {
            var stem = RustPath.FileStem(output) ?? throw new PsignException($"invalid App Installer output path {output}");
            return RustPath.SetFileName(output, stem);
        }

        return output;
    }

    /// <summary>Rust <c>ensure_parent_dir</c>.</summary>
    private static void EnsureParentDir(string path)
    {
        if (RustPath.Parent(path) is { Length: > 0 } parent)
        {
            RustIo.CreateDirAll(parent, $"create output directory {parent}");
        }
    }

    private static T Ctx<T>(string context, Func<T> action) => CodeSigner.Ctx(context, action);
}
