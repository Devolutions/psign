using System.Globalization;
using System.Numerics;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Verification;

namespace Devolutions.Psign.Signing.Portable;

public static partial class PortableCore
{
    private const string DigestValidNoTrust = "Portable digest binding is valid; trust was not evaluated.";

    /// <summary>
    /// Inspect a file's portable signature (Rust <c>portable_get_signature</c>): recompute the format digest binding,
    /// summarize the PKCS#7, decode the Artifact Signing identity, and run explicit trust verification when the request
    /// supplies anchors (or Artifact Signing options).
    /// </summary>
    public static PortableSignatureResponse PortableGetSignature(PortableGetSignatureRequest request, PortableCoreOptions? options = null)
    {
        var data = ReadFile(request.Path);
        var format = InferFormatFromPathOrData(request.Path, data);
        var path = request.Path;
        var response = format switch
        {
            PortableFileFormat.Pe => InspectPe(path, data),
            PortableFileFormat.Cab => InspectCab(path),
            PortableFileFormat.Msi => InspectMsi(path),
            PortableFileFormat.Msix => InspectMsix(path),
            PortableFileFormat.MsixUpload => throw new PsignException(
                "MSIX/AppX upload bundles (.appxupload/.msixupload) are dotnet/SignTool packaging containers, not AppX SIP verify subjects"),
            PortableFileFormat.MsixEncrypted => throw new PsignException(
                "encrypted MSIX/AppX packages require Windows AppxSip OS delegation; portable cleartext digest validation does not apply"),
            PortableFileFormat.NuGet => InspectNuGet(path, data),
            PortableFileFormat.Vsix => InspectVsixOpc(path, data),
            PortableFileFormat.ClickOnceManifest => InspectClickOnceManifest(path, data),
            PortableFileFormat.AppInstaller => InspectAppInstaller(path),
            PortableFileFormat.Zip => InspectZip(path, data),
            PortableFileFormat.PowerShellScript or PortableFileFormat.WshScript => InspectScript(path, data),
            PortableFileFormat.Catalog => InspectPkcs7File(path, format),
            _ => BaseResponse(path, format, PortableSignatureStatus.NotSupportedFileFormat, "Unsupported file format for portable Authenticode inspection."),
        };

        response.ArtifactSigning = ArtifactSigningIdentityOf(response.SignerCertificateDerBase64);
        ApplyTrustIfRequested(request, format, data, response);
        return response;
    }

    /// <summary>Decode the Azure Artifact Signing identity of a DER certificate (Rust <c>portable_get_artifact_signing_identity</c>).</summary>
    public static PortableArtifactSigningIdentityResponse PortableGetArtifactSigningIdentity(PortableArtifactSigningIdentityRequest request)
    {
        var der = DecodeBase64(request.CertificateDerBase64.Trim(), "decode certificate_der_base64");
        return new PortableArtifactSigningIdentityResponse { Identity = Verification.ArtifactSigning.IdentityFromCertBytes(der) };
    }

    /// <summary>Remove PE Authenticode signatures in place (Rust <c>portable_clear_signature</c>; PE only).</summary>
    public static PortableClearSignatureResponse PortableClearSignature(PortableClearSignatureRequest request)
    {
        var data = ReadFile(request.Path);
        var format = InferFormatFromPathOrData(request.Path, data);
        return format switch
        {
            PortableFileFormat.Pe => ClearPeSignature(request.Path, format),
            PortableFileFormat.Unknown => throw new PsignException($"unsupported portable signature clear format: {request.Path}"),
            _ => throw new PsignException($"portable signature clear is not supported for {format}; use script signature removal for PowerShell files"),
        };
    }

    /// <summary>Validate in-memory PowerShell content (Rust <c>portable_validate_powershell_script</c>).</summary>
    public static PortableSignatureResponse PortableValidatePowerShellScript(PortableValidatePowerShellRequest request, PortableCoreOptions? options = null)
    {
        var data = DecodeBase64(request.ContentBase64, "decode content_base64");
        var format = InferPowerShellSourceFormat(request.SourcePathOrExtension);
        if (format != PortableFileFormat.PowerShellScript)
        {
            return BaseResponse(
                request.SourcePathOrExtension,
                format,
                PortableSignatureStatus.NotSupportedFileFormat,
                "Unsupported file format for portable PowerShell signature validation.");
        }

        var response = InspectScript(request.SourcePathOrExtension, data);
        ApplyTrustIfRequested(request.ToSignatureRequest(request.SourcePathOrExtension), format, data, response);
        return response;
    }

    private static ArtifactSigningIdentity? ArtifactSigningIdentityOf(string? derBase64)
    {
        if (derBase64 is null || Base64Standard.TryDecode(derBase64) is not { } der)
        {
            return null;
        }

        try
        {
            return Verification.ArtifactSigning.IdentityFromCertBytes(der);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return null;
        }
    }

    private static PortableClearSignatureResponse ClearPeSignature(string path, PortableFileFormat format)
    {
        var image = ReadFile(path);
        var (cleared, removed) = WithContext($"remove PE Authenticode signatures from {path}", () => PeEmbed.RemoveCertificates(image));
        if (removed == 0)
        {
            return new PortableClearSignatureResponse
            {
                Path = path,
                Format = format,
                SignatureRemoved = false,
                BytesRemoved = removed,
                Message = "No PE Authenticode certificate table found.",
            };
        }

        WriteFile(path, cleared);
        return new PortableClearSignatureResponse
        {
            Path = path,
            Format = format,
            SignatureRemoved = true,
            BytesRemoved = removed,
            Message = "PE Authenticode certificate table removed.",
        };
    }

    // ------------------------------------------------------------------ trust

    private static void ApplyTrustIfRequested(PortableGetSignatureRequest request, PortableFileFormat format, byte[] data, PortableSignatureResponse response)
    {
        if (!TrustRequested(request) || response.Status != PortableSignatureStatus.Valid)
        {
            return;
        }

        var (opts, tempDir) = TrustOptions(request);
        TrustVerifyPeReport? report = null;
        Exception? error = null;
        try
        {
            report = format switch
            {
                PortableFileFormat.Pe => TrustVerifyPe.TrustVerifyPeBytes(data, opts),
                PortableFileFormat.Cab => TrustVerifyFormats.TrustVerifyCabBytes(data, opts),
                PortableFileFormat.Msi => TrustVerifyFormats.TrustVerifyMsiBytes(data, opts),
                PortableFileFormat.Zip => TrustVerifyFormats.TrustVerifyZipBytes(data, opts),
                PortableFileFormat.Catalog => TrustVerifyFormats.TrustVerifyCatalogBytes(data, opts),
                PortableFileFormat.PowerShellScript or PortableFileFormat.WshScript =>
                    TrustVerifyFormats.TrustVerifyScriptBytes(data, ScriptExtensionFor(request.Path), opts),
                PortableFileFormat.Msix => TrustVerifyFormats.TrustVerifyMsixBytes(data, ScriptExtensionFor(request.Path), opts),
                PortableFileFormat.NuGet => TrustVerifyFormats.TrustVerifyNuGetBytes(data, opts),
                PortableFileFormat.Vsix => TrustVerifyVsix.TrustVerifyVsixBytes(data, opts),
                PortableFileFormat.AppInstaller or PortableFileFormat.MsixUpload or PortableFileFormat.MsixEncrypted or PortableFileFormat.ClickOnceManifest =>
                    throw new PsignException($"explicit trust verification is not yet available for format {format} through the portable inspection path"),
                _ => throw new PsignException($"explicit trust verification is not implemented for format {format}"),
            };
        }
        catch (Exception e) when (IsOperationError(e))
        {
            error = e;
        }
        finally
        {
            if (tempDir is not null)
            {
                try
                {
                    Directory.Delete(tempDir, recursive: true);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                }
            }
        }

        if (report is not null)
        {
            response.TrustStatus = PortableSignatureStatus.Valid;
            if (report.ArtifactSigning.Count > 0)
            {
                var sig = report.ArtifactSigning[0];
                response.StatusMessage = "Portable digest binding and Azure Artifact Signing verification are valid.";
                response.Diagnostics.Add($"artifact_signing=valid publisher_id={sig.Identity.PublisherId} kind={sig.Identity.Kind.AsStr()} root_sha1={sig.RootSha1}");
                response.ArtifactSigning = sig.Identity;
                response.ArtifactSigningVerification = sig;
            }
            else
            {
                response.StatusMessage = "Portable digest binding and explicit trust verification are valid.";
                response.Diagnostics.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"explicit_trust=valid pkcs7_entries_verified={report.Pkcs7EntriesVerified} anchors={report.AnchorThumbprints}"));
            }
        }
        else
        {
            response.Status = PortableSignatureStatus.NotTrusted;
            response.TrustStatus = PortableSignatureStatus.NotTrusted;
            response.StatusMessage = error!.Message;
            response.Diagnostics.Add("explicit_trust=failed");
        }
    }

    private static bool TrustRequested(PortableGetSignatureRequest request) =>
        request.ArtifactSigning is not null
        || request.TrustedCertificatePaths.Count > 0
        || request.TrustedCertificatesDerBase64.Count > 0
        || request.AnchorDirectory is not null
        || request.AuthrootCab is not null;

    /// <summary>Trust options for a request (Rust <c>trust_options</c>); also returns the temporary directory holding inline anchors.</summary>
    internal static (TrustVerifyPeOptions Options, string? TempDir) TrustOptions(PortableGetSignatureRequest request)
    {
        if (request.ArtifactSigning is not null
            && (request.TrustedCertificatePaths.Count > 0 || request.TrustedCertificatesDerBase64.Count > 0 || request.AnchorDirectory is not null || request.AuthrootCab is not null))
        {
            throw new PsignException(
                "trusted certificates, anchor directory, and AuthRoot CAB cannot be combined with Artifact Signing validation, which pins its own roots");
        }

        var trustedCaFiles = new List<string>(request.TrustedCertificatePaths);
        string? tempDir = null;
        if (request.TrustedCertificatesDerBase64.Count > 0)
        {
            var dir = Path.Combine(
                Path.GetTempPath(),
                string.Create(CultureInfo.InvariantCulture, $"psign-portable-trust-{Environment.ProcessId}-{DateTime.UtcNow.Ticks}-{Guid.NewGuid():N}"));
            try
            {
                Directory.CreateDirectory(dir);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new PsignException($"create temporary trust directory {dir}", e);
            }

            try
            {
                for (int i = 0; i < request.TrustedCertificatesDerBase64.Count; i++)
                {
                    var bytes = DecodeBase64(request.TrustedCertificatesDerBase64[i], $"decode trusted_certificates_der_base64[{i}]");
                    var path = Path.Combine(dir, string.Create(CultureInfo.InvariantCulture, $"trusted-{i}.cer"));
                    WriteFile(path, bytes);
                    trustedCaFiles.Add(path);
                }
            }
            catch
            {
                try
                {
                    Directory.Delete(dir, recursive: true);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                }

                throw;
            }

            tempDir = dir;
        }

        // An AuthRoot CAB only carries root thumbprints, so AIA fetching lets the chain builder obtain the root itself.
        var effectiveAia = request.OnlineAia || request.AuthrootCab is not null;
        var opts = new TrustVerifyPeOptions
        {
            AnchorDir = request.AnchorDirectory,
            TrustedCaFiles = trustedCaFiles,
            AuthrootCab = request.AuthrootCab,
            ExpectAuthrootCabSha256 = null,
            VerificationInstantOverride = request.AsOf is { } asOf ? ParseUtcDate(asOf) : null,
            VerboseChain = false,
            Online = new OnlineTrustOptions
            {
                EnableAia = effectiveAia,
                EnableOcsp = request.OnlineOcsp,
                RevocationMode = request.RevocationMode.ToRevocationMode(),
            },
            Policy = new AuthenticodeTrustPolicy
            {
                StrictCodeSigningEku = false,
                PreferTimestampSigningTime = request.PreferTimestampSigningTime || request.RequireValidTimestamp,
                RequireValidTimestamp = request.RequireValidTimestamp,
            },
            ArtifactSigning = request.ArtifactSigning is { } a
                ? new ArtifactSigningPolicy
                {
                    ExpectedPublisherIds = [.. a.PublisherIds],
                    PrivateTrustRootFiles = [.. a.PrivateTrustRootPaths],
                    RequireTimestamp = !a.AllowMissingTimestamp,
                }
                : null,
        };
        return (opts, tempDir);
    }

    /// <summary><c>yyyy-MM-dd</c> (time suffix after <c>T</c> ignored) at UTC midnight (Rust <c>parse_utc_date</c>).</summary>
    internal static DateTimeOffset ParseUtcDate(string input)
    {
        int t = input.IndexOf('T', StringComparison.Ordinal);
        var date = (t >= 0 ? input[..t] : input).Trim();
        var parts = date.Split('-');
        var year = ParsePart<ushort>(parts[0], $"invalid year in as_of date '{input}'");
        var month = parts.Length > 1 ? ParsePart<byte>(parts[1], $"invalid month in as_of date '{input}'") : throw new PsignException("missing month in as_of date");
        var day = parts.Length > 2 ? ParsePart<byte>(parts[2], $"invalid day in as_of date '{input}'") : throw new PsignException("missing day in as_of date");
        if (parts.Length > 3)
        {
            throw new PsignException($"invalid as_of date '{input}': expected yyyy-MM-dd");
        }

        if (year is < 1 or > 9999 || month is < 1 or > 12 || day < 1 || day > DateTime.DaysInMonth(year, month))
        {
            throw new PsignException($"invalid as_of date '{input}': expected a valid yyyy-MM-dd date");
        }

        return new DateTimeOffset(year, month, day, 0, 0, 0, TimeSpan.Zero);
    }

    private static T ParsePart<T>(string text, string error)
        where T : struct, INumber<T>
    {
        var s = text.StartsWith('+') ? text[1..] : text;
        if (s.Length == 0 || !s.All(char.IsAsciiDigit) || !T.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw new PsignException(error);
        }

        return value;
    }

    // ------------------------------------------------------------------ per-format inspection

    private static PortableSignatureResponse InspectPe(string path, byte[] data)
    {
        InspectPeFileReport? inspect = null;
        try
        {
            inspect = AuthenticodeInspector.InspectPeAuthenticode(data);
        }
        catch (Exception e) when (IsOperationError(e))
        {
        }

        PeDigestConsistencyResult result;
        try
        {
            result = PeAuthenticode.VerifyDigestConsistency(data);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, PortableFileFormat.Pe, e);
        }

        var summary = inspect is null ? new Pkcs7Summary() : SummarizePkcs7Reports(inspect.Entries.Select(e => e.Pkcs7));
        try
        {
            summary.Pkcs7DerBase64 = Convert.ToBase64String(PeAuthenticode.NthPkcs7(data, result.MatchedAttributeCertificateIndex));
        }
        catch (Exception e) when (IsOperationError(e))
        {
            summary.Pkcs7DerBase64 = null;
        }

        var response = ValidResponse(path, PortableFileFormat.Pe, "Portable digest binding is valid; trust was not evaluated.", summary);
        response.SignatureCount = result.Pkcs7AuthenticodeEntries;
        response.Diagnostics.Add(string.Create(CultureInfo.InvariantCulture, $"matched_attribute_certificate_index={result.MatchedAttributeCertificateIndex}"));
        return response;
    }

    private static PortableSignatureResponse InspectCab(string path)
    {
        try
        {
            CabDigest.VerifyDigestConsistency(ReadFile(path));
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, PortableFileFormat.Cab, e);
        }

        var data = ReadFile(path);
        var summary = TryOrNull(() => CabDigest.SignaturePkcs7Der(data)) is { } pkcs7 ? SummarizePkcs7Der(pkcs7) : null;
        return ValidResponse(path, PortableFileFormat.Cab, DigestValidNoTrust, summary ?? new Pkcs7Summary());
    }

    private static PortableSignatureResponse InspectMsi(string path)
    {
        try
        {
            MsiDigest.VerifyDigestConsistency(ReadFile(path));
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, PortableFileFormat.Msi, e);
        }

        var data = ReadFile(path);
        var summary = TryOrNull(() => MsiDigest.DigitalSignaturePkcs7Der(data)) is { } pkcs7 ? SummarizePkcs7Der(pkcs7) : null;
        return ValidResponse(path, PortableFileFormat.Msi, DigestValidNoTrust, summary ?? new Pkcs7Summary());
    }

    private static PortableSignatureResponse InspectMsix(string path)
    {
        try
        {
            MsixDigest.VerifyMsixDigestConsistency(path);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, PortableFileFormat.Msix, e);
        }

        var data = ReadFile(path);
        var summary = TryOrNull(() => MsixDigest.MsixSignaturePkcs7Der(data)) is { } pkcs7 ? SummarizePkcs7Der(pkcs7) : null;
        return ValidResponse(path, PortableFileFormat.Msix, "Portable MSIX digest binding is valid; trust was not evaluated.", summary ?? new Pkcs7Summary());
    }

    private static PortableSignatureResponse InspectZip(string path, byte[] data)
    {
        ZipAuthenticodeSignature sig;
        try
        {
            sig = ZipAuthenticode.VerifyZipDigestBinding(data);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, PortableFileFormat.Zip, e);
        }

        var script = ZipAuthenticode.SignatureScriptFromParts(sig.Digest, sig.Pkcs7Base64);
        try
        {
            ScriptDigest.VerifyScriptDigestConsistency(Encoding.UTF8.GetBytes(script), "ps1");
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, PortableFileFormat.Zip, e);
        }

        var pkcs7 = ZipAuthenticode.SignaturePkcs7Der(sig);
        return ValidResponse(path, PortableFileFormat.Zip, "Portable ZIP digest binding is valid; trust was not evaluated.", SummarizePkcs7Der(pkcs7) ?? new Pkcs7Summary());
    }

    private static PortableSignatureResponse InspectNuGet(string path, byte[] data)
    {
        bool hasSignature;
        try
        {
            hasSignature = NuGetPackage.InspectNupkgPath(path).Signed;
        }
        catch (Exception e) when (IsOperationError(e))
        {
            hasSignature = false;
        }

        if (!hasSignature)
        {
            return BaseResponse(path, PortableFileFormat.NuGet, PortableSignatureStatus.NotSigned, "NuGet package does not contain .signature.p7s");
        }

        var signature = ExtractNuGetSignatureP7s(data);
        try
        {
            TrustVerifyFormats.NuGetVerifiedSignatureContent(data, signature);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, PortableFileFormat.NuGet, e);
        }

        return ValidResponse(
            path,
            PortableFileFormat.NuGet,
            "NuGet package hash matches the signed .signature.p7s content; trust was not evaluated.",
            SummarizePkcs7Der(signature) ?? new Pkcs7Summary());
    }

    private static byte[] ExtractNuGetSignatureP7s(byte[] data)
    {
        var archive = WithContext("open NuGet ZIP", () => ZipCrateArchive.Open(data));
        var entry = archive.ByName(NuGetPackage.PackageSignatureFileName)
            ?? throw new PsignException("read .signature.p7s", new PsignException("specified file not found in archive"));
        return WithContext("read .signature.p7s", () => archive.Read(entry));
    }

    private static PortableSignatureResponse InspectVsixOpc(string path, byte[] data)
    {
        bool hasSignature;
        try
        {
            hasSignature = VsixPackage.InspectVsixPath(path).HasOpcSignature;
        }
        catch (Exception e) when (IsOperationError(e))
        {
            hasSignature = false;
        }

        if (!hasSignature)
        {
            return BaseResponse(path, PortableFileFormat.Vsix, PortableSignatureStatus.NotSigned, "VSIX package does not contain an OPC digital signature");
        }

        VsixSignature sig;
        try
        {
            sig = TrustVerifyVsix.VerifyVsixSignatureBytes(data);
        }
        catch (Exception standardError) when (IsOperationError(standardError))
        {
            // Legacy only: signatures from psign releases before the OPC layout referenced parts directly and are not
            // verifiable by Visual Studio; keep reporting their part digests so existing packages still inspect.
            var sigXml = TryOrNull(() => VsixPackage.ExtractSignatureXmlPath(path)) ?? [];
            bool legacyOk = sigXml.Length > 0
                && TryOrNull(() => (object)VsixPackage.VerifyLegacySignatureReferenceXml(data, sigXml, VsixHashAlgorithm.Sha256)) is not null;
            var full = PsignException.Render(standardError);
            var response = legacyOk
                ? BaseResponse(
                    path,
                    PortableFileFormat.Vsix,
                    PortableSignatureStatus.Valid,
                    "Legacy psign VSIX signature references are valid; the signature is not a standard OPC XMLDSig signature and cannot be trust-verified.")
                : BaseResponse(path, PortableFileFormat.Vsix, PortableSignatureStatus.HashMismatch, $"VSIX OPC XMLDSig signature is invalid: {full}");
            response.Diagnostics.Add($"standard_xmldsig=failed: {full}");
            return response;
        }

        var valid = BaseResponse(
            path,
            PortableFileFormat.Vsix,
            PortableSignatureStatus.Valid,
            "VSIX OPC XMLDSig signature, part digests, and SignatureValue are valid; trust was not evaluated.");
        valid.SignerCertificateDerBase64 = Convert.ToBase64String(sig.SignerCertificateDer);
        if (sig.TimestampToken is not null)
        {
            valid.TimestampKinds.Add("opc_encoded_time");
        }

        return valid;
    }

    private static PortableSignatureResponse InspectClickOnceManifest(string path, byte[] data)
    {
        var text = RustText.TryFromUtf8(data) ?? string.Empty;
        var hasSignature = text.Contains("<Signature", StringComparison.Ordinal) && text.Contains("</Signature>", StringComparison.Ordinal);
        return hasSignature
            ? BaseResponse(path, PortableFileFormat.ClickOnceManifest, PortableSignatureStatus.Valid, "ClickOnce manifest contains an XMLDSig Signature; trust was not evaluated.")
            : BaseResponse(path, PortableFileFormat.ClickOnceManifest, PortableSignatureStatus.NotSigned, "ClickOnce manifest does not contain an XMLDSig Signature element");
    }

    private static PortableSignatureResponse InspectAppInstaller(string path)
    {
        var companion = AppInstallerCompanionPath(path);
        if (!File.Exists(companion) && !Directory.Exists(companion))
        {
            return BaseResponse(
                path,
                PortableFileFormat.AppInstaller,
                PortableSignatureStatus.NotSigned,
                "App Installer descriptor does not have a companion .p7 signature file");
        }

        var pkcs7 = ReadFile(companion, $"read companion {companion}");
        return ValidResponse(
            path,
            PortableFileFormat.AppInstaller,
            "App Installer companion .p7 signature is present; trust was not evaluated.",
            SummarizePkcs7Der(pkcs7) ?? new Pkcs7Summary());
    }

    private static PortableSignatureResponse InspectScript(string path, byte[] data)
    {
        var ext = ScriptExtensionFor(path);
        var format = InferPowerShellSourceFormat(path);
        try
        {
            ScriptDigest.VerifyScriptDigestConsistency(data, ext);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, format, e);
        }

        var summary = TryOrNull(() => ScriptDigest.ScriptDigestReport(data, ext)) is { } report ? SummarizePkcs7Der(report.Pkcs7Der) : null;
        return ValidResponse(path, format, "Portable script digest binding is valid; trust was not evaluated.", summary ?? new Pkcs7Summary());
    }

    private static PortableSignatureResponse InspectPkcs7File(string path, PortableFileFormat format)
    {
        var data = ReadFile(path);
        if (CmsSignedData.TryParse(data) is { SignerInfos.Count: 0 })
        {
            var unsigned = BaseResponse(path, format, PortableSignatureStatus.NotSigned, "PKCS#7 SignedData has no SignerInfo.");
            unsigned.Pkcs7DerBase64 = Convert.ToBase64String(data);
            return unsigned;
        }

        InspectPkcs7Report report;
        try
        {
            report = AuthenticodeInspector.InspectAuthenticodePkcs7Der(data);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return MapDigestError(path, format, e);
        }

        var summary = SummarizePkcs7Reports([report]);
        summary.Pkcs7DerBase64 = Convert.ToBase64String(data);
        return ValidResponse(path, format, "PKCS#7 structure is valid; detached content and trust were not evaluated.", summary);
    }

    private static T? TryOrNull<T>(Func<T> action)
        where T : class
    {
        try
        {
            return action();
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return null;
        }
    }

    // ------------------------------------------------------------------ PKCS#7 summary

    private sealed class Pkcs7Summary
    {
        public string? DigestAlgorithm { get; set; }

        public List<string> TimestampKinds { get; } = [];

        public string? TimestampSigningTime { get; set; }

        public string? Pkcs7DerBase64 { get; set; }

        public int? SignerIndex { get; set; }

        public string? SignerCertificateDerBase64 { get; set; }

        public string? TimestamperCertificateDerBase64 { get; set; }

        public int EmbeddedCertificateCount { get; set; }
    }

    private static Pkcs7Summary? SummarizePkcs7Der(byte[] pkcs7Der)
    {
        InspectPkcs7Report report;
        try
        {
            report = AuthenticodeInspector.InspectAuthenticodePkcs7Der(pkcs7Der);
        }
        catch (Exception e) when (IsOperationError(e))
        {
            return null;
        }

        var summary = SummarizePkcs7Reports([report]);
        summary.Pkcs7DerBase64 = Convert.ToBase64String(pkcs7Der);
        return summary;
    }

    private static Pkcs7Summary SummarizePkcs7Reports(IEnumerable<InspectPkcs7Report> reports)
    {
        var summary = new Pkcs7Summary();
        foreach (var report in reports)
        {
            CollectPkcs7Summary(report, summary);
        }

        return summary;
    }

    private static void CollectPkcs7Summary(InspectPkcs7Report report, Pkcs7Summary summary)
    {
        summary.EmbeddedCertificateCount += report.CertificateCount;
        summary.TimestampSigningTime ??= report.TimestampSigningTime;
        if (summary.DigestAlgorithm is null && report.AuthenticodeDigest is { } digest)
        {
            summary.DigestAlgorithm = digest.DigestAlgorithmOid;
        }

        foreach (var signer in report.Signers)
        {
            summary.SignerIndex ??= signer.SignerIndex;
            summary.SignerCertificateDerBase64 ??= signer.SignerCertificateDerBase64;
            summary.TimestamperCertificateDerBase64 ??= signer.TimestampSignerCertificateDerBase64;
            foreach (var hint in signer.TimestampHints)
            {
                if (!summary.TimestampKinds.Contains(hint.Kind))
                {
                    summary.TimestampKinds.Add(hint.Kind);
                }
            }
        }

        foreach (var nested in report.NestedSignatures)
        {
            CollectPkcs7Summary(nested, summary);
        }
    }

    private static PortableSignatureResponse ValidResponse(string path, PortableFileFormat format, string message, Pkcs7Summary summary)
    {
        var response = new PortableSignatureResponse
        {
            Path = path,
            Format = format,
            Status = PortableSignatureStatus.Valid,
            StatusMessage = message,
            SignatureCount = 1,
            SignerIndex = summary.SignerIndex,
            SignerCertificateDerBase64 = summary.SignerCertificateDerBase64,
            TimestamperCertificateDerBase64 = summary.TimestamperCertificateDerBase64,
            EmbeddedCertificateCount = summary.EmbeddedCertificateCount,
            DigestAlgorithm = summary.DigestAlgorithm,
            TimestampSigningTime = summary.TimestampSigningTime,
            Pkcs7DerBase64 = summary.Pkcs7DerBase64,
        };
        response.TimestampKinds.AddRange(summary.TimestampKinds);
        return response;
    }

    private static PortableSignatureResponse BaseResponse(string path, PortableFileFormat format, PortableSignatureStatus status, string message) => new()
    {
        Path = path,
        Format = format,
        Status = status,
        StatusMessage = message,
        SignatureCount = status == PortableSignatureStatus.Valid ? 1 : 0,
    };

    private static PortableSignatureResponse MapDigestError(string path, PortableFileFormat format, Exception error)
    {
        var message = error.Message;
        PortableSignatureStatus status;
        if (LooksUnsigned(message))
        {
            status = PortableSignatureStatus.NotSigned;
        }
        else if (RustText.ToAsciiLowercase(message).Contains("mismatch", StringComparison.Ordinal))
        {
            status = PortableSignatureStatus.HashMismatch;
        }
        else if (format == PortableFileFormat.Unknown)
        {
            status = PortableSignatureStatus.NotSupportedFileFormat;
        }
        else
        {
            status = PortableSignatureStatus.Incompatible;
        }

        return new PortableSignatureResponse
        {
            Path = path,
            Format = format,
            Status = status,
            StatusMessage = message,
            SignatureCount = 0,
        };
    }

    /// <summary>Error-message heuristics for "no signature present" (Rust <c>looks_unsigned</c>).</summary>
    internal static bool LooksUnsigned(string message)
    {
        var lower = RustText.ToAsciiLowercase(message);
        return lower.Contains("not found", StringComparison.Ordinal)
            || lower.Contains("not signed", StringComparison.Ordinal)
            || lower.Contains("no certificate table", StringComparison.Ordinal)
            || lower.Contains("no pkcs#7", StringComparison.Ordinal)
            || lower.Contains("no signerinfo", StringComparison.Ordinal)
            || lower.Contains("digital signature stream", StringComparison.Ordinal)
            || lower.Contains("signature comment not found", StringComparison.Ordinal)
            || lower.Contains("appxsignature.p7x", StringComparison.Ordinal)
            || lower.Contains("signature block", StringComparison.Ordinal);
    }
}
