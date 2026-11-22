using System.Text;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.Portable;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Verification;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>
/// <c>psign-tool verify --artifact-signing…</c>: Azure Artifact Signing policy shared by both tool modes (port of
/// <c>src/artifact_signing_verify.rs</c>). Portable mode runs it instead of the generic AuthRoot trust; the same
/// <c>Devolutions.Psign.Verification</c> entry points evaluate the signature as the Rust trust crate.
/// </summary>
internal static class ArtifactSigningVerify
{
    /// <summary>
    /// NuGet / VSIX packages: signed with CMS or XMLDSig inside a ZIP, with no Windows SIP, so <c>WinVerifyTrust</c> cannot
    /// evaluate them and Windows mode relies on the shared check alone.
    /// </summary>
    public static bool IsPackageWithoutWindowsSip(string path) =>
        CliIo.RustExtension(path) is { } ext && RustText.ToAsciiLowercase(ext) is "nupkg" or "snupkg" or "vsix";

    /// <summary><c>true</c> when any <c>--artifact-signing*</c> option was given.</summary>
    public static bool Requested(VerifyArgs args) =>
        args.ArtifactSigning
        || args.ArtifactSigningPublisherId.Count > 0
        || args.ArtifactSigningPrivateTrustRoot.Count > 0
        || args.ArtifactSigningAllowMissingTimestamp;

    /// <summary>Reject options that would widen or contradict the Artifact Signing policy.</summary>
    public static void Validate(VerifyArgs args)
    {
        (bool Set, string Flag)[] conflicts =
        [
            (args.AnchorDir is not null, "--anchor-dir"),
            (args.TrustedCa.Count > 0, "--trusted-ca"),
            (args.AdditionalTrustedCa.Count > 0, "--additional-trusted-ca"),
            (args.AuthrootCab is not null, "--authroot-cab"),
            (args.ExpectAuthrootCabSha256 is not null, "--expect-authroot-cab-sha256"),
            (args.AllowLooseSigningCert, "--allow-loose-signing-cert"),
            (args.CatalogSearch is not null, "--catalog-search"),
            (args.CatalogDatabaseGuid is not null, "--catalog-database-guid"),
            (args.KernelPolicy, "--kernel-policy"),
        ];
        foreach (var (set, flag) in conflicts)
        {
            if (set)
            {
                throw new PsignException(
                    $"{flag} cannot be combined with --artifact-signing: Artifact Signing pins its own roots (use --artifact-signing-private-trust-root for Private Trust)");
            }
        }
    }

    /// <summary>Rust <c>trust_options</c>: Artifact Signing policy plus the verification date and online options.</summary>
    internal static TrustVerifyPeOptions TrustOptions(VerifyArgs args) => new()
    {
        VerificationInstantOverride = args.AsOf is { } asOf ? VerificationInstant.ParseVerificationDateYmd(asOf) : null,
        VerboseChain = args.VerboseChain,
        Online = new OnlineTrustOptions
        {
            EnableAia = args.OnlineAia,
            AiaUrlOverride = args.AiaUrlOverride,
            EnableOcsp = args.OnlineOcsp,
            OcspUrlOverride = args.OcspUrlOverride,
            RevocationMode = args.RevocationMode switch
            {
                "best-effort" => RevocationMode.BestEffort,
                "require" => RevocationMode.Require,
                _ => RevocationMode.Off,
            },
            CrlUrlOverride = args.CrlUrlOverride,
            Timeout = TimeSpan.FromSeconds(Math.Min(args.OnlineTimeoutSecs, (ulong)int.MaxValue)),
            MaxDownloadBytes = (int)Math.Min(args.OnlineMaxDownloadBytes, int.MaxValue),
        },
        ArtifactSigning = new ArtifactSigningPolicy
        {
            ExpectedPublisherIds = args.ArtifactSigningPublisherId.ToList(),
            PrivateTrustRootFiles = args.ArtifactSigningPrivateTrustRoot.ToList(),
            RequireTimestamp = !args.ArtifactSigningAllowMissingTimestamp,
        },
        Log = StderrWriter.Instance,
    };

    /// <summary>
    /// Verify every verify target as an Artifact Signing signature; returns the report text. Detached
    /// (<c>--detached-pkcs7</c>) checks the PKCS#7 against its content; <c>--catalog</c> checks the catalog signature
    /// (member hashes are left to the caller's normal catalog verification).
    /// </summary>
    public static string VerifyTargets(VerifyArgs args)
    {
        Validate(args);
        var opts = TrustOptions(args);
        var output = new StringBuilder();
        if (args.DetachedPkcs7 is { } signature)
        {
            var contentPath = args.DetachedPkcs7Content ?? args.Files.FirstOrDefault()
                ?? throw new PsignException("--detached-pkcs7 requires a content file");
            var content = Output.ReadFile(contentPath);
            var pkcs7 = Output.ReadFile(signature);
            var report = PeCommands.Wrap($"Artifact Signing {signature}", () => TrustVerifyDetached.TrustVerifyDetachedBytes(content, pkcs7, opts));
            output.Append(report.FormatArtifactSigningVerified(signature));
        }
        else if (args.Catalog is { } catalog)
        {
            var bytes = Output.ReadFile(catalog);
            var report = PeCommands.Wrap($"Artifact Signing {catalog}", () => TrustVerifyCatalog.TrustVerifyCatalogBytes(bytes, opts));
            output.Append(report.FormatArtifactSigningVerified(catalog));
        }
        else
        {
            foreach (var path in args.Files)
            {
                var report = PeCommands.Wrap($"Artifact Signing {path}", () => TrustVerifyFile.TrustVerifyPath(path, opts));
                output.Append(report.FormatArtifactSigningVerified(path));
            }
        }

        return output.ToString();
    }
}
