using System.Globalization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Verification.AuthRoot;

namespace Devolutions.Psign.Verification;

/// <summary>
/// The trust options of the Rust <c>psign-tool portable trust-verify-*</c> commands (<c>TrustVerifySharedArgs</c> in
/// <c>crates/psign-digest-cli/src/main.rs</c>). <see cref="ToOptions"/> reproduces <c>trust_verify_options_from_shared</c>
/// (Artifact Signing conflicts, automatic AuthRoot cache resolution, AIA auto-enable with an AuthRoot CAB) so a managed
/// CLI produces identical behaviour.
/// </summary>
public sealed record TrustVerifySharedArgs
{
    public string? AnchorDir { get; init; }

    public IReadOnlyList<string> TrustedCa { get; init; } = [];

    public IReadOnlyList<string> AdditionalTrustedCa { get; init; } = [];

    public string? AuthrootCab { get; init; }

    public string? ExpectAuthrootCabSha256 { get; init; }

    public bool VerboseChain { get; init; }

    public bool AllowLooseSigningCert { get; init; }

    public bool PreferTimestampSigningTime { get; init; }

    public bool RequireValidTimestamp { get; init; }

    /// <summary><c>--as-of YYYY-MM-DD</c>.</summary>
    public string? AsOf { get; init; }

    public bool OnlineAia { get; init; }

    public string? AiaUrlOverride { get; init; }

    public bool OnlineOcsp { get; init; }

    public string? OcspUrlOverride { get; init; }

    public RevocationMode RevocationMode { get; init; } = RevocationMode.Off;

    public string? CrlUrlOverride { get; init; }

    public ulong OnlineTimeoutSecs { get; init; } = 5;

    public int OnlineMaxDownloadBytes { get; init; } = 1024 * 1024;

    public bool ArtifactSigning { get; init; }

    public IReadOnlyList<string> ArtifactSigningPublisherId { get; init; } = [];

    public IReadOnlyList<string> ArtifactSigningPrivateTrustRoot { get; init; } = [];

    public bool ArtifactSigningAllowMissingTimestamp { get; init; }

    /// <summary>Rust <c>artifact_signing_policy</c>: <c>null</c> unless an <c>--artifact-signing*</c> option is set.</summary>
    public ArtifactSigningPolicy? ArtifactSigningPolicy()
    {
        if (!(ArtifactSigning || ArtifactSigningPublisherId.Count > 0 || ArtifactSigningPrivateTrustRoot.Count > 0 || ArtifactSigningAllowMissingTimestamp))
        {
            return null;
        }

        (bool Set, string Flag)[] conflicts =
        [
            (AnchorDir is not null, "--anchor-dir"),
            (TrustedCa.Count > 0, "--trusted-ca"),
            (AdditionalTrustedCa.Count > 0, "--additional-trusted-ca"),
            (AuthrootCab is not null, "--authroot-cab"),
            (ExpectAuthrootCabSha256 is not null, "--expect-authroot-cab-sha256"),
            (AllowLooseSigningCert, "--allow-loose-signing-cert"),
        ];
        foreach (var (set, flag) in conflicts)
        {
            if (set)
            {
                throw new PsignException(
                    $"{flag} cannot be combined with --artifact-signing: Artifact Signing pins its own roots (use --artifact-signing-private-trust-root for Private Trust)");
            }
        }

        return new ArtifactSigningPolicy
        {
            ExpectedPublisherIds = ArtifactSigningPublisherId.ToList(),
            PrivateTrustRootFiles = ArtifactSigningPrivateTrustRoot.ToList(),
            RequireTimestamp = !ArtifactSigningAllowMissingTimestamp,
        };
    }

    /// <summary><c>--anchor-dir</c> or <c>--trusted-ca</c> replace the automatic AuthRoot cache (additional CAs do not).</summary>
    public bool ExplicitAnchorsReplaceAutomaticAuthRoot => AnchorDir is not null || TrustedCa.Count > 0;

    /// <summary>True when any trust option that triggers trust verification is present (Rust <c>trust_verify_args_present</c>).</summary>
    public bool TrustVerifyArgsPresent =>
        AnchorDir is not null || TrustedCa.Count > 0 || AdditionalTrustedCa.Count > 0 || AuthrootCab is not null
        || ExpectAuthrootCabSha256 is not null || AsOf is not null || OnlineAia || OnlineOcsp
        || RevocationMode != RevocationMode.Off || CrlUrlOverride is not null || AiaUrlOverride is not null || OcspUrlOverride is not null;

    /// <summary>Rust <c>trust_verify_options_from_shared</c>.</summary>
    public TrustVerifyPeOptions ToOptions()
    {
        var pin = ExpectAuthrootCabSha256 is { } s ? ParseSha256Hex(s) : null;
        var instant = AsOf is { } a ? VerificationInstant.ParseVerificationDateYmd(a) : (DateTimeOffset?)null;
        var artifact = ArtifactSigningPolicy();
        var cab = artifact is not null ? null : ResolveAuthRootCab();
        return new TrustVerifyPeOptions
        {
            AnchorDir = AnchorDir,
            TrustedCaFiles = TrustedCa.Concat(AdditionalTrustedCa).ToList(),
            AuthrootCab = cab,
            ExpectAuthrootCabSha256 = pin,
            VerificationInstantOverride = instant,
            VerboseChain = VerboseChain,
            Online = new OnlineTrustOptions
            {
                EnableAia = OnlineAia || cab is not null,
                AiaUrlOverride = AiaUrlOverride,
                EnableOcsp = OnlineOcsp,
                OcspUrlOverride = OcspUrlOverride,
                RevocationMode = RevocationMode,
                CrlUrlOverride = CrlUrlOverride,
                Timeout = TimeSpan.FromSeconds(OnlineTimeoutSecs),
                MaxDownloadBytes = OnlineMaxDownloadBytes,
            },
            Policy = new AuthenticodeTrustPolicy
            {
                StrictCodeSigningEku = !AllowLooseSigningCert,
                PreferTimestampSigningTime = PreferTimestampSigningTime,
                RequireValidTimestamp = RequireValidTimestamp,
            },
            ArtifactSigning = artifact,
        };
    }

    private string? ResolveAuthRootCab()
    {
        if (AuthrootCab is not null)
        {
            return AuthrootCab;
        }

        if (ExplicitAnchorsReplaceAutomaticAuthRoot)
        {
            return null;
        }

        return AuthRootCache.GetOrDownloadAuthRootCabFromEnv()?.Path;
    }

    /// <summary>Rust <c>parse_sha256_hex</c> (64 hex chars, optional <c>0x</c>).</summary>
    public static byte[] ParseSha256Hex(string s)
    {
        var hex = s.Trim();
        if (hex.StartsWith("0x", StringComparison.Ordinal))
        {
            hex = hex[2..];
        }

        if (hex.StartsWith("0X", StringComparison.Ordinal))
        {
            hex = hex[2..];
        }

        if (hex.Length != 64)
        {
            throw new PsignException($"expect 64 hex chars for SHA-256, got {hex.Length}");
        }

        var output = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            if (!byte.TryParse(hex.AsSpan(i * 2, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out output[i]))
            {
                throw new PsignException("invalid hex");
            }
        }

        return output;
    }
}
