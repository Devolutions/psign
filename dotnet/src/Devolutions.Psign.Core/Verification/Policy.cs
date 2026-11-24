namespace Devolutions.Psign.Verification;

/// <summary>Trust policy knobs (Rust <c>policy::AuthenticodeTrustPolicy</c>).</summary>
public sealed record AuthenticodeTrustPolicy
{
    /// <summary>When true (default), enforce Authenticode <b>code signing</b> EKU rules on the signer.</summary>
    public bool StrictCodeSigningEku { get; init; } = true;

    /// <summary>Prefer RFC 3161 / Authenticode nested timestamp signing time for the verification instant when present.</summary>
    public bool PreferTimestampSigningTime { get; init; }

    /// <summary>When <see cref="PreferTimestampSigningTime"/> is set, fail if no usable timestamp token is found.</summary>
    public bool RequireValidTimestamp { get; init; }
}

/// <summary>Revocation checking mode for explicit online checks (Rust <c>policy::RevocationMode</c>).</summary>
public enum RevocationMode
{
    Off,
    BestEffort,
    Require,
}

/// <summary>Explicit online retrieval options (Rust <c>policy::OnlineTrustOptions</c>).</summary>
public sealed record OnlineTrustOptions
{
    /// <summary>Fetch issuer certificates from AIA caIssuers URLs when the PKCS#7 / anchor pool lacks an issuer.</summary>
    public bool EnableAia { get; init; }

    /// <summary>Deterministic test override used before certificate AIA URLs.</summary>
    public string? AiaUrlOverride { get; init; }

    /// <summary>Query OCSP responders for signer / intermediate revocation status.</summary>
    public bool EnableOcsp { get; init; }

    /// <summary>Deterministic OCSP responder URL override used before certificate AIA OCSP URLs.</summary>
    public string? OcspUrlOverride { get; init; }

    /// <summary>Revocation checking mode for explicit online checks.</summary>
    public RevocationMode RevocationMode { get; init; } = RevocationMode.Off;

    /// <summary>Deterministic CRL URL override used before certificate CDP parsing.</summary>
    public string? CrlUrlOverride { get; init; }

    /// <summary>Per-request timeout for online certificate retrieval (default 5 s).</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Maximum downloaded response size for online certificate retrieval (default 1 MiB).</summary>
    public int MaxDownloadBytes { get; init; } = 1024 * 1024;
}
