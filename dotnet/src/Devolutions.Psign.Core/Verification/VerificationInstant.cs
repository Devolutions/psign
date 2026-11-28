using System.Globalization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>Resolve the certificate validity instant from policy (Rust <c>verification_instant.rs</c>).</summary>
public static class VerificationInstant
{
    /// <summary>Calendar date at UTC midnight (<c>YYYY-MM-DD</c>) for reproducible verification.</summary>
    public static DateTimeOffset ParseVerificationDateYmd(string s)
    {
        var p = s.Trim().Split('-');
        if (p.Length != 3)
        {
            throw new PsignException("expected YYYY-MM-DD");
        }

        if (!ushort.TryParse(p[0], NumberStyles.None, CultureInfo.InvariantCulture, out var y))
        {
            throw new PsignException("invalid year");
        }

        if (!byte.TryParse(p[1], NumberStyles.None, CultureInfo.InvariantCulture, out var m))
        {
            throw new PsignException("invalid month");
        }

        if (!byte.TryParse(p[2], NumberStyles.None, CultureInfo.InvariantCulture, out var d))
        {
            throw new PsignException("invalid day");
        }

        if (y is < 1 or > 9999 || m is < 1 or > 12 || d < 1 || d > DateTime.DaysInMonth(y, m))
        {
            throw new PsignException($"invalid calendar date {y}-{m:00}-{d:00}");
        }

        return new DateTimeOffset(y, m, d, 0, 0, 0, TimeSpan.Zero);
    }

    /// <summary>Wall clock, or the embedded timestamp / signing time when the policy prefers it.</summary>
    public static DateTimeOffset ResolveVerificationUtcDate(ReadOnlySpan<byte> pkcs7Der, AuthenticodeTrustPolicy policy)
    {
        if (!policy.PreferTimestampSigningTime)
        {
            return PickyFormat.Now();
        }

        if (Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(pkcs7Der) is { } d)
        {
            return d;
        }

        if (policy.RequireValidTimestamp)
        {
            throw new PsignException(
                "timestamp required by policy but no usable RFC3161 / Authenticode timestamp token or PKCS#9 signing-time was found");
        }

        return PickyFormat.Now();
    }

    /// <summary>The override when set, else <see cref="ResolveVerificationUtcDate"/>.</summary>
    public static DateTimeOffset ResolveVerificationInstantForPkcs7(ReadOnlySpan<byte> pkcs7Der, AuthenticodeTrustPolicy policy, DateTimeOffset? instantOverride) =>
        instantOverride ?? ResolveVerificationUtcDate(pkcs7Der, policy);

    /// <summary>
    /// The override when set; otherwise, when a valid timestamp is required, a cryptographically verified trusted RFC 3161
    /// timestamp; otherwise <see cref="ResolveVerificationUtcDate"/>. Also reports whether a cryptographically verified
    /// timestamp supplied the instant.
    /// </summary>
    internal static (DateTimeOffset Instant, bool Timestamped) ResolveVerificationInstantForPkcs7WithTrustInfo(
        ReadOnlySpan<byte> pkcs7Der,
        AuthenticodeTrustPolicy policy,
        DateTimeOffset? instantOverride,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        OnlineTrustOptions online,
        bool verboseChain,
        TextWriter? log = null)
    {
        if (instantOverride is { } o)
        {
            return (o, false);
        }

        if (!policy.PreferTimestampSigningTime)
        {
            return (PickyFormat.Now(), false);
        }

        if (policy.RequireValidTimestamp)
        {
            var ts = Rfc3161Extract.TrustedUtcDateFromAuthenticodeTimestampToken(pkcs7Der, anchors, anchorCerts, online, verboseChain, log)
                ?? throw new PsignException(
                    "timestamp required by policy but no cryptographically valid trusted RFC3161 timestamp token was found");
            return (ts, true);
        }

        return (ResolveVerificationUtcDate(pkcs7Der, policy), false);
    }

    /// <summary>
    /// The override when set; otherwise, when a valid timestamp is required, a cryptographically verified trusted RFC 3161
    /// timestamp; otherwise <see cref="ResolveVerificationUtcDate"/>.
    /// </summary>
    public static DateTimeOffset ResolveVerificationInstantForPkcs7WithTrust(
        ReadOnlySpan<byte> pkcs7Der,
        AuthenticodeTrustPolicy policy,
        DateTimeOffset? instantOverride,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        OnlineTrustOptions online,
        bool verboseChain,
        TextWriter? log = null) =>
        ResolveVerificationInstantForPkcs7WithTrustInfo(pkcs7Der, policy, instantOverride, anchors, anchorCerts, online, verboseChain, log).Instant;
}
