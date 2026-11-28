using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.AuthRoot;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>Kind of durable pin recommended for a verified MSIX signer.</summary>
public enum MsixPinKind
{
    /// <summary>Azure Artifact Signing certificate profile publisher ID (stable across 72h renewals).</summary>
    ArtifactSigningPublisherId,

    /// <summary>Lowercase hex SHA-256 thumbprint of the leaf signing certificate DER.</summary>
    CertificateSha256,
}

/// <summary>Recommended durable pin for a verified MSIX signer (Rust <c>MsixRecommendedPin</c>).</summary>
public sealed record MsixRecommendedPin(MsixPinKind Kind, string Value)
{
    /// <summary>Create an Azure Artifact Signing publisher ID recommendation.</summary>
    public static MsixRecommendedPin ArtifactSigningPublisherId(string publisherId) =>
        new(MsixPinKind.ArtifactSigningPublisherId, publisherId);

    /// <summary>Create a leaf certificate SHA-256 thumbprint recommendation.</summary>
    public static MsixRecommendedPin CertificateSha256(string sha256Hex) =>
        new(MsixPinKind.CertificateSha256, sha256Hex);
}

/// <summary>Cryptographically verified signer details for an MSIX / AppX package (Rust <c>MsixVerifiedSigner</c>).</summary>
public sealed record MsixVerifiedSigner
{
    /// <summary>DER-encoded leaf signing certificate.</summary>
    [JsonIgnore]
    public byte[] SignerCertificateDer { get; init; } = [];

    /// <summary>Lowercase hex SHA-256 thumbprint of <see cref="SignerCertificateDer"/>.</summary>
    [JsonPropertyName("signer_sha256_hex")]
    public string SignerSha256Hex { get; init; } = string.Empty;

    /// <summary>Lowercase hex SHA-1 thumbprint of <see cref="SignerCertificateDer"/>.</summary>
    [JsonPropertyName("signer_sha1_hex")]
    public string SignerSha1Hex { get; init; } = string.Empty;

    /// <summary>Subject distinguished name of the leaf signing certificate.</summary>
    [JsonPropertyName("signer_subject")]
    public string SignerSubject { get; init; } = string.Empty;

    /// <summary>Decoded Azure Artifact Signing identity when present on the leaf certificate.</summary>
    [JsonPropertyName("artifact_signing")]
    public ArtifactSigningIdentity? ArtifactSigning { get; init; }

    /// <summary>Recommended pin for this verified signer.</summary>
    [JsonPropertyName("recommended_pin")]
    public MsixRecommendedPin RecommendedPin { get; init; } = MsixRecommendedPin.CertificateSha256(string.Empty);
}

/// <summary>Options for pinning and trust-verifying an MSIX / AppX package (Rust <c>MsixPinVerifyOptions</c>).</summary>
public sealed record MsixPinVerifyOptions
{
    /// <summary>
    /// Allowed leaf certificate thumbprints (lowercase/uppercase hex with optional <c>:</c>, <c>-</c>, or whitespace
    /// separators and optional <c>sha256:</c>/<c>sha-256:</c>/<c>sha1:</c>/<c>sha-1:</c> prefix; 64 hex matches SHA-256,
    /// 40 hex matches SHA-1).
    /// </summary>
    public IReadOnlyList<string> ExpectedCertThumbprints { get; init; } = [];

    /// <summary>Allowed Azure Artifact Signing publisher IDs (exact dotted-decimal string match).</summary>
    public IReadOnlyList<string> ExpectedArtifactSigningPublisherIds { get; init; } = [];

    /// <summary>Explicit trusted CA / subscriber root files (PEM or DER).</summary>
    public IReadOnlyList<string> TrustedCaFiles { get; init; } = [];

    /// <summary>Explicit trusted CA / subscriber root certificates as DER bytes.</summary>
    public IReadOnlyList<byte[]> TrustedCaDer { get; init; } = [];

    /// <summary>
    /// When <c>true</c> and <see cref="ExpectedCertThumbprints"/> is non-empty with no explicit <c>TrustedCa*</c>, allows a
    /// thumbprint-matched leaf certificate to satisfy trust when standard CA trust fails, provided the leaf is currently
    /// valid or covered by a trusted RFC 3161 timestamp.
    /// </summary>
    public bool AllowPinnedLeafTrust { get; init; }
}

/// <summary>MSIX / AppX (and bundle) Authenticode trust: APPX SIP digest + PKCS#7 chain (Rust <c>trust_verify_msix.rs</c>).</summary>
public static class TrustVerifyMsix
{
    private readonly record struct ParsedThumbprintPin(bool IsSha256, string HexValue)
    {
        public static ParsedThumbprintPin Parse(string raw)
        {
            var lower = raw.Trim().ToLowerInvariant();
            string? forcedKind = null;
            string rest = lower;
            if (lower.StartsWith("sha256:", StringComparison.Ordinal))
            {
                forcedKind = "sha256";
                rest = lower["sha256:".Length..];
            }
            else if (lower.StartsWith("sha-256:", StringComparison.Ordinal))
            {
                forcedKind = "sha256";
                rest = lower["sha-256:".Length..];
            }
            else if (lower.StartsWith("sha1:", StringComparison.Ordinal))
            {
                forcedKind = "sha1";
                rest = lower["sha1:".Length..];
            }
            else if (lower.StartsWith("sha-1:", StringComparison.Ordinal))
            {
                forcedKind = "sha1";
                rest = lower["sha-1:".Length..];
            }

            var sb = new StringBuilder(rest.Length);
            foreach (var ch in rest)
            {
                if (ch is ':' or '-' || char.IsWhiteSpace(ch))
                {
                    continue;
                }

                if (!Uri.IsHexDigit(ch))
                {
                    throw new PsignException($"invalid certificate thumbprint pin \"{raw}\": contains non-hex character '{ch}'");
                }

                sb.Append(ch);
            }

            var hex = sb.ToString();
            return (forcedKind, hex.Length) switch
            {
                ("sha256" or null, 64) => new ParsedThumbprintPin(true, hex),
                ("sha1" or null, 40) => new ParsedThumbprintPin(false, hex),
                ("sha256", var n) => throw new PsignException($"invalid SHA-256 certificate thumbprint pin \"{raw}\": expected 64 hex digits, got {n}"),
                ("sha1", var n) => throw new PsignException($"invalid SHA-1 certificate thumbprint pin \"{raw}\": expected 40 hex digits, got {n}"),
                (_, var n) => throw new PsignException($"invalid certificate thumbprint pin \"{raw}\": expected 64 (SHA-256) or 40 (SHA-1) hex digits, got {n}"),
            };
        }

        public bool Matches(string sha256Hex, string sha1Hex) =>
            IsSha256 ? string.Equals(HexValue, sha256Hex, StringComparison.Ordinal) : string.Equals(HexValue, sha1Hex, StringComparison.Ordinal);
    }

    private static void EnsureSingleMsixSigner(byte[] pkcs7)
    {
        var normalized = Pkcs7Wire.NormalizeForAuthenticode(pkcs7);
        var sd = CmsTrustHelpers.ParsePkcs7SignedDataDer(normalized);
        if (sd.SignerInfos.Count != 1)
        {
            throw new PsignException("MSIX signature must contain exactly one signer");
        }
    }

    /// <summary>
    /// Verify package integrity and the embedded CMS signature without evaluating certificate trust or validity. Returns
    /// the DER-encoded signing certificate, which must be subject to the caller's publisher policy. This is not a trust
    /// verification (Rust <c>verify_msix_signature_without_trust</c>).
    /// </summary>
    public static byte[] VerifyMsixSignatureWithoutTrust(byte[] data, string extension)
    {
        var (pkcs7, digest) = MsixDigest.MsixVerifiedSignature(data, extension);
        return VerifyMsixPkcs7WithoutTrust(pkcs7, digest);
    }

    internal static byte[] VerifyMsixPkcs7WithoutTrust(byte[] pkcs7, byte[] digest)
    {
        var normalized = Pkcs7Wire.NormalizeForAuthenticode(pkcs7);
        var sd = CmsTrustHelpers.ParsePkcs7SignedDataDer(normalized);
        if (sd.SignerInfos.Count != 1)
        {
            throw new PsignException("MSIX signature must contain exactly one signer");
        }

        var cert = CmsTrustHelpers.CertificateForSigner(sd, sd.SignerInfos[0]);
        if (!CmsTrustHelpers.HasCodeSigningEku(cert))
        {
            throw new PsignException("MSIX signing certificate lacks code-signing extended key usage");
        }

        var picky = PickyAuthenticode.TryParse(normalized);
        if (picky is not null)
        {
            try
            {
                picky.VerifyBasic(digest);
            }
            catch (PickyException e)
            {
                throw new PsignException($"MSIX Authenticode signature validation: {e.Message}");
            }
        }
        else
        {
            try
            {
                CmsTrustHelpers.VerifyAuthenticodeIndirectDigestAndRsaSha256(sd, 0, digest);
            }
            catch (PsignException e)
            {
                throw PsignException.Context("MSIX CMS signature validation", e);
            }
        }

        return cert.RawData.ToArray();
    }

    private static List<byte[]> LoadSystemRootCertificates()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var roots = new List<byte[]>();
        List<string>? errors = null;

        void ReadStore(StoreLocation location)
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadOnly);
                foreach (var cert in store.Certificates)
                {
                    var der = cert.RawData;
                    if (der.Length > 0 && seen.Add(Anchors.CertDerSha1Hex(der)))
                    {
                        roots.Add(der);
                    }
                }
            }
            catch (Exception e) when (e is CryptographicException or PlatformNotSupportedException)
            {
                errors ??= [];
                errors.Add($"{location}: {e.Message}");
            }
        }

        ReadStore(StoreLocation.LocalMachine);
        ReadStore(StoreLocation.CurrentUser);

        if (roots.Count == 0)
        {
            if (errors is { Count: > 0 })
            {
                throw new PsignException($"failed to load system trust anchors: {string.Join("; ", errors)}");
            }

            throw new PsignException("system trust store contains no certificates");
        }

        return roots;
    }

    /// <summary>
    /// Select OS trust anchors or a pinned automatic AuthRoot cache when no anchors are configured
    /// (Rust <c>msix_options_with_auto_authroot</c>).
    /// </summary>
    public static (TrustVerifyPeOptions Options, AuthRootCacheResolution? Cache) MsixOptionsWithAutoAuthRoot(TrustVerifyPeOptions opts)
    {
        var resolved = opts;
        AuthRootCacheResolution? cache = null;
        if (resolved.ArtifactSigning is null
            && resolved.AuthrootCab is null
            && resolved.AnchorDir is null
            && resolved.TrustedCaFiles.Count == 0
            && resolved.TrustedCaDer.Count == 0)
        {
            if (resolved.ExpectAuthrootCabSha256 is not null)
            {
                cache = AuthRootCache.GetOrDownloadAuthRootCabFromEnv();
            }
            else
            {
                resolved = resolved with
                {
                    TrustedCaDer = LoadSystemRootCertificates(),
                    Online = resolved.Online with { EnableAia = true },
                };
            }
        }

        if (cache is not null)
        {
            resolved = resolved with { AuthrootCab = cache.Path };
        }

        if (resolved.AuthrootCab is not null)
        {
            resolved = resolved with { Online = resolved.Online with { EnableAia = true } };
        }

        return (resolved, cache);
    }

    /// <summary>
    /// Trust-verify at the current time, falling back to a cryptographically trusted RFC 3161 timestamp if current-time
    /// validation fails (Rust <c>trust_verify_msix_current_or_timestamp</c>).
    /// </summary>
    public static TrustVerifyPeReport TrustVerifyMsixCurrentOrTimestamp(byte[] data, string extension, TrustVerifyPeOptions opts) =>
        CurrentOrTimestamp(opts, o => TrustVerifyMsixBytes(data, extension, o));

    internal static T CurrentOrTimestamp<T>(TrustVerifyPeOptions opts, Func<TrustVerifyPeOptions, T> verify)
    {
        if (opts.VerificationInstantOverride is not null || opts.ArtifactSigning is not null)
        {
            throw new PsignException(
                "current-or-timestamp verification cannot use an explicit instant or Artifact Signing policy");
        }

        var current = opts with
        {
            Policy = opts.Policy with { PreferTimestampSigningTime = false, RequireValidTimestamp = false },
        };
        try
        {
            return verify(current);
        }
        catch (PsignException currentError)
        {
            var timestamped = current with
            {
                Policy = current.Policy with { PreferTimestampSigningTime = true, RequireValidTimestamp = true },
            };
            try
            {
                return verify(timestamped);
            }
            catch (PsignException timestampError)
            {
                throw new PsignException(
                    $"MSIX current-time verification failed: {PsignException.Render(currentError)}; trusted-timestamp verification failed: {PsignException.Render(timestampError)}");
            }
        }
    }

    /// <summary>
    /// Trust-verify a cleartext <c>.msix</c> / <c>.appx</c> / <c>.msixbundle</c> / <c>.appxbundle</c> package
    /// (<paramref name="extension"/> without the dot). The APPX <c>messageDigest</c> blob is recomputed and compared before
    /// the PKCS#7 trust step.
    /// </summary>
    public static TrustVerifyPeReport TrustVerifyMsixBytes(byte[] data, string extension, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var (pkcs7, digest) = MsixDigest.MsixVerifiedSignature(data, extension);
        EnsureSingleMsixSigner(pkcs7);
        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(pkcs7, 0, digest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
        return report;
    }

    private static void VerifyPinnedLeafValidity(byte[] pkcs7, CertificateInfo signer)
    {
        var now = PickyFormat.Now();
        if (now >= signer.NotBefore && now <= signer.NotAfter)
        {
            return;
        }

        var tsaAnchors = AnchorStore.Empty();
        var tsaCerts = ArtifactSigning.PublicTrustAnchorCerts();
        tsaAnchors.MergeCertThumbprints(tsaCerts);
        try
        {
            var (sysOpts, _) = MsixOptionsWithAutoAuthRoot(new TrustVerifyPeOptions());
            var (_, sysCerts) = TrustVerifyPe.LoadTrustMaterial(sysOpts);
            tsaAnchors.MergeCertThumbprints(sysCerts);
            tsaCerts.AddRange(sysCerts);
        }
        catch (PsignException)
        {
        }

        var online = new OnlineTrustOptions { EnableAia = true };
        DateTimeOffset? tsDate;
        try
        {
            tsDate = Rfc3161Extract.TrustedUtcDateFromAuthenticodeTimestampToken(pkcs7, tsaAnchors, tsaCerts, online, verboseChain: false);
        }
        catch (PsignException e)
        {
            throw PsignException.Context("pinned MSIX signer certificate is expired or not yet valid; trusted timestamp check failed", e);
        }

        if (tsDate is not { } verifiedTime)
        {
            throw new PsignException(
                $"pinned MSIX signer certificate is not valid at current time (not_before={signer.NotBefore:O}, not_after={signer.NotAfter:O}) and has no trusted RFC 3161 timestamp");
        }

        if (verifiedTime < signer.NotBefore || verifiedTime > signer.NotAfter)
        {
            throw new PsignException(
                $"pinned MSIX signer certificate was not valid at timestamp time (not_before={signer.NotBefore:O}, not_after={signer.NotAfter:O})");
        }
    }

    /// <summary>
    /// Verify an MSIX / AppX package and enforce optional certificate thumbprint and Azure Artifact Signing publisher ID
    /// pins (Rust <c>verify_msix_with_pins</c>).
    /// </summary>
    public static MsixVerifiedSigner VerifyMsixWithPins(byte[] data, string extension, MsixPinVerifyOptions opts)
    {
        var parsedThumbprints = opts.ExpectedCertThumbprints.Select(ParsedThumbprintPin.Parse).ToList();
        var expectedPublisherIds = new List<string>(opts.ExpectedArtifactSigningPublisherIds.Count);
        foreach (var id in opts.ExpectedArtifactSigningPublisherIds)
        {
            var trimmed = id.Trim();
            if (trimmed.Length == 0)
            {
                throw new PsignException("expected Artifact Signing publisher ID cannot be empty");
            }

            expectedPublisherIds.Add(trimmed);
        }

        var (pkcs7, digest) = MsixDigest.MsixVerifiedSignature(data, extension);
        var signerDer = VerifyMsixPkcs7WithoutTrust(pkcs7, digest);
        var signerSha256Hex = Anchors.CertDerSha256Hex(signerDer);
        var signerSha1Hex = Anchors.CertDerSha1Hex(signerDer);
        var signerCert = CertificateInfo.Parse(signerDer);
        var signerSubject = PickyCert.SubjectDisplay(signerCert);
        var artifactSigning = ArtifactSigning.IdentityFromCertificate(signerCert);
        if (artifactSigning?.Kind == ArtifactSigningCertificateKind.PrivateTrustCiPolicy)
        {
            throw new PsignException("Private Trust CI Policy certificates sign WDAC policies, not Authenticode code");
        }

        if (parsedThumbprints.Count > 0 && !parsedThumbprints.Any(pin => pin.Matches(signerSha256Hex, signerSha1Hex)))
        {
            throw new PsignException(
                $"MSIX signer certificate thumbprint (sha256={signerSha256Hex}, sha1={signerSha1Hex}) does not match any expected pin");
        }

        bool hasExplicitCa = opts.TrustedCaFiles.Count > 0 || opts.TrustedCaDer.Count > 0;
        bool isPublicTrustAs = artifactSigning is
        {
            Kind: ArtifactSigningCertificateKind.PublicTrust,
            HasPublicTrustMarker: true,
            HasCodeSigningEku: true,
        };
        bool isPrivateOrTestAs = artifactSigning is
        {
            Kind: ArtifactSigningCertificateKind.PrivateTrust or ArtifactSigningCertificateKind.PublicTrustTest,
            HasCodeSigningEku: true,
        };

        bool artifactSigningVerified;
        if (expectedPublisherIds.Count > 0)
        {
            if (artifactSigning is null)
            {
                throw new PsignException($"MSIX signer certificate {PickyFormat.StrDebug(signerSubject)} has no Artifact Signing identity EKU");
            }

            bool requireTimestamp = !hasExplicitCa || artifactSigning.Kind == ArtifactSigningCertificateKind.PublicTrust;
            var policy = new ArtifactSigningPolicy
            {
                ExpectedPublisherIds = expectedPublisherIds,
                PrivateTrustRootFiles = opts.TrustedCaFiles,
                PrivateTrustRootDer = opts.TrustedCaDer,
                RequireTimestamp = requireTimestamp,
            };
            TrustVerifyMsixBytes(data, extension, new TrustVerifyPeOptions { ArtifactSigning = policy });
            artifactSigningVerified = true;
        }
        else if (parsedThumbprints.Count > 0)
        {
            if (hasExplicitCa)
            {
                TrustVerifyMsixCurrentOrTimestamp(data, extension, new TrustVerifyPeOptions
                {
                    TrustedCaFiles = opts.TrustedCaFiles,
                    TrustedCaDer = opts.TrustedCaDer,
                });
                artifactSigningVerified = false;
            }
            else
            {
                try
                {
                    if (isPublicTrustAs)
                    {
                        TrustVerifyMsixBytes(data, extension, new TrustVerifyPeOptions { ArtifactSigning = new ArtifactSigningPolicy() });
                        artifactSigningVerified = true;
                    }
                    else
                    {
                        var (resolved, _) = MsixOptionsWithAutoAuthRoot(new TrustVerifyPeOptions());
                        TrustVerifyMsixCurrentOrTimestamp(data, extension, resolved);
                        artifactSigningVerified = false;
                    }
                }
                catch (PsignException standardError) when (opts.AllowPinnedLeafTrust)
                {
                    try
                    {
                        VerifyPinnedLeafValidity(pkcs7, signerCert);
                    }
                    catch (PsignException leafError)
                    {
                        throw PsignException.Context(
                            $"standard trust failed ({PsignException.Render(standardError)}) and pinned leaf validity check failed",
                            leafError);
                    }

                    artifactSigningVerified = false;
                }
            }
        }
        else if (hasExplicitCa)
        {
            if (isPrivateOrTestAs)
            {
                var policy = new ArtifactSigningPolicy
                {
                    PrivateTrustRootFiles = opts.TrustedCaFiles,
                    PrivateTrustRootDer = opts.TrustedCaDer,
                    RequireTimestamp = false,
                };
                TrustVerifyMsixBytes(data, extension, new TrustVerifyPeOptions { ArtifactSigning = policy });
                artifactSigningVerified = true;
            }
            else
            {
                TrustVerifyMsixCurrentOrTimestamp(data, extension, new TrustVerifyPeOptions
                {
                    TrustedCaFiles = opts.TrustedCaFiles,
                    TrustedCaDer = opts.TrustedCaDer,
                });
                artifactSigningVerified = false;
            }
        }
        else if (isPublicTrustAs)
        {
            TrustVerifyMsixBytes(data, extension, new TrustVerifyPeOptions { ArtifactSigning = new ArtifactSigningPolicy() });
            artifactSigningVerified = true;
        }
        else
        {
            var (resolved, _) = MsixOptionsWithAutoAuthRoot(new TrustVerifyPeOptions());
            TrustVerifyMsixCurrentOrTimestamp(data, extension, resolved);
            artifactSigningVerified = false;
        }

        var recommendedPin = artifactSigning is not null && artifactSigningVerified
            ? MsixRecommendedPin.ArtifactSigningPublisherId(artifactSigning.PublisherId)
            : MsixRecommendedPin.CertificateSha256(signerSha256Hex);

        return new MsixVerifiedSigner
        {
            SignerCertificateDer = signerDer,
            SignerSha256Hex = signerSha256Hex,
            SignerSha1Hex = signerSha1Hex,
            SignerSubject = signerSubject,
            ArtifactSigning = artifactSigning,
            RecommendedPin = recommendedPin,
        };
    }

    /// <summary>
    /// Trust-verify an MSIX / AppX package and return its cryptographically bound signer details with a recommended durable
    /// pin (<see cref="MsixPinKind.ArtifactSigningPublisherId"/> for verified Artifact Signing certificates, or
    /// <see cref="MsixPinKind.CertificateSha256"/> otherwise) (Rust <c>verify_msix_for_pinning</c>).
    /// </summary>
    public static MsixVerifiedSigner VerifyMsixForPinning(byte[] data, string extension, IReadOnlyList<string>? trustedCaFiles = null) =>
        VerifyMsixWithPins(data, extension, new MsixPinVerifyOptions
        {
            TrustedCaFiles = trustedCaFiles ?? [],
        });
}
