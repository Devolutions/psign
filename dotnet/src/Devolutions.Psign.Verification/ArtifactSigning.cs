using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>A Microsoft root certificate pinned for Artifact Signing validation.</summary>
public sealed class PinnedRoot
{
    internal PinnedRoot(string name, string sha1Hex, string sha256Hex, string pem)
    {
        Name = name;
        Sha1 = Hex.Decode(sha1Hex);
        Sha256 = Hex.Decode(sha256Hex);
        Pem = pem;
    }

    public string Name { get; }

    public byte[] Sha1 { get; }

    public byte[] Sha256 { get; }

    internal string Pem { get; }

    /// <summary>Parse the embedded certificate and confirm it matches both pinned thumbprints.</summary>
    public CertificateInfo Certificate()
    {
        CertificateInfo cert;
        try
        {
            cert = Anchors.ParseCertBytes(Encoding.ASCII.GetBytes(Pem));
        }
        catch (PsignException e)
        {
            throw PsignException.Context($"parse pinned root {Name}", e);
        }

        if (!Anchors.CertSha1Thumbprint(cert).AsSpan().SequenceEqual(Sha1) || !SHA256.HashData(cert.RawData).AsSpan().SequenceEqual(Sha256))
        {
            throw new PsignException($"embedded pinned root {Name} does not match its pinned thumbprints");
        }

        return cert;
    }
}

/// <summary>Artifact Signing certificate profile kind.</summary>
[JsonConverter(typeof(ArtifactSigningCertificateKindJsonConverter))]
public enum ArtifactSigningCertificateKind
{
    PublicTrust,

    PublicTrustTest,

    PrivateTrust,

    PrivateTrustCiPolicy,
}

/// <summary>Serializes <see cref="ArtifactSigningCertificateKind"/> as its snake-case name (serde <c>rename_all</c>).</summary>
public sealed class ArtifactSigningCertificateKindJsonConverter : JsonConverter<ArtifactSigningCertificateKind>
{
    public override ArtifactSigningCertificateKind Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options) =>
        reader.GetString() switch
        {
            "public_trust" => ArtifactSigningCertificateKind.PublicTrust,
            "public_trust_test" => ArtifactSigningCertificateKind.PublicTrustTest,
            "private_trust" => ArtifactSigningCertificateKind.PrivateTrust,
            "private_trust_ci_policy" => ArtifactSigningCertificateKind.PrivateTrustCiPolicy,
            var other => throw new System.Text.Json.JsonException($"unknown variant `{other}`"),
        };

    public override void Write(System.Text.Json.Utf8JsonWriter writer, ArtifactSigningCertificateKind value, System.Text.Json.JsonSerializerOptions options) =>
        writer.WriteStringValue(value.AsStr());
}

/// <summary>String helpers for <see cref="ArtifactSigningCertificateKind"/>.</summary>
public static class ArtifactSigningCertificateKindExtensions
{
    /// <summary>Snake-case name (Rust <c>as_str</c>).</summary>
    public static string AsStr(this ArtifactSigningCertificateKind kind) => kind switch
    {
        ArtifactSigningCertificateKind.PublicTrust => "public_trust",
        ArtifactSigningCertificateKind.PublicTrustTest => "public_trust_test",
        ArtifactSigningCertificateKind.PrivateTrust => "private_trust",
        _ => "private_trust_ci_policy",
    };
}

/// <summary>Durable Artifact Signing identity decoded from a certificate's EKU extension.</summary>
public sealed record ArtifactSigningIdentity
{
    [JsonPropertyName("kind")]
    public ArtifactSigningCertificateKind Kind { get; init; }

    /// <summary>Dotted arcs that follow the profile-type prefix (stable across daily certificate renewals).</summary>
    [JsonPropertyName("publisher_id")]
    public string PublisherId { get; init; } = string.Empty;

    /// <summary>Full identity EKU OID (<c>1.3.6.1.4.1.311.97.…</c>).</summary>
    [JsonPropertyName("identity_eku")]
    public string IdentityEku { get; init; } = string.Empty;

    [JsonPropertyName("has_public_trust_marker")]
    public bool HasPublicTrustMarker { get; init; }

    [JsonPropertyName("has_code_signing_eku")]
    public bool HasCodeSigningEku { get; init; }
}

/// <summary>Signer identity for one PE certificate-table PKCS#7 entry.</summary>
public sealed record ArtifactSigningSignerIdentity
{
    [JsonPropertyName("pkcs7_index")]
    public int Pkcs7Index { get; init; }

    [JsonPropertyName("signer_subject")]
    public string SignerSubject { get; init; } = string.Empty;

    [JsonPropertyName("identity")]
    public ArtifactSigningIdentity? Identity { get; init; }
}

/// <summary>
/// Artifact Signing policy applied by every trust-verify entry point when
/// <see cref="TrustVerifyPeOptions.ArtifactSigning"/> is set. Replaces the generic anchors with the pinned Microsoft roots
/// (Public Trust) or the subscriber roots (Private Trust / Public Trust Test).
/// </summary>
public sealed record ArtifactSigningPolicy
{
    /// <summary>When non-empty, the signer's publisher ID must equal one of these values.</summary>
    public IReadOnlyList<string> ExpectedPublisherIds { get; init; } = [];

    /// <summary>Subscriber roots for Private Trust / Public Trust Test signatures (PEM or DER files).</summary>
    public IReadOnlyList<string> PrivateTrustRootFiles { get; init; } = [];

    /// <summary>Require a timestamp countersignature chained to the pinned Microsoft roots (default <c>true</c>).</summary>
    public bool RequireTimestamp { get; init; } = true;
}

/// <summary>One verified Artifact Signing signature.</summary>
public sealed record ArtifactSigningVerifiedSignature
{
    /// <summary>PE certificate-table entry index; <c>0</c> for single-signature formats.</summary>
    [JsonPropertyName("signature_index")]
    public int SignatureIndex { get; init; }

    [JsonPropertyName("signer_subject")]
    public string SignerSubject { get; init; } = string.Empty;

    [JsonPropertyName("identity")]
    public ArtifactSigningIdentity Identity { get; init; } = new();

    /// <summary>Subject of the trust anchor that terminates the signer chain.</summary>
    [JsonPropertyName("root_subject")]
    public string RootSubject { get; init; } = string.Empty;

    /// <summary>Lowercase hex SHA-1 thumbprint of that trust anchor.</summary>
    [JsonPropertyName("root_sha1")]
    public string RootSha1 { get; init; } = string.Empty;

    /// <summary><c>true</c> when the verification time came from a trusted timestamp countersignature.</summary>
    [JsonPropertyName("timestamped")]
    public bool Timestamped { get; init; }

    /// <summary>RFC 3339 instant used for certificate validity checks.</summary>
    [JsonPropertyName("verification_time")]
    public string VerificationTime { get; init; } = string.Empty;

    /// <summary>Rust <c>Display</c>: <c>signature[i] subject publisher_id=… kind=… root=… time=…[ (timestamp)]</c>.</summary>
    public override string ToString() =>
        $"signature[{SignatureIndex}] {SignerSubject} publisher_id={Identity.PublisherId} kind={Identity.Kind.AsStr()} root={RootSha1} time={VerificationTime}{(Timestamped ? " (timestamp)" : string.Empty)}";
}

/// <summary>
/// Azure Artifact Signing (formerly Trusted Signing) certificate identity and pinned-root trust (Rust
/// <c>artifact_signing.rs</c>; see <c>docs/artifact-signing-validation.md</c>).
/// </summary>
public static class ArtifactSigning
{
    private static readonly ulong[] ArtifactSigningEkuArcs = [1, 3, 6, 1, 4, 1, 311, 97];
    private static readonly ulong[] CodeSigningEkuArcs = [1, 3, 6, 1, 5, 5, 7, 3, 3];

    /// <summary>Prefix of every Artifact Signing EKU, including the trailing dot.</summary>
    public const string ArtifactSigningEkuPrefix = "1.3.6.1.4.1.311.97.";

    /// <summary>EKU present on every Artifact Signing Public Trust certificate.</summary>
    public const string PublicTrustMarkerEku = "1.3.6.1.4.1.311.97.1.0";

    /// <summary>Microsoft Identity Verification Root Certificate Authority 2020.</summary>
    public static readonly PinnedRoot MicrosoftIdentityVerificationRoot2020 = new(
        "Microsoft Identity Verification Root Certificate Authority 2020",
        "f40042e2e5f7e8ef8189fed15519aece42c3bfa2",
        "5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270",
        """
        -----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----
        """);

    /// <summary>Roots accepted for Artifact Signing Public Trust code signing and its timestamps.</summary>
    public static readonly IReadOnlyList<PinnedRoot> PublicTrustRoots = [MicrosoftIdentityVerificationRoot2020];

    /// <summary>Decode the EKU <c>SEQUENCE OF OBJECT IDENTIFIER</c> into arcs (handles arcs wider than 32 bits).</summary>
    internal static List<ulong[]> DecodeEkuArcs(ReadOnlySpan<byte> der)
    {
        var outer = Der.First(der) ?? throw new PsignException("ExtendedKeyUsage header: malformed DER");
        if (outer.Tag != 0x30)
        {
            throw new PsignException("ExtendedKeyUsage extension is not a SEQUENCE");
        }

        if (outer.End != der.Length)
        {
            throw new PsignException("ExtendedKeyUsage trailing data: trailing data");
        }

        var result = new List<ulong[]>();
        int pos = outer.ValueStart;
        while (pos < outer.ValueEnd)
        {
            var entry = Der.TlvAt(der, pos, outer.ValueEnd) ?? throw new PsignException("ExtendedKeyUsage OID header: malformed DER");
            if (entry.Tag != 0x06)
            {
                throw new PsignException("ExtendedKeyUsage entry is not an OBJECT IDENTIFIER");
            }

            result.Add(DecodeOidArcs(entry.Value(der)));
            pos = entry.End;
        }

        return result;
    }

    private static ulong[] DecodeOidArcs(ReadOnlySpan<byte> value)
    {
        var subs = new List<ulong>();
        ulong current = 0;
        bool startsSub = true;
        foreach (var b in value)
        {
            if (startsSub && b == 0x80)
            {
                throw new PsignException("ExtendedKeyUsage contains a non-canonical OID");
            }

            if (current > (ulong.MaxValue >> 7))
            {
                throw new PsignException("ExtendedKeyUsage OID arc exceeds 64 bits");
            }

            current = (current << 7) | (uint)(b & 0x7f);
            startsSub = (b & 0x80) == 0;
            if (startsSub)
            {
                subs.Add(current);
                current = 0;
            }
        }

        if (!startsSub || subs.Count == 0)
        {
            throw new PsignException("ExtendedKeyUsage contains a truncated OID");
        }

        ulong first = subs[0];
        (ulong a, ulong b2) = first switch
        {
            <= 39 => (0UL, first),
            <= 79 => (1UL, first - 40),
            _ => (2UL, first - 80),
        };
        var arcs = new List<ulong> { a, b2 };
        arcs.AddRange(subs.Skip(1));
        return arcs.ToArray();
    }

    private static string Dotted(IEnumerable<ulong> arcs) => string.Join('.', arcs.Select(a => a.ToString(CultureInfo.InvariantCulture)));

    /// <summary>Classify the arcs after <c>1.3.6.1.4.1.311.97</c>; <c>null</c> for the marker and unknown sub-types.</summary>
    internal static (ArtifactSigningCertificateKind Kind, ulong[] Id)? ClassifyIdentitySuffix(ulong[] rest)
    {
        ArtifactSigningCertificateKind kind;
        ulong[] id;
        if (rest is [1, 2, .. var a])
        {
            (kind, id) = (ArtifactSigningCertificateKind.PublicTrustTest, a);
        }
        else if (rest is [1, 3, 1, .. var b])
        {
            (kind, id) = (ArtifactSigningCertificateKind.PrivateTrust, b);
        }
        else if (rest is [1, 4, 1, .. var c])
        {
            (kind, id) = (ArtifactSigningCertificateKind.PrivateTrustCiPolicy, c);
        }
        else if (rest is [1, ..])
        {
            return null;
        }
        else
        {
            (kind, id) = (ArtifactSigningCertificateKind.PublicTrust, rest);
        }

        return id.Length > 0 ? (kind, id) : null;
    }

    /// <summary>
    /// Extract the Artifact Signing identity from a certificate. Returns <c>null</c> when the certificate has no identity
    /// EKU; throws when it carries more than one distinct identity EKU.
    /// </summary>
    public static ArtifactSigningIdentity? IdentityFromCertificate(CertificateInfo cert)
    {
        ArtifactSigningIdentity? identity = null;
        bool marker = false;
        bool codeSigning = false;
        foreach (var ext in cert.Extensions.Where(e => e.Oid == Oids.ExtendedKeyUsage))
        {
            foreach (var arcs in DecodeEkuArcs(ext.Value))
            {
                if (arcs.AsSpan().SequenceEqual(CodeSigningEkuArcs))
                {
                    codeSigning = true;
                    continue;
                }

                if (arcs.Length < ArtifactSigningEkuArcs.Length || !arcs.AsSpan(0, ArtifactSigningEkuArcs.Length).SequenceEqual(ArtifactSigningEkuArcs))
                {
                    continue;
                }

                var rest = arcs[ArtifactSigningEkuArcs.Length..];
                if (rest is [1, 0])
                {
                    marker = true;
                    continue;
                }

                if (ClassifyIdentitySuffix(rest) is not { } classified)
                {
                    continue;
                }

                var found = new ArtifactSigningIdentity
                {
                    Kind = classified.Kind,
                    PublisherId = Dotted(classified.Id),
                    IdentityEku = Dotted(arcs),
                };
                if (identity is null)
                {
                    identity = found;
                }
                else if (identity.IdentityEku != found.IdentityEku)
                {
                    throw new PsignException(
                        $"certificate carries multiple Artifact Signing identity EKUs ({identity.IdentityEku} and {found.IdentityEku})");
                }
            }
        }

        return identity is null ? null : identity with { HasPublicTrustMarker = marker, HasCodeSigningEku = codeSigning };
    }

    /// <summary><see cref="IdentityFromCertificate"/> for a DER or PEM encoded certificate.</summary>
    public static ArtifactSigningIdentity? IdentityFromCertBytes(ReadOnlySpan<byte> raw) => IdentityFromCertificate(Anchors.ParseCertBytes(raw));

    private static (CertificateInfo Cert, ArtifactSigningIdentity? Identity) Pkcs7SignerIdentity(ReadOnlySpan<byte> pkcs7Der)
    {
        var sd = CmsTrustHelpers.ParsePkcs7SignedDataDer(pkcs7Der);
        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("SignedData has no SignerInfo");
        }

        var cert = CmsTrustHelpers.CertificateForSigner(sd, sd.SignerInfos[0]);
        return (cert, IdentityFromCertificate(cert));
    }

    /// <summary>Artifact Signing identity of the primary signer in a PKCS#7 / CMS <c>SignedData</c> blob.</summary>
    public static ArtifactSigningIdentity? IdentityFromPkcs7Der(ReadOnlySpan<byte> pkcs7Der) => Pkcs7SignerIdentity(pkcs7Der).Identity;

    /// <summary>Artifact Signing identities of every embedded PE Authenticode signature (no trust checks).</summary>
    public static List<ArtifactSigningSignerIdentity> IdentitiesFromPe(byte[] peBytes)
    {
        var output = new List<ArtifactSigningSignerIdentity>();
        PeAuthenticode.ForEachPkcs7(peBytes, (index, der) =>
        {
            (CertificateInfo Cert, ArtifactSigningIdentity? Identity) r;
            try
            {
                r = Pkcs7SignerIdentity(der);
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"PKCS#7 index {index}", e);
            }

            output.Add(new ArtifactSigningSignerIdentity
            {
                Pkcs7Index = index,
                SignerSubject = PickyCert.SubjectDisplay(r.Cert),
                Identity = r.Identity,
            });
        });
        return output;
    }

    /// <summary>Pinned Microsoft roots used for Public Trust signer chains and timestamp countersignatures.</summary>
    public static List<CertificateInfo> PublicTrustAnchorCerts() => PublicTrustRoots.Select(r => r.Certificate()).ToList();

    /// <summary>Anchor store holding only the pinned Public Trust roots.</summary>
    public static (AnchorStore Store, List<CertificateInfo> Certs) PublicTrustAnchors() => AnchorsFromCerts(PublicTrustAnchorCerts());

    private static (AnchorStore, List<CertificateInfo>) AnchorsFromCerts(List<CertificateInfo> certs)
    {
        var store = AnchorStore.Empty();
        store.MergeCertThumbprints(certs);
        return (store, certs);
    }

    private static (string Subject, ArtifactSigningIdentity Identity) CheckedIdentity(CertificateInfo signer, ArtifactSigningPolicy policy)
    {
        var subject = PickyCert.SubjectDisplay(signer);
        var identity = IdentityFromCertificate(signer)
            ?? throw new PsignException($"signer {PickyFormat.StrDebug(subject)} has no Artifact Signing identity EKU ({ArtifactSigningEkuPrefix}…)");
        if (identity.Kind == ArtifactSigningCertificateKind.PublicTrust && !identity.HasPublicTrustMarker)
        {
            throw new PsignException($"Public Trust signer lacks the {PublicTrustMarkerEku} marker EKU");
        }

        if (identity.Kind == ArtifactSigningCertificateKind.PrivateTrustCiPolicy)
        {
            throw new PsignException("Private Trust CI Policy certificates sign WDAC policies, not Authenticode code");
        }

        if (!identity.HasCodeSigningEku)
        {
            throw new PsignException("signer lacks the code signing EKU");
        }

        if (policy.ExpectedPublisherIds.Count > 0 && !policy.ExpectedPublisherIds.Any(id => id.Trim() == identity.PublisherId))
        {
            throw new PsignException(
                $"Artifact Signing publisher ID {identity.PublisherId} is not one of the expected IDs ({string.Join(", ", policy.ExpectedPublisherIds)})");
        }

        return (subject, identity);
    }

    private static (bool Timestamped, DateTimeOffset Instant) ArtifactSigningInstant(
        ArtifactSigningPolicy policy,
        TrustVerifyPeOptions opts,
        Func<AnchorStore, IReadOnlyList<CertificateInfo>, DateTimeOffset?> trustedTimestamp)
    {
        if (opts.VerificationInstantOverride is { } o)
        {
            return (false, o);
        }

        var (msAnchors, msCerts) = PublicTrustAnchors();
        DateTimeOffset? ts;
        try
        {
            ts = trustedTimestamp(msAnchors, msCerts);
        }
        catch (PsignException e)
        {
            throw PsignException.Context("Artifact Signing timestamp countersignature", e);
        }

        if (ts is { } instant)
        {
            return (true, instant);
        }

        if (policy.RequireTimestamp)
        {
            throw new PsignException("Artifact Signing signature has no RFC 3161 timestamp countersignature");
        }

        return (false, PickyFormat.Now());
    }

    private static (AnchorStore, List<CertificateInfo>) ArtifactSigningAnchors(ArtifactSigningCertificateKind kind, ArtifactSigningPolicy policy)
    {
        if (kind == ArtifactSigningCertificateKind.PublicTrust)
        {
            return PublicTrustAnchors();
        }

        if (policy.PrivateTrustRootFiles.Count == 0)
        {
            throw new PsignException($"{kind.AsStr()} signature requires the subscriber root certificate (private trust root)");
        }

        var (_, certs) = AnchorStore.LoadFiles(policy.PrivateTrustRootFiles);
        var usable = certs
            .Where(c => !PublicTrustRoots.Any(r => r.Sha1.AsSpan().SequenceEqual(Anchors.CertSha1Thumbprint(c))))
            .ToList();
        if (usable.Count == 0)
        {
            throw new PsignException(
                $"no usable private trust roots (Microsoft Public Trust roots are not accepted for {kind.AsStr()})");
        }

        return AnchorsFromCerts(usable);
    }

    private static ArtifactSigningVerifiedSignature VerifiedSignature(
        int index, string subject, ArtifactSigningIdentity identity, CertificateInfo root, bool timestamped, DateTimeOffset instant) => new()
    {
        SignatureIndex = index,
        SignerSubject = subject,
        Identity = identity,
        RootSubject = PickyCert.SubjectDisplay(root),
        RootSha1 = Anchors.CertSha1ThumbprintHex(root),
        Timestamped = timestamped,
        VerificationTime = UtcDateRfc3339(instant),
    };

    /// <summary>
    /// Verify one PKCS#7 as an Artifact Signing signature whose digest binding equals <paramref name="subjectDigest"/>:
    /// identity EKU (+ Public Trust marker), publisher pin, timestamp chained to a pinned Microsoft root, and the signer
    /// chain terminating at a pinned root (Public Trust) or a supplied subscriber root, valid at the timestamp.
    /// </summary>
    public static ArtifactSigningVerifiedSignature VerifyArtifactSigningPkcs7(
        byte[] pkcs7Der,
        int pkcs7Index,
        byte[] subjectDigest,
        Pkcs7DigestBinding binding,
        ArtifactSigningPolicy policy,
        TrustVerifyPeOptions opts)
    {
        var (signer, _) = Pkcs7SignerIdentity(pkcs7Der);
        var (subject, identity) = CheckedIdentity(signer, policy);
        var (timestamped, instant) = ArtifactSigningInstant(policy, opts, (anchors, certs) =>
            Rfc3161Extract.TrustedUtcDateFromAuthenticodeTimestampToken(pkcs7Der, anchors, certs, opts.Online, opts.VerboseChain, opts.Log));
        var (asAnchors, asCerts) = ArtifactSigningAnchors(identity.Kind, policy);
        var trustPolicy = new AuthenticodeTrustPolicy
        {
            StrictCodeSigningEku = true,
            PreferTimestampSigningTime = false,
            RequireValidTimestamp = false,
        };
        TrustPkcs7.VerifyPkcs7TrustWithBinding(binding, pkcs7Der, pkcs7Index, subjectDigest, asAnchors, asCerts, trustPolicy, opts.Online, instant, opts.VerboseChain, opts.Log);
        var root = SignerTerminalRoot(pkcs7Der, asAnchors, asCerts);
        return VerifiedSignature(pkcs7Index, subject, identity, root, timestamped, instant);
    }

    /// <summary>
    /// Artifact Signing policy for non-CMS signatures (VSIX XMLDSig): the caller already verified the signature value with
    /// <paramref name="signer"/>'s key; this checks the identity, the timestamp token (token DER and the bytes it covers),
    /// and the signer chain to the anchors.
    /// </summary>
    public static ArtifactSigningVerifiedSignature VerifyArtifactSigningCertificate(
        CertificateInfo signer,
        IEnumerable<CertificateInfo> extraCerts,
        (byte[] Token, byte[] Covered)? timestamp,
        int signatureIndex,
        ArtifactSigningPolicy policy,
        TrustVerifyPeOptions opts)
    {
        var (subject, identity) = CheckedIdentity(signer, policy);
        var (timestamped, instant) = ArtifactSigningInstant(policy, opts, (anchors, certs) =>
            timestamp is { } t
                ? Rfc3161Extract.TrustedUtcDateFromTimestampToken(t.Token, t.Covered, anchors, certs, opts.Online, opts.VerboseChain, opts.Log)
                : null);
        var (asAnchors, asCerts) = ArtifactSigningAnchors(identity.Kind, policy);
        var root = TrustChain.VerifyCertificateChainToAnchors(signer, extraCerts, asAnchors, asCerts, opts.Online, instant, opts.VerboseChain, opts.Log);
        return VerifiedSignature(signatureIndex, subject, identity, root, timestamped, instant);
    }

    private static CertificateInfo SignerTerminalRoot(byte[] pkcs7Der, AnchorStore anchors, IReadOnlyList<CertificateInfo> anchorCerts)
    {
        var sd = CmsTrustHelpers.ParsePkcs7SignedDataDer(Pkcs7Wire.NormalizeForAuthenticode(pkcs7Der));
        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("SignedData has no SignerInfo");
        }

        var leaf = CmsTrustHelpers.CertificateForSigner(sd, sd.SignerInfos[0]);
        var pool = TrustChain.MergeUniqueCerts(anchorCerts, sd.GetCertificates());
        var chain = TrustChain.IssuerChainExcludingLeaf(leaf, pool, anchors);
        return TrustChain.TerminalRootCert(leaf, chain);
    }

    private static string UtcDateRfc3339(DateTimeOffset d) =>
        PickyFormat.Truncate(d).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
