using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.AuthRoot;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>Options shared by every trust-verify entry point (Rust <c>trust_verify_pe::TrustVerifyPeOptions</c>).</summary>
public sealed record TrustVerifyPeOptions
{
    /// <summary>Directory of <c>.crt</c>/<c>.cer</c>/<c>.pem</c> anchors.</summary>
    public string? AnchorDir { get; init; }

    /// <summary>Explicit trusted CA files (<c>--trusted-ca</c> + <c>--additional-trusted-ca</c>).</summary>
    public IReadOnlyList<string> TrustedCaFiles { get; init; } = [];

    /// <summary>DER-encoded certificates explicitly trusted as anchors.</summary>
    public IReadOnlyList<byte[]> TrustedCaDer { get; init; } = [];

    /// <summary>Microsoft AuthRoot CAB (certificates + CTL thumbprints).</summary>
    public string? AuthrootCab { get; init; }

    /// <summary>When set, require the AuthRoot CAB file to match this SHA-256 (bootstrap integrity).</summary>
    public byte[]? ExpectAuthrootCabSha256 { get; init; }

    /// <summary>When set, use this instant instead of wall clock / timestamp policy.</summary>
    public DateTimeOffset? VerificationInstantOverride { get; init; }

    /// <summary>Print the chain to <see cref="Log"/> (stderr by default).</summary>
    public bool VerboseChain { get; init; }

    public OnlineTrustOptions Online { get; init; } = new();

    public AuthenticodeTrustPolicy Policy { get; init; } = new();

    /// <summary>Validate as Azure Artifact Signing: pinned Microsoft roots replace the anchors above.</summary>
    public ArtifactSigningPolicy? ArtifactSigning { get; init; }

    /// <summary>Destination for verbose chain output (C# addition; defaults to <see cref="Console.Error"/>).</summary>
    public TextWriter? Log { get; init; }
}

/// <summary>Cryptographically verified signer and chain metadata for one signature (Rust <c>VerifiedSignature</c>).</summary>
public sealed record VerifiedSignature
{
    /// <summary>PE certificate-table entry index; <c>0</c> for single-signature formats.</summary>
    [JsonPropertyName("signature_index")]
    public int SignatureIndex { get; init; }

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

    /// <summary>Subject distinguished name of the terminal trust anchor, if known.</summary>
    [JsonPropertyName("root_subject")]
    public string? RootSubject { get; init; }

    /// <summary>Lowercase hex SHA-1 thumbprint of the terminal trust anchor, if known.</summary>
    [JsonPropertyName("root_sha1_hex")]
    public string? RootSha1Hex { get; init; }

    /// <summary>Lowercase hex SHA-256 thumbprint of the terminal trust anchor, if known.</summary>
    [JsonPropertyName("root_sha256_hex")]
    public string? RootSha256Hex { get; init; }

    /// <summary><c>true</c> when the verification instant came from a cryptographically verified RFC 3161 timestamp.</summary>
    [JsonPropertyName("timestamped")]
    public bool Timestamped { get; init; }

    /// <summary>Decoded Azure Artifact Signing identity when the signer carries an identity EKU.</summary>
    [JsonPropertyName("artifact_signing")]
    public ArtifactSigningIdentity? ArtifactSigning { get; init; }
}

/// <summary>Result of a trust verification (Rust <c>TrustVerifyPeReport</c>).</summary>
public sealed class TrustVerifyPeReport
{
    internal TrustVerifyPeReport(AnchorStore anchors)
    {
        AnchorThumbprints = anchors.ThumbprintCount;
    }

    public int Pkcs7EntriesVerified { get; internal set; }

    public int AnchorThumbprints { get; }

    /// <summary>One entry per verified PKCS#7 when <see cref="TrustVerifyPeOptions.ArtifactSigning"/> is set.</summary>
    public List<ArtifactSigningVerifiedSignature> ArtifactSigning { get; } = [];

    /// <summary>One entry per verified signature across both generic trust and Artifact Signing.</summary>
    public List<VerifiedSignature> VerifiedSignatures { get; } = [];

    /// <summary>
    /// The stdout lines the Rust CLI prints on success (<c>print_trust_ok</c>), e.g.
    /// <c>trust-verify-pe: ok — verified 1 PKCS#7 entr(y/ies); 1 anchor thumbprint(s)</c>.
    /// </summary>
    public IReadOnlyList<string> FormatOkLines(string prefix)
    {
        if (ArtifactSigning.Count > 0)
        {
            return ArtifactSigning.Select(sig => $"{prefix}: ok — Artifact Signing {sig}").ToList();
        }

        return [$"{prefix}: ok — verified {Pkcs7EntriesVerified} PKCS#7 entr(y/ies); {AnchorThumbprints} anchor thumbprint(s)"];
    }

    /// <summary>
    /// The report text <c>psign-tool verify --artifact-signing</c> appends per target (Rust
    /// <c>artifact_signing_verify::append_report</c>): <c>Artifact Signing verified: {path}</c> then one indented line per signature.
    /// </summary>
    public string FormatArtifactSigningVerified(string displayPath)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("Artifact Signing verified: ").Append(displayPath).Append('\n');
        foreach (var sig in ArtifactSigning)
        {
            sb.Append("  ").Append(sig).Append('\n');
        }

        return sb.ToString();
    }
}

/// <summary>Portable PE Authenticode trust verification with explicit anchors (Rust <c>trust_verify_pe.rs</c>).</summary>
public static class TrustVerifyPe
{
    /// <summary>
    /// Anchors for <paramref name="opts"/>: <see cref="LoadTrustMaterial"/>, or the pinned Microsoft roots when
    /// <see cref="TrustVerifyPeOptions.ArtifactSigning"/> is set.
    /// </summary>
    public static (AnchorStore Store, List<CertificateInfo> Certs) TrustMaterialFor(TrustVerifyPeOptions opts) =>
        opts.ArtifactSigning is not null ? Verification.ArtifactSigning.PublicTrustAnchors() : LoadTrustMaterial(opts);

    internal static VerifiedSignature VerifiedSignatureFromCerts(int signatureIndex, CertificateInfo leaf, CertificateInfo root, bool timestamped)
    {
        ArtifactSigningIdentity? artifactSigning = null;
        try
        {
            artifactSigning = Verification.ArtifactSigning.IdentityFromCertificate(leaf);
        }
        catch (PsignException)
        {
        }

        return new VerifiedSignature
        {
            SignatureIndex = signatureIndex,
            SignerCertificateDer = leaf.RawData.ToArray(),
            SignerSha256Hex = Anchors.CertSha256ThumbprintHex(leaf),
            SignerSha1Hex = Anchors.CertSha1ThumbprintHex(leaf),
            SignerSubject = PickyCert.SubjectDisplay(leaf),
            RootSubject = PickyCert.SubjectDisplay(root),
            RootSha1Hex = Anchors.CertSha1ThumbprintHex(root),
            RootSha256Hex = Anchors.CertSha256ThumbprintHex(root),
            Timestamped = timestamped,
            ArtifactSigning = artifactSigning,
        };
    }

    /// <summary>
    /// Trust-verify one PKCS#7 whose <paramref name="digest"/> already matched the recomputed subject digest, applying
    /// either the generic anchor policy or <see cref="TrustVerifyPeOptions.ArtifactSigning"/>. Format verifiers (CAB, MSI,
    /// catalog, script, ZIP, MSIX, NuGet, …) call this after their own digest check.
    /// </summary>
    public static void VerifyPkcs7Entry(
        byte[] pkcs7Der,
        int pkcs7Index,
        byte[] digest,
        Pkcs7DigestBinding binding,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        TrustVerifyPeOptions opts,
        TrustVerifyPeReport report)
    {
        if (opts.ArtifactSigning is { } policy)
        {
            var (asSig, summary) = Verification.ArtifactSigning.VerifyArtifactSigningPkcs7WithDetails(pkcs7Der, pkcs7Index, digest, binding, policy, opts);
            report.ArtifactSigning.Add(asSig);
            report.VerifiedSignatures.Add(summary);
        }
        else
        {
            var (instant, timestamped) = VerificationInstant.ResolveVerificationInstantForPkcs7WithTrustInfo(
                pkcs7Der, opts.Policy, opts.VerificationInstantOverride, anchors, anchorCerts, opts.Online, opts.VerboseChain, opts.Log);
            var chain = TrustPkcs7.VerifyPkcs7TrustWithBindingChain(binding, pkcs7Der, pkcs7Index, digest, anchors, anchorCerts, opts.Policy, opts.Online, instant, opts.VerboseChain, opts.Log);
            report.VerifiedSignatures.Add(VerifiedSignatureFromCerts(pkcs7Index, chain.Leaf, chain.Root, timestamped));
        }

        report.Pkcs7EntriesVerified++;
    }

    /// <summary>New empty report for <paramref name="anchors"/> (for format verifiers implemented elsewhere).</summary>
    public static TrustVerifyPeReport NewReport(AnchorStore anchors) => new(anchors);

    /// <summary>Load anchors from the anchor directory, trusted CA files and AuthRoot CAB (applying the CAB pin).</summary>
    public static (AnchorStore Store, List<CertificateInfo> Certs) LoadTrustMaterial(TrustVerifyPeOptions opts)
    {
        AnchorStore store;
        List<CertificateInfo> certs;
        if (opts.AnchorDir is { } dir)
        {
            try
            {
                (store, certs) = AnchorStore.LoadDir(dir);
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"anchor-dir {dir}", e);
            }
        }
        else
        {
            store = AnchorStore.Empty();
            certs = [];
        }

        if (opts.TrustedCaFiles.Count > 0)
        {
            var (_, fileCerts) = AnchorStore.LoadFiles(opts.TrustedCaFiles);
            store.MergeThumbprintsOnly(fileCerts.Select(Anchors.CertSha1Thumbprint));
            certs.AddRange(fileCerts);
        }

        if (opts.TrustedCaDer.Count > 0)
        {
            foreach (var der in opts.TrustedCaDer)
            {
                CertificateInfo parsed;
                try
                {
                    parsed = CertificateInfo.Parse(der);
                }
                catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException or CryptographicException)
                {
                    throw new PsignException($"parse trusted CA DER: {e.Message}");
                }

                store.MergeThumbprintsOnly([SHA1.HashData(der)]);
                certs.Add(parsed);
            }
        }

        if (opts.AuthrootCab is { } cab)
        {
            byte[] cabBytes;
            try
            {
                cabBytes = File.ReadAllBytes(cab);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw PsignException.Context($"read {cab}", e);
            }

            if (opts.ExpectAuthrootCabSha256 is { } expected)
            {
                var digest = SHA256.HashData(cabBytes);
                if (!digest.AsSpan().SequenceEqual(expected))
                {
                    throw new PsignException(
                        $"authroot CAB SHA-256 mismatch (pin differs from file {cab} — {Hex.Lower(digest)} vs {Hex.Lower(expected)})");
                }
            }

            List<CertificateInfo> cabCerts;
            List<byte[]> ctlThumbs;
            try
            {
                (cabCerts, ctlThumbs) = AuthRootCab.IngestAuthRootCabBytes(cabBytes);
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"authroot-cab {cab}", e);
            }

            store.MergeCertThumbprints(cabCerts);
            store.MergeThumbprintsOnly(ctlThumbs);
            certs.AddRange(cabCerts);
        }

        if (store.ThumbprintCount == 0)
        {
            throw new PsignException(
                "no trust anchors configured (use --anchor-dir, --trusted-ca, --additional-trusted-ca, and/or --authroot-cab)");
        }

        return (store, certs);
    }

    /// <summary>Verify every embedded PE Authenticode PKCS#7 (digest recomputation + trust).</summary>
    public static TrustVerifyPeReport TrustVerifyPeBytes(byte[] peBytes, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustMaterialFor(opts);
        var report = new TrustVerifyPeReport(anchors);
        PeAuthenticode.ForEachPkcs7(peBytes, (idx, pkcs7) => VerifyOnePkcs7(peBytes, idx, pkcs7, anchors, anchorCerts, opts, report));
        return report;
    }

    private static void VerifyOnePkcs7(byte[] peBytes, int index, byte[] pkcs7Der, AnchorStore anchors, List<CertificateInfo> anchorCerts, TrustVerifyPeOptions opts, TrustVerifyPeReport report)
    {
        var normalized = Pkcs7Wire.NormalizeForAuthenticode(pkcs7Der);
        AuthenticodeSignature sig;
        try
        {
            sig = AuthenticodeSignature.Parse(normalized);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            throw new PsignException($"authenticode-rs PKCS#7 parse (digest probe): {e.Message}");
        }

        var embedded = sig.Digest;
        var kind = sig.IndirectData.HashKind
            ?? throw new PsignException($"unsupported Authenticode digest algorithm OID {sig.IndirectData.DigestAlgorithm.Oid}");
        if (embedded.Length != kind.DigestLength())
        {
            throw new PsignException(
                $"Authenticode digest length {embedded.Length} does not match algorithm {kind.Name()} ({kind.DigestLength()} bytes)");
        }

        var peDigest = PeAuthenticode.Digest(peBytes, kind);
        if (!peDigest.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException($"PE digest mismatch before trust checks for PKCS#7 index {index}");
        }

        VerifyPkcs7Entry(pkcs7Der, index, peDigest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
    }

    /// <summary>Terminal root of a PKCS#7 using only its embedded certificates (Rust <c>pkcs7_signed_data_der_terminal_root</c>).</summary>
    public static CertificateInfo Pkcs7SignedDataDerTerminalRoot(ReadOnlySpan<byte> pkcs7Der)
    {
        var picky = PickyAuthenticode.TryParse(pkcs7Der) ?? throw new PsignException("picky PKCS#7: (ASN1) couldn't deserialize pkcs7 certificate");
        var merged = TrustChain.MergeUniqueCerts(picky.DecodeCertificates(), []);
        CertificateInfo leaf;
        try
        {
            leaf = picky.SigningCertificate(merged);
        }
        catch (PickyException e)
        {
            throw new PsignException($"resolve signing certificate: {e.Message}");
        }

        var chain = TrustChain.IssuerChainExcludingLeaf(leaf, merged, null);
        return TrustChain.TerminalRootCert(leaf, chain);
    }

    /// <summary>Terminal root of the first embedded PE PKCS#7 (useful to build a temporary anchor directory).</summary>
    public static CertificateInfo PeFirstPkcs7TerminalRoot(byte[] peBytes)
    {
        byte[]? first = null;
        PeAuthenticode.ForEachPkcs7(peBytes, (_, der) => first ??= der);
        return Pkcs7SignedDataDerTerminalRoot(first ?? throw new PsignException("no PKCS#7 in PE"));
    }
}
