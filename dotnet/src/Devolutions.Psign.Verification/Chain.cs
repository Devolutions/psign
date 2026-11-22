using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>Issuer walk over PKCS#7-embedded + anchor pools (Rust <c>chain.rs</c>).</summary>
public static class TrustChain
{
    private static bool SubjectEquals(CertificateInfo c, byte[] name) => c.Subject.AsSpan().SequenceEqual(name);

    private static PsignException Unresolved(byte[] issuerDn) =>
        new($"could not resolve issuer certificate for subject {PickyFormat.NameDebug(issuerDn)}");

    /// <summary>
    /// Follow <c>leaf.issuer</c> through <paramref name="pool"/> until a self-signed certificate is reached. Returns the
    /// certificates from the leaf's immediate issuer toward the terminal root. When <paramref name="anchors"/> is given and
    /// a chain certificate's SHA-1 thumbprint is trusted, the walk stops there ("trust at boundary").
    /// </summary>
    public static List<CertificateInfo> IssuerChainExcludingLeaf(CertificateInfo leaf, IReadOnlyList<CertificateInfo> pool, AnchorStore? anchors)
    {
        var output = new List<CertificateInfo>();
        if (PickyCert.IsSelfIssued(leaf))
        {
            return output;
        }

        byte[] issuerDn = leaf.Issuer;
        int steps = 0;
        while (true)
        {
            var parent = pool.FirstOrDefault(c => SubjectEquals(c, issuerDn));
            if (parent is null)
            {
                if (anchors is not null && output.Count > 0 && anchors.Contains(output[^1]))
                {
                    break;
                }

                throw Unresolved(issuerDn);
            }

            output.Add(parent);
            steps++;
            if (steps > 32)
            {
                throw new PsignException("certificate chain too long (possible loop)");
            }

            if (PickyCert.IsSelfIssued(parent))
            {
                break;
            }

            if (anchors is not null && anchors.Contains(parent))
            {
                break;
            }

            issuerDn = parent.Issuer;
        }

        return output;
    }

    /// <summary>
    /// Like <see cref="IssuerChainExcludingLeaf"/>, fetching missing issuers through AIA when <paramref name="online"/>
    /// enables it. Fetched certificates are appended to <paramref name="pool"/>.
    /// </summary>
    public static List<CertificateInfo> IssuerChainExcludingLeafOnline(CertificateInfo leaf, List<CertificateInfo> pool, OnlineTrustOptions online, AnchorStore? anchors)
    {
        var output = new List<CertificateInfo>();
        if (PickyCert.IsSelfIssued(leaf))
        {
            return output;
        }

        var current = leaf;
        int steps = 0;
        while (true)
        {
            byte[] issuerDn = current.Issuer;
            var parent = pool.FirstOrDefault(c => SubjectEquals(c, issuerDn));
            if (parent is not null)
            {
                steps++;
                if (steps > 32)
                {
                    throw new PsignException("certificate chain too long (possible loop)");
                }

                bool done = PickyCert.IsSelfIssued(parent);
                output.Add(parent);
                if (anchors is not null && anchors.Contains(parent))
                {
                    break;
                }

                if (done)
                {
                    break;
                }

                current = parent;
                continue;
            }

            var fetched = OnlineTrust.IssuerCandidatesFromAia(current, online);
            if (fetched.Count == 0)
            {
                if (anchors is not null && output.Count > 0 && anchors.Contains(output[^1]))
                {
                    break;
                }

                throw Unresolved(issuerDn);
            }

            pool.AddRange(fetched);
        }

        return output;
    }

    /// <summary>
    /// Build <paramref name="leaf"/>'s chain from <paramref name="pool"/> plus the anchor certificates (AIA when enabled),
    /// require it to end in <paramref name="anchors"/>, apply the revocation policy, and verify every certificate signature
    /// and validity period at <paramref name="instant"/>. Returns the terminal root.
    /// </summary>
    public static CertificateInfo VerifyCertificateChainToAnchors(
        CertificateInfo leaf,
        IEnumerable<CertificateInfo> pool,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        OnlineTrustOptions online,
        DateTimeOffset instant,
        bool verboseChain,
        TextWriter? log = null)
    {
        var merged = MergeUniqueCerts(anchorCerts, pool);
        var chain = IssuerChainExcludingLeafOnline(leaf, merged, online, anchors);
        var root = TerminalRootCert(leaf, chain);
        var rootThumb = Anchors.CertSha1Thumbprint(root);
        if (verboseChain)
        {
            log ??= Console.Error;
            log.WriteLine($"trust-verify: leaf subject: {PickyCert.SubjectDisplay(leaf)}");
            for (int i = 0; i < chain.Count; i++)
            {
                log.WriteLine($"trust-verify:   chain[{i}] subject: {PickyCert.SubjectDisplay(chain[i])}");
            }
        }

        if (!anchors.ContainsThumbprint(rootThumb))
        {
            throw new PsignException(
                $"terminal root certificate is not in the anchor store (SHA-1 thumbprint {rootThumb[0]:x2}{rootThumb[1]:x2}…)");
        }

        OnlineTrust.CheckRevocationChain(leaf, chain, online);
        if (PickyCert.IsSelfIssued(leaf) && chain.Count == 0)
        {
            return root;
        }

        try
        {
            PickyCert.VerifyExact(leaf, chain, instant);
        }
        catch (PickyException e)
        {
            throw new PsignException($"certificate chain verification: {e.Message}");
        }

        return root;
    }

    /// <summary>The leaf when self-issued, otherwise the last chain certificate.</summary>
    public static CertificateInfo TerminalRootCert(CertificateInfo leaf, IReadOnlyList<CertificateInfo> chain)
    {
        if (PickyCert.IsSelfIssued(leaf))
        {
            return leaf;
        }

        if (chain.Count == 0)
        {
            throw new InvalidOperationException("non-empty issuer chain");
        }

        return chain[^1];
    }

    /// <summary>Merge certificate bags and drop duplicates by SHA-1 thumbprint.</summary>
    public static List<CertificateInfo> MergeUniqueCerts(IEnumerable<CertificateInfo> primary, IEnumerable<CertificateInfo> extra)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var output = new List<CertificateInfo>();
        foreach (var c in primary.Concat(extra))
        {
            if (seen.Add(Anchors.CertSha1ThumbprintHex(c)))
            {
                output.Add(c);
            }
        }

        return output;
    }
}
