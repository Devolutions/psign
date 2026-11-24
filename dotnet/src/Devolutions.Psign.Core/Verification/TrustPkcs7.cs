using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>How a PKCS#7 binds to the signed subject (Rust <c>trust_pkcs7::Pkcs7DigestBinding</c>).</summary>
public enum Pkcs7DigestBinding
{
    /// <summary>Authenticode <c>SpcIndirectDataContent</c> digest (PE, CAB, MSI, WIM/ESD, scripts, ZIP).</summary>
    AuthenticodeIndirect,

    /// <summary>PKCS#9 <c>messageDigest</c> over external content (catalogs, detached CMS).</summary>
    Pkcs9MessageDigest,
}

/// <summary>Shared PKCS#7 Authenticode trust step, digest already known (Rust <c>trust_pkcs7.rs</c>).</summary>
public static class TrustPkcs7
{
    private static void VerifyTrustChainVerbose(
        int pkcs7Index,
        CertificateInfo leaf,
        List<CertificateInfo> chain,
        CertificateInfo root,
        byte[] rootThumb,
        DateTimeOffset verificationInstant,
        bool verboseChain,
        TextWriter? log)
    {
        if (verboseChain)
        {
            log ??= Console.Error;
            log.WriteLine($"trust-verify: PKCS#7[{pkcs7Index}] leaf subject: {PickyCert.SubjectDisplay(leaf)}");
            for (int i = 0; i < chain.Count; i++)
            {
                log.WriteLine($"trust-verify:   chain[{i}] subject: {PickyCert.SubjectDisplay(chain[i])} issuer: {PickyCert.IssuerDisplay(chain[i])}");
            }

            log.WriteLine($"trust-verify:   root subject: {PickyCert.SubjectDisplay(root)} (thumb SHA-1 {Hex.Lower(rootThumb)})");
        }

        if (PickyCert.IsSelfIssued(leaf) && Anchors.CertSha1Thumbprint(leaf).AsSpan().SequenceEqual(rootThumb))
        {
            return;
        }

        try
        {
            PickyCert.VerifyExact(leaf, chain, verificationInstant);
        }
        catch (PickyException e)
        {
            throw new PsignException($"certificate chain verification (PKCS#7 {pkcs7Index}): {e.Message}");
        }
    }

    private static void RequireAnchoredRoot(CertificateInfo root, AnchorStore anchors, out byte[] rootThumb)
    {
        rootThumb = Anchors.CertSha1Thumbprint(root);
        if (!anchors.ContainsThumbprint(rootThumb))
        {
            throw new PsignException(
                $"terminal root certificate is not in the anchor store (SHA-1 thumbprint {rootThumb[0]:x2}{rootThumb[1]:x2}…)");
        }
    }

    private static void VerifyCmsRsaSha256Fallback(
        byte[] slice,
        int pkcs7Index,
        Pkcs7DigestBinding binding,
        ReadOnlySpan<byte> digest,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        AuthenticodeTrustPolicy policy,
        OnlineTrustOptions online,
        DateTimeOffset verificationInstant,
        bool verboseChain,
        TextWriter? log)
    {
        CmsSignedData sd;
        try
        {
            sd = CmsTrustHelpers.ParsePkcs7SignedDataDer(slice);
        }
        catch (PsignException e)
        {
            throw new PsignException($"CMS SignedData decode (non-PE SpcIndirectData PKCS#7): {e.Message}");
        }

        if (binding == Pkcs7DigestBinding.AuthenticodeIndirect)
        {
            try
            {
                CmsTrustHelpers.VerifyAuthenticodeIndirectDigestAndRsaSha256(sd, 0, digest);
            }
            catch (PsignException e)
            {
                throw new PsignException($"CMS RSA/SHA-256 Authenticode fallback (PKCS#7 {pkcs7Index}): {e.Message}");
            }
        }
        else
        {
            try
            {
                CmsTrustHelpers.VerifyPkcs9MessageDigestAndRsaSha256(sd, 0, digest);
            }
            catch (PsignException e)
            {
                throw new PsignException($"CMS RSA/SHA-256 detached fallback (PKCS#7 {pkcs7Index}): {e.Message}");
            }
        }

        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("SignedData has no SignerInfo");
        }

        CertificateInfo x509Leaf;
        try
        {
            x509Leaf = CmsTrustHelpers.CertificateForSigner(sd, sd.SignerInfos[0]);
        }
        catch (PsignException e)
        {
            throw new PsignException($"CMS fallback: resolve signer certificate (PKCS#7 {pkcs7Index}): {e.Message}");
        }

        if (policy.StrictCodeSigningEku && !CmsTrustHelpers.HasCodeSigningEku(x509Leaf))
        {
            throw new PsignException(
                $"CMS fallback: leaf certificate lacks code-signing extended key usage (PKCS#7 {pkcs7Index})");
        }

        var embedded = CmsTrustHelpers.EmbeddedCertificatesStrict(sd, "picky embedded certificate");
        var merged = TrustChain.MergeUniqueCerts(anchorCerts, embedded);
        var leafThumb = Anchors.CertSha1ThumbprintHex(x509Leaf);
        var leaf = embedded.Concat(anchorCerts).FirstOrDefault(c => Anchors.CertSha1ThumbprintHex(c) == leafThumb) ?? x509Leaf;

        var chain = TrustChain.IssuerChainExcludingLeafOnline(leaf, merged, online, anchors);
        var root = TrustChain.TerminalRootCert(leaf, chain);
        RequireAnchoredRoot(root, anchors, out var rootThumb);
        OnlineTrust.CheckRevocationChain(leaf, chain, online);
        VerifyTrustChainVerbose(pkcs7Index, leaf, chain, root, rootThumb, verificationInstant, verboseChain, log);
    }

    /// <summary>
    /// Verify Authenticode PKCS#7 cryptographic checks and the certificate chain to the configured anchors.
    /// <paramref name="subjectDigest"/> must match the PKCS#7 indirect <c>messageDigest</c>.
    /// </summary>
    public static void VerifyAuthenticodePkcs7Trust(
        ReadOnlySpan<byte> pkcs7Der,
        int pkcs7Index,
        ReadOnlySpan<byte> subjectDigest,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        AuthenticodeTrustPolicy policy,
        OnlineTrustOptions online,
        DateTimeOffset verificationInstant,
        bool verboseChain,
        TextWriter? log = null)
    {
        var slice = Pkcs7Wire.NormalizeForAuthenticode(pkcs7Der);
        var picky = PickyAuthenticode.TryParse(slice);
        if (picky is null)
        {
            VerifyCmsRsaSha256Fallback(slice, pkcs7Index, Pkcs7DigestBinding.AuthenticodeIndirect, subjectDigest, anchors, anchorCerts, policy, online, verificationInstant, verboseChain, log);
            return;
        }

        try
        {
            picky.VerifyBasic(subjectDigest);
            if (policy.StrictCodeSigningEku)
            {
                picky.VerifySigningCertificate(verificationInstant);
            }
        }
        catch (PickyException e)
        {
            throw new PsignException($"picky Authenticode validation (PKCS#7 {pkcs7Index}): {e.Message}");
        }

        var embedded = picky.DecodeCertificates();
        var merged = TrustChain.MergeUniqueCerts(embedded, anchorCerts);
        CertificateInfo leaf;
        try
        {
            leaf = picky.SigningCertificate(merged);
        }
        catch (PickyException e)
        {
            throw new PsignException($"resolve signing certificate: {e.Message}");
        }

        var chain = TrustChain.IssuerChainExcludingLeafOnline(leaf, merged, online, anchors);
        var root = TrustChain.TerminalRootCert(leaf, chain);
        RequireAnchoredRoot(root, anchors, out var rootThumb);
        OnlineTrust.CheckRevocationChain(leaf, chain, online);
        VerifyTrustChainVerbose(pkcs7Index, leaf, chain, root, rootThumb, verificationInstant, verboseChain, log);
    }

    /// <summary>Verify CMS / PKCS#7 where PKCS#9 <c>messageDigest</c> binds the signature to an external content digest.</summary>
    public static void VerifyPkcs9MessageDigestPkcs7Trust(
        ReadOnlySpan<byte> pkcs7Der,
        int pkcs7Index,
        ReadOnlySpan<byte> contentDigest,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        AuthenticodeTrustPolicy policy,
        OnlineTrustOptions online,
        DateTimeOffset verificationInstant,
        bool verboseChain,
        TextWriter? log = null)
    {
        var slice = Pkcs7Wire.NormalizeForAuthenticode(pkcs7Der);
        VerifyCmsRsaSha256Fallback(slice, pkcs7Index, Pkcs7DigestBinding.Pkcs9MessageDigest, contentDigest, anchors, anchorCerts, policy, online, verificationInstant, verboseChain, log);
    }

    /// <summary>Dispatch on <paramref name="binding"/>.</summary>
    public static void VerifyPkcs7TrustWithBinding(
        Pkcs7DigestBinding binding,
        ReadOnlySpan<byte> pkcs7Der,
        int pkcs7Index,
        ReadOnlySpan<byte> digest,
        AnchorStore anchors,
        IReadOnlyList<CertificateInfo> anchorCerts,
        AuthenticodeTrustPolicy policy,
        OnlineTrustOptions online,
        DateTimeOffset verificationInstant,
        bool verboseChain,
        TextWriter? log = null)
    {
        if (binding == Pkcs7DigestBinding.AuthenticodeIndirect)
        {
            VerifyAuthenticodePkcs7Trust(pkcs7Der, pkcs7Index, digest, anchors, anchorCerts, policy, online, verificationInstant, verboseChain, log);
        }
        else
        {
            VerifyPkcs9MessageDigestPkcs7Trust(pkcs7Der, pkcs7Index, digest, anchors, anchorCerts, policy, online, verificationInstant, verboseChain, log);
        }
    }
}
