using Devolutions.Psign.Core;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>
/// Certificate-chain trust for XMLDSig signer certificates (ClickOnce manifests, VSIX signature XML), port of
/// <c>verify_xml_signer_certificate_trust</c> in <c>crates/psign-digest-cli/src/main.rs</c>. The signer certificate is
/// chained to the configured anchors (never the Artifact Signing roots), revocation policy is applied, and the chain is
/// validated at <c>--as-of</c> or the current time.
/// </summary>
public static class XmlSignerTrust
{
    /// <summary>Verify <paramref name="certDer"/> against the anchors of <paramref name="shared"/>; returns the anchor count.</summary>
    public static int VerifyXmlSignerCertificateTrust(byte[] certDer, TrustVerifySharedArgs shared, TextWriter? log = null) =>
        VerifyXmlSignerCertificateTrust(certDer, shared.ToOptions() with { Log = log });

    /// <summary>Verify <paramref name="certDer"/> against the anchors of <paramref name="opts"/>; returns the anchor count.</summary>
    public static int VerifyXmlSignerCertificateTrust(byte[] certDer, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.LoadTrustMaterial(opts);
        Core.X509.CertificateInfo leaf;
        try
        {
            leaf = Anchors.ParseCertBytes(certDer);
        }
        catch (PsignException e)
        {
            throw PsignException.Context("parse XMLDSig signer certificate for trust verification", e);
        }

        var merged = TrustChain.MergeUniqueCerts([leaf], anchorCerts);
        var chain = TrustChain.IssuerChainExcludingLeafOnline(leaf, merged, opts.Online, anchors);
        var root = TrustChain.TerminalRootCert(leaf, chain);
        var rootThumb = Anchors.CertSha1Thumbprint(root);
        if (!anchors.ContainsThumbprint(rootThumb))
        {
            throw new PsignException(
                $"XMLDSig terminal root certificate is not in the anchor store (SHA-1 thumbprint {rootThumb[0]:x2}{rootThumb[1]:x2}...)");
        }

        OnlineTrust.CheckRevocationChain(leaf, chain, opts.Online);

        DateTimeOffset instant;
        if (opts.VerificationInstantOverride is { } o)
        {
            instant = o;
        }
        else if (opts.Policy.PreferTimestampSigningTime && opts.Policy.RequireValidTimestamp)
        {
            throw new PsignException(
                "VSIX XMLDSig timestamp trust verification is not implemented; use --as-of for deterministic certificate-chain validation");
        }
        else
        {
            instant = VerificationInstant.ResolveVerificationUtcDate([], opts.Policy);
        }

        try
        {
            PickyCert.VerifyExact(leaf, chain, instant);
        }
        catch (PickyException e)
        {
            throw new PsignException($"XMLDSig certificate chain verification: {e.Message}");
        }

        if (opts.VerboseChain)
        {
            var log = opts.Log ?? Console.Error;
            log.WriteLine($"xml-trust: leaf subject: {PickyCert.SubjectDisplay(leaf)}");
            for (int i = 0; i < chain.Count; i++)
            {
                log.WriteLine($"xml-trust:   chain[{i}] subject: {PickyCert.SubjectDisplay(chain[i])} issuer: {PickyCert.IssuerDisplay(chain[i])}");
            }

            log.WriteLine($"xml-trust:   root subject: {PickyCert.SubjectDisplay(root)} (thumb SHA-1 {Hex.Lower(rootThumb)})");
        }

        return anchors.ThumbprintCount;
    }
}
