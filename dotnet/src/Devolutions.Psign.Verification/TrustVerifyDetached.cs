using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Verification;

/// <summary>Detached PKCS#7 trust: content bytes vs indirect digest or PKCS#9 messageDigest (Rust <c>trust_verify_detached.rs</c>).</summary>
public static class TrustVerifyDetached
{
    private static byte[] HashContentImplicit(byte[] content, int embeddedLength) =>
        AuthenticodeHashKinds.FromDigestLength(embeddedLength).Hash(content);

    /// <summary>Verify a detached PKCS#7 signature over <paramref name="content"/>.</summary>
    public static TrustVerifyPeReport TrustVerifyDetachedBytes(byte[] content, ReadOnlySpan<byte> pkcs7Der, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var slice = Pkcs7Wire.NormalizeForAuthenticode(pkcs7Der);
        var report = TrustVerifyPe.NewReport(anchors);

        AuthenticodeSignature? sig = null;
        string? authenticodeErr = null;
        try
        {
            sig = AuthenticodeSignature.Parse(slice);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            authenticodeErr = e.Message;
        }

        if (sig is not null)
        {
            var embedded = sig.Digest;
            var computed = HashContentImplicit(content, embedded.Length);
            if (!computed.AsSpan().SequenceEqual(embedded))
            {
                throw new PsignException(
                    "detached content digest does not match PKCS#7 indirect digest (algorithm inferred from embedded digest length)");
            }

            TrustVerifyPe.VerifyPkcs7Entry(slice, 0, computed, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
            return report;
        }

        CmsSignedData sd;
        try
        {
            sd = CmsTrustHelpers.ParsePkcs7SignedDataDer(slice);
        }
        catch (PsignException cmsErr)
        {
            throw new PsignException($"detached PKCS#7: {authenticodeErr}; CMS detached fallback parse failed: {cmsErr.Message}");
        }

        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("detached PKCS#7: CMS detached fallback found no SignerInfo");
        }

        byte[] md;
        try
        {
            md = CmsTrustHelpers.SignerInfoPkcs9MessageDigestOctets(sd.SignerInfos[0]);
        }
        catch (PsignException e)
        {
            throw new PsignException($"detached PKCS#7: CMS detached fallback missing messageDigest: {e.Message}");
        }

        var computedMd = HashContentImplicit(content, md.Length);
        if (!computedMd.AsSpan().SequenceEqual(md))
        {
            throw new PsignException(
                "detached content digest does not match PKCS#9 messageDigest (algorithm inferred from embedded digest length)");
        }

        TrustVerifyPe.VerifyPkcs7Entry(slice, 0, computedMd, Pkcs7DigestBinding.Pkcs9MessageDigest, anchors, anchorCerts, opts, report);
        return report;
    }
}
