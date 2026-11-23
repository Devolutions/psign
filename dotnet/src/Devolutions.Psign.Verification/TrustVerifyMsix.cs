using Devolutions.Psign.Core.Msix;

namespace Devolutions.Psign.Verification;

/// <summary>MSIX / AppX (and bundle) Authenticode trust: APPX SIP digest + PKCS#7 chain (Rust <c>trust_verify_msix.rs</c>).</summary>
public static class TrustVerifyMsix
{
    /// <summary>
    /// Trust-verify a cleartext <c>.msix</c> / <c>.appx</c> / <c>.msixbundle</c> / <c>.appxbundle</c> package
    /// (<paramref name="extension"/> without the dot). The APPX <c>messageDigest</c> blob is recomputed and compared before
    /// the PKCS#7 trust step.
    /// </summary>
    public static TrustVerifyPeReport TrustVerifyMsixBytes(byte[] data, string extension, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var (pkcs7, digest) = MsixDigest.MsixVerifiedSignature(data, extension);
        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(pkcs7, 0, digest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
        return report;
    }
}
