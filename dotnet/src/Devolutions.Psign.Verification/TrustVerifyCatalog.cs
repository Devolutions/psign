using Devolutions.Psign.Core.Catalog;

namespace Devolutions.Psign.Verification;

/// <summary>Catalog <c>.cat</c> trust: CMS digest consistency + PKCS#7 chain (Rust <c>trust_verify_catalog.rs</c>).</summary>
public static class TrustVerifyCatalog
{
    /// <summary>Rust <c>trust_verify_catalog_bytes</c>.</summary>
    public static TrustVerifyPeReport TrustVerifyCatalogBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        CatalogDigest.VerifyDigestConsistency(data);
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var digest = CatalogDigest.EContentDigest(data);
        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(data, 0, digest, Pkcs7DigestBinding.Pkcs9MessageDigest, anchors, anchorCerts, opts, report);
        return report;
    }
}
