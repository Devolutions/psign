using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msi;

namespace Devolutions.Psign.Verification;

/// <summary>Windows Installer Authenticode trust: MSI/MSP digest + PKCS#7 chain (Rust <c>trust_verify_msi.rs</c>).</summary>
public static class TrustVerifyMsi
{
    /// <summary>Rust <c>trust_verify_msi_bytes</c>.</summary>
    public static TrustVerifyPeReport TrustVerifyMsiBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var pkcs7 = MsiDigest.DigitalSignaturePkcs7Der(data);
        var (kind, embedded) = TrustVerifyFormats.EmbeddedIndirectDigestAndKind(pkcs7, "MSI PKCS#7");
        var msiDigest = MsiDigest.ComputeAuthenticodeDigest(data, kind);
        if (!msiDigest.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException("MSI Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)");
        }

        // Also validate MsiDigitalSignatureEx metadata pre-hash stream when present.
        MsiDigest.VerifyDigestConsistency(data);

        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(pkcs7, 0, msiDigest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
        return report;
    }
}
