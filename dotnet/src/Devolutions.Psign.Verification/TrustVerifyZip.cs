using System.Text;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Verification;

/// <summary>Custom ZIP Authenticode trust (Devolutions ZIP comment convention; Rust <c>trust_verify_zip.rs</c>).</summary>
public static class TrustVerifyZip
{
    /// <summary>Rust <c>trust_verify_zip_bytes</c>.</summary>
    public static TrustVerifyPeReport TrustVerifyZipBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var sig = ZipAuthenticode.VerifyZipDigestBinding(data);
        var script = ZipAuthenticode.SignatureScriptFromParts(sig.Digest, sig.Pkcs7Base64);
        var scriptReport = PsScript.PowerShellClassDigestReport(Encoding.UTF8.GetBytes(script), "ps1");
        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(scriptReport.Pkcs7Der, 0, scriptReport.ComputedDigest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
        return report;
    }
}
