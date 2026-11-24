using Devolutions.Psign.Core.Scripts;

namespace Devolutions.Psign.Verification;

/// <summary>
/// Script Authenticode trust: PowerShell-class (<c>pwrshsip</c>) and WSH (<c>.js</c>, <c>.jse</c>, <c>.vbs</c>, <c>.vbe</c>,
/// <c>.wsf</c>) SIP digest + PKCS#7 chain (Rust <c>trust_verify_script.rs</c>).
/// </summary>
public static class TrustVerifyScript
{
    /// <summary>Rust <c>trust_verify_script_bytes</c>; <paramref name="extension"/> has no dot.</summary>
    public static TrustVerifyPeReport TrustVerifyScriptBytes(byte[] data, string extension, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var scriptReport = ScriptDigest.ScriptDigestReport(data, extension);
        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(scriptReport.Pkcs7Der, 0, scriptReport.ComputedDigest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
        return report;
    }
}
