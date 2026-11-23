using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;

namespace Devolutions.Psign.Verification;

/// <summary>CAB Authenticode trust: CAB SIP digest + PKCS#7 chain (Rust <c>trust_verify_cab.rs</c>).</summary>
public static class TrustVerifyCab
{
    /// <summary>Rust <c>trust_verify_cab_bytes</c>.</summary>
    public static TrustVerifyPeReport TrustVerifyCabBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var ctx = CabDigest.ParseContext(data);
        var pkcs7 = CabDigest.SignaturePkcs7Der(data);
        var embedded = TrustVerifyFormats.EmbeddedIndirectDigest(pkcs7, "CAB PKCS#7");
        var kind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
        var cabDigest = CabDigest.ComputeAuthenticodeDigest(data, ctx, kind);
        if (!cabDigest.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException("CAB Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)");
        }

        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(pkcs7, 0, cabDigest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
        return report;
    }
}

/// <summary>Helpers shared by the format trust verifiers.</summary>
internal static class TrustVerifyFormats
{
    /// <summary>Indirect digest of an Authenticode PKCS#7 (Rust <c>AuthenticodeSignature::from_bytes(..)?.digest()</c>).</summary>
    public static byte[] EmbeddedIndirectDigest(byte[] pkcs7, string context)
    {
        try
        {
            return AuthenticodeSignature.Parse(pkcs7).Digest;
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            throw new PsignException($"{context}: {e.Message}");
        }
    }
}
