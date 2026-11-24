using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Esd;

namespace Devolutions.Psign.Verification;

/// <summary>WIM/ESD Authenticode trust: ESD SIP digest + PKCS#7 chain (Rust <c>trust_verify_esd.rs</c>).</summary>
public static class TrustVerifyEsd
{
    /// <summary>Rust <c>trust_verify_wim_esd_path</c>.</summary>
    public static TrustVerifyPeReport TrustVerifyWimEsdPath(string path, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        FileStream f;
        try
        {
            f = File.OpenRead(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw PsignException.Context($"open {path}", IoErrorText.Inner(e));
        }

        using (f)
        {
            byte[] header;
            try
            {
                header = EsdDigest.ReadHeader(f);
            }
            catch (Exception e) when (e is IOException or PsignException)
            {
                throw PsignException.Context($"read WIM/ESD header {path}", e is EndOfStreamException ? new PsignException("failed to fill whole buffer") : e);
            }

            var pkcs7 = EsdDigest.ReadEmbeddedPkcs7(f, header);
            var (kind, embedded) = TrustVerifyFormats.EmbeddedIndirectDigestAndKind(pkcs7, "WIM/ESD PKCS#7 parse failed");
            var computed = EsdDigest.ComputeWimImageDigestFromHeader(f, header, kind);
            if (!computed.AsSpan().SequenceEqual(embedded))
            {
                throw new PsignException("WIM/ESD Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)");
            }

            var report = TrustVerifyPe.NewReport(anchors);
            TrustVerifyPe.VerifyPkcs7Entry(pkcs7, 0, computed, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts, report);
            return report;
        }
    }
}
