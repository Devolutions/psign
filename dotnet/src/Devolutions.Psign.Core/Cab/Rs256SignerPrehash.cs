using System.Security.Cryptography;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.Cab;

/// <summary>
/// Local copy of Rust <c>pkcs7::signed_data_rsa_sha256_signer_prehash_digest</c> used by the CAB / MSI / catalog
/// <c>*_rsa_sha256_signer_prehash_digest</c> helpers (SHA-256 over the DER <c>SET OF</c> signed attributes).
/// </summary>
internal static class Rs256SignerPrehash
{
    /// <summary>SHA-256 over the authenticated attributes of <paramref name="sd"/>'s signer at <paramref name="signerIndex"/>.</summary>
    public static byte[] Compute(CmsSignedData sd, int signerIndex)
    {
        if (signerIndex < 0 || signerIndex >= sd.SignerInfos.Count)
        {
            throw new PsignException($"SignerInfo index {signerIndex} out of range (len {sd.SignerInfos.Count})");
        }

        var si = sd.SignerInfos[signerIndex];
        if (si.DigestAlgorithm.Oid != Oids.Sha256)
        {
            throw new PsignException(
                $"SignerInfo.digestAlgorithm must be SHA-256 ({Oids.Sha256}) for RS256 prehash; got {si.DigestAlgorithm.Oid}");
        }

        if (si.SignedAttributes is null)
        {
            throw new PsignException(
                $"authenticated-attribute SET hash (SignerInfo index {signerIndex}) — need signedAttrs",
                new PsignException("SignerInfo has no authenticated attributes"));
        }

        return SHA256.HashData(si.SignedAttributesSetDer());
    }
}
