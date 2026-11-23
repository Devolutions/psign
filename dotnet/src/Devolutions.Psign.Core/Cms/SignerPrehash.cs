using System.Security.Cryptography;

namespace Devolutions.Psign.Core.Cms;

/// <summary>
/// Signer-attribute prehash helpers (Rust <c>pkcs7::signed_data_rsa_sha256_signer_prehash_digest</c>): the digest a remote
/// RSA signer (Azure Key Vault <c>RS256</c>, Artifact Signing) signs when re-signing a CMS <c>SignerInfo</c>.
/// </summary>
public static class SignerPrehash
{
    /// <summary>
    /// SHA-256 over the DER <c>SET OF Attribute</c> authenticated attributes of <paramref name="sd"/>'s signer at
    /// <paramref name="signerIndex"/> (RFC 5652 §5.4). Requires a SHA-256 <c>digestAlgorithm</c> and <c>signedAttrs</c>.
    /// </summary>
    public static byte[] Rs256(CmsSignedData sd, int signerIndex)
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
