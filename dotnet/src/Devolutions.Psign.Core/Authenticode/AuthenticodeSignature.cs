using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.Authenticode;

/// <summary>
/// Structurally validated Authenticode PKCS#7 signature (port of the <c>authenticode</c> crate's
/// <c>AuthenticodeSignature::from_bytes</c> rules).
/// </summary>
public sealed class AuthenticodeSignature
{
    private AuthenticodeSignature(CmsSignedData signedData, SpcIndirectDataContent indirectData)
    {
        SignedData = signedData;
        IndirectData = indirectData;
    }

    public CmsSignedData SignedData { get; }

    public SpcIndirectDataContent IndirectData { get; }

    /// <summary>The only <c>SignerInfo</c>.</summary>
    public CmsSignerInfo SignerInfo => SignedData.SignerInfos[0];

    /// <summary>Embedded subject digest.</summary>
    public byte[] Digest => IndirectData.Digest;

    /// <summary>Parse and validate (input is normalized via <see cref="Pkcs7Wire.NormalizeForAuthenticode"/>).</summary>
    public static AuthenticodeSignature Parse(ReadOnlySpan<byte> pkcs7)
    {
        if (pkcs7.IsEmpty)
        {
            throw new PsignException("empty signature");
        }

        var sd = CmsSignedData.Parse(pkcs7);
        if (sd.Version != 1)
        {
            throw new PsignException($"invalid signed data version: V{sd.Version}");
        }

        if (sd.DigestAlgorithms.Count != 1)
        {
            throw new PsignException($"invalid number of digest algorithms: {sd.DigestAlgorithms.Count}");
        }

        if (sd.EncapContentType != Oids.SpcIndirectData)
        {
            throw new PsignException($"invalid encapsulated content type: {sd.EncapContentType}");
        }

        if (sd.EncapContent is null)
        {
            throw new PsignException("empty encapsulated content");
        }

        SpcIndirectDataContent indirect;
        try
        {
            indirect = SpcIndirectDataContent.Parse(sd.EncapContent);
        }
        catch (PsignException e)
        {
            throw new PsignException($"invalid SpcIndirectDataContent: {e.Message}", e);
        }

        if (sd.SignerInfos.Count != 1)
        {
            throw new PsignException($"invalid number of signer info: {sd.SignerInfos.Count}");
        }

        var si = sd.SignerInfos[0];
        if (si.Version != 1)
        {
            throw new PsignException($"invalid signer info version: V{si.Version}");
        }

        if (!si.DigestAlgorithm.Equals(sd.DigestAlgorithms[0]))
        {
            throw new PsignException("signer info digest algorithm does not match signed data digest algorithm");
        }

        if (si.SignedAttributes is null)
        {
            throw new PsignException("empty authenticated attributes");
        }

        if (!si.SignedAttributes.Any(a => a.Oid == Oids.Pkcs9ContentType))
        {
            throw new PsignException("missing content type authenticated attribute");
        }

        if (!si.SignedAttributes.Any(a => a.Oid == Oids.Pkcs9MessageDigest))
        {
            throw new PsignException("missing message digest authenticated attribute");
        }

        return new AuthenticodeSignature(sd, indirect);
    }
}
