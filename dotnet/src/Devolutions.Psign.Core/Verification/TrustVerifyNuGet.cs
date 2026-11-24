using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.NuGet;

namespace Devolutions.Psign.Verification;

/// <summary>
/// NuGet package author-signature trust (<c>.nupkg</c> / <c>.snupkg</c>; Rust <c>trust_verify_nuget.rs</c>). The
/// <c>.signature.p7s</c> CMS encapsulates the signature content (<c>Version:1</c> + <c>&lt;hash OID&gt;-Hash:&lt;base64&gt;</c>).
/// The package hash is recomputed over the exact unsigned package bytes
/// (<see cref="NuGetPackage.SignedPackageUnsignedBytes"/>), then the CMS is trust-verified with its PKCS#9
/// <c>messageDigest</c> bound to that content.
/// </summary>
public static class TrustVerifyNuGet
{
    private static readonly NuGetHashAlgorithm[] Algorithms = [NuGetHashAlgorithm.Sha256, NuGetHashAlgorithm.Sha384, NuGetHashAlgorithm.Sha512];

    private static byte[] DigestForLength(int len, byte[] data) => len switch
    {
        32 => AuthenticodeHashKind.Sha256.Hash(data),
        48 => AuthenticodeHashKind.Sha384.Hash(data),
        64 => AuthenticodeHashKind.Sha512.Hash(data),
        _ => throw new PsignException($"unsupported NuGet signature digest length {len}"),
    };

    /// <summary>
    /// The verified NuGet signature content of <paramref name="package"/> and its PKCS#9 <c>messageDigest</c> (Rust
    /// <c>nuget_verified_signature_content</c>). Embedded content (as <c>dotnet nuget sign</c> writes it) must record the
    /// package hash of the exact unsigned bytes. A detached CMS (written by earlier psign releases) is accepted when the
    /// signature content rebuilt from that package hash matches the signed <c>messageDigest</c>.
    /// </summary>
    public static (byte[] Content, byte[] MessageDigest) NuGetVerifiedSignatureContent(byte[] package, byte[] signature)
    {
        CmsSignedData sd;
        try
        {
            sd = CmsTrustHelpers.ParsePkcs7SignedDataDer(signature);
        }
        catch (PsignException e)
        {
            throw PsignException.Context("NuGet .signature.p7s CMS", e);
        }

        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("NuGet signature has no SignerInfo");
        }

        byte[] messageDigest;
        try
        {
            messageDigest = CmsTrustHelpers.SignerInfoPkcs9MessageDigestOctets(sd.SignerInfos[0]);
        }
        catch (PsignException e)
        {
            throw new PsignException($"NuGet signature messageDigest: {e.Message}");
        }

        var unsigned = NuGetPackage.SignedPackageUnsignedBytes(package);

        byte[] content;
        if (sd.EncapContent is { } econtent)
        {
            var tlv = Der.First(econtent);
            if (tlv is not { Tag: 0x04 } t || t.End != econtent.Length)
            {
                throw new PsignException("NuGet signature content is not an OCTET STRING: unexpected ASN.1 DER tag");
            }

            content = t.Value(econtent).ToArray();
            var parsed = NuGetPackage.ParseSignatureContent(content);
            if (!parsed.HashAlgorithm.Hash(unsigned).AsSpan().SequenceEqual(parsed.PackageHash))
            {
                throw new PsignException("NuGet package hash mismatch: the package content changed after signing");
            }
        }
        else
        {
            byte[]? found = null;
            foreach (var alg in Algorithms)
            {
                var candidate = NuGetPackage.SignatureContentBytes(alg, alg.Hash(unsigned));
                if (messageDigest.Length is 32 or 48 or 64 && DigestForLength(messageDigest.Length, candidate).AsSpan().SequenceEqual(messageDigest))
                {
                    found = candidate;
                    break;
                }
            }

            content = found ?? throw new PsignException("NuGet package hash mismatch: the package content changed after signing");
        }

        var siDigestKind = AuthenticodeHashKinds.FromOid(sd.SignerInfos[0].DigestAlgorithm.Oid)
            ?? throw new PsignException($"unsupported NuGet signature digest algorithm OID {sd.SignerInfos[0].DigestAlgorithm.Oid}");
        if (siDigestKind == AuthenticodeHashKind.Sha1 || messageDigest.Length != siDigestKind.DigestLength())
        {
            throw new PsignException(
                $"NuGet signature messageDigest length {messageDigest.Length} does not match SignerInfo digestAlgorithm {siDigestKind.Name()}");
        }

        if (!DigestForLength(messageDigest.Length, content).AsSpan().SequenceEqual(messageDigest))
        {
            throw new PsignException("NuGet signature messageDigest mismatch: the signed content differs from the embedded content");
        }

        return (content, messageDigest);
    }

    /// <summary>Rust <c>trust_verify_nuget_bytes</c>.</summary>
    public static TrustVerifyPeReport TrustVerifyNuGetBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var signature = NuGetPackage.ExtractSignature(data);
        var (_, contentDigest) = NuGetVerifiedSignatureContent(data, signature);
        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(signature, 0, contentDigest, Pkcs7DigestBinding.Pkcs9MessageDigest, anchors, anchorCerts, opts, report);
        return report;
    }
}
