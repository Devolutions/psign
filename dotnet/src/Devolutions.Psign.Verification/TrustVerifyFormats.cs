using System.Formats.Asn1;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Esd;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Verification;

/// <summary>
/// Per-format portable trust verification over explicit anchors (Rust <c>trust_verify_cab.rs</c>,
/// <c>trust_verify_msi.rs</c>, <c>trust_verify_catalog.rs</c>, <c>trust_verify_zip.rs</c>,
/// <c>trust_verify_script.rs</c>, <c>trust_verify_msix.rs</c>, <c>trust_verify_nuget.rs</c> and
/// <c>trust_verify_esd.rs</c>). Each verifier recomputes the subject digest, compares it with the signed digest, and then
/// applies <see cref="TrustVerifyPe.VerifyPkcs7Entry"/> (generic anchors or the Artifact Signing policy).
/// VSIX lives in <see cref="TrustVerifyVsix"/>.
/// </summary>
public static class TrustVerifyFormats
{
    /// <summary>CAB Authenticode trust (Rust <c>trust_verify_cab_bytes</c>).</summary>
    public static TrustVerifyPeReport TrustVerifyCabBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var ctx = CabDigest.ParseContext(data);
        var pkcs7 = CabDigest.SignaturePkcs7Der(data);
        var embedded = EmbeddedAuthenticodeDigest(pkcs7, "CAB PKCS#7");
        var kind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
        var digest = CabDigest.ComputeAuthenticodeDigest(data, ctx, kind);
        if (!digest.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException("CAB Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)");
        }

        return VerifySingle(pkcs7, digest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts);
    }

    /// <summary>MSI / MSP Authenticode trust (Rust <c>trust_verify_msi_bytes</c>).</summary>
    public static TrustVerifyPeReport TrustVerifyMsiBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var pkcs7 = MsiDigest.DigitalSignaturePkcs7Der(data);
        var embedded = EmbeddedAuthenticodeDigest(pkcs7, "MSI PKCS#7");
        var kind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
        var digest = MsiDigest.ComputeAuthenticodeDigest(data, kind);
        if (!digest.AsSpan().SequenceEqual(embedded))
        {
            throw new PsignException("MSI Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)");
        }

        return VerifySingle(pkcs7, digest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts);
    }

    /// <summary>Catalog (<c>.cat</c>) trust: CMS digest consistency + PKCS#7 chain (Rust <c>trust_verify_catalog_bytes</c>).</summary>
    public static TrustVerifyPeReport TrustVerifyCatalogBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        CatalogDigest.VerifyDigestConsistency(data);
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var digest = CatalogDigest.EContentDigest(data);
        return VerifySingle(data, digest, Pkcs7DigestBinding.Pkcs9MessageDigest, anchors, anchorCerts, opts);
    }

    /// <summary>Devolutions ZIP Authenticode trust (Rust <c>trust_verify_zip_bytes</c>).</summary>
    public static TrustVerifyPeReport TrustVerifyZipBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var sig = ZipAuthenticode.VerifyZipDigestBinding(data);
        var script = ZipAuthenticode.SignatureScriptFromParts(sig.Digest, sig.Pkcs7Base64);
        var scriptReport = PsScript.PowerShellClassDigestReport(System.Text.Encoding.UTF8.GetBytes(script), "ps1");
        return VerifySingle(scriptReport.Pkcs7Der, scriptReport.ComputedDigest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts);
    }

    /// <summary>
    /// Script Authenticode trust: PowerShell-class and WSH SIP digest + PKCS#7 chain (Rust <c>trust_verify_script_bytes</c>).
    /// <paramref name="extension"/> is the lowercase extension without the dot.
    /// </summary>
    public static TrustVerifyPeReport TrustVerifyScriptBytes(byte[] data, string extension, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var scriptReport = ScriptDigest.ScriptDigestReport(data, extension);
        return VerifySingle(scriptReport.Pkcs7Der, scriptReport.ComputedDigest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts);
    }

    /// <summary>
    /// Cleartext <c>.msix</c> / <c>.appx</c> / <c>.msixbundle</c> / <c>.appxbundle</c> trust (Rust <c>trust_verify_msix_bytes</c>).
    /// <paramref name="extension"/> is the package extension without the dot.
    /// </summary>
    public static TrustVerifyPeReport TrustVerifyMsixBytes(byte[] data, string extension, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var (pkcs7, digest) = MsixDigest.MsixVerifiedSignature(data, extension);
        return VerifySingle(pkcs7, digest, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts);
    }

    /// <summary>NuGet author-signature trust (Rust <c>trust_verify_nuget_bytes</c>).</summary>
    public static TrustVerifyPeReport TrustVerifyNuGetBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var signature = NuGetPackage.ExtractSignature(data);
        var (_, contentDigest) = NuGetVerifiedSignatureContent(data, signature);
        return VerifySingle(signature, contentDigest, Pkcs7DigestBinding.Pkcs9MessageDigest, anchors, anchorCerts, opts);
    }

    /// <summary>WIM / ESD trust (Rust <c>trust_verify_wim_esd_path</c>).</summary>
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
            throw PsignException.Context($"open {path}", e);
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
                throw PsignException.Context($"read WIM/ESD header {path}", e);
            }

            var pkcs7 = EsdDigest.ReadEmbeddedPkcs7(f, header);
            byte[] embedded;
            try
            {
                embedded = AuthenticodeSignature.Parse(Pkcs7Wire.NormalizeForAuthenticode(pkcs7)).Digest;
            }
            catch (Exception e) when (e is PsignException or AsnContentException or FormatException)
            {
                throw new PsignException($"WIM/ESD PKCS#7 parse failed: {e.Message}", e);
            }

            var kind = AuthenticodeHashKinds.FromDigestLength(embedded.Length);
            var computed = EsdDigest.ComputeWimImageDigestFromHeader(f, header, kind);
            if (!computed.AsSpan().SequenceEqual(embedded))
            {
                throw new PsignException("WIM/ESD Authenticode digest mismatch before trust checks (Rust SIP vs PKCS#7 indirect digest)");
            }

            return VerifySingle(pkcs7, computed, Pkcs7DigestBinding.AuthenticodeIndirect, anchors, anchorCerts, opts);
        }
    }

    /// <summary>
    /// The verified NuGet signature content of <paramref name="package"/> and its PKCS#9 <c>messageDigest</c> (Rust
    /// <c>nuget_verified_signature_content</c>). Embedded content must record the package hash of the exact unsigned bytes; a
    /// detached CMS is accepted when the content rebuilt from that hash matches the signed <c>messageDigest</c>.
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
            throw new PsignException($"NuGet signature messageDigest: {e.Message}", e);
        }

        var unsigned = NuGetPackage.SignedPackageUnsignedBytes(package);
        byte[] content;
        if (sd.EncapContent is { } econtent)
        {
            var t = Der.First(econtent);
            if (t is null || t.Value.Tag != 0x04 || t.Value.End != econtent.Length)
            {
                throw new PsignException("NuGet signature content is not an OCTET STRING");
            }

            content = t.Value.Value(econtent).ToArray();
            var parsed = NuGetPackage.ParseSignatureContent(content);
            if (!parsed.HashAlgorithm.Hash(unsigned).AsSpan().SequenceEqual(parsed.PackageHash))
            {
                throw new PsignException("NuGet package hash mismatch: the package content changed after signing");
            }
        }
        else
        {
            byte[]? found = null;
            foreach (var alg in new[] { NuGetHashAlgorithm.Sha256, NuGetHashAlgorithm.Sha384, NuGetHashAlgorithm.Sha512 })
            {
                var candidate = NuGetPackage.SignatureContentBytes(alg, alg.Hash(unsigned));
                if (DigestForLength(messageDigest.Length, candidate) is { } d && d.AsSpan().SequenceEqual(messageDigest))
                {
                    found = candidate;
                    break;
                }
            }

            content = found ?? throw new PsignException("NuGet package hash mismatch: the package content changed after signing");
        }

        var contentDigest = DigestForLength(messageDigest.Length, content)
            ?? throw new PsignException($"unsupported NuGet signature digest length {messageDigest.Length}");
        if (!contentDigest.AsSpan().SequenceEqual(messageDigest))
        {
            throw new PsignException("NuGet signature messageDigest mismatch: the signed content differs from the embedded content");
        }

        return (content, messageDigest);
    }

    private static byte[]? DigestForLength(int length, byte[] data) => length switch
    {
        32 => AuthenticodeHashKind.Sha256.Hash(data),
        48 => AuthenticodeHashKind.Sha384.Hash(data),
        64 => AuthenticodeHashKind.Sha512.Hash(data),
        _ => null,
    };

    private static byte[] EmbeddedAuthenticodeDigest(byte[] pkcs7, string label)
    {
        try
        {
            return AuthenticodeSignature.Parse(Pkcs7Wire.NormalizeForAuthenticode(pkcs7)).Digest;
        }
        catch (Exception e) when (e is PsignException or AsnContentException or FormatException)
        {
            throw new PsignException($"{label}: {e.Message}", e);
        }
    }

    private static TrustVerifyPeReport VerifySingle(
        byte[] pkcs7,
        byte[] digest,
        Pkcs7DigestBinding binding,
        AnchorStore anchors,
        List<Core.X509.CertificateInfo> anchorCerts,
        TrustVerifyPeOptions opts)
    {
        var report = TrustVerifyPe.NewReport(anchors);
        TrustVerifyPe.VerifyPkcs7Entry(pkcs7, 0, digest, binding, anchors, anchorCerts, opts, report);
        return report;
    }
}
