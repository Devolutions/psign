using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Msix;

/// <summary>
/// End-to-end cleartext MSIX / APPX / bundle signing: stage the package in AppxPackaging layout with a
/// <c>PKCX</c> placeholder, compute the APPX digest blob, build the Authenticode PKCS#7 with
/// <see cref="SpcIndirectDataContent.ForMsix"/>, optionally timestamp it and embed <c>AppxSignature.p7x</c>.
/// Port of <c>pkcs7::msix_spc_indirect_data</c> / <c>create_msix_authenticode_pkcs7_der_rsa</c> and the MSIX branch
/// of the portable signer (<c>psign-portable-core</c> <c>sign_msix</c> / <c>sign_msix_bytes_with_provider</c>).
/// Output is byte-identical to the Rust signer for the same key and input package.
/// </summary>
public static class MsixSigner
{
    /// <summary>
    /// Build the Authenticode <c>SpcIndirectDataContent</c> for a package that already contains the final
    /// <c>[Content_Types].xml</c> and an <c>AppxSignature.p7x</c> placeholder (Rust <c>msix_spc_indirect_data</c>).
    /// </summary>
    public static SpcIndirectDataContent SpcIndirectData(byte[] packageWithSignaturePart, string extension, AuthenticodeHashKind digest)
    {
        var (kind, blob) = MsixDigest.MsixAuthenticodeDigestBlob(packageWithSignaturePart, extension);
        if (kind != digest)
        {
            throw new PsignException(
                $"MSIX AppxBlockMap HashMethod {SpcIndirectDataContent.Display(kind)} does not match requested signing digest {SpcIndirectDataContent.Display(digest)}");
        }

        return SpcIndirectDataContent.ForMsix(digest, blob);
    }

    /// <summary>Create the PKCS#7 <c>ContentInfo(SignedData)</c> for a staged package (Rust <c>create_msix_authenticode_pkcs7_der_rsa</c>).</summary>
    public static byte[] CreateAuthenticodePkcs7(
        byte[] packageWithSignaturePart,
        string extension,
        AuthenticodeHashKind digest,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer)
    {
        var indirect = SpcIndirectData(packageWithSignaturePart, extension, digest);
        return Pkcs7Builder.CreateAuthenticode(indirect, digest, signerCert, chainCerts, signer);
    }

    /// <summary>Wrap a PKCS#7 DER blob as <c>AppxSignature.p7x</c> (<c>PKCX</c> prefix).</summary>
    public static byte[] ToP7x(ReadOnlySpan<byte> pkcs7)
    {
        var p7x = new byte[4 + pkcs7.Length];
        "PKCX"u8.CopyTo(p7x);
        pkcs7.CopyTo(p7x.AsSpan(4));
        return p7x;
    }

    /// <summary>
    /// Sign package bytes (Rust <c>sign_msix_bytes_with_provider</c>). Unsigned embedded <c>.msix</c> / <c>.appx</c>
    /// children of a bundle are signed first. <paramref name="timestamp"/> receives the PKCS#7 DER and returns the
    /// timestamped PKCS#7 (Rust <c>maybe_timestamp_pkcs7</c>); pass <c>null</c> to skip timestamping.
    /// </summary>
    public static byte[] SignBytes(
        byte[] package,
        string ext,
        AuthenticodeHashKind digest,
        CertificateInfo signerCert,
        IReadOnlyList<CertificateInfo> chainCerts,
        IDigestSigner signer,
        Func<byte[], byte[]>? timestamp = null,
        string label = "package")
    {
        ext = MsixDigest.AsciiLower(ext);
        var source = AppxPackage.IsMsixBundleExtension(ext) && BundleHasUnsignedEmbeddedChildren(package)
            ? SignUnsignedBundleChildren(package, digest, signerCert, chainCerts, signer, timestamp, label)
            : package;

        byte[] staged;
        try
        {
            staged = AppxPackage.StageMsixFamilyForSignature(source, ext, digest);
        }
        catch (PsignException e)
        {
            throw new PsignException($"stage {label} for MSIX signing", e);
        }

        var indirect = SpcIndirectData(staged, ext, digest);
        byte[] pkcs7;
        try
        {
            pkcs7 = Pkcs7Builder.CreateAuthenticode(indirect, digest, signerCert, chainCerts, signer);
        }
        catch (PsignException e)
        {
            throw new PsignException($"create portable MSIX Authenticode signature for {label}", e);
        }

        if (timestamp is not null)
        {
            try
            {
                pkcs7 = timestamp(pkcs7);
            }
            catch (PsignException e)
            {
                throw new PsignException($"timestamp {label}", e);
            }
        }

        try
        {
            return AppxPackage.ReplaceMsixSignaturePart(staged, ToP7x(pkcs7));
        }
        catch (PsignException e)
        {
            throw new PsignException($"embed AppxSignature.p7x in {label}", e);
        }
    }

    /// <summary>
    /// Sign a package file (Rust portable <c>sign_msix</c>). Returns <c>true</c> when the package was skipped because
    /// <paramref name="skipSigned"/> is set and it already carries <c>AppxSignature.p7x</c>.
    /// </summary>
    public static bool SignFile(
        string path,
        string outputPath,
        AuthenticodeHashKind digest,
        CertificateInfo signerCert,
        IReadOnlyList<CertificateInfo> chainCerts,
        IDigestSigner signer,
        bool skipSigned = false,
        Func<byte[], byte[]>? timestamp = null)
    {
        var rawExt = Path.GetExtension(path);
        var ext = MsixDigest.AsciiLower(string.IsNullOrEmpty(rawExt) ? string.Empty : rawExt[1..]);
        if (MsixDigest.IsEncryptedMsixExtension(ext))
        {
            throw new PsignException($"portable MSIX signing does not support encrypted packages (.{ext}); encrypted packages require Windows AppxSip OS delegation");
        }

        if (!AppxPackage.IsCleartextMsixFamilyExtension(ext))
        {
            throw new PsignException($"portable MSIX signing supports flat .msix/.appx packages and .msixbundle/.appxbundle bundles; got .{ext}");
        }

        byte[] package;
        try
        {
            package = File.ReadAllBytes(path);
        }
        catch (IOException e)
        {
            throw new PsignException($"read {path}", e);
        }

        if (skipSigned && MsixDigest.MsixSignaturePartPresent(package))
        {
            if (!string.Equals(Path.GetFullPath(outputPath), Path.GetFullPath(path), StringComparison.Ordinal))
            {
                File.Copy(path, outputPath, overwrite: true);
            }

            return true;
        }

        byte[] signed;
        try
        {
            signed = SignBytes(package, ext, digest, signerCert, chainCerts, signer, timestamp, path);
        }
        catch (PsignException e)
        {
            throw new PsignException($"sign MSIX/AppX {path}", e);
        }

        File.WriteAllBytes(outputPath, signed);
        return false;
    }

    private static string ChildExtension(string name)
    {
        int dot = name.LastIndexOf('.');
        return dot >= 0 ? MsixDigest.AsciiLower(name[(dot + 1)..]) : string.Empty;
    }

    private static ZipCrateArchive OpenBundle(byte[] package)
    {
        try
        {
            return ZipCrateArchive.Open(package);
        }
        catch (PsignException e)
        {
            throw new PsignException("open MSIX bundle ZIP", e);
        }
    }

    private static ZipCrateEntry ReadEntry(ZipCrateArchive archive, int i)
    {
        try
        {
            return archive.ByIndex(i);
        }
        catch (PsignException e)
        {
            throw new PsignException("read MSIX bundle ZIP entry", e);
        }
    }

    /// <summary>Whether a bundle embeds an unsigned <c>.msix</c> / <c>.appx</c> child (Rust <c>bundle_has_unsigned_embedded_children</c>).</summary>
    public static bool BundleHasUnsignedEmbeddedChildren(byte[] package)
    {
        var archive = OpenBundle(package);
        for (int i = 0; i < archive.Count; i++)
        {
            var entry = ReadEntry(archive, i);
            if (entry.IsDir)
            {
                continue;
            }

            if (ChildExtension(entry.Name) is "msix" or "appx")
            {
                var child = archive.Read(i);
                if (!MsixDigest.MsixSignaturePartPresent(child))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static byte[] SignUnsignedBundleChildren(
        byte[] package,
        AuthenticodeHashKind digest,
        CertificateInfo signerCert,
        IReadOnlyList<CertificateInfo> chainCerts,
        IDigestSigner signer,
        Func<byte[], byte[]>? timestamp,
        string label)
    {
        var archive = OpenBundle(package);
        var entries = new List<(string Name, byte[] Data)>();
        for (int i = 0; i < archive.Count; i++)
        {
            var entry = ReadEntry(archive, i);
            var name = entry.Name.Replace('\\', '/');
            if (name.EndsWith('/'))
            {
                continue;
            }

            var data = archive.Read(i);
            var childExt = ChildExtension(name);
            if (childExt is "msix" or "appx" && !MsixDigest.MsixSignaturePartPresent(data))
            {
                try
                {
                    data = SignBytes(data, childExt, digest, signerCert, chainCerts, signer, timestamp, label);
                }
                catch (PsignException e)
                {
                    throw new PsignException($"sign unsigned bundle child `{name}`", e);
                }
            }

            entries.Add((name, data));
        }

        return ZipCrateWriter.WriteStored(entries);
    }
}
