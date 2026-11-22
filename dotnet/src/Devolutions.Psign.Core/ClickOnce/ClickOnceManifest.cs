using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Xml;

namespace Devolutions.Psign.Core.ClickOnce;

/// <summary>ClickOnce <c>.deploy</c> payload info (Rust <c>ClickOnceDeployInfo</c>).</summary>
public sealed record ClickOnceDeployInfo(bool Deployed, string? ContentName, ulong Len);

/// <summary>File reference digest check (Rust <c>ClickOnceManifestHashEntry</c>).</summary>
public sealed record ClickOnceManifestHashEntry(
    string Path,
    AuthenticodeHashKind Algorithm,
    ulong? ExpectedSize,
    ulong ActualSize,
    string ExpectedDigestB64,
    string ActualDigestB64)
{
    /// <summary><c>valid</c> or <c>mismatch</c> (Rust <c>status()</c>).</summary>
    public string Status =>
        ExpectedSize is { } size && size != ActualSize ? "mismatch"
        : ExpectedDigestB64 == ActualDigestB64 ? "valid"
        : "mismatch";
}

/// <summary>A <c>&lt;file&gt;</c> / <c>&lt;dependentAssembly&gt;</c> reference and its text spans (Rust <c>ClickOnceManifestReference</c>).</summary>
public sealed record ClickOnceManifestReference(
    int TagStart,
    int TagEnd,
    string Path,
    ulong? Size,
    AuthenticodeHashKind Algorithm,
    string DigestValue,
    int DigestMethodTagStart,
    int DigestMethodTagEnd,
    int DigestValueContentStart,
    int DigestValueContentEnd);

/// <summary>Result of rewriting manifest hashes (Rust <c>UpdatedClickOnceManifest</c>).</summary>
public sealed record UpdatedClickOnceManifest(string Text, int Updated);

/// <summary>ClickOnce manifest signing / verification report (Rust <c>ClickOnceManifestSignatureReport</c>).</summary>
public sealed record ClickOnceManifestSignatureReport(AuthenticodeHashKind Digest, string ManifestDigestB64, int SignatureLen)
{
    /// <summary>Rust <c>format!("{:?}", digest)</c> (<c>Sha256</c>, <c>Sha384</c>, <c>Sha512</c>).</summary>
    public string DigestDebugName => ClickOnceManifest.DigestDebugName(Digest);

    /// <summary>Signer certificate bytes used for verification (embedded or supplied).</summary>
    public byte[]? SignerCertificate { get; init; }

    /// <summary>Anchor count returned by the trust hook when one was supplied.</summary>
    public int? TrustAnchorCount { get; init; }
}

/// <summary>
/// ClickOnce deployment manifest helpers (ported from the <c>clickonce_*</c> functions in Rust
/// <c>psign-digest-cli/src/main.rs</c> and <c>src/code.rs</c>): <c>.deploy</c> payloads, file reference hashes,
/// enveloped XMLDSig <c>SignedInfo</c> construction, signature assembly from an external signature, extraction and
/// cryptographic verification. RSA signing lives in <c>Devolutions.Psign.Signing.ClickOnce.ClickOnceSigner</c>;
/// certificate chain trust is supplied by the caller through a hook.
/// </summary>
public static class ClickOnceManifest
{
    // ---------------------------------------------------------------- deploy payloads

    /// <summary>Rust <c>inspect_clickonce_deploy_payload</c>.</summary>
    public static ClickOnceDeployInfo InspectDeployPayload(string path)
    {
        long len;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists)
            {
                throw new FileNotFoundException("The system cannot find the file specified.", path);
            }

            len = fi.Length;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"stat {path}", e);
        }

        string? contentName = DeployContentName(path);
        return new ClickOnceDeployInfo(contentName is not null, contentName, (ulong)len);
    }

    /// <summary>File name without the <c>.deploy</c> suffix, or <c>null</c> (Rust <c>clickonce_deploy_content_name</c>).</summary>
    public static string? DeployContentName(string path)
    {
        string fileName = System.IO.Path.GetFileName(path.TrimEnd('/', '\\'));
        if (fileName.Length == 0 || fileName == "." || fileName == "..")
        {
            return null;
        }

        if (!fileName.EndsWith(".deploy", StringComparison.Ordinal))
        {
            return null;
        }

        string name = fileName[..^".deploy".Length];
        return name.Length == 0 ? null : name;
    }

    /// <summary>Copy a <c>.deploy</c> payload and return the byte count (Rust <c>copy_clickonce_deploy_payload</c>).</summary>
    public static long CopyDeployPayload(string input, string output)
    {
        if (DeployContentName(input) is null)
        {
            throw new PsignException($"ClickOnce deploy payload name must end with .deploy: {input}");
        }

        try
        {
            File.Copy(input, output, overwrite: true);
            return new FileInfo(output).Length;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"copy {input} to {output}", e);
        }
    }

    // ---------------------------------------------------------------- file reference hashes

    /// <summary>Read a manifest as strict UTF-8 (Rust <c>read_to_string</c>; a BOM is kept as U+FEFF).</summary>
    public static string ReadManifestText(string path)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(File.ReadAllBytes(path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or DecoderFallbackException)
        {
            throw new PsignException($"read ClickOnce manifest {path}", e is DecoderFallbackException ? new PsignException("stream did not contain valid UTF-8") : e);
        }
    }

    private static string BaseDirectoryFor(string manifestPath, string? baseDirectory)
    {
        if (baseDirectory is not null)
        {
            return baseDirectory;
        }

        string? parent = System.IO.Path.GetDirectoryName(manifestPath);
        return string.IsNullOrEmpty(parent) ? "." : parent;
    }

    /// <summary>Rust <c>clickonce_manifest_hashes</c>.</summary>
    public static List<ClickOnceManifestHashEntry> ManifestHashes(string manifestPath, string? baseDirectory)
    {
        string text = ReadManifestText(manifestPath);
        return ManifestHashesFromText(text, BaseDirectoryFor(manifestPath, baseDirectory));
    }

    /// <summary>Recompute the digest of every referenced file (Rust <c>clickonce_manifest_hashes_from_text</c>).</summary>
    public static List<ClickOnceManifestHashEntry> ManifestHashesFromText(string text, string baseDirectory)
    {
        var entries = ReferenceSpans(text);
        var output = new List<ClickOnceManifestHashEntry>(entries.Count);
        foreach (var entry in entries)
        {
            string filePath = ResolveManifestPath(baseDirectory, entry.Path);
            byte[] bytes = ReadReferencedFile(filePath);
            output.Add(new ClickOnceManifestHashEntry(
                entry.Path,
                entry.Algorithm,
                entry.Size,
                (ulong)bytes.Length,
                entry.DigestValue,
                Convert.ToBase64String(entry.Algorithm.Hash(bytes))));
        }

        return output;
    }

    /// <summary>Rewrite hashes and write the manifest; returns the number of updated references (Rust <c>update_clickonce_manifest_hashes</c>).</summary>
    public static int UpdateManifestHashes(string manifestPath, string? baseDirectory, string output, AuthenticodeHashKind algorithm)
    {
        string text = ReadManifestText(manifestPath);
        var updated = UpdateManifestHashesInText(text, BaseDirectoryFor(manifestPath, baseDirectory), algorithm);
        try
        {
            File.WriteAllBytes(output, Encoding.UTF8.GetBytes(updated.Text));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"write ClickOnce manifest {output}", e);
        }

        return updated.Updated;
    }

    /// <summary>
    /// Rewrite every reference's <c>size</c>, <c>DigestMethod/@Algorithm</c> and <c>DigestValue</c> in place (Rust
    /// <c>update_clickonce_manifest_hashes_in_text</c>).
    /// </summary>
    public static UpdatedClickOnceManifest UpdateManifestHashesInText(string text, string baseDirectory, AuthenticodeHashKind algorithm)
    {
        var entries = ReferenceSpans(text);
        var replacements = new List<(int Start, int End, string Replacement)>(entries.Count * 3);
        foreach (var entry in entries)
        {
            string filePath = ResolveManifestPath(baseDirectory, entry.Path);
            byte[] bytes = ReadReferencedFile(filePath);
            byte[] digest = algorithm.Hash(bytes);
            string size = bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
            replacements.Add((entry.TagStart, entry.TagEnd + 1,
                XmlTextScan.ReplaceOrInsertXmlAttr(text[entry.TagStart..(entry.TagEnd + 1)], "size", size)));
            replacements.Add((entry.DigestMethodTagStart, entry.DigestMethodTagEnd + 1,
                XmlTextScan.ReplaceOrInsertXmlAttr(text[entry.DigestMethodTagStart..(entry.DigestMethodTagEnd + 1)], "Algorithm", DigestAlgorithmUri(algorithm))));
            replacements.Add((entry.DigestValueContentStart, entry.DigestValueContentEnd, Convert.ToBase64String(digest)));
        }

        replacements.Sort((a, b) => a.Start.CompareTo(b.Start));
        var sb = new StringBuilder(text.Length);
        int cursor = 0;
        foreach (var (start, end, replacement) in replacements)
        {
            if (start < cursor)
            {
                throw new PsignException("internal ClickOnce manifest replacement overlap");
            }

            sb.Append(text, cursor, start - cursor);
            sb.Append(replacement);
            cursor = end;
        }

        sb.Append(text, cursor, text.Length - cursor);
        return new UpdatedClickOnceManifest(sb.ToString(), entries.Count);
    }

    /// <summary><c>&lt;file name&gt;</c> and <c>&lt;dependentAssembly codebase&gt;</c> references in text order (Rust <c>clickonce_manifest_reference_spans</c>).</summary>
    public static List<ClickOnceManifestReference> ReferenceSpans(string text)
    {
        var refs = new List<ClickOnceManifestReference>();
        CollectReferences(text, "file", "name", refs);
        CollectReferences(text, "dependentAssembly", "codebase", refs);

        // Rust sort_by_key is stable.
        return refs.Select((r, i) => (r, i)).OrderBy(x => x.r.TagStart).ThenBy(x => x.i).Select(x => x.r).ToList();
    }

    private static void CollectReferences(string text, string tag, string pathAttr, List<ClickOnceManifestReference> refs)
    {
        int cursor = 0;
        while (XmlTextScan.FindXmlStartTag(text, tag, cursor) is { } start)
        {
            int tagEnd = text.IndexOf('>', start);
            if (tagEnd < 0)
            {
                throw new PsignException($"ClickOnce manifest <{tag}> tag is not closed");
            }

            string startTag = text[start..(tagEnd + 1)];
            cursor = tagEnd + 1;
            if (startTag.EndsWith("/>", StringComparison.Ordinal))
            {
                continue;
            }

            if (XmlTextScan.XmlAttr(startTag, pathAttr) is not { } path)
            {
                continue;
            }

            string close = $"</{tag}>";
            int closeStart = text.IndexOf(close, cursor, StringComparison.Ordinal);
            if (closeStart < 0)
            {
                continue;
            }

            int blockEnd = closeStart + close.Length;
            string block = text[(tagEnd + 1)..closeStart];
            if (XmlTextScan.FindXmlStartTagByLocalName(block, "DigestMethod", 0) is not { } method)
            {
                continue;
            }

            if (XmlTextScan.FindXmlElementByLocalName(block, "DigestValue", 0) is not { } value)
            {
                continue;
            }

            string methodTag = block[method.Start..(method.End + 1)];
            var algorithm = XmlTextScan.XmlAttr(methodTag, "Algorithm") is { } uri ? HashAlgFromUri(uri) : AuthenticodeHashKind.Sha256;
            ulong? size = null;
            if (XmlTextScan.XmlAttr(startTag, "size") is { } sizeText)
            {
                if (!ulong.TryParse(sizeText, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out var parsed)
                    || sizeText.StartsWith('-'))
                {
                    throw new PsignException("parse ClickOnce manifest size attribute", new PsignException(sizeText.Length == 0 ? "cannot parse integer from empty string" : "invalid digit found in string"));
                }

                size = parsed;
            }

            refs.Add(new ClickOnceManifestReference(
                start,
                tagEnd,
                path,
                size,
                algorithm,
                block[value.ContentStart..value.ContentEnd].Trim(),
                tagEnd + 1 + method.Start,
                tagEnd + 1 + method.End,
                tagEnd + 1 + value.ContentStart,
                tagEnd + 1 + value.ContentEnd));
            cursor = blockEnd;
        }
    }

    /// <summary>Join a manifest-relative path under the base directory, rejecting escapes (Rust <c>resolve_clickonce_manifest_path</c>).</summary>
    public static string ResolveManifestPath(string baseDirectory, string manifestPath)
    {
        var parts = new List<string>();
        bool windows = OperatingSystem.IsWindows();
        if (manifestPath.StartsWith('/') || (windows && (manifestPath.StartsWith('\\') || (manifestPath.Length >= 2 && manifestPath[1] == ':'))))
        {
            throw Escape(manifestPath);
        }

        var separators = windows ? new[] { '/', '\\' } : new[] { '/' };
        foreach (var component in manifestPath.Split(separators))
        {
            if (component.Length == 0 || component == ".")
            {
                continue;
            }

            if (component == "..")
            {
                throw Escape(manifestPath);
            }

            parts.Add(component);
        }

        if (parts.Count == 0)
        {
            throw new PsignException("ClickOnce manifest path is empty");
        }

        return System.IO.Path.Combine([baseDirectory, .. parts]);

        static PsignException Escape(string p) =>
            new($"ClickOnce manifest path must be relative and stay under the base directory: {p}");
    }

    private static byte[] ReadReferencedFile(string filePath)
    {
        try
        {
            return File.ReadAllBytes(filePath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read {filePath}", e);
        }
    }

    // ---------------------------------------------------------------- algorithms

    /// <summary>Rust <c>clickonce_hash_alg_from_uri</c>.</summary>
    public static AuthenticodeHashKind HashAlgFromUri(string uri) => uri switch
    {
        "http://www.w3.org/2000/09/xmldsig#sha1" => AuthenticodeHashKind.Sha1,
        "http://www.w3.org/2001/04/xmlenc#sha256" => AuthenticodeHashKind.Sha256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => AuthenticodeHashKind.Sha384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => AuthenticodeHashKind.Sha512,
        _ => throw new PsignException($"unsupported ClickOnce digest method Algorithm: {uri}"),
    };

    /// <summary>Rust <c>clickonce_digest_algorithm_uri</c>.</summary>
    public static string DigestAlgorithmUri(AuthenticodeHashKind algorithm) => algorithm switch
    {
        AuthenticodeHashKind.Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        AuthenticodeHashKind.Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        AuthenticodeHashKind.Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        AuthenticodeHashKind.Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>Rust <c>clickonce_signature_algorithm_uri</c> (SHA-2 only).</summary>
    public static string SignatureAlgorithmUri(AuthenticodeHashKind digest) => RequireSignDigest(digest) switch
    {
        AuthenticodeHashKind.Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        AuthenticodeHashKind.Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        _ => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    };

    /// <summary>Rust <c>clickonce_signature_digest_uri</c>.</summary>
    public static string SignatureDigestUri(AuthenticodeHashKind digest) => DigestAlgorithmUri(RequireSignDigest(digest));

    /// <summary>Lowercase label (Rust <c>hash_alg_label</c>).</summary>
    public static string HashAlgLabel(AuthenticodeHashKind algorithm) => algorithm.Name();

    /// <summary>Rust <c>{:?}</c> of <c>PortableSignDigest</c>.</summary>
    public static string DigestDebugName(AuthenticodeHashKind digest) => digest switch
    {
        AuthenticodeHashKind.Sha1 => "Sha1",
        AuthenticodeHashKind.Sha256 => "Sha256",
        AuthenticodeHashKind.Sha384 => "Sha384",
        AuthenticodeHashKind.Sha512 => "Sha512",
        _ => digest.ToString(),
    };

    /// <summary>Reject SHA-1 for XMLDSig signatures (the Rust <c>PortableSignDigest</c> enum has no SHA-1).</summary>
    public static AuthenticodeHashKind RequireSignDigest(AuthenticodeHashKind digest) =>
        digest == AuthenticodeHashKind.Sha1
            ? throw new PsignException("portable signing supports SHA-256, SHA-384, and SHA-512 digests only")
            : digest;

    // ---------------------------------------------------------------- XMLDSig

    /// <summary>Manifest text with the first <c>Signature</c> element removed (Rust <c>unsigned_clickonce_manifest_text</c>).</summary>
    public static string UnsignedManifestText(string text)
    {
        if (XmlTextScan.FindXmlElementSpanByLocalName(text, "Signature", 0) is not { } span)
        {
            return text;
        }

        return text[..span.Start] + text[span.End..];
    }

    /// <summary>Whether the manifest already contains a <c>Signature</c> element (Rust <c>clickonce_manifest_has_signature</c>).</summary>
    public static bool HasSignature(byte[] bytes)
    {
        try
        {
            string text = new UTF8Encoding(false, true).GetString(bytes);
            return XmlTextScan.FindXmlElementSpanByLocalName(text, "Signature", 0) is not null;
        }
        catch (Exception e) when (e is DecoderFallbackException or PsignException)
        {
            return false;
        }
    }

    /// <summary>Digest of the unsigned manifest UTF-8 octets.</summary>
    public static byte[] ManifestDigest(string unsignedManifestText, AuthenticodeHashKind digest) =>
        RequireSignDigest(digest).Hash(Encoding.UTF8.GetBytes(unsignedManifestText));

    /// <summary>Enveloped-signature <c>SignedInfo</c> over the unsigned manifest (Rust <c>clickonce_manifest_signed_info_xml</c>).</summary>
    public static byte[] SignedInfoXml(string unsignedManifestText, AuthenticodeHashKind digest)
    {
        string digestB64 = Convert.ToBase64String(ManifestDigest(unsignedManifestText, digest));
        return Encoding.UTF8.GetBytes(
            "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
            + $"<SignatureMethod Algorithm=\"{SignatureAlgorithmUri(digest)}\"/>"
            + "<Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms>"
            + $"<DigestMethod Algorithm=\"{SignatureDigestUri(digest)}\"/><DigestValue>{digestB64}</DigestValue></Reference></SignedInfo>");
    }

    /// <summary>Digest a remote signer must sign (Rust <c>clickonce_signed_info_remote_prehash</c>).</summary>
    public static byte[] SignedInfoRemotePrehash(AuthenticodeHashKind digest, byte[] signedInfo) => RequireSignDigest(digest).Hash(signedInfo);

    /// <summary>Prehash for the <c>clickonce-sign-manifest-prehash</c> flow (unsigned text → SignedInfo → digest).</summary>
    public static byte[] SignManifestPrehash(string manifestText, AuthenticodeHashKind digest) =>
        SignedInfoRemotePrehash(digest, SignedInfoXml(UnsignedManifestText(manifestText), digest));

    /// <summary><c>Signature</c> element with value and certificate (Rust <c>clickonce_manifest_signature_xml</c>).</summary>
    public static string SignatureXml(byte[] signedInfo, byte[] signature, byte[] certBytes)
    {
        string si = Encoding.UTF8.GetString(signedInfo);
        return $"<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">{si}<SignatureValue>{Convert.ToBase64String(signature)}</SignatureValue>"
            + $"<KeyInfo><X509Data><X509Certificate>{Convert.ToBase64String(certBytes)}</X509Certificate></X509Data></KeyInfo></Signature>";
    }

    /// <summary>Insert the signature before the root end tag (Rust <c>insert_clickonce_signature_xml</c>).</summary>
    public static string InsertSignatureXml(string unsignedManifestText, string signatureXml)
    {
        var root = XmlTextScan.FindXmlRootStartTag(unsignedManifestText);
        string close = $"</{root.Name}>";
        int closeStart = unsignedManifestText.LastIndexOf(close, StringComparison.Ordinal);
        if (closeStart < 0)
        {
            throw new PsignException($"ClickOnce manifest root </{root.Name}> tag is not closed");
        }

        return unsignedManifestText[..closeStart] + signatureXml + unsignedManifestText[closeStart..];
    }

    /// <summary>Document-form <c>SignedInfo</c> element octets (Rust <c>clickonce_signed_info_from_signature_xml</c>).</summary>
    public static byte[] SignedInfoFromSignatureXml(string signatureXml)
    {
        if (XmlTextScan.FindXmlElementSpanByLocalName(signatureXml, "SignedInfo", 0) is not { } span)
        {
            throw new PsignException("ClickOnce manifest signature is missing SignedInfo");
        }

        return Encoding.UTF8.GetBytes(signatureXml[span.Start..span.End]);
    }

    /// <summary>Decoded <c>SignatureValue</c> (Rust <c>clickonce_signature_value_from_signature_xml</c>).</summary>
    public static byte[] SignatureValueFromSignatureXml(string signatureXml)
    {
        var value = XmlTextScan.FindXmlElementByLocalName(signatureXml, "SignatureValue", 0)
            ?? throw new PsignException("ClickOnce manifest signature is missing SignatureValue");
        byte[] signature;
        try
        {
            signature = Base64Standard.DecodeXmlDsig(signatureXml[value.ContentStart..value.ContentEnd].Trim());
        }
        catch (PsignException e)
        {
            throw new PsignException("decode ClickOnce SignatureValue", e);
        }

        if (signature.Length == 0)
        {
            throw new PsignException("ClickOnce manifest SignatureValue is empty");
        }

        return signature;
    }

    /// <summary>Decoded <c>X509Certificate</c> (Rust <c>clickonce_signer_certificate_from_signature_xml</c>).</summary>
    public static byte[] SignerCertificateFromSignatureXml(string signatureXml)
    {
        var value = XmlTextScan.FindXmlElementByLocalName(signatureXml, "X509Certificate", 0)
            ?? throw new PsignException("ClickOnce manifest signature is missing X509Certificate");
        byte[] cert;
        try
        {
            cert = Base64Standard.DecodeXmlDsig(signatureXml[value.ContentStart..value.ContentEnd].Trim());
        }
        catch (PsignException e)
        {
            throw new PsignException("decode ClickOnce X509Certificate", e);
        }

        if (cert.Length == 0)
        {
            throw new PsignException("ClickOnce manifest X509Certificate is empty");
        }

        return cert;
    }

    /// <summary>
    /// Assemble a signed manifest from an externally produced RSA signature over <see cref="SignedInfoXml"/> (Rust
    /// <c>sign_clickonce_manifest_from_external_signature_path</c> without file I/O). <paramref name="certBytes"/> is
    /// embedded verbatim (DER, or PEM like the Rust tool) and must parse as a certificate.
    /// </summary>
    public static (string SignedManifest, ClickOnceManifestSignatureReport Report) AssembleSignedManifest(
        string manifestText,
        AuthenticodeHashKind digest,
        byte[] certBytes,
        byte[] signature,
        string certLabel = "certificate")
    {
        string unsigned = UnsignedManifestText(manifestText);
        try
        {
            CertificateLoader.ParseCertificate(certBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse signer certificate {certLabel}", e);
        }

        byte[] signedInfo = SignedInfoXml(unsigned, digest);
        string signatureXml = SignatureXml(signedInfo, signature, certBytes);
        string signed = InsertSignatureXml(unsigned, signatureXml);
        return (signed, new ClickOnceManifestSignatureReport(digest, Convert.ToBase64String(ManifestDigest(unsigned, digest)), signature.Length));
    }

    /// <summary>Rust <c>sign_clickonce_manifest_from_external_signature_path</c>.</summary>
    public static ClickOnceManifestSignatureReport SignManifestFromExternalSignaturePath(
        string path,
        string certPath,
        string signaturePath,
        AuthenticodeHashKind digest,
        string output)
    {
        string text = ReadManifestText(path);
        byte[] certBytes = ReadFile(certPath);
        string unsigned = UnsignedManifestText(text);
        try
        {
            CertificateLoader.ParseCertificate(certBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse signer certificate {certPath}", e);
        }

        byte[] signature = ReadFile(signaturePath);
        var (signed, report) = AssembleSignedManifest(unsigned, digest, certBytes, signature, certPath);
        WriteManifest(output, signed);
        return report;
    }

    /// <summary>
    /// Verify an embedded ClickOnce XMLDSig signature (Rust <c>verify_clickonce_manifest_signature_path</c>):
    /// <c>SignedInfo</c> must equal the one recomputed from the unsigned manifest, and the RSA PKCS#1 v1.5
    /// <c>SignatureValue</c> must verify with the supplied or embedded certificate. Certificate chain trust is delegated
    /// to <paramref name="verifySignerTrust"/> (returns the anchor count), called only when provided.
    /// </summary>
    public static ClickOnceManifestSignatureReport VerifyManifestSignature(
        string manifestText,
        AuthenticodeHashKind digest,
        byte[]? certBytes = null,
        Func<byte[], int>? verifySignerTrust = null)
    {
        string unsigned = UnsignedManifestText(manifestText);
        var span = XmlTextScan.FindXmlElementSpanByLocalName(manifestText, "Signature", 0)
            ?? throw new PsignException("ClickOnce manifest is missing XMLDSig Signature");
        string signatureXml = manifestText[span.Start..span.End];
        byte[] signedInfo = SignedInfoFromSignatureXml(signatureXml);
        byte[] signature = SignatureValueFromSignatureXml(signatureXml);
        byte[] embeddedCert = SignerCertificateFromSignatureXml(signatureXml);
        byte[] signerBytes = certBytes ?? embeddedCert;
        CertificateInfo signerCert;
        try
        {
            signerCert = CertificateLoader.ParseCertificate(signerBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException("parse ClickOnce signer certificate", e);
        }

        byte[] expectedSignedInfo = SignedInfoXml(unsigned, digest);
        if (!signedInfo.AsSpan().SequenceEqual(expectedSignedInfo))
        {
            throw new PsignException("ClickOnce manifest SignedInfo does not match manifest digest");
        }

        VerifySignedInfo(digest, signerCert, signedInfo, signature, "ClickOnce");
        int? anchors = verifySignerTrust?.Invoke(signerBytes);
        return new ClickOnceManifestSignatureReport(digest, Convert.ToBase64String(ManifestDigest(unsigned, digest)), signature.Length)
        {
            SignerCertificate = signerBytes,
            TrustAnchorCount = anchors,
        };
    }

    /// <summary>Path form of <see cref="VerifyManifestSignature"/>.</summary>
    public static ClickOnceManifestSignatureReport VerifyManifestSignaturePath(
        string path,
        string? certPath,
        AuthenticodeHashKind digest,
        Func<byte[], int>? verifySignerTrust = null)
    {
        string text = ReadManifestText(path);
        byte[]? cert = certPath is null ? null : ReadFile(certPath);
        return VerifyManifestSignature(text, digest, cert, verifySignerTrust);
    }

    /// <summary>
    /// RSA PKCS#1 v1.5 verification of <paramref name="signedInfo"/> (Rust <c>verify_clickonce_signed_info</c> /
    /// <c>verify_xml_signed_info</c>); <paramref name="label"/> is <c>ClickOnce</c> or <c>VSIX</c>.
    /// </summary>
    public static void VerifySignedInfo(AuthenticodeHashKind digest, CertificateInfo signerCert, byte[] signedInfo, byte[] signature, string label)
    {
        RSA rsa;
        try
        {
            rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(signerCert.SubjectPublicKeyInfo, out _);
            if (signerCert.PublicKeyAlgorithm.Oid != Oids.RsaEncryption)
            {
                throw new CryptographicException("unknown/unsupported algorithm OID");
            }
        }
        catch (CryptographicException e)
        {
            throw new PsignException($"RSA public key from signer certificate: {e.Message}");
        }

        using (rsa)
        {
            bool ok;
            try
            {
                ok = rsa.VerifyData(signedInfo, signature, RequireSignDigest(digest).HashAlgorithmName(), RSASignaturePadding.Pkcs1);
            }
            catch (CryptographicException)
            {
                ok = false;
            }

            if (!ok)
            {
                throw new PsignException($"verify {label} SignatureValue: signature error: verification error");
            }
        }
    }

    internal static byte[] ReadFile(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read {path}", e);
        }
    }

    internal static void WriteManifest(string output, string text)
    {
        try
        {
            File.WriteAllBytes(output, Encoding.UTF8.GetBytes(text));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"write ClickOnce manifest {output}", e);
        }
    }
}
