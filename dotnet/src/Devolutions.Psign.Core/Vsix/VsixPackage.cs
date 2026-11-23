using System.Text;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Core.Vsix;

/// <summary>VSIX reference / signature digest algorithm (Rust <c>vsix::VsixHashAlgorithm</c>).</summary>
public enum VsixHashAlgorithm
{
    Sha256,
    Sha384,
    Sha512,
}

/// <summary>Helpers for <see cref="VsixHashAlgorithm"/>.</summary>
public static class VsixHashAlgorithmExtensions
{
    /// <summary>XMLDSig <c>DigestMethod</c> URI.</summary>
    public static string DigestUri(this VsixHashAlgorithm algorithm) => algorithm switch
    {
        VsixHashAlgorithm.Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        VsixHashAlgorithm.Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        VsixHashAlgorithm.Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>XMLDSig <c>SignatureMethod</c> URI (RSA PKCS#1 v1.5).</summary>
    public static string SignatureUri(this VsixHashAlgorithm algorithm) => algorithm switch
    {
        VsixHashAlgorithm.Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        VsixHashAlgorithm.Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        VsixHashAlgorithm.Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>One-shot digest.</summary>
    public static byte[] Hash(this VsixHashAlgorithm algorithm, ReadOnlySpan<byte> bytes) => algorithm.ToHashKind().Hash(bytes);

    /// <summary>Equivalent <see cref="AuthenticodeHashKind"/>.</summary>
    public static AuthenticodeHashKind ToHashKind(this VsixHashAlgorithm algorithm) => algorithm switch
    {
        VsixHashAlgorithm.Sha256 => AuthenticodeHashKind.Sha256,
        VsixHashAlgorithm.Sha384 => AuthenticodeHashKind.Sha384,
        VsixHashAlgorithm.Sha512 => AuthenticodeHashKind.Sha512,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>CLI label (Rust <c>vsix_hash_alg_label</c>).</summary>
    public static string Label(this VsixHashAlgorithm algorithm) => algorithm.ToHashKind().Name();

    /// <summary>Map a SHA-2 hash kind (SHA-1 is rejected).</summary>
    public static VsixHashAlgorithm FromHashKind(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha256 => VsixHashAlgorithm.Sha256,
        AuthenticodeHashKind.Sha384 => VsixHashAlgorithm.Sha384,
        AuthenticodeHashKind.Sha512 => VsixHashAlgorithm.Sha512,
        _ => throw new PsignException("VSIX signing supports SHA-256, SHA-384, and SHA-512 only"),
    };
}

/// <summary>VSIX OPC signature marker info (Rust <c>vsix::VsixPackageInfo</c>).</summary>
public sealed record VsixPackageInfo(PackageSummary Package, bool HasOpcSignature);

/// <summary><c>SignatureTime</c> source (Rust <c>vsix::VsixSigningTime</c>).</summary>
public enum VsixSigningTime
{
    /// <summary>Current UTC time, for one-shot signing.</summary>
    Now,

    /// <summary>Newest ZIP entry modification time, so split prehash / from-signature steps produce identical <c>SignedInfo</c>.</summary>
    FromPackage,
}

/// <summary>
/// OPC package signature ready to be signed, in the <c>System.IO.Packaging</c> layout (Rust
/// <c>vsix::VsixSignatureTemplate</c>). <see cref="SignedInfo"/> is the exact canonical octet string the RSA
/// signature covers.
/// </summary>
public sealed class VsixSignatureTemplate
{
    internal VsixSignatureTemplate(byte[] signedInfo, string signedInfoInDocument, string objectInDocument, int references)
    {
        SignedInfo = signedInfo;
        SignedInfoInDocument = signedInfoInDocument;
        ObjectInDocument = objectInDocument;
        ReferenceCount = references;
    }

    /// <summary>Canonical <c>SignedInfo</c> octets to sign.</summary>
    public byte[] SignedInfo { get; }

    /// <summary><c>SignedInfo</c> element as written inside the signature document.</summary>
    public string SignedInfoInDocument { get; }

    /// <summary>Package <c>Object</c> element as written inside the signature document.</summary>
    public string ObjectInDocument { get; }

    /// <summary>Number of package parts referenced by the manifest.</summary>
    public int ReferenceCount { get; }

    /// <summary>Signature part XML carrying <paramref name="signatureValue"/> (Rust <c>signature_xml</c>).</summary>
    public string SignatureXml(ReadOnlySpan<byte> signatureValue, byte[]? signerCertDer)
    {
        var xml = new StringBuilder();
        xml.Append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
        xml.Append("<Signature Id=\"SignatureIdValue\" xmlns=\"").Append(VsixPackage.XmlDsigNs).Append("\">");
        xml.Append(SignedInfoInDocument);
        xml.Append("<SignatureValue>").Append(Convert.ToBase64String(signatureValue)).Append("</SignatureValue>");
        if (signerCertDer is not null)
        {
            xml.Append("<KeyInfo><X509Data><X509Certificate>");
            xml.Append(Convert.ToBase64String(signerCertDer));
            xml.Append("</X509Certificate></X509Data></KeyInfo>");
        }

        xml.Append(ObjectInDocument);
        xml.Append("</Signature>");
        return xml.ToString();
    }

    /// <summary>UTF-8 bytes of <see cref="SignatureXml"/>.</summary>
    public byte[] SignatureXmlBytes(ReadOnlySpan<byte> signatureValue, byte[]? signerCertDer) =>
        Encoding.UTF8.GetBytes(SignatureXml(signatureValue, signerCertDer));
}

/// <summary>
/// Portable VSIX (OPC XML digital signature) package primitives (port of Rust <c>psign-opc-sign/src/vsix.rs</c>):
/// signature templates, reference verification, extraction and embedding of signature XML.
/// </summary>
public static class VsixPackage
{
    public const string DefaultVsixSignaturePart = "package/services/digital-signature/xml-signature/psign-signature.psdsxs";
    public const string OpcSignatureOriginRelsPart = "package/services/digital-signature/_rels/origin.psdsor.rels";
    public const string OpcSignatureOriginContentType = "application/vnd.openxmlformats-package.digital-signature-origin";
    public const string OpcSignatureXmlContentType = "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml";
    public const string OpcSignatureOriginRelType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
    public const string OpcSignatureRelType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";
    public const string XmlDsigNs = "http://www.w3.org/2000/09/xmldsig#";
    public const string OpcDigitalSignatureNs = "http://schemas.openxmlformats.org/package/2006/digital-signature";
    public const string C14nUri = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    public const string XmlDsigObjectType = "http://www.w3.org/2000/09/xmldsig#Object";
    public const string RelationshipsContentType = "application/vnd.openxmlformats-package.relationships+xml";

    /// <summary>OPC <c>SignatureTime/Format</c> value.</summary>
    public const string VsixSignatureTimeFormat = "YYYY-MM-DDThh:mm:ss.sTZD";

    // ---------------------------------------------------------------- inspection

    /// <summary>Rust <c>inspect_vsix_path</c>.</summary>
    public static VsixPackageInfo InspectVsixPath(string path) => FromSummary(OpcPackage.InspectPackagePath(path));

    /// <summary>Inspect VSIX bytes.</summary>
    public static VsixPackageInfo InspectVsix(byte[] package) => FromSummary(OpcPackage.InspectPackage(package));

    private static VsixPackageInfo FromSummary(PackageSummary package) =>
        new(package, package.HasOpcSignatureOrigin || package.OpcSignatureParts.Count > 0);

    // ---------------------------------------------------------------- templates

    /// <summary>Rust <c>signature_reference_xml_path</c>.</summary>
    public static byte[] SignatureReferenceXmlPath(string path, VsixHashAlgorithm algorithm) =>
        WithPath(path, $"create VSIX signature reference XML for {path}", b => SignatureReferenceXml(b, algorithm));

    /// <summary>Unsigned signature skeleton (empty <c>SignatureValue</c>) (Rust <c>signature_reference_xml</c>).</summary>
    public static byte[] SignatureReferenceXml(byte[] package, VsixHashAlgorithm algorithm) =>
        SignatureTemplate(package, algorithm, VsixSigningTime.FromPackage).SignatureXmlBytes([], null);

    /// <summary>Rust <c>signed_info_xml_path</c>.</summary>
    public static byte[] SignedInfoXmlPath(string path, VsixHashAlgorithm algorithm) =>
        WithPath(path, $"create VSIX SignedInfo XML for {path}", b => SignedInfoXml(b, algorithm));

    /// <summary>Canonical <c>SignedInfo</c> octets with a package-derived signing time (Rust <c>signed_info_xml</c>).</summary>
    public static byte[] SignedInfoXml(byte[] package, VsixHashAlgorithm algorithm) =>
        SignatureTemplate(package, algorithm, VsixSigningTime.FromPackage).SignedInfo;

    /// <summary>Complete signature XML with a package-derived signing time (Rust <c>signature_xml_path</c>).</summary>
    public static byte[] SignatureXmlPath(string path, VsixHashAlgorithm algorithm, byte[] signatureValue, byte[]? signerCertDer) =>
        SignatureTemplatePath(path, algorithm, VsixSigningTime.FromPackage).SignatureXmlBytes(signatureValue, signerCertDer);

    /// <summary>Build the OPC signature template for a package (Rust <c>signature_template</c>).</summary>
    /// <param name="package">Unsigned or re-signed VSIX bytes.</param>
    /// <param name="algorithm">Digest algorithm.</param>
    /// <param name="signingTime">Signing time source.</param>
    /// <param name="now">Override for <see cref="VsixSigningTime.Now"/> (defaults to the current UTC time).</param>
    public static VsixSignatureTemplate SignatureTemplate(byte[] package, VsixHashAlgorithm algorithm, VsixSigningTime signingTime, DateTimeOffset? now = null)
    {
        var prepared = WriteSignedPackage(package, null, overwrite: true);
        var archive = NuGetPackage.OpenZip(prepared, "open prepared VSIX ZIP");
        string timeValue = signingTime == VsixSigningTime.Now
            ? SignatureTimeValue(now ?? DateTimeOffset.UtcNow)
            : PackageSignatureTimeValue(archive);
        return TemplateFromPrepared(archive, algorithm, timeValue);
    }

    /// <summary>Rust <c>signature_template_path</c>.</summary>
    public static VsixSignatureTemplate SignatureTemplatePath(string path, VsixHashAlgorithm algorithm, VsixSigningTime signingTime, DateTimeOffset? now = null) =>
        WithPath(path, $"create VSIX signature for {path}", b => SignatureTemplate(b, algorithm, signingTime, now));

    /// <summary><c>SignatureTime/Value</c> text (<c>yyyy-MM-ddTHH:mm:ss.f+00:00</c>, UTC).</summary>
    public static string SignatureTimeValue(DateTimeOffset time)
    {
        var t = time.ToUniversalTime();
        return $"{t.Year:D4}-{t.Month:D2}-{t.Day:D2}T{t.Hour:D2}:{t.Minute:D2}:{t.Second:D2}.{t.Millisecond / 100}+00:00";
    }

    private static string PackageSignatureTimeValue(ZipCrateArchive archive)
    {
        ZipDateTime? newest = null;
        foreach (var file in archive.Entries)
        {
            var d = file.LastModified;
            if (newest is null || d.SortKey > newest.Value.SortKey)
            {
                newest = d;
            }
        }

        var n = newest ?? ZipDateTime.Default;
        return $"{n.Year:D4}-{n.Month:D2}-{n.Day:D2}T{n.Hour:D2}:{n.Minute:D2}:{n.Second:D2}.0+00:00";
    }

    private static VsixSignatureTemplate TemplateFromPrepared(ZipCrateArchive archive, VsixHashAlgorithm algorithm, string timeValue)
    {
        var contentTypesEntry = archive.ByName(OpcPackage.ContentTypesPart)
            ?? throw new PsignException("prepared VSIX has no [Content_Types].xml", new PsignException("specified file not found in archive"));
        var contentTypes = ContentTypes.Parse(archive.Read(contentTypesEntry));

        var manifest = new StringBuilder("<Manifest>");
        int references = 0;
        foreach (var file in archive.Entries)
        {
            try
            {
                archive.EnsureReadable(file);
            }
            catch (PsignException e)
            {
                throw new PsignException("read VSIX ZIP entry", e);
            }

            string name = OpcPackage.NormalizeZipPartName(file.Name);
            if (file.IsDir || name == OpcPackage.ContentTypesPart || name == DefaultVsixSignaturePart)
            {
                continue;
            }

            string contentType = contentTypes.ForPart(name)
                ?? throw new PsignException($"VSIX part /{name} has no content type in [Content_Types].xml");
            var bytes = archive.Read(file);
            manifest.Append("<Reference URI=\"").Append(C14nAttr($"/{name}?ContentType={contentType}")).Append("\">");
            manifest.Append("<DigestMethod Algorithm=\"").Append(algorithm.DigestUri()).Append("\"></DigestMethod>");
            manifest.Append("<DigestValue>").Append(Convert.ToBase64String(algorithm.Hash(bytes))).Append("</DigestValue></Reference>");
            references++;
        }

        if (references == 0)
        {
            throw new PsignException("VSIX package has no parts to sign");
        }

        manifest.Append("</Manifest>");

        string objectBody = manifest
            + "<SignatureProperties>"
            + "<SignatureProperty Id=\"idSignatureTime\" Target=\"#SignatureIdValue\">"
            + $"<SignatureTime xmlns=\"{OpcDigitalSignatureNs}\"><Format>{VsixSignatureTimeFormat}</Format><Value>{C14nText(timeValue)}</Value></SignatureTime>"
            + "</SignatureProperty></SignatureProperties></Object>";
        string objectCanonical = $"<Object xmlns=\"{XmlDsigNs}\" Id=\"idPackageObject\">{objectBody}";
        string objectInDocument = DocumentForm($"<Object Id=\"idPackageObject\">{objectBody}");

        string signedInfoBody =
            $"<CanonicalizationMethod Algorithm=\"{C14nUri}\"></CanonicalizationMethod>"
            + $"<SignatureMethod Algorithm=\"{algorithm.SignatureUri()}\"></SignatureMethod>"
            + $"<Reference Type=\"{XmlDsigObjectType}\" URI=\"#idPackageObject\">"
            + $"<DigestMethod Algorithm=\"{algorithm.DigestUri()}\"></DigestMethod><DigestValue>{Convert.ToBase64String(algorithm.Hash(Encoding.UTF8.GetBytes(objectCanonical)))}</DigestValue>"
            + "</Reference></SignedInfo>";

        return new VsixSignatureTemplate(
            Encoding.UTF8.GetBytes($"<SignedInfo xmlns=\"{XmlDsigNs}\">{signedInfoBody}"),
            DocumentForm($"<SignedInfo>{signedInfoBody}"),
            objectInDocument,
            references);
    }

    // ---------------------------------------------------------------- verification of references

    /// <summary>Rust <c>verify_signature_reference_xml_path</c>.</summary>
    public static int VerifySignatureReferenceXmlPath(string path, byte[] signatureXml, VsixHashAlgorithm algorithm) =>
        WithPath(path, $"verify VSIX signature references for {path}", b => VerifySignatureReferenceXml(b, signatureXml, algorithm));

    /// <summary>
    /// Check that <paramref name="signatureXml"/> carries the <c>SignedInfo</c> and package <c>Object</c> this package
    /// produces with the same signing time; returns the number of referenced parts (Rust
    /// <c>verify_signature_reference_xml</c>).
    /// </summary>
    public static int VerifySignatureReferenceXml(byte[] package, byte[] signatureXml, VsixHashAlgorithm algorithm)
    {
        string text = Utf8(signatureXml, "VSIX signature XML is not UTF-8");
        int timeStart = text.IndexOf("<SignatureTime", StringComparison.Ordinal);
        if (timeStart < 0)
        {
            throw new PsignException("VSIX signature XML has no SignatureTime");
        }

        string timeValue = ElementText(text[timeStart..], "Value")
            ?? throw new PsignException("VSIX signature XML SignatureTime has no Value");
        var prepared = WriteSignedPackage(package, null, overwrite: true);
        var archive = NuGetPackage.OpenZip(prepared, "open prepared VSIX ZIP");
        var template = TemplateFromPrepared(archive, algorithm, timeValue);
        if (!text.Contains(template.ObjectInDocument, StringComparison.Ordinal))
        {
            throw new PsignException("VSIX signature manifest digest mismatch: package parts differ from the signed manifest");
        }

        if (!text.Contains(template.SignedInfoInDocument, StringComparison.Ordinal))
        {
            throw new PsignException("VSIX SignedInfo digest mismatch");
        }

        return template.ReferenceCount;
    }

    /// <summary>
    /// Part digests of a signature written by psign releases before the OPC layout (Rust
    /// <c>verify_legacy_signature_reference_xml</c>).
    /// </summary>
    public static int VerifyLegacySignatureReferenceXml(byte[] package, byte[] signatureXml, VsixHashAlgorithm algorithm)
    {
        var expected = LegacyReferenceDigests(package, algorithm);
        var actual = ParseLegacyReferenceDigests(signatureXml, algorithm);
        if (actual.Count != expected.Count)
        {
            throw new PsignException($"VSIX signature reference count mismatch: expected {expected.Count}, found {actual.Count}");
        }

        foreach (var (name, digest) in expected)
        {
            if (!actual.TryGetValue(name, out var actualDigest))
            {
                throw new PsignException($"VSIX signature reference missing for {name}");
            }

            if (!actualDigest.AsSpan().SequenceEqual(digest))
            {
                throw new PsignException($"VSIX signature reference digest mismatch for {name}");
            }
        }

        return expected.Count;
    }

    private static SortedDictionary<string, byte[]> LegacyReferenceDigests(byte[] package, VsixHashAlgorithm algorithm)
    {
        var archive = NuGetPackage.OpenZip(package, "open VSIX ZIP");
        var references = new SortedDictionary<string, byte[]>(Utf8Ordinal.Comparer);
        foreach (var file in archive.Entries)
        {
            EnsureReadable(archive, file);
            string name = OpcPackage.NormalizeZipPartName(file.Name);
            if (file.IsDir || name == OpcPackage.ContentTypesPart || name == OpcPackage.RootRelationshipsPart || IsOpcSignatureEntry(name))
            {
                continue;
            }

            references[name] = algorithm.Hash(archive.Read(file));
        }

        return references;
    }

    private static SortedDictionary<string, byte[]> ParseLegacyReferenceDigests(byte[] signatureXml, VsixHashAlgorithm algorithm)
    {
        string text = Utf8(signatureXml, "VSIX signature XML is not UTF-8");
        var references = new SortedDictionary<string, byte[]>(Utf8Ordinal.Comparer);
        int cursor = 0;
        while (true)
        {
            int referenceStart = text.IndexOf("<Reference ", cursor, StringComparison.Ordinal);
            if (referenceStart < 0)
            {
                break;
            }

            int tagEnd = text.IndexOf('>', referenceStart);
            if (tagEnd < 0)
            {
                throw new PsignException("VSIX signature XML Reference tag is not closed");
            }

            int closeStart = text.IndexOf("</Reference>", tagEnd, StringComparison.Ordinal);
            if (closeStart < 0)
            {
                throw new PsignException("VSIX signature XML Reference element is not closed");
            }

            string tag = text[referenceStart..(tagEnd + 1)];
            string body = text[(tagEnd + 1)..closeStart];
            string uri = XmlAttr(tag, "URI") ?? throw new PsignException("VSIX signature XML Reference is missing URI");
            if (!uri.StartsWith('/'))
            {
                throw new PsignException("VSIX signature XML Reference URI must be package-absolute");
            }

            string name = OpcPackage.NormalizeZipPartName(uri[1..]);
            if (!body.Contains($"<DigestMethod Algorithm=\"{algorithm.DigestUri()}\"/>", StringComparison.Ordinal))
            {
                throw new PsignException($"VSIX signature XML Reference for {name} does not use expected digest algorithm");
            }

            string digestValue = ElementText(body, "DigestValue")
                ?? throw new PsignException($"VSIX signature XML Reference for {name} is missing DigestValue");
            byte[] digest;
            try
            {
                digest = Base64Standard.Decode(digestValue);
            }
            catch (FormatException e)
            {
                throw new PsignException("VSIX signature XML DigestValue is not valid base64", e);
            }

            if (!references.TryAdd(name, digest))
            {
                throw new PsignException($"duplicate VSIX signature XML Reference for {name}");
            }

            cursor = closeStart + "</Reference>".Length;
        }

        return references;
    }

    // ---------------------------------------------------------------- extraction

    /// <summary>Rust <c>extract_signature_xml_path</c>.</summary>
    public static byte[] ExtractSignatureXmlPath(string path)
    {
        var bytes = NuGetPackage.ReadFileForOpen(path);
        try
        {
            return ExtractSignatureXml(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"extract VSIX signature XML from {path}", e);
        }
    }

    /// <summary>The single OPC signature XML part (Rust <c>extract_signature_xml</c>).</summary>
    public static byte[] ExtractSignatureXml(byte[] package)
    {
        var archive = NuGetPackage.OpenZip(package, "open VSIX ZIP");
        string? signaturePart = null;
        foreach (var file in archive.Entries)
        {
            EnsureReadable(archive, file);
            string name = OpcPackage.NormalizeZipPartName(file.Name);
            if (!file.IsDir && name.StartsWith(OpcPackage.OpcSignaturesPrefix, StringComparison.Ordinal))
            {
                if (signaturePart is not null)
                {
                    throw new PsignException("VSIX package contains multiple OPC signature XML parts");
                }

                signaturePart = name;
            }
        }

        if (signaturePart is null)
        {
            throw new PsignException("VSIX package does not contain OPC signature XML");
        }

        var entry = archive.ByName(signaturePart)
            ?? throw new PsignException($"read VSIX signature XML part {signaturePart}", new PsignException("specified file not found in archive"));
        byte[] xml;
        try
        {
            xml = archive.Read(entry);
        }
        catch (PsignException e)
        {
            throw new PsignException("read VSIX signature XML", e);
        }

        if (xml.Length == 0)
        {
            throw new PsignException("VSIX signature XML payload is empty");
        }

        return xml;
    }

    /// <summary>Document-form <c>SignedInfo</c> element (Rust <c>signed_info_xml_from_signature_xml</c>).</summary>
    public static byte[] SignedInfoXmlFromSignatureXml(byte[] signatureXml)
    {
        string text = Utf8(signatureXml, "VSIX signature XML is not UTF-8");
        int start = text.IndexOf("<SignedInfo>", StringComparison.Ordinal);
        if (start < 0)
        {
            throw new PsignException("VSIX signature XML is missing SignedInfo");
        }

        int close = text.IndexOf("</SignedInfo>", start, StringComparison.Ordinal);
        if (close < 0)
        {
            throw new PsignException("VSIX signature XML SignedInfo element is not closed");
        }

        return Encoding.UTF8.GetBytes(text[start..(close + "</SignedInfo>".Length)]);
    }

    /// <summary>Decoded <c>SignatureValue</c> (Rust <c>signature_value_from_signature_xml</c>).</summary>
    public static byte[] SignatureValueFromSignatureXml(byte[] signatureXml)
    {
        string text = Utf8(signatureXml, "VSIX signature XML is not UTF-8");
        string value = ElementText(text, "SignatureValue") ?? throw new PsignException("VSIX signature XML is missing SignatureValue");
        byte[] signature;
        try
        {
            signature = Base64Standard.Decode(value);
        }
        catch (FormatException e)
        {
            throw new PsignException("VSIX SignatureValue is not valid base64", e);
        }

        if (signature.Length == 0)
        {
            throw new PsignException("VSIX SignatureValue is empty");
        }

        return signature;
    }

    /// <summary>Decoded <c>X509Certificate</c> (Rust <c>signer_certificate_from_signature_xml</c>).</summary>
    public static byte[] SignerCertificateFromSignatureXml(byte[] signatureXml)
    {
        string text = Utf8(signatureXml, "VSIX signature XML is not UTF-8");
        string value = ElementText(text, "X509Certificate") ?? throw new PsignException("VSIX signature XML is missing X509Certificate");
        byte[] cert;
        try
        {
            cert = Base64Standard.Decode(value);
        }
        catch (FormatException e)
        {
            throw new PsignException("VSIX X509Certificate is not valid base64", e);
        }

        if (cert.Length == 0)
        {
            throw new PsignException("VSIX X509Certificate is empty");
        }

        return cert;
    }

    // ---------------------------------------------------------------- embedding

    /// <summary>Rust <c>embed_signature_xml_path</c>.</summary>
    public static void EmbedSignatureXmlPath(string input, string output, byte[] signatureXml, bool overwrite)
    {
        if (signatureXml.Length == 0)
        {
            throw new PsignException("VSIX signature XML payload is empty");
        }

        var info = InspectVsixPath(input);
        if (info.HasOpcSignature && !overwrite)
        {
            throw new PsignException($"{input} already contains OPC signature parts; pass overwrite to replace them");
        }

        var bytes = NuGetPackage.ReadFileForOpen(input);
        byte[] signed;
        try
        {
            signed = EmbedSignatureXml(bytes, signatureXml, overwrite);
        }
        catch (PsignException e)
        {
            throw new PsignException($"embed VSIX signature XML into {output}", e);
        }

        try
        {
            File.WriteAllBytes(output, signed);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"create {output}", e);
        }
    }

    /// <summary>
    /// Embed <paramref name="signatureXml"/> as the OPC signature part with the signature origin and relationships
    /// (Rust <c>embed_signature_xml</c>).
    /// </summary>
    public static byte[] EmbedSignatureXml(byte[] package, byte[] signatureXml, bool overwrite)
    {
        if (signatureXml.Length == 0)
        {
            throw new PsignException("VSIX signature XML payload is empty");
        }

        return WriteSignedPackage(package, signatureXml, overwrite);
    }

    /// <summary>
    /// Copy the package with the OPC signature infrastructure and, when given, the signature part (Rust
    /// <c>write_signed_package</c>). Exposed for the trust verifier, which digests the prepared package.
    /// </summary>
    public static byte[] WriteSignedPackage(byte[] package, byte[]? signatureXml, bool overwrite)
    {
        var input = NuGetPackage.OpenZip(package, "open VSIX ZIP");
        var output = new ZipCrateWriter();
        bool hadSignature = false;
        bool wroteContentTypes = false;
        bool wroteRootRelationships = false;

        foreach (var file in input.Entries)
        {
            EnsureReadable(input, file);
            string name = OpcPackage.NormalizeZipPartName(file.Name);
            if (IsOpcSignatureEntry(name))
            {
                hadSignature = true;
                if (overwrite)
                {
                    continue;
                }

                throw new PsignException("package already contains OPC signature parts; pass overwrite to replace them");
            }

            if (file.IsDir)
            {
                output.AddDirectory(name);
            }
            else
            {
                var bytes = input.Read(file);
                if (name == OpcPackage.ContentTypesPart)
                {
                    wroteContentTypes = true;
                    bytes = EnsureSignatureContentTypes(bytes);
                }
                else if (name == OpcPackage.RootRelationshipsPart)
                {
                    wroteRootRelationships = true;
                    bytes = EnsureRootSignatureOriginRelationship(bytes);
                }

                output.StartFile(name, bytes, file.CompressionMethod);
            }
        }

        if (!hadSignature || overwrite)
        {
            if (!wroteContentTypes)
            {
                output.StartFile(OpcPackage.ContentTypesPart, EnsureSignatureContentTypes([]), ZipCrateWriter.Stored);
            }

            if (!wroteRootRelationships)
            {
                output.StartFile(OpcPackage.RootRelationshipsPart, EnsureRootSignatureOriginRelationship([]), ZipCrateWriter.Stored);
            }

            output.StartFile(OpcPackage.OpcSignatureOriginPart, [], ZipCrateWriter.Stored);
            output.StartFile(OpcSignatureOriginRelsPart, SignatureOriginRelationshipsXml(), ZipCrateWriter.Stored);
            if (signatureXml is not null)
            {
                output.StartFile(DefaultVsixSignaturePart, signatureXml, ZipCrateWriter.Stored);
            }
        }

        return output.Finish();
    }

    /// <summary>OPC signature entries (origin, origin relationships, signature parts).</summary>
    public static bool IsOpcSignatureEntry(string name) =>
        name == OpcPackage.OpcSignatureOriginPart
        || name == OpcSignatureOriginRelsPart
        || name.StartsWith(OpcPackage.OpcSignaturesPrefix, StringComparison.Ordinal);

    /// <summary>Add signature content type defaults to <c>[Content_Types].xml</c> (Rust <c>ensure_signature_content_types</c>).</summary>
    public static byte[] EnsureSignatureContentTypes(byte[] bytes)
    {
        string text = bytes.Length == 0
            ? "<?xml version=\"1.0\" encoding=\"utf-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"></Types>"
            : Utf8(bytes, "OPC [Content_Types].xml is not UTF-8");
        text = EnsureContentTypeDefault(text, "psdsor", OpcSignatureOriginContentType);
        text = EnsureContentTypeDefault(text, "psdsxs", OpcSignatureXmlContentType);
        if (!AsciiLower(text).Contains("extension=\"rels\"", StringComparison.Ordinal))
        {
            int insertAt = text.LastIndexOf("</Types>", StringComparison.Ordinal);
            if (insertAt < 0)
            {
                throw new PsignException("OPC [Content_Types].xml is missing </Types>");
            }

            text = text.Insert(insertAt, $"<Default Extension=\"rels\" ContentType=\"{RelationshipsContentType}\"/>");
        }

        return Encoding.UTF8.GetBytes(text);
    }

    private static string EnsureContentTypeDefault(string text, string extension, string contentType)
    {
        text = ExpandSelfClosingXmlRoot(text, "Types");
        if (text.Contains($"Extension=\"{extension}\"", StringComparison.Ordinal)
            || text.Contains($"ContentType=\"{contentType}\"", StringComparison.Ordinal))
        {
            return text;
        }

        int insertAt = text.LastIndexOf("</Types>", StringComparison.Ordinal);
        if (insertAt < 0)
        {
            throw new PsignException("OPC [Content_Types].xml is missing </Types>");
        }

        return text.Insert(insertAt, $"<Default Extension=\"{extension}\" ContentType=\"{contentType}\"/>");
    }

    /// <summary>Ensure <c>_rels/.rels</c> references the signature origin (Rust <c>ensure_root_signature_origin_relationship</c>).</summary>
    public static byte[] EnsureRootSignatureOriginRelationship(byte[] bytes) =>
        EnsureRelationship(bytes, OpcSignatureOriginRelType, $"/{OpcPackage.OpcSignatureOriginPart}", "PsignSignatureOrigin");

    /// <summary>Signature origin relationships part (Rust <c>signature_origin_relationships_xml</c>).</summary>
    public static byte[] SignatureOriginRelationshipsXml() => Encoding.UTF8.GetBytes(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
        + $"<Relationship Id=\"PsignSignature\" Type=\"{OpcSignatureRelType}\" Target=\"xml-signature/psign-signature.psdsxs\"/></Relationships>");

    private static byte[] EnsureRelationship(byte[] bytes, string relType, string target, string preferredId)
    {
        string text = bytes.Length == 0
            ? "<?xml version=\"1.0\" encoding=\"utf-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>"
            : Utf8(bytes, "OPC relationships part is not UTF-8");
        text = ExpandSelfClosingXmlRoot(text, "Relationships");
        if (text.Contains($"Type=\"{relType}\"", StringComparison.Ordinal))
        {
            return Encoding.UTF8.GetBytes(text);
        }

        int insertAt = text.LastIndexOf("</Relationships>", StringComparison.Ordinal);
        if (insertAt < 0)
        {
            throw new PsignException("OPC relationships part is missing </Relationships>");
        }

        string id = UniqueRelationshipId(text, preferredId);
        return Encoding.UTF8.GetBytes(text.Insert(insertAt, $"<Relationship Id=\"{id}\" Type=\"{relType}\" Target=\"{target}\"/>"));
    }

    /// <summary>Turn a self-closing document element into an open/close pair (Rust <c>expand_self_closing_xml_root</c>).</summary>
    internal static string ExpandSelfClosingXmlRoot(string text, string root)
    {
        int start = text.IndexOf($"<{root}", StringComparison.Ordinal);
        if (start < 0)
        {
            return text;
        }

        int tagEnd = text.IndexOf('>', start);
        if (tagEnd < 0)
        {
            return text;
        }

        if (tagEnd == 0 || text[tagEnd - 1] != '/')
        {
            return text;
        }

        int end = tagEnd - 1;
        return text[..end] + ">" + $"</{root}>" + text[(end + 2)..];
    }

    private static string UniqueRelationshipId(string text, string preferredId)
    {
        if (!text.Contains($"Id=\"{preferredId}\"", StringComparison.Ordinal))
        {
            return preferredId;
        }

        for (int i = 2; ; i++)
        {
            string candidate = $"{preferredId}{i}";
            if (!text.Contains($"Id=\"{candidate}\"", StringComparison.Ordinal))
            {
                return candidate;
            }
        }
    }

    // ---------------------------------------------------------------- text helpers

    private static string C14nAttr(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            sb.Append(c switch
            {
                '&' => "&amp;",
                '<' => "&lt;",
                '"' => "&quot;",
                '\t' => "&#x9;",
                '\n' => "&#xA;",
                '\r' => "&#xD;",
                _ => c.ToString(),
            });
        }

        return sb.ToString();
    }

    private static string C14nText(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            sb.Append(c switch
            {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '\r' => "&#xD;",
                _ => c.ToString(),
            });
        }

        return sb.ToString();
    }

    /// <summary>Empty algorithm elements written self-closing (Rust <c>document_form</c>).</summary>
    private static string DocumentForm(string canonical)
    {
        string output = canonical;
        foreach (var name in new[] { "CanonicalizationMethod", "SignatureMethod", "DigestMethod" })
        {
            output = output.Replace($"></{name}>", " />", StringComparison.Ordinal);
        }

        return output;
    }

    /// <summary>Text between <c>&lt;name&gt;</c> and <c>&lt;/name&gt;</c> (Rust <c>element_text</c>).</summary>
    internal static string? ElementText(string text, string name)
    {
        string open = $"<{name}>";
        string close = $"</{name}>";
        int start = text.IndexOf(open, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        start += open.Length;
        int end = text.IndexOf(close, start, StringComparison.Ordinal);
        return end < 0 ? null : text[start..end];
    }

    /// <summary>Raw attribute value preceded by a space (Rust <c>vsix::xml_attr</c>; no unescaping).</summary>
    internal static string? XmlAttr(string tag, string name)
    {
        foreach (char quote in new[] { '"', '\'' })
        {
            string needle = $" {name}={quote}";
            int idx = tag.IndexOf(needle, StringComparison.Ordinal);
            if (idx >= 0)
            {
                int start = idx + needle.Length;
                int end = tag.IndexOf(quote, start);
                return end < 0 ? null : tag[start..end];
            }
        }

        return null;
    }

    internal static string AsciiLower(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            if (chars[i] is >= 'A' and <= 'Z')
            {
                chars[i] = (char)(chars[i] + 32);
            }
        }

        return new string(chars);
    }

    internal static string Utf8(byte[] bytes, string error)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException(error, e);
        }
    }

    private static void EnsureReadable(ZipCrateArchive archive, ZipCrateEntry file)
    {
        try
        {
            archive.EnsureReadable(file);
        }
        catch (PsignException e)
        {
            throw new PsignException("read VSIX ZIP entry", e);
        }
    }

    private static T WithPath<T>(string path, string context, Func<byte[], T> action)
    {
        var bytes = NuGetPackage.ReadFileForOpen(path);
        try
        {
            return action(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException(context, e);
        }
    }

    /// <summary><c>[Content_Types].xml</c> lookup (Rust <c>ContentTypes</c>).</summary>
    private sealed class ContentTypes
    {
        private readonly SortedDictionary<string, string> _defaults = new(Utf8Ordinal.Comparer);
        private readonly SortedDictionary<string, string> _overrides = new(Utf8Ordinal.Comparer);

        public static ContentTypes Parse(byte[] xml)
        {
            string text = Utf8(xml, "OPC [Content_Types].xml is not UTF-8");
            var ct = new ContentTypes();
            foreach (var (tag, map, keyAttr) in new[] { ("<Default ", ct._defaults, "Extension"), ("<Override ", ct._overrides, "PartName") })
            {
                int cursor = 0;
                while (true)
                {
                    int start = text.IndexOf(tag, cursor, StringComparison.Ordinal);
                    if (start < 0)
                    {
                        break;
                    }

                    int end = text.IndexOf('>', start);
                    if (end < 0)
                    {
                        throw new PsignException($"unterminated {tag} in [Content_Types].xml");
                    }

                    string element = text[start..(end + 1)];
                    if (XmlAttr(element, keyAttr) is { } key && XmlAttr(element, "ContentType") is { } contentType)
                    {
                        map[AsciiLower(key.TrimStart('/'))] = contentType;
                    }

                    cursor = end + 1;
                }
            }

            return ct;
        }

        public string? ForPart(string part)
        {
            string key = AsciiLower(part);
            if (_overrides.TryGetValue(key, out var ct))
            {
                return ct;
            }

            int dot = key.LastIndexOf('.');
            string ext = dot < 0 ? string.Empty : key[(dot + 1)..];
            return _defaults.TryGetValue(ext, out var d) ? d : null;
        }
    }
}
