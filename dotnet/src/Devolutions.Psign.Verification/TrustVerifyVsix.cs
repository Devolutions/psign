using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Xml;

namespace Devolutions.Psign.Verification;

/// <summary>A VSIX signature whose XMLDSig structure, part digests, and <c>SignatureValue</c> verified (Rust <c>VsixSignature</c>).</summary>
/// <param name="SignerCertificateDer">DER of the <c>KeyInfo</c> certificate whose key produced the <c>SignatureValue</c>.</param>
/// <param name="TimestampToken">RFC 3161 token from <c>&lt;TimeStamp&gt;&lt;EncodedTime&gt;</c> (not yet trust-verified).</param>
/// <param name="ReferenceCount">Number of package parts covered by the signed manifest.</param>
public sealed record VsixSignature(byte[] SignerCertificateDer, byte[]? TimestampToken, int ReferenceCount);

/// <summary>
/// VSIX (OPC XML digital signature) trust verification (Rust <c>trust_verify_vsix.rs</c>). Verifies the package signature
/// the way Visual Studio / <c>System.IO.Packaging</c> and dotnet/sign produce it:
/// <list type="number">
/// <item>Exactly one XML signature part (<c>/package/services/digital-signature/xml-signature/*</c>).</item>
/// <item><c>SignedInfo</c> is canonicalized (C14N 1.0 or exclusive C14N) and its <c>SignatureValue</c> is an RSA PKCS#1 v1.5
/// signature (SHA-256/384/512) by a certificate from <c>KeyInfo</c>.</item>
/// <item>Every <c>SignedInfo</c> reference (<c>#id</c> same-document objects) and every <c>Manifest</c> reference (package
/// parts, optionally with C14N / OPC RelationshipTransform) digest matches.</item>
/// <item>The <c>Manifest</c> is inside an <c>Object</c> covered by <c>SignedInfo</c>; every package part except
/// <c>[Content_Types].xml</c> and the signature part is referenced, and each reference's <c>ContentType</c> matches
/// <c>[Content_Types].xml</c>.</item>
/// <item>Trust: the signer chain ends at the configured anchors (or the Artifact Signing policy), at the RFC 3161 time from
/// <c>&lt;Object&gt;&lt;TimeStamp&gt;&lt;EncodedTime&gt;</c> when present (imprint over the <c>SignatureValue</c> octets).</item>
/// </list>
/// </summary>
public static class TrustVerifyVsix
{
    private const string Dsig = "http://www.w3.org/2000/09/xmldsig#";
    private const string OpcDsig = "http://schemas.openxmlformats.org/package/2006/digital-signature";
    private const string OpcRels = "http://schemas.openxmlformats.org/package/2006/relationships";
    private const string OpcContentTypes = "http://schemas.openxmlformats.org/package/2006/content-types";
    private const string RelationshipTransformUri = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
    private const string SignaturePartPrefix = "package/services/digital-signature/xml-signature/";
    private const string ContentTypesPart = "[Content_Types].xml";

    private static AuthenticodeHashKind HashFromDigestUri(string uri) => uri switch
    {
        "http://www.w3.org/2001/04/xmlenc#sha256" => AuthenticodeHashKind.Sha256,
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => AuthenticodeHashKind.Sha384,
        "http://www.w3.org/2001/04/xmlenc#sha512" => AuthenticodeHashKind.Sha512,
        _ => throw new PsignException($"unsupported XMLDSig DigestMethod {uri}"),
    };

    private static AuthenticodeHashKind HashFromSignatureUri(string uri) => uri switch
    {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => AuthenticodeHashKind.Sha256,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => AuthenticodeHashKind.Sha384,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => AuthenticodeHashKind.Sha512,
        _ => throw new PsignException($"unsupported XMLDSig SignatureMethod {uri}"),
    };

    private static bool VerifyRsa(AuthenticodeHashKind hash, CertificateInfo cert, byte[] data, byte[] signature)
    {
        if (cert.PublicKeyAlgorithm.Oid != Oids.RsaEncryption)
        {
            return false;
        }

        using var rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(cert.SubjectPublicKeyInfo, out _);
            return rsa.VerifyData(data, signature, hash.HashAlgorithmName(), RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static byte[] DecodeBase64(string text, string what)
    {
        var compact = new string(text.Where(c => !char.IsWhiteSpace(c)).ToArray());
        try
        {
            return Base64Standard.Decode(compact);
        }
        catch (FormatException e)
        {
            throw new PsignException($"{what} is not valid base64", new PsignException(e.Message));
        }
    }

    private static string Algorithm(XmlC14nElement e, string child) =>
        e.Child(Dsig, child)?.Attr("Algorithm") ?? throw new PsignException($"XMLDSig {e.LocalName} is missing {child}");

    /// <summary>Percent-decoded, slash-trimmed OPC part name for ZIP lookup and comparison (case-insensitive).</summary>
    internal static string PartKey(string name)
    {
        var bytes = Encoding.UTF8.GetBytes(name.TrimStart('/'));
        var output = new List<byte>(bytes.Length);
        int i = 0;
        while (i < bytes.Length)
        {
            if (bytes[i] == (byte)'%' && i + 2 < bytes.Length && TryHexByte(bytes[i + 1], bytes[i + 2], out byte b))
            {
                output.Add(b);
                i += 3;
                continue;
            }

            output.Add(bytes[i]);
            i++;
        }

        return RustText.ToAsciiLowercase(RustText.FromUtf8Lossy(output.ToArray()));
    }

    private static bool TryHexByte(byte hi, byte lo, out byte value)
    {
        static int Nibble(byte c) => c switch
        {
            >= (byte)'0' and <= (byte)'9' => c - '0',
            >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
            >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
            _ => -1,
        };

        // u8::from_str_radix(&String::from_utf8_lossy(..), 16) also accepts a leading '+' sign.
        int h = Nibble(hi);
        int l = Nibble(lo);
        if (hi == (byte)'+' && l >= 0)
        {
            value = (byte)l;
            return true;
        }

        if (h < 0 || l < 0)
        {
            value = 0;
            return false;
        }

        value = (byte)((h << 4) | l);
        return true;
    }

    private sealed class Package
    {
        public SortedDictionary<string, byte[]> Parts { get; } = new(StringComparer.Ordinal);

        /// <summary>Part key → content type from <c>[Content_Types].xml</c>.</summary>
        public Dictionary<string, string> ContentTypes { get; } = new(StringComparer.Ordinal);

        public string SignaturePart { get; set; } = string.Empty;
    }

    private static Package ReadPackage(byte[] data)
    {
        var archive = NuGetPackage.OpenZip(data, "open VSIX ZIP");
        var package = new Package();
        byte[]? rawContentTypes = null;
        foreach (var file in archive.Entries)
        {
            try
            {
                archive.EnsureReadable(file);
            }
            catch (PsignException e)
            {
                throw PsignException.Context("read VSIX ZIP entry", e);
            }

            if (file.IsDir)
            {
                continue;
            }

            string name = file.Name;
            byte[] bytes;
            try
            {
                bytes = archive.Read(file);
            }
            catch (Exception e) when (e is PsignException or IOException or InvalidDataException)
            {
                throw PsignException.Context($"read VSIX part {name}", e);
            }

            if (PartKey(name) == PartKey(ContentTypesPart))
            {
                rawContentTypes = bytes;
                continue;
            }

            if (!package.Parts.TryAdd(PartKey(name), bytes))
            {
                throw new PsignException($"VSIX contains duplicate part name {name}");
            }
        }

        var signatures = package.Parts.Keys.Where(k => k.StartsWith(SignaturePartPrefix, StringComparison.Ordinal)).Take(2).ToList();
        if (signatures.Count == 0)
        {
            throw new PsignException("VSIX package has no OPC XML signature part");
        }

        if (signatures.Count > 1)
        {
            throw new PsignException("VSIX package has more than one OPC XML signature part");
        }

        package.SignaturePart = signatures[0];

        XmlC14nElement ctDoc;
        try
        {
            ctDoc = XmlC14n.ParseDocument(rawContentTypes ?? throw new PsignException("VSIX package has no [Content_Types].xml"));
        }
        catch (PsignException e) when (rawContentTypes is not null)
        {
            throw PsignException.Context("[Content_Types].xml", e);
        }

        var defaults = new Dictionary<string, string>(StringComparer.Ordinal);
        var overrides = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var e in ctDoc.ChildElements)
        {
            if (e.Namespace != OpcContentTypes)
            {
                continue;
            }

            if (e.LocalName == "Default" && e.Attr("Extension") is { } ext && e.Attr("ContentType") is { } dct)
            {
                defaults[RustText.ToAsciiLowercase(ext)] = dct;
            }
            else if (e.LocalName == "Override" && e.Attr("PartName") is { } p && e.Attr("ContentType") is { } oct)
            {
                overrides[PartKey(p)] = oct;
            }
        }

        foreach (var k in package.Parts.Keys)
        {
            if (overrides.TryGetValue(k, out var ct))
            {
                package.ContentTypes[k] = ct;
                continue;
            }

            int slash = k.LastIndexOf('/');
            string leaf = slash >= 0 ? k[(slash + 1)..] : k;
            int dot = leaf.LastIndexOf('.');
            string ext = dot < 0 ? string.Empty : leaf[(dot + 1)..];
            if (defaults.TryGetValue(ext, out var dct))
            {
                package.ContentTypes[k] = dct;
            }
        }

        return package;
    }

    /// <summary>
    /// OPC RelationshipTransform (ECMA-376 Part 2): keep the selected relationships sorted by <c>Id</c>, with
    /// <c>TargetMode</c> defaulted, as a new <c>Relationships</c> element (then canonicalized).
    /// </summary>
    internal static XmlC14nElement RelationshipTransform(XmlC14nElement transform, byte[] relsXml)
    {
        var sourceIds = new HashSet<string>(
            transform.ChildrenNamed(OpcDsig, "RelationshipReference").Select(e => e.Attr("SourceId")).OfType<string>(),
            StringComparer.Ordinal);
        var sourceTypes = new HashSet<string>(
            transform.ChildrenNamed(OpcDsig, "RelationshipsGroupReference").Select(e => e.Attr("SourceType")).OfType<string>(),
            StringComparer.Ordinal);
        XmlC14nElement rels;
        try
        {
            rels = XmlC14n.ParseDocument(relsXml);
        }
        catch (PsignException e)
        {
            throw PsignException.Context("relationships part", e);
        }

        if (!rels.Is(OpcRels, "Relationships"))
        {
            throw new PsignException("RelationshipTransform input is not a Relationships part");
        }

        var selected = new List<XmlC14nElement>();
        foreach (var r in rels.ChildrenNamed(OpcRels, "Relationship"))
        {
            bool keep = (r.Attr("Id") is { } id && sourceIds.Contains(id)) || (r.Attr("Type") is { } t && sourceTypes.Contains(t));
            if (!keep)
            {
                continue;
            }

            var attrs = new List<KeyValuePair<string, string>>();
            foreach (var name in new[] { "Id", "Target", "TargetMode", "Type" })
            {
                var v = r.Attr(name);
                if (v is not null)
                {
                    attrs.Add(new(name, v));
                }
                else if (name == "TargetMode")
                {
                    attrs.Add(new(name, "Internal"));
                }
            }

            selected.Add(new XmlC14nElement("Relationship", attrs, [], new SortedDictionary<string, string>(rels.Scope, StringComparer.Ordinal)));
        }

        // Rust sort_by(Option<&str>::cmp) is stable and orders None before any Some, then by bytes.
        var sorted = selected
            .Select((e, i) => (e, i))
            .OrderBy(x => x.e.Attr("Id"), Comparer<string?>.Create(CompareOptionStr))
            .ThenBy(x => x.i)
            .Select(x => (XmlC14nNode)x.e)
            .ToList();
        var scope = new SortedDictionary<string, string>(StringComparer.Ordinal) { [string.Empty] = OpcRels };
        return new XmlC14nElement("Relationships", [new("xmlns", OpcRels)], sorted, scope);
    }

    private static int CompareOptionStr(string? a, string? b)
    {
        if (a is null)
        {
            return b is null ? 0 : -1;
        }

        if (b is null)
        {
            return 1;
        }

        return Core.Opc.Utf8Ordinal.Comparer.Compare(a, b);
    }

    /// <summary>Octets a package-part reference digests, after its transforms.</summary>
    private static byte[] PartReferenceOctets(XmlC14nElement reference, byte[] part)
    {
        var transforms = reference.Child(Dsig, "Transforms");
        if (transforms is null)
        {
            return part;
        }

        XmlC14nElement? current = null;
        byte[] octets = part;
        foreach (var transform in transforms.ChildrenNamed(Dsig, "Transform"))
        {
            string uri = transform.Attr("Algorithm") ?? string.Empty;
            if (uri == RelationshipTransformUri)
            {
                current = RelationshipTransform(transform, octets);
            }
            else if (XmlC14n.ModeFromUri(uri) is { } mode)
            {
                var element = current ?? XmlC14n.ParseDocument(octets);
                current = null;
                octets = XmlC14n.Canonicalize(element, mode);
            }
            else
            {
                throw new PsignException($"unsupported XMLDSig part transform {uri}");
            }
        }

        if (current is not null)
        {
            octets = XmlC14n.Canonicalize(current, C14nMode.Inclusive);
        }

        return octets;
    }

    /// <summary>Octets a same-document (<c>#id</c>) reference digests.</summary>
    private static byte[] ObjectReferenceOctets(XmlC14nElement reference, XmlC14nElement target)
    {
        var mode = C14nMode.Inclusive;
        if (reference.Child(Dsig, "Transforms") is { } transforms)
        {
            foreach (var transform in transforms.ChildrenNamed(Dsig, "Transform"))
            {
                string uri = transform.Attr("Algorithm") ?? string.Empty;
                mode = XmlC14n.ModeFromUri(uri) ?? throw new PsignException($"unsupported XMLDSig object transform {uri}");
            }
        }

        return XmlC14n.Canonicalize(target, mode);
    }

    private static void CheckDigest(XmlC14nElement reference, byte[] octets, string what)
    {
        var hash = HashFromDigestUri(Algorithm(reference, "DigestMethod"));
        var digestValue = reference.Child(Dsig, "DigestValue") ?? throw new PsignException($"XMLDSig reference {what} has no DigestValue");
        var expected = DecodeBase64(digestValue.Text(), "DigestValue");
        if (!hash.Hash(octets).AsSpan().SequenceEqual(expected))
        {
            throw new PsignException($"VSIX signature digest mismatch for {what}");
        }
    }

    private sealed record VerifiedXmlSignature(
        CertificateInfo Signer,
        List<CertificateInfo> Certificates,
        byte[] SignatureValue,
        byte[]? TimestampToken,
        int ReferenceCount);

    private static string RustDebugStr(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in s)
        {
            sb.Append(c switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                '\0' => "\\0",
                _ when char.IsControl(c) => $"\\u{{{(int)c:x}}}",
                _ => c.ToString(),
            });
        }

        return sb.Append('"').ToString();
    }

    private static VerifiedXmlSignature VerifyXmlSignature(Package package)
    {
        XmlC14nElement doc;
        try
        {
            doc = XmlC14n.ParseDocument(package.Parts[package.SignaturePart]);
        }
        catch (PsignException e)
        {
            throw PsignException.Context("VSIX signature XML", e);
        }

        if (!doc.Is(Dsig, "Signature"))
        {
            throw new PsignException("VSIX signature part is not an XMLDSig Signature");
        }

        var signedInfo = doc.Child(Dsig, "SignedInfo") ?? throw new PsignException("XMLDSig Signature has no SignedInfo");
        string c14nUri = Algorithm(signedInfo, "CanonicalizationMethod");
        var c14n = XmlC14n.ModeFromUri(c14nUri) ?? throw new PsignException($"unsupported XMLDSig CanonicalizationMethod {c14nUri}");
        var sigHash = HashFromSignatureUri(Algorithm(signedInfo, "SignatureMethod"));
        var signatureValueElement = doc.Child(Dsig, "SignatureValue") ?? throw new PsignException("XMLDSig Signature has no SignatureValue");
        var signatureValue = DecodeBase64(signatureValueElement.Text(), "SignatureValue");

        // KeyInfo certificates; the signer is the one whose key verifies SignedInfo.
        var x509 = new List<byte[]>();
        if (doc.Child(Dsig, "KeyInfo") is { } keyInfo)
        {
            foreach (var data in keyInfo.ChildrenNamed(Dsig, "X509Data"))
            {
                foreach (var cert in data.ChildrenNamed(Dsig, "X509Certificate"))
                {
                    x509.Add(DecodeBase64(cert.Text(), "X509Certificate"));
                }
            }
        }

        var canonicalSignedInfo = XmlC14n.Canonicalize(signedInfo, c14n);
        CertificateInfo? signer = null;
        foreach (var der in x509)
        {
            CertificateInfo cert;
            try
            {
                cert = CertificateInfo.Parse(der);
            }
            catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException or CryptographicException)
            {
                continue;
            }

            if (VerifyRsa(sigHash, cert, canonicalSignedInfo, signatureValue))
            {
                signer = cert;
                break;
            }
        }

        if (signer is null)
        {
            throw new PsignException("VSIX SignatureValue does not verify with any KeyInfo X509Certificate");
        }

        var certificates = new List<CertificateInfo>(x509.Count);
        foreach (var der in x509)
        {
            try
            {
                certificates.Add(Anchors.ParseCertBytes(der));
            }
            catch (PsignException)
            {
            }
        }

        // SignedInfo references: same-document objects.
        var coveredObjects = new List<XmlC14nElement>();
        foreach (var reference in signedInfo.ChildrenNamed(Dsig, "Reference"))
        {
            string uri = reference.Attr("URI") ?? string.Empty;
            if (!uri.StartsWith('#'))
            {
                throw new PsignException($"unsupported SignedInfo reference URI {RustDebugStr(uri)}");
            }

            string id = uri[1..];
            var targets = new List<XmlC14nElement>();
            doc.FindAll(e => e.Attr("Id") == id, targets);
            if (targets.Count != 1)
            {
                throw new PsignException($"SignedInfo reference #{id} must match exactly one element");
            }

            CheckDigest(reference, ObjectReferenceOctets(reference, targets[0]), uri);
            coveredObjects.Add(targets[0]);
        }

        // The package manifest must sit inside a covered object.
        var manifests = new List<XmlC14nElement>();
        foreach (var obj in coveredObjects)
        {
            obj.FindAll(e => e.Is(Dsig, "Manifest"), manifests);
        }

        if (manifests.Count == 0)
        {
            throw new PsignException("VSIX signature does not sign a package Manifest");
        }

        var referenced = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var manifest in manifests)
        {
            foreach (var reference in manifest.ChildrenNamed(Dsig, "Reference"))
            {
                string uri = reference.Attr("URI") ?? string.Empty;
                int q = uri.IndexOf('?');
                string path = q < 0 ? uri : uri[..q];
                string query = q < 0 ? string.Empty : uri[(q + 1)..];
                if (!path.StartsWith('/'))
                {
                    throw new PsignException($"unsupported Manifest reference URI {RustDebugStr(uri)}");
                }

                string key = PartKey(path);
                if (!package.Parts.TryGetValue(key, out var part))
                {
                    throw new PsignException($"VSIX signature references missing part {path}");
                }

                if (query.StartsWith("ContentType=", StringComparison.Ordinal))
                {
                    string ct = query["ContentType=".Length..];
                    if (!package.ContentTypes.TryGetValue(key, out var actual) || actual != ct)
                    {
                        throw new PsignException($"VSIX part {path} content type differs from the signed {ct}");
                    }
                }

                CheckDigest(reference, PartReferenceOctets(reference, part), path);
                referenced.Add(key);
            }
        }

        foreach (var k in package.Parts.Keys)
        {
            if (k != package.SignaturePart && !referenced.Contains(k))
            {
                throw new PsignException($"VSIX part /{k} is not covered by the signature");
            }
        }

        var stamps = new List<XmlC14nElement>();
        doc.FindAll(e => e.Is(OpcDsig, "EncodedTime"), stamps);
        byte[]? timestampToken = stamps.Count switch
        {
            0 => null,
            1 => DecodeBase64(stamps[0].Text(), "EncodedTime"),
            _ => throw new PsignException("VSIX signature has more than one timestamp"),
        };

        return new VerifiedXmlSignature(signer, certificates, signatureValue, timestampToken, referenced.Count);
    }

    /// <summary>Verify the VSIX signature binding (steps 1-4) without any trust decision (Rust <c>verify_vsix_signature_bytes</c>).</summary>
    public static VsixSignature VerifyVsixSignatureBytes(byte[] data)
    {
        var sig = VerifyXmlSignature(ReadPackage(data));
        return new VsixSignature(sig.Signer.RawData.ToArray(), sig.TimestampToken, sig.ReferenceCount);
    }

    /// <summary>Trust-verify a signed VSIX package (Rust <c>trust_verify_vsix_bytes</c>).</summary>
    public static TrustVerifyPeReport TrustVerifyVsixBytes(byte[] data, TrustVerifyPeOptions opts)
    {
        var (anchors, anchorCerts) = TrustVerifyPe.TrustMaterialFor(opts);
        var package = ReadPackage(data);
        var sig = VerifyXmlSignature(package);
        var report = TrustVerifyPe.NewReport(anchors);

        if (opts.ArtifactSigning is { } policy)
        {
            report.ArtifactSigning.Add(ArtifactSigning.VerifyArtifactSigningCertificate(
                sig.Signer,
                sig.Certificates,
                sig.TimestampToken is { } t ? (t, sig.SignatureValue) : null,
                0,
                policy,
                opts));
        }
        else
        {
            if (opts.Policy.StrictCodeSigningEku && !CmsTrustHelpers.HasCodeSigningEku(sig.Signer))
            {
                throw new PsignException("VSIX signer certificate lacks the code signing EKU");
            }

            DateTimeOffset instant;
            if (opts.VerificationInstantOverride is { } o)
            {
                instant = o;
            }
            else if (opts.Policy.PreferTimestampSigningTime)
            {
                if (sig.TimestampToken is { } token)
                {
                    try
                    {
                        instant = Rfc3161Extract.TrustedUtcDateFromTimestampToken(token, sig.SignatureValue, anchors, anchorCerts, opts.Online, opts.VerboseChain, opts.Log);
                    }
                    catch (PsignException e)
                    {
                        throw PsignException.Context("VSIX timestamp", e);
                    }
                }
                else if (opts.Policy.RequireValidTimestamp)
                {
                    throw new PsignException("VSIX signature has no RFC 3161 timestamp");
                }
                else
                {
                    instant = Picky.PickyFormat.Now();
                }
            }
            else
            {
                instant = Picky.PickyFormat.Now();
            }

            var leaf = Anchors.ParseCertBytes(sig.Signer.RawData);
            TrustChain.VerifyCertificateChainToAnchors(leaf, sig.Certificates, anchors, anchorCerts, opts.Online, instant, opts.VerboseChain, opts.Log);
        }

        report.Pkcs7EntriesVerified = 1;
        return report;
    }
}
