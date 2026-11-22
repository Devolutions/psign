using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Xml;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification;

/// <summary>A VSIX signature whose XMLDSig structure, part digests, and <c>SignatureValue</c> verified (Rust <c>VsixSignature</c>).</summary>
/// <param name="SignerCertificateDer">DER of the <c>KeyInfo</c> certificate whose key produced the <c>SignatureValue</c>.</param>
/// <param name="TimestampToken">RFC 3161 token from <c>&lt;TimeStamp&gt;&lt;EncodedTime&gt;</c> (not yet trust-verified).</param>
/// <param name="ReferenceCount">Number of package parts covered by the signed manifest.</param>
public sealed record VsixSignature(byte[] SignerCertificateDer, byte[]? TimestampToken, int ReferenceCount);

/// <summary>
/// VSIX (OPC XML digital signature) trust verification (Rust <c>trust_verify_vsix.rs</c>): exactly one XML signature
/// part, canonicalized <c>SignedInfo</c> verified with a <c>KeyInfo</c> certificate (RSA PKCS#1 v1.5, SHA-256/384/512),
/// every <c>SignedInfo</c> and <c>Manifest</c> reference digest, full part coverage with matching content types, then
/// chain trust at the RFC 3161 time from <c>&lt;Object&gt;&lt;TimeStamp&gt;&lt;EncodedTime&gt;</c> when present.
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

    /// <summary>Verify the VSIX signature binding without any trust decision (Rust <c>verify_vsix_signature_bytes</c>).</summary>
    public static VsixSignature VerifyVsixSignatureBytes(byte[] data)
    {
        var sig = VerifyXmlSignature(ReadPackage(data));
        return new VsixSignature(sig.Signer.RawData, sig.TimestampToken, sig.ReferenceCount);
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
                sig.TimestampToken is { } token ? (token, sig.SignatureValue) : null,
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
            if (opts.VerificationInstantOverride is { } overrideInstant)
            {
                instant = overrideInstant;
            }
            else if (opts.Policy.PreferTimestampSigningTime)
            {
                if (sig.TimestampToken is { } token)
                {
                    try
                    {
                        instant = Rfc3161Extract.TrustedUtcDateFromTimestampToken(
                            token, sig.SignatureValue, anchors, anchorCerts, opts.Online, opts.VerboseChain, opts.Log);
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
                    instant = PickyFormat.Now();
                }
            }
            else
            {
                instant = PickyFormat.Now();
            }

            TrustChain.VerifyCertificateChainToAnchors(sig.Signer, sig.Certificates, anchors, anchorCerts, opts.Online, instant, opts.VerboseChain, opts.Log);
        }

        report.Pkcs7EntriesVerified = 1;
        return report;
    }

    /// <summary>Percent-decoded, slash-trimmed, ASCII-lowercased OPC part name (Rust <c>part_key</c>).</summary>
    internal static string PartKey(string name)
    {
        var bytes = Encoding.UTF8.GetBytes(name.TrimStart('/'));
        var output = new List<byte>(bytes.Length);
        int i = 0;
        while (i < bytes.Length)
        {
            if (bytes[i] == (byte)'%' && i + 2 < bytes.Length && FromStrRadix16(bytes[i + 1], bytes[i + 2]) is { } b)
            {
                output.Add(b);
                i += 3;
                continue;
            }

            output.Add(bytes[i]);
            i++;
        }

        return RustText.ToAsciiLowercase(Encoding.UTF8.GetString(output.ToArray()));
    }

    // Rust `u8::from_str_radix(two_chars, 16)`: an optional leading '+' followed by hex digits.
    private static byte? FromStrRadix16(byte a, byte b)
    {
        static int Hex(byte c) => c switch
        {
            >= (byte)'0' and <= (byte)'9' => c - '0',
            >= (byte)'a' and <= (byte)'f' => c - 'a' + 10,
            >= (byte)'A' and <= (byte)'F' => c - 'A' + 10,
            _ => -1,
        };

        if (a == (byte)'+')
        {
            int v = Hex(b);
            return v < 0 ? null : (byte)v;
        }

        int hi = Hex(a);
        int lo = Hex(b);
        return hi < 0 || lo < 0 ? null : (byte)((hi << 4) | lo);
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
            throw new PsignException($"{what} is not valid base64", e);
        }
    }

    private static string Algorithm(XmlC14nElement e, string child) =>
        e.Child(Dsig, child)?.Attr("Algorithm") ?? throw new PsignException($"XMLDSig {e.LocalName} is missing {child}");

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
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(cert.SubjectPublicKeyInfo, out _);
            return rsa.VerifyData(data, signature, hash.HashAlgorithmName(), RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private sealed class Package
    {
        public SortedDictionary<string, byte[]> Parts { get; } = new(StringComparer.Ordinal);

        public SortedDictionary<string, string> ContentTypes { get; } = new(StringComparer.Ordinal);

        public string SignaturePart { get; set; } = string.Empty;
    }

    private static Package ReadPackage(byte[] data)
    {
        ZipCrateArchive archive;
        try
        {
            archive = ZipCrateArchive.Open(data);
        }
        catch (PsignException e)
        {
            throw PsignException.Context("open VSIX ZIP", e);
        }

        var package = new Package();
        byte[]? rawContentTypes = null;
        foreach (var file in archive.Entries)
        {
            if (file.IsDir)
            {
                continue;
            }

            var name = file.Name;
            byte[] bytes;
            try
            {
                bytes = archive.Read(file);
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"read VSIX part {name}", e);
            }

            if (name == ContentTypesPart)
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

        var defaults = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var overrides = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var e in ctDoc.ChildElements)
        {
            if (e.Namespace != OpcContentTypes)
            {
                continue;
            }

            if (e.LocalName == "Default")
            {
                if (e.Attr("Extension") is { } ext && e.Attr("ContentType") is { } ct)
                {
                    defaults[RustText.ToAsciiLowercase(ext)] = ct;
                }
            }
            else if (e.LocalName == "Override")
            {
                if (e.Attr("PartName") is { } p && e.Attr("ContentType") is { } ct)
                {
                    overrides[PartKey(p)] = ct;
                }
            }
        }

        foreach (var k in package.Parts.Keys)
        {
            if (overrides.TryGetValue(k, out var ct))
            {
                package.ContentTypes[k] = ct;
                continue;
            }

            int dot = k.LastIndexOf('.');
            var ext = dot >= 0 ? k[(dot + 1)..] : string.Empty;
            if (defaults.TryGetValue(ext, out var dct))
            {
                package.ContentTypes[k] = dct;
            }
        }

        return package;
    }

    /// <summary>OPC RelationshipTransform (ECMA-376 Part 2) selection (Rust <c>relationship_transform</c>).</summary>
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
            bool include = (r.Attr("Id") is { } id && sourceIds.Contains(id)) || (r.Attr("Type") is { } t && sourceTypes.Contains(t));
            if (!include)
            {
                continue;
            }

            var attrs = new List<KeyValuePair<string, string>>();
            foreach (var name in new[] { "Id", "Target", "TargetMode", "Type" })
            {
                if (r.Attr(name) is { } v)
                {
                    attrs.Add(new(name, v));
                }
                else if (name == "TargetMode")
                {
                    attrs.Add(new(name, "Internal"));
                }
            }

            selected.Add(new XmlC14nElement("Relationship", attrs, [], new SortedDictionary<string, string>(rels.Scope, rels.Scope.Comparer)));
        }

        // Stable sort by Id (Rust `sort_by` over Option<&str>; None sorts first).
        var ordered = selected
            .Select((e, i) => (e, i))
            .OrderBy(x => x.e.Attr("Id") is null ? 0 : 1)
            .ThenBy(x => x.e.Attr("Id") ?? string.Empty, StringComparer.Ordinal)
            .ThenBy(x => x.i)
            .Select(x => (XmlC14nNode)x.e)
            .ToList();
        return new XmlC14nElement(
            "Relationships",
            [new("xmlns", OpcRels)],
            ordered,
            new SortedDictionary<string, string>(rels.Scope.Comparer) { [string.Empty] = OpcRels });
    }

    private static byte[] PartReferenceOctets(XmlC14nElement reference, byte[] part)
    {
        if (reference.Child(Dsig, "Transforms") is not { } transforms)
        {
            return part;
        }

        XmlC14nElement? current = null;
        var octets = part;
        foreach (var transform in transforms.ChildrenNamed(Dsig, "Transform"))
        {
            var uri = transform.Attr("Algorithm") ?? string.Empty;
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

    private static byte[] ObjectReferenceOctets(XmlC14nElement reference, XmlC14nElement target)
    {
        var mode = C14nMode.Inclusive;
        if (reference.Child(Dsig, "Transforms") is { } transforms)
        {
            foreach (var transform in transforms.ChildrenNamed(Dsig, "Transform"))
            {
                var uri = transform.Attr("Algorithm") ?? string.Empty;
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
        var c14nUri = Algorithm(signedInfo, "CanonicalizationMethod");
        var c14n = XmlC14n.ModeFromUri(c14nUri) ?? throw new PsignException($"unsupported XMLDSig CanonicalizationMethod {c14nUri}");
        var sigHash = HashFromSignatureUri(Algorithm(signedInfo, "SignatureMethod"));
        var signatureValueElement = doc.Child(Dsig, "SignatureValue") ?? throw new PsignException("XMLDSig Signature has no SignatureValue");
        var signatureValue = DecodeBase64(signatureValueElement.Text(), "SignatureValue");

        var x509 = new List<byte[]>();
        if (doc.Child(Dsig, "KeyInfo") is { } keyInfo)
        {
            foreach (var x509Data in keyInfo.ChildrenNamed(Dsig, "X509Data"))
            {
                foreach (var cert in x509Data.ChildrenNamed(Dsig, "X509Certificate"))
                {
                    x509.Add(DecodeBase64(cert.Text(), "X509Certificate"));
                }
            }
        }

        var canonicalSignedInfo = XmlC14n.Canonicalize(signedInfo, c14n);
        var signer = x509
            .Select(der => CertificateInfo.TryParse(der))
            .OfType<CertificateInfo>()
            .FirstOrDefault(cert => VerifyRsa(sigHash, cert, canonicalSignedInfo, signatureValue))
            ?? throw new PsignException("VSIX SignatureValue does not verify with any KeyInfo X509Certificate");
        var certificates = x509.Select(der => Anchors.ParseCertBytes(der)).ToList();

        var coveredObjects = new List<XmlC14nElement>();
        foreach (var reference in signedInfo.ChildrenNamed(Dsig, "Reference"))
        {
            var uri = reference.Attr("URI") ?? string.Empty;
            if (!uri.StartsWith('#'))
            {
                throw new PsignException($"unsupported SignedInfo reference URI {RustDebugString(uri)}");
            }

            var id = uri[1..];
            var targets = new List<XmlC14nElement>();
            doc.FindAll(e => e.Attr("Id") == id, targets);
            if (targets.Count != 1)
            {
                throw new PsignException($"SignedInfo reference #{id} must match exactly one element");
            }

            CheckDigest(reference, ObjectReferenceOctets(reference, targets[0]), uri);
            coveredObjects.Add(targets[0]);
        }

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
                var uri = reference.Attr("URI") ?? string.Empty;
                int q = uri.IndexOf('?');
                var path = q >= 0 ? uri[..q] : uri;
                var query = q >= 0 ? uri[(q + 1)..] : string.Empty;
                if (!path.StartsWith('/'))
                {
                    throw new PsignException($"unsupported Manifest reference URI {RustDebugString(uri)}");
                }

                var key = PartKey(path);
                if (!package.Parts.TryGetValue(key, out var part))
                {
                    throw new PsignException($"VSIX signature references missing part {path}");
                }

                if (query.StartsWith("ContentType=", StringComparison.Ordinal))
                {
                    var ct = query["ContentType=".Length..];
                    if (!package.ContentTypes.TryGetValue(key, out var actual) || actual != ct)
                    {
                        throw new PsignException($"VSIX part {path} content type differs from the signed {ct}");
                    }
                }

                CheckDigest(reference, PartReferenceOctets(reference, part), path);
                referenced.Add(key);
            }
        }

        var unsigned = package.Parts.Keys.FirstOrDefault(k => k != package.SignaturePart && !referenced.Contains(k));
        if (unsigned is not null)
        {
            throw new PsignException($"VSIX part /{unsigned} is not covered by the signature");
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

    // Rust `{:?}` for &str: quoted with `\"`, `\\` and control characters escaped.
    private static string RustDebugString(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in s)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    if (char.IsControl(c))
                    {
                        sb.Append("\\u{").Append(((int)c).ToString("x", CultureInfo.InvariantCulture)).Append('}');
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        return sb.Append('"').ToString();
    }
}
