using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Core.Cms;

/// <summary>
/// CMS / PKCS#7 <c>SignedData</c> (RFC 5652 §5.1) with raw-preserving fields.
/// <para>
/// Parsing accepts the same inputs as Rust <c>parse_pkcs7_signed_data_der</c> (after
/// <see cref="Pkcs7Wire.NormalizeForAuthenticode"/>), and encoding produces DER with sorted SET OF elements, matching the
/// Rust <c>cms</c> crate encoder byte-for-byte for the same logical structure.
/// </para>
/// </summary>
public sealed class CmsSignedData
{
    public CmsSignedData(
        int version,
        List<AlgorithmIdentifier> digestAlgorithms,
        string encapContentType,
        byte[]? encapContent,
        List<byte[]>? certificates,
        List<byte[]>? crls,
        List<CmsSignerInfo> signerInfos)
    {
        Version = version;
        DigestAlgorithms = digestAlgorithms;
        EncapContentType = encapContentType;
        EncapContent = encapContent;
        Certificates = certificates;
        Crls = crls;
        SignerInfos = signerInfos;
    }

    public int Version { get; set; }

    public List<AlgorithmIdentifier> DigestAlgorithms { get; set; }

    /// <summary><c>encapContentInfo.eContentType</c>.</summary>
    public string EncapContentType { get; set; }

    /// <summary>The encoded TLV inside <c>encapContentInfo.eContent [0] EXPLICIT</c>, or <c>null</c> when detached.</summary>
    public byte[]? EncapContent { get; set; }

    /// <summary>Encoded <c>CertificateChoices</c> elements, or <c>null</c> when the field is absent.</summary>
    public List<byte[]>? Certificates { get; set; }

    /// <summary>Encoded <c>RevocationInfoChoice</c> elements, or <c>null</c> when absent.</summary>
    public List<byte[]>? Crls { get; set; }

    public List<CmsSignerInfo> SignerInfos { get; set; }

    /// <summary>
    /// Octets digested for PKCS#9 <c>messageDigest</c> (RFC 5652 §5.4): the content octets of <c>eContent</c>
    /// (for an OCTET STRING, its value; for other types, the value octets of the TLV, i.e. without tag/length).
    /// </summary>
    public byte[] EncapContentDigestInput()
    {
        if (EncapContent is null)
        {
            throw new PsignException("SignedData missing encapsulated content");
        }

        var t = Der.First(EncapContent) ?? throw new PsignException("SignedData eContent is malformed");
        return t.Value(EncapContent).ToArray();
    }

    /// <summary>Parsed X.509 certificates (non-certificate choices are skipped).</summary>
    public List<CertificateInfo> GetCertificates()
    {
        var result = new List<CertificateInfo>();
        if (Certificates is null)
        {
            return result;
        }

        foreach (var c in Certificates)
        {
            if (c.Length > 0 && c[0] == 0x30 && CertificateInfo.TryParse(c) is { } info)
            {
                result.Add(info);
            }
        }

        return result;
    }

    /// <summary>
    /// Locate the embedded certificate matching <paramref name="signer"/>'s SID (Rust
    /// <c>signed_data_certificate_for_signer_identifier</c>).
    /// </summary>
    public CertificateInfo CertificateForSigner(CmsSignerInfo signer)
    {
        if (Certificates is null)
        {
            throw new PsignException("SignedData has no certificates");
        }

        foreach (var cert in GetCertificates())
        {
            if (signer.MatchesCertificate(cert))
            {
                return cert;
            }
        }

        throw new PsignException("no embedded certificate matches SignerIdentifier");
    }

    /// <summary>Encode the <c>SignedData</c> SEQUENCE.</summary>
    public byte[] EncodeSignedData()
    {
        var parts = new List<byte[]>
        {
            CmsSignerInfo.EncodeSmallInteger(Version),
            Der.EncodeSetOf(0x31, DigestAlgorithms.Select(a => a.Encode())),
            EncodeEncapContentInfo(),
        };
        if (Certificates is not null)
        {
            parts.Add(Der.EncodeTlv(0xA0, Der.SortRustCmsChoiceSet(Certificates).ToArray()));
        }

        if (Crls is not null)
        {
            parts.Add(Der.EncodeTlv(0xA1, Der.SortRustCmsChoiceSet(Crls).ToArray()));
        }

        parts.Add(Der.EncodeTlv(0x31, SignerInfos.Select(s => s.Encode()).OrderBy(e => e, Comparer<byte[]>.Create(Der.CompareRustSignerInfo)).ToArray()));
        return Der.EncodeTlv(0x30, parts.ToArray());
    }

    private byte[] EncodeEncapContentInfo()
    {
        var oid = Der.EncodeOid(EncapContentType);
        return EncapContent is null
            ? Der.EncodeSequence(oid)
            : Der.EncodeSequence(oid, Der.EncodeTlv(0xA0, EncapContent));
    }

    /// <summary>Encode as a PKCS#7 <c>ContentInfo</c> (<c>contentType = id-signedData</c>).</summary>
    public byte[] Encode() => Pkcs7Wire.WrapSignedDataInContentInfo(EncodeSignedData());

    /// <summary>Deep-enough copy (lists and signer infos cloned; byte arrays shared).</summary>
    public CmsSignedData Clone() => new(
        Version,
        DigestAlgorithms.ToList(),
        EncapContentType,
        EncapContent,
        Certificates?.ToList(),
        Crls?.ToList(),
        SignerInfos.Select(s => s.Clone()).ToList());

    /// <summary>
    /// Decode <c>SignedData</c> from PKCS#7 DER (outer <c>ContentInfo</c> with <c>id-signedData</c>), after
    /// <see cref="Pkcs7Wire.NormalizeForAuthenticode"/>. Trailing octets after the <c>ContentInfo</c> are ignored.
    /// </summary>
    public static CmsSignedData Parse(ReadOnlySpan<byte> pkcs7)
    {
        var normalized = Pkcs7Wire.NormalizeForAuthenticode(pkcs7);
        ReadOnlySpan<byte> d = normalized;
        if (d.IsEmpty)
        {
            throw new PsignException("empty PKCS#7");
        }

        var outer = Der.First(d);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            throw new PsignException("PKCS#7 ContentInfo decode: expected SEQUENCE");
        }

        var ci = Der.Children(d, outer.Value);
        if (ci is null || ci.Count != 2 || ci[0].Tag != 0x06 || ci[1].Tag != 0xA0)
        {
            throw new PsignException("PKCS#7 ContentInfo decode: malformed ContentInfo");
        }

        string contentType = Der.DecodeOid(ci[0].Encoded(d)) ?? throw new PsignException("PKCS#7 ContentInfo decode: bad OID");
        if (contentType != Oids.Pkcs7SignedData)
        {
            throw new PsignException($"PKCS#7 root content type is not SignedData (got {contentType})");
        }

        var explicitChildren = Der.Children(d, ci[1]);
        if (explicitChildren is not { Count: 1 })
        {
            throw new PsignException("SignedData: malformed [0] EXPLICIT content");
        }

        return ParseSignedData(explicitChildren[0].Encoded(d));
    }

    /// <summary>Try to parse; returns <c>null</c> on failure.</summary>
    public static CmsSignedData? TryParse(ReadOnlySpan<byte> pkcs7)
    {
        try
        {
            return Parse(pkcs7);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            return null;
        }
    }

    /// <summary>Decode a bare <c>SignedData</c> SEQUENCE.</summary>
    public static CmsSignedData ParseSignedData(ReadOnlySpan<byte> derSpan)
    {
        byte[] der = derSpan.ToArray();
        var outer = Der.First(der);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            throw new PsignException("SignedData: expected SEQUENCE");
        }

        var c = Der.Children(der, outer.Value) ?? throw new PsignException("SignedData: malformed content");
        if (c.Count < 4)
        {
            throw new PsignException("SignedData: too few fields");
        }

        int i = 0;
        int version = CmsSignerInfo.DecodeSmallInteger(c[i++].Encoded(der));
        if (c[i].Tag != 0x31)
        {
            throw new PsignException("SignedData: digestAlgorithms is not a SET");
        }

        var digestAlgs = (Der.Children(der, c[i]) ?? throw new PsignException("SignedData: malformed digestAlgorithms"))
            .Select(t => AlgorithmIdentifier.Parse(t.Encoded(der)))
            .ToList();
        i++;

        if (c[i].Tag != 0x30)
        {
            throw new PsignException("SignedData: encapContentInfo is not a SEQUENCE");
        }

        var eci = Der.Children(der, c[i]) ?? throw new PsignException("SignedData: malformed encapContentInfo");
        if (eci.Count is < 1 or > 2 || eci[0].Tag != 0x06)
        {
            throw new PsignException("SignedData: malformed encapContentInfo");
        }

        string eContentType = Der.DecodeOid(eci[0].Encoded(der)) ?? throw new PsignException("SignedData: bad eContentType");
        byte[]? eContent = null;
        if (eci.Count == 2)
        {
            if (eci[1].Tag != 0xA0)
            {
                throw new PsignException("SignedData: eContent is not [0] EXPLICIT");
            }

            var inner = Der.Children(der, eci[1]);
            if (inner is not { Count: 1 })
            {
                throw new PsignException("SignedData: malformed eContent");
            }

            eContent = inner[0].Encoded(der).ToArray();
        }

        i++;

        List<byte[]>? certs = null;
        if (i < c.Count && c[i].Tag == 0xA0)
        {
            certs = (Der.Children(der, c[i]) ?? throw new PsignException("SignedData: malformed certificates"))
                .Select(t => t.Encoded(der).ToArray())
                .ToList();
            i++;
        }

        List<byte[]>? crls = null;
        if (i < c.Count && c[i].Tag == 0xA1)
        {
            crls = (Der.Children(der, c[i]) ?? throw new PsignException("SignedData: malformed crls"))
                .Select(t => t.Encoded(der).ToArray())
                .ToList();
            i++;
        }

        if (i >= c.Count || c[i].Tag != 0x31)
        {
            throw new PsignException("SignedData: missing signerInfos SET");
        }

        var signers = (Der.Children(der, c[i]) ?? throw new PsignException("SignedData: malformed signerInfos"))
            .Select(t => CmsSignerInfo.Parse(t.Encoded(der)))
            .ToList();
        i++;
        if (i != c.Count)
        {
            throw new PsignException("SignedData: unexpected trailing fields");
        }

        return new CmsSignedData(version, digestAlgs, eContentType, eContent, certs, crls, signers);
    }
}
