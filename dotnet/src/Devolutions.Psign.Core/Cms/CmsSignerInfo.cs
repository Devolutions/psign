using System.Numerics;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Core.Cms;

/// <summary>
/// CMS <c>SignerInfo</c> (RFC 5652 §5.3) with raw-preserving fields. <see cref="Encode"/> re-encodes in DER with SET OF
/// sorting, matching the Rust <c>cms</c>/<c>der</c> encoder.
/// </summary>
public sealed class CmsSignerInfo
{
    public CmsSignerInfo(
        int version,
        byte[] sid,
        AlgorithmIdentifier digestAlgorithm,
        List<CmsAttribute>? signedAttributes,
        AlgorithmIdentifier signatureAlgorithm,
        byte[] signature,
        List<CmsAttribute>? unsignedAttributes)
    {
        Version = version;
        Sid = sid;
        DigestAlgorithm = digestAlgorithm;
        SignedAttributes = signedAttributes;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
        UnsignedAttributes = unsignedAttributes;
    }

    /// <summary>CMSVersion (1 for issuerAndSerialNumber, 3 for subjectKeyIdentifier).</summary>
    public int Version { get; set; }

    /// <summary>Encoded <c>SignerIdentifier</c> (an <c>IssuerAndSerialNumber</c> SEQUENCE or <c>[0]</c> key identifier).</summary>
    public byte[] Sid { get; set; }

    public AlgorithmIdentifier DigestAlgorithm { get; set; }

    /// <summary>Authenticated attributes, or <c>null</c> when absent.</summary>
    public List<CmsAttribute>? SignedAttributes { get; set; }

    public AlgorithmIdentifier SignatureAlgorithm { get; set; }

    /// <summary>Signature value octets.</summary>
    public byte[] Signature { get; set; }

    /// <summary>Unauthenticated attributes, or <c>null</c> when absent.</summary>
    public List<CmsAttribute>? UnsignedAttributes { get; set; }

    /// <summary>True when <see cref="Sid"/> is an <c>IssuerAndSerialNumber</c>.</summary>
    public bool SidIsIssuerAndSerialNumber => Sid.Length > 0 && Sid[0] == 0x30;

    /// <summary>Issuer name DER and serial INTEGER content octets from an <c>IssuerAndSerialNumber</c> SID.</summary>
    public (byte[] Issuer, byte[] Serial)? SidIssuerAndSerial
    {
        get
        {
            if (!SidIsIssuerAndSerialNumber)
            {
                return null;
            }

            ReadOnlySpan<byte> d = Sid;
            var outer = Der.First(d);
            if (outer is null)
            {
                return null;
            }

            var children = Der.Children(d, outer.Value);
            if (children is not { Count: 2 } || children[1].Tag != 0x02)
            {
                return null;
            }

            return (children[0].Encoded(d).ToArray(), children[1].Value(d).ToArray());
        }
    }

    /// <summary>Subject key identifier from a <c>[0]</c> SID.</summary>
    public byte[]? SidSubjectKeyIdentifier
    {
        get
        {
            if (Sid.Length == 0 || (Sid[0] != 0x80 && Sid[0] != 0xA0))
            {
                return null;
            }

            ReadOnlySpan<byte> d = Sid;
            var outer = Der.First(d);
            if (outer is null)
            {
                return null;
            }

            if (Sid[0] == 0x80)
            {
                return outer.Value.Value(d).ToArray();
            }

            var inner = Der.Children(d, outer.Value);
            return inner is { Count: 1 } && inner[0].Tag == 0x04 ? inner[0].Value(d).ToArray() : null;
        }
    }

    /// <summary>Build an <c>IssuerAndSerialNumber</c> SID from a certificate.</summary>
    public static byte[] IssuerAndSerialSid(CertificateInfo cert) =>
        Der.EncodeSequence(cert.Issuer, cert.SerialNumberEncoded);

    /// <summary>True when <paramref name="cert"/> matches <see cref="Sid"/>.</summary>
    public bool MatchesCertificate(CertificateInfo cert)
    {
        if (SidIssuerAndSerial is { } ias)
        {
            return ias.Issuer.AsSpan().SequenceEqual(cert.Issuer) && SerialEquals(ias.Serial, cert.SerialNumber);
        }

        if (SidSubjectKeyIdentifier is { } ski)
        {
            return cert.SubjectKeyIdentifier is { } c && c.AsSpan().SequenceEqual(ski);
        }

        return false;
    }

    private static bool SerialEquals(byte[] a, byte[] b) =>
        a.AsSpan().SequenceEqual(b) ||
        new BigInteger(a, isUnsigned: false, isBigEndian: true) == new BigInteger(b, isUnsigned: false, isBigEndian: true);

    /// <summary>First signed attribute with <paramref name="oid"/>.</summary>
    public CmsAttribute? GetSignedAttribute(string oid) => SignedAttributes?.FirstOrDefault(a => a.Oid == oid);

    /// <summary>First unsigned attribute with <paramref name="oid"/>.</summary>
    public CmsAttribute? GetUnsignedAttribute(string oid) => UnsignedAttributes?.FirstOrDefault(a => a.Oid == oid);

    /// <summary>
    /// DER encoding of the signed attributes as an explicit <c>SET OF Attribute</c> (tag <c>0x31</c>): the octets that
    /// are digested and signed per RFC 5652 §5.4.
    /// </summary>
    public byte[] SignedAttributesSetDer()
    {
        if (SignedAttributes is null)
        {
            throw new PsignException("SignerInfo has no signed attributes");
        }

        return CmsAttribute.EncodeSet(0x31, SignedAttributes);
    }

    /// <summary>PKCS#9 <c>messageDigest</c> attribute octets.</summary>
    public byte[] MessageDigest()
    {
        var attr = GetSignedAttribute(Oids.Pkcs9MessageDigest)
            ?? throw new PsignException("SignerInfo signed attributes missing PKCS#9 messageDigest");
        if (attr.Values.Count != 1)
        {
            throw new PsignException("PKCS#9 messageDigest attribute must have exactly one value");
        }

        var v = attr.Values[0];
        var tlv = Der.First(v);
        if (tlv is null || tlv.Value.Tag != 0x04)
        {
            throw new PsignException("PKCS#9 messageDigest value is not an OCTET STRING");
        }

        return tlv.Value.Value(v).ToArray();
    }

    /// <summary>DER encoding.</summary>
    public byte[] Encode()
    {
        var parts = new List<byte[]>
        {
            EncodeSmallInteger(Version),
            Sid,
            DigestAlgorithm.Encode(),
        };
        if (SignedAttributes is not null)
        {
            parts.Add(CmsAttribute.EncodeSet(0xA0, SignedAttributes));
        }

        parts.Add(SignatureAlgorithm.Encode());
        parts.Add(Der.EncodeTlv(0x04, Signature));
        if (UnsignedAttributes is not null)
        {
            parts.Add(CmsAttribute.EncodeSet(0xA1, UnsignedAttributes));
        }

        return Der.EncodeTlv(0x30, parts.ToArray());
    }

    /// <summary>Shallow copy with independent attribute lists.</summary>
    public CmsSignerInfo Clone() => new(
        Version,
        Sid,
        DigestAlgorithm,
        SignedAttributes?.ToList(),
        SignatureAlgorithm,
        Signature,
        UnsignedAttributes?.ToList());

    /// <summary>Parse an encoded <c>SignerInfo</c>.</summary>
    public static CmsSignerInfo Parse(ReadOnlySpan<byte> der)
    {
        var outer = Der.First(der);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            throw new PsignException("SignerInfo: expected SEQUENCE");
        }

        var c = Der.Children(der, outer.Value) ?? throw new PsignException("SignerInfo: malformed content");
        if (c.Count < 5)
        {
            throw new PsignException("SignerInfo: too few fields");
        }

        int i = 0;
        int version = DecodeSmallInteger(c[i++].Encoded(der));
        byte[] sid = c[i++].Encoded(der).ToArray();
        var digestAlg = AlgorithmIdentifier.Parse(c[i++].Encoded(der));
        List<CmsAttribute>? signed = null;
        if (c[i].Tag == 0xA0)
        {
            signed = CmsAttribute.ParseSetContent(c[i].Value(der));
            i++;
        }

        if (i + 2 > c.Count)
        {
            throw new PsignException("SignerInfo: missing signatureAlgorithm/signature");
        }

        var sigAlg = AlgorithmIdentifier.Parse(c[i++].Encoded(der));
        if (c[i].Tag != 0x04)
        {
            throw new PsignException("SignerInfo: signature is not an OCTET STRING");
        }

        byte[] signature = c[i++].Value(der).ToArray();
        List<CmsAttribute>? unsigned = null;
        if (i < c.Count && c[i].Tag == 0xA1)
        {
            unsigned = CmsAttribute.ParseSetContent(c[i].Value(der));
            i++;
        }

        if (i != c.Count)
        {
            throw new PsignException("SignerInfo: unexpected trailing fields");
        }

        return new CmsSignerInfo(version, sid, digestAlg, signed, sigAlg, signature, unsigned);
    }

    internal static byte[] EncodeSmallInteger(int value)
    {
        var w = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        w.WriteInteger(value);
        return w.Encode();
    }

    internal static int DecodeSmallInteger(ReadOnlySpan<byte> tlv)
    {
        var t = Der.First(tlv);
        if (t is null || t.Value.Tag != 0x02 || t.Value.ValueLength is 0 or > 4)
        {
            throw new PsignException("expected small INTEGER");
        }

        return (int)new BigInteger(t.Value.Value(tlv), isUnsigned: false, isBigEndian: true);
    }
}
