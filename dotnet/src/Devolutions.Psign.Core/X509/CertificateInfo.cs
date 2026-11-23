using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.X509;

/// <summary>An X.509 v3 extension with raw value octets.</summary>
public sealed record CertificateExtension(string Oid, bool Critical, byte[] Value);

/// <summary>
/// Lightweight structural view of an X.509 certificate that keeps the raw DER of every field. Name comparisons are
/// done on raw DER (as the Rust <c>x509-cert</c> structural equality does) rather than on rendered strings.
/// </summary>
public sealed class CertificateInfo : IEquatable<CertificateInfo>
{
    private X509Certificate2? _x509;

    private CertificateInfo(byte[] der)
    {
        RawData = der;
        ReadOnlySpan<byte> d = der;
        var outer = Der.First(d);
        if (outer is null || outer.Value.Tag != 0x30 || outer.Value.End != d.Length)
        {
            throw new PsignException("certificate: expected outer SEQUENCE");
        }

        var top = Der.Children(d, outer.Value);
        if (top is null || top.Count != 3 || top[0].Tag != 0x30 || top[2].Tag != 0x03)
        {
            throw new PsignException("certificate: expected tbsCertificate, signatureAlgorithm, signatureValue");
        }

        TbsCertificate = top[0].Encoded(d).ToArray();
        SignatureAlgorithm = AlgorithmIdentifier.Parse(top[1].Encoded(d));
        var sigBits = top[2].Value(d);
        if (sigBits.IsEmpty)
        {
            throw new PsignException("certificate: empty signature BIT STRING");
        }

        Signature = sigBits[1..].ToArray();

        var tbs = Der.Children(d, top[0]) ?? throw new PsignException("certificate: malformed tbsCertificate");
        int i = 0;
        Version = 1;
        if (tbs.Count > 0 && tbs[0].Tag == 0xA0)
        {
            var verChildren = Der.Children(d, tbs[0]);
            if (verChildren is { Count: 1 } && verChildren[0].Tag == 0x02)
            {
                Version = (int)new BigInteger(verChildren[0].Value(d), isUnsigned: false, isBigEndian: true) + 1;
            }

            i++;
        }

        if (tbs.Count < i + 6)
        {
            throw new PsignException("certificate: tbsCertificate has too few fields");
        }

        if (tbs[i].Tag != 0x02)
        {
            throw new PsignException("certificate: expected serialNumber INTEGER");
        }

        SerialNumberEncoded = tbs[i].Encoded(d).ToArray();
        SerialNumber = tbs[i].Value(d).ToArray();
        i++;
        TbsSignatureAlgorithm = AlgorithmIdentifier.Parse(tbs[i].Encoded(d));
        i++;
        Issuer = tbs[i].Encoded(d).ToArray();
        i++;
        var validity = Der.Children(d, tbs[i]);
        if (validity is null || validity.Count != 2)
        {
            throw new PsignException("certificate: malformed validity");
        }

        NotBefore = Asn1Time.Decode(validity[0].Encoded(d));
        NotAfter = Asn1Time.Decode(validity[1].Encoded(d));
        i++;
        Subject = tbs[i].Encoded(d).ToArray();
        i++;
        SubjectPublicKeyInfo = tbs[i].Encoded(d).ToArray();
        i++;
        var spki = Der.Children(d, tbs[i - 1]);
        if (spki is null || spki.Count != 2)
        {
            throw new PsignException("certificate: malformed SubjectPublicKeyInfo");
        }

        PublicKeyAlgorithm = AlgorithmIdentifier.Parse(spki[0].Encoded(d));
        var pkBits = spki[1].Value(d);
        PublicKey = pkBits.IsEmpty ? [] : pkBits[1..].ToArray();

        var extensions = new List<CertificateExtension>();
        for (; i < tbs.Count; i++)
        {
            if (tbs[i].Tag != 0xA3)
            {
                continue;
            }

            var extSeq = Der.Children(d, tbs[i]);
            if (extSeq is not { Count: 1 })
            {
                throw new PsignException("certificate: malformed extensions");
            }

            var exts = Der.Children(d, extSeq[0]) ?? throw new PsignException("certificate: malformed extensions");
            foreach (var ext in exts)
            {
                var parts = Der.Children(d, ext);
                if (parts is null || parts.Count is < 2 or > 3 || parts[0].Tag != 0x06)
                {
                    throw new PsignException("certificate: malformed extension");
                }

                string oid = Der.DecodeOid(parts[0].Encoded(d)) ?? throw new PsignException("certificate: bad extension OID");
                bool critical = false;
                int vi = 1;
                if (parts.Count == 3)
                {
                    critical = parts[1].Value(d) is [not 0];
                    vi = 2;
                }

                if (parts[vi].Tag != 0x04)
                {
                    throw new PsignException("certificate: extension value is not OCTET STRING");
                }

                extensions.Add(new CertificateExtension(oid, critical, parts[vi].Value(d).ToArray()));
            }
        }

        Extensions = extensions;
    }

    /// <summary>Full certificate DER.</summary>
    public byte[] RawData { get; }

    /// <summary>Encoded <c>tbsCertificate</c>.</summary>
    public byte[] TbsCertificate { get; }

    /// <summary>X.509 version (1, 2, or 3).</summary>
    public int Version { get; }

    /// <summary>Serial number INTEGER content octets (two's complement, big-endian, as encoded).</summary>
    public byte[] SerialNumber { get; }

    /// <summary>Serial number full INTEGER TLV.</summary>
    public byte[] SerialNumberEncoded { get; }

    public AlgorithmIdentifier TbsSignatureAlgorithm { get; }

    /// <summary>Encoded issuer <c>Name</c>.</summary>
    public byte[] Issuer { get; }

    /// <summary>Encoded subject <c>Name</c>.</summary>
    public byte[] Subject { get; }

    public DateTimeOffset NotBefore { get; }

    public DateTimeOffset NotAfter { get; }

    /// <summary>Encoded <c>SubjectPublicKeyInfo</c>.</summary>
    public byte[] SubjectPublicKeyInfo { get; }

    public AlgorithmIdentifier PublicKeyAlgorithm { get; }

    /// <summary>Public key BIT STRING payload (without unused-bits octet).</summary>
    public byte[] PublicKey { get; }

    public IReadOnlyList<CertificateExtension> Extensions { get; }

    public AlgorithmIdentifier SignatureAlgorithm { get; }

    /// <summary>Signature BIT STRING payload.</summary>
    public byte[] Signature { get; }

    /// <summary>Lazily created <see cref="X509Certificate2"/> (for key extraction and string rendering).</summary>
    public X509Certificate2 X509 => _x509 ??= X509CertificateLoaderCompat.LoadCertificate(RawData);

    /// <summary>SHA-1 thumbprint (lowercase hex).</summary>
    public string Sha1ThumbprintHex => Hex.Lower(SHA1.HashData(RawData));

    /// <summary>SHA-256 thumbprint (lowercase hex).</summary>
    public string Sha256ThumbprintHex => Hex.Lower(SHA256.HashData(RawData));

    /// <summary>Serial number as uppercase hex (as encoded, including leading zero octets).</summary>
    public string SerialNumberHex => Hex.Upper(SerialNumber);

    /// <summary>RFC 4514-ish rendering of the subject via .NET.</summary>
    public string SubjectName => new X500DistinguishedName(Subject).Name;

    /// <summary>RFC 4514-ish rendering of the issuer via .NET.</summary>
    public string IssuerName => new X500DistinguishedName(Issuer).Name;

    /// <summary>True when subject and issuer names are byte-identical.</summary>
    public bool IsSelfIssued => Subject.AsSpan().SequenceEqual(Issuer);

    /// <summary>Find an extension by OID.</summary>
    public CertificateExtension? GetExtension(string oid) => Extensions.FirstOrDefault(e => e.Oid == oid);

    /// <summary>BasicConstraints cA flag (false when absent or unparsable).</summary>
    public bool IsCa
    {
        get
        {
            var ext = GetExtension(Oids.BasicConstraints);
            if (ext is null)
            {
                return false;
            }

            try
            {
                var r = new AsnReader(ext.Value, AsnEncodingRules.BER).ReadSequence();
                return r.HasData && r.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && r.ReadBoolean();
            }
            catch (AsnContentException)
            {
                return false;
            }
        }
    }

    /// <summary>BasicConstraints pathLenConstraint when present.</summary>
    public int? PathLengthConstraint
    {
        get
        {
            var ext = GetExtension(Oids.BasicConstraints);
            if (ext is null)
            {
                return null;
            }

            try
            {
                var r = new AsnReader(ext.Value, AsnEncodingRules.BER).ReadSequence();
                if (r.HasData && r.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                {
                    r.ReadBoolean();
                }

                if (r.HasData && r.TryReadInt32(out int len))
                {
                    return len;
                }
            }
            catch (AsnContentException)
            {
            }

            return null;
        }
    }

    /// <summary>Extended key usage OIDs, or <c>null</c> when the extension is absent or malformed.</summary>
    public IReadOnlyList<string>? ExtendedKeyUsages
    {
        get
        {
            var ext = GetExtension(Oids.ExtendedKeyUsage);
            if (ext is null)
            {
                return null;
            }

            try
            {
                var r = new AsnReader(ext.Value, AsnEncodingRules.BER).ReadSequence();
                var list = new List<string>();
                while (r.HasData)
                {
                    list.Add(r.ReadObjectIdentifier());
                }

                return list;
            }
            catch (AsnContentException)
            {
                return null;
            }
        }
    }

    /// <summary>Key usage bits (X509KeyUsageFlags) when present.</summary>
    public X509KeyUsageFlags? KeyUsage
    {
        get
        {
            var ext = GetExtension(Oids.KeyUsage);
            if (ext is null)
            {
                return null;
            }

            try
            {
                return new X509KeyUsageExtension(new AsnEncodedData(Oids.KeyUsage, ext.Value), ext.Critical).KeyUsages;
            }
            catch (CryptographicException)
            {
                return null;
            }
        }
    }

    /// <summary>Subject key identifier extension value when present.</summary>
    public byte[]? SubjectKeyIdentifier
    {
        get
        {
            var ext = GetExtension(Oids.SubjectKeyIdentifier);
            if (ext is null)
            {
                return null;
            }

            try
            {
                return new AsnReader(ext.Value, AsnEncodingRules.BER).ReadOctetString();
            }
            catch (AsnContentException)
            {
                return null;
            }
        }
    }

    /// <summary>Authority key identifier keyIdentifier field when present.</summary>
    public byte[]? AuthorityKeyIdentifier
    {
        get
        {
            var ext = GetExtension(Oids.AuthorityKeyIdentifier);
            if (ext is null)
            {
                return null;
            }

            try
            {
                var r = new AsnReader(ext.Value, AsnEncodingRules.BER).ReadSequence();
                if (r.HasData && r.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    return r.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }
            }
            catch (AsnContentException)
            {
            }

            return null;
        }
    }

    /// <summary>Parse certificate DER.</summary>
    public static CertificateInfo Parse(ReadOnlySpan<byte> der) => new(der.ToArray());

    /// <summary>Parse certificate DER, returning <c>null</c> when malformed.</summary>
    public static CertificateInfo? TryParse(ReadOnlySpan<byte> der)
    {
        try
        {
            return new CertificateInfo(der.ToArray());
        }
        catch (Exception e) when (e is PsignException or AsnContentException or CryptographicException or FormatException)
        {
            return null;
        }
    }

    /// <summary>Wrap an existing <see cref="X509Certificate2"/>.</summary>
    public static CertificateInfo From(X509Certificate2 cert)
    {
        var info = new CertificateInfo(cert.RawData);
        info._x509 = cert;
        return info;
    }

    /// <summary>True when issuer DER and serial number match (CMS <c>IssuerAndSerialNumber</c> identity).</summary>
    public bool SameIssuerAndSerial(CertificateInfo other) =>
        Issuer.AsSpan().SequenceEqual(other.Issuer) && SerialNumber.AsSpan().SequenceEqual(other.SerialNumber);

    /// <summary>True when <paramref name="other"/>'s issuer name equals this certificate's subject name.</summary>
    public bool IsIssuerOf(CertificateInfo other) => Subject.AsSpan().SequenceEqual(other.Issuer);

    /// <summary>
    /// Verify that this certificate was signed by <paramref name="issuer"/>'s public key (RSA PKCS#1 v1.5, RSA-PSS, ECDSA).
    /// </summary>
    public bool VerifySignatureBy(CertificateInfo issuer) =>
        SignatureVerifier.Verify(issuer.SubjectPublicKeyInfo, SignatureAlgorithm, TbsCertificate, Signature);

    public bool Equals(CertificateInfo? other) => other is not null && RawData.AsSpan().SequenceEqual(other.RawData);

    public override bool Equals(object? obj) => obj is CertificateInfo c && Equals(c);

    public override int GetHashCode()
    {
        var h = new HashCode();
        h.AddBytes(RawData.AsSpan(0, Math.Min(64, RawData.Length)));
        h.Add(RawData.Length);
        return h.ToHashCode();
    }

    public override string ToString() => SubjectName;
}
