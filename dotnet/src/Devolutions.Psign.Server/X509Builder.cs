using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core.Asn1;

namespace Devolutions.Psign.Server;

/// <summary>
/// Emulation of the Rust <c>x509-cert</c> 0.2.5 <c>CertificateBuilder</c> as used by <c>psign-server.rs</c>
/// (<c>Profile::Root</c> / <c>Profile::Leaf</c> with RSA PKCS#1 v1.5 SHA-256 signers): v3 certificates with the same
/// extension order, criticality and encodings (SKI, AKI, BasicConstraints, KeyUsage, then added extensions such as an
/// ExtendedKeyUsage that is critical unless it contains anyExtendedKeyUsage), <c>Validity::from_now</c> truncated to
/// seconds and encoded as UTCTime before 2050.
/// </summary>
internal static class X509Builder
{
    internal const string OidSha256WithRsa = "1.2.840.113549.1.1.11";
    internal const string OidCommonName = "2.5.4.3";
    internal const string OidSubjectKeyIdentifier = "2.5.29.14";
    internal const string OidKeyUsage = "2.5.29.15";
    internal const string OidBasicConstraints = "2.5.29.19";
    internal const string OidAuthorityKeyIdentifier = "2.5.29.35";
    internal const string OidExtendedKeyUsage = "2.5.29.37";
    internal const string OidAnyExtendedKeyUsage = "2.5.29.37.0";

    /// <summary><c>sha256WithRSAEncryption</c> with NULL parameters (rsa crate <c>SigningKey&lt;Sha256&gt;</c>).</summary>
    internal static readonly byte[] Sha256WithRsaEncryptionDer =
    [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];

    /// <summary>Validity duration used by every generated certificate (<c>86_400 * 365</c> seconds).</summary>
    internal static readonly TimeSpan OneYear = TimeSpan.FromSeconds(86_400L * 365);

    /// <summary>Time source (overridable by tests).</summary>
    internal static Func<DateTimeOffset> UtcNow { get; set; } = () => DateTimeOffset.UtcNow;

    /// <summary><c>Name::from_str("CN=...")</c>: one RDN with a UTF8String common name.</summary>
    public static byte[] CommonNameName(string commonName)
    {
        var atv = Der.EncodeSequence(Der.EncodeOid(OidCommonName), Der.EncodeTlv(0x0c, Encoding.UTF8.GetBytes(commonName)));
        return Der.EncodeSequence(Der.EncodeTlv(0x31, atv));
    }

    /// <summary>Encode a <c>u32</c> serial as a minimal positive DER INTEGER TLV (<c>SerialNumber::from(u32)</c>).</summary>
    public static byte[] SerialInteger(uint serial)
    {
        var o = new List<byte>();
        DerPush.PushIntegerU64(o, serial);
        return o.ToArray();
    }

    /// <summary>Build a self-signed root (<c>Profile::Root</c>).</summary>
    public static byte[] BuildRoot(uint serial, byte[] subjectName, RSA key)
    {
        var spki = key.ExportSubjectPublicKeyInfo();
        var extensions = new List<byte[]>
        {
            Extension(OidSubjectKeyIdentifier, false, Der.EncodeTlv(0x04, KeyIdentifier(spki))),
            Extension(OidBasicConstraints, true, [0x30, 0x03, 0x01, 0x01, 0xff]),
            Extension(OidKeyUsage, true, [0x03, 0x02, 0x01, 0x06]),
        };
        return Build(serial, subjectName, subjectName, spki, extensions, key);
    }

    /// <summary>Build a leaf (<c>Profile::Leaf</c>, no key agreement / encipherment) plus an ExtendedKeyUsage extension.</summary>
    public static byte[] BuildLeaf(uint serial, byte[] issuerName, byte[] subjectName, RSA subjectKey, RSA issuerKey, params string[] ekuOids)
    {
        var spki = subjectKey.ExportSubjectPublicKeyInfo();
        var issuerSpki = issuerKey.ExportSubjectPublicKeyInfo();
        var extensions = new List<byte[]>
        {
            Extension(OidSubjectKeyIdentifier, false, Der.EncodeTlv(0x04, KeyIdentifier(spki))),
            Extension(OidAuthorityKeyIdentifier, false, Der.EncodeSequence(Der.EncodeTlv(0x80, KeyIdentifier(issuerSpki)))),
            Extension(OidBasicConstraints, true, [0x30, 0x00]),
            Extension(OidKeyUsage, true, [0x03, 0x02, 0x06, 0xc0]),
            Extension(OidExtendedKeyUsage, !ekuOids.Contains(OidAnyExtendedKeyUsage), Der.EncodeSequence(ekuOids.Select(Der.EncodeOid).ToArray())),
        };
        return Build(serial, issuerName, subjectName, spki, extensions, issuerKey);
    }

    private static byte[] Build(uint serial, byte[] issuer, byte[] subject, byte[] spki, List<byte[]> extensions, RSA signer)
    {
        var now = UtcNow().ToUniversalTime();
        var notBefore = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second, TimeSpan.Zero);
        var notAfter = notBefore + OneYear;
        var tbs = Der.EncodeSequence(
            Der.EncodeTlv(0xa0, [0x02, 0x01, 0x02]),
            SerialInteger(serial),
            Sha256WithRsaEncryptionDer,
            issuer,
            Der.EncodeSequence(EncodeTime(notBefore), EncodeTime(notAfter)),
            subject,
            spki,
            Der.EncodeTlv(0xa3, Der.EncodeSequence(extensions.ToArray())));
        var signature = signer.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Der.EncodeSequence(tbs, Sha256WithRsaEncryptionDer, Der.EncodeTlv(0x03, [0x00, .. signature]));
    }

    /// <summary>x509-cert <c>Time</c> after <c>rfc5280_adjust_utc_time</c>: UTCTime for 1950..2049, else GeneralizedTime.</summary>
    internal static byte[] EncodeTime(DateTimeOffset t)
    {
        if (t.Year is >= 1950 and < 2050)
        {
            return Der.EncodeTlv(0x17, Encoding.ASCII.GetBytes(t.ToString("yyMMddHHmmss", CultureInfo.InvariantCulture) + "Z"));
        }

        return Der.EncodeTlv(0x18, Encoding.ASCII.GetBytes(t.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z"));
    }

    /// <summary>x509-cert key identifier: SHA-1 of the SPKI <c>subjectPublicKey</c> BIT STRING contents (without the unused-bits octet).</summary>
    internal static byte[] KeyIdentifier(byte[] spki) => SHA1.HashData(SubjectPublicKeyBits(spki));

    internal static byte[] SubjectPublicKeyBits(byte[] spki)
    {
        var outer = Der.First(spki);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            throw new Devolutions.Psign.Core.PsignException("malformed SubjectPublicKeyInfo");
        }

        var children = Der.Children(spki, outer.Value);
        if (children is not { Count: 2 } || children[1].Tag != 0x03)
        {
            throw new Devolutions.Psign.Core.PsignException("malformed SubjectPublicKeyInfo");
        }

        var bitString = children[1].Value(spki);
        if (bitString.Length == 0 || bitString[0] != 0)
        {
            throw new Devolutions.Psign.Core.PsignException("malformed SubjectPublicKeyInfo");
        }

        return bitString[1..].ToArray();
    }

    private static byte[] Extension(string oid, bool critical, byte[] value) =>
        critical
            ? Der.EncodeSequence(Der.EncodeOid(oid), [0x01, 0x01, 0xff], Der.EncodeTlv(0x04, value))
            : Der.EncodeSequence(Der.EncodeOid(oid), Der.EncodeTlv(0x04, value));
}
