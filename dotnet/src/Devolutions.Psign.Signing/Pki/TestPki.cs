using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Internal;
using Devolutions.Psign.Signing.Keys;

namespace Devolutions.Psign.Signing.Pki;

/// <summary>Parameters for generating a self-signed test Root CA (Rust <c>RootCaSpec</c>).</summary>
public sealed record RootCaSpec(string Subject, uint ValidityDays = 3650, int KeyBits = 2048);

/// <summary>Parameters for issuing a Code Signing leaf certificate (Rust <c>CodeSigningCertSpec</c>).</summary>
public sealed record CodeSigningCertSpec(string Subject, uint ValidityDays = 365, int KeyBits = 2048, IReadOnlyList<string>? ExtraEkuOids = null);

/// <summary>Parameters for issuing a TLS Server leaf certificate (Rust <c>TlsServerCertSpec</c>).</summary>
public sealed record TlsServerCertSpec(
    string? Subject,
    IReadOnlyList<string> DnsNames,
    IReadOnlyList<IPAddress> IpAddresses,
    uint ValidityDays = 365,
    int KeyBits = 2048);

/// <summary>CA signing material used to issue leaf certificates (Rust <c>CaIssuerMaterial</c>).</summary>
public sealed class CaIssuerMaterial
{
    internal CaIssuerMaterial(CertificateInfo certificate, PrivateKeyMaterial privateKey, IReadOnlyList<byte[]> extraChainCertificatesDer)
    {
        Certificate = certificate;
        PrivateKey = privateKey;
        ExtraChainCertificatesDer = extraChainCertificatesDer;
    }

    public CertificateInfo Certificate { get; }

    public byte[] CertificateDer => Certificate.RawData;

    public PrivateKeyMaterial PrivateKey { get; }

    public IReadOnlyList<byte[]> ExtraChainCertificatesDer { get; }
}

/// <summary>Generated certificate, private key and chain (Rust <c>GeneratedCertMaterial</c>).</summary>
public sealed class GeneratedCertMaterial
{
    internal GeneratedCertMaterial(CertificateInfo certificate, PrivateKeyMaterial privateKey, IReadOnlyList<byte[]> chainCertificatesDer, GeneratedCertSummary summary)
    {
        Certificate = certificate;
        PrivateKey = privateKey;
        ChainCertificatesDer = chainCertificatesDer;
        Summary = summary;
    }

    public CertificateInfo Certificate { get; }

    public byte[] CertificateDer => Certificate.RawData;

    public PrivateKeyMaterial PrivateKey { get; }

    /// <summary>Unencrypted PKCS#8 PEM (Rust <c>private_key_pem</c>).</summary>
    public string PrivateKeyPem => PrivateKey.ToPkcs8Pem();

    /// <summary>Issuer chain certificates (CA first), empty for a root.</summary>
    public IReadOnlyList<byte[]> ChainCertificatesDer { get; }

    public GeneratedCertSummary Summary { get; }

    /// <summary>Use this material as an issuing CA (for example a freshly generated root).</summary>
    public CaIssuerMaterial AsIssuer() => TestPki.BuildCaIssuerMaterial(CertificateDer, PrivateKey, ChainCertificatesDer.ToList());
}

/// <summary>Machine-readable metadata describing a generated certificate (Rust <c>GeneratedCertSummary</c>).</summary>
public sealed record GeneratedCertSummary(
    string Subject,
    string Issuer,
    string ThumbprintSha1,
    string ThumbprintSha256,
    string SerialHex,
    string NotBefore,
    string NotAfter,
    bool IsCa,
    IReadOnlyList<string> EkuOids,
    IReadOnlyList<string> DnsNames,
    IReadOnlyList<string> IpAddresses,
    int ChainCertificateCount)
{
    /// <summary>JSON object with the Rust <c>serde</c> field names (empty lists omitted).</summary>
    public JsonObject ToJsonObject()
    {
        var o = new JsonObject
        {
            ["subject"] = Subject,
            ["issuer"] = Issuer,
            ["thumbprint_sha1"] = ThumbprintSha1,
            ["thumbprint_sha256"] = ThumbprintSha256,
            ["serial_hex"] = SerialHex,
            ["not_before"] = NotBefore,
            ["not_after"] = NotAfter,
            ["is_ca"] = IsCa,
        };
        if (EkuOids.Count > 0)
        {
            o["eku_oids"] = new JsonArray(EkuOids.Select(e => (JsonNode)JsonValue.Create(e)!).ToArray());
        }

        if (DnsNames.Count > 0)
        {
            o["dns_names"] = new JsonArray(DnsNames.Select(e => (JsonNode)JsonValue.Create(e)!).ToArray());
        }

        if (IpAddresses.Count > 0)
        {
            o["ip_addresses"] = new JsonArray(IpAddresses.Select(e => (JsonNode)JsonValue.Create(e)!).ToArray());
        }

        o["chain_certificate_count"] = ChainCertificateCount;
        return o;
    }

    /// <summary><c>serde_json::to_string_pretty</c> rendering.</summary>
    public string ToJson() => SerdeJson.Pretty(ToJsonObject());
}

/// <summary>
/// Portable test PKI generation (port of Rust <c>psign-authenticode-trust/src/test_pki.rs</c>): RFC 5280 / CryptoAPI
/// compatible Root CA, Code Signing and TLS Server certificates plus PKCS#12 and PEM bundles, without touching OS stores.
/// </summary>
public static class TestPki
{
    /// <summary>Backdate generated certificates by 24 hours so VM clock skew does not reject fresh certificates.</summary>
    public static readonly TimeSpan NotBeforeClockSkew = TimeSpan.FromSeconds(86_400);

    internal const string OidSha256WithRsa = "1.2.840.113549.1.1.11";
    internal const string OidEkuServerAuth = "1.3.6.1.5.5.7.3.1";
    internal const string OidEkuCodeSigning = "1.3.6.1.5.5.7.3.3";
    internal const string OidAnyExtendedKeyUsage = "2.5.29.37.0";
    internal const string OidSubjectKeyIdentifier = "2.5.29.14";
    internal const string OidKeyUsage = "2.5.29.15";
    internal const string OidSubjectAltName = "2.5.29.17";
    internal const string OidBasicConstraints = "2.5.29.19";
    internal const string OidAuthorityKeyIdentifier = "2.5.29.35";
    internal const string OidExtendedKeyUsage = "2.5.29.37";

    // KeyUsage bit positions (RFC 5280 4.2.1.3).
    private const int KuDigitalSignature = 0;
    private const int KuKeyEncipherment = 2;
    private const int KuKeyCertSign = 5;
    private const int KuCrlSign = 6;

    /// <summary>Time source (overridable for tests).</summary>
    internal static Func<DateTimeOffset> UtcNow { get; set; } = () => DateTimeOffset.UtcNow;

    /// <summary>Load CA signing material from a PKCS#12 archive (Rust <c>load_ca_issuer_from_pfx</c>).</summary>
    public static CaIssuerMaterial LoadCaIssuerFromPfx(byte[] pfx, string password)
    {
        var parsed = Pkcs12Identity.Parse(pfx, password);
        return BuildCaIssuerMaterial(parsed.SignerCertificateDer, parsed.PrivateKey, parsed.ChainCertificatesDer.ToList());
    }

    /// <summary>
    /// Load CA signing material from separate certificate (DER / PEM) and RSA private key (DER / PEM) bytes
    /// (Rust <c>load_ca_issuer_from_cert_and_key</c>).
    /// </summary>
    public static CaIssuerMaterial LoadCaIssuerFromCertAndKey(byte[] certBytes, byte[] keyBytes, IReadOnlyList<byte[]>? extraChainCertificatesDer = null)
    {
        CertificateInfo cert;
        try
        {
            cert = SigningMaterialLoader.ParseCertificate(certBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException("parse CA certificate", e);
        }

        PrivateKeyMaterial key;
        try
        {
            key = SigningMaterialLoader.ParseRsaPrivateKeyMaterial(keyBytes);
        }
        catch (PsignException e)
        {
            throw new PsignException("parse CA RSA private key", e);
        }

        return BuildCaIssuerMaterial(cert.RawData, key, extraChainCertificatesDer?.ToList() ?? []);
    }

    internal static CaIssuerMaterial BuildCaIssuerMaterial(byte[] certDer, PrivateKeyMaterial key, List<byte[]> extraChain)
    {
        CertificateInfo cert;
        try
        {
            cert = CertificateInfo.Parse(certDer);
        }
        catch (PsignException e)
        {
            throw new PsignException("parse CA X.509 certificate", e);
        }

        if (!IsCa(cert))
        {
            throw new PsignException($"issuer certificate '{DistinguishedName.FormatWindows(cert.Subject)}' is not a CA certificate (BasicConstraints CA=true required)");
        }

        if (key.Algorithm != PrivateKeyAlgorithm.Rsa)
        {
            throw new PsignException("parse CA RSA private key", new PsignException($"private key algorithm {key.AlgorithmOid} is not RSA"));
        }

        try
        {
            key.EnsureMatchesCertificate(cert);
        }
        catch (PsignException e)
        {
            throw new PsignException("verify CA private key matches CA certificate", e);
        }

        return new CaIssuerMaterial(cert, key, extraChain);
    }

    /// <summary>Generate a self-signed X.509 v3 Root CA certificate and RSA key (Rust <c>generate_root_ca</c>).</summary>
    public static GeneratedCertMaterial GenerateRootCa(RootCaSpec spec)
    {
        ValidateKeyBits(spec.KeyBits);
        if (spec.ValidityDays == 0)
        {
            throw new PsignException("validity_days must be at least 1");
        }

        var subject = DistinguishedName.Parse(spec.Subject);
        using var rsa = RSA.Create(spec.KeyBits);
        var key = PrivateKeyMaterial.FromRsa(rsa);
        var spki = rsa.ExportSubjectPublicKeyInfo();

        var now = UtcNow();
        var notBefore = now - NotBeforeClockSkew;
        var notAfter = now + TimeSpan.FromDays(spec.ValidityDays);

        var extensions = new List<byte[]>
        {
            Extension(OidSubjectKeyIdentifier, false, Der.EncodeTlv(0x04, ComputeSki(spki))),
            Extension(OidBasicConstraints, true, BasicConstraints(true)),
            Extension(OidKeyUsage, true, KeyUsage(KuKeyCertSign, KuCrlSign)),
        };

        var certDer = BuildAndSign(subject, subject, notBefore, notAfter, spki, extensions, rsa);
        return Finalize(certDer, key, [], [], [], []);
    }

    /// <summary>
    /// Issue an X.509 v3 Code Signing leaf certificate chained to <paramref name="ca"/> (Rust <c>issue_code_signing_cert</c>):
    /// SKI, AKI, <c>BasicConstraints(CA=false)</c>, <c>KeyUsage(DigitalSignature)</c>, <c>ExtendedKeyUsage(codeSigning, ...)</c>.
    /// </summary>
    public static GeneratedCertMaterial IssueCodeSigningCert(CaIssuerMaterial ca, CodeSigningCertSpec spec)
    {
        ValidateKeyBits(spec.KeyBits);
        if (spec.ValidityDays == 0)
        {
            throw new PsignException("validity_days must be at least 1");
        }

        var subject = DistinguishedName.Parse(spec.Subject);
        var ekuOids = new List<string> { OidEkuCodeSigning };
        foreach (var extra in spec.ExtraEkuOids ?? [])
        {
            var oid = extra.Trim();
            if (!DistinguishedName.IsValidOid(oid))
            {
                throw new PsignException($"invalid extra EKU OID '{extra}': OID malformed");
            }

            if (!ekuOids.Contains(oid))
            {
                ekuOids.Add(oid);
            }
        }

        using var rsa = RSA.Create(spec.KeyBits);
        var key = PrivateKeyMaterial.FromRsa(rsa);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var (notBefore, notAfter) = LeafValidityClampedToCa(ca, spec.ValidityDays);

        var extensions = new List<byte[]>
        {
            Extension(OidSubjectKeyIdentifier, false, Der.EncodeTlv(0x04, ComputeSki(spki))),
            Extension(OidAuthorityKeyIdentifier, false, AuthorityKeyIdentifier(ExtractOrComputeCaSki(ca.Certificate))),
            Extension(OidBasicConstraints, true, BasicConstraints(false)),
            Extension(OidKeyUsage, true, KeyUsage(KuDigitalSignature)),
            Extension(OidExtendedKeyUsage, !ekuOids.Contains(OidAnyExtendedKeyUsage), Der.EncodeSequence(ekuOids.Select(Der.EncodeOid).ToArray())),
        };

        using var caKey = ca.PrivateKey.CreateRsa();
        var certDer = BuildAndSign(ca.Certificate.Subject, subject, notBefore, notAfter, spki, extensions, caKey);
        var chain = new List<byte[]> { ca.CertificateDer };
        chain.AddRange(ca.ExtraChainCertificatesDer);
        return Finalize(certDer, key, chain, ekuOids, [], []);
    }

    /// <summary>
    /// Issue an X.509 v3 TLS Server leaf certificate with DNS and/or IP SANs chained to <paramref name="ca"/>
    /// (Rust <c>issue_tls_server_cert</c>).
    /// </summary>
    public static GeneratedCertMaterial IssueTlsServerCert(CaIssuerMaterial ca, TlsServerCertSpec spec)
    {
        ValidateKeyBits(spec.KeyBits);
        if (spec.ValidityDays == 0)
        {
            throw new PsignException("validity_days must be at least 1");
        }

        if (spec.DnsNames.Count == 0 && spec.IpAddresses.Count == 0)
        {
            throw new PsignException("TLS server certificate requires at least one --dns or --ip Subject Alternative Name");
        }

        var sanEntries = new List<byte[]>();
        var normalizedDns = new List<string>();
        foreach (var dns in spec.DnsNames)
        {
            var host = dns.Trim();
            if (host.Length == 0)
            {
                throw new PsignException("DNS Subject Alternative Name must not be empty");
            }

            if (host.Any(c => c > 0x7F))
            {
                throw new PsignException($"DNS Subject Alternative Name '{host}' must be ASCII IA5String: malformed ASN.1 DER value for IA5String");
            }

            sanEntries.Add(Der.EncodeTlv(0x82, Encoding.ASCII.GetBytes(host)));
            normalizedDns.Add(host);
        }

        var normalizedIps = new List<string>();
        foreach (var ip in spec.IpAddresses)
        {
            sanEntries.Add(Der.EncodeTlv(0x87, ip.GetAddressBytes()));
            normalizedIps.Add(FormatIp(ip));
        }

        var subjectText = spec.Subject?.Trim();
        if (string.IsNullOrEmpty(subjectText))
        {
            var primary = normalizedDns.Count > 0 ? normalizedDns[0] : normalizedIps[0];
            subjectText = "CN=" + DistinguishedName.QuoteWindowsValue(primary);
        }

        var subject = DistinguishedName.Parse(subjectText);
        using var rsa = RSA.Create(spec.KeyBits);
        var key = PrivateKeyMaterial.FromRsa(rsa);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var (notBefore, notAfter) = LeafValidityClampedToCa(ca, spec.ValidityDays);

        var extensions = new List<byte[]>
        {
            Extension(OidSubjectKeyIdentifier, false, Der.EncodeTlv(0x04, ComputeSki(spki))),
            Extension(OidAuthorityKeyIdentifier, false, AuthorityKeyIdentifier(ExtractOrComputeCaSki(ca.Certificate))),
            Extension(OidBasicConstraints, true, BasicConstraints(false)),
            Extension(OidKeyUsage, true, KeyUsage(KuDigitalSignature, KuKeyEncipherment)),
            Extension(OidExtendedKeyUsage, true, Der.EncodeSequence(Der.EncodeOid(OidEkuServerAuth))),
            Extension(OidSubjectAltName, false, Der.EncodeSequence(sanEntries.ToArray())),
        };

        using var caKey = ca.PrivateKey.CreateRsa();
        var certDer = BuildAndSign(ca.Certificate.Subject, subject, notBefore, notAfter, spki, extensions, caKey);
        var chain = new List<byte[]> { ca.CertificateDer };
        chain.AddRange(ca.ExtraChainCertificatesDer);
        return Finalize(certDer, key, chain, [OidEkuServerAuth], normalizedDns, normalizedIps);
    }

    /// <summary>
    /// Encode certificate, key and chain as a password-protected PKCS#12 archive using PBES2 (AES-256-CBC +
    /// PBKDF2-HMAC-SHA256) and an HMAC-SHA256 MAC (Rust <c>encode_pfx_der</c>). The <c>localKeyId</c> is the SHA-1 of the
    /// leaf's subject public key bits.
    /// </summary>
    public static byte[] EncodePfxDer(GeneratedCertMaterial material, string password)
    {
        var localKeyId = SHA1.HashData(material.Certificate.PublicKey);
        return Pkcs12Writer.Encode(material.CertificateDer, material.PrivateKey, material.ChainCertificatesDer, localKeyId, password);
    }

    /// <summary>Encode a certificate, key and chain as PKCS#12 (same format as <see cref="EncodePfxDer(GeneratedCertMaterial, string)"/>).</summary>
    public static byte[] EncodePfxDer(byte[] certificateDer, PrivateKeyMaterial key, IEnumerable<byte[]> chainCertificatesDer, string password)
    {
        var cert = CertificateInfo.Parse(certificateDer);
        return Pkcs12Writer.Encode(certificateDer, key, chainCertificatesDer, SHA1.HashData(cert.PublicKey), password);
    }

    /// <summary>Encode DER certificates as a PEM bundle (Rust <c>encode_pem_certificate_bundle</c>).</summary>
    public static string EncodePemCertificateBundle(IEnumerable<byte[]> certificatesDer)
    {
        var sb = new StringBuilder();
        foreach (var der in certificatesDer)
        {
            sb.Append(Pem.Encode("CERTIFICATE", der));
        }

        return sb.ToString();
    }

    internal static bool IsCa(CertificateInfo cert)
    {
        var bc = cert.GetExtension(OidBasicConstraints);
        if (bc is null)
        {
            return false;
        }

        var seq = Der.First(bc.Value);
        if (seq is null || seq.Value.Tag != 0x30)
        {
            return false;
        }

        var children = Der.Children(bc.Value, seq.Value);
        return children is { Count: > 0 } && children[0].Tag == 0x01 && children[0].Value(bc.Value) is [not 0];
    }

    private static void ValidateKeyBits(int keyBits)
    {
        if (keyBits is not (2048 or 3072 or 4096))
        {
            throw new PsignException($"unsupported RSA key size {keyBits}; supported values are 2048, 3072, or 4096");
        }
    }

    /// <summary>16 random bytes, high bit cleared and second bit set (minimal positive INTEGER, 16 octets).</summary>
    internal static byte[] RandomSerialNumber()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        bytes[0] &= 0x7f;
        if (bytes.All(b => b == 0))
        {
            bytes[15] = 1;
        }

        bytes[0] |= 0x40;
        return bytes;
    }

    private static byte[] ComputeSki(byte[] spki) => SHA1.HashData(SpkiPublicKeyBits(spki));

    private static byte[] SpkiPublicKeyBits(byte[] spki)
    {
        var outer = Der.First(spki) ?? throw new PsignException("malformed SubjectPublicKeyInfo");
        var children = Der.Children(spki, outer);
        if (children is not { Count: 2 } || children[1].Tag != 0x03)
        {
            throw new PsignException("malformed SubjectPublicKeyInfo");
        }

        return children[1].Value(spki)[1..].ToArray();
    }

    private static byte[] ExtractOrComputeCaSki(CertificateInfo ca)
    {
        if (ca.SubjectKeyIdentifier is { } ski)
        {
            return ski;
        }

        return SHA1.HashData(ca.PublicKey);
    }

    private static byte[] Extension(string oid, bool critical, byte[] value) =>
        critical
            ? Der.EncodeSequence(Der.EncodeOid(oid), [0x01, 0x01, 0xFF], Der.EncodeTlv(0x04, value))
            : Der.EncodeSequence(Der.EncodeOid(oid), Der.EncodeTlv(0x04, value));

    private static byte[] BasicConstraints(bool ca) => ca ? [0x30, 0x03, 0x01, 0x01, 0xFF] : [0x30, 0x00];

    private static byte[] AuthorityKeyIdentifier(byte[] keyId) => Der.EncodeSequence(Der.EncodeTlv(0x80, keyId));

    /// <summary>DER <c>KeyUsage</c> BIT STRING with trailing zero bits removed.</summary>
    internal static byte[] KeyUsage(params int[] bits)
    {
        var highest = bits.Max();
        var length = (highest / 8) + 1;
        var content = new byte[length];
        foreach (var bit in bits)
        {
            content[bit / 8] |= (byte)(0x80 >> (bit % 8));
        }

        var unused = 7 - (highest % 8);
        return Der.EncodeTlv(0x03, [(byte)unused, .. content]);
    }

    private static (DateTimeOffset NotBefore, DateTimeOffset NotAfter) LeafValidityClampedToCa(CaIssuerMaterial ca, uint validityDays)
    {
        var now = UtcNow();
        var caNotBefore = ca.Certificate.NotBefore;
        var caNotAfter = ca.Certificate.NotAfter;
        if (caNotAfter <= now)
        {
            throw new PsignException($"CA certificate is expired (not_after={Asn1Time.Rfc3339(caNotAfter)})");
        }

        var desiredNotBefore = now - NotBeforeClockSkew;
        var notBefore = desiredNotBefore > caNotBefore ? desiredNotBefore : caNotBefore;
        var desiredNotAfter = now + TimeSpan.FromDays(validityDays);
        var notAfter = desiredNotAfter < caNotAfter ? desiredNotAfter : caNotAfter;
        return (notBefore, notAfter);
    }

    private static byte[] BuildAndSign(byte[] issuer, byte[] subject, DateTimeOffset notBefore, DateTimeOffset notAfter, byte[] spki, List<byte[]> extensions, RSA signer)
    {
        if (TruncateSeconds(notAfter) <= TruncateSeconds(notBefore))
        {
            throw new PsignException("certificate not_after must be strictly after not_before");
        }

        var sigAlg = Der.EncodeSequence(Der.EncodeOid(OidSha256WithRsa), Der.Null);
        var tbs = Der.EncodeSequence(
            Der.EncodeTlv(0xA0, [0x02, 0x01, 0x02]),
            Der.EncodeTlv(0x02, RandomSerialNumber()),
            sigAlg,
            issuer,
            Der.EncodeSequence(Asn1Time.EncodeTime(notBefore), Asn1Time.EncodeTime(notAfter)),
            subject,
            spki,
            Der.EncodeTlv(0xA3, Der.EncodeSequence(extensions.ToArray())));
        var signature = signer.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Der.EncodeSequence(tbs, sigAlg, Der.EncodeTlv(0x03, [0x00, .. signature]));
    }

    private static DateTimeOffset TruncateSeconds(DateTimeOffset t)
    {
        var u = t.ToUniversalTime();
        return new DateTimeOffset(u.Year, u.Month, u.Day, u.Hour, u.Minute, u.Second, TimeSpan.Zero);
    }

    private static GeneratedCertMaterial Finalize(byte[] certDer, PrivateKeyMaterial key, List<byte[]> chain, List<string> ekuOids, List<string> dnsNames, List<string> ipAddresses)
    {
        var cert = CertificateInfo.Parse(certDer);
        var summary = new GeneratedCertSummary(
            DistinguishedName.FormatWindows(cert.Subject),
            DistinguishedName.FormatWindows(cert.Issuer),
            Hex.Upper(SHA1.HashData(certDer)),
            Hex.Upper(SHA256.HashData(certDer)),
            Hex.Upper(cert.SerialNumber),
            Asn1Time.Rfc3339(cert.NotBefore),
            Asn1Time.Rfc3339(cert.NotAfter),
            IsCa(cert),
            ekuOids,
            dnsNames,
            ipAddresses,
            chain.Count);
        return new GeneratedCertMaterial(cert, key, chain, summary);
    }

    /// <summary>Rust <c>IpAddr</c> <c>Display</c>.</summary>
    internal static string FormatIp(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var copy = new IPAddress(ip.GetAddressBytes());
            return copy.ToString();
        }

        return ip.ToString();
    }
}
