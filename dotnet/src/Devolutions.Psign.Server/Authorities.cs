using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Server;

/// <summary>Parsed <c>TimeStampReq</c> fields (Rust <c>TimestampRequest</c>).</summary>
internal sealed class TimestampRequest
{
    public required byte[] DigestAlgTlv { get; init; }

    public required byte[] HashedMessage { get; init; }

    public byte[]? NonceTlv { get; init; }

    /// <summary>Rust <c>parse_timestamp_request_der</c>.</summary>
    public static TimestampRequest Parse(byte[] input)
    {
        var outer = Ctx("TimeStampReq SEQUENCE", () => DerPush.ExpectTlv(input, 0x30));
        int pos = 0;
        var version = Ctx("TimeStampReq.version", () => DerPush.ReadTlv(outer, ref pos));
        if (!version.AsSpan().SequenceEqual(new byte[] { 0x02, 0x01, 0x01 }))
        {
            throw new PsignException("unsupported TimeStampReq version");
        }

        var imprintTlv = Ctx("TimeStampReq.messageImprint", () => DerPush.ReadTlv(outer, ref pos));
        var imprint = Ctx("MessageImprint SEQUENCE", () => DerPush.ExpectTlv(imprintTlv, 0x30));
        int ipos = 0;
        var digestAlgTlv = Ctx("MessageImprint.hashAlgorithm", () => DerPush.ReadTlv(imprint, ref ipos));
        var hashedTlv = Ctx("MessageImprint.hashedMessage", () => DerPush.ReadTlv(imprint, ref ipos));
        if (ipos != imprint.Length)
        {
            throw new PsignException("MessageImprint has trailing fields");
        }

        var hashedMessage = Ctx("hashedMessage OCTET STRING", () => DerPush.ExpectTlv(hashedTlv, 0x04));
        byte[]? nonce = null;
        while (pos < outer.Length)
        {
            var tlv = Ctx("TimeStampReq optional field", () => DerPush.ReadTlv(outer, ref pos));
            switch (tlv.Length > 0 ? tlv[0] : -1)
            {
                case 0x02:
                    nonce = tlv;
                    break;
                case 0x01:
                case 0x06:
                case 0xa0:
                    break;
                default:
                    throw new PsignException("unsupported TimeStampReq optional field");
            }
        }

        return new TimestampRequest { DigestAlgTlv = digestAlgTlv, HashedMessage = hashedMessage, NonceTlv = nonce };
    }

    internal static T Ctx<T>(string context, Func<T> f)
    {
        try
        {
            return f();
        }
        catch (PsignException e)
        {
            throw new PsignException(context, e);
        }
    }
}

/// <summary>Rust <c>TimestampAuthority</c>: generated root + TSA leaf and an RFC 3161 token builder.</summary>
internal sealed class TimestampAuthority : IDisposable
{
    internal const string OidTstInfo = "1.2.840.113549.1.9.16.1.4";
    internal const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    internal const string OidTimeStamping = "1.3.6.1.5.5.7.3.8";
    internal const string OidSigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    internal const string DefaultPolicyOid = "1.3.6.1.4.1.311.97.99.1";

    private long _serial = 1;

    public TimestampAuthority()
    {
        using var rootKey = RSA.Create(2048);
        var rootSubject = X509Builder.CommonNameName("psign local timestamp test root CA");
        RootCertDer = X509Builder.BuildRoot(1, rootSubject, rootKey);
        Key = RSA.Create(2048);
        CertDer = X509Builder.BuildLeaf(2, rootSubject, X509Builder.CommonNameName("psign local timestamp test TSA"), Key, rootKey, OidTimeStamping);
        Cert = CertificateInfo.Parse(CertDer);
    }

    public byte[] CertDer { get; }

    public byte[] RootCertDer { get; }

    public CertificateInfo Cert { get; }

    public RSA Key { get; }

    public byte[] BuildTimeStampResponse(TimestampRequest req, string genTime)
    {
        ulong serial = (ulong)(Interlocked.Increment(ref _serial) - 1);
        var tstInfo = BuildTstInfo(req, serial, genTime);
        var token = BuildTimeStampToken(tstInfo);
        return BuildGrantedResponse(token);
    }

    public byte[] BuildTimeStampToken(byte[] tstInfo)
    {
        var econtent = Der.EncodeTlv(0x04, tstInfo);
        var attrs = new List<CmsAttribute>
        {
            new(OidSigningCertificateV2, SigningCertificateV2Value()),
            new(Oids.Pkcs9MessageDigest, Der.EncodeTlv(0x04, SHA256.HashData(tstInfo))),
            new(Oids.Pkcs9ContentType, Der.EncodeOid(OidTstInfo)),
        };
        var signedAttrsDer = CmsAttribute.EncodeSet(0x31, attrs);
        var signature = Key.SignData(signedAttrsDer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signerInfo = new CmsSignerInfo(
            1,
            Der.EncodeSequence(Cert.Issuer, Cert.SerialNumberEncoded),
            AlgorithmIdentifier.Absent(OidSha256),
            attrs,
            AlgorithmIdentifier.WithNull(X509Builder.OidSha256WithRsa),
            signature,
            null);
        var sd = new CmsSignedData(3, [AlgorithmIdentifier.Absent(OidSha256)], OidTstInfo, econtent, [CertDer, RootCertDer], null, [signerInfo]);
        return sd.Encode();
    }

    /// <summary>Rust <c>signing_certificate_v2_attribute</c> value: ESSCertIDv2 without hashAlgorithm (SHA-256 default).</summary>
    private byte[] SigningCertificateV2Value()
    {
        var essBody = new List<byte>();
        DerPush.PushOctetString(essBody, SHA256.HashData(CertDer));
        essBody.AddRange(IssuerSerialDer(Cert));
        var ess = DerPush.Sequence(essBody.ToArray());
        var certs = DerPush.Sequence(ess);
        return DerPush.Sequence(certs);
    }

    private static byte[] IssuerSerialDer(CertificateInfo cert)
    {
        var generalNames = DerPush.Sequence(DerPush.Tlv(0xa4, cert.Issuer));
        var body = new List<byte>();
        body.AddRange(generalNames);
        body.AddRange(cert.SerialNumberEncoded);
        return DerPush.Sequence(body.ToArray());
    }

    /// <summary>Rust <c>build_tst_info</c>.</summary>
    public static byte[] BuildTstInfo(TimestampRequest req, ulong serial, string genTime)
    {
        var imprint = new List<byte>();
        imprint.AddRange(req.DigestAlgTlv);
        DerPush.PushOctetString(imprint, req.HashedMessage);
        var body = new List<byte>();
        DerPush.PushIntegerU64(body, 1);
        DerPush.PushOid(body, DefaultPolicyOid);
        DerPush.PushSequence(body, imprint.ToArray());
        DerPush.PushIntegerU64(body, serial);
        DerPush.PushGeneralizedTime(body, genTime);
        if (req.NonceTlv is not null)
        {
            body.AddRange(req.NonceTlv);
        }

        return DerPush.Sequence(body.ToArray());
    }

    /// <summary>Rust <c>build_granted_response</c>.</summary>
    public static byte[] BuildGrantedResponse(byte[] token)
    {
        var statusInfo = new List<byte>();
        DerPush.PushIntegerU64(statusInfo, 0);
        var body = new List<byte>();
        DerPush.PushSequence(body, statusInfo.ToArray());
        body.AddRange(token);
        return DerPush.Sequence(body.ToArray());
    }

    /// <summary>Rust <c>build_status_only_response</c>.</summary>
    public static byte[] BuildStatusOnlyResponse(uint status, string? text, byte? failInfoBit)
    {
        var statusInfo = new List<byte>();
        DerPush.PushIntegerU64(statusInfo, status);
        if (text is not null)
        {
            var strings = new List<byte>();
            DerPush.PushUtf8String(strings, text);
            DerPush.PushSequence(statusInfo, strings.ToArray());
        }

        if (failInfoBit is { } bit)
        {
            byte b = (byte)(0x80 >> (bit % 8));
            byte unused = (byte)(7 - (bit % 8));
            statusInfo.AddRange([0x03, 0x02, unused, b]);
        }

        var body = new List<byte>();
        DerPush.PushSequence(body, statusInfo.ToArray());
        return DerPush.Sequence(body.ToArray());
    }

    public void Dispose() => Key.Dispose();
}

/// <summary>OCSP status served by the PKI server (Rust <c>PkiOcspStatus</c>).</summary>
internal enum PkiOcspStatus
{
    Good,
    Revoked,
    Unknown,
}

/// <summary>Rust <c>PkiAuthority</c>: root, code-signing leaf (with PKCS#8 key), CRL and OCSP response.</summary>
internal sealed class PkiAuthority
{
    private static readonly byte[] Sha1AlgorithmIdentifierDer = [0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00];
    private const string OidOcspBasic = "1.3.6.1.5.5.7.48.1.1";
    internal const string OidCodeSigning = "1.3.6.1.5.5.7.3.3";

    public PkiAuthority(bool revokeLeaf, PkiOcspStatus ocspStatus)
    {
        using var rootKey = RSA.Create(2048);
        var rootSubject = X509Builder.CommonNameName("psign local online certificate test root CA");
        RootCertDer = X509Builder.BuildRoot(10, rootSubject, rootKey);
        using var leafKey = RSA.Create(2048);
        LeafKeyDer = leafKey.ExportPkcs8PrivateKey();
        LeafCertDer = X509Builder.BuildLeaf(11, rootSubject, X509Builder.CommonNameName("psign local online code signing leaf"), leafKey, rootKey, OidCodeSigning);
        var root = CertificateInfo.Parse(RootCertDer);
        var leaf = CertificateInfo.Parse(LeafCertDer);
        CrlDer = BuildCrlDer(root, rootKey, revokeLeaf ? leaf : null);
        OcspDer = BuildOcspResponseDer(root, rootKey, leaf, ocspStatus);
    }

    public byte[] RootCertDer { get; }

    public byte[] LeafCertDer { get; }

    public byte[] LeafKeyDer { get; }

    public byte[] CrlDer { get; }

    public byte[] OcspDer { get; }

    /// <summary>Rust <c>build_ocsp_response_der</c>.</summary>
    internal static byte[] BuildOcspResponseDer(CertificateInfo issuer, RSA issuerKey, CertificateInfo leaf, PkiOcspStatus status)
    {
        var certIdBody = new List<byte>();
        certIdBody.AddRange(Sha1AlgorithmIdentifierDer);
        certIdBody.AddRange(DerPush.OctetStringDer(SHA1.HashData(issuer.Subject)));
        certIdBody.AddRange(DerPush.OctetStringDer(SHA1.HashData(X509Builder.SubjectPublicKeyBits(issuer.SubjectPublicKeyInfo))));
        certIdBody.AddRange(leaf.SerialNumberEncoded);
        var certId = DerPush.Sequence(certIdBody.ToArray());

        var single = new List<byte>();
        single.AddRange(certId);
        switch (status)
        {
            case PkiOcspStatus.Good:
                DerPush.PushTlv(single, 0x80, []);
                break;
            case PkiOcspStatus.Revoked:
                var revoked = new List<byte>();
                DerPush.PushGeneralizedTime(revoked, "20240101000000Z");
                DerPush.PushTlv(single, 0xa1, revoked.ToArray());
                break;
            default:
                DerPush.PushTlv(single, 0x82, []);
                break;
        }

        DerPush.PushGeneralizedTime(single, "20240101000000Z");
        var nextUpdate = new List<byte>();
        DerPush.PushGeneralizedTime(nextUpdate, "20490101000000Z");
        DerPush.PushTlv(single, 0xa0, nextUpdate.ToArray());
        var singleSeq = DerPush.Sequence(single.ToArray());
        var responses = DerPush.Sequence(singleSeq);

        var responseDataBody = new List<byte>();
        responseDataBody.AddRange(DerPush.Tlv(0xa1, issuer.Subject));
        DerPush.PushGeneralizedTime(responseDataBody, "20240101000000Z");
        responseDataBody.AddRange(responses);
        var responseData = DerPush.Sequence(responseDataBody.ToArray());

        var sig = issuerKey.SignData(responseData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var basicBody = new List<byte>();
        basicBody.AddRange(responseData);
        basicBody.AddRange(X509Builder.Sha256WithRsaEncryptionDer);
        DerPush.PushTlv(basicBody, 0x03, [0, .. sig]);
        var basic = DerPush.Sequence(basicBody.ToArray());

        var responseBytesBody = new List<byte>();
        DerPush.PushOid(responseBytesBody, OidOcspBasic);
        DerPush.PushOctetString(responseBytesBody, basic);
        var responseBytes = DerPush.Sequence(responseBytesBody.ToArray());

        var ocspBody = new List<byte>();
        DerPush.PushTlv(ocspBody, 0x0a, [0]);
        DerPush.PushTlv(ocspBody, 0xa0, responseBytes);
        return DerPush.Sequence(ocspBody.ToArray());
    }

    /// <summary>Rust <c>build_crl_der</c>.</summary>
    internal static byte[] BuildCrlDer(CertificateInfo issuer, RSA issuerKey, CertificateInfo? revokedLeaf)
    {
        var tbsBody = new List<byte>();
        DerPush.PushIntegerU64(tbsBody, 1);
        tbsBody.AddRange(X509Builder.Sha256WithRsaEncryptionDer);
        tbsBody.AddRange(issuer.Subject);
        DerPush.PushUtcTime(tbsBody, "240101000000Z");
        DerPush.PushUtcTime(tbsBody, "490101000000Z");
        if (revokedLeaf is not null)
        {
            var entry = new List<byte>();
            entry.AddRange(revokedLeaf.SerialNumberEncoded);
            DerPush.PushUtcTime(entry, "240101000000Z");
            var entrySeq = DerPush.Sequence(entry.ToArray());
            DerPush.PushSequence(tbsBody, entrySeq);
        }

        var tbs = DerPush.Sequence(tbsBody.ToArray());
        var sig = issuerKey.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var crlBody = new List<byte>();
        crlBody.AddRange(tbs);
        crlBody.AddRange(X509Builder.Sha256WithRsaEncryptionDer);
        DerPush.PushTlv(crlBody, 0x03, [0, .. sig]);
        return DerPush.Sequence(crlBody.ToArray());
    }
}

/// <summary>Rust <c>AzureSigningIdentity</c>: generated root + code-signing leaf whose key signs remote digests.</summary>
internal sealed class AzureSigningIdentity : IDisposable
{
    public AzureSigningIdentity(string rootCommonName, string leafCommonName, uint rootSerial, uint leafSerial)
    {
        using var rootKey = RSA.Create(2048);
        var rootSubject = X509Builder.CommonNameName(rootCommonName);
        RootCertDer = X509Builder.BuildRoot(rootSerial, rootSubject, rootKey);
        LeafKey = RSA.Create(2048);
        LeafCertDer = X509Builder.BuildLeaf(leafSerial, rootSubject, X509Builder.CommonNameName(leafCommonName), LeafKey, rootKey, PkiAuthority.OidCodeSigning);
    }

    public byte[] RootCertDer { get; }

    public byte[] LeafCertDer { get; }

    public RSA LeafKey { get; }

    /// <summary>Rust <c>leaf_root_pem_bundle</c>.</summary>
    public byte[] LeafRootPemBundle() => Encoding.UTF8.GetBytes(DerCertToPem(LeafCertDer) + DerCertToPem(RootCertDer));

    /// <summary>Rust <c>sign_digest</c>: RS256 / RS384 / RS512 PKCS#1 v1.5 over a precomputed digest.</summary>
    public byte[] SignDigest(string alg, byte[] digest)
    {
        var trimmed = alg.Trim();
        (int Length, HashAlgorithmName Hash, string Label) spec = trimmed switch
        {
            "RS256" => (32, HashAlgorithmName.SHA256, "RS256 requires a 32-byte SHA-256 digest"),
            "RS384" => (48, HashAlgorithmName.SHA384, "RS384 requires a 48-byte SHA-384 digest"),
            "RS512" => (64, HashAlgorithmName.SHA512, "RS512 requires a 64-byte SHA-512 digest"),
            _ => throw new PsignException($"unsupported Azure test signing algorithm {trimmed}"),
        };
        if (digest.Length != spec.Length)
        {
            throw new PsignException(spec.Label);
        }

        return LeafKey.SignHash(digest, spec.Hash, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Rust <c>der_cert_to_pem</c> (64-column lines, LF endings).</summary>
    internal static string DerCertToPem(byte[] der)
    {
        var b64 = Convert.ToBase64String(der);
        var sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < b64.Length; i += 64)
        {
            sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
        }

        sb.Append("-----END CERTIFICATE-----\n");
        return sb.ToString();
    }

    public void Dispose() => LeafKey.Dispose();
}
