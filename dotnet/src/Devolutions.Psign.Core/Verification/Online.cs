using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Verification;

/// <summary>
/// Explicit online certificate retrieval for portable trust verification (Rust <c>online.rs</c>): AIA caIssuers,
/// OCSP (RSA PKCS#1 v1.5 responses) and CRL checks over plain <c>http://</c>.
/// </summary>
public static class OnlineTrust
{
    private const string AiaOid = "1.3.6.1.5.5.7.1.1";
    private const string CrlDistributionPointsOid = "2.5.29.31";
    private const string Context = "portable online trust";

    private static readonly byte[] CaIssuersOidDer = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
    private static readonly byte[] OcspOidDer = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    private static readonly byte[] OcspBasicOidDer = [0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
    private static readonly byte[] Sha1AlgorithmIdentifierDer = [0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00];
    private static readonly byte[] Pkcs1OidPrefix = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];

    internal enum RsaPkcs1v15Hash
    {
        Sha256,
        Sha384,
        Sha512,
    }

    internal enum OcspCheckOutcome
    {
        NotConfigured,
        Good,
        Revoked,
        Unknown,
    }

    internal sealed record ParsedOcspSingleResponse(byte[] CertIdTlv, OcspCheckOutcome Status, DateTimeOffset ThisUpdate, DateTimeOffset NextUpdate);

    internal sealed record ParsedOcspResponse(byte[] TbsResponseDataTlv, RsaPkcs1v15Hash SignatureHash, byte[] Signature, List<ParsedOcspSingleResponse> Responses);

    internal sealed record ParsedCrl(byte[] TbsTlv, byte[] IssuerTlv, RsaPkcs1v15Hash SignatureHash, byte[] Signature, DateTimeOffset ThisUpdate, DateTimeOffset NextUpdate, List<byte[]> RevokedSerialTlvs);

    /// <summary>Map a DER <c>AlgorithmIdentifier</c> to <c>sha{256,384,512}WithRSAEncryption</c> (NULL params or absent).</summary>
    internal static RsaPkcs1v15Hash? RsaHashFromAlgorithmIdentifierTlv(byte[] tlv)
    {
        try
        {
            var body = ExpectTlv(tlv, 0x30);
            int pos = 0;
            var oid = ExpectTlv(ReadTlv(body, ref pos), 0x06);
            if (pos != body.Length && !body.AsSpan(pos).SequenceEqual(new byte[] { 0x05, 0x00 }))
            {
                return null;
            }

            if (oid.Length != Pkcs1OidPrefix.Length + 1 || !oid.AsSpan(0, Pkcs1OidPrefix.Length).SequenceEqual(Pkcs1OidPrefix))
            {
                return null;
            }

            return oid[^1] switch
            {
                0x0b => RsaPkcs1v15Hash.Sha256,
                0x0c => RsaPkcs1v15Hash.Sha384,
                0x0d => RsaPkcs1v15Hash.Sha512,
                _ => null,
            };
        }
        catch (PsignException)
        {
            return null;
        }
    }

    /// <summary>Fetch issuer candidates from the AIA override and/or certificate caIssuers URLs.</summary>
    public static List<CertificateInfo> IssuerCandidatesFromAia(CertificateInfo cert, OnlineTrustOptions options)
    {
        var output = new List<CertificateInfo>();
        if (!options.EnableAia && options.AiaUrlOverride is null)
        {
            return output;
        }

        var urls = new List<string>();
        if (options.AiaUrlOverride is not null)
        {
            urls.Add(options.AiaUrlOverride);
        }

        if (options.EnableAia)
        {
            urls.AddRange(AiaCaIssuersUrls(cert));
        }

        foreach (var url in urls)
        {
            byte[] bytes;
            try
            {
                bytes = HttpGetLimited(url, options);
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"fetch AIA issuer certificate from {url}", e);
            }

            try
            {
                output.Add(ParseCertBytes(bytes));
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"parse AIA issuer {url}", e);
            }
        }

        return output;
    }

    private static CertificateInfo ParseCertBytes(byte[] raw) => Anchors.ParseCertBytes(raw);

    /// <summary>caIssuers HTTP(S) URIs from the AIA extension.</summary>
    public static List<string> AiaCaIssuersUrls(CertificateInfo cert)
    {
        var urls = new List<string>();
        foreach (var ext in cert.Extensions.Where(e => e.Oid == AiaOid))
        {
            urls.AddRange(ParseAiaCaIssuers(ext.Value));
        }

        return urls;
    }

    /// <summary>HTTP CRL distribution point URIs.</summary>
    public static List<string> CrlDistributionPointUrls(CertificateInfo cert)
    {
        var urls = new List<string>();
        foreach (var ext in cert.Extensions.Where(e => e.Oid == CrlDistributionPointsOid))
        {
            urls.AddRange(ParseHttpUriGeneralNames(ext.Value));
        }

        return urls;
    }

    /// <summary>HTTP OCSP responder URIs from the AIA extension.</summary>
    public static List<string> OcspUrls(CertificateInfo cert)
    {
        var urls = new List<string>();
        foreach (var ext in cert.Extensions.Where(e => e.Oid == AiaOid))
        {
            urls.AddRange(ParseAiaOcsp(ext.Value));
        }

        return urls;
    }

    /// <summary>Apply the configured revocation policy (OCSP, then CRL) to every leaf→issuer pair in the chain.</summary>
    public static void CheckRevocationChain(CertificateInfo leaf, IReadOnlyList<CertificateInfo> chain, OnlineTrustOptions options)
    {
        if (options.RevocationMode == RevocationMode.Off)
        {
            return;
        }

        var subjects = new List<CertificateInfo>(chain.Count + 1) { leaf };
        subjects.AddRange(chain);
        for (int idx = 0; idx + 1 < subjects.Count; idx++)
        {
            var cert = subjects[idx];
            var issuer = subjects[idx + 1];
            OcspCheckOutcome? outcome = null;
            try
            {
                outcome = CheckOneCertOcsp(cert, issuer, options);
            }
            catch (PsignException) when (options.RevocationMode == RevocationMode.BestEffort)
            {
            }

            switch (outcome)
            {
                case OcspCheckOutcome.Good:
                    continue;
                case OcspCheckOutcome.Unknown when options.RevocationMode != RevocationMode.BestEffort:
                    throw new PsignException("OCSP status is unknown");
                case OcspCheckOutcome.Revoked:
                    throw new PsignException("OCSP status is revoked");
            }

            try
            {
                CheckOneCertCrl(cert, issuer, options);
            }
            catch (PsignException e) when (options.RevocationMode == RevocationMode.BestEffort)
            {
                if (e.Message.StartsWith("certificate is revoked by CRL ", StringComparison.Ordinal))
                {
                    throw;
                }
            }
        }
    }

    private static OcspCheckOutcome CheckOneCertOcsp(CertificateInfo cert, CertificateInfo issuer, OnlineTrustOptions options)
    {
        if (!options.EnableOcsp && options.OcspUrlOverride is null)
        {
            return OcspCheckOutcome.NotConfigured;
        }

        string? url = options.OcspUrlOverride;
        if (url is null)
        {
            try
            {
                url = OcspUrls(cert).FirstOrDefault();
            }
            catch (PsignException)
            {
                url = null;
            }
        }

        if (url is null)
        {
            throw new PsignException("OCSP checking requires --ocsp-url-override or a certificate AIA OCSP HTTP URL");
        }

        var request = BuildOcspRequestDer(cert, issuer);
        byte[] response;
        try
        {
            response = HttpPostLimited(url, "application/ocsp-request", "application/ocsp-response", request, options);
        }
        catch (PsignException e)
        {
            throw PsignException.Context($"POST OCSP request to {url}", e);
        }

        ParsedOcspResponse parsed;
        try
        {
            parsed = ParseOcspResponseDer(response);
        }
        catch (PsignException e)
        {
            throw PsignException.Context($"parse OCSP response from {url}", e);
        }

        VerifyRsaPkcs1v15Signature(parsed.SignatureHash, parsed.TbsResponseDataTlv, parsed.Signature, issuer, "OCSP");
        var certId = BuildOcspCertIdDer(cert, issuer);
        var entry = OcspResponseForCertId(parsed, certId);
        EnsureTimeWindowFresh("OCSP SingleResponse", entry.ThisUpdate, entry.NextUpdate);
        return entry.Status;
    }

    internal static ParsedOcspSingleResponse OcspResponseForCertId(ParsedOcspResponse parsed, byte[] certIdTlv) =>
        parsed.Responses.FirstOrDefault(e => e.CertIdTlv.AsSpan().SequenceEqual(certIdTlv))
        ?? throw new PsignException("OCSP response does not contain the requested certificate ID");

    private static void CheckOneCertCrl(CertificateInfo cert, CertificateInfo issuer, OnlineTrustOptions options)
    {
        string? url = options.CrlUrlOverride;
        if (url is null)
        {
            try
            {
                url = CrlDistributionPointUrls(cert).FirstOrDefault();
            }
            catch (PsignException)
            {
                url = null;
            }
        }

        if (url is null)
        {
            throw new PsignException("revocation checking requires --crl-url-override or a certificate CRL distribution point HTTP URL");
        }

        byte[] crlBytes;
        try
        {
            crlBytes = HttpGetLimited(url, options);
        }
        catch (PsignException e)
        {
            throw PsignException.Context($"fetch CRL from {url}", e);
        }

        ParsedCrl crl;
        try
        {
            crl = ParseCertificateListDer(crlBytes);
        }
        catch (PsignException e)
        {
            throw PsignException.Context($"parse CRL from {url}", e);
        }

        if (!crl.IssuerTlv.AsSpan().SequenceEqual(issuer.Subject))
        {
            throw new PsignException($"CRL issuer does not match certificate issuer for {url}");
        }

        VerifyCrlSignature(crl, issuer);
        EnsureTimeWindowFresh("CRL", crl.ThisUpdate, crl.NextUpdate);
        var serial = cert.SerialNumberEncoded;
        var serialVal = new System.Numerics.BigInteger(cert.SerialNumber, isUnsigned: false, isBigEndian: true);
        if (crl.RevokedSerialTlvs.Any(s => SerialTlvMatches(s, serial, serialVal)))
        {
            throw new PsignException($"certificate is revoked by CRL {url}");
        }
    }

    private static bool SerialTlvMatches(byte[] tlv, byte[] expectedTlv, System.Numerics.BigInteger expectedValue)
    {
        if (tlv.AsSpan().SequenceEqual(expectedTlv))
        {
            return true;
        }

        var parsed = Der.First(tlv);
        if (parsed is null || parsed.Value.Tag != 0x02 || parsed.Value.ValueLength == 0)
        {
            return false;
        }

        return new System.Numerics.BigInteger(parsed.Value.Value(tlv), isUnsigned: false, isBigEndian: true) == expectedValue;
    }

    private static T Ctx<T>(string context, Func<T> f)
    {
        try
        {
            return f();
        }
        catch (PsignException e)
        {
            throw PsignException.Context(context, e);
        }
    }

    internal static ParsedOcspResponse ParseOcspResponseDer(byte[] input)
    {
        var outer = Ctx("OCSPResponse", () => ExpectTlv(input, 0x30));
        int pos = 0;
        var statusTlv = ReadTlv(outer, ref pos);
        var status = Ctx("OCSPResponseStatus", () => ExpectTlv(statusTlv, 0x0a));
        if (status is not [0])
        {
            throw new PsignException("OCSP responder returned non-success status");
        }

        var rbTlv = ReadTlv(outer, ref pos);
        if (pos != outer.Length)
        {
            throw new PsignException("OCSPResponse has trailing fields");
        }

        var responseBytes = Ctx("responseBytes", () => ExpectTlv(rbTlv, 0xa0));
        var rb = Ctx("ResponseBytes", () => ExpectTlv(responseBytes, 0x30));
        int rbPos = 0;
        var responseType = Ctx("ResponseBytes.responseType", () => ReadTlv(rb, ref rbPos));
        if (!responseType.AsSpan().SequenceEqual(OcspBasicOidDer))
        {
            throw new PsignException("unsupported OCSP response type");
        }

        var responseTlv = Ctx("ResponseBytes.response", () => ReadTlv(rb, ref rbPos));
        if (rbPos != rb.Length)
        {
            throw new PsignException("ResponseBytes has trailing fields");
        }

        var basicOctets = Ctx("ResponseBytes.response OCTET STRING", () => ExpectTlv(responseTlv, 0x04));
        return ParseBasicOcspResponseDer(basicOctets);
    }

    private static ParsedOcspResponse ParseBasicOcspResponseDer(byte[] input)
    {
        var outer = Ctx("BasicOCSPResponse", () => ExpectTlv(input, 0x30));
        int pos = 0;
        var tbsResponseDataTlv = Ctx("BasicOCSPResponse.tbsResponseData", () => ReadTlv(outer, ref pos));
        var sigAlg = Ctx("BasicOCSPResponse.signatureAlgorithm", () => ReadTlv(outer, ref pos));
        var signatureHash = RsaHashFromAlgorithmIdentifierTlv(sigAlg)
            ?? throw new PsignException("unsupported OCSP signature algorithm");
        var sigTlv = Ctx("BasicOCSPResponse.signature", () => ReadTlv(outer, ref pos));
        var signatureBody = Ctx("OCSP signature BIT STRING", () => ExpectTlv(sigTlv, 0x03));
        if (signatureBody is not [0, ..])
        {
            throw new PsignException("OCSP signature BIT STRING has unused bits");
        }

        var tbs = Ctx("ResponseData", () => ExpectTlv(tbsResponseDataTlv, 0x30));
        int tbsPos = 0;
        if (tbsPos < tbs.Length && tbs[tbsPos] == 0xa0)
        {
            Ctx("ResponseData.version", () => ReadTlv(tbs, ref tbsPos));
        }

        Ctx("ResponseData.responderID", () => ReadTlv(tbs, ref tbsPos));
        Ctx("ResponseData.producedAt", () => ReadTlv(tbs, ref tbsPos));
        var responsesTlv = ReadTlv(tbs, ref tbsPos);
        var responses = Ctx("ResponseData.responses", () => ExpectTlv(responsesTlv, 0x30));
        int responsesPos = 0;
        var parsed = new List<ParsedOcspSingleResponse>();
        while (responsesPos < responses.Length)
        {
            var singleTlv = ReadTlv(responses, ref responsesPos);
            var single = Ctx("SingleResponse", () => ExpectTlv(singleTlv, 0x30));
            int singlePos = 0;
            var certIdTlv = Ctx("SingleResponse.certID", () => ReadTlv(single, ref singlePos));
            Ctx("CertID", () => ExpectTlv(certIdTlv, 0x30));
            var certStatus = Ctx("SingleResponse.certStatus", () => ReadTlv(single, ref singlePos));
            var status = certStatus.Length == 0
                ? throw new PsignException("missing OCSP CertStatus")
                : certStatus[0] switch
                {
                    0x80 => OcspCheckOutcome.Good,
                    0xa1 => OcspCheckOutcome.Revoked,
                    0x82 => OcspCheckOutcome.Unknown,
                    var tag => throw new PsignException($"unsupported OCSP CertStatus tag 0x{tag:x2}"),
                };
            var thisUpdateTlv = Ctx("SingleResponse.thisUpdate", () => ReadTlv(single, ref singlePos));
            var thisUpdate = Ctx("SingleResponse.thisUpdate", () => ParseDerTimeTlv(thisUpdateTlv));
            var nextUpdateTlv = Ctx("SingleResponse.nextUpdate is required for revocation freshness", () => ReadTlv(single, ref singlePos));
            if (nextUpdateTlv is not [0xa0, ..])
            {
                throw new PsignException("SingleResponse.nextUpdate is required");
            }

            var nextUpdateInner = Ctx("SingleResponse.nextUpdate", () => ExpectTlv(nextUpdateTlv, 0xa0));
            int nextPos = 0;
            var nextTimeTlv = Ctx("nextUpdate time", () => ReadTlv(nextUpdateInner, ref nextPos));
            var nextUpdate = Ctx("SingleResponse.nextUpdate", () => ParseDerTimeTlv(nextTimeTlv));
            if (nextPos != nextUpdateInner.Length)
            {
                throw new PsignException("SingleResponse.nextUpdate has trailing fields");
            }

            parsed.Add(new ParsedOcspSingleResponse(certIdTlv, status, thisUpdate, nextUpdate));
        }

        return new ParsedOcspResponse(tbsResponseDataTlv, signatureHash, signatureBody[1..], parsed);
    }

    internal static ParsedCrl ParseCertificateListDer(byte[] input)
    {
        var outer = Ctx("CertificateList", () => ExpectTlv(input, 0x30));
        int pos = 0;
        var tbsTlv = Ctx("CertificateList.tbsCertList", () => ReadTlv(outer, ref pos));
        var signatureAlgorithmTlv = Ctx("CertificateList.signatureAlgorithm", () => ReadTlv(outer, ref pos));
        var signatureTlv = Ctx("CertificateList.signatureValue", () => ReadTlv(outer, ref pos));
        if (pos != outer.Length)
        {
            throw new PsignException("CertificateList has trailing fields");
        }

        var signatureHash = RsaHashFromAlgorithmIdentifierTlv(signatureAlgorithmTlv)
            ?? throw new PsignException("unsupported CRL signature algorithm");
        var signatureBody = Ctx("CRL signature BIT STRING", () => ExpectTlv(signatureTlv, 0x03));
        if (signatureBody is not [0, ..])
        {
            throw new PsignException("CRL signature BIT STRING has unused bits");
        }

        var tbs = Ctx("TBSCertList", () => ExpectTlv(tbsTlv, 0x30));
        int tbsPos = 0;
        if (tbsPos < tbs.Length && tbs[tbsPos] == 0x02)
        {
            Ctx("TBSCertList.version", () => ReadTlv(tbs, ref tbsPos));
        }

        var tbsSigAlg = Ctx("TBSCertList.signature", () => ReadTlv(tbs, ref tbsPos));
        if (!tbsSigAlg.AsSpan().SequenceEqual(signatureAlgorithmTlv))
        {
            throw new PsignException("CRL signatureAlgorithm does not match TBSCertList.signature");
        }

        var issuerTlv = Ctx("TBSCertList.issuer", () => ReadTlv(tbs, ref tbsPos));
        var thisUpdateTlv = Ctx("TBSCertList.thisUpdate", () => ReadTlv(tbs, ref tbsPos));
        var thisUpdate = Ctx("TBSCertList.thisUpdate", () => ParseDerTimeTlv(thisUpdateTlv));
        DateTimeOffset nextUpdate;
        if (tbsPos < tbs.Length && tbs[tbsPos] is 0x17 or 0x18)
        {
            var nextTlv = Ctx("TBSCertList.nextUpdate", () => ReadTlv(tbs, ref tbsPos));
            nextUpdate = Ctx("TBSCertList.nextUpdate", () => ParseDerTimeTlv(nextTlv));
        }
        else
        {
            throw new PsignException("TBSCertList.nextUpdate is required for revocation freshness");
        }

        var revoked = new List<byte[]>();
        if (tbsPos < tbs.Length && tbs[tbsPos] == 0x30)
        {
            var revokedTlv = ReadTlv(tbs, ref tbsPos);
            var list = Ctx("TBSCertList.revokedCertificates", () => ExpectTlv(revokedTlv, 0x30));
            int rpos = 0;
            while (rpos < list.Length)
            {
                var entryTlv = ReadTlv(list, ref rpos);
                var entry = Ctx("RevokedCertificate", () => ExpectTlv(entryTlv, 0x30));
                int epos = 0;
                var serialTlv = Ctx("RevokedCertificate.userCertificate", () => ReadTlv(entry, ref epos));
                Ctx("RevokedCertificate.userCertificate INTEGER", () => ExpectTlv(serialTlv, 0x02));
                revoked.Add(serialTlv);
            }
        }

        return new ParsedCrl(tbsTlv, issuerTlv, signatureHash, signatureBody[1..], thisUpdate, nextUpdate, revoked);
    }

    internal static void VerifyCrlSignature(ParsedCrl crl, CertificateInfo issuer) =>
        VerifyRsaPkcs1v15Signature(crl.SignatureHash, crl.TbsTlv, crl.Signature, issuer, "CRL");

    private static void VerifyRsaPkcs1v15Signature(RsaPkcs1v15Hash hash, byte[] signedTlv, byte[] signature, CertificateInfo issuer, string label)
    {
        using var rsa = RSA.Create();
        try
        {
            if (SignatureVerifier.SpkiAlgorithm(issuer.SubjectPublicKeyInfo) != Oids.RsaEncryption)
            {
                throw new CryptographicException("unknown/unsupported algorithm OID");
            }

            rsa.ImportSubjectPublicKeyInfo(issuer.SubjectPublicKeyInfo, out _);
        }
        catch (Exception e) when (e is CryptographicException or System.Formats.Asn1.AsnContentException)
        {
            throw new PsignException($"{label} issuer RSA public key parse failed: {e.Message}");
        }

        var name = hash switch
        {
            RsaPkcs1v15Hash.Sha256 => HashAlgorithmName.SHA256,
            RsaPkcs1v15Hash.Sha384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512,
        };
        bool ok;
        try
        {
            ok = rsa.VerifyData(signedTlv, signature, name, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            ok = false;
        }

        if (!ok)
        {
            throw new PsignException($"{label} signature verification failed: signature error");
        }
    }

    private static DateTimeOffset ParseDerTimeTlv(byte[] tlv)
    {
        try
        {
            return Picky.PickyFormat.Truncate(Asn1Time.Decode(tlv));
        }
        catch (PsignException e)
        {
            throw new PsignException($"DER time decode failed: {e.Message}");
        }
    }

    internal static void EnsureTimeWindowFresh(string label, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate)
    {
        var now = DateTimeOffset.UtcNow;
        static (int, int, int) Key(DateTimeOffset d)
        {
            var u = d.ToUniversalTime();
            return (u.Year, u.Month, u.Day);
        }

        if (Key(thisUpdate).CompareTo(Key(now)) > 0)
        {
            throw new PsignException($"{label} thisUpdate is in the future");
        }

        if (nextUpdate is not { } next)
        {
            throw new PsignException($"{label} nextUpdate is required for revocation freshness");
        }

        if (Key(next).CompareTo(Key(now)) < 0)
        {
            throw new PsignException($"{label} nextUpdate is stale");
        }
    }

    internal static List<string> ParseAiaCaIssuers(byte[] input)
    {
        var outer = Ctx("AuthorityInfoAccessSyntax", () => ExpectTlv(input, 0x30));
        int pos = 0;
        var urls = new List<string>();
        while (pos < outer.Length)
        {
            var adTlv = ReadTlv(outer, ref pos);
            var ad = Ctx("AccessDescription", () => ExpectTlv(adTlv, 0x30));
            int adPos = 0;
            var method = Ctx("AccessDescription.accessMethod", () => ReadTlv(ad, ref adPos));
            var location = Ctx("AccessDescription.accessLocation", () => ReadTlv(ad, ref adPos));
            if (adPos != ad.Length)
            {
                throw new PsignException("AccessDescription has trailing fields");
            }

            if (method.AsSpan().SequenceEqual(CaIssuersOidDer) && location is [0x86, ..])
            {
                var body = Ctx("uniformResourceIdentifier", () => ExpectTlv(location, 0x86));
                urls.Add(Utf8Strict(body, "AIA URL is not UTF-8"));
            }
        }

        return urls;
    }

    private static List<string> ParseAiaOcsp(byte[] input)
    {
        var outer = Ctx("AuthorityInfoAccessSyntax", () => ExpectTlv(input, 0x30));
        int pos = 0;
        var urls = new List<string>();
        while (pos < outer.Length)
        {
            var adTlv = ReadTlv(outer, ref pos);
            var ad = Ctx("AccessDescription", () => ExpectTlv(adTlv, 0x30));
            int adPos = 0;
            var method = Ctx("AccessDescription.accessMethod", () => ReadTlv(ad, ref adPos));
            var location = Ctx("AccessDescription.accessLocation", () => ReadTlv(ad, ref adPos));
            if (adPos != ad.Length)
            {
                throw new PsignException("AccessDescription has trailing fields");
            }

            if (method.AsSpan().SequenceEqual(OcspOidDer) && location is [0x86, ..])
            {
                var body = Ctx("uniformResourceIdentifier", () => ExpectTlv(location, 0x86));
                var uri = Utf8Strict(body, "AIA OCSP URL is not UTF-8");
                if (uri.StartsWith("http://", StringComparison.Ordinal))
                {
                    urls.Add(uri);
                }
            }
        }

        return urls;
    }

    private static string Utf8Strict(byte[] body, string error)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(body);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException($"{error}: {e.Message}");
        }
    }

    internal static byte[] BuildOcspRequestDer(CertificateInfo cert, CertificateInfo issuer)
    {
        var certId = BuildOcspCertIdDer(cert, issuer);
        var request = Der.EncodeTlv(0x30, certId);
        var requestList = Der.EncodeTlv(0x30, request);
        var tbsRequest = Der.EncodeTlv(0x30, requestList);
        return Der.EncodeTlv(0x30, tbsRequest);
    }

    internal static byte[] BuildOcspCertIdDer(CertificateInfo cert, CertificateInfo issuer)
    {
        var body = new List<byte>();
        body.AddRange(Sha1AlgorithmIdentifierDer);
        body.AddRange(Der.EncodeTlv(0x04, SHA1.HashData(issuer.Subject)));
        body.AddRange(Der.EncodeTlv(0x04, SHA1.HashData(issuer.PublicKey)));
        body.AddRange(cert.SerialNumberEncoded);
        return Der.EncodeTlv(0x30, body.ToArray());
    }

    internal static List<string> ParseHttpUriGeneralNames(byte[] input)
    {
        var urls = new List<string>();
        CollectHttpUriGeneralNames(input, 0, input.Length, urls, depth: 0);
        return urls;
    }

    private static void CollectHttpUriGeneralNames(byte[] input, int start, int end, List<string> urls, int depth)
    {
        if (depth > 32)
        {
            return;
        }

        int pos = start;
        while (pos < end)
        {
            byte tag = input[pos];
            var (bodyStart, len) = ReadLen(input, pos + 1);
            long tlvEnd = (long)bodyStart + len;
            if (tlvEnd > end)
            {
                throw new PsignException("TLV length exceeds input");
            }

            if (tag == 0x86)
            {
                var uri = Utf8Strict(input[bodyStart..(int)tlvEnd], "URI is not UTF-8");
                if (uri.StartsWith("http://", StringComparison.Ordinal))
                {
                    urls.Add(uri);
                }
            }
            else if ((tag & 0x20) != 0)
            {
                CollectHttpUriGeneralNames(input, bodyStart, (int)tlvEnd, urls, depth + 1);
            }

            pos = (int)tlvEnd;
        }
    }

    /// <summary>GET with the online size/time limits (also used by the AuthRoot cache downloader).</summary>
    internal static byte[] HttpGetLimited(string url, OnlineTrustOptions options) =>
        HttpRequestLimited(url, HttpMethod.Get, null, options);

    private static byte[] HttpPostLimited(string url, string contentType, string accept, byte[] body, OnlineTrustOptions options) =>
        HttpRequestLimited(url, HttpMethod.Post, (contentType, accept, body), options);

    private static byte[] HttpRequestLimited(string url, HttpMethod method, (string ContentType, string Accept, byte[] Body)? body, OnlineTrustOptions options)
    {
        if (!url.StartsWith("http://", StringComparison.Ordinal))
        {
            throw new PsignException($"only http:// URLs are supported by {Context}");
        }

        var withoutScheme = url["http://".Length..];
        int delim = withoutScheme.IndexOfAny(['/', '?', '#']);
        string authority = delim >= 0 ? withoutScheme[..delim] : withoutScheme;
        string path = delim < 0
            ? "/"
            : withoutScheme[delim] == '/' ? withoutScheme[delim..] : "/" + withoutScheme[delim..];
        string host = authority;
        int port = 80;
        int colon = authority.LastIndexOf(':');
        if (colon >= 0 && ushort.TryParse(authority[(colon + 1)..], out var p))
        {
            host = authority[..colon];
            port = p;
        }

        if (host.Length == 0)
        {
            throw new PsignException($"{Context} URL host is empty");
        }

        if (options.Timeout <= TimeSpan.Zero)
        {
            throw new PsignException($"{Context} timeout must be positive");
        }

        if (options.MaxDownloadBytes <= 0)
        {
            throw new PsignException($"{Context} max download size must be positive");
        }

        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = options.Timeout,
        };
        using var client = new HttpClient(handler) { Timeout = options.Timeout };
        Uri uri;
        try
        {
            uri = new Uri($"http://{authority}{path}");
        }
        catch (UriFormatException e)
        {
            throw new PsignException($"connect {host}:{port}: {e.Message}");
        }

        using var request = new HttpRequestMessage(method, uri);
        request.Headers.ConnectionClose = true;
        if (body is { } b)
        {
            request.Content = new ByteArrayContent(b.Body);
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(b.ContentType);
            request.Headers.TryAddWithoutValidation("Accept", b.Accept);
        }
        else
        {
            request.Headers.TryAddWithoutValidation("Accept", "application/pkix-cert, application/octet-stream, */*");
        }

        HttpResponseMessage response;
        try
        {
            response = client.Send(request, HttpCompletionOption.ResponseHeadersRead);
        }
        catch (HttpRequestException e) when (e.InnerException is SocketException)
        {
            throw PsignException.Context($"connect {host}:{port}", e);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
        {
            throw PsignException.Context($"read {Context} HTTP response", e);
        }

        using (response)
        {
            int status = (int)response.StatusCode;
            byte[] data;
            try
            {
                using var stream = response.Content.ReadAsStream();
                using var ms = new MemoryStream();
                var buf = new byte[8192];
                int n;
                while ((n = stream.Read(buf, 0, buf.Length)) > 0)
                {
                    ms.Write(buf, 0, n);
                    if (ms.Length > (long)options.MaxDownloadBytes + (64 * 1024))
                    {
                        throw new PsignException($"{Context} HTTP response exceeds configured size limit");
                    }
                }

                data = ms.ToArray();
            }
            catch (Exception e) when (e is IOException or HttpRequestException or TaskCanceledException)
            {
                throw PsignException.Context($"read {Context} HTTP response", e);
            }

            if (status != 200)
            {
                throw new PsignException($"{Context} HTTP GET returned status {status}");
            }

            if (data.Length > options.MaxDownloadBytes)
            {
                throw new PsignException($"{Context} download exceeds configured size limit");
            }

            return data;
        }
    }

    internal static byte[] ExpectTlv(byte[] input, byte tag)
    {
        if (input.Length == 0 || input[0] != tag)
        {
            throw new PsignException("unexpected tag");
        }

        var (bodyStart, len) = ReadLen(input, 1);
        long end = (long)bodyStart + len;
        if (end != input.Length)
        {
            throw new PsignException("TLV trailing bytes");
        }

        return input[bodyStart..(int)end];
    }

    internal static byte[] ReadTlv(byte[] input, ref int pos)
    {
        int start = pos;
        if (start >= input.Length)
        {
            throw new PsignException("missing TLV tag");
        }

        var (bodyStart, len) = ReadLen(input, start + 1);
        long end = (long)bodyStart + len;
        if (end > input.Length)
        {
            throw new PsignException("TLV length exceeds input");
        }

        pos = (int)end;
        return input[start..(int)end];
    }

    private static (int BodyStart, int Length) ReadLen(byte[] input, int pos)
    {
        if (pos >= input.Length)
        {
            throw new PsignException("missing length");
        }

        byte first = input[pos++];
        if (first < 0x80)
        {
            return (pos, first);
        }

        int n = first & 0x7f;
        if (n is 0 or > 3)
        {
            throw new PsignException("unsupported DER length form");
        }

        int len = 0;
        for (int i = 0; i < n; i++)
        {
            if (pos >= input.Length)
            {
                throw new PsignException("truncated length");
            }

            byte b = input[pos++];
            if (i == 0 && b == 0)
            {
                throw new PsignException("non-minimal DER length");
            }

            len = (len << 8) | b;
        }

        if (len < 0x80)
        {
            throw new PsignException("non-minimal DER length");
        }

        return (pos, len);
    }
}
