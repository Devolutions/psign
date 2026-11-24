using System.Net.Http.Headers;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Signing.Internal;
using Devolutions.Psign.Signing.Vsix;
using TimestampClient = Devolutions.Psign.Signing.Timestamp.TimestampClient;

namespace Devolutions.Psign.Signing.Code;

/// <summary>
/// RFC 3161 timestamping used by the <c>code</c> orchestrator (Rust <c>timestamp_*_if_requested</c>,
/// <c>timestamp_pkcs7_der_rfc3161</c>, <c>timestamp_pe_rfc3161</c>, <c>timestamp_vsix_signature_rfc3161</c> and
/// <c>post_rfc3161_timestamp_request</c> in <c>src/code.rs</c>).
/// </summary>
internal sealed class CodeTimestamp
{
    private readonly string? _url;
    private readonly CodeDigestAlgorithm? _digest;
    private readonly HttpMessageHandler? _handler;

    public CodeTimestamp(string? url, CodeDigestAlgorithm? digest, HttpMessageHandler? handler)
    {
        _url = url;
        _digest = digest;
        _handler = handler;
    }

    public bool Requested => _url is not null || _digest is not null;

    private (string Url, CodeDigestAlgorithm Digest)? Resolve()
    {
        return (_url, _digest) switch
        {
            ({ } url, { } digest) => (url, digest),
            (not null, null) => throw new PsignException("`psign-tool code` requires --timestamp-digest with --timestamp-url"),
            (null, not null) => throw new PsignException("`psign-tool code` requires --timestamp-url with --timestamp-digest"),
            _ => null,
        };
    }

    /// <summary>Rust <c>timestamp_pkcs7_if_requested</c>.</summary>
    public byte[] Pkcs7IfRequested(byte[] pkcs7Der, Rfc3161TimestampAttribute attribute) =>
        Resolve() is { } r ? Pkcs7Der(pkcs7Der, r.Url, r.Digest, attribute) : pkcs7Der;

    /// <summary>Rust <c>timestamp_pe_if_requested</c>.</summary>
    public byte[] PeIfRequested(byte[] image)
    {
        if (Resolve() is not { } r)
        {
            return image;
        }

        int count = CodeSigner.Ctx("inspect PE/WinMD Authenticode PKCS#7 rows", () => PeAuthenticode.Pkcs7Blobs(image).Count);
        if (count == 0)
        {
            throw new PsignException("PE/WinMD has no PKCS#7 Authenticode row to timestamp");
        }

        int index = count - 1;
        var der = CodeSigner.Ctx($"extract PE/WinMD PKCS#7 row {index}", () => PeAuthenticode.NthPkcs7(image, index));
        var stamped = CodeSigner.Ctx($"timestamp PE/WinMD PKCS#7 row {index}", () => Pkcs7Der(der, r.Url, r.Digest, Rfc3161TimestampAttribute.MicrosoftAuthenticode));
        return CodeSigner.Ctx($"replace PE/WinMD PKCS#7 row {index}", () => PeEmbed.ReplacePkcs7CertificateAt(image, index, stamped));
    }

    /// <summary>Rust <c>timestamp_vsix_signature_if_requested</c>: dotnet/sign <c>&lt;EncodedTime&gt;</c> over <c>SignatureValue</c>.</summary>
    public byte[] VsixIfRequested(byte[] signatureXml)
    {
        if (Resolve() is not { } r)
        {
            return signatureXml;
        }

        var signatureValue = VsixPackage.SignatureValueFromSignatureXml(signatureXml);
        var imprint = DigestBytes(r.Digest, signatureValue);
        var token = TimestampClient.ExtractGrantedToken(Post(r.Url, r.Digest, imprint));
        return VsixSigner.AddSignatureTimestamp(signatureXml, token);
    }

    private byte[] Pkcs7Der(byte[] pkcs7Der, string url, CodeDigestAlgorithm digest, Rfc3161TimestampAttribute attribute)
    {
        CmsSignedData sd;
        try
        {
            sd = CmsSignedData.Parse(pkcs7Der);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            throw new PsignException("parse PKCS#7 SignedData", e);
        }

        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("PKCS#7 SignedData has no SignerInfo to timestamp");
        }

        var imprint = DigestBytes(digest, sd.SignerInfos[0].Signature);
        var token = TimestampClient.ExtractGrantedToken(Post(url, digest, imprint));
        CmsSignedData stamped;
        try
        {
            stamped = attribute == Rfc3161TimestampAttribute.MicrosoftAuthenticode
                ? Pkcs7Builder.AddTimestampToken(sd, 0, token)
                : Pkcs7Builder.AddPkcs9TimestampToken(sd, 0, token);
        }
        catch (PsignException e)
        {
            throw new PsignException("attach RFC3161 timestamp token", e);
        }

        return stamped.Encode();
    }

    private static AuthenticodeHashKind Kind(CodeDigestAlgorithm digest) => digest switch
    {
        CodeDigestAlgorithm.Sha1 => AuthenticodeHashKind.Sha1,
        CodeDigestAlgorithm.Sha256 => AuthenticodeHashKind.Sha256,
        CodeDigestAlgorithm.Sha384 => AuthenticodeHashKind.Sha384,
        CodeDigestAlgorithm.Sha512 => AuthenticodeHashKind.Sha512,
        _ => throw new PsignException("`psign-tool code` timestamping supports SHA-1, SHA-256, SHA-384, or SHA-512"),
    };

    private static byte[] DigestBytes(CodeDigestAlgorithm digest, byte[] bytes) => Kind(digest).Hash(bytes);

    /// <summary>Rust <c>post_rfc3161_timestamp_request</c>.</summary>
    private byte[] Post(string url, CodeDigestAlgorithm algorithm, byte[] imprint)
    {
        var der = Devolutions.Psign.Core.Timestamp.Rfc3161.BuildTimestampRequestBytes(new Devolutions.Psign.Core.Timestamp.Rfc3161TimestampRequestPlan { DigestAlgOid = Kind(algorithm).Oid(), Nonce = null, CertReq = true }, imprint)
            ?? throw new PsignException("unsupported digest OID / preimage length for RFC3161 TimeStampReq");
        var target = url.Trim();
        if (!Uri.TryCreate(target, UriKind.Absolute, out var targetUri)
            || (!string.Equals(targetUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(targetUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            throw new PsignException($"POST TimeStampReq to {target}: invalid URL");
        }

        using var http = new HttpTransport(_handler);
        var rsp = HttpTransport.RunSync(async () =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, targetUri) { Content = new ByteArrayContent(der) };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
            request.Headers.TryAddWithoutValidation("Accept", "application/timestamp-reply, application/timestamp-response");
            return await http.SendAsync(request, TimeSpan.FromSeconds(120), $"POST TimeStampReq to {target}", CancellationToken.None).ConfigureAwait(false);
        });
        if (!rsp.IsSuccess)
        {
            int n = Math.Min(rsp.Body.Length, 256);
            throw new PsignException($"TSA HTTP {rsp.StatusText} - first {n} body bytes (hex): {Hex.Lower(rsp.Body.AsSpan(0, n))}");
        }

        return rsp.Body;
    }
}
