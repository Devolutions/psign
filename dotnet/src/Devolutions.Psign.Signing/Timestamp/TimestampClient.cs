using System.Net.Http.Headers;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Internal;

namespace Devolutions.Psign.Signing.Timestamp;

/// <summary>
/// RFC 3161 TSA HTTP client (port of the <c>timestamp-http</c> helpers in Rust <c>psign-digest-cli</c>
/// (<c>rfc3161-timestamp-http-post</c>, <c>post_rfc3161_timestamp_request</c>, <c>timestamp_pkcs7_der_rfc3161</c>) and
/// <c>psign-portable-core</c> <c>request_rfc3161_token</c>): POSTs <c>application/timestamp-query</c>, validates the reply
/// and extracts the <c>timeStampToken</c>. Does not verify the token's CMS signature.
/// </summary>
public sealed class TimestampClient : IDisposable
{
    private readonly HttpTransport _http;

    /// <param name="handler">Optional HTTP handler (tests inject an in-memory handler); not disposed by the client.</param>
    public TimestampClient(HttpMessageHandler? handler = null)
    {
        _http = new HttpTransport(handler);
    }

    /// <summary>Request timeout (Rust: 120 seconds).</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(120);

    /// <summary>
    /// POST an already-encoded <c>TimeStampReq</c> and return the raw <c>TimeStampResp</c> body
    /// (Rust <c>run_rfc3161_timestamp_http_post</c>). Non-2xx responses fail with the first 256 body bytes in hex.
    /// </summary>
    public byte[] PostTimestampRequest(string url, byte[] timeStampReqDer) =>
        HttpTransport.RunSync(() => PostTimestampRequestAsync(url, timeStampReqDer));

    /// <inheritdoc cref="PostTimestampRequest"/>
    public async Task<byte[]> PostTimestampRequestAsync(string url, byte[] timeStampReqDer, CancellationToken cancellationToken = default)
    {
        var target = url.Trim();
        if (!Uri.TryCreate(target, UriKind.Absolute, out var targetUri)
            || (!string.Equals(targetUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(targetUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            throw new PsignException($"POST TimeStampReq to {target}: invalid URL");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, targetUri) { Content = new ByteArrayContent(timeStampReqDer) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        request.Headers.TryAddWithoutValidation("Accept", "application/timestamp-reply, application/timestamp-response");
        var rsp = await _http.SendAsync(request, Timeout, $"POST TimeStampReq to {target}", cancellationToken).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            var n = Math.Min(rsp.Body.Length, 256);
            throw new PsignException($"TSA HTTP {rsp.StatusText} — first {n} body bytes (hex): {Hex.Lower(rsp.Body.AsSpan(0, n))}");
        }

        return rsp.Body;
    }

    /// <summary>
    /// Build a <c>TimeStampReq</c> (<c>certReq</c> true, no nonce) for <paramref name="messageImprint"/> and POST it
    /// (Rust <c>post_rfc3161_timestamp_request</c>).
    /// </summary>
    public byte[] PostRfc3161TimestampRequest(string url, AuthenticodeHashKind algorithm, byte[] messageImprint)
    {
        if (messageImprint.Length != algorithm.DigestLength())
        {
            throw new PsignException($"timestamp message imprint must be exactly {algorithm.DigestLength()} bytes for {DebugName(algorithm)}, got {messageImprint.Length}");
        }

        var der = BuildRequest(algorithm, messageImprint)
            ?? throw new PsignException("unsupported digest OID / preimage length for RFC3161 TimeStampReq");
        return PostTimestampRequest(url, der);
    }

    /// <summary>
    /// Request a timestamp token whose imprint covers <paramref name="stamped"/> (hashed with <paramref name="algorithm"/>)
    /// and return the token <c>ContentInfo</c> DER (Rust portable-core <c>request_rfc3161_token</c>).
    /// </summary>
    public byte[] RequestToken(string timestampServer, AuthenticodeHashKind algorithm, byte[] stamped) =>
        HttpTransport.RunSync(() => RequestTokenAsync(timestampServer, algorithm, stamped));

    /// <inheritdoc cref="RequestToken"/>
    public async Task<byte[]> RequestTokenAsync(string timestampServer, AuthenticodeHashKind algorithm, byte[] stamped, CancellationToken cancellationToken = default)
    {
        var target = timestampServer.Trim();
        if (!Uri.TryCreate(target, UriKind.Absolute, out var targetUri)
            || (!string.Equals(targetUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(targetUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            throw new PsignException($"POST TimeStampReq to {target}: invalid URL");
        }

        var imprint = algorithm.Hash(stamped);
        var requestDer = BuildRequest(algorithm, imprint)
            ?? throw new PsignException("build RFC3161 TimeStampReq");
        using var request = new HttpRequestMessage(HttpMethod.Post, targetUri) { Content = new ByteArrayContent(requestDer) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        request.Headers.TryAddWithoutValidation("Accept", "application/timestamp-reply");
        var rsp = await _http.SendAsync(request, Timeout, $"POST TimeStampReq to {timestampServer}", cancellationToken).ConfigureAwait(false);
        if (!rsp.IsSuccess)
        {
            var kind = (int)rsp.Status >= 500 ? "server" : "client";
            throw new PsignException(
                $"TSA returned an HTTP error from {timestampServer}",
                new PsignException($"HTTP status {kind} error ({rsp.StatusText}) for url ({timestampServer})"));
        }

        return ExtractGrantedToken(rsp.Body);
    }

    /// <summary>
    /// Timestamp the first signer of a PKCS#7 <c>SignedData</c>: hash its signature, request a token and attach it as an
    /// unsigned attribute (Rust <c>timestamp_pkcs7_der_rfc3161</c>).
    /// </summary>
    public byte[] TimestampPkcs7(byte[] pkcs7Der, string timestampUrl, AuthenticodeHashKind timestampDigest, Rfc3161TimestampAttribute attribute = Rfc3161TimestampAttribute.MicrosoftAuthenticode)
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

        var imprint = timestampDigest.Hash(sd.SignerInfos[0].Signature);
        var response = PostRfc3161TimestampRequest(timestampUrl, timestampDigest, imprint);
        var token = ExtractGrantedToken(response);
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

    /// <summary>Parse a <c>TimeStampResp</c> and return its token when the status is granted.</summary>
    public static byte[] ExtractGrantedToken(byte[] timeStampResp)
    {
        var parsed = Rfc3161.ParseTimeStampRespDer(timeStampResp)
            ?? throw new PsignException("could not parse TimeStampResp DER from TSA response");
        if (!parsed.PkiStatus.Granted)
        {
            throw new PsignException($"TimeStampResp status is not granted (status={parsed.PkiStatus.AsRawInteger()})");
        }

        return parsed.TimeStampToken ?? throw new PsignException("TimeStampResp has no timeStampToken");
    }

    private static string DebugName(AuthenticodeHashKind kind) => kind.ToString();

    /// <summary><c>TimeStampReq</c> with <c>certReq</c> true and no nonce (Rust <c>build_timestamp_request_bytes</c>).</summary>
    private static byte[]? BuildRequest(AuthenticodeHashKind algorithm, byte[] imprint) =>
        Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = algorithm.Oid(), CertReq = true }, imprint);

    public void Dispose() => _http.Dispose();
}
