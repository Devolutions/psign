using System.Net.Http.Headers;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Internal;

namespace Devolutions.Psign.Signing.Timestamp;

/// <summary>Unsigned attribute used to attach an RFC 3161 token (Rust <c>Rfc3161TimestampAttribute</c>).</summary>
public enum Rfc3161TimestampAttribute
{
    /// <summary>Microsoft Authenticode <c>1.3.6.1.4.1.311.3.3.1</c>.</summary>
    MicrosoftAuthenticode,

    /// <summary>CMS / PKCS#9 <c>id-aa-timeStampToken</c> (<c>1.2.840.113549.1.9.16.2.14</c>).</summary>
    CmsTimeStampToken,
}

/// <summary>Parsed <c>TimeStampResp</c> (status, optional token TLV, status strings, optional failInfo TLV).</summary>
public sealed record TimestampResponse(int Status, byte[]? TimeStampToken, IReadOnlyList<string> StatusStrings, byte[]? FailInfoTlv)
{
    /// <summary><c>granted</c> (0) or <c>grantedWithMods</c> (1).</summary>
    public bool Granted => Status is 0 or 1;
}

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
        using var request = new HttpRequestMessage(HttpMethod.Post, target) { Content = new ByteArrayContent(timeStampReqDer) };
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

        var der = TimestampRequestBuilder.Build(algorithm.Oid(), messageImprint, nonce: null, certReq: true)
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
        var imprint = algorithm.Hash(stamped);
        var requestDer = TimestampRequestBuilder.Build(algorithm.Oid(), imprint, nonce: null, certReq: true)
            ?? throw new PsignException("build RFC3161 TimeStampReq");
        using var request = new HttpRequestMessage(HttpMethod.Post, timestampServer) { Content = new ByteArrayContent(requestDer) };
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
        catch (PsignException e)
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
        var parsed = TimestampResponseParser.Parse(timeStampResp)
            ?? throw new PsignException("could not parse TimeStampResp DER from TSA response");
        if (!parsed.Granted)
        {
            throw new PsignException($"TimeStampResp status is not granted (status={parsed.Status})");
        }

        return parsed.TimeStampToken ?? throw new PsignException("TimeStampResp has no timeStampToken");
    }

    private static string DebugName(AuthenticodeHashKind kind) => kind.ToString();

    public void Dispose() => _http.Dispose();
}

/// <summary>
/// Minimal RFC 3161 <c>TimeStampReq</c> encoder (Rust <c>timestamp::build_timestamp_request_bytes</c>).
/// TODO: switch to <c>Devolutions.Psign.Core.Timestamp</c> once the Core timestamp port is merged.
/// </summary>
internal static class TimestampRequestBuilder
{
    public static byte[]? Build(string digestOid, byte[] imprint, ulong? nonce, bool certReq)
    {
        var expected = digestOid switch
        {
            "1.3.14.3.2.26" => 20,
            "2.16.840.1.101.3.4.2.1" => 32,
            "2.16.840.1.101.3.4.2.2" => 48,
            "2.16.840.1.101.3.4.2.3" => 64,
            _ => -1,
        };
        if (expected < 0 || imprint.Length != expected)
        {
            return null;
        }

        var parts = new List<byte[]>
        {
            new byte[] { 0x02, 0x01, 0x01 },
            Der.EncodeSequence(Der.EncodeSequence(Der.EncodeOid(digestOid), Der.Null), Der.EncodeTlv(0x04, imprint)),
        };
        if (nonce is { } n)
        {
            parts.Add(EncodeUInt64(n));
        }

        if (certReq)
        {
            parts.Add([0x01, 0x01, 0xFF]);
        }

        return Der.EncodeSequence(parts.ToArray());
    }

    private static byte[] EncodeUInt64(ulong n)
    {
        if (n == 0)
        {
            return [0x02, 0x01, 0x00];
        }

        var digits = new List<byte>();
        for (var x = n; x > 0; x >>= 8)
        {
            digits.Insert(0, (byte)(x & 0xFF));
        }

        if ((digits[0] & 0x80) != 0)
        {
            digits.Insert(0, 0);
        }

        return Der.EncodeTlv(0x02, digits.ToArray());
    }
}

/// <summary>
/// Minimal strict RFC 3161 <c>TimeStampResp</c> parser (Rust <c>timestamp::parse_time_stamp_resp_der</c>).
/// TODO: switch to <c>Devolutions.Psign.Core.Timestamp</c> once the Core timestamp port is merged.
/// </summary>
internal static class TimestampResponseParser
{
    public static TimestampResponse? Parse(byte[] input)
    {
        var outer = Der.First(input);
        if (outer is null || outer.Value.Tag != 0x30 || outer.Value.End != input.Length)
        {
            return null;
        }

        var children = Der.Children(input, outer.Value);
        if (children is null || children.Count is 0 or > 2)
        {
            return null;
        }

        var statusInfo = children[0];
        if (statusInfo.Tag != 0x30)
        {
            return null;
        }

        var si = Der.Children(input, statusInfo);
        if (si is null || si.Count == 0 || si[0].Tag != 0x02)
        {
            return null;
        }

        var intBody = si[0].Value(input);
        if (intBody.Length is 0 or > 5 || (intBody[0] & 0x80) != 0)
        {
            return null;
        }

        long status = 0;
        foreach (var b in intBody)
        {
            status = (status << 8) | b;
        }

        if (status > uint.MaxValue)
        {
            return null;
        }

        var strings = new List<string>();
        byte[]? failInfo = null;
        var phase = 0;
        for (var i = 1; i < si.Count; i++)
        {
            var tlv = si[i];
            if (tlv.Tag == 0x30 && phase == 0)
            {
                var texts = Der.Children(input, tlv);
                if (texts is null)
                {
                    return null;
                }

                foreach (var t in texts)
                {
                    if (t.Tag != 0x0C)
                    {
                        return null;
                    }

                    strings.Add(HttpText.Lossy(t.Value(input).ToArray()));
                }

                phase = 1;
            }
            else if (tlv.Tag == 0x03 && phase <= 1)
            {
                failInfo = tlv.Encoded(input).ToArray();
                phase = 2;
            }
            else
            {
                return null;
            }
        }

        var token = children.Count == 2 ? children[1].Encoded(input).ToArray() : null;
        return new TimestampResponse((int)Math.Min(status, int.MaxValue), token, strings, failInfo);
    }
}
