using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>
/// RFC 3161 timestamping for the portable package signing commands (<c>--timestamp-url</c> / <c>--timestamp-digest</c>),
/// mirroring <c>timestamp_pkcs7_if_requested</c> / <c>vsix_timestamp_if_requested</c> in the Rust CLI.
/// <para>
/// All TSA traffic goes through <see cref="Fetch"/>, which uses the managed RFC 3161 HTTP client
/// (<c>Signing/Timestamp/TimestampClient.cs</c>).
///
/// </para>
/// </summary>
internal static class CliTimestamp
{
    internal static readonly string[] HashAlgValues = ["sha1", "sha256", "sha384", "sha512"];

    /// <summary>
    /// POST a <c>TimeStampReq</c> (certReq = true, no nonce) for <paramref name="imprint"/> to <paramref name="url"/> and return
    /// the raw <c>TimeStampResp</c> DER (Rust <c>post_rfc3161_timestamp_request</c>).
    /// </summary>
    public static byte[] Fetch(string url, AuthenticodeHashKind digestKind, byte[] imprint)
    {
        if (imprint.Length != digestKind.DigestLength())
        {
            throw new PsignException(
                $"timestamp message imprint must be exactly {digestKind.DigestLength()} bytes for {DebugName(digestKind)}, got {imprint.Length}");
        }

        using var client = new Devolutions.Psign.Signing.Timestamp.TimestampClient(HandlerOverride);
        return client.PostRfc3161TimestampRequest(url, digestKind, imprint);
    }

    /// <summary>Test hook: HTTP handler used for TSA requests (null = default transport).</summary>
    internal static HttpMessageHandler? HandlerOverride { get; set; }

    /// <summary>Granted <c>timeStampToken</c> from a TSA response (Rust <c>parse_time_stamp_resp_der</c> + status checks).</summary>
    public static byte[] TokenFromResponse(byte[] response)
    {
        var parsed = Rfc3161.ParseTimeStampRespDer(response)
            ?? throw new PsignException("could not parse TimeStampResp DER from TSA response");
        if (!parsed.PkiStatus.Granted)
        {
            throw new PsignException($"TimeStampResp status is not granted (status={parsed.PkiStatus.AsRawInteger()})");
        }

        return parsed.TimeStampToken ?? throw new PsignException("TimeStampResp has no timeStampToken");
    }

    /// <summary>Rust <c>timestamp_pkcs7_if_requested</c>.</summary>
    public static byte[] TimestampPkcs7IfRequested(byte[] pkcs7, string? url, string? digest, Rfc3161TimestampAttribute attribute, string context)
    {
        switch (url, digest)
        {
            case (not null, not null):
                var kind = AuthenticodeHashKinds.Parse(digest);
                try
                {
                    return Pkcs7IdData.Timestamp(pkcs7, input => TokenFromResponse(Fetch(url, kind, kind.Hash(input))), attribute);
                }
                catch (PsignException e)
                {
                    throw new PsignException($"RFC3161 timestamp {context}", e);
                }

            case (not null, null):
                throw new PsignException($"{context} requires --timestamp-digest with --timestamp-url");
            case (null, not null):
                throw new PsignException($"{context} requires --timestamp-url with --timestamp-digest");
            default:
                return pkcs7;
        }
    }

    /// <summary>Rust <c>vsix_timestamp_if_requested</c>.</summary>
    public static byte[] VsixTimestampIfRequested(byte[] signatureXml, string? url, string? digest)
    {
        switch (url, digest)
        {
            case (not null, not null):
                var kind = AuthenticodeHashKinds.Parse(digest);
                var signatureValue = Signing.Vsix.VsixSigner.TimestampImprintInput(signatureXml);
                byte[] response;
                try
                {
                    response = Fetch(url, kind, kind.Hash(signatureValue));
                }
                catch (PsignException e)
                {
                    throw new PsignException("vsix-sign: RFC3161 timestamp request", e);
                }

                return Signing.Vsix.VsixSigner.AddSignatureTimestamp(signatureXml, TokenFromResponse(response));
            case (not null, null):
                throw new PsignException("vsix-sign requires --timestamp-digest with --timestamp-url");
            case (null, not null):
                throw new PsignException("vsix-sign requires --timestamp-url with --timestamp-digest");
            default:
                return signatureXml;
        }
    }

    private static string DebugName(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => "Sha1",
        AuthenticodeHashKind.Sha256 => "Sha256",
        AuthenticodeHashKind.Sha384 => "Sha384",
        _ => "Sha512",
    };
}
