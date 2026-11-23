using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Internal;

/// <summary>A buffered HTTP response.</summary>
internal sealed record HttpResult(HttpStatusCode Status, HttpResponseMessage Message, byte[] Body)
{
    public bool IsSuccess => (int)Status is >= 200 and <= 299;

    public string Text => HttpText.Lossy(Body);

    public string StatusText => HttpText.Status(Status);

    public string? Header(string name)
    {
        if (Message.Headers.TryGetValues(name, out var values))
        {
            return values.FirstOrDefault();
        }

        if (Message.Content.Headers.TryGetValues(name, out var contentValues))
        {
            return contentValues.FirstOrDefault();
        }

        return null;
    }
}

/// <summary>
/// Shared <see cref="HttpClient"/> plumbing for the remote signers and the TSA client: an injectable
/// <see cref="HttpMessageHandler"/> (tests use an in-memory handler), per-request timeouts, and Rust-style error context.
/// </summary>
internal sealed class HttpTransport : IDisposable
{
    private readonly HttpClient _client;
    private readonly HttpClient _noRedirectClient;

    public HttpTransport(HttpMessageHandler? handler)
    {
        if (handler is not null)
        {
            _client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
            _noRedirectClient = _client;
        }
        else
        {
            _client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true }) { Timeout = Timeout.InfiniteTimeSpan };
            _noRedirectClient = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = Timeout.InfiniteTimeSpan };
        }
    }

    /// <summary>Send <paramref name="request"/> and buffer the response body (optionally bounded).</summary>
    public async Task<HttpResult> SendAsync(
        HttpRequestMessage request,
        TimeSpan timeout,
        string context,
        CancellationToken cancellationToken,
        bool followRedirects = true,
        Func<HttpStatusCode, (int Max, string Context)>? bodyLimit = null)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        HttpResponseMessage response;
        try
        {
            response = await (followRedirects ? _client : _noRedirectClient)
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                .ConfigureAwait(false);
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or InvalidOperationException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new PsignException(context, e is OperationCanceledException ? new PsignException("operation timed out", e) : e);
        }

        try
        {
            byte[] body;
            if (bodyLimit is not null)
            {
                var (max, limitContext) = bodyLimit(response.StatusCode);
                try
                {
                    var stream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
                    await using (stream.ConfigureAwait(false))
                    {
                        body = await ReadBoundedAsync(stream, max, cts.Token).ConfigureAwait(false);
                    }
                }
                catch (Exception e) when (e is PsignException or IOException or HttpRequestException or OperationCanceledException)
                {
                    throw new PsignException(limitContext, e);
                }
            }
            else
            {
                body = await response.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
            }

            return new HttpResult(response.StatusCode, response, body);
        }
        catch (Exception e) when (e is IOException or HttpRequestException or OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new PsignException(context, e);
        }
    }

    /// <summary>Read at most <paramref name="max"/> bytes (Rust <c>read_bounded_body</c>; message names Artifact Signing).</summary>
    public static async Task<byte[]> ReadBoundedAsync(Stream stream, int max, CancellationToken cancellationToken)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            ms.Write(buffer, 0, read);
            if (ms.Length > max)
            {
                throw new PsignException($"Artifact Signing root certificate response exceeds {max} bytes");
            }
        }

        return ms.ToArray();
    }

    /// <summary>Parse a JSON body, wrapping failures with <paramref name="context"/>.</summary>
    public static JsonNode? ParseJson(byte[] body, string context)
    {
        try
        {
            return JsonNode.Parse(body);
        }
        catch (JsonException e)
        {
            throw new PsignException(context, e);
        }
    }

    /// <summary>Extract a required string member (serde <c>#[derive(Deserialize)]</c> struct field).</summary>
    public static string RequiredString(byte[] body, string field, string context)
    {
        var node = ParseJson(body, context);
        if (node is not JsonObject obj)
        {
            throw new PsignException(context, new PsignException($"invalid type: expected struct with field `{field}`"));
        }

        if (!obj.TryGetPropertyValue(field, out var value) || value is null)
        {
            throw new PsignException(context, new PsignException($"missing field `{field}`"));
        }

        if (value is not JsonValue v || v.GetValueKind() != JsonValueKind.String)
        {
            throw new PsignException(context, new PsignException($"invalid type for field `{field}`, expected a string"));
        }

        return v.GetValue<string>();
    }

    /// <summary>Run an async operation synchronously (blocking API surface mirroring the Rust blocking clients).</summary>
    public static T RunSync<T>(Func<Task<T>> action) => Task.Run(action).GetAwaiter().GetResult();

    public void Dispose()
    {
        if (!ReferenceEquals(_client, _noRedirectClient))
        {
            _noRedirectClient.Dispose();
        }

        _client.Dispose();
    }
}
