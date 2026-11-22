using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>A request received by <see cref="LocalHttpServer"/>.</summary>
internal sealed record LocalHttpRequest(string Method, string PathAndQuery, Dictionary<string, string> Headers, byte[] Body)
{
    public string BodyText => Encoding.UTF8.GetString(Body);

    public string Path => PathAndQuery.Split('?')[0];
}

/// <summary>A response produced by a <see cref="LocalHttpServer"/> handler.</summary>
internal sealed record LocalHttpResponse(int Status, byte[] Body, params (string Name, string Value)[] Headers)
{
    public static LocalHttpResponse Json(string json, int status = 200) => new(status, Encoding.UTF8.GetBytes(json), ("Content-Type", "application/json"));
}

/// <summary>
/// Minimal HTTP/1.1 server on <c>127.0.0.1</c> (one request per connection, <c>Connection: close</c>) so the Rust FFI and
/// the C# implementation can talk to the same mock TSA / Key Vault / Artifact Signing endpoints over real sockets. Bodies
/// must use <c>Content-Length</c> (both clients send it for buffered bodies).
/// </summary>
internal sealed class LocalHttpServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly Func<LocalHttpRequest, LocalHttpResponse> _handler;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public LocalHttpServer(Func<LocalHttpRequest, LocalHttpResponse> handler)
    {
        _handler = handler;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        BaseUrl = $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";
        _loop = Task.Run(AcceptLoop);
    }

    public string BaseUrl { get; }

    public List<LocalHttpRequest> Requests { get; } = [];

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = Task.Run(() => Serve(client));
        }
    }

    private async Task Serve(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                var head = new List<byte>();
                var one = new byte[1];
                while (!(head.Count >= 4 && head[^4] == '\r' && head[^3] == '\n' && head[^2] == '\r' && head[^1] == '\n'))
                {
                    if (await stream.ReadAsync(one).ConfigureAwait(false) == 0)
                    {
                        return;
                    }

                    head.Add(one[0]);
                }

                var lines = Encoding.ASCII.GetString(head.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                var requestLine = lines[0].Split(' ');
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in lines.Skip(1))
                {
                    int colon = line.IndexOf(':');
                    if (colon > 0)
                    {
                        headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
                    }
                }

                var length = headers.TryGetValue("Content-Length", out var cl) ? int.Parse(cl, CultureInfo.InvariantCulture) : 0;
                var body = new byte[length];
                int read = 0;
                while (read < length)
                {
                    int n = await stream.ReadAsync(body.AsMemory(read)).ConfigureAwait(false);
                    if (n == 0)
                    {
                        break;
                    }

                    read += n;
                }

                var request = new LocalHttpRequest(requestLine[0], requestLine[1], headers, body);
                lock (Requests)
                {
                    Requests.Add(request);
                }

                LocalHttpResponse response;
                try
                {
                    response = _handler(request);
                }
                catch (Exception e)
                {
                    response = new LocalHttpResponse(500, Encoding.UTF8.GetBytes(e.ToString()));
                }

                var sb = new StringBuilder();
                sb.Append(CultureInfo.InvariantCulture, $"HTTP/1.1 {response.Status} {(response.Status < 400 ? "OK" : "Error")}\r\n");
                sb.Append(CultureInfo.InvariantCulture, $"Content-Length: {response.Body.Length}\r\nConnection: close\r\n");
                foreach (var (name, value) in response.Headers)
                {
                    sb.Append(CultureInfo.InvariantCulture, $"{name}: {value}\r\n");
                }

                sb.Append("\r\n");
                await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString())).ConfigureAwait(false);
                await stream.WriteAsync(response.Body).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
            }
            catch (Exception e) when (e is IOException or SocketException or ObjectDisposedException)
            {
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try
        {
            _loop.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
        }

        _cts.Dispose();
    }
}
