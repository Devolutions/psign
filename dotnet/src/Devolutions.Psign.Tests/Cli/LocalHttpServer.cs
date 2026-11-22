using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>A request received by <see cref="LocalHttpServer"/>.</summary>
internal sealed record LocalHttpRequest(string Method, string Target, Dictionary<string, string> Headers, byte[] Body)
{
    public string Path => Target.Split('?')[0];

    public string BodyText => Encoding.UTF8.GetString(Body);
}

/// <summary>A response produced by a <see cref="LocalHttpServer"/> handler.</summary>
internal sealed record LocalHttpResponse(int Status, byte[] Body, string ContentType = "application/octet-stream", params (string Name, string Value)[] Headers)
{
    public static LocalHttpResponse Json(string json, int status = 200, params (string Name, string Value)[] headers) =>
        new(status, Encoding.UTF8.GetBytes(json), "application/json", headers);
}

/// <summary>
/// Minimal HTTP/1.1 server on <c>127.0.0.1</c> (raw <see cref="TcpListener"/>, one request per connection) used to mock
/// TSA / Azure Key Vault / Artifact Signing endpoints for both the Rust and the managed <c>psign-tool</c> without real
/// network access or HTTP.sys URL ACLs.
/// </summary>
internal sealed class LocalHttpServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly Func<LocalHttpRequest, LocalHttpResponse> _handler;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;
    private readonly object _gate = new();

    public LocalHttpServer(Func<LocalHttpRequest, LocalHttpResponse> handler)
    {
        _handler = handler;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _loop = Task.Run(AcceptLoop);
    }

    public int Port { get; }

    public string BaseUrl => $"http://127.0.0.1:{Port}";

    public List<LocalHttpRequest> Requests { get; } = [];

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception) when (_cts.IsCancellationRequested)
            {
                return;
            }
            catch (SocketException)
            {
                return;
            }

            _ = Task.Run(() => Serve(client));
        }
    }

    private void Serve(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                stream.ReadTimeout = 30_000;
                var request = ReadRequest(stream);
                if (request is null)
                {
                    return;
                }

                lock (_gate)
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
                    response = new LocalHttpResponse(500, Encoding.UTF8.GetBytes("mock handler failed: " + e.Message), "text/plain");
                }

                var head = new StringBuilder();
                head.Append("HTTP/1.1 ").Append(response.Status).Append(' ').Append(Reason(response.Status)).Append("\r\n");
                head.Append("Content-Type: ").Append(response.ContentType).Append("\r\n");
                head.Append("Content-Length: ").Append(response.Body.Length).Append("\r\n");
                foreach (var (name, value) in response.Headers)
                {
                    head.Append(name).Append(": ").Append(value).Append("\r\n");
                }

                head.Append("Connection: close\r\n\r\n");
                stream.Write(Encoding.ASCII.GetBytes(head.ToString()));
                stream.Write(response.Body);
                stream.Flush();
                client.Client.Shutdown(SocketShutdown.Send);
            }
            catch (IOException)
            {
            }
            catch (SocketException)
            {
            }
        }
    }

    private static LocalHttpRequest? ReadRequest(NetworkStream stream)
    {
        var header = new List<byte>();
        while (true)
        {
            int b = stream.ReadByte();
            if (b < 0)
            {
                return null;
            }

            header.Add((byte)b);
            int n = header.Count;
            if (n >= 4 && header[n - 4] == '\r' && header[n - 3] == '\n' && header[n - 2] == '\r' && header[n - 1] == '\n')
            {
                break;
            }
        }

        var lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
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

        byte[] body;
        if (headers.TryGetValue("Content-Length", out var len))
        {
            body = new byte[int.Parse(len, System.Globalization.CultureInfo.InvariantCulture)];
            stream.ReadExactly(body);
        }
        else if (headers.TryGetValue("Transfer-Encoding", out var te) && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            body = ReadChunked(stream);
        }
        else
        {
            body = [];
        }

        return new LocalHttpRequest(requestLine[0], requestLine[1], headers, body);
    }

    private static byte[] ReadChunked(NetworkStream stream)
    {
        var body = new MemoryStream();
        while (true)
        {
            var sizeLine = ReadLine(stream);
            int size = int.Parse(sizeLine.Split(';')[0].Trim(), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
            if (size == 0)
            {
                ReadLine(stream);
                return body.ToArray();
            }

            var chunk = new byte[size];
            stream.ReadExactly(chunk);
            body.Write(chunk);
            ReadLine(stream);
        }
    }

    private static string ReadLine(NetworkStream stream)
    {
        var sb = new StringBuilder();
        int prev = -1;
        while (true)
        {
            int b = stream.ReadByte();
            if (b < 0 || (prev == '\r' && b == '\n'))
            {
                return sb.ToString().TrimEnd('\r');
            }

            sb.Append((char)b);
            prev = b;
        }
    }

    private static string Reason(int status) => status switch
    {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    };

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
