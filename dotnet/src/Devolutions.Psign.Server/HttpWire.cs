using System.Net.Sockets;
using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Server;

/// <summary>Parsed HTTP/1.1 request (Rust <c>HttpRequest</c>).</summary>
internal sealed class HttpRequest
{
    public required string Method { get; init; }

    /// <summary>Request target (path plus optional query).</summary>
    public required string Path { get; init; }

    public required List<(string Name, string Value)> Headers { get; init; }

    public required byte[] Body { get; init; }

    /// <summary>First header value whose name matches case-insensitively (ASCII).</summary>
    public string? Header(string name)
    {
        foreach (var (n, v) in Headers)
        {
            if (EqualsIgnoreAsciiCase(n, name))
            {
                return v;
            }
        }

        return null;
    }

    internal static bool EqualsIgnoreAsciiCase(string a, string b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        for (int i = 0; i < a.Length; i++)
        {
            char x = a[i] is >= 'A' and <= 'Z' ? (char)(a[i] + 32) : a[i];
            char y = b[i] is >= 'A' and <= 'Z' ? (char)(b[i] + 32) : b[i];
            if (x != y)
            {
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// The minimal HTTP/1.1 wire handling of <c>psign-server.rs</c>: one request per connection, headers up to the first
/// <c>\r\n\r\n</c> (64 KiB limit), <c>Content-Length</c> body, and <c>Connection: close</c> responses with
/// <c>Content-Type</c> / <c>Content-Length</c> first.
/// </summary>
internal static class HttpWire
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Rust <c>read_http_request</c>.</summary>
    public static HttpRequest ReadRequest(Socket socket)
    {
        var buf = new List<byte>();
        var tmp = new byte[4096];
        int headerEnd;
        while (true)
        {
            int n = Receive(socket, tmp, "read HTTP request");
            if (n == 0)
            {
                throw new PsignException("client closed before HTTP headers completed");
            }

            buf.AddRange(tmp.AsSpan(0, n));
            var pos = FindHeaderEnd(buf);
            if (pos >= 0)
            {
                headerEnd = pos;
                break;
            }

            if (buf.Count > 64 * 1024)
            {
                throw new PsignException("HTTP headers too large");
            }
        }

        var raw = buf.ToArray();
        string headers;
        try
        {
            headers = StrictUtf8.GetString(raw, 0, headerEnd);
        }
        catch (DecoderFallbackException)
        {
            throw new PsignException("HTTP headers are not UTF-8", new PsignException(Utf8ErrorText(raw.AsSpan(0, headerEnd))));
        }

        var lines = RustLines(headers);
        if (lines.Count == 0)
        {
            throw new PsignException("missing HTTP request line");
        }

        var parts = SplitWhitespace(lines[0]);
        if (parts.Count < 1)
        {
            throw new PsignException("missing HTTP method");
        }

        if (parts.Count < 2)
        {
            throw new PsignException("missing HTTP path");
        }

        ulong contentLen = 0;
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon < 0)
            {
                continue;
            }

            if (HttpRequest.EqualsIgnoreAsciiCase(line[..colon], "content-length") && TryParseUsize(line[(colon + 1)..].Trim(), out var v))
            {
                contentLen = v;
                break;
            }
        }

        var parsedHeaders = new List<(string, string)>();
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon >= 0)
            {
                parsedHeaders.Add((line[..colon].Trim(), line[(colon + 1)..].Trim()));
            }
        }

        long bodyStart = headerEnd + 4;
        while ((ulong)buf.Count < (ulong)bodyStart + contentLen)
        {
            int n = Receive(socket, tmp, "read HTTP body");
            if (n == 0)
            {
                throw new PsignException("client closed before HTTP body completed");
            }

            buf.AddRange(tmp.AsSpan(0, n));
        }

        var all = buf.ToArray();
        return new HttpRequest
        {
            Method = parts[0],
            Path = parts[1],
            Headers = parsedHeaders,
            Body = all.AsSpan((int)bodyStart, (int)contentLen).ToArray(),
        };
    }

    private static int Receive(Socket socket, byte[] buffer, string context)
    {
        try
        {
            return socket.Receive(buffer);
        }
        catch (SocketException e)
        {
            throw new PsignException(context, new PsignException(RustNet.SocketErrorText(e)));
        }
    }

    private static int FindHeaderEnd(List<byte> buf)
    {
        for (int i = 0; i + 4 <= buf.Count; i++)
        {
            if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>Rust <c>usize::from_str</c> (optional leading <c>+</c>, decimal digits, no overflow).</summary>
    private static bool TryParseUsize(string s, out ulong value)
    {
        value = 0;
        var span = s.AsSpan();
        if (span.Length > 0 && span[0] == '+')
        {
            span = span[1..];
        }

        if (span.IsEmpty)
        {
            return false;
        }

        foreach (var c in span)
        {
            if (c is < '0' or > '9')
            {
                return false;
            }

            try
            {
                value = checked((value * 10) + (ulong)(c - '0'));
            }
            catch (OverflowException)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Rust <c>str::lines</c>.</summary>
    internal static List<string> RustLines(string text)
    {
        var lines = new List<string>();
        int start = 0;
        while (start < text.Length)
        {
            int nl = text.IndexOf('\n', start);
            string line;
            if (nl < 0)
            {
                line = text[start..];
                start = text.Length;
            }
            else
            {
                line = text[start..nl];
                start = nl + 1;
            }

            if (line.EndsWith('\r'))
            {
                line = line[..^1];
            }

            lines.Add(line);
        }

        return lines;
    }

    /// <summary>Rust <c>str::split_whitespace</c>.</summary>
    internal static List<string> SplitWhitespace(string s)
    {
        var parts = new List<string>();
        int i = 0;
        while (i < s.Length)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i]))
            {
                i++;
            }

            int start = i;
            while (i < s.Length && !char.IsWhiteSpace(s[i]))
            {
                i++;
            }

            if (i > start)
            {
                parts.Add(s[start..i]);
            }
        }

        return parts;
    }

    /// <summary>Rust <c>core::str::Utf8Error</c> display text.</summary>
    internal static string Utf8ErrorText(ReadOnlySpan<byte> bytes)
    {
        int i = 0;
        while (i < bytes.Length)
        {
            byte b = bytes[i];
            if (b < 0x80)
            {
                i++;
                continue;
            }

            int width = b switch
            {
                >= 0xc2 and <= 0xdf => 2,
                >= 0xe0 and <= 0xef => 3,
                >= 0xf0 and <= 0xf4 => 4,
                _ => 0,
            };
            if (width == 0)
            {
                return $"invalid utf-8 sequence of 1 bytes from index {i}";
            }

            int valid = 1;
            for (int k = 1; k < width; k++)
            {
                if (i + k >= bytes.Length)
                {
                    return $"incomplete utf-8 byte sequence from index {i}";
                }

                byte c = bytes[i + k];
                bool ok = k == 1
                    ? b switch
                    {
                        0xe0 => c is >= 0xa0 and <= 0xbf,
                        0xed => c is >= 0x80 and <= 0x9f,
                        0xf0 => c is >= 0x90 and <= 0xbf,
                        0xf4 => c is >= 0x80 and <= 0x8f,
                        _ => c is >= 0x80 and <= 0xbf,
                    }
                    : c is >= 0x80 and <= 0xbf;
                if (!ok)
                {
                    return $"invalid utf-8 sequence of {valid} bytes from index {i}";
                }

                valid++;
            }

            i += width;
        }

        return "invalid utf-8";
    }

    /// <summary>Rust <c>write_http_response_with_headers</c> (single send of the identical byte stream).</summary>
    public static void WriteResponse(Socket socket, int status, string reason, string contentType, byte[] body, params (string Name, string Value)[] headers)
    {
        var sb = new StringBuilder();
        sb.Append("HTTP/1.1 ").Append(status).Append(' ').Append(reason).Append("\r\n");
        sb.Append("Content-Type: ").Append(contentType).Append("\r\n");
        sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");
        sb.Append("Connection: close\r\n");
        foreach (var (name, value) in headers)
        {
            sb.Append(name).Append(": ").Append(value).Append("\r\n");
        }

        sb.Append("\r\n");
        var head = Encoding.UTF8.GetBytes(sb.ToString());
        var all = new byte[head.Length + body.Length];
        head.CopyTo(all, 0);
        body.CopyTo(all, head.Length);
        try
        {
            int sent = 0;
            while (sent < all.Length)
            {
                sent += socket.Send(all, sent, all.Length - sent, SocketFlags.None);
            }
        }
        catch (SocketException e)
        {
            throw new PsignException("write HTTP response headers", new PsignException(RustNet.SocketErrorText(e)));
        }
    }

    public static void WriteText(Socket socket, int status, string reason, string body) =>
        WriteResponse(socket, status, reason, "text/plain", Encoding.UTF8.GetBytes(body));

    public static void WriteJson(Socket socket, int status, string reason, System.Text.Json.Nodes.JsonNode body) =>
        WriteResponse(socket, status, reason, "application/json", Encoding.UTF8.GetBytes(Core.Json.RustJson.Compact(body, sortKeys: true)));
}
