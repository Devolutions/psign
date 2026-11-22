using System.Globalization;
using System.Net;
using System.Text;

namespace Devolutions.Psign.Signing.Internal;

/// <summary>HTTP helpers that reproduce the Rust <c>reqwest</c> / <c>url</c> crate text forms used in error messages and URLs.</summary>
internal static class HttpText
{
    /// <summary>Render a status code like Rust <c>http::StatusCode</c> <c>Display</c> (<c>"403 Forbidden"</c>).</summary>
    public static string Status(HttpStatusCode code)
    {
        var n = (int)code;
        var reason = CanonicalReason(n);
        return reason is null
            ? n.ToString(CultureInfo.InvariantCulture) + " <unknown status code>"
            : n.ToString(CultureInfo.InvariantCulture) + " " + reason;
    }

    /// <summary>Canonical reason phrases from the Rust <c>http</c> crate.</summary>
    public static string? CanonicalReason(int code) => code switch
    {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => null,
    };

    /// <summary>Percent-encode a URL path segment like the Rust <c>url</c> crate <c>path_segments_mut().push</c>.</summary>
    public static string EncodePathSegment(string segment)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(segment))
        {
            var encode = b < 0x20 || b >= 0x7f || b is (byte)' ' or (byte)'"' or (byte)'#' or (byte)'<' or (byte)'>'
                or (byte)'?' or (byte)'`' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';
            if (encode)
            {
                sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
            else
            {
                sb.Append((char)b);
            }
        }

        return sb.ToString();
    }

    /// <summary><c>application/x-www-form-urlencoded</c> encoding (Rust <c>form_urlencoded</c> / <c>append_pair</c>).</summary>
    public static string FormEncode(string value)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            if (b is >= (byte)'a' and <= (byte)'z' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'0' and <= (byte)'9'
                or (byte)'*' or (byte)'-' or (byte)'.' or (byte)'_')
            {
                sb.Append((char)b);
            }
            else if (b == (byte)' ')
            {
                sb.Append('+');
            }
            else
            {
                sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return sb.ToString();
    }

    /// <summary>Build an <c>application/x-www-form-urlencoded</c> body / query string.</summary>
    public static string FormEncode(IEnumerable<KeyValuePair<string, string>> pairs) =>
        string.Join('&', pairs.Select(p => FormEncode(p.Key) + "=" + FormEncode(p.Value)));

    /// <summary>Append <c>key=value</c> to a URL query (Rust <c>query_pairs_mut().append_pair</c>).</summary>
    public static string AppendQueryPair(string url, string key, string value)
    {
        var hashIndex = url.IndexOf('#');
        var fragment = hashIndex >= 0 ? url[hashIndex..] : string.Empty;
        var head = hashIndex >= 0 ? url[..hashIndex] : url;
        var q = head.IndexOf('?');
        var pair = FormEncode(key) + "=" + FormEncode(value);
        if (q < 0)
        {
            return head + "?" + pair + fragment;
        }

        return head.Length == q + 1 ? head + pair + fragment : head + "&" + pair + fragment;
    }

    /// <summary>Read a response body as UTF-8 text with lossy replacement (Rust <c>String::from_utf8_lossy</c>).</summary>
    public static string Lossy(byte[] body) => Encoding.UTF8.GetString(body);
}
