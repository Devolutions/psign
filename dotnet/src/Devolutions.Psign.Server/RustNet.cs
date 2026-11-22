using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Server;

/// <summary>
/// Rust <c>std::net::TcpListener::bind(&amp;str)</c> semantics: parse a literal <c>SocketAddr</c> first, otherwise split
/// <c>host:port</c> at the last colon and resolve the host, binding the first address that works. Error texts follow
/// <c>std::io::Error</c> display strings.
/// </summary>
internal static class RustNet
{
    /// <summary>Bind a listening socket like <c>TcpListener::bind</c> (backlog 128).</summary>
    public static Socket Bind(string listen)
    {
        var addresses = ToSocketAddrs(listen);
        Exception? last = null;
        foreach (var ep in addresses)
        {
            var socket = new Socket(ep.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                if (ep.AddressFamily == AddressFamily.InterNetworkV6 && OperatingSystem.IsWindows())
                {
                    socket.DualMode = false;
                }

                socket.Bind(ep);
                socket.Listen(128);
                return socket;
            }
            catch (SocketException e)
            {
                socket.Dispose();
                last = new PsignException(SocketErrorText(e));
            }
        }

        throw last ?? new PsignException("could not resolve to any addresses");
    }

    /// <summary>Rust <c>impl ToSocketAddrs for str</c>.</summary>
    internal static List<IPEndPoint> ToSocketAddrs(string s)
    {
        if (TryParseSocketAddr(s, out var literal))
        {
            return [literal];
        }

        int colon = s.LastIndexOf(':');
        if (colon < 0)
        {
            throw new PsignException("invalid socket address");
        }

        var host = s[..colon];
        var portText = s[(colon + 1)..];
        if (!TryParseU16(portText, out var port))
        {
            throw new PsignException("invalid port value");
        }

        IPAddress[] resolved;
        try
        {
            resolved = Dns.GetHostAddresses(host);
        }
        catch (SocketException e)
        {
            // Windows surfaces the raw WSA error; Unix wraps gai_strerror text.
            throw new PsignException(OperatingSystem.IsWindows()
                ? SocketErrorText(e)
                : $"failed to lookup address information: {e.Message}");
        }
        catch (ArgumentException)
        {
            throw new PsignException("failed to lookup address information: invalid host name");
        }

        return resolved.Select(a => new IPEndPoint(a, port)).ToList();
    }

    private static bool TryParseSocketAddr(string s, out IPEndPoint ep)
    {
        ep = null!;
        if (s.StartsWith('['))
        {
            int close = s.IndexOf(']');
            if (close < 0 || close + 1 >= s.Length || s[close + 1] != ':')
            {
                return false;
            }

            var inner = s[1..close];
            uint scope = 0;
            int pct = inner.IndexOf('%');
            if (pct >= 0)
            {
                if (!uint.TryParse(inner[(pct + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out scope))
                {
                    return false;
                }

                inner = inner[..pct];
            }

            if (!IsStrictIpv6(inner) || !IPAddress.TryParse(inner, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }

            if (!TryParsePortDigits(s[(close + 2)..], out var port6))
            {
                return false;
            }

            v6.ScopeId = scope;
            ep = new IPEndPoint(v6, port6);
            return true;
        }

        int colon = s.IndexOf(':');
        if (colon < 0 || s.IndexOf(':', colon + 1) >= 0)
        {
            return false;
        }

        if (!TryParseStrictIpv4(s[..colon], out var v4) || !TryParsePortDigits(s[(colon + 1)..], out var port4))
        {
            return false;
        }

        ep = new IPEndPoint(v4, port4);
        return true;
    }

    private static bool IsStrictIpv6(string s) => s.Length > 0 && s.All(c => c == ':' || c == '.' || Uri.IsHexDigit(c));

    private static bool TryParseStrictIpv4(string s, out IPAddress address)
    {
        address = IPAddress.None;
        var parts = s.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        var bytes = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            var p = parts[i];
            if (p.Length == 0 || p.Length > 3 || !p.All(char.IsAsciiDigit) || (p.Length > 1 && p[0] == '0'))
            {
                return false;
            }

            int v = int.Parse(p, CultureInfo.InvariantCulture);
            if (v > 255)
            {
                return false;
            }

            bytes[i] = (byte)v;
        }

        address = new IPAddress(bytes);
        return true;
    }

    /// <summary>Port in a literal socket address: decimal digits only.</summary>
    private static bool TryParsePortDigits(string s, out ushort port)
    {
        port = 0;
        if (s.Length == 0 || !s.All(char.IsAsciiDigit))
        {
            return false;
        }

        return ushort.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out port);
    }

    /// <summary>Rust <c>u16::from_str</c> (optional leading <c>+</c>).</summary>
    private static bool TryParseU16(string s, out ushort port)
    {
        port = 0;
        var t = s.StartsWith('+') ? s[1..] : s;
        if (t.Length == 0 || !t.All(char.IsAsciiDigit))
        {
            return false;
        }

        return ushort.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out port);
    }

    /// <summary>Rust <c>SocketAddr</c> display (<c>1.2.3.4:5</c>, <c>[::1]:5</c>, <c>[fe80::1%3]:5</c>).</summary>
    public static string FormatEndPoint(IPEndPoint ep)
    {
        if (ep.Address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var copy = new IPAddress(ep.Address.GetAddressBytes());
            var scope = ep.Address.ScopeId != 0 ? "%" + ep.Address.ScopeId.ToString(CultureInfo.InvariantCulture) : string.Empty;
            return $"[{copy}{scope}]:{ep.Port}";
        }

        return $"{ep.Address}:{ep.Port}";
    }

    /// <summary><c>std::io::Error</c> display for an OS socket error (<c>message (os error N)</c>).</summary>
    public static string SocketErrorText(SocketException e)
    {
        var message = e.Message.TrimEnd();
        return $"{message} (os error {e.NativeErrorCode})";
    }
}
