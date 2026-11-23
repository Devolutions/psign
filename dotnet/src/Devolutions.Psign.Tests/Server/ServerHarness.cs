using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Devolutions.Psign.Core.Asn1;
using Xunit;

namespace Devolutions.Psign.Tests.Server;

/// <summary>
/// Locates the Rust tool binaries that have no <see cref="RustTool"/> equivalent (<c>psign-server</c>,
/// <c>psign-depgraph</c>) via <c>PSIGN_RUST_SERVER</c> / <c>PSIGN_RUST_DEPGRAPH</c> or <c>target/{debug,release}</c>, and
/// the managed ports next to the test assembly.
/// </summary>
internal static class RustBinaries
{
    private static readonly Lazy<string?> ServerPath = new(() => Locate("PSIGN_RUST_SERVER", "psign-server"));
    private static readonly Lazy<string?> DepGraphPath = new(() => Locate("PSIGN_RUST_DEPGRAPH", "psign-depgraph"));

    private static string? Locate(string envVar, string name)
    {
        var env = Environment.GetEnvironmentVariable(envVar);
        if (!string.IsNullOrEmpty(env) && File.Exists(env))
        {
            return env;
        }

        var exe = OperatingSystem.IsWindows() ? name + ".exe" : name;
        foreach (var profile in new[] { "debug", "release" })
        {
            var p = Path.Combine(Fixtures.RepoRoot, "target", profile, exe);
            if (File.Exists(p))
            {
                return p;
            }
        }

        return null;
    }

    /// <summary>Rust <c>psign-server</c> (skips the test when it is not built).</summary>
    public static string RequireServer()
    {
        Skip.If(ServerPath.Value is null, "Rust psign-server not built (set PSIGN_RUST_SERVER or run cargo build --features timestamp-server --bin psign-server)");
        return ServerPath.Value!;
    }

    /// <summary>Rust <c>psign-depgraph</c> (skips the test when it is not built).</summary>
    public static string RequireDepGraph()
    {
        Skip.If(DepGraphPath.Value is null, "Rust psign-depgraph not built (set PSIGN_RUST_DEPGRAPH or run cargo build -p psign --bin psign-depgraph)");
        return DepGraphPath.Value!;
    }

    /// <summary>The managed <c>psign-server</c> apphost (or dll) copied next to the tests, or <c>PSIGN_MANAGED_SERVER</c>.</summary>
    public static string ManagedServer => Managed("PSIGN_MANAGED_SERVER", "psign-server");

    /// <summary>The managed <c>psign-depgraph</c> apphost (or dll) copied next to the tests, or <c>PSIGN_MANAGED_DEPGRAPH</c>.</summary>
    public static string ManagedDepGraph => Managed("PSIGN_MANAGED_DEPGRAPH", "psign-depgraph");

    private static string Managed(string envVar, string name)
    {
        // An external build (for example a NativeAOT publish) overrides the copy next to the tests.
        if (Environment.GetEnvironmentVariable(envVar) is { Length: > 0 } external && File.Exists(external))
        {
            return external;
        }

        var apphost = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? name + ".exe" : name);
        return File.Exists(apphost) ? apphost : Path.Combine(AppContext.BaseDirectory, name + ".dll");
    }

    /// <summary>Process start info for an executable or a framework-dependent <c>.dll</c>.</summary>
    public static ProcessStartInfo StartInfo(string path, IEnumerable<string> args, string? workingDirectory = null)
    {
        ProcessStartInfo psi;
        if (path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            psi = new ProcessStartInfo("dotnet");
            psi.ArgumentList.Add(path);
        }
        else
        {
            psi = new ProcessStartInfo(path);
        }

        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.RedirectStandardInput = true;
        psi.UseShellExecute = false;
        psi.StandardOutputEncoding = Encoding.UTF8;
        psi.StandardErrorEncoding = Encoding.UTF8;
        if (workingDirectory is not null)
        {
            psi.WorkingDirectory = workingDirectory;
        }

        return psi;
    }

    /// <summary>Run to completion; returns exit code and both streams.</summary>
    public static (int ExitCode, string Stdout, string Stderr) Run(string path, IEnumerable<string> args, string? workingDirectory = null, int timeoutMs = 120_000)
    {
        using var p = Process.Start(StartInfo(path, args, workingDirectory))!;
        p.StandardInput.Close();
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutMs))
        {
            p.Kill(entireProcessTree: true);
            throw new TimeoutException($"{path} {string.Join(' ', args)} did not exit");
        }

        p.WaitForExit();
        return (p.ExitCode, stdout.Result, stderr.Result);
    }

    /// <summary>The clap binary name of an executable (<c>argv[0]</c> file name).</summary>
    public static string BinName(string path) =>
        path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? Path.GetFileNameWithoutExtension(path) : Path.GetFileName(path);
}

/// <summary>A running psign-server process (Rust or managed) with its startup lines and base URL.</summary>
internal sealed class ServerProcess : IDisposable
{
    private static readonly Regex ListenRegex = new(@"listening on http://(?<host>[^/\s]+)/", RegexOptions.CultureInvariant);
    private readonly Process _process;
    private readonly Task<string> _stderr;
    private readonly StringBuilder _stdoutRest = new();
    private Task? _stdoutPump;

    private ServerProcess(Process process, List<string> lines, Task<string> stderr)
    {
        _process = process;
        Lines = lines;
        _stderr = stderr;
        var m = ListenRegex.Match(lines[0]);
        Assert.True(m.Success, $"unexpected startup line: {lines[0]}");
        HostPort = m.Groups["host"].Value;
        Port = int.Parse(HostPort[(HostPort.LastIndexOf(':') + 1)..], System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Startup lines printed before the accept loop.</summary>
    public List<string> Lines { get; }

    /// <summary><c>127.0.0.1:port</c>.</summary>
    public string HostPort { get; }

    public int Port { get; }

    public string BaseUrl => $"http://{HostPort}/";

    /// <summary>Start a server and wait for <paramref name="startupLines"/> stdout lines.</summary>
    public static ServerProcess Start(string exe, int startupLines, params string[] args)
    {
        var p = Process.Start(RustBinaries.StartInfo(exe, args))!;
        p.StandardInput.Close();
        var stderr = p.StandardError.ReadToEndAsync();
        var lines = new List<string>();
        var readTask = Task.Run(() =>
        {
            while (lines.Count < startupLines)
            {
                var line = p.StandardOutput.ReadLine();
                if (line is null)
                {
                    break;
                }

                lines.Add(line);
            }
        });
        if (!readTask.Wait(TimeSpan.FromSeconds(60)) || lines.Count < startupLines)
        {
            try
            {
                p.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }

            throw new InvalidOperationException($"{exe} {string.Join(' ', args)} did not start: stdout={string.Join("|", lines)} stderr={(stderr.Wait(5000) ? stderr.Result : string.Empty)}");
        }

        var server = new ServerProcess(p, lines, stderr);
        server._stdoutPump = Task.Run(() =>
        {
            string? l;
            while ((l = p.StandardOutput.ReadLine()) is not null)
            {
                lock (server._stdoutRest)
                {
                    server._stdoutRest.Append(l).Append('\n');
                }
            }
        });
        return server;
    }

    /// <summary>Wait for the process to exit on its own (after <c>--max-requests</c>) and return exit code and stderr.</summary>
    public (int ExitCode, string Stderr) WaitForExit(int timeoutMs = 60_000)
    {
        if (!_process.WaitForExit(timeoutMs))
        {
            _process.Kill(entireProcessTree: true);
            throw new TimeoutException("server did not exit after --max-requests");
        }

        _process.WaitForExit();
        _stdoutPump?.Wait(5000);
        return (_process.ExitCode, _stderr.Result);
    }

    public void Dispose()
    {
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(10_000);
            }
        }
        catch (InvalidOperationException)
        {
        }

        _process.Dispose();
    }
}

/// <summary>Raw HTTP/1.1 exchange helpers over loopback (no HttpClient normalization).</summary>
internal static class RawHttp
{
    /// <summary>Send <paramref name="request"/> and read until the server closes; empty when it closes or resets without a response.</summary>
    public static byte[] Exchange(int port, byte[] request)
    {
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, port);
        client.ReceiveTimeout = 60_000;
        using var stream = client.GetStream();
        try
        {
            stream.Write(request);
            stream.Flush();
            client.Client.Shutdown(SocketShutdown.Send);
        }
        catch (IOException)
        {
        }

        using var ms = new MemoryStream();
        var buf = new byte[8192];
        try
        {
            int n;
            while ((n = stream.Read(buf, 0, buf.Length)) > 0)
            {
                ms.Write(buf, 0, n);
            }
        }
        catch (IOException)
        {
            // Connection reset after the server dropped the stream without responding.
        }

        return ms.ToArray();
    }

    public static byte[] Request(string method, string target, byte[]? body = null, params (string Name, string Value)[] headers)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(target).Append(" HTTP/1.1\r\nHost: 127.0.0.1\r\n");
        foreach (var (n, v) in headers)
        {
            sb.Append(n).Append(": ").Append(v).Append("\r\n");
        }

        if (body is not null)
        {
            sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");
        }

        sb.Append("\r\n");
        var head = Encoding.UTF8.GetBytes(sb.ToString());
        return body is null ? head : [.. head, .. body];
    }

    public static byte[] JsonRequest(string method, string target, string json, params (string Name, string Value)[] headers) =>
        Request(method, target, Encoding.UTF8.GetBytes(json), [("Content-Type", "application/json"), .. headers]);

    /// <summary>Split a raw response into head (status line + headers, as text) and body.</summary>
    public static (string Head, byte[] Body) Split(byte[] response)
    {
        for (int i = 0; i + 4 <= response.Length; i++)
        {
            if (response[i] == '\r' && response[i + 1] == '\n' && response[i + 2] == '\r' && response[i + 3] == '\n')
            {
                return (Encoding.ASCII.GetString(response, 0, i + 4), response[(i + 4)..]);
            }
        }

        return (Encoding.ASCII.GetString(response), []);
    }

    /// <summary>Replace a server's own <c>host:port</c> with a placeholder so two servers' outputs compare equal.</summary>
    public static string NormalizePort(string text, ServerProcess server) => text.Replace(server.HostPort, "127.0.0.1:PORT", StringComparison.Ordinal);
}

/// <summary>
/// Structural DER comparison for outputs that embed fresh RSA keys: every TLV must have the same tag and the same
/// length, constructed values recurse, and primitive values must be byte-identical except BIT STRINGs (public keys and
/// signatures), UTC / Generalized times of certificate validity, 20 / 32-byte OCTET STRING key identifiers / hashes,
/// 256-byte OCTET STRING RSA signatures, and the 20-byte <c>[0]</c> AuthorityKeyIdentifier key identifier.
/// OCTET STRINGs holding DER (extension values, encapsulated content) are compared recursively.
/// </summary>
internal static class DerShape
{
    public static void AssertSame(byte[] expected, byte[] actual, string what)
    {
        var diffs = new List<string>();
        Compare(expected, actual, what, diffs, allowTimeDifference: true);
        Assert.True(diffs.Count == 0, $"{what}: DER shape differs:\n" + string.Join("\n", diffs.Take(20)));
    }

    private static List<(byte Tag, byte[] Content)>? Elements(byte[] data)
    {
        var list = new List<(byte, byte[])>();
        int pos = 0;
        while (pos < data.Length)
        {
            var t = Der.TlvAt(data, pos, data.Length);
            if (t is null)
            {
                return null;
            }

            list.Add((t.Value.Tag, t.Value.Value(data).ToArray()));
            pos = t.Value.End;
        }

        return list;
    }

    private static void Compare(byte[] a, byte[] b, string path, List<string> diffs, bool allowTimeDifference)
    {
        var ea = Elements(a);
        var eb = Elements(b);
        if (ea is null || eb is null)
        {
            if (!a.AsSpan().SequenceEqual(b))
            {
                diffs.Add($"{path}: unparsable content differs ({Hex(a)} vs {Hex(b)})");
            }

            return;
        }

        if (ea.Count != eb.Count)
        {
            diffs.Add($"{path}: element count {ea.Count} vs {eb.Count}");
            return;
        }

        for (int i = 0; i < ea.Count; i++)
        {
            var (ta, ca) = ea[i];
            var (tb, cb) = eb[i];
            var p = $"{path}/{i}[{ta:x2}]";
            if (ta != tb)
            {
                diffs.Add($"{p}: tag {ta:x2} vs {tb:x2}");
                continue;
            }

            if (ca.Length != cb.Length)
            {
                diffs.Add($"{p}: length {ca.Length} vs {cb.Length}");
                continue;
            }

            if ((ta & 0x20) != 0)
            {
                Compare(ca, cb, p, diffs, allowTimeDifference);
                continue;
            }

            if (ca.AsSpan().SequenceEqual(cb))
            {
                continue;
            }

            switch (ta)
            {
                case 0x03:
                    continue;
                case 0x17 or 0x18 when allowTimeDifference:
                    continue;
                case 0x04:
                {
                    // Key identifiers / certificate hashes, and RSA-2048 SignerInfo signatures, are random per run.
                    bool opaqueLength = ca.Length is 20 or 32 or 256;
                    if (Elements(ca) is { Count: > 0 } && Elements(cb) is { Count: > 0 })
                    {
                        // Random bytes occasionally parse as DER too (for example a key identifier starting 5e 12 ...),
                        // so a structural mismatch inside an opaque-length value is not a difference.
                        var inner = new List<string>();
                        Compare(ca, cb, p, inner, allowTimeDifference);
                        if (inner.Count > 0 && !opaqueLength)
                        {
                            diffs.AddRange(inner);
                        }

                        continue;
                    }

                    if (opaqueLength)
                    {
                        continue;
                    }

                    break;
                }
                case 0x80 when ca.Length == 20:
                    // AuthorityKeyIdentifier.keyIdentifier [0] IMPLICIT.
                    continue;
            }

            diffs.Add($"{p}: value {Hex(ca)} vs {Hex(cb)}");
        }
    }

    private static string Hex(byte[] b) => Devolutions.Psign.Core.Hex.Lower(b.Length > 48 ? b[..48] : b) + (b.Length > 48 ? "..." : string.Empty);
}
