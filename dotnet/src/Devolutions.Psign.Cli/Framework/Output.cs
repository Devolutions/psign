using System.Text;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.Framework;

/// <summary>
/// Process output helpers matching Rust <c>println!</c> / <c>eprintln!</c>: UTF-8 without BOM and <c>\n</c> line endings on
/// every platform. Tests can redirect output with <see cref="Capture"/>.
/// </summary>
public static class Output
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);
    private static readonly AsyncLocal<Sink?> Current = new();

    internal sealed class Sink
    {
        public MemoryStream Stdout { get; } = new();

        public MemoryStream Stderr { get; } = new();
    }

    /// <summary>Captured output.</summary>
    public sealed class Captured : IDisposable
    {
        private readonly Sink _sink;
        private readonly Sink? _previous;

        internal Captured(Sink sink, Sink? previous)
        {
            _sink = sink;
            _previous = previous;
        }

        public byte[] StdoutBytes => _sink.Stdout.ToArray();

        public string Stdout => Utf8NoBom.GetString(_sink.Stdout.ToArray());

        public string Stderr => Utf8NoBom.GetString(_sink.Stderr.ToArray());

        public void Dispose() => Current.Value = _previous;
    }

    /// <summary>Redirect stdout/stderr into memory for the current async flow.</summary>
    public static Captured Capture()
    {
        var sink = new Sink();
        var prev = Current.Value;
        Current.Value = sink;
        return new Captured(sink, prev);
    }

    private static Stream? _stdout;
    private static Stream? _stderr;

    private static Stream StdoutStream => Current.Value?.Stdout ?? (_stdout ??= Console.OpenStandardOutput());

    private static Stream StderrStream => Current.Value?.Stderr ?? (_stderr ??= Console.OpenStandardError());

    /// <summary><c>println!</c>.</summary>
    public static void Line(string text = "")
    {
        var bytes = Utf8NoBom.GetBytes(text + "\n");
        StdoutStream.Write(bytes);
        StdoutStream.Flush();
    }

    /// <summary><c>print!</c>.</summary>
    public static void Write(string text)
    {
        var bytes = Utf8NoBom.GetBytes(text);
        StdoutStream.Write(bytes);
        StdoutStream.Flush();
    }

    /// <summary>Raw bytes to stdout.</summary>
    public static void Raw(ReadOnlySpan<byte> bytes)
    {
        StdoutStream.Write(bytes);
        StdoutStream.Flush();
    }

    /// <summary><c>eprintln!</c>.</summary>
    public static void ErrorLine(string text = "")
    {
        var bytes = Utf8NoBom.GetBytes(text + "\n");
        StderrStream.Write(bytes);
        StderrStream.Flush();
    }

    /// <summary><c>eprint!</c>.</summary>
    public static void ErrorWrite(string text)
    {
        var bytes = Utf8NoBom.GetBytes(text);
        StderrStream.Write(bytes);
        StderrStream.Flush();
    }

    /// <summary>Read a file with Rust-style error context (<c>read {path}</c>).</summary>
    public static byte[] ReadFile(string path, string? context = null)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException(context ?? $"read {path}", new PsignException(IoMessage(e)));
        }
    }

    /// <summary>Write a file with Rust-style error context (<c>write {path}</c>).</summary>
    public static void WriteFile(string path, ReadOnlySpan<byte> data, string? context = null)
    {
        try
        {
            File.WriteAllBytes(path, data.ToArray());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException(context ?? $"write {path}", new PsignException(IoMessage(e)));
        }
    }

    /// <summary>Approximate Rust <c>std::io::Error</c> display text.</summary>
    public static string IoMessage(Exception e) => IoErrorText.Message(e);

    /// <summary>Write digest output (Rust <c>write_digest_output</c>): hex line or raw bytes, to file or stdout.</summary>
    public static void Digest(string encoding, byte[] digest, string? outputPath)
    {
        if (outputPath is not null)
        {
            try
            {
                if (encoding == "raw")
                {
                    File.WriteAllBytes(outputPath, digest);
                }
                else
                {
                    File.WriteAllBytes(outputPath, Utf8NoBom.GetBytes(Hex.Lower(digest) + "\n"));
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new PsignException($"create {outputPath}", new PsignException(IoMessage(e)));
            }

            return;
        }

        if (encoding == "raw")
        {
            Raw(digest);
        }
        else
        {
            Line(Hex.Lower(digest));
        }
    }
}
