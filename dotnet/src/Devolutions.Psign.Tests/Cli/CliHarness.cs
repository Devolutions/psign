using System.Diagnostics;
using Devolutions.Psign.Cli;
using Devolutions.Psign.Cli.Framework;
using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>Result of a CLI invocation.</summary>
internal sealed record CliResult(int ExitCode, byte[] StdoutBytes, string Stderr)
{
    public string Stdout => System.Text.Encoding.UTF8.GetString(StdoutBytes);
}

/// <summary>Runs the managed CLI in-process and the Rust CLI out-of-process for differential comparisons.</summary>
internal static class CliHarness
{
    private static readonly object Gate = new();

    /// <summary>Run the managed <c>psign-tool</c> in-process.</summary>
    public static CliResult RunManaged(params string[] args)
    {
        lock (Gate)
        {
            using var capture = Output.Capture();
            int code = PsignTool.Run(args);
            return new CliResult(code, capture.StdoutBytes, capture.Stderr);
        }
    }

    /// <summary>Run the Rust <c>psign-tool</c> (skips the test when unavailable).</summary>
    public static CliResult RunRust(params string[] args)
    {
        var psi = new ProcessStartInfo(RustTool.Require())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment["PSIGN_TOOL_MODE"] = "portable";
        using var p = Process.Start(psi)!;
        using var ms = new MemoryStream();
        var copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        copy.Wait();
        return new CliResult(p.ExitCode, ms.ToArray(), stderr);
    }

    /// <summary>Assert that both CLIs produce identical exit codes and stdout bytes.</summary>
    public static (CliResult Managed, CliResult Rust) AssertSameStdout(params string[] args)
    {
        var rust = RunRust(args);
        var managed = RunManaged(args);
        Assert.True(rust.ExitCode == managed.ExitCode, $"exit code mismatch for {string.Join(' ', args)}: rust={rust.ExitCode} managed={managed.ExitCode}\nrust stderr: {rust.Stderr}\nmanaged stderr: {managed.Stderr}");
        Assert.Equal(rust.Stdout, managed.Stdout);
        Assert.Equal(rust.StdoutBytes, managed.StdoutBytes);
        return (managed, rust);
    }

    /// <summary>Assert identical exit code, stdout, and stderr.</summary>
    public static void AssertSameOutput(params string[] args)
    {
        var (managed, rust) = AssertSameStdout(args);
        Assert.Equal(Normalize(rust.Stderr), Normalize(managed.Stderr));
    }

    private static string Normalize(string s) => s.Replace("\r\n", "\n", StringComparison.Ordinal);
}
