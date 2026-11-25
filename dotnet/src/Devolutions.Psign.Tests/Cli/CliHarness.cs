using Devolutions.Psign.Cli;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.Portable;
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

    private static IReadOnlyDictionary<string, string?> NoEnv => RustTool.NoEnv;

    /// <summary>
    /// Optional external managed <c>psign-tool</c> (for example a NativeAOT publish) set with <c>PSIGN_MANAGED_TOOL</c>;
    /// when set, <see cref="RunManaged(IReadOnlyDictionary{string, string?}, string[])"/> runs it out of process instead
    /// of calling the CLI in-process.
    /// </summary>
    private static readonly string? ExternalManagedTool =
        Environment.GetEnvironmentVariable("PSIGN_MANAGED_TOOL") is { Length: > 0 } tool && File.Exists(tool) ? tool : null;

    /// <summary>
    /// Skip a test that injects in-process hooks (for example a mock HTTP handler) when the managed CLI runs out of
    /// process through <c>PSIGN_MANAGED_TOOL</c>.
    /// </summary>
    public static void RequireInProcess() =>
        Skip.If(ExternalManagedTool is not null, "injects in-process hooks; PSIGN_MANAGED_TOOL runs the managed CLI out of process");

    /// <summary>Run the managed <c>psign-tool</c> in-process (or <c>PSIGN_MANAGED_TOOL</c> out of process).</summary>
    public static CliResult RunManaged(params string[] args) => RunManaged(NoEnv, args);

    /// <summary>Scope a signing transport override to serialized in-process CLI calls.</summary>
    public static T WithSigningHttpHandler<T>(HttpMessageHandler handler, Func<T> action)
    {
        RequireInProcess();
        lock (Gate)
        {
            var previous = SigningCommands.HttpHandlerFactory;
            SigningCommands.HttpHandlerFactory = () => handler;
            try
            {
                return action();
            }
            finally
            {
                SigningCommands.HttpHandlerFactory = previous;
            }
        }
    }

    /// <summary>
    /// Run the managed <c>psign-tool</c> in-process with environment overrides (<c>null</c> removes a variable). The
    /// overrides are applied process-wide for the duration of the run, serialized with every other managed run.
    /// </summary>
    public static CliResult RunManaged(IReadOnlyDictionary<string, string?> env, params string[] args)
    {
        if (ExternalManagedTool is not null)
        {
            var (exitCode, stdout, stderr) = RustTool.RunProcessBytes(ExternalManagedTool, env, args);
            return new CliResult(exitCode, stdout, stderr);
        }

        lock (Gate)
        {
            var saved = env.Keys.ToDictionary(k => k, Environment.GetEnvironmentVariable);
            try
            {
                foreach (var (k, v) in env)
                {
                    Environment.SetEnvironmentVariable(k, v);
                }

                using var capture = Output.Capture();
                int code = PsignTool.Run(args);
                if (!OperatingSystem.IsWindows())
                {
                    // Unix truncates process exit statuses to 8 bits (e.g. AzureSignTool HRESULT codes).
                    code &= 0xFF;
                }

                return new CliResult(code, capture.StdoutBytes, capture.Stderr);
            }
            finally
            {
                foreach (var (k, v) in saved)
                {
                    Environment.SetEnvironmentVariable(k, v);
                }
            }
        }
    }

    /// <summary>Run the Rust <c>psign-tool</c> (skips the test when unavailable).</summary>
    public static CliResult RunRust(params string[] args) => RunRust(NoEnv, args);

    /// <summary>Run the Rust <c>psign-tool</c> with environment overrides (<c>null</c> removes a variable).</summary>
    public static CliResult RunRust(IReadOnlyDictionary<string, string?> env, params string[] args)
    {
        var (code, stdout, stderr) = RustTool.RunBytes(env, args);
        return new CliResult(code, stdout, stderr);
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
