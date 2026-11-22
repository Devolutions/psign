using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.Portable;
using Devolutions.Psign.Cli.TopLevel;

namespace Devolutions.Psign.Cli;

internal static class Program
{
    private static int Main(string[] args) => PsignTool.Run(args);
}

/// <summary>Managed <c>psign-tool</c> entry points.</summary>
public static class PsignTool
{
    public const string BinName = "psign-tool";

    /// <summary>Top-level commands that bypass backend mode resolution (Rust <c>execute</c>).</summary>
    private static readonly HashSet<string> ModeIndependentCommands = new(StringComparer.Ordinal) { "portable", "cert-store", "code" };

    /// <summary>Run the top-level CLI with <paramref name="args"/> (argv without the executable).</summary>
    public static int Run(IReadOnlyList<string> args)
    {
        if (args.Count == 0)
        {
            return CliRunner.Run(BuildRoot(), args, BinName);
        }

        List<List<string>> invocations;
        try
        {
            invocations = ResponseArgv.ExpandInvocations(args);
        }
        catch (Devolutions.Psign.Core.PsignException e)
        {
            Output.ErrorLine(e.FullMessage);
            return 1;
        }

        int batchExit = 0;
        foreach (var invocation in invocations)
        {
            var argv = NativeArgv.Normalize(invocation);
            int code = CliRunner.Run(BuildRoot(), argv, BinName, p => p.Flag("quiet"));
            if (code == 2 && invocations.Count == 1)
            {
                return 2;
            }

            batchExit = ResponseArgv.CombineBatchExitCodes(batchExit, code);
        }

        return batchExit;
    }

    /// <summary>Run the <c>psign-tool portable ...</c> command parser directly.</summary>
    public static int RunPortable(IReadOnlyList<string> args) => CliRunner.Run(PortableCli.Build(), args, BinName);

    /// <summary>
    /// Rust <c>run_portable_args</c>: run the portable parser in-process (empty argv shows help). Handler errors propagate
    /// to the caller (the outer runner prints them unless <c>--quiet</c>); help and usage errors print and surface as
    /// <see cref="CliExitException"/> like the Rust process exit.
    /// </summary>
    internal static void RunPortableArgs(IReadOnlyList<string> args)
    {
        var parsed = CliRunner.ParseOrExit(PortableCli.Build(), args.Count == 0 ? ["--help"] : args, BinName);
        var leaf = parsed.Leaf;
        var handler = leaf.Spec.Handler ?? throw new InvalidOperationException($"no handler for {leaf.Path}");
        int code = handler(leaf);
        if (code != 0)
        {
            throw new CliExitException(code);
        }
    }

    /// <summary>
    /// Rust <c>print_output</c>: <c>--debug</c> reports the exit code and stdout length on stderr; stdout is suppressed by
    /// <c>--quiet</c> unless the exit code is non-zero.
    /// </summary>
    internal static int PrintOutput(ParsedCommand p, string stdout, int exitCode = 0)
    {
        if (p.Flag("debug"))
        {
            Output.ErrorLine($"[debug] exit_code={exitCode} stdout_len={System.Text.Encoding.UTF8.GetByteCount(stdout)}");
        }

        if (!p.Flag("quiet") || exitCode != 0)
        {
            Output.Write(stdout);
        }

        return exitCode;
    }

    internal static CommandSpec BuildRoot()
    {
        var root = new CommandSpec(BinName, "Pure C# reimplementation of the psign portable signtool surface (Authenticode sign / verify / timestamp)");
        root.Flag("quiet", "Quiet mode (native /q): suppress stdout on success.", 'q').MakeGlobal();
        root.Flag("verbose", "Verbose mode (native /v).", 'v').MakeGlobal();
        root.Flag("debug", "Debug diagnostics (native /debug).").MakeGlobal();
        root.Choice("mode", ["auto", "windows", "portable"], null, "Backend mode. The managed tool always runs the portable backend.").MakeGlobal();

        root.Sub("portable", "Portable-only diagnostics and helpers (no Win32 APIs).", c =>
        {
            c.DisableHelpFlag = true;
            c.Positionals.Add(new PositionalSpec("args", required: false, multiple: true) { Trailing = true });
            c.Handler = p =>
            {
                RunPortableArgs(p.PosAll("args"));
                return PrintOutput(p, string.Empty);
            };
        });

        Devolutions.Psign.Cli.TopLevel.CertStoreCommand.Register(root);
        Devolutions.Psign.Cli.TopLevel.ArtifactSigningSubmitCommand.Register(root);
        TopLevel.CodeCommand.Register(root);
        VerifyCommand.Register(root);
        SignCommand.Register(root);
        TimestampCommand.Register(root);
        CatdbCommand.Register(root);

        root.Sub("remove", "Remove embedded signature data from a PE file (native remove).", c =>
        {
            c.Flag("strip-signature", "Remove signature(s) entirely (native /s).").Alias("s");
            c.Flag("strip-chain-except-signer", "Remove all certificates except the signer from the embedded signature (native /c).").Alias("c");
            c.Flag("strip-unauthenticated-attributes", "Remove unauthenticated attributes (native /u).").Alias("u");
            c.Positionals.Add(new PositionalSpec("files", required: true, multiple: true) { ValueName = "FILES" });
            c.Handler = p =>
            {
                bool quiet = p.Flag("quiet");
                var text = Devolutions.Psign.Signing.Remove.PortableRemove.RemoveCommand(
                    p.PosAll("files"),
                    p.Flag("strip-signature"),
                    p.Flag("strip-chain-except-signer"),
                    p.Flag("strip-unauthenticated-attributes"),
                    quiet);
                return PrintOutput(p, text);
            };
        });

        InspectSignatureCommand.Register(root);
        RdpCommand.Register(root);

        // Rust `execute`: every command except portable / cert-store / code resolves the backend mode first. Register
        // new top-level commands above this loop.
        foreach (var command in root.Subcommands)
        {
            if (ModeIndependentCommands.Contains(command.Name) || command.Handler is not { } handler)
            {
                continue;
            }

            command.Handler = p =>
            {
                RequirePortableMode(p);
                return handler(p);
            };
        }

        return root;
    }

    /// <summary>
    /// Rust <c>resolved_tool_mode</c> + <c>effective_tool_mode</c>: <c>--mode</c>, else <c>PSIGN_TOOL_MODE</c>
    /// (<c>auto</c> / <c>windows</c> / <c>win32</c> / <c>portable</c>, case-insensitive). The managed tool only implements the
    /// portable backend, so <c>auto</c> resolves to portable on every OS and <c>windows</c> is rejected.
    /// </summary>
    internal static void RequirePortableMode(ParsedCommand p)
    {
        if (ResolveToolMode(p.Value("mode"), Environment.GetEnvironmentVariable("PSIGN_TOOL_MODE")) == "windows")
        {
            throw new Devolutions.Psign.Core.PsignException(
                "--mode windows requires the native psign-tool (WinVerifyTrust, SignerSignEx3, registered CryptSIP); the managed psign-tool implements the portable backend only");
        }
    }

    /// <summary>Resolve the backend mode to <c>auto</c>, <c>windows</c>, or <c>portable</c> (Rust <c>parse_tool_mode</c>).</summary>
    internal static string ResolveToolMode(string? flag, string? env)
    {
        if (flag is not null)
        {
            return flag;
        }

        if (env is null)
        {
            return "auto";
        }

        var t = Devolutions.Psign.Core.Text.RustText.ToAsciiLowercase(env.Trim());
        if (t is "auto" or "windows" or "portable")
        {
            return t;
        }

        if (t == "win32")
        {
            return "windows";
        }

        throw new Devolutions.Psign.Core.PsignException("PSIGN_TOOL_MODE must be one of: auto, windows, portable");
    }
}
