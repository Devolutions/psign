using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.Portable;

namespace Devolutions.Psign.Cli;

internal static class Program
{
    private static int Main(string[] args) => PsignTool.Run(args);
}

/// <summary>Managed <c>psign-tool</c> entry points.</summary>
public static class PsignTool
{
    public const string BinName = "psign-tool";

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
            c.Handler = p => RunPortable(p.PosAll("args").Count == 0 ? ["--help"] : p.PosAll("args"));
        });

        root.Sub("remove", "Remove embedded signature data from a PE file (native remove).", c =>
        {
            c.Flag("strip-signature", "Remove signature(s) entirely (native /s).").Alias("s");
            c.Flag("strip-chain-except-signer", "Remove all certificates except the signer from the embedded signature (native /c).").Alias("c");
            c.Flag("strip-unauthenticated-attributes", "Remove unauthenticated attributes (native /u).").Alias("u");
            c.Positionals.Add(new PositionalSpec("files", required: true, multiple: true) { ValueName = "FILES" });
            c.Handler = p =>
            {
                RequirePortableMode(p);
                bool quiet = p.Flag("quiet");
                var text = Devolutions.Psign.Signing.Remove.PortableRemove.RemoveCommand(
                    p.PosAll("files"),
                    p.Flag("strip-signature"),
                    p.Flag("strip-chain-except-signer"),
                    p.Flag("strip-unauthenticated-attributes"),
                    quiet);
                Output.Write(text);
                return 0;
            };
        });

        return root;
    }

    /// <summary>The managed tool only implements the portable backend.</summary>
    internal static void RequirePortableMode(ParsedCommand p)
    {
        var mode = p.Value("mode") ?? Environment.GetEnvironmentVariable("PSIGN_TOOL_MODE");
        if (mode is not null && mode.Trim().Equals("windows", StringComparison.OrdinalIgnoreCase))
        {
            throw new Devolutions.Psign.Core.PsignException(
                "--mode windows requires the native psign-tool (WinVerifyTrust, SignerSignEx3, registered CryptSIP); the managed psign-tool implements the portable backend only");
        }
    }
}
