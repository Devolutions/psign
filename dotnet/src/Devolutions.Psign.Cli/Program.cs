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
            c.Handler = p => RunPortable(p.PosAll("args"));
        });

        return root;
    }
}
