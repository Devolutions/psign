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
        var root = BuildRoot();
        return CliRunner.Run(root, args, BinName, p => p.Flag("quiet"));
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
