using Devolutions.Psign.Cli.Framework;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>Command tree for <c>psign-tool portable ...</c> (port of <c>crates/psign-digest-cli/src/main.rs</c>).</summary>
internal static class PortableCli
{
    public static CommandSpec Build()
    {
        var portable = new CommandSpec(PsignTool.BinName, "Portable Authenticode digest, verification, trust, signing, and package helpers.");
        PeCommands.Register(portable);
        FormatCommands.Register(portable);
        ScriptCommands.Register(portable);
        MsixCommands.Register(portable);
        return portable;
    }
}
