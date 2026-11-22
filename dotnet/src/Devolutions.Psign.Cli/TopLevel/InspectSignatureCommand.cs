using Devolutions.Psign.Cli.Framework;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>
/// <c>psign-tool inspect-signature</c> (Rust <c>InspectSignatureArgs</c> + <c>execute_portable_inspect</c>): runs
/// <c>psign-tool portable inspect-authenticode</c> in-process.
/// </summary>
internal static class InspectSignatureCommand
{
    public static void Register(CommandSpec root)
    {
        root.Sub("inspect-signature", "Inspect Authenticode PKCS#7 layers (nested 1.3.6.1.4.1.311.2.4.1, timestamp OIDs) as JSON — same portable parser as psign-tool portable inspect-authenticode.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("input", ["pe", "pkcs7"], "pe", "PE (embedded attribute PKCS#7 rows) vs raw PKCS#7 file.");
            c.Handler = p =>
            {
                PsignTool.RunPortableArgs(["inspect-authenticode", p.Pos("path")!, "--input", p.Value("input") ?? "pe"]);
                return PsignTool.PrintOutput(p, string.Empty);
            };
        });
    }
}
