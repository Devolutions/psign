using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>
/// <c>psign-tool rdp</c> (Rust <c>RdpArgs</c>): parses the native rdpsign-style arguments; the portable backend points to
/// <c>psign-tool portable rdp ...</c> (Rust <c>execute_portable</c>).
/// </summary>
internal static class RdpCommand
{
    public static void Register(CommandSpec root)
    {
        root.Sub("rdp", "Sign Remote Desktop Protocol .rdp files (native rdpsign.exe semantics).", c =>
        {
            var sha1 = new OptionSpec("cert-sha1", "sha1", OptionKind.Value) { ValueName = "CERT_SHA1", Help = "SHA1 thumbprint of the RDP signing certificate (legacy rdpsign mode)." };
            sha1.Conflicts("cert-sha256");
            c.Options.Add(sha1);
            var sha256 = new OptionSpec("cert-sha256", "sha256", OptionKind.Value) { ValueName = "CERT_SHA256", Help = "SHA256 thumbprint of the RDP signing certificate." };
            sha256.Conflicts("cert-sha1");
            c.Options.Add(sha256);
            c.RequiredOneOf.Add(["cert-sha1", "cert-sha256"]);
            var dryRun = new OptionSpec("dry-run", "dry-run", OptionKind.Flag) { Short = 'l', Help = "Test signing without replacing input files (native /l)." };
            dryRun.Alias("l");
            c.Options.Add(dryRun);
            c.Positionals.Add(new PositionalSpec("files", required: true, multiple: true) { ValueName = "FILES", Help = ".rdp file(s) to sign." });
            c.Handler = _ => throw new PsignException("--mode portable rdp is available as `psign-tool portable rdp ...`");
        });
    }
}
