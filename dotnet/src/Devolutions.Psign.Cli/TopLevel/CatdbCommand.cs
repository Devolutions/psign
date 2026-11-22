using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>
/// <c>psign-tool catdb</c> (Rust <c>CatdbArgs</c>): parses the native arguments; the portable backend rejects it because
/// catalog database operations require Win32 (Rust <c>execute_portable</c>).
/// </summary>
internal static class CatdbCommand
{
    public static void Register(CommandSpec root)
    {
        root.Sub("catdb", "Add or remove catalog files in a catalog database (native catdb).", c =>
        {
            c.Flag("default-database", "Operate on the default catalog database instead of the driver database (native /d).").Alias("d");
            c.Value("database-guid", null, "Operate on the catalog database identified by this GUID (native /g).").Alias("g");
            c.Flag("remove", "Remove catalogs from the database (native /r).").Alias("r");
            c.Flag("unique-name", "Generate unique catalog names when adding (native /u).").Alias("u");
            c.Positionals.Add(new PositionalSpec("catalogs", required: false, multiple: true) { ValueName = "CATALOGS", Help = "Catalog files to add or remove." });
            c.Handler = _ => throw new PsignException(
                "--mode portable catdb is unsupported because catalog database operations require Win32");
        });
    }
}
