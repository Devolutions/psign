using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Signing.CertStore;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>
/// <c>psign-tool cert-store ...</c> (port of Rust <c>CertStoreArgs</c> in <c>src/cli.rs</c> and
/// <c>cert_store::cert_store_command</c>). Runs regardless of <c>--mode</c>, like the Rust dispatcher.
/// </summary>
internal static class CertStoreCommand
{
    public static void Register(CommandSpec root)
    {
        root.Sub("cert-store", "Manage the portable psign certificate store (`~/.psign/cert-store` by default).", c =>
        {
            c.Sub("import", "Import a PEM or DER X.509 certificate into a store.", s =>
            {
                AddSelection(s);
                s.Value("key", null, "PEM-encoded unencrypted PKCS#8 private key to store as `<thumb>.key`.");
                s.Positional("cert", help: "PEM or DER X.509 certificate to import.", valueName: "CERT");
                s.Handler = p => Emit(p, new PortableCertStore().Import(Selection(p), p.Pos("cert")!, p.Value("key")).Format());
            });

            c.Sub("import-pfx", "Import a PFX/PKCS#12 certificate and private key into a store.", s =>
            {
                AddSelection(s);
                s.Value("password", null, "Password for the PFX/PKCS#12 file.").Alias("p").Req();
                s.Positional("pfx", help: "PFX/PKCS#12 file to import. The store writes `<thumb>.der` and `<thumb>.key`, not `.pfx`.", valueName: "PFX");
                s.Handler = p => Emit(p, new PortableCertStore().ImportPfx(Selection(p), p.Pos("pfx")!, p.Required("password")).Format());
            });

            c.Sub("list", "List certificates in a store.", s =>
            {
                AddSelection(s);
                s.Flag("json", "Emit machine-readable JSON.");
                s.Handler = p =>
                {
                    var report = new PortableCertStore().List(Selection(p));
                    return Emit(p, p.Flag("json") ? report.ToJson() : report.Format());
                };
            });

            c.Sub("print", "Print details for one certificate by SHA-1 thumbprint.", s =>
            {
                AddSelection(s);
                s.Value("sha1", null, "SHA-1 thumbprint of the certificate to print.").Req();
                s.Flag("json", "Emit machine-readable JSON.");
                s.Handler = p =>
                {
                    var details = new PortableCertStore().Print(Selection(p), p.Required("sha1"));
                    return Emit(p, p.Flag("json") ? details.ToJson() : details.Format());
                };
            });

            c.Sub("export", "Export one certificate as DER.", s =>
            {
                AddSelection(s);
                s.Value("sha1", null, "SHA-1 thumbprint of the certificate to export.").Req();
                s.Value("out", null, "Output DER certificate path.").Req();
                s.Flag("with-key", "Also export the matching `<thumb>.key` private key.");
                s.Value("key-out", null, "Output private key path when `--with-key` is set.").Requiring("with-key");
                s.Flag("force", "Replace the output file if it already exists.");
                s.Handler = p => Emit(p, new PortableCertStore().Export(
                    Selection(p),
                    p.Required("sha1"),
                    p.Required("out"),
                    p.Flag("with-key"),
                    p.Value("key-out"),
                    p.Flag("force")));
            });

            c.Sub("remove", "Remove one certificate from a store.", s =>
            {
                AddSelection(s);
                s.Value("sha1", null, "SHA-1 thumbprint of the certificate to remove.").Req();
                s.Handler = p => Emit(p, new PortableCertStore().Remove(Selection(p), p.Required("sha1")));
            });
        });
    }

    /// <summary>Rust <c>CertStoreSelectionArgs</c>.</summary>
    private static void AddSelection(CommandSpec s)
    {
        s.Value("cert-store-dir", null, "Certificate store base directory. Defaults to `PSIGN_CERT_STORE` or `~/.psign/cert-store`.");
        s.Flag("machine-store", "Use the LocalMachine scope under the configured cert-store directory.").Alias("sm");
        var store = s.Value("store", null, "Certificate store name (default: MY).", "MY").Alias("s");
        store.ValueName = "STORE_NAME";
    }

    private static CertStoreSelection Selection(ParsedCommand p) =>
        new(p.Value("cert-store-dir"), p.Flag("machine-store"), p.Required("store"));

    /// <summary>Rust <c>print_output</c>: stdout is suppressed by <c>--quiet</c> on success.</summary>
    private static int Emit(ParsedCommand p, string text)
    {
        if (!p.Flag("quiet"))
        {
            Output.Write(text);
        }

        return 0;
    }
}
