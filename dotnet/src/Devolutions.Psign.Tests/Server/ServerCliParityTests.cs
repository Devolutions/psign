using Xunit;

namespace Devolutions.Psign.Tests.Server;

/// <summary>Rust <c>psign-server</c> vs managed <c>psign-server</c>: clap help / version / error output and exit codes.</summary>
public sealed class ServerCliParityTests
{
    public static TheoryData<string[]> ArgSets() => new()
    {
        Array.Empty<string>(),
        new[] { "--help" },
        new[] { "-h" },
        new[] { "-V" },
        new[] { "--version" },
        new[] { "--version=1" },
        new[] { "--help=x" },
        new[] { "-Vh" },
        new[] { "-hV" },
        new[] { "-x" },
        new[] { "--hlp" },
        new[] { "--foo" },
        new[] { "bogus" },
        new[] { "timestamp" },
        new[] { "server" },
        new[] { "help" },
        new[] { "help", "help" },
        new[] { "help", "pki-server" },
        new[] { "help", "timestamp-server" },
        new[] { "help", "artifact-signing-server" },
        new[] { "help", "azure-key-vault-server" },
        new[] { "help", "bogus" },
        new[] { "help", "help", "help" },
        new[] { "help", "pki-server", "extra" },
        new[] { "help", "--help" },
        new[] { "help", "-h" },
        new[] { "timestamp-server", "--help" },
        new[] { "timestamp-server", "-h" },
        new[] { "pki-server", "--help" },
        new[] { "pki-server", "-h" },
        new[] { "pki-server", "-hx" },
        new[] { "azure-key-vault-server", "--help" },
        new[] { "azure-key-vault-server", "-h" },
        new[] { "artifact-signing-server", "--help" },
        new[] { "artifact-signing-server", "-h" },
        new[] { "pki-server", "--listen", "a", "--listen", "b" },
        new[] { "pki-server", "--crl-revoke-leaf", "--crl-revoke-leaf" },
        new[] { "pki-server", "--crl-revoke-leaf=yes" },
        new[] { "pki-server", "--listn", "x" },
        new[] { "pki-server", "--leaf-cert" },
        new[] { "pki-server", "--crl" },
        new[] { "timestamp-server", "--status", "grant" },
        new[] { "timestamp-server", "--status", "nope" },
        new[] { "timestamp-server", "--response-mode", "bad-al" },
        new[] { "artifact-signing-server", "--response-mode", "poll-http" },
        new[] { "artifact-signing-server", "--expect-api" },
        new[] { "pki-server", "--ocsp-status", "bad" },
        new[] { "pki-server", "foo" },
        new[] { "pki-server", "--listen", "-x" },
        new[] { "pki-server", "--max-requests", "" },
        new[] { "pki-server", "--max-requests", "99999999999999999999" },
        new[] { "pki-server", "--max-requests", "99999999999999999999x" },
        new[] { "pki-server", "--max-requests", "x" },
        new[] { "pki-server", "--max-requests", "+" },
        new[] { "timestamp-server", "--max-requests", "-1" },
        new[] { "pki-server", "--", "foo" },
        new[] { "pki-server", "-x" },
        new[] { "pki-server", "--listen", "a", "-x" },
        new[] { "pki-server", "--bogus", "--help" },
        new[] { "pki-server", "--help", "--bogus" },
        new[] { "pki-server", "--listen", "a", "foo" },
        new[] { "pki-server", "--listen", "a", "--nope" },
        new[] { "pki-server", "--listen", "a", "--crl-revoke-leaf=x" },
        new[] { "pki-server", "--crl-revoke-leaf", "--max-requests", "1", "--listn" },
        new[] { "pki-server", "--ocsp-status", "good", "--root-cert-output", "x", "--crl-revoke-leaf", "--nope" },
        new[] { "pki-server", "--max-requests=1", "--listen=a", "--nope" },
        new[] { "pki-server", "--listen" },
        new[] { "pki-server", "--ocsp-status" },
        new[] { "artifact-signing-server", "--response-mode" },
        new[] { "pki-server", "--listen", "--nope" },
        new[] { "pki-server", "--listen", "--crl-revoke-leaf", "--nope" },
        new[] { "pki-server", "--listen", "--help" },
        new[] { "pki-server", "--listen", "--crl-revoke-leaf" },
        new[] { "pki-server", "--help=1" },
        new[] { "pki-server", "-V" },
        new[] { "azure-key-vault-server", "--version" },
        new[] { "azure-key-vault-server", "-V" },
        new[] { "timestamp-server", "--gen-time", "2024" },
        new[] { "timestamp-server", "--gen-time", "2024010203040Z5" },
        new[] { "timestamp-server", "--gen-time", "２０２４０１０２０３０４０５Z" },
        new[] { "pki-server", "--listen", "nonsense" },
        new[] { "pki-server", "--listen=" },
        new[] { "pki-server", "--listen", "127.0.0.1:x" },
        new[] { "pki-server", "--listen", "127.0.0.1:+x" },
        new[] { "pki-server", "--listen", "127.0.0.1:65536" },
    };

    [SkippableTheory]
    [MemberData(nameof(ArgSets))]
    public void CliOutputMatchesRust(string[] args)
    {
        var rust = RustBinaries.RequireServer();
        var managed = RustBinaries.ManagedServer;
        var r = RustBinaries.Run(rust, args, timeoutMs: 30_000);
        var m = RustBinaries.Run(managed, args, timeoutMs: 30_000);
        string Normalize(string s) => s.Replace(RustBinaries.BinName(rust), RustBinaries.BinName(managed), StringComparison.Ordinal);
        Assert.Equal(r.ExitCode, m.ExitCode);
        Assert.Equal(Normalize(r.Stdout), m.Stdout);
        Assert.Equal(Normalize(r.Stderr), m.Stderr);
    }

    [Fact]
    public void JaroMatchesStrsim()
    {
        Assert.Equal(0.0, Devolutions.Psign.Server.Cli.Jaro("", "abc"));
        Assert.Equal(1.0, Devolutions.Psign.Server.Cli.Jaro("", ""));
        Assert.Equal(0.944, Math.Round(Devolutions.Psign.Server.Cli.Jaro("martha", "marhta"), 3));
        Assert.Equal(0.767, Math.Round(Devolutions.Psign.Server.Cli.Jaro("dixon", "dicksonx"), 3));
    }
}
