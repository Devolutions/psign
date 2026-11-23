using Xunit;

namespace Devolutions.Psign.Tests.Cli;

public class ScriptCommandParityTests
{
    public static IEnumerable<object[]> ScriptFixtures() =>
        Directory.GetDirectories(Fixtures.Path("generated-signed/scripts"), "*", SearchOption.AllDirectories)
            .SelectMany(Directory.GetFiles)
            .Concat(Directory.GetDirectories(Fixtures.Path("generated-unsigned/scripts"), "*", SearchOption.AllDirectories).SelectMany(Directory.GetFiles).Take(20))
            .Select(f => new object[] { Path.GetRelativePath(Fixtures.Dir, f) });

    [SkippableTheory]
    [MemberData(nameof(ScriptFixtures))]
    public void VerifyScriptMatchesRust(string fixture) =>
        CliHarness.AssertSameOutput("portable", "verify-script", Fixtures.Path(fixture));

    [SkippableTheory]
    [InlineData("zip-authenticode/signed/sample.signed.zip")]
    [InlineData("zip-authenticode/unsigned/sample.zip")]
    public void VerifyZipMatchesRust(string fixture) =>
        CliHarness.AssertSameOutput("portable", "verify-zip", Fixtures.Path(fixture));

    [SkippableFact]
    public void TimestampRequestAndInspectMatchRust()
    {
        foreach (var alg in new[] { "sha1", "sha256", "sha384", "sha512" })
        {
            int len = alg switch { "sha1" => 20, "sha256" => 32, "sha384" => 48, _ => 64 };
            var hex = string.Concat(Enumerable.Repeat("ab", len));
            CliHarness.AssertSameOutput("portable", "rfc3161-timestamp-req", "--algorithm", alg, "--digest-hex", hex, "--output", "hex");
            CliHarness.AssertSameOutput("portable", "rfc3161-timestamp-req", "--algorithm", alg, "--digest-hex", hex, "--nonce", "12345", "--cert-req");
        }

        CliHarness.AssertSameOutput("portable", "rfc3161-timestamp-req", "--digest-hex", "abcd");
        CliHarness.AssertSameOutput("portable", "rfc3161-timestamp-req");
        var resp = Fixtures.Path("rfc3161/ts_resp_granted_outer_len81.der");
        CliHarness.AssertSameOutput("portable", "rfc3161-timestamp-resp-inspect", resp);
        CliHarness.AssertSameOutput("portable", "rfc3161-timestamp-resp-inspect", resp, "--expect-nonce", "7", "--expect-digest-hex", "00");
    }

    [SkippableFact]
    public void RdpSigningMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        foreach (var fixture in Directory.GetFiles(Fixtures.Path("rdp")))
        {
            var name = Path.GetFileName(fixture);
            var rustOut = dir.File("rust-" + name);
            var managedOut = dir.File("managed-" + name);
            var rust = CliHarness.RunRust("portable", "rdp", "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", rustOut, fixture);
            var managed = CliHarness.RunManaged("portable", "rdp", "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", managedOut, fixture);
            Assert.True(rust.ExitCode == managed.ExitCode, $"{name}: rust={rust.ExitCode} {rust.Stderr} managed={managed.ExitCode} {managed.Stderr}");
            Assert.Equal(rust.Stderr.Replace(rustOut, "OUT", StringComparison.Ordinal), managed.Stderr.Replace(managedOut, "OUT", StringComparison.Ordinal));
            Assert.Equal(rust.Stdout.Replace(rustOut, "OUT", StringComparison.Ordinal), managed.Stdout.Replace(managedOut, "OUT", StringComparison.Ordinal));
            if (rust.ExitCode == 0)
            {
                Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(managedOut));
            }

            CliHarness.AssertSameOutput("portable", "rdp", "--cert", signer.CertPath, "--key", signer.KeyPath, "--dry-run", fixture);
        }
    }
}
