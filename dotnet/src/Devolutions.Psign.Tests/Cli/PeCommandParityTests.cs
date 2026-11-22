using Xunit;

namespace Devolutions.Psign.Tests.Cli;

public class PeCommandParityTests
{
    public static IEnumerable<object[]> PeFixtures() =>
    [
        ["pe-authenticode-upstream/tiny32.signed.efi"],
        ["pe-authenticode-upstream/tiny64.signed.efi"],
        ["generated-unsigned/pe/tiny64-pe-alias.dll"],
    ];

    [SkippableTheory]
    [MemberData(nameof(PeFixtures))]
    public void DigestRangesChecksumMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        foreach (var alg in new[] { "sha1", "sha256", "sha384", "sha512" })
        {
            CliHarness.AssertSameOutput("portable", "pe-digest", path, "--algorithm", alg);
        }

        CliHarness.AssertSameOutput("portable", "pe-digest", path, "--encoding", "raw");
        CliHarness.AssertSameOutput("portable", "pe-authenticode-ranges", path);
        CliHarness.AssertSameOutput("portable", "pe-checksum", path);
        CliHarness.AssertSameStdout("portable", "verify-pe", path);
        CliHarness.AssertSameStdout("portable", "list-pe-pkcs7", path);
    }

    [SkippableTheory]
    [InlineData("pe-authenticode-upstream/tiny32.signed.efi")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi")]
    public void SignedPeInspectionMatchesRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        CliHarness.AssertSameOutput("portable", "inspect-pe-spc-indirect", path);
        CliHarness.AssertSameOutput("portable", "inspect-pe-spc-indirect", path, "--include-image-value-der-hex");
        CliHarness.AssertSameOutput("portable", "extract-pe-pkcs7", path);
        CliHarness.AssertSameOutput("portable", "pe-signer-rs256-prehash", path);
        CliHarness.AssertSameOutput("portable", "pe-signer-rs256-prehash", path, "--encoding", "raw");
    }

    [SkippableFact]
    public void AppendPkcs7MatchesRust()
    {
        using var dir = new TempDir();
        var signed = Fixtures.Path("pe-authenticode-upstream/tiny64.signed.efi");
        var pkcs7 = dir.File("sig.p7");
        File.WriteAllBytes(pkcs7, CliHarness.RunManaged("portable", "extract-pe-pkcs7", signed).StdoutBytes);
        var rustOut = dir.File("rust.efi");
        var managedOut = dir.File("managed.efi");
        Assert.Equal(0, CliHarness.RunRust("portable", "append-pe-pkcs7", "--pe", signed, "--pkcs7", pkcs7, "--output", rustOut).ExitCode);
        Assert.Equal(0, CliHarness.RunManaged("portable", "append-pe-pkcs7", "--pe", signed, "--pkcs7", pkcs7, "--output", managedOut).ExitCode);
        Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(managedOut));
        CliHarness.AssertSameOutput("portable", "list-pe-pkcs7", managedOut);
        CliHarness.AssertSameOutput("portable", "pkcs7-signer-rs256-prehash", pkcs7);
    }

    [SkippableFact]
    public void ErrorsMatchRust()
    {
        CliHarness.AssertSameStdout("portable", "verify-pe", Fixtures.Path("generated-unsigned/pe/tiny64-pe-alias.dll"));
        CliHarness.AssertSameOutput("portable", "pe-digest", Fixtures.Path("unsigned-sample.ps1"));
    }
}
