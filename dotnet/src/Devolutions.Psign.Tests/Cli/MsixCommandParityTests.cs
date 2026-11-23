using Xunit;

namespace Devolutions.Psign.Tests.Cli;

public class MsixCommandParityTests
{
    public static IEnumerable<object[]> Packages() =>
        new[] { "generated-signed/msix", "generated-unsigned/msix", "msix-edge-cases/signed", "msix-edge-cases/unsigned", "generated-unsigned/msix-encrypted-negative" }
            .SelectMany(d => Directory.GetFiles(Fixtures.Path(d)))
            .Where(f => !f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) && !f.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
            .Select(f => new object[] { Path.GetRelativePath(Fixtures.Dir, f) });

    [SkippableTheory]
    [MemberData(nameof(Packages))]
    public void VerifyAndManifestInfoMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        CliHarness.AssertSameStdout("portable", "verify-msix", path);
        CliHarness.AssertSameOutput("portable", "msix-manifest-info", path);
    }

    [SkippableTheory]
    [MemberData(nameof(Packages))]
    public void SetPublisherMatchesRust(string fixture)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var path = Fixtures.Path(fixture);
        var ext = Path.GetExtension(path);
        var rustOut = dir.File("rust" + ext);
        var managedOut = dir.File("managed" + ext);
        var rust = CliHarness.RunRust("portable", "msix-set-publisher", path, "--publisher", "CN=Parity Test", "--output", rustOut);
        var managed = CliHarness.RunManaged("portable", "msix-set-publisher", path, "--publisher", "CN=Parity Test", "--output", managedOut);
        Assert.Equal(rust.ExitCode, managed.ExitCode);
        if (rust.ExitCode == 0)
        {
            Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(managedOut));
        }
    }
}
