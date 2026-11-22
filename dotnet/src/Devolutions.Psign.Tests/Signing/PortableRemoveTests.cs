using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Signing.Remove;
using Devolutions.Psign.Tests.Cli;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

public class PortableRemoveTests
{
    [Fact]
    public void RemovesScriptSignatureAndItsSurroundingNewline()
    {
        const string signed = "Write-Output test\r\n# SIG # Begin signature block\r\n# YWJj\r\n# SIG # End signature block\r\n";
        Assert.True(PortableRemove.IsAuthenticodeSignatureBlock("\r\n# YWJj\r\n", "ps1"));
        Assert.Equal("Write-Output test", PortableRemove.RemoveScriptSignatureBlock(signed, "ps1"));
    }

    [Fact]
    public void RemovesXmlAndMofSignatureBlocks()
    {
        Assert.Equal("<root />", PortableRemove.RemoveScriptSignatureBlock(
            "<root />\n<!-- SIG # Begin signature block -->\n<!-- YWJj -->\n<!-- SIG # End signature block -->\n", "ps1xml"));
        Assert.Equal("instance of x {}", PortableRemove.RemoveScriptSignatureBlock(
            "instance of x {}\n/* SIG # Begin signature block */\n/* YWJj */\n/* SIG # End signature block */\n", "mof"));
    }

    [Fact]
    public void DoesNotRemoveNonterminalOrNonCmsMarkerBlocks()
    {
        Assert.Null(PortableRemove.RemoveScriptSignatureBlock(
            "# SIG # Begin signature block\nnot-a-signature\n# SIG # End signature block\nWrite-Output test\n", "ps1"));
    }

    [Fact]
    public void CliStripsPowerShellSignatureBlock()
    {
        using var dir = new TempDir();
        var path = dir.File("module.psd1");
        File.WriteAllText(path, "@{ RootModule = 'module.psm1' }\r\n# SIG # Begin signature block\r\n# YWJj\r\n# SIG # End signature block\r\n");
        var r = CliHarness.RunManaged("--mode", "portable", "remove", "--strip-signature", path);
        Assert.Equal(0, r.ExitCode);
        Assert.Contains("Removed embedded Authenticode data", r.Stdout);
        Assert.Equal("@{ RootModule = 'module.psm1' }", File.ReadAllText(path));
    }

    [Fact]
    public void CliStripsPeSignature()
    {
        using var dir = new TempDir();
        var path = dir.File("signed.exe");
        var unsigned = Fixtures.Bytes("generated-unsigned/pe/tiny32-pe-alias.exe");
        File.WriteAllBytes(path, PeEmbed.AppendPkcs7Certificate(unsigned, [1, 2, 3]));
        var r = CliHarness.RunManaged("remove", "/s", path);
        Assert.Equal(0, r.ExitCode);
        Assert.Contains("Removed embedded Authenticode data", r.Stdout);
        var (_, remaining) = PeEmbed.RemoveCertificates(File.ReadAllBytes(path));
        Assert.Equal(0, remaining);
    }

    [Fact]
    public void CliRejectsPartialCmsMutation()
    {
        using var dir = new TempDir();
        var path = dir.File("module.ps1");
        File.WriteAllText(path, "Write-Output test");
        var r = CliHarness.RunManaged("--mode", "portable", "remove", "--strip-chain-except-signer", path);
        Assert.NotEqual(0, r.ExitCode);
        Assert.Contains("portable remove supports only --strip-signature", r.Stderr);
    }

    [SkippableFact]
    public void PeRemovalMatchesRustByteForByte()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var signed = Fixtures.Bytes("pe-authenticode-upstream/tiny64.signed.efi");
        var rustPath = dir.File("rust.efi");
        var managedPath = dir.File("managed.efi");
        File.WriteAllBytes(rustPath, signed);
        File.WriteAllBytes(managedPath, signed);
        var rust = CliHarness.RunRust("--mode", "portable", "remove", "--strip-signature", rustPath);
        var managed = CliHarness.RunManaged("--mode", "portable", "remove", "--strip-signature", managedPath);
        Assert.Equal(rust.ExitCode, managed.ExitCode);
        Assert.Equal(rust.Stdout.Replace(rustPath, "X", StringComparison.Ordinal), managed.Stdout.Replace(managedPath, "X", StringComparison.Ordinal));
        Assert.Equal(File.ReadAllBytes(rustPath), File.ReadAllBytes(managedPath));
    }
}
