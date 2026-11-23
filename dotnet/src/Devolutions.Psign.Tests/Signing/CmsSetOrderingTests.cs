using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Tests.Cli;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// The Rust <c>cms</c> crate orders <c>CertificateChoices</c> by comparing their DER as a <c>SEQUENCE OF INTEGER</c>
/// (octets ≥ 0x80 count as longer INTEGERs). These tests pin that ordering.
/// </summary>
public class CmsSetOrderingTests
{
    [Fact]
    public void ChoiceOrderingCountsHighOctetsBeforeLexicographicOrder()
    {
        // Lexicographically {0x01, 0x02} > {0x00, 0x80}, but the second has a high octet, so its SEQUENCE OF INTEGER is longer.
        Assert.True(Der.CompareRustCmsChoice([0x01, 0x02], [0x00, 0x80]) < 0);
        Assert.True(Der.CompareDer([0x01, 0x02], [0x00, 0x80]) > 0);

        // Same encoded length: numeric octet order.
        Assert.True(Der.CompareRustCmsChoice([0x6C, 0x01], [0x7F, 0x01]) < 0);

        // Equal prefix: shorter first.
        Assert.True(Der.CompareRustCmsChoice([0x10], [0x10, 0x00]) < 0);
        Assert.Equal(0, Der.CompareRustCmsChoice([0x10, 0x81], [0x10, 0x81]));

        // Complete TLVs: the element header (length) decides before the SEQUENCE OF INTEGER length.
        Assert.True(Der.CompareRustCmsChoice([0x30, 0x02, 0x90, 0x90], [0x30, 0x03, 0x01, 0x01, 0x01]) < 0);
    }

    [SkippableFact]
    public void ChainCertificateOrderMatchesRustAcrossRandomCertificates()
    {
        RustTool.Require();
        var unsigned = Fixtures.Path("generated-unsigned/pe/tiny64-pe-alias.exe");
        for (int round = 0; round < 12; round++)
        {
            using var dir = new TempDir();
            using var signer = new TestSigner(dir);
            using var chainDir = new TempDir();
            using var chain = new TestSigner(chainDir, "CN=psign ordering chain " + round);
            var rustOut = dir.File("rust.exe");
            var managedOut = dir.File("managed.exe");
            var args = new[] { "portable", "sign-pe", "--cert", signer.CertPath, "--key", signer.KeyPath, "--chain-cert", chain.CertPath };
            Assert.Equal(0, CliHarness.RunRust([.. args, "--output", rustOut, unsigned]).ExitCode);
            Assert.Equal(0, CliHarness.RunManaged([.. args, "--output", managedOut, unsigned]).ExitCode);
            Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(managedOut));
        }
    }
}
