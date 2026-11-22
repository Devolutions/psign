using Xunit;

namespace Devolutions.Psign.Tests.Cli;

public class FormatCommandParityTests
{
    public static IEnumerable<object[]> Cabs() =>
    [
        ["cab-authenticode-upstream/tiny-signed.cab"],
        ["generated-signed/cab/sample.cab"],
        ["generated-unsigned/cab/sample.cab"],
    ];

    [SkippableTheory]
    [MemberData(nameof(Cabs))]
    public void CabCommandsMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        foreach (var alg in new[] { "sha1", "sha256", "sha384", "sha512" })
        {
            CliHarness.AssertSameOutput("portable", "cab-digest", path, "--algorithm", alg);
        }

        CliHarness.AssertSameStdout("portable", "verify-cab", path);
        CliHarness.AssertSameStdout("portable", "extract-cab-pkcs7", path);
        CliHarness.AssertSameStdout("portable", "cab-signer-rs256-prehash", path);
    }

    public static IEnumerable<object[]> Installers() =>
    [
        ["generated-signed/installer/tiny.msi"],
        ["generated-signed/installer/tiny-patch.msp"],
        ["generated-signed/installer/tiny-transform.mst"],
        ["generated-unsigned/installer/tiny.msi"],
        ["msi-authenticode-upstream/tiny-pkcs7-stub.msi"],
    ];

    [SkippableTheory]
    [MemberData(nameof(Installers))]
    public void MsiCommandsMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        CliHarness.AssertSameStdout("portable", "verify-msi", path);
        CliHarness.AssertSameStdout("portable", "extract-msi-pkcs7", path);
        CliHarness.AssertSameStdout("portable", "msi-signer-rs256-prehash", path);
    }

    [SkippableTheory]
    [InlineData("generated-signed/wim-esd/tiny.esd")]
    [InlineData("generated-signed/wim-esd/tiny.wim")]
    [InlineData("generated-unsigned/wim-esd/tiny.esd")]
    [InlineData("generated-unsigned/wim-esd/bad-magic.wim")]
    [InlineData("generated-unsigned/wim-esd/unsigned-header.esd")]
    public void EsdCommandsMatchRust(string fixture) =>
        CliHarness.AssertSameStdout("portable", "verify-esd", Fixtures.Path(fixture));

    [SkippableTheory]
    [InlineData("generated-signed/catalog/sample.cat")]
    [InlineData("generated-unsigned/catalog/sample.cat")]
    [InlineData("catalog-workflows/multi-member.cat")]
    [InlineData("catalog-workflows/single-pe.cat")]
    public void CatalogCommandsMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        CliHarness.AssertSameStdout("portable", "verify-catalog", path);
        CliHarness.AssertSameStdout("portable", "catalog-signer-rs256-prehash", path);
    }

    [SkippableTheory]
    [InlineData("catalog-workflows/multi-member.cat", "catalog-workflows/subjects/hello.txt")]
    [InlineData("catalog-workflows/multi-member.cat", "catalog-workflows/subjects/tiny32.efi")]
    [InlineData("catalog-workflows/single-binary.cat", "catalog-workflows/subjects/blob.bin")]
    [InlineData("catalog-workflows/single-text.cat", "catalog-workflows/subjects/blob.bin")]
    public void CatalogMemberMatchesRust(string catalog, string subject) =>
        CliHarness.AssertSameStdout("portable", "verify-catalog-member", "--catalog", Fixtures.Path(catalog), Fixtures.Path(subject));

    [SkippableTheory]
    [InlineData("pe-authenticode-upstream/tiny32.signed.efi")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi")]
    public void PageHashCommandsMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        CliHarness.AssertSameOutput("portable", "pe-has-page-hashes", path);
        CliHarness.AssertSameOutput("portable", "pe-page-hash-info", path);
        CliHarness.AssertSameStdout("portable", "verify-pe-page-hashes", path);
    }

    [SkippableFact]
    public void PkcxExtractMatchesRust()
    {
        foreach (var f in Directory.GetFiles(Fixtures.Path("generated-signed/p7x")))
        {
            CliHarness.AssertSameOutput("portable", "extract-pkcx-pkcs7", f);
        }

        CliHarness.AssertSameOutput("portable", "extract-pkcx-pkcs7", Fixtures.Path("generated-signed/cab/sample.cab"));
    }
}
