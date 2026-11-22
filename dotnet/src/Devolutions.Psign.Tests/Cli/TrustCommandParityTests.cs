using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>Managed vs Rust <c>psign-tool portable trust-verify-*</c> / inspection commands (stdout, stderr, exit code).</summary>
public class TrustCommandParityTests
{
    private const string TestCa = "devolutions-authenticode/authenticode-test-ca.crt";
    private const string AsOf = "2026-06-01";

    private static string[] Trust(params string[] extra) => ["--trusted-ca", Fixtures.Path(TestCa), "--as-of", AsOf, .. extra];

    private static void Same(string command, string fixture, params string[] trust) =>
        CliHarness.AssertSameOutput(["portable", command, Fixtures.Path(fixture), .. trust]);

    public static IEnumerable<object[]> SignedFixtures() =>
    [
        ["trust-verify-pe", "generated-signed/pe/tiny64-pe-alias.exe"],
        ["trust-verify-pe", "generated-signed/winmd/tiny32-pe-copy.winmd"],
        ["trust-verify-cab", "generated-signed/cab/sample.cab"],
        ["trust-verify-msi", "generated-signed/installer/tiny.msi"],
        ["trust-verify-msi", "generated-signed/installer/tiny-patch.msp"],
        ["trust-verify-esd", "generated-signed/wim-esd/tiny.esd"],
        ["trust-verify-esd", "generated-signed/wim-esd/tiny.wim"],
        ["trust-verify-catalog", "generated-signed/catalog/sample.cat"],
        ["trust-verify-zip", "zip-authenticode/signed/sample.signed.zip"],
        ["trust-verify-script", "generated-signed/scripts/powershell/ps1/utf8-crlf.ps1"],
        ["trust-verify-script", "generated-signed/scripts/powershell/psd1/utf16le-bom-lf.psd1"],
        ["trust-verify-script", "generated-signed/scripts/wsh/js/utf8-crlf.js"],
        ["trust-verify-script", "generated-signed/scripts/wsh/vbs/utf8-bom-crlf.vbs"],
        ["trust-verify-script", "generated-signed/scripts/wsh/wsf/utf8-crlf.wsf"],
        ["trust-verify-msix", "generated-signed/msix/sample.msix"],
        ["trust-verify-msix", "generated-signed/msix/sample.appxbundle"],
        ["trust-verify-msix", "msix-edge-cases/signed/flat-sha384.signed.msix"],
        ["trust-verify-nupkg", "package-signing/signed/sample.signed.nupkg"],
        ["trust-verify-nupkg", "package-signing/signed/with-pe.signed.nupkg"],
        ["trust-verify-nupkg", "package-signing/signed/sample.signed.snupkg"],
        ["trust-verify-vsix", "package-signing/signed/sample.signed.vsix"],
        ["trust-verify-vsix", "package-signing/signed/deep-nested.signed.vsix"],
    ];

    [SkippableTheory]
    [MemberData(nameof(SignedFixtures))]
    public void TrustVerifyMatchesRust(string command, string fixture)
    {
        Same(command, fixture, Trust());
        Same(command, fixture, Trust("--allow-loose-signing-cert"));
        Same(command, fixture, Trust("--verbose-chain"));
        if (command != "trust-verify-zip")
        {
            // Known gap: the Rust picky parser rejects the psign-produced ZIP PKCS#7 (CMS fallback path, "certificate
            // chain verification" error text) while the managed picky approximation accepts it ("picky Authenticode
            // validation"); both reject the expired chain.
            Same(command, fixture, "--trusted-ca", Fixtures.Path(TestCa), "--as-of", "2030-01-01");
        }

        Same(command, fixture, "--anchor-dir", Fixtures.Path("devolutions-authenticode"), "--as-of", AsOf);
    }

    [SkippableTheory]
    [MemberData(nameof(SignedFixtures))]
    public void TrustVerifyWithWrongAnchorMatchesRust(string command, string fixture)
    {
        using var dir = new TempDir();
        using var pki = new GeneratedTestPki(dir);
        Same(command, fixture, "--trusted-ca", pki.RootPath, "--as-of", AsOf);
    }

    [SkippableTheory]
    [InlineData("trust-verify-cab", "generated-unsigned/cab/sample.cab")]
    [InlineData("trust-verify-msi", "generated-unsigned/installer/tiny.msi")]
    [InlineData("trust-verify-esd", "generated-unsigned/wim-esd/tiny.esd")]
    [InlineData("trust-verify-esd", "generated-unsigned/wim-esd/bad-magic.wim")]
    [InlineData("trust-verify-catalog", "generated-unsigned/catalog/sample.cat")]
    [InlineData("trust-verify-zip", "zip-authenticode/unsigned/sample.zip")]
    [InlineData("trust-verify-script", "unsigned-sample.ps1")]
    [InlineData("trust-verify-script", "unsigned-sample.vbs")]
    [InlineData("trust-verify-nupkg", "package-signing/unsigned/sample.nupkg")]
    [InlineData("trust-verify-vsix", "package-signing/unsigned/sample.vsix")]
    [InlineData("trust-verify-pe", "generated-unsigned/pe/tiny32-pe-alias.exe")]
    [InlineData("trust-verify-vsix", "missing-file.vsix")]
    [InlineData("trust-verify-esd", "missing-file.esd")]
    public void TrustVerifyFailuresMatchRust(string command, string fixture) => Same(command, fixture, Trust());

    [SkippableFact]
    public void SharedOptionErrorsMatchRust()
    {
        var vsix = "package-signing/signed/sample.signed.vsix";
        Same("trust-verify-vsix", vsix, "--artifact-signing", "--trusted-ca", Fixtures.Path(TestCa));
        Same("trust-verify-nupkg", "package-signing/signed/sample.signed.nupkg", "--anchor-dir", Fixtures.Path("devolutions-authenticode"), "--artifact-signing-allow-missing-timestamp");
        Same("trust-verify-cab", "generated-signed/cab/sample.cab", Trust("--expect-authroot-cab-sha256", "abc"));
        Same("trust-verify-cab", "generated-signed/cab/sample.cab", "--trusted-ca", Fixtures.Path(TestCa), "--as-of", "2026-13-01");
        Same("trust-verify-script", "devolutions-authenticode/README.md", Trust());
    }

    [SkippableFact]
    public void DetachedAndCompanionMatchRust()
    {
        foreach (var (content, sig) in new[]
        {
            ("generated-unsigned/detached/content.bin", "generated-signed/detached/content/content.bin.p7"),
            ("generated-unsigned/detached/content-utf8.txt", "generated-signed/detached/content-utf8/content-utf8.txt.p7"),
            ("generated-unsigned/detached/content-utf16le-bom.txt", "generated-signed/detached/content-utf16le-bom/content-utf16le-bom.txt.p7"),
            ("generated-unsigned/detached/content-utf8.txt", "generated-signed/detached/content/content.bin.p7"),
        })
        {
            CliHarness.AssertSameOutput(["portable", "trust-verify-detached", Fixtures.Path(content), Fixtures.Path(sig), .. Trust()]);
        }

        var appinstaller = Fixtures.Path("generated-unsigned/appinstaller/sample.appinstaller");
        var companion = Fixtures.Path("generated-signed/appinstaller/sample.appinstaller.p7");
        CliHarness.AssertSameOutput(["portable", "appinstaller-verify-companion", appinstaller, "--signature", companion, .. Trust()]);
        CliHarness.AssertSameOutput(["portable", "trust-verify-detached", appinstaller, companion, .. Trust()]);
    }

    [SkippableFact]
    public void ArtifactSigningPrivateTrustMatchesRust()
    {
        var root = Fixtures.Path("artifact-signing/private-trust/root.cer");
        foreach (var (command, file) in new[]
        {
            ("trust-verify-script", "sample.js"),
            ("trust-verify-msix", "sample.msix"),
            ("trust-verify-nupkg", "sample.nupkg"),
            ("trust-verify-vsix", "sample.vsix"),
        })
        {
            var path = "artifact-signing/private-trust/" + file;
            // Without a timestamp the verification time is the wall clock: compare with the time= field masked.
            string[] ok = ["portable", command, Fixtures.Path(path), "--artifact-signing-publisher-id", "11.22.33.44.55.66.77.88", "--artifact-signing-private-trust-root", root, "--artifact-signing-allow-missing-timestamp"];
            var rust = CliHarness.RunRust(ok);
            var managed = CliHarness.RunManaged(ok);
            Assert.Equal(0, rust.ExitCode);
            Assert.Equal(0, managed.ExitCode);
            Assert.Equal(MaskTime(rust.Stdout), MaskTime(managed.Stdout));
            Same(command, path, "--artifact-signing-publisher-id", "1.2.3.4", "--artifact-signing-private-trust-root", root, "--artifact-signing-allow-missing-timestamp");
            Same(command, path, "--artifact-signing-allow-missing-timestamp");
        }
    }

    private static string MaskTime(string s) => System.Text.RegularExpressions.Regex.Replace(s, @"time=\S+", "time=*");

    [SkippableFact]
    public void InspectionCommandsMatchRust()
    {
        CliHarness.AssertSameOutput("portable", "inspect-authenticode", Fixtures.Path("generated-signed/pe/tiny64-pe-alias.exe"));
        CliHarness.AssertSameOutput("portable", "inspect-authenticode", Fixtures.Path("pe-authenticode-upstream/tiny64.signed.efi"));
        CliHarness.AssertSameOutput("portable", "inspect-authenticode", "--input", "pkcs7", Fixtures.Path("artifact-signing/psign-tool.pkcs7.der"));
        CliHarness.AssertSameOutput("portable", "inspect-authenticode", "--input", "pkcs7", Fixtures.Path("generated-signed/appinstaller/sample.appinstaller.p7"));
        CliHarness.AssertSameOutput("portable", "inspect-pkcs7", Fixtures.Path("generated-signed/p7x/appxsignature-from-sample-msix.p7x"));
        CliHarness.AssertSameOutput("portable", "inspect-pkcs7", Fixtures.Path("generated-signed/catalog/sample.cat"));
        CliHarness.AssertSameOutput("portable", "inspect-pkcs7", Fixtures.Path("missing.p7"));
    }

    [SkippableFact]
    public void ArtifactSigningPublisherIdMatchesRust()
    {
        foreach (var format in new[] { "json", "publisher-id" })
        {
            CliHarness.AssertSameOutput("portable", "artifact-signing-publisher-id", "--input", "cert", "--format", format, Fixtures.Path("artifact-signing/devolutions-signer.pem"));
            CliHarness.AssertSameOutput("portable", "artifact-signing-publisher-id", "--input", "pkcs7", "--format", format, Fixtures.Path("artifact-signing/psign-tool.pkcs7.der"));
            CliHarness.AssertSameOutput("portable", "artifact-signing-publisher-id", "--format", format, Fixtures.Path("generated-signed/pe/tiny32-pe-alias.exe"));
            CliHarness.AssertSameOutput("portable", "artifact-signing-publisher-id", "--input", "cert", "--format", format, Fixtures.Path(TestCa));
        }
    }
}
