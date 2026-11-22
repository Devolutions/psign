using Devolutions.Psign.Cli;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.TopLevel;
using Devolutions.Psign.Core;
using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>
/// Ports of the <c>src/lib.rs</c> unit tests and the portable-relevant <c>tests/cli_verify_filters.rs</c> /
/// <c>tests/artifact_signing_cli.rs</c> parse checks for the top-level verify surface.
/// </summary>
public class TopLevelVerifyTests
{
    private static ParsedCommand ParseLeaf(params string[] argv) =>
        CommandLineParser.Parse(PsignTool.BuildRoot(), NativeArgv.Normalize(argv), PsignTool.BinName).Leaf;

    private static VerifyArgs ParseVerify(params string[] argv)
    {
        var leaf = ParseLeaf(argv);
        Assert.Equal("verify", leaf.Spec.Name);
        return VerifyCommand.Parse(leaf);
    }

    private static UsageException ParseError(params string[] argv) =>
        Assert.Throws<UsageException>(() => CommandLineParser.Parse(PsignTool.BuildRoot(), NativeArgv.Normalize(argv), PsignTool.BinName));

    [Fact]
    public void PortableTrustCommandMappingCoversSupportedVerifyFormats()
    {
        Assert.Equal("trust-verify-pe", VerifyCommand.PortableTrustCommandForVerifyCommand("verify-pe"));
        Assert.Equal("trust-verify-cab", VerifyCommand.PortableTrustCommandForVerifyCommand("verify-cab"));
        Assert.Equal("trust-verify-msi", VerifyCommand.PortableTrustCommandForVerifyCommand("verify-msi"));
        Assert.Equal("trust-verify-esd", VerifyCommand.PortableTrustCommandForVerifyCommand("verify-esd"));
        Assert.Equal("trust-verify-catalog", VerifyCommand.PortableTrustCommandForVerifyCommand("verify-catalog"));
        Assert.Equal("trust-verify-zip", VerifyCommand.PortableTrustCommandForVerifyCommand("verify-zip"));
        Assert.Null(VerifyCommand.PortableTrustCommandForVerifyCommand("verify-msix"));
        Assert.Null(VerifyCommand.PortableTrustCommandForVerifyCommand("verify-script"));
    }

    [Fact]
    public void ExplicitTrustCommandCoversScriptsMsixAndPackages()
    {
        Assert.Equal("trust-verify-pe", VerifyCommand.PortableExplicitTrustCommand("verify-pe"));
        Assert.Equal("trust-verify-script", VerifyCommand.PortableExplicitTrustCommand("verify-script"));
        Assert.Equal("trust-verify-msix", VerifyCommand.PortableExplicitTrustCommand("verify-msix"));
        Assert.Equal("trust-verify-nupkg", VerifyCommand.PortableExplicitTrustCommand("trust-verify-nupkg"));
        Assert.Equal("trust-verify-vsix", VerifyCommand.PortableExplicitTrustCommand("trust-verify-vsix"));
        Assert.Null(VerifyCommand.PortableExplicitTrustCommand("verify-bogus"));
    }

    [Theory]
    [InlineData("a.exe", "verify-pe")]
    [InlineData("a.DLL", "verify-pe")]
    [InlineData("a.sys", "verify-pe")]
    [InlineData("a.ocx", "verify-pe")]
    [InlineData("a.efi", "verify-pe")]
    [InlineData("a.winmd", "verify-pe")]
    [InlineData("a.cab", "verify-cab")]
    [InlineData("a.msi", "verify-msi")]
    [InlineData("a.msp", "verify-msi")]
    [InlineData("a.wim", "verify-esd")]
    [InlineData("a.esd", "verify-esd")]
    [InlineData("a.msix", "verify-msix")]
    [InlineData("a.appxbundle", "verify-msix")]
    [InlineData("a.zip", "verify-zip")]
    [InlineData("a.cat", "verify-catalog")]
    [InlineData("a.ps1", "verify-script")]
    [InlineData("a.psd1", "verify-script")]
    [InlineData("a.mof", "verify-script")]
    [InlineData("a.wsf", "verify-script")]
    [InlineData("a.VBE", "verify-script")]
    [InlineData("a.nupkg", "trust-verify-nupkg")]
    [InlineData("a.snupkg", "trust-verify-nupkg")]
    [InlineData("a.vsix", "trust-verify-vsix")]
    public void PortableCommandForPathInfersFormat(string path, string command) =>
        Assert.Equal(command, VerifyCommand.PortableCommandForPath(path));

    [Fact]
    public void PortableCommandForPathRejectsEncryptedUploadAndUnknown()
    {
        var enc = Assert.Throws<PsignException>(() => VerifyCommand.PortableCommandForPath("pkg.EAPPX"));
        Assert.Equal("encrypted MSIX/AppX packages (.eappx) require Windows AppxSip OS delegation; portable verify cannot rehash encrypted package stores for pkg.EAPPX", enc.Message);
        var upload = Assert.Throws<PsignException>(() => VerifyCommand.PortableCommandForPath("pkg.msixupload"));
        Assert.StartsWith("MSIX/AppX upload bundles (.msixupload) are dotnet/SignTool-style packaging containers", upload.Message);
        Assert.Equal("portable verify cannot infer a supported SIP format for .hidden", Assert.Throws<PsignException>(() => VerifyCommand.PortableCommandForPath(".hidden")).Message);
        Assert.Equal("portable verify cannot infer a supported SIP format for file.txt", Assert.Throws<PsignException>(() => VerifyCommand.PortableCommandForPath("file.txt")).Message);
    }

    [Fact]
    public void VerifyOsVersionCheckParses()
    {
        var v = ParseVerify("verify", "--policy", "pa", "--os-version-check", "386:10.0.26100.0", "x.exe");
        Assert.Equal("386:10.0.26100.0", v.OsVersionCheck);
        Assert.True(VerifyCommand.PortableVerifyUnsupported(v));
    }

    [Fact]
    public void VerifyRepeatableThumbprintsAndQuietShortParse()
    {
        var leaf = ParseLeaf(
            "-q", "verify",
            "--signer-thumbprint-sha1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--signer-thumbprint-sha1", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "--intermediate-ca-sha1", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "--warn-if-missing-eku", "1.3.6.1.5.5.7.3.3",
            "--policy", "pa",
            "x.exe");
        Assert.True(leaf.Flag("quiet"));
        var v = VerifyCommand.Parse(leaf);
        Assert.Equal(new[] { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }, v.SignerThumbprintSha1);
        Assert.Equal(new[] { "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" }, v.IntermediateCaSha1);
        Assert.Equal(new[] { "1.3.6.1.5.5.7.3.3" }, v.WarnIfMissingEku);
        Assert.Equal("pa", v.Policy);
    }

    [Fact]
    public void VerifyPortableTrustOptionsParse()
    {
        var v = ParseVerify(
            "--mode", "portable", "verify",
            "--authroot-cab", "authrootstl.cab",
            "--expect-authroot-cab-sha256", new string('a', 64),
            "--verbose-chain",
            "--allow-loose-signing-cert",
            "--prefer-timestamp-signing-time",
            "--require-valid-timestamp",
            "--online-timeout-secs", "9",
            "--online-max-download-bytes", "4096",
            "x.exe");
        Assert.Equal("authrootstl.cab", v.AuthrootCab);
        Assert.Equal(new string('a', 64), v.ExpectAuthrootCabSha256);
        Assert.True(v.VerboseChain);
        Assert.True(v.AllowLooseSigningCert);
        Assert.True(v.PreferTimestampSigningTime);
        Assert.True(v.RequireValidTimestamp);
        Assert.Equal(9UL, v.OnlineTimeoutSecs);
        Assert.Equal(4096UL, v.OnlineMaxDownloadBytes);
        Assert.True(VerifyCommand.PortableVerifyExplicitTrustRequested(v));
        Assert.False(VerifyCommand.PortableVerifyUnsupported(v));

        var argv = new List<string>();
        VerifyCommand.AppendPortableTrustArgs(v, argv);
        Assert.Equal(
            new[]
            {
                "--authroot-cab", "authrootstl.cab", "--expect-authroot-cab-sha256", new string('a', 64), "--verbose-chain",
                "--allow-loose-signing-cert", "--prefer-timestamp-signing-time", "--require-valid-timestamp",
                "--online-timeout-secs", "9", "--online-max-download-bytes", "4096",
            },
            argv);
    }

    [Fact]
    public void VerifyDefaultsAreNotExplicitTrust()
    {
        var v = ParseVerify("verify", "--online-timeout-secs", "5", "--online-max-download-bytes", "1048576", "x.exe");
        Assert.False(VerifyCommand.PortableVerifyExplicitTrustRequested(v));
        var argv = new List<string>();
        VerifyCommand.AppendPortableTrustArgs(v, argv);
        Assert.Empty(argv);
        Assert.Equal("default", v.Policy);
        Assert.Equal("sha256", v.CatalogHashAlgorithm);
        Assert.False(VerifyCommand.PortableVerifyUnsupported(v));
    }

    [Fact]
    public void VerifyAcceptsMultipleTrailingFiles()
    {
        var v = ParseVerify("verify", "--policy", "pa", "first.dll", "second.dll");
        Assert.Equal(new[] { "first.dll", "second.dll" }, v.Files);
    }

    [Fact]
    public void VerifyAliasesParse()
    {
        Assert.Equal("sig.p7s", ParseVerify("verify", "--p7s", "sig.p7s", "x.exe").DetachedPkcs7);
        Assert.True(ParseVerify("verify", "--vr", "--policy", "pa", "x.exe").RevocationCheck);
        Assert.True(ParseVerify("verify", "--testroot", "--policy", "pa", "x.exe").AllowTestRoot);
        Assert.True(ParseVerify("verify", "--sl", "--policy", "pa", "x.exe").VerifySealingSignatures);
        Assert.True(ParseVerify("verify", "--tw", "--policy", "pa", "x.exe").WarnIfNotTimestamped);
        Assert.Equal(3U, ParseVerify("verify", "/ds", "3", "x.exe").SignatureIndex);
        Assert.Equal("sha1", ParseVerify("verify", "/hash", "SHA1", "x.exe").CatalogHashAlgorithm);
        Assert.Equal("system", ParseVerify("verify", "/as", "x.exe").CatalogSearch);
        Assert.Equal("x.cat", ParseVerify("verify", "/c", "x.cat", "x.exe").Catalog);
        Assert.Equal("{F750E6C3-38EE-11d1-85E5-00C04FC295EE}", ParseVerify("verify", "/pg", "{F750E6C3-38EE-11d1-85E5-00C04FC295EE}", "x.exe").PolicyGuid);
    }

    [Fact]
    public void VerifyRustSipDigestChecksParse()
    {
        Assert.True(ParseVerify("verify", "--rust-sip-script-digest-check", "x.ps1").RustSipScriptDigestCheck);
        Assert.True(ParseVerify("verify", "--rust-sip-pe-digest-check", "x.exe").RustSipPeDigestCheck);
        Assert.True(ParseVerify("verify", "--rust-sip-msi-digest-check", "x.msi").RustSipMsiDigestCheck);
        Assert.True(ParseVerify("verify", "--rust-sip-msix-digest-check", "x.msix").RustSipMsixDigestCheck);
        Assert.True(ParseVerify("verify", "--rust-sip-esd-digest-check", "x.esd").RustSipEsdDigestCheck);
        Assert.True(ParseVerify("verify", "--rust-sip-cab-digest-check", "x.cab").RustSipCabDigestCheck);
        Assert.True(ParseVerify("verify", "--rust-sip-catalog-digest-check", "x.cat").RustSipCatalogDigestCheck);
        var all = ParseVerify("verify", "/rust-sip-all-digest-checks", "x.exe");
        Assert.True(all.RustSipAllDigestChecks);
        Assert.True(VerifyCommand.PortableVerifyUnsupported(all));
    }

    [Fact]
    public void WindowsSlashArgvNormalizesToVerify()
    {
        var leaf = ParseLeaf("verify", "/pa", "/q", "fixture.exe");
        Assert.True(leaf.Flag("quiet"));
        Assert.Equal("pa", VerifyCommand.Parse(leaf).Policy);
    }

    [Fact]
    public void VerifyParseErrors()
    {
        Assert.StartsWith("the following required arguments were not provided", ParseError("verify").Message);
        Assert.Equal("the argument '--detached-pkcs7 <DETACHED_PKCS7>' cannot be used with '--catalog <CATALOG>'", ParseError("verify", "--detached-pkcs7", "a", "--catalog", "b", "x.exe").Message);
        Assert.Equal("invalid value 'abc' for '--signature-index <SIGNATURE_INDEX>': invalid digit found in string", ParseError("verify", "--signature-index", "abc", "x.exe").Message);
        Assert.Equal("invalid value '4294967296' for '--signature-index <SIGNATURE_INDEX>': 4294967296 is not in 0..=4294967295", ParseError("verify", "--ds", "4294967296", "x.exe").Message);
        Assert.Equal("invalid value '99999999999999999999' for '--online-max-download-bytes <ONLINE_MAX_DOWNLOAD_BYTES>': number too large to fit in target type", ParseError("verify", "--online-max-download-bytes", "99999999999999999999", "x.exe").Message);
        Assert.StartsWith("invalid value 'win32' for '--mode <MODE>'", ParseError("--mode", "win32", "verify", "x.exe").Message);
    }

    [Fact]
    public void RdpAcceptsSha256AndMultipleTrailingFiles()
    {
        var leaf = ParseLeaf("rdp", "--sha256", new string('A', 64), "--dry-run", "one.rdp", "two.rdp");
        Assert.Equal(new string('A', 64), leaf.Value("cert-sha256"));
        Assert.True(leaf.Flag("dry-run"));
        Assert.Equal(new[] { "one.rdp", "two.rdp" }, leaf.PosAll("files"));
        Assert.True(ParseLeaf("rdp", "/sha1", "AA", "/l", "x.rdp").Flag("dry-run"));
        Assert.True(ParseLeaf("rdp", "-l", "--sha1", "AA", "x.rdp").Flag("dry-run"));
    }

    [Fact]
    public void RdpRequiresOneThumbprintAlgorithm()
    {
        ParseError("rdp", "file.rdp");
        ParseError("rdp", "--sha1", new string('A', 40), "--sha256", new string('B', 64), "file.rdp");
        ParseError("rdp", "--sha1", "AA");
    }

    [Fact]
    public void CatdbAndInspectSignatureParse()
    {
        var catdb = ParseLeaf("catdb", "/d", "/g", "{guid}", "/r", "/u", "a.cat", "b.cat");
        Assert.True(catdb.Flag("default-database"));
        Assert.Equal("{guid}", catdb.Value("database-guid"));
        Assert.True(catdb.Flag("remove"));
        Assert.True(catdb.Flag("unique-name"));
        Assert.Equal(new[] { "a.cat", "b.cat" }, catdb.PosAll("catalogs"));
        Assert.Empty(ParseLeaf("catdb").PosAll("catalogs"));

        Assert.Equal("pe", ParseLeaf("inspect-signature", "x.exe").Value("input"));
        Assert.Equal("pkcs7", ParseLeaf("inspect-signature", "--input", "pkcs7", "x.p7").Value("input"));
        ParseError("inspect-signature", "--input", "PE", "x.exe");
    }

    [Fact]
    public void ArtifactSigningRequestedAndPackageHelpers()
    {
        Assert.False(ArtifactSigningVerify.Requested(ParseVerify("verify", "x.exe")));
        Assert.True(ArtifactSigningVerify.Requested(ParseVerify("verify", "--artifact-signing", "x.exe")));
        Assert.True(ArtifactSigningVerify.Requested(ParseVerify("verify", "--artifact-signing-publisher-id", "1.2", "x.exe")));
        Assert.True(ArtifactSigningVerify.Requested(ParseVerify("verify", "--artifact-signing-private-trust-root", "r.cer", "x.exe")));
        Assert.True(ArtifactSigningVerify.Requested(ParseVerify("verify", "--artifact-signing-allow-missing-timestamp", "x.exe")));

        Assert.True(ArtifactSigningVerify.IsPackageWithoutWindowsSip("a.nupkg"));
        Assert.True(ArtifactSigningVerify.IsPackageWithoutWindowsSip("a.SNUPKG"));
        Assert.True(ArtifactSigningVerify.IsPackageWithoutWindowsSip("dir/a.vsix"));
        Assert.False(ArtifactSigningVerify.IsPackageWithoutWindowsSip("a.msix"));
        Assert.False(ArtifactSigningVerify.IsPackageWithoutWindowsSip("nupkg"));

        // `/pa` is accepted only together with Artifact Signing.
        Assert.False(VerifyCommand.PortableVerifyUnsupported(ParseVerify("verify", "/pa", "--artifact-signing", "x.exe")));
        Assert.True(VerifyCommand.PortableVerifyUnsupported(ParseVerify("verify", "/pa", "x.exe")));
        Assert.True(VerifyCommand.PortableVerifyUnsupported(ParseVerify("verify", "--policy", "pg", "--artifact-signing", "x.exe")));
    }

    [Theory]
    [InlineData("--anchor-dir", "d")]
    [InlineData("--trusted-ca", "c")]
    [InlineData("--additional-trusted-ca", "c")]
    [InlineData("--authroot-cab", "c")]
    [InlineData("--expect-authroot-cab-sha256", "c")]
    [InlineData("--allow-loose-signing-cert", null)]
    [InlineData("--catalog-search", "all")]
    [InlineData("--catalog-database-guid", "g")]
    [InlineData("--kernel-policy", null)]
    public void ArtifactSigningValidateRejectsWideningOptions(string flag, string? value)
    {
        string[] argv = value is null ? ["verify", "--artifact-signing", flag, "x.exe"] : ["verify", "--artifact-signing", flag, value, "x.exe"];
        var e = Assert.Throws<PsignException>(() => ArtifactSigningVerify.Validate(ParseVerify(argv)));
        Assert.Equal($"{flag} cannot be combined with --artifact-signing: Artifact Signing pins its own roots (use --artifact-signing-private-trust-root for Private Trust)", e.Message);
    }

    [Fact]
    public void ToolModeResolution()
    {
        Assert.Equal("portable", PsignTool.ResolveToolMode("portable", "windows"));
        Assert.Equal("windows", PsignTool.ResolveToolMode("windows", null));
        Assert.Equal("auto", PsignTool.ResolveToolMode(null, null));
        Assert.Equal("auto", PsignTool.ResolveToolMode(null, " Auto "));
        Assert.Equal("windows", PsignTool.ResolveToolMode(null, "WIN32"));
        Assert.Equal("windows", PsignTool.ResolveToolMode(null, "Windows"));
        Assert.Equal("portable", PsignTool.ResolveToolMode(null, "portable\t"));
        Assert.Equal("PSIGN_TOOL_MODE must be one of: auto, windows, portable", Assert.Throws<PsignException>(() => PsignTool.ResolveToolMode(null, "native")).Message);
        Assert.Throws<PsignException>(() => PsignTool.ResolveToolMode(null, string.Empty));
    }

    [Fact]
    public void WindowsModeIsRejectedForModeDependentCommands()
    {
        const string message = "--mode windows requires the native psign-tool (WinVerifyTrust, SignerSignEx3, registered CryptSIP); the managed psign-tool implements the portable backend only\n";
        var portable = new Dictionary<string, string?> { ["PSIGN_TOOL_MODE"] = "portable" };
        foreach (var argv in new[]
        {
            new[] { "--mode", "windows", "verify", "x.exe" },
            new[] { "verify", "--mode", "windows", "x.exe" },
            new[] { "--mode", "windows", "inspect-signature", "x.exe" },
            new[] { "--mode", "windows", "catdb", "x.cat" },
            new[] { "--mode", "windows", "rdp", "--sha1", "AA", "x.rdp" },
            new[] { "--mode", "windows", "remove", "--s", "x.exe" },
        })
        {
            var r = CliHarness.RunManaged(portable, argv);
            Assert.Equal(1, r.ExitCode);
            Assert.Equal(message, r.Stderr);
            Assert.Empty(r.Stdout);
        }

        // `-q` suppresses the error text; `PSIGN_TOOL_MODE=win32` is the env-only Windows alias.
        var quiet = CliHarness.RunManaged(portable, "-q", "--mode", "windows", "verify", "x.exe");
        Assert.Equal(1, quiet.ExitCode);
        Assert.Empty(quiet.Stderr);
        var win32 = CliHarness.RunManaged(new Dictionary<string, string?> { ["PSIGN_TOOL_MODE"] = "win32" }, "catdb");
        Assert.Equal(message, win32.Stderr);

        // `--mode` overrides the environment; portable / cert-store / code bypass mode resolution entirely.
        var exe = Fixtures.Path("generated-signed/pe/tiny64-pe-alias.exe");
        var winEnv = new Dictionary<string, string?> { ["PSIGN_TOOL_MODE"] = "windows", ["PSIGN_NO_AUTO_TRUST"] = "1" };
        Assert.Equal(0, CliHarness.RunManaged(winEnv, "--mode", "portable", "verify", exe).ExitCode);
        Assert.Equal(0, CliHarness.RunManaged(winEnv, "--mode", "windows", "portable", "verify-pe", exe).ExitCode);
        Assert.Equal(0, CliHarness.RunManaged(winEnv, "portable", "verify-pe", exe).ExitCode);
    }

    [Fact]
    public void AutoModeRunsPortableBackendOnEveryOs()
    {
        string[] trust = ["--trusted-ca", Fixtures.Path("devolutions-authenticode/authenticode-test-ca.crt"), "--as-of", "2026-06-01", Fixtures.Path("generated-signed/pe/tiny64-pe-alias.exe")];
        var env = new Dictionary<string, string?> { ["PSIGN_TOOL_MODE"] = null, ["PSIGN_NO_AUTO_TRUST"] = "1" };
        var r = CliHarness.RunManaged(env, ["--mode", "auto", "verify", .. trust]);
        Assert.Equal(0, r.ExitCode);
        Assert.StartsWith("trust-verify-pe: ok", r.Stdout);
        var envAuto = new Dictionary<string, string?> { ["PSIGN_TOOL_MODE"] = "auto", ["PSIGN_NO_AUTO_TRUST"] = "1" };
        Assert.Equal(r.Stdout, CliHarness.RunManaged(envAuto, ["verify", .. trust]).Stdout);
        Assert.Equal(r.Stdout, CliHarness.RunManaged(env, ["verify", .. trust]).Stdout);
    }

    [Fact]
    public void DebugAndQuietFollowPrintOutput()
    {
        var env = new Dictionary<string, string?> { ["PSIGN_TOOL_MODE"] = "portable", ["PSIGN_NO_AUTO_TRUST"] = "1" };
        var exe = Fixtures.Path("generated-signed/pe/tiny64-pe-alias.exe");
        var debug = CliHarness.RunManaged(env, "--debug", "verify", exe);
        Assert.Equal(0, debug.ExitCode);
        Assert.Equal("[debug] exit_code=0 stdout_len=0\n", debug.Stderr);

        // The inner portable command prints directly, so `-q` keeps its stdout (as in Rust).
        var quiet = CliHarness.RunManaged(env, "-q", "verify", "--trusted-ca", Fixtures.Path("devolutions-authenticode/authenticode-test-ca.crt"), "--as-of", "2026-06-01", exe);
        Assert.StartsWith("trust-verify-pe: ok", quiet.Stdout);

        var root = Fixtures.Path("artifact-signing/private-trust/root.cer");
        var js = Fixtures.Path("artifact-signing/private-trust/sample.js");
        string[] artifact = ["verify", "--artifact-signing-publisher-id", "11.22.33.44.55.66.77.88", "--artifact-signing-private-trust-root", root, "--artifact-signing-allow-missing-timestamp", js];
        var loud = CliHarness.RunManaged(env, artifact);
        Assert.Equal(0, loud.ExitCode);
        Assert.StartsWith($"Artifact Signing verified: {js}\n  signature[0] ", loud.Stdout);
        var debugArtifact = CliHarness.RunManaged(env, ["--debug", .. artifact]);
        Assert.Equal($"[debug] exit_code=0 stdout_len={System.Text.Encoding.UTF8.GetByteCount(loud.Stdout)}\n", debugArtifact.Stderr);
        var quietArtifact = CliHarness.RunManaged(env, ["-q", .. artifact]);
        Assert.Empty(quietArtifact.Stdout);
        Assert.Equal(0, quietArtifact.ExitCode);
    }
}
