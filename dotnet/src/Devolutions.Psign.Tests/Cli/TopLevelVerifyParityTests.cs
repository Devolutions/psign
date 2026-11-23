using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>
/// Managed vs Rust top-level <c>psign-tool verify</c> / <c>inspect-signature</c> / <c>catdb</c> / <c>rdp</c> in portable mode
/// (stdout, stderr, exit code). Automatic AuthRoot trust is disabled (<c>PSIGN_NO_AUTO_TRUST=1</c>) unless a test points
/// both tools at a local AuthRoot cache, so nothing touches the network.
/// </summary>
public class TopLevelVerifyParityTests
{
    private const string TestCa = "devolutions-authenticode/authenticode-test-ca.crt";
    private const string AsOf = "2026-06-01";
    private const string PrivateTrustId = "11.22.33.44.55.66.77.88";

    private static readonly Dictionary<string, string?> NoAutoTrust = new()
    {
        ["PSIGN_TOOL_MODE"] = "portable",
        ["PSIGN_NO_AUTO_TRUST"] = "1",
        ["PSIGN_AUTHROOT_URL"] = "http://127.0.0.1:9/authrootstl.cab",
    };

    private static string F(string rel) => Fixtures.Path(rel);

    private static string[] Trust(params string[] extra) => ["--trusted-ca", F(TestCa), "--as-of", AsOf, .. extra];

    private static string[] PrivateTrust(string publisherId) =>
    [
        "--artifact-signing-publisher-id", publisherId,
        "--artifact-signing-private-trust-root", F("artifact-signing/private-trust/root.cer"),
        "--artifact-signing-allow-missing-timestamp",
    ];

    /// <summary>Compare exit code, stdout and stderr (Rust clap prints its own executable name in usage lines).</summary>
    private static CliResult Same(IReadOnlyDictionary<string, string?> env, params string[] args)
    {
        var rust = CliHarness.RunRust(env, args);
        var managed = CliHarness.RunManaged(env, args);
        var line = string.Join(' ', args);
        Assert.True(rust.ExitCode == managed.ExitCode, $"exit code mismatch for {line}: rust={rust.ExitCode} managed={managed.ExitCode}\nrust stderr: {rust.Stderr}\nmanaged stderr: {managed.Stderr}");
        // Artifact Signing reports print the verification instant (` time=...Z`) when no --as-of is given.
        Assert.Equal(MaskTime(rust.Stdout), MaskTime(managed.Stdout));
        if (MaskTime(rust.Stdout) == rust.Stdout)
        {
            Assert.Equal(rust.StdoutBytes, managed.StdoutBytes);
        }

        Assert.Equal(NormalizeRustStderr(rust.Stderr), managed.Stderr.Replace("\r\n", "\n", StringComparison.Ordinal));
        return managed;
    }

    private static CliResult Same(params string[] args) => Same(NoAutoTrust, args);

    /// <summary>Usage errors: same exit code (2) and the same first <c>error:</c> line (usage text formatting differs).</summary>
    private static void SameUsageError(params string[] args)
    {
        var rust = CliHarness.RunRust(NoAutoTrust, args);
        var managed = CliHarness.RunManaged(NoAutoTrust, args);
        Assert.Equal(2, rust.ExitCode);
        Assert.Equal(rust.ExitCode, managed.ExitCode);
        Assert.Equal(FirstLine(rust.Stderr), FirstLine(managed.Stderr));
        Assert.Equal(rust.Stdout, managed.Stdout);
    }

    private static string MaskTime(string s) =>
        System.Text.RegularExpressions.Regex.Replace(s, @" time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", " time=<now>");

    private static string FirstLine(string s) => s.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n')[0];

    private static string NormalizeRustStderr(string s) =>
        s.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("psign-tool.exe", "psign-tool", StringComparison.Ordinal);

    public static IEnumerable<object[]> InferredFixtures() =>
    [
        ["generated-signed/pe/tiny64-pe-alias.exe"],
        ["generated-signed/pe/tiny32-pe-alias.dll"],
        ["generated-signed/pe/tiny32-pe-alias.sys"],
        ["generated-signed/pe/tiny64-pe-alias.ocx"],
        ["generated-signed/pe/tiny64-pe-alias.efi"],
        ["generated-signed/winmd/tiny32-pe-copy.winmd"],
        ["generated-signed/cab/sample.cab"],
        ["generated-signed/installer/tiny.msi"],
        ["generated-signed/installer/tiny-patch.msp"],
        ["generated-signed/wim-esd/tiny.esd"],
        ["generated-signed/wim-esd/tiny.wim"],
        ["generated-signed/msix/sample.msix"],
        ["generated-signed/msix/sample.appx"],
        ["generated-signed/msix/sample.msixbundle"],
        ["generated-signed/msix/sample.appxbundle"],
        ["zip-authenticode/signed/sample.signed.zip"],
        ["generated-signed/catalog/sample.cat"],
        ["generated-signed/scripts/powershell/ps1/utf8-crlf.ps1"],
        ["generated-signed/scripts/powershell/psd1/utf16le-bom-lf.psd1"],
        ["generated-signed/scripts/wsh/js/utf8-crlf.js"],
        ["generated-signed/scripts/wsh/vbs/utf8-bom-crlf.vbs"],
        ["generated-signed/scripts/wsh/wsf/utf8-crlf.wsf"],
        ["package-signing/signed/sample.signed.nupkg"],
        ["package-signing/signed/sample.signed.snupkg"],
        ["package-signing/signed/sample.signed.vsix"],
        ["generated-unsigned/pe/tiny32-pe-alias.exe"],
        ["generated-unsigned/cab/sample.cab"],
        ["pe-authenticode-upstream/tiny64.signed.efi"],
    ];

    [SkippableTheory]
    [MemberData(nameof(InferredFixtures))]
    public void InferredFormatDigestOnlyMatchesRust(string fixture)
    {
        Same("verify", F(fixture));
        Same("--mode", "portable", "verify", F(fixture));
    }

    [SkippableTheory]
    [MemberData(nameof(InferredFixtures))]
    public void InferredFormatExplicitTrustMatchesRust(string fixture)
    {
        Same(["verify", .. Trust(), F(fixture)]);
        Same(["verify", .. Trust("--verbose-chain", "--online-timeout-secs", "9"), F(fixture)]);
        Same("verify", "--anchor-dir", F("devolutions-authenticode"), "--as-of", AsOf, F(fixture));
        if (!fixture.EndsWith(".zip", StringComparison.Ordinal))
        {
            // Known trust-verify-zip gap (see TrustCommandParityTests): the expired-chain error text differs.
            Same("verify", "--additional-trusted-ca", F(TestCa), "--as-of", "2030-01-01", F(fixture));
        }
    }

    [SkippableFact]
    public void MultipleFilesStopAtFirstFailure()
    {
        Same("verify", F("generated-signed/pe/tiny64-pe-alias.exe"), F("generated-signed/cab/sample.cab"), F("generated-signed/scripts/wsh/js/utf8-crlf.js"));
        Same("verify", F("generated-signed/pe/tiny64-pe-alias.exe"), F("missing-file.exe"), F("generated-signed/cab/sample.cab"));
        Same(["verify", .. Trust(), F("generated-signed/installer/tiny.msi"), F("generated-unsigned/installer/tiny.msi"), F("generated-signed/cab/sample.cab")]);
    }

    [SkippableTheory]
    [InlineData("x.eappx")]
    [InlineData("x.EMSIXBUNDLE")]
    [InlineData("x.appxupload")]
    [InlineData("x.msixupload")]
    [InlineData("x.txt")]
    [InlineData("noextension")]
    [InlineData("missing-file.exe")]
    [InlineData("missing-file.vsix")]
    public void InferenceErrorsMatchRust(string name)
    {
        Same("verify", name);
        Same(["verify", .. Trust(), name]);
    }

    public static IEnumerable<object[]> UnsupportedOptions() =>
    [
        [new[] { "/pa" }],
        [new[] { "--policy", "pg" }],
        [new[] { "/pg", "{F750E6C3-38EE-11d1-85E5-00C04FC295EE}" }],
        [new[] { "--policy-guid", "x" }],
        [new[] { "/vr" }],
        [new[] { "/a" }],
        [new[] { "/ad" }],
        [new[] { "/as" }],
        [new[] { "/ag", "{00000000-0000-0000-0000-000000000000}" }],
        [new[] { "/o", "386:10.0.26100.0" }],
        [new[] { "/kp" }],
        [new[] { "/all" }],
        [new[] { "/testroot" }],
        [new[] { "/tw" }],
        [new[] { "/ds", "0" }],
        [new[] { "/ms" }],
        [new[] { "/p7" }],
        [new[] { "/d" }],
        [new[] { "/ph" }],
        [new[] { "/r", "Microsoft" }],
        [new[] { "/sha1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }],
        [new[] { "--signer-thumbprint-sha1", "A", "--signer-thumbprint-sha1", "B" }],
        [new[] { "/ca", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" }],
        [new[] { "/u", "1.3.6.1.5.5.7.3.3" }],
        [new[] { "/p7content", "content.bin" }],
        [new[] { "--detached-pkcs7-content", "content.bin" }],
        [new[] { "/w2010pca" }],
        [new[] { "/now2010pca" }],
        [new[] { "--warn-pca-2010", "--no-warn-pca-2010" }],
        [new[] { "/sl" }],
        [new[] { "--rust-sip-pe-digest-check" }],
        [new[] { "--rust-sip-script-digest-check" }],
        [new[] { "--rust-sip-msi-digest-check" }],
        [new[] { "--rust-sip-esd-digest-check" }],
        [new[] { "--rust-sip-msix-digest-check" }],
        [new[] { "--rust-sip-cab-digest-check" }],
        [new[] { "--rust-sip-catalog-digest-check" }],
        [new[] { "/rust-sip-all-digest-checks" }],
        [new[] { "/bp" }],
        [new[] { "/enclave" }],
        [new[] { "--policy", "pa", "--verify-sealing-signatures", "--detached-pkcs7", "missing.p7s" }],
        [new[] { "--artifact-signing", "/kp" }],
        [new[] { "--artifact-signing", "/ad" }],
        [new[] { "--artifact-signing", "--policy", "pg" }],
    ];

    [SkippableTheory]
    [MemberData(nameof(UnsupportedOptions))]
    public void UnsupportedOptionsMatchRust(string[] options)
    {
        Same(["verify", .. options, F("generated-signed/pe/tiny64-pe-alias.exe")]);
        Same(["--mode", "portable", "verify", .. options, "x.exe"]);
    }

    [SkippableFact]
    public void DetachedPkcs7MatchesRust()
    {
        var sig = F("generated-signed/detached/content/content.bin.p7");
        var content = F("generated-unsigned/detached/content.bin");
        Same(["verify", "--detached-pkcs7", sig, content, .. Trust()]);
        Same(["verify", "/p7s", sig, "/p7content", content, F("anything.exe"), .. Trust()]);
        Same(["verify", "--detached-pkcs7", sig, F("generated-unsigned/detached/content-utf8.txt"), .. Trust()]);
        Same(["verify", "--detached-pkcs7", F("generated-signed/detached/content-utf8/content-utf8.txt.p7"), F("generated-unsigned/detached/content-utf8.txt"), .. Trust("--verbose-chain")]);
        Same("verify", "--detached-pkcs7", sig, content);
        Same("verify", "--detached-pkcs7", sig, "a.exe", "b.exe");
        Same("verify", "--detached-pkcs7", "missing.p7s", content);
        Same(["verify", "--detached-pkcs7", sig, content, "--trusted-ca", F(TestCa), "--as-of", "2030-01-01"]);
    }

    [SkippableFact]
    public void CatalogMembersMatchRust()
    {
        var multi = F("catalog-workflows/multi-member.cat");
        var subjects = new[] { F("catalog-workflows/subjects/tiny32.efi"), F("catalog-workflows/subjects/hello.txt"), F("catalog-workflows/subjects/blob.bin") };
        Same(["verify", "--catalog", multi, .. subjects]);
        Same(["verify", "/c", multi, .. subjects]);
        Same(["verify", "--catalog", multi, .. Trust(), .. subjects]);
        Same("verify", "/c", F("catalog-workflows/single-pe.cat"), F("catalog-workflows/subjects/tiny32.efi"));
        Same("verify", "/c", F("catalog-workflows/single-pe.cat"), F("catalog-workflows/subjects/hello.txt"));
        Same("verify", "/c", F("catalog-workflows/single-text.cat"), F("catalog-workflows/subjects/hello.txt"));
        Same("verify", "/c", F("catalog-workflows/single-pe.cat"), "/hash", "SHA1", F("catalog-workflows/subjects/tiny32.efi"));
        Same("verify", "--catalog", F("catalog-workflows/single-pe.cat"), "--catalog-hash-algorithm", "sha256", F("catalog-workflows/subjects/tiny32.efi"));
        Same(["verify", "--catalog", F("generated-signed/catalog/sample.cat"), .. Trust(), F("catalog-workflows/subjects/tiny32.efi")]);
        Same("verify", "--catalog", F("missing.cat"), F("catalog-workflows/subjects/tiny32.efi"));
    }

    [SkippableFact]
    public void ArtifactSigningPrivateTrustMatchesRust()
    {
        foreach (var file in new[] { "sample.js", "sample.msix", "sample.nupkg", "sample.vsix" })
        {
            var path = F($"artifact-signing/private-trust/{file}");
            var ok = Same(["--mode", "portable", "verify", .. PrivateTrust(PrivateTrustId), path]);
            Assert.Contains($"publisher_id={PrivateTrustId} kind=private_trust", ok.Stdout);
            Same(["--mode", "portable", "verify", .. PrivateTrust("1.2.3.4"), path]);
            Same(["verify", "/pa", .. PrivateTrust(PrivateTrustId), path]);
        }

        var all = new[] { "sample.js", "sample.msix", "sample.nupkg", "sample.vsix" }.Select(f => F($"artifact-signing/private-trust/{f}")).ToArray();
        Same(["verify", .. PrivateTrust(PrivateTrustId), .. all]);
        Same(["verify", "--debug", .. PrivateTrust(PrivateTrustId), all[0]]);
        Same(["verify", "-q", .. PrivateTrust(PrivateTrustId), all[0]]);
        Same(["verify", "/q", "/debug", .. PrivateTrust(PrivateTrustId), all[0]]);
        Same(["verify", .. PrivateTrust(PrivateTrustId), "--as-of", AsOf, all[0]]);
        Same(["verify", .. PrivateTrust(PrivateTrustId), "--as-of", "2026-13-01", all[0]]);
        Same(["verify", .. PrivateTrust(PrivateTrustId), all[0], F("missing-file.js")]);
    }

    [SkippableFact]
    public void ArtifactSigningRejectionsMatchRust()
    {
        var efi = F("pe-authenticode-upstream/tiny64.signed.efi");
        Same("--mode", "portable", "verify", "--artifact-signing", efi);
        Same("verify", "--artifact-signing-publisher-id", "285218949.549339218.252840042.443064405", "--trusted-ca", F("artifact-signing/devolutions-signer.pem"), efi);
        Same("verify", "--artifact-signing", "--anchor-dir", F("artifact-signing"), efi);
        Same("verify", "--artifact-signing", "--additional-trusted-ca", F(TestCa), efi);
        Same("verify", "--artifact-signing", "--authroot-cab", F("generated-signed/cab/sample.cab"), efi);
        Same("verify", "--artifact-signing", "--expect-authroot-cab-sha256", "abc", efi);
        Same("verify", "--artifact-signing", "--allow-loose-signing-cert", efi);
        Same("--mode", "portable", "verify", "--artifact-signing-allow-missing-timestamp", F("artifact-signing/private-trust/sample.vsix"));
        Same("verify", "--artifact-signing", F("generated-signed/pe/tiny64-pe-alias.exe"), F("x.txt"));
        Same("verify", "--artifact-signing", "--detached-pkcs7", F("generated-signed/detached/content/content.bin.p7"), F("generated-unsigned/detached/content.bin"));
        Same("verify", "--artifact-signing", "--detached-pkcs7", F("generated-signed/detached/content/content.bin.p7"), "a.exe", "b.exe");
        Same("verify", "--artifact-signing", "--catalog", F("generated-signed/catalog/sample.cat"), F("catalog-workflows/subjects/tiny32.efi"));
        Same("verify", "--artifact-signing", "--catalog", F("missing.cat"), F("catalog-workflows/subjects/tiny32.efi"));
    }

    [SkippableFact]
    public void InspectSignatureMatchesRust()
    {
        Same("inspect-signature", F("pe-authenticode-upstream/tiny64.signed.efi"));
        Same("inspect-signature", F("generated-signed/pe/tiny64-pe-alias.exe"), "--input", "pe");
        Same("inspect-signature", "--input", "pkcs7", F("artifact-signing/psign-tool.pkcs7.der"));
        Same("inspect-signature", "--input", "pkcs7", F("generated-signed/detached/content/content.bin.p7"));
        Same("--debug", "inspect-signature", F("pe-authenticode-upstream/tiny64.signed.efi"));
        Same("-q", "inspect-signature", F("pe-authenticode-upstream/tiny64.signed.efi"));
        Same("inspect-signature", F("missing-file.exe"));
        Same("inspect-signature", F("generated-unsigned/pe/tiny32-pe-alias.exe"));
        Same("inspect-signature", "--input", "pe", F("generated-signed/detached/content/content.bin.p7"));
        SameUsageError("inspect-signature", "--input", "cert", F("pe-authenticode-upstream/tiny64.signed.efi"));
        SameUsageError("inspect-signature");
    }

    [SkippableFact]
    public void CatdbAndRdpMatchRust()
    {
        Same("catdb", "x.cat");
        Same("catdb");
        Same("catdb", "/d", "/g", "{00000000-0000-0000-0000-000000000000}", "/r", "/u", "a.cat", "b.cat");
        Same("catdb", "--default-database", "--unique-name", "a.cat");
        Same("-q", "catdb", "x.cat");
        Same("--debug", "catdb", "x.cat");
        Same("rdp", "--sha1", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "x.rdp");
        Same("rdp", "/sha256", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "/l", "one.rdp", "two.rdp");
        Same("rdp", "-l", "--sha256", "AA", "x.rdp");
        Same("rdp", "--dry-run", "--sha1", "AA", "x.rdp");
        Same("rdp", "--l", "--sha1", "AA", "x.rdp");
        SameUsageError("rdp", "file.rdp");
        SameUsageError("rdp", "--sha1", "AA", "--sha256", "BB", "file.rdp");
        SameUsageError("rdp", "--sha1", "AA");
    }

    [SkippableFact]
    public void QuietDebugAndModeMatchRust()
    {
        var exe = F("generated-signed/pe/tiny64-pe-alias.exe");
        Same("-q", "verify", exe);
        Same("verify", "-q", exe);
        Same("verify", "/q", exe);
        Same("-q", "verify", F("missing-file.exe"));
        Same("--debug", "verify", exe);
        Same("verify", "--debug", F("missing-file.exe"));
        Same("/debug", "verify", "/q", exe);
        Same("-qv", "verify", exe);
        Same("-q", "verify", "/pa", exe);
        Same("--mode", "portable", "verify", exe);
        Same("verify", "--mode", "portable", exe);
        Same("-q", "portable", "trust-verify-pe", F("missing-file.exe"));
        Same("--debug", "portable", "pe-digest", exe);
        SameUsageError("--mode", "win32", "verify", exe);
        SameUsageError("verify", "--mode", "bogus", exe);

        var bogusMode = new Dictionary<string, string?>(NoAutoTrust) { ["PSIGN_TOOL_MODE"] = "bogus" };
        Same(bogusMode, "verify", exe);
        Same(bogusMode, "-q", "verify", exe);
        Same(bogusMode, "portable", "pe-digest", exe);
        Same(bogusMode, "--mode", "portable", "verify", exe);
        Same(bogusMode, "inspect-signature", exe);
        Same(bogusMode, "catdb", "x.cat");
        var paddedMode = new Dictionary<string, string?>(NoAutoTrust) { ["PSIGN_TOOL_MODE"] = "  PORTABLE " };
        Same(paddedMode, "verify", exe);
    }

    [SkippableFact]
    public void UsageErrorsMatchRust()
    {
        SameUsageError("verify");
        SameUsageError("verify", "--policy", "bogus", "x.exe");
        SameUsageError("verify", "--signature-index", "abc", "x.exe");
        SameUsageError("verify", "--signature-index", "99999999999", "x.exe");
        SameUsageError("verify", "--catalog-search", "everything", "x.exe");
        SameUsageError("verify", "--revocation-mode", "maybe", "x.exe");
        SameUsageError("verify", "--hash", "sha384", "x.exe");
        SameUsageError("verify", "--online-timeout-secs", "soon", "x.exe");
        SameUsageError("verify", "--detached-pkcs7", "sig.p7s", "--catalog", "x.cat", "a.exe");
        SameUsageError("verify", "--bogus-flag", "x.exe");
    }

    [SkippableFact]
    public void AutomaticAuthRootRoutingMatchesRust()
    {
        // A fresh local AuthRoot cache entry (not a real AuthRoot CAB) exercises the automatic trust routing without network.
        using var dir = new TempDir();
        File.Copy(F("generated-signed/cab/sample.cab"), dir.File("authrootstl.cab"));
        File.WriteAllText(dir.File("authrootstl.cab.json"), $"{{\"downloaded_at_unix_secs\":{DateTimeOffset.UtcNow.ToUnixTimeSeconds()},\"source_url\":\"test\",\"size_bytes\":1}}");
        var env = new Dictionary<string, string?>
        {
            ["PSIGN_TOOL_MODE"] = "portable",
            ["PSIGN_NO_AUTO_TRUST"] = null,
            ["PSIGN_AUTHROOT_CACHE_DIR"] = dir.DirPath,
            ["PSIGN_AUTHROOT_URL"] = "http://127.0.0.1:9/authrootstl.cab",
        };

        // Formats with an automatic trust command route to trust-verify-*; scripts and MSIX stay digest-only.
        Same(env, "verify", F("generated-signed/pe/tiny64-pe-alias.exe"));
        Same(env, "verify", F("generated-signed/cab/sample.cab"));
        Same(env, "verify", F("generated-signed/scripts/wsh/js/utf8-crlf.js"), F("generated-signed/msix/sample.msix"));
        Same(env, "verify", F("package-signing/signed/sample.signed.nupkg"));
        Same(env, "verify", "--additional-trusted-ca", F(TestCa), "--as-of", AsOf, F("generated-signed/pe/tiny64-pe-alias.exe"));
        Same(env, "verify", "--trusted-ca", F(TestCa), "--as-of", AsOf, F("generated-signed/msix/sample.msix"));
        Same(env, ["verify", .. PrivateTrust(PrivateTrustId), F("artifact-signing/private-trust/sample.js")]);
    }

    [SkippableFact]
    public void ResponseFilesMatchRust()
    {
        using var dir = new TempDir();
        var single = dir.File("single.rsp");
        File.WriteAllText(single, $"verify\n/q\n\"{F("generated-signed/pe/tiny64-pe-alias.exe")}\"\n");
        Same("@" + single);

        var batch = dir.File("batch.rsp");
        File.WriteAllText(batch, $"verify\n\"{F("generated-signed/pe/tiny64-pe-alias.exe")}\"\n\n\nverify\n/pa\n\"{F("generated-signed/cab/sample.cab")}\"\n\n\ninspect-signature\n\"{F("pe-authenticode-upstream/tiny64.signed.efi")}\"\n");
        Same("@" + batch);
    }
}
