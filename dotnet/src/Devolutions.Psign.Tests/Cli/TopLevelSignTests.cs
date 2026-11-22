using Devolutions.Psign.Cli;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.TopLevel;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Portable;
using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>
/// Managed-only tests for top-level <c>sign</c> / <c>timestamp</c> (ports of the Rust <c>portable_sign</c> unit tests,
/// <c>cert_store_cli.rs</c> portable-sign cases, <c>cli_verify_filters.rs</c> parse cases, and glob semantics).
/// </summary>
public class TopLevelSignTests : IClassFixture<SigningCliPki>
{
    private readonly SigningCliPki _pki;

    public TopLevelSignTests(SigningCliPki pki) => _pki = pki;

    private static ParsedCommand ParseSign(params string[] args) =>
        CommandLineParser.Parse(PsignTool.BuildRoot(), NativeArgv.Normalize(args), PsignTool.BinName).Leaf;

    // ------------------------------------------------------------------ argument parsing

    [Fact]
    public void SignAcceptsMultipleTrailingFilesAndNativeSwitches()
    {
        var args = SignCommand.Parse(ParseSign("sign", "/f", "a.pfx", "/p", "pw", "/fd", "SHA384", "/td", "CERTHASH", "/ac", "x.cer", "/ac", "y.cer", "/sa", "1.2.3", "v", "/s", "Root", "one.dll", "two.dll"));
        Assert.Equal("a.pfx", args.Pfx);
        Assert.Equal("pw", args.Password);
        Assert.Equal("sha384", args.Digest);
        Assert.Equal("cert-hash", args.TimestampDigest);
        Assert.Equal(["x.cer", "y.cer"], args.AdditionalCerts);
        Assert.Equal(["1.2.3", "v"], args.SignAuthPairs);
        Assert.Equal("Root", args.StoreName);
        Assert.Equal(["one.dll", "two.dll"], args.Files);
    }

    [Theory]
    [InlineData("azure")]
    [InlineData("azuresigntool")]
    public void SignAcceptsAzureSignToolExitCodeModes(string value)
    {
        var args = SignCommand.Parse(ParseSign("sign", "--f", "missing.pfx", "--fd", "sha256", "--exit-codes", value, "one.dll"));
        Assert.Equal("azuresigntool", args.ExitCodes);
    }

    [Fact]
    public void SignDefaultsAndInputListMakeFilesOptional()
    {
        var args = SignCommand.Parse(ParseSign("sign", "--ifl", "list.txt"));
        Assert.Equal("sha256", args.Digest);
        Assert.Equal("MY", args.StoreName);
        Assert.Empty(args.Files);
        Assert.Null(args.MaxDegreeParallelism);
        Assert.Equal(18446744073709551615UL, SignCommand.Parse(ParseSign("sign", "--mdop", "18446744073709551615", "x")).MaxDegreeParallelism);
    }

    [Fact]
    public void TimestampAcceptsMultipleTrailingFiles()
    {
        var args = TimestampCommand.Parse(ParseSign("timestamp", "/tr", "http://ts.example/rfc3161", "/td", "SHA256", "/tp", "2", "a.exe", "b.exe"));
        Assert.Equal("http://ts.example/rfc3161", args.Rfc3161Url);
        Assert.Equal("sha256", args.Digest);
        Assert.Equal(2u, args.SignatureIndex);
        Assert.Equal(["a.exe", "b.exe"], args.Files);
    }

    [Fact]
    public void ExitCodeSchemesFollowFlagThenEnvironment()
    {
        var none = new SignArgs();
        Assert.Equal("signtool", SignCommand.ResolvedSignExitCodes(none, _ => null));
        Assert.Equal("azuresigntool", SignCommand.ResolvedSignExitCodes(none, n => n == SignCommand.EnvExitCodes ? " Azure " : null));
        Assert.Equal("azuresigntool", SignCommand.ResolvedSignExitCodes(none, n => n == SignCommand.LegacyEnvExitCodes ? "AZURESIGNTOOL" : null));
        Assert.Equal("signtool", SignCommand.ResolvedSignExitCodes(none, n => n == SignCommand.EnvExitCodes ? "nope" : "azure"));
        Assert.Equal("signtool", SignCommand.ResolvedSignExitCodes(none with { ExitCodes = "signtool" }, _ => "azure"));

        Assert.Equal(0, SignCommand.BatchExitCode("signtool", 3, 0));
        Assert.Equal(1, SignCommand.BatchExitCode("signtool", 3, 1));
        Assert.Equal(0, SignCommand.BatchExitCode("azuresigntool", 2, 0));
        Assert.Equal(0x20000001, SignCommand.BatchExitCode("azuresigntool", 2, 1));
        Assert.Equal(unchecked((int)0xA0000002), SignCommand.BatchExitCode("azuresigntool", 0, 2));
        Assert.Equal(0, SignCommand.BatchExitCode("azuresigntool", 0, 0));
    }

    // ------------------------------------------------------------------ targets (Rust portable_sign unit tests)

    [Fact]
    public void DeduplicatesExistingPathAliases()
    {
        using var dir = new TempDir();
        var target = dir.File("target.ps1");
        File.WriteAllText(target, "Write-Output test");
        var alias = Path.Combine(dir.DirPath, ".", "target.ps1");
        var upper = Path.Combine(dir.DirPath, "TARGET.PS1");
        var targets = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        SignCommand.InsertSignTarget(target, targets, seen);
        SignCommand.InsertSignTarget(alias, targets, seen);
        if (OperatingSystem.IsWindows())
        {
            SignCommand.InsertSignTarget(upper, targets, seen);
        }

        Assert.Single(targets);
    }

    [Fact]
    public void TemporaryOutputPathsDoNotCollideForSameNamedTargets()
    {
        using var dir = new TempDir();
        var first = Path.Combine(dir.DirPath, "one", "target.ps1");
        var second = Path.Combine(dir.DirPath, "two", "target.ps1");
        var a = SignCommand.TemporaryOutputPath(first);
        Assert.NotEqual(a, SignCommand.TemporaryOutputPath(second));
        Assert.Equal(Path.Combine(dir.DirPath, "one"), Path.GetDirectoryName(a));
        Assert.Matches(@"^target\.psign-\d+-[0-9a-f]{16}\.ps1$", Path.GetFileName(a));
        Assert.Matches(@"^noext\.psign-\d+-[0-9a-f]{16}$", SignCommand.TemporaryOutputPath("noext"));
    }

    [Fact]
    public void PreservesRepeatedDirectTargetsAndRunsThemSequentially()
    {
        using var dir = new TempDir();
        var target = dir.File("target.exe");
        File.WriteAllText(target, "test");
        var args = SignCommand.Parse(ParseSign("sign", "--sha1", new string('A', 40), "--digest", "sha256", target, target));
        var targets = SignCommand.ExpandSignTargets(args);
        Assert.Equal([target, target], targets);
        Assert.True(SignCommand.HasDuplicateTargetIdentities(targets));
    }

    [Fact]
    public void GlobMatchesLikeRustGlobCrate()
    {
        using var dir = new TempDir();
        foreach (var name in new[] { "b.txt", "a.txt", "C.TXT", ".hidden.txt", "sub/x.txt", "sub/deep/y.txt", "sub/deep/z.log", "other/w.txt" })
        {
            var path = dir.File(name);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, name);
        }

        var root = dir.DirPath;
        string J(params string[] parts) => string.Join(Path.DirectorySeparatorChar, [root, .. parts]);

        Assert.Equal([J(".hidden.txt"), J("a.txt"), J("b.txt")], RustGlob.Expand(J("*.txt")));
        Assert.Equal([J("C.TXT")], RustGlob.Expand(J("*.TXT")));
        Assert.Equal([J("a.txt"), J("b.txt")], RustGlob.Expand(J("[ab].txt")));
        Assert.Equal([J("C.TXT")], RustGlob.Expand(J("[!ab].???")));
        Assert.Equal([J("other", "w.txt"), J("sub", "deep", "y.txt"), J("sub", "x.txt")], RustGlob.Expand(J("*", "**", "*.txt")));
        Assert.Equal([J(".hidden.txt"), J("a.txt"), J("b.txt"), J("other", "w.txt"), J("sub", "deep", "y.txt"), J("sub", "x.txt")], RustGlob.Expand(J("**", "*.txt")));
        Assert.Equal([J("sub", "deep")], RustGlob.Expand(J("s?b", "d*") + Path.DirectorySeparatorChar));
        Assert.Empty(RustGlob.Expand(J("missing", "*.txt")));

        // The literal root keeps its spelling; every later component is joined with the platform separator (Rust
        // `PathBuf::push`), so `C:/a/b/*.txt` yields `C:/a\b\x.txt` on Windows (checked against the Rust tool).
        var forward = root.Replace('\\', '/') + "/sub/*.txt";
        var expected = OperatingSystem.IsWindows() ? forward[..3] + root[3..] + "\\sub\\x.txt" : root + "/sub/x.txt";
        Assert.Equal([expected], RustGlob.Expand(forward));

        AssertPatternError("a***", "Pattern syntax error near position 3: wildcards are either regular `*` or recursive `**`");
        AssertPatternError("a**/b", "Pattern syntax error near position 0: recursive wildcards must form a single path component");
        AssertPatternError("**a", "Pattern syntax error near position 2: recursive wildcards must form a single path component");
        AssertPatternError("[a", "Pattern syntax error near position 0: invalid range pattern");
        AssertPatternError("x[!]", "Pattern syntax error near position 1: invalid range pattern");
    }

    private static void AssertPatternError(string pattern, string message)
    {
        var e = Assert.Throws<PsignException>(() => RustGlob.Expand(pattern));
        Assert.Equal(message, e.Message);
    }

    // ------------------------------------------------------------------ self-check guard

    private static PortableSignResponse FakeSignResponse(PortableSignatureStatus status) => new()
    {
        InputPath = "target.msix",
        OutputPath = "target.msix",
        Format = PortableFileFormat.Msix,
        Signature = new PortableSignatureResponse { Path = "target.msix", Format = PortableFileFormat.Msix, Status = status, StatusMessage = "test fixture", SignatureCount = 1 },
    };

    [Fact]
    public void EnsureValidSignatureResponseAcceptsValidStatus()
    {
        SignCommand.EnsureValidSignatureResponse(FakeSignResponse(PortableSignatureStatus.Valid), "target.msix");
        var skipped = FakeSignResponse(PortableSignatureStatus.Valid);
        skipped.Skipped = true;
        SignCommand.EnsureValidSignatureResponse(skipped, "target.msix");
    }

    [Fact]
    public void EnsureValidSignatureResponseRejectsHashMismatchEvenWhenSkipped()
    {
        var e = Assert.Throws<PsignException>(() => SignCommand.EnsureValidSignatureResponse(FakeSignResponse(PortableSignatureStatus.HashMismatch), "target.msix"));
        Assert.Equal("portable sign produced a signature that failed self-verification for 'target.msix': HashMismatch (test fixture)", e.Message);
        var skipped = FakeSignResponse(PortableSignatureStatus.HashMismatch);
        skipped.Skipped = true;
        Assert.Contains("HashMismatch", Assert.Throws<PsignException>(() => SignCommand.EnsureValidSignatureResponse(skipped, "target.msix")).Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ end to end (cert_store_cli.rs portable sign cases)

    private string Store(TempDir dir)
    {
        var store = dir.File("cert-store");
        var import = CliHarness.RunManaged("cert-store", "import", "--cert-store-dir", store, "--key", _pki.LeafKey, _pki.LeafCert);
        Assert.True(import.ExitCode == 0, import.Stderr);
        return store;
    }

    [Fact]
    public void CertStoreSha1SignsPeWithTheStoreIdentity()
    {
        using var dir = new TempDir();
        var store = Store(dir);
        var target = dir.File("signed.efi");
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.efi"), target);
        var r = CliHarness.RunManaged("--mode", "portable", "sign", "--cert-store-dir", store, "/sha1", _pki.LeafThumbprint, "/s", "MY", "/fd", "SHA256", target);
        Assert.True(r.ExitCode == 0, r.Stderr);
        Assert.Equal($"Signed: {target}\nthumbprint_sha1={_pki.LeafThumbprint}\nstore=CurrentUser\\MY\n", r.Stdout);
        var signed = File.ReadAllBytes(target);
        PeAuthenticode.VerifyDigestConsistency(signed);
        var sd = CmsSignedData.Parse(PeAuthenticode.FirstPkcs7(signed));
        Assert.Contains(sd.Certificates!, c => c.AsSpan().SequenceEqual(_pki.LeafDer));
    }

    [Fact]
    public void CertStoreSigningReplacesByDefaultAppendsWithFlagAndSkipsSigned()
    {
        using var dir = new TempDir();
        var store = Store(dir);
        var replaced = dir.File("replaced.efi");
        var appended = dir.File("appended.efi");
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"), replaced);
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"), appended);
        string[] id = ["sign", "--cert-store-dir", store, "--sha1", _pki.LeafThumbprint, "--fd", "SHA256"];
        Assert.Equal(0, CliHarness.RunManaged([.. id, replaced]).ExitCode);
        Assert.Single(PeAuthenticode.Pkcs7Blobs(File.ReadAllBytes(replaced)));
        Assert.Equal(0, CliHarness.RunManaged([.. id, "--append-signature", appended]).ExitCode);
        Assert.Equal(2, PeAuthenticode.Pkcs7Blobs(File.ReadAllBytes(appended)).Count);
        Assert.Equal(0, CliHarness.RunManaged([.. id, "--append-signature", appended, appended]).ExitCode);
        Assert.Equal(4, PeAuthenticode.Pkcs7Blobs(File.ReadAllBytes(appended)).Count);

        var before = File.ReadAllBytes(replaced);
        var skip = CliHarness.RunManaged([.. id, "--skip-signed", replaced]);
        Assert.Equal($"Skipped (already signed): {replaced}\n", skip.Stdout);
        Assert.Equal(before, File.ReadAllBytes(replaced));

        var corrupt = dir.File("corrupt.efi");
        var bytes = File.ReadAllBytes(Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi"));
        var ranges = PeAuthenticode.DigestFileRanges(bytes);
        bytes[ranges.Last(r => r.End > r.Start).Start] ^= 0x01;
        File.WriteAllBytes(corrupt, bytes);
        var failed = CliHarness.RunManaged([.. id, "--skip-signed", corrupt]);
        Assert.Equal(1, failed.ExitCode);
        Assert.StartsWith($"check existing PE/WinMD Authenticode signature on '{corrupt}'", failed.Stderr, StringComparison.Ordinal);
        Assert.Contains("mismatch", failed.Stderr, StringComparison.Ordinal);
        Assert.Equal(bytes, File.ReadAllBytes(corrupt));
    }

    [Fact]
    public void CertStoreErrorsMissingKeyAndUnsupportedFormats()
    {
        using var dir = new TempDir();
        var store = dir.File("store");
        Assert.Equal(0, CliHarness.RunManaged("cert-store", "import", "--cert-store-dir", store, _pki.LeafCert).ExitCode);
        var pe = dir.File("x.efi");
        File.Copy(Fixtures.Path("pe-authenticode-upstream/tiny32.efi"), pe);
        var missingKey = CliHarness.RunManaged("--mode", "portable", "sign", "--cert-store-dir", store, "--sha1", _pki.LeafThumbprint, pe);
        Assert.Equal(1, missingKey.ExitCode);
        Assert.Contains("private key", missingKey.Stderr, StringComparison.Ordinal);

        var txt = dir.File("plain.txt");
        File.WriteAllText(txt, "not a PE");
        var unsupported = CliHarness.RunManaged("sign", "--pfx", _pki.LeafPfx, "--password", SigningCliPki.PfxPassword, txt);
        Assert.Equal(1, unsupported.ExitCode);
        Assert.Contains("PE/WinMD", unsupported.Stderr, StringComparison.Ordinal);

        var cab = dir.File("sample.cab");
        File.Copy(Fixtures.Path("generated-unsigned/cab/sample.cab"), cab);
        var append = CliHarness.RunManaged("sign", "--pfx", _pki.LeafPfx, "--password", SigningCliPki.PfxPassword, "--append-signature", cab);
        Assert.Equal("--as/--append-signature is only supported for portable PE/WinMD signing\n", append.Stderr);
    }

    [Fact]
    public void PfxSignsCabAndPowerShellFromInputFileListInParallel()
    {
        using var dir = new TempDir();
        var cab = dir.File("sample.cab");
        var script = dir.File("sample.psd1");
        File.Copy(Fixtures.Path("generated-unsigned/cab/sample.cab"), cab);
        File.Copy(Fixtures.Path("unsigned-sample.psd1"), script);
        var list = dir.File("inputs.txt");
        File.WriteAllText(list, $"{cab}\n{script}\n");
        var r = CliHarness.RunManaged("--mode", "portable", "sign", "--pfx", _pki.LeafPfx, "--password", SigningCliPki.PfxPassword, "--input-file-list", list, "--max-degree-of-parallelism", "2", "--exit-codes", "azure");
        Assert.True(r.ExitCode == 0, r.Stderr);
        Assert.Equal($"Signed: {cab}\npfx={_pki.LeafPfx}\n\nSigned: {script}\npfx={_pki.LeafPfx}\n", r.Stdout);
        CabDigest.SignaturePkcs7Der(File.ReadAllBytes(cab));
        Assert.Contains("# SIG # Begin signature block", File.ReadAllText(script), StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(dir.DirPath, "*.psign-*"));
    }

    [Fact]
    public void ContinueOnErrorReportsFailuresInInputOrderWithAzureExitCodes()
    {
        using var dir = new TempDir();
        var cab = dir.File("sample.cab");
        File.Copy(Fixtures.Path("generated-unsigned/cab/sample.cab"), cab);
        var txt = dir.File("unsupported.txt");
        File.WriteAllText(txt, "x");
        var r = CliHarness.RunManaged("sign", "--pfx", _pki.LeafPfx, "--password", SigningCliPki.PfxPassword, "--continue-on-error", "--exit-codes", "azure", txt, cab);
        Assert.Equal(0x20000001, r.ExitCode);
        Assert.StartsWith($"Failed: {txt}: portable native-shaped signing supports", r.Stdout, StringComparison.Ordinal);
        Assert.EndsWith($"\n\nSigned: {cab}\npfx={_pki.LeafPfx}\n", r.Stdout, StringComparison.Ordinal);

        var all = CliHarness.RunManaged(new Dictionary<string, string?> { ["PSIGN_EXIT_CODES"] = "azure" }, "sign", "--pfx", _pki.LeafPfx, "--continue-on-error", txt);
        Assert.Equal(unchecked((int)0xA0000002), all.ExitCode);
    }

    [Fact]
    public void TimestampRejectsUnsupportedModesAndNonPeInputs()
    {
        void Reject(string expected, params string[] args)
        {
            var r = CliHarness.RunManaged(args);
            Assert.NotEqual(0, r.ExitCode);
            Assert.Contains(expected, r.Stderr, StringComparison.Ordinal);
        }

        Reject("legacy", "--mode", "portable", "timestamp", "--legacy-url", "http://tsa.example/legacy", "missing.exe");
        Reject("sealing", "--mode", "portable", "timestamp", "--seal-timestamp-url", "http://tsa.example/sealed", "missing.exe");
        Reject("timestamp-pkcs7", "--mode", "portable", "timestamp", "--rfc3161-url", "http://tsa.example/rfc3161", "--digest", "sha256", "--timestamp-pkcs7-files", "missing.p7");
        Reject("signature-index", "--mode", "portable", "timestamp", "--rfc3161-url", "http://tsa.example/rfc3161", "--digest", "sha256", "--signature-index", "1", "missing.exe");
        using var dir = new TempDir();
        var nonPe = dir.File("not-a-pe.txt");
        File.WriteAllText(nonPe, "not a PE");
        Reject("only PE/WinMD", "--mode", "portable", "timestamp", "--rfc3161-url", "http://tsa.example/rfc3161", "--digest", "sha256", nonPe);
    }
}
