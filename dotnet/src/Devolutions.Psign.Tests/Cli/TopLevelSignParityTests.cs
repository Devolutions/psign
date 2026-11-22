using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Signing.Cms;
using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>
/// Managed vs Rust top-level <c>psign-tool sign</c> / <c>timestamp</c> in portable mode. Each scenario copies its fixtures into
/// two identical directories (one per tool, since signing mutates files in place) and compares exit codes, stdout / stderr
/// (with the directory and the per-process temporary output names normalized) and the signed bytes. MSI/MSP containers
/// are compared through their signature streams (the OLE layout differs). TSA, Azure Key Vault and Artifact Signing are
/// served by a local mock shared by both tools; no real network access is used.
/// </summary>
public partial class TopLevelSignParityTests : IClassFixture<SigningCliPki>
{
    private const string UnsignedPeDll = "generated-unsigned/pe/tiny64-pe-alias.dll";
    private const string UnsignedPe32Dll = "generated-unsigned/pe/tiny32-pe-alias.dll";
    private const string UnsignedEfi = "pe-authenticode-upstream/tiny32.efi";
    private const string SignedEfi = "pe-authenticode-upstream/tiny32.signed.efi";
    private const string UnsignedCab = "generated-unsigned/cab/sample.cab";
    private const string UnsignedMsi = "generated-unsigned/installer/tiny.msi";
    private const string UnsignedMsp = "generated-unsigned/installer/tiny-patch.msp";
    private const string UnsignedPsd1 = "unsigned-sample.psd1";
    private const string UnsignedPs1 = "unsigned-sample.ps1";
    private const string UnsignedMsix = "generated-unsigned/msix/sample.msix";
    private const string UnsignedAppx = "generated-unsigned/msix/sample.appx";
    private const string UnsignedMsixBundle = "generated-unsigned/msix/sample.msixbundle";
    private const string UnsignedAppInstaller = "generated-unsigned/appinstaller/sample.appinstaller";
    private const string UnsignedZip = "zip-authenticode/unsigned/sample.zip";
    private const string UnsignedNupkg = "package-signing/unsigned/sample.nupkg";
    private const string UnsignedVsix = "package-signing/unsigned/sample.vsix";
    private const string UnsignedVbs = "unsigned-sample.vbs";

    private readonly SigningCliPki _pki;

    public TopLevelSignParityTests(SigningCliPki pki) => _pki = pki;

    // ------------------------------------------------------------------ harness

    private static readonly IReadOnlyDictionary<string, string?> NoEnv = new Dictionary<string, string?>();

    private static CliResult RunRust(IReadOnlyDictionary<string, string?> env, params string[] args)
    {
        var psi = new ProcessStartInfo(RustTool.Require())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment["PSIGN_TOOL_MODE"] = "portable";
        psi.Environment["NO_PROXY"] = "127.0.0.1,localhost";
        psi.Environment.Remove("SIGNTOOL_PORTABLE_DEBUG");
        psi.Environment.Remove("PSIGN_EXIT_CODES");
        psi.Environment.Remove("SIGNTOOL_RS_EXIT_CODES");
        foreach (var (k, v) in env)
        {
            if (v is null)
            {
                psi.Environment.Remove(k);
            }
            else
            {
                psi.Environment[k] = v;
            }
        }

        using var p = Process.Start(psi)!;
        p.StandardInput.Close();
        using var ms = new MemoryStream();
        var copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        copy.Wait();
        return new CliResult(p.ExitCode, ms.ToArray(), stderr);
    }

    private static CliResult RunManaged(IReadOnlyDictionary<string, string?> env, params string[] args)
    {
        var merged = new Dictionary<string, string?> { ["PSIGN_EXIT_CODES"] = null, ["SIGNTOOL_RS_EXIT_CODES"] = null };
        foreach (var (k, v) in env)
        {
            merged[k] = v;
        }

        return CliHarness.RunManaged(merged, args);
    }

    [GeneratedRegex(@"\.psign-\d+-[0-9a-f]{16}")]
    private static partial Regex TempOutputName();

    private static string Normalize(string text, string dir)
    {
        text = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace(dir, "{dir}", StringComparison.Ordinal);
        if (OperatingSystem.IsWindows())
        {
            // Glob results of `C:/...` patterns spell the root with `/` and the rest with the platform separator.
            text = text.Replace(dir[..3].Replace('\\', '/') + dir[3..], "{dir}", StringComparison.Ordinal);
        }

        return TempOutputName().Replace(text, ".psign-{tmp}");
    }

    /// <summary>Two identical working directories populated with the given fixtures (file name = fixture file name).</summary>
    private sealed class Workspace : IDisposable
    {
        private readonly TempDir _root = new();

        public Workspace(params string[] fixtures)
        {
            RustDir = Path.Combine(_root.DirPath, "rs");
            ManagedDir = Path.Combine(_root.DirPath, "cs");
            Directory.CreateDirectory(RustDir);
            Directory.CreateDirectory(ManagedDir);
            foreach (var fixture in fixtures)
            {
                Add(Path.GetFileName(fixture), Fixtures.Bytes(fixture));
            }
        }

        public string RustDir { get; }

        public string ManagedDir { get; }

        public string Scratch => _root.DirPath;

        /// <summary>Files whose content embeds the tool directory (not compared).</summary>
        public HashSet<string> Generated { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void Add(string relative, byte[] bytes)
        {
            foreach (var dir in new[] { RustDir, ManagedDir })
            {
                var path = Path.Combine(dir, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllBytes(path, bytes);
            }
        }

        public void AddText(string relative, Func<string, string> text)
        {
            Generated.Add(relative.Replace('/', Path.DirectorySeparatorChar));
            foreach (var dir in new[] { RustDir, ManagedDir })
            {
                var path = Path.Combine(dir, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, text(dir));
            }
        }

        public void Dispose() => _root.Dispose();
    }

    /// <summary>Run <paramref name="args"/> (given the tool's directory) with both tools and compare everything.</summary>
    private static (CliResult Rust, CliResult Managed) Same(Workspace ws, Func<string, string[]> args, IReadOnlyDictionary<string, string?>? env = null, string[]? skipCompare = null)
    {
        env ??= NoEnv;
        var rust = RunRust(env, args(ws.RustDir));
        var managed = RunManaged(env, args(ws.ManagedDir));
        var line = string.Join(' ', args("{dir}"));
        Assert.True(rust.ExitCode == managed.ExitCode, $"exit code mismatch for {line}: rust={rust.ExitCode} managed={managed.ExitCode}\nrust stdout: {rust.Stdout}\nrust stderr: {rust.Stderr}\nmanaged stdout: {managed.Stdout}\nmanaged stderr: {managed.Stderr}");
        Assert.Equal(Normalize(rust.Stdout, ws.RustDir), Normalize(managed.Stdout, ws.ManagedDir));
        Assert.Equal(Normalize(rust.Stderr, ws.RustDir), Normalize(managed.Stderr, ws.ManagedDir));
        AssertSameTree(ws, skipCompare ?? []);
        return (rust, managed);
    }

    /// <summary>Both directories hold the same files; byte-identical except MSI/MSP (same signature streams).</summary>
    private static void AssertSameTree(Workspace ws, params string[] nondeterministic)
    {
        var rustFiles = Directory.GetFiles(ws.RustDir, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(ws.RustDir, f)).Order(StringComparer.Ordinal).ToList();
        var managedFiles = Directory.GetFiles(ws.ManagedDir, "*", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(ws.ManagedDir, f)).Order(StringComparer.Ordinal).ToList();
        Assert.Equal(rustFiles, managedFiles);
        foreach (var rel in rustFiles)
        {
            var r = File.ReadAllBytes(Path.Combine(ws.RustDir, rel));
            var m = File.ReadAllBytes(Path.Combine(ws.ManagedDir, rel));
            var ext = Path.GetExtension(rel).ToLowerInvariant();
            if (ws.Generated.Contains(rel))
            {
                continue;
            }

            if (ext is ".msi" or ".msp")
            {
                Assert.Equal(MsiSignature(r), MsiSignature(m));
            }
            else if (!nondeterministic.Contains(ext))
            {
                Assert.True(r.AsSpan().SequenceEqual(m), $"{rel} differs between the Rust and managed outputs");
            }
        }
    }

    private static string MsiSignature(byte[] msi)
    {
        try
        {
            return Hex.Lower(MsiDigest.DigitalSignaturePkcs7Der(msi));
        }
        catch (PsignException)
        {
            return "unsigned:" + Hex.Lower(SHA256.HashData(msi));
        }
    }

    /// <summary>clap usage errors: exit code 2 and the same <c>error:</c> line.</summary>
    private static void SameUsageError(params string[] args)
    {
        var rust = RunRust(NoEnv, args);
        var managed = RunManaged(NoEnv, args);
        Assert.Equal(2, rust.ExitCode);
        Assert.Equal(2, managed.ExitCode);
        Assert.Equal(rust.Stderr.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n')[0], managed.Stderr.Split('\n')[0]);
        Assert.Equal(rust.Stdout, managed.Stdout);
    }

    private static string In(string dir, string name) => Path.Combine(dir, name);

    private static void AssertSigned(CliResult result, int count)
    {
        Assert.True(result.ExitCode == 0, result.Stderr);
        Assert.Equal(count, Regex.Count(result.Stdout, "^Signed: ", RegexOptions.Multiline));
    }

    private string[] Pfx() => ["--pfx", _pki.LeafPfx, "--password", SigningCliPki.PfxPassword];

    private string ImportToStore(string storeDir)
    {
        var import = RunManaged(NoEnv, "cert-store", "import", "--cert-store-dir", storeDir, "--key", _pki.LeafKey, _pki.LeafCert);
        Assert.True(import.ExitCode == 0, import.Stderr);
        return _pki.LeafThumbprint;
    }

    // ------------------------------------------------------------------ local PFX

    [SkippableFact]
    public void NativeArgvPfxBatchMatchesRust()
    {
        RustTool.Require();
        using var ws = new Workspace(UnsignedPeDll, UnsignedPe32Dll, UnsignedEfi, UnsignedCab, UnsignedMsi, UnsignedMsp, UnsignedPsd1, UnsignedPs1, UnsignedMsix, UnsignedAppx, UnsignedMsixBundle, UnsignedAppInstaller, UnsignedZip);
        string[] names = ["tiny64-pe-alias.dll", "tiny32-pe-alias.dll", "tiny32.efi", "sample.cab", "tiny.msi", "tiny-patch.msp", "unsigned-sample.psd1", "unsigned-sample.ps1", "sample.msix", "sample.appx", "sample.msixbundle", "sample.appinstaller", "sample.zip"];
        var (batch, _) = Same(ws, d => ["sign", "/fd", "SHA256", "/f", _pki.LeafPfx, "/p", SigningCliPki.PfxPassword, "/ac", _pki.CaCert, .. names.Select(n => In(d, n))]);
        AssertSigned(batch, names.Length);
        Assert.True(File.Exists(In(ws.ManagedDir, "sample.appinstaller.p7")));
        PeAuthenticode.VerifyDigestConsistency(File.ReadAllBytes(In(ws.ManagedDir, "tiny64-pe-alias.dll")));
        CabDigest.VerifyDigestConsistency(In(ws.ManagedDir, "sample.cab"));
        MsiDigest.VerifyDigestConsistency(In(ws.ManagedDir, "tiny.msi"));
        MsixDigest.VerifyMsixDigestConsistency(In(ws.ManagedDir, "sample.msixbundle"));
        Assert.Equal(0, RunRust(NoEnv, "portable", "verify-msi", In(ws.ManagedDir, "tiny-patch.msp")).ExitCode);
        Assert.Equal(0, RunRust(NoEnv, "portable", "verify-script", In(ws.ManagedDir, "unsigned-sample.ps1")).ExitCode);
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("SHA384")]
    [InlineData("sha512")]
    public void PfxDigestsAndQuietDebugMatchRust(string digest)
    {
        RustTool.Require();
        using var ws = new Workspace(UnsignedPeDll, UnsignedCab);
        Same(ws, d => ["sign", .. Pfx(), "--digest", digest, "--additional-certs", _pki.CaCert, In(d, "tiny64-pe-alias.dll")]);
        Same(ws, d => ["-q", "sign", .. Pfx(), "--fd", digest, In(d, "sample.cab")]);
        Same(ws, d => ["sign", "--debug", .. Pfx(), "--fd", digest, "--mdop", "1", In(d, "tiny64-pe-alias.dll"), In(d, "sample.cab")]);
        Same(ws, d => ["/q", "sign", "/debug", .. Pfx(), "--fd", digest, In(d, "sample.cab")]);
    }

    [SkippableFact]
    public void PackageFormatsSignLikeRust()
    {
        RustTool.Require();
        using var ws = new Workspace(UnsignedNupkg, UnsignedVsix);
        // NuGet / VSIX signatures embed the signing time, so only the stdout and verifiability are compared.
        var rust = RunRust(NoEnv, ["sign", .. Pfx(), "--mdop", "1", In(ws.RustDir, "sample.nupkg"), In(ws.RustDir, "sample.vsix")]);
        var managed = RunManaged(NoEnv, ["sign", .. Pfx(), "--mdop", "1", In(ws.ManagedDir, "sample.nupkg"), In(ws.ManagedDir, "sample.vsix")]);
        Assert.True(rust.ExitCode == 0, rust.Stderr);
        Assert.True(managed.ExitCode == 0, managed.Stderr);
        Assert.Equal(Normalize(rust.Stdout, ws.RustDir), Normalize(managed.Stdout, ws.ManagedDir));
        AssertSameTree(ws, ".nupkg", ".vsix");
        foreach (var (cmd, file) in new[] { ("trust-verify-nupkg", "sample.nupkg"), ("trust-verify-vsix", "sample.vsix") })
        {
            var verify = RunRust(NoEnv, "portable", cmd, "--trusted-ca", _pki.CaCert, In(ws.ManagedDir, file));
            Assert.True(verify.ExitCode == 0, $"{cmd}: {verify.Stdout}{verify.Stderr}");
        }

        // ClickOnce manifests (deterministic) and malformed ones (identical errors).
        ws.Add("app.exe.manifest", Encoding.UTF8.GetBytes(ClickOnceManifest));
        ws.Add("app.application", Encoding.UTF8.GetBytes(ClickOnceManifest));
        ws.Add("probe.manifest", Fixtures.Bytes("generated-unsigned/optional-provider/probe.manifest"));
        Same(ws, d => ["sign", .. Pfx(), "--fd", "sha384", "--coe", In(d, "app.exe.manifest"), In(d, "app.application"), In(d, "probe.manifest")], skipCompare: [".nupkg", ".vsix"]);
    }

    private const string ClickOnceManifest =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n  <assemblyIdentity name=\"ClickOnce.Sample\" version=\"1.0.0.0\" />\n  <description asmv2:publisher=\"Example\" xmlns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" />\n</assembly>";

    [SkippableFact]
    public void AppendSkipSignedAndRepeatedTargetsMatchRust()
    {
        RustTool.Require();
        using var ws = new Workspace(SignedEfi, UnsignedEfi);
        // Skip-signed: the signed fixture is skipped, the unsigned one signed.
        Same(ws, d => ["sign", .. Pfx(), "--skip-signed", In(d, "tiny32.signed.efi"), In(d, "tiny32.efi")]);

        // Repeated direct targets are operations (sequential): appending twice adds two signatures.
        Same(ws, d => ["sign", .. Pfx(), "--as", In(d, "tiny32.efi"), In(d, "tiny32.efi")]);
        Assert.Equal(3, PeAuthenticode.Pkcs7Blobs(File.ReadAllBytes(In(ws.ManagedDir, "tiny32.efi"))).Count);

        // Default replaces existing signatures.
        Same(ws, d => ["sign", .. Pfx(), "/fd", "sha384", In(d, "tiny32.signed.efi")]);
        Assert.Single(PeAuthenticode.Pkcs7Blobs(File.ReadAllBytes(In(ws.ManagedDir, "tiny32.signed.efi"))));

        // Corrupt existing signature with --skip-signed fails without modifying the file.
        var corrupt = Fixtures.Bytes(SignedEfi);
        corrupt[0x40] ^= 0x01;
        ws.Add("corrupt.efi", corrupt);
        Same(ws, d => ["sign", .. Pfx(), "--skip-signed", In(d, "corrupt.efi")]);
        Assert.Equal(corrupt, File.ReadAllBytes(In(ws.ManagedDir, "corrupt.efi")));

        // Append is PE-only.
        ws.Add("sample.cab", Fixtures.Bytes(UnsignedCab));
        Same(ws, d => ["sign", .. Pfx(), "/as", In(d, "sample.cab")]);
        Same(ws, d => ["sign", .. Pfx(), "--skip-signed", In(d, "sample.cab")]);
        Same(ws, d => ["sign", .. Pfx(), "--skip-signed", In(d, "sample.cab")]);
    }

    // ------------------------------------------------------------------ certificate store

    [SkippableFact]
    public void CertStoreSha1SigningMatchesRust()
    {
        RustTool.Require();
        using var ws = new Workspace(UnsignedPeDll, UnsignedCab, UnsignedPsd1);
        var store = Path.Combine(ws.Scratch, "store");
        var thumb = ImportToStore(store);
        var (storeSign, _) = Same(ws, d => ["sign", "--cert-store-dir", store, "/sha1", thumb, "/s", "MY", "/fd", "SHA256", In(d, "tiny64-pe-alias.dll"), In(d, "sample.cab")]);
        AssertSigned(storeSign, 2);
        Assert.Contains($"thumbprint_sha1={thumb}\nstore=CurrentUser\\MY\n", storeSign.Stdout, StringComparison.Ordinal);
        var colon = string.Join(':', Enumerable.Range(0, thumb.Length / 2).Select(i => thumb.Substring(i * 2, 2).ToLowerInvariant()));
        Same(ws, d => ["sign", "--cert-store-dir", store, "--cert-sha1", colon, "--store-name", "my", In(d, "unsigned-sample.psd1")]);

        // Missing certificate / scope / private key and malformed thumbprints.
        Same(ws, d => ["sign", "--cert-store-dir", store, "--sha1", thumb, "--sm", In(d, "sample.cab")]);
        Same(ws, d => ["sign", "--cert-store-dir", store, "--sha1", new string('A', 40), In(d, "sample.cab")]);
        Same(ws, d => ["sign", "--cert-store-dir", store, "--sha1", "zz", In(d, "sample.cab")]);
        File.Delete(Path.Combine(store, "CurrentUser", "MY", thumb + ".key"));
        Same(ws, d => ["sign", "--cert-store-dir", store, "--sha1", thumb, In(d, "sample.cab")]);
        Same(ws, d => ["sign", In(d, "sample.cab")]);
    }

    // ------------------------------------------------------------------ targets: globs, input lists, batches

    [SkippableFact]
    public void GlobsInputListsAndDeduplicationMatchRust()
    {
        RustTool.Require();
        using var ws = new Workspace();
        ws.Add("a.ps1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("B.ps1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("c.PS1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("sub/d.ps1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("sub/deeper/e.ps1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("x1.dll", Fixtures.Bytes(UnsignedPeDll));
        ws.Add("x2.dll", Fixtures.Bytes(UnsignedPe32Dll));

        // Case-sensitive single-level glob (c.PS1 does not match), name-ordered output.
        AssertSigned(Same(ws, d => ["sign", .. Pfx(), In(d, "*.ps1")]).Rust, 2);
        // Recursive glob, character class, `?`, and a duplicate pattern deduplicated against earlier matches. Re-signing
        // the already signed a.ps1 / B.ps1 fails the Rust script self-check (HashMismatch); the port reproduces it.
        Same(ws, d => ["sign", .. Pfx(), "--mdop", "3", In(d, "**/*.ps1"), In(d, "x?.dll"), In(d, "[x]1.dll")]);
        Same(ws, d => ["sign", .. Pfx(), "--coe", "--mdop", "3", In(d, "**/*.ps1"), In(d, "x?.dll"), In(d, "[x]1.dll")]);

        // Input file list: comments, blanks, trimming, globs, duplicates (including an alias spelling).
        ws.Add("list/f.ps1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("list/g.ps1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("list/h.dll", Fixtures.Bytes(UnsignedPeDll));
        ws.AddText("list.txt", d => $"# comment\n\n  {In(d, "x1.dll")}  \r\n{In(d, "x*.dll")}\n{Path.Combine(d, ".", "x1.dll")}\n{In(d, "list/*.ps1")}\n");
        AssertSigned(Same(ws, d => ["sign", .. Pfx(), "--ifl", In(d, "list.txt"), In(d, "list/h.dll")]).Rust, 5);
        // --skip-signed only inspects PE/CAB/MSI/MSIX, so the signed scripts are re-signed (and hit the same self-check failure).
        Same(ws, d => ["sign", .. Pfx(), "--input-file-list", In(d, "list.txt"), "--max-degree-of-parallelism", "1", "--skip-signed", "--coe"]);

        // No matches, invalid patterns, missing list.
        Same(ws, d => ["sign", .. Pfx(), In(d, "*.nothing")]);
        Same(ws, d => ["sign", .. Pfx(), "--skip-signed", d.Replace('\\', '/') + "/x*.dll", d.Replace('\\', '/') + "/**/h.dll"]);
        Same(ws, d => ["sign", .. Pfx(), In(d, "***.ps1")]);
        Same(ws, d => ["sign", .. Pfx(), In(d, "a**.ps1")]);
        Same(ws, d => ["sign", .. Pfx(), In(d, "[*.ps1")]);
        Same(ws, d => ["sign", .. Pfx(), "--ifl", In(d, "missing.txt")]);
        ws.Add("bad.txt", [0xff, 0xfe, 0x00]);
        Same(ws, d => ["sign", .. Pfx(), "--ifl", In(d, "bad.txt")]);
        ws.AddText("empty.txt", _ => "# nothing\n");
        Same(ws, d => ["sign", .. Pfx(), "--ifl", In(d, "empty.txt")]);
    }

    [SkippableFact]
    public void ContinueOnErrorAndExitCodeSchemesMatchRust()
    {
        RustTool.Require();
        using var ws = new Workspace(UnsignedPeDll, UnsignedCab, UnsignedVbs);
        ws.Add("plain.txt", "not signable"u8.ToArray());
        ws.Add("tiny.cat", [0x30, 0x00]);
        ws.Add("pkg.emsix", [0x50, 0x4b]);
        ws.Add("pkg.msixupload", [0x50, 0x4b]);
        Func<string, string[]> targets = d =>
            [In(d, "tiny64-pe-alias.dll"), In(d, "plain.txt"), In(d, "sample.cab"), In(d, "unsigned-sample.vbs"), In(d, "tiny.cat"), In(d, "pkg.emsix"), In(d, "pkg.msixupload"), In(d, "missing.dll")];

        // Without --continue-on-error every target is attempted, the first error is reported.
        Same(ws, d => ["sign", .. Pfx(), .. targets(d)]);
        Same(ws, d => ["sign", .. Pfx(), "--coe", .. targets(d)]);
        Same(ws, d => ["sign", .. Pfx(), "--continue-on-error", "--exit-codes", "azure", .. targets(d)]);
        Same(ws, d => ["sign", .. Pfx(), "--continue-on-error", "--exit-codes", "signtool", In(d, "plain.txt")], new Dictionary<string, string?> { ["PSIGN_EXIT_CODES"] = "azure" });
        Same(ws, d => ["sign", .. Pfx(), "--continue-on-error", In(d, "plain.txt"), In(d, "missing.dll")], new Dictionary<string, string?> { ["PSIGN_EXIT_CODES"] = " AzureSignTool " });
        Same(ws, d => ["sign", .. Pfx(), "--continue-on-error", In(d, "plain.txt")], new Dictionary<string, string?> { ["SIGNTOOL_RS_EXIT_CODES"] = "azure" });
        Same(ws, d => ["sign", .. Pfx(), "--continue-on-error", In(d, "plain.txt")], new Dictionary<string, string?> { ["PSIGN_EXIT_CODES"] = "other" });
        Same(ws, d => ["sign", .. Pfx(), "--coe", "--exit-codes", "azuresigntool", In(d, "sample.cab")]);
        Same(ws, d => ["-q", "sign", .. Pfx(), "--coe", "--exit-codes", "azure", In(d, "plain.txt"), In(d, "sample.cab")]);
    }

    // ------------------------------------------------------------------ option validation

    [SkippableFact]
    public void UnsupportedOptionsAndValidationErrorsMatchRust()
    {
        RustTool.Require();
        using var ws = new Workspace(UnsignedCab);
        string[][] rejected =
        [
            ["--fd", "sha1"], ["--fd", "certHash"], ["/fd", "CERTHASH"], ["--sha1", "AA"], ["--a"], ["--n", "Subject"], ["--i", "Issuer"],
            ["--csp", "x"], ["--kc", "c"], ["--ph"], ["--nph"], ["--dlib", "x.dll"], ["--trusted-signing-dlib-root", "root"],
            ["--tr", "http://127.0.0.1:9/"], ["--td", "sha256"], ["--t", "http://127.0.0.1:9/"], ["/tseal", "http://127.0.0.1:9/"],
            ["/d", "desc"], ["/du", "https://example.invalid"], ["/r", "Root"], ["/u", "1.3.6.1.5.5.7.3.3"], ["/uw"],
            ["--signing-cert-eku-prefix", "1.3"], ["/dg", "dir"], ["/ds"], ["/di", "x.p7"], ["/dxml"], ["/p7", "dir"], ["/p7co", "1.2.3"],
            ["--p7ce", "embedded"], ["/c", "Template"], ["/sa", "1.2.3", "value"], ["/fdchw"], ["/tdchw"], ["/rmc"], ["/seal"], ["/itos"],
            ["/force"], ["/nosealwarn"], ["/noenclavewarn"], ["/rust-sip", "PE"], ["--azure-key-vault-credential-type", "default", "--kvu", " "],
            ["--mdop", "0"], ["--d", " "], ["--kvu", "https://kv.example", "--artifact-signing-region", "r"],
        ];
        foreach (var extra in rejected)
        {
            Same(ws, d => ["sign", .. Pfx(), .. extra, In(d, "sample.cab")]);
        }

        Same(ws, d => ["sign", "--p", "pw", In(d, "sample.cab")]);
        Same(ws, d => ["sign", "--f", _pki.LeafPfx, "--p", "wrong", In(d, "sample.cab")]);
        Same(ws, d => ["sign", "--f", Path.Combine(d, "missing.pfx"), In(d, "sample.cab")]);
        Same(ws, d => ["--mode", "portable", "sign", .. Pfx(), "--fd", "sha512", "--rust-sip", "off", In(d, "sample.cab")]);

        SameUsageError("sign");
        SameUsageError("sign", "--sign-auth", "1.2.3");
        SameUsageError("sign", "--fd", "md5", "x.exe");
        SameUsageError("sign", "--exit-codes", "AZURE", "x.exe");
        SameUsageError("sign", "--p7ce", "DetachedSignedData", "x.exe");
        SameUsageError("sign", "--tr", "a", "--t", "b", "x.exe");
        SameUsageError("sign", "--trusted-signing-dlib-root", "a", "--dlib", "b", "x.exe");
        SameUsageError("sign", "--mdop", "-1", "x.exe");
        SameUsageError("sign", "--mdop", "x", "x.exe");
        SameUsageError("sign", "--azure-key-vault-credential-type", "bogus", "x.exe");
        SameUsageError("timestamp");
        SameUsageError("timestamp", "--td", "md5", "x.exe");
        SameUsageError("timestamp", "--tp", "4294967296", "x.exe");
        SameUsageError("timestamp", "--tr", "a", "--tseal", "b", "x.exe");

        var windows = RunManaged(NoEnv, "--mode", "windows", "sign", "x.exe");
        Assert.Equal(1, windows.ExitCode);
        Assert.Contains("--mode windows requires the native psign-tool", windows.Stderr, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ RFC 3161 (local mock TSA)

    private byte[] TsaToken(byte[] messageImprintTlv, byte[]? nonceTlv)
    {
        var parts = new List<byte[]>
        {
            new byte[] { 0x02, 0x01, 0x01 },
            Der.EncodeOid("1.3.6.1.4.1.601.10.3.1"),
            messageImprintTlv,
            new byte[] { 0x02, 0x03, 0x00, 0xbe, 0xef },
            Der.EncodeTlv(0x18, "20251122103000Z"u8),
        };
        if (nonceTlv is not null)
        {
            parts.Add(nonceTlv);
        }

        var tstinfo = Der.EncodeSequence([.. parts]);
        return Pkcs7Builder.CreateSignedData(Oids.TstInfo, Der.EncodeTlv(0x04, tstinfo), AuthenticodeHashKind.Sha256, _pki.TsaInfo, [], _pki.TsaRsa);
    }

    private LocalHttpResponse TsaHandler(LocalHttpRequest req)
    {
        if (req.Path == "/fail")
        {
            return new LocalHttpResponse(500, "tsa down"u8.ToArray(), "text/plain");
        }

        var der = req.Body;
        var outer = Der.First(der)!.Value;
        var kids = Der.Children(der, outer)!;
        var imprint = kids[1].Encoded(der).ToArray();
        byte[]? nonce = kids.Count > 2 && kids[2].Tag == 0x02 ? kids[2].Encoded(der).ToArray() : null;
        var token = TsaToken(imprint, nonce);
        return new LocalHttpResponse(200, Der.EncodeSequence(Der.EncodeSequence([0x02, 0x01, 0x00]), token), "application/timestamp-reply");
    }

    [SkippableFact]
    public void SignWithTimestampMatchesRust()
    {
        RustTool.Require();
        using var server = new LocalHttpServer(TsaHandler);
        using var ws = new Workspace(UnsignedPeDll, UnsignedCab, UnsignedMsix, UnsignedPsd1, UnsignedMsi);
        var tsa = server.BaseUrl + "/tsa";
        AssertSigned(Same(ws, d => ["sign", "/fd", "sha256", "/f", _pki.LeafPfx, "/p", SigningCliPki.PfxPassword, "/tr", tsa, "/td", "SHA256", "--mdop", "1", In(d, "tiny64-pe-alias.dll"), In(d, "sample.cab"), In(d, "sample.msix"), In(d, "unsigned-sample.psd1"), In(d, "tiny.msi")]).Rust, 5);
        var sd = CmsSignedData.Parse(PeAuthenticode.NthPkcs7(File.ReadAllBytes(In(ws.ManagedDir, "tiny64-pe-alias.dll")), 0));
        Assert.NotNull(sd.SignerInfos[0].GetUnsignedAttribute(Oids.MsRfc3161TimestampToken));
        Same(ws, d => ["sign", .. Pfx(), "--timestamp-url", " " + tsa + " ", "--timestamp-digest", "sha384", In(d, "sample.cab")]);
        Same(ws, d => ["sign", .. Pfx(), "--timestamp-url", server.BaseUrl + "/fail", "--timestamp-digest", "sha256", In(d, "sample.cab")]);
        Same(ws, d => ["sign", .. Pfx(), "--timestamp-url", tsa, "--timestamp-digest", "cert-hash", In(d, "sample.cab")]);
    }

    [SkippableFact]
    public void TimestampCommandMatchesRust()
    {
        RustTool.Require();
        using var server = new LocalHttpServer(TsaHandler);
        using var ws = new Workspace(UnsignedPeDll, UnsignedEfi, UnsignedCab);
        var tsa = server.BaseUrl + "/tsa";
        Same(ws, d => ["sign", .. Pfx(), In(d, "tiny64-pe-alias.dll"), In(d, "tiny32.efi")]);
        var (stamped, _) = Same(ws, d => ["timestamp", "/tr", tsa, "/td", "sha256", In(d, "tiny64-pe-alias.dll"), In(d, "tiny32.efi")]);
        Assert.Equal(0, stamped.ExitCode);
        Assert.Equal(2, Regex.Count(stamped.Stdout, "timestamp-pe-rfc3161: ok"));
        Same(ws, d => ["timestamp", "--rfc3161-url", tsa, "--digest", "SHA512", In(d, "tiny32.efi")]);
        Same(ws, d => ["-q", "timestamp", "--tr", tsa, "--td", "sha1", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", server.BaseUrl + "/fail", "--td", "sha256", In(d, "tiny32.efi")]);

        Same(ws, d => ["timestamp", "/t", "http://127.0.0.1:9/legacy", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "/tseal", tsa, In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", tsa, "/force", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", tsa, "/nosealwarn", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", tsa, "--td", "sha256", "/p7", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", tsa, "--td", "sha256", "/tp", "1", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--td", "sha256", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", tsa, In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", tsa, "--td", "certHash", In(d, "tiny32.efi")]);
        Same(ws, d => ["timestamp", "--tr", tsa, "--td", "sha256", In(d, "sample.cab")]);
        Same(ws, d => ["timestamp", "--tr", tsa, "--td", "sha256", In(d, "missing.exe")]);
        ws.Add("unsigned.dll", Fixtures.Bytes(UnsignedPeDll));
        Same(ws, d => ["timestamp", "--tr", tsa, "--td", "sha256", In(d, "unsigned.dll")]);
    }

    // ------------------------------------------------------------------ Azure Key Vault (local mock)

    private LocalHttpResponse KeyVaultHandler(LocalHttpServer server, LocalHttpRequest req)
    {
        if (req.Headers.GetValueOrDefault("Authorization") != "Bearer kv-token")
        {
            return LocalHttpResponse.Json("{\"error\":{\"code\":\"Unauthorized\"}}", 401);
        }

        var kid = server.BaseUrl + "/keys/signer/0123456789abcdef";
        if (req.Method == "GET" && req.Path == "/certificates/signer")
        {
            return LocalHttpResponse.Json(new JsonObject { ["kid"] = kid, ["cer"] = Convert.ToBase64String(_pki.LeafDer) }.ToJsonString());
        }

        if (req.Method == "POST" && req.Path == "/keys/signer/0123456789abcdef/sign")
        {
            var body = JsonNode.Parse(req.Body)!;
            var hash = body["alg"]!.GetValue<string>() switch
            {
                "RS256" => HashAlgorithmName.SHA256,
                "RS384" => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA512,
            };
            var digest = Base64UrlDecode(body["value"]!.GetValue<string>());
            var sig = _pki.LeafRsa.SignHash(digest, hash, RSASignaturePadding.Pkcs1);
            return LocalHttpResponse.Json(new JsonObject { ["kid"] = kid, ["value"] = Convert.ToBase64String(sig).TrimEnd('=').Replace('+', '-').Replace('/', '_') }.ToJsonString());
        }

        return LocalHttpResponse.Json("{\"error\":{\"code\":\"NotFound\"}}", 404);
    }

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t + new string('=', (4 - (t.Length % 4)) % 4));
    }

    [SkippableFact]
    public void KeyVaultSigningMatchesRust()
    {
        RustTool.Require();
        LocalHttpServer? server = null;
        server = new LocalHttpServer(req => KeyVaultHandler(server!, req));
        using (server)
        {
            using var tsa = new LocalHttpServer(TsaHandler);
            using var ws = new Workspace(UnsignedPeDll, UnsignedCab, UnsignedPsd1, UnsignedMsix, UnsignedMsi, SignedEfi);
            string[] kv = ["--kvu", server.BaseUrl + "/", "--kvc", " signer ", "--kva", "kv-token"];
            var (kvBatch, _) = Same(ws, d => ["sign", .. kv, "--fd", "sha384", "--ac", _pki.CaCert, "--coe", "--exit-codes", "azure", In(d, "tiny64-pe-alias.dll"), In(d, "sample.cab"), In(d, "unsigned-sample.psd1"), In(d, "sample.msix"), In(d, "tiny.msi"), In(d, "missing.txt")]);
            Assert.Equal(Devolutions.Psign.Cli.Framework.ResponseArgv.AzureSignExitPartialSuccess, kvBatch.ExitCode);
            Assert.Equal(5, Regex.Count(kvBatch.Stdout, "^Signed: ", RegexOptions.Multiline));
            Same(ws, d => ["sign", .. kv, "--skip-signed", "--tr", tsa.BaseUrl + "/tsa", "--td", "sha256", In(d, "tiny32.signed.efi"), In(d, "tiny64-pe-alias.dll")]);
            Same(ws, d => ["sign", "--kvu", server.BaseUrl, "--kvc", "signer", "--kva", "wrong", In(d, "sample.cab")]);
            Same(ws, d => ["sign", "--kvu", server.BaseUrl, "--kvc", "missing", "--kva", "kv-token", In(d, "sample.cab")]);
            Same(ws, d => ["sign", "--azure-key-vault-url", server.BaseUrl, "--azure-key-vault-certificate", "signer", "--azure-key-vault-credential-type", "access-token", "--azure-key-vault-accesstoken", "kv-token", In(d, "sample.cab")]);

            // Validation.
            string[][] rejected =
            [
                ["--f", "x.pfx"], ["--p", "pw"], ["--sha1", "AA"], ["--sm"], ["--s", "Root"], ["--cert-store-dir", "store"], ["--dmdf", "m.json"],
                ["--azure-key-vault-credential-type", "workload-identity"], ["--fd", "sha1"], ["--tr", "http://x"], ["--td", "sha1"],
                ["/d", "x"], ["--mdop", "0"], ["--rust-sip", "pe"], ["--ph"],
            ];
            foreach (var extra in rejected)
            {
                Same(ws, d => ["sign", .. kv, .. extra, In(d, "sample.cab")]);
            }

            Same(ws, d => ["sign", "--kvu", "https://kv.example", In(d, "sample.cab")]);
            Same(ws, d => ["sign", "--azure-key-vault-managed-identity", "--kvc", "c", In(d, "sample.cab")]);
            Same(ws, d => ["sign", "--azure-authority", "https://login.example", In(d, "*.nothing")]);
        }
    }

    // ------------------------------------------------------------------ Artifact Signing (local mock)

    private sealed class ArtifactSigningMock
    {
        private readonly SigningCliPki _pki;
        private readonly object _gate = new();
        private byte[]? _lastSignature;

        public ArtifactSigningMock(SigningCliPki pki) => _pki = pki;

        public LocalHttpResponse Handle(LocalHttpRequest req)
        {
            if (req.Headers.GetValueOrDefault("Authorization") != "Bearer as-token")
            {
                return LocalHttpResponse.Json("{\"error\":\"unauthorized\"}", 401);
            }

            const string prefix = "/codesigningaccounts/acct/certificateprofiles/prof";
            lock (_gate)
            {
                if (req.Method == "POST" && req.Path == prefix + ":sign")
                {
                    var body = JsonNode.Parse(req.Body)!;
                    var digest = Convert.FromBase64String(body["digest"]!.GetValue<string>());
                    var hash = body["signatureAlgorithm"]!.GetValue<string>() switch
                    {
                        "RS256" => HashAlgorithmName.SHA256,
                        "RS384" => HashAlgorithmName.SHA384,
                        _ => HashAlgorithmName.SHA512,
                    };
                    _lastSignature = _pki.LeafRsa.SignHash(digest, hash, RSASignaturePadding.Pkcs1);
                    return LocalHttpResponse.Json("{\"id\":\"op-1\",\"status\":\"InProgress\"}", 202, ("Operation-Location", prefix + "/sign/op-1?api-version=2024-06-15"));
                }

                if (req.Method == "GET" && req.Path == prefix + "/sign/op-1" && _lastSignature is not null)
                {
                    var json = new JsonObject
                    {
                        ["status"] = "Succeeded",
                        ["id"] = "op-1",
                        ["result"] = new JsonObject
                        {
                            ["signature"] = Convert.ToBase64String(_lastSignature),
                            ["signingCertificate"] = Convert.ToBase64String(Encoding.ASCII.GetBytes(_pki.PemBundle)),
                        },
                    };
                    return LocalHttpResponse.Json(json.ToJsonString());
                }
            }

            return LocalHttpResponse.Json("{\"error\":\"not found\"}", 404);
        }
    }

    [SkippableFact]
    public void ArtifactSigningMatchesRust()
    {
        RustTool.Require();
        var mock = new ArtifactSigningMock(_pki);
        using var server = new LocalHttpServer(mock.Handle);
        using var ws = new Workspace(UnsignedPeDll, UnsignedCab, UnsignedMsi, UnsignedPsd1, UnsignedMsix, UnsignedZip);
        string[] options =
        [
            "--artifact-signing-endpoint-base-url", server.BaseUrl, "--artifact-signing-account-name", "acct",
            "--artifact-signing-profile-name", "prof", "--artifact-signing-access-token", "as-token",
        ];

        // PE / CAB / MSI route through the in-process portable sign-* commands, scripts / MSIX through portable-core.
        var (asBatch, _) = Same(ws, d => ["sign", .. options, "--mdop", "1", "--coe", In(d, "tiny64-pe-alias.dll"), In(d, "sample.cab"), In(d, "tiny.msi"), In(d, "unsigned-sample.psd1"), In(d, "sample.msix"), In(d, "sample.zip")]);
        Assert.Equal(1, asBatch.ExitCode);
        Assert.Equal(5, Regex.Count(asBatch.Stdout, "^artifact_signing_profile=prof$", RegexOptions.Multiline));
        Same(ws, d => ["sign", .. options, "--mdop", "1", "--as", In(d, "tiny64-pe-alias.dll"), In(d, "sample.cab")]);
        Same(ws, d => ["sign", .. options, "--skip-signed", "--mdop", "1", In(d, "tiny64-pe-alias.dll"), In(d, "sample.cab")]);

        var metadata = Path.Combine(ws.Scratch, "metadata.json");
        File.WriteAllText(metadata, $"{{\"Endpoint\":\"{server.BaseUrl}\",\"CodeSigningAccountName\":\"acct\",\"CertificateProfileName\":\"prof\",\"CorrelationId\":\"corr-1\"}}");
        ws.Add("fresh.ps1", Fixtures.Bytes(UnsignedPs1));
        ws.Add("fresh.dll", Fixtures.Bytes(UnsignedPe32Dll));
        Same(ws, d => ["sign", "/dmdf", metadata, "--artifact-signing-access-token", "as-token", "--mdop", "1", In(d, "fresh.ps1"), In(d, "fresh.dll")]);
        Assert.Contains(server.Requests, r => r.Headers.TryGetValue("x-ms-correlation-id", out var c) && c == "corr-1");

        // Errors.
        Same(ws, d => ["sign", .. options, In(d, "x.cat")]);
        Same(ws, d => ["sign", .. options, In(d, "sample.zip")]);
        Same(ws, d => ["sign", .. options, "--artifact-signing-api-version", "2020", In(d, "unsigned-sample.psd1")]);
        Same(ws, d => ["sign", "--artifact-signing-account-name", "acct", "--artifact-signing-profile-name", "prof", In(d, "unsigned-sample.psd1")]);
        Same(ws, d => ["sign", "--artifact-signing-region", "r", In(d, "unsigned-sample.psd1")]);
        Same(ws, d => ["sign", "--artifact-signing-region", "r", "--artifact-signing-account-name", "acct", In(d, "unsigned-sample.psd1")]);
        Same(ws, d => ["sign", "--artifact-signing-metadata", Path.Combine(d, "missing.json"), In(d, "unsigned-sample.psd1")]);
        Same(ws, d => ["sign", "--artifact-signing-metadata", metadata, "--dmdf", metadata, In(d, "unsigned-sample.psd1")]);
        Same(ws, d => ["sign", "--artifact-signing-endpoint-base-url", server.BaseUrl, "--artifact-signing-account-name", "acct", "--artifact-signing-profile-name", "prof", "--artifact-signing-access-token", "wrong", In(d, "unsigned-sample.psd1")]);
        Same(ws, d => ["sign", "--artifact-signing-endpoint-base-url", server.BaseUrl, "--artifact-signing-account-name", "acct", "--artifact-signing-profile-name", "prof", "--artifact-signing-access-token", "wrong", In(d, "sample.cab")]);
        string[][] rejected = [["--f", "x.pfx"], ["--sha1", "AA"], ["--s", "CA"], ["--sm"], ["--cert-store-dir", "s"], ["--fd", "sha1"], ["--tr", "http://x"], ["/seal"], ["--mdop", "0"], ["--kvu", "https://kv"]];
        foreach (var extra in rejected)
        {
            Same(ws, d => ["sign", .. options, .. extra, In(d, "sample.cab")]);
        }
    }

    // ------------------------------------------------------------------ response files

    [SkippableFact]
    public void ResponseFileBatchesMatchRust()
    {
        RustTool.Require();
        using var ws = new Workspace(UnsignedPeDll, UnsignedCab);
        // One argument per line.
        ws.AddText("args.rsp", d => string.Join('\n', ["sign", "/fd", "sha256", "/f", _pki.LeafPfx, "/p", SigningCliPki.PfxPassword, In(d, "tiny64-pe-alias.dll")]) + "\n");
        Same(ws, d => ["@" + In(d, "args.rsp")]);
        ws.Add("plain.txt", "x"u8.ToArray());
        ws.AddText("bad.rsp", d => string.Join('\n', ["sign", "/f", _pki.LeafPfx, "/p", SigningCliPki.PfxPassword, In(d, "plain.txt"), In(d, "sample.cab")]) + "\n");
        Same(ws, d => ["@" + In(d, "bad.rsp")]);
        Same(ws, d => ["sign", "/f", _pki.LeafPfx, "@" + In(d, "missing.rsp")]);
    }
}
