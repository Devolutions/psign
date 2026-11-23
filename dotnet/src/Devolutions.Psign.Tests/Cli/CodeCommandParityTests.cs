using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Tests.Signing;
using Xunit;
using static Devolutions.Psign.Tests.Signing.CodeTestKit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>
/// Differential tests for <c>psign-tool code</c>: managed vs Rust CLI stdout / stderr / exit codes, signed outputs
/// byte-for-byte where deterministic (PE, ClickOnce, App Installer companions) and structurally (entry lists, entry
/// contents, Rust verification) for packages whose signatures embed a signing time (NuGet, VSIX) or whose rewritten ZIP
/// entries carry the current time.
/// </summary>
public class CodeCommandParityTests
{
    private static string[] Code(params string[] args) => ["code", .. args];

    // ------------------------------------------------------------------ dry-run plans

    public static TheoryData<string[]> DryRunCases()
    {
        var pkg = Fixtures.Path("package-signing");
        var gen = Fixtures.Path("generated-unsigned");
        var repo = Fixtures.RepoRoot;
        return new TheoryData<string[]>
        {
            Code("--dry-run", "--base-directory", pkg, "**/*"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "**/*"),
            Code("--dry-run", "--plan-json", "--base-directory", repo, "tests/fixtures/package-signing/unsigned/deep-nested.vsix"),
            Code("--dry-run", "--plan-json", "--base-directory", repo, "--output", "signed/out.vsix", "tests/fixtures/package-signing/unsigned/deep-nested.vsix"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "--output", "signed-dir", "unsigned/*.nupkg"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "--output", "single/", "unsigned/sample.nupkg"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "--recurse-containers", "false", "**/*.vsix"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "--max-concurrency", "3", "--continue-on-error", "--skip-signed", "unsigned/{sample,nested}.{vsix,nupkg}"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "--timestamp-url", "http://tsa.invalid/", "--timestamp-digest", "SHA384", "--file-digest", "certHash", "signed/*"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "**/*.vsix", "!**/nested*", "!signed/deep*"),
            Code("--dry-run", "--base-directory", gen, "pe/*", "appinstaller/**", "clickonce/**", "msix/*.msix"),
            Code("--dry-run", "--plan-json", "--base-directory", gen, "**/*.{exe,dll,winmd,cab,msi,cat,ps1,js,appinstaller,application,manifest}"),
            Code("--dry-run", "--base-directory", gen, "**/*"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "unsigned/sample.nupkg", "UNSIGNED/SAMPLE.NUPKG", "unsigned/./sample.vsix", "unsigned//nested.vsix"),
            Code("--dry-run", "--plan-json", "--base-directory", pkg, "\\!missing.dll", "unsigned/nothing-*.zip"),
        };
    }

    [SkippableTheory]
    [MemberData(nameof(DryRunCases))]
    public void DryRunMatchesRust(string[] args) => CliHarness.AssertSameOutput(args);

    [SkippableFact]
    public void DryRunFileListOrderingAndClassificationMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        foreach (var name in new[] { "lib/net8.0/a1.dll", "lib/net8.0/a2.dll", "lib/net7.0/a1.dll", "a-b/x.dll", "a/x.dll", "a.b/x.dll", "tools/readme.txt", "valid.app", "other.app", "app.exe.deploy", "app.application", "x.vsto", "enc.eappxbundle", "pkg.appxupload", "Upper.DLL" })
        {
            WriteFile(dir.File(name), name.EndsWith("valid.app", StringComparison.Ordinal) ? "NAVX\0x"u8.ToArray() : "pe"u8.ToArray());
        }

        WriteZip(dir.File("bundle.zip"), ("inner/a.dll", "pe"u8.ToArray()), ("inner/skip.txt", "x"u8.ToArray()), ("inner/n.app", "NAVX"u8.ToArray()), ("z.nupkg", File.ReadAllBytes(Pkg("unsigned/with-pe.nupkg"))));
        File.WriteAllText(dir.File("files.txt"), "# comment\n\n  lib/net{7..8}.0/a?.dll  \n!lib/net8.0/a2.dll\r\n**/x.dll\n*.app\n*.{deploy,application,vsto,eappxbundle,appxupload}\nupper.dll\nbundle.zip\n");
        CliHarness.AssertSameOutput(Code("--dry-run", "--plan-json", "--base-directory", dir.DirPath, "--file-list", "files.txt"));
        CliHarness.AssertSameOutput(Code("--dry-run", "--base-directory", dir.DirPath, "--file-list", dir.File("files.txt"), "--output", dir.File("out")));
        CliHarness.AssertSameOutput(Code("--dry-run", "--plan-json", "--base-directory", dir.DirPath, "**/*", "!**/*.zip"));
    }

    // ------------------------------------------------------------------ errors

    public static TheoryData<string[]> ErrorCases()
    {
        var pkg = Fixtures.Path("package-signing");
        var missing = Path.Combine(Path.GetTempPath(), "psign-code-missing-" + Guid.NewGuid().ToString("N"));
        var data = new TheoryData<string[]>
        {
            Code("--dry-run", "--max-concurrency", "0"),
            Code("--dry-run", "--timestamp-url", "http://tsa.invalid/", "a.dll"),
            Code("--dry-run", "--timestamp-digest", "sha256", "a.dll"),
            Code("--dry-run", "--base-directory", missing, "a.dll"),
            Code("--dry-run", "--base-directory", Fixtures.Path("pe-authenticode-upstream/tiny32.efi"), "a.dll"),
            Code("--dry-run", "--base-directory", pkg),
            Code("--dry-run", "--base-directory", pkg, "../x.dll"),
            Code("--dry-run", "--base-directory", pkg, "a/../../x.dll"),
            Code("--dry-run", "--base-directory", pkg, "a{b"),
            Code("--dry-run", "--base-directory", pkg, "a}b"),
            Code("--dry-run", "--base-directory", pkg, "a\\"),
            Code("--dry-run", "--base-directory", pkg, "!"),
            Code("--dry-run", "--base-directory", pkg, "--file-list", "missing-list.txt"),
            Code("--dry-run", "--base-directory", Fixtures.Path("generated-unsigned"), "**/*.vsix"),
            Code("--base-directory", pkg, "unsigned/sample.nupkg"),
            Code("--base-directory", pkg, "--pfx", "x.pfx", "--azure-key-vault-url", "https://kv.invalid", "unsigned/sample.nupkg"),
            Code("--base-directory", pkg, "--azure-key-vault-url", "https://kv.invalid", "--azure-key-vault-credential-type", "workload-identity", "unsigned/sample.nupkg"),
            Code("--base-directory", pkg, "--azure-key-vault-accesstoken", "t", "unsigned/sample.nupkg"),
            Code("--base-directory", pkg, "--pfx", missing + ".pfx", "unsigned/sample.nupkg"),
            Code("--base-directory", pkg, "--cert", missing + ".der", "--key", missing + ".key", "--chain-cert", missing + ".chain", "unsigned/sample.nupkg"),
        };
        if (OperatingSystem.IsWindows())
        {
            data.Add(Code("--dry-run", "--base-directory", pkg, "C:\\abs.dll"));
            data.Add(Code("--dry-run", "--base-directory", pkg, "C:rel.dll"));
            data.Add(Code("--dry-run", "--base-directory", pkg, "\\rooted.dll"));
        }

        return data;
    }

    [SkippableTheory]
    [MemberData(nameof(ErrorCases))]
    public void ErrorsMatchRust(string[] args) => CliHarness.AssertSameOutput(args);

    [SkippableTheory]
    [InlineData("--plan-json", "a")]
    [InlineData("--dry-run", "--overwrite", "--skip-signed", "a")]
    [InlineData("--dry-run", "--cert", "c.der", "a")]
    [InlineData("--dry-run", "--key", "k.pem", "a")]
    [InlineData("--dry-run", "--password", "p", "a")]
    [InlineData("--dry-run", "--pfx", "a.pfx", "--sha1", "00", "a")]
    [InlineData("--dry-run", "--recurse-containers", "maybe", "a")]
    [InlineData("--dry-run", "--file-digest", "md5", "a")]
    [InlineData("--dry-run", "--azure-key-vault-credential-type", "bogus", "a")]
    [InlineData("--dry-run", "--bogus")]
    public void UsageErrorsMatchRustExitCode(params string[] args)
    {
        var rust = CliHarness.RunRust(Code(args));
        var managed = CliHarness.RunManaged(Code(args));
        Assert.Equal(2, rust.ExitCode);
        Assert.Equal(rust.ExitCode, managed.ExitCode);
        Assert.StartsWith("error: ", managed.Stderr);
    }

    [SkippableFact]
    public void ExecutionErrorsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.WriteAllText(dir.File("bad.key"), "not a key");
        File.WriteAllText(dir.File("bad.der"), "not a cert");
        WriteFile(dir.File("encrypted.emsix"), "x"u8.ToArray());
        WriteFile(dir.File("valid.app"), "NAVX\0x"u8.ToArray());
        WriteFile(dir.File("archive.cab"), "MSCF"u8.ToArray());
        WriteFile(dir.File("unsupported.exe"), "MZunsupported"u8.ToArray());
        WriteFile(dir.File("broken.zip"), "not a zip"u8.ToArray());
        File.WriteAllText(dir.File("app.application"), SampleClickOnceManifest);
        WriteFile(dir.File("bad.appinstaller"), "<NotAppInstaller/>"u8.ToArray());
        WriteZip(dir.File("scripts.zip"), ("tools/install.ps1", "Write-Host hi"u8.ToArray()));
        WriteZip(dir.File("signed.msix"), ("AppxManifest.xml", "<Package/>"u8.ToArray()), ("AppxSignature.p7x", [1]));
        WriteZip(dir.File("nomanifest.msix"), ("readme.txt", "x"u8.ToArray()));
        WriteZip(dir.File("nobundle.msixbundle"), ("readme.txt", "x"u8.ToArray()));
        WriteZip(dir.File("companion.zip"), ("app.appinstaller", File.ReadAllBytes(Fixtures.Path("generated-unsigned/appinstaller/sample.appinstaller"))), ("app.appinstaller.p7", [1]));
        WriteZip(dir.File("app.deploy.zip"), ("data.txt.deploy", "x"u8.ToArray()));
        var output = dir.File("out");
        string[] Local(params string[] tail) => Code(["--base-directory", dir.DirPath, "--cert", signer.CertPath, "--key", signer.KeyPath, .. tail]);

        CliHarness.AssertSameOutput(Local("unsupported.exe"));
        CliHarness.AssertSameOutput(Local("--output", output, "--file-digest", "sha1", "unsupported.exe"));
        foreach (var input in new[] { "encrypted.emsix", "valid.app", "archive.cab", "unsupported.exe", "broken.zip", "bad.appinstaller", "scripts.zip", "signed.msix", "nomanifest.msix", "nobundle.msixbundle", "companion.zip", "app.deploy.zip" })
        {
            CliHarness.AssertSameOutput(Local("--output", Path.Combine(output, input), input));
        }

        CliHarness.AssertSameOutput(Local("--output", output, "--timestamp-url", "http://127.0.0.1:9/tsa", "--timestamp-digest", "sha256", "app.application"));
        CliHarness.AssertSameOutput(Local("--output", output, "--continue-on-error", "encrypted.emsix", "valid.app", "archive.cab", "app.application"));
        CliHarness.AssertSameOutput(Local("--output", output, "--continue-on-error", "--max-concurrency", "3", "encrypted.emsix", "valid.app", "archive.cab", "unsupported.exe"));
        CliHarness.AssertSameOutput(Local("--output", output, "--publisher-name", "", "companion.zip"));
        CliHarness.AssertSameOutput(Code("--base-directory", dir.DirPath, "--cert", dir.File("bad.der"), "--key", signer.KeyPath, "--output", output, "app.application", "unsupported.exe", "--continue-on-error"));
        // The innermost key-parser diagnostic text comes from different ASN.1 libraries; the context chain matches.
        var badKey = Code("--base-directory", dir.DirPath, "--cert", signer.CertPath, "--key", dir.File("bad.key"), "--output", output, "app.application");
        var rustBadKey = CliHarness.RunRust(badKey);
        var managedBadKey = CliHarness.RunManaged(badKey);
        Assert.Equal(rustBadKey.ExitCode, managedBadKey.ExitCode);
        Assert.StartsWith(rustBadKey.Stderr[..rustBadKey.Stderr.IndexOf("parse DER RSA private key: ", StringComparison.Ordinal)], managedBadKey.Stderr);
        Assert.Contains("parse DER RSA private key: ", managedBadKey.Stderr);
        CliHarness.AssertSameOutput(Code("--base-directory", dir.DirPath, "--cert", signer.CertPath, "--key", dir.File("missing.key"), "--output", output, "app.application"));
    }

    // ------------------------------------------------------------------ signed outputs

    /// <summary>Run Rust then managed with the same output location; returns the output snapshots.</summary>
    private static (Dictionary<string, byte[]> Rust, Dictionary<string, byte[]> Managed) RunBoth(string outputRoot, string[] args, bool compareStderr = true)
    {
        var rust = CliHarness.RunRust(args);
        var rustFiles = Snapshot(outputRoot);
        if (Directory.Exists(outputRoot))
        {
            Directory.Delete(outputRoot, recursive: true);
        }

        var managed = CliHarness.RunManaged(args);
        var managedFiles = Snapshot(outputRoot);
        Assert.True(rust.ExitCode == managed.ExitCode, $"exit code mismatch: rust={rust.ExitCode} managed={managed.ExitCode}\nrust stderr: {rust.Stderr}\nmanaged stderr: {managed.Stderr}");
        Assert.Equal(rust.Stdout, managed.Stdout);
        if (compareStderr)
        {
            Assert.Equal(rust.Stderr.Replace("\r\n", "\n", StringComparison.Ordinal), managed.Stderr.Replace("\r\n", "\n", StringComparison.Ordinal));
        }

        Assert.Equal(rustFiles.Keys.Order(StringComparer.Ordinal), managedFiles.Keys.Order(StringComparer.Ordinal));
        return (rustFiles, managedFiles);
    }

    private static Dictionary<string, byte[]> Snapshot(string root)
    {
        var map = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (!Directory.Exists(root))
        {
            return map;
        }

        foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            map[Path.GetRelativePath(root, file).Replace('\\', '/')] = File.ReadAllBytes(file);
        }

        return map;
    }

    private static readonly string[] ContainerExtensions = [".nupkg", ".snupkg", ".vsix", ".zip", ".msix", ".appx", ".msixbundle", ".appxbundle", ".msixupload", ".appxupload"];

    private static readonly HashSet<string> TimeDependentParts = new(StringComparer.Ordinal)
    {
        NuGetPackage.PackageSignatureFileName,
        "package/services/digital-signature/xml-signature/psign-signature.psdsxs",
    };

    /// <summary>Same entry names in the same order and equal contents, recursing into nested containers; signature parts that embed a signing time are skipped.</summary>
    private static void AssertZipEquivalent(byte[] rust, byte[] managed, string label)
    {
        var a = ZipCrateArchive.Open(rust);
        var b = ZipCrateArchive.Open(managed);
        Assert.Equal(a.Entries.Select(e => e.Name), b.Entries.Select(e => e.Name));
        foreach (var entry in a.Entries.Where(e => !e.IsDir))
        {
            var other = b.RequireByName(entry.Name);
            Assert.True(entry.CompressionMethod == other.CompressionMethod, $"{label}!{entry.Name} compression differs");
            var x = a.Read(entry);
            var y = b.Read(other);
            if (TimeDependentParts.Contains(entry.Name))
            {
                continue;
            }

            if (ContainerExtensions.Any(ext => entry.Name.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) && !x.AsSpan().SequenceEqual(y))
            {
                AssertZipEquivalent(x, y, $"{label}!{entry.Name}");
                continue;
            }

            Assert.True(x.AsSpan().SequenceEqual(y), $"{label}!{entry.Name} content differs");
        }
    }

    [SkippableFact]
    public void DeterministicSignedOutputsMatchRustByteForByte()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        using var chainDir = new TempDir();
        using var chain = new TestSigner(chainDir, "CN=psign code parity chain");
        File.Copy(TinyPe, dir.File("app.exe"));
        File.Copy(TinyPe, dir.File("app.exe.deploy"));
        File.Copy(TinySignedPe, dir.File("signed.dll"));
        File.Copy(TinyPe, dir.File("lib.winmd"));
        File.WriteAllText(dir.File("app.exe.manifest"), SampleClickOnceManifest);
        File.WriteAllText(dir.File("app.vsto"), "\uFEFF" + SampleClickOnceManifest.Replace("</assembly>", "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><old/></Signature></assembly>", StringComparison.Ordinal));
        File.Copy(Fixtures.Path("generated-unsigned/appinstaller/sample.appinstaller"), dir.File("sample.appinstaller"));
        var output = dir.File("out");
        string[] Local(params string[] tail) => Code(["--base-directory", dir.DirPath, "--cert", signer.CertPath, "--key", signer.KeyPath, .. tail]);

        foreach (var (args, outRoot) in new (string[], string)[]
        {
            (Local("--output", Path.Combine(output, "app.signed.exe"), "app.exe"), output),
            (Local("--output", output + Path.DirectorySeparatorChar, "app.exe", "app.exe.deploy", "app.exe.manifest", "app.vsto", "signed.dll", "lib.winmd", "sample.appinstaller"), output),
            (Local("--output", Path.Combine(output, "pub", "updated.appinstaller.p7"), "--publisher-name", "CN=Parity \"Publisher\" & <Co>", "sample.appinstaller"), output),
            (Local("--output", Path.Combine(output, "plain", "descriptor.appinstaller"), "--publisher-name", "CN=Plain", "sample.appinstaller"), output),
            (Local("--output", output, "--skip-signed", "signed.dll", "app.vsto", "app.exe"), output),
            (Local("--output", output, "--chain-cert", chain.CertPath, "--chain-cert", chain.CertPath, "app.exe", "sample.appinstaller"), output),
            (Local("--output", output, "--file-digest", "sha512", "app.exe.manifest", "sample.appinstaller"), output),
            (Local("--output", output, "--max-concurrency", "4", "app.exe", "app.exe.deploy", "app.exe.manifest", "sample.appinstaller"), output),
        })
        {
            var (rust, managed) = RunBoth(outRoot, args);
            foreach (var (name, bytes) in rust)
            {
                Assert.True(bytes.AsSpan().SequenceEqual(managed[name]), $"{name} differs for {string.Join(' ', args)}");
            }

            Directory.Delete(outRoot, recursive: true);
        }
    }

    [SkippableFact]
    public void PfxSignedPeMatchesRustByteForByte()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        using var chainDir = new TempDir();
        using var chain = new TestSigner(chainDir, "CN=psign code pfx chain");
        File.WriteAllBytes(dir.File("plain.pfx"), Pkcs12Writer.Encode(signer.Certificate.RawData, PrivateKeyMaterial.FromRsa(signer.Key), [], [1, 2, 3, 4], "secret"));
        File.WriteAllBytes(dir.File("chain.pfx"), Pkcs12Writer.Encode(signer.Certificate.RawData, PrivateKeyMaterial.FromRsa(signer.Key), [chain.Certificate.RawData], [1, 2, 3, 4], "secret"));
        File.Copy(TinyPe, dir.File("app.exe"));
        File.WriteAllText(dir.File("app.exe.manifest"), SampleClickOnceManifest);
        File.Copy(Fixtures.Path("generated-unsigned/appinstaller/sample.appinstaller"), dir.File("sample.appinstaller"));
        var output = dir.File("out");
        foreach (var pfx in new[] { "plain.pfx", "chain.pfx" })
        {
            var (rust, managed) = RunBoth(output, Code("--base-directory", dir.DirPath, "--pfx", dir.File(pfx), "--password", "secret", "--output", output, "app.exe", "app.exe.manifest", "sample.appinstaller"));
            foreach (var (name, bytes) in rust)
            {
                Assert.True(bytes.AsSpan().SequenceEqual(managed[name]), $"{name} differs for {pfx}");
            }

            Directory.Delete(output, recursive: true);
        }
    }

    [SkippableFact]
    public void PackageSignedOutputsMatchRustStructureAndVerify()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        foreach (var name in new[] { "unsigned/sample.nupkg", "unsigned/sample.snupkg", "unsigned/with-pe.nupkg", "unsigned/sample.vsix", "unsigned/deep-nested.vsix", "unsigned/nested.vsix", "signed/sample.signed.nupkg", "signed/sample.signed.vsix" })
        {
            File.Copy(Pkg(name), dir.File(Path.GetFileName(name)));
        }

        WriteZip(dir.File("bundle.zip"),
            ("readme.txt", Utf8("container")),
            ("packages/sample.nupkg", File.ReadAllBytes(Pkg("unsigned/sample.nupkg"))),
            ("bin/app.exe", File.ReadAllBytes(TinyPe)),
            ("publish/app.exe.manifest", Utf8(SampleClickOnceManifest)),
            ("publish/app.exe.deploy", File.ReadAllBytes(TinyPe)),
            ("descriptors/app.appinstaller", File.ReadAllBytes(Fixtures.Path("generated-unsigned/appinstaller/sample.appinstaller"))),
            ("ext/sample.vsix", File.ReadAllBytes(Pkg("unsigned/sample.vsix"))));
        WriteZip(dir.File("resign.zip"), ("packages/sample.nupkg", File.ReadAllBytes(Pkg("signed/sample.signed.nupkg"))), ("ext/sample.vsix", File.ReadAllBytes(Pkg("signed/sample.signed.vsix"))));
        WriteZip(dir.File("sample.msix"), FlatMsixEntries("Psign.Parity", "x64"));
        WriteZip(dir.File("inner.msix"), FlatMsixEntries("Psign.Child", "x64"));
        WriteZip(dir.File("upload.msixupload"), ("metadata/readme.txt", Utf8("upload")), ("packages/inner.msix", File.ReadAllBytes(dir.File("inner.msix"))));
        var output = dir.File("out");
        string[] Local(params string[] tail) => Code(["--base-directory", dir.DirPath, "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", output, .. tail]);

        foreach (var args in new[]
        {
            Local("sample.nupkg", "sample.snupkg", "with-pe.nupkg", "sample.vsix", "deep-nested.vsix", "nested.vsix", "bundle.zip"),
            Local("--overwrite", "sample.signed.nupkg", "sample.signed.vsix", "resign.zip"),
            Local("--skip-signed", "sample.signed.nupkg", "sample.signed.vsix", "with-pe.nupkg"),
            Local("--publisher-name", "CN=Parity Publisher", "bundle.zip", "sample.msix", "upload.msixupload"),
            Local("--file-list", "files.txt"),
            Local("--file-digest", "sha384", "sample.nupkg", "sample.vsix"),
            Local("--max-concurrency", "8", "sample.nupkg", "sample.vsix", "nested.vsix", "with-pe.nupkg"),
        })
        {
            File.WriteAllText(dir.File("files.txt"), "deep-nested.vsix\nbundle.zip\n!**/*.dll\n!**/app.exe\n");
            var (rust, managed) = RunBoth(output, args);
            foreach (var (name, bytes) in rust)
            {
                AssertZipEquivalent(bytes, managed[name], name);
            }

            foreach (var (name, _) in managed)
            {
                var path = Path.Combine(output, name);
                if (name.EndsWith("nupkg", StringComparison.Ordinal))
                {
                    // The Rust trust verifier's CMS fallback only accepts SHA-256 signers; SHA-384 output is covered by the structural comparison.
                    bool resignedByUs = !(name.Contains("signed.nupkg", StringComparison.Ordinal) && args.Contains("--skip-signed"));
                    if (resignedByUs && !args.Contains("sha384"))
                    {
                        Assert.Contains("nupkg-verify-signature: ok", RustTool.RunOk("portable", "nupkg-verify-signature", path, "--trusted-ca", signer.CertPath, "--allow-loose-signing-cert"));
                    }
                }
                else if (name.EndsWith(".vsix", StringComparison.Ordinal))
                {
                    Assert.Contains("vsix-verify-signature: ok", RustTool.RunOk("portable", "vsix-verify-signature", path));
                }
            }

            Directory.Delete(output, recursive: true);
        }
    }
}
