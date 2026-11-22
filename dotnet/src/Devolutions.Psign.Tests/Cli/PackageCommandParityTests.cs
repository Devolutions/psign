using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Zip;
using Xunit;

namespace Devolutions.Psign.Tests.Cli;

/// <summary>
/// Managed vs Rust NuGet / VSIX / ClickOnce / App Installer / Business Central portable commands: stdout, stderr, exit code,
/// and output files byte-for-byte (where the Rust output is deterministic) on fixtures and generated PKI. No network: every
/// trust check uses explicit anchors and <c>--as-of</c>.
/// </summary>
public class PackageCommandParityTests
{
    private const string TestCa = "devolutions-authenticode/authenticode-test-ca.crt";
    private const string AsOf = "2026-06-01";
    private const string AppInstaller = "generated-unsigned/appinstaller/sample.appinstaller";

    private static string[] FixtureTrust => ["--trusted-ca", Fixtures.Path(TestCa), "--as-of", AsOf];

    private static string[] PkiTrust(GeneratedTestPki pki) => ["--trusted-ca", pki.RootPath, "--as-of", GeneratedTestPki.Today];

    private static string Norm(string s) => s.Replace("\r\n", "\n", StringComparison.Ordinal);

    /// <summary>
    /// Run both CLIs with <c>{out}</c> replaced by a per-implementation output path; compare exit code, stdout and stderr
    /// (with the output path normalized). Returns the two output paths.
    /// </summary>
    private static (string Rust, string Managed) SameWithOutput(TempDir dir, string name, params string[] args)
    {
        var rustOut = dir.File("rust-" + name);
        var managedOut = dir.File("managed-" + name);
        var rust = CliHarness.RunRust(args.Select(a => a.Replace("{out}", rustOut, StringComparison.Ordinal)).ToArray());
        var managed = CliHarness.RunManaged(args.Select(a => a.Replace("{out}", managedOut, StringComparison.Ordinal)).ToArray());
        Assert.True(
            rust.ExitCode == managed.ExitCode,
            $"exit code mismatch for {string.Join(' ', args)}: rust={rust.ExitCode} managed={managed.ExitCode}\nrust stderr: {rust.Stderr}\nmanaged stderr: {managed.Stderr}");
        Assert.Equal(rust.Stdout.Replace(rustOut, "{out}", StringComparison.Ordinal), managed.Stdout.Replace(managedOut, "{out}", StringComparison.Ordinal));
        Assert.Equal(Norm(rust.Stderr).Replace(rustOut, "{out}", StringComparison.Ordinal), Norm(managed.Stderr).Replace(managedOut, "{out}", StringComparison.Ordinal));
        return (rustOut, managedOut);
    }

    /// <summary>
    /// Both CLIs fail with exit code 1 and the same error context chain up to (and including) <paramref name="prefix"/>; the
    /// innermost decoder text (Rust <c>der</c> / <c>rsa</c> crates vs BCL) is not compared.
    /// </summary>
    private static void SameFailurePrefix(string prefix, params string[] args)
    {
        var rust = CliHarness.RunRust(args);
        var managed = CliHarness.RunManaged(args);
        Assert.Equal(1, rust.ExitCode);
        Assert.Equal(1, managed.ExitCode);
        Assert.Equal(rust.Stdout, managed.Stdout);
        Assert.StartsWith(prefix, rust.Stderr, StringComparison.Ordinal);
        Assert.StartsWith(prefix, managed.Stderr, StringComparison.Ordinal);
    }

    private static void SameFiles((string Rust, string Managed) outputs) =>
        Assert.Equal(File.ReadAllBytes(outputs.Rust), File.ReadAllBytes(outputs.Managed));

    // ---------------------------------------------------------------- NuGet

    [SkippableTheory]
    [InlineData("package-signing/signed/sample.signed.nupkg")]
    [InlineData("package-signing/signed/sample.signed.snupkg")]
    [InlineData("package-signing/unsigned/sample.nupkg")]
    [InlineData("package-signing/unsigned/with-pe.nupkg")]
    [InlineData("generated-signed/cab/sample.cab")]
    public void NuGetReadOnlyCommandsMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        CliHarness.AssertSameOutput("portable", "nupkg-signature-info", path);
        foreach (var alg in new[] { "sha256", "sha384", "sha512" })
        {
            CliHarness.AssertSameOutput("portable", "nupkg-digest", path, "--algorithm", alg);
            CliHarness.AssertSameOutput("portable", "nupkg-signature-content", path, "--algorithm", alg);
        }

        CliHarness.AssertSameOutput("portable", "nupkg-digest", path, "--encoding", "raw");
        CliHarness.AssertSameOutput(["portable", "nupkg-verify-signature", path, .. FixtureTrust]);
        CliHarness.AssertSameOutput(["portable", "nupkg-verify-signature", path, "--algorithm", "sha512", .. FixtureTrust]);
    }

    [SkippableFact]
    public void NuGetSignatureContentRoundTripsMatchRust()
    {
        using var dir = new TempDir();
        var package = Fixtures.Path("package-signing/unsigned/with-pe.nupkg");
        var outputs = SameWithOutput(dir, "content.bin", "portable", "nupkg-signature-content", package, "--algorithm", "sha384", "--output", "{out}");
        SameFiles(outputs);
        CliHarness.AssertSameOutput("portable", "nupkg-verify-signature-content", package, "--content", outputs.Rust);
        CliHarness.AssertSameOutput("portable", "nupkg-verify-signature-content", Fixtures.Path("package-signing/unsigned/sample.nupkg"), "--content", outputs.Rust);
        SameFiles(SameWithOutput(dir, "digest.bin", "portable", "nupkg-digest", package, "--encoding", "raw", "--output", "{out}"));
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void NuGetSplitSigningMatchesRust(string alg)
    {
        using var dir = new TempDir();
        using var pki = new GeneratedTestPki(dir);
        var package = Fixtures.Path("package-signing/unsigned/sample.nupkg");
        var prehash = SameWithOutput(dir, "prehash.bin", "portable", "nupkg-signature-pkcs7-prehash", package, "--algorithm", alg, "--cert", pki.LeafPath, "--encoding", "raw", "--output", "{out}");
        SameFiles(prehash);
        CliHarness.AssertSameOutput("portable", "nupkg-signature-pkcs7-prehash", package, "--algorithm", alg, "--cert", pki.LeafPemPath);

        var hashName = alg == "sha256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
        var signature = dir.File("external.sig");
        File.WriteAllBytes(signature, pki.LeafKey.SignHash(File.ReadAllBytes(prehash.Rust), hashName, RSASignaturePadding.Pkcs1));
        var cms = SameWithOutput(dir, "from-signature.p7s", "portable", "nupkg-signature-pkcs7-from-signature", package, "--algorithm", alg, "--cert", pki.LeafPath, "--chain-cert", pki.RootPath, "--signature", signature, "--output", "{out}");
        SameFiles(cms);

        var embedded = SameWithOutput(dir, "embedded.nupkg", "portable", "nupkg-embed-signature", package, "--signature", cms.Rust, "--output", "{out}");
        AssertSameNuGetPackage(embedded.Rust, embedded.Managed);
        SameWithOutput(dir, "again.nupkg", "portable", "nupkg-embed-signature", embedded.Rust, "--signature", cms.Rust, "--output", "{out}");
        AssertSameNuGetPackage(
            SameWithOutput(dir, "overwrite.nupkg", "portable", "nupkg-embed-signature", embedded.Rust, "--signature", cms.Rust, "--output", "{out}", "--overwrite").Rust,
            embedded.Managed);

        CliHarness.AssertSameOutput(["portable", "nupkg-verify-signature", embedded.Managed, "--algorithm", alg, .. PkiTrust(pki)]);
        CliHarness.AssertSameOutput(["portable", "trust-verify-nupkg", embedded.Managed, .. PkiTrust(pki)]);
        CliHarness.AssertSameOutput(["portable", "trust-verify-nupkg", embedded.Managed, .. FixtureTrust]);
    }

    /// <summary>NuGet embedding stamps the signature entry with the current time; compare everything else.</summary>
    private static void AssertSameNuGetPackage(string rust, string managed)
    {
        var a = File.ReadAllBytes(rust);
        var b = File.ReadAllBytes(managed);
        Assert.Equal(NuGetPackage.ExtractSignature(a), NuGetPackage.ExtractSignature(b));
        Assert.Equal(NuGetPackage.WritePackageWithoutSignature(a), NuGetPackage.WritePackageWithoutSignature(b));
        var stamp = ZipCrateArchive.Open(a).ByName(NuGetPackage.PackageSignatureFileName)!.LastModified;
        Assert.Equal(a, NuGetPackage.EmbedSignature(NuGetPackage.WritePackageWithoutSignature(b), NuGetPackage.ExtractSignature(b), false, stamp));
    }

    [SkippableFact]
    public void NuGetLocalSigningMatchesRust()
    {
        using var dir = new TempDir();
        using var pki = new GeneratedTestPki(dir);
        var package = Fixtures.Path("package-signing/unsigned/with-pe.nupkg");

        // signingTime makes the CMS bytes time-dependent; stdout (lengths) and verification must agree.
        var cms = SameWithOutput(dir, "local.p7s", "portable", "nupkg-signature-pkcs7", package, "--algorithm", "sha384", "--cert", pki.LeafPath, "--key", pki.LeafKeyPemPath, "--output", "{out}");
        Assert.Equal(File.ReadAllBytes(cms.Rust).Length, File.ReadAllBytes(cms.Managed).Length);

        var signed = SameWithOutput(dir, "signed.nupkg", "portable", "nupkg-sign", package, "--cert", pki.LeafPemPath, "--key", pki.LeafKeyPath, "--chain-cert", pki.RootPath, "--output", "{out}");
        foreach (var output in new[] { signed.Rust, signed.Managed })
        {
            CliHarness.AssertSameOutput(["portable", "trust-verify-nupkg", output, .. PkiTrust(pki)]);
            CliHarness.AssertSameOutput(["portable", "nupkg-verify-signature", output, .. PkiTrust(pki)]);
            CliHarness.AssertSameOutput("portable", "nupkg-signature-info", output);
        }

        SameWithOutput(dir, "resign.nupkg", "portable", "nupkg-sign", signed.Rust, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}");
        // Key parse failures: the innermost key-decoder text differs (rsa crate vs BCL); the context chain and exit code match.
        SameFailurePrefix(
            $"nupkg-sign create CMS for {package}: parse RSA private key {pki.LeafPath}: parse DER RSA private key: ",
            "portable", "nupkg-sign", package, "--cert", pki.LeafPath, "--key", pki.LeafPath, "--output", dir.File("bad-key.nupkg"));
        SameFailurePrefix(
            $"nupkg-sign create CMS for {package}: parse signer certificate {pki.LeafKeyPath}: parse DER certificate: ",
            "portable", "nupkg-sign", package, "--cert", pki.LeafKeyPath, "--key", pki.LeafKeyPath, "--output", dir.File("bad-cert.nupkg"));
        SameWithOutput(dir, "ts1.nupkg", "portable", "nupkg-sign", package, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}", "--timestamp-url", "http://127.0.0.1:9/");
        SameWithOutput(dir, "ts2.p7s", "portable", "nupkg-signature-pkcs7", package, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}", "--td", "sha256");
    }

    // ---------------------------------------------------------------- VSIX

    [SkippableTheory]
    [InlineData("package-signing/signed/sample.signed.vsix")]
    [InlineData("package-signing/signed/nested.signed.vsix")]
    [InlineData("package-signing/unsigned/deep-nested.vsix")]
    [InlineData("package-signing/unsigned/sample.vsix")]
    public void VsixReadOnlyCommandsMatchRust(string fixture)
    {
        var path = Fixtures.Path(fixture);
        CliHarness.AssertSameOutput("portable", "vsix-signature-info", path);
        foreach (var alg in new[] { "sha256", "sha384", "sha512" })
        {
            CliHarness.AssertSameOutput("portable", "vsix-signature-reference-xml", path, "--algorithm", alg);
            CliHarness.AssertSameOutput("portable", "vsix-signature-xml-prehash", path, "--algorithm", alg);
        }

        CliHarness.AssertSameOutput(["portable", "vsix-verify-signature", path, .. FixtureTrust]);
        CliHarness.AssertSameOutput("portable", "vsix-verify-signature", path);
        CliHarness.AssertSameOutput("portable", "vsix-verify-signature", path, "--cert", Fixtures.Path(TestCa));
        CliHarness.AssertSameOutput(["portable", "vsix-verify-signature", path, "--algorithm", "sha384", "--trusted-ca", Fixtures.Path(TestCa), "--as-of", "2030-01-01"]);
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    public void VsixSigningMatchesRust(string alg)
    {
        using var dir = new TempDir();
        using var pki = new GeneratedTestPki(dir);
        var package = Fixtures.Path("package-signing/unsigned/nested.vsix");

        var reference = SameWithOutput(dir, "reference.xml", "portable", "vsix-signature-reference-xml", package, "--algorithm", alg, "--output", "{out}");
        SameFiles(reference);
        CliHarness.AssertSameOutput("portable", "vsix-verify-signature-reference-xml", package, "--signature-xml", reference.Rust, "--algorithm", alg);
        CliHarness.AssertSameOutput("portable", "vsix-verify-signature-reference-xml", Fixtures.Path("package-signing/unsigned/sample.vsix"), "--signature-xml", reference.Rust, "--algorithm", alg);

        var xml = SameWithOutput(dir, "signature.xml", "portable", "vsix-signature-xml", package, "--algorithm", alg, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}");
        SameFiles(xml);

        var prehash = SameWithOutput(dir, "prehash.bin", "portable", "vsix-signature-xml-prehash", package, "--algorithm", alg, "--encoding", "raw", "--output", "{out}");
        SameFiles(prehash);
        var hashName = alg == "sha256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
        var signature = dir.File("external.sig");
        File.WriteAllBytes(signature, pki.LeafKey.SignHash(File.ReadAllBytes(prehash.Rust), hashName, RSASignaturePadding.Pkcs1));
        var fromSignature = SameWithOutput(dir, "from-signature.xml", "portable", "vsix-signature-xml-from-signature", package, "--algorithm", alg, "--cert", pki.LeafPath, "--signature", signature, "--output", "{out}");
        SameFiles(fromSignature);
        Assert.Equal(File.ReadAllBytes(xml.Rust), File.ReadAllBytes(fromSignature.Rust));

        var embedded = SameWithOutput(dir, "embedded.vsix", "portable", "vsix-embed-signature-xml", package, "--signature-xml", xml.Rust, "--output", "{out}");
        SameFiles(embedded);
        SameWithOutput(dir, "embedded-again.vsix", "portable", "vsix-embed-signature-xml", embedded.Rust, "--signature-xml", xml.Rust, "--output", "{out}");

        string[] verify = ["--algorithm", alg];
        CliHarness.AssertSameOutput(["portable", "vsix-verify-signature-xml", package, "--signature-xml", xml.Rust, "--cert", pki.LeafPath, .. verify]);
        CliHarness.AssertSameOutput(["portable", "vsix-verify-signature-xml", package, "--signature-xml", xml.Rust, "--cert", pki.LeafPemPath, .. verify, .. PkiTrust(pki)]);
        CliHarness.AssertSameOutput(["portable", "vsix-verify-signature-xml", package, "--signature-xml", xml.Rust, "--cert", pki.RootPath, .. verify]);
        CliHarness.AssertSameOutput(["portable", "vsix-verify-signature", embedded.Managed, .. verify, .. PkiTrust(pki)]);
        CliHarness.AssertSameOutput(["portable", "vsix-verify-signature", embedded.Managed, "--cert", pki.LeafPath, .. verify, .. FixtureTrust]);
        CliHarness.AssertSameOutput(["portable", "trust-verify-vsix", embedded.Managed, .. PkiTrust(pki)]);
        CliHarness.AssertSameOutput(["portable", "trust-verify-vsix", embedded.Managed, "--prefer-timestamp-signing-time", "--require-valid-timestamp", "--trusted-ca", pki.RootPath]);
    }

    [SkippableFact]
    public void VsixSignMatchesRust()
    {
        using var dir = new TempDir();
        using var pki = new GeneratedTestPki(dir);
        var package = Fixtures.Path("package-signing/unsigned/deep-nested.vsix");
        var signed = SameWithOutput(dir, "signed.vsix", "portable", "vsix-sign", package, "--algorithm", "sha512", "--cert", pki.LeafPath, "--key", pki.LeafKeyPemPath, "--output", "{out}");
        foreach (var output in new[] { signed.Rust, signed.Managed })
        {
            CliHarness.AssertSameOutput(["portable", "vsix-verify-signature", output, "--algorithm", "sha512", "--cert", pki.LeafPath, .. PkiTrust(pki)]);
            CliHarness.AssertSameOutput(["portable", "trust-verify-vsix", output, .. PkiTrust(pki)]);
            CliHarness.AssertSameOutput("portable", "vsix-signature-info", output);
        }

        SameWithOutput(dir, "resign.vsix", "portable", "vsix-sign", signed.Rust, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}");
        SameWithOutput(dir, "ts.vsix", "portable", "vsix-sign", package, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}", "--tr", "http://127.0.0.1:9/");
        SameWithOutput(dir, "ts2.vsix", "portable", "vsix-sign", package, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}", "--timestamp-digest", "sha1");
    }

    // ---------------------------------------------------------------- ClickOnce

    private const string Manifest = """
        <?xml version="1.0" encoding="utf-8"?>
        <asmv1:assembly xmlns="urn:schemas-microsoft-com:asm.v2" xmlns:asmv1="urn:schemas-microsoft-com:asm.v1" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" manifestVersion="1.0">
          <asmv1:assemblyIdentity name="App.exe" version="1.0.0.0" publicKeyToken="0000000000000000" language="neutral" processorArchitecture="msil" type="win32" />
          <dependency>
            <dependentAssembly dependencyType="install" allowDelayedBinding="true" codebase="bin\App.dll" size="3">
              <assemblyIdentity name="App" version="1.0.0.0" language="neutral" processorArchitecture="msil" />
              <hash>
                <dsig:Transforms><dsig:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity" /></dsig:Transforms>
                <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <dsig:DigestValue>stale</dsig:DigestValue>
              </hash>
            </dependentAssembly>
          </dependency>
          <file name="data/config.json" size="0">
            <hash>
              <dsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
              <dsig:DigestValue>stale</dsig:DigestValue>
            </hash>
          </file>
        </asmv1:assembly>
        """;

    private static string WriteClickOnceTree(TempDir dir)
    {
        Directory.CreateDirectory(dir.File("bin"));
        Directory.CreateDirectory(dir.File("data"));
        File.WriteAllBytes(dir.File("bin/App.dll"), "MZ!"u8.ToArray());
        File.WriteAllBytes(dir.File("data/config.json"), "{\"a\":1}"u8.ToArray());
        var manifest = dir.File("App.exe.manifest");
        File.WriteAllText(manifest, Manifest.Replace("\r\n", "\n", StringComparison.Ordinal), new UTF8Encoding(false));
        return manifest;
    }

    [SkippableFact]
    public void ClickOnceManifestHashCommandsMatchRust()
    {
        using var dir = new TempDir();
        var manifest = WriteClickOnceTree(dir);
        CliHarness.AssertSameOutput("portable", "clickonce-manifest-hashes", manifest);
        // Missing referenced file: the I/O error text comes from Core (BCL message), so compare stdout / exit code only.
        CliHarness.AssertSameStdout("portable", "clickonce-manifest-hashes", manifest, "--base-directory", dir.File("bin"));
        foreach (var alg in new[] { "sha1", "sha256", "sha512" })
        {
            var updated = SameWithOutput(dir, alg + ".manifest", "portable", "clickonce-update-manifest-hashes", manifest, "--algorithm", alg, "--output", "{out}");
            SameFiles(updated);
            CliHarness.AssertSameOutput("portable", "clickonce-manifest-hashes", updated.Rust, "--base-directory", dir.DirPath);
        }

        CliHarness.AssertSameOutput("portable", "clickonce-manifest-hashes", dir.File("missing.manifest"));
        File.WriteAllBytes(dir.File("bad.manifest"), [0xFF, 0xFE, 0x00]);
        CliHarness.AssertSameOutput("portable", "clickonce-manifest-hashes", dir.File("bad.manifest"));
    }

    [SkippableFact]
    public void ClickOnceDeployCommandsMatchRust()
    {
        using var dir = new TempDir();
        var deployed = dir.File("App.dll.deploy");
        File.WriteAllBytes(deployed, "payload bytes"u8.ToArray());
        CliHarness.AssertSameOutput("portable", "clickonce-deploy-info", deployed);
        CliHarness.AssertSameOutput("portable", "clickonce-deploy-info", Fixtures.Path("generated-unsigned/optional-provider/probe.manifest"));
        CliHarness.AssertSameOutput("portable", "clickonce-deploy-info", dir.File("missing.deploy"));
        SameFiles(SameWithOutput(dir, "App.dll", "portable", "clickonce-copy-deploy-payload", deployed, "--output", "{out}"));
        SameWithOutput(dir, "x", "portable", "clickonce-copy-deploy-payload", Fixtures.Path("generated-unsigned/optional-provider/probe.manifest"), "--output", "{out}");
        SameWithOutput(dir, "y", "portable", "clickonce-copy-deploy-payload", dir.File("missing.deploy"), "--output", "{out}");
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void ClickOnceSigningMatchesRust(string digest)
    {
        using var dir = new TempDir();
        using var pki = new GeneratedTestPki(dir);
        var manifest = WriteClickOnceTree(dir);

        var signed = SameWithOutput(dir, "signed.manifest", "portable", "clickonce-sign-manifest", manifest, "--digest", digest, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}");
        SameFiles(signed);
        var signedPem = SameWithOutput(dir, "signed-pem.manifest", "portable", "clickonce-sign-manifest", manifest, "--digest", digest, "--cert", pki.LeafPemPath, "--key", pki.LeafKeyPemPath, "--output", "{out}");
        SameFiles(signedPem);

        var prehash = SameWithOutput(dir, "prehash.bin", "portable", "clickonce-sign-manifest-prehash", signed.Rust, "--digest", digest, "--encoding", "raw", "--output", "{out}");
        SameFiles(prehash);
        CliHarness.AssertSameOutput("portable", "clickonce-sign-manifest-prehash", manifest, "--digest", digest);
        var hashName = digest == "sha256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA512;
        var signature = dir.File("external.sig");
        File.WriteAllBytes(signature, pki.LeafKey.SignHash(File.ReadAllBytes(prehash.Rust), hashName, RSASignaturePadding.Pkcs1));
        var fromSignature = SameWithOutput(dir, "from-signature.manifest", "portable", "clickonce-sign-manifest-from-signature", manifest, "--digest", digest, "--cert", pki.LeafPath, "--signature", signature, "--output", "{out}");
        SameFiles(fromSignature);
        Assert.Equal(File.ReadAllBytes(signed.Rust), File.ReadAllBytes(fromSignature.Rust));

        foreach (var output in new[] { signed.Managed, signedPem.Managed })
        {
            CliHarness.AssertSameOutput("portable", "clickonce-verify-manifest-signature", output, "--digest", digest);
            CliHarness.AssertSameOutput("portable", "clickonce-verify-manifest-signature", output, "--digest", digest, "--cert", pki.LeafPemPath);
            CliHarness.AssertSameOutput(["portable", "clickonce-verify-manifest-signature", output, "--digest", digest, .. PkiTrust(pki)]);
            CliHarness.AssertSameOutput(["portable", "clickonce-verify-manifest-signature", output, "--digest", digest, "--verbose-chain", "--anchor-dir", dir.DirPath, "--as-of", GeneratedTestPki.Today]);
            CliHarness.AssertSameOutput(["portable", "clickonce-verify-manifest-signature", output, "--digest", digest, .. FixtureTrust]);
            CliHarness.AssertSameOutput(["portable", "clickonce-verify-manifest-signature", output, "--digest", digest, "--prefer-timestamp-signing-time", "--require-valid-timestamp", "--trusted-ca", pki.RootPath]);
            CliHarness.AssertSameOutput("portable", "clickonce-verify-manifest-signature", output, "--digest", digest == "sha256" ? "sha384" : "sha256");
            CliHarness.AssertSameOutput("portable", "clickonce-verify-manifest-signature", output, "--digest", digest, "--cert", pki.RootPath);
        }

        CliHarness.AssertSameOutput("portable", "clickonce-verify-manifest-signature", manifest);
        SameFailurePrefix(
            $"clickonce-sign-manifest {manifest}: parse signer certificate {pki.LeafKeyPath}: parse DER certificate: ",
            "portable", "clickonce-sign-manifest", manifest, "--cert", pki.LeafKeyPath, "--key", pki.LeafKeyPath, "--output", dir.File("bad.manifest"));
    }

    // ---------------------------------------------------------------- App Installer / Business Central

    [SkippableFact]
    public void AppInstallerReadOnlyCommandsMatchRust()
    {
        using var dir = new TempDir();
        var path = Fixtures.Path(AppInstaller);
        var companion = Fixtures.Path("generated-signed/appinstaller/sample.appinstaller.p7");
        CliHarness.AssertSameOutput("portable", "appinstaller-info", path);
        CliHarness.AssertSameOutput("portable", "appinstaller-info", path, "--signature", companion);
        CliHarness.AssertSameOutput("portable", "appinstaller-info", path, "--signature", dir.File("missing.p7"));
        CliHarness.AssertSameOutput("portable", "appinstaller-info", Fixtures.Path("msix-edge-cases/unsigned/bundle-bom.appinstaller"));
        CliHarness.AssertSameOutput("portable", "appinstaller-info", Fixtures.Path("unsigned-sample.ps1"));
        CliHarness.AssertSameOutput("portable", "appinstaller-info", dir.File("missing.appinstaller"));
        SameFiles(SameWithOutput(dir, "publisher.appinstaller", "portable", "appinstaller-set-publisher", path, "--publisher", "CN=New <Publisher> & \"Co\"", "--output", "{out}"));
        SameWithOutput(dir, "empty.appinstaller", "portable", "appinstaller-set-publisher", path, "--publisher", "", "--output", "{out}");
        CliHarness.AssertSameOutput(["portable", "appinstaller-verify-companion", path, "--signature", companion, .. FixtureTrust]);
        CliHarness.AssertSameOutput(["portable", "appinstaller-verify-companion", Fixtures.Path("msix-edge-cases/unsigned/bundle-bom.appinstaller"), "--signature", companion, .. FixtureTrust]);
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    public void AppInstallerCompanionSigningMatchesRust(string digest)
    {
        using var dir = new TempDir();
        using var pki = new GeneratedTestPki(dir);
        var path = Fixtures.Path(AppInstaller);

        var companion = SameWithOutput(dir, "companion.p7", "portable", "appinstaller-sign-companion", path, "--digest", digest, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--chain-cert", pki.RootPath, "--output", "{out}");
        SameFiles(companion);

        var prehash = SameWithOutput(dir, "prehash.bin", "portable", "appinstaller-sign-companion-prehash", path, "--digest", digest, "--encoding", "raw", "--output", "{out}");
        SameFiles(prehash);
        CliHarness.AssertSameOutput("portable", "appinstaller-sign-companion-prehash", path, "--digest", digest);
        var hashName = digest == "sha256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA384;
        var signature = dir.File("external.sig");
        File.WriteAllBytes(signature, pki.LeafKey.SignHash(File.ReadAllBytes(prehash.Rust), hashName, RSASignaturePadding.Pkcs1));
        var fromSignature = SameWithOutput(dir, "from-signature.p7", "portable", "appinstaller-sign-companion-from-signature", path, "--digest", digest, "--cert", pki.LeafPath, "--chain-cert", pki.RootPath, "--signature", signature, "--output", "{out}");
        SameFiles(fromSignature);
        Assert.Equal(File.ReadAllBytes(companion.Rust), File.ReadAllBytes(fromSignature.Rust));

        CliHarness.AssertSameOutput(["portable", "appinstaller-verify-companion", path, "--signature", companion.Managed, .. PkiTrust(pki)]);
        CliHarness.AssertSameOutput(["portable", "appinstaller-verify-companion", path, "--signature", companion.Managed, .. FixtureTrust]);
        CliHarness.AssertSameOutput(["portable", "trust-verify-detached", path, companion.Managed, .. PkiTrust(pki)]);

        SameWithOutput(dir, "ts.p7", "portable", "appinstaller-sign-companion", path, "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}", "--timestamp-url", "http://127.0.0.1:9/");
        SameWithOutput(dir, "ts2.p7", "portable", "appinstaller-sign-companion-from-signature", path, "--cert", pki.LeafPath, "--signature", signature, "--output", "{out}", "--timestamp-digest", "sha256");
        SameWithOutput(dir, "bad.p7", "portable", "appinstaller-sign-companion", Fixtures.Path("unsigned-sample.ps1"), "--cert", pki.LeafPath, "--key", pki.LeafKeyPath, "--output", "{out}");
        SameWithOutput(dir, "nocert.p7", "portable", "appinstaller-sign-companion", path, "--cert", dir.File("missing.cer"), "--key", pki.LeafKeyPath, "--output", "{out}");
    }

    [SkippableFact]
    public void BusinessCentralAppInfoMatchesRust()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("app.app"), [.. "NAVX"u8.ToArray(), 1, 2, 3]);
        File.WriteAllBytes(dir.File("other.app"), "PK\u0003\u0004"u8.ToArray());
        CliHarness.AssertSameOutput("portable", "business-central-app-info", dir.File("app.app"));
        CliHarness.AssertSameOutput("portable", "business-central-app-info", dir.File("other.app"));
        CliHarness.AssertSameOutput("portable", "business-central-app-info", dir.File("missing.app"));
    }
}
