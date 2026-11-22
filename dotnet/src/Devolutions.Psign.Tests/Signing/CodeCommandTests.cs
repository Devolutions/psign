using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.CertStore;
using Devolutions.Psign.Signing.Code;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Tests.Cli;
using Xunit;
using static Devolutions.Psign.Tests.Signing.CodeTestKit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// Port of Rust <c>tests/code_command.rs</c> against the managed <c>psign-tool code</c> (in-process). The Rust tests that
/// spawn <c>psign-server</c> (TSA, Azure Key Vault, Artifact Signing) use in-memory HTTP handlers instead.
/// </summary>
public class CodeCommandTests
{
    private static CliResult Run(params string[] args) => CliHarness.RunManaged(args);

    private static CliResult RunOk(params string[] args)
    {
        var r = Run(args);
        Assert.True(r.ExitCode == 0, $"psign-tool {string.Join(' ', args)} failed ({r.ExitCode}): {r.Stderr}\n{r.Stdout}");
        return r;
    }

    private static CliResult RunFail(params string[] args)
    {
        var r = Run(args);
        Assert.True(r.ExitCode != 0, $"psign-tool {string.Join(' ', args)} unexpectedly succeeded: {r.Stdout}");
        return r;
    }

    private static string[] Sign(string baseDir, TestSigner signer, string output, params string[] tail) =>
        ["code", "--base-directory", baseDir, "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", output, .. tail];

    private static List<string> PlanPaths(string json, string field = "path")
    {
        var list = JsonNode.Parse(json)!["nodes"]!.AsArray().Select(n => n![field]!.GetValue<string>()).ToList();
        list.Sort(StringComparer.Ordinal);
        return list;
    }

    private static List<(string Path, string Format, string Signer)> PlanFormats(string json) =>
        JsonNode.Parse(json)!["nodes"]!.AsArray()
            .Select(n => (n!["path"]!.GetValue<string>(), n["format"]!.GetValue<string>(), n["signer"]!.GetValue<string>()))
            .ToList();

    [Fact]
    public void HelpListsCodeOrchestratorCommand() => Assert.Contains("code", RunOk("--help").Stdout);

    [Fact]
    public void DryRunFileListAppliesGlobsBracesRangesAndNegation()
    {
        using var dir = new TempDir();
        WriteFile(dir.File("lib/net8.0/a1.dll"), "pe"u8.ToArray());
        WriteFile(dir.File("lib/net8.0/a2.dll"), "pe"u8.ToArray());
        WriteFile(dir.File("lib/net7.0/a1.dll"), "pe"u8.ToArray());
        WriteFile(dir.File("tools/readme.txt"), "text"u8.ToArray());
        File.WriteAllText(dir.File("files.txt"), "lib/net{7..8}.0/a?.dll\n!lib/net8.0/a2.dll\n");

        var r = RunOk("code", "--dry-run", "--plan-json", "--base-directory", dir.DirPath, "--file-list", "files.txt");
        Assert.Equal(["lib/net7.0/a1.dll", "lib/net8.0/a1.dll"], PlanPaths(r.Stdout));
    }

    [Fact]
    public void DryRunRecursesNestedVsixAndNupkgInsideOut()
    {
        var r = RunOk("code", "--dry-run", "--plan-json", "--base-directory", Repo, "tests/fixtures/package-signing/unsigned/deep-nested.vsix");
        var paths = PlanPaths(r.Stdout);
        Assert.Contains("tests/fixtures/package-signing/unsigned/deep-nested.vsix", paths);
        Assert.Contains(paths, p => p.EndsWith("!packages/with-pe.nupkg", StringComparison.Ordinal));
        Assert.Contains(paths, p => p.EndsWith("!packages/with-pe.nupkg!lib/net8.0/tiny32.dll", StringComparison.Ordinal));
        Assert.NotEmpty(JsonNode.Parse(r.Stdout)!["edges"]!.AsArray());
    }

    [Fact]
    public void DryRunAppliesExcludeFiltersInsideContainers()
    {
        using var dir = new TempDir();
        var fileList = dir.File("nested-exclude.txt");
        File.WriteAllText(fileList, "tests/fixtures/package-signing/unsigned/deep-nested.vsix\n!**/*.dll\n");
        var paths = PlanPaths(RunOk("code", "--dry-run", "--plan-json", "--base-directory", Repo, "--file-list", fileList).Stdout);
        Assert.Contains(paths, p => p.EndsWith("!packages/with-pe.nupkg", StringComparison.Ordinal));
        Assert.DoesNotContain(paths, p => p.EndsWith("!packages/with-pe.nupkg!lib/net8.0/tiny32.dll", StringComparison.Ordinal));
    }

    [Fact]
    public void CodeWithoutDryRunFailsSafely()
    {
        var r = RunFail("code", "--base-directory", Repo, "tests/fixtures/package-signing/unsigned/sample.nupkg");
        Assert.Contains("requires exactly one signer", r.Stderr);
    }

    [Fact]
    public void SignsTopLevelNupkgWithLocalCertKey()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("signed.nupkg");
        var r = RunOk(Sign(Repo, signer, output, "tests/fixtures/package-signing/unsigned/sample.nupkg"));
        Assert.Contains("signed tests/fixtures/package-signing/unsigned/sample.nupkg", r.Stdout);
        Assert.Contains(".signature.p7s", r.Stdout);
        AssertNuGetAuthorAttributes(output);
    }

    [Fact]
    public void SignsNupkgWithPortableCertStoreIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var keyPem = dir.File("signer.pem");
        File.WriteAllText(keyPem, signer.Key.ExportPkcs8PrivateKeyPem());
        File.Copy(Pkg("unsigned/sample.nupkg"), dir.File("sample.nupkg"));
        var store = dir.File("cert-store");
        var import = new PortableCertStore().Import(new CertStoreSelection(store), signer.CertPath, keyPem);
        var output = dir.File("signed-store.nupkg");

        RunOk("code", "--base-directory", dir.DirPath, "--cert-store-dir", store, "--sha1", import.ThumbprintSha1, "--output", output, "sample.nupkg");
        AssertNuGetAuthorAttributes(output);
    }

    [Fact]
    public void SignsNupkgWithPfxIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var pfx = dir.File("signer.pfx");
        File.WriteAllBytes(pfx, Pkcs12Writer.Encode(signer.Certificate.RawData, PrivateKeyMaterial.FromRsa(signer.Key), [], [1, 2, 3, 4], "secret"));
        File.Copy(Pkg("unsigned/sample.nupkg"), dir.File("sample.nupkg"));
        var output = dir.File("signed-pfx.nupkg");

        RunOk("code", "--base-directory", dir.DirPath, "--pfx", pfx, "--password", "secret", "--output", output, "sample.nupkg");
        AssertNuGetSignatureValid(output);
    }

    [Fact]
    public void SignsTopLevelPeWithLocalCertKey()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(TinyPe, dir.File("app.exe"));
        var output = dir.File("app.signed.exe");
        Assert.Contains("Authenticode PE/WinMD", RunOk(Sign(dir.DirPath, signer, output, "app.exe")).Stdout);
        AssertPeVerifies(output);
    }

    [Fact]
    public void SignsPeWithChainCertificate()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        using var extraDir = new TempDir();
        using var extra = new TestSigner(extraDir, "CN=psign code chain");
        File.Copy(TinyPe, dir.File("app.exe"));
        var output = dir.File("app.signed.exe");
        RunOk([.. Sign(dir.DirPath, signer, output, "app.exe"), "--chain-cert", extra.CertPath]);
        AssertPeVerifies(output);
        var sd = CmsSignedData.Parse(PeAuthenticode.FirstPkcs7(File.ReadAllBytes(output)));
        Assert.Equal(2, sd.Certificates!.Count);
    }

    [Fact]
    public void SkipSignedCopiesAlreadySignedPe()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(TinyPe, dir.File("app.exe"));
        var signed = dir.File("app.initially-signed.exe");
        RunOk(Sign(dir.DirPath, signer, signed, "app.exe"));

        var output = dir.File("app.skipped.exe");
        var r = RunOk([.. Sign(dir.DirPath, signer, output, "app.initially-signed.exe"), "--skip-signed"]);
        Assert.Contains("skipped", r.Stdout);
        Assert.Contains("already signed", r.Stdout);
        Assert.Equal(File.ReadAllBytes(signed), File.ReadAllBytes(output));
    }

    [Fact]
    public void SigningReplacesExistingPeSignatureByDefault()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(TinySignedPe, dir.File("app.signed.exe"));
        var output = dir.File("app.resigned.exe");
        RunOk(Sign(dir.DirPath, signer, output, "app.signed.exe"));
        var resigned = File.ReadAllBytes(output);
        PeAuthenticode.VerifyDigestConsistency(resigned);
        Assert.Single(PeAuthenticode.Pkcs7Blobs(resigned));
    }

    [Fact]
    public void SkipSignedCopiesAlreadySignedNupkg()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("already-signed.nupkg");
        var r = RunOk([.. Sign(Repo, signer, output, "tests/fixtures/package-signing/signed/sample.signed.nupkg"), "--skip-signed"]);
        Assert.Contains("skipped", r.Stdout);
        Assert.Contains("already signed", r.Stdout);
        Assert.True(NuGetPackage.InspectNupkgPath(output).Signed);
    }

    [Fact]
    public void OverwriteResignsAlreadySignedNupkg()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("resigned.nupkg");
        var r = RunOk([.. Sign(Repo, signer, output, "tests/fixtures/package-signing/signed/sample.signed.nupkg"), "--overwrite"]);
        Assert.Contains("signed tests/fixtures/package-signing/signed/sample.signed.nupkg", r.Stdout);
        Assert.Contains(".signature.p7s", r.Stdout);
        var sd = AssertNuGetSignatureValid(output);
        Assert.Equal(signer.Certificate.RawData, sd.Certificates![0]);
    }

    [Fact]
    public void SignsAppInstallerCompanionWithLocalCertKey()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("sample.appinstaller.p7");
        const string input = "tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller";
        Assert.Contains("detached PKCS#7 companion", RunOk(Sign(Repo, signer, output, input)).Stdout);
        AssertCmsSignatureValid(File.ReadAllBytes(output), File.ReadAllBytes(Path.Combine(Repo, input)));
    }

    [Fact]
    public void SignsAppInstallerCompanionWithAuthenticodeTimestamp()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("sample.appinstaller.p7");
        var tsa = TimestampServer();
        CodeOrchestrator.Run(new CodeOptions
        {
            BaseDirectory = Repo,
            Cert = signer.CertPath,
            Key = signer.KeyPath,
            TimestampUrl = "http://tsa.mock.test/rfc3161",
            TimestampDigest = CodeDigestAlgorithm.Sha256,
            Output = output,
            Inputs = ["tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller"],
            HttpHandler = tsa,
        });
        Assert.Equal(1, tsa.Requests);
        var der = File.ReadAllBytes(output);
        Assert.True(HasUnsignedAttribute(der, Oids.MsRfc3161TimestampToken));
        Assert.False(HasUnsignedAttribute(der, Oids.Pkcs9Rfc3161TimestampToken));
    }

    [Fact]
    public void UpdatesAppInstallerPublisherBeforeSigningCompanion()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var descriptor = dir.File("updated.appinstaller");
        var signature = dir.File("updated.appinstaller.p7");
        const string publisher = "CN=Updated App Installer Publisher, O=Example & Co";
        var r = RunOk([.. Sign(Repo, signer, signature, "tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller"), "--publisher-name", publisher]);
        Assert.Contains("updated descriptor", r.Stdout);
        Assert.Contains("detached PKCS#7 companion", r.Stdout);
        var info = Devolutions.Psign.Core.AppInstaller.AppInstallerDescriptor.Parse(File.ReadAllText(descriptor));
        Assert.Equal(publisher, info.Publisher);
        AssertCmsSignatureValid(File.ReadAllBytes(signature), File.ReadAllBytes(descriptor));
    }

    [Fact]
    public void UpdatesPrefixedAppInstallerMainBundleBeforeSigning()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.WriteAllText(dir.File("prefixed.appinstaller"), """<AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2021" xmlns:pkg="urn:example" Version="1.0.0.0" Uri="https://example.invalid/app.appinstaller"><pkg:MainBundle Name="Example.Bundle" Publisher="CN=Old" Version="1.0.0.0" Uri="https://example.invalid/app.msixbundle"/></AppInstaller>""");
        var signature = dir.File("prefixed.signed.appinstaller.p7");
        RunOk([.. Sign(dir.DirPath, signer, signature, "prefixed.appinstaller"), "--publisher-name", "CN=Updated Bundle Publisher"]);
        var xml = File.ReadAllText(dir.File("prefixed.signed.appinstaller"));
        Assert.Contains("<pkg:MainBundle", xml);
        Assert.Contains("Publisher=\"CN=Updated Bundle Publisher\"", xml);
        AssertCmsSignatureValid(File.ReadAllBytes(signature), File.ReadAllBytes(dir.File("prefixed.signed.appinstaller")));
    }

    [Fact]
    public void SignsNestedAppInstallerInsideGenericZip()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(
            dir.File("bundle.zip"),
            ("readme.txt", Utf8("App Installer bundle")),
            ("descriptors/app.appinstaller", Utf8("""<AppInstaller xmlns="http://schemas.microsoft.com/appx/appinstaller/2021" Version="1.0.0.0" Uri="https://example.invalid/app.appinstaller"><MainPackage Name="Example.App" Publisher="CN=Old" Version="1.0.0.0" ProcessorArchitecture="x64" Uri="https://example.invalid/app.msix"/></AppInstaller>""")));
        var output = dir.File("signed-bundle.zip");
        RunOk([.. Sign(dir.DirPath, signer, output, "bundle.zip"), "--publisher-name", "CN=Nested App Installer Publisher"]);

        var descriptor = ReadZipEntry(output, "descriptors/app.appinstaller");
        Assert.Contains("CN=Nested App Installer Publisher", System.Text.Encoding.UTF8.GetString(descriptor));
        AssertCmsSignatureValid(ReadZipEntry(output, "descriptors/app.appinstaller.p7"), descriptor);
        Assert.Equal(ZipCrateWriter.Stored, ZipCrateArchive.Open(File.ReadAllBytes(output)).RequireByName("descriptors/app.appinstaller.p7").CompressionMethod);
    }

    [Fact]
    public void SignsClickOnceDeployPePayloadWithLocalCertKey()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(TinyPe, dir.File("app.exe.deploy"));
        var output = dir.File("app.signed.exe.deploy");
        Assert.Contains("ClickOnce .deploy payload", RunOk(Sign(dir.DirPath, signer, output, "app.exe.deploy")).Stdout);
        AssertPeVerifies(output);
    }

    [Fact]
    public void SignsClickOnceManifestWithLocalCertKey()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.WriteAllText(dir.File("app.exe.manifest"), SampleClickOnceManifest);
        var output = dir.File("app.signed.exe.manifest");
        Assert.Contains("ClickOnce manifest XMLDSig", RunOk(Sign(dir.DirPath, signer, output, "app.exe.manifest")).Stdout);
        AssertClickOnceSignatureValid(output, signer.Certificate.RawData);
    }

    [Fact]
    public void SignsNestedClickOnceManifestInsideGenericZip()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(dir.File("bundle.zip"), ("readme.txt", Utf8("ClickOnce manifest bundle")), ("publish/app.exe.manifest", Utf8(SampleClickOnceManifest)));
        var output = dir.File("signed.zip");
        RunOk(Sign(dir.DirPath, signer, output, "bundle.zip"));
        AssertClickOnceSignatureValid(ExtractZipEntry(output, "publish/app.exe.manifest", dir.File("nested.signed.manifest")), signer.Certificate.RawData);
    }

    [Fact]
    public void RejectsClickOnceManifestTimestampingExplicitly()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.WriteAllText(dir.File("app.application"), SampleClickOnceManifest);
        var r = RunFail([.. Sign(dir.DirPath, signer, dir.File("app.signed.application"), "app.application"), "--timestamp-url", "http://127.0.0.1:9/tsa", "--timestamp-digest", "sha256"]);
        Assert.Contains("ClickOnce manifest XMLDSig timestamping is not implemented", r.Stderr);
    }

    [Fact]
    public void TimestampsVsixSignatureThroughConfiguredTsa()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/sample.vsix"), dir.File("sample.vsix"));
        var options = new CodeOptions
        {
            BaseDirectory = dir.DirPath,
            Cert = signer.CertPath,
            Key = signer.KeyPath,
            TimestampUrl = "http://tsa.mock.test/rfc3161",
            TimestampDigest = CodeDigestAlgorithm.Sha256,
            Output = dir.File("timestamped.vsix"),
            Inputs = ["sample.vsix"],
            HttpHandler = new LambdaHandler((_, _) => new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.ServiceUnavailable)),
        };
        var err = Assert.Throws<PsignException>(() => CodeOrchestrator.Run(options));
        Assert.Contains("timestamp VSIX signature for sample.vsix", PsignException.Render(err));
        Assert.Contains("TSA HTTP 503 Service Unavailable - first 0 body bytes (hex): ", PsignException.Render(err));

        options.HttpHandler = TimestampServer();
        CodeOrchestrator.Run(options);
        var xml = Devolutions.Psign.Core.Vsix.VsixPackage.ExtractSignatureXml(File.ReadAllBytes(options.Output));
        Assert.Contains("<EncodedTime>" + Convert.ToBase64String(FakeTimestampToken) + "</EncodedTime>", System.Text.Encoding.UTF8.GetString(xml));
    }

    [Fact]
    public void PreparesMsixWithNestedPeAndPublisherUpdate()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(dir.File("sample.msix"), FlatMsixEntries("Psign.Test", "x86"));
        var output = dir.File("prepared.msix");
        Assert.Contains("unsigned MSIX/AppX", RunOk([.. Sign(dir.DirPath, signer, output, "sample.msix"), "--publisher-name", "CN=Updated Publisher, O=Example & Co"]).Stdout);
        Assert.Contains("publisher=CN=Updated Publisher, O=Example & Co", RunOk("portable", "msix-manifest-info", output).Stdout);
        AssertPeVerifies(ExtractZipEntry(output, "app.exe", dir.File("app.signed.exe")));
        var blockMap = System.Text.Encoding.UTF8.GetString(ReadZipEntry(output, "AppxBlockMap.xml"));
        Assert.Contains("app.exe", blockMap);
        Assert.Contains("AppxManifest.xml", blockMap);
    }

    [Fact]
    public void PreparesMsixUploadNestedPackageWithPublisherUpdate()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(dir.File("inner.msix"), FlatMsixEntries("Psign.Test", "x86"));
        WriteZip(dir.File("sample.msixupload"), ("metadata/readme.txt", Utf8("upload container")), ("packages/inner.msix", File.ReadAllBytes(dir.File("inner.msix"))));
        var output = dir.File("prepared.msixupload");
        RunOk([.. Sign(dir.DirPath, signer, output, "sample.msixupload"), "--publisher-name", "CN=Updated Upload Publisher"]);

        var extracted = ExtractZipEntry(output, "packages/inner.msix", dir.File("prepared-inner.msix"));
        Assert.Contains("publisher=CN=Updated Upload Publisher", RunOk("portable", "msix-manifest-info", extracted).Stdout);
        AssertPeVerifies(ExtractZipEntry(extracted, "app.exe", dir.File("app.signed.exe")));
    }

    [Fact]
    public void PreparesMsixBundleWithBundleManifestPublisherUpdate()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(dir.File("inner.msix"), FlatMsixEntries("Psign.BundleChild", "x64"));
        WriteZip(
            dir.File("bundle.msixbundle"),
            ("AppxMetadata/AppxBundleManifest.xml", Utf8("""<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle" SchemaVersion="5.0"><Identity Name="Psign.Bundle" Publisher="CN=Old" Version="1.0.0.0"/><Packages><Package Type="application" Version="1.0.0.0" Architecture="x64" FileName="inner.msix" Publisher="CN=Old"/></Packages></Bundle>""")),
            ("AppxBlockMap.xml", Utf8(BlockMap)),
            ("[Content_Types].xml", Utf8("""<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="msix" ContentType="application/vnd.ms-appx"/><Default Extension="xml" ContentType="application/vnd.ms-appx.bundlemanifest+xml"/><Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/></Types>""")),
            ("inner.msix", File.ReadAllBytes(dir.File("inner.msix"))));
        var output = dir.File("prepared.msixbundle");
        Assert.Contains("unsigned MSIX/AppX", RunOk([.. Sign(dir.DirPath, signer, output, "bundle.msixbundle"), "--publisher-name", "CN=Updated Bundle Publisher"]).Stdout);

        var bundleManifest = System.Text.Encoding.UTF8.GetString(ReadZipEntry(output, "AppxMetadata/AppxBundleManifest.xml"));
        var blockMap = System.Text.Encoding.UTF8.GetString(ReadZipEntry(output, "AppxBlockMap.xml"));
        Assert.Contains("Name=\"AppxMetadata\\AppxBundleManifest.xml\"", blockMap);
        Assert.DoesNotContain("inner.msix", blockMap);
        Assert.Equal(2, bundleManifest.Split("Publisher=\"CN=Updated Bundle Publisher\"").Length - 1);

        var child = ExtractZipEntry(output, "inner.msix", dir.File("prepared-inner.msix"));
        Assert.Contains("publisher=CN=Updated Bundle Publisher", RunOk("portable", "msix-manifest-info", child).Stdout);
        AssertPeVerifies(ExtractZipEntry(child, "app.exe", dir.File("app.signed.exe")));
    }

    [Fact]
    public void ClassifiesEncryptedMsixAsOsOnlyAndFailsExplicitly()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteFile(dir.File("encrypted.emsix"), "encrypted-placeholder"u8.ToArray());
        var node = JsonNode.Parse(RunOk("code", "--dry-run", "--plan-json", "--base-directory", dir.DirPath, "encrypted.emsix").Stdout)!["nodes"]![0]!;
        Assert.Equal("encrypted-msix", node["format"]!.GetValue<string>());
        Assert.Equal("msix-encrypted-os-only", node["signer"]!.GetValue<string>());

        var r = RunFail(Sign(dir.DirPath, signer, dir.File("prepared.emsix"), "encrypted.emsix"));
        Assert.Contains("encrypted MSIX/AppX package", r.Stderr);
        Assert.Contains("Windows AppxSip OS delegation", r.Stderr);
    }

    [Fact]
    public void SignsTopLevelVsixWithLocalCertKey()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("signed.vsix");
        Assert.Contains("psign-signature.psdsxs", RunOk(Sign(Repo, signer, output, "tests/fixtures/package-signing/unsigned/sample.vsix")).Stdout);
        AssertVsixSignatureValid(File.ReadAllBytes(output), signer.Certificate.RawData);
    }

    [Fact]
    public void OverwriteResignsAlreadySignedVsix()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("resigned.vsix");
        var r = RunOk([.. Sign(Repo, signer, output, "tests/fixtures/package-signing/signed/sample.signed.vsix"), "--overwrite"]);
        Assert.Contains("signed tests/fixtures/package-signing/signed/sample.signed.vsix", r.Stdout);
        Assert.Contains("psign-signature.psdsxs", r.Stdout);
        AssertVsixSignatureValid(File.ReadAllBytes(output), signer.Certificate.RawData);
    }

    [Fact]
    public void SignsNestedNupkgBeforeOuterVsix()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(
            dir.File("nested.vsix"),
            ("extension.vsixmanifest", Utf8("<PackageManifest/>")),
            ("[Content_Types].xml", Utf8("""<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="vsixmanifest" ContentType="text/xml"/><Default Extension="nupkg" ContentType="application/octet-stream"/></Types>""")),
            ("packages/sample.nupkg", File.ReadAllBytes(Pkg("unsigned/sample.nupkg"))));
        var output = dir.File("signed.vsix");
        Assert.Contains("signed nested.vsix", RunOk(Sign(dir.DirPath, signer, output, "nested.vsix")).Stdout);
        AssertNuGetSignatureValid(ExtractZipEntry(output, "packages/sample.nupkg", dir.File("nested-signed.nupkg")));
        AssertVsixSignatureValid(File.ReadAllBytes(output), signer.Certificate.RawData);
    }

    [Fact]
    public void SignsNestedNupkgInsideGenericZip()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(dir.File("bundle.zip"), ("readme.txt", Utf8("unsigned container")), ("packages/sample.nupkg", File.ReadAllBytes(Pkg("unsigned/sample.nupkg"))));
        var output = dir.File("signed.zip");
        Assert.Contains("nested package entries", RunOk(Sign(dir.DirPath, signer, output, "bundle.zip")).Stdout);
        AssertNuGetSignatureValid(ExtractZipEntry(output, "packages/sample.nupkg", dir.File("nested-signed.nupkg")));
    }

    [Fact]
    public void ContinueOnErrorSignsRemainingTopLevelInputs()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteFile(dir.File("unsupported.exe"), "MZunsupported"u8.ToArray());
        WriteZip(dir.File("bundle.zip"), ("packages/sample.nupkg", File.ReadAllBytes(Pkg("unsigned/sample.nupkg"))));
        var outputDir = dir.File("signed");
        var r = Run([.. Sign(dir.DirPath, signer, outputDir, "bundle.zip", "unsupported.exe"), "--continue-on-error"]);
        Assert.Equal(1, r.ExitCode);
        Assert.Contains("signed bundle.zip", r.Stdout);
        Assert.Contains("failed unsupported.exe", r.Stdout);
        AssertNuGetSignatureValid(ExtractZipEntry(Path.Combine(outputDir, "bundle.zip"), "packages/sample.nupkg", dir.File("nested-signed.nupkg")));
    }

    [Fact]
    public void MaxConcurrencySignsIndependentTopLevelPackages()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/sample.nupkg"), dir.File("a.nupkg"));
        File.Copy(Pkg("unsigned/sample.snupkg"), dir.File("b.snupkg"));
        var outputDir = dir.File("signed");
        var r = RunOk([.. Sign(dir.DirPath, signer, outputDir, "a.nupkg", "b.snupkg"), "--max-concurrency", "2"]);
        Assert.Contains("signed a.nupkg", r.Stdout);
        Assert.Contains("signed b.snupkg", r.Stdout);
        Assert.True(r.Stdout.IndexOf("signed a.nupkg", StringComparison.Ordinal) < r.Stdout.IndexOf("signed b.snupkg", StringComparison.Ordinal));
        foreach (var name in new[] { "a.nupkg", "b.snupkg" })
        {
            AssertNuGetSignatureValid(Path.Combine(outputDir, name));
        }
    }

    [Fact]
    public void SignsNupkgWithRfc3161Timestamp()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/sample.nupkg"), dir.File("sample.nupkg"));
        var output = dir.File("timestamped.nupkg");
        var tsa = TimestampServer();
        CodeOrchestrator.Run(new CodeOptions
        {
            BaseDirectory = dir.DirPath,
            Cert = signer.CertPath,
            Key = signer.KeyPath,
            TimestampUrl = "http://tsa.mock.test/rfc3161",
            TimestampDigest = CodeDigestAlgorithm.Sha256,
            Output = output,
            Inputs = ["sample.nupkg"],
            HttpHandler = tsa,
        });
        Assert.Equal(1, tsa.Requests);
        var der = NuGetPackage.ExtractSignaturePath(output);
        Assert.True(HasUnsignedAttribute(der, Oids.Pkcs9Rfc3161TimestampToken));
        Assert.False(HasUnsignedAttribute(der, Oids.MsRfc3161TimestampToken));
    }

    [Fact]
    public void SignsNupkgNestedPeWithRfc3161Timestamp()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/with-pe.nupkg"), dir.File("with-pe.nupkg"));
        var output = dir.File("with-pe.timestamped.nupkg");
        var tsa = TimestampServer();
        CodeOrchestrator.Run(new CodeOptions
        {
            BaseDirectory = dir.DirPath,
            Cert = signer.CertPath,
            Key = signer.KeyPath,
            TimestampUrl = "http://tsa.mock.test/rfc3161",
            TimestampDigest = CodeDigestAlgorithm.Sha256,
            Output = output,
            Inputs = ["with-pe.nupkg"],
            HttpHandler = tsa,
        });
        Assert.Equal(2, tsa.Requests);
        var der = NuGetPackage.ExtractSignaturePath(output);
        Assert.True(HasUnsignedAttribute(der, Oids.Pkcs9Rfc3161TimestampToken));
        Assert.False(HasUnsignedAttribute(der, Oids.MsRfc3161TimestampToken));
        var nested = PeAuthenticode.FirstPkcs7(ReadZipEntry(output, "lib/net8.0/tiny32.dll"));
        Assert.True(HasUnsignedAttribute(nested, Oids.MsRfc3161TimestampToken));
        Assert.False(HasUnsignedAttribute(nested, Oids.Pkcs9Rfc3161TimestampToken));
    }

    [Fact]
    public void SignsTopLevelPeWithRfc3161Timestamp()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(TinyPe, dir.File("app.exe"));
        var output = dir.File("app.timestamped.exe");
        CodeOrchestrator.Run(new CodeOptions
        {
            BaseDirectory = dir.DirPath,
            Cert = signer.CertPath,
            Key = signer.KeyPath,
            TimestampUrl = "http://tsa.mock.test/rfc3161",
            TimestampDigest = CodeDigestAlgorithm.Sha256,
            Output = output,
            Inputs = ["app.exe"],
            HttpHandler = TimestampServer(),
        });
        AssertPeVerifies(output);
        var der = PeAuthenticode.FirstPkcs7(File.ReadAllBytes(output));
        Assert.True(HasUnsignedAttribute(der, Oids.MsRfc3161TimestampToken));
        Assert.False(HasUnsignedAttribute(der, Oids.Pkcs9Rfc3161TimestampToken));
    }

    [Fact]
    public void RejectsZeroMaxConcurrency()
    {
        var r = RunFail("code", "--dry-run", "--max-concurrency", "0");
        Assert.Contains("--max-concurrency must be greater than zero", r.Stderr);
    }

    [Fact]
    public void OverwriteResignsSignedNupkgInsideGenericZip()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(dir.File("bundle.zip"), ("readme.txt", Utf8("signed container")), ("packages/sample.nupkg", File.ReadAllBytes(Pkg("signed/sample.signed.nupkg"))));
        var output = dir.File("resigned.zip");
        Assert.Contains("nested package entries", RunOk([.. Sign(dir.DirPath, signer, output, "bundle.zip"), "--overwrite"]).Stdout);
        var sd = AssertNuGetSignatureValid(ExtractZipEntry(output, "packages/sample.nupkg", dir.File("nested-resigned.nupkg")));
        Assert.Equal(signer.Certificate.RawData, sd.Certificates![0]);
    }

    [Fact]
    public void OverwriteResignsSignedVsixInsideGenericZip()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteZip(dir.File("bundle.zip"), ("readme.txt", Utf8("signed container")), ("extensions/sample.vsix", File.ReadAllBytes(Pkg("signed/sample.signed.vsix"))));
        var output = dir.File("resigned.zip");
        Assert.Contains("nested package entries", RunOk([.. Sign(dir.DirPath, signer, output, "bundle.zip"), "--overwrite"]).Stdout);
        AssertVsixSignatureValid(ReadZipEntry(output, "extensions/sample.vsix"), signer.Certificate.RawData);
    }

    [Fact]
    public void SignsNestedPackageWhenExcludingUnsupportedInnerPayload()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/deep-nested.vsix"), dir.File("deep-nested.vsix"));
        File.WriteAllText(dir.File("files.txt"), "deep-nested.vsix\n!**/*.dll\n");
        var output = dir.File("signed.vsix");
        Assert.Contains("signed deep-nested.vsix", RunOk([.. Sign(dir.DirPath, signer, output), "--file-list", "files.txt"]).Stdout);
        var nested = ExtractZipEntry(output, "packages/with-pe.nupkg", dir.File("with-pe-signed.nupkg"));
        AssertNuGetSignatureValid(nested);
        Assert.Empty(PeAuthenticodePkcs7Count(ReadZipEntry(nested, "lib/net8.0/tiny32.dll")));
        AssertVsixSignatureValid(File.ReadAllBytes(output), signer.Certificate.RawData);
    }

    private static List<byte[]> PeAuthenticodePkcs7Count(byte[] pe)
    {
        try
        {
            return PeAuthenticode.Pkcs7Blobs(pe);
        }
        catch (PsignException)
        {
            return [];
        }
    }

    [Fact]
    public void SignsNestedPeBeforeNupkgBeforeVsix()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/deep-nested.vsix"), dir.File("deep-nested.vsix"));
        var output = dir.File("signed.vsix");
        Assert.Contains("signed deep-nested.vsix", RunOk(Sign(dir.DirPath, signer, output, "deep-nested.vsix")).Stdout);
        var nested = ExtractZipEntry(output, "packages/with-pe.nupkg", dir.File("with-pe-signed.nupkg"));
        AssertPeVerifies(ExtractZipEntry(nested, "lib/net8.0/tiny32.dll", dir.File("tiny32.signed.dll")));
        AssertNuGetSignatureValid(nested);
        AssertVsixSignatureValid(File.ReadAllBytes(output), signer.Certificate.RawData);
    }

    [Fact]
    public void DryRunDetectsOnlyNavxBusinessCentralAppFiles()
    {
        using var dir = new TempDir();
        WriteFile(dir.File("valid.app"), "NAVX\0fixture"u8.ToArray());
        WriteFile(dir.File("not-business-central.app"), "ZIP?"u8.ToArray());
        var formats = PlanFormats(RunOk("code", "--dry-run", "--plan-json", "--base-directory", dir.DirPath, "*.app").Stdout);
        Assert.Contains(formats, f => f.Path == "valid.app" && f.Format == "business-central-app");
        Assert.Contains(formats, f => f.Path == "not-business-central.app" && f.Format == "unknown");
    }

    [Fact]
    public void ExecutionReportsBusinessCentralNavxGap()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        WriteFile(dir.File("valid.app"), "NAVX\0fixture"u8.ToArray());
        Assert.Contains("Business Central NAVX .app", RunFail(Sign(dir.DirPath, signer, dir.File("signed.app"), "valid.app")).Stderr);
    }

    [Fact]
    public void DryRunClassifiesClickOnceDeployPayloads()
    {
        using var dir = new TempDir();
        WriteFile(dir.File("app.application"), "manifest"u8.ToArray());
        WriteFile(dir.File("app.exe.manifest"), "manifest"u8.ToArray());
        WriteFile(dir.File("app.exe.deploy"), "pe"u8.ToArray());
        var formats = PlanFormats(RunOk("code", "--dry-run", "--plan-json", "--base-directory", dir.DirPath, "**/*").Stdout);
        Assert.Contains(("app.application", "click-once-application", "clickonce-manifest"), formats);
        Assert.Contains(("app.exe.manifest", "manifest", "clickonce-manifest"), formats);
        Assert.Contains(("app.exe.deploy", "deploy", "clickonce-manifest"), formats);
    }

    [Fact]
    public void DryRunPlansOutputDirectoryLayout()
    {
        using var dir = new TempDir();
        var output = dir.File("signed-output");
        WriteFile(dir.File("lib/a.dll"), "pe"u8.ToArray());
        WriteFile(dir.File("tools/b.dll"), "pe"u8.ToArray());
        var paths = PlanPaths(RunOk("code", "--dry-run", "--plan-json", "--base-directory", dir.DirPath, "--output", output, "**/*.dll").Stdout, "output_path");
        var root = output.Replace('\\', '/');
        Assert.Equal([$"{root}/lib/a.dll", $"{root}/tools/b.dll"], paths);
    }

    [Fact]
    public void DryRunPlansSingleFileOutputForNestedContainer()
    {
        using var dir = new TempDir();
        var output = dir.File("signed-extension.vsix");
        var paths = PlanPaths(RunOk("code", "--dry-run", "--plan-json", "--base-directory", Repo, "--output", output, "tests/fixtures/package-signing/unsigned/deep-nested.vsix").Stdout, "output_path");
        var root = output.Replace('\\', '/');
        Assert.Contains(root, paths);
        Assert.Contains(paths, p => p.EndsWith("signed-extension.vsix!packages/with-pe.nupkg!lib/net8.0/tiny32.dll", StringComparison.Ordinal));
    }

    [Fact]
    public void DryRunTextPlanAndQuietMode()
    {
        using var dir = new TempDir();
        WriteFile(dir.File("a.dll"), "pe"u8.ToArray());
        var text = RunOk("code", "--dry-run", "--base-directory", dir.DirPath, "a.dll").Stdout;
        Assert.StartsWith("psign code dry-run plan\nbase_directory=", text);
        Assert.Contains("\nnodes=1\n#000 depth=0 format=Pe signer=authenticode path=a.dll output=a.dll\n", text);
        Assert.Equal(string.Empty, RunOk("--quiet", "code", "--dry-run", "--base-directory", dir.DirPath, "a.dll").Stdout);
    }

    [Fact]
    public void RecurseContainersFalseKeepsOnlyTopLevelNodes()
    {
        var json = RunOk("code", "--dry-run", "--plan-json", "--recurse-containers", "false", "--base-directory", Repo, "tests/fixtures/package-signing/unsigned/deep-nested.vsix").Stdout;
        Assert.Single(JsonNode.Parse(json)!["nodes"]!.AsArray());
        Assert.Equal(2, Run("code", "--dry-run", "--recurse-containers", "maybe", "a").ExitCode);
    }

    // ------------------------------------------------------------------ remote signers (mock HTTP)

    private static CodeOptions KeyVaultOptions(string baseDir, string output, string input, TestSigner signer, out CodeTestKit.LambdaHandler handler)
    {
        const string vault = "http://kv.mock.test";
        handler = KeyVault(signer.Key, signer.Certificate.RawData, vault);
        return new CodeOptions
        {
            BaseDirectory = baseDir,
            AzureKeyVaultUrl = vault,
            AzureKeyVaultCertificate = "code-cert",
            AzureKeyVaultAccessToken = "test-token",
            Output = output,
            Inputs = [input],
            HttpHandler = handler,
        };
    }

    [Fact]
    public void SignsNupkgWithAzureKeyVaultIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/sample.nupkg"), dir.File("sample.nupkg"));
        var output = dir.File("signed-kv.nupkg");
        var result = CodeOrchestrator.Run(KeyVaultOptions(dir.DirPath, output, "sample.nupkg", signer, out var kv));
        Assert.Contains(".signature.p7s", result.Stdout);
        Assert.Equal(2, kv.Requests);
        AssertNuGetAuthorAttributes(output);
    }

    [Fact]
    public void SignsPeWithAzureKeyVaultIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(TinyPe, dir.File("app.exe"));
        var output = dir.File("app.signed-kv.exe");
        Assert.Contains("Authenticode PE/WinMD", CodeOrchestrator.Run(KeyVaultOptions(dir.DirPath, output, "app.exe", signer, out _)).Stdout);
        AssertPeVerifies(output);
        var sd = AssertCmsSignatureValidAuthenticode(PeAuthenticode.FirstPkcs7(File.ReadAllBytes(output)));
        Assert.Equal(signer.Certificate.RawData, sd.Certificates![0]);
    }

    [Fact]
    public void SignsAppInstallerWithAzureKeyVaultIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("sample.appinstaller.p7");
        const string input = "tests/fixtures/generated-unsigned/appinstaller/sample.appinstaller";
        Assert.Contains("detached PKCS#7 companion", CodeOrchestrator.Run(KeyVaultOptions(Repo, output, input, signer, out _)).Stdout);
        AssertCmsSignatureValid(File.ReadAllBytes(output), File.ReadAllBytes(Path.Combine(Repo, input)));
    }

    [Fact]
    public void SignsClickOnceManifestWithAzureKeyVaultIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.WriteAllText(dir.File("app.exe.manifest"), SampleClickOnceManifest);
        var output = dir.File("app.signed.exe.manifest");
        Assert.Contains("ClickOnce manifest XMLDSig", CodeOrchestrator.Run(KeyVaultOptions(dir.DirPath, output, "app.exe.manifest", signer, out _)).Stdout);
        AssertClickOnceSignatureValid(output);
    }

    [Fact]
    public void SignsVsixWithAzureKeyVaultIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("signed-kv.vsix");
        Assert.Contains("psign-signature.psdsxs", CodeOrchestrator.Run(KeyVaultOptions(Repo, output, "tests/fixtures/package-signing/unsigned/sample.vsix", signer, out _)).Stdout);
        AssertVsixSignatureValid(File.ReadAllBytes(output), signer.Certificate.RawData);
    }

    private static CodeOptions ArtifactOptions(string baseDir, string output, string input, TestSigner signer, out CodeTestKit.LambdaHandler handler)
    {
        handler = ArtifactSigning(signer.Key, signer.Certificate.RawData);
        return new CodeOptions
        {
            BaseDirectory = baseDir,
            ArtifactSigningEndpoint = "http://codesigning.mock.test",
            ArtifactSigningAccountName = "acct",
            ArtifactSigningProfileName = "profile",
            ArtifactSigningAccessToken = "test-token",
            Output = output,
            Inputs = [input],
            HttpHandler = handler,
            Environment = _ => null,
        };
    }

    [Fact]
    public void SignsNupkgWithArtifactSigningIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(Pkg("unsigned/sample.nupkg"), dir.File("sample.nupkg"));
        var output = dir.File("signed-artifact.nupkg");
        CodeOrchestrator.Run(ArtifactOptions(dir.DirPath, output, "sample.nupkg", signer, out var handler));
        Assert.Equal(2, handler.Requests);
        AssertNuGetAuthorAttributes(output);
    }

    [Fact]
    public void SignsPeWithArtifactSigningIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        File.Copy(TinyPe, dir.File("app.exe"));
        var output = dir.File("app.signed-artifact.exe");
        Assert.Contains("Authenticode PE/WinMD", CodeOrchestrator.Run(ArtifactOptions(dir.DirPath, output, "app.exe", signer, out _)).Stdout);
        AssertPeVerifies(output);
    }

    [Fact]
    public void SignsVsixWithArtifactSigningIdentity()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var output = dir.File("signed-artifact.vsix");
        CodeOrchestrator.Run(ArtifactOptions(Repo, output, "tests/fixtures/package-signing/unsigned/sample.vsix", signer, out _));
        AssertVsixSignatureValid(File.ReadAllBytes(output), signer.Certificate.RawData);
    }

    [Fact]
    public void ArtifactSigningCertificateParsingAcceptsPemDerAndBase64()
    {
        using var dir = new TempDir();
        using var leaf = new TestSigner(dir, "CN=leaf");
        using var otherDir = new TempDir();
        using var other = new TestSigner(otherDir, "CN=other");

        var (fromPem, pemChain) = ArtifactSigningCertificates.Parse(System.Text.Encoding.ASCII.GetBytes(leaf.Certificate.ExportCertificatePem()));
        Assert.Equal(leaf.Certificate.RawData, fromPem.RawData);
        Assert.Empty(pemChain);

        var (fromDer, _) = ArtifactSigningCertificates.Parse(leaf.Certificate.RawData);
        Assert.Equal(leaf.Certificate.RawData, fromDer.RawData);

        var nested = System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(leaf.Certificate.RawData))));
        Assert.Equal(leaf.Certificate.RawData, ArtifactSigningCertificates.Parse(nested).Signer.RawData);

        // Two unrelated code-signing leaves without a SignerInfo are ambiguous (like the Rust selector).
        var bag = leaf.Certificate.ExportCertificatePem() + "\n" + other.Certificate.ExportCertificatePem();
        var err = Assert.Throws<PsignException>(() => ArtifactSigningCertificates.Parse(System.Text.Encoding.ASCII.GetBytes(bag)));
        Assert.Contains("signer certificate is ambiguous", PsignException.Render(err));
    }

    private static CmsSignedData AssertCmsSignatureValidAuthenticode(byte[] pkcs7)
    {
        var sd = CmsSignedData.Parse(pkcs7);
        var si = sd.SignerInfos[0];
        var signer = Devolutions.Psign.Core.X509.CertificateInfo.Parse(sd.Certificates![0]);
        using var rsa = signer.X509.GetRSAPublicKey()!;
        Assert.True(rsa.VerifyData(si.SignedAttributesSetDer(), si.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        return sd;
    }
}
