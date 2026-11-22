using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.ClickOnce;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Xml;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class ClickOnceManifestTests
{
    private const string StaleManifest = """
        <?xml version="1.0" encoding="utf-8"?>
        <assembly xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
          <file name="bin/app.dll" size="0">
            <hash>
              <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
              <dsig:DigestValue>stale</dsig:DigestValue>
            </hash>
          </file>
        </assembly>
        """;

    [Fact]
    public void DeployInfoAndCopyPayloadUseContentName()
    {
        using var dir = new TempDir();
        var deployed = dir.File("app.exe.deploy");
        var output = dir.File("app.exe");
        File.WriteAllBytes(deployed, "payload"u8.ToArray());

        var info = ClickOnceManifest.InspectDeployPayload(deployed);
        Assert.True(info.Deployed);
        Assert.Equal("app.exe", info.ContentName);
        Assert.Equal(7ul, info.Len);

        Assert.Equal(7, ClickOnceManifest.CopyDeployPayload(deployed, output));
        Assert.Equal("payload"u8.ToArray(), File.ReadAllBytes(output));

        Assert.Null(ClickOnceManifest.DeployContentName(dir.File(".deploy")));
        Assert.Null(ClickOnceManifest.DeployContentName(dir.File("app.exe")));
        var e = Assert.Throws<PsignException>(() => ClickOnceManifest.CopyDeployPayload(output, dir.File("x")));
        Assert.Contains("must end with .deploy", e.Message);
    }

    [Fact]
    public void ManifestHashesCanUpdateAndVerifyFileReferences()
    {
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("bin"));
        File.WriteAllBytes(dir.File("bin/app.dll"), "ClickOnce payload"u8.ToArray());
        var manifest = dir.File("app.exe.manifest");
        var updated = dir.File("app.updated.manifest");
        File.WriteAllText(manifest, StaleManifest);

        var stale = ClickOnceManifest.ManifestHashes(manifest, dir.DirPath);
        Assert.Single(stale);
        Assert.Equal("mismatch", stale[0].Status);
        Assert.Equal(AuthenticodeHashKind.Sha1, stale[0].Algorithm);

        Assert.Equal(1, ClickOnceManifest.UpdateManifestHashes(manifest, dir.DirPath, updated, AuthenticodeHashKind.Sha256));
        string updatedText = File.ReadAllText(updated);
        Assert.Contains("size=\"17\"", updatedText);
        Assert.Contains("http://www.w3.org/2001/04/xmlenc#sha256", updatedText);
        Assert.DoesNotContain(">stale<", updatedText);

        var valid = ClickOnceManifest.ManifestHashes(updated, dir.DirPath);
        Assert.Single(valid);
        Assert.Equal("bin/app.dll", valid[0].Path);
        Assert.Equal(AuthenticodeHashKind.Sha256, valid[0].Algorithm);
        Assert.Equal("valid", valid[0].Status);
    }

    [Theory]
    [InlineData("../x")]
    [InlineData("/etc/passwd")]
    public void ResolveManifestPathRejectsEscapes(string path)
    {
        var e = Assert.Throws<PsignException>(() => ClickOnceManifest.ResolveManifestPath("base", path));
        Assert.Contains("must be relative", e.Message);
        Assert.Contains("is empty", Assert.Throws<PsignException>(() => ClickOnceManifest.ResolveManifestPath("base", "./")).Message);
    }

    [Fact]
    public void SignedInfoLayoutMatchesRust()
    {
        string unsigned = "<assembly/>";
        string si = Encoding.UTF8.GetString(ClickOnceManifest.SignedInfoXml(unsigned, AuthenticodeHashKind.Sha256));
        string digest = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(unsigned)));
        Assert.Equal(
            "<SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>"
            + digest + "</DigestValue></Reference></SignedInfo>",
            si);
        Assert.Throws<PsignException>(() => ClickOnceManifest.SignedInfoXml(unsigned, AuthenticodeHashKind.Sha1));
    }

    [Fact]
    public void SignatureInsertionAndRemovalRoundTrip()
    {
        string manifest = "<?xml version=\"1.0\"?>\n<!-- c --><asmv1:assembly xmlns:asmv1=\"urn:x\"><a/></asmv1:assembly>\n";
        var si = ClickOnceManifest.SignedInfoXml(manifest, AuthenticodeHashKind.Sha384);
        string sig = ClickOnceManifest.SignatureXml(si, [9, 9], [0x30, 0x00]);
        string signed = ClickOnceManifest.InsertSignatureXml(manifest, sig);
        Assert.EndsWith(sig + "</asmv1:assembly>\n", signed);
        Assert.Equal(manifest, ClickOnceManifest.UnsignedManifestText(signed));
        Assert.Equal(si, ClickOnceManifest.SignedInfoFromSignatureXml(sig));
        Assert.Equal(new byte[] { 9, 9 }, ClickOnceManifest.SignatureValueFromSignatureXml(sig));
        Assert.Equal(new byte[] { 0x30, 0x00 }, ClickOnceManifest.SignerCertificateFromSignatureXml(sig));
        Assert.True(ClickOnceManifest.HasSignature(Encoding.UTF8.GetBytes(signed)));
        Assert.False(ClickOnceManifest.HasSignature(Encoding.UTF8.GetBytes(manifest)));
    }

    [Fact]
    public void XmlDsigBase64DecoderMatchesRustQuirks()
    {
        Assert.Equal(new byte[] { 1, 2, 3 }, RustBase64.DecodeXmlDsig(" AQ\nID "));
        Assert.Equal(new byte[] { 1 }, RustBase64.DecodeXmlDsig("AQ=="));
        Assert.Contains("truncated", Assert.Throws<PsignException>(() => RustBase64.DecodeXmlDsig("AQI")).Message);
        Assert.Contains("invalid base64", Assert.Throws<PsignException>(() => RustBase64.DecodeXmlDsig("A*==")).Message);
    }

    [Fact]
    public void TextScanHelpersMatchRust()
    {
        Assert.Equal("a & b", XmlTextScan.XmlAttr("<x data-Name=\"no\" Name=\"a &amp; b\">", "Name"));
        Assert.Equal("&bogus; A", XmlTextScan.XmlAttr("<x Name='&bogus; &#x41;'>", "Name"));
        Assert.Null(XmlTextScan.XmlAttr("<x xName=\"a\">", "Name"));
        Assert.Equal("<x a=\"1\" b=\"2\"/>", XmlTextScan.ReplaceOrInsertXmlAttr("<x a=\"1\"/>", "b", "2"));
        Assert.Equal("<x a=\"3\">", XmlTextScan.ReplaceOrInsertXmlAttr("<x a=\"1\">", "a", "3"));
        Assert.Equal("&amp;&quot;&lt;&gt;", XmlTextScan.XmlEscapeAttr("&\"<>"));
        var root = XmlTextScan.FindXmlRootStartTag("<?xml?><!--x--><p:root a='1'>");
        Assert.Equal("p:root", root.Name);
        Assert.Contains("unexpected closing tag", Assert.Throws<PsignException>(() => XmlTextScan.FindXmlRootStartTag("</x>")).Message);
        Assert.Equal(3, XmlTextScan.FindXmlStartTag("<a><file>", "file", 0));
        Assert.Null(XmlTextScan.FindXmlStartTag("<files>", "file", 0));
    }

    // ---------------------------------------------------------------- differential vs Rust

    [SkippableFact]
    public void ManifestHashesOutputMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        Directory.CreateDirectory(dir.File("bin"));
        File.WriteAllBytes(dir.File("bin/app.dll"), "ClickOnce payload"u8.ToArray());
        File.WriteAllBytes(dir.File("bin/other.dll"), "other"u8.ToArray());
        var manifest = dir.File("app.exe.manifest");
        File.WriteAllText(manifest, StaleManifest.Replace("</assembly>", """
              <dependentAssembly codebase="bin/other.dll" size="5">
                <hash><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue> x </DigestValue></hash>
              </dependentAssembly>
            </assembly>
            """, StringComparison.Ordinal));

        var (code, stdout, stderr) = RustTool.Run("portable", "clickonce-manifest-hashes", manifest, "--base-directory", dir.DirPath);
        Assert.NotEqual(0, code);
        Assert.Contains("hash verification failed (2 mismatch(es))", stderr);
        Assert.Equal(RenderHashes(ClickOnceManifest.ManifestHashes(manifest, dir.DirPath)), stdout.Replace("\r\n", "\n"));

        foreach (var alg in new[] { "sha1", "sha256", "sha384", "sha512" })
        {
            var rustOut = dir.File($"rust-{alg}.manifest");
            var csOut = dir.File($"cs-{alg}.manifest");
            var rustStdout = RustTool.RunOk("portable", "clickonce-update-manifest-hashes", manifest, "--base-directory", dir.DirPath, "--algorithm", alg, "--output", rustOut);
            int updated = ClickOnceManifest.UpdateManifestHashes(manifest, dir.DirPath, csOut, AuthenticodeHashKinds.Parse(alg));
            Assert.Contains($"updated={updated}", rustStdout);
            Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(csOut));
            Assert.Equal(RenderHashes(ClickOnceManifest.ManifestHashes(csOut, dir.DirPath)), RustTool.RunOk("portable", "clickonce-manifest-hashes", csOut, "--base-directory", dir.DirPath).Replace("\r\n", "\n"));
        }
    }

    [SkippableFact]
    public void DeployInfoMatchesRust()
    {
        RustTool.Require();
        var probe = Fixtures.Path("generated-unsigned/optional-provider/probe.deploy");
        var info = ClickOnceManifest.InspectDeployPayload(probe);
        string expected = $"deployed={(info.Deployed ? "yes" : "no")}\ncontent_name={info.ContentName ?? "-"}\nlen={info.Len}\n";
        Assert.Equal(expected, RustTool.RunOk("portable", "clickonce-deploy-info", probe).Replace("\r\n", "\n"));
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void SignManifestPrehashMatchesRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var manifest = dir.File("app.exe.manifest");
        File.WriteAllText(manifest, "﻿<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">\r\n  <assemblyIdentity name=\"ClickOnce.External\" version=\"1.0.0.0\" />\r\n</assembly>");
        var prehash = dir.File("prehash.bin");
        RustTool.RunOk("portable", "clickonce-sign-manifest-prehash", manifest, "--digest", digest, "--encoding", "raw", "--output", prehash);
        Assert.Equal(File.ReadAllBytes(prehash), ClickOnceManifest.SignManifestPrehash(ClickOnceManifest.ReadManifestText(manifest), AuthenticodeHashKinds.Parse(digest)));
    }

    internal static string RenderHashes(List<ClickOnceManifestHashEntry> entries)
    {
        var sb = new StringBuilder();
        sb.Append($"references={entries.Count}\n");
        int mismatches = 0;
        foreach (var e in entries)
        {
            if (e.Status != "valid")
            {
                mismatches++;
            }

            sb.Append($"path={e.Path} algorithm={ClickOnceManifest.HashAlgLabel(e.Algorithm)} expected_size={(e.ExpectedSize?.ToString() ?? "-")} actual_size={e.ActualSize} status={e.Status}\n");
            sb.Append($"expected_digest_b64={e.ExpectedDigestB64}\n");
            sb.Append($"actual_digest_b64={e.ActualDigestB64}\n");
        }

        sb.Append($"mismatches={mismatches}\n");
        return sb.ToString();
    }
}
