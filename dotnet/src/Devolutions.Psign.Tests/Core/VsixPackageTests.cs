using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.Zip;
using Xunit;
using static Devolutions.Psign.Tests.Core.PackageTestUtil;

namespace Devolutions.Psign.Tests.Core;

public class VsixPackageTests
{
    private const string Types = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"vsixmanifest\" ContentType=\"text/xml\"/></Types>";

    [Fact]
    public void EmbedSignatureXmlAddsOpcSignatureMarkers()
    {
        var zip = ZipWith(("[Content_Types].xml", B("<Types/>")));
        var output = VsixPackage.EmbedSignatureXml(zip, B("<Signature/>"), false);
        var info = OpcPackage.InspectPackage(output);
        var archive = ZipCrateArchive.Open(output);
        string contentTypes = Encoding.UTF8.GetString(archive.Read(archive.ByName(OpcPackage.ContentTypesPart)!));
        string rootRels = Encoding.UTF8.GetString(archive.Read(archive.ByName(OpcPackage.RootRelationshipsPart)!));
        string originRels = Encoding.UTF8.GetString(archive.Read(archive.ByName(VsixPackage.OpcSignatureOriginRelsPart)!));

        Assert.True(info.HasOpcSignatureOrigin);
        Assert.Equal([VsixPackage.DefaultVsixSignaturePart], info.OpcSignatureParts);
        Assert.Contains(VsixPackage.OpcSignatureOriginContentType, contentTypes);
        Assert.Contains(VsixPackage.OpcSignatureXmlContentType, contentTypes);
        Assert.Contains(VsixPackage.OpcSignatureOriginRelType, rootRels);
        Assert.Contains(VsixPackage.OpcSignatureRelType, originRels);
    }

    [Fact]
    public void SignatureInfrastructureKeepsExistingContentTypesWellFormed()
    {
        var types = B("<?xml version=\"1.0\" encoding=\"utf-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"text/xml\" /></Types>");
        string output = Encoding.UTF8.GetString(VsixPackage.EnsureSignatureContentTypes(types));
        Assert.Contains("<Default Extension=\"xml\" ContentType=\"text/xml\" />", output);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(output, "</Types>"));
        Assert.Contains("Extension=\"psdsor\"", output);
        Assert.Contains("Extension=\"rels\"", output);

        string empty = Encoding.UTF8.GetString(VsixPackage.EnsureSignatureContentTypes(B("<Types/>")));
        Assert.StartsWith("<Types>", empty);
        Assert.EndsWith("</Types>", empty);
    }

    [Fact]
    public void EmbedSignatureXmlRejectsExistingSignatureWithoutOverwrite()
    {
        var zip = ZipWith((VsixPackage.DefaultVsixSignaturePart, B("<Signature/>")));
        var e = Assert.Throws<PsignException>(() => VsixPackage.EmbedSignatureXml(zip, B("<New/>"), false));
        Assert.Contains("already contains OPC signature", e.Message);
    }

    [Fact]
    public void SignatureReferenceXmlCoversEveryPartButTheSignature()
    {
        var zip = ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("manifest")), (VsixPackage.DefaultVsixSignaturePart, B("<OldSignature/>")));
        var xml = VsixPackage.SignatureReferenceXml(zip, VsixHashAlgorithm.Sha256);
        string text = Encoding.UTF8.GetString(xml);

        Assert.Contains("<Reference URI=\"/extension.vsixmanifest?ContentType=text/xml\">", text);
        Assert.Contains("<Reference URI=\"/_rels/.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml\">", text);
        Assert.Contains($"<Reference URI=\"/{OpcPackage.OpcSignatureOriginPart}?", text);
        Assert.DoesNotContain("[Content_Types].xml?", text);
        Assert.DoesNotContain(VsixPackage.DefaultVsixSignaturePart, text);
        Assert.Contains("<Reference Type=\"http://www.w3.org/2000/09/xmldsig#Object\" URI=\"#idPackageObject\">", text);
        Assert.Equal(4, VsixPackage.VerifySignatureReferenceXml(
            ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("manifest"))),
            xml,
            VsixHashAlgorithm.Sha256));
    }

    [Fact]
    public void SignatureReferenceXmlDetectsTamperedPart()
    {
        var zip = ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("manifest")));
        var xml = VsixPackage.SignatureReferenceXml(zip, VsixHashAlgorithm.Sha256);
        var e = Assert.Throws<PsignException>(() => VsixPackage.VerifySignatureReferenceXml(
            ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("changed"))),
            xml,
            VsixHashAlgorithm.Sha256));
        Assert.Contains("digest mismatch", e.Message);
    }

    [Fact]
    public void SplitSigningStepsProduceIdenticalSignedInfo()
    {
        var zip = ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("m")));
        var first = VsixPackage.SignedInfoXml(zip, VsixHashAlgorithm.Sha256);
        var second = VsixPackage.SignedInfoXml(zip, VsixHashAlgorithm.Sha256);
        Assert.Equal(first, second);
        Assert.StartsWith("<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">", Encoding.UTF8.GetString(first));
    }

    [Fact]
    public void ExtractSignatureXmlReturnsEmbeddedSignaturePart()
    {
        var zip = ZipWith(("[Content_Types].xml", B("<Types/>")), (VsixPackage.DefaultVsixSignaturePart, B("<Signature/>")));
        Assert.Equal(B("<Signature/>"), VsixPackage.ExtractSignatureXml(zip));
    }

    [Fact]
    public void ExtractSignatureXmlRejectsMultipleOrMissingParts()
    {
        var multi = ZipWith(
            (VsixPackage.DefaultVsixSignaturePart, B("<Signature/>")),
            ("package/services/digital-signature/xml-signature/other.psdsxs", B("<Signature/>")));
        Assert.Contains("multiple", Assert.Throws<PsignException>(() => VsixPackage.ExtractSignatureXml(multi)).Message);
        Assert.Contains("does not contain", Assert.Throws<PsignException>(() => VsixPackage.ExtractSignatureXml(ZipWith(("a", B("b"))))).Message);
    }

    [Fact]
    public void SignatureXmlExtractorsRoundTrip()
    {
        var zip = ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("m")));
        var template = VsixPackage.SignatureTemplate(zip, VsixHashAlgorithm.Sha384, VsixSigningTime.FromPackage);
        var xml = template.SignatureXmlBytes([1, 2, 3], [0x30, 0x03, 0x02, 0x01, 0x01]);
        Assert.Equal(new byte[] { 1, 2, 3 }, VsixPackage.SignatureValueFromSignatureXml(xml));
        Assert.Equal(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, VsixPackage.SignerCertificateFromSignatureXml(xml));
        Assert.Equal(template.SignedInfoInDocument, Encoding.UTF8.GetString(VsixPackage.SignedInfoXmlFromSignatureXml(xml)));
        Assert.Contains("<Value>1980-01-01T00:00:00.0+00:00</Value>", Encoding.UTF8.GetString(xml));
        Assert.Equal(4, template.ReferenceCount);
    }

    [Fact]
    public void SignatureTimeValueUsesTenthsOfSeconds()
    {
        Assert.Equal("2026-11-22T10:31:05.4+00:00", VsixPackage.SignatureTimeValue(new DateTimeOffset(2026, 11, 22, 11, 31, 5, 456, TimeSpan.FromHours(1))));
    }

    [Fact]
    public void LegacyReferenceVerificationChecksDigests()
    {
        var zip = ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("m")));
        string digest = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(B("m")));
        string legacy = $"<Signature><SignedInfo><Reference URI=\"/extension.vsixmanifest\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>{digest}</DigestValue></Reference></SignedInfo></Signature>";
        Assert.Equal(1, VsixPackage.VerifyLegacySignatureReferenceXml(zip, B(legacy), VsixHashAlgorithm.Sha256));
        var tampered = ZipWith(("[Content_Types].xml", B(Types)), ("extension.vsixmanifest", B("x")));
        Assert.Contains("digest mismatch", Assert.Throws<PsignException>(() => VsixPackage.VerifyLegacySignatureReferenceXml(tampered, B(legacy), VsixHashAlgorithm.Sha256)).Message);
    }

    [Fact]
    public void ReferenceXmlVerifiesAgainstDotnetSignedFixturePackage()
    {
        // The dotnet-signed fixture uses System.IO.Packaging's layout; our template must at least produce SignedInfo for
        // its unsigned source without error and cover every part.
        var unsigned = Fixtures.Bytes("package-signing/unsigned/sample.vsix");
        var template = VsixPackage.SignatureTemplate(unsigned, VsixHashAlgorithm.Sha256, VsixSigningTime.FromPackage);
        Assert.True(template.ReferenceCount >= 4);
    }

    // ---------------------------------------------------------------- differential vs Rust

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void SignatureReferenceXmlAndPrehashMatchRust(string alg)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var algorithm = VsixHashAlgorithmExtensions.FromHashKind(AuthenticodeHashKinds.Parse(alg));
        foreach (var rel in new[] { "package-signing/unsigned/sample.vsix", "package-signing/unsigned/nested.vsix", "package-signing/unsigned/deep-nested.vsix", "package-signing/signed/sample.signed.vsix" })
        {
            var path = Fixtures.Path(rel);
            var refPath = dir.File("ref.xml");
            RustTool.RunOk("portable", "vsix-signature-reference-xml", path, "--algorithm", alg, "--output", refPath);
            Assert.Equal(File.ReadAllBytes(refPath), VsixPackage.SignatureReferenceXmlPath(path, algorithm));

            var prehashPath = dir.File("prehash.bin");
            RustTool.RunOk("portable", "vsix-signature-xml-prehash", path, "--algorithm", alg, "--encoding", "raw", "--output", prehashPath);
            Assert.Equal(File.ReadAllBytes(prehashPath), algorithm.Hash(VsixPackage.SignedInfoXmlPath(path, algorithm)));

            var stdout = RustTool.RunOk("portable", "vsix-verify-signature-reference-xml", path, "--signature-xml", refPath, "--algorithm", alg);
            int count = VsixPackage.VerifySignatureReferenceXmlPath(path, File.ReadAllBytes(refPath), algorithm);
            Assert.Contains($"reference_count={count}", stdout);
        }
    }

    [SkippableFact]
    public void EmbedSignatureXmlIsByteIdenticalToRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var xmlPath = dir.File("sig.xml");
        File.WriteAllBytes(xmlPath, B("<Signature>opaque</Signature>"));
        var inputs = new List<byte[]>
        {
            Fixtures.Bytes("package-signing/unsigned/sample.vsix"),
            Fixtures.Bytes("package-signing/unsigned/deep-nested.vsix"),
            BclZip([.. StressPayloads().Select(p => (p.Name, p.Data, false)), ("[Content_Types].xml", B(Types), false), ("dir/", Array.Empty<byte>(), true)]),
            ZipWith(("[Content_Types].xml", B("<Types/>"))),
            ZipWith(("payload.bin", B("x"))),
        };
        foreach (var input in inputs)
        {
            var inPath = dir.File("in.vsix");
            var outPath = dir.File("out.vsix");
            File.WriteAllBytes(inPath, input);
            RustTool.RunOk("portable", "vsix-embed-signature-xml", inPath, "--signature-xml", xmlPath, "--output", outPath);
            Assert.Equal(File.ReadAllBytes(outPath), VsixPackage.EmbedSignatureXml(input, File.ReadAllBytes(xmlPath), false));
        }

        // Overwrite of an already signed package.
        var signed = Fixtures.Path("package-signing/signed/sample.signed.vsix");
        var overwritten = dir.File("over.vsix");
        RustTool.RunOk("portable", "vsix-embed-signature-xml", signed, "--signature-xml", xmlPath, "--output", overwritten, "--overwrite");
        Assert.Equal(File.ReadAllBytes(overwritten), VsixPackage.EmbedSignatureXml(File.ReadAllBytes(signed), File.ReadAllBytes(xmlPath), true));
    }

    [SkippableFact]
    public void EmbedErrorsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var xmlPath = dir.File("sig.xml");
        File.WriteAllBytes(xmlPath, B("<Signature/>"));
        var signed = Fixtures.Path("package-signing/signed/sample.signed.vsix");
        var (code, _, stderr) = RustTool.Run("portable", "vsix-embed-signature-xml", signed, "--signature-xml", xmlPath, "--output", dir.File("x.vsix"));
        Assert.NotEqual(0, code);
        var e = Assert.Throws<PsignException>(() => VsixPackage.EmbedSignatureXmlPath(signed, dir.File("y.vsix"), File.ReadAllBytes(xmlPath), false));
        Assert.Contains(e.Message, stderr);
    }
}
