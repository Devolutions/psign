using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.AppInstaller;
using Devolutions.Psign.Core.ClickOnce;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.AppInstaller;
using Devolutions.Psign.Signing.ClickOnce;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.NuGet;
using Devolutions.Psign.Signing.Vsix;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

public class PackageSignerParityTests
{
    private const string AppInstallerFixture = "generated-unsigned/appinstaller/sample.appinstaller";

    // ---------------------------------------------------------------- NuGet

    [Fact]
    public void NuGetSignedPackageCarriesVerifiableCms()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var unsigned = Fixtures.Bytes("package-signing/unsigned/sample.nupkg");
        var result = NuGetSigner.SignPackage(unsigned, NuGetHashAlgorithm.Sha256, signer.Info, [], new RsaDigestSigner(signer.Key), overwrite: false);

        Assert.Equal(result.SignatureDer, NuGetPackage.ExtractSignature(result.SignedPackage));
        var content = NuGetPackage.SignedPackageSignatureContent(result.SignedPackage, NuGetHashAlgorithm.Sha256);
        Assert.Equal(result.SignatureContent, content);

        var cms = CmsSignedData.Parse(result.SignatureDer);
        Assert.Equal(Pkcs7IdData.EContentDer(content), cms.EncapContent);
        var si = cms.SignerInfos[0];
        Assert.True(signer.Key.VerifyData(si.SignedAttributesSetDer(), si.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Equal(SHA256.HashData(content), si.MessageDigest());
        Assert.NotNull(si.GetSignedAttribute(Oids.Pkcs9SigningTime));

        Assert.Throws<PsignException>(() => NuGetSigner.SignPackage(result.SignedPackage, NuGetHashAlgorithm.Sha256, signer.Info, [], new RsaDigestSigner(signer.Key), overwrite: false));
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    public void NuGetPrehashAndFromSignatureMatchRust(string alg)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var algorithm = NuGetHashAlgorithmExtensions.FromHashKind(AuthenticodeHashKinds.Parse(alg));
        var package = Fixtures.Path("package-signing/unsigned/with-pe.nupkg");

        var prehashPath = dir.File("prehash.bin");
        RustTool.RunOk("portable", "nupkg-signature-pkcs7-prehash", package, "--algorithm", alg, "--cert", signer.CertPath, "--encoding", "raw", "--output", prehashPath);
        var prehash = NuGetSigner.SignaturePkcs7Prehash(File.ReadAllBytes(package), algorithm, signer.Info);
        Assert.Equal(File.ReadAllBytes(prehashPath), prehash);

        var signature = signer.Key.SignHash(prehash, algorithm.ToHashKind().HashAlgorithmName(), RSASignaturePadding.Pkcs1);
        var sigPath = dir.File("external.sig");
        File.WriteAllBytes(sigPath, signature);
        var rustCms = dir.File("rust.p7s");
        RustTool.RunOk("portable", "nupkg-signature-pkcs7-from-signature", package, "--algorithm", alg, "--cert", signer.CertPath, "--signature", sigPath, "--output", rustCms);
        var cms = NuGetSigner.SignaturePkcs7FromSignature(File.ReadAllBytes(package), algorithm, signer.Info, [], signature);
        Assert.Equal(File.ReadAllBytes(rustCms), cms);

        // nupkg-sign with an embedded signature is byte-identical once the signing time / ZIP timestamp are aligned.
        var rustSigned = dir.File("rust-signed.nupkg");
        RustTool.RunOk("portable", "nupkg-embed-signature", package, "--signature", rustCms, "--output", rustSigned);
        var rustBytes = File.ReadAllBytes(rustSigned);
        var stamp = ZipCrateArchive.Open(rustBytes).ByName(NuGetPackage.PackageSignatureFileName)!.LastModified;
        Assert.Equal(rustBytes, NuGetPackage.EmbedSignature(File.ReadAllBytes(package), cms, false, stamp));
    }

    [SkippableFact]
    public void NuGetSignOutputMatchesRustStructure()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var package = Fixtures.Path("package-signing/unsigned/sample.nupkg");
        var rustOut = dir.File("rust.nupkg");
        var stdout = RustTool.RunOk("portable", "nupkg-sign", package, "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", rustOut);
        var rustBytes = File.ReadAllBytes(rustOut);
        var rustCms = CmsSignedData.Parse(NuGetPackage.ExtractSignature(rustBytes));
        var signingTimeAttr = rustCms.SignerInfos[0].GetSignedAttribute(Oids.Pkcs9SigningTime)!;
        var signingTime = new System.Formats.Asn1.AsnReader(signingTimeAttr.Values[0], System.Formats.Asn1.AsnEncodingRules.DER).ReadUtcTime();
        var stamp = ZipCrateArchive.Open(rustBytes).ByName(NuGetPackage.PackageSignatureFileName)!.LastModified;

        var result = NuGetSigner.SignPackage(File.ReadAllBytes(package), NuGetHashAlgorithm.Sha256, signer.Info, [], new RsaDigestSigner(signer.Key), false, signingTime, stamp);
        Assert.Equal(rustBytes, result.SignedPackage);
        Assert.Contains($"signature_len={result.SignatureDer.Length}", stdout);
    }

    // ---------------------------------------------------------------- VSIX

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void VsixSignatureXmlMatchesRust(string alg)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var algorithm = VsixHashAlgorithmExtensions.FromHashKind(AuthenticodeHashKinds.Parse(alg));
        var package = Fixtures.Path("package-signing/unsigned/nested.vsix");

        var rustXml = dir.File("rust.xml");
        RustTool.RunOk("portable", "vsix-signature-xml", package, "--algorithm", alg, "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", rustXml);
        var (xml, _) = VsixSigner.CreateSignatureXml(File.ReadAllBytes(package), algorithm, signer.Certificate.RawData, signer.Key, VsixSigningTime.FromPackage);
        Assert.Equal(File.ReadAllBytes(rustXml), xml);

        // From-signature flow.
        var prehash = VsixSigner.SignedInfoRemotePrehash(algorithm, VsixPackage.SignedInfoXml(File.ReadAllBytes(package), algorithm));
        var sigPath = dir.File("sig.bin");
        File.WriteAllBytes(sigPath, signer.Key.SignHash(prehash, algorithm.ToHashKind().HashAlgorithmName(), RSASignaturePadding.Pkcs1));
        var rustFromSig = dir.File("rust-from-sig.xml");
        RustTool.RunOk("portable", "vsix-signature-xml-from-signature", package, "--algorithm", alg, "--cert", signer.CertPath, "--signature", sigPath, "--output", rustFromSig);
        Assert.Equal(File.ReadAllBytes(rustFromSig), VsixPackage.SignatureXmlPath(package, algorithm, File.ReadAllBytes(sigPath), signer.Certificate.RawData));

        // Rust verifies the C# signature after embedding.
        var embedded = dir.File("embedded.vsix");
        VsixPackage.EmbedSignatureXmlPath(package, embedded, xml, false);
        var verify = RustTool.RunOk("portable", "vsix-verify-signature", embedded, "--algorithm", alg, "--trusted-ca", signer.CertPath, "--allow-loose-signing-cert", "--as-of", DateTime.UtcNow.ToString("yyyy-MM-dd"));
        Assert.Contains("vsix-verify-signature: ok", verify);
    }

    [SkippableFact]
    public void VsixSignWithFixedTimeMatchesRustStructure()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var package = Fixtures.Path("package-signing/unsigned/sample.vsix");
        var rustOut = dir.File("rust.vsix");
        var stdout = RustTool.RunOk("portable", "vsix-sign", package, "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", rustOut);
        var rustBytes = File.ReadAllBytes(rustOut);
        string rustXml = Encoding.UTF8.GetString(VsixPackage.ExtractSignatureXml(rustBytes));
        string value = rustXml[(rustXml.IndexOf("<Value>", StringComparison.Ordinal) + 7)..rustXml.IndexOf("</Value>", StringComparison.Ordinal)];
        var time = DateTimeOffset.Parse(value[..19] + "Z", System.Globalization.CultureInfo.InvariantCulture).AddMilliseconds((value[20] - '0') * 100);

        var result = VsixSigner.SignPackage(File.ReadAllBytes(package), VsixHashAlgorithm.Sha256, signer.Certificate.RawData, signer.Key, false, time);
        Assert.Equal(rustBytes, result.SignedPackage);
        Assert.Contains($"reference_count={result.Template.ReferenceCount}", stdout);
        Assert.Contains($"signature_xml_len={result.SignatureXml.Length}", stdout);
    }

    [Fact]
    public void VsixTimestampIsAppendedAsEncodedTimeObject()
    {
        var xml = VsixSigner.AddSignatureTimestamp("<Signature><SignatureValue>AA==</SignatureValue></Signature>"u8.ToArray(), [0x30, 0x00]);
        string text = Encoding.UTF8.GetString(xml);
        Assert.EndsWith("<EncodedTime>MAA=</EncodedTime></TimeStamp></Object></Signature>", text);
        Assert.Throws<PsignException>(() => VsixSigner.AddSignatureTimestamp(xml, [0x30, 0x00]));
        Assert.Equal(new byte[] { 0 }, VsixSigner.TimestampImprintInput(xml));
    }

    // ---------------------------------------------------------------- ClickOnce

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    public void ClickOnceSignManifestMatchesRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var kind = AuthenticodeHashKinds.Parse(digest);
        var manifest = dir.File("app.exe.manifest");
        File.WriteAllText(manifest, """
            <?xml version="1.0" encoding="utf-8"?>
            <assembly xmlns="urn:schemas-microsoft-com:asm.v1">
              <assemblyIdentity name="ClickOnce.Sample" version="1.0.0.0" />
              <description asmv2:publisher="Example" xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" />
            </assembly>
            """);

        var rustOut = dir.File("rust.manifest");
        var stdout = RustTool.RunOk("portable", "clickonce-sign-manifest", manifest, "--digest", digest, "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", rustOut);
        var csOut = dir.File("cs.manifest");
        var report = ClickOnceSigner.SignManifestPath(manifest, signer.CertPath, signer.Key, kind, csOut);
        Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(csOut));
        Assert.Equal($"output={rustOut}\ndigest={report.DigestDebugName}\nmanifest_digest_b64={report.ManifestDigestB64}\nsignature_len={report.SignatureLen}\n", stdout.Replace("\r\n", "\n"));

        // Re-signing replaces the existing signature.
        var resigned = ClickOnceSigner.SignManifest(File.ReadAllText(csOut), kind, signer.Certificate.RawData, signer.Key);
        Assert.Equal(File.ReadAllText(csOut), resigned.SignedManifest);

        // Verification (crypto + trust hook) and the Rust verifier agree.
        int hookCalls = 0;
        var verified = ClickOnceManifest.VerifyManifestSignaturePath(rustOut, null, kind, cert => { hookCalls++; return 1; });
        Assert.Equal(report.ManifestDigestB64, verified.ManifestDigestB64);
        Assert.Equal(1, hookCalls);
        Assert.Equal(1, verified.TrustAnchorCount);
        var rustVerify = RustTool.RunOk("portable", "clickonce-verify-manifest-signature", csOut, "--digest", digest);
        Assert.Equal(
            $"clickonce-verify-manifest-signature: ok\ndigest={verified.DigestDebugName}\nmanifest_digest_b64={verified.ManifestDigestB64}\nmanifest_digest_match=yes\nsignature_value_match=yes\nsignature_len={verified.SignatureLen}\n",
            rustVerify.Replace("\r\n", "\n"));

        // Tampering is detected the same way.
        var tampered = dir.File("tampered.manifest");
        File.WriteAllText(tampered, File.ReadAllText(csOut).Replace("ClickOnce.Sample", "ClickOnce.Tampered", StringComparison.Ordinal));
        var e = Assert.Throws<PsignException>(() => ClickOnceManifest.VerifyManifestSignaturePath(tampered, null, kind));
        var (code, _, stderr) = RustTool.Run("portable", "clickonce-verify-manifest-signature", tampered, "--digest", digest);
        Assert.NotEqual(0, code);
        Assert.Contains(e.Message, stderr);
    }

    [SkippableFact]
    public void ClickOnceFromSignatureMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var manifest = dir.File("app.exe.manifest");
        File.WriteAllText(manifest, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n  <assemblyIdentity name=\"ClickOnce.External\" version=\"1.0.0.0\" />\n</assembly>");
        var prehash = ClickOnceManifest.SignManifestPrehash(ClickOnceManifest.ReadManifestText(manifest), AuthenticodeHashKind.Sha256);
        var sigPath = dir.File("sig.bin");
        File.WriteAllBytes(sigPath, signer.Key.SignHash(prehash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        var rustOut = dir.File("rust.manifest");
        RustTool.RunOk("portable", "clickonce-sign-manifest-from-signature", manifest, "--cert", signer.CertPath, "--signature", sigPath, "--output", rustOut);
        var csOut = dir.File("cs.manifest");
        ClickOnceManifest.SignManifestFromExternalSignaturePath(manifest, signer.CertPath, sigPath, AuthenticodeHashKind.Sha256, csOut);
        Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(csOut));

        var report = ClickOnceManifest.VerifyManifestSignature(File.ReadAllText(csOut), AuthenticodeHashKind.Sha256, signer.Certificate.RawData);
        Assert.Equal(256, report.SignatureLen);

        // Wrong key fails the cryptographic check.
        using var other = new TestSigner(dir, "CN=other");
        var e = Assert.Throws<PsignException>(() => ClickOnceManifest.VerifyManifestSignature(File.ReadAllText(csOut), AuthenticodeHashKind.Sha256, other.Certificate.RawData));
        Assert.Contains("verify ClickOnce SignatureValue", e.Message);
    }

    // ---------------------------------------------------------------- App Installer

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void AppInstallerCompanionMatchesRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var kind = AuthenticodeHashKinds.Parse(digest);
        var descriptor = Fixtures.Path(AppInstallerFixture);
        string text = AppInstallerDescriptor.ReadText(descriptor);

        var rustOut = dir.File("rust.p7");
        var stdout = RustTool.RunOk("portable", "appinstaller-sign-companion", descriptor, "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", digest, "--output", rustOut);
        var cms = AppInstallerCompanionSigner.SignCompanion(text, signer.Info, [], signer.Key, kind);
        Assert.Equal(File.ReadAllBytes(rustOut), cms);
        Assert.Contains($"companion_signature_len={cms.Length}", stdout);
        Assert.Contains($"digest={ClickOnceManifest.DigestDebugName(kind)}", stdout);

        var prehashPath = dir.File("prehash.bin");
        RustTool.RunOk("portable", "appinstaller-sign-companion-prehash", descriptor, "--digest", digest, "--encoding", "raw", "--output", prehashPath);
        var prehash = AppInstallerCompanionSigner.CompanionPrehash(text, kind);
        Assert.Equal(File.ReadAllBytes(prehashPath), prehash);

        var sigPath = dir.File("sig.bin");
        File.WriteAllBytes(sigPath, signer.Key.SignHash(prehash, kind.HashAlgorithmName(), RSASignaturePadding.Pkcs1));
        var rustFromSig = dir.File("rust-from-sig.p7");
        RustTool.RunOk("portable", "appinstaller-sign-companion-from-signature", descriptor, "--cert", signer.CertPath, "--signature", sigPath, "--digest", digest, "--output", rustFromSig);
        Assert.Equal(File.ReadAllBytes(rustFromSig), AppInstallerCompanionSigner.SignCompanionFromSignature(text, signer.Info, [], kind, File.ReadAllBytes(sigPath)));

        if (kind != AuthenticodeHashKind.Sha256)
        {
            // The Rust detached CMS trust fallback only accepts SHA-256 signer digests.
            return;
        }

        var csPath = dir.File("cs.p7");
        File.WriteAllBytes(csPath, cms);
        var verify = RustTool.RunOk("portable", "appinstaller-verify-companion", descriptor, "--signature", csPath, "--trusted-ca", signer.CertPath, "--allow-loose-signing-cert");
        Assert.Contains("appinstaller-verify-companion: ok", verify);
    }

    [Fact]
    public void TimestampAttachmentUsesRequestedAttribute()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        string text = AppInstallerDescriptor.ReadText(Fixtures.Path(AppInstallerFixture));
        var cms = AppInstallerCompanionSigner.SignCompanion(text, signer.Info, [], signer.Key, AuthenticodeHashKind.Sha256);
        byte[] token = Pkcs7Builder.CreateUnsignedSignedData(Oids.Pkcs7Data, Pkcs7IdData.EContentDer([1]), Pkcs7Builder.DigestAlgorithm(AuthenticodeHashKind.Sha256));
        byte[]? seen = null;
        var stamped = Pkcs7IdData.Timestamp(cms, sig => { seen = sig; return token; }, Rfc3161TimestampAttribute.MicrosoftAuthenticode);
        var sd = CmsSignedData.Parse(stamped);
        Assert.Equal(sd.SignerInfos[0].Signature, seen);
        Assert.NotNull(sd.SignerInfos[0].GetUnsignedAttribute(Oids.MsRfc3161TimestampToken));
        var nuget = CmsSignedData.Parse(NuGetSigner.AttachTimestampToken(cms, token));
        Assert.NotNull(nuget.SignerInfos[0].GetUnsignedAttribute(Oids.Pkcs9Rfc3161TimestampToken));
    }
}
