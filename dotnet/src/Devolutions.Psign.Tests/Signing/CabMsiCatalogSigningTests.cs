using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cab;
using Devolutions.Psign.Signing.Catalog;
using Devolutions.Psign.Signing.Msi;
using OpenMcdf;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

public class CabMsiCatalogSigningTests
{
    private const string UnsignedCab = "generated-unsigned/cab/sample.cab";

    private static readonly string[] CatalogSubjects =
    [
        "catalog-workflows/subjects/tiny32.efi",
        "catalog-workflows/subjects/hello.txt",
        "catalog-workflows/subjects/blob.bin",
    ];

    private static List<CatalogSubjectInput> Subjects(IEnumerable<string> paths) =>
        paths.Select(p => new CatalogSubjectInput(Path.GetFileName(p), Fixtures.Bytes(p))).ToList();

    private static byte[] ReadRootStream(byte[] image, string name)
    {
        using var root = RootStorage.Open(new MemoryStream(image, writable: false));
        using var s = root.OpenStream(name);
        var buf = new byte[s.Length];
        s.ReadExactly(buf);
        return buf;
    }

    // ------------------------------------------------------------------ CAB

    [Theory]
    [InlineData(AuthenticodeHashKind.Sha256)]
    [InlineData(AuthenticodeHashKind.Sha384)]
    [InlineData(AuthenticodeHashKind.Sha512)]
    public void SignedCabVerifies(AuthenticodeHashKind kind)
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var signed = CabSigning.Sign(Fixtures.Bytes(UnsignedCab), kind, signer.Info, [], signer.Key);
        CabDigest.VerifyDigestConsistency(signed);
        var sig = AuthenticodeSignature.Parse(CabDigest.SignaturePkcs7Der(signed));
        Assert.Equal(Oids.SpcLink, sig.IndirectData.DataType);
        Assert.Equal(kind.DigestLength(), sig.Digest.Length);
    }

    [Fact]
    public void CabSigningRejectsSha1()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        Assert.Throws<PsignException>(() => CabSigning.Sign(Fixtures.Bytes(UnsignedCab), AuthenticodeHashKind.Sha1, signer.Info, [], signer.Key));
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void CabSignatureMatchesRustByteForByte(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var rustOut = dir.File("rust.cab");
        RustTool.RunOk("portable", "sign-cab", "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", digest, "--output", rustOut, Fixtures.Path(UnsignedCab));

        var signed = CabSigning.Sign(Fixtures.Bytes(UnsignedCab), AuthenticodeHashKinds.Parse(digest), signer.Info, [], signer.Key);
        Assert.Equal(File.ReadAllBytes(rustOut), signed);

        var csOut = dir.File("cs.cab");
        File.WriteAllBytes(csOut, signed);
        RustTool.RunOk("portable", "verify-cab", csOut);
    }

    // ------------------------------------------------------------------ MSI

    [Theory]
    [InlineData("generated-unsigned/installer/tiny.msi", AuthenticodeHashKind.Sha256)]
    [InlineData("generated-unsigned/installer/tiny-patch.msp", AuthenticodeHashKind.Sha384)]
    [InlineData("generated-unsigned/installer/tiny.msi", AuthenticodeHashKind.Sha512)]
    public void SignedMsiVerifies(string fixture, AuthenticodeHashKind kind)
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var signed = MsiSigning.Sign(Fixtures.Bytes(fixture), kind, signer.Info, [], signer.Key);
        MsiDigest.VerifyDigestConsistency(signed);
        var sig = AuthenticodeSignature.Parse(MsiDigest.DigitalSignaturePkcs7Der(signed));
        Assert.Equal(Oids.SpcSigInfo, sig.IndirectData.DataType);
    }

    [Fact]
    public void ResigningSignedMsiReplacesSignature()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var once = MsiSigning.Sign(Fixtures.Bytes("generated-unsigned/installer/tiny.msi"), AuthenticodeHashKind.Sha256, signer.Info, [], signer.Key);
        var twice = MsiSigning.Sign(once, AuthenticodeHashKind.Sha384, signer.Info, [], signer.Key);
        MsiDigest.VerifyDigestConsistency(twice);
        Assert.Equal(48, AuthenticodeSignature.Parse(MsiDigest.DigitalSignaturePkcs7Der(twice)).Digest.Length);
    }

    [SkippableTheory]
    [InlineData("generated-unsigned/installer/tiny.msi", "sha256")]
    [InlineData("generated-unsigned/installer/tiny.msi", "sha384")]
    [InlineData("generated-unsigned/installer/tiny.msi", "sha512")]
    [InlineData("generated-unsigned/installer/tiny-patch.msp", "sha256")]
    [InlineData("generated-unsigned/installer/tiny-patch.msp", "sha512")]
    [InlineData("generated-unsigned/installer/tiny-transform.mst", "sha384")]
    [InlineData("generated-signed/installer/tiny.msi", "sha256")]
    [InlineData("generated-signed/installer/tiny-patch.msp", "sha384")]
    [InlineData("generated-signed/installer/tiny-transform.mst", "sha512")]
    [InlineData("msi-authenticode-upstream/tiny-pkcs7-stub.msi", "sha256")]
    public void MsiSignatureCrossVerifiesWithRust(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var kind = AuthenticodeHashKinds.Parse(digest);
        var rustOut = dir.File("rust.msi");
        RustTool.RunOk("portable", "sign-msi", "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", digest, "--output", rustOut, Fixtures.Path(fixture));
        var rustSigned = File.ReadAllBytes(rustOut);

        var csSigned = MsiSigning.Sign(Fixtures.Bytes(fixture), kind, signer.Info, [], signer.Key);
        var csOut = dir.File("cs.msi");
        File.WriteAllBytes(csOut, csSigned);

        // The compound-file container is edited exactly like the Rust `cfb` crate does: whole files are identical.
        Assert.Equal(MsiDigest.DigitalSignaturePkcs7Der(rustSigned), MsiDigest.DigitalSignaturePkcs7Der(csSigned));
        Assert.Equal(ReadRootStream(rustSigned, MsiDigest.ExtendedSignatureEntry), ReadRootStream(csSigned, MsiDigest.ExtendedSignatureEntry));
        Assert.Equal(MsiDigest.ComputeAuthenticodeDigest(rustSigned, kind), MsiDigest.ComputeAuthenticodeDigest(csSigned, kind));
        Assert.Equal(rustSigned, csSigned);

        // Each implementation verifies the other's output.
        RustTool.RunOk("portable", "verify-msi", csOut);
        MsiDigest.VerifyDigestConsistency(rustSigned);

        using var rustExtract = new TempDir();
        var p7 = rustExtract.File("cs.p7");
        RustTool.RunOk("portable", "extract-msi-pkcs7", "--output", p7, csOut);
        Assert.Equal(MsiDigest.DigitalSignaturePkcs7Der(csSigned), File.ReadAllBytes(p7));
    }

    [SkippableTheory]
    [InlineData("generated-unsigned/installer/tiny.msi", "sha256", "sha512")]
    [InlineData("generated-unsigned/installer/tiny-patch.msp", "sha512", "sha256")]
    [InlineData("generated-unsigned/installer/tiny-transform.mst", "sha384", "sha384")]
    public void ResigningMsiMatchesRustByteForByte(string fixture, string first, string second)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var rustOnce = dir.File("rust-once.msi");
        var rustTwice = dir.File("rust-twice.msi");
        RustTool.RunOk("portable", "sign-msi", "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", first, "--output", rustOnce, Fixtures.Path(fixture));
        RustTool.RunOk("portable", "sign-msi", "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", second, "--output", rustTwice, rustOnce);

        var csOnce = MsiSigning.Sign(Fixtures.Bytes(fixture), AuthenticodeHashKinds.Parse(first), signer.Info, [], signer.Key);
        Assert.Equal(File.ReadAllBytes(rustOnce), csOnce);
        var csTwice = MsiSigning.Sign(csOnce, AuthenticodeHashKinds.Parse(second), signer.Info, [], signer.Key);
        Assert.Equal(File.ReadAllBytes(rustTwice), csTwice);
        MsiDigest.VerifyDigestConsistency(csTwice);
    }

    [SkippableTheory]
    [InlineData("generated-unsigned/installer/tiny.msi")]
    [InlineData("generated-signed/installer/tiny-patch.msp")]
    public void MsiSignatureStreamCrossingMiniStreamCutoffMatchesRust(string fixture)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);

        // Extra chain certificates push the PKCS#7 past the 4096-byte mini-stream cutoff (regular FAT sectors).
        var chain = new List<CertificateInfo>();
        var chainArgs = new List<string>();
        for (int i = 0; i < 4; i++)
        {
            using var scratch = new TempDir();
            using var extra = new TestSigner(scratch, $"CN=psign C# chain filler {i}, O=Devolutions, OU=MSI mini stream cutoff coverage");
            var path = dir.File($"chain{i}.der");
            File.WriteAllBytes(path, extra.Certificate.RawData);
            chain.Add(extra.Info);
            chainArgs.Add("--chain-cert");
            chainArgs.Add(path);
        }

        string RustSign(string input, string output, string digest, bool large)
        {
            var args = new List<string> { "portable", "sign-msi", "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", digest };
            if (large)
            {
                args.AddRange(chainArgs);
            }

            args.AddRange(["--output", output, input]);
            RustTool.RunOk([.. args]);
            return output;
        }

        // large (regular stream) -> small (mini stream) -> large again, each step against Rust.
        var rust1 = RustSign(Fixtures.Path(fixture), dir.File("r1.msi"), "sha256", large: true);
        var cs1 = MsiSigning.Sign(Fixtures.Bytes(fixture), AuthenticodeHashKind.Sha256, signer.Info, chain, signer.Key);
        Assert.True(MsiDigest.DigitalSignaturePkcs7Der(cs1).Length >= CfbFile.MiniStreamCutoff);
        Assert.Equal(File.ReadAllBytes(rust1), cs1);

        var rust2 = RustSign(rust1, dir.File("r2.msi"), "sha384", large: false);
        var cs2 = MsiSigning.Sign(cs1, AuthenticodeHashKind.Sha384, signer.Info, [], signer.Key);
        Assert.True(MsiDigest.DigitalSignaturePkcs7Der(cs2).Length < CfbFile.MiniStreamCutoff);
        Assert.Equal(File.ReadAllBytes(rust2), cs2);

        var rust3 = RustSign(rust2, dir.File("r3.msi"), "sha512", large: true);
        var cs3 = MsiSigning.Sign(cs2, AuthenticodeHashKind.Sha512, signer.Info, chain, signer.Key);
        Assert.Equal(File.ReadAllBytes(rust3), cs3);
        MsiDigest.VerifyDigestConsistency(cs3);
        RustTool.RunOk("portable", "verify-msi", rust3);
    }

    // ------------------------------------------------------------------ catalog

    [Fact]
    public void SignedCatalogVerifiesAndListsMembers()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var result = CatalogSigning.Create(Subjects(CatalogSubjects), AuthenticodeHashKind.Sha256, signer.Info, [], signer.Key);
        CatalogDigest.VerifyDigestConsistency(result.Pkcs7Der);
        var members = CatalogDigest.Members(result.Pkcs7Der);
        Assert.Equal(result.Members, members);
        Assert.Equal(Oids.SpcPeImageData, members[0].DataOid);
        Assert.Equal(Oids.SpcCabData, members[1].DataOid);
        Assert.Equal("tiny32.efi", members[0].SubjectName);
        foreach (var subject in CatalogSubjects)
        {
            CatalogDigest.VerifyMember(result.Pkcs7Der, Fixtures.Bytes(subject));
        }
    }

    [Fact]
    public void UnsignedCatalogHasMembersAndNoSigners()
    {
        var result = CatalogSigning.CreateUnsigned(Subjects(CatalogSubjects), AuthenticodeHashKind.Sha1);
        var sd = CatalogDigest.ParseSignedData(result.Pkcs7Der);
        Assert.Empty(sd.SignerInfos);
        Assert.Equal(result.Members, CatalogDigest.Members(result.Pkcs7Der));
        Assert.Equal(20, result.Members[0].Digest.Length);
        var e = Assert.Throws<PsignException>(() => CatalogDigest.VerifyDigestConsistency(result.Pkcs7Der));
        Assert.Equal("catalog SignedData has no SignerInfo", e.Message);
    }

    [Fact]
    public void CatalogAuthoringRejectsBadSubjects()
    {
        Assert.Equal(
            "catalog signing requires at least one subject file",
            Assert.Throws<PsignException>(() => CatalogSigning.CreateUnsigned([], AuthenticodeHashKind.Sha256)).Message);
        Assert.Equal(
            "catalog contains duplicate subject file name A.TXT",
            Assert.Throws<PsignException>(() => CatalogSigning.CreateUnsigned(
                [new CatalogSubjectInput("a.txt", [1]), new CatalogSubjectInput("A.TXT", [2])], AuthenticodeHashKind.Sha256)).Message);
        Assert.Equal(
            "catalog subject name must not be empty",
            Assert.Throws<PsignException>(() => CatalogSigning.CreateUnsigned([new CatalogSubjectInput(string.Empty, [1])], AuthenticodeHashKind.Sha256)).Message);
    }

    [SkippableTheory]
    [InlineData("sha256")]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void CatalogMatchesRustByteForByte(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var rustOut = dir.File("rust.cat");
        RustTool.RunOk(
            ["portable", "sign-catalog", "--cert", signer.CertPath, "--key", signer.KeyPath, "--digest", digest, "--output", rustOut,
            .. CatalogSubjects.Select(Fixtures.Path)]);

        var result = CatalogSigning.Create(Subjects(CatalogSubjects), AuthenticodeHashKinds.Parse(digest), signer.Info, [], signer.Key);
        Assert.Equal(File.ReadAllBytes(rustOut), result.Pkcs7Der);

        var csOut = dir.File("cs.cat");
        File.WriteAllBytes(csOut, result.Pkcs7Der);
        RustTool.RunOk("portable", "verify-catalog", csOut);
        RustTool.RunOk("portable", "verify-catalog-member", "--catalog", csOut, Fixtures.Path(CatalogSubjects[0]));
    }

    [Fact]
    public void CatalogRemoteDigestMatchesSignedAttributes()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var (econtent, _) = CatalogSigning.CreateCtlEContentDer(Subjects(CatalogSubjects), AuthenticodeHashKind.Sha256);
        var digest = CatalogSigning.RemoteSignedAttributesDigest(econtent, AuthenticodeHashKind.Sha256);
        var result = CatalogSigning.Create(Subjects(CatalogSubjects), AuthenticodeHashKind.Sha256, signer.Info, [], signer.Key);
        var sd = CmsSignedData.Parse(result.Pkcs7Der);
        Assert.Equal(digest, System.Security.Cryptography.SHA256.HashData(sd.SignerInfos[0].SignedAttributesSetDer()));
    }
}
