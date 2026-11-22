using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Msix;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>PFX-backed signing identity shared with the Rust tool (<c>tests/fixtures/devolutions-authenticode</c>).</summary>
internal sealed class MsixPfxIdentity : IDisposable
{
    public const string Password = "CodeSign123!";

    private readonly X509Certificate2Collection _collection;

    public MsixPfxIdentity(string pfxPath, string password = Password)
    {
        PfxPath = pfxPath;
        PfxPasswordText = password;
        _collection = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057 // test-only PFX import
        _collection.Import(pfxPath, password, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        var leaf = _collection.First(c => c.HasPrivateKey);
        Key = leaf.GetRSAPrivateKey()!;
        Signer = CertificateInfo.Parse(leaf.RawData);
        Chain = _collection.Where(c => !c.HasPrivateKey).Select(c => CertificateInfo.Parse(c.RawData)).ToList();
    }

    public static MsixPfxIdentity Default() => new(Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx"));

    public string PfxPath { get; }

    public string PfxPasswordText { get; }

    public RSA Key { get; }

    public CertificateInfo Signer { get; }

    public List<CertificateInfo> Chain { get; }

    public void Dispose()
    {
        Key.Dispose();
        foreach (var c in _collection)
        {
            c.Dispose();
        }
    }
}

public class MsixSignerParityTests
{
    public static IEnumerable<object[]> UnsignedPackages()
    {
        yield return ["generated-unsigned/msix/sample.msix", "sha256"];
        yield return ["generated-unsigned/msix/sample.appx", "sha256"];
        yield return ["generated-unsigned/msix/sample.msixbundle", "sha256"];
        yield return ["generated-unsigned/msix/sample.appxbundle", "sha256"];
        yield return ["msix-edge-cases/unsigned/flat-sha384.msix", "sha384"];
        yield return ["msix-edge-cases/unsigned/flat-sha512.msix", "sha512"];
        yield return ["msix-edge-cases/unsigned/flat-nocompress.msix", "sha256"];
        yield return ["msix-edge-cases/unsigned/flat-multiblock-paths.msix", "sha256"];
        yield return ["msix-edge-cases/unsigned/flat-resource.msix", "sha256"];
        yield return ["msix-edge-cases/unsigned/flat-resource.appx", "sha256"];
        yield return ["msix-edge-cases/unsigned/flat-optional-nonexec.msix", "sha256"];
        yield return ["msix-edge-cases/unsigned/flat-plain-zip.msix", "sha256"];
        yield return ["msix-edge-cases/unsigned/bundle-multi.msixbundle", "sha256"];
        yield return ["msix-edge-cases/unsigned/bundle-multi.appxbundle", "sha256"];
        yield return ["msix-edge-cases/unsigned/bundle-multi.appxbundle", "sha384"];
        yield return ["msix-edge-cases/unsigned/bundle-multi.appxbundle", "sha512"];
        yield return ["msix-edge-cases/unsigned/bundle-multi-presigned-children.msixbundle", "sha256"];
        yield return ["msix-edge-cases/unsigned/bundle-sparse.msixbundle", "sha256"];
        yield return ["msix-edge-cases/unsigned/bundle-sparse.appxbundle", "sha256"];
    }

    [SkippableTheory]
    [MemberData(nameof(UnsignedPackages))]
    public void SignedPackageMatchesRustByteForByte(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var id = MsixPfxIdentity.Default();
        var ext = Path.GetExtension(fixture);
        var rustTarget = dir.File("rust" + ext);
        File.Copy(Fixtures.Path(fixture), rustTarget);
        RustTool.RunOk("--mode", "portable", "sign", "--pfx", id.PfxPath, "--password", id.PfxPasswordText, "--digest", digest, rustTarget);

        var kind = AuthenticodeHashKinds.Parse(digest);
        var signed = MsixSigner.SignBytes(Fixtures.Bytes(fixture), ext[1..], kind, id.Signer, id.Chain, new RsaDigestSigner(id.Key));

        var rust = File.ReadAllBytes(rustTarget);
        Assert.Equal(rust.Length, signed.Length);
        Assert.True(rust.AsSpan().SequenceEqual(signed), $"{fixture}: C# signed package differs from Rust");

        // Re-signing an already signed package is also byte-identical.
        RustTool.RunOk("--mode", "portable", "sign", "--pfx", id.PfxPath, "--password", id.PfxPasswordText, "--digest", digest, rustTarget);
        var resigned = MsixSigner.SignBytes(signed, ext[1..], kind, id.Signer, id.Chain, new RsaDigestSigner(id.Key));
        Assert.True(File.ReadAllBytes(rustTarget).AsSpan().SequenceEqual(resigned), $"{fixture}: C# re-signed package differs from Rust");

        // The C# output verifies with both implementations.
        var csTarget = dir.File("cs" + ext);
        File.WriteAllBytes(csTarget, resigned);
        RustTool.RunOk("portable", "verify-msix", csTarget);
        MsixDigest.VerifyMsixDigestConsistency(csTarget);
    }

    private static byte[] SyntheticPayloadPackage(int seed)
    {
        var rng = new Random(seed);
        var random = new byte[70_000];
        rng.NextBytes(random);
        var words = new[] { "alpha", "beta", "gamma", "delta", "MSIX", "AppxBlockMap", "signtool", "<Element attr=\"v\"/>", "\r\n", "0123456789" };
        var text = new System.Text.StringBuilder();
        while (text.Length < 210_000)
        {
            text.Append(words[rng.Next(words.Length)]).Append(rng.Next(3) == 0 ? ' ' : '_');
        }

        var mixed = new List<byte>();
        mixed.AddRange(random.AsSpan(0, 40_000).ToArray());
        mixed.AddRange(new byte[100_000]);
        mixed.AddRange(System.Text.Encoding.ASCII.GetBytes(text.ToString(0, 60_000)));
        mixed.AddRange(random.AsSpan(40_000).ToArray());
        for (int i = 0; i < 50_000; i++)
        {
            mixed.Add((byte)((i * i) >> 3));
        }

        var entries = new List<(string, byte[])>
        {
            ("AppxManifest.xml", Fixtures.Bytes("msix-minimal/AppxManifest.xml")),
            ("big.bin", mixed.ToArray()),
            ("docs/text.txt", System.Text.Encoding.UTF8.GetBytes(text.ToString())),
            ("Assets/Sub%20Dir/notes%20%26%20config.xml", System.Text.Encoding.UTF8.GetBytes("<config a=\"1\">" + new string('z', 3000) + "</config>")),
            ("Assets/donn%C3%A9es.txt", System.Text.Encoding.UTF8.GetBytes("données " + new string('d', 500))),
            ("random.dat", random),
            ("empty.dat", []),
            ("LICENSE", System.Text.Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("Permission is hereby granted. ", 100)))),
            ("small.txt", "tiny"u8.ToArray()),
            ("Assets/logo.png", random.AsSpan(0, 5000).ToArray()),
        };
        return LegacyZipWriter.WriteStored(entries);
    }

    [SkippableTheory]
    [InlineData(1, "sha256")]
    [InlineData(2, "sha384")]
    [InlineData(3, "sha512")]
    public void SyntheticDeflateStressPackageMatchesRust(int seed, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var id = MsixPfxIdentity.Default();
        var package = SyntheticPayloadPackage(seed);
        var rustTarget = dir.File("synthetic.msix");
        File.WriteAllBytes(rustTarget, package);
        RustTool.RunOk("--mode", "portable", "sign", "--pfx", id.PfxPath, "--password", id.PfxPasswordText, "--digest", digest, rustTarget);

        var signed = MsixSigner.SignBytes(package, "msix", AuthenticodeHashKinds.Parse(digest), id.Signer, id.Chain, new RsaDigestSigner(id.Key));
        var rust = File.ReadAllBytes(rustTarget);
        var archive = ZipArchiveReader.Open(signed);
        foreach (var e in archive.Entries)
        {
            Assert.True(ZipArchiveReader.Open(rust).ReadRaw(e.Index).AsSpan().SequenceEqual(archive.ReadRaw(e.Index)), $"entry `{e.Name}` compressed bytes differ");
        }

        Assert.True(rust.AsSpan().SequenceEqual(signed), "synthetic package differs from Rust");
        Assert.Contains(archive.Entries, e => e.CompressionMethod == 8);
        MsixDigest.MsixVerifiedSignature(signed, "msix");
    }

    public static IEnumerable<object[]> PublisherTargets()
    {
        yield return ["generated-unsigned/msix/sample.msix"];
        yield return ["generated-unsigned/msix/sample.appx"];
        yield return ["generated-unsigned/msix/sample.msixbundle"];
        yield return ["generated-unsigned/msix/sample.appxbundle"];
        yield return ["msix-edge-cases/unsigned/bundle-multi.msixbundle"];
        yield return ["msix-edge-cases/unsigned/bundle-multi.appxbundle"];
        yield return ["msix-edge-cases/unsigned/bundle-sparse.msixbundle"];
        yield return ["msix-edge-cases/unsigned/flat-sha384.msix"];
        yield return ["msix-edge-cases/unsigned/flat-plain-zip.msix"];
    }

    [SkippableTheory]
    [MemberData(nameof(PublisherTargets))]
    public void SetPublisherMatchesRustByteForByte(string fixture)
    {
        RustTool.Require();
        using var dir = new TempDir();
        const string publisher = "CN=Devolutions Release & QA, OU=Packaging, O=\"Devolutions, Inc.\", L=Lavaltrie, S=Quebec, C=CA";
        var ext = Path.GetExtension(fixture);
        var rustOut = dir.File("rust" + ext);
        RustTool.RunOk("portable", "msix-set-publisher", Fixtures.Path(fixture), "--publisher", publisher, "--output", rustOut);

        var updated = AppxPackage.SetUnsignedMsixFamilyPublisherBytes(Fixtures.Bytes(fixture), ext[1..], publisher);
        Assert.True(File.ReadAllBytes(rustOut).AsSpan().SequenceEqual(updated), $"{fixture}: msix-set-publisher output differs from Rust");

        var csOut = dir.File("cs" + ext);
        File.WriteAllBytes(csOut, updated);
        var info = RustTool.RunOk("portable", "msix-manifest-info", csOut);
        Assert.Contains("publisher=" + publisher, info);

        var restaged = AppxPackage.RestageUnsignedMsixFamilyBytes(updated, ext[1..], null);
        Assert.False(MsixDigest.MsixSignaturePartPresent(restaged));
    }

    [SkippableFact]
    public void SetPublisherUpdatesEveryEmbeddedBundleChild()
    {
        RustTool.Require();
        using var dir = new TempDir();
        const string publisher = "CN=Psign Bundle Children, O=Devolutions, C=CA";
        var updated = AppxPackage.SetUnsignedMsixFamilyPublisherBytes(Fixtures.Bytes("msix-edge-cases/unsigned/bundle-multi.msixbundle"), "msixbundle", publisher);
        var archive = ZipArchiveReader.Open(updated);
        var children = archive.Entries.Where(e => e.Name.EndsWith(".msix", StringComparison.Ordinal) || e.Name.EndsWith(".appx", StringComparison.Ordinal)).ToList();
        Assert.Equal(3, children.Count);
        foreach (var child in children)
        {
            var path = dir.File(child.Name.Replace('/', '_'));
            File.WriteAllBytes(path, archive.ReadAll(child.Index));
            Assert.Contains("publisher=" + publisher, RustTool.RunOk("portable", "msix-manifest-info", path));
        }
    }

    public static IEnumerable<object[]> SignedFixtures()
    {
        foreach (var entry in Core.MsixFixtureTests.LoadManifest().Where(e => e.ExpectedPortableVerify == "valid"))
        {
            yield return [entry.SignedPath!];
        }

        yield return ["tests/fixtures/generated-signed/msix/sample.msix"];
        yield return ["tests/fixtures/generated-signed/msix/sample.appxbundle"];
    }

    [SkippableTheory]
    [MemberData(nameof(SignedFixtures))]
    public void VerifiedSignatureAndPkcxExtractionMatchRust(string repoRelative)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var path = Core.MsixFixtureTests.RepoFixture(repoRelative);
        RustTool.RunOk("portable", "verify-msix", path);
        MsixDigest.VerifyMsixDigestConsistency(path);

        var p7x = ZipArchiveReader.Open(File.ReadAllBytes(path)).ReadAll("AppxSignature.p7x");
        var p7xPath = dir.File("AppxSignature.p7x");
        File.WriteAllBytes(p7xPath, p7x);
        var rustPkcs7 = dir.File("inner.p7");
        RustTool.RunOk("portable", "extract-pkcx-pkcs7", p7xPath, "--output", rustPkcs7);
        var (pkcs7, _) = MsixDigest.MsixVerifiedSignature(File.ReadAllBytes(path), Path.GetExtension(path)[1..]);
        Assert.Equal(File.ReadAllBytes(rustPkcs7), pkcs7);
        Assert.Equal(pkcs7, MsixDigest.TryStripPkcxWrapper(p7x));
    }

    [SkippableFact]
    public void TamperedPackagesAreRejectedByBothImplementations()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var signed = Fixtures.Bytes("generated-signed/msix/sample.msix");
        var archive = ZipArchiveReader.Open(signed);
        foreach (var entry in archive.Entries.Where(e => e.Name != "AppxSignature.p7x"))
        {
            var tampered = (byte[])signed.Clone();
            tampered[(int)archive.DataStart(entry)] ^= 0x01;
            var path = dir.File("tampered.msix");
            File.WriteAllBytes(path, tampered);
            var (code, _, stderr) = RustTool.Run("portable", "verify-msix", path);
            Assert.NotEqual(0, code);
            var e = Assert.ThrowsAny<PsignException>(() => MsixDigest.VerifyMsixDigestConsistency(path));
            var rustMessage = stderr.Trim();
            Assert.True(rustMessage.Contains(e.Message, StringComparison.Ordinal), $"{entry.Name}: Rust `{rustMessage}` vs C# `{e.Message}`");
        }
    }

    [SkippableFact]
    public void ChainCertificateIsEmbeddedAndMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();

        // Root -> leaf PFX carrying the root as chain certificate (test_pki_msix.rs: embedded chain).
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Psign C# MSIX Root CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        const string publisher = "CN=Devolutions Inc., O=Devolutions Inc., L=Lavaltrie, S=Quebec, C=CA";
        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest(publisher, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
        using var leafPub = leafReq.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), [1, 2, 3, 4, 5, 6, 7, 8]);
        using var leaf = leafPub.CopyWithPrivateKey(leafKey);
        using var rootPublic = X509CertificateLoaderCompat.LoadCertificate(root.RawData);
        var pfxPath = dir.File("codesign.pfx");
        var export = new X509Certificate2Collection { leaf, rootPublic };
        File.WriteAllBytes(pfxPath, export.Export(X509ContentType.Pkcs12, "SignPass123!")!);

        var source = dir.File("source2.msix");
        File.WriteAllBytes(source, AppxPackage.SetUnsignedMsixFamilyPublisherBytes(Fixtures.Bytes("generated-unsigned/msix/sample.msix"), "msix", publisher));
        var csInput = File.ReadAllBytes(source);
        RustTool.RunOk("--mode", "portable", "sign", "--pfx", pfxPath, "--password", "SignPass123!", "--digest", "sha256", source);

        using var id = new MsixPfxIdentity(pfxPath, "SignPass123!");
        Assert.Single(id.Chain);
        var signed = MsixSigner.SignBytes(csInput, "msix", AuthenticodeHashKind.Sha256, id.Signer, id.Chain, new RsaDigestSigner(id.Key));
        Assert.True(File.ReadAllBytes(source).AsSpan().SequenceEqual(signed), "chain-signed package differs from Rust");

        var (pkcs7, _) = MsixDigest.MsixVerifiedSignature(signed, "msix");
        var certs = Devolutions.Psign.Core.Cms.CmsSignedData.Parse(pkcs7).GetCertificates();
        Assert.Equal(2, certs.Count);
        Assert.Contains(certs, c => c.RawData.AsSpan().SequenceEqual(leaf.RawData));

        var outPath = dir.File("cs.msix");
        File.WriteAllBytes(outPath, signed);
        var rootPath = dir.File("root.cer");
        File.WriteAllBytes(rootPath, root.RawData);
        RustTool.RunOk("portable", "trust-verify-msix", outPath, "--trusted-ca", rootPath);
    }

    [Fact]
    public void SignFileHonorsSkipSignedAndRejectsEncryptedTargets()
    {
        using var dir = new TempDir();
        using var id = MsixPfxIdentity.Default();
        var signer = new RsaDigestSigner(id.Key);
        var signedInput = dir.File("signed.msix");
        File.Copy(Fixtures.Path("generated-signed/msix/sample.msix"), signedInput);
        var output = dir.File("out.msix");
        Assert.True(MsixSigner.SignFile(signedInput, output, AuthenticodeHashKind.Sha256, id.Signer, id.Chain, signer, skipSigned: true));
        Assert.Equal(File.ReadAllBytes(signedInput), File.ReadAllBytes(output));

        var encrypted = dir.File("x.emsix");
        File.WriteAllBytes(encrypted, [1, 2, 3]);
        Assert.Contains("encrypted packages", Assert.Throws<PsignException>(() =>
            MsixSigner.SignFile(encrypted, output, AuthenticodeHashKind.Sha256, id.Signer, id.Chain, signer)).Message);

        var upload = dir.File("x.msixupload");
        File.WriteAllBytes(upload, [1, 2, 3]);
        Assert.Contains("got .msixupload", Assert.Throws<PsignException>(() =>
            MsixSigner.SignFile(upload, output, AuthenticodeHashKind.Sha256, id.Signer, id.Chain, signer)).Message);

        var unsigned = dir.File("u.msix");
        File.Copy(Fixtures.Path("generated-unsigned/msix/sample.msix"), unsigned);
        Assert.False(MsixSigner.SignFile(unsigned, output, AuthenticodeHashKind.Sha256, id.Signer, id.Chain, signer, skipSigned: true));
        MsixDigest.VerifyMsixDigestConsistency(output);

        Assert.Contains("does not match requested signing digest", Assert.Throws<PsignException>(() =>
            MsixSigner.SpcIndirectData(File.ReadAllBytes(output), "msix", AuthenticodeHashKind.Sha384)).Message);
    }
}
