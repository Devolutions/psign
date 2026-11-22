using System.IO.Compression;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Xml;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>
/// Generic (explicit-anchor) trust for CAB, MSI, ESD, catalog, ZIP, script, MSIX, NuGet, and VSIX signatures, using fixtures
/// signed by the Devolutions test CA (port of <c>crates/psign-authenticode-trust/tests/format_trust.rs</c> plus the
/// <c>trust_verify_vsix.rs</c> module tests).
/// </summary>
public class FormatTrustTests
{
    private const string TestCa = "devolutions-authenticode/authenticode-test-ca.crt";

    /// <summary>Inside the test certificate's validity window (2022-03-22 .. 2027-03-22).</summary>
    internal static TrustVerifyPeOptions TestCaOpts() => new()
    {
        TrustedCaFiles = [Fixtures.Path(TestCa)],
        VerificationInstantOverride = VerificationInstant.ParseVerificationDateYmd("2026-06-01"),
    };

    [Theory]
    [InlineData("generated-signed/scripts/wsh/js/utf8-crlf.js")]
    [InlineData("generated-signed/scripts/wsh/js/utf16le-bom-lf.js")]
    [InlineData("generated-signed/scripts/wsh/vbs/utf8-bom-crlf.vbs")]
    [InlineData("generated-signed/scripts/wsh/wsf/utf8-crlf.wsf")]
    [InlineData("generated-signed/scripts/wsh-probe/jse/utf8-crlf.jse")]
    [InlineData("generated-signed/scripts/wsh-probe/vbe/utf8-crlf.vbe")]
    [InlineData("generated-signed/scripts/powershell/ps1/utf8-crlf.ps1")]
    [InlineData("generated-signed/scripts/powershell/psm1/utf16le-bom-lf.psm1")]
    public void ScriptsTrustVerify(string rel)
    {
        var report = TrustVerifyFile.TrustVerifyPath(Fixtures.Path(rel), TestCaOpts());
        Assert.Equal(1, report.Pkcs7EntriesVerified);
        Assert.Equal(1, report.AnchorThumbprints);
    }

    [Theory]
    [InlineData("generated-signed/cab/sample.cab")]
    [InlineData("generated-signed/installer/tiny.msi")]
    [InlineData("generated-signed/installer/tiny-patch.msp")]
    [InlineData("generated-signed/wim-esd/tiny.esd")]
    [InlineData("generated-signed/wim-esd/tiny.wim")]
    [InlineData("generated-signed/catalog/sample.cat")]
    [InlineData("zip-authenticode/signed/sample.signed.zip")]
    public void ContainerFormatsTrustVerify(string rel) =>
        Assert.Equal(1, TrustVerifyFile.TrustVerifyPath(Fixtures.Path(rel), TestCaOpts()).Pkcs7EntriesVerified);

    [Theory]
    [InlineData("generated-signed/msix/sample.msix")]
    [InlineData("generated-signed/msix/sample.appx")]
    [InlineData("generated-signed/msix/sample.msixbundle")]
    [InlineData("generated-signed/msix/sample.appxbundle")]
    [InlineData("msix-edge-cases/signed/flat-sha384.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-sha512.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-nocompress.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-multiblock-paths.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-pagehashes.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-resource.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-resource.signed.appx")]
    [InlineData("msix-edge-cases/signed/flat-optional-nonexec.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-skip-pcontent-hash.signed.msix")]
    [InlineData("msix-edge-cases/signed/flat-plain-zip.portable-signed.msix")]
    [InlineData("msix-edge-cases/signed/bundle-multi.signed.msixbundle")]
    [InlineData("msix-edge-cases/signed/bundle-multi-presigned-children.portable-signed.msixbundle")]
    [InlineData("msix-edge-cases/signed/bundle-multi.signed.appxbundle")]
    [InlineData("msix-edge-cases/signed/bundle-sparse.signed.msixbundle")]
    [InlineData("msix-edge-cases/signed/bundle-sparse.signed.appxbundle")]
    public void MsixPackagesTrustVerify(string rel) =>
        Assert.Equal(1, TrustVerifyFile.TrustVerifyPath(Fixtures.Path(rel), TestCaOpts()).Pkcs7EntriesVerified);

    [Fact]
    public void MsixSkipPContentHashAndNestedBundleChildTamperAreRejected()
    {
        // Even when AXPC uses the SkipPackageContentHash sentinel, block-map validation must reject payload byte
        // modifications without changing ZIP record lengths.
        var skipAxpc = Fixtures.Bytes("msix-edge-cases/signed/flat-skip-pcontent-hash.signed.msix");
        var archive = ZipCrateArchive.Open(skipAxpc);
        var logo = archive.Entries.First(e => e.Name.EndsWith(".png", StringComparison.Ordinal));
        skipAxpc[archive.DataStart(logo)] ^= 0xFF;
        var msg = PsignException.Render(Assert.ThrowsAny<Exception>(() => TrustVerifyMsix.TrustVerifyMsixBytes(skipAxpc, "msix", TestCaOpts()))).ToLowerInvariant();
        Assert.True(msg.Contains("checksum") || msg.Contains("crc") || msg.Contains("mismatch"), msg);

        // Tampering inside a subdirectory resource child of a 3-child bundle must fail verification.
        var bundle = Fixtures.Bytes("msix-edge-cases/signed/bundle-multi-presigned-children.portable-signed.msixbundle");
        var bundleArchive = ZipCrateArchive.Open(bundle);
        var child = bundleArchive.RequireByName("resources/scale-200.msix");
        bundle[bundleArchive.DataStart(child) + 40] = 0xAA;
        Assert.ThrowsAny<Exception>(() => TrustVerifyMsix.TrustVerifyMsixBytes(bundle, "msixbundle", TestCaOpts()));
    }

    [Theory]
    [InlineData("package-signing/signed/sample.signed.nupkg")]
    [InlineData("package-signing/signed/sample.signed.snupkg")]
    [InlineData("package-signing/signed/with-pe.signed.nupkg")]
    public void NuGetPackagesTrustVerify(string rel) =>
        Assert.Equal(1, TrustVerifyFile.TrustVerifyPath(Fixtures.Path(rel), TestCaOpts()).Pkcs7EntriesVerified);

    [Fact]
    public void NuGetPackageTamperIsRejected()
    {
        var bytes = Fixtures.Bytes("package-signing/signed/sample.signed.nupkg");
        // Flip a byte inside the first local file entry's data (well before the signature entry).
        bytes[80] ^= 0x01;
        var err = PsignException.Render(Assert.ThrowsAny<Exception>(() => TrustVerifyNuGet.TrustVerifyNuGetBytes(bytes, TestCaOpts())));
        Assert.True(err.Contains("mismatch", StringComparison.OrdinalIgnoreCase) || err.Contains("ZIP", StringComparison.Ordinal), err);
    }

    [Fact]
    public void NuGetVerifiedSignatureContentRecordsPackageHash()
    {
        var bytes = Fixtures.Bytes("package-signing/signed/sample.signed.nupkg");
        var signature = NuGetPackage.ExtractSignature(bytes);
        var (content, digest) = TrustVerifyNuGet.NuGetVerifiedSignatureContent(bytes, signature);
        var parsed = NuGetPackage.ParseSignatureContent(content);
        Assert.Equal(parsed.HashAlgorithm.Hash(NuGetPackage.SignedPackageUnsignedBytes(bytes)), parsed.PackageHash);
        Assert.Equal(AuthenticodeHashKinds.FromDigestLength(digest.Length).Hash(content), digest);
    }

    [Theory]
    [InlineData("package-signing/signed/sample.signed.vsix")]
    [InlineData("package-signing/signed/nested.signed.vsix")]
    [InlineData("package-signing/signed/deep-nested.signed.vsix")]
    public void VsixPackagesTrustVerify(string rel)
    {
        Assert.Equal(1, TrustVerifyFile.TrustVerifyPath(Fixtures.Path(rel), TestCaOpts()).Pkcs7EntriesVerified);
        var sig = TrustVerifyVsix.VerifyVsixSignatureBytes(Fixtures.Bytes(rel));
        Assert.True(sig.ReferenceCount > 0);
        Assert.NotEmpty(sig.SignerCertificateDer);
    }

    /// <summary>Rewrite a ZIP, letting <paramref name="edit"/> change entries and optionally appending one.</summary>
    private static byte[] RewriteZip(byte[] src, Func<string, byte[], byte[]> edit, (string Name, byte[] Bytes)? extra = null)
    {
        var input = ZipCrateArchive.Open(src);
        using var ms = new MemoryStream();
        using (var output = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in input.Entries)
            {
                var bytes = edit(entry.Name, input.Read(entry));
                using var s = output.CreateEntry(entry.Name).Open();
                s.Write(bytes);
            }

            if (extra is { } x)
            {
                using var s = output.CreateEntry(x.Name).Open();
                s.Write(x.Bytes);
            }
        }

        return ms.ToArray();
    }

    private static string VsixErr(byte[] bytes) =>
        PsignException.Render(Assert.ThrowsAny<Exception>(() => TrustVerifyVsix.TrustVerifyVsixBytes(bytes, TestCaOpts())));

    [Fact]
    public void VsixTamperingIsRejected()
    {
        var signed = Fixtures.Bytes("package-signing/signed/sample.signed.vsix");

        // Unmodified round trip through the rewriter still verifies.
        TrustVerifyVsix.TrustVerifyVsixBytes(RewriteZip(signed, (_, b) => b), TestCaOpts());

        var tampered = RewriteZip(signed, (n, b) =>
        {
            if (n == "payload.txt")
            {
                b[0] ^= 1;
            }

            return b;
        });
        Assert.Contains("digest mismatch for /payload.txt", VsixErr(tampered), StringComparison.Ordinal);

        var injected = RewriteZip(signed, (_, b) => b, ("evil.dll", "MZ"u8.ToArray()));
        Assert.Contains("not covered by the signature", VsixErr(injected), StringComparison.Ordinal);

        var retyped = RewriteZip(signed, (n, b) => n == "[Content_Types].xml"
            ? Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(b).Replace("text/plain", "application/octet-stream", StringComparison.Ordinal))
            : b);
        Assert.Contains("content type", VsixErr(retyped), StringComparison.Ordinal);

        var resigned = RewriteZip(signed, (n, b) =>
        {
            if (!n.StartsWith("package/services/digital-signature/xml-signature/", StringComparison.Ordinal))
            {
                return b;
            }

            // Change a signed byte inside SignedInfo (a DigestValue character).
            var t = Encoding.UTF8.GetString(b);
            int i = t.IndexOf("<DigestValue>z", StringComparison.Ordinal);
            return i < 0 ? b : Encoding.UTF8.GetBytes(t[..i] + "<DigestValue>Z" + t[(i + "<DigestValue>z".Length)..]);
        });
        Assert.Contains("SignatureValue does not verify", VsixErr(resigned), StringComparison.Ordinal);
    }

    [Fact]
    public void VsixRequiresTrustedAnchor()
    {
        var signed = Fixtures.Bytes("package-signing/signed/sample.signed.vsix");
        using var dir = new TempDir();
        using var other = new TestSigner(dir, "CN=unrelated root");
        _ = signed.Length;
        var opts = TestCaOpts() with { TrustedCaFiles = [other.CertPath] };
        Assert.Throws<PsignException>(() => TrustVerifyVsix.TrustVerifyVsixBytes(signed, opts));
    }

    [Fact]
    public void PartKeysAreDecodedAndCaseInsensitive()
    {
        Assert.Equal("_rels/.rels", TrustVerifyVsix.PartKey("/_rels/.rels"));
        Assert.Equal("a b.txt", TrustVerifyVsix.PartKey("/A%20b.TXT"));
    }

    [Fact]
    public void RelationshipTransformSelectsAndSorts()
    {
        var transform = XmlC14n.ParseDocument(Encoding.UTF8.GetBytes(
            "<Transform xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:m=\"http://schemas.openxmlformats.org/package/2006/digital-signature\"><m:RelationshipReference SourceId=\"R2\"/><m:RelationshipReference SourceId=\"R1\"/></Transform>"));
        var rels = Encoding.UTF8.GetBytes(
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Type=\"t2\" Target=\"/b\" Id=\"R2\"/><Relationship Type=\"t3\" Target=\"/c\" Id=\"R3\"/><Relationship Type=\"t1\" Target=\"http://x\" TargetMode=\"External\" Id=\"R1\"/></Relationships>");
        var output = XmlC14n.Canonicalize(TrustVerifyVsix.RelationshipTransform(transform, rels), C14nMode.Inclusive);
        Assert.Equal(
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
            + "<Relationship Id=\"R1\" Target=\"http://x\" TargetMode=\"External\" Type=\"t1\"></Relationship>"
            + "<Relationship Id=\"R2\" Target=\"/b\" TargetMode=\"Internal\" Type=\"t2\"></Relationship>"
            + "</Relationships>",
            Encoding.UTF8.GetString(output));
    }

    [Fact]
    public void XmlSignerTrustChainsToAnchor()
    {
        using var dir = new TempDir();
        using var pki = new Cli.TestPki(dir);
        var today = Cli.TestPki.Today;
        var shared = new TrustVerifySharedArgs { TrustedCa = [pki.RootPath], AsOf = today };
        Assert.Equal(1, XmlSignerTrust.VerifyXmlSignerCertificateTrust(pki.Leaf.RawData, shared));

        // A self-signed leaf trusted directly has no root in its (empty) picky chain.
        using var signer = new TestSigner(dir);
        var selfSigned = new TrustVerifySharedArgs { TrustedCa = [signer.CertPath], AsOf = today };
        Assert.Contains("chain is missing a root certificate", Assert.Throws<PsignException>(() => XmlSignerTrust.VerifyXmlSignerCertificateTrust(signer.Certificate.RawData, selfSigned)).Message, StringComparison.Ordinal);

        using var otherDir = new TempDir();
        using var other = new TestSigner(otherDir, "CN=other");
        var bad = new TrustVerifySharedArgs { TrustedCa = [other.CertPath], AsOf = today };
        var err = Assert.Throws<PsignException>(() => XmlSignerTrust.VerifyXmlSignerCertificateTrust(signer.Certificate.RawData, bad));
        Assert.Contains("XMLDSig terminal root certificate is not in the anchor store", err.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryFormatIsDispatched()
    {
        foreach (var format in Enum.GetValues<TrustVerifyFormat>())
        {
            Assert.True(TrustVerifyFile.IsFormatAvailable(format));
        }
    }
}
