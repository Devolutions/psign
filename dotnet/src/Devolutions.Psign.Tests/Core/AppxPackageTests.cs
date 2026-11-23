using System.IO.Compression;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.Zip;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class AppxPackageTests
{
    private static byte[] InflateSync(byte[] compressed)
    {
        // A full-flushed block ends with an empty stored block, so it inflates without a final block.
        using var input = new MemoryStream(compressed);
        using var inflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        try
        {
            int n;
            while ((n = inflate.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, n);
            }
        }
        catch (InvalidDataException)
        {
            // Truncated stream (no final block) — everything decodable has already been produced.
        }

        return output.ToArray();
    }

    [Fact]
    public void EachDeflatedBlockInflatesIndependently()
    {
        var data = Enumerable.Range(0, (AppxPackage.AppxBlockSize * 2) + 1234).Select(i => (byte)((i / 17) & 0xff)).ToArray();
        var (compressed, sizes) = AppxPackage.DeflateAppxBlocks(data);
        Assert.Equal((data.Length + AppxPackage.AppxBlockSize - 1) / AppxPackage.AppxBlockSize, sizes.Count);

        int cursor = 0;
        int offset = 0;
        foreach (var size in sizes)
        {
            int end = cursor + (int)size;
            int len = Math.Min(AppxPackage.AppxBlockSize, data.Length - offset);
            var decoded = InflateSync(compressed[cursor..end]);
            Assert.Equal(data.AsSpan(offset, len).ToArray(), decoded);
            cursor = end;
            offset += len;
        }

        Assert.True(compressed.Length > cursor, "stream must end with final block");

        using var whole = new DeflateStream(new MemoryStream(compressed), CompressionMode.Decompress);
        using var all = new MemoryStream();
        whole.CopyTo(all);
        Assert.Equal(data, all.ToArray());
    }

    [Fact]
    public void PayloadEntryStoresMediaEmptyAndIncompressibleFiles()
    {
        Assert.Equal(0, AppxZipEntry.Payload("empty.txt", []).Method);
        Assert.Equal(0, AppxZipEntry.Payload("Assets/logo.png", Enumerable.Repeat((byte)7, 4096).ToArray()).Method);
        uint state = 0x1234_5678;
        var noise = new byte[1024];
        for (int i = 0; i < noise.Length; i++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            noise[i] = (byte)state;
        }

        Assert.Equal(0, AppxZipEntry.Payload("noise.bin", noise).Method);
        var text = AppxZipEntry.Payload("index.db", Enumerable.Repeat((byte)'a', 70_000).ToArray());
        Assert.Equal(8, text.Method);
        Assert.Equal(2, text.BlockSizes!.Count);
    }

    [Fact]
    public void U32FieldEnforcesNonSentinel4GibBoundary()
    {
        Assert.Equal(uint.MaxValue - 1, AppxPackage.U32Field((ulong)uint.MaxValue - 1, "test size"));
        Assert.Contains("exceeds 4 GiB", Assert.Throws<PsignException>(() => AppxPackage.U32Field(uint.MaxValue, "test size")).Message);
        Assert.Contains("exceeds 4 GiB", Assert.Throws<PsignException>(() => AppxPackage.U32Field((ulong)uint.MaxValue + 1, "test size")).Message);
    }

    [Fact]
    public void BundleManifestSupportsSparseExternalAndEmbeddedChildren()
    {
        var sparse = "<Bundle xmlns=\"http://schemas.microsoft.com/appx/2013/bundle\"><Packages><Package Type=\"application\" FileName=\"external-x64.msix\"/><Package Type=\"application\" FileName=\"flat-zero.msix\" Offset=\"0\" Size=\"1234\"/></Packages></Bundle>"u8.ToArray();
        var xml = Encoding.UTF8.GetString(AppxPackage.BundleManifestForStoredChildren(sparse, []));
        Assert.True(xml.Contains("FileName=\"external-x64.msix\"") && !xml.Contains("external-x64.msix\" Offset="), xml);
        Assert.Contains("FileName=\"flat-zero.msix\" Offset=\"0\" Size=\"1234\"", xml);

        var missing = "<Bundle xmlns=\"http://schemas.microsoft.com/appx/2013/bundle\"><Packages><Package Type=\"application\" FileName=\"embedded.msix\" Offset=\"73\" Size=\"500\"/></Packages></Bundle>"u8.ToArray();
        Assert.Contains("missing from ZIP", Assert.Throws<PsignException>(() => AppxPackage.BundleManifestForStoredChildren(missing, [])).Message);
    }

    [Fact]
    public void BundleManifestRewritesEmbeddedChildOffsets()
    {
        var manifest = "<Bundle><Packages><Package Type=\"application\" FileName=\"a.msix\" Offset=\"1\" Size=\"2\"/><Package FileName=\"dir\\b c.msix\" Offset=\"9\"/></Packages></Bundle>"u8.ToArray();
        var children = new List<(string, byte[])> { ("a.msix", new byte[10]), ("dir/b c.msix", new byte[5]) };
        var xml = Encoding.UTF8.GetString(AppxPackage.BundleManifestForStoredChildren(manifest, children));

        // a.msix: header 30 + 6 → data at 36, size 10; b: 46 + 30 + len("dir/b%20c.msix") = 90.
        Assert.Contains("<Package Type=\"application\" FileName=\"a.msix\" Offset=\"36\" Size=\"10\"/>", xml);
        Assert.Contains("<Package FileName=\"dir\\b c.msix\" Offset=\"90\" Size=\"5\"/>", xml);
    }

    [Fact]
    public void BundleBlockMapUsesCanonicalSha384AndSha512Uris()
    {
        Assert.Contains("HashMethod=\"http://www.w3.org/2001/04/xmldsig-more#sha384\"", AppxPackage.BuildMsixBundleBlockMap("<Bundle/>"u8.ToArray(), AuthenticodeHashKind.Sha384));
        Assert.Contains("HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha512\"", AppxPackage.BuildMsixBundleBlockMap("<Bundle/>"u8.ToArray(), AuthenticodeHashKind.Sha512));
        Assert.Throws<PsignException>(() => AppxPackage.BuildMsixBundleBlockMap("<Bundle/>"u8.ToArray(), AuthenticodeHashKind.Sha1));
    }

    [Fact]
    public void BundlePublisherRewritePreservesXsdValidPackageElements()
    {
        var xml = "<Bundle SchemaVersion=\"4.0\" xmlns=\"http://schemas.microsoft.com/appx/2013/bundle\"><Identity Name=\"Demo\" Publisher=\"CN=Old\" Version=\"1.0.0.0\"/><Packages><Package Type=\"application\" Version=\"1.0.0.0\" Architecture=\"x64\" FileName=\"app.msix\" Offset=\"73\" Size=\"500\"/></Packages></Bundle>"u8.ToArray();
        var rewritten = Encoding.UTF8.GetString(AppxPackage.RewriteXmlPublisher(xml, ["Identity", "Package"], "CN=New, O=\"Lab & Co\""));
        Assert.Contains("Identity Name=\"Demo\" Publisher=\"CN=New, O=&quot;Lab &amp; Co&quot;\" Version=\"1.0.0.0\"", rewritten);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(rewritten, "Publisher="));
    }

    [Fact]
    public void PublisherRewriteInsertsMissingIdentityPublisherAndPreservesMarkup()
    {
        var xml = "﻿<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<!-- c --><Package xmlns:x='urn:x'><Identity Name='A&amp;B' /><x:Data><![CDATA[<raw>]]>&amp;text</x:Data></Package >"u8.ToArray();
        var rewritten = Encoding.UTF8.GetString(AppxPackage.RewriteXmlPublisher(xml, ["Identity"], "CN=P"));
        Assert.Equal("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<!-- c --><Package xmlns:x='urn:x'><Identity Name=\"A&amp;B\" Publisher=\"CN=P\"/><x:Data><![CDATA[<raw>]]>&amp;text</x:Data></Package>", rewritten);
    }

    [Fact]
    public void WriteAppxZipProducesValidatedAppxLayout()
    {
        var entries = new List<AppxZipEntry>
        {
            AppxZipEntry.Payload("AppxManifest.xml", Encoding.UTF8.GetBytes(new string('x', 5000))),
            AppxZipEntry.Stored("AppxSignature.p7x", "PKCX"u8.ToArray()),
        };
        var zip = AppxPackage.WriteAppxZip(entries);
        var tail = MsixDigest.ParseZipTail(zip);
        MsixDigest.ValidateZipFileLayout(zip, ZipCrateArchive.Open(zip), tail);
        var archive = ZipCrateArchive.Open(zip);
        Assert.Equal(new string('x', 5000), Encoding.UTF8.GetString(archive.Read("AppxManifest.xml")));
        Assert.Equal(8, archive.OpenByName("AppxManifest.xml").CompressionMethod);
    }

    [Fact]
    public void StagingRejectsAlreadySignedAndEncryptedForUnsignedHelpers()
    {
        var signed = Fixtures.Bytes("generated-signed/msix/sample.msix");
        Assert.Contains("already contains AppxSignature.p7x", Assert.Throws<PsignException>(() => AppxPackage.RestageUnsignedMsixFamilyBytes(signed, "msix", null)).Message);
        Assert.Contains("already contains AppxSignature.p7x", Assert.Throws<PsignException>(() => AppxPackage.SetUnsignedMsixFamilyPublisherBytes(signed, "msix", "CN=X")).Message);
        Assert.Contains("encrypted MSIX/AppX", Assert.Throws<PsignException>(() => AppxPackage.RestageUnsignedMsixFamilyBytes(signed, "emsix", null)).Message);
        Assert.Contains("encrypted MSIX/AppX", Assert.Throws<PsignException>(() => AppxPackage.SetUnsignedMsixFamilyPublisherBytes(signed, "eappx", "CN=X")).Message);
        Assert.Contains("publisher cannot be empty", Assert.Throws<PsignException>(() => AppxPackage.SetUnsignedMsixFamilyPublisherBytes(Fixtures.Bytes("generated-unsigned/msix/sample.msix"), "msix", string.Empty)).Message);
    }

    [Theory]
    [InlineData("generated-unsigned/msix/sample.msix")]
    [InlineData("msix-edge-cases/unsigned/bundle-multi-presigned-children.msixbundle")]
    [InlineData("msix-edge-cases/unsigned/bundle-sparse.appxbundle")]
    [InlineData("msix-edge-cases/unsigned/flat-multiblock-paths.msix")]
    public void StagedPackageAcceptsPlaceholderAndValidatesAppxDigest(string fixture)
    {
        var ext = Path.GetExtension(fixture)[1..];
        var staged = AppxPackage.StageMsixFamilyForSignature(Fixtures.Bytes(fixture), ext, AuthenticodeHashKind.Sha256);
        Assert.True(MsixDigest.MsixSignaturePartPresent(staged));
        var (kind, blob) = MsixDigest.MsixAuthenticodeDigestBlob(staged, ext);
        Assert.Equal(AuthenticodeHashKind.Sha256, kind);
        var (len, _) = MsixDigest.ParseSignedAppxBlob(blob);
        Assert.Equal(32, len);

        var restaged = AppxPackage.RestageUnsignedMsixFamilyBytes(Fixtures.Bytes(fixture), ext, null);
        Assert.False(MsixDigest.MsixSignaturePartPresent(restaged));
        Assert.Equal(AuthenticodeHashKind.Sha256, MsixDigest.DetectBlockMapHashKind(restaged));
    }

    [Theory]
    [InlineData("generated-unsigned/msix/sample.appxbundle", "sample.appx")]
    [InlineData("msix-edge-cases/unsigned/bundle-multi.msixbundle", "app-x64.msix")]
    public void StagedBundleDigestRequiresSignedChildren(string fixture, string child)
    {
        var ext = Path.GetExtension(fixture)[1..];
        var staged = AppxPackage.StageMsixFamilyForSignature(Fixtures.Bytes(fixture), ext, AuthenticodeHashKind.Sha256);
        var msg = Assert.Throws<PsignException>(() => MsixDigest.MsixAuthenticodeDigestBlob(staged, ext)).Message;
        Assert.Equal($"bundle child package `{child}` failed MSIX SIP validation: APPX/MSIX package must contain exactly one required part `AppxSignature.p7x`", msg);
    }
}
