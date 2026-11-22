using System.Buffers.Binary;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msix;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

/// <summary>ZIP construction / patching helpers mirroring the Rust <c>msix_digest.rs</c> test helpers.</summary>
internal static class ZipTestHelpers
{
    public static byte[] ZipWithEntries(params (string Name, byte[] Data)[] entries) => LegacyZipWriter.WriteStored(entries);

    public static int FindEocd(byte[] zip)
    {
        for (int i = zip.Length - 4; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(i)) == 0x0605_4b50)
            {
                return i;
            }
        }

        throw new InvalidOperationException("EOCD");
    }

    public static uint ReadU32(byte[] b, int off) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(off));

    public static ushort ReadU16(byte[] b, int off) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(off));

    public static void WriteU16(byte[] b, int off, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(off), v);

    public static void WriteU32(byte[] b, int off, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(off), v);

    public static byte[] Splice(byte[] b, int at, byte[] insert)
    {
        var r = new byte[b.Length + insert.Length];
        b.AsSpan(0, at).CopyTo(r);
        insert.CopyTo(r.AsSpan(at));
        b.AsSpan(at).CopyTo(r.AsSpan(at + insert.Length));
        return r;
    }

    public static int FirstCentralDirectoryOffset(byte[] zip) => (int)ReadU32(zip, FindEocd(zip) + 16);

    public static int FirstLocalHeaderOffset(byte[] zip) => (int)ReadU32(zip, FirstCentralDirectoryOffset(zip) + 42);

    public static string Message(Exception e) => e is PsignException p ? p.FullMessage : e.Message;
}

public class MsixDigestTests
{
    private static readonly byte[] A = "a"u8.ToArray();
    private static readonly byte[] B = "b"u8.ToArray();

    private static string Err(Action action) => ZipTestHelpers.Message(Assert.ThrowsAny<PsignException>(action));

    private static byte[] BlockMapXmlForFile(string name, int size, byte[] hash) => Encoding.UTF8.GetBytes(
        $"<?xml version=\"1.0\" encoding=\"UTF-8\"?><BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" HashMethod=\"{MsixDigest.HashSha256}\"><File Name=\"{name}\" Size=\"{size}\"><Block Hash=\"{Convert.ToBase64String(hash)}\"/></File></BlockMap>");

    private static byte[] Sha256(byte[] data) => MsixDigest.HashBytes(AuthenticodeHashKind.Sha256, data);

    private static byte[] ZipWithGapBeforeCentralDirectory()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        int eocd = ZipTestHelpers.FindEocd(zip);
        int cd = (int)ZipTestHelpers.ReadU32(zip, eocd + 16);
        var gap = "GAP"u8.ToArray();
        zip = ZipTestHelpers.Splice(zip, cd, gap);
        ZipTestHelpers.WriteU32(zip, eocd + gap.Length + 16, (uint)(cd + gap.Length));
        return zip;
    }

    private static byte[] ZipWithGapBetweenLocalFiles()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A), ("b.txt", B));
        int eocd = ZipTestHelpers.FindEocd(zip);
        int cd = (int)ZipTestHelpers.ReadU32(zip, eocd + 16);
        int secondCd = cd + 46 + ZipTestHelpers.ReadU16(zip, cd + 28) + ZipTestHelpers.ReadU16(zip, cd + 30) + ZipTestHelpers.ReadU16(zip, cd + 32);
        int secondLocal = (int)ZipTestHelpers.ReadU32(zip, secondCd + 42);
        var gap = "GAP"u8.ToArray();
        zip = ZipTestHelpers.Splice(zip, secondLocal, gap);
        ZipTestHelpers.WriteU32(zip, secondCd + gap.Length + 42, (uint)(secondLocal + gap.Length));
        ZipTestHelpers.WriteU32(zip, eocd + gap.Length + 16, (uint)(cd + gap.Length));
        return zip;
    }

    private static byte[] ZipWithCentralDirectoryFileComment()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        int eocd = ZipTestHelpers.FindEocd(zip);
        int cd = (int)ZipTestHelpers.ReadU32(zip, eocd + 16);
        uint cdSize = ZipTestHelpers.ReadU32(zip, eocd + 12);
        int commentAt = cd + 46 + ZipTestHelpers.ReadU16(zip, cd + 28) + ZipTestHelpers.ReadU16(zip, cd + 30);
        var comment = "cmt"u8.ToArray();
        zip = ZipTestHelpers.Splice(zip, commentAt, comment);
        ZipTestHelpers.WriteU16(zip, cd + 32, (ushort)comment.Length);
        ZipTestHelpers.WriteU32(zip, eocd + comment.Length + 12, cdSize + (uint)comment.Length);
        return zip;
    }

    private static byte[] ZipWithLeadingBytes()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        var prefix = "PX"u8.ToArray();
        int oldEocd = ZipTestHelpers.FindEocd(zip);
        int oldCd = (int)ZipTestHelpers.ReadU32(zip, oldEocd + 16);
        int cdSize = (int)ZipTestHelpers.ReadU32(zip, oldEocd + 12);
        zip = ZipTestHelpers.Splice(zip, 0, prefix);
        int newCd = oldCd + prefix.Length;
        ZipTestHelpers.WriteU32(zip, oldEocd + prefix.Length + 16, (uint)newCd);
        int cursor = newCd;
        while (cursor < newCd + cdSize)
        {
            Assert.Equal(MsixDigest.CdSig, ZipTestHelpers.ReadU32(zip, cursor));
            uint local = ZipTestHelpers.ReadU32(zip, cursor + 42);
            ZipTestHelpers.WriteU32(zip, cursor + 42, local + (uint)prefix.Length);
            cursor += 46 + ZipTestHelpers.ReadU16(zip, cursor + 28) + ZipTestHelpers.ReadU16(zip, cursor + 30) + ZipTestHelpers.ReadU16(zip, cursor + 32);
        }

        return zip;
    }

    private static byte[] AppxWithTamperedManifest(byte[] original)
    {
        var source = ZipArchiveReader.Open(original);
        var entries = new List<(string, byte[])>();
        for (int i = 0; i < source.Count; i++)
        {
            var e = source.ByIndex(i);
            if (e.IsDirectory)
            {
                continue;
            }

            var data = source.ReadAll(i);
            if (e.Name == "AppxManifest.xml")
            {
                data = "tampered manifest"u8.ToArray();
            }

            entries.Add((e.Name, data));
        }

        return LegacyZipWriter.WriteStored(entries);
    }

    [Fact]
    public void ParseAppxBlobRoundtripWidths()
    {
        var blob = new List<byte>(MsixDigest.SigAppx);
        var z = Enumerable.Repeat((byte)7, 32).ToArray();
        foreach (var t in new[] { MsixDigest.TagAxpc, MsixDigest.TagAxcd, MsixDigest.TagAxct, MsixDigest.TagAxbm })
        {
            blob.AddRange(t);
            blob.AddRange(z);
        }

        var (ml, p) = MsixDigest.ParseSignedAppxBlob(blob.ToArray());
        Assert.Equal(32, ml);
        Assert.Null(p.Axci);

        blob.AddRange(MsixDigest.TagAxci);
        blob.AddRange(z);
        var (ml2, p2) = MsixDigest.ParseSignedAppxBlob(blob.ToArray());
        Assert.Equal(32, ml2);
        Assert.NotNull(p2.Axci);
    }

    [Fact]
    public void HashMethodParsesSha256Uri()
    {
        var xml = "<?xml version=\"1.0\"?><BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\" />"u8.ToArray();
        Assert.Equal(AuthenticodeHashKind.Sha256, MsixDigest.ParseBlockMapXml(xml).Kind);
    }

    [Fact]
    public void BlockMapParserRejectsFileOutsideRootAndDuplicateRoot()
    {
        Assert.Contains("File outside BlockMap", Err(() => MsixDigest.ParseBlockMapXml("<File Name=\"payload.txt\" Size=\"1\"><Block Hash=\"AAAA\"/></File>"u8.ToArray())));
        Assert.Contains("duplicate", Err(() => MsixDigest.ParseBlockMapXml(
            "<BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\" />"u8.ToArray())));
    }

    [Fact]
    public void BlockMapParserRejectsMissingOrUnsupportedHashMethod()
    {
        Assert.Contains("HashMethod", Err(() => MsixDigest.ParseBlockMapXml("<BlockMap><File Name=\"payload.txt\" Size=\"1\"><Block Hash=\"AAAA\"/></File></BlockMap>"u8.ToArray())));
        Assert.Contains("unsupported", Err(() => MsixDigest.ParseBlockMapXml(
            "<BlockMap HashMethod=\"http://example.invalid/sha3-256\"><File Name=\"payload.txt\" Size=\"1\"><Block Hash=\"AAAA\"/></File></BlockMap>"u8.ToArray())));
    }

    [Fact]
    public void ContentTypesValidationRejectsMalformedOverrides()
    {
        Assert.Contains("not absolute", Err(() => MsixDigest.ValidateContentTypesXml(
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Override PartName=\"AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/></Types>"u8.ToArray())));
        Assert.Contains("duplicate", Err(() => MsixDigest.ValidateContentTypesXml(
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"a\"/><Default Extension=\"XML\" ContentType=\"b\"/></Types>"u8.ToArray())));
    }

    [Fact]
    public void ContentTypesValidationRejectsTextAndCodeIntegrityMismatch()
    {
        Assert.Contains("non-whitespace text", Err(() => MsixDigest.ValidateContentTypesXml(
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">not allowed</Types>"u8.ToArray())));

        var xml = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/><Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/><Override PartName=\"/AppxManifest.xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/><Override PartName=\"/AppxMetadata/CodeIntegrity.cat\" ContentType=\"application/octet-stream\"/></Types>"u8.ToArray();
        var ct = MsixDigest.ValidateContentTypesXml(xml);
        Assert.Contains("CodeIntegrity.cat", Err(() => MsixDigest.ValidateReservedContentTypes(ct, new MsixDigest.AppxPackageInventory(true), "appx")));
    }

    [Fact]
    public void ContentTypesValidationRejectsReservedContentTypeMismatch()
    {
        var inventory = new MsixDigest.AppxPackageInventory(false);
        var ct = MsixDigest.ValidateContentTypesXml(
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/xml\"/><Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/></Types>"u8.ToArray());
        Assert.Contains("AppxBlockMap.xml", Err(() => MsixDigest.ValidateReservedContentTypes(ct, inventory, "appx")));

        var missing = MsixDigest.ValidateContentTypesXml(
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/><Override PartName=\"/AppxSignature.p7x\" ContentType=\"application/vnd.ms-appx.signature\"/></Types>"u8.ToArray());
        Assert.Contains("AppxManifest.xml", Err(() => MsixDigest.ValidateReservedContentTypes(missing, inventory, "appx")));
    }

    [Fact]
    public void EncryptedMsixExtensionIsDetected()
    {
        Assert.True(MsixDigest.IsEncryptedMsixExtension("emsix"));
        Assert.True(MsixDigest.IsEncryptedMsixExtension("eappxbundle"));
        Assert.False(MsixDigest.IsEncryptedMsixExtension("msix"));
    }

    [Fact]
    public void VerifyRejectsAllEncryptedMsixExtensions()
    {
        using var dir = new TempDir();
        foreach (var ext in new[] { "eappx", "eappxbundle", "emsix", "emsixbundle" })
        {
            var p = dir.File($"psign_fake_encrypted.{ext}");
            File.WriteAllBytes(p, "not-a-real-package"u8.ToArray());
            var msg = Err(() => MsixDigest.VerifyMsixDigestConsistency(p));
            Assert.True(msg.Contains("encrypted") && msg.Contains("Eappx"), $"unexpected message for {ext}: {msg}");
        }
    }

    [Fact]
    public void ZipTailRejectsTrailingGarbageAfterEocd()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A)).Concat("trailing"u8.ToArray()).ToArray();
        var msg = Err(() => MsixDigest.ParseZipTail(zip));
        Assert.True(msg.Contains("central-directory") || msg.Contains("EOCD"), msg);
    }

    [Fact]
    public void ZipTailRejectsMultidiskClassicEocd()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        ZipTestHelpers.WriteU16(zip, ZipTestHelpers.FindEocd(zip) + 4, 1);
        Assert.Contains("multi-disk", Err(() => MsixDigest.ParseZipTail(zip)));
    }

    [Fact]
    public void ZipTailRejectsZip64SentinelWithoutLocator()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        ZipTestHelpers.WriteU32(zip, ZipTestHelpers.FindEocd(zip) + 12, uint.MaxValue);
        var msg = Err(() => MsixDigest.ParseZipTail(zip));
        Assert.True(msg.Contains("ZIP64") && msg.Contains("locator"), msg);
    }

    [Fact]
    public void ZipTailRejectsCentralDirectoryExtentMismatch()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        int eocd = ZipTestHelpers.FindEocd(zip);
        ZipTestHelpers.WriteU32(zip, eocd + 12, ZipTestHelpers.ReadU32(zip, eocd + 12) - 1);
        Assert.Contains("central directory extent", Err(() => MsixDigest.ParseZipTail(zip)));
    }

    private static string LayoutErr(byte[] zip) =>
        Err(() => MsixDigest.ValidateZipFileLayout(zip, ZipArchiveReader.Open(zip), MsixDigest.ParseZipTail(zip)));

    [Fact]
    public void ZipLayoutRejectsGapBeforeCentralDirectory() =>
        Assert.Contains("gap before the central directory", LayoutErr(ZipWithGapBeforeCentralDirectory()));

    [Fact]
    public void ZipLayoutRejectsGapBetweenLocalFileRecords() =>
        Assert.Contains("gap between local file records", LayoutErr(ZipWithGapBetweenLocalFiles()));

    [Fact]
    public void ZipLayoutRejectsCentralDirectoryFileComments()
    {
        var zip = ZipWithCentralDirectoryFileComment();
        Assert.Contains("file comments", Err(() => MsixDigest.ValidateCentralDirectoryRecords(zip, MsixDigest.ParseZipTail(zip))));
    }

    [Fact]
    public void ZipLayoutRejectsLeadingBytesBeforeFirstLocalFile() =>
        Assert.Contains("leading bytes", LayoutErr(ZipWithLeadingBytes()));

    [Fact]
    public void ZipLayoutRejectsLocalAndCentralNameMismatch()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        zip[ZipTestHelpers.FirstLocalHeaderOffset(zip) + 30] = (byte)'b';
        Assert.Contains("local file name", LayoutErr(zip));
    }

    [Fact]
    public void ZipLayoutRejectsLocalCrcAndSizeMismatch()
    {
        var crcZip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        ZipTestHelpers.WriteU32(crcZip, ZipTestHelpers.FirstLocalHeaderOffset(crcZip) + 14, 0x1234_5678);
        Assert.Contains("CRC", LayoutErr(crcZip));

        var sizeZip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        ZipTestHelpers.WriteU32(sizeZip, ZipTestHelpers.FirstLocalHeaderOffset(sizeZip) + 22, 99);
        Assert.Contains("uncompressed size", LayoutErr(sizeZip));
    }

    [Fact]
    public void ZipLayoutRejectsEncryptedOrUnsupportedCompressionBits()
    {
        var encrypted = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        ZipTestHelpers.WriteU16(encrypted, ZipTestHelpers.FirstCentralDirectoryOffset(encrypted) + 8, 1);
        ZipTestHelpers.WriteU16(encrypted, ZipTestHelpers.FirstLocalHeaderOffset(encrypted) + 6, 1);
        Assert.Contains("encrypted ZIP", LayoutErr(encrypted));

        var unsupported = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        int local = ZipTestHelpers.FirstLocalHeaderOffset(unsupported);
        ZipTestHelpers.WriteU16(unsupported, ZipTestHelpers.FirstCentralDirectoryOffset(unsupported) + 10, 99);
        ZipTestHelpers.WriteU16(unsupported, local + 8, 99);
        Assert.Contains("unsupported ZIP compression", Err(() => MsixDigest.ValidateCentralDirectoryRecords(unsupported, MsixDigest.ParseZipTail(unsupported))));
    }

    [Fact]
    public void ZipLayoutRejectsCentralDirectoryEntryCountMismatch()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", A));
        int eocd = ZipTestHelpers.FindEocd(zip);
        ZipTestHelpers.WriteU16(zip, eocd + 8, 2);
        ZipTestHelpers.WriteU16(zip, eocd + 10, 2);
        Assert.Contains("entry count", Err(() => MsixDigest.ValidateCentralDirectoryRecords(zip, MsixDigest.ParseZipTail(zip))));
    }

    [Fact]
    public void PackageInventoryRejectsMissingRequiredAndNoncanonicalReservedParts()
    {
        var missing = ZipTestHelpers.ZipWithEntries(("[Content_Types].xml", []), ("AppxBlockMap.xml", []), ("AppxSignature.p7x", []));
        Assert.Contains("AppxManifest.xml", Err(() => MsixDigest.ValidatePackagePartInventory(ZipArchiveReader.Open(missing), "appx")));

        var wrongCase = ZipTestHelpers.ZipWithEntries(("[Content_Types].xml", []), ("AppxBlockMap.xml", []), ("AppxSignature.p7x", []), ("appxmanifest.xml", []));
        Assert.Contains("canonical path", Err(() => MsixDigest.ValidatePackagePartInventory(ZipArchiveReader.Open(wrongCase), "appx")));
    }

    [Fact]
    public void PackageInventoryRejectsCaseCollidingPartsAndEncryptedBundleChildren()
    {
        var dup = ZipTestHelpers.ZipWithEntries(("[Content_Types].xml", []), ("AppxBlockMap.xml", []), ("AppxSignature.p7x", []), ("AppxManifest.xml", []), ("payload.txt", []), ("Payload.txt", []));
        Assert.Contains("case-insensitive", Err(() => MsixDigest.ValidatePackagePartInventory(ZipArchiveReader.Open(dup), "appx")));

        var enc = ZipTestHelpers.ZipWithEntries(("[Content_Types].xml", []), ("AppxBlockMap.xml", []), ("AppxSignature.p7x", []), ("AppxMetadata/AppxBundleManifest.xml", []), ("child.emsix", []));
        Assert.Contains("encrypted child", Err(() => MsixDigest.ValidatePackagePartInventory(ZipArchiveReader.Open(enc), "appxbundle")));
    }

    [Fact]
    public void BlockMapValidationAcceptsMatchingPayloadHash()
    {
        var payload = "manifest bytes"u8.ToArray();
        var (kind, files) = MsixDigest.ParseBlockMapXml(BlockMapXmlForFile("AppxManifest.xml", payload.Length, Sha256(payload)));
        MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("AppxManifest.xml", payload)), kind, files);
    }

    [Fact]
    public void BlockMapValidationAcceptsMultiplePayloadBlocks()
    {
        var payload = Enumerable.Repeat((byte)0x41, MsixDigest.AppxBlockSize + 17).ToArray();
        payload[MsixDigest.AppxBlockSize] = 0x42;
        var first = Convert.ToBase64String(Sha256(payload[..MsixDigest.AppxBlockSize]));
        var second = Convert.ToBase64String(Sha256(payload[MsixDigest.AppxBlockSize..]));
        var bm = Encoding.UTF8.GetBytes($"<?xml version=\"1.0\"?><BlockMap HashMethod=\"{MsixDigest.HashSha256}\"><File Name=\"large.bin\" Size=\"{payload.Length}\"><Block Hash=\"{first}\"/><Block Hash=\"{second}\"/></File></BlockMap>");
        var (kind, files) = MsixDigest.ParseBlockMapXml(bm);
        MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("large.bin", payload)), kind, files);
    }

    [Fact]
    public void BlockMapValidationRejectsTamperedPayloadHash()
    {
        var (kind, files) = MsixDigest.ParseBlockMapXml(BlockMapXmlForFile("AppxManifest.xml", 14, Sha256("expected bytes"u8.ToArray())));
        Assert.Contains("hash mismatch", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("AppxManifest.xml", "tampered bytes"u8.ToArray())), kind, files)));
    }

    [Fact]
    public void BlockMapValidationRejectsDeclaredSizeMismatch()
    {
        var payload = "abc"u8.ToArray();
        var (kind, files) = MsixDigest.ParseBlockMapXml(BlockMapXmlForFile("AppxManifest.xml", 99, Sha256(payload)));
        Assert.Contains("Size 99", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("AppxManifest.xml", payload)), kind, files)));
    }

    [Fact]
    public void BlockMapValidationRejectsMissingPayload()
    {
        var (kind, files) = MsixDigest.ParseBlockMapXml(BlockMapXmlForFile("Missing.txt", 3, Sha256("abc"u8.ToArray())));
        Assert.Contains("missing from package", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("Other.txt", "abc"u8.ToArray())), kind, files)));
    }

    [Fact]
    public void BlockMapValidationRejectsWrongLfhSize()
    {
        var payload = "abc"u8.ToArray();
        var bm = Encoding.UTF8.GetBytes($"<BlockMap HashMethod=\"{MsixDigest.HashSha256}\"><File Name=\"payload.txt\" Size=\"{payload.Length}\" LfhSize=\"999\"><Block Hash=\"{Convert.ToBase64String(Sha256(payload))}\"/></File></BlockMap>");
        var (kind, files) = MsixDigest.ParseBlockMapXml(bm);
        Assert.Contains("LfhSize", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("payload.txt", payload)), kind, files)));
    }

    [Fact]
    public void BlockMapValidationRejectsBadBlockSizeAttribute()
    {
        var payload = "abc"u8.ToArray();
        var hash = Convert.ToBase64String(Sha256(payload));
        var bad = Encoding.UTF8.GetBytes($"<BlockMap HashMethod=\"{MsixDigest.HashSha256}\"><File Name=\"payload.txt\" Size=\"{payload.Length}\"><Block Hash=\"{hash}\" Size=\"not-a-number\"/></File></BlockMap>");
        Assert.Contains("invalid `Size`", Err(() => MsixDigest.ParseBlockMapXml(bad)));

        var zero = Encoding.UTF8.GetBytes($"<BlockMap HashMethod=\"{MsixDigest.HashSha256}\"><File Name=\"payload.txt\" Size=\"{payload.Length}\"><Block Hash=\"{hash}\" Size=\"0\"/></File></BlockMap>");
        var (kind, files) = MsixDigest.ParseBlockMapXml(zero);
        Assert.Contains("zero Size", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("payload.txt", payload)), kind, files)));
    }

    [Fact]
    public void BlockMapValidationRejectsMetadataAndBlockCountMismatches()
    {
        var meta = "metadata is not payload"u8.ToArray();
        var (kind, files) = MsixDigest.ParseBlockMapXml(BlockMapXmlForFile("AppxBlockMap.xml", meta.Length, Sha256(meta)));
        Assert.Contains("metadata part", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("AppxBlockMap.xml", meta)), kind, files)));

        (kind, files) = MsixDigest.ParseBlockMapXml("<BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\"><File Name=\"payload.txt\" Size=\"3\"/></BlockMap>"u8.ToArray());
        Assert.Contains("no block hashes", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("payload.txt", "abc"u8.ToArray())), kind, files)));

        (kind, files) = MsixDigest.ParseBlockMapXml(BlockMapXmlForFile("empty.txt", 0, Sha256([])));
        Assert.Contains("empty but has block hashes", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("empty.txt", [])), kind, files)));

        var payload = "abc"u8.ToArray();
        var h = Convert.ToBase64String(Sha256(payload));
        (kind, files) = MsixDigest.ParseBlockMapXml(Encoding.UTF8.GetBytes($"<BlockMap HashMethod=\"{MsixDigest.HashSha256}\"><File Name=\"payload.txt\" Size=\"{payload.Length}\"><Block Hash=\"{h}\"/><Block Hash=\"{h}\"/></File></BlockMap>"));
        Assert.Contains("too many block hashes", Err(() => MsixDigest.ValidateBlockMapFileHashes(ZipTestHelpers.ZipWithEntries(("payload.txt", payload)), kind, files)));
    }

    [Fact]
    public void BlockMapValidationRejectsDuplicateZipNamesAfterNormalization()
    {
        var payload = "abc"u8.ToArray();
        var (kind, files) = MsixDigest.ParseBlockMapXml(BlockMapXmlForFile("dir/file.txt", payload.Length, Sha256(payload)));
        var zip = ZipTestHelpers.ZipWithEntries(("dir/file.txt", payload), ("dir\\file.txt", payload));
        Assert.Contains("duplicate ZIP entry", Err(() => MsixDigest.ValidateBlockMapFileHashes(zip, kind, files)));
    }

    [Fact]
    public void BlockMapParserRejectsTraversalNamesAndBadHashes()
    {
        Assert.Contains("invalid path segment", Err(() => MsixDigest.ParseBlockMapXml(
            "<?xml version=\"1.0\"?><BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\"><File Name=\"..\\evil.txt\" Size=\"1\"><Block Hash=\"AAAA\"/></File></BlockMap>"u8.ToArray())));
        Assert.Contains("base64", Err(() => MsixDigest.ParseBlockMapXml(
            "<?xml version=\"1.0\"?><BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\"><File Name=\"ok.txt\" Size=\"1\"><Block Hash=\"not-base64!\"/></File></BlockMap>"u8.ToArray())));
    }

    [Fact]
    public void SignedAppxbundleFixtureRecursivelyVerifiesChildPackage() =>
        MsixDigest.VerifyMsixDigestConsistency(Fixtures.Path("generated-signed/msix/sample.appxbundle"));

    [Fact]
    public void BundleChildPackageValidationRejectsStaleChildSignature()
    {
        var tampered = AppxWithTamperedManifest(Fixtures.Bytes("generated-signed/msix/sample.appx"));
        var bundle = ZipTestHelpers.ZipWithEntries(("tampered.appx", tampered));
        Assert.Contains("bundle child package `tampered.appx`", Err(() => MsixDigest.VerifyBundleChildPackages(bundle)));
    }

    private static byte[] CdHashForTest(byte[] zip)
    {
        var tail = MsixDigest.ParseZipTail(zip);
        return MsixDigest.HashCdAndEocd(zip, ZipArchiveReader.Open(zip), tail, AuthenticodeHashKind.Sha256, tail.CentralDirectoryOffset);
    }

    [Fact]
    public void NormalizeZipForAppxSigningWritesMakeappxLayout()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", "alpha"u8.ToArray()), ("dir/b.txt", "beta"u8.ToArray()));
        var normalized = MsixDigest.NormalizeZipForAppxSigning(zip);
        var tail = MsixDigest.ParseZipTail(normalized);
        var z64 = Assert.IsType<MsixDigest.Zip64Eocd>(tail.Zip64Eocd);
        Assert.Equal(MsixDigest.Zip64EocdRecordSize, z64.RecordSize);
        Assert.Equal(MsixDigest.Zip64Version, z64.VersionMadeBy);
        Assert.Equal(MsixDigest.Zip64Version, z64.VersionNeededToExtract);
        Assert.Equal(2UL, z64.NumberOfFiles);
        Assert.Empty(z64.TailAfterFixed);
        var locator = Assert.IsType<MsixDigest.Zip64Locator>(tail.Locator);
        Assert.Equal(1u, locator.NumberOfDisks);
        Assert.Equal(tail.Zip64EocdOffset, locator.EndOfCentralDirectoryOffset);
        Assert.Equal(ushort.MaxValue, tail.Classic.DiskNumber);
        Assert.Equal(ushort.MaxValue, tail.Classic.NumberOfFiles);
        Assert.Equal(uint.MaxValue, tail.Classic.CentralDirectorySize);
        Assert.Equal(uint.MaxValue, tail.Classic.CentralDirectoryOffset);

        var archive = ZipArchiveReader.Open(normalized);
        for (int i = 0; i < archive.Count; i++)
        {
            int central = (int)archive.ByIndex(i).CentralHeaderStart;
            Assert.Equal(MsixDigest.Zip64Version, ZipTestHelpers.ReadU16(normalized, central + 4));
            Assert.Equal(0u, ZipTestHelpers.ReadU32(normalized, central + 38));
        }

        Assert.Equal("beta"u8.ToArray(), archive.ReadAll("dir/b.txt"));
        int cd = (int)tail.CentralDirectoryOffset;
        Assert.Equal(zip[..cd], normalized[..cd]);
        Assert.Equal(normalized, MsixDigest.NormalizeZipForAppxSigning(normalized));
    }

    [Fact]
    public void CdDigestRejectsLayoutsWindowsAppxSipRejects()
    {
        var zip = ZipTestHelpers.ZipWithEntries(("a.txt", "alpha"u8.ToArray()));
        Assert.Contains("version made by 0x032e", Err(() => CdHashForTest(zip)));

        var classicOnly = (byte[])zip.Clone();
        int cd = ZipTestHelpers.FirstCentralDirectoryOffset(classicOnly);
        ZipTestHelpers.WriteU16(classicOnly, cd + 4, MsixDigest.Zip64Version);
        ZipTestHelpers.WriteU32(classicOnly, cd + 38, 0);
        Assert.Contains("no ZIP64 end-of-central-directory", Err(() => CdHashForTest(classicOnly)));

        var archiveAttr = MsixDigest.NormalizeZipForAppxSigning(zip);
        var tail = MsixDigest.ParseZipTail(archiveAttr);
        ZipTestHelpers.WriteU32(archiveAttr, (int)tail.CentralDirectoryOffset + 38, 0x20);
        Assert.Contains("external attributes 0x00000020", Err(() => CdHashForTest(archiveAttr)));

        CdHashForTest(MsixDigest.NormalizeZipForAppxSigning(zip));
    }

    [Fact]
    public void BlockMapFileHashIsParsedAndValidated()
    {
        var payload = "abc"u8.ToArray();
        var hash = Sha256(payload);
        var hashB64 = Convert.ToBase64String(hash);
        byte[] BlockMap(string fileHash) => Encoding.UTF8.GetBytes(
            $"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><BlockMap xmlns=\"http://schemas.microsoft.com/appx/2010/blockmap\" xmlns:b4=\"http://schemas.microsoft.com/appx/2021/blockmap\" IgnorableNamespaces=\"b4\" HashMethod=\"{MsixDigest.HashSha256}\"><File Name=\"payload.txt\" Size=\"{payload.Length}\" LfhSize=\"41\"><Block Hash=\"{hashB64}\"/>{fileHash}</File></BlockMap>");
        var zip = ZipTestHelpers.ZipWithEntries(("payload.txt", payload));

        var (kind, files) = MsixDigest.ParseBlockMapXml(BlockMap($"<b4:FileHash Hash=\"{hashB64}\"/>"));
        Assert.Equal(hash, files[0].FileHash);
        MsixDigest.ValidateBlockMapFileHashes(zip, kind, files);

        var other = Convert.ToBase64String(Sha256("abd"u8.ToArray()));
        (kind, files) = MsixDigest.ParseBlockMapXml(BlockMap($"<b4:FileHash Hash=\"{other}\"/>"));
        Assert.Contains("FileHash mismatch", Err(() => MsixDigest.ValidateBlockMapFileHashes(zip, kind, files)));

        Assert.Contains("3-byte FileHash", Err(() => MsixDigest.ParseBlockMapXml(BlockMap("<b4:FileHash Hash=\"AAAA\"/>"))));
        Assert.Contains("duplicate FileHash", Err(() => MsixDigest.ParseBlockMapXml(BlockMap($"<b4:FileHash Hash=\"{hashB64}\"/><b4:FileHash Hash=\"{hashB64}\"/>"))));
    }

    [Fact]
    public void ContentTypesForSigningFillGapsAndKeepExistingTypes()
    {
        var inventory = new MsixDigest.AppxPackageInventory(false);
        var generated = MsixDigest.AppxContentTypesForSigning(null, ["AppxManifest.xml", "Public/index.db", "Assets/Logo.PNG", "LICENSE"], false);
        var parsed = MsixDigest.ValidateContentTypesXml(Encoding.UTF8.GetBytes(generated));
        Assert.Equal(MsixDigest.ContentTypeManifest, MsixDigest.ContentTypeForPart(parsed, "AppxManifest.xml"));
        Assert.Equal("image/png", MsixDigest.ContentTypeForPart(parsed, "Assets/Logo.PNG"));
        Assert.Equal("application/octet-stream", MsixDigest.ContentTypeForPart(parsed, "Public/index.db"));
        Assert.Equal("application/octet-stream", MsixDigest.ContentTypeForPart(parsed, "LICENSE"));
        MsixDigest.ValidateReservedContentTypes(parsed, inventory, "msix");

        var existing = "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/><Default Extension=\"db\" ContentType=\"application/x-sqlite3\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/xml\"/></Types>"u8.ToArray();
        var merged = MsixDigest.AppxContentTypesForSigning(existing, ["AppxManifest.xml", "Public/index.db", "Public/extra.xml"], false);
        parsed = MsixDigest.ValidateContentTypesXml(Encoding.UTF8.GetBytes(merged));
        Assert.Equal(MsixDigest.ContentTypeManifest, MsixDigest.ContentTypeForPart(parsed, "AppxManifest.xml"));
        Assert.Equal("application/xml", MsixDigest.ContentTypeForPart(parsed, "Public/extra.xml"));
        Assert.Equal("application/x-sqlite3", MsixDigest.ContentTypeForPart(parsed, "Public/index.db"));
        MsixDigest.ValidateReservedContentTypes(parsed, inventory, "msix");

        var makeappx = "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"text/xml\"/><Override PartName=\"/AppxManifest.xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/></Types>"u8.ToArray();
        merged = MsixDigest.AppxContentTypesForSigning(makeappx, ["AppxManifest.xml", "Assets/License.xml"], false);
        parsed = MsixDigest.ValidateContentTypesXml(Encoding.UTF8.GetBytes(merged));
        Assert.Equal(MsixDigest.ContentTypeManifest, MsixDigest.ContentTypeForPart(parsed, "AppxManifest.xml"));
        Assert.Equal("text/xml", MsixDigest.ContentTypeForPart(parsed, "Assets/License.xml"));
        MsixDigest.ValidateReservedContentTypes(parsed, inventory, "msix");

        var bundle = MsixDigest.AppxContentTypesForSigning(null, ["app.msix", "AppxMetadata/AppxBundleManifest.xml"], true);
        parsed = MsixDigest.ValidateContentTypesXml(Encoding.UTF8.GetBytes(bundle));
        MsixDigest.ValidateReservedContentTypes(parsed, inventory, "msixbundle");
        Assert.Equal("application/msix", MsixDigest.ContentTypeForPart(parsed, "app.msix"));
    }

    [Fact]
    public void DataDescriptorVariantsAndCorruptionAreValidated()
    {
        var payload = "descriptor payload"u8.ToArray();
        uint crc = ZipCrc32.Compute(payload);
        uint len32 = (uint)payload.Length;
        ulong len64 = (ulong)payload.Length;
        var reference = ZipTestHelpers.ZipWithEntries(("item.bin", payload));
        var zf = ZipArchiveReader.Open(reference).ByIndex(0);

        var classicNoSig = BitConverter.GetBytes(crc).Concat(BitConverter.GetBytes(len32)).Concat(BitConverter.GetBytes(len32)).ToArray();
        Assert.Equal(12UL, MsixDigest.DataDescriptorLenAndValidate(classicNoSig, 0, false, zf));

        var classicSig = BitConverter.GetBytes(MsixDigest.DdSig).Concat(classicNoSig).ToArray();
        Assert.Equal(16UL, MsixDigest.DataDescriptorLenAndValidate(classicSig, 0, false, zf));

        var zip64NoSig = BitConverter.GetBytes(crc).Concat(BitConverter.GetBytes(len64)).Concat(BitConverter.GetBytes(len64)).ToArray();
        Assert.Equal(20UL, MsixDigest.DataDescriptorLenAndValidate(zip64NoSig, 0, true, zf));

        var zip64Sig = BitConverter.GetBytes(MsixDigest.DdSig).Concat(zip64NoSig).ToArray();
        Assert.Equal(24UL, MsixDigest.DataDescriptorLenAndValidate(zip64Sig, 0, true, zf));

        var badCrc = (byte[])zip64Sig.Clone();
        badCrc[4] ^= 0x01;
        Assert.Contains("CRC does not match", Assert.ThrowsAny<PsignException>(() => MsixDigest.DataDescriptorLenAndValidate(badCrc, 0, true, zf)).Message);

        var badSizes = (byte[])zip64Sig.Clone();
        badSizes[8] ^= 0x01;
        Assert.Contains("sizes do not match", Assert.ThrowsAny<PsignException>(() => MsixDigest.DataDescriptorLenAndValidate(badSizes, 0, true, zf)).Message);

        var emptyZip = ZipTestHelpers.ZipWithEntries(("empty.bin", []));
        var emptyZf = ZipArchiveReader.Open(emptyZip).ByIndex(0);
        var emptyDd = BitConverter.GetBytes(MsixDigest.DdSig).Concat(BitConverter.GetBytes(0u)).Concat(BitConverter.GetBytes(emptyZf.CompressedSize)).Concat(BitConverter.GetBytes(0UL)).ToArray();
        Assert.Equal(24UL, MsixDigest.DataDescriptorLenAndValidate(emptyDd, 0, true, emptyZf));
    }

    [Fact]
    public void NativeSkipPackageContentHashFixtureUsesAxpcSentinelAndVerifies()
    {
        var bytes = Fixtures.Bytes("msix-edge-cases/signed/flat-skip-pcontent-hash.signed.msix");
        var (_, embedded) = MsixDigest.MsixVerifiedSignature(bytes, "msix");
        var (pieceLen, parts) = MsixDigest.ParseSignedAppxBlob(embedded);
        Assert.Equal(32, pieceLen);
        Assert.Equal(MsixDigest.SkipPackageContentHashSentinel[..32].ToArray(), parts.Axpc);
        Assert.NotNull(parts.Axci);
    }

    [Theory]
    [InlineData("Assets/Sub%20Dir/notes%20%26%20config.xml", "Assets/Sub Dir/notes & config.xml")]
    [InlineData("Assets/donn%C3%A9es-utf8.txt", "Assets/données-utf8.txt")]
    [InlineData("[Content_Types].xml", "[Content_Types].xml")]
    [InlineData("dir\\file.txt", "dir/file.txt")]
    public void OpcPartNamesDecode(string encoded, string logical) => Assert.Equal(logical, MsixDigest.DecodeOpcZipPartName(encoded));

    [Theory]
    [InlineData("a%2Fb.txt", "forbidden path separator")]
    [InlineData("a%5Cb.txt", "forbidden path separator")]
    [InlineData("/abs.txt", "leading or trailing")]
    [InlineData("a//b.txt", "empty path segment")]
    [InlineData("a/../b.txt", "invalid path segment")]
    [InlineData("c:evil.txt", "invalid path segment")]
    [InlineData("bad%FF.txt", "invalid UTF-8")]
    public void OpcPartNamesRejectForbiddenForms(string encoded, string message) => Assert.Contains(message, Err(() => MsixDigest.DecodeOpcZipPartName(encoded)));

    [Fact]
    public void OpcPartNamesEncodeLikeAppxPackaging()
    {
        Assert.Equal("Assets/Sub%20Dir/notes%20%26%20config.xml", MsixDigest.EncodeOpcPartName("Assets/Sub Dir/notes & config.xml"));
        Assert.Equal("Assets/donn%C3%A9es-utf8.txt", MsixDigest.EncodeOpcPartName("Assets/données-utf8.txt"));
        Assert.Equal("[Content_Types].xml", MsixDigest.EncodeOpcPartName("[Content_Types].xml"));
        Assert.Equal("a-b.c_d~e!f", MsixDigest.EncodeOpcPartName("a-b.c_d~e!f"));
    }
}
