using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Pe;
using OpenMcdf;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class MsiDigestTests
{
    private const string Stub = "msi-authenticode-upstream/tiny-pkcs7-stub.msi";

    private static readonly AuthenticodeHashKind[] AllKinds =
        [AuthenticodeHashKind.Sha1, AuthenticodeHashKind.Sha256, AuthenticodeHashKind.Sha384, AuthenticodeHashKind.Sha512];

    private static byte[] CompoundWithSignatureNamedStreams(byte rootByte, byte nestedByte)
    {
        var ms = new MemoryStream();
        using (var root = RootStorage.Create(ms, OpenMcdf.Version.V3, StorageModeFlags.LeaveOpen))
        {
            using (var s = root.CreateStream(MsiDigest.DigitalSignatureEntry))
            {
                s.WriteByte(rootByte);
            }

            var nested = root.CreateStorage("Nested");
            nested.CreationTime = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            nested.ModifiedTime = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            using (var s = nested.CreateStream(MsiDigest.DigitalSignatureEntry))
            {
                s.WriteByte(nestedByte);
            }
        }

        return ms.ToArray();
    }

    [Fact]
    public void DigitalSignaturePkcs7MatchesPeFixtureOnStub()
    {
        var got = MsiDigest.DigitalSignaturePkcs7Der(Fixtures.Bytes(Stub));
        var want = PeAuthenticode.FirstPkcs7(Fixtures.Bytes("pe-authenticode-upstream/tiny32.signed.efi"));
        Assert.Equal(want, got);
        Assert.True(MsiDigest.HasDigitalSignature(Fixtures.Bytes(Stub)));
    }

    [Fact]
    public void RsaSha256SignerPrehashMatchesDirectOnStub()
    {
        var msi = Fixtures.Bytes(Stub);
        var sd = CmsSignedData.Parse(MsiDigest.DigitalSignaturePkcs7Der(msi));
        var direct = SHA256.HashData(sd.SignerInfos[0].SignedAttributesSetDer());
        Assert.Equal(direct, MsiDigest.RsaSha256SignerPrehashDigest(msi, 0));
    }

    [Fact]
    public void RsaSha256SignerPrehashErrorsWhenNotOle()
    {
        var e = Assert.Throws<PsignException>(() => MsiDigest.RsaSha256SignerPrehashDigest("not an msi"u8.ToArray(), 0));
        Assert.StartsWith("open as OLE compound file", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("generated-signed/installer/tiny.msi")]
    [InlineData("generated-signed/installer/tiny-patch.msp")]
    public void GeneratedSignedInstallerFixturesMatchMsiSipDigest(string fixture)
    {
        MsiDigest.VerifyDigestConsistency(Fixtures.Path(fixture));
    }

    [Fact]
    public void PreparingMsiWritesMetadataDigestBeforeComputingSigningDigest()
    {
        var msi = Fixtures.Bytes(Stub);
        foreach (var kind in AllKinds)
        {
            var prepared = MsiDigest.PrepareForAuthenticodeSigning(msi, kind);
            using (var root = RootStorage.Open(new MemoryStream(prepared.Image, writable: false)))
            using (var s = root.OpenStream(MsiDigest.ExtendedSignatureEntry))
            {
                var extended = new byte[s.Length];
                s.ReadExactly(extended);
                Assert.Equal(MsiDigest.ComputeMetadataDigest(prepared.Image, kind), extended);
                Assert.Equal(MsiDigest.ComputeMetadataDigest(msi, kind), extended);
            }

            Assert.Equal(MsiDigest.ComputeAuthenticodeDigest(prepared.Image, kind), prepared.Digest);
            Assert.Equal(MsiDigest.ComputePreparedAuthenticodeDigest(prepared.Image, kind), prepared.Digest);

            var preparedAgain = MsiDigest.PrepareForAuthenticodeSigning(prepared.Image, kind);
            Assert.Equal(prepared.Digest, preparedAgain.Digest);
        }
    }

    [Fact]
    public void SipNameOrderPutsLongerPrefixFirst()
    {
        Assert.True(MsiDigest.CompareUtf16Name("NameExtra", "Name") < 0);
        Assert.True(MsiDigest.CompareUtf16Name("Name", "NameExtra") > 0);
        // UTF-16LE byte order: low byte first ('Ł' 0x41 0x01 sorts before 'B' 0x42 0x00).
        Assert.True(MsiDigest.CompareUtf16Name("Ł", "B") < 0);
        Assert.True(MsiDigest.CompareUtf16Name("A", "Ł") < 0);
    }

    [Fact]
    public void OnlyRootSignatureStreamsAreExcludedFromContentDigest()
    {
        var kind = AuthenticodeHashKind.Sha256;
        var baseline = CompoundWithSignatureNamedStreams(1, 1);
        var changedRoot = CompoundWithSignatureNamedStreams(2, 1);
        var changedNested = CompoundWithSignatureNamedStreams(1, 2);
        Assert.Equal(MsiDigest.ComputeAuthenticodeDigest(baseline, kind), MsiDigest.ComputeAuthenticodeDigest(changedRoot, kind));
        Assert.NotEqual(MsiDigest.ComputeAuthenticodeDigest(baseline, kind), MsiDigest.ComputeAuthenticodeDigest(changedNested, kind));
    }

    [Fact]
    public void PreparedSigningDigestRequiresMatchingExtendedStream()
    {
        var msi = Fixtures.Bytes(Stub);
        var kind = AuthenticodeHashKind.Sha256;
        var missing = Assert.Throws<PsignException>(() => MsiDigest.ComputePreparedAuthenticodeDigest(msi, kind));
        Assert.Contains("MsiDigitalSignatureEx", missing.Message, StringComparison.Ordinal);

        var prepared = MsiDigest.PrepareForAuthenticodeSigning(msi, kind);
        var tampered = MsiDigest.WriteRootStream(prepared.Image, MsiDigest.ExtendedSignatureEntry, new byte[32]);
        Assert.Throws<PsignException>(() => MsiDigest.ComputePreparedAuthenticodeDigest(tampered, kind));
    }

    [Fact]
    public void StubDigestMismatchIsReported()
    {
        var e = Assert.Throws<PsignException>(() => MsiDigest.VerifyDigestConsistency(Fixtures.Bytes(Stub)));
        Assert.Contains("digest mismatch", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnsignedMsiIsMissingSignature()
    {
        var e = Assert.Throws<PsignException>(() => MsiDigest.DigitalSignaturePkcs7Der(Fixtures.Bytes("generated-unsigned/installer/tiny.msi")));
        Assert.Equal("MSI is missing \\u{5}DigitalSignature stream", e.Message);
    }

    [SkippableTheory]
    [InlineData("generated-signed/installer/tiny.msi")]
    [InlineData("generated-signed/installer/tiny-patch.msp")]
    [InlineData(Stub)]
    public void ExtractedPkcs7MatchesRust(string fixture)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var output = dir.File("sig.p7");
        RustTool.RunOk("portable", "extract-msi-pkcs7", "--output", output, Fixtures.Path(fixture));
        Assert.Equal(File.ReadAllBytes(output), MsiDigest.DigitalSignaturePkcs7Der(Fixtures.Bytes(fixture)));
    }

    [SkippableTheory]
    [InlineData("generated-signed/installer/tiny.msi")]
    [InlineData("generated-signed/installer/tiny-patch.msp")]
    [InlineData("generated-signed/installer/tiny-transform.mst")]
    [InlineData(Stub)]
    public void VerifyOutcomeMatchesRust(string fixture)
    {
        RustTool.Require();
        var (code, _, _) = RustTool.Run("portable", "verify-msi", Fixtures.Path(fixture));
        bool ok;
        try
        {
            MsiDigest.VerifyDigestConsistency(Fixtures.Path(fixture));
            ok = true;
        }
        catch (PsignException)
        {
            ok = false;
        }

        Assert.Equal(code == 0, ok);
    }
}
