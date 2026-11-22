using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>Ports of <c>trust_verify_pe.rs</c> / <c>trust_verify_detached.rs</c> / <c>inspect.rs</c> tests and PE/detached cases of <c>format_trust.rs</c>.</summary>
public class TrustVerifyPeTests
{
    private static TrustVerifyPeOptions TestCaOpts() => new()
    {
        TrustedCaFiles = [Fixtures.Path("devolutions-authenticode/authenticode-test-ca.crt")],
        // Inside the test certificate's validity window (2022-03-22 .. 2027-03-22).
        VerificationInstantOverride = VerificationInstant.ParseVerificationDateYmd("2026-06-01"),
    };

    public static IEnumerable<object[]> GeneratedPe() =>
        Directory.GetFiles(Fixtures.Path("generated-signed/pe")).Select(p => new object[] { "generated-signed/pe/" + Path.GetFileName(p) });

    [Theory]
    [MemberData(nameof(GeneratedPe))]
    public void GeneratedPeTrustVerify(string rel)
    {
        var report = TrustVerifyPe.TrustVerifyPeBytes(Fixtures.Bytes(rel), TestCaOpts());
        Assert.Equal(1, report.Pkcs7EntriesVerified);
        Assert.Equal(1, report.AnchorThumbprints);
        Assert.Equal(["trust-verify-pe: ok — verified 1 PKCS#7 entr(y/ies); 1 anchor thumbprint(s)"], report.FormatOkLines("trust-verify-pe"));
    }

    [Theory]
    [InlineData("generated-signed/pe/tiny32-pe-alias.exe")]
    [InlineData("generated-signed/pe/tiny64-pe-alias.dll")]
    public void TrustVerifyPathDispatchesPe(string rel)
    {
        Assert.Equal(1, TrustVerifyFile.TrustVerifyPath(Fixtures.Path(rel), TestCaOpts()).Pkcs7EntriesVerified);
    }

    [Fact]
    public void TrustVerifyPathReportsUnsupportedAndUnregisteredFormats()
    {
        var e = Assert.Throws<PsignException>(() => TrustVerifyFile.TrustVerifyPath("file.unknown", TestCaOpts()));
        Assert.Equal("portable trust verification does not support this file format: file.unknown", e.Message);
        Assert.True(TrustVerifyFile.IsFormatAvailable(TrustVerifyFormat.Pe));
        Assert.Equal(TrustVerifyFormat.Script, TrustVerifyFile.FormatForExtension("ps1"));
    }

    [Fact]
    public void TamperedPeIsRejected()
    {
        var pe = Fixtures.Bytes("generated-signed/pe/tiny32-pe-alias.exe");
        pe[0x200] ^= 0xFF;
        var e = Assert.Throws<PsignException>(() => TrustVerifyPe.TrustVerifyPeBytes(pe, TestCaOpts()));
        Assert.Equal("PE digest mismatch before trust checks for PKCS#7 index 0", e.Message);
    }

    [Fact]
    public void UnsignedPeHasNoCertificateTable()
    {
        Assert.Throws<PsignException>(() => TrustVerifyPe.TrustVerifyPeBytes(Fixtures.Bytes("pe-authenticode-upstream/tiny64.efi"), TestCaOpts()));
    }

    [Fact]
    public void NoAnchorsIsAnError()
    {
        var e = Assert.Throws<PsignException>(() => TrustVerifyPe.TrustVerifyPeBytes(Fixtures.Bytes("generated-signed/pe/tiny32-pe-alias.exe"), new TrustVerifyPeOptions()));
        Assert.Equal("no trust anchors configured (use --anchor-dir, --trusted-ca, --additional-trusted-ca, and/or --authroot-cab)", e.Message);
    }

    [Fact]
    public void AuthRootCabPinMismatchIsRejected()
    {
        using var dir = new TempDir();
        var cab = dir.File("authroot.cab");
        File.WriteAllBytes(cab, [1, 2, 3]);
        var opts = TestCaOpts() with { AuthrootCab = cab, ExpectAuthrootCabSha256 = new byte[32] };
        var e = Assert.Throws<PsignException>(() => TrustVerifyPe.LoadTrustMaterial(opts));
        Assert.StartsWith($"authroot CAB SHA-256 mismatch (pin differs from file {cab} — 039058c6", e.Message);
    }

    [Fact]
    public void VerboseChainIsWrittenToLog()
    {
        using var log = new StringWriter();
        TrustVerifyPe.TrustVerifyPeBytes(Fixtures.Bytes("generated-signed/pe/tiny32-pe-alias.exe"), TestCaOpts() with { VerboseChain = true, Log = log });
        Assert.Contains("trust-verify: PKCS#7[0] leaf subject: CN=Test Code Signing Certificate", log.ToString());
        Assert.Contains("trust-verify:   root subject: CN=Devolutions Authenticode Test CA (thumb SHA-1 247e24ee83dc1a29110a2c1a2a5d4dfefac369b7)", log.ToString());
    }

    // --- trust_verify_detached.rs ---
    [Fact]
    public void DetachedTrustErrorsWithoutAnchors()
    {
        var pe = Fixtures.Bytes("pe-authenticode-upstream/tiny32.signed.efi");
        var pkcs7 = PeAuthenticode.FirstPkcs7(pe);
        var e = Assert.Throws<PsignException>(() => TrustVerifyDetached.TrustVerifyDetachedBytes(pe, pkcs7, new TrustVerifyPeOptions()));
        Assert.Contains("no trust anchors", e.FullMessage);
    }

    [Fact]
    public void DetachedTrustPeContentMismatchesEmbeddedPkcs7Digest()
    {
        var pe = Fixtures.Bytes("pe-authenticode-upstream/tiny32.signed.efi");
        var pkcs7 = PeAuthenticode.FirstPkcs7(pe);
        var root = TrustVerifyPe.PeFirstPkcs7TerminalRoot(pe);
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("anchor.crt"), root.RawData);
        var opts = new TrustVerifyPeOptions
        {
            AnchorDir = dir.DirPath,
            VerificationInstantOverride = VerificationInstant.ParseVerificationDateYmd("2023-07-01"),
        };
        var e = Assert.Throws<PsignException>(() => TrustVerifyDetached.TrustVerifyDetachedBytes(pe, pkcs7, opts));
        Assert.True(e.FullMessage.Contains("detached content digest") || e.FullMessage.Contains("does not match"), e.FullMessage);
    }

    [Theory]
    [InlineData("generated-unsigned/detached/content-utf16le-bom.txt", "generated-signed/detached/content-utf16le-bom/content-utf16le-bom.txt.p7")]
    [InlineData("generated-unsigned/detached/content-utf8.txt", "generated-signed/detached/content-utf8/content-utf8.txt.p7")]
    [InlineData("generated-unsigned/detached/content.bin", "generated-signed/detached/content/content.bin.p7")]
    public void GeneratedDetachedTrustVerify(string content, string sig)
    {
        var report = TrustVerifyDetached.TrustVerifyDetachedBytes(Fixtures.Bytes(content), Fixtures.Bytes(sig), TestCaOpts());
        Assert.Equal(1, report.Pkcs7EntriesVerified);
    }

    // --- inspect.rs ---
    [Fact]
    public void InspectUpstreamSignedPeHasOuterPkcs7Signers()
    {
        var r = AuthenticodeInspector.InspectPeAuthenticode(Fixtures.Bytes("pe-authenticode-upstream/tiny64.signed.efi"));
        Assert.NotEmpty(r.Entries);
        Assert.NotEmpty(r.Entries[0].Pkcs7.Signers);
        Assert.Equal("2023-06-24T00:00:00Z", r.Entries[0].Pkcs7.TimestampSigningTime);
    }

    [Fact]
    public void Pkcs7TerminalRootUsesEmbeddedCertificates()
    {
        var root = TrustVerifyPe.Pkcs7SignedDataDerTerminalRoot(PeAuthenticode.FirstPkcs7(Fixtures.Bytes("pe-authenticode-upstream/tiny64.signed.efi")));
        Assert.Equal(root.Subject, root.Issuer);
    }

    [Fact]
    public void SharedArgsMirrorRustOptionMapping()
    {
        var args = new TrustVerifySharedArgs
        {
            TrustedCa = ["a.cer", "b.cer"],
            AdditionalTrustedCa = ["c.cer"],
            AsOf = "2024-02-29",
            AllowLooseSigningCert = true,
            ExpectAuthrootCabSha256 = "0x" + new string('a', 64),
        };
        var opts = args.ToOptions();
        Assert.Equal(["a.cer", "b.cer", "c.cer"], opts.TrustedCaFiles);
        Assert.Null(opts.AuthrootCab);
        Assert.False(opts.Online.EnableAia);
        Assert.False(opts.Policy.StrictCodeSigningEku);
        Assert.Equal(new DateTimeOffset(2024, 2, 29, 0, 0, 0, TimeSpan.Zero), opts.VerificationInstantOverride);
        Assert.True(args.ExplicitAnchorsReplaceAutomaticAuthRoot);
        Assert.False((args with { TrustedCa = [] }).ExplicitAnchorsReplaceAutomaticAuthRoot);
        Assert.True((args with { AuthrootCab = "x.cab" }).ToOptions().Online.EnableAia);
        Assert.Equal("expect 64 hex chars for SHA-256, got 3", Assert.Throws<PsignException>(() => TrustVerifySharedArgs.ParseSha256Hex("abc")).Message);
    }
}
