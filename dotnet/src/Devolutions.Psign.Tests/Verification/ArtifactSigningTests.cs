using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>Ports of <c>artifact_signing.rs</c> unit tests.</summary>
public class ArtifactSigningTests
{
    private static readonly ulong[] Ms = [1, 3, 6, 1, 4, 1, 311, 97];

    private static ulong[] Arcs(params ulong[] suffix) => [.. Ms, .. suffix];

    private static (ArtifactSigningCertificateKind, string)? IdentityFromEku(params ulong[][] oids)
    {
        (ArtifactSigningCertificateKind, string)? kinds = null;
        foreach (var arcs in ArtifactSigning.DecodeEkuArcs(OnlineAndEkuTests.EncodeEku(oids)))
        {
            if (arcs.Length >= Ms.Length && arcs.AsSpan(0, Ms.Length).SequenceEqual(Ms)
                && ArtifactSigning.ClassifyIdentitySuffix(arcs[Ms.Length..]) is { } c)
            {
                kinds = (c.Kind, string.Join('.', c.Id));
            }
        }

        return kinds;
    }

    [Fact]
    public void PinnedRootMatchesThumbprints()
    {
        var roots = ArtifactSigning.PublicTrustAnchorCerts();
        Assert.Single(roots);
        Assert.Equal(roots[0].Subject, roots[0].Issuer);
    }

    [Theory]
    [InlineData(ArtifactSigningCertificateKind.PublicTrust, "990309390.766961637.194916062.941502583", new ulong[] { 990309390, 766961637, 194916062, 941502583 })]
    [InlineData(ArtifactSigningCertificateKind.PublicTrustTest, "548345392.570456524.348779735.628493769", new ulong[] { 1, 2, 548_345_392, 570_456_524, 348_779_735, 628_493_769 })]
    [InlineData(ArtifactSigningCertificateKind.PrivateTrust, "29433.35007.34545.16815.37291.11644.53265.56135", new ulong[] { 1, 3, 1, 29433, 35007, 34545, 16815, 37291, 11644, 53265, 56135 })]
    [InlineData(ArtifactSigningCertificateKind.PrivateTrustCiPolicy, "29433.35007.34545.16815.37291.11644.53265.56135", new ulong[] { 1, 4, 1, 29433, 35007, 34545, 16815, 37291, 11644, 53265, 56135 })]
    public void ClassifiesDocumentedIdentityEkus(ArtifactSigningCertificateKind kind, string id, ulong[] suffix)
    {
        Assert.Equal((kind, id), IdentityFromEku(Arcs(suffix)));
    }

    [Fact]
    public void MarkerAndUnknownSubtypesAreNotIdentities() =>
        Assert.Null(IdentityFromEku(Arcs(1, 0), Arcs(1, 9, 7)));

    [Fact]
    public void RejectsTruncatedAndNonCanonicalOids()
    {
        Assert.Throws<PsignException>(() => ArtifactSigning.DecodeEkuArcs([0x30, 0x03, 0x06, 0x01, 0x80]));
        Assert.Throws<PsignException>(() => ArtifactSigning.DecodeEkuArcs([0x30, 0x04, 0x06, 0x02, 0x80, 0x01]));
    }

    [Fact]
    public void ExtractsPublisherIdFromRealSignerCertificate()
    {
        var id = ArtifactSigning.IdentityFromCertBytes(Fixtures.Bytes("artifact-signing/devolutions-signer.pem"))!;
        Assert.Equal(ArtifactSigningCertificateKind.PublicTrust, id.Kind);
        Assert.Equal("285218949.549339218.252840042.443064405", id.PublisherId);
        Assert.Equal("1.3.6.1.4.1.311.97.285218949.549339218.252840042.443064405", id.IdentityEku);
        Assert.True(id.HasPublicTrustMarker);
        Assert.True(id.HasCodeSigningEku);
    }

    [Fact]
    public void NonArtifactSigningCertificateHasNoIdentity() =>
        Assert.Null(ArtifactSigning.IdentityFromCertificate(ArtifactSigning.MicrosoftIdentityVerificationRoot2020.Certificate()));

    private static (byte[] Pkcs7, byte[] Digest) RealPkcs7AndDigest()
    {
        var pkcs7 = Fixtures.Bytes("artifact-signing/psign-tool.pkcs7.der");
        var digest = AuthenticodeSignature.Parse(Pkcs7Wire.NormalizeForAuthenticode(pkcs7)).Digest;
        return (pkcs7, digest);
    }

    private static ArtifactSigningVerifiedSignature VerifyReal(byte[] digest, ArtifactSigningPolicy policy, TrustVerifyPeOptions? opts = null) =>
        ArtifactSigning.VerifyArtifactSigningPkcs7(RealPkcs7AndDigest().Pkcs7, 0, digest, Pkcs7DigestBinding.AuthenticodeIndirect, policy, opts ?? new TrustVerifyPeOptions());

    private static ArtifactSigningPolicy Pinned(params string[] ids) => new() { ExpectedPublisherIds = ids };

    [Fact]
    public void VerifiesRealPublicTrustSignatureAtTimestamp()
    {
        var report = VerifyReal(RealPkcs7AndDigest().Digest, Pinned());
        Assert.True(report.Timestamped);
        Assert.Equal("285218949.549339218.252840042.443064405", report.Identity.PublisherId);
        Assert.Equal("f40042e2e5f7e8ef8189fed15519aece42c3bfa2", report.RootSha1);
        Assert.Contains("publisher_id=285218949.549339218.252840042.443064405 kind=public_trust root=f40042e2e5f7e8ef8189fed15519aece42c3bfa2", report.ToString());
        Assert.EndsWith(" (timestamp)", report.ToString());
    }

    [Fact]
    public void RejectsUnexpectedPublisherId()
    {
        var e = Assert.Throws<PsignException>(() => VerifyReal(RealPkcs7AndDigest().Digest, Pinned("990309390.766961637.194916062.941502583")));
        Assert.Contains("not one of the expected", e.FullMessage);
    }

    [Fact]
    public void AcceptsExpectedPublisherId() =>
        VerifyReal(RealPkcs7AndDigest().Digest, Pinned("1.2.3.4", "285218949.549339218.252840042.443064405"));

    [Fact]
    public void RejectsSignerOutside72HourValidityWithoutTimestampTime()
    {
        var opts = new TrustVerifyPeOptions { VerificationInstantOverride = VerificationInstant.ParseVerificationDateYmd("2026-11-01") };
        Assert.Throws<PsignException>(() => VerifyReal(RealPkcs7AndDigest().Digest, Pinned(), opts));
    }

    [Fact]
    public void RejectsDigestMismatch()
    {
        var digest = RealPkcs7AndDigest().Digest.ToArray();
        digest[0] ^= 0xff;
        Assert.Throws<PsignException>(() => VerifyReal(digest, Pinned()));
    }

    [Fact]
    public void GenericAnchorsCannotSatisfyArtifactSigningPolicy()
    {
        var pe = Fixtures.Bytes("pe-authenticode-upstream/tiny64.signed.efi");
        using var dir = new TempDir();
        var root = dir.File("root.der");
        File.WriteAllBytes(root, TrustVerifyPe.PeFirstPkcs7TerminalRoot(pe).RawData);
        var opts = new TrustVerifyPeOptions
        {
            TrustedCaFiles = [root],
            VerificationInstantOverride = VerificationInstant.ParseVerificationDateYmd("2023-07-01"),
        };
        TrustVerifyPe.TrustVerifyPeBytes(pe, opts);
        var e = Assert.Throws<PsignException>(() => TrustVerifyPe.TrustVerifyPeBytes(pe, opts with { ArtifactSigning = Pinned() }));
        Assert.Contains("no Artifact Signing identity EKU", e.FullMessage);
    }

    [Fact]
    public void PrivateTrustRequiresSubscriberRoot()
    {
        var shared = new TrustVerifySharedArgs { ArtifactSigning = true, TrustedCa = ["x.cer"] };
        var e = Assert.Throws<PsignException>(() => shared.ArtifactSigningPolicy());
        Assert.StartsWith("--trusted-ca cannot be combined with --artifact-signing", e.Message);
    }

    [Fact]
    public void ArtifactSigningPolicyJsonUsesSnakeCase()
    {
        var json = RustJson.ToStringPretty(new ArtifactSigningIdentity { Kind = ArtifactSigningCertificateKind.PrivateTrustCiPolicy, PublisherId = "1", IdentityEku = "x" });
        Assert.Contains("\"kind\": \"private_trust_ci_policy\"", json);
    }
}
