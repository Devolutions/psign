using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Msix;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>
/// Tests for MSIX PR #57 parity helpers, <see cref="VerifiedSignature"/> reporting, SHA-256 thumbprint helpers,
/// <see cref="ArtifactSigningPolicy.PrivateTrustRootDer"/>, and MSIX pinning / auto-pinning verification.
/// </summary>
public class MsixPinningTests
{
    private static byte[] SignTestMsix(CertificateInfo signerCert, IReadOnlyList<CertificateInfo> chainCerts, RSA key)
    {
        var unsigned = Fixtures.Bytes("generated-unsigned/msix/sample.msix");
        var signer = new RsaDigestSigner(key);
        return MsixSigner.SignBytes(unsigned, "msix", AuthenticodeHashKind.Sha256, signerCert, chainCerts, signer);
    }

    private static (CertificateInfo Cert, RSA Key) CreateSelfSignedCodeSigningCert(DateTimeOffset notBefore, DateTimeOffset notAfter, params string[] extraEkus)
    {
        var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Psign Self-Signed Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var ekus = new OidCollection { new(Oids.EkuCodeSigning) };
        foreach (var oid in extraEkus)
        {
            ekus.Add(new Oid(oid));
        }

        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        using var cert = req.CreateSelfSigned(notBefore, notAfter);
        return (CertificateInfo.Parse(cert.RawData), key);
    }

    private static (CertificateInfo Root, CertificateInfo Leaf, RSA LeafKey) CreateCaAndLeaf(params string[] extraEkus)
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Psign Pinning Test CA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
        using var rootCert = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

        var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=Test Code Signing Certificate", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var ekus = new OidCollection { new(Oids.EkuCodeSigning) };
        foreach (var oid in extraEkus)
        {
            ekus.Add(new Oid(oid));
        }

        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, false));
        leafReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafReq.PublicKey, false));
        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7f;
        serial[0] |= 0x01;
        using var leafCert = leafReq.Create(rootCert, now.AddHours(-1), now.AddDays(15), serial);
        return (CertificateInfo.Parse(rootCert.RawData), CertificateInfo.Parse(leafCert.RawData), leafKey);
    }

    [Fact]
    public void VerifiedSignaturesAndThumbprintHelpersArePopulated()
    {
        var root = ArtifactSigning.MicrosoftIdentityVerificationRoot2020.Certificate();
        Assert.Equal(ArtifactSigning.MicrosoftIdentityVerificationRoot2020.Sha256, Anchors.CertSha256Thumbprint(root));
        Assert.Equal("5367f20c7ade0e2bca790915056d086b720c33c1fa2a2661acf787e3292e1270", Anchors.CertDerSha256Hex(root.RawData));
        Assert.Equal("f40042e2e5f7e8ef8189fed15519aece42c3bfa2", Anchors.CertDerSha1Hex(root.RawData));

        // Generic MSIX trust populates VerifiedSignatures.
        var msix = Fixtures.Bytes("generated-signed/msix/sample.msix");
        var report = TrustVerifyMsix.TrustVerifyMsixBytes(msix, "msix", FormatTrustTests.TestCaOpts());
        var sig = Assert.Single(report.VerifiedSignatures);
        Assert.Equal(0, sig.SignatureIndex);
        Assert.NotEmpty(sig.SignerCertificateDer);
        Assert.Equal(Anchors.CertDerSha256Hex(sig.SignerCertificateDer), sig.SignerSha256Hex);
        Assert.Equal(Anchors.CertDerSha1Hex(sig.SignerCertificateDer), sig.SignerSha1Hex);
        Assert.False(string.IsNullOrEmpty(sig.SignerSubject));
        Assert.NotNull(sig.RootSubject);
        Assert.Equal(40, sig.RootSha1Hex?.Length);
        Assert.Equal(64, sig.RootSha256Hex?.Length);
        Assert.False(sig.Timestamped);
        Assert.Null(sig.ArtifactSigning);

        // Private Trust via PrivateTrustRootDer populates both ArtifactSigning and VerifiedSignatures.
        var ptMsix = Fixtures.Bytes("artifact-signing/private-trust/sample.msix");
        var ptRootDer = Fixtures.Bytes("artifact-signing/private-trust/root.cer");
        var ptReport = TrustVerifyMsix.TrustVerifyMsixBytes(ptMsix, "msix", new TrustVerifyPeOptions
        {
            ArtifactSigning = new ArtifactSigningPolicy
            {
                ExpectedPublisherIds = ["11.22.33.44.55.66.77.88"],
                PrivateTrustRootDer = [ptRootDer],
                RequireTimestamp = false,
            },
        });
        Assert.Single(ptReport.ArtifactSigning);
        var ptSig = Assert.Single(ptReport.VerifiedSignatures);
        Assert.Equal("11.22.33.44.55.66.77.88", ptSig.ArtifactSigning?.PublisherId);
        Assert.Equal(Anchors.CertDerSha256Hex(ptRootDer), ptSig.RootSha256Hex);

        // Generic VSIX trust also populates VerifiedSignatures.
        var vsix = Fixtures.Bytes("package-signing/signed/sample.signed.vsix");
        var vsixReport = TrustVerifyVsix.TrustVerifyVsixBytes(vsix, FormatTrustTests.TestCaOpts());
        var vsixSig = Assert.Single(vsixReport.VerifiedSignatures);
        Assert.Equal(64, vsixSig.SignerSha256Hex.Length);
    }

    [Fact]
    public void MsixParityHelpersWork()
    {
        var msix = Fixtures.Bytes("generated-signed/msix/sample.msix");
        var signerDer = TrustVerifyMsix.VerifyMsixSignatureWithoutTrust(msix, "msix");
        var (pkcs7, _) = MsixDigest.MsixVerifiedSignature(msix, "msix");
        var inspection = AuthenticodeInspector.InspectAuthenticodePkcs7Der(pkcs7);
        Assert.Equal(Convert.ToBase64String(signerDer), inspection.Signers[0].SignerCertificateDerBase64);

        var tampered = msix.ToArray();
        tampered[40] ^= 1;
        Assert.ThrowsAny<PsignException>(() => TrustVerifyMsix.VerifyMsixSignatureWithoutTrust(tampered, "msix"));

        var explicitOpts = FormatTrustTests.TestCaOpts();
        var (resolvedExplicit, cacheExplicit) = TrustVerifyMsix.MsixOptionsWithAutoAuthRoot(explicitOpts);
        Assert.Null(cacheExplicit);
        Assert.Equal(explicitOpts.TrustedCaFiles, resolvedExplicit.TrustedCaFiles);
        Assert.Null(resolvedExplicit.AuthrootCab);

        var (resolvedSystem, cacheSystem) = TrustVerifyMsix.MsixOptionsWithAutoAuthRoot(new TrustVerifyPeOptions());
        Assert.Null(cacheSystem);
        Assert.NotEmpty(resolvedSystem.TrustedCaDer);
        var (anchors, _) = TrustVerifyPe.LoadTrustMaterial(resolvedSystem);
        Assert.True(anchors.ThumbprintCount > 0);

        Assert.Throws<PsignException>(() => TrustVerifyMsix.TrustVerifyMsixCurrentOrTimestamp(msix, "msix", explicitOpts));
        var untrustedErr = Assert.Throws<PsignException>(() =>
            TrustVerifyMsix.TrustVerifyMsixCurrentOrTimestamp(msix, "msix", new TrustVerifyPeOptions()));
        Assert.Contains("no trust anchors configured", untrustedErr.FullMessage);
    }

    [Fact]
    public void MsixPinningArtifactSigningPrivateAndPublicTrust()
    {
        var ptMsix = Fixtures.Bytes("artifact-signing/private-trust/sample.msix");
        var ptRootPath = Fixtures.Path("artifact-signing/private-trust/root.cer");
        var ptRootDer = Fixtures.Bytes("artifact-signing/private-trust/root.cer");

        var verified = TrustVerifyMsix.VerifyMsixWithPins(ptMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedArtifactSigningPublisherIds = ["11.22.33.44.55.66.77.88"],
            TrustedCaFiles = [ptRootPath],
        });
        Assert.Equal(MsixRecommendedPin.ArtifactSigningPublisherId("11.22.33.44.55.66.77.88"), verified.RecommendedPin);
        Assert.Equal(ArtifactSigningCertificateKind.PrivateTrust, verified.ArtifactSigning?.Kind);

        var verifiedDer = TrustVerifyMsix.VerifyMsixWithPins(ptMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedArtifactSigningPublisherIds = ["11.22.33.44.55.66.77.88"],
            TrustedCaDer = [ptRootDer],
        });
        Assert.Equal(verified.SignerSha256Hex, verifiedDer.SignerSha256Hex);

        // Wrong publisher ID rejected.
        Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(ptMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedArtifactSigningPublisherIds = ["99.99.99.99"],
            TrustedCaFiles = [ptRootPath],
        }));

        // Private Trust without subscriber root fails closed.
        Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(ptMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedArtifactSigningPublisherIds = ["11.22.33.44.55.66.77.88"],
        }));

        // Auto-pinning recommends ArtifactSigningPublisherId for Private Trust with subscriber root.
        var autoPt = TrustVerifyMsix.VerifyMsixForPinning(ptMsix, "msix", [ptRootPath]);
        Assert.Equal(MsixRecommendedPin.ArtifactSigningPublisherId("11.22.33.44.55.66.77.88"), autoPt.RecommendedPin);

        // Private Trust CI Policy EKU is rejected.
        var (ciRoot, ciLeaf, ciKey) = CreateCaAndLeaf("1.3.6.1.4.1.311.97.1.4.1.11.22.33.44");
        using (ciKey)
        {
            var ciMsix = SignTestMsix(ciLeaf, [ciRoot], ciKey);
            var ciErr = Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(ciMsix, "msix", new MsixPinVerifyOptions
            {
                ExpectedArtifactSigningPublisherIds = ["11.22.33.44"],
                TrustedCaDer = [ciRoot.RawData],
            }));
            Assert.Contains("Private Trust CI Policy", ciErr.FullMessage);
        }

        // Fake Public Trust EKU signed by non-Microsoft CA fails Public Trust verification.
        var (fakeRoot, fakeLeaf, fakeKey) = CreateCaAndLeaf("1.3.6.1.4.1.311.97.1.0", "1.3.6.1.4.1.311.97.12345.67890");
        using (fakeKey)
        {
            var fakeMsix = SignTestMsix(fakeLeaf, [fakeRoot], fakeKey);
            Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(fakeMsix, "msix", new MsixPinVerifyOptions
            {
                ExpectedArtifactSigningPublisherIds = ["12345.67890"],
            }));
        }
    }

    [Fact]
    public void MsixThumbprintPinningAndAutoPinning()
    {
        var (caRoot, leaf, leafKey) = CreateCaAndLeaf();
        byte[] caMsix;
        using (leafKey)
        {
            caMsix = SignTestMsix(leaf, [caRoot], leafKey);
        }

        var leafSha256 = Anchors.CertDerSha256Hex(leaf.RawData);
        var leafSha1 = Anchors.CertDerSha1Hex(leaf.RawData);

        using var dir = new TempDir();
        var caPath = dir.File("ca.cer");
        File.WriteAllBytes(caPath, caRoot.RawData);

        // SHA-256 pin with prefix, uppercase, and colons.
        var colonUpper = string.Join(':', Enumerable.Range(0, 32).Select(i => leafSha256.Substring(i * 2, 2).ToUpperInvariant()));
        var pinnedSha256 = TrustVerifyMsix.VerifyMsixWithPins(caMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [$"sha256:{colonUpper}"],
            TrustedCaFiles = [caPath],
        });
        Assert.Equal(leafSha256, pinnedSha256.SignerSha256Hex);
        Assert.Equal(leafSha1, pinnedSha256.SignerSha1Hex);
        Assert.Equal(MsixRecommendedPin.CertificateSha256(leafSha256), pinnedSha256.RecommendedPin);

        // SHA-1 pin with in-memory CA DER.
        var pinnedSha1 = TrustVerifyMsix.VerifyMsixWithPins(caMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [$"sha1:{leafSha1}"],
            TrustedCaDer = [caRoot.RawData],
        });
        Assert.Equal(leafSha1, pinnedSha1.SignerSha1Hex);

        // Wrong thumbprint & malformed thumbprint rejected.
        Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(caMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [new string('0', 64)],
            TrustedCaDer = [caRoot.RawData],
        }));
        Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(caMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [$"sha256:{leafSha1}"],
            TrustedCaDer = [caRoot.RawData],
        }));

        // Tampered MSIX rejected even with matching thumbprint and CA.
        var tampered = caMsix.ToArray();
        tampered[40] ^= 0xff;
        Assert.ThrowsAny<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(tampered, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [leafSha256],
            TrustedCaDer = [caRoot.RawData],
        }));

        // Private-CA-issued leaf without explicit CA succeeds when AllowPinnedLeafTrust is true.
        TrustVerifyMsix.VerifyMsixWithPins(caMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [leafSha256],
            AllowPinnedLeafTrust = true,
        });

        // VerifyMsixForPinning recommends CertificateSha256 with CA and fails closed without CA.
        var autoRegular = TrustVerifyMsix.VerifyMsixForPinning(caMsix, "msix", [caPath]);
        Assert.Equal(MsixRecommendedPin.CertificateSha256(leafSha256), autoRegular.RecommendedPin);
        Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixForPinning(caMsix, "msix"));

        // Self-signed valid cert: succeeds only with AllowPinnedLeafTrust.
        var now = DateTimeOffset.UtcNow;
        var (selfCert, selfKey) = CreateSelfSignedCodeSigningCert(now.AddHours(-1), now.AddDays(7));
        byte[] selfMsix;
        using (selfKey)
        {
            selfMsix = SignTestMsix(selfCert, [], selfKey);
        }

        var selfSha256 = Anchors.CertDerSha256Hex(selfCert.RawData);
        Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixForPinning(selfMsix, "msix"));
        Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(selfMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [selfSha256],
            AllowPinnedLeafTrust = false,
        }));
        var selfVerified = TrustVerifyMsix.VerifyMsixWithPins(selfMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [selfSha256],
            AllowPinnedLeafTrust = true,
        });
        Assert.Equal(MsixRecommendedPin.CertificateSha256(selfSha256), selfVerified.RecommendedPin);

        // Expired untimestamped self-signed cert rejected even with AllowPinnedLeafTrust.
        var (expiredCert, expiredKey) = CreateSelfSignedCodeSigningCert(now.AddDays(-30), now.AddHours(-1));
        byte[] expiredMsix;
        using (expiredKey)
        {
            expiredMsix = SignTestMsix(expiredCert, [], expiredKey);
        }

        var expiredErr = Assert.Throws<PsignException>(() => TrustVerifyMsix.VerifyMsixWithPins(expiredMsix, "msix", new MsixPinVerifyOptions
        {
            ExpectedCertThumbprints = [Anchors.CertDerSha256Hex(expiredCert.RawData)],
            AllowPinnedLeafTrust = true,
        }));
        Assert.Contains("not valid at current time", expiredErr.FullMessage);
    }
}
