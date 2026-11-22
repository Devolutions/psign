using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification;
using Devolutions.Psign.Verification.Picky;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>Ports of <c>chain.rs</c> / <c>anchor.rs</c> tests plus picky chain-validation semantics.</summary>
public class ChainAndAnchorTests
{
    internal static (CertificateInfo Ca, CertificateInfo Leaf) SyntheticCaAndLeaf(
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        bool caIsCa = true,
        string? leafEku = Oids.EkuCodeSigning)
    {
        var nb = notBefore ?? DateTimeOffset.UtcNow.AddDays(-1);
        var na = notAfter ?? DateTimeOffset.UtcNow.AddYears(1);
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caReq = new CertificateRequest("CN=Trust Test CA", caKey, HashAlgorithmName.SHA256);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(caIsCa, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        caReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));
        using var ca = caReq.CreateSelfSigned(nb, na);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafReq = new CertificateRequest("CN=leaf.trust.test", leafKey, HashAlgorithmName.SHA256);
        if (leafEku is not null)
        {
            leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(leafEku) }, false));
        }

        leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
        using var leaf = leafReq.Create(ca.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey), nb, na, [1, 2, 3, 4]);
        return (CertificateInfo.Parse(ca.RawData), CertificateInfo.Parse(leaf.RawData));
    }

    [Fact]
    public void IssuerChainSingleCa()
    {
        var (ca, leaf) = SyntheticCaAndLeaf();
        var chain = TrustChain.IssuerChainExcludingLeaf(leaf, [ca, leaf], null);
        Assert.Single(chain);
        Assert.Equal(ca.Subject, chain[0].Subject);
    }

    [Fact]
    public void NonSelfSignedLeafAnchorDoesNotTerminateChain()
    {
        var (ca, leaf) = SyntheticCaAndLeaf();
        var anchors = AnchorStore.Empty();
        anchors.MergeCertThumbprints([leaf]);
        var chain = TrustChain.IssuerChainExcludingLeaf(leaf, [ca, leaf], anchors);
        Assert.Single(chain);
        Assert.Equal(ca.Subject, chain[0].Subject);
    }

    [Fact]
    public void MergeUniqueDropsDuplicateThumbprints()
    {
        var (_, leaf) = SyntheticCaAndLeaf();
        var merged = TrustChain.MergeUniqueCerts([leaf], [leaf]);
        Assert.Single(merged);
        Assert.Equal(Anchors.CertSha1Thumbprint(leaf), Anchors.CertSha1Thumbprint(merged[0]));
    }

    [Fact]
    public void MissingIssuerReportsPickyDebugName()
    {
        var (_, leaf) = SyntheticCaAndLeaf();
        var e = Assert.Throws<PsignException>(() => TrustChain.IssuerChainExcludingLeaf(leaf, [], null));
        Assert.Equal(
            "could not resolve issuer certificate for subject DirectoryName(Name(Asn1SequenceOf([Asn1SetOf([AttributeTypeAndValue { ty: ObjectIdentifierAsn1(ObjectIdentifier { root: JointIsoItuT, first_node: 5, child_nodes: [4, 3] }), value: CommonName(PrintableString(PrintableStringAsn1(PRINTABLE(\"Trust Test CA\")))) }])])))",
            e.Message);
    }

    [Fact]
    public void PickyVerifiesEcdsaChainAndValidity()
    {
        var (ca, leaf) = SyntheticCaAndLeaf();
        PickyCert.VerifyExact(leaf, [ca], DateTimeOffset.UtcNow);

        var expired = Assert.Throws<PickyException>(() => PickyCert.VerifyExact(leaf, [ca], DateTimeOffset.UtcNow.AddYears(5)));
        Assert.StartsWith("invalid certificate 'CN=leaf.trust.test': certificate expired (not after: ", expired.Message);

        var notYet = Assert.Throws<PickyException>(() => PickyCert.VerifyExact(leaf, [ca], DateTimeOffset.UtcNow.AddYears(-5)));
        Assert.StartsWith("invalid certificate 'CN=leaf.trust.test': certificate is not yet valid (not before: ", notYet.Message);
    }

    [Fact]
    public void PickyRejectsNonCaIssuerAndMissingRoot()
    {
        var (ca, leaf) = SyntheticCaAndLeaf(caIsCa: false);
        var e = Assert.Throws<PickyException>(() => PickyCert.VerifyExact(leaf, [ca], DateTimeOffset.UtcNow));
        Assert.Equal("CA chain error: issuer certificate 'CN=Trust Test CA' is not a CA", e.Message);

        var (_, leaf2) = SyntheticCaAndLeaf();
        var noRoot = Assert.Throws<PickyException>(() => PickyCert.VerifyExact(leaf2, [], DateTimeOffset.UtcNow));
        Assert.Equal("CA chain error: chain is missing a root certificate", noRoot.Message);
    }

    [Fact]
    public void PickyRejectsWrongIssuerKey()
    {
        var (_, leaf) = SyntheticCaAndLeaf();
        var (otherCa, _) = SyntheticCaAndLeaf();
        var e = Assert.Throws<PickyException>(() => PickyCert.VerifyExact(leaf, [otherCa], DateTimeOffset.UtcNow));
        Assert.Contains("authority key id doesn't match", e.Message);
    }

    [Fact]
    public void VerifyCertificateChainToAnchorsReturnsRoot()
    {
        var (ca, leaf) = SyntheticCaAndLeaf();
        var anchors = AnchorStore.Empty();
        anchors.MergeCertThumbprints([ca]);
        var root = TrustChain.VerifyCertificateChainToAnchors(leaf, [], anchors, [ca], new OnlineTrustOptions(), DateTimeOffset.UtcNow, false);
        Assert.Equal(ca, root);

        var empty = AnchorStore.Empty();
        empty.MergeThumbprintsOnly([new byte[20]]);
        var e = Assert.Throws<PsignException>(() =>
            TrustChain.VerifyCertificateChainToAnchors(leaf, [ca], empty, [], new OnlineTrustOptions(), DateTimeOffset.UtcNow, false));
        Assert.StartsWith("terminal root certificate is not in the anchor store (SHA-1 thumbprint ", e.Message);
    }

    [Fact]
    public void ParseCertBytesAcceptsPemAndDer()
    {
        var pem = Fixtures.Bytes("artifact-signing/devolutions-signer.pem");
        var fromPem = Anchors.ParseCertBytes(pem);
        var fromDer = Anchors.ParseCertBytes(fromPem.RawData);
        Assert.Equal(fromPem, fromDer);

        var padded = Encoding.ASCII.GetBytes("\n  ").Concat(pem).ToArray();
        Assert.Equal(fromPem, Anchors.ParseCertBytes(padded));

        var e = Assert.Throws<PsignException>(() => Anchors.ParseCertBytes("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"u8));
        Assert.Equal("PEM parse failed: invalid PEM label: PRIVATE KEY", e.Message);
        Assert.StartsWith("DER parse failed: ", Assert.Throws<PsignException>(() => Anchors.ParseCertBytes([1, 2, 3])).Message);
    }

    [Fact]
    public void LoadDirFiltersExtensionsAndRequiresCertificates()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("root.crt"), Fixtures.Bytes("devolutions-authenticode/authenticode-test-ca.crt"));
        File.WriteAllBytes(dir.File("ignored.txt"), [1, 2, 3]);
        File.Copy(Fixtures.Path("artifact-signing/devolutions-signer.pem"), dir.File("signer.PEM"));
        var (store, certs) = AnchorStore.LoadDir(dir.DirPath);
        Assert.Equal(2, certs.Count);
        Assert.Equal(2, store.ThumbprintCount);

        using var empty = new TempDir();
        var e = Assert.Throws<PsignException>(() => AnchorStore.LoadDir(empty.DirPath));
        Assert.Equal($"no certificates loaded from anchor dir {empty.DirPath} (expected .crt/.cer/.pem)", e.Message);
        Assert.Equal("no trusted CA files were supplied", Assert.Throws<PsignException>(() => AnchorStore.LoadFiles([])).Message);
    }

    [Fact]
    public void NameDisplayMatchesPickyFormatter()
    {
        var ts = Anchors.ParseCertBytes(Fixtures.Bytes("artifact-signing/microsoft-public-rsa-timestamping-ca-2020.pem"));
        Assert.Equal("C=US,O=Microsoft Corporation,CN=Microsoft Public RSA Timestamping CA 2020", PickyFormat.NameDisplay(ts.Subject));
    }
}
