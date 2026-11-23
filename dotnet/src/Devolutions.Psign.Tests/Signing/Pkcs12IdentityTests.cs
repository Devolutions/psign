using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Signing.Pki;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>PKCS#12 identity extraction, key loading and signer identity tests.</summary>
public class Pkcs12IdentityTests
{
    private const string FixturePfx = "devolutions-authenticode/authenticode-test-cert.pfx";
    private const string FixturePassword = "CodeSign123!";

    [Fact]
    public void ParsesVendoredAuthenticodeTestPfx()
    {
        var parsed = Pkcs12Identity.Parse(Fixtures.Bytes(FixturePfx), FixturePassword);
        Assert.Equal("A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38", Hex.Upper(SHA1.HashData(parsed.SignerCertificateDer)));
        Assert.Equal(PrivateKeyAlgorithm.Rsa, parsed.PrivateKey.Algorithm);
        Assert.True(parsed.PrivateKey.MatchesCertificate(parsed.SignerCertificate));
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----\n", parsed.PrivateKeyPem, StringComparison.Ordinal);
        Assert.EndsWith("\n-----END PRIVATE KEY-----\n", parsed.PrivateKeyPem, StringComparison.Ordinal);

        // Cross-check against the BCL loader.
        using var bcl = X509CertificateLoaderCompat.LoadPkcs12(Fixtures.Bytes(FixturePfx), FixturePassword);
        Assert.Equal(bcl.RawData, parsed.SignerCertificateDer);
    }

    [Fact]
    public void WrongPasswordIsRejected()
    {
        var e = Assert.Throws<PsignException>(() => Pkcs12Identity.Parse(Fixtures.Bytes(FixturePfx), "nope"));
        Assert.Contains("MAC", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ParsesBclExportedPfxAndPrefersLocalKeyIdPairing()
    {
        // A PFX exported by the platform (Windows: PFXExportCertStoreEx, 3DES/SHA1 or AES depending on version) with an
        // unrelated certificate first: the signer must still be the certificate matching the key.
        using var other = new TestSignerCert("CN=other");
        using var signer = new TestSignerCert("CN=signer");
        var collection = new X509Certificate2Collection { other.PublicOnly, signer.WithKey };
        var pfx = collection.Export(X509ContentType.Pkcs12, "pw")!;
        var parsed = Pkcs12Identity.Parse(pfx, "pw");
        Assert.Equal(signer.WithKey.RawData, parsed.SignerCertificateDer);
        Assert.Equal(new[] { other.PublicOnly.RawData }, parsed.ChainCertificatesDer);
    }

#if NET9_0_OR_GREATER
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ParsesPbes2AndLegacyEncryptedPfx(bool aes)
    {
        using var signer = new TestSignerCert("CN=pbe");
        var pfx = signer.WithKey.ExportPkcs12(aes ? Pkcs12ExportPbeParameters.Pbes2Aes256Sha256 : Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, "secret é");
        var parsed = Pkcs12Identity.Parse(pfx, "secret é");
        Assert.Equal(signer.WithKey.RawData, parsed.SignerCertificateDer);
    }
#endif

    [Fact]
    public void EmptyPasswordRoundTrip()
    {
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Empty Password Root"));
        var pfx = TestPki.EncodePfxDer(root, string.Empty);
        var parsed = Pkcs12Identity.Parse(pfx, string.Empty);
        Assert.Equal(root.CertificateDer, parsed.SignerCertificateDer);
        using var bcl = X509CertificateLoaderCompat.LoadPkcs12(pfx, string.Empty);
        Assert.True(bcl.HasPrivateKey);
    }

    [Fact]
    public void Pkcs12KdfMatchesRfc7292Vectors()
    {
        // Known-answer test: OpenSSL / BouncyCastle PKCS12 KDF vector (SHA-1, password "smeg", 8-byte salt).
        var password = Pkcs12Crypto.BmpPassword("smeg");
        var salt = Hex.Decode("0A58CF64530D823F");
        Assert.Equal("8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3", Hex.Upper(Pkcs12Crypto.Derive(HashAlgorithmName.SHA1, password, salt, 1, 1, 24)));
        Assert.Equal("79993DFE048D3B76", Hex.Upper(Pkcs12Crypto.Derive(HashAlgorithmName.SHA1, password, salt, 1, 2, 8)));
    }

    [Fact]
    public void RsaKeyLoaderAcceptsAllEncodings()
    {
        using var rsa = RSA.Create(2048);
        var expected = PrivateKeyMaterial.FromRsa(rsa).Pkcs8Der;
        var pkcs8Der = rsa.ExportPkcs8PrivateKey();
        var pkcs1Der = rsa.ExportRSAPrivateKey();
        var inputs = new[]
        {
            pkcs8Der,
            pkcs1Der,
            Encoding.ASCII.GetBytes(new string(PemEncoding.Write("PRIVATE KEY", pkcs8Der))),
            Encoding.UTF8.GetBytes("\uFEFF \n" + new string(PemEncoding.Write("RSA PRIVATE KEY", pkcs1Der))),
        };
        foreach (var input in inputs)
        {
            Assert.Equal(expected, PrivateKeyLoader.ParseRsaPrivateKeyMaterial(input).Pkcs8Der);
        }

        Assert.Equal("parse DER RSA private key", Assert.Throws<PsignException>(() => PrivateKeyLoader.ParseRsaPrivateKey([1, 2, 3])).Message);
        Assert.Equal(
            "parse PKCS#8 RSA private key PEM",
            Assert.Throws<PsignException>(() => PrivateKeyLoader.ParseRsaPrivateKey(Encoding.ASCII.GetBytes("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))).Message);

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecError = Assert.Throws<PsignException>(() => PrivateKeyLoader.ParseRsaPrivateKey(ec.ExportPkcs8PrivateKey()));
        Assert.Equal("parse DER RSA private key", ecError.Message);
        var ecPem = Encoding.ASCII.GetBytes(new string(PemEncoding.Write("PRIVATE KEY", ec.ExportPkcs8PrivateKey())));
        Assert.Contains("is not RSA", Assert.Throws<PsignException>(() => PrivateKeyLoader.ParseRsaPrivateKey(ecPem)).FullMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Pkcs8PemValidationRequiresPrivateKeyLabel()
    {
        const string pem = "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n";
        var e = Assert.Throws<PsignException>(() => PrivateKeyMaterial.FromPkcs8Pem(pem));
        Assert.Contains("PRIVATE KEY", e.Message, StringComparison.Ordinal);
        Assert.Equal("private key PEM label must be PRIVATE KEY, got RSA PRIVATE KEY", e.Message);
    }

    [Fact]
    public void CertificateLoaderHandlesDerPemAndBundles()
    {
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Loader Root"));
        var leaf = TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=Loader Leaf"));
        var bundle = Encoding.ASCII.GetBytes(TestPki.EncodePemCertificateBundle([leaf.CertificateDer, root.CertificateDer]));

        Assert.Equal(leaf.CertificateDer, CertificateLoader.ParseCertificate(leaf.CertificateDer).RawData);
        // Rust rdp::parse_certificate (pem-rfc7468) accepts exactly one PEM block; bundles go through ParseCertificates.
        Assert.Equal("parse PEM certificate", Assert.Throws<PsignException>(() => CertificateLoader.ParseCertificate(bundle)).Message);
        Assert.Equal(2, CertificateLoader.ParseCertificates(bundle).Count);
        Assert.Equal(leaf.CertificateDer, CertificateLoader.PemOrDerToDer(bundle));
        Assert.Equal("parse DER certificate", Assert.Throws<PsignException>(() => CertificateLoader.ParseCertificate([0x30, 0x00])).Message);
        Assert.Equal(
            "PEM certificate is missing END CERTIFICATE marker",
            Assert.Throws<PsignException>(() => CertificateLoader.PemOrDerToDer(Encoding.ASCII.GetBytes("-----BEGIN CERTIFICATE-----\nAAAA"))).Message);
    }

    [Fact]
    public void SignerIdentitySignsVerifiableAuthenticodeDigests()
    {
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Identity Root"));
        var leaf = TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=Identity Leaf"));
        using var fromPfx = SignerIdentity.FromPfx(TestPki.EncodePfxDer(leaf, "pw"), "pw");
        Assert.Equal(leaf.CertificateDer, fromPfx.Certificate.RawData);
        Assert.Equal(new[] { leaf.CertificateDer, root.CertificateDer }, fromPfx.CertificateChainDer());

        var digest = SHA256.HashData("hello"u8);
        var signature = fromPfx.Signer.SignDigest(digest, AuthenticodeHashKind.Sha256);
        using var pub = leaf.Certificate.X509.GetRSAPublicKey()!;
        Assert.True(pub.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        using var fromFiles = SignerIdentity.FromCertificateAndKey(
            Encoding.ASCII.GetBytes(TestPki.EncodePemCertificateBundle([leaf.CertificateDer, root.CertificateDer])),
            Encoding.ASCII.GetBytes(leaf.PrivateKeyPem));
        Assert.Single(fromFiles.Chain);
        Assert.Equal(signature, fromFiles.Signer.SignDigest(digest, AuthenticodeHashKind.Sha256));

        var mismatch = Assert.Throws<PsignException>(() => SignerIdentity.FromCertificateAndKey(root.CertificateDer, Encoding.ASCII.GetBytes(leaf.PrivateKeyPem)));
        Assert.Equal("private key does not match certificate public key", mismatch.Message);
    }

    [Fact]
    public void PfxWithoutKeyOrCertIsRejected()
    {
        using var signer = new TestSignerCert("CN=nokey");
        var certOnly = signer.PublicOnly.Export(X509ContentType.Pkcs12, "pw")!;
        Assert.Equal("PFX did not contain a private key", Assert.Throws<PsignException>(() => Pkcs12Identity.Parse(certOnly, "pw")).Message);
    }

    /// <summary>Self-signed RSA certificate with and without a private key.</summary>
    internal sealed class TestSignerCert : IDisposable
    {
        public TestSignerCert(string subject)
        {
            using var key = RSA.Create(2048);
            var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            WithKey = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
            PublicOnly = X509CertificateLoaderCompat.LoadCertificate(WithKey.RawData);
        }

        public X509Certificate2 WithKey { get; }

        public X509Certificate2 PublicOnly { get; }

        public void Dispose()
        {
            WithKey.Dispose();
            PublicOnly.Dispose();
        }
    }
}
