using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Signing.Pki;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>Port of the <c>test_pki.rs</c> unit tests plus structural checks of the generated certificates.</summary>
public class TestPkiTests
{
    [Fact]
    public void WindowsDnRoundtripsOrderAndStateAlias()
    {
        const string input = "CN=Devolutions Test, O=\"Devolutions, Inc.\", L=Lavaltrie, S=Quebec, C=CA";
        var rdns = DistinguishedName.ParseRdns(input);
        Assert.Equal(5, rdns.Count);
        Assert.Equal("2.5.4.6", rdns[0][0].Oid);
        Assert.Equal("2.5.4.3", rdns[4][0].Oid);
        Assert.Equal(input, DistinguishedName.FormatWindows(DistinguishedName.Parse(input)));
    }

    [Fact]
    public void DnDistinguishesSnSurnameFromSerialNumber()
    {
        const string input = "SN=Doe, SERIALNUMBER=ABC-12345, CN=Jane Doe, C=CA";
        var rdns = DistinguishedName.ParseRdns(input);
        Assert.Equal("2.5.4.5", rdns[2][0].Oid);
        Assert.Equal("2.5.4.4", rdns[3][0].Oid);
        Assert.Equal(input, DistinguishedName.FormatWindows(DistinguishedName.Parse(input)));
    }

    [Fact]
    public void DnHandlesBackslashesEscapedSpacesAndBmpStringRoundtrips()
    {
        const string quotedBs = "CN=\"ACME\\Engineering, Corp.\", O=\"Div\\Unit\", C=US";
        Assert.Equal(quotedBs, DistinguishedName.FormatWindows(DistinguishedName.Parse(quotedBs)));

        var rfcBs = DistinguishedName.Parse("CN=a\\\\b, C=US");
        Assert.Equal("CN=\"a\\b\", C=US", DistinguishedName.FormatWindows(rfcBs));
        Assert.Equal(rfcBs, DistinguishedName.Parse(DistinguishedName.FormatWindows(rfcBs)));

        Assert.Throws<PsignException>(() => DistinguishedName.Parse("CN=a\\b"));
        Assert.Throws<PsignException>(() => DistinguishedName.Parse("CN=a\\z"));

        var spaced = DistinguishedName.Parse("  CN=\\ foo\\   ,  O=Trailing\\   ");
        Assert.Equal("CN=\" foo \", O=\"Trailing \"", DistinguishedName.FormatWindows(spaced));
        Assert.Equal(spaced, DistinguishedName.Parse(DistinguishedName.FormatWindows(spaced)));

        byte[] bmp = [0x00, (byte)'a', 0x00, (byte)'\\', 0x00, (byte)'b'];
        var name = DistinguishedName.Encode([[new X500Attribute("2.5.4.3", Der.EncodeTlv(0x1E, bmp))]]);
        Assert.Equal("CN=\"a\\b\"", DistinguishedName.FormatWindows(name));
    }

    [Fact]
    public void DnValidatesCountryCodePrintableStringAndIa5String()
    {
        Assert.Throws<PsignException>(() => DistinguishedName.Parse("C=USA, CN=Test"));
        Assert.Throws<PsignException>(() => DistinguishedName.Parse("C=U, CN=Test"));
        Assert.Throws<PsignException>(() => DistinguishedName.Parse("C=U$, CN=Test"));
        Assert.Throws<PsignException>(() => DistinguishedName.Parse("SERIALNUMBER=bad$char, CN=Test"));
        Assert.Throws<PsignException>(() => DistinguishedName.Parse("E=user@exämple.com, CN=Test"));
        Assert.Throws<PsignException>(() => DistinguishedName.Parse("DC=exämple, CN=Test"));

        var valid = DistinguishedName.Parse("CN=Test, E=ops@devolutions.net, DC=devolutions, C=CA");
        Assert.Equal("CN=Test, E=ops@devolutions.net, DC=devolutions, C=CA", DistinguishedName.FormatWindows(valid));
    }

    [Fact]
    public void DnErrorMessagesMatchRust()
    {
        Assert.Equal("distinguished name must not be empty", Assert.Throws<PsignException>(() => DistinguishedName.Parse("  ")).Message);
        Assert.Equal("distinguished name 'CN=a,,O=b' contains an empty RDN component", Assert.Throws<PsignException>(() => DistinguishedName.Parse("CN=a,,O=b")).Message);
        Assert.Equal(
            "distinguished name component 'Example' must be in KEY=VALUE form (for example, CN=Example)",
            Assert.Throws<PsignException>(() => DistinguishedName.Parse("Example")).Message);
        Assert.Equal("unsupported X.500 attribute 'FOO'", Assert.Throws<PsignException>(() => DistinguishedName.Parse("FOO=bar")).Message);
        Assert.Equal("unterminated double quote in distinguished name 'CN=\"abc'", Assert.Throws<PsignException>(() => DistinguishedName.Parse("CN=\"abc")).Message);
        Assert.Equal("RDN 'C' must be a 2-character ISO 3166 country code, got 'USA'", Assert.Throws<PsignException>(() => DistinguishedName.Parse("C=USA")).Message);
        Assert.Equal(
            "RDN 'C' must be PrintableString: malformed ASN.1 DER value for PrintableString",
            Assert.Throws<PsignException>(() => DistinguishedName.Parse("C=U$")).Message);
    }

    [Fact]
    public void DnSupportsOidsHexValuesAndMultiValuedRdns()
    {
        var name = DistinguishedName.Parse("OID.1.2.3.4=custom, 2.5.4.3=#0C0468657821, CN=b+O=a");
        var rdns = DistinguishedName.ParseRdns("OID.1.2.3.4=custom, 2.5.4.3=#0C0468657821, CN=b+O=a");
        Assert.Equal(2, rdns[0].Count);
        Assert.Equal("OID.1.2.3.4=custom, CN=hex!, CN=b + O=a", DistinguishedName.FormatWindows(name));
        Assert.Equal("1.2.3.4=#0c06637573746f6d,CN=hex!,CN=b+O=a", DistinguishedName.FormatRfc4514(name));
    }

    [Fact]
    public void Rfc4514FormattingMatchesX509CertDisplay()
    {
        var name = DistinguishedName.Parse("CN=\" lead#,+;<>\\\", O=Org, ST=Quebec, E=a@b.c, C=CA");
        Assert.Equal("CN=\\ lead#\\,\\+\\;\\<\\>\\\\,O=Org,ST=Quebec,EMAIL=a@b.c,C=CA", DistinguishedName.FormatRfc4514(name));
        Assert.Equal("CN=\\#x", DistinguishedName.FormatRfc4514(DistinguishedName.Parse("CN=\\#x")));
    }

    [Fact]
    public void KeyUsageBitStringsAreMinimal()
    {
        Assert.Equal(new byte[] { 0x03, 0x02, 0x07, 0x80 }, TestPki.KeyUsage(0));
        Assert.Equal(new byte[] { 0x03, 0x02, 0x01, 0x06 }, TestPki.KeyUsage(5, 6));
        Assert.Equal(new byte[] { 0x03, 0x02, 0x05, 0xA0 }, TestPki.KeyUsage(0, 2));
    }

    [Fact]
    public void SerialNumbersArePositiveSixteenOctets()
    {
        for (var i = 0; i < 32; i++)
        {
            var serial = TestPki.RandomSerialNumber();
            Assert.Equal(16, serial.Length);
            Assert.Equal(0x40, serial[0] & 0xC0);
        }
    }

    [Fact]
    public void GeneratedRootCodesignAndTlsPfxPreserveChainsAndVerify()
    {
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Devolutions Static Feed Test Root CA, O=Devolutions Inc., C=CA", 3650, 2048));
        var rootPfx = TestPki.EncodePfxDer(root, "RootPass123!");

        var caIssuer = TestPki.LoadCaIssuerFromPfx(rootPfx, "RootPass123!");
        var codesign = TestPki.IssueCodeSigningCert(caIssuer, new CodeSigningCertSpec("CN=Devolutions Inc., O=Devolutions Inc., L=Lavaltrie, S=Quebec, C=CA", 365, 2048));
        Assert.Single(codesign.ChainCertificatesDer);
        Assert.Equal(root.CertificateDer, codesign.ChainCertificatesDer[0]);

        var codesignPfx = TestPki.EncodePfxDer(codesign, "SignPass123!");
        var extracted = Pkcs12Identity.Parse(codesignPfx, "SignPass123!");
        Assert.Equal(codesign.CertificateDer, extracted.SignerCertificateDer);
        Assert.Equal(new[] { root.CertificateDer }, extracted.ChainCertificatesDer);
        Assert.Equal(codesign.PrivateKeyPem, extracted.PrivateKeyPem);

        var tls = TestPki.IssueTlsServerCert(caIssuer, new TlsServerCertSpec(
            null,
            ["winget.devolutions.test", "localhost"],
            [IPAddress.Parse("127.0.0.1")],
            365,
            2048));
        Assert.Equal("CN=winget.devolutions.test", tls.Summary.Subject);
        var tlsPfx = TestPki.EncodePfxDer(tls, "TlsPass123!");
        var extractedTls = Pkcs12Identity.Parse(tlsPfx, "TlsPass123!");
        Assert.Equal(tls.CertificateDer, extractedTls.SignerCertificateDer);
        Assert.Equal(new[] { root.CertificateDer }, extractedTls.ChainCertificatesDer);

        foreach (var leaf in new[] { codesign, tls })
        {
            Assert.True(leaf.Certificate.VerifySignatureBy(root.Certificate));
            Assert.True(root.Certificate.IsIssuerOf(leaf.Certificate));
            Assert.Equal(root.Certificate.SubjectKeyIdentifier, leaf.Certificate.AuthorityKeyIdentifier);
            AssertWindowsChainBuilds(leaf.CertificateDer, root.CertificateDer, leaf == codesign ? "1.3.6.1.5.5.7.3.3" : "1.3.6.1.5.5.7.3.1");
        }

        // The BCL PKCS#12 loader (Windows PFXImportCertStore / managed loader) accepts the archive and pairs the key.
        using var loaded = X509CertificateLoaderCompat.LoadPkcs12(codesignPfx, "SignPass123!");
        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(codesign.CertificateDer, loaded.RawData);
        var collection = X509CertificateLoaderCompat.LoadPkcs12Collection(codesignPfx, "SignPass123!");
        Assert.Equal(2, collection.Count);
    }

    [Fact]
    public void GeneratedCertificateContentsMatchRustProfile()
    {
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Root", 10, 2048));
        Assert.Equal(3, root.Certificate.Version);
        Assert.Equal("1.2.840.113549.1.1.11", root.Certificate.SignatureAlgorithm.Oid);
        Assert.True(root.Certificate.SignatureAlgorithm.HasNullParameters);
        Assert.Equal(16, root.Certificate.SerialNumber.Length);
        Assert.Equal(
            new[] { ("2.5.29.14", false), ("2.5.29.19", true), ("2.5.29.15", true) },
            root.Certificate.Extensions.Select(e => (e.Oid, e.Critical)).ToArray());
        Assert.Equal(new byte[] { 0x30, 0x03, 0x01, 0x01, 0xFF }, root.Certificate.GetExtension("2.5.29.19")!.Value);
        Assert.Equal(SHA1.HashData(root.Certificate.PublicKey), root.Certificate.SubjectKeyIdentifier);
        Assert.True(root.Summary.IsCa);
        Assert.Equal(TimeSpan.FromDays(11), root.Certificate.NotAfter - root.Certificate.NotBefore);

        var leaf = TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=Leaf", 3650, 2048, [" 1.3.6.1.4.1.311.10.3.13 ", "1.3.6.1.5.5.7.3.3"]));
        Assert.Equal(
            new[] { ("2.5.29.14", false), ("2.5.29.35", false), ("2.5.29.19", true), ("2.5.29.15", true), ("2.5.29.37", true) },
            leaf.Certificate.Extensions.Select(e => (e.Oid, e.Critical)).ToArray());
        Assert.Equal(new[] { "1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.10.3.13" }, leaf.Summary.EkuOids);
        Assert.Equal(new byte[] { 0x30, 0x00 }, leaf.Certificate.GetExtension("2.5.29.19")!.Value);

        // Validity is clamped to the CA's notAfter.
        Assert.Equal(root.Certificate.NotAfter, leaf.Certificate.NotAfter);

        var anyEku = TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=Any", 1, 2048, ["2.5.29.37.0"]));
        Assert.False(anyEku.Certificate.GetExtension("2.5.29.37")!.Critical);
    }

    [Fact]
    public void SpecValidationErrors()
    {
        Assert.Equal(
            "unsupported RSA key size 1024; supported values are 2048, 3072, or 4096",
            Assert.Throws<PsignException>(() => TestPki.GenerateRootCa(new RootCaSpec("CN=x", 1, 1024))).Message);
        Assert.Equal("validity_days must be at least 1", Assert.Throws<PsignException>(() => TestPki.GenerateRootCa(new RootCaSpec("CN=x", 0))).Message);

        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Root"));
        Assert.Equal(
            "TLS server certificate requires at least one --dns or --ip Subject Alternative Name",
            Assert.Throws<PsignException>(() => TestPki.IssueTlsServerCert(root.AsIssuer(), new TlsServerCertSpec(null, [], []))).Message);

        var leaf = TestPki.IssueCodeSigningCert(root.AsIssuer(), new CodeSigningCertSpec("CN=Leaf"));
        var e = Assert.Throws<PsignException>(() => TestPki.LoadCaIssuerFromCertAndKey(leaf.CertificateDer, Encoding.ASCII.GetBytes(leaf.PrivateKeyPem)));
        Assert.Equal("issuer certificate 'CN=Leaf' is not a CA certificate (BasicConstraints CA=true required)", e.Message);

        var mismatch = Assert.Throws<PsignException>(() => TestPki.LoadCaIssuerFromCertAndKey(root.CertificateDer, Encoding.ASCII.GetBytes(leaf.PrivateKeyPem)));
        Assert.Equal("verify CA private key matches CA certificate: private key does not match certificate public key", mismatch.FullMessage);
    }

    [Fact]
    public void CaIssuerFromPemCertAndPkcs1Key()
    {
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=PEM Root"));
        using var rsa = root.PrivateKey.CreateRsa();
        var pkcs1Pem = Encoding.ASCII.GetBytes(new string(PemEncoding.Write("RSA PRIVATE KEY", rsa.ExportRSAPrivateKey())));
        var certPem = Encoding.ASCII.GetBytes(TestPki.EncodePemCertificateBundle([root.CertificateDer]));
        var issuer = TestPki.LoadCaIssuerFromCertAndKey(certPem, pkcs1Pem);
        Assert.Equal(root.CertificateDer, issuer.CertificateDer);
        Assert.Equal(root.PrivateKey.Pkcs8Der, issuer.PrivateKey.Pkcs8Der);

        var tls = TestPki.IssueTlsServerCert(issuer, new TlsServerCertSpec(" ", [], [IPAddress.Parse("::1")]));
        Assert.Equal("CN=::1", tls.Summary.Subject);
        Assert.Equal(new[] { "::1" }, tls.Summary.IpAddresses);
        var san = tls.Certificate.GetExtension("2.5.29.17")!.Value;
        Assert.Equal(Der.EncodeSequence(Der.EncodeTlv(0x87, IPAddress.IPv6Loopback.GetAddressBytes())), san);
    }

    [Fact]
    public void PemBundleAndSummaryJson()
    {
        var root = TestPki.GenerateRootCa(new RootCaSpec("CN=Json Root"));
        var pem = TestPki.EncodePemCertificateBundle([root.CertificateDer, root.CertificateDer]);
        Assert.Equal(2, pem.Split("-----BEGIN CERTIFICATE-----\n").Length - 1);
        Assert.All(pem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal)), l => Assert.True(l.Length <= 64));
        Assert.EndsWith("-----END CERTIFICATE-----\n", pem, StringComparison.Ordinal);

        var json = root.Summary.ToJson();
        Assert.StartsWith("{\n  \"subject\": \"CN=Json Root\",\n  \"issuer\": \"CN=Json Root\",\n", json, StringComparison.Ordinal);
        Assert.DoesNotContain("eku_oids", json, StringComparison.Ordinal);
        Assert.EndsWith("  \"is_ca\": true,\n  \"chain_certificate_count\": 0\n}", json, StringComparison.Ordinal);
    }

    internal static void AssertWindowsChainBuilds(byte[] leafDer, byte[] rootDer, string ekuOid)
    {
        using var leaf = X509CertificateLoaderCompat.LoadCertificate(leafDer);
        using var root = X509CertificateLoaderCompat.LoadCertificate(rootDer);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ekuOid));
        var ok = chain.Build(leaf);
        Assert.True(ok, string.Join("; ", chain.ChainStatus.Select(s => s.Status + ": " + s.StatusInformation)));
    }
}
