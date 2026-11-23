using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class CertificateLoaderTests
{
    private static X509Certificate2 MakeCert(string subject)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static string Pem(byte[] der, string label = "CERTIFICATE") =>
        new string(PemEncoding.Write(label, der)) + "\n";

    [Fact]
    public void ParsesDerAndPem()
    {
        using var cert = MakeCert("CN=loader");
        Assert.Equal(cert.RawData, CertificateLoader.ParseCertificate(cert.RawData).RawData);
        var pem = Pem(cert.RawData);
        Assert.Equal(cert.RawData, CertificateLoader.ParseCertificate(Encoding.UTF8.GetBytes(pem)).RawData);
        Assert.Equal(cert.RawData, CertificateLoader.ParseCertificate(Encoding.UTF8.GetBytes("﻿ \r\n" + pem.Replace("\n", "\r\n", StringComparison.Ordinal))).RawData);
    }

    [Fact]
    public void SinglePemRejectsBundlesAndWrongLabels()
    {
        using var a = MakeCert("CN=a");
        using var b = MakeCert("CN=b");
        var bundle = Pem(a.RawData) + Pem(b.RawData);
        var err = Assert.Throws<PsignException>(() => CertificateLoader.ParseCertificate(Encoding.UTF8.GetBytes(bundle)));
        Assert.Equal("parse PEM certificate", err.Message);

        err = Assert.Throws<PsignException>(() => CertificateLoader.ParseCertificate(Encoding.UTF8.GetBytes(Pem(a.RawData, "PUBLIC KEY"))));
        Assert.Equal("parse PEM certificate", err.Message);

        var list = CertificateLoader.ParseCertificates(Encoding.UTF8.GetBytes(" \n" + bundle));
        Assert.Equal(2, list.Count);
        Assert.Equal(a.RawData, list[0].RawData);
        Assert.Equal(b.RawData, list[1].RawData);

        var withJunk = "junk\n" + Pem(a.RawData, "PUBLIC KEY") + bundle;
        var blocks = CertificateLoader.DecodePemBlocks(withJunk);
        Assert.Equal(["PUBLIC KEY", "CERTIFICATE", "CERTIFICATE"], blocks.Select(x => x.Label).ToArray());
        Assert.Equal(2, CertificateLoader.ParsePemBundle(withJunk).Count);
    }

    [Fact]
    public void DerErrorsAndPemUtf8Errors()
    {
        var err = Assert.Throws<PsignException>(() => CertificateLoader.ParseCertificate([0x30, 0x03, 0x02, 0x01, 0x00]));
        Assert.Equal("parse DER certificate", err.Message);
        Assert.Null(CertificateLoader.PemText([0x30, 0x00]));
        var bad = Encoding.ASCII.GetBytes("-----BEGIN CERTIFICATE-----\n").Concat(new byte[] { 0xFF }).ToArray();
        Assert.Equal("PEM input is not valid UTF-8", Assert.Throws<PsignException>(() => CertificateLoader.PemText(bad)).Message);
    }

    [Fact]
    public void LoadsRepoTestCa()
    {
        var info = CertificateLoader.ParseCertificate(Fixtures.Bytes("devolutions-authenticode/authenticode-test-ca.crt"));
        Assert.True(info.IsSelfIssued);
    }

    [Theory]
    [InlineData("QUJD", "ABC")]
    [InlineData("QUI=", "AB")]
    [InlineData("QQ==", "A")]
    [InlineData("", "")]
    public void Base64DecodesCanonical(string b64, string expected)
    {
        Assert.Equal(Encoding.ASCII.GetBytes(expected), Base64Standard.Decode(b64));
    }

    [Theory]
    [InlineData("QUJD\n", "Invalid symbol 10, offset 4.")]
    [InlineData("QUI", "Invalid padding")]
    [InlineData("QR==", "Invalid last symbol 82, offset 1.")]
    [InlineData("Q===", "Invalid symbol 61, offset 1.")]
    [InlineData("QUJDQ", "Invalid input length: 5")]
    [InlineData("A$AA", "Invalid symbol 36, offset 1.")]
    [InlineData("QQ==QUJD", "Invalid symbol 61, offset 2.")]
    public void Base64ErrorsMatchRust(string b64, string message)
    {
        Assert.Equal(message, Assert.Throws<FormatException>(() => Base64Standard.Decode(b64)).Message);
    }

    [Fact]
    public void RustLinesSemantics()
    {
        Assert.Equal(["foo", "bar", "", "baz\r"], RustText.Lines("foo\r\nbar\n\r\nbaz\r").ToArray());
        Assert.Equal(["a"], RustText.Lines("a\n").ToArray());
        Assert.Empty(RustText.Lines(string.Empty));
        Assert.Equal("[\"a\\\"\\\\\\n\\u0001é\"]", RustJson.StringArray(["a\"\\\n\u0001é"]));
    }
}
