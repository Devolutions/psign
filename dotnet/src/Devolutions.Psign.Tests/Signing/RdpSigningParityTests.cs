using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Rdp;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Signing.Rdp;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>RDP signing: byte-for-byte parity with <c>psign-tool portable rdp</c>.</summary>
public class RdpSigningParityTests
{
    public static TheoryData<string> RdpFixtures() =>
    [
        "unsigned-utf8.rdp",
        "unsigned-utf8-bom.rdp",
        "unsigned-utf16le-bom.rdp",
        "unsigned-utf16le-nobom.rdp",
        "unsigned-utf16be-bom.rdp",
        "unsigned-utf16be-nobom.rdp",
        "partial-signed-scope.rdp",
        "with-stale-signature.rdp",
        "malformed-lines.rdp",
        "minimal.rdp",
        "signed-test-cert.rdp",
    ];

    private static (string Output, List<string> Lines) RunCSharp(RdpPortableSignOptions options)
    {
        var lines = new List<string>();
        RdpSigner.Run(options, lines.Add);
        return (options.OutputPath ?? options.Files[0], lines);
    }

    [SkippableTheory]
    [MemberData(nameof(RdpFixtures))]
    public void CertKeySigningMatchesRustByteForByte(string fixture)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var input = Fixtures.Path("rdp/" + fixture);
        var rustOut = dir.File("rust.rdp");
        var stdout = RustTool.RunOk("portable", "rdp", "--cert", signer.CertPath, "--key", signer.KeyPath, "--output", rustOut, input);

        var csOut = dir.File("cs.rdp");
        var (_, lines) = RunCSharp(new RdpPortableSignOptions { CertPath = signer.CertPath, KeyPath = signer.KeyPath, OutputPath = csOut, Files = [input] });
        Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(csOut));
        Assert.Equal($"Signed {rustOut}", stdout.Trim());
        Assert.Equal([$"Signed {csOut}"], lines);

        // The embedded PKCS#7 binds the secure-settings blob and verifies with the signer key.
        var records = RdpFile.ParseRecords(RdpFile.DecodeRdpText(File.ReadAllBytes(csOut)));
        var sd = CmsSignedData.Parse(RdpFile.SignatureRecordPkcs7(records));
        var si = sd.SignerInfos[0];
        var unsigned = records.ToList();
        RdpFile.RemoveRecord(unsigned, "Signature");
        var blob = RdpFile.SecureSettingsBlob(unsigned, RdpFile.FindRecord(unsigned, "SignScope")!.Value);
        Assert.Equal(SHA256.HashData(blob), si.MessageDigest());
        Assert.True(SignatureVerifier.Verify(signer.Info.SubjectPublicKeyInfo, si.SignatureAlgorithm, si.SignedAttributesSetDer(), si.Signature, AuthenticodeHashKind.Sha256));
    }

    [SkippableFact]
    public void PemInputsAndChainCertsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        using var other = new TestSigner(dir, "CN=psign chain extra");
        var certPem = dir.File("signer.pem");
        File.WriteAllText(certPem, new string(PemEncoding.Write("CERTIFICATE", signer.Certificate.RawData)) + "\n");
        var keyPem = dir.File("signer-pkcs1.pem");
        File.WriteAllText(keyPem, new string(PemEncoding.Write("RSA PRIVATE KEY", signer.Key.ExportRSAPrivateKey())) + "\n");
        var chainDer = dir.File("chain.der");
        File.WriteAllBytes(chainDer, other.Certificate.RawData);
        var input = Fixtures.Path("rdp/unsigned-utf8.rdp");

        var rustOut = dir.File("rust.rdp");
        RustTool.RunOk("portable", "rdp", "--cert", certPem, "--key", keyPem, "--chain-cert", chainDer, "--output", rustOut, input);
        var csOut = dir.File("cs.rdp");
        RunCSharp(new RdpPortableSignOptions { CertPath = certPem, KeyPath = keyPem, ChainCertPaths = [chainDer], OutputPath = csOut, Files = [input] });
        Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(csOut));

        var sd = CmsSignedData.Parse(RdpFile.SignatureRecordPkcs7(RdpFile.ParseRecords(RdpFile.DecodeRdpText(File.ReadAllBytes(csOut)))));
        Assert.Equal(2, sd.Certificates!.Count);
    }

    [SkippableFact]
    public void ExternalPkcs7MatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        var pkcs7 = dir.File("sig.p7b");
        File.WriteAllBytes(pkcs7, "pkcs7"u8.ToArray());
        foreach (var fixture in RdpFixtures())
        {
            var input = Fixtures.Path("rdp/" + fixture);
            var rustOut = dir.File(fixture + ".rust.rdp");
            RustTool.RunOk("portable", "rdp", "--signature-pkcs7", pkcs7, "--output", rustOut, input);
            var csOut = dir.File(fixture + ".cs.rdp");
            RunCSharp(new RdpPortableSignOptions { SignaturePkcs7Path = pkcs7, OutputPath = csOut, Files = [input] });
            Assert.Equal(File.ReadAllBytes(rustOut), File.ReadAllBytes(csOut));
            var text = RdpFile.DecodeRdpText(File.ReadAllBytes(csOut));
            Assert.Contains("Signature:s:AQABAAEAAAAFAAAAcGtjczc=", text, StringComparison.Ordinal);
        }
    }

    [SkippableFact]
    public void DryRunAndErrorsMatchRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var copy = dir.File("in-place.rdp");
        File.Copy(Fixtures.Path("rdp/minimal.rdp"), copy);
        var before = File.ReadAllBytes(copy);
        var stdout = RustTool.RunOk("portable", "rdp", "--cert", signer.CertPath, "--key", signer.KeyPath, "--dry-run", copy);
        var (_, lines) = RunCSharp(new RdpPortableSignOptions { CertPath = signer.CertPath, KeyPath = signer.KeyPath, DryRun = true, Files = [copy] });
        Assert.Equal(stdout.Trim(), lines.Single());
        Assert.Equal(before, File.ReadAllBytes(copy));

        var missing = Fixtures.Path("rdp/missing-full-address.rdp");
        var pkcs7 = dir.File("sig.p7b");
        File.WriteAllBytes(pkcs7, "pkcs7"u8.ToArray());
        AssertSameError(["--signature-pkcs7", pkcs7, "--output", dir.File("x.rdp"), missing], new RdpPortableSignOptions { SignaturePkcs7Path = pkcs7, OutputPath = dir.File("y.rdp"), Files = [missing] }, sameText: false);
        // clap enforces --cert/--key pairing in Rust; the library reports the run_rdp_portable error.
        Assert.Equal("rdp requires either --cert and --key, or --signature-pkcs7", Assert.Throws<PsignException>(() => RunCSharp(new RdpPortableSignOptions { CertPath = signer.CertPath, Files = [missing] })).Message);
        Assert.Equal("rdp requires at least one input file", Assert.Throws<PsignException>(() => RunCSharp(new RdpPortableSignOptions { SignaturePkcs7Path = pkcs7 })).Message);
        AssertSameError(["--signature-pkcs7", pkcs7, "--dry-run", "--output", dir.File("z.rdp"), missing], new RdpPortableSignOptions { SignaturePkcs7Path = pkcs7, DryRun = true, OutputPath = dir.File("z.rdp"), Files = [missing] });
        AssertSameError(["--signature-pkcs7", pkcs7, missing, copy], new RdpPortableSignOptions { SignaturePkcs7Path = pkcs7, Files = [missing, copy] });
        var badKey = dir.File("bad.key");
        File.WriteAllBytes(badKey, [1, 2, 3]);
        AssertSameError(["--cert", signer.CertPath, "--key", badKey, copy], new RdpPortableSignOptions { CertPath = signer.CertPath, KeyPath = badKey, Files = [copy] }, sameText: false);
    }

    private static void AssertSameError(string[] rustArgs, RdpPortableSignOptions options, bool sameText = true)
    {
        var (code, _, stderr) = RustTool.Run(["portable", "rdp", .. rustArgs]);
        Assert.NotEqual(0, code);
        var err = Assert.Throws<PsignException>(() => RunCSharp(options));
        if (sameText)
        {
            Assert.Equal(stderr.Trim(), err.FullMessage);
        }
        else
        {
            // Paths in the message differ (distinct output files); compare the outermost context and the leaf message prefix.
            Assert.StartsWith(err.Message.Split(' ')[0], stderr.Trim(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void SecureBlobSignatureIsDeterministicAndRejectsDuplicateChainCerts()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var blob = Encoding.Unicode.GetBytes("full address:s:x\r\n\0");
        var a = RdpSigner.SignSecureBlobRsaSha256(blob, signer.Info, [], signer.Key);
        var b = RdpSigner.SignSecureBlobRsaSha256(blob, signer.Info, [], signer.Key);
        Assert.Equal(a, b);
        var sd = CmsSignedData.Parse(a);
        Assert.Equal(Oids.Pkcs7Data, sd.EncapContentType);
        Assert.Null(sd.EncapContent);
        Assert.Equal(Oids.Sha256WithRsa, sd.SignerInfos[0].SignatureAlgorithm.Oid);
        Assert.Throws<PsignException>(() => RdpSigner.SignSecureBlobRsaSha256(blob, signer.Info, [signer.Info], signer.Key));
    }

    [Fact]
    public void KeyLoaderAcceptsAllEncodings()
    {
        using var rsa = RSA.Create(2048);
        var expected = rsa.ExportParameters(false).Modulus;
        var inputs = new[]
        {
            rsa.ExportPkcs8PrivateKey(),
            rsa.ExportRSAPrivateKey(),
            Encoding.UTF8.GetBytes(new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()))),
            Encoding.UTF8.GetBytes("﻿" + new string(PemEncoding.Write("RSA PRIVATE KEY", rsa.ExportRSAPrivateKey())) + "\r\n"),
        };
        foreach (var input in inputs)
        {
            using var key = RsaPrivateKeyLoader.ParseRsaPrivateKey(input);
            Assert.Equal(expected, key.ExportParameters(false).Modulus);
        }

        Assert.Equal("parse DER RSA private key", Assert.Throws<PsignException>(() => RsaPrivateKeyLoader.ParseRsaPrivateKey([1, 2, 3])).Message);
        var wrongLabel = Encoding.UTF8.GetBytes(new string(PemEncoding.Write("PUBLIC KEY", rsa.ExportSubjectPublicKeyInfo())));
        Assert.Equal("parse PKCS#8 RSA private key PEM", Assert.Throws<PsignException>(() => RsaPrivateKeyLoader.ParseRsaPrivateKey(wrongLabel)).Message);
    }

    [Fact]
    public void NativeCommandHelpers()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var sha1 = SHA1.HashData(signer.Certificate.RawData);
        var text = string.Join(":", sha1.Select(b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture))) + "‎";
        var parsed = RdpSigner.ParseThumbprint(text, 20, "SHA1");
        Assert.Equal(sha1, parsed);
        Assert.True(RdpSigner.ThumbprintMatches(signer.Info, parsed));
        Assert.Equal("SHA256 thumbprint must be 64 hex characters", Assert.Throws<PsignException>(() => RdpSigner.ParseThumbprint("abcd", 32, "SHA256")).Message);
        Assert.Equal("SHA1 thumbprint contains invalid hex", Assert.Throws<PsignException>(() => RdpSigner.ParseThumbprint(new string('z', 40), 20, "SHA1")).Message);

        RdpSigner.ValidateSigningCertificate(signer.Info, DateTimeOffset.UtcNow);
        Assert.Equal("certificate is outside its validity period", Assert.Throws<PsignException>(() => RdpSigner.ValidateSigningCertificate(signer.Info, DateTimeOffset.UtcNow.AddYears(5))).Message);

        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=email only", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.4")], false));
        using var emailCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        Assert.StartsWith("certificate is not valid for RDP signing", Assert.Throws<PsignException>(() => RdpSigner.ValidateSigningCertificate(CertificateInfo.Parse(emailCert.RawData), DateTimeOffset.UtcNow)).Message, StringComparison.Ordinal);
    }
}
