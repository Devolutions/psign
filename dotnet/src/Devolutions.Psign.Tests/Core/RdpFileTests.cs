using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Rdp;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class RdpFileTests
{
    private static string FixtureText(string name) => RdpFile.DecodeRdpText(Fixtures.Bytes("rdp/" + name));

    private static string RawFixture(string name) => Encoding.UTF8.GetString(Fixtures.Bytes("rdp/" + name));

    [Fact]
    public void ParsesFixtureAndBuildsNativeScope()
    {
        var prepared = RdpFile.PrepareForSignature(RdpFile.ParseRecords(RawFixture("minimal.rdp")));
        Assert.Equal("Full Address,Alternate Full Address,Server Port,EnableCredSspSupport", prepared.SignScope);
        Assert.Null(RdpFile.FindRecord(prepared.Records, "Signature"));
        Assert.Equal("server.example.test", RdpFile.FindRecord(prepared.Records, "Alternate Full Address")!.Value);
    }

    [Fact]
    public void DecodesFixtureTextEncodings()
    {
        var expected = FixtureText("unsigned-utf8.rdp");
        foreach (var name in new[] { "unsigned-utf8-bom.rdp", "unsigned-utf16le-bom.rdp", "unsigned-utf16le-nobom.rdp", "unsigned-utf16be-bom.rdp", "unsigned-utf16be-nobom.rdp" })
        {
            Assert.Equal(expected, FixtureText(name));
        }
    }

    [Fact]
    public void PartialSignedScopeAndStaleSignatureAreReplaced()
    {
        var prepared = RdpFile.PrepareForSignature(RdpFile.ParseRecords(FixtureText("partial-signed-scope.rdp")));
        Assert.Equal("Full Address,Alternate Full Address,Server Port,GatewayHostname,Prompt For Credentials", prepared.SignScope);
        RdpFile.ApplyPkcs7Signature(prepared.Records, "fresh"u8);
        var text = RdpFile.RecordsToText(prepared.Records);
        Assert.DoesNotContain("signscope:s:Full Address,Server Port\r\n", text, StringComparison.Ordinal);
        Assert.DoesNotContain("AQABAAEAAAAFAAAAc3RhbGU=", text, StringComparison.Ordinal);
        Assert.Contains("gatewayhostname:s:gateway.example.test", text, StringComparison.Ordinal);
        Assert.Contains("Signature:s:AQABAAEAAAAFAAAAZnJlc2g=", text, StringComparison.Ordinal);
    }

    [Fact]
    public void SecureBlobIsUtf16LeLinesPlusNul()
    {
        var prepared = RdpFile.PrepareForSignature(RdpFile.ParseRecords(RawFixture("minimal.rdp")));
        const string expected =
            "full address:s:server.example.test\r\n" +
            "Alternate Full Address:s:server.example.test\r\n" +
            "server port:i:3389\r\n" +
            "enablecredsspsupport:i:1\r\n" +
            "SignScope:s:Full Address,Alternate Full Address,Server Port,EnableCredSspSupport\r\n" +
            "\0";
        Assert.Equal(Encoding.Unicode.GetBytes(expected), prepared.SecureBlob);
    }

    [Fact]
    public void StaleSignatureRecordsAreReplaced()
    {
        var prepared = RdpFile.PrepareForSignature(RdpFile.ParseRecords(RawFixture("with-stale-signature.rdp")));
        RdpFile.ApplyPkcs7Signature(prepared.Records, "pkcs7"u8);
        var text = RdpFile.RecordsToText(prepared.Records);
        Assert.Single(text.Split("SignScope:s:").Skip(1));
        Assert.Single(text.Split("Signature:s:").Skip(1));
        Assert.DoesNotContain("stale", text, StringComparison.Ordinal);
        Assert.Contains("Signature:s:AQABAAEAAAAFAAAAcGtjczc=", text, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingFullAddressIsAnError()
    {
        var err = Assert.Throws<PsignException>(() => RdpFile.PrepareForSignature(RdpFile.ParseRecords("server port:i:3389\r\n")));
        Assert.Contains("Full Address", err.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EmptyFullAddressIsAnError()
    {
        var err = Assert.Throws<PsignException>(() => RdpFile.PrepareForSignature(RdpFile.ParseRecords("full address:s:\r\n")));
        Assert.Equal("RDP file is missing required Full Address setting", err.Message);
    }

    [Fact]
    public void NativeUnicodeEncodingUsesUtf16LeBom()
    {
        var bytes = RdpFile.EncodeNativeUnicode("full address:s:x\r\n");
        Assert.Equal(new byte[] { 0xFF, 0xFE }, bytes[..2]);
        Assert.Equal("full address:s:x\r\n", RdpFile.DecodeRdpText(bytes));
    }

    [Fact]
    public void SerializedSignatureIsNativeHeaderPlusBlob()
    {
        var serialized = RdpFile.SerializeSignature([0xAA, 0xBB]);
        Assert.Equal("AQABAAEAAAACAAAAqrs=", Convert.ToBase64String(serialized));
        Assert.Equal(new byte[] { 0xAA, 0xBB }, RdpFile.SignaturePkcs7FromSerialized(serialized));
    }

    [Fact]
    public void MalformedSignaturePayloadsAreRejected()
    {
        Assert.Throws<PsignException>(() => RdpFile.SignaturePkcs7FromSerialized(new byte[11]));
        var wrongVersion = RdpFile.SerializeSignature("pkcs7"u8);
        wrongVersion[0] = 0;
        Assert.Equal("unsupported RDP Signature version 0x00010000", Assert.Throws<PsignException>(() => RdpFile.SignaturePkcs7FromSerialized(wrongVersion)).Message);
        var wrongLen = RdpFile.SerializeSignature("pkcs7"u8);
        wrongLen[8] = 0xFF;
        Assert.Equal("RDP Signature length header says 255 byte(s), payload has 5", Assert.Throws<PsignException>(() => RdpFile.SignaturePkcs7FromSerialized(wrongLen)).Message);
        var err = Assert.Throws<PsignException>(() => RdpFile.SignaturePkcs7FromBase64("not base64"));
        Assert.Equal("decode RDP Signature base64: Invalid symbol 32, offset 3.", err.FullMessage);
    }

    [Fact]
    public void SignScopeReferencesMissingFieldIsMalformed()
    {
        var records = RdpFile.ParseRecords(FixtureText("signscope-missing-field.rdp"));
        var signScope = RdpFile.FindRecord(records, "SignScope")!.Value;
        var err = Assert.Throws<PsignException>(() => RdpFile.SecureSettingsBlob(records, signScope));
        Assert.Contains("NoSuch", err.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MalformedLinesAreIgnoredButValidRecordsAreKept()
    {
        var records = RdpFile.ParseRecords(FixtureText("malformed-lines.rdp"));
        Assert.Equal(2, records.Count);
        var prepared = RdpFile.PrepareForSignature(records);
        Assert.Equal("Full Address,Alternate Full Address,Server Port", prepared.SignScope);
    }

    [Fact]
    public void MalformedMissingRequiredFullAddressFixtureErrors()
    {
        var err = Assert.Throws<PsignException>(() => RdpFile.PrepareForSignature(RdpFile.ParseRecords(FixtureText("missing-full-address.rdp"))));
        Assert.Contains("Full Address", err.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SignedFixtureUsesRepoTestCertificateOverSecureBlob()
    {
        var records = RdpFile.ParseRecords(FixtureText("signed-test-cert.rdp"));
        var pkcs7 = RdpFile.SignatureRecordPkcs7(records);
        var sd = CmsSignedData.Parse(pkcs7);
        var messageDigest = sd.SignerInfos[0].MessageDigest();

        var unsigned = records.ToList();
        RdpFile.RemoveRecord(unsigned, "Signature");
        var signScope = RdpFile.FindRecord(unsigned, "SignScope")!.Value;
        var secureBlob = RdpFile.SecureSettingsBlob(unsigned, signScope);
        Assert.Equal(SHA256.HashData(secureBlob), messageDigest);
    }

    [Fact]
    public void ParseLineHandlesWhitespaceAndCase()
    {
        var r = RdpFile.ParseLine("  \tFull Address \t: S \t:  host\r");
        Assert.NotNull(r);
        Assert.Equal("Full Address", r!.Name);
        Assert.Equal(RdpValueKind.String, r.Kind);
        Assert.Equal("host", r.Value);
        Assert.Null(RdpFile.ParseLine("no colon here"));
        Assert.Null(RdpFile.ParseLine("name:x:value"));
        Assert.Null(RdpFile.ParseLine("name:s value"));
        Assert.Null(RdpFile.ParseLine("   "));
        Assert.Equal(RdpValueKind.Binary, RdpFile.ParseLine("blob:b:00ff")!.Kind);
        Assert.Equal(RdpValueKind.Integer, RdpFile.ParseLine("port:I:1")!.Kind);
    }

    [Fact]
    public void NonAsciiNamesAreNotCaseFolded()
    {
        var records = new List<RdpRecord> { RdpRecord.String("\u00e9", "x") };
        Assert.Null(RdpFile.FindRecord(records, "\u00c9"));
        Assert.NotNull(RdpFile.FindRecord(records, "\u00e9"));
    }
}
