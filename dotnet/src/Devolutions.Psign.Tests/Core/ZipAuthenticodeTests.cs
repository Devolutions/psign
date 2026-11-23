using System.Buffers.Binary;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Zip;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class ZipAuthenticodeTests
{
    internal static byte[] TinyZip(byte[] comment)
    {
        var output = new List<byte>();
        output.AddRange(new byte[] { 0x50, 0x4b, 0x03, 0x04, 20 });
        output.AddRange(new byte[25]);
        uint centralOffset = (uint)output.Count;
        output.AddRange(new byte[] { 0x50, 0x4b, 0x01, 0x02, 20, 0, 20 });
        output.AddRange(new byte[39]);
        output.AddRange(new byte[] { 0x50, 0x4b, 0x05, 0x06 });
        output.AddRange(new byte[] { 0, 0, 0, 0, 1, 0, 1, 0 });
        var tmp = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(tmp, 46);
        output.AddRange(tmp);
        BinaryPrimitives.WriteUInt32LittleEndian(tmp, centralOffset);
        output.AddRange(tmp);
        output.Add((byte)comment.Length);
        output.Add((byte)(comment.Length >> 8));
        output.AddRange(comment);
        return output.ToArray();
    }

    [Fact]
    public void DigestIgnoresExistingComment()
    {
        Assert.Equal(
            ZipAuthenticode.ZipAuthenticodeDigestString(TinyZip([])),
            ZipAuthenticode.ZipAuthenticodeDigestString(TinyZip("hello"u8.ToArray())));
    }

    [Fact]
    public void EocdScanRejectsFalseSignatureInComment()
    {
        var comment = Encoding.Latin1.GetBytes("prefix PK\x05\x06 fake");
        var eocd = ZipAuthenticode.FindEocd(TinyZip(comment));
        Assert.Equal(comment.Length, eocd.CommentLength);
    }

    [Fact]
    public void SignatureCommentRoundtripsScriptFormat()
    {
        var pkcs7 = Convert.ToBase64String([1, 2, 3, 4]);
        var line = $"ZipAuthenticode=sha256:{new string('a', 64)},{pkcs7}";
        var script = ZipAuthenticode.SignatureScriptFromCommentLine(line);
        Assert.Contains(ZipAuthenticode.BeginSigBlock, script, StringComparison.Ordinal);
        Assert.Equal(line, ZipAuthenticode.SignatureCommentLineFromScript(Encoding.UTF8.GetBytes(script)));
    }

    [Fact]
    public void EmbedReplacesZipComment()
    {
        var zip = TinyZip("old"u8.ToArray());
        var pkcs7 = Convert.ToBase64String([1, 2, 3]);
        var line = $"ZipAuthenticode=sha256:{new string('b', 64)},{pkcs7}";
        var signed = ZipAuthenticode.EmbedSignatureCommentLine(zip, line);
        Assert.Equal(Encoding.UTF8.GetBytes(line), ZipAuthenticode.ZipComment(signed));
    }

    [Fact]
    public void ParseRejectsMalformedLines()
    {
        Assert.Equal("ZIP signature comment must start with ZipAuthenticode=", Assert.Throws<PsignException>(() => ZipAuthenticode.ParseSignatureCommentLine("nope")).Message);
        Assert.Equal("ZIP signature comment is missing PKCS#7 separator", Assert.Throws<PsignException>(() => ZipAuthenticode.ParseSignatureCommentLine("ZipAuthenticode=sha256:00")).Message);
        Assert.Equal("ZIP signature digest must use sha256:<64 hex chars>", Assert.Throws<PsignException>(() => ZipAuthenticode.ParseSignatureCommentLine("ZipAuthenticode=sha1:00,AAAA")).Message);
        Assert.Equal("ZIP signature PKCS#7 payload is empty", Assert.Throws<PsignException>(() => ZipAuthenticode.ParseSignatureCommentLine($"ZipAuthenticode=sha256:{new string('c', 64)},  ")).Message);
        var bad = Assert.Throws<PsignException>(() => ZipAuthenticode.ParseSignatureCommentLine($"ZipAuthenticode=sha256:{new string('c', 64)},A$AA"));
        Assert.Equal("ZIP signature PKCS#7 base64 decode: Invalid symbol 36, offset 1.", bad.FullMessage);

        var upper = ZipAuthenticode.ParseSignatureCommentLine($"ZipAuthenticode=sha256:{new string('C', 64)},AAAA");
        Assert.Equal("sha256:" + new string('c', 64), upper.Digest);
    }

    [Fact]
    public void FindEocdErrors()
    {
        Assert.Equal("ZIP file is too short to contain an EOCD record", Assert.Throws<PsignException>(() => ZipAuthenticode.FindEocd(new byte[10])).Message);
        Assert.Equal("could not find a valid ZIP end-of-central-directory record", Assert.Throws<PsignException>(() => ZipAuthenticode.FindEocd(new byte[40])).Message);
        var big = new byte[ZipAuthenticode.MaxZipCommentLen + 1];
        Assert.Contains("ZIP comment is too large", Assert.Throws<PsignException>(() => ZipAuthenticode.SetZipComment(TinyZip([]), big)).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SignedFixtureVerifies()
    {
        var bytes = Fixtures.Bytes("zip-authenticode/signed/sample.signed.zip");
        var (sig, report) = ZipAuthenticode.VerifyZipSignature(bytes);
        Assert.Equal(ZipAuthenticode.ZipAuthenticodeDigestString(bytes), sig.Digest);
        Assert.Equal(report.EmbeddedDigest, report.ComputedDigest);
        Assert.Equal(ZipAuthenticode.SignaturePkcs7Der(sig), report.Pkcs7Der);

        var unsigned = Fixtures.Bytes("zip-authenticode/unsigned/sample.zip");
        Assert.Equal(ZipAuthenticode.ZipAuthenticodeDigestString(unsigned), sig.Digest);
        Assert.Equal("ZIP Authenticode signature comment not found", Assert.Throws<PsignException>(() => ZipAuthenticode.VerifyZipDigestBinding(unsigned)).Message);
    }

    [Fact]
    public void SignedFixtureDetectsTamper()
    {
        var bytes = Fixtures.Bytes("zip-authenticode/signed/sample.signed.zip");
        bytes[30] ^= 0x01;
        var err = Assert.Throws<PsignException>(() => ZipAuthenticode.VerifyZipDigestBinding(bytes));
        Assert.StartsWith("ZIP Authenticode digest mismatch", err.Message, StringComparison.Ordinal);
    }
}
