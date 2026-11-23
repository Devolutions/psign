using System.Globalization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Signing.Cms;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>RFC 3161 request building / response inspection parity with <c>psign-tool portable rfc3161-*</c>.</summary>
public class Rfc3161ParityTests
{
    public static TheoryData<string, string?, bool> RequestCases() => new()
    {
        { "sha256", null, false },
        { "sha1", null, false },
        { "sha384", "42", true },
        { "sha512", "18446744073709551615", false },
        { "sha256", "0", true },
        { "sha256", "128", false },
    };

    [SkippableTheory]
    [MemberData(nameof(RequestCases))]
    public void TimestampRequestHexMatchesRust(string algorithm, string? nonce, bool certReq)
    {
        RustTool.Require();
        var kind = AuthenticodeHashKinds.Parse(algorithm);
        var digest = new byte[kind.DigestLength()];
        for (int i = 0; i < digest.Length; i++)
        {
            digest[i] = (byte)(i * 7);
        }

        var args = new List<string> { "portable", "rfc3161-timestamp-req", "--algorithm", algorithm, "--digest-hex", Hex.Lower(digest), "--output", "hex" };
        if (nonce is not null)
        {
            args.AddRange(["--nonce", nonce]);
        }

        if (certReq)
        {
            args.Add("--cert-req");
        }

        var rust = RustTool.RunOk([.. args]);
        var parsedNonce = nonce is null ? (ulong?)null : ulong.Parse(nonce, CultureInfo.InvariantCulture);
        var der = Rfc3161.BuildTimestampRequest(kind, Rfc3161.ParseHexDigestFixed(Hex.Lower(digest), kind.DigestLength()), parsedNonce, certReq);
        Assert.Equal(rust.Trim(), Hex.Lower(der));
    }

    [SkippableFact]
    public void TimestampRequestErrorMatchesRust()
    {
        RustTool.Require();
        var (code, _, stderr) = RustTool.Run("portable", "rfc3161-timestamp-req", "--algorithm", "sha256", "--digest-hex", "abcd");
        Assert.NotEqual(0, code);
        var err = Assert.Throws<PsignException>(() => Rfc3161.ParseHexDigestFixed("abcd", 32));
        Assert.Equal(stderr.Trim(), err.FullMessage);
    }

    private static byte[] BuildTstInfo(byte[] hashed, ulong? nonce)
    {
        var imprint = Der.EncodeSequence(Rfc3161.MessageImprintAlgorithmIdentifierDer(Oids.Sha256)!, Der.EncodeTlv(0x04, hashed));
        var parts = new List<byte[]>
        {
            new byte[] { 0x02, 0x01, 0x01 },
            Der.EncodeOid("1.3.6.1.4.1.601.10.3.1"),
            imprint,
            new byte[] { 0x02, 0x03, 0x00, 0xbe, 0xef },
            Der.EncodeTlv(0x18, "20251122103000Z"u8),
            Der.EncodeSequence([0x02, 0x01, 0x01]),
        };
        if (nonce is { } n)
        {
            parts.Add(Rfc3161.DerIntegerU64(n));
        }

        parts.Add([0x01, 0x01, 0x00]);
        return Der.EncodeSequence([.. parts]);
    }

    private static byte[] TimeStampResp(byte[] statusInfo, byte[]? token) =>
        token is null ? Der.EncodeSequence(statusInfo) : Der.EncodeSequence(statusInfo, token);

    public static IEnumerable<object?[]> ResponseCases()
    {
        yield return ["granted-no-token", new byte[] { 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00 }];
        yield return ["rejection-strings-failinfo", new byte[] { 0x30, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x02, 0x30, 0x03, 0x0c, 0x01, 0x77, 0x03, 0x02, 0x00, 0xc0 }];
        yield return ["bad-failinfo", new byte[] { 0x30, 0x09, 0x30, 0x07, 0x02, 0x01, 0x00, 0x03, 0x02, 0x08, 0x00 }];
        yield return ["opaque-token", new byte[] { 0x30, 0x0a, 0x30, 0x03, 0x02, 0x01, 0x00, 0x30, 0x03, 0x02, 0x01, 0x2a }];
        yield return ["unknown-128", new byte[] { 0x30, 0x06, 0x30, 0x04, 0x02, 0x02, 0x00, 0x80 }];
        yield return ["escaped-strings", TimeStampResp(Der.EncodeSequence([0x02, 0x01, 0x02], Der.EncodeSequence(Der.EncodeTlv(0x0c, "a\"b\\c\nd\u0001é"u8), Der.EncodeTlv(0x0c, [0xff, 0x41]))), null)];
        yield return ["malformed", new byte[] { 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00, 0xff }];
    }

    [SkippableTheory]
    [MemberData(nameof(ResponseCases))]
    public void RespInspectMatchesRust(string name, byte[] der)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var path = dir.File(name + ".der");
        File.WriteAllBytes(path, der);
        AssertInspectParity(path, der, null, null);
        AssertInspectParity(path, der, "0xAB", 7);
    }

    [SkippableFact]
    public void RespInspectFixtureMatchesRust()
    {
        RustTool.Require();
        var path = Fixtures.Path("rfc3161/ts_resp_granted_outer_len81.der");
        AssertInspectParity(path, File.ReadAllBytes(path), null, null);
    }

    [SkippableTheory]
    [InlineData(null)]
    [InlineData(0x1122334455667788UL)]
    public void RespInspectWithSignedTokenMatchesRust(ulong? nonce)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var hashed = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var tstinfo = BuildTstInfo(hashed, nonce);
        var token = Pkcs7Builder.CreateSignedData(Oids.TstInfo, Der.EncodeTlv(0x04, tstinfo), AuthenticodeHashKind.Sha256, signer.Info, [], signer.Key);
        var resp = TimeStampResp(Der.EncodeSequence([0x02, 0x01, 0x00]), token);
        var path = dir.File("resp.der");
        File.WriteAllBytes(path, resp);

        var parsed = Rfc3161.ParseTimeStampTokenTstInfo(Rfc3161.ParseTimeStampRespDer(resp)!.TimeStampToken!)!;
        Assert.Equal("1.3.6.1.4.1.601.10.3.1", parsed.PolicyOid);
        Assert.Equal(hashed, parsed.MessageImprintHashedMessage);
        Assert.Equal("00beef", parsed.SerialNumberHex);
        Assert.Equal("20251122103000Z", parsed.GenTime);
        Assert.Equal(nonce is null ? null : Rfc3161.NonceHex(nonce.Value), parsed.NonceHex);

        AssertInspectParity(path, resp, null, null);
        AssertInspectParity(path, resp, Hex.Lower(hashed), nonce ?? 1);
        AssertInspectParity(path, resp, "00", nonce);
    }

    private static void AssertInspectParity(string path, byte[] der, string? expectDigest, ulong? expectNonce)
    {
        var args = new List<string> { "portable", "rfc3161-timestamp-resp-inspect", path };
        if (expectDigest is not null)
        {
            args.AddRange(["--expect-digest-hex", expectDigest]);
        }

        if (expectNonce is not null)
        {
            args.AddRange(["--expect-nonce", expectNonce.Value.ToString(CultureInfo.InvariantCulture)]);
        }

        var (code, stdout, stderr) = RunUtf8(args);
        string csharp;
        try
        {
            csharp = Rfc3161.FormatTimeStampRespInspection(der, expectDigest, expectNonce);
        }
        catch (PsignException e)
        {
            Assert.NotEqual(0, code);
            Assert.Equal(stderr.Trim(), e.FullMessage);
            return;
        }

        Assert.True(code == 0, stderr);
        Assert.Equal(stdout.Replace("\r\n", "\n", StringComparison.Ordinal), csharp);
    }

    private static (int ExitCode, string Stdout, string Stderr) RunUtf8(List<string> args)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(RustTool.Require())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = System.Text.Encoding.UTF8,
            StandardErrorEncoding = System.Text.Encoding.UTF8,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using var p = System.Diagnostics.Process.Start(psi)!;
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, stdoutTask.Result, stderr);
    }
}
