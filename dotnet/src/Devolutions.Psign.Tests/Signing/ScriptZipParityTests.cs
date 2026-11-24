using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Scripts;
using Devolutions.Psign.Signing.Zip;
using Devolutions.Psign.Tests.Core;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>Script / ZIP signing and verification: byte-for-byte and verdict parity with the Rust <c>psign-tool</c>.</summary>
public class ScriptZipParityTests
{
    public static TheoryData<string> UnsignedPowerShellFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var f in ScriptDigestTests.ScriptFixtures("generated-unsigned/scripts/powershell"))
        {
            data.Add(f);
        }

        data.Add("unsigned-sample.ps1");
        data.Add("unsigned-sample.psd1");
        data.Add("unsigned-sample.psm1");
        return data;
    }

    public static TheoryData<string> AllScriptFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var f in ScriptDigestTests.ScriptFixtures("generated-signed/scripts").Concat(ScriptDigestTests.ScriptFixtures("generated-unsigned/scripts")))
        {
            data.Add(f);
        }

        foreach (var f in new[] { "unsigned-sample.ps1", "unsigned-sample.psd1", "unsigned-sample.psm1", "unsigned-sample.js", "unsigned-sample.vbs", "unsigned-sample.wsf" })
        {
            data.Add(f);
        }

        return data;
    }

    private static string RustSignInPlace(TempDir dir, string name, byte[] content, string digest)
    {
        var path = dir.File(name);
        File.WriteAllBytes(path, content);
        RustTool.RunOk("--mode", "portable", "sign", "--pfx", Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx"), "--password", PfxIdentity.Password, "--digest", digest, path);
        return path;
    }

    /// <summary>Assert the C# verifier reaches the same verdict (and error text) as <c>psign-tool portable verify-script</c>.</summary>
    private static void AssertVerifyScriptParity(string path, byte[] bytes, string ext)
    {
        var (code, _, stderr) = RustTool.Run("portable", "verify-script", path);
        string? csharpError = null;
        try
        {
            ScriptDigest.VerifyScriptDigestConsistency(bytes, ext);
        }
        catch (PsignException e)
        {
            csharpError = e.FullMessage;
        }

        Assert.True((code == 0) == (csharpError is null), $"verdict mismatch for {path}: rust exit {code} ({stderr.Trim()}), C# {csharpError ?? "ok"}");
        if (csharpError is not null)
        {
            Assert.Equal($"verify-script {path}: {csharpError}", stderr.Trim());
        }
    }

    [SkippableTheory]
    [MemberData(nameof(UnsignedPowerShellFixtures))]
    public void ScriptSignatureMatchesRustByteForByte(string fixture)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var id = new PfxIdentity();
        var unsigned = Fixtures.Bytes(fixture);
        var name = Path.GetFileName(fixture);
        var ext = ScriptDigestTests.Ext(fixture);
        var signed = ScriptSigner.SignScript(unsigned, ext, AuthenticodeHashKind.Sha256, id.Signer, id.Chain, id.Key);
        var rustPath = RustSignInPlace(dir, name, unsigned, "sha256");
        Assert.Equal(File.ReadAllBytes(rustPath), signed);
        AssertVerifyScriptParity(rustPath, signed, ext);
        ScriptDigest.VerifyScriptDigestConsistency(signed, ext);
    }

    [SkippableTheory]
    [InlineData("sha384")]
    [InlineData("sha512")]
    public void ScriptSignatureDigestVariantsMatchRust(string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var id = new PfxIdentity();
        var unsigned = Fixtures.Bytes("generated-unsigned/scripts/powershell/ps1xml/utf8-bom-crlf.ps1xml");
        var rustPath = RustSignInPlace(dir, "x.ps1xml", unsigned, digest);
        var signed = ScriptSigner.SignScript(unsigned, "ps1xml", AuthenticodeHashKinds.Parse(digest), id.Signer, id.Chain, id.Key);
        Assert.Equal(File.ReadAllBytes(rustPath), signed);
        var report = PsScript.PowerShellClassDigestReport(signed, "ps1xml");
        Assert.Equal(AuthenticodeHashKinds.Parse(digest).DigestLength(), report.EmbeddedDigest.Length);
    }

    [SkippableTheory]
    [MemberData(nameof(AllScriptFixtures))]
    public void VerifyScriptVerdictMatchesRust(string fixture)
    {
        RustTool.Require();
        AssertVerifyScriptParity(Fixtures.Path(fixture), Fixtures.Bytes(fixture), ScriptDigestTests.Ext(fixture));
    }

    [SkippableFact]
    public void TamperedScriptErrorMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        foreach (var fixture in new[] { "generated-signed/scripts/powershell/psm1/utf8-lf.psm1", "generated-signed/scripts/wsh/vbs/utf16le-bom-crlf.vbs" })
        {
            var bytes = Fixtures.Bytes(fixture);
            bytes[5] ^= 0x01;
            var path = dir.File(Path.GetFileName(fixture));
            File.WriteAllBytes(path, bytes);
            AssertVerifyScriptParity(path, bytes, ScriptDigestTests.Ext(fixture));
        }
    }

    [SkippableTheory]
    [InlineData("zip-authenticode/unsigned/sample.zip", "sha256")]
    [InlineData("zip-authenticode/signed/sample.signed.zip", "sha256")]
    [InlineData("zip-authenticode/unsigned/sample.zip", "sha512")]
    public void ZipSignatureMatchesRustByteForByte(string fixture, string digest)
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var id = new PfxIdentity();
        var zip = Fixtures.Bytes(fixture);
        var rustPath = RustSignInPlace(dir, "archive.zip", zip, digest);

        var signed = ZipAuthenticodeSigner.SignZip(zip, AuthenticodeHashKinds.Parse(digest), id.Signer, id.Chain, id.Key);
        Assert.Equal(File.ReadAllBytes(rustPath), signed);

        var (sig, report) = ZipAuthenticode.VerifyZipSignature(signed);
        Assert.Equal(ZipAuthenticode.ZipAuthenticodeDigestString(zip), sig.Digest);
        Assert.Equal(report.EmbeddedDigest, report.ComputedDigest);
        RustTool.RunOk("portable", "verify-zip", rustPath);
    }

    [SkippableFact]
    public void ZipSignFileMatchesRust()
    {
        RustTool.Require();
        using var dir = new TempDir();
        using var id = new PfxIdentity();
        var zip = ZipAuthenticodeTests.TinyZip("old comment"u8.ToArray());
        var rustPath = RustSignInPlace(dir, "tiny.zip", zip, "sha256");
        var input = dir.File("input.zip");
        File.WriteAllBytes(input, zip);
        var output = dir.File("out.zip");
        ZipAuthenticodeSigner.SignZipFile(input, output, AuthenticodeHashKind.Sha256, id.Signer, id.Chain, new RsaDigestSigner(id.Key));
        Assert.Equal(File.ReadAllBytes(rustPath), File.ReadAllBytes(output));
    }

    [SkippableTheory]
    [InlineData(null)]
    [InlineData(30)]
    [InlineData(-1)]
    public void VerifyZipVerdictMatchesRust(int? tamperOffset)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var bytes = tamperOffset == -1 ? Fixtures.Bytes("zip-authenticode/unsigned/sample.zip") : Fixtures.Bytes("zip-authenticode/signed/sample.signed.zip");
        if (tamperOffset is > 0)
        {
            bytes[tamperOffset.Value] ^= 0x01;
        }

        var path = dir.File("v.zip");
        File.WriteAllBytes(path, bytes);
        var (code, _, stderr) = RustTool.Run("portable", "verify-zip", path);
        string? error = null;
        try
        {
            ZipAuthenticode.VerifyZipSignature(bytes);
        }
        catch (PsignException e)
        {
            error = e.FullMessage;
        }

        Assert.Equal(code == 0, error is null);
        if (error is not null)
        {
            Assert.Equal($"verify-zip {path}: {error}", stderr.Trim());
        }
    }

    [Fact]
    public void ScriptSignerRejectsUnsupportedExtensionAndSha1()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var err = Assert.Throws<PsignException>(() => ScriptSigner.SignScript("x"u8, "js", AuthenticodeHashKind.Sha256, signer.Info, [], signer.Key));
        Assert.Equal("portable script signing supports ps1, psd1, psm1, ps1xml, psc1, cdxml, and mof scripts", err.Message);
        Assert.Throws<PsignException>(() => ScriptSigner.SignScript("x"u8, "ps1", AuthenticodeHashKind.Sha1, signer.Info, [], signer.Key));
    }

    [Fact]
    public void SignedScriptRoundTripsThroughVerifier()
    {
        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        var script = "Write-Output 'hello'\r\n"u8.ToArray();
        int timestampCalls = 0;
        var signed = ScriptSigner.SignScript(script, "ps1", AuthenticodeHashKind.Sha256, signer.Info, [], signer.Key, p =>
        {
            timestampCalls++;
            return p;
        });
        Assert.Equal(1, timestampCalls);
        var report = ScriptDigest.ScriptDigestReport(signed, "ps1");
        var sig = Devolutions.Psign.Core.Authenticode.AuthenticodeSignature.Parse(report.Pkcs7Der);
        Assert.Equal(signer.Certificate.RawData, sig.SignedData.CertificateForSigner(sig.SignerInfo).RawData);

        var remote = ScriptSigner.RemoteSignedAttributesDigest(script, AuthenticodeHashKind.Sha256);
        Assert.Equal(Pkcs7Builder.SignedAttributesDigest(sig.SignerInfo.SignedAttributes!, AuthenticodeHashKind.Sha256), remote);
    }
}
