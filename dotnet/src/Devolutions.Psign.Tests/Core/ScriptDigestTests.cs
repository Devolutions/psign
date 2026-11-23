using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Scripts;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

public class ScriptDigestTests
{
    public static TheoryData<string> SignedScriptFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var f in ScriptFixtures("generated-signed/scripts"))
        {
            data.Add(f);
        }

        return data;
    }

    public static TheoryData<string> UnsignedScriptFixtures()
    {
        var data = new TheoryData<string>();
        foreach (var f in ScriptFixtures("generated-unsigned/scripts"))
        {
            data.Add(f);
        }

        foreach (var f in new[] { "unsigned-sample.ps1", "unsigned-sample.psd1", "unsigned-sample.psm1", "unsigned-sample.js", "unsigned-sample.vbs", "unsigned-sample.wsf" })
        {
            data.Add(f);
        }

        return data;
    }

    internal static IEnumerable<string> ScriptFixtures(string root) =>
        Directory.GetFiles(Fixtures.Path(root), "*", SearchOption.AllDirectories)
            .Select(p => Path.GetRelativePath(Fixtures.Dir, p).Replace('\\', '/'))
            .Where(p => PsScript.ExtensionSupported(Ext(p)) || PsScript.IsWshExtension(Ext(p)))
            .OrderBy(p => p, StringComparer.Ordinal);

    internal static string Ext(string path) => Path.GetExtension(path).TrimStart('.');

    [Fact]
    public void StripRemovesHashStyleBlockUtf16()
    {
        var units = ("before" + "\r\n# SIG # Begin signature block\r\n" + "# SIG # End signature block\r\n" + "after").ToCharArray();
        var output = PsScript.StripSignatureRegionUtf16(units, PowerShellMarkerFamily.Hash);
        Assert.Equal("beforeafter", new string(output));
    }

    [Fact]
    public void ScriptDigestUnsignedErrorsMissingMarkers()
    {
        var raw = "# no signature markers\nWrite-Output 1\n"u8.ToArray();
        var err = Assert.Throws<PsignException>(() => PsScript.VerifyPowerShellClassDigest(raw, "ps1"));
        Assert.True(err.FullMessage.Contains("marker", StringComparison.Ordinal) || err.FullMessage.Contains("signature", StringComparison.Ordinal), err.FullMessage);
    }

    [Fact]
    public void StripJsBlockFindsLastMarker()
    {
        var units = ("aaa" + WshScript.BeginMarker(WshKind.Js) + "ignored" + WshScript.EndMarker(WshKind.Js) + "zzz").ToCharArray();
        var (output, off) = WshScript.StripWshSignatureUnits(units, WshKind.Js);
        Assert.Equal("aaazzz", new string(output));
        Assert.Equal(3u, off);
    }

    [Fact]
    public void WshDigestUnsignedErrorsMissingMarkers()
    {
        var raw = "// no sig markers\nconsole.log(1);\n"u8.ToArray();
        var err = Assert.Throws<PsignException>(() => WshScript.VerifyWshDigestConsistency(raw, "js"));
        var msg = err.FullMessage;
        Assert.True(msg.Contains("marker", StringComparison.Ordinal) || msg.Contains("Begin", StringComparison.Ordinal) || msg.Contains("PKCS", StringComparison.Ordinal), msg);
    }

    [Fact]
    public void StripWshBlockRejectsMissingEndMarker()
    {
        var units = ("before" + WshScript.BeginMarker(WshKind.Vbs) + "'' SIG '' QUJD").ToCharArray();
        var err = Assert.Throws<PsignException>(() => WshScript.StripWshSignatureUnits(units, WshKind.Vbs));
        Assert.Contains("end signature marker", err.FullMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void ExtractWshBase64RejectsMissingPrefixNonAsciiAndEmptyPayload()
    {
        var err = Assert.Throws<PsignException>(() => WshScript.ExtractBase64Ascii("QUJD".ToCharArray(), WshKind.Js));
        Assert.Contains("missing", err.FullMessage, StringComparison.Ordinal);
        Assert.Equal("WSH signature region line missing \"// SIG // \" prefix", err.Message);

        err = Assert.Throws<PsignException>(() => WshScript.ExtractBase64Ascii("// SIG // Ā\r\n".ToCharArray(), WshKind.Js));
        Assert.Contains("non-ASCII", err.FullMessage, StringComparison.Ordinal);

        err = Assert.Throws<PsignException>(() => WshScript.ExtractBase64Ascii("// SIG // \r\n".ToCharArray(), WshKind.Js));
        Assert.Contains("empty", err.FullMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void WshExtensionClassificationIsCaseInsensitiveAndLimited()
    {
        Assert.Equal(WshKind.Vbs, WshScript.WshKindFromExt("VBE"));
        Assert.Equal(WshKind.Js, WshScript.WshKindFromExt("JSE"));
        Assert.Equal(WshKind.Wsf, WshScript.WshKindFromExt("WSF"));
        Assert.Null(WshScript.WshKindFromExt("ps1"));
    }

    [Fact]
    public void ExtensionHelpers()
    {
        foreach (var e in new[] { "ps1", "PSD1", "psm1", "ps1xml", "psc1", "cdxml", "mof" })
        {
            Assert.True(PsScript.ExtensionSupported(e), e);
            Assert.False(PsScript.IsWshExtension(e), e);
        }

        foreach (var e in new[] { "js", "JSE", "vbs", "vbe", "wsf" })
        {
            Assert.True(PsScript.IsWshExtension(e), e);
            Assert.False(PsScript.ExtensionSupported(e), e);
        }

        Assert.Throws<PsignException>(() => PsScript.MarkerFamily("txt"));
        var err = Assert.Throws<PsignException>(() => PsScript.PowerShellClassDigestReport([], "txt"));
        Assert.Equal("Rust SIP script digest does not support extension .txt", err.Message);
    }

    [Fact]
    public void FileUtf16UnitsHandlesBomsAndUtf8()
    {
        Assert.Equal("ab", new string(PsScript.FileUtf16Units([0xFF, 0xFE, (byte)'a', 0, (byte)'b', 0, 0x99])));
        Assert.Equal("ab", new string(PsScript.FileUtf16Units([0xFE, 0xFF, 0, (byte)'a', 0, (byte)'b'])));
        Assert.Equal("﻿ab", new string(PsScript.FileUtf16Units([0xEF, 0xBB, 0xBF, (byte)'a', (byte)'b'])));
        Assert.Equal("a�b", new string(PsScript.FileUtf16Units([(byte)'a', 0xFF, (byte)'b'])));
    }

    [Theory]
    [MemberData(nameof(SignedScriptFixtures))]
    public void SignedFixturesVerify(string fixture)
    {
        var raw = Fixtures.Bytes(fixture);
        var report = ScriptDigest.ScriptDigestReport(raw, Ext(fixture));
        Assert.Equal(report.EmbeddedDigest, report.ComputedDigest);
        Assert.NotEmpty(report.Pkcs7Der);
    }

    [Theory]
    [MemberData(nameof(UnsignedScriptFixtures))]
    public void UnsignedFixturesFail(string fixture)
    {
        Assert.Throws<PsignException>(() => ScriptDigest.VerifyScriptDigestConsistency(Fixtures.Bytes(fixture), Ext(fixture)));
    }

    [Fact]
    public void TamperedSignedScriptReportsDigestMismatch()
    {
        var raw = Fixtures.Bytes("generated-signed/scripts/powershell/ps1/utf8-crlf.ps1");
        raw[3] ^= 0x01;
        var err = Assert.Throws<PsignException>(() => ScriptDigest.VerifyScriptDigestConsistency(raw, "ps1"));
        Assert.Equal("script Authenticode digest mismatch (experimental UTF-16 strip heuristic vs PKCS#7)", err.Message);

        var js = Fixtures.Bytes("generated-signed/scripts/wsh/js/utf8-crlf.js");
        js[3] ^= 0x01;
        err = Assert.Throws<PsignException>(() => ScriptDigest.VerifyScriptDigestConsistency(js, "js"));
        Assert.Equal("WSH Authenticode digest mismatch (wshext strip + offset dword vs PKCS#7)", err.Message);
    }

    [Fact]
    public void FormatsScriptSignatureMarkerFamily()
    {
        var ps1 = ScriptSignatureBlock.FormatPowerShellSignatureBlock("abc"u8, "ps1");
        Assert.Contains("# SIG # Begin signature block", ps1, StringComparison.Ordinal);
        Assert.Contains("# YWJj", ps1, StringComparison.Ordinal);
        Assert.Contains("# SIG # End signature block", ps1, StringComparison.Ordinal);

        var xml = ScriptSignatureBlock.FormatPowerShellSignatureBlock("abc"u8, "ps1xml");
        Assert.Contains("<!-- SIG # Begin signature block -->", xml, StringComparison.Ordinal);
        Assert.Contains("<!-- YWJj -->", xml, StringComparison.Ordinal);
        Assert.Contains("<!-- SIG # End signature block -->", xml, StringComparison.Ordinal);

        var mof = ScriptSignatureBlock.FormatPowerShellSignatureBlock("abc"u8, "mof");
        Assert.Contains("/* SIG # Begin signature block */", mof, StringComparison.Ordinal);
        Assert.Contains("/* YWJj */", mof, StringComparison.Ordinal);
        Assert.Contains("/* SIG # End signature block */", mof, StringComparison.Ordinal);

        var wide = ScriptSignatureBlock.FormatPowerShellSignatureBlock(new byte[100], "ps1");
        var lines = wide.Split("\r\n");
        Assert.Equal(64 + 2, lines[2].Length);
    }

    [Fact]
    public void AppendsScriptSignatureBlockUsingSourceUtf16Encoding()
    {
        const string block = "\r\n# SIG # Begin signature block\r\n";
        var le = ScriptSignatureBlock.AppendSignatureBlock([0xFF, 0xFE, (byte)'x', 0], block);
        Assert.Equal(new byte[] { 0xFF, 0xFE, (byte)'x', 0 }, le[..4]);
        Assert.Equal("x" + block, Encoding.Unicode.GetString(le, 2, le.Length - 2));

        var be = ScriptSignatureBlock.AppendSignatureBlock([0xFE, 0xFF, 0, (byte)'x'], block);
        Assert.Equal(new byte[] { 0xFE, 0xFF, 0, (byte)'x' }, be[..4]);
        Assert.Equal("x" + block, Encoding.BigEndianUnicode.GetString(be, 2, be.Length - 2));

        var utf8 = ScriptSignatureBlock.AppendSignatureBlock("x"u8, block);
        Assert.Equal("x" + block, Encoding.UTF8.GetString(utf8));
    }
}
