using System.Text;
using Devolutions.Psign.Cli.Framework;
using Xunit;

namespace Devolutions.Psign.Tests.Cli;

public class ArgvTests
{
    [Fact]
    public void NativeVerifySwitchesNormalize()
    {
        Assert.Equal(new[] { "verify", "--policy", "pa", "file.exe" }, NativeArgv.Normalize(["verify", "/pa", "file.exe"]));
        Assert.Equal(
            new[] { "verify", "--policy", "pg", "--policy-guid", "{F750E6C3-38EE-11d1-85E5-00C04FC295EE}", "x" },
            NativeArgv.Normalize(["verify", "/pg", "{F750E6C3-38EE-11d1-85E5-00C04FC295EE}", "x"]));
        Assert.Equal(new[] { "verify", "--catalog-search", "default-db" }, NativeArgv.Normalize(["verify", "/ad"]));
        Assert.Equal(new[] { "verify", "--hash", "sha256" }, NativeArgv.Normalize(["verify", "/hash"]));
        Assert.Equal(new[] { "verify", "--ds", "0" }, NativeArgv.Normalize(["verify", "/ds"]));
        Assert.Equal(new[] { "verify", "--os-version-check", "386:10.0.26100.0" }, NativeArgv.Normalize(["verify", "/o", "386:10.0.26100.0"]));
    }

    [Fact]
    public void NativeSignAndGlobalsNormalize()
    {
        Assert.Equal(
            new[] { "-q", "sign", "--fd", "sha384", "--tr", "http://tsa", "--td", "sha256", "-v", "/usr/bin/app" },
            NativeArgv.Normalize(["/q", "SIGN", "/fd", "SHA384", "/tr", "http://tsa", "/td", "sha256", "/v", "/usr/bin/app"]));
        Assert.Equal(new[] { "sign", "--sign-auth", "1.2.3", "val", "f" }, NativeArgv.Normalize(["sign", "/sa", "1.2.3", "val", "f"]));
        Assert.Equal(new[] { "sign", "/sa", "1.2.3" }, NativeArgv.Normalize(["sign", "/sa", "1.2.3"]));
        Assert.Equal(new[] { "cert-store", "--s", "Root", "--sm" }, NativeArgv.Normalize(["cert-store", "/s", "Root", "/sm"]));
        Assert.Equal(new[] { "timestamp", "--tp", "2", "--p7" }, NativeArgv.Normalize(["timestamp", "/tp", "2", "/p7"]));
        Assert.Equal(new[] { "rdp", "--dry-run" }, NativeArgv.Normalize(["rdp", "/l"]));
        Assert.Equal(new[] { "portable", "pe-digest", "/tmp/x" }, NativeArgv.Normalize(["portable", "pe-digest", "/tmp/x"]));
    }

    [Fact]
    public void ResponseFilesExpand()
    {
        using var dir = new TempDir();
        var rsp = dir.File("args.rsp");
        File.WriteAllText(rsp, "verify\n/pa\n\"C:\\Program Files\\x.exe\"\n");
        var inv = ResponseArgv.ExpandInvocations(["-v", "@" + rsp]);
        Assert.Single(inv);
        Assert.Equal(new[] { "-v", "verify", "/pa", "C:\\Program Files\\x.exe" }, inv[0]);

        var blocks = dir.File("blocks.rsp");
        File.WriteAllText(blocks, "verify\r\na.exe\r\n\r\n\r\nverify\r\nb.exe\r\n");
        var two = ResponseArgv.ExpandInvocations(["@" + blocks]);
        Assert.Equal(2, two.Count);
        Assert.Equal(new[] { "verify", "b.exe" }, two[1]);

        var utf16 = dir.File("u16.rsp");
        File.WriteAllBytes(utf16, [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("sign\n\"a \"\"b\"\"\"\n")]);
        Assert.Equal(new[] { "sign", "a \"b\"" }, ResponseArgv.ExpandInvocations(["x", "@" + utf16])[0].Skip(1));

        Assert.Equal(new[] { "@lit", "@" }, ResponseArgv.ExpandInvocations(["@@lit", "@@"])[0]);
    }

    [Fact]
    public void BatchExitCodesCombine()
    {
        Assert.Equal(2, ResponseArgv.CombineBatchExitCodes(0, 2));
        Assert.Equal(1, ResponseArgv.CombineBatchExitCodes(2, 1));
        Assert.Equal(0, ResponseArgv.CombineBatchExitCodes(0, 0));
        Assert.Equal(ResponseArgv.AzureSignExitAllFailed, ResponseArgv.CombineBatchExitCodes(ResponseArgv.AzureSignExitPartialSuccess, ResponseArgv.AzureSignExitAllFailed));
        Assert.Equal(ResponseArgv.AzureSignExitPartialSuccess, ResponseArgv.CombineBatchExitCodes(2, ResponseArgv.AzureSignExitPartialSuccess));
    }
}
