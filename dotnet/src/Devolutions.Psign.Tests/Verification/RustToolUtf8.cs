using System.Diagnostics;
using System.Text;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary><see cref="RustTool"/> variant that decodes stdout/stderr as UTF-8 (the Rust tool prints “—” and “…”).</summary>
internal static class RustToolUtf8
{
    public static (int ExitCode, string Stdout, string Stderr) Run(params string[] args)
    {
        var psi = new ProcessStartInfo(RustTool.Require())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment["PSIGN_TOOL_MODE"] = "portable";
        psi.Environment["PSIGN_NO_AUTO_TRUST"] = "1";
        using var p = Process.Start(psi)!;
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, stdoutTask.Result, stderr);
    }

    public static string RunOk(params string[] args)
    {
        var (code, stdout, stderr) = Run(args);
        Assert.True(code == 0, $"rust psign-tool {string.Join(' ', args)} failed ({code}): {stderr}\n{stdout}");
        return stdout;
    }
}
