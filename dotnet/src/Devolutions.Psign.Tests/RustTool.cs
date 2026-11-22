using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace Devolutions.Psign.Tests;

/// <summary>
/// Differential-testing helper that runs the Rust <c>psign-tool</c> (set <c>PSIGN_RUST_TOOL</c> or build
/// <c>target/debug/psign-tool</c> / <c>target/release/psign-tool</c> at the repo root). Tests call <see cref="Require"/>
/// which skips when the tool is unavailable.
/// </summary>
internal static class RustTool
{
    private static readonly Lazy<string?> ToolPath = new(() =>
    {
        var env = Environment.GetEnvironmentVariable("PSIGN_RUST_TOOL");
        if (!string.IsNullOrEmpty(env) && File.Exists(env))
        {
            return env;
        }

        var exe = OperatingSystem.IsWindows() ? "psign-tool.exe" : "psign-tool";
        foreach (var profile in new[] { "debug", "release" })
        {
            var p = System.IO.Path.Combine(Fixtures.RepoRoot, "target", profile, exe);
            if (File.Exists(p))
            {
                return p;
            }
        }

        return null;
    });

    /// <summary>Path to the Rust tool or <c>null</c>.</summary>
    public static string? Path => ToolPath.Value;

    /// <summary>Skip the current test when the Rust tool is unavailable; return its path otherwise.</summary>
    public static string Require()
    {
        Skip.If(Path is null, "Rust psign-tool not built (set PSIGN_RUST_TOOL or run cargo build -p psign --bin psign-tool)");
        return Path!;
    }

    /// <summary>Run the Rust tool and return (exit code, stdout, stderr).</summary>
    public static (int ExitCode, string Stdout, string Stderr) Run(params string[] args)
    {
        var psi = new ProcessStartInfo(Require())
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        psi.Environment["PSIGN_TOOL_MODE"] = "portable";
        using var p = Process.Start(psi)!;
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, stdoutTask.Result, stderr);
    }

    /// <summary>Run and assert success.</summary>
    public static string RunOk(params string[] args)
    {
        var (code, stdout, stderr) = Run(args);
        Assert.True(code == 0, $"rust psign-tool {string.Join(' ', args)} failed ({code}): {stderr}\n{stdout}");
        return stdout;
    }
}

/// <summary>Temporary directory deleted on dispose.</summary>
internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        DirPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "psign-cs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(DirPath);
    }

    public string DirPath { get; }

    public string File(string name) => System.IO.Path.Combine(DirPath, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(DirPath, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}

/// <summary>Deterministic-enough test signing identity (RSA-2048 code signing cert) with files on disk.</summary>
internal sealed class TestSigner : IDisposable
{
    public TestSigner(TempDir dir, string subject = "CN=psign C# test signer")
    {
        Key = RSA.Create(2048);
        var req = new CertificateRequest(subject, Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") }, false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        Certificate = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
        CertPath = dir.File("signer.der");
        KeyPath = dir.File("signer.pk8");
        System.IO.File.WriteAllBytes(CertPath, Certificate.RawData);
        System.IO.File.WriteAllBytes(KeyPath, Key.ExportPkcs8PrivateKey());
    }

    public RSA Key { get; }

    public X509Certificate2 Certificate { get; }

    public Devolutions.Psign.Core.X509.CertificateInfo Info => Devolutions.Psign.Core.X509.CertificateInfo.Parse(Certificate.RawData);

    public string CertPath { get; }

    public string KeyPath { get; }

    public void Dispose()
    {
        Key.Dispose();
        Certificate.Dispose();
    }
}
