using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Verification;
using Xunit;

namespace Devolutions.Psign.Tests.Verification;

/// <summary>
/// Differential tests: run the Rust <c>psign-tool portable …</c> trust / inspect commands and compare stdout (or the
/// error line) with the C# API output.
/// </summary>
public class TrustDifferentialTests
{
    private static readonly string TestCa = "devolutions-authenticode/authenticode-test-ca.crt";

    public static IEnumerable<object[]> GeneratedPe() =>
        Directory.GetFiles(Fixtures.Path("generated-signed/pe")).OrderBy(p => p, StringComparer.Ordinal).Select(p => new object[] { Path.GetFileName(p) });

    private static (int Code, string Stdout, string Stderr) RunRust(params string[] args) => RustTool.Run(RustTool.NoAutoTrust, args);

    /// <summary>Run the C# trust verification and render it like the Rust CLI (stdout on success, error line otherwise).</summary>
    private static (bool Ok, string Text) RunCs(string prefix, string displayPath, Func<TrustVerifyPeReport> verify)
    {
        try
        {
            var report = verify();
            return (true, string.Join("\n", report.FormatOkLines(prefix)));
        }
        catch (PsignException e)
        {
            return (false, $"{prefix} {displayPath}: {e.FullMessage}");
        }
    }

    private static void AssertSame((int Code, string Stdout, string Stderr) rust, (bool Ok, string Text) cs)
    {
        if (rust.Code == 0)
        {
            Assert.True(cs.Ok, $"Rust succeeded but C# failed: {cs.Text}\nRust: {rust.Stdout}");
            Assert.Equal(rust.Stdout.TrimEnd('\r', '\n').Replace("\r\n", "\n"), cs.Text);
        }
        else
        {
            Assert.False(cs.Ok, $"Rust failed but C# succeeded: {cs.Text}\nRust: {rust.Stderr}");
            Assert.Equal(rust.Stderr.Trim().Replace("\r\n", "\n"), cs.Text);
        }
    }

    private static TrustVerifySharedArgs Args(string[] extra)
    {
        // Minimal parser for the subset of shared trust arguments used by these tests.
        var a = new TrustVerifySharedArgs();
        var trusted = new List<string>();
        for (int i = 0; i < extra.Length; i++)
        {
            switch (extra[i])
            {
                case "--trusted-ca":
                    trusted.Add(extra[++i]);
                    break;
                case "--anchor-dir":
                    a = a with { AnchorDir = extra[++i] };
                    break;
                case "--as-of":
                    a = a with { AsOf = extra[++i] };
                    break;
                case "--authroot-cab":
                    a = a with { AuthrootCab = extra[++i] };
                    break;
                case "--allow-loose-signing-cert":
                    a = a with { AllowLooseSigningCert = true };
                    break;
                case "--prefer-timestamp-signing-time":
                    a = a with { PreferTimestampSigningTime = true };
                    break;
                case "--require-valid-timestamp":
                    a = a with { RequireValidTimestamp = true };
                    break;
                case "--artifact-signing":
                    a = a with { ArtifactSigning = true };
                    break;
                case "--artifact-signing-publisher-id":
                    a = a with { ArtifactSigningPublisherId = [.. a.ArtifactSigningPublisherId, extra[++i]] };
                    break;
                default:
                    throw new ArgumentException(extra[i]);
            }
        }

        return a with { TrustedCa = trusted };
    }

    private static void CompareTrustVerifyPe(string relPath, params string[] trustArgs)
    {
        RustTool.Require();
        var path = Fixtures.Path(relPath);
        var rust = RunRust(["portable", "trust-verify-pe", path, .. trustArgs]);
        var cs = RunCs("trust-verify-pe", path, () =>
        {
            var bytes = File.ReadAllBytes(path);
            var opts = Args(trustArgs).ToOptions();
            try
            {
                return TrustVerifyPe.TrustVerifyPeBytes(bytes, opts);
            }
            catch (PsignException e)
            {
                throw PsignException.Context($"trust-verify-pe {path}", e);
            }
        });
        if (!cs.Ok)
        {
            // The context already carries the prefix and path.
            cs = (false, cs.Text[(("trust-verify-pe " + path + ": ").Length)..]);
        }

        AssertSame(rust, cs);
    }

    [SkippableTheory]
    [MemberData(nameof(GeneratedPe))]
    public void GeneratedPeWithTestCaMatchesRust(string file)
    {
        CompareTrustVerifyPe("generated-signed/pe/" + file, "--trusted-ca", Fixtures.Path(TestCa), "--as-of", "2026-06-01");
    }

    [SkippableTheory]
    [InlineData("2026-06-01")]
    [InlineData("2020-01-01")]
    [InlineData("2030-01-01")]
    public void GeneratedPeDatesMatchRust(string asOf)
    {
        CompareTrustVerifyPe("generated-signed/pe/tiny64-pe-alias.exe", "--trusted-ca", Fixtures.Path(TestCa), "--as-of", asOf);
        CompareTrustVerifyPe("generated-signed/pe/tiny64-pe-alias.exe", "--trusted-ca", Fixtures.Path(TestCa), "--as-of", asOf, "--allow-loose-signing-cert");
    }

    [SkippableTheory]
    [InlineData("pe-authenticode-upstream/tiny32.signed.efi", "2023-07-01")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi", "2023-07-01")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi", "2026-06-01")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi", "2023-01-01")]
    public void UpstreamPeWithEmbeddedRootMatchesRust(string rel, string asOf)
    {
        RustTool.Require();
        using var dir = new TempDir();
        var root = TrustVerifyPe.PeFirstPkcs7TerminalRoot(Fixtures.Bytes(rel));
        File.WriteAllBytes(dir.File("anchor.crt"), root.RawData);
        CompareTrustVerifyPe(rel, "--anchor-dir", dir.DirPath, "--as-of", asOf);
        CompareTrustVerifyPe(rel, "--anchor-dir", dir.DirPath, "--as-of", asOf, "--allow-loose-signing-cert");
        CompareTrustVerifyPe(rel, "--anchor-dir", dir.DirPath, "--prefer-timestamp-signing-time");
        CompareTrustVerifyPe(rel, "--anchor-dir", dir.DirPath, "--prefer-timestamp-signing-time", "--require-valid-timestamp");
    }

    [SkippableFact]
    public void WrongAnchorsMatchRust()
    {
        var other = Fixtures.Path("artifact-signing/microsoft-public-rsa-timestamping-ca-2020.pem");
        CompareTrustVerifyPe("generated-signed/pe/tiny32-pe-alias.exe", "--trusted-ca", other, "--as-of", "2026-06-01");
        CompareTrustVerifyPe("pe-authenticode-upstream/tiny64.signed.efi", "--trusted-ca", other, "--as-of", "2023-07-01");
        CompareTrustVerifyPe("pe-authenticode-upstream/tiny64.signed.efi", "--trusted-ca", Fixtures.Path(TestCa), "--as-of", "2023-07-01");
        CompareTrustVerifyPe("pe-authenticode-upstream/tiny64.efi", "--trusted-ca", Fixtures.Path(TestCa), "--as-of", "2023-07-01");
    }

    [SkippableFact]
    public void ArtifactSigningPolicyOnGenericPeMatchesRust()
    {
        CompareTrustVerifyPe("generated-signed/pe/tiny32-pe-alias.exe", "--artifact-signing");
        CompareTrustVerifyPe("generated-signed/pe/tiny32-pe-alias.exe", "--artifact-signing", "--trusted-ca", Fixtures.Path(TestCa));
    }

    [SkippableFact]
    public void AuthRootCabAnchorCountMatchesRust()
    {
        var cab = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? Environment.GetEnvironmentVariable("HOME") ?? ".", ".psign", "authroot", "authrootstl.cab");
        Skip.IfNot(File.Exists(cab), "no cached AuthRoot CAB");
        CompareTrustVerifyPe("generated-signed/pe/tiny32-pe-alias.exe", "--trusted-ca", Fixtures.Path(TestCa), "--authroot-cab", cab, "--as-of", "2026-06-01");
    }

    public static IEnumerable<object[]> DetachedCases() =>
    [
        ["generated-unsigned/detached/content-utf16le-bom.txt", "generated-signed/detached/content-utf16le-bom/content-utf16le-bom.txt.p7"],
        ["generated-unsigned/detached/content-utf8.txt", "generated-signed/detached/content-utf8/content-utf8.txt.p7"],
        ["generated-unsigned/detached/content.bin", "generated-signed/detached/content/content.bin.p7"],
        ["generated-unsigned/detached/content-utf8.txt", "generated-signed/detached/content/content.bin.p7"],
    ];

    [SkippableTheory]
    [MemberData(nameof(DetachedCases))]
    public void DetachedMatchesRust(string content, string sig)
    {
        RustTool.Require();
        var contentPath = Fixtures.Path(content);
        Skip.IfNot(File.Exists(contentPath), "content fixture missing");
        var sigPath = Fixtures.Path(sig);
        foreach (var asOf in new[] { "2026-06-01", "2019-01-01" })
        {
            string[] trust = ["--trusted-ca", Fixtures.Path(TestCa), "--as-of", asOf];
            var rust = RunRust(["portable", "trust-verify-detached", contentPath, sigPath, .. trust]);
            var cs = RunCs("trust-verify-detached", contentPath, () =>
                TrustVerifyDetached.TrustVerifyDetachedBytes(File.ReadAllBytes(contentPath), File.ReadAllBytes(sigPath), Args(trust).ToOptions()));
            AssertSame(rust, cs);
        }
    }

    public static IEnumerable<object[]> InspectPeCases() =>
        GeneratedPe().Select(x => new object[] { "generated-signed/pe/" + (string)x[0] })
            .Concat([["pe-authenticode-upstream/tiny32.signed.efi"], ["pe-authenticode-upstream/tiny64.signed.efi"]]);

    [SkippableTheory]
    [MemberData(nameof(InspectPeCases))]
    public void InspectPeMatchesRust(string rel)
    {
        var path = Fixtures.Path(rel);
        var rust = RustTool.RunOk(RustTool.NoAutoTrust, "portable", "inspect-authenticode", path);
        var cs = RustJson.ToStringPretty(AuthenticodeInspector.InspectPeAuthenticode(File.ReadAllBytes(path)), VerificationJsonContext.Default.InspectPeFileReport);
        Assert.Equal(rust.TrimEnd('\r', '\n').Replace("\r\n", "\n"), cs);
    }

    public static IEnumerable<object[]> InspectPkcs7Cases() =>
    [
        ["artifact-signing/psign-tool.pkcs7.der"],
        ["generated-signed/detached/content/content.bin.p7"],
        ["generated-signed/detached/content-utf8/content-utf8.txt.p7"],
    ];

    [SkippableTheory]
    [MemberData(nameof(InspectPkcs7Cases))]
    public void InspectPkcs7MatchesRust(string rel)
    {
        var path = Fixtures.Path(rel);
        var rust = RustTool.RunOk(RustTool.NoAutoTrust, "portable", "inspect-authenticode", path, "--input", "pkcs7");
        var cs = RustJson.ToStringPretty(AuthenticodeInspector.InspectAuthenticodePkcs7Der(File.ReadAllBytes(path)), VerificationJsonContext.Default.InspectPkcs7Report);
        Assert.Equal(rust.TrimEnd('\r', '\n').Replace("\r\n", "\n"), cs);
    }

    [SkippableTheory]
    [InlineData("artifact-signing/psign-tool.pkcs7.der", "pkcs7")]
    [InlineData("artifact-signing/devolutions-signer.pem", "cert")]
    [InlineData("artifact-signing/microsoft-public-rsa-timestamping-ca-2020.pem", "cert")]
    [InlineData("generated-signed/pe/tiny32-pe-alias.exe", "pe")]
    [InlineData("pe-authenticode-upstream/tiny64.signed.efi", "pe")]
    public void PublisherIdJsonMatchesRust(string rel, string input)
    {
        var path = Fixtures.Path(rel);
        var rust = RustTool.RunOk(RustTool.NoAutoTrust, "portable", "artifact-signing-publisher-id", path, "--input", input);
        var bytes = File.ReadAllBytes(path);
        string cs = input switch
        {
            "pe" => RustJson.ToStringPretty(ArtifactSigning.IdentitiesFromPe(bytes), VerificationJsonContext.Default.ListArtifactSigningSignerIdentity),
            "pkcs7" => RustJson.ToStringPretty(ArtifactSigning.IdentityFromPkcs7Der(bytes), VerificationJsonContext.Default.ArtifactSigningIdentity),
            _ => RustJson.ToStringPretty(ArtifactSigning.IdentityFromCertBytes(bytes), VerificationJsonContext.Default.ArtifactSigningIdentity),
        };
        Assert.Equal(rust.TrimEnd('\r', '\n').Replace("\r\n", "\n"), cs);
    }

    [SkippableFact]
    public void ArtifactSigningRealPkcs7VerifiedLikeRust()
    {
        // The Rust CLI has no command that verifies a bare Authenticode PKCS#7 against its own digest; compare the
        // detached-PKCS#7 path, which takes the CMS fallback for this content (digest mismatch → identical error text).
        RustTool.Require();
        using var dir = new TempDir();
        var content = dir.File("content.bin");
        File.WriteAllBytes(content, [1, 2, 3]);
        var sig = Fixtures.Path("artifact-signing/psign-tool.pkcs7.der");
        var rust = RunRust("portable", "trust-verify-detached", content, sig, "--artifact-signing");
        var cs = RunCs("trust-verify-detached", content, () =>
            TrustVerifyDetached.TrustVerifyDetachedBytes(File.ReadAllBytes(content), File.ReadAllBytes(sig), Args(["--artifact-signing"]).ToOptions()));
        AssertSame(rust, cs);
    }

    [Fact]
    public void PeDigestHelperIsConsistent()
    {
        var pe = Fixtures.Bytes("generated-signed/pe/tiny32-pe-alias.exe");
        Assert.Single(PeAuthenticode.Pkcs7Blobs(pe));
    }
}
