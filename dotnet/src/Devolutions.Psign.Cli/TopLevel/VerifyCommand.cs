using System.Globalization;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.Portable;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Verification.AuthRoot;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>Parsed <c>psign-tool verify</c> arguments (Rust <c>cli::VerifyArgs</c>).</summary>
internal sealed record VerifyArgs
{
    /// <summary><c>default</c>, <c>pa</c>, or <c>pg</c>.</summary>
    public string Policy { get; init; } = "default";

    public string? PolicyGuid { get; init; }

    public bool RevocationCheck { get; init; }

    public string? DetachedPkcs7 { get; init; }

    public string? Catalog { get; init; }

    /// <summary><c>all</c>, <c>default-db</c>, or <c>system</c>.</summary>
    public string? CatalogSearch { get; init; }

    public string? CatalogDatabaseGuid { get; init; }

    /// <summary><c>sha1</c> or <c>sha256</c>.</summary>
    public string CatalogHashAlgorithm { get; init; } = "sha256";

    public string? OsVersionCheck { get; init; }

    public bool KernelPolicy { get; init; }

    public bool AllSignatures { get; init; }

    public bool AllowTestRoot { get; init; }

    public bool WarnIfNotTimestamped { get; init; }

    public uint? SignatureIndex { get; init; }

    public bool MultipleSemantics { get; init; }

    public bool VerifyPkcs7File { get; init; }

    public bool PrintDescription { get; init; }

    public bool VerifyPageHashes { get; init; }

    public string? ChainRootSubject { get; init; }

    public IReadOnlyList<string> SignerThumbprintSha1 { get; init; } = [];

    public IReadOnlyList<string> IntermediateCaSha1 { get; init; } = [];

    public IReadOnlyList<string> WarnIfMissingEku { get; init; } = [];

    public string? DetachedPkcs7Content { get; init; }

    public bool WarnPca2010 { get; init; }

    public bool NoWarnPca2010 { get; init; }

    public bool VerifySealingSignatures { get; init; }

    public bool RustSipPeDigestCheck { get; init; }

    public bool RustSipScriptDigestCheck { get; init; }

    public bool RustSipMsiDigestCheck { get; init; }

    public bool RustSipEsdDigestCheck { get; init; }

    public bool RustSipMsixDigestCheck { get; init; }

    public bool RustSipCabDigestCheck { get; init; }

    public bool RustSipCatalogDigestCheck { get; init; }

    public bool RustSipAllDigestChecks { get; init; }

    public bool BiometricPolicy { get; init; }

    public bool EnclavePolicy { get; init; }

    public string? AnchorDir { get; init; }

    public IReadOnlyList<string> TrustedCa { get; init; } = [];

    public IReadOnlyList<string> AdditionalTrustedCa { get; init; } = [];

    public bool OnlineAia { get; init; }

    public string? AiaUrlOverride { get; init; }

    public bool OnlineOcsp { get; init; }

    public string? OcspUrlOverride { get; init; }

    /// <summary><c>off</c>, <c>best-effort</c>, or <c>require</c> when given.</summary>
    public string? RevocationMode { get; init; }

    public string? CrlUrlOverride { get; init; }

    public string? AsOf { get; init; }

    public string? AuthrootCab { get; init; }

    public string? ExpectAuthrootCabSha256 { get; init; }

    public bool VerboseChain { get; init; }

    public bool AllowLooseSigningCert { get; init; }

    public bool PreferTimestampSigningTime { get; init; }

    public bool RequireValidTimestamp { get; init; }

    public ulong OnlineTimeoutSecs { get; init; } = VerifyCommand.DefaultOnlineTimeoutSecs;

    public ulong OnlineMaxDownloadBytes { get; init; } = VerifyCommand.DefaultOnlineMaxDownloadBytes;

    public bool ArtifactSigning { get; init; }

    public IReadOnlyList<string> ArtifactSigningPublisherId { get; init; } = [];

    public IReadOnlyList<string> ArtifactSigningPrivateTrustRoot { get; init; } = [];

    public bool ArtifactSigningAllowMissingTimestamp { get; init; }

    public IReadOnlyList<string> Files { get; init; } = [];
}

/// <summary>
/// <c>psign-tool verify</c> (Rust <c>VerifyArgs</c> + <c>execute_portable_verify</c>): every native verify flag parses, the
/// portable backend routes each file to the matching <c>psign-tool portable verify-*</c> / <c>trust-verify-*</c> command.
/// </summary>
internal static class VerifyCommand
{
    public const ulong DefaultOnlineTimeoutSecs = 5;

    public const ulong DefaultOnlineMaxDownloadBytes = 1024 * 1024;

    public static void Register(CommandSpec root)
    {
        root.Sub("verify", "Verify embedded Authenticode signature on a file.", c =>
        {
            c.Choice("policy", ["default", "pa", "pg"], "default", "Verification policy mode.");
            c.Value("policy-guid", null, "Custom policy GUID for `--policy pg`.");
            c.Flag("revocation-check", "Enable revocation checks.").Alias("vr");
            c.Value("detached-pkcs7", null, "Optional detached PKCS#7 signature file.").Alias("p7s").Conflicts("catalog");
            c.Value("catalog", null, "Optional catalog file (native /c).").Alias("c").Conflicts("detached-pkcs7");
            c.Choice("catalog-search", ["all", "default-db", "system"], null, "Catalog database search mode (native /a, /ad, /as).");
            c.Value("catalog-database-guid", null, "Catalog database GUID (native /ag).").Alias("ag");
            c.Choice("catalog-hash-algorithm", ["sha1", "sha256"], "sha256", "Hash algorithm for catalog member lookup (native /hash).").Alias("hash");
            c.Value("os-version-check", null, "OS/platform validity context for catalog verification (native /o <ver>).");
            c.Flag("kernel-policy", "Verify using kernel-mode driver policy (native /kp).").Alias("kp");
            c.Flag("all-signatures", "Verify all signatures where available (native /all).").Alias("all");
            c.Flag("allow-test-root", "Allow test roots when building chain.").Alias("testroot");
            c.Flag("warn-if-not-timestamped", "Warn (exit code 2) if the signature is not timestamped (native /tw).").Alias("tw");
            c.Value("signature-index", null, "Verify only the signature at this index (native /ds).").Alias("ds").Validator = ClapU32Error;
            c.Flag("multiple-semantics", "Multiple verification semantics (native /ms) — compatibility flag.").Alias("ms");
            c.Flag("verify-pkcs7-file", "Treat input as PKCS#7-centric verification (native /p7) — limited parity.").Alias("p7");
            c.Flag("print-description", "Print description / URL when available (native /d; requires -v / --verbose like native).").Alias("d");
            c.Flag("verify-page-hashes", "Print and verify page hashes (native /ph; requires -v / --verbose like native).").Alias("ph");
            c.Value("chain-root-subject", null, "Require signing chain to a root whose subject contains this string (native /r).").Alias("r");
            c.Multi("signer-thumbprint-sha1", null, "Signer certificate SHA1 thumbprint(s); verification succeeds if any matches (native /sha1, repeatable).").Alias("sha1");
            c.Multi("intermediate-ca-sha1", null, "Intermediate CA certificate SHA1 thumbprint(s); at least one must appear in the chain (native /ca, repeatable).").Alias("ca");
            c.Multi("warn-if-missing-eku", null, "Emit warning (exit 2) if the signer cert lacks this EKU OID (native verify /u, repeatable).").Alias("u");
            c.Value("detached-pkcs7-content", null, "Content file for detached PKCS#7 verification (native /p7content); default is the first verify target path.").Alias("p7content");
            c.Flag("warn-pca-2010", "Warn (exit 2) if Microsoft Windows PCA 2010 appears in the chain (native /w2010pca).").Alias("w2010pca");
            c.Flag("no-warn-pca-2010", "Suppress PCA 2010 chain warnings, including driver-policy defaults (native /now2010pca).").Alias("now2010pca");
            c.Flag("verify-sealing-signatures", "Verify sealing signatures (native /sl) via WinTrust WSS_VERIFY_SEALING (embedded verify only).").Alias("sl");
            c.Flag("rust-sip-pe-digest-check", "After a successful embedded WinTrust verification, recompute the PE Authenticode digest in Rust (experimental).");
            c.Flag("rust-sip-script-digest-check", "After embedded WinTrust success on signed scripts, run the Rust digest heuristic vs PKCS#7 (experimental).");
            c.Flag("rust-sip-msi-digest-check", "After embedded WinTrust success on a signed .msi, run the Rust MSI SIP digest vs PKCS#7 (experimental).");
            c.Flag("rust-sip-esd-digest-check", "After embedded WinTrust success on a signed WIM/ESD file, run the Rust ESD SIP prefix digest vs PKCS#7 (experimental).");
            c.Flag("rust-sip-msix-digest-check", "After embedded WinTrust success on a signed MSIX/AppX, compare PKCS#7 APPX blob with Rust ZIP hashes (experimental).");
            c.Flag("rust-sip-cab-digest-check", "After embedded WinTrust success on a signed .cab, recompute the CAB MSCF digest in Rust vs PKCS#7 (experimental).");
            c.Flag("rust-sip-catalog-digest-check", "After embedded WinTrust success on a signed .cat, compare CMS eContent digest with PKCS#9 messageDigest (experimental).");
            c.Flag("rust-sip-all-digest-checks", "Shorthand: enable every --rust-sip-*-digest-check option above for embedded verify (experimental).");
            c.Flag("biometric-policy", "Verify with biometric signing policy (native /bp) — not implemented.").Alias("bp");
            c.Flag("enclave-policy", "Verify with enclave signing policy (native /enclave) — not implemented.").Alias("enclave");
            c.Value("anchor-dir", null, "Portable trust anchor directory (.crt/.cer/.pem); does not modify OS certificate stores.");
            c.Multi("trusted-ca", null, "Portable trust anchor CA certificate file; repeatable and does not modify OS certificate stores.");
            c.Multi("additional-trusted-ca", null, "Additional portable trust anchor CA certificate file; repeatable and preserves automatic anchors.");
            c.Flag("online-aia", "Portable trust: fetch missing issuers from AIA caIssuers HTTP URLs.");
            c.Value("aia-url-override", null, "Portable trust: deterministic AIA issuer URL override for local tests.");
            c.Flag("online-ocsp", "Portable trust: query OCSP responders while applying online revocation policy.");
            c.Value("ocsp-url-override", null, "Portable trust: deterministic OCSP responder URL override for local tests.");
            c.Choice("revocation-mode", TrustArgs.RevocationModes, null, "Portable trust: online revocation policy for CRL checks.");
            c.Value("crl-url-override", null, "Portable trust: deterministic CRL URL override for local tests.");
            c.Value("as-of", null, "Portable trust: fixed verification date (YYYY-MM-DD).");
            c.Value("authroot-cab", null, "Portable trust: ingest roots and disallowed CTL data from an AuthRoot-style CAB.");
            c.Value("expect-authroot-cab-sha256", null, "Portable trust: require the AuthRoot CAB SHA-256 before ingesting it.");
            c.Flag("verbose-chain", "Portable trust: print certificate-chain diagnostics.");
            c.Flag("allow-loose-signing-cert", "Portable trust: skip strict code-signing EKU/policy checks on the signing certificate.");
            c.Flag("prefer-timestamp-signing-time", "Portable trust: prefer embedded timestamp signing instants for chain validation.");
            c.Flag("require-valid-timestamp", "Portable trust: require a cryptographically valid timestamp when timestamp preference is enabled.");
            c.Value("online-timeout-secs", null, "Portable trust: timeout for online issuer, OCSP, and CRL HTTP requests.", "5").Unsigned();
            c.Value("online-max-download-bytes", null, "Portable trust: maximum bytes accepted for online issuer downloads.", "1048576").Unsigned();
            c.Flag("artifact-signing", "Require an Azure Artifact Signing signature: identity EKU, signer and timestamp chains pinned to Microsoft Identity Verification Root CA 2020, validity at the trusted timestamp.");
            c.Multi("artifact-signing-publisher-id", "ID", "Require this Artifact Signing publisher ID (certificate profile EKU suffix); repeatable, any match passes. Implies --artifact-signing.");
            c.Multi("artifact-signing-private-trust-root", "PATH", "Subscriber root for Private Trust / Public Trust Test signatures (PEM or DER); repeatable. Implies --artifact-signing.");
            c.Flag("artifact-signing-allow-missing-timestamp", "Accept Artifact Signing signatures without a timestamp (validated at the current time). Implies --artifact-signing.");
            c.Positionals.Add(new PositionalSpec("files", required: true, multiple: true) { ValueName = "FILES", Help = "Files to verify (native <filename(s)>; one or more trailing paths)." });
            c.Handler = p => PsignTool.PrintOutput(p, ExecutePortableVerify(Parse(p)));
        });
    }

    /// <summary>Build <see cref="VerifyArgs"/> from the parsed command.</summary>
    internal static VerifyArgs Parse(ParsedCommand p) => new()
    {
        Policy = p.Value("policy") ?? "default",
        PolicyGuid = p.Value("policy-guid"),
        RevocationCheck = p.Flag("revocation-check"),
        DetachedPkcs7 = p.Value("detached-pkcs7"),
        Catalog = p.Value("catalog"),
        CatalogSearch = p.Value("catalog-search"),
        CatalogDatabaseGuid = p.Value("catalog-database-guid"),
        CatalogHashAlgorithm = p.Value("catalog-hash-algorithm") ?? "sha256",
        OsVersionCheck = p.Value("os-version-check"),
        KernelPolicy = p.Flag("kernel-policy"),
        AllSignatures = p.Flag("all-signatures"),
        AllowTestRoot = p.Flag("allow-test-root"),
        WarnIfNotTimestamped = p.Flag("warn-if-not-timestamped"),
        SignatureIndex = p.Value("signature-index") is { } ds ? uint.Parse(ds.StartsWith('+') ? ds[1..] : ds, NumberStyles.None, CultureInfo.InvariantCulture) : null,
        MultipleSemantics = p.Flag("multiple-semantics"),
        VerifyPkcs7File = p.Flag("verify-pkcs7-file"),
        PrintDescription = p.Flag("print-description"),
        VerifyPageHashes = p.Flag("verify-page-hashes"),
        ChainRootSubject = p.Value("chain-root-subject"),
        SignerThumbprintSha1 = p.Values("signer-thumbprint-sha1").ToList(),
        IntermediateCaSha1 = p.Values("intermediate-ca-sha1").ToList(),
        WarnIfMissingEku = p.Values("warn-if-missing-eku").ToList(),
        DetachedPkcs7Content = p.Value("detached-pkcs7-content"),
        WarnPca2010 = p.Flag("warn-pca-2010"),
        NoWarnPca2010 = p.Flag("no-warn-pca-2010"),
        VerifySealingSignatures = p.Flag("verify-sealing-signatures"),
        RustSipPeDigestCheck = p.Flag("rust-sip-pe-digest-check"),
        RustSipScriptDigestCheck = p.Flag("rust-sip-script-digest-check"),
        RustSipMsiDigestCheck = p.Flag("rust-sip-msi-digest-check"),
        RustSipEsdDigestCheck = p.Flag("rust-sip-esd-digest-check"),
        RustSipMsixDigestCheck = p.Flag("rust-sip-msix-digest-check"),
        RustSipCabDigestCheck = p.Flag("rust-sip-cab-digest-check"),
        RustSipCatalogDigestCheck = p.Flag("rust-sip-catalog-digest-check"),
        RustSipAllDigestChecks = p.Flag("rust-sip-all-digest-checks"),
        BiometricPolicy = p.Flag("biometric-policy"),
        EnclavePolicy = p.Flag("enclave-policy"),
        AnchorDir = p.Value("anchor-dir"),
        TrustedCa = p.Values("trusted-ca").ToList(),
        AdditionalTrustedCa = p.Values("additional-trusted-ca").ToList(),
        OnlineAia = p.Flag("online-aia"),
        AiaUrlOverride = p.Value("aia-url-override"),
        OnlineOcsp = p.Flag("online-ocsp"),
        OcspUrlOverride = p.Value("ocsp-url-override"),
        RevocationMode = p.Value("revocation-mode"),
        CrlUrlOverride = p.Value("crl-url-override"),
        AsOf = p.Value("as-of"),
        AuthrootCab = p.Value("authroot-cab"),
        ExpectAuthrootCabSha256 = p.Value("expect-authroot-cab-sha256"),
        VerboseChain = p.Flag("verbose-chain"),
        AllowLooseSigningCert = p.Flag("allow-loose-signing-cert"),
        PreferTimestampSigningTime = p.Flag("prefer-timestamp-signing-time"),
        RequireValidTimestamp = p.Flag("require-valid-timestamp"),
        OnlineTimeoutSecs = ParseU64(p.Value("online-timeout-secs"), DefaultOnlineTimeoutSecs),
        OnlineMaxDownloadBytes = ParseU64(p.Value("online-max-download-bytes"), DefaultOnlineMaxDownloadBytes),
        ArtifactSigning = p.Flag("artifact-signing"),
        ArtifactSigningPublisherId = p.Values("artifact-signing-publisher-id").ToList(),
        ArtifactSigningPrivateTrustRoot = p.Values("artifact-signing-private-trust-root").ToList(),
        ArtifactSigningAllowMissingTimestamp = p.Flag("artifact-signing-allow-missing-timestamp"),
        Files = p.PosAll("files").ToList(),
    };

    /// <summary>clap <c>value_parser!(u32)</c> (an <c>i64</c> parse followed by a range check).</summary>
    private static string? ClapU32Error(string v)
    {
        if (OptionSpecExtensions.UnsignedError(v, long.MaxValue) is { } error)
        {
            return error;
        }

        var value = ulong.Parse(v.TrimStart('+'), NumberStyles.None, CultureInfo.InvariantCulture);
        return value > uint.MaxValue ? $"{value} is not in 0..=4294967295" : null;
    }

    private static ulong ParseU64(string? value, ulong defaultValue)
    {
        if (value is null)
        {
            return defaultValue;
        }

        var digits = value.StartsWith('+') ? value[1..] : value;
        if (!ulong.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new PsignException($"invalid unsigned integer value '{value}'");
        }

        return parsed;
    }

    /// <summary>Rust <c>execute_portable_verify</c>; returns the command stdout (inner portable commands print directly).</summary>
    internal static string ExecutePortableVerify(VerifyArgs args)
    {
        if (PortableVerifyUnsupported(args))
        {
            throw new PsignException(
                "--mode portable verify supports file verification and portable trust inputs; use `psign-tool portable ...` for lower-level diagnostic commands");
        }

        if (ArtifactSigningVerify.Requested(args))
        {
            // Same policy as Windows mode; it re-hashes each subject, so no separate digest pass.
            var output = ArtifactSigningVerify.VerifyTargets(args);
            if (args.Catalog is { } artifactCatalog)
            {
                foreach (var subject in args.Files)
                {
                    PsignTool.RunPortableArgs(["verify-catalog-member", "--catalog", artifactCatalog, "--", subject]);
                }
            }

            return output;
        }

        if (args.DetachedPkcs7 is { } signature)
        {
            if (args.Files.Count != 1)
            {
                throw new PsignException("--mode portable verify --detached-pkcs7 requires exactly one verify target");
            }

            var content = args.DetachedPkcs7Content ?? args.Files[0];
            var argv = new List<string> { "trust-verify-detached" };
            AppendPortableTrustArgs(args, argv);
            argv.Add("--");
            argv.Add(content);
            argv.Add(signature);
            PsignTool.RunPortableArgs(argv);
            return string.Empty;
        }

        if (args.Catalog is { } catalog)
        {
            if (args.CatalogHashAlgorithm != "sha256")
            {
                throw new PsignException(
                    "--mode portable verify --catalog derives each member digest algorithm from the catalog; --catalog-hash-algorithm must be sha256");
            }

            var trustArgv = new List<string> { "trust-verify-catalog" };
            AppendPortableTrustArgs(args, trustArgv);
            trustArgv.Add("--");
            trustArgv.Add(catalog);
            PsignTool.RunPortableArgs(trustArgv);

            foreach (var subject in args.Files)
            {
                PsignTool.RunPortableArgs(["verify-catalog-member", "--catalog", catalog, "--", subject]);
            }

            return string.Empty;
        }

        foreach (var path in args.Files)
        {
            var inferred = PortableCommandForPath(path);
            string command;
            if (PortableVerifyExplicitTrustRequested(args))
            {
                command = PortableExplicitTrustCommand(inferred)
                    ?? throw new PsignException($"--mode portable verify trust options are not supported for inferred command {inferred}");
            }
            else if (PortableAutoTrustEnabled())
            {
                command = PortableTrustCommandForVerifyCommand(inferred) ?? inferred;
            }
            else
            {
                command = inferred;
            }

            var argv = new List<string> { command };
            AppendPortableTrustArgs(args, argv);
            argv.Add("--");
            argv.Add(path);
            PsignTool.RunPortableArgs(argv);
        }

        return string.Empty;
    }

    /// <summary>Rust <c>portable_command_for_path</c>: map a verify target to its <c>psign-tool portable</c> command.</summary>
    internal static string PortableCommandForPath(string path)
    {
        var ext = RustText.ToAsciiLowercase(CliIo.RustExtension(path) ?? string.Empty);
        return ext switch
        {
            "exe" or "dll" or "sys" or "ocx" or "efi" or "winmd" => "verify-pe",
            "cab" => "verify-cab",
            "msi" or "msp" => "verify-msi",
            "wim" or "esd" => "verify-esd",
            "msix" or "appx" or "msixbundle" or "appxbundle" => "verify-msix",
            "eappx" or "eappxbundle" or "emsix" or "emsixbundle" => throw new PsignException(
                $"encrypted MSIX/AppX packages (.{ext}) require Windows AppxSip OS delegation; portable verify cannot rehash encrypted package stores for {path}"),
            "appxupload" or "msixupload" => throw new PsignException(
                $"MSIX/AppX upload bundles (.{ext}) are dotnet/SignTool-style packaging containers, not AppX SIP verify subjects; prepare nested packages with `psign-tool code` instead: {path}"),
            "zip" => "verify-zip",
            "cat" => "verify-catalog",
            "ps1" or "psd1" or "psm1" or "ps1xml" or "psc1" or "cdxml" or "mof" or "js" or "jse" or "vbs" or "vbe" or "wsf" => "verify-script",

            // Package signatures have no digest-only check; they always need trust inputs.
            "nupkg" or "snupkg" => "trust-verify-nupkg",
            "vsix" => "trust-verify-vsix",
            _ => throw new PsignException($"portable verify cannot infer a supported SIP format for {path}"),
        };
    }

    /// <summary>Rust <c>portable_verify_unsupported</c>: native-only verify options rejected by the portable backend.</summary>
    internal static bool PortableVerifyUnsupported(VerifyArgs args)
    {
        // Portable trust is Authenticode (`/pa`) policy; accept it explicitly with --artifact-signing so the same command
        // line works in both modes.
        bool paWithArtifactSigning = args.Policy == "pa" && ArtifactSigningVerify.Requested(args);
        return (args.Policy != "default" && !paWithArtifactSigning)
            || args.PolicyGuid is not null
            || args.RevocationCheck
            || args.CatalogSearch is not null
            || args.CatalogDatabaseGuid is not null
            || args.OsVersionCheck is not null
            || args.KernelPolicy
            || args.AllSignatures
            || args.AllowTestRoot
            || args.WarnIfNotTimestamped
            || args.SignatureIndex is not null
            || args.MultipleSemantics
            || args.VerifyPkcs7File
            || args.PrintDescription
            || args.VerifyPageHashes
            || args.ChainRootSubject is not null
            || args.SignerThumbprintSha1.Count > 0
            || args.IntermediateCaSha1.Count > 0
            || args.WarnIfMissingEku.Count > 0
            || (args.DetachedPkcs7Content is not null && args.DetachedPkcs7 is null)
            || args.WarnPca2010
            || args.NoWarnPca2010
            || args.VerifySealingSignatures
            || args.RustSipPeDigestCheck
            || args.RustSipScriptDigestCheck
            || args.RustSipMsiDigestCheck
            || args.RustSipEsdDigestCheck
            || args.RustSipMsixDigestCheck
            || args.RustSipCabDigestCheck
            || args.RustSipCatalogDigestCheck
            || args.RustSipAllDigestChecks
            || args.BiometricPolicy
            || args.EnclavePolicy;
    }

    /// <summary>Rust <c>append_portable_trust_args</c>.</summary>
    internal static void AppendPortableTrustArgs(VerifyArgs args, List<string> argv)
    {
        if (args.AnchorDir is { } dir)
        {
            argv.Add("--anchor-dir");
            argv.Add(dir);
        }

        foreach (var ca in args.TrustedCa)
        {
            argv.Add("--trusted-ca");
            argv.Add(ca);
        }

        foreach (var ca in args.AdditionalTrustedCa)
        {
            argv.Add("--additional-trusted-ca");
            argv.Add(ca);
        }

        if (args.AuthrootCab is { } cab)
        {
            argv.Add("--authroot-cab");
            argv.Add(cab);
        }

        if (args.ExpectAuthrootCabSha256 is { } expected)
        {
            argv.Add("--expect-authroot-cab-sha256");
            argv.Add(expected);
        }

        if (args.VerboseChain)
        {
            argv.Add("--verbose-chain");
        }

        if (args.AllowLooseSigningCert)
        {
            argv.Add("--allow-loose-signing-cert");
        }

        if (args.PreferTimestampSigningTime)
        {
            argv.Add("--prefer-timestamp-signing-time");
        }

        if (args.RequireValidTimestamp)
        {
            argv.Add("--require-valid-timestamp");
        }

        if (args.OnlineAia)
        {
            argv.Add("--online-aia");
        }

        if (args.AiaUrlOverride is { } aia)
        {
            argv.Add("--aia-url-override");
            argv.Add(aia);
        }

        if (args.OnlineOcsp)
        {
            argv.Add("--online-ocsp");
        }

        if (args.OcspUrlOverride is { } ocsp)
        {
            argv.Add("--ocsp-url-override");
            argv.Add(ocsp);
        }

        if (args.RevocationMode is { } mode)
        {
            argv.Add("--revocation-mode");
            argv.Add(mode);
        }

        if (args.CrlUrlOverride is { } crl)
        {
            argv.Add("--crl-url-override");
            argv.Add(crl);
        }

        if (args.AsOf is { } asOf)
        {
            argv.Add("--as-of");
            argv.Add(asOf);
        }

        if (args.OnlineTimeoutSecs != DefaultOnlineTimeoutSecs)
        {
            argv.Add("--online-timeout-secs");
            argv.Add(args.OnlineTimeoutSecs.ToString(CultureInfo.InvariantCulture));
        }

        if (args.OnlineMaxDownloadBytes != DefaultOnlineMaxDownloadBytes)
        {
            argv.Add("--online-max-download-bytes");
            argv.Add(args.OnlineMaxDownloadBytes.ToString(CultureInfo.InvariantCulture));
        }
    }

    /// <summary>Rust <c>portable_verify_explicit_trust_requested</c>.</summary>
    internal static bool PortableVerifyExplicitTrustRequested(VerifyArgs args) =>
        args.AnchorDir is not null
        || args.TrustedCa.Count > 0
        || args.AdditionalTrustedCa.Count > 0
        || args.AuthrootCab is not null
        || args.ExpectAuthrootCabSha256 is not null
        || args.VerboseChain
        || args.AllowLooseSigningCert
        || args.PreferTimestampSigningTime
        || args.RequireValidTimestamp
        || args.OnlineAia
        || args.AiaUrlOverride is not null
        || args.OnlineOcsp
        || args.OcspUrlOverride is not null
        || args.RevocationMode is not null
        || args.CrlUrlOverride is not null
        || args.AsOf is not null
        || args.OnlineTimeoutSecs != DefaultOnlineTimeoutSecs
        || args.OnlineMaxDownloadBytes != DefaultOnlineMaxDownloadBytes;

    /// <summary>Rust <c>portable_auto_trust_enabled</c> (<c>PSIGN_NO_AUTO_TRUST</c> unset).</summary>
    internal static bool PortableAutoTrustEnabled() => !AuthRootCache.IsAutoTrustDisabled();

    /// <summary>
    /// Rust <c>portable_explicit_trust_command</c>: trust command used when explicit trust inputs are given; also covers
    /// formats whose automatic (AuthRoot) routing stays digest-only.
    /// </summary>
    internal static string? PortableExplicitTrustCommand(string command) =>
        PortableTrustCommandForVerifyCommand(command) ?? command switch
        {
            "verify-script" => "trust-verify-script",
            "verify-msix" => "trust-verify-msix",
            "trust-verify-nupkg" => "trust-verify-nupkg",
            "trust-verify-vsix" => "trust-verify-vsix",
            _ => null,
        };

    /// <summary>Rust <c>portable_trust_command_for_verify_command</c>.</summary>
    internal static string? PortableTrustCommandForVerifyCommand(string command) => command switch
    {
        "verify-pe" => "trust-verify-pe",
        "verify-cab" => "trust-verify-cab",
        "verify-msi" => "trust-verify-msi",
        "verify-esd" => "trust-verify-esd",
        "verify-catalog" => "trust-verify-catalog",
        "verify-zip" => "trust-verify-zip",
        _ => null,
    };
}
