using System.Globalization;
using System.Text;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Verification;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>
/// The flattened <c>TrustVerifySharedArgs</c> clap group of the Rust portable CLI (anchors, AuthRoot, online revocation,
/// Artifact Signing) and helpers shared by the trust-backed commands.
/// </summary>
internal static class TrustArgs
{
    public static readonly string[] RevocationModes = ["off", "best-effort", "require"];

    /// <summary>Declare the shared trust options on <paramref name="c"/> (Rust <c>#[command(flatten)] shared: TrustVerifySharedArgs</c>).</summary>
    public static void Declare(CommandSpec c)
    {
        c.Value("anchor-dir", "DIR");
        c.Multi("trusted-ca", "PATH", "Trust this CA certificate file as an anchor (repeatable, PEM or DER).");
        c.Multi("additional-trusted-ca", "PATH", "Add a CA without replacing the selected or automatically discovered trust anchors (repeatable, PEM or DER).");
        c.Value("authroot-cab", "PATH");
        c.Value("expect-authroot-cab-sha256", "HEX64", "Require --authroot-cab file SHA-256 (64 lowercase hex chars) to match before ingest.");
        c.Flag("verbose-chain");
        c.Flag("allow-loose-signing-cert", "Skip picky's strict code signing checks on the signing certificate (ignore_signing_certificate_check).");
        c.Flag("prefer-timestamp-signing-time", "Prefer nested RFC3161 TSTInfo.genTime (unsigned attrs) and PKCS#9 signing-time for picky exact_date.");
        c.Flag("require-valid-timestamp", "With --prefer-timestamp-signing-time, fail when no usable timestamp token exists.");
        c.Value("as-of", "YYYY-MM-DD", "Use this UTC date (YYYY-MM-DD) for exact_date instead of wall clock (for expired fixtures / reproducible CI).");
        c.Flag("online-aia", "Fetch missing issuer certificates from AIA caIssuers HTTP URLs while building the chain.");
        c.Value("aia-url-override", "URL", "Deterministic AIA issuer URL override for local tests.");
        c.Flag("online-ocsp", "Query OCSP responders while applying online revocation policy.");
        c.Value("ocsp-url-override", "URL", "Deterministic OCSP responder URL override for local tests.");
        c.Choice("revocation-mode", RevocationModes, "off", "Online revocation policy for CRL checks.");
        c.Value("crl-url-override", "URL", "Deterministic CRL URL override for local tests.");
        c.Value("online-timeout-secs", null, "Timeout for online trust HTTP requests.", "5");
        c.Value("online-max-download-bytes", null, "Maximum bytes accepted for an online issuer certificate download.", "1048576");
        c.Flag("artifact-signing", "Validate as Azure Artifact Signing: identity EKU, signer and timestamp chains pinned to Microsoft Identity Verification Root CA 2020 (AuthRoot is not consulted), validity at the trusted timestamp.");
        c.Multi("artifact-signing-publisher-id", "ID", "Require this Artifact Signing publisher ID (certificate profile EKU suffix); repeatable, any match passes. Implies --artifact-signing.");
        c.Multi("artifact-signing-private-trust-root", "PATH", "Subscriber root for Private Trust / Public Trust Test signatures (PEM or DER); repeatable. Implies --artifact-signing.");
        c.Flag("artifact-signing-allow-missing-timestamp", "Accept Artifact Signing signatures without a timestamp (validated at the current time). Implies --artifact-signing.");
    }

    /// <summary>Parsed shared trust arguments.</summary>
    public static TrustVerifySharedArgs From(ParsedCommand p) => new()
    {
        AnchorDir = p.Value("anchor-dir"),
        TrustedCa = p.Values("trusted-ca").ToList(),
        AdditionalTrustedCa = p.Values("additional-trusted-ca").ToList(),
        AuthrootCab = p.Value("authroot-cab"),
        ExpectAuthrootCabSha256 = p.Value("expect-authroot-cab-sha256"),
        VerboseChain = p.Flag("verbose-chain"),
        AllowLooseSigningCert = p.Flag("allow-loose-signing-cert"),
        PreferTimestampSigningTime = p.Flag("prefer-timestamp-signing-time"),
        RequireValidTimestamp = p.Flag("require-valid-timestamp"),
        AsOf = p.Value("as-of"),
        OnlineAia = p.Flag("online-aia"),
        AiaUrlOverride = p.Value("aia-url-override"),
        OnlineOcsp = p.Flag("online-ocsp"),
        OcspUrlOverride = p.Value("ocsp-url-override"),
        RevocationMode = p.Value("revocation-mode") switch
        {
            "best-effort" => RevocationMode.BestEffort,
            "require" => RevocationMode.Require,
            _ => RevocationMode.Off,
        },
        CrlUrlOverride = p.Value("crl-url-override"),
        OnlineTimeoutSecs = ulong.Parse(p.Value("online-timeout-secs") ?? "5", NumberStyles.None, CultureInfo.InvariantCulture),
        OnlineMaxDownloadBytes = int.Parse(p.Value("online-max-download-bytes") ?? "1048576", NumberStyles.None, CultureInfo.InvariantCulture),
        ArtifactSigning = p.Flag("artifact-signing"),
        ArtifactSigningPublisherId = p.Values("artifact-signing-publisher-id").ToList(),
        ArtifactSigningPrivateTrustRoot = p.Values("artifact-signing-private-trust-root").ToList(),
        ArtifactSigningAllowMissingTimestamp = p.Flag("artifact-signing-allow-missing-timestamp"),
    };

    /// <summary>Rust <c>trust_verify_options_from_shared</c>, with verbose chain output routed to the CLI stderr.</summary>
    public static TrustVerifyPeOptions Options(TrustVerifySharedArgs shared) => shared.ToOptions() with { Log = StderrWriter.Instance };

    /// <summary>Rust <c>print_trust_ok</c>.</summary>
    public static void PrintOk(string prefix, TrustVerifyPeReport report)
    {
        foreach (var line in report.FormatOkLines(prefix))
        {
            Output.Line(line);
        }
    }

    /// <summary>Rust <c>verify_xml_signer_certificate_trust</c> (returns the anchor count).</summary>
    public static int VerifyXmlSignerTrust(byte[] certDer, TrustVerifySharedArgs shared) =>
        XmlSignerTrust.VerifyXmlSignerCertificateTrust(certDer, Options(shared));
}

/// <summary><c>eprintln!</c>-compatible <see cref="TextWriter"/> over <see cref="Output.ErrorWrite"/> (UTF-8, <c>\n</c>).</summary>
internal sealed class StderrWriter : TextWriter
{
    public static readonly StderrWriter Instance = new();

    private StderrWriter()
    {
        NewLine = "\n";
    }

    public override Encoding Encoding => Encoding.UTF8;

    public override void Write(char value) => Output.ErrorWrite(value.ToString());

    public override void Write(string? value)
    {
        if (value is not null)
        {
            Output.ErrorWrite(value);
        }
    }

    public override void WriteLine(string? value) => Output.ErrorWrite((value ?? string.Empty) + "\n");
}

/// <summary>Shared I/O helpers with Rust-compatible error contexts for the package commands.</summary>
internal static class CliIo
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary><c>std::fs::read_to_string(path).with_context(|| context)</c>.</summary>
    public static string ReadText(string path, string? context = null)
    {
        var bytes = Output.ReadFile(path, context ?? $"read {path}");
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new PsignException(context ?? $"read {path}", new PsignException("stream did not contain valid UTF-8"));
        }
    }

    /// <summary><c>std::fs::write(path, bytes).with_context(|| context)</c>.</summary>
    public static void Write(string path, ReadOnlySpan<byte> bytes, string? context = null) =>
        Output.WriteFile(path, bytes, context ?? $"write {path}");

    /// <summary>Write to <paramref name="output"/> when set, else raw bytes to stdout.</summary>
    public static void WriteOutputOrStdout(string? output, ReadOnlySpan<byte> bytes)
    {
        if (output is not null)
        {
            Write(output, bytes);
        }
        else
        {
            Output.Raw(bytes);
        }
    }

    /// <summary>
    /// Rust <c>Path::extension</c> (<c>None</c> for dot-files and names without a dot; <c>Some("")</c> for a trailing dot).
    /// </summary>
    public static string? RustExtension(string path)
    {
        var name = Path.GetFileName(path);
        if (string.IsNullOrEmpty(name) || name == "..")
        {
            return null;
        }

        int dot = name.LastIndexOf('.');
        if (dot <= 0)
        {
            return null;
        }

        return name[(dot + 1)..];
    }
}
