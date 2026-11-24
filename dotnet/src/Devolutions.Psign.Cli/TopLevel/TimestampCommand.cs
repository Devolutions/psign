using System.Globalization;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Pe;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>Parsed <c>psign-tool timestamp</c> arguments (Rust <c>cli::TimestampArgs</c>).</summary>
internal sealed record TimestampArgs
{
    public string? Rfc3161Url { get; init; }

    public string? LegacyUrl { get; init; }

    public string? SealTimestampUrl { get; init; }

    /// <summary><c>sha1</c>, <c>sha256</c>, <c>sha384</c>, <c>sha512</c>, or <c>cert-hash</c> when given.</summary>
    public string? Digest { get; init; }

    public uint? SignatureIndex { get; init; }

    public bool TimestampPkcs7Files { get; init; }

    public bool RemoveSeal { get; init; }

    public bool NoSealWarn { get; init; }

    public IReadOnlyList<string> Files { get; init; } = [];
}

/// <summary>
/// <c>psign-tool timestamp</c> in portable mode (Rust <c>cli::TimestampArgs</c> + <c>execute_portable_timestamp</c>): RFC 3161
/// timestamping of the primary embedded PE/WinMD signature through <c>psign-tool portable timestamp-pe-rfc3161</c>.
/// </summary>
internal static class TimestampCommand
{
    public static void Register(CommandSpec root)
    {
        root.Sub("timestamp", "Add timestamp to an existing signature.", c =>
        {
            c.Value("rfc3161-url", null, "RFC3161 timestamp URL (native /tr).").Alias("tr").Conflicts("legacy-url", "seal-timestamp-url");
            c.Value("legacy-url", null, "Legacy Authenticode timestamp URL (native /t).").Alias("t").Conflicts("rfc3161-url", "seal-timestamp-url");
            c.Value("seal-timestamp-url", null, "RFC3161 timestamp URL for sealed files (native timestamp /tseal).").Alias("tseal").Conflicts("rfc3161-url", "legacy-url");
            SignCommand.DigestChoice(c, "digest", null, "Timestamp digest algorithm (native /td; required with RFC3161 /tr and /tseal).").Alias("td");
            c.Value("signature-index", null, "Timestamp the signature at this index (native /tp).").Alias("tp").Validator = ClapU32Error;
            c.Flag("timestamp-pkcs7-files", "Timestamp PKCS#7 files (native /p7) — not implemented.").Alias("p7");
            c.Flag("remove-seal", "Remove sealing signature before timestamping (native /force) — not implemented.").Alias("force");
            c.Flag("no-seal-warn", "Sealing-removal warnings do not affect exit code (native /nosealwarn) — not implemented.").Alias("nosealwarn");
            c.Positionals.Add(new PositionalSpec("files", required: true, multiple: true)
            {
                ValueName = "FILES",
                Help = "File(s) with an existing signature to timestamp (native trailing <filename(s)>).",
            });
            c.Handler = p =>
            {
                ExecutePortableTimestamp(Parse(p));
                return PsignTool.PrintOutput(p, string.Empty);
            };
        });
    }

    internal static TimestampArgs Parse(ParsedCommand p) => new()
    {
        Rfc3161Url = p.Value("rfc3161-url"),
        LegacyUrl = p.Value("legacy-url"),
        SealTimestampUrl = p.Value("seal-timestamp-url"),
        Digest = p.Value("digest"),
        SignatureIndex = p.Value("signature-index") is { } tp ? uint.Parse(tp.StartsWith('+') ? tp[1..] : tp, NumberStyles.None, CultureInfo.InvariantCulture) : null,
        TimestampPkcs7Files = p.Flag("timestamp-pkcs7-files"),
        RemoveSeal = p.Flag("remove-seal"),
        NoSealWarn = p.Flag("no-seal-warn"),
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

    /// <summary>Rust <c>execute_portable_timestamp</c>.</summary>
    internal static void ExecutePortableTimestamp(TimestampArgs args)
    {
        if (args.LegacyUrl is not null)
        {
            throw new PsignException("--mode portable timestamp does not support legacy --legacy-url (/t); use RFC3161 --rfc3161-url (/tr)");
        }

        if (args.SealTimestampUrl is not null || args.RemoveSeal || args.NoSealWarn)
        {
            throw new PsignException(
                "--mode portable timestamp does not support sealing (--seal-timestamp-url (/tseal), --remove-seal (/force), or --no-seal-warn (/nosealwarn))");
        }

        if (args.TimestampPkcs7Files)
        {
            throw new PsignException(
                "--mode portable timestamp does not support --timestamp-pkcs7-files (/p7); only embedded PE/WinMD signatures are supported");
        }

        if (args.SignatureIndex is not null)
        {
            throw new PsignException(
                "--mode portable timestamp does not support --signature-index (/tp); portable RFC3161 insertion safely timestamps only the primary embedded signature");
        }

        var url = args.Rfc3161Url
            ?? throw new PsignException("--mode portable timestamp requires RFC3161 --rfc3161-url (/tr) and --digest (/td)");
        var digest = args.Digest switch
        {
            "sha1" or "sha256" or "sha384" or "sha512" => args.Digest,
            "cert-hash" => throw new PsignException("--mode portable timestamp does not support --digest certHash; use sha1, sha256, sha384, or sha512"),
            _ => throw new PsignException("--mode portable timestamp requires --digest (/td) with --rfc3161-url (/tr)"),
        };

        foreach (var path in args.Files)
        {
            byte[] image;
            try
            {
                image = File.ReadAllBytes(path);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
            {
                throw new PsignException($"read {path}: {IoErrorText.Message(e)}");
            }

            try
            {
                PeAuthenticode.NthPkcs7(image, 0);
            }
            catch (Exception e) when (e is PsignException or InvalidDataException or ArgumentException or IndexOutOfRangeException or OverflowException or System.Formats.Asn1.AsnContentException)
            {
                // Rust formats the inner error with `{e}`: only its outermost message.
                throw new PsignException(
                    $"--mode portable timestamp supports only PE/WinMD files with a primary embedded Authenticode signature ({path}): {e.Message}");
            }

            PsignTool.RunPortableArgs(["timestamp-pe-rfc3161", "--rfc3161-url", url, "--digest", digest, "--output", path, "--", path]);
        }
    }
}
