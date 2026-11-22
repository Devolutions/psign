using System.Reflection;
using System.Text;

namespace Devolutions.Psign.Server;

/// <summary>Outcome of command-line parsing: a parsed subcommand, or text to print with an exit code.</summary>
internal sealed record CliOutcome(string Command, Dictionary<string, string?> Values, string? Stdout, string? Stderr, int ExitCode)
{
    public static CliOutcome Print(string stdout) => new(string.Empty, [], stdout, null, 0);

    public static CliOutcome Fail(string stderr) => new(string.Empty, [], null, stderr, 2);

    public bool IsCommand => Command.Length != 0;
}

/// <summary>One long option of a subcommand (clap <c>Arg</c>); <see cref="ValueName"/> is <c>null</c> for flags.</summary>
internal sealed record OptSpec(string Long, string? ValueName, string[]? PossibleValues = null, bool IsU64 = false)
{
    public string Display => ValueName is null ? $"--{Long}" : $"--{Long} <{ValueName}>";
}

/// <summary>
/// Emulation of the clap 4 derive parser behind the Rust <c>psign-server</c> CLI: the same subcommands, options,
/// defaults, value validation, help / version output and error texts (including <c>tip:</c> suggestions computed with
/// Jaro similarity &gt; 0.7, usage lines listing the arguments used so far, and exit code 2).
/// </summary>
internal static class Cli
{
    private static readonly string[] Subcommands = ["timestamp-server", "pki-server", "azure-key-vault-server", "artifact-signing-server", "help"];

    internal static readonly string[] ServerStatusValues = ["granted", "rejection", "waiting"];
    internal static readonly string[] ResponseModeValues = ["valid", "bad-alg", "http-error", "malformed-der", "mismatched-imprint", "invalid-signature"];
    internal static readonly string[] OcspStatusValues = ["good", "revoked", "unknown"];
    internal static readonly string[] ArtifactResponseModeValues =
    [
        "valid", "sync-success", "body-id", "body-operation-id", "pem-chain", "http-error", "poll-http-error", "failed",
        "canceled", "malformed-json", "poll-malformed-json",
    ];

    private static readonly OptSpec Listen = new("listen", "LISTEN");
    private static readonly OptSpec MaxRequests = new("max-requests", "MAX_REQUESTS", IsU64: true);
    private static readonly OptSpec RootCertOutput = new("root-cert-output", "PATH");
    private static readonly OptSpec LeafCertOutput = new("leaf-cert-output", "PATH");

    internal static readonly Dictionary<string, OptSpec[]> Specs = new()
    {
        ["timestamp-server"] =
        [
            Listen,
            new("status", "STATUS", ServerStatusValues),
            new("response-mode", "RESPONSE_MODE", ResponseModeValues),
            new("gen-time", "GEN_TIME"),
            new("cert-output", "PATH"),
            new("tsa-cert-output", "PATH"),
            MaxRequests,
        ],
        ["pki-server"] =
        [
            Listen,
            RootCertOutput,
            LeafCertOutput,
            new("leaf-key-output", "PATH"),
            new("crl-revoke-leaf", null),
            new("ocsp-status", "OCSP_STATUS", OcspStatusValues),
            MaxRequests,
        ],
        ["azure-key-vault-server"] =
        [
            Listen,
            new("certificate-name", "CERTIFICATE_NAME"),
            new("key-name", "KEY_NAME"),
            new("version", "VERSION"),
            RootCertOutput,
            LeafCertOutput,
            MaxRequests,
        ],
        ["artifact-signing-server"] =
        [
            Listen,
            new("response-mode", "RESPONSE_MODE", ArtifactResponseModeValues),
            new("expect-signature-algorithm", "EXPECT_SIGNATURE_ALGORITHM"),
            new("expect-api-version", "EXPECT_API_VERSION"),
            new("expect-correlation-id", "EXPECT_CORRELATION_ID"),
            RootCertOutput,
            LeafCertOutput,
            MaxRequests,
        ],
    };

    /// <summary>Binary name shown in usage lines (clap uses the file name of <c>argv[0]</c>).</summary>
    internal static string BinName
    {
        get
        {
            var path = Environment.ProcessPath;
            var name = path is null ? null : Path.GetFileName(path);
            if (name is null || name.StartsWith("dotnet", StringComparison.OrdinalIgnoreCase) || name.StartsWith("testhost", StringComparison.OrdinalIgnoreCase))
            {
                return "psign-server";
            }

            return name;
        }
    }

    /// <summary><c>psign-server {version}</c> (package version without build metadata).</summary>
    internal static string VersionLine
    {
        get
        {
            var asm = typeof(Cli).Assembly;
            var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?? asm.GetName().Version?.ToString(3) ?? "0.0.0";
            int plus = info.IndexOf('+');
            return $"psign-server {(plus >= 0 ? info[..plus] : info)}\n";
        }
    }

    public static CliOutcome Parse(string[] args) => Parse(args, BinName);

    public static CliOutcome Parse(string[] args, string bin)
    {
        string Help(string text) => text.Replace("{bin}", bin);
        string topUsage = $"{bin} <COMMAND>";
        if (args.Length == 0)
        {
            return CliOutcome.Fail(Help(HelpTexts.Top));
        }

        // The top level only accepts -h / -V or a subcommand, so the first token always decides.
        const int i = 0;
        {
            var a = args[i];
            if (a.StartsWith("--", StringComparison.Ordinal) && a.Length > 2)
            {
                var (name, value) = SplitLong(a);
                if (name is "help" or "version")
                {
                    if (value is not null)
                    {
                        return CliOutcome.Fail(Error($"unexpected value '{value}' for '--{name}' found; no more were expected", null, $"{bin} --{name} <COMMAND>"));
                    }

                    return CliOutcome.Print(name == "help" ? Help(HelpTexts.Top) : VersionLine);
                }

                var suggestion = DidYouMean(name, ["help", "version"]).LastOrDefault();
                var usage = suggestion is null ? topUsage : $"{bin} --{suggestion} <COMMAND>";
                var tip = suggestion is null ? null : $"a similar argument exists: '--{suggestion}'";
                return CliOutcome.Fail(Error($"unexpected argument '{a}' found", tip, usage));
            }

            if (a.StartsWith('-') && a.Length > 1 && a != "--")
            {
                // Short clusters are processed left to right; the first character decides.
                char c = a[1];
                if (c == 'h')
                {
                    return CliOutcome.Print(Help(HelpTexts.Top));
                }

                if (c == 'V')
                {
                    return CliOutcome.Print(VersionLine);
                }

                return CliOutcome.Fail(Error($"unexpected argument '-{c}' found", null, topUsage));
            }

            if (a == "help")
            {
                return HelpSubcommand(args[(i + 1)..], bin);
            }

            if (Specs.ContainsKey(a))
            {
                return ParseSubcommand(a, args[(i + 1)..], bin);
            }

            var candidates = DidYouMean(a, Subcommands);
            string? subTip = candidates.Count switch
            {
                0 => null,
                1 => $"a similar subcommand exists: '{candidates[0]}'",
                _ => "some similar subcommands exist: " + string.Join(", ", candidates.Select(c => $"'{c}'")),
            };
            return CliOutcome.Fail(Error($"unrecognized subcommand '{a}'", subTip, topUsage));
        }
    }

    private static CliOutcome HelpSubcommand(string[] rest, string bin)
    {
        string current = string.Empty;
        foreach (var a in rest)
        {
            if (current.Length == 0 && Subcommands.Contains(a))
            {
                current = a;
                continue;
            }

            var usage = current switch
            {
                "" => $"{bin} <COMMAND>",
                "help" => $"{bin} help [COMMAND]...",
                _ => $"{bin} {current} [OPTIONS]",
            };
            var sb = new StringBuilder($"error: unrecognized subcommand '{a}'\n\nUsage: {usage}\n");
            if (current != "help")
            {
                sb.Append("\nFor more information, try '--help'.\n");
            }

            return CliOutcome.Fail(sb.ToString());
        }

        return CliOutcome.Print(LongHelp(current).Replace("{bin}", bin));
    }

    private static string LongHelp(string command) => command switch
    {
        "timestamp-server" => HelpTexts.TimestampLong,
        "pki-server" => HelpTexts.Pki,
        "azure-key-vault-server" => HelpTexts.KeyVault,
        "artifact-signing-server" => HelpTexts.ArtifactLong,
        "help" => HelpTexts.HelpHelp,
        _ => HelpTexts.Top,
    };

    private static string ShortHelp(string command) => command switch
    {
        "timestamp-server" => HelpTexts.TimestampShort,
        "artifact-signing-server" => HelpTexts.ArtifactShort,
        _ => LongHelp(command),
    };

    private static (string Name, string? Value) SplitLong(string token)
    {
        var body = token[2..];
        int eq = body.IndexOf('=');
        return eq >= 0 ? (body[..eq], body[(eq + 1)..]) : (body, null);
    }

    private static bool LooksLikeFlag(string token) => token.StartsWith('-') && token.Length > 1;

    private static CliOutcome ParseSubcommand(string command, string[] rest, string bin)
    {
        var specs = Specs[command];
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);
        var used = new List<OptSpec>();
        OptSpec? pending = null;
        bool afterDoubleDash = false;
        string Usage(IEnumerable<OptSpec> args)
        {
            var list = args.ToList();
            return list.Count == 0
                ? $"{bin} {command} [OPTIONS]"
                : $"{bin} {command} " + string.Join(' ', list.Select(a => a.Display));
        }

        string MissingValue(OptSpec opt)
        {
            var sb = new StringBuilder($"error: a value is required for '{opt.Display}' but none was supplied\n");
            if (opt.PossibleValues is { } pv)
            {
                sb.Append("  [possible values: ").Append(string.Join(", ", pv)).Append("]\n");
            }

            sb.Append("\nFor more information, try '--help'.\n");
            return sb.ToString();
        }

        string? Assign(OptSpec opt, string value)
        {
            if (opt.PossibleValues is { } pv && !pv.Contains(value))
            {
                var sb = new StringBuilder($"error: invalid value '{value}' for '{opt.Display}'\n");
                sb.Append("  [possible values: ").Append(string.Join(", ", pv)).Append("]\n");
                var best = DidYouMean(value, pv).LastOrDefault();
                if (best is not null)
                {
                    sb.Append($"\n  tip: a similar value exists: '{best}'\n");
                }

                sb.Append("\nFor more information, try '--help'.\n");
                return sb.ToString();
            }

            if (opt.IsU64 && RustU64Error(value) is { } err)
            {
                return $"error: invalid value '{value}' for '{opt.Display}': {err}\n\nFor more information, try '--help'.\n";
            }

            values[opt.Long] = value;
            used.Add(opt);
            return null;
        }

        string? Duplicate(OptSpec opt) =>
            values.ContainsKey(opt.Long)
                ? Error($"the argument '{opt.Display}' cannot be used multiple times", null, Usage([]))
                : null;

        foreach (var token in rest)
        {
            if (pending is not null)
            {
                if (afterDoubleDash || !LooksLikeFlag(token))
                {
                    var err = Assign(pending, token);
                    if (err is not null)
                    {
                        return CliOutcome.Fail(err);
                    }

                    pending = null;
                    continue;
                }

                // A flag-like token ends the pending option: unknown flags win, known ones report the missing value.
                if (!IsKnownFlag(specs, token))
                {
                    return CliOutcome.Fail(UnknownArgument(token, specs, used, Usage));
                }

                return CliOutcome.Fail(MissingValue(pending));
            }

            if (afterDoubleDash || !LooksLikeFlag(token))
            {
                return CliOutcome.Fail(Error($"unexpected argument '{token}' found", null, Usage([])));
            }

            if (token == "--")
            {
                afterDoubleDash = true;
                continue;
            }

            if (token.StartsWith("--", StringComparison.Ordinal))
            {
                var (name, value) = SplitLong(token);
                if (name == "help")
                {
                    if (value is not null)
                    {
                        return CliOutcome.Fail(Error($"unexpected value '{value}' for '--help' found; no more were expected", null, $"{bin} {command} --help"));
                    }

                    return CliOutcome.Print(LongHelp(command).Replace("{bin}", bin));
                }

                var opt = specs.FirstOrDefault(s => s.Long == name);
                if (opt is null)
                {
                    return CliOutcome.Fail(UnknownArgument(token, specs, used, Usage));
                }

                if (Duplicate(opt) is { } dup)
                {
                    return CliOutcome.Fail(dup);
                }

                if (opt.ValueName is null)
                {
                    if (value is not null)
                    {
                        return CliOutcome.Fail(Error($"unexpected value '{value}' for '{opt.Display}' found; no more were expected", null, Usage([opt])));
                    }

                    values[opt.Long] = null;
                    used.Add(opt);
                    continue;
                }

                if (value is not null)
                {
                    var err = Assign(opt, value);
                    if (err is not null)
                    {
                        return CliOutcome.Fail(err);
                    }

                    continue;
                }

                pending = opt;
                continue;
            }

            if (token[1] == 'h')
            {
                return CliOutcome.Print(ShortHelp(command).Replace("{bin}", bin));
            }

            return CliOutcome.Fail(Error($"unexpected argument '-{token[1]}' found", null, Usage([])));
        }

        if (pending is not null)
        {
            return CliOutcome.Fail(MissingValue(pending));
        }

        return new CliOutcome(command, values, null, null, 0);
    }

    private static bool IsKnownFlag(OptSpec[] specs, string token)
    {
        if (token == "--")
        {
            return true;
        }

        if (token.StartsWith("--", StringComparison.Ordinal))
        {
            var (name, _) = SplitLong(token);
            return name == "help" || specs.Any(s => s.Long == name);
        }

        return token[1] == 'h';
    }

    private static string UnknownArgument(string token, OptSpec[] specs, List<OptSpec> used, Func<IEnumerable<OptSpec>, string> usage)
    {
        if (!token.StartsWith("--", StringComparison.Ordinal))
        {
            return Error($"unexpected argument '-{token[1]}' found", null, usage([]));
        }

        var (name, _) = SplitLong(token);
        var longs = specs.Select(s => s.Long).Append("help").ToList();
        var suggestion = DidYouMean(name, longs).LastOrDefault();
        if (suggestion is null)
        {
            return Error($"unexpected argument '{token}' found", null, usage(used));
        }

        var suggestedSpec = specs.FirstOrDefault(s => s.Long == suggestion) ?? new OptSpec("help", null);
        var shown = used.ToList();
        if (!shown.Contains(suggestedSpec))
        {
            shown.Add(suggestedSpec);
        }

        return Error($"unexpected argument '{token}' found", $"a similar argument exists: '--{suggestion}'", usage(shown));
    }

    private static string Error(string message, string? tip, string? usage)
    {
        var sb = new StringBuilder("error: ").Append(message).Append('\n');
        if (tip is not null)
        {
            sb.Append("\n  tip: ").Append(tip).Append('\n');
        }

        if (usage is not null)
        {
            sb.Append("\nUsage: ").Append(usage).Append('\n');
        }

        sb.Append("\nFor more information, try '--help'.\n");
        return sb.ToString();
    }

    /// <summary>Rust <c>u64::from_str</c> error text, or <c>null</c> when the value parses.</summary>
    internal static string? RustU64Error(string value)
    {
        if (value.Length == 0)
        {
            return "cannot parse integer from empty string";
        }

        var digits = value.StartsWith('+') ? value[1..] : value;
        if (digits.Length == 0 && value.Length == 1)
        {
            return "invalid digit found in string";
        }

        ulong acc = 0;
        foreach (var c in digits)
        {
            if (c is < '0' or > '9')
            {
                return "invalid digit found in string";
            }

            try
            {
                acc = checked((acc * 10) + (ulong)(c - '0'));
            }
            catch (OverflowException)
            {
                return "number too large to fit in target type";
            }
        }

        return null;
    }

    /// <summary>clap <c>did_you_mean</c>: candidates with Jaro similarity &gt; 0.7, ascending by confidence (stable).</summary>
    internal static List<string> DidYouMean(string value, IEnumerable<string> possible)
    {
        return possible
            .Select((p, idx) => (Confidence: Jaro(value, p), Value: p, Index: idx))
            .Where(c => c.Confidence > 0.7)
            .OrderBy(c => c.Confidence)
            .ThenBy(c => c.Index)
            .Select(c => c.Value)
            .ToList();
    }

    /// <summary><c>strsim::jaro</c> over Unicode scalar values.</summary>
    internal static double Jaro(string a, string b)
    {
        var ac = a.EnumerateRunes().ToArray();
        var bc = b.EnumerateRunes().ToArray();
        if (ac.Length == 0 && bc.Length == 0)
        {
            return 1.0;
        }

        if (ac.Length == 0 || bc.Length == 0)
        {
            return 0.0;
        }

        int searchRange = Math.Max(ac.Length, bc.Length) / 2;
        searchRange = Math.Max(0, searchRange - 1);
        var aFlags = new bool[ac.Length];
        var bFlags = new bool[bc.Length];
        int matches = 0;
        for (int i = 0; i < ac.Length; i++)
        {
            int minBound = i > searchRange ? i - searchRange : 0;
            int maxBound = Math.Min(bc.Length, i + searchRange + 1);
            for (int j = 0; j < maxBound; j++)
            {
                if (minBound <= j && ac[i] == bc[j] && !bFlags[j])
                {
                    aFlags[i] = true;
                    bFlags[j] = true;
                    matches++;
                    break;
                }
            }
        }

        int transpositions = 0;
        if (matches != 0)
        {
            int bi = 0;
            for (int i = 0; i < ac.Length; i++)
            {
                if (!aFlags[i])
                {
                    continue;
                }

                while (bi < bc.Length && !bFlags[bi])
                {
                    bi++;
                }

                if (bi < bc.Length)
                {
                    if (ac[i] != bc[bi])
                    {
                        transpositions++;
                    }

                    bi++;
                }
            }
        }

        transpositions /= 2;
        if (matches == 0)
        {
            return 0.0;
        }

        return (((double)matches / ac.Length) + ((double)matches / bc.Length) + ((double)(matches - transpositions) / matches)) / 3.0;
    }
}
