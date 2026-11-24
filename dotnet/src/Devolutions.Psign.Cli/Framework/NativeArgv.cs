namespace Devolutions.Psign.Cli.Framework;

/// <summary>
/// Normalize Windows-style <c>signtool.exe</c> argv (<c>/pa</c>, <c>/fd sha256</c>, ...) into GNU-style tokens
/// (port of <c>src/native_argv.rs</c>). Unknown slash-prefixed tokens pass through so Unix absolute paths still work.
/// </summary>
public static class NativeArgv
{
    private enum Verb
    {
        CertStore,
        Verify,
        Sign,
        Timestamp,
        Catdb,
        Remove,
        Rdp,
    }

    /// <summary>Mapping row: replacement tokens, values consumed, default for a missing value, lowercase the value.</summary>
    private sealed record Map(string[] Pieces, int Eat = 0, string Default = "", bool Lower = false);

    private static Map F(params string[] pieces) => new(pieces);

    private static Map V(string flag, string def = "", bool lower = false) => new([flag], 1, def, lower);

    private static readonly Dictionary<string, Map> VerifyMap = new()
    {
        ["pa"] = F("--policy", "pa"),
        ["kp"] = F("--kp"),
        ["all"] = F("--all"),
        ["tw"] = F("--tw"),
        ["ms"] = F("--ms"),
        ["p7"] = F("--p7"),
        ["d"] = F("--d"),
        ["ph"] = F("--ph"),
        ["vr"] = F("--vr"),
        ["testroot"] = F("--testroot"),
        ["w2010pca"] = F("--w2010pca"),
        ["now2010pca"] = F("--now2010pca"),
        ["sl"] = F("--sl"),
        ["bp"] = F("--bp"),
        ["enclave"] = F("--enclave"),
        ["a"] = F("--catalog-search", "all"),
        ["ad"] = F("--catalog-search", "default-db"),
        ["as"] = F("--catalog-search", "system"),
        ["pg"] = new(["--policy", "pg", "--policy-guid"], 1),
        ["ag"] = V("--ag"),
        ["c"] = V("--c"),
        ["hash"] = V("--hash", "sha256", lower: true),
        ["o"] = V("--os-version-check"),
        ["r"] = V("--r"),
        ["sha1"] = V("--sha1"),
        ["ca"] = V("--ca"),
        ["u"] = V("--u"),
        ["ds"] = V("--ds", "0"),
        ["p7content"] = V("--p7content"),
        ["p7s"] = V("--p7s"),
        ["rust-sip-pe-digest-check"] = F("--rust-sip-pe-digest-check"),
        ["rust-sip-script-digest-check"] = F("--rust-sip-script-digest-check"),
        ["rust-sip-msi-digest-check"] = F("--rust-sip-msi-digest-check"),
        ["rust-sip-esd-digest-check"] = F("--rust-sip-esd-digest-check"),
        ["rust-sip-msix-digest-check"] = F("--rust-sip-msix-digest-check"),
        ["rust-sip-cab-digest-check"] = F("--rust-sip-cab-digest-check"),
        ["rust-sip-catalog-digest-check"] = F("--rust-sip-catalog-digest-check"),
        ["rust-sip-all-digest-checks"] = F("--rust-sip-all-digest-checks"),
    };

    private static readonly Dictionary<string, Map> CertStoreMap = new()
    {
        ["sm"] = F("--sm"),
        ["p"] = V("--p"),
        ["s"] = V("--s", "MY"),
        ["sha1"] = V("--sha1"),
    };

    private static readonly Dictionary<string, Map> SignMap = new()
    {
        ["a"] = F("--a"),
        ["sm"] = F("--sm"),
        ["as"] = F("--as"),
        ["ph"] = F("--ph"),
        ["nph"] = F("--nph"),
        ["uw"] = F("--uw"),
        ["dxml"] = F("--dxml"),
        ["ds"] = F("--ds"),
        ["f"] = V("--f"),
        ["p"] = V("--p"),
        ["n"] = V("--n"),
        ["i"] = V("--i"),
        ["sha1"] = V("--sha1"),
        ["csp"] = V("--csp"),
        ["kc"] = V("--kc"),
        ["s"] = V("--s", "MY"),
        ["fd"] = V("--fd", "sha256", lower: true),
        ["tr"] = V("--tr"),
        ["tseal"] = V("--tseal"),
        ["t"] = V("--t"),
        ["td"] = V("--td", "sha256", lower: true),
        ["d"] = V("--d"),
        ["du"] = V("--du"),
        ["ac"] = V("--ac"),
        ["r"] = V("--r"),
        ["u"] = V("--u"),
        ["dlib"] = V("--dlib"),
        ["dmdf"] = V("--dmdf"),
        ["dg"] = V("--dg"),
        ["di"] = V("--di"),
        ["p7"] = V("--p7"),
        ["p7co"] = V("--p7co"),
        ["p7ce"] = V("--p7ce"),
        ["c"] = V("--certificate-template"),
        ["fdchw"] = F("--fdchw"),
        ["tdchw"] = F("--tdchw"),
        ["rmc"] = F("--rmc"),
        ["seal"] = F("--seal"),
        ["itos"] = F("--itos"),
        ["force"] = F("--force"),
        ["nosealwarn"] = F("--nosealwarn"),
        ["noenclavewarn"] = F("--noenclavewarn"),
        ["rust-sip"] = V("--rust-sip", "pe", lower: true),
    };

    private static readonly Dictionary<string, Map> TimestampMap = new()
    {
        ["tr"] = V("--tr"),
        ["tseal"] = V("--tseal"),
        ["t"] = V("--t"),
        ["td"] = V("--td", "sha256", lower: true),
        ["tp"] = V("--tp", "0"),
        ["p7"] = F("--p7"),
        ["force"] = F("--force"),
        ["nosealwarn"] = F("--nosealwarn"),
    };

    private static readonly Dictionary<string, Map> CatdbMap = new()
    {
        ["d"] = F("--d"),
        ["g"] = V("--g"),
        ["r"] = F("--r"),
        ["u"] = F("--u"),
    };

    private static readonly Dictionary<string, Map> RemoveMap = new()
    {
        ["s"] = F("--s"),
        ["c"] = F("--c"),
        ["u"] = F("--u"),
    };

    private static readonly Dictionary<string, Map> RdpMap = new()
    {
        ["sha1"] = V("--sha1"),
        ["sha256"] = V("--sha256"),
        ["l"] = F("--dry-run"),
    };

    private static Verb? IsVerb(string s) => s.ToLowerInvariant() switch
    {
        "verify" => Verb.Verify,
        "cert-store" or "certstore" => Verb.CertStore,
        "sign" => Verb.Sign,
        "timestamp" => Verb.Timestamp,
        "catdb" => Verb.Catdb,
        "remove" => Verb.Remove,
        "rdp" => Verb.Rdp,
        _ => null,
    };

    private static bool IsSlashSwitch(string s) => s.Length >= 2 && s[0] == '/' && !s.StartsWith("//", StringComparison.Ordinal);

    private static string StripSlash(string s) => s.TrimStart('/').ToLowerInvariant();

    private static string[]? TryGlobal(string arg)
    {
        if (!IsSlashSwitch(arg))
        {
            return null;
        }

        return StripSlash(arg) switch
        {
            "q" => ["-q"],
            "v" => ["-v"],
            "debug" => ["--debug"],
            _ => null,
        };
    }

    private static (List<string> Pieces, int Eat) Translate(Verb verb, string key, string? next, string? next2)
    {
        if (verb == Verb.Sign && key == "sa")
        {
            var oid = next?.Trim() ?? string.Empty;
            var val = next2?.Trim() ?? string.Empty;
            return oid.Length == 0 || val.Length == 0 ? ([], 0) : (["--sign-auth", oid, val], 2);
        }

        var map = verb switch
        {
            Verb.Verify => VerifyMap,
            Verb.CertStore => CertStoreMap,
            Verb.Sign => SignMap,
            Verb.Timestamp => TimestampMap,
            Verb.Catdb => CatdbMap,
            Verb.Remove => RemoveMap,
            _ => RdpMap,
        };
        if (!map.TryGetValue(key, out var m))
        {
            return ([], 0);
        }

        var pieces = new List<string>(m.Pieces);
        if (m.Eat == 1)
        {
            var v = next is null ? m.Default : next.Trim();
            pieces.Add(m.Lower ? v.ToLowerInvariant() : v);
        }

        return (pieces, m.Eat);
    }

    /// <summary>Normalize argv (excluding the executable).</summary>
    public static List<string> Normalize(IReadOnlyList<string> args)
    {
        if (args.Count < 1)
        {
            return args.ToList();
        }

        int verbIdx = -1;
        Verb verb = Verb.Verify;
        for (int i = 0; i < args.Count; i++)
        {
            var token = args[i].Trim();
            if (token.Equals("--mode", StringComparison.Ordinal))
            {
                i++;
                continue;
            }

            if (token.ToLowerInvariant() is "portable" or "code" or "artifact-signing-submit" or "inspect-signature")
            {
                break;
            }

            if (IsVerb(token) is { } v)
            {
                verbIdx = i;
                verb = v;
                break;
            }
        }

        if (verbIdx < 0)
        {
            return args.ToList();
        }

        var output = new List<string>(args.Count + 4);
        for (int i = 0; i < verbIdx; i++)
        {
            output.AddRange(TryGlobal(args[i]) ?? [args[i]]);
        }

        output.Add(args[verbIdx].ToLowerInvariant());
        int j = verbIdx + 1;
        while (j < args.Count)
        {
            var arg = args[j];
            if (TryGlobal(arg) is { } g)
            {
                output.AddRange(g);
                j++;
                continue;
            }

            if (!IsSlashSwitch(arg))
            {
                output.Add(arg);
                j++;
                continue;
            }

            var key = StripSlash(arg);
            var next = j + 1 < args.Count ? args[j + 1] : null;
            var next2 = j + 2 < args.Count ? args[j + 2] : null;
            var (pieces, eat) = Translate(verb, key, next, next2);
            if (pieces.Count == 0)
            {
                output.Add(arg);
                j++;
                continue;
            }

            output.AddRange(pieces);
            j += 1 + eat;
        }

        return output;
    }
}
