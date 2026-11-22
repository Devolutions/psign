using System.Globalization;
using System.Text;

namespace Devolutions.Psign.Cli.Framework;

/// <summary>Usage error (clap exits with status 2).</summary>
public sealed class UsageException : Exception
{
    public UsageException(string message, string? usage)
        : base(message)
    {
        Usage = usage;
    }

    public string? Usage { get; }
}

/// <summary>Help or version requested (exit 0 after printing <see cref="Text"/>).</summary>
public sealed class HelpRequestedException : Exception
{
    public HelpRequestedException(string text)
        : base("help requested")
    {
        Text = text;
    }

    public string Text { get; }
}

/// <summary>Result of parsing one command level.</summary>
public sealed class ParsedCommand
{
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _flags = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<string>> _positionals = new(StringComparer.Ordinal);
    private readonly HashSet<string> _explicit = new(StringComparer.Ordinal);

    internal ParsedCommand(CommandSpec spec, ParsedCommand? parent, string path)
    {
        Spec = spec;
        Parent = parent;
        Path = path;
    }

    public CommandSpec Spec { get; }

    public ParsedCommand? Parent { get; }

    /// <summary>Selected subcommand, if any.</summary>
    public ParsedCommand? Subcommand { get; internal set; }

    /// <summary>Space-separated command path (for usage messages).</summary>
    public string Path { get; }

    /// <summary>Leaf command.</summary>
    public ParsedCommand Leaf => Subcommand?.Leaf ?? this;

    internal void AddValue(string id, string value)
    {
        if (!_values.TryGetValue(id, out var list))
        {
            list = [];
            _values[id] = list;
        }

        list.Add(value);
        _explicit.Add(id);
    }

    internal void SetValue(string id, string value)
    {
        _values[id] = [value];
        _explicit.Add(id);
    }

    internal void SetDefault(string id, string value)
    {
        if (!_values.ContainsKey(id))
        {
            _values[id] = [value];
        }
    }

    internal void AddFlag(string id)
    {
        _flags[id] = _flags.TryGetValue(id, out var n) ? n + 1 : 1;
        _explicit.Add(id);
    }

    internal void AddPositional(string id, string value)
    {
        if (!_positionals.TryGetValue(id, out var list))
        {
            list = [];
            _positionals[id] = list;
        }

        list.Add(value);
        _explicit.Add(id);
    }

    internal void SetPositionalDefault(string id, string value)
    {
        if (!_positionals.ContainsKey(id))
        {
            _positionals[id] = [value];
        }
    }

    /// <summary>True when the option / positional was given on the command line (not just defaulted).</summary>
    public bool IsPresent(string id) => _explicit.Contains(id) || (Parent?.IsPresentGlobal(id) ?? false);

    private bool IsPresentGlobal(string id) => (Spec.Options.Any(o => o.Id == id && o.Global) && _explicit.Contains(id)) || (Parent?.IsPresentGlobal(id) ?? false);

    /// <summary>Single value (last occurrence) or default, searching global options on parents.</summary>
    public string? Value(string id)
    {
        if (_values.TryGetValue(id, out var list) && list.Count > 0)
        {
            return list[^1];
        }

        return Parent?.GlobalValue(id);
    }

    private string? GlobalValue(string id)
    {
        if (Spec.Options.Any(o => o.Id == id && o.Global) && _values.TryGetValue(id, out var list) && list.Count > 0)
        {
            return list[^1];
        }

        return Parent?.GlobalValue(id);
    }

    /// <summary>Required single value.</summary>
    public string Required(string id) => Value(id) ?? throw new InvalidOperationException($"missing value for {id}");

    /// <summary>All values of a repeatable option.</summary>
    public IReadOnlyList<string> Values(string id) => _values.TryGetValue(id, out var list) ? list : [];

    /// <summary>Boolean flag (also searches global flags on parents). Explicit-bool options parse true/false.</summary>
    public bool Flag(string id)
    {
        if (_flags.TryGetValue(id, out var n) && n > 0)
        {
            return true;
        }

        if (_values.TryGetValue(id, out var list) && list.Count > 0)
        {
            return ParseBool(list[^1]);
        }

        return Parent?.GlobalFlag(id) ?? false;
    }

    private bool GlobalFlag(string id)
    {
        if (Spec.Options.Any(o => o.Id == id && o.Global) && _flags.TryGetValue(id, out var n) && n > 0)
        {
            return true;
        }

        return Parent?.GlobalFlag(id) ?? false;
    }

    /// <summary>Count of a counted flag.</summary>
    public int Count(string id) => _flags.TryGetValue(id, out var n) ? n : 0;

    /// <summary>First value of a positional.</summary>
    public string? Pos(string id) => _positionals.TryGetValue(id, out var list) && list.Count > 0 ? list[0] : null;

    /// <summary>All values of a positional.</summary>
    public IReadOnlyList<string> PosAll(string id) => _positionals.TryGetValue(id, out var list) ? list : [];

    /// <summary>Parse an unsigned integer option.</summary>
    public int Int(string id, int defaultValue = 0)
    {
        var v = Value(id);
        return v is null ? defaultValue : int.Parse(v.TrimStart('+'), NumberStyles.None, CultureInfo.InvariantCulture);
    }

    /// <summary>Optional integer option.</summary>
    public int? IntOrNull(string id)
    {
        var v = Value(id);
        return v is null ? null : int.Parse(v.TrimStart('+'), NumberStyles.None, CultureInfo.InvariantCulture);
    }

    internal static bool ParseBool(string v) => v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" || v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("on", StringComparison.OrdinalIgnoreCase);
}

/// <summary>clap-compatible argv parser.</summary>
public static class CommandLineParser
{
    /// <summary>Parse <paramref name="args"/> (without the executable) against <paramref name="root"/>.</summary>
    public static ParsedCommand Parse(CommandSpec root, IReadOnlyList<string> args, string binName)
    {
        var parsed = new ParsedCommand(root, null, binName);
        var globals = new List<OptionSpec>();
        ParseLevel(parsed, root, args, 0, globals, binName);
        return parsed;
    }

    private static void ParseLevel(ParsedCommand parsed, CommandSpec spec, IReadOnlyList<string> args, int start, List<OptionSpec> inheritedGlobals, string path)
    {
        var globals = new List<OptionSpec>(inheritedGlobals);
        globals.AddRange(spec.Options.Where(o => o.Global));
        int posIndex = 0;
        int posCount = 0;
        bool optionsEnded = false;
        string usage = Usage(spec, path);
        int i = start;
        while (i < args.Count)
        {
            string arg = args[i];
            if (!optionsEnded && arg == "--")
            {
                optionsEnded = true;
                i++;
                continue;
            }

            var currentPos = posIndex < spec.Positionals.Count ? spec.Positionals[posIndex] : null;
            if (currentPos is { Trailing: true } && (posCount > 0 || !LooksLikeOption(arg) || optionsEnded))
            {
                for (; i < args.Count; i++)
                {
                    parsed.AddPositional(currentPos.Id, args[i]);
                }

                break;
            }

            if (!optionsEnded && arg.StartsWith("--", StringComparison.Ordinal) && arg.Length > 2)
            {
                string name = arg[2..];
                string? inline = null;
                int eq = name.IndexOf('=');
                if (eq >= 0)
                {
                    inline = name[(eq + 1)..];
                    name = name[..eq];
                }

                if (!spec.DisableHelpFlag && name == "help")
                {
                    throw new HelpRequestedException(HelpText(spec, path));
                }

                var (opt, owner) = FindLong(spec, globals, name);
                if (opt is null)
                {
                    if (currentPos is { Trailing: true })
                    {
                        for (; i < args.Count; i++)
                        {
                            parsed.AddPositional(currentPos.Id, args[i]);
                        }

                        break;
                    }

                    throw new UsageException(UnexpectedArgument("--" + name), usage);
                }

                i = Consume(parsed, opt, args, i, inline, $"--{name}", usage);
                continue;
            }

            if (!optionsEnded && arg.Length > 1 && arg[0] == '-' && arg != "-")
            {
                char c = arg[1];
                if (!spec.DisableHelpFlag && c == 'h' && arg.Length == 2)
                {
                    throw new HelpRequestedException(HelpText(spec, path));
                }

                var (opt, _) = FindShort(spec, globals, c);
                if (opt is null)
                {
                    if (currentPos is { Trailing: true })
                    {
                        for (; i < args.Count; i++)
                        {
                            parsed.AddPositional(currentPos.Id, args[i]);
                        }

                        break;
                    }

                    throw new UsageException(UnexpectedArgument(arg), usage);
                }

                string? inline = arg.Length > 2 ? (arg[2] == '=' ? arg[3..] : arg[2..]) : null;
                if (opt.Kind is OptionKind.Flag or OptionKind.Count && inline is not null)
                {
                    // Combined short flags (-qv).
                    parsed.AddFlag(opt.Id);
                    foreach (char extra in inline)
                    {
                        var (o2, _) = FindShort(spec, globals, extra);
                        if (o2 is null || o2.Kind is not (OptionKind.Flag or OptionKind.Count))
                        {
                            throw new UsageException($"unexpected argument '-{extra}' found", usage);
                        }

                        parsed.AddFlag(o2.Id);
                    }

                    i++;
                    continue;
                }

                i = Consume(parsed, opt, args, i, inline, $"-{c}", usage);
                continue;
            }

            // Subcommand?
            if (spec.Subcommands.Count > 0 && posIndex == 0 && posCount == 0)
            {
                var sub = spec.Subcommands.FirstOrDefault(s => s.Name == arg || s.Aliases.Contains(arg));
                if (sub is not null)
                {
                    var child = new ParsedCommand(sub, parsed, path + " " + sub.Name);
                    parsed.Subcommand = child;
                    ApplyDefaults(parsed, spec);
                    Validate(parsed, spec, usage);
                    ParseLevel(child, sub, args, i + 1, globals, path + " " + sub.Name);
                    return;
                }

                if (arg == "help")
                {
                    throw new HelpRequestedException(HelpText(spec, path));
                }

                if (spec.Positionals.Count == 0)
                {
                    throw new UsageException($"unrecognized subcommand '{arg}'", usage);
                }
            }

            if (currentPos is null)
            {
                throw new UsageException(LooksLikeOption(arg) ? UnexpectedArgument(arg) : $"unexpected argument '{arg}' found", usage);
            }

            CheckPossible(currentPos.PossibleValues, currentPos.IgnoreCase, arg, currentPos.Display, usage);
            parsed.AddPositional(currentPos.Id, NormalizeChoice(currentPos.PossibleValues, currentPos.IgnoreCase, arg));
            posCount++;
            if (!currentPos.Multiple && !currentPos.Trailing)
            {
                posIndex++;
                posCount = 0;
            }

            i++;
        }

        if (spec.Subcommands.Count > 0 && parsed.Subcommand is null && spec.SubcommandRequired && spec.Handler is null)
        {
            throw new HelpRequestedException(HelpText(spec, path)) { HResult = 2 };
        }

        ApplyDefaults(parsed, spec);
        Validate(parsed, spec, usage);
    }

    private static bool LooksLikeOption(string arg) => arg.Length > 1 && arg[0] == '-';

    /// <summary>Long option names that Rust declares with unsigned integer types (value = max).</summary>
    private static readonly Dictionary<string, ulong> KnownUnsignedOptions = new(StringComparer.Ordinal)
    {
        ["index"] = ulong.MaxValue,
        ["signer-index"] = ulong.MaxValue,
        ["nonce"] = ulong.MaxValue,
        ["expect-nonce"] = ulong.MaxValue,
        ["online-timeout-secs"] = ulong.MaxValue,
        ["online-max-download-bytes"] = ulong.MaxValue,
        ["max-concurrency"] = ulong.MaxValue,
        ["max-degree-of-parallelism"] = ulong.MaxValue,
    };

    private static void CheckUnsigned(OptionSpec opt, string value)
    {
        ulong? max = opt.UnsignedMax;
        if (max is null && opt.Long is not null && KnownUnsignedOptions.TryGetValue(opt.Long, out var known))
        {
            max = known;
        }

        if (max is null)
        {
            return;
        }

        // Rust `u64::from_str`: optional leading '+', ASCII digits only.
        var digits = value.StartsWith('+') ? value[1..] : value;
        string? error = null;
        if (digits.Length == 0)
        {
            error = "cannot parse integer from empty string";
        }
        else if (!digits.All(char.IsAsciiDigit))
        {
            error = "invalid digit found in string";
        }
        else if (!ulong.TryParse(digits, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) || n > max)
        {
            error = "number too large to fit in target type";
        }

        if (error is not null)
        {
            throw new UsageException($"invalid value '{value}' for '{opt.Display}': {error}", null);
        }
    }

    private static string UnexpectedArgument(string arg) =>
        $"unexpected argument '{arg}' found\n\n  tip: to pass '{arg}' as a value, use '-- {arg}'";

    private static int Consume(ParsedCommand parsed, OptionSpec opt, IReadOnlyList<string> args, int i, string? inline, string shown, string usage)
    {
        switch (opt.Kind)
        {
            case OptionKind.Flag:
            case OptionKind.Count:
                if (inline is not null)
                {
                    throw new UsageException($"unexpected value '{inline}' for '{shown}' found; no more were expected", usage);
                }

                parsed.AddFlag(opt.Id);
                return i + 1;
            default:
                string value;
                int next = i + 1;
                if (inline is not null)
                {
                    value = inline;
                }
                else if (next < args.Count && (opt.AllowHyphenValues || !LooksLikeOption(args[next])))
                {
                    value = args[next];
                    next++;
                }
                else if (next < args.Count && args[next].Length > 1 && args[next][0] == '-' && char.IsDigit(args[next][1]))
                {
                    throw new UsageException(UnexpectedArgument(args[next]), usage);
                }
                else if (opt.DefaultMissingValue is not null)
                {
                    value = opt.DefaultMissingValue;
                }
                else
                {
                    throw new UsageException($"a value is required for '{opt.Display}' but none was supplied", usage);
                }

                if (opt.IsExplicitBool && !IsBoolLiteral(value))
                {
                    throw new UsageException($"invalid value '{value}' for '{opt.Display}'\n  [possible values: true, false]", string.Empty);
                }

                CheckPossible(opt.PossibleValues, opt.IgnoreCase, value, opt.Display, usage);
                CheckUnsigned(opt, value);
                value = NormalizeChoice(opt.PossibleValues, opt.IgnoreCase, value);
                if (opt.Validator?.Invoke(value) is { } invalid)
                {
                    throw new UsageException($"invalid value '{value}' for '{opt.Display}': {invalid}", string.Empty);
                }

                if (opt.Kind == OptionKind.Multi)
                {
                    parsed.AddValue(opt.Id, value);
                }
                else
                {
                    parsed.SetValue(opt.Id, value);
                }

                return next;
        }
    }

    private static bool IsBoolLiteral(string v) => v is "true" or "false";

    private static void CheckPossible(string[]? possible, bool ignoreCase, string value, string display, string usage)
    {
        if (possible is null)
        {
            return;
        }

        var cmp = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!possible.Any(p => string.Equals(p, value, cmp)))
        {
            throw new UsageException(
                $"invalid value '{value}' for '{display}'\n  [possible values: {string.Join(", ", possible)}]",
                string.Empty);
        }
    }

    private static string NormalizeChoice(string[]? possible, bool ignoreCase, string value)
    {
        if (possible is null || !ignoreCase)
        {
            return value;
        }

        return possible.First(p => string.Equals(p, value, StringComparison.OrdinalIgnoreCase));
    }

    private static (OptionSpec? Opt, CommandSpec? Owner) FindLong(CommandSpec spec, List<OptionSpec> globals, string name)
    {
        foreach (var o in spec.Options)
        {
            if (o.Long == name || o.Aliases.Contains(name))
            {
                return (o, spec);
            }
        }

        foreach (var o in globals)
        {
            if (o.Long == name || o.Aliases.Contains(name))
            {
                return (o, null);
            }
        }

        return (null, null);
    }

    private static (OptionSpec? Opt, CommandSpec? Owner) FindShort(CommandSpec spec, List<OptionSpec> globals, char c)
    {
        foreach (var o in spec.Options)
        {
            if (o.Short == c || o.ShortAliases.Contains(c))
            {
                return (o, spec);
            }
        }

        foreach (var o in globals)
        {
            if (o.Short == c || o.ShortAliases.Contains(c))
            {
                return (o, null);
            }
        }

        return (null, null);
    }

    private static void ApplyDefaults(ParsedCommand parsed, CommandSpec spec)
    {
        foreach (var o in spec.Options)
        {
            if (o.Default is not null && o.Kind is OptionKind.Value)
            {
                parsed.SetDefault(o.Id, o.Default);
            }
        }

        foreach (var p in spec.Positionals)
        {
            if (p.Default is not null)
            {
                parsed.SetPositionalDefault(p.Id, p.Default);
            }
        }
    }

    private static void Validate(ParsedCommand parsed, CommandSpec spec, string usage)
    {
        var missing = new List<string>();
        foreach (var o in spec.Options)
        {
            if (o.Required && !parsed.IsPresent(o.Id))
            {
                missing.Add(o.Display);
            }
        }

        if (parsed.Subcommand is null)
        {
            foreach (var p in spec.Positionals)
            {
                if (p.Required && parsed.PosAll(p.Id).Count == 0)
                {
                    missing.Add(p.Display);
                }
            }
        }

        if (missing.Count > 0)
        {
            throw new UsageException(
                "the following required arguments were not provided:\n" + string.Join("\n", missing.Select(m => "  " + m)),
                RequiredUsage(spec, parsed.Path));
        }

        foreach (var o in spec.Options)
        {
            if (o.Required && !parsed.IsPresent(o.Id))
            {
                throw new UsageException($"the following required arguments were not provided:\n  {o.Display}", usage);
            }

            if (!parsed.IsPresent(o.Id))
            {
                continue;
            }

            foreach (var r in o.Requires)
            {
                if (!parsed.IsPresent(r))
                {
                    var other = spec.Options.FirstOrDefault(x => x.Id == r);
                    var requiresUsage = new StringBuilder("Usage: ").Append(parsed.Path).Append(' ').Append(o.Display).Append(' ').Append(other?.Display ?? "--" + r);
                    foreach (var rp in spec.Positionals.Where(rp => rp.Required))
                    {
                        requiresUsage.Append(' ').Append(rp.Display);
                    }

                    throw new UsageException(
                        $"the following required arguments were not provided:\n  {other?.Display ?? "--" + r}",
                        requiresUsage.ToString());
                }
            }

            foreach (var c in o.ConflictsWith)
            {
                if (parsed.IsPresent(c))
                {
                    var other = spec.Options.FirstOrDefault(x => x.Id == c);
                    throw new UsageException($"the argument '{o.Display}' cannot be used with '{other?.Display ?? "--" + c}'", usage);
                }
            }
        }

        foreach (var group in spec.ExclusiveGroups)
        {
            var present = group.Where(parsed.IsPresent).ToList();
            if (present.Count > 1)
            {
                var a = spec.Options.FirstOrDefault(x => x.Id == present[0]);
                var b = spec.Options.FirstOrDefault(x => x.Id == present[1]);
                throw new UsageException($"the argument '{a?.Display}' cannot be used with '{b?.Display}'", usage);
            }
        }

        foreach (var group in spec.RequiredOneOf)
        {
            if (!group.Any(parsed.IsPresent))
            {
                var names = string.Join(" ", group.Select(g => spec.Options.FirstOrDefault(x => x.Id == g)?.Display ?? g));
                throw new UsageException($"the following required arguments were not provided:\n  <{names}>", usage);
            }
        }

        if (parsed.Subcommand is null)
        {
            foreach (var p in spec.Positionals)
            {
                if (p.Required && parsed.PosAll(p.Id).Count == 0)
                {
                    throw new UsageException($"the following required arguments were not provided:\n  {p.Display}", usage);
                }
            }
        }
    }

    /// <summary>One-line usage string (clap style: <c>[OPTIONS]</c>, required options, then positionals).</summary>
    public static string Usage(CommandSpec spec, string path)
    {
        var sb = new StringBuilder("Usage: ").Append(path);
        if (spec.Options.Any(o => !o.Hidden && !o.Required))
        {
            sb.Append(" [OPTIONS]");
        }

        foreach (var o in spec.Options.Where(o => o.Required))
        {
            sb.Append(' ').Append(o.Display);
        }

        foreach (var p in spec.Positionals)
        {
            sb.Append(' ').Append(p.Required ? p.Display : $"[{p.Display.Trim('<', '>', '.')}]" + (p.Multiple ? "..." : string.Empty));
        }

        if (spec.Subcommands.Count > 0)
        {
            sb.Append(" <COMMAND>");
        }

        return sb.ToString();
    }

    /// <summary>Usage line printed with missing-required-argument errors (required arguments only).</summary>
    public static string RequiredUsage(CommandSpec spec, string path)
    {
        var sb = new StringBuilder("Usage: ").Append(path);
        foreach (var o in spec.Options.Where(o => o.Required))
        {
            sb.Append(' ').Append(o.Display);
        }

        foreach (var p in spec.Positionals.Where(p => p.Required))
        {
            sb.Append(' ').Append(p.Display);
        }

        return sb.ToString();
    }

    /// <summary>Help text for a command.</summary>
    public static string HelpText(CommandSpec spec, string path)
    {
        var sb = new StringBuilder();
        if (!string.IsNullOrEmpty(spec.LongAbout ?? spec.About))
        {
            sb.Append(spec.LongAbout ?? spec.About).Append("\n\n");
        }

        sb.Append(Usage(spec, path)).Append('\n');
        var subs = spec.Subcommands.Where(s => !s.Hidden).ToList();
        if (subs.Count > 0)
        {
            sb.Append("\nCommands:\n");
            int width = subs.Max(s => s.Name.Length);
            foreach (var s in subs)
            {
                sb.Append("  ").Append(s.Name.PadRight(width)).Append("  ").Append(FirstLine(s.About)).Append('\n');
            }
        }

        if (spec.Positionals.Count > 0)
        {
            sb.Append("\nArguments:\n");
            foreach (var p in spec.Positionals)
            {
                sb.Append("  ").Append(p.Display);
                if (!string.IsNullOrEmpty(p.Help))
                {
                    sb.Append("\n          ").Append(p.Help);
                }

                sb.Append('\n');
            }
        }

        sb.Append("\nOptions:\n");
        foreach (var o in spec.Options.Where(o => !o.Hidden))
        {
            sb.Append("  ");
            if (o.Short is not null)
            {
                sb.Append('-').Append(o.Short).Append(o.Long is not null ? ", " : string.Empty);
            }
            else
            {
                sb.Append("    ");
            }

            sb.Append(o.Display);
            if (!string.IsNullOrEmpty(o.Help))
            {
                sb.Append("\n          ").Append(o.Help);
            }

            if (o.Default is not null)
            {
                sb.Append("\n          [default: ").Append(o.Default).Append(']');
            }

            if (o.PossibleValues is not null)
            {
                sb.Append("\n          [possible values: ").Append(string.Join(", ", o.PossibleValues)).Append(']');
            }

            if (o.Aliases.Count > 0)
            {
                sb.Append("\n          [aliases: ").Append(string.Join(", ", o.Aliases.Select(a => "--" + a))).Append(']');
            }

            sb.Append('\n');
        }

        if (!spec.DisableHelpFlag)
        {
            sb.Append("  -h, --help\n          Print help\n");
        }

        return sb.ToString();
    }

    private static string FirstLine(string? s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return string.Empty;
        }

        int nl = s.IndexOf('\n');
        return nl >= 0 ? s[..nl] : s;
    }
}
