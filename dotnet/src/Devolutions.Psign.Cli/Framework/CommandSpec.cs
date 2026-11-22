namespace Devolutions.Psign.Cli.Framework;

/// <summary>Kind of a named option (mirrors clap <c>ArgAction</c>).</summary>
public enum OptionKind
{
    /// <summary>Boolean switch (<c>ArgAction::SetTrue</c>).</summary>
    Flag,

    /// <summary>Single value (<c>Option&lt;T&gt;</c>); the last occurrence wins.</summary>
    Value,

    /// <summary>Repeatable value (<c>Vec&lt;T&gt;</c>, <c>ArgAction::Append</c>).</summary>
    Multi,

    /// <summary>Counted flag (<c>ArgAction::Count</c>).</summary>
    Count,
}

/// <summary>Named option definition.</summary>
public sealed class OptionSpec
{
    public OptionSpec(string id, string? longName, OptionKind kind)
    {
        Id = id;
        Long = longName;
        Kind = kind;
    }

    /// <summary>Stable identifier used to read the value (defaults to the long name).</summary>
    public string Id { get; }

    /// <summary>Long name without dashes (for example <c>anchor-dir</c>).</summary>
    public string? Long { get; }

    public OptionKind Kind { get; }

    public char? Short { get; set; }

    /// <summary>Long aliases (visible or hidden).</summary>
    public List<string> Aliases { get; } = [];

    /// <summary>Short aliases.</summary>
    public List<char> ShortAliases { get; } = [];

    public string? ValueName { get; set; }

    public string? Help { get; set; }

    /// <summary>Default value applied when the option is absent.</summary>
    public string? Default { get; set; }

    /// <summary>Allowed values (clap <c>ValueEnum</c>), compared case-sensitively unless <see cref="IgnoreCase"/>.</summary>
    public string[]? PossibleValues { get; set; }

    public bool IgnoreCase { get; set; }

    public bool Required { get; set; }

    /// <summary>Global options may appear before or after the subcommand.</summary>
    public bool Global { get; set; }

    public bool AllowHyphenValues { get; set; }

    public bool Hidden { get; set; }

    /// <summary>Option ids that must also be present.</summary>
    public List<string> Requires { get; } = [];

    /// <summary>Option ids that must not be present together with this option.</summary>
    public List<string> ConflictsWith { get; } = [];

    /// <summary>For <see cref="OptionKind.Value"/> booleans with <c>ArgAction::Set</c> (explicit true/false value).</summary>
    public bool IsExplicitBool { get; set; }

    /// <summary>
    /// When set, the value must parse as an unsigned integer no larger than this (clap <c>u32</c>/<c>u64</c>/<c>usize</c>
    /// value parsers). <c>null</c> applies the built-in table of known numeric psign options.
    /// </summary>
    public ulong? UnsignedMax { get; set; }

    /// <summary>Optional value (<c>num_args = 0..=1</c>); <see cref="DefaultMissingValue"/> is used when omitted.</summary>
    public string? DefaultMissingValue { get; set; }

    /// <summary>
    /// Typed value parser check (clap <c>value_parser</c>): returns an error message for an invalid value, which becomes the
    /// usage error <c>invalid value '{v}' for '{opt}': {message}</c>.
    /// </summary>
    public Func<string, string?>? Validator { get; set; }

    /// <summary>Hidden value aliases (clap <c>#[value(alias = ...)]</c>) mapped to their canonical possible value.</summary>
    public Dictionary<string, string>? ValueAliases { get; set; }

    /// <summary>Values consumed per occurrence (clap <c>num_args = N</c>); only meaningful for <see cref="OptionKind.Multi"/>.</summary>
    public int ValuesPerOccurrence { get; set; } = 1;

    internal string Display => Long is not null
        ? (Kind is OptionKind.Flag or OptionKind.Count ? $"--{Long}" : $"--{Long} <{ValueName ?? Long.ToUpperInvariant().Replace('-', '_')}>")
        : $"-{Short}";
}

/// <summary>Positional argument definition.</summary>
public sealed class PositionalSpec
{
    public PositionalSpec(string id, bool required = true, bool multiple = false)
    {
        Id = id;
        Required = required;
        Multiple = multiple;
    }

    public string Id { get; }

    public bool Required { get; set; }

    /// <summary>Consumes all remaining positionals.</summary>
    public bool Multiple { get; set; }

    /// <summary>Consumes all remaining argv tokens including ones that look like options (clap <c>trailing_var_arg</c>).</summary>
    public bool Trailing { get; set; }

    public string? ValueName { get; set; }

    public string? Help { get; set; }

    public string? Default { get; set; }

    public string[]? PossibleValues { get; set; }

    public bool IgnoreCase { get; set; }

    /// <summary>Required unless the option with this id is present (clap <c>required_unless_present</c>).</summary>
    public string? RequiredUnlessPresent { get; set; }

    internal string Display => Multiple ? $"<{ValueName ?? Id.ToUpperInvariant()}>..." : $"<{ValueName ?? Id.ToUpperInvariant()}>";
}

/// <summary>Command (or subcommand) definition.</summary>
public sealed class CommandSpec
{
    public CommandSpec(string name, string? about = null)
    {
        Name = name;
        About = about;
    }

    public string Name { get; }

    public string? About { get; set; }

    public string? LongAbout { get; set; }

    public List<string> Aliases { get; } = [];

    public List<OptionSpec> Options { get; } = [];

    public List<PositionalSpec> Positionals { get; } = [];

    public List<CommandSpec> Subcommands { get; } = [];

    public bool SubcommandRequired { get; set; } = true;

    /// <summary>Handler invoked with the parsed leaf command. Returns the process exit code.</summary>
    public Func<ParsedCommand, int>? Handler { get; set; }

    public bool DisableHelpFlag { get; set; }

    public bool Hidden { get; set; }

    /// <summary>Groups of option ids where at least one must be present.</summary>
    public List<string[]> RequiredOneOf { get; } = [];

    /// <summary>Groups of option ids that are mutually exclusive.</summary>
    public List<string[]> ExclusiveGroups { get; } = [];

    // ----- fluent builders

    public OptionSpec Flag(string longName, string? help = null, char? shortName = null)
    {
        var o = new OptionSpec(longName, longName, OptionKind.Flag) { Help = help, Short = shortName };
        Options.Add(o);
        return o;
    }

    public OptionSpec Value(string longName, string? valueName = null, string? help = null, string? defaultValue = null)
    {
        var o = new OptionSpec(longName, longName, OptionKind.Value) { ValueName = valueName, Help = help, Default = defaultValue };
        Options.Add(o);
        return o;
    }

    public OptionSpec Multi(string longName, string? valueName = null, string? help = null)
    {
        var o = new OptionSpec(longName, longName, OptionKind.Multi) { ValueName = valueName, Help = help };
        Options.Add(o);
        return o;
    }

    public OptionSpec Choice(string longName, string[] values, string? defaultValue = null, string? help = null)
    {
        var o = new OptionSpec(longName, longName, OptionKind.Value) { PossibleValues = values, Default = defaultValue, Help = help };
        Options.Add(o);
        return o;
    }

    public PositionalSpec Positional(string id, bool required = true, string? help = null, string? valueName = null)
    {
        var p = new PositionalSpec(id, required) { Help = help, ValueName = valueName };
        Positionals.Add(p);
        return p;
    }

    public PositionalSpec Positionals_(string id, bool required = false, string? help = null)
    {
        var p = new PositionalSpec(id, required, multiple: true) { Help = help };
        Positionals.Add(p);
        return p;
    }

    public CommandSpec Sub(string name, string? about, Action<CommandSpec> configure)
    {
        var c = new CommandSpec(name, about);
        configure(c);
        Subcommands.Add(c);
        return c;
    }

    public CommandSpec Sub(CommandSpec command)
    {
        Subcommands.Add(command);
        return command;
    }
}

/// <summary>Fluent helpers for <see cref="OptionSpec"/>.</summary>
public static class OptionSpecExtensions
{
    public static OptionSpec Alias(this OptionSpec o, params string[] aliases)
    {
        o.Aliases.AddRange(aliases);
        return o;
    }

    public static OptionSpec ShortAlias(this OptionSpec o, params char[] aliases)
    {
        o.ShortAliases.AddRange(aliases);
        return o;
    }

    public static OptionSpec WithShort(this OptionSpec o, char shortName)
    {
        o.Short = shortName;
        return o;
    }

    public static OptionSpec Req(this OptionSpec o)
    {
        o.Required = true;
        return o;
    }

    public static OptionSpec Requiring(this OptionSpec o, params string[] ids)
    {
        o.Requires.AddRange(ids);
        return o;
    }

    public static OptionSpec Conflicts(this OptionSpec o, params string[] ids)
    {
        o.ConflictsWith.AddRange(ids);
        return o;
    }

    public static OptionSpec Values(this OptionSpec o, params string[] values)
    {
        o.PossibleValues = values;
        return o;
    }

    public static OptionSpec CaseInsensitive(this OptionSpec o)
    {
        o.IgnoreCase = true;
        return o;
    }

    public static OptionSpec Default(this OptionSpec o, string value)
    {
        o.Default = value;
        return o;
    }

    public static OptionSpec MakeGlobal(this OptionSpec o)
    {
        o.Global = true;
        return o;
    }

    public static OptionSpec HyphenValues(this OptionSpec o)
    {
        o.AllowHyphenValues = true;
        return o;
    }

    /// <summary>Accept <paramref name="alias"/> as a hidden spelling of the possible value <paramref name="canonical"/>.</summary>
    public static OptionSpec ValueAlias(this OptionSpec o, string alias, string canonical)
    {
        (o.ValueAliases ??= new Dictionary<string, string>(StringComparer.Ordinal))[alias] = canonical;
        return o;
    }

    public static OptionSpec Hide(this OptionSpec o)
    {
        o.Hidden = true;
        return o;
    }

    /// <summary>Parse the value as an unsigned integer no larger than <paramref name="max"/> (Rust <c>u32</c> / <c>u64</c> / <c>usize</c>).</summary>
    public static OptionSpec Unsigned(this OptionSpec o, ulong max = ulong.MaxValue)
    {
        o.Validator = v => UnsignedError(v, max);
        return o;
    }

    /// <summary>Rust <c>ParseIntError</c> display for an unsigned integer value, or <c>null</c> when valid.</summary>
    internal static string? UnsignedError(string v, ulong max)
    {
        if (v.Length == 0)
        {
            return "cannot parse integer from empty string";
        }

        var digits = v[0] == '+' ? v[1..] : v;
        if (digits.Length == 0 || digits.Any(c => c is < '0' or > '9'))
        {
            return "invalid digit found in string";
        }

        ulong value = 0;
        foreach (char c in digits)
        {
            ulong d = (ulong)(c - '0');
            if (value > (max - d) / 10)
            {
                return "number too large to fit in target type";
            }

            value = (value * 10) + d;
        }

        return null;
    }
}
