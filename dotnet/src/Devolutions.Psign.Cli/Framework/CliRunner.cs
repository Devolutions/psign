using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.Framework;

/// <summary>Parses argv, dispatches to handlers, and maps errors to exit codes like the Rust binaries.</summary>
public static class CliRunner
{
    /// <summary>
    /// Parse and run. Usage errors print clap-style messages to stderr and return 2; handler errors print the
    /// <c>{e:#}</c>-style chain to stderr and return 1.
    /// </summary>
    public static int Run(CommandSpec root, IReadOnlyList<string> args, string binName, Func<ParsedCommand, bool>? quiet = null)
    {
        ParsedCommand parsed;
        try
        {
            parsed = CommandLineParser.Parse(root, args, binName);
        }
        catch (HelpRequestedException help)
        {
            if (help.HResult == 2)
            {
                Output.ErrorWrite(help.Text);
                return 2;
            }

            Output.Write(help.Text);
            return 0;
        }
        catch (UsageException usage)
        {
            Output.ErrorLine($"error: {usage.Message}");
            Output.ErrorLine();
            if (usage.Usage is not null)
            {
                Output.ErrorLine(usage.Usage);
                Output.ErrorLine();
            }

            Output.ErrorLine("For more information, try '--help'.");
            return 2;
        }

        return Execute(parsed, quiet);
    }

    /// <summary>Run the handler of an already-parsed command.</summary>
    public static int Execute(ParsedCommand parsed, Func<ParsedCommand, bool>? quiet = null)
    {
        var leaf = parsed.Leaf;
        var handler = leaf.Spec.Handler ?? throw new InvalidOperationException($"no handler for {leaf.Path}");
        try
        {
            return handler(leaf);
        }
        catch (Exception e) when (e is PsignException or IOException or UnauthorizedAccessException or FormatException or System.Security.Cryptography.CryptographicException or System.Formats.Asn1.AsnContentException or InvalidDataException or HttpRequestException or ArgumentException or OverflowException)
        {
            if (quiet is null || !quiet(leaf))
            {
                Output.ErrorLine(PsignException.Render(e));
            }

            return 1;
        }
    }
}
