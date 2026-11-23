using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.Framework;

/// <summary>
/// Raised by a nested parser when the Rust process would have exited immediately (clap <c>Error::exit</c> after printing
/// usage errors or help). <see cref="CliRunner.Execute"/> maps it to <see cref="ExitCode"/> without printing anything else.
/// </summary>
public sealed class CliExitException : Exception
{
    public CliExitException(int exitCode)
        : base($"exit {exitCode}")
    {
        ExitCode = exitCode;
    }

    public int ExitCode { get; }
}

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
            return PrintHelp(help);
        }
        catch (UsageException usage)
        {
            return PrintUsage(usage);
        }

        return Execute(parsed, quiet);
    }

    /// <summary>
    /// Parse a nested command line the way Rust <c>Cli::parse_from</c> does inside a running command: help and usage errors
    /// are printed and then surface as <see cref="CliExitException"/> (the Rust process exits immediately).
    /// </summary>
    public static ParsedCommand ParseOrExit(CommandSpec root, IReadOnlyList<string> args, string binName)
    {
        try
        {
            return CommandLineParser.Parse(root, args, binName);
        }
        catch (HelpRequestedException help)
        {
            throw new CliExitException(PrintHelp(help));
        }
        catch (UsageException usage)
        {
            throw new CliExitException(PrintUsage(usage));
        }
    }

    private static int PrintHelp(HelpRequestedException help)
    {
        if (help.HResult == 2)
        {
            Output.ErrorWrite(help.Text);
            return 2;
        }

        Output.Write(help.Text);
        return 0;
    }

    private static int PrintUsage(UsageException usage)
    {
        Output.ErrorLine($"error: {usage.Message}");
        Output.ErrorLine();
        if (!string.IsNullOrEmpty(usage.Usage))
        {
            // clap omits the usage line for value errors (`ErrorKind::InvalidValue` / `ValueValidation`).
            Output.ErrorLine(usage.Usage);
            Output.ErrorLine();
        }

        Output.ErrorLine("For more information, try '--help'.");
        return 2;
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
        catch (CliExitException exit)
        {
            return exit.ExitCode;
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
