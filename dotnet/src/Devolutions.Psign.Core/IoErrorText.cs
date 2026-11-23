namespace Devolutions.Psign.Core;

/// <summary>
/// Rust <c>std::io::Error</c> display text for common .NET I/O exceptions, so error chains such as
/// <c>read {path}: The system cannot find the file specified. (os error 2)</c> match the Rust tool. This is the single
/// mapping used by the CLI, verification and signing layers.
/// </summary>
public static class IoErrorText
{
    /// <summary>Approximate Rust <c>std::io::Error</c> display text for <paramref name="e"/>.</summary>
    public static string Message(Exception e) => e switch
    {
        FileNotFoundException => OperatingSystem.IsWindows()
            ? "The system cannot find the file specified. (os error 2)"
            : "No such file or directory (os error 2)",
        DirectoryNotFoundException => OperatingSystem.IsWindows()
            ? "The system cannot find the path specified. (os error 3)"
            : "No such file or directory (os error 2)",
        UnauthorizedAccessException => OperatingSystem.IsWindows()
            ? "Access is denied. (os error 5)"
            : "Permission denied (os error 13)",
        PathTooLongException => OperatingSystem.IsWindows()
            ? "The filename or extension is too long. (os error 206)"
            : "File name too long (os error 36)",
        ArgumentException or NotSupportedException => OperatingSystem.IsWindows()
            ? "The filename, directory name, or volume label syntax is incorrect. (os error 123)"
            : "invalid filename",
        _ => e.Message,
    };

    /// <summary>Inner exception carrying the Rust-style I/O message (use as the cause of a context error).</summary>
    public static PsignException Inner(Exception e) => new(Message(e));
}
