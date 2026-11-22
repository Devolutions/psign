namespace Devolutions.Psign.Core;

/// <summary>
/// Rust <c>std::io::Error</c> display text for common .NET I/O exceptions, so error chains such as
/// <c>read {path}: The system cannot find the file specified. (os error 2)</c> match the Rust tool.
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
        _ => e.Message,
    };

    /// <summary>Inner exception carrying the Rust-style I/O message (use as the cause of a context error).</summary>
    public static PsignException Inner(Exception e) => new(Message(e));
}
