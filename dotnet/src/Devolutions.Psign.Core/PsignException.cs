namespace Devolutions.Psign.Core;

/// <summary>
/// Error raised by psign portable operations. Mirrors the Rust <c>anyhow</c> error chain: <see cref="Exception.Message"/>
/// holds the outermost context and <see cref="FullMessage"/> renders the chain as <c>outer: inner: ...</c>
/// (the Rust <c>{:#}</c> format).
/// </summary>
public class PsignException : Exception
{
    public PsignException(string message)
        : base(message)
    {
    }

    public PsignException(string message, Exception? inner)
        : base(message, inner)
    {
    }

    /// <summary>Render the error chain as <c>outer: inner: ...</c>.</summary>
    public string FullMessage => Render(this);

    /// <summary>Render any exception chain as <c>outer: inner: ...</c>.</summary>
    public static string Render(Exception e)
    {
        var parts = new List<string>();
        for (Exception? cur = e; cur is not null; cur = cur.InnerException)
        {
            if (cur is AggregateException agg && agg.InnerExceptions.Count == 1 && cur.InnerException is not null)
            {
                continue;
            }

            parts.Add(cur is IOException or UnauthorizedAccessException ? IoErrorText.Message(cur) : cur.Message);
        }

        return string.Join(": ", parts);
    }

    /// <summary>Wrap <paramref name="inner"/> with additional context (Rust <c>.context(..)</c>).</summary>
    public static PsignException Context(string context, Exception inner) => new(context, inner);
}
