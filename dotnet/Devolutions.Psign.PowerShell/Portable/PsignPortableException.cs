namespace Devolutions.Psign.PowerShell.Portable;

internal sealed class PsignPortableException(uint statusCode, string message) : Exception(message)
{
    public uint StatusCode { get; } = statusCode;
}
