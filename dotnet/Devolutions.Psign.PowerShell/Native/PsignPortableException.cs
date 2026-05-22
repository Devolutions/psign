namespace Devolutions.Psign.PowerShell.Native;

internal sealed class PsignPortableException(uint statusCode, string message) : Exception(message)
{
    public uint StatusCode { get; } = statusCode;
}
