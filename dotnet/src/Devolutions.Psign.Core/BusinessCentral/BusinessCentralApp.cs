namespace Devolutions.Psign.Core.BusinessCentral;

/// <summary>Business Central <c>.app</c> header info (Rust <c>BusinessCentralAppInfo</c>).</summary>
public sealed record BusinessCentralAppInfo(bool IsNavx, ulong Len)
{
    /// <summary><c>NAVX</c> or <c>-</c> as printed by <c>business-central-app-info</c>.</summary>
    public string Header => IsNavx ? "NAVX" : "-";
}

/// <summary>Business Central extension helpers (Rust <c>inspect_business_central_app</c>).</summary>
public static class BusinessCentralApp
{
    private static readonly byte[] NavxMagic = "NAVX"u8.ToArray();

    /// <summary>Inspect raw <c>.app</c> bytes.</summary>
    public static BusinessCentralAppInfo Inspect(ReadOnlySpan<byte> bytes) => new(bytes.StartsWith(NavxMagic), (ulong)bytes.Length);

    /// <summary>Rust <c>inspect_business_central_app</c>.</summary>
    public static BusinessCentralAppInfo InspectPath(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read {path}", e);
        }

        return Inspect(bytes);
    }
}
