using Devolutions.Psign.Core;

namespace Devolutions.Psign.Verification;

/// <summary>Format families dispatched by <see cref="TrustVerifyFile.TrustVerifyPath"/> (Rust <c>trust_verify_file.rs</c>).</summary>
public enum TrustVerifyFormat
{
    Pe,
    WimEsd,
    Cab,
    Msi,
    Catalog,
    Zip,
    Script,
    Msix,
    NuGet,
    Vsix,
}

/// <summary>
/// Path-based format dispatch over the <c>TrustVerify*</c> entry points (same extension mapping as portable
/// <c>psign-tool verify</c>), so every caller applies the same per-format checks (Rust <c>trust_verify_file.rs</c>).
/// </summary>
public static class TrustVerifyFile
{
    /// <summary>True when a verifier is available for <paramref name="format"/> (every format is implemented).</summary>
    public static bool IsFormatAvailable(TrustVerifyFormat format) => Enum.IsDefined(format);

    /// <summary>Map a lowercase extension (no dot) to its format family, or <c>null</c> when unsupported.</summary>
    public static TrustVerifyFormat? FormatForExtension(string ext) => ext switch
    {
        "wim" or "esd" => TrustVerifyFormat.WimEsd,
        "exe" or "dll" or "sys" or "ocx" or "efi" or "winmd" => TrustVerifyFormat.Pe,
        "cab" => TrustVerifyFormat.Cab,
        "msi" or "msp" => TrustVerifyFormat.Msi,
        "cat" => TrustVerifyFormat.Catalog,
        "zip" => TrustVerifyFormat.Zip,
        "ps1" or "psd1" or "psm1" or "ps1xml" or "psc1" or "cdxml" or "mof" or "js" or "jse" or "vbs" or "vbe" or "wsf" => TrustVerifyFormat.Script,
        "msix" or "appx" or "msixbundle" or "appxbundle" => TrustVerifyFormat.Msix,
        "nupkg" or "snupkg" => TrustVerifyFormat.NuGet,
        "vsix" => TrustVerifyFormat.Vsix,
        _ => null,
    };

    /// <summary>Trust-verify <paramref name="path"/>, choosing the format from its extension (Rust <c>trust_verify_path</c>).</summary>
    public static TrustVerifyPeReport TrustVerifyPath(string path, TrustVerifyPeOptions opts)
    {
        var ext = Core.Text.RustText.ToAsciiLowercase(Path.GetExtension(path).TrimStart('.'));
        var format = FormatForExtension(ext)
            ?? throw new PsignException($"portable trust verification does not support this file format: {path}");
        return format switch
        {
            TrustVerifyFormat.WimEsd => TrustVerifyEsd.TrustVerifyWimEsdPath(path, opts),
            TrustVerifyFormat.Pe => TrustVerifyPe.TrustVerifyPeBytes(Read(path), opts),
            TrustVerifyFormat.Cab => TrustVerifyCab.TrustVerifyCabBytes(Read(path), opts),
            TrustVerifyFormat.Msi => TrustVerifyMsi.TrustVerifyMsiBytes(Read(path), opts),
            TrustVerifyFormat.Catalog => TrustVerifyCatalog.TrustVerifyCatalogBytes(Read(path), opts),
            TrustVerifyFormat.Zip => TrustVerifyZip.TrustVerifyZipBytes(Read(path), opts),
            TrustVerifyFormat.Script => TrustVerifyScript.TrustVerifyScriptBytes(Read(path), ext, opts),
            TrustVerifyFormat.Msix => TrustVerifyMsix.TrustVerifyMsixBytes(Read(path), ext, opts),
            TrustVerifyFormat.NuGet => TrustVerifyNuGet.TrustVerifyNuGetBytes(Read(path), opts),
            TrustVerifyFormat.Vsix => TrustVerifyVsix.TrustVerifyVsixBytes(Read(path), opts),
            _ => throw new PsignException($"portable trust verification does not support this file format: {path}"),
        };
    }

    private static byte[] Read(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw PsignException.Context($"read {path}", e);
        }
    }
}
