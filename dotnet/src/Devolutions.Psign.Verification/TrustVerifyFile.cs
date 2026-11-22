using System.Collections.Concurrent;
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

/// <summary>Verifier for one format: receives the path, the lowercase extension (no dot) and the options.</summary>
public delegate TrustVerifyPeReport TrustVerifyFormatHandler(string path, string extension, TrustVerifyPeOptions opts);

/// <summary>
/// Path-based format dispatch over the trust-verify entry points (same extension mapping as portable
/// <c>psign-tool verify</c>). PE is implemented here; the other formats are <b>extension points</b>: their SIP digest code is
/// being ported to Core separately, and each verifier registers itself with <see cref="RegisterFormat"/>. A registered
/// verifier should recompute the format digest and then call <see cref="TrustVerifyPe.VerifyPkcs7Entry"/> (with
/// <see cref="TrustVerifyPe.TrustMaterialFor"/> / <see cref="TrustVerifyPe.NewReport"/>), mirroring the Rust
/// <c>trust_verify_{cab,msi,catalog,zip,script,msix,nuget,vsix,esd}.rs</c> modules.
/// </summary>
public static class TrustVerifyFile
{
    private static readonly ConcurrentDictionary<TrustVerifyFormat, TrustVerifyFormatHandler> Handlers = new();

    /// <summary>Register (or replace) the verifier for a non-PE format.</summary>
    public static void RegisterFormat(TrustVerifyFormat format, TrustVerifyFormatHandler handler) => Handlers[format] = handler;

    /// <summary>True when a verifier is available for <paramref name="format"/>.</summary>
    public static bool IsFormatAvailable(TrustVerifyFormat format) => format == TrustVerifyFormat.Pe || Handlers.ContainsKey(format);

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

    /// <summary>Trust-verify <paramref name="path"/>, choosing the format from its extension.</summary>
    public static TrustVerifyPeReport TrustVerifyPath(string path, TrustVerifyPeOptions opts)
    {
        var ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
        var format = FormatForExtension(ext)
            ?? throw new PsignException($"portable trust verification does not support this file format: {path}");
        if (format == TrustVerifyFormat.Pe)
        {
            return TrustVerifyPe.TrustVerifyPeBytes(Read(path), opts);
        }

        if (Handlers.TryGetValue(format, out var handler))
        {
            return handler(path, ext, opts);
        }

        throw new PsignException(
            $"portable trust verification for .{ext} ({format}) is not available in this build (no verifier registered via TrustVerifyFile.RegisterFormat): {path}");
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
