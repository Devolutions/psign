using System.Reflection;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Signing.Portable;

/// <summary>
/// Injectable dependencies for <see cref="PortableCore"/> (the Rust implementation uses the system clock, the process
/// environment and real HTTP). Tests and hosts can replace them; every member is optional.
/// </summary>
public sealed class PortableCoreOptions
{
    /// <summary>HTTP handler for RFC 3161 timestamping, Azure Key Vault and Artifact Signing (not disposed).</summary>
    public HttpMessageHandler? HttpHandler { get; set; }

    /// <summary>Environment lookup (Artifact Signing credentials, <c>SIGNTOOL_PORTABLE_DEBUG</c>); defaults to the process environment.</summary>
    public Func<string, string?>? Environment { get; set; }

    /// <summary>Clock for the NuGet <c>signingTime</c> attribute and the VSIX <c>SignatureTime</c> (defaults to UTC now).</summary>
    public Func<DateTimeOffset>? Clock { get; set; }

    /// <summary>Local DOS timestamp for the NuGet <c>.signature.p7s</c> ZIP entry (defaults to the local wall clock).</summary>
    public Func<ZipDateTime>? ZipClock { get; set; }

    /// <summary>Artifact Signing long-running-operation poll interval override (tests).</summary>
    public TimeSpan? ArtifactSigningPollInterval { get; set; }

    /// <summary>Destination for <c>[debug]</c> lines when <c>SIGNTOOL_PORTABLE_DEBUG</c> is set (defaults to stderr).</summary>
    public TextWriter? DebugLog { get; set; }

    internal static PortableCoreOptions Default { get; } = new();

    internal string? GetEnvironment(string name) => (Environment ?? System.Environment.GetEnvironmentVariable)(name);

    internal DateTimeOffset Now() => Clock?.Invoke() ?? DateTimeOffset.UtcNow;
}

/// <summary>
/// Portable Authenticode JSON façade — managed port of Rust <c>psign-portable-core</c> (the API behind the PowerShell
/// module's <c>psign-portable-ffi</c> and <c>psign-tool --mode portable sign</c>): sign, inspect / trust-verify, clear,
/// and file-catalog operations over the request / response models in this namespace. Errors are thrown as
/// <see cref="PsignException"/> (message = outermost context, like <c>anyhow</c>'s <c>Display</c>); use
/// <see cref="PortableCoreJson.Invoke(string, string?, PortableCoreOptions?)"/> for the FFI-style JSON contract.
/// </summary>
public static partial class PortableCore
{
    /// <summary>Response <c>schema_version</c>.</summary>
    public const uint SchemaVersion = 1;

    /// <summary>Crate name reported by <see cref="Version"/>.</summary>
    public const string CrateName = "psign-portable-core";

    private static readonly string[] MsixFlatExtensions = ["msix", "appx"];
    private static readonly string[] MsixBundleExtensions = ["msixbundle", "appxbundle"];

    /// <summary>Library identity (Rust <c>version</c>).</summary>
    public static PortableVersionResponse Version()
    {
        var v = typeof(PortableCore).Assembly.GetName().Version;
        var text = v is null ? "0.0.0" : $"{v.Major}.{v.Minor}.{Math.Max(v.Build, 0)}";
        return new PortableVersionResponse { CrateVersion = text };
    }

    /// <summary>Structured error payload (Rust <c>portable_error_response</c>).</summary>
    public static PortableErrorResponse CreateErrorResponse(PortableErrorCode code, string message) =>
        new() { Code = code, Message = message };

    /// <summary>
    /// Cleartext MSIX family extensions accepted by portable signing: flat <c>msix</c> / <c>appx</c> and
    /// <c>msixbundle</c> / <c>appxbundle</c> (Rust <c>is_portable_msix_family_extension</c>; exact lowercase match).
    /// </summary>
    public static bool IsPortableMsixFamilyExtension(string ext) =>
        MsixFlatExtensions.Contains(ext, StringComparer.Ordinal) || MsixBundleExtensions.Contains(ext, StringComparer.Ordinal);

    private static bool IsMsixBundleExtension(string ext) => MsixBundleExtensions.Contains(ext, StringComparer.Ordinal);

    /// <summary>File format from the path extension (Rust <c>infer_format</c>).</summary>
    public static PortableFileFormat InferFormat(string path)
    {
        if (RustPath.Extension(path) is not { } ext)
        {
            return PortableFileFormat.Unknown;
        }

        return Core.Text.RustText.ToAsciiLowercase(ext) switch
        {
            "exe" or "dll" or "sys" or "efi" or "winmd" or "mui" or "ocx" or "scr" or "cpl" => PortableFileFormat.Pe,
            "cab" => PortableFileFormat.Cab,
            "msi" or "msp" => PortableFileFormat.Msi,
            "msix" or "appx" or "msixbundle" or "appxbundle" => PortableFileFormat.Msix,
            "appxupload" or "msixupload" => PortableFileFormat.MsixUpload,
            "eappx" or "eappxbundle" or "emsix" or "emsixbundle" => PortableFileFormat.MsixEncrypted,
            "cat" => PortableFileFormat.Catalog,
            "nupkg" or "snupkg" => PortableFileFormat.NuGet,
            "vsix" => PortableFileFormat.Vsix,
            "manifest" or "application" or "vsto" => PortableFileFormat.ClickOnceManifest,
            "appinstaller" => PortableFileFormat.AppInstaller,
            "zip" => PortableFileFormat.Zip,
            "ps1" or "psm1" or "psd1" or "ps1xml" or "psc1" or "cdxml" or "mof" => PortableFileFormat.PowerShellScript,
            "vbs" or "vbe" or "js" or "jse" or "wsf" => PortableFileFormat.WshScript,
            _ => PortableFileFormat.Unknown,
        };
    }

    /// <summary>Extension-based format with a PE magic fallback for unknown extensions (Rust <c>infer_format_from_path_or_data</c>).</summary>
    internal static PortableFileFormat InferFormatFromPathOrData(string path, ReadOnlySpan<byte> data)
    {
        var format = InferFormat(path);
        if (format != PortableFileFormat.Unknown)
        {
            return format;
        }

        return IsProbablyPe(data) ? PortableFileFormat.Pe : PortableFileFormat.Unknown;
    }

    internal static bool IsProbablyPe(ReadOnlySpan<byte> data)
    {
        if (data.Length < 0x40 || data[0] != (byte)'M' || data[1] != (byte)'Z')
        {
            return false;
        }

        ulong peOffset = BitConverter.ToUInt32(data[0x3c..0x40]);
        return peOffset + 4 <= (ulong)data.Length && data.Slice((int)peOffset, 4).SequenceEqual("PE\0\0"u8);
    }

    /// <summary>Format for a PowerShell validation source: path extension or a bare extension name (Rust <c>infer_powershell_source_format</c>).</summary>
    internal static PortableFileFormat InferPowerShellSourceFormat(string path)
    {
        var format = InferFormat(path);
        if (format != PortableFileFormat.Unknown)
        {
            return format;
        }

        if (RustPath.FileName(path) is not { } source)
        {
            return PortableFileFormat.Unknown;
        }

        var extension = source.TrimStart('.');
        return PsScript.ExtensionSupported(extension) ? PortableFileFormat.PowerShellScript : PortableFileFormat.Unknown;
    }

    /// <summary>Lowercase extension or <c>ps1</c> (Rust <c>script_extension_for</c>).</summary>
    internal static string ScriptExtensionFor(string path) =>
        RustPath.Extension(path) is { } ext ? Core.Text.RustText.ToAsciiLowercase(ext) : "ps1";

    internal static byte[] ReadFile(string path, string? context = null)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException(context ?? $"read {path}", e);
        }
    }

    internal static void WriteFile(string path, byte[] data, string? context = null)
    {
        try
        {
            File.WriteAllBytes(path, data);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException(context ?? $"write {path}", e);
        }
    }

    internal static void CopyFile(string from, string to)
    {
        try
        {
            File.Copy(from, to, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"copy {from} to {to}", e);
        }
    }

    /// <summary>Whether two request paths name the same file (Rust compares <c>Path</c>s; resolved here to avoid self-copies).</summary>
    internal static bool SamePath(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.Ordinal))
        {
            return true;
        }

        try
        {
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), comparison);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    /// <summary><c>&lt;path&gt;.p7</c> companion of an App Installer descriptor (Rust <c>with_extension("{ext}.p7")</c>).</summary>
    internal static string AppInstallerCompanionPath(string path) => path + ".p7";
}

/// <summary>Rust <c>std::path::Path</c> name helpers (<c>file_name</c> / <c>extension</c>).</summary>
internal static class RustPath
{
    private static bool IsSeparator(char c) => c == '/' || (OperatingSystem.IsWindows() && c == '\\');

    /// <summary>Last normal component, or <c>null</c> when the path ends in <c>..</c> or has none.</summary>
    public static string? FileName(string path)
    {
        var p = path;
        if (OperatingSystem.IsWindows() && p.Length >= 2 && p[1] == ':' && char.IsAsciiLetter(p[0]))
        {
            p = p[2..];
        }

        string? last = null;
        int start = 0;
        for (int i = 0; i <= p.Length; i++)
        {
            if (i == p.Length || IsSeparator(p[i]))
            {
                if (i > start)
                {
                    var segment = p[start..i];
                    if (segment != ".")
                    {
                        last = segment;
                    }
                }

                start = i + 1;
            }
        }

        return last is null or ".." ? null : last;
    }

    /// <summary>Text after the last <c>.</c> of the file name (none for dotfiles such as <c>.ps1</c>).</summary>
    public static string? Extension(string path)
    {
        if (FileName(path) is not { } name)
        {
            return null;
        }

        int dot = name.LastIndexOf('.');
        return dot <= 0 ? null : name[(dot + 1)..];
    }
}
