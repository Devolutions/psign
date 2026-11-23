namespace Devolutions.Psign.Signing.Code;

/// <summary>Format classification of a planned input (Rust <c>code::CodeFormat</c>; the member names are the Rust <c>Debug</c> names).</summary>
public enum CodeFormat
{
    Pe,
    Winmd,
    Cab,
    Msi,
    Msp,
    Mst,
    Catalog,
    Script,
    Msix,
    Appx,
    MsixBundle,
    AppxBundle,
    AppxUpload,
    MsixUpload,
    EncryptedMsix,
    Nuget,
    Snupkg,
    Vsix,
    ClickOnceApplication,
    Vsto,
    Manifest,
    Deploy,
    AppInstaller,
    BusinessCentralApp,
    Zip,
    Unknown,
}

/// <summary>Helpers for <see cref="CodeFormat"/>.</summary>
public static class CodeFormats
{
    /// <summary>ZIP/OPC containers whose entries are planned recursively (Rust <c>CodeFormat::is_container</c>).</summary>
    public static bool IsContainer(this CodeFormat format) => format is CodeFormat.Nuget or CodeFormat.Snupkg or CodeFormat.Vsix
        or CodeFormat.Msix or CodeFormat.Appx or CodeFormat.MsixBundle or CodeFormat.AppxBundle or CodeFormat.AppxUpload
        or CodeFormat.MsixUpload or CodeFormat.Zip;

    /// <summary>serde <c>rename_all = "kebab-case"</c> name used in plan JSON.</summary>
    public static string KebabName(this CodeFormat format) => format switch
    {
        CodeFormat.MsixBundle => "msix-bundle",
        CodeFormat.AppxBundle => "appx-bundle",
        CodeFormat.AppxUpload => "appx-upload",
        CodeFormat.MsixUpload => "msix-upload",
        CodeFormat.EncryptedMsix => "encrypted-msix",
        CodeFormat.ClickOnceApplication => "click-once-application",
        CodeFormat.AppInstaller => "app-installer",
        CodeFormat.BusinessCentralApp => "business-central-app",
        _ => format.ToString().ToLowerInvariant(),
    };

    /// <summary>Rust <c>{:?}</c> rendering (the variant name).</summary>
    public static string DebugName(this CodeFormat format) => format.ToString();

    /// <summary>Signer family label (Rust <c>signer_for_format</c>).</summary>
    public static string SignerName(this CodeFormat format) => format switch
    {
        CodeFormat.Nuget or CodeFormat.Snupkg => "nuget-package-native",
        CodeFormat.Vsix => "vsix-opc-xmldsig",
        CodeFormat.ClickOnceApplication or CodeFormat.Vsto or CodeFormat.Manifest or CodeFormat.Deploy => "clickonce-manifest",
        CodeFormat.EncryptedMsix => "msix-encrypted-os-only",
        CodeFormat.AppInstaller => "appinstaller-detached-pkcs7",
        CodeFormat.BusinessCentralApp => "business-central-app",
        CodeFormat.Zip => "container-only",
        CodeFormat.Unknown => "unsupported",
        _ => "authenticode",
    };

    /// <summary>
    /// Classify <paramref name="path"/> by extension; <c>.app</c> files are Business Central packages only when
    /// <paramref name="bytes"/> starts with <c>NAVX</c> (Rust <c>detect_format</c>).
    /// </summary>
    public static CodeFormat Detect(string path, ReadOnlySpan<byte> bytes, bool haveBytes)
    {
        if (RustPath.IsExtension(path, "app"))
        {
            return haveBytes && bytes.StartsWith("NAVX"u8) ? CodeFormat.BusinessCentralApp : CodeFormat.Unknown;
        }

        return RustPath.Extension(path) is { } ext ? FromExtension(AsciiLower(ext)) : CodeFormat.Unknown;
    }

    /// <summary><see cref="Detect(string, ReadOnlySpan{byte}, bool)"/> without content bytes.</summary>
    public static CodeFormat Detect(string path) => Detect(path, default, false);

    private static CodeFormat FromExtension(string ext) => ext switch
    {
        "exe" or "dll" or "sys" or "ocx" or "efi" or "scr" or "cpl" or "mui" => CodeFormat.Pe,
        "winmd" => CodeFormat.Winmd,
        "cab" => CodeFormat.Cab,
        "msi" => CodeFormat.Msi,
        "msp" => CodeFormat.Msp,
        "mst" => CodeFormat.Mst,
        "cat" => CodeFormat.Catalog,
        "ps1" or "psd1" or "psm1" or "ps1xml" or "psc1" or "cdxml" or "mof" or "js" or "vbs" or "wsf" or "jse" or "vbe" or "wsc" => CodeFormat.Script,
        "msix" => CodeFormat.Msix,
        "appx" => CodeFormat.Appx,
        "msixbundle" => CodeFormat.MsixBundle,
        "appxbundle" => CodeFormat.AppxBundle,
        "appxupload" => CodeFormat.AppxUpload,
        "msixupload" => CodeFormat.MsixUpload,
        "eappx" or "emsix" or "eappxbundle" or "emsixbundle" => CodeFormat.EncryptedMsix,
        "nupkg" => CodeFormat.Nuget,
        "snupkg" => CodeFormat.Snupkg,
        "vsix" => CodeFormat.Vsix,
        "application" => CodeFormat.ClickOnceApplication,
        "vsto" => CodeFormat.Vsto,
        "manifest" => CodeFormat.Manifest,
        "deploy" => CodeFormat.Deploy,
        "appinstaller" => CodeFormat.AppInstaller,
        "zip" => CodeFormat.Zip,
        _ => CodeFormat.Unknown,
    };

    /// <summary>Formats the nested executor refuses explicitly (Rust <c>is_unsupported_nested_signable</c>).</summary>
    internal static bool IsUnsupportedNestedSignable(this CodeFormat format) => format is CodeFormat.Cab or CodeFormat.Msi
        or CodeFormat.Msp or CodeFormat.Mst or CodeFormat.Catalog or CodeFormat.Script or CodeFormat.Msix or CodeFormat.Appx
        or CodeFormat.MsixBundle or CodeFormat.AppxBundle or CodeFormat.AppxUpload or CodeFormat.MsixUpload
        or CodeFormat.EncryptedMsix or CodeFormat.ClickOnceApplication or CodeFormat.Vsto or CodeFormat.Manifest
        or CodeFormat.AppInstaller or CodeFormat.BusinessCentralApp;

    internal static bool IsMsixFamily(this CodeFormat format) => format is CodeFormat.Msix or CodeFormat.Appx
        or CodeFormat.MsixBundle or CodeFormat.AppxBundle or CodeFormat.AppxUpload or CodeFormat.MsixUpload;

    internal static string AsciiLower(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            if (chars[i] is >= 'A' and <= 'Z')
            {
                chars[i] = (char)(chars[i] + 32);
            }
        }

        return new string(chars);
    }
}
