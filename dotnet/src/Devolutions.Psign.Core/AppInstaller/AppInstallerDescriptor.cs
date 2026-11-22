using System.Text;
using Devolutions.Psign.Core.Xml;

namespace Devolutions.Psign.Core.AppInstaller;

/// <summary>App Installer descriptor summary (Rust <c>AppInstallerDescriptorInfo</c>).</summary>
public sealed record AppInstallerDescriptorInfo(string Root, string? Namespace, bool HasMainPackage, bool HasMainBundle, string? Publisher);

/// <summary>
/// <c>.appinstaller</c> descriptor helpers (ported from <c>parse_appinstaller_descriptor</c> /
/// <c>update_appinstaller_publisher</c> in Rust <c>psign-digest-cli/src/main.rs</c>). Companion PKCS#7 signing lives in
/// <c>Devolutions.Psign.Signing.AppInstaller.AppInstallerCompanionSigner</c>; detached-signature trust verification is
/// performed by the verification port over <see cref="CompanionSignedContent"/>.
/// </summary>
public static class AppInstallerDescriptor
{
    /// <summary>Read a descriptor as strict UTF-8 (Rust <c>read_to_string</c>).</summary>
    public static string ReadText(string path)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(File.ReadAllBytes(path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read {path}", e);
        }
        catch (DecoderFallbackException)
        {
            throw new PsignException($"read {path}", new PsignException("stream did not contain valid UTF-8"));
        }
    }

    /// <summary>Rust <c>parse_appinstaller_descriptor</c>.</summary>
    public static AppInstallerDescriptorInfo Parse(string text)
    {
        int rootStart = text.IndexOf("<AppInstaller", StringComparison.Ordinal);
        if (rootStart < 0)
        {
            throw new PsignException("App Installer descriptor root <AppInstaller> not found");
        }

        int rootEnd = text.IndexOf('>', rootStart);
        if (rootEnd < 0)
        {
            throw new PsignException("App Installer root tag is not closed");
        }

        string rootTag = text[rootStart..(rootEnd + 1)];
        string? ns = XmlTextScan.XmlAttr(rootTag, "xmlns");
        string? mainPackage;
        string? mainBundle;
        try
        {
            mainPackage = XmlTextScan.FirstStartTagByLocalName(text, "MainPackage");
        }
        catch (PsignException e)
        {
            throw new PsignException("parse MainPackage tag", e);
        }

        try
        {
            mainBundle = XmlTextScan.FirstStartTagByLocalName(text, "MainBundle");
        }
        catch (PsignException e)
        {
            throw new PsignException("parse MainBundle tag", e);
        }

        string? publisher = (mainPackage is null ? null : XmlTextScan.XmlAttr(mainPackage, "Publisher"))
            ?? (mainBundle is null ? null : XmlTextScan.XmlAttr(mainBundle, "Publisher"));
        return new AppInstallerDescriptorInfo("AppInstaller", ns, mainPackage is not null, mainBundle is not null, publisher);
    }

    /// <summary>Set <c>Publisher</c> on every <c>MainPackage</c> / <c>MainBundle</c> (Rust <c>update_appinstaller_publisher</c>).</summary>
    public static string UpdatePublisher(string text, string publisher)
    {
        if (publisher.Length == 0)
        {
            throw new PsignException("App Installer publisher cannot be empty");
        }

        var info = Parse(text);
        if (!info.HasMainPackage && !info.HasMainBundle)
        {
            throw new PsignException("App Installer descriptor does not contain MainPackage or MainBundle");
        }

        string escaped = XmlTextScan.XmlEscapeAttr(publisher);
        string updated = text;
        foreach (var tag in new[] { "MainPackage", "MainBundle" })
        {
            updated = XmlTextScan.UpdateAttrForLocalTags(updated, tag, "Publisher", escaped);
        }

        return updated;
    }

    /// <summary>
    /// Content covered by the detached companion signature: the descriptor text's UTF-8 octets (the Rust commands sign
    /// <c>text.as_bytes()</c> after a strict UTF-8 read).
    /// </summary>
    public static byte[] CompanionSignedContent(string text) => Encoding.UTF8.GetBytes(text);
}
