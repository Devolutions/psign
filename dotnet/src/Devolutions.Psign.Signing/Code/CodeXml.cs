using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Xml;

namespace Devolutions.Psign.Signing.Code;

/// <summary>
/// App Installer descriptor helpers of the <c>code</c> orchestrator (Rust <c>validate_appinstaller_descriptor</c>,
/// <c>update_appinstaller_publisher_bytes</c>, <c>update_attr_for_local_tags</c>, <c>replace_or_insert_xml_attr</c>).
/// </summary>
internal static class CodeXml
{
    /// <summary>Rust <c>validate_appinstaller_descriptor</c>.</summary>
    public static void ValidateAppInstallerDescriptor(byte[] bytes)
    {
        var text = RustIo.Utf8(bytes, "App Installer descriptor is not UTF-8");
        if (XmlTextScan.FindXmlStartTagByLocalName(text, "AppInstaller", 0) is null)
        {
            throw new PsignException("App Installer descriptor root <AppInstaller> not found");
        }

        if (XmlTextScan.FindXmlStartTagByLocalName(text, "MainPackage", 0) is null
            && XmlTextScan.FindXmlStartTagByLocalName(text, "MainBundle", 0) is null)
        {
            throw new PsignException("App Installer descriptor does not contain MainPackage or MainBundle");
        }
    }

    /// <summary>Rewrite <c>Publisher</c> on every <c>MainPackage</c> / <c>MainBundle</c> start tag (Rust <c>update_appinstaller_publisher_bytes</c>).</summary>
    public static byte[] UpdateAppInstallerPublisherBytes(byte[] bytes, string publisher)
    {
        if (publisher.Length == 0)
        {
            throw new PsignException("App Installer publisher cannot be empty");
        }

        var text = RustIo.Utf8(bytes, "App Installer descriptor is not UTF-8");
        ValidateAppInstallerDescriptor(bytes);
        var escaped = XmlTextScan.XmlEscapeAttr(publisher);
        var updated = text;
        foreach (var tag in new[] { "MainPackage", "MainBundle" })
        {
            updated = UpdateAttrForLocalTags(updated, tag, "Publisher", escaped);
        }

        return Encoding.UTF8.GetBytes(updated);
    }

    private static string UpdateAttrForLocalTags(string text, string localName, string attr, string escapedValue) =>
        XmlTextScan.UpdateAttrForLocalTags(text, localName, attr, escapedValue);
}
