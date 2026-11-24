using System.Globalization;
using System.Text;

namespace Devolutions.Psign.Core.Xml;

/// <summary>Start tag span: <c>&lt;</c> offset, <c>&gt;</c> offset (inclusive) and the qualified name.</summary>
public readonly record struct XmlStartTagSpan(int Start, int End, string Name);

/// <summary>Element content span (between the start tag's <c>&gt;</c> and the matching end tag).</summary>
public readonly record struct XmlElementSpan(int ContentStart, int ContentEnd);

/// <summary>
/// Text-level XML span helpers used by the ClickOnce / App Installer / MSIX manifest commands (ported from the
/// <c>find_xml_*</c>, <c>xml_attr</c> and attribute rewrite helpers in Rust <c>psign-digest-cli/src/main.rs</c>). They
/// operate on the original text so edits preserve formatting byte-for-byte.
/// </summary>
public static class XmlTextScan
{
    /// <summary>Offset of <c>&lt;tag</c> followed by whitespace, <c>&gt;</c> or <c>/</c> (Rust <c>find_xml_start_tag</c>).</summary>
    public static int? FindXmlStartTag(string text, string tag, int from)
    {
        string needle = "<" + tag;
        int cursor = from;
        while (true)
        {
            int start = text.IndexOf(needle, cursor, StringComparison.Ordinal);
            if (start < 0)
            {
                return null;
            }

            int nextIdx = start + needle.Length;
            if (nextIdx < text.Length && text[nextIdx] is ' ' or '\t' or '\r' or '\n' or '>' or '/')
            {
                return start;
            }

            cursor = start + needle.Length;
        }
    }

    /// <summary>First start tag whose local name matches (Rust <c>find_xml_start_tag_by_local_name</c>).</summary>
    public static XmlStartTagSpan? FindXmlStartTagByLocalName(string text, string localName, int from)
    {
        int cursor = from;
        while (true)
        {
            int start = text.IndexOf('<', cursor);
            if (start < 0)
            {
                return null;
            }

            if (start + 1 >= text.Length)
            {
                return null;
            }

            char first = text[start + 1];
            if (first == '!')
            {
                if (text.AsSpan(start).StartsWith("<!--", StringComparison.Ordinal))
                {
                    int commentEnd = text.IndexOf("-->", start + 4, StringComparison.Ordinal);
                    if (commentEnd < 0)
                    {
                        throw new PsignException("ClickOnce XML comment is not closed");
                    }

                    cursor = commentEnd + 3;
                    continue;
                }

                if (text.AsSpan(start).StartsWith("<![CDATA[", StringComparison.Ordinal))
                {
                    int cdataEnd = text.IndexOf("]]>", start + 9, StringComparison.Ordinal);
                    if (cdataEnd < 0)
                    {
                        throw new PsignException("ClickOnce XML CDATA is not closed");
                    }

                    cursor = cdataEnd + 3;
                    continue;
                }

                int declEnd = text.IndexOf('>', start + 2);
                cursor = declEnd < 0 ? text.Length : declEnd + 1;
                continue;
            }

            if (first == '?')
            {
                int piEnd = text.IndexOf("?>", start + 2, StringComparison.Ordinal);
                cursor = piEnd < 0 ? text.Length : piEnd + 2;
                continue;
            }

            if (first == '/')
            {
                cursor = start + 1;
                continue;
            }

            int end = text.IndexOf('>', start);
            if (end < 0)
            {
                throw new PsignException("ClickOnce XML tag is not closed");
            }

            int nameStart = start + 1;
            int nameEnd = end;
            for (int i = nameStart; i <= end; i++)
            {
                char ch = text[i];
                if (char.IsWhiteSpace(ch) || ch == '>' || ch == '/')
                {
                    nameEnd = i;
                    break;
                }
            }

            string name = text[nameStart..nameEnd];
            int colon = name.LastIndexOf(':');
            string nameLocal = colon < 0 ? name : name[(colon + 1)..];
            if (nameLocal == localName)
            {
                return new XmlStartTagSpan(start, end, name);
            }

            cursor = end + 1;
        }
    }

    /// <summary>Content span of the first element with the local name (Rust <c>find_xml_element_by_local_name</c>).</summary>
    public static XmlElementSpan? FindXmlElementByLocalName(string text, string localName, int from)
    {
        if (FindXmlStartTagByLocalName(text, localName, from) is not { } startTag)
        {
            return null;
        }

        string close = $"</{startTag.Name}>";
        int contentStart = startTag.End + 1;
        int contentEnd = text.IndexOf(close, contentStart, StringComparison.Ordinal);
        if (contentEnd < 0)
        {
            throw new PsignException($"ClickOnce XML </{startTag.Name}> tag is not closed");
        }

        return new XmlElementSpan(contentStart, contentEnd);
    }

    /// <summary>Whole element span <c>[start, end)</c> (Rust <c>find_xml_element_span_by_local_name</c>).</summary>
    public static (int Start, int End)? FindXmlElementSpanByLocalName(string text, string localName, int from)
    {
        if (FindXmlStartTagByLocalName(text, localName, from) is not { } startTag)
        {
            return null;
        }

        string close = $"</{startTag.Name}>";
        int contentStart = startTag.End + 1;
        int closeStart = text.IndexOf(close, contentStart, StringComparison.Ordinal);
        if (closeStart < 0)
        {
            throw new PsignException($"ClickOnce XML </{startTag.Name}> tag is not closed");
        }

        return (startTag.Start, closeStart + close.Length);
    }

    /// <summary>Document element start tag (Rust <c>find_xml_root_start_tag</c>).</summary>
    public static XmlStartTagSpan FindXmlRootStartTag(string text)
    {
        int cursor = 0;
        while (true)
        {
            int start = text.IndexOf('<', cursor);
            if (start < 0 || start + 1 >= text.Length)
            {
                break;
            }

            char first = text[start + 1];
            if (first == '?')
            {
                int piEnd = text.IndexOf("?>", start + 2, StringComparison.Ordinal);
                if (piEnd < 0)
                {
                    throw new PsignException("ClickOnce XML declaration/comment is not closed");
                }

                cursor = piEnd + 2;
                continue;
            }

            if (first == '!')
            {
                if (text.AsSpan(start).StartsWith("<!--", StringComparison.Ordinal))
                {
                    int commentEnd = text.IndexOf("-->", start + 4, StringComparison.Ordinal);
                    if (commentEnd < 0)
                    {
                        throw new PsignException("ClickOnce XML declaration/comment is not closed");
                    }

                    cursor = commentEnd + 3;
                    continue;
                }

                int declEnd = text.IndexOf('>', start);
                if (declEnd < 0)
                {
                    throw new PsignException("ClickOnce XML declaration/comment is not closed");
                }

                cursor = declEnd + 1;
                continue;
            }

            if (first == '/')
            {
                throw new PsignException("ClickOnce XML starts with an unexpected closing tag");
            }

            int end = text.IndexOf('>', start);
            if (end < 0)
            {
                throw new PsignException("ClickOnce XML root tag is not closed");
            }

            int nameStart = start + 1;
            int nameEnd = end;
            for (int i = nameStart; i <= end; i++)
            {
                char ch = text[i];
                if (char.IsWhiteSpace(ch) || ch == '>' || ch == '/')
                {
                    nameEnd = i;
                    break;
                }
            }

            return new XmlStartTagSpan(start, end, text[nameStart..nameEnd]);
        }

        throw new PsignException("ClickOnce manifest does not contain a root XML element");
    }

    /// <summary>First <c>&lt;tag...&gt;</c> (prefix match, Rust <c>first_tag</c>).</summary>
    public static string? FirstTag(string text, string tag)
    {
        int start = text.IndexOf("<" + tag, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        int end = text.IndexOf('>', start);
        return end < 0 ? null : text[start..(end + 1)];
    }

    /// <summary>First start tag text with the local name (Rust <c>first_start_tag_by_local_name</c>).</summary>
    public static string? FirstStartTagByLocalName(string text, string localName) =>
        FindXmlStartTagByLocalName(text, localName, 0) is { } tag ? text[tag.Start..(tag.End + 1)] : null;

    /// <summary>
    /// Unescaped attribute value; the name must be preceded by ASCII whitespace or start the string (Rust
    /// <c>xml_attr</c> in <c>psign-digest-cli</c>).
    /// </summary>
    public static string? XmlAttr(string tag, string name)
    {
        foreach (char quote in new[] { '"', '\'' })
        {
            string needle = $"{name}={quote}";
            int searchFrom = 0;
            while (true)
            {
                int attrPos = tag.IndexOf(needle, searchFrom, StringComparison.Ordinal);
                if (attrPos < 0)
                {
                    break;
                }

                bool boundaryOk = attrPos == 0 || IsAsciiWhitespace(tag[attrPos - 1]);
                int valStart = attrPos + needle.Length;
                if (boundaryOk)
                {
                    int valEnd = tag.IndexOf(quote, valStart);
                    if (valEnd < 0)
                    {
                        return null;
                    }

                    return XmlUnescapeAttr(tag[valStart..valEnd]);
                }

                searchFrom = valStart;
            }
        }

        return null;
    }

    /// <summary>Lenient entity decoding (Rust <c>xml_unescape_attr</c>): unknown references are kept literally.</summary>
    public static string XmlUnescapeAttr(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        int rest = 0;
        while (true)
        {
            int amp = raw.IndexOf('&', rest);
            if (amp < 0)
            {
                break;
            }

            sb.Append(raw, rest, amp - rest);
            int afterAmp = amp + 1;
            int semi = raw.IndexOf(';', afterAmp);
            if (semi >= 0)
            {
                string entity = raw[afterAmp..semi];
                string? decoded = entity switch
                {
                    "amp" => "&",
                    "quot" => "\"",
                    "apos" => "'",
                    "lt" => "<",
                    "gt" => ">",
                    _ when entity.StartsWith("#x", StringComparison.Ordinal) || entity.StartsWith("#X", StringComparison.Ordinal) =>
                        DecodeScalar(entity[2..], NumberStyles.AllowHexSpecifier),
                    _ when entity.StartsWith('#') => DecodeScalar(entity[1..], NumberStyles.None),
                    _ => null,
                };
                if (decoded is not null)
                {
                    sb.Append(decoded);
                    rest = semi + 1;
                    continue;
                }
            }

            sb.Append('&');
            rest = afterAmp;
        }

        sb.Append(raw, rest, raw.Length - rest);
        return sb.ToString();
    }

    private static string? DecodeScalar(string digits, NumberStyles style)
    {
        // Rust u32::from_str_radix accepts an optional leading '+'.
        string d = digits.StartsWith('+') ? digits[1..] : digits;
        if (d.Length == 0 || !uint.TryParse(d, style, CultureInfo.InvariantCulture, out uint v))
        {
            return null;
        }

        if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF))
        {
            return null;
        }

        return char.ConvertFromUtf32((int)v);
    }

    /// <summary>Escape an attribute value (Rust <c>xml_escape_attr</c>).</summary>
    public static string XmlEscapeAttr(string value) =>
        value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);

    /// <summary>
    /// Replace the first <c>attr="..."</c> value in a start tag, or insert the attribute before <c>/&gt;</c> or
    /// <c>&gt;</c> (Rust <c>replace_or_insert_xml_attr</c>).
    /// </summary>
    public static string ReplaceOrInsertXmlAttr(string tag, string attr, string escapedValue)
    {
        foreach (char quote in new[] { '"', '\'' })
        {
            string needle = $"{attr}={quote}";
            int searchFrom = 0;
            while (true)
            {
                int idx = tag.IndexOf(needle, searchFrom, StringComparison.Ordinal);
                if (idx < 0)
                {
                    break;
                }

                bool boundaryOk = idx == 0 || IsAsciiWhitespace(tag[idx - 1]);
                int valueStart = idx + needle.Length;
                if (boundaryOk)
                {
                    int valueEnd = tag.IndexOf(quote, valueStart);
                    if (valueEnd < 0)
                    {
                        throw new PsignException($"App Installer {attr} attribute is not closed");
                    }

                    return tag[..idx] + attr + "=\"" + escapedValue + "\"" + tag[(valueEnd + 1)..];
                }

                searchFrom = valueStart;
            }
        }

        int insertAt = tag.LastIndexOf("/>", StringComparison.Ordinal);
        if (insertAt < 0)
        {
            insertAt = tag.LastIndexOf('>');
        }

        if (insertAt < 0)
        {
            throw new PsignException("App Installer tag is not closed");
        }

        return tag[..insertAt] + " " + attr + "=\"" + escapedValue + "\"" + tag[insertAt..];
    }

    /// <summary>Rewrite <paramref name="attr"/> on every start tag with the local name (Rust <c>update_attr_for_local_tags</c>).</summary>
    public static string UpdateAttrForLocalTags(string text, string localName, string attr, string escapedValue)
    {
        var sb = new StringBuilder(text.Length);
        int cursor = 0;
        while (FindXmlStartTagByLocalName(text, localName, cursor) is { } tag)
        {
            sb.Append(text, cursor, tag.Start - cursor);
            sb.Append(ReplaceOrInsertXmlAttr(text[tag.Start..(tag.End + 1)], attr, escapedValue));
            cursor = tag.End + 1;
        }

        sb.Append(text, cursor, text.Length - cursor);
        return sb.ToString();
    }

    private static bool IsAsciiWhitespace(char c) => c is ' ' or '\t' or '\n' or '\r' or '\f';
}
