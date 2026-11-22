using System.Text;

namespace Devolutions.Psign.Core.Msix;

/// <summary>Event kinds produced by <see cref="QuickXmlReader"/> (Rust <c>quick_xml::events::Event</c>).</summary>
internal enum XmlEventKind
{
    Start,
    End,
    Empty,
    Text,
    CData,
    Comment,
    Decl,
    PI,
    DocType,
    GeneralRef,
    Eof,
}

/// <summary>Raw XML attribute: key and still-escaped value bytes.</summary>
internal readonly record struct XmlAttribute(byte[] Key, byte[] Value)
{
    public string KeyString => Encoding.UTF8.GetString(Key);

    public bool KeyIs(string name) => Key.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(name));

    /// <summary>UTF-8 decode and unescape the value (Rust <c>decode_and_unescape_value</c>).</summary>
    public string DecodeAndUnescape() => QuickXml.Unescape(QuickXml.DecodeUtf8(Value));
}

/// <summary>One XML event. For element events <see cref="Content"/> is the bytes between <c>&lt;</c> and <c>&gt;</c>
/// (minus the trailing <c>/</c> for <see cref="XmlEventKind.Empty"/>).</summary>
internal sealed class XmlEvent
{
    public XmlEvent(XmlEventKind kind, byte[] content, int nameLen = 0)
    {
        Kind = kind;
        Content = content;
        NameLen = nameLen;
    }

    public XmlEventKind Kind { get; }

    public byte[] Content { get; private set; }

    public int NameLen { get; }

    /// <summary>Qualified element name.</summary>
    public ReadOnlySpan<byte> Name => Content.AsSpan(0, NameLen);

    /// <summary>Local name (after the last <c>:</c>).</summary>
    public string LocalName
    {
        get
        {
            var name = Kind == XmlEventKind.End ? Content.AsSpan() : Name;
            int colon = name.IndexOf((byte)':');
            return Encoding.UTF8.GetString(colon >= 0 ? name[(colon + 1)..] : name);
        }
    }

    /// <summary>Iterate attributes lazily with quick-xml's XML-mode checks (errors throw when reached).</summary>
    public IEnumerable<XmlAttribute> Attributes() => QuickXml.ParseAttributes(Content, NameLen);

    /// <summary>Clone with all attributes removed (Rust <c>to_owned().clear_attributes()</c>).</summary>
    public XmlEvent CloneWithoutAttributes() => new(Kind, Content.AsSpan(0, NameLen).ToArray(), NameLen);

    /// <summary>Append an attribute with a raw (already escaped) value (Rust <c>push_attribute(Attribute)</c>).</summary>
    public void PushRawAttribute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> value)
    {
        var sb = new List<byte>(Content.Length + key.Length + value.Length + 4);
        sb.AddRange(Content);
        sb.Add((byte)' ');
        sb.AddRange(key.ToArray());
        sb.Add((byte)'=');
        sb.Add((byte)'"');
        sb.AddRange(value.ToArray());
        sb.Add((byte)'"');
        Content = sb.ToArray();
    }

    /// <summary>Append an attribute from text, escaping the value (Rust <c>push_attribute((&amp;str, &amp;str))</c>).</summary>
    public void PushAttribute(string key, string value) =>
        PushRawAttribute(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(QuickXml.Escape(value)));
}

/// <summary>Malformed XML (Rust <c>quick_xml::Error</c>).</summary>
internal sealed class QuickXmlException : Exception
{
    public QuickXmlException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// Minimal pull parser reproducing the Rust <c>quick_xml</c> 0.38 <c>Reader</c> over a byte slice (no namespace
/// processing, BOM stripping, end-name checks, general references emitted as separate events, optional text
/// trimming). Used where the Rust code relies on quick-xml tokenization semantics.
/// </summary>
internal sealed class QuickXmlReader
{
    private enum State
    {
        Init,
        InsideText,
        InsideRef,
        InsideMarkup,
        Done,
    }

    private readonly byte[] _buf;
    private readonly bool _trimText;
    private readonly List<byte[]> _opened = [];
    private int _pos;
    private State _state = State.Init;

    public QuickXmlReader(byte[] xml, bool trimText)
    {
        _buf = xml;
        _trimText = trimText;
    }

    public XmlEvent Read()
    {
        while (true)
        {
            switch (_state)
            {
                case State.Init:
                    if (_buf.AsSpan().StartsWith("﻿"u8))
                    {
                        _pos = 3;
                    }

                    _state = State.InsideText;
                    continue;
                case State.InsideText:
                    {
                        if (_trimText)
                        {
                            while (_pos < _buf.Length && IsWhitespace(_buf[_pos]))
                            {
                                _pos++;
                            }
                        }

                        var rest = _buf.AsSpan(_pos);
                        int i = rest.IndexOfAny((byte)'<', (byte)'&');
                        if (i == 0 && rest[0] == '<')
                        {
                            _pos++;
                            _state = State.InsideMarkup;
                            continue;
                        }

                        if (i == 0)
                        {
                            _state = State.InsideRef;
                            continue;
                        }

                        if (i > 0 && rest[i] == '<')
                        {
                            var bytes = rest[..i].ToArray();
                            _pos += i + 1;
                            _state = State.InsideMarkup;
                            return Done(new XmlEvent(XmlEventKind.Text, TrimEnd(bytes)));
                        }

                        if (i > 0)
                        {
                            var bytes = rest[..i].ToArray();
                            _pos += i;
                            _state = State.InsideRef;
                            return Done(new XmlEvent(XmlEventKind.Text, TrimEnd(bytes)));
                        }

                        var tail = TrimEnd(rest.ToArray());
                        _pos = _buf.Length;
                        _state = State.Done;
                        return Done(tail.Length == 0 ? new XmlEvent(XmlEventKind.Eof, []) : new XmlEvent(XmlEventKind.Text, tail));
                    }

                case State.InsideRef:
                    {
                        var rest = _buf.AsSpan(_pos);
                        int i = rest[1..].IndexOfAny((byte)';', (byte)'&', (byte)'<');
                        if (i >= 0 && rest[i + 1] == '&')
                        {
                            _pos += i + 1;
                            throw new QuickXmlException("ill-formed document: unclosed reference");
                        }

                        if (i >= 0)
                        {
                            int end = i + 1;
                            bool isEnd = rest[end] == ';';
                            var bytes = rest[..end].ToArray();
                            _pos += end + 1;
                            if (isEnd)
                            {
                                _state = State.InsideText;
                                return Done(new XmlEvent(XmlEventKind.GeneralRef, bytes[1..]));
                            }

                            _state = State.InsideMarkup;
                            throw new QuickXmlException("ill-formed document: unclosed reference");
                        }

                        _state = State.Done;
                        throw new QuickXmlException("ill-formed document: unclosed reference");
                    }

                case State.InsideMarkup:
                    return Done(ReadUntilClose());
                case State.Done:
                    return new XmlEvent(XmlEventKind.Eof, []);
            }
        }
    }

    private XmlEvent Done(XmlEvent e)
    {
        if (e.Kind == XmlEventKind.Eof)
        {
            _state = State.Done;
        }

        return e;
    }

    private byte[] TrimEnd(byte[] bytes)
    {
        if (!_trimText)
        {
            return bytes;
        }

        int len = bytes.Length;
        while (len > 0 && IsWhitespace(bytes[len - 1]))
        {
            len--;
        }

        return len == bytes.Length ? bytes : bytes[..len];
    }

    private XmlEvent ReadUntilClose()
    {
        _state = State.InsideText;
        if (_pos >= _buf.Length)
        {
            _state = State.Done;
            throw new QuickXmlException("syntax error: tag not closed: `>` not found before end of input");
        }

        var rest = _buf.AsSpan(_pos);
        switch (rest[0])
        {
            case (byte)'!':
                return ReadBang(rest);
            case (byte)'/':
                {
                    int i = FindElementEnd(rest);
                    var content = rest[..i].ToArray();
                    _pos += i + 1;
                    return EmitEnd(content);
                }

            case (byte)'?':
                {
                    int i = -1;
                    for (int k = 0; k < rest.Length; k++)
                    {
                        if (rest[k] == '>' && k > 0 && rest[k - 1] == '?')
                        {
                            i = k;
                            break;
                        }
                    }

                    if (i < 0)
                    {
                        _pos = _buf.Length;
                        _state = State.Done;
                        throw new QuickXmlException("syntax error: processing instruction or xml declaration not closed: `?>` not found before end of input");
                    }

                    var content = rest[..i].ToArray();
                    _pos += i + 1;
                    int len = content.Length;
                    if (len > 1 && content[len - 1] == '?')
                    {
                        var inner = content[1..(len - 1)];
                        bool decl = inner.AsSpan().StartsWith("xml"u8) && (inner.Length == 3 || IsWhitespace(inner[3]));
                        return new XmlEvent(decl ? XmlEventKind.Decl : XmlEventKind.PI, inner, NameLength(inner));
                    }

                    _state = State.Done;
                    throw new QuickXmlException("syntax error: processing instruction or xml declaration not closed: `?>` not found before end of input");
                }

            default:
                {
                    int i = FindElementEnd(rest);
                    var content = rest[..i].ToArray();
                    _pos += i + 1;
                    if (content.Length > 0 && content[^1] == '/')
                    {
                        var c = content[..^1];
                        return new XmlEvent(XmlEventKind.Empty, c, NameLength(c));
                    }

                    var start = new XmlEvent(XmlEventKind.Start, content, NameLength(content));
                    _opened.Add(start.Name.ToArray());
                    return start;
                }
        }
    }

    private int FindElementEnd(ReadOnlySpan<byte> rest)
    {
        byte quote = 0;
        for (int k = 0; k < rest.Length; k++)
        {
            byte b = rest[k];
            if (quote == 0)
            {
                if (b == '>')
                {
                    return k;
                }

                if (b is (byte)'"' or (byte)'\'')
                {
                    quote = b;
                }
            }
            else if (b == quote)
            {
                quote = 0;
            }
        }

        _pos = _buf.Length;
        _state = State.Done;
        throw new QuickXmlException("syntax error: tag not closed: `>` not found before end of input");
    }

    private XmlEvent EmitEnd(byte[] buf)
    {
        var content = buf.AsSpan(1);
        int last = content.Length - 1;
        while (last >= 0 && IsWhitespace(content[last]))
        {
            last--;
        }

        var name = last >= 0 ? content[..(last + 1)].ToArray() : content.ToArray();
        if (_opened.Count == 0)
        {
            throw new QuickXmlException($"ill-formed document: close tag `</{Encoding.UTF8.GetString(name)}>` does not match any open tag");
        }

        var expected = _opened[^1];
        _opened.RemoveAt(_opened.Count - 1);
        if (!expected.AsSpan().SequenceEqual(name))
        {
            throw new QuickXmlException($"ill-formed document: expected `</{Encoding.UTF8.GetString(expected)}>`, but `</{Encoding.UTF8.GetString(name)}>` was found");
        }

        return new XmlEvent(XmlEventKind.End, name, name.Length);
    }

    private XmlEvent ReadBang(ReadOnlySpan<byte> rest)
    {
        byte kind = rest.Length > 1 ? rest[1] : (byte)0;
        int end = -1;
        string unclosed;
        switch (kind)
        {
            case (byte)'[':
                unclosed = "CDATA not closed: `]]>` not found before end of input";
                for (int i = 0; i < rest.Length; i++)
                {
                    if (rest[i] == '>' && rest[..i].EndsWith("]]"u8))
                    {
                        end = i;
                        break;
                    }
                }

                break;
            case (byte)'-':
                unclosed = "comment not closed: `-->` not found before end of input";
                for (int i = 0; i < rest.Length; i++)
                {
                    if (rest[i] == '>' && i > 4 && rest[..i].EndsWith("--"u8))
                    {
                        end = i;
                        break;
                    }
                }

                break;
            case (byte)'D' or (byte)'d':
                unclosed = "DOCTYPE not closed: `>` not found before end of input";
                int balance = 0;
                for (int i = 0; i < rest.Length; i++)
                {
                    if (rest[i] == '<')
                    {
                        balance++;
                    }
                    else if (rest[i] == '>')
                    {
                        if (balance == 0)
                        {
                            end = i;
                            break;
                        }

                        balance--;
                    }
                }

                break;
            default:
                _state = State.Done;
                throw new QuickXmlException("syntax error: unknown or missed symbol in markup");
        }

        if (end < 0)
        {
            _pos = _buf.Length;
            _state = State.Done;
            throw new QuickXmlException("syntax error: " + unclosed);
        }

        var buf = rest[..end].ToArray();
        _pos += end + 1;
        int len = buf.Length;
        if (kind == '-' && buf.AsSpan().StartsWith("!--"u8))
        {
            return new XmlEvent(XmlEventKind.Comment, buf[3..(len - 2)]);
        }

        if (kind == '[' && buf.AsSpan().StartsWith("![CDATA["u8))
        {
            return new XmlEvent(XmlEventKind.CData, buf[8..(len - 2)]);
        }

        if (kind is (byte)'D' or (byte)'d' && len >= 8 && Encoding.ASCII.GetString(buf, 0, 8).Equals("!DOCTYPE", StringComparison.OrdinalIgnoreCase))
        {
            int s = 8;
            while (s < len && IsWhitespace(buf[s]))
            {
                s++;
            }

            if (s == len)
            {
                throw new QuickXmlException("ill-formed document: missing DOCTYPE name");
            }

            return new XmlEvent(XmlEventKind.DocType, buf[s..]);
        }

        _state = State.Done;
        throw new QuickXmlException("syntax error: " + unclosed);
    }

    internal static bool IsWhitespace(byte b) => b is (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t';

    internal static int NameLength(ReadOnlySpan<byte> bytes)
    {
        int n = 0;
        while (n < bytes.Length && !IsWhitespace(bytes[n]))
        {
            n++;
        }

        return n;
    }
}

/// <summary>XML writer reproducing <c>quick_xml::Writer::write_event</c> (no indentation).</summary>
internal sealed class QuickXmlWriter
{
    private readonly MemoryStream _out = new();

    public void Write(XmlEvent e)
    {
        switch (e.Kind)
        {
            case XmlEventKind.Start:
                Wrapped("<"u8, e.Content, ">"u8);
                break;
            case XmlEventKind.End:
                Wrapped("</"u8, e.Content, ">"u8);
                break;
            case XmlEventKind.Empty:
                Wrapped("<"u8, e.Content, "/>"u8);
                break;
            case XmlEventKind.Text:
                _out.Write(e.Content);
                break;
            case XmlEventKind.Comment:
                Wrapped("<!--"u8, e.Content, "-->"u8);
                break;
            case XmlEventKind.CData:
                Wrapped("<![CDATA["u8, e.Content, "]]>"u8);
                break;
            case XmlEventKind.Decl:
            case XmlEventKind.PI:
                Wrapped("<?"u8, e.Content, "?>"u8);
                break;
            case XmlEventKind.DocType:
                Wrapped("<!DOCTYPE "u8, e.Content, ">"u8);
                break;
            case XmlEventKind.GeneralRef:
                Wrapped("&"u8, e.Content, ";"u8);
                break;
        }
    }

    public byte[] ToArray() => _out.ToArray();

    private void Wrapped(ReadOnlySpan<byte> before, ReadOnlySpan<byte> content, ReadOnlySpan<byte> after)
    {
        _out.Write(before);
        _out.Write(content);
        _out.Write(after);
    }
}

/// <summary>quick-xml escaping helpers and attribute tokenizer.</summary>
internal static class QuickXml
{
    /// <summary>Strict UTF-8 decode (Rust <c>Decoder::decode</c>).</summary>
    public static string DecodeUtf8(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new QuickXmlException("cannot decode input using UTF-8");
        }
    }

    /// <summary>Escape <c>&lt; &gt; &amp; ' "</c> (Rust <c>quick_xml::escape::escape</c>).</summary>
    public static string Escape(string raw)
    {
        if (raw.AsSpan().IndexOfAny("<>&'\"") < 0)
        {
            return raw;
        }

        var sb = new StringBuilder(raw.Length + 16);
        foreach (char c in raw)
        {
            sb.Append(c switch
            {
                '<' => "&lt;",
                '>' => "&gt;",
                '\'' => "&apos;",
                '&' => "&amp;",
                '"' => "&quot;",
                _ => c.ToString(),
            });
        }

        return sb.ToString();
    }

    /// <summary>Unescape predefined entities and character references (Rust <c>quick_xml::escape::unescape</c>).</summary>
    public static string Unescape(string raw)
    {
        int amp = raw.IndexOf('&');
        if (amp < 0)
        {
            return raw;
        }

        var sb = new StringBuilder(raw.Length);
        int lastEnd = 0;
        int i = 0;
        while (true)
        {
            int start = -1;
            while (i < raw.Length)
            {
                if (raw[i] == '&')
                {
                    start = i;
                    i++;
                    break;
                }

                i++;
            }

            if (start < 0)
            {
                break;
            }

            int end = -1;
            while (i < raw.Length)
            {
                if (raw[i] == '&' || raw[i] == ';')
                {
                    end = i;
                    i++;
                    break;
                }

                i++;
            }

            if (end < 0 || raw[end] != ';')
            {
                throw new QuickXmlException("Error while escaping character at range " + start + ".." + raw.Length + ": Cannot find ';' after '&'");
            }

            sb.Append(raw, lastEnd, start - lastEnd);
            var pat = raw[(start + 1)..end];
            if (pat.StartsWith('#'))
            {
                sb.Append(ParseCharRef(pat[1..]));
            }
            else
            {
                string? value = pat switch
                {
                    "lt" => "<",
                    "gt" => ">",
                    "amp" => "&",
                    "apos" => "'",
                    "quot" => "\"",
                    _ => null,
                };
                if (value is null)
                {
                    throw new QuickXmlException($"Error while escaping character at range {start + 1}..{end}: Unrecognized escape symbol: \"{pat}\"");
                }

                sb.Append(value);
            }

            lastEnd = end + 1;
        }

        sb.Append(raw, lastEnd, raw.Length - lastEnd);
        return sb.ToString();
    }

    private static string ParseCharRef(string num)
    {
        bool hex = num.StartsWith('x');
        var digits = hex ? num[1..] : num;
        if (digits.Length == 0 || digits[0] is '+' or '-')
        {
            throw new QuickXmlException("invalid character reference");
        }

        uint code;
        try
        {
            code = Convert.ToUInt32(digits, hex ? 16 : 10);
        }
        catch (Exception e) when (e is FormatException or OverflowException or ArgumentException)
        {
            throw new QuickXmlException("invalid character reference");
        }

        if (code == 0 || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF))
        {
            throw new QuickXmlException("invalid character reference");
        }

        return char.ConvertFromUtf32((int)code);
    }

    /// <summary>Lazy XML-mode attribute tokenizer with duplicate checks (Rust <c>Attributes::next</c>).</summary>
    public static IEnumerable<XmlAttribute> ParseAttributes(byte[] content, int nameLen)
    {
        var keys = new List<byte[]>();
        int pos = nameLen;
        while (true)
        {
            while (pos < content.Length && QuickXmlReader.IsWhitespace(content[pos]))
            {
                pos++;
            }

            if (pos >= content.Length)
            {
                yield break;
            }

            int keyStart = pos;
            while (pos < content.Length && content[pos] != '=' && !QuickXmlReader.IsWhitespace(content[pos]))
            {
                pos++;
            }

            int keyEnd = pos;
            if (pos >= content.Length)
            {
                throw new QuickXmlException($"position {content.Length}: attribute key must be directly followed by `=` or space");
            }

            if (content[pos] != '=')
            {
                while (pos < content.Length && QuickXmlReader.IsWhitespace(content[pos]))
                {
                    pos++;
                }

                if (pos >= content.Length || content[pos] != '=')
                {
                    throw new QuickXmlException($"position {pos}: attribute key must be directly followed by `=` or space");
                }
            }

            pos++; // '='
            var key = content[keyStart..keyEnd];
            if (keys.Any(k => k.AsSpan().SequenceEqual(key)))
            {
                throw new QuickXmlException($"position {keyStart}: duplicated attribute");
            }

            keys.Add(key);
            while (pos < content.Length && QuickXmlReader.IsWhitespace(content[pos]))
            {
                pos++;
            }

            if (pos >= content.Length)
            {
                throw new QuickXmlException($"position {content.Length}: `=` must be followed by an attribute value");
            }

            byte quote = content[pos];
            if (quote is not ((byte)'"' or (byte)'\''))
            {
                throw new QuickXmlException($"position {pos}: attribute value must be enclosed in `\"` or `'`");
            }

            int valueStart = pos + 1;
            int close = Array.IndexOf(content, quote, valueStart);
            if (close < 0)
            {
                throw new QuickXmlException($"position {content.Length}: missing closing quote");
            }

            pos = close + 1;
            yield return new XmlAttribute(key, content[valueStart..close]);
        }
    }
}
