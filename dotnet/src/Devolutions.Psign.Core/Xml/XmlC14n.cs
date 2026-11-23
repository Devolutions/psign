using System.Globalization;
using System.Text;
using Devolutions.Psign.Core.Opc;

namespace Devolutions.Psign.Core.Xml;

/// <summary>Node of the minimal XML DOM used for XMLDSig canonicalization (Rust <c>xml_c14n::Node</c>).</summary>
public abstract class XmlC14nNode
{
}

/// <summary>Text node (normalized, unescaped character data).</summary>
public sealed class XmlC14nText : XmlC14nNode
{
    public XmlC14nText(string value) => Value = value;

    public string Value { get; set; }
}

/// <summary>Element node (Rust <c>xml_c14n::Element</c>).</summary>
public sealed class XmlC14nElement : XmlC14nNode
{
    public XmlC14nElement(string qname, List<KeyValuePair<string, string>> attributes, List<XmlC14nNode> children, SortedDictionary<string, string> scope)
    {
        QName = qname;
        Attributes = attributes;
        Children = children;
        Scope = scope;
    }

    /// <summary>Qualified name as written (<c>prefix:local</c> or <c>local</c>).</summary>
    public string QName { get; set; }

    /// <summary>Attributes as written, including <c>xmlns</c> declarations; values are normalized and unescaped.</summary>
    public List<KeyValuePair<string, string>> Attributes { get; set; }

    public List<XmlC14nNode> Children { get; set; }

    /// <summary>Namespaces in scope (prefix → URI, <c>""</c> is the default namespace), inherited plus declared here.</summary>
    public SortedDictionary<string, string> Scope { get; set; }

    public string LocalName => XmlC14n.SplitQName(QName).Local;

    public string Namespace => Scope.TryGetValue(XmlC14n.SplitQName(QName).Prefix, out var ns) ? ns : string.Empty;

    public bool Is(string ns, string local) => LocalName == local && Namespace == ns;

    /// <summary>Unprefixed attribute value.</summary>
    public string? Attr(string name)
    {
        foreach (var a in Attributes)
        {
            if (a.Key == name)
            {
                return a.Value;
            }
        }

        return null;
    }

    public IEnumerable<XmlC14nElement> ChildElements => Children.OfType<XmlC14nElement>();

    public XmlC14nElement? Child(string ns, string local) => ChildElements.FirstOrDefault(e => e.Is(ns, local));

    public IEnumerable<XmlC14nElement> ChildrenNamed(string ns, string local) => ChildElements.Where(e => e.Is(ns, local));

    /// <summary>Concatenated text of direct text children.</summary>
    public string Text() => string.Concat(Children.OfType<XmlC14nText>().Select(t => t.Value));

    /// <summary>Depth-first search including this element.</summary>
    public void FindAll(Func<XmlC14nElement, bool> predicate, List<XmlC14nElement> output)
    {
        if (predicate(this))
        {
            output.Add(this);
        }

        foreach (var child in ChildElements)
        {
            child.FindAll(predicate, output);
        }
    }
}

/// <summary>Canonicalization algorithm (Rust <c>xml_c14n::C14nMode</c>).</summary>
public enum C14nMode
{
    /// <summary><c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</c>.</summary>
    Inclusive,

    /// <summary><c>http://www.w3.org/2001/10/xml-exc-c14n#</c> (no <c>InclusiveNamespaces</c> prefix list).</summary>
    Exclusive,
}

/// <summary>
/// Minimal XML DOM + Canonical XML 1.0 (inclusive and exclusive, without comments) for XMLDSig (port of Rust
/// <c>psign-authenticode-trust/src/xml_c14n.rs</c>). DOCTYPE and processing instructions inside the document element are
/// rejected; line endings and attribute values are normalized as an XML 1.0 processor would.
/// </summary>
public static class XmlC14n
{
    private const string XmlNs = "http://www.w3.org/XML/1998/namespace";

    /// <summary>Map an algorithm URI to a mode (Rust <c>C14nMode::from_uri</c>).</summary>
    public static C14nMode? ModeFromUri(string uri) => uri switch
    {
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => C14nMode.Inclusive,
        "http://www.w3.org/2001/10/xml-exc-c14n#" => C14nMode.Exclusive,
        _ => null,
    };

    internal static (string Prefix, string Local) SplitQName(string qname)
    {
        int idx = qname.IndexOf(':');
        return idx < 0 ? (string.Empty, qname) : (qname[..idx], qname[(idx + 1)..]);
    }

    // ---------------------------------------------------------------- parsing

    /// <summary>Parse a UTF-8 XML document (optional BOM) into its document element (Rust <c>parse_document</c>).</summary>
    public static XmlC14nElement ParseDocument(byte[] xml)
    {
        ReadOnlySpan<byte> span = xml;
        if (span.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
        {
            span = span[3..];
        }

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(span);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("XML document is not UTF-8", e);
        }

        return new Parser(text).Run();
    }

    private static string NormalizeNewlines(string s) => s.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');

    private sealed class Parser
    {
        private readonly string _s;
        private int _pos;
        private readonly List<XmlC14nElement> _stack = [];
        private XmlC14nElement? _root;

        public Parser(string s) => _s = s;

        private PsignException Error(string message) => new($"XML parse error at {_pos}: {message}");

        public XmlC14nElement Run()
        {
            while (_pos < _s.Length)
            {
                if (_s[_pos] == '<')
                {
                    ParseMarkup();
                }
                else
                {
                    ParseText();
                }
            }

            if (_stack.Count != 0)
            {
                throw new PsignException("XML document is truncated");
            }

            return _root ?? throw new PsignException("XML document has no document element");
        }

        private void ParseMarkup()
        {
            if (Starts("<?"))
            {
                int end = _s.IndexOf("?>", _pos + 2, StringComparison.Ordinal);
                if (end < 0)
                {
                    throw Error("processing instruction not closed");
                }

                string content = _s[(_pos + 2)..end];
                _pos = end + 2;
                bool isDecl = content.Length >= 3 && content.StartsWith("xml", StringComparison.Ordinal)
                    && (content.Length == 3 || IsXmlWhitespace(content[3]));
                if (!isDecl && _stack.Count != 0)
                {
                    throw new PsignException("XML processing instructions are not supported");
                }

                return;
            }

            if (Starts("<!--"))
            {
                int end = _s.IndexOf("-->", _pos + 4, StringComparison.Ordinal);
                if (end < 0)
                {
                    throw Error("comment not closed");
                }

                _pos = end + 3;
                return;
            }

            if (Starts("<![CDATA["))
            {
                int end = _s.IndexOf("]]>", _pos + 9, StringComparison.Ordinal);
                if (end < 0)
                {
                    throw Error("CDATA not closed");
                }

                string raw = _s[(_pos + 9)..end];
                _pos = end + 3;
                PushText(NormalizeNewlines(raw));
                return;
            }

            if (_pos + 9 <= _s.Length && string.Compare(_s, _pos, "<!DOCTYPE", 0, 9, StringComparison.OrdinalIgnoreCase) == 0)
            {
                throw new PsignException("XML DOCTYPE is not allowed");
            }

            if (Starts("<!"))
            {
                throw Error("unexpected markup declaration");
            }

            if (Starts("</"))
            {
                int end = _s.IndexOf('>', _pos + 2);
                if (end < 0)
                {
                    throw Error("end tag not closed");
                }

                string name = _s[(_pos + 2)..end].TrimEnd(' ', '\t', '\r', '\n');
                _pos = end + 1;
                if (_stack.Count == 0)
                {
                    throw new PsignException("unbalanced XML end tag");
                }

                var done = _stack[^1];
                if (done.QName != name)
                {
                    throw Error($"expected `{done.QName}`, but `{name}` was found");
                }

                _stack.RemoveAt(_stack.Count - 1);
                FinishElement(done);
                return;
            }

            ParseStartTag();
        }

        private void ParseStartTag()
        {
            // Find the end of the tag, honoring quoted attribute values.
            int i = _pos + 1;
            char quote = '\0';
            while (i < _s.Length)
            {
                char c = _s[i];
                if (quote != '\0')
                {
                    if (c == quote)
                    {
                        quote = '\0';
                    }
                }
                else if (c is '"' or '\'')
                {
                    quote = c;
                }
                else if (c == '>')
                {
                    break;
                }

                i++;
            }

            if (i >= _s.Length)
            {
                throw Error("start tag not closed");
            }

            string body = _s[(_pos + 1)..i];
            _pos = i + 1;
            bool empty = body.EndsWith('/');
            if (empty)
            {
                body = body[..^1];
            }

            int nameEnd = 0;
            while (nameEnd < body.Length && !IsXmlWhitespace(body[nameEnd]))
            {
                nameEnd++;
            }

            string qname = body[..nameEnd];
            if (qname.Length == 0)
            {
                throw Error("empty element name");
            }

            if (_root is not null && _stack.Count == 0)
            {
                throw new PsignException("XML has more than one document element");
            }

            var parentScope = _stack.Count > 0 ? _stack[^1].Scope : new SortedDictionary<string, string>(Utf8Ordinal.Comparer);
            var scope = new SortedDictionary<string, string>(parentScope, Utf8Ordinal.Comparer);
            var attrs = new List<KeyValuePair<string, string>>();
            ParseAttributes(body, nameEnd, attrs, scope);
            scope["xml"] = XmlNs;

            var element = new XmlC14nElement(qname, attrs, [], scope);
            if (empty)
            {
                FinishElement(element);
            }
            else
            {
                _stack.Add(element);
            }
        }

        private void ParseAttributes(string body, int p, List<KeyValuePair<string, string>> attrs, SortedDictionary<string, string> scope)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (true)
            {
                while (p < body.Length && IsXmlWhitespace(body[p]))
                {
                    p++;
                }

                if (p >= body.Length)
                {
                    return;
                }

                int keyStart = p;
                while (p < body.Length && body[p] != '=' && !IsXmlWhitespace(body[p]))
                {
                    p++;
                }

                string key = body[keyStart..p];
                while (p < body.Length && IsXmlWhitespace(body[p]))
                {
                    p++;
                }

                if (p >= body.Length || body[p] != '=')
                {
                    throw new PsignException($"XML attribute: position {keyStart}: attribute value must be enclosed in quotes");
                }

                p++;
                while (p < body.Length && IsXmlWhitespace(body[p]))
                {
                    p++;
                }

                if (p >= body.Length || (body[p] != '"' && body[p] != '\''))
                {
                    throw new PsignException($"XML attribute: position {keyStart}: attribute value must be enclosed in quotes");
                }

                char quote = body[p];
                int valueStart = p + 1;
                int valueEnd = body.IndexOf(quote, valueStart);
                if (valueEnd < 0)
                {
                    throw new PsignException($"XML attribute: position {keyStart}: attribute value must be enclosed in quotes");
                }

                if (!seen.Add(key))
                {
                    throw new PsignException($"XML attribute: position {keyStart}: duplicated attribute");
                }

                string raw = body[valueStart..valueEnd];
                p = valueEnd + 1;
                string normalized = NormalizeNewlines(raw).Replace('\t', ' ').Replace('\n', ' ');
                string value;
                try
                {
                    value = Unescape(normalized);
                }
                catch (PsignException e)
                {
                    throw new PsignException($"XML attribute {key} value: {e.Message}");
                }

                if (key == "xmlns")
                {
                    scope[string.Empty] = value;
                }
                else if (key.StartsWith("xmlns:", StringComparison.Ordinal))
                {
                    scope[key["xmlns:".Length..]] = value;
                }

                attrs.Add(new KeyValuePair<string, string>(key, value));
            }
        }

        private void FinishElement(XmlC14nElement done)
        {
            if (_stack.Count > 0)
            {
                _stack[^1].Children.Add(done);
            }
            else
            {
                _root = done;
            }
        }

        private void ParseText()
        {
            int end = _s.IndexOf('<', _pos);
            if (end < 0)
            {
                end = _s.Length;
            }

            int p = _pos;
            while (p < end)
            {
                int amp = _s.IndexOf('&', p, end - p);
                if (amp < 0)
                {
                    PushText(NormalizeNewlines(_s[p..end]));
                    break;
                }

                if (amp > p)
                {
                    PushText(NormalizeNewlines(_s[p..amp]));
                }

                int semi = _s.IndexOf(';', amp + 1, end - amp - 1);
                if (semi < 0)
                {
                    _pos = amp;
                    throw Error("unterminated entity reference");
                }

                string name = _s[(amp + 1)..semi];
                PushText(ResolveGeneralRef(name));
                p = semi + 1;
            }

            _pos = end;
        }

        private static string ResolveGeneralRef(string name)
        {
            if (name.StartsWith('#'))
            {
                var ch = ResolveCharRef(name[1..]) ?? throw new PsignException("invalid XML character reference");
                return ch;
            }

            return name switch
            {
                "amp" => "&",
                "lt" => "<",
                "gt" => ">",
                "quot" => "\"",
                "apos" => "'",
                _ => throw new PsignException($"undefined XML entity &{name};"),
            };
        }

        private void PushText(string text)
        {
            if (text.Length == 0)
            {
                return;
            }

            if (_stack.Count == 0)
            {
                if (text.Trim().Length == 0)
                {
                    return;
                }

                throw new PsignException("XML text outside the document element");
            }

            var top = _stack[^1];
            if (top.Children.Count > 0 && top.Children[^1] is XmlC14nText last)
            {
                last.Value += text;
            }
            else
            {
                top.Children.Add(new XmlC14nText(text));
            }
        }

        private bool Starts(string prefix) => string.CompareOrdinal(_s, _pos, prefix, 0, prefix.Length) == 0;
    }

    private static bool IsXmlWhitespace(char c) => c is ' ' or '\t' or '\r' or '\n';

    /// <summary>Resolve <c>#</c>-less character reference body (<c>x41</c> or <c>65</c>).</summary>
    private static string? ResolveCharRef(string body)
    {
        uint code;
        if (body.StartsWith('x'))
        {
            if (!uint.TryParse(body[1..], NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out code))
            {
                return null;
            }
        }
        else if (!uint.TryParse(body, NumberStyles.None, CultureInfo.InvariantCulture, out code))
        {
            return null;
        }

        if (code == 0 || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF))
        {
            return null;
        }

        return char.ConvertFromUtf32((int)code);
    }

    /// <summary>Attribute value unescaping (quick-xml <c>escape::unescape</c>).</summary>
    private static string Unescape(string s)
    {
        if (!s.Contains('&'))
        {
            return s;
        }

        var sb = new StringBuilder(s.Length);
        int p = 0;
        while (p < s.Length)
        {
            int amp = s.IndexOf('&', p);
            if (amp < 0)
            {
                sb.Append(s, p, s.Length - p);
                break;
            }

            sb.Append(s, p, amp - p);
            int semi = s.IndexOf(';', amp + 1);
            if (semi < 0)
            {
                throw new PsignException($"Error while escaping character at range {amp}..: Cannot find ';' after '&'");
            }

            string name = s[(amp + 1)..semi];
            string? resolved = name switch
            {
                "lt" => "<",
                "gt" => ">",
                "amp" => "&",
                "apos" => "'",
                "quot" => "\"",
                _ when name.StartsWith('#') => ResolveCharRef(name[1..]),
                _ => null,
            };
            sb.Append(resolved ?? throw new PsignException($"Error while escaping character at range {amp}..{semi}: Unrecognized escape symbol: {name}"));
            p = semi + 1;
        }

        return sb.ToString();
    }

    // ---------------------------------------------------------------- canonicalization

    /// <summary>
    /// Canonicalize <paramref name="element"/> and its subtree as an XMLDSig node-set (the element is the apex; its
    /// ancestors' namespaces are in <see cref="XmlC14nElement.Scope"/>) (Rust <c>canonicalize</c>).
    /// </summary>
    public static byte[] Canonicalize(XmlC14nElement element, C14nMode mode)
    {
        var sb = new StringBuilder();
        WriteElement(element, mode, new SortedDictionary<string, string>(Utf8Ordinal.Comparer), sb);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static string Lookup(SortedDictionary<string, string> scope, string prefix) =>
        scope.TryGetValue(prefix, out var v) ? v : string.Empty;

    private static void WriteElement(XmlC14nElement e, C14nMode mode, SortedDictionary<string, string> rendered, StringBuilder output)
    {
        var emit = new List<(string Prefix, string Uri)>();
        if (mode == C14nMode.Inclusive)
        {
            foreach (var (prefix, uri) in e.Scope)
            {
                if (prefix == "xml")
                {
                    continue;
                }

                if (Lookup(rendered, prefix) != uri)
                {
                    emit.Add((prefix, uri));
                }
            }
        }
        else
        {
            var used = new List<string> { SplitQName(e.QName).Prefix };
            foreach (var a in e.Attributes)
            {
                if (a.Key == "xmlns" || a.Key.StartsWith("xmlns:", StringComparison.Ordinal))
                {
                    continue;
                }

                var prefix = SplitQName(a.Key).Prefix;
                if (prefix.Length != 0)
                {
                    used.Add(prefix);
                }
            }

            foreach (var prefix in used.Distinct().OrderBy(p => p, Utf8Ordinal.Comparer))
            {
                if (prefix == "xml")
                {
                    continue;
                }

                string uri = Lookup(e.Scope, prefix);
                if (Lookup(rendered, prefix) != uri)
                {
                    emit.Add((prefix, uri));
                }
            }
        }

        // xmlns="" only undoes a non-empty default rendered on an output ancestor.
        emit.RemoveAll(x => x.Prefix.Length == 0 && x.Uri.Length == 0 && Lookup(rendered, string.Empty).Length == 0);
        emit = emit.OrderBy(x => x.Prefix, Utf8Ordinal.Comparer).ToList();

        var attrs = e.Attributes
            .Where(a => a.Key != "xmlns" && !a.Key.StartsWith("xmlns:", StringComparison.Ordinal))
            .Select(a =>
            {
                var (prefix, local) = SplitQName(a.Key);
                string ns = prefix.Length == 0 ? string.Empty : Lookup(e.Scope, prefix);
                return (Ns: ns, Local: local, Name: a.Key, a.Value);
            })
            .OrderBy(a => a.Ns, Utf8Ordinal.Comparer)
            .ThenBy(a => a.Local, Utf8Ordinal.Comparer)
            .ToList();

        output.Append('<').Append(e.QName);
        foreach (var (prefix, uri) in emit)
        {
            output.Append(prefix.Length == 0 ? " xmlns" : " xmlns:");
            output.Append(prefix).Append("=\"");
            EscapeAttr(uri, output);
            output.Append('"');
        }

        foreach (var a in attrs)
        {
            output.Append(' ').Append(a.Name).Append("=\"");
            EscapeAttr(a.Value, output);
            output.Append('"');
        }

        output.Append('>');

        var childRendered = new SortedDictionary<string, string>(rendered, Utf8Ordinal.Comparer);
        foreach (var (prefix, uri) in emit)
        {
            childRendered[prefix] = uri;
        }

        foreach (var child in e.Children)
        {
            switch (child)
            {
                case XmlC14nText t:
                    EscapeText(t.Value, output);
                    break;
                case XmlC14nElement c:
                    WriteElement(c, mode, childRendered, output);
                    break;
            }
        }

        output.Append("</").Append(e.QName).Append('>');
    }

    private static void EscapeText(string s, StringBuilder output)
    {
        foreach (char c in s)
        {
            switch (c)
            {
                case '&':
                    output.Append("&amp;");
                    break;
                case '<':
                    output.Append("&lt;");
                    break;
                case '>':
                    output.Append("&gt;");
                    break;
                case '\r':
                    output.Append("&#xD;");
                    break;
                default:
                    output.Append(c);
                    break;
            }
        }
    }

    private static void EscapeAttr(string s, StringBuilder output)
    {
        foreach (char c in s)
        {
            switch (c)
            {
                case '&':
                    output.Append("&amp;");
                    break;
                case '<':
                    output.Append("&lt;");
                    break;
                case '"':
                    output.Append("&quot;");
                    break;
                case '\t':
                    output.Append("&#x9;");
                    break;
                case '\n':
                    output.Append("&#xA;");
                    break;
                case '\r':
                    output.Append("&#xD;");
                    break;
                default:
                    output.Append(c);
                    break;
            }
        }
    }
}
