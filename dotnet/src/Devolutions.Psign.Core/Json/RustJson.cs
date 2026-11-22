using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Devolutions.Psign.Core.Json;

/// <summary>
/// JSON writer that reproduces <c>serde_json</c> output byte-for-byte: compact (<c>to_string</c>) or pretty
/// (<c>to_string_pretty</c>: two-space indent, <c>": "</c> separators, empty containers as <c>{}</c>/<c>[]</c>), raw UTF-8
/// (only <c>"</c>, <c>\</c>, and control characters are escaped).
/// <para>
/// Object key order is preserved from the <see cref="JsonObject"/>. Note that Rust <c>serde_json::json!</c> objects are
/// <c>BTreeMap</c>-backed (keys sorted by UTF-8 bytes) — build those with <c>SortedObject</c> — while
/// <c>#[derive(Serialize)]</c> structs keep declaration order.
/// </para>
/// </summary>
public static class RustJson
{
    /// <summary>Serialize like <c>serde_json::to_string_pretty</c>.</summary>
    public static string Pretty(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(sb, node, pretty: true, indent: 0);
        return sb.ToString();
    }

    /// <summary>Serialize like <c>serde_json::to_string</c>.</summary>
    public static string Compact(JsonNode? node)
    {
        var sb = new StringBuilder();
        Write(sb, node, pretty: false, indent: 0);
        return sb.ToString();
    }

    /// <summary>Create an object whose keys are sorted by ordinal UTF-8 byte order (serde_json <c>Map</c> default).</summary>
    public static JsonObject SortedObject(IEnumerable<KeyValuePair<string, JsonNode?>> properties)
    {
        var list = properties.ToList();
        list.Sort((a, b) => CompareUtf8(a.Key, b.Key));
        var obj = new JsonObject();
        foreach (var kv in list)
        {
            obj[kv.Key] = kv.Value;
        }

        return obj;
    }

    /// <summary>Create a sorted object from (key, value) tuples.</summary>
    public static JsonObject SortedObject(params (string Key, JsonNode? Value)[] properties) =>
        SortedObject(properties.Select(p => new KeyValuePair<string, JsonNode?>(p.Key, p.Value)));

    /// <summary>Recursively sort all object keys (to emulate <c>serde_json::Value</c> built via <c>json!</c> / maps).</summary>
    public static JsonNode? SortKeysDeep(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                {
                    var props = o.Select(kv => new KeyValuePair<string, JsonNode?>(kv.Key, SortKeysDeep(kv.Value?.DeepClone()))).ToList();
                    return SortedObject(props);
                }

            case JsonArray a:
                {
                    var arr = new JsonArray();
                    foreach (var item in a)
                    {
                        arr.Add(SortKeysDeep(item?.DeepClone()));
                    }

                    return arr;
                }

            default:
                return node?.DeepClone();
        }
    }

    private static int CompareUtf8(string a, string b)
    {
        return Encoding.UTF8.GetBytes(a).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(b));
    }

    private static void Write(StringBuilder sb, JsonNode? node, bool pretty, int indent)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                break;
            case JsonObject obj:
                if (obj.Count == 0)
                {
                    sb.Append("{}");
                    break;
                }

                sb.Append('{');
                bool first = true;
                foreach (var kv in obj)
                {
                    if (!first)
                    {
                        sb.Append(',');
                    }

                    first = false;
                    if (pretty)
                    {
                        sb.Append('\n');
                        sb.Append(' ', (indent + 1) * 2);
                    }

                    WriteString(sb, kv.Key);
                    sb.Append(pretty ? ": " : ":");
                    Write(sb, kv.Value, pretty, indent + 1);
                }

                if (pretty)
                {
                    sb.Append('\n');
                    sb.Append(' ', indent * 2);
                }

                sb.Append('}');
                break;
            case JsonArray arr:
                if (arr.Count == 0)
                {
                    sb.Append("[]");
                    break;
                }

                sb.Append('[');
                for (int i = 0; i < arr.Count; i++)
                {
                    if (i > 0)
                    {
                        sb.Append(',');
                    }

                    if (pretty)
                    {
                        sb.Append('\n');
                        sb.Append(' ', (indent + 1) * 2);
                    }

                    Write(sb, arr[i], pretty, indent + 1);
                }

                if (pretty)
                {
                    sb.Append('\n');
                    sb.Append(' ', indent * 2);
                }

                sb.Append(']');
                break;
            case JsonValue value:
                WriteValue(sb, value);
                break;
            default:
                throw new InvalidOperationException("unsupported JSON node");
        }
    }

    private static void WriteValue(StringBuilder sb, JsonValue value)
    {
        var element = value.GetValueKind();
        switch (element)
        {
            case JsonValueKind.String:
                WriteString(sb, value.GetValue<string>());
                break;
            case JsonValueKind.True:
                sb.Append("true");
                break;
            case JsonValueKind.False:
                sb.Append("false");
                break;
            case JsonValueKind.Null:
                sb.Append("null");
                break;
            case JsonValueKind.Number:
                WriteNumber(sb, value);
                break;
            default:
                sb.Append(value.ToJsonString());
                break;
        }
    }

    private static void WriteNumber(StringBuilder sb, JsonValue value)
    {
        if (value.TryGetValue<long>(out var l))
        {
            sb.Append(l.ToString(CultureInfo.InvariantCulture));
        }
        else if (value.TryGetValue<ulong>(out var ul))
        {
            sb.Append(ul.ToString(CultureInfo.InvariantCulture));
        }
        else if (value.TryGetValue<int>(out var i))
        {
            sb.Append(i.ToString(CultureInfo.InvariantCulture));
        }
        else if (value.TryGetValue<uint>(out var ui))
        {
            sb.Append(ui.ToString(CultureInfo.InvariantCulture));
        }
        else if (value.TryGetValue<double>(out var d))
        {
            // serde_json uses ryu: shortest round-trip, always with a fractional part or exponent.
            if (double.IsFinite(d) && Math.Floor(d) == d && Math.Abs(d) < 1e16)
            {
                sb.Append(d.ToString("0.0", CultureInfo.InvariantCulture));
            }
            else
            {
                sb.Append(double.IsFinite(d) ? d.ToString("R", CultureInfo.InvariantCulture) : "null");
            }
        }
        else
        {
            sb.Append(value.ToJsonString());
        }
    }

    /// <summary>serde_json string escaping.</summary>
    public static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u00");
                        sb.Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }

                    break;
            }
        }

        sb.Append('"');
    }
}
