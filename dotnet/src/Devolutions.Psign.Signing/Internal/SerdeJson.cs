using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Devolutions.Psign.Signing.Internal;

/// <summary>
/// JSON writer that reproduces <c>serde_json</c> output (<c>to_string</c> / <c>to_string_pretty</c>): two-space
/// indentation, <c>": "</c> separators, only <c>"</c>, <c>\</c> and control characters escaped (lower-case
/// <c>\u00xx</c>), raw UTF-8 for everything else. Objects keep insertion order unless <c>sortKeys</c> is set (the
/// Rust <c>serde_json::Value</c> map is a <c>BTreeMap</c>, so dynamic JSON values are emitted with sorted keys).
/// </summary>
internal static class SerdeJson
{
    public static string Pretty(JsonNode? node, bool sortKeys = false)
    {
        var sb = new StringBuilder();
        Write(sb, node, pretty: true, indent: 0, sortKeys);
        return sb.ToString();
    }

    public static string Compact(JsonNode? node, bool sortKeys = false)
    {
        var sb = new StringBuilder();
        Write(sb, node, pretty: false, indent: 0, sortKeys);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, JsonNode? node, bool pretty, int indent, bool sortKeys)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                break;
            case JsonObject obj:
                {
                    IEnumerable<KeyValuePair<string, JsonNode?>> props = obj;
                    if (sortKeys)
                    {
                        props = obj.OrderBy(p => p.Key, StringComparer.Ordinal);
                    }

                    var list = props.ToList();
                    if (list.Count == 0)
                    {
                        sb.Append("{}");
                        break;
                    }

                    sb.Append('{');
                    for (var i = 0; i < list.Count; i++)
                    {
                        if (i > 0)
                        {
                            sb.Append(',');
                        }

                        if (pretty)
                        {
                            sb.Append('\n').Append(' ', (indent + 1) * 2);
                        }

                        WriteString(sb, list[i].Key);
                        sb.Append(pretty ? ": " : ":");
                        Write(sb, list[i].Value, pretty, indent + 1, sortKeys);
                    }

                    if (pretty)
                    {
                        sb.Append('\n').Append(' ', indent * 2);
                    }

                    sb.Append('}');
                    break;
                }

            case JsonArray arr:
                {
                    if (arr.Count == 0)
                    {
                        sb.Append("[]");
                        break;
                    }

                    sb.Append('[');
                    for (var i = 0; i < arr.Count; i++)
                    {
                        if (i > 0)
                        {
                            sb.Append(',');
                        }

                        if (pretty)
                        {
                            sb.Append('\n').Append(' ', (indent + 1) * 2);
                        }

                        Write(sb, arr[i], pretty, indent + 1, sortKeys);
                    }

                    if (pretty)
                    {
                        sb.Append('\n').Append(' ', indent * 2);
                    }

                    sb.Append(']');
                    break;
                }

            case JsonValue value:
                WriteValue(sb, value);
                break;
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
                sb.Append(value.ToJsonString());
                break;
            default:
                sb.Append(value.ToJsonString());
                break;
        }
    }

    public static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
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
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u00").Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
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
