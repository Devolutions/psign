using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Portable;

/// <summary>
/// A request JSON document could not be deserialized (Rust <c>serde_json</c> error mapped to
/// <see cref="PortableErrorCode.InvalidRequest"/>).
/// </summary>
public sealed class PortableRequestException : PsignException
{
    public PortableRequestException(string message)
        : base(message)
    {
    }

    public PortableRequestException(string message, Exception? inner)
        : base(message, inner)
    {
    }
}

/// <summary>
/// Minimal <c>serde</c>-compatible reader for the portable request structs: unknown fields are ignored, duplicate known
/// fields and type mismatches are errors, <c>#[serde(default)]</c> fields may be omitted, <c>Option</c> fields accept
/// <c>null</c>, and enum variants must match exactly.
/// </summary>
internal sealed class SerdeObject
{
    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 128,
    };

    private readonly Dictionary<string, JsonElement> _fields;
    private readonly string _typeName;

    private SerdeObject(JsonElement element, string typeName, IReadOnlyCollection<string> knownFields)
    {
        _typeName = typeName;
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new PortableRequestException($"invalid type: {Describe(element)}, expected struct {typeName}");
        }

        _fields = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!knownFields.Contains(property.Name))
            {
                continue;
            }

            if (!_fields.TryAdd(property.Name, property.Value))
            {
                throw new PortableRequestException($"duplicate field `{property.Name}`");
            }
        }
    }

    /// <summary>Parse <paramref name="json"/> as a struct named <paramref name="typeName"/>.</summary>
    public static T Parse<T>(string json, string typeName, IReadOnlyCollection<string> knownFields, Func<SerdeObject, T> read)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, DocumentOptions);
        }
        catch (JsonException e)
        {
            var line = (e.LineNumber ?? 0) + 1;
            var column = (e.BytePositionInLine ?? 0) + 1;
            throw new PortableRequestException(
                string.Create(CultureInfo.InvariantCulture, $"{FirstSentence(e.Message)} at line {line} column {column}"), e);
        }

        using (document)
        {
            return read(new SerdeObject(document.RootElement, typeName, knownFields));
        }
    }

    /// <summary>Nested struct value.</summary>
    public static SerdeObject Nested(JsonElement element, string typeName, IReadOnlyCollection<string> knownFields) =>
        new(element, typeName, knownFields);

    public string RequiredString(string name)
    {
        if (!_fields.TryGetValue(name, out var value))
        {
            throw new PortableRequestException($"missing field `{name}`");
        }

        return AsString(value, name);
    }

    public string? OptionalString(string name) =>
        _fields.TryGetValue(name, out var value) && value.ValueKind != JsonValueKind.Null ? AsString(value, name) : null;

    public bool Bool(string name) =>
        _fields.TryGetValue(name, out var value) && AsBool(value, name);

    public bool? OptionalBool(string name) =>
        _fields.TryGetValue(name, out var value) && value.ValueKind != JsonValueKind.Null ? AsBool(value, name) : null;

    public uint U32(string name)
    {
        if (!_fields.TryGetValue(name, out var value))
        {
            return 0;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetUInt32(out var n))
        {
            return n;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var i))
        {
            throw new PortableRequestException(
                string.Create(CultureInfo.InvariantCulture, $"invalid value: integer `{i}`, expected u32"));
        }

        throw new PortableRequestException($"invalid type: {Describe(value)}, expected u32");
    }

    public List<string> StringList(string name)
    {
        if (!_fields.TryGetValue(name, out var value))
        {
            return [];
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new PortableRequestException($"invalid type: {Describe(value)}, expected a sequence");
        }

        return value.EnumerateArray().Select(v => AsString(v, name)).ToList();
    }

    public T Enum<T>(string name, T defaultValue)
        where T : struct, System.Enum =>
        _fields.TryGetValue(name, out var value) ? AsEnum<T>(value) : defaultValue;

    public T? OptionalEnum<T>(string name)
        where T : struct, System.Enum =>
        _fields.TryGetValue(name, out var value) && value.ValueKind != JsonValueKind.Null ? AsEnum<T>(value) : null;

    public JsonElement? OptionalElement(string name) =>
        _fields.TryGetValue(name, out var value) && value.ValueKind != JsonValueKind.Null ? value : null;

    private static string AsString(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : throw new PortableRequestException($"invalid type: {Describe(value)}, expected a string");

    private static bool AsBool(JsonElement value, string name) => value.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => throw new PortableRequestException($"invalid type: {Describe(value)}, expected a boolean"),
    };

    private static T AsEnum<T>(JsonElement value)
        where T : struct, System.Enum
    {
        var names = System.Enum.GetNames<T>();
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new PortableRequestException($"invalid type: {Describe(value)}, expected enum {typeof(T).Name}");
        }

        var text = value.GetString()!;
        if (names.Contains(text, StringComparer.Ordinal))
        {
            return System.Enum.Parse<T>(text);
        }

        throw new PortableRequestException(
            $"unknown variant `{text}`, expected one of {string.Join(", ", names.Select(n => $"`{n}`"))}");
    }

    private static string Describe(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null => "null",
        JsonValueKind.True => "boolean `true`",
        JsonValueKind.False => "boolean `false`",
        JsonValueKind.String => $"string \"{value.GetString()}\"",
        JsonValueKind.Number => value.TryGetInt64(out var i)
            ? (i < 0 ? $"integer `{i}`" : $"integer `{i}`")
            : $"floating point `{value.GetRawText()}`",
        JsonValueKind.Array => "sequence",
        JsonValueKind.Object => "map",
        _ => "value",
    };

    private static string FirstSentence(string message)
    {
        int idx = message.IndexOf(". ", StringComparison.Ordinal);
        return idx > 0 ? message[..idx] : message.TrimEnd('.');
    }

    /// <summary>Owner type name (diagnostics).</summary>
    public override string ToString() => _typeName;
}

/// <summary>JSON output helpers (serde field order is preserved by construction).</summary>
internal static class SerdeWrite
{
    public static JsonArray StringArray(IEnumerable<string> values)
    {
        var array = new JsonArray();
        foreach (var v in values)
        {
            array.Add(JsonValue.Create(v));
        }

        return array;
    }

    public static JsonNode? OptionalString(string? value) => value is null ? null : JsonValue.Create(value);

    public static JsonNode? OptionalBool(bool? value) => value is null ? null : JsonValue.Create(value.Value);

    public static JsonNode? OptionalEnum<T>(T? value)
        where T : struct, System.Enum => value is null ? null : JsonValue.Create(value.Value.ToString());

    /// <summary><c>serde_json::to_string</c> rendering.</summary>
    public static string Compact(JsonNode node) => Core.Json.RustJson.Compact(node);

    /// <summary>Ordinal comparison of the UTF-8 encodings (Rust <c>String</c> ordering).</summary>
    public static int CompareUtf8(string a, string b) =>
        Encoding.UTF8.GetBytes(a).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(b));

    /// <summary>Comparer for <see cref="CompareUtf8"/>.</summary>
    public static readonly IComparer<string> Utf8Comparer = Comparer<string>.Create(CompareUtf8);
}
