using System.Text.Encodings.Web;
using System.Text.Json;

namespace Devolutions.Psign.Verification;

/// <summary>
/// JSON rendering compatible with Rust <c>serde_json::to_string_pretty</c> (two-space indent, <c>\n</c> newlines, no
/// HTML escaping) for the report models in this assembly.
/// </summary>
public static class RustJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
#if NET9_0_OR_GREATER
        NewLine = "\n",
#endif
    };

    /// <summary>Serialize <paramref name="value"/> like <c>serde_json::to_string_pretty</c>.</summary>
    public static string ToStringPretty<T>(T value)
    {
        var json = JsonSerializer.Serialize(value, Options);
        return json.Replace("\r\n", "\n", StringComparison.Ordinal);
    }
}
