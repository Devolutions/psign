using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

internal sealed class PortableErrorResponse
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}
