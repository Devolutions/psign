using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

internal sealed class PortableSignResponse
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("input_path")]
    public string InputPath { get; init; } = string.Empty;

    [JsonPropertyName("output_path")]
    public string OutputPath { get; init; } = string.Empty;

    [JsonPropertyName("format")]
    public string Format { get; init; } = string.Empty;

    [JsonPropertyName("signature")]
    public PortableSignature Signature { get; init; } = new();
}
