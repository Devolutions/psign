using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

public sealed class PortableSignature
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("path")]
    public string Path { get; init; } = string.Empty;

    [JsonPropertyName("format")]
    public string Format { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("status_message")]
    public string StatusMessage { get; init; } = string.Empty;

    [JsonPropertyName("signature_count")]
    public int SignatureCount { get; init; }

    [JsonPropertyName("digest_algorithm")]
    public string? DigestAlgorithm { get; init; }

    [JsonPropertyName("timestamp_kinds")]
    public string[] TimestampKinds { get; init; } = [];

    [JsonPropertyName("diagnostics")]
    public string[] PortableDiagnostics { get; init; } = [];

    public object? SignerCertificate => null;

    public object? TimeStamperCertificate => null;

    public string SignatureType => Format;

    public bool IsOSBinary => false;
}
