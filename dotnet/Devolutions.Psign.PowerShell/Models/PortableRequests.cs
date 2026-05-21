using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

internal sealed class PortableGetSignatureRequest
{
    [JsonPropertyName("path")]
    public required string Path { get; init; }
}

internal sealed class PortableSignRequest
{
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("output_path")]
    public string? OutputPath { get; init; }

    [JsonPropertyName("hash_algorithm")]
    public string HashAlgorithm { get; init; } = "Sha256";

    [JsonPropertyName("certificate_path")]
    public string? CertificatePath { get; init; }

    [JsonPropertyName("private_key_path")]
    public string? PrivateKeyPath { get; init; }

    [JsonPropertyName("certificate_der_base64")]
    public string? CertificateDerBase64 { get; init; }

    [JsonPropertyName("private_key_der_base64")]
    public string? PrivateKeyDerBase64 { get; init; }
}
