using System.Text.Json.Serialization;
using System.Security.Cryptography.X509Certificates;

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

    [JsonPropertyName("trust_status")]
    public string? TrustStatus { get; init; }

    [JsonPropertyName("signature_count")]
    public int SignatureCount { get; init; }

    [JsonPropertyName("signer_index")]
    public int? SignerIndex { get; init; }

    [JsonPropertyName("signer_certificate_der_base64")]
    public string? SignerCertificateDerBase64 { get; init; }

    [JsonPropertyName("timestamper_certificate_der_base64")]
    public string? TimeStamperCertificateDerBase64 { get; init; }

    [JsonPropertyName("embedded_certificate_count")]
    public int EmbeddedCertificateCount { get; init; }

    [JsonPropertyName("digest_algorithm")]
    public string? DigestAlgorithm { get; init; }

    [JsonPropertyName("timestamp_kinds")]
    public string[] TimestampKinds { get; init; } = [];

    [JsonPropertyName("timestamp_signing_time")]
    public DateTime? TimestampSigningTime { get; init; }

    [JsonPropertyName("diagnostics")]
    public string[] PortableDiagnostics { get; init; } = [];

    [JsonIgnore]
    public X509Certificate2? SignerCertificate => DecodeCertificate(SignerCertificateDerBase64);

    [JsonIgnore]
    public X509Certificate2? TimeStamperCertificate => DecodeCertificate(TimeStamperCertificateDerBase64);

    [JsonIgnore]
    public string SignatureType => Format;

    [JsonIgnore]
    public bool IsOSBinary => false;

    [JsonIgnore]
    public string? SourcePathOrExtension { get; set; }

    [JsonIgnore]
    public byte[]? Content { get; set; }

    private static X509Certificate2? DecodeCertificate(string? derBase64)
    {
        if (string.IsNullOrWhiteSpace(derBase64))
        {
            return null;
        }

        return new X509Certificate2(Convert.FromBase64String(derBase64));
    }
}
