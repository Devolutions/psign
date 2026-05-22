using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

internal sealed class PortableGetSignatureRequest
{
    [JsonPropertyName("path")]
    public required string Path { get; init; }

    [JsonPropertyName("trusted_certificate_paths")]
    public string[] TrustedCertificatePaths { get; init; } = [];

    [JsonPropertyName("trusted_certificates_der_base64")]
    public string[] TrustedCertificatesDerBase64 { get; init; } = [];

    [JsonPropertyName("anchor_directory")]
    public string? AnchorDirectory { get; init; }

    [JsonPropertyName("authroot_cab")]
    public string? AuthRootCab { get; init; }

    [JsonPropertyName("as_of")]
    public string? AsOf { get; init; }

    [JsonPropertyName("prefer_timestamp_signing_time")]
    public bool PreferTimestampSigningTime { get; init; }

    [JsonPropertyName("require_valid_timestamp")]
    public bool RequireValidTimestamp { get; init; }

    [JsonPropertyName("online_aia")]
    public bool OnlineAia { get; init; }

    [JsonPropertyName("online_ocsp")]
    public bool OnlineOcsp { get; init; }

    [JsonPropertyName("revocation_mode")]
    public string RevocationMode { get; init; } = "Off";
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

    [JsonPropertyName("chain_certificate_paths")]
    public string[] ChainCertificatePaths { get; init; } = [];

    [JsonPropertyName("chain_certificates_der_base64")]
    public string[] ChainCertificatesDerBase64 { get; init; } = [];

    [JsonPropertyName("timestamp_server")]
    public string? TimestampServer { get; init; }

    [JsonPropertyName("timestamp_hash_algorithm")]
    public string? TimestampHashAlgorithm { get; init; }
}
