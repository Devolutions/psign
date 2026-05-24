using System.Text.Json.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Management.Automation;

namespace Devolutions.Psign.PowerShell.Models;

public sealed class PortableSignature
{
    private X509Certificate2? _signerCertificate;
    private X509Certificate2? _timeStamperCertificate;
    private bool _signerCertificateResolved;
    private bool _timeStamperCertificateResolved;

    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("path")]
    public string Path { get; init; } = string.Empty;

    [JsonPropertyName("format")]
    public string Format { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public SignatureStatus Status { get; init; } = SignatureStatus.UnknownError;

    [JsonPropertyName("status_message")]
    public string StatusMessage { get; init; } = string.Empty;

    [JsonPropertyName("trust_status")]
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public SignatureStatus? TrustStatus { get; init; }

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
    public X509Certificate2? SignerCertificate
    {
        get
        {
            if (!_signerCertificateResolved)
            {
                _signerCertificate = DecodeCertificate(SignerCertificateDerBase64);
                _signerCertificateResolved = true;
            }
            return _signerCertificate;
        }
    }

    [JsonIgnore]
    public X509Certificate2? TimeStamperCertificate
    {
        get
        {
            if (!_timeStamperCertificateResolved)
            {
                _timeStamperCertificate = DecodeCertificate(TimeStamperCertificateDerBase64);
                _timeStamperCertificateResolved = true;
            }
            return _timeStamperCertificate;
        }
    }

    [JsonIgnore]
    public SignatureType SignatureType
    {
        get
        {
            if (Status is SignatureStatus.NotSigned or SignatureStatus.NotSupportedFileFormat)
            {
                return SignatureType.None;
            }

            return Format.Equals("Catalog", StringComparison.OrdinalIgnoreCase)
                ? SignatureType.Catalog
                : SignatureType.Authenticode;
        }
    }

    [JsonIgnore]
    public bool IsOSBinary => false;

    [JsonIgnore]
    public string[]? SubjectAlternativeName => ExtractSubjectAlternativeName(SignerCertificate);

    [JsonIgnore]
    public string PortableStatus => Status.ToString();

    [JsonIgnore]
    public string? PortableTrustStatus => TrustStatus?.ToString();

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

    private static string[]? ExtractSubjectAlternativeName(X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return null;
        }

        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value != "2.5.29.17")
            {
                continue;
            }

            string formatted = extension.Format(multiLine: true);
            if (string.IsNullOrWhiteSpace(formatted))
            {
                return null;
            }

            return formatted.Split(
                ["\r\n", "\n", "\r"],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return null;
    }
}
