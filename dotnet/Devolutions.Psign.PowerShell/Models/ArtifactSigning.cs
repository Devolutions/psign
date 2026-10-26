using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

/// <summary>
/// Azure Artifact Signing identity decoded from a signer certificate's certificate-profile EKU
/// (<c>1.3.6.1.4.1.311.97.*</c>). Decoding alone is not a trust decision.
/// </summary>
public sealed class PsignArtifactSigningIdentity
{
    /// <summary><c>public_trust</c>, <c>public_trust_test</c>, <c>private_trust</c>, or <c>private_trust_ci_policy</c>.</summary>
    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    /// <summary>Dotted arcs after the profile-type prefix; stable across daily certificate renewals.</summary>
    [JsonPropertyName("publisher_id")]
    public string PublisherId { get; init; } = string.Empty;

    [JsonPropertyName("identity_eku")]
    public string IdentityEku { get; init; } = string.Empty;

    [JsonPropertyName("has_public_trust_marker")]
    public bool HasPublicTrustMarker { get; init; }

    [JsonPropertyName("has_code_signing_eku")]
    public bool HasCodeSigningEku { get; init; }

    /// <summary>File the identity was read from, when known.</summary>
    [JsonIgnore]
    public string? Path { get; set; }

    /// <summary>Subject of the certificate carrying the identity, when known.</summary>
    [JsonIgnore]
    public string? Subject { get; set; }

    public override string ToString() => PublisherId;
}

/// <summary>Result of a successful Azure Artifact Signing validation.</summary>
public sealed class PsignArtifactSigningVerification
{
    /// <summary>PE certificate-table entry index; 0 for single-signature formats.</summary>
    [JsonPropertyName("signature_index")]
    public int SignatureIndex { get; init; }

    [JsonPropertyName("signer_subject")]
    public string SignerSubject { get; init; } = string.Empty;

    [JsonPropertyName("identity")]
    public PsignArtifactSigningIdentity? Identity { get; init; }

    [JsonPropertyName("root_subject")]
    public string RootSubject { get; init; } = string.Empty;

    [JsonPropertyName("root_sha1")]
    public string RootSha1 { get; init; } = string.Empty;

    /// <summary><c>true</c> when certificate validity was checked at a trusted timestamp.</summary>
    [JsonPropertyName("timestamped")]
    public bool Timestamped { get; init; }

    [JsonPropertyName("verification_time")]
    public DateTime VerificationTime { get; init; }
}

internal sealed class PortableArtifactSigningOptions
{
    [JsonPropertyName("publisher_ids")]
    public string[] PublisherIds { get; init; } = [];

    [JsonPropertyName("private_trust_root_paths")]
    public string[] PrivateTrustRootPaths { get; init; } = [];

    [JsonPropertyName("allow_missing_timestamp")]
    public bool AllowMissingTimestamp { get; init; }
}

internal sealed class PortableArtifactSigningIdentityRequest
{
    [JsonPropertyName("certificate_der_base64")]
    public required string CertificateDerBase64 { get; init; }
}

internal sealed class PortableArtifactSigningIdentityResponse
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("identity")]
    public PsignArtifactSigningIdentity? Identity { get; init; }
}
