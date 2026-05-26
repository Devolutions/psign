using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PsignCatalogValidationStatus
{
    Valid,
    ValidationFailed,
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PsignCatalogItemStatus
{
    Valid,
    Missing,
    HashMismatch,
    NotInCatalog,
    Skipped,
}

public sealed class PsignCatalogItem
{
    [JsonPropertyName("path")]
    public string Path { get; init; } = string.Empty;

    [JsonPropertyName("hash")]
    public string Hash { get; init; } = string.Empty;
}

public sealed class PsignCatalogPathItem
{
    [JsonPropertyName("path")]
    public string Path { get; init; } = string.Empty;

    [JsonPropertyName("hash")]
    public string? Hash { get; init; }

    [JsonPropertyName("status")]
    public PsignCatalogItemStatus Status { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }
}

internal sealed class PortableNewFileCatalogResponse
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("catalog_file_path")]
    public string CatalogFilePath { get; init; } = string.Empty;

    [JsonPropertyName("catalog_version")]
    public int CatalogVersion { get; init; }

    [JsonPropertyName("hash_algorithm")]
    public string HashAlgorithm { get; init; } = string.Empty;

    [JsonPropertyName("item_count")]
    public int ItemCount { get; init; }

    [JsonPropertyName("catalog_items")]
    public PsignCatalogItem[] CatalogItems { get; init; } = [];
}

public sealed class PortableTestFileCatalogResponse
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("catalog_file_path")]
    public string CatalogFilePath { get; init; } = string.Empty;

    [JsonPropertyName("status")]
    public PsignCatalogValidationStatus Status { get; init; }

    [JsonPropertyName("hash_algorithm")]
    public string HashAlgorithm { get; init; } = string.Empty;

    [JsonPropertyName("catalog_items")]
    public PsignCatalogItem[] CatalogItems { get; init; } = [];

    [JsonPropertyName("path_items")]
    public PsignCatalogPathItem[] PathItems { get; init; } = [];

    [JsonPropertyName("skipped_items")]
    public string[] SkippedItems { get; init; } = [];

    [JsonPropertyName("signature")]
    public PortableSignature Signature { get; init; } = new();
}
