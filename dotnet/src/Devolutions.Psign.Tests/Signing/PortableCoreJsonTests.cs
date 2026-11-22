using System.Text.Json.Nodes;
using Devolutions.Psign.Signing.Portable;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// Ports of the <c>psign-portable-ffi</c> tests plus JSON-contract tests for <see cref="PortableCoreJson"/> (serde field
/// names, defaults, skipped fields and error mapping).
/// </summary>
public sealed class PortableCoreJsonTests
{
    [Fact]
    public void VersionReturnsJson()
    {
        var (status, json) = PortableCoreJson.Invoke("version", null);
        Assert.Equal(PortableCoreJson.StatusOk, status);
        Assert.Contains("psign-portable-core", json, StringComparison.Ordinal);
        var v = typeof(PortableCore).Assembly.GetName().Version!;
        Assert.Equal($"{{\"schema_version\":1,\"crate_name\":\"psign-portable-core\",\"crate_version\":\"{v.Major}.{v.Minor}.{v.Build}\"}}", json);
    }

    [Fact]
    public void InvalidJsonReturnsStructuredError()
    {
        var (status, json) = PortableCoreJson.Invoke("get_signature", "{not json");
        Assert.Equal(PortableCoreJson.StatusInvalidRequest, status);
        Assert.Contains("InvalidRequest", json, StringComparison.Ordinal);
        var node = JsonNode.Parse(json)!;
        Assert.Equal(1, node["schema_version"]!.GetValue<int>());
        Assert.Equal("InvalidRequest", node["code"]!.GetValue<string>());
    }

    [Fact]
    public void NullRequestIsInvalidRequest()
    {
        var (status, json) = PortableCoreJson.Invoke("psign_core_sign", null);
        Assert.Equal(PortableCoreJson.StatusInvalidRequest, status);
        Assert.Equal("{\"schema_version\":1,\"code\":\"InvalidRequest\",\"message\":\"request JSON pointer is null\"}", json);
    }

    [Fact]
    public void MissingFieldsAndBadEnumsAreInvalidRequests()
    {
        var (status, json) = PortableCoreJson.Invoke("get_signature", "{}");
        Assert.Equal(PortableCoreJson.StatusInvalidRequest, status);
        Assert.Contains("missing field `path`", json, StringComparison.Ordinal);

        (status, json) = PortableCoreJson.Invoke("sign", "{\"path\":\"a.exe\",\"hash_algorithm\":\"Sha1\"}");
        Assert.Equal(PortableCoreJson.StatusInvalidRequest, status);
        Assert.Contains("unknown variant `Sha1`, expected one of `Sha256`, `Sha384`, `Sha512`", json, StringComparison.Ordinal);

        (status, json) = PortableCoreJson.Invoke("get_signature", "{\"path\":\"a\",\"online_aia\":1}");
        Assert.Equal(PortableCoreJson.StatusInvalidRequest, status);
        Assert.Contains("expected a boolean", json, StringComparison.Ordinal);

        (status, json) = PortableCoreJson.Invoke("get_signature", "{\"path\":\"a\",\"path\":\"b\"}");
        Assert.Equal(PortableCoreJson.StatusInvalidRequest, status);
        Assert.Contains("duplicate field `path`", json, StringComparison.Ordinal);

        (status, _) = PortableCoreJson.Invoke("nope", "{}");
        Assert.Equal(PortableCoreJson.StatusInvalidRequest, status);
    }

    [Fact]
    public void UnknownFieldsAreIgnoredAndOperationErrorsUseOuterContext()
    {
        using var dir = new TempDir();
        var missing = dir.File("missing.exe");
        var request = new JsonObject { ["path"] = missing, ["future_field"] = 42 }.ToJsonString();
        var (status, json) = PortableCoreJson.Invoke("get_signature", request);
        Assert.Equal(PortableCoreJson.StatusOperationFailed, status);
        var node = JsonNode.Parse(json)!;
        Assert.Equal("OperationFailed", node["code"]!.GetValue<string>());
        Assert.Equal("read " + missing, node["message"]!.GetValue<string>());
    }

    [Fact]
    public void ValidatePowerShellScriptReturnsJson()
    {
        var (status, json) = PortableCoreJson.Invoke(
            "validate_powershell_script",
            "{\"source_path_or_extension\":\".ps1\",\"content_base64\":\"V3JpdGUtT3V0cHV0IDENCg==\"}");
        Assert.Equal(PortableCoreJson.StatusOk, status);
        Assert.Contains("PowerShellScript", json, StringComparison.Ordinal);
        Assert.Contains("NotSigned", json, StringComparison.Ordinal);
        Assert.StartsWith("{\"schema_version\":1,\"path\":\".ps1\",\"format\":\"PowerShellScript\",\"status\":\"NotSigned\",\"status_message\":", json, StringComparison.Ordinal);
        Assert.EndsWith(",\"signature_count\":0}", json, StringComparison.Ordinal);
    }

    [Fact]
    public void FileCatalogCreateAndTestReturnJson()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("a.txt"), "alpha"u8.ToArray());
        var catalog = dir.File("catalog.cat");
        var create = new JsonObject
        {
            ["catalog_file_path"] = catalog,
            ["paths"] = new JsonArray(dir.DirPath),
            ["catalog_version"] = 2,
        }.ToJsonString();
        var (status, json) = PortableCoreJson.Invoke("new_file_catalog", create);
        Assert.Equal(PortableCoreJson.StatusOk, status);
        Assert.Contains("SHA256", json, StringComparison.Ordinal);

        var test = new JsonObject
        {
            ["catalog_file_path"] = catalog,
            ["paths"] = new JsonArray(dir.DirPath),
            ["files_to_skip"] = new JsonArray(),
        }.ToJsonString();
        (status, json) = PortableCoreJson.Invoke("test_file_catalog", test);
        Assert.Equal(PortableCoreJson.StatusOk, status);
        Assert.Contains("Valid", json, StringComparison.Ordinal);
        var node = JsonNode.Parse(json)!;
        Assert.Equal("Valid", node["status"]!.GetValue<string>());
        Assert.Equal(
            ["schema_version", "catalog_file_path", "status", "hash_algorithm", "catalog_items", "path_items", "skipped_items", "signature"],
            node.AsObject().Select(p => p.Key));
        Assert.Equal("{\"path\":\"a.txt\",\"hash\":\"8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8\",\"status\":\"Valid\"}", node["path_items"]![0]!.ToJsonString());
    }

    [Fact]
    public void RequestModelsRoundTripSerdeShape()
    {
        var request = PortableSignRequest.FromJson("{\"path\":\"a.exe\",\"pfx_path\":\"x.pfx\",\"timestamp_hash_algorithm\":\"Sha384\",\"azure_key_vault_managed_identity\":null}");
        Assert.Equal(PortableDigestAlgorithm.Sha256, request.HashAlgorithm);
        Assert.Equal(PortableTimestampDigestAlgorithm.Sha384, request.TimestampHashAlgorithm);
        Assert.Null(request.AzureKeyVaultManagedIdentity);
        var json = request.ToJson();
        Assert.StartsWith("{\"path\":\"a.exe\",\"append_signature\":false,\"skip_signed\":false,\"output_path\":null,\"hash_algorithm\":\"Sha256\"", json, StringComparison.Ordinal);
        Assert.Equal(json, PortableSignRequest.FromJson(json).ToJson());

        var get = PortableGetSignatureRequest.FromJson("{\"path\":\"p\",\"revocation_mode\":\"BestEffort\",\"artifact_signing\":{\"publisher_ids\":[\"1.2\"]}}");
        Assert.Equal(PortableRevocationMode.BestEffort, get.RevocationMode);
        Assert.Equal(["1.2"], get.ArtifactSigning!.PublisherIds);
        Assert.False(get.ArtifactSigning.AllowMissingTimestamp);
        Assert.Equal(get.ToJson(), PortableGetSignatureRequest.FromJson(get.ToJson()).ToJson());
    }

    [Fact]
    public void SignatureResponseSkipsEmptyFieldsLikeSerde()
    {
        var response = new PortableSignatureResponse { Path = "x", Format = PortableFileFormat.Pe, Status = PortableSignatureStatus.NotSigned, StatusMessage = "m" };
        Assert.Equal("{\"schema_version\":1,\"path\":\"x\",\"format\":\"Pe\",\"status\":\"NotSigned\",\"status_message\":\"m\",\"signature_count\":0}", response.ToJson());
        response.TrustStatus = PortableSignatureStatus.NotTrusted;
        response.Diagnostics.Add("dé\"");
        Assert.Equal(
            "{\"schema_version\":1,\"path\":\"x\",\"format\":\"Pe\",\"status\":\"NotSigned\",\"status_message\":\"m\",\"trust_status\":\"NotTrusted\",\"signature_count\":0,\"diagnostics\":[\"dé\\\"\"]}",
            response.ToJson());
    }

    [Fact]
    public void ArtifactSigningIdentityJson()
    {
        var der = Devolutions.Psign.Verification.Anchors.ParseCertBytes(Fixtures.Bytes("artifact-signing/devolutions-signer.pem")).RawData;
        var (status, json) = PortableCoreJson.Invoke("get_artifact_signing_identity", new JsonObject { ["certificate_der_base64"] = Convert.ToBase64String(der) }.ToJsonString());
        Assert.Equal(PortableCoreJson.StatusOk, status);
        Assert.Contains("\"identity\":{\"kind\":\"", json, StringComparison.Ordinal);
        Assert.Contains("\"publisher_id\":\"285218949.549339218.252840042.443064405\"", json, StringComparison.Ordinal);

        using var dir = new TempDir();
        using var signer = new TestSigner(dir);
        (status, json) = PortableCoreJson.Invoke("get_artifact_signing_identity", new JsonObject { ["certificate_der_base64"] = Convert.ToBase64String(signer.Certificate.RawData) }.ToJsonString());
        Assert.Equal(PortableCoreJson.StatusOk, status);
        Assert.Equal("{\"schema_version\":1,\"identity\":null}", json);
    }
}
