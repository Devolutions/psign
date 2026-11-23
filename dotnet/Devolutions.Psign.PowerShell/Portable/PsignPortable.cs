using System.Text.Json;
using Devolutions.Psign.PowerShell.Models;
using PortableCoreJson = Devolutions.Psign.Signing.Portable.PortableCoreJson;
using PortableCoreOperations = Devolutions.Psign.Signing.Portable.PortableCoreOperations;

namespace Devolutions.Psign.PowerShell.Portable;

/// <summary>
/// Bridge from the cmdlets to the managed portable core (<see cref="PortableCoreJson"/>). It keeps the JSON request /
/// response contract of the Rust <c>psign-core</c> FFI, so the cmdlet models are unchanged, but runs entirely in-process
/// in pure C# with no native library.
/// </summary>
internal static class PsignPortable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
    };

    internal static PortableSignature GetSignature(PortableGetSignatureRequest request)
    {
        return Invoke<PortableGetSignatureRequest, PortableSignature>(PortableCoreOperations.GetSignature, request);
    }

    internal static PortableArtifactSigningIdentityResponse GetArtifactSigningIdentity(PortableArtifactSigningIdentityRequest request)
    {
        return Invoke<PortableArtifactSigningIdentityRequest, PortableArtifactSigningIdentityResponse>(
            PortableCoreOperations.GetArtifactSigningIdentity,
            request);
    }

    internal static PortableNewFileCatalogResponse NewFileCatalog(PortableNewFileCatalogRequest request)
    {
        return Invoke<PortableNewFileCatalogRequest, PortableNewFileCatalogResponse>(PortableCoreOperations.NewFileCatalog, request);
    }

    internal static PortableTestFileCatalogResponse TestFileCatalog(PortableTestFileCatalogRequest request)
    {
        return Invoke<PortableTestFileCatalogRequest, PortableTestFileCatalogResponse>(PortableCoreOperations.TestFileCatalog, request);
    }

    internal static PortableSignResponse Sign(PortableSignRequest request)
    {
        return Invoke<PortableSignRequest, PortableSignResponse>(PortableCoreOperations.Sign, request);
    }

    internal static PortableClearSignatureResponse ClearSignature(PortableClearSignatureRequest request)
    {
        return Invoke<PortableClearSignatureRequest, PortableClearSignatureResponse>(PortableCoreOperations.ClearSignature, request);
    }

    private static TResponse Invoke<TRequest, TResponse>(string operation, TRequest request)
    {
        string requestJson = JsonSerializer.Serialize(request, JsonOptions);
        (uint statusCode, string responseJson) = PortableCoreJson.Invoke(operation, requestJson);

        if (statusCode != PortableCoreJson.StatusOk)
        {
            PortableErrorResponse? error = null;
            try
            {
                error = JsonSerializer.Deserialize<PortableErrorResponse>(responseJson, JsonOptions);
            }
            catch (JsonException)
            {
            }

            string message = string.IsNullOrEmpty(error?.Message) ? responseJson : error.Message;
            throw new PsignPortableException(statusCode, message);
        }

        return JsonSerializer.Deserialize<TResponse>(responseJson, JsonOptions)
            ?? throw new PsignPortableException(statusCode, "psign portable returned an empty JSON response.");
    }
}
