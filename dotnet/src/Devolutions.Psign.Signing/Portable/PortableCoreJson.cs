using Devolutions.Psign.Core;

namespace Devolutions.Psign.Signing.Portable;

/// <summary>Operation names accepted by <see cref="PortableCoreJson.Invoke(string, string?, PortableCoreOptions?)"/> (the <c>psign_core_*</c> FFI exports without the prefix).</summary>
public static class PortableCoreOperations
{
    public const string Version = "version";
    public const string GetSignature = "get_signature";
    public const string NewFileCatalog = "new_file_catalog";
    public const string TestFileCatalog = "test_file_catalog";
    public const string GetArtifactSigningIdentity = "get_artifact_signing_identity";
    public const string ValidatePowerShellScript = "validate_powershell_script";
    public const string Sign = "sign";
    public const string ClearSignature = "clear_signature";

    /// <summary>Every operation name.</summary>
    public static IReadOnlyList<string> All { get; } =
        [Version, GetSignature, NewFileCatalog, TestFileCatalog, GetArtifactSigningIdentity, ValidatePowerShellScript, Sign, ClearSignature];
}

/// <summary>
/// Managed equivalent of the <c>psign-portable-ffi</c> C ABI (<c>psign_core_*</c>): JSON request in, status code and JSON
/// response out, so a host (for example the PowerShell module) can switch from the native library to managed calls without
/// changing its JSON handling. Status codes: <see cref="StatusOk"/> (response JSON), <see cref="StatusInvalidRequest"/>
/// and <see cref="StatusOperationFailed"/> (<see cref="PortableErrorResponse"/> JSON), <see cref="StatusPanic"/>
/// (unexpected internal error, the analogue of a Rust panic crossing the FFI boundary).
/// </summary>
public static class PortableCoreJson
{
    public const uint StatusOk = 0;
    public const uint StatusInvalidRequest = 1;
    public const uint StatusOperationFailed = 2;
    public const uint StatusPanic = 3;

    private const string FallbackErrorJson =
        "{\"schema_version\":1,\"code\":\"OperationFailed\",\"message\":\"failed to serialize psign portable error\"}";

    /// <summary>
    /// Run <paramref name="operation"/> (see <see cref="PortableCoreOperations"/>; a <c>psign_core_</c> prefix is accepted)
    /// on <paramref name="requestJson"/>. <c>version</c> ignores the request. A <c>null</c> request is an invalid request
    /// (the FFI's null pointer).
    /// </summary>
    public static (uint StatusCode, string Json) Invoke(string operation, string? requestJson, PortableCoreOptions? options = null)
    {
        var op = operation.StartsWith("psign_core_", StringComparison.Ordinal) ? operation["psign_core_".Length..] : operation;
        try
        {
            return op switch
            {
                PortableCoreOperations.Version => Ok(PortableCore.Version().ToJson()),
                PortableCoreOperations.GetSignature => Run(requestJson, PortableGetSignatureRequest.FromJson, r => PortableCore.PortableGetSignature(r, options).ToJson()),
                PortableCoreOperations.NewFileCatalog => Run(requestJson, PortableNewFileCatalogRequest.FromJson, r => PortableCore.PortableNewFileCatalog(r).ToJson()),
                PortableCoreOperations.TestFileCatalog => Run(requestJson, PortableTestFileCatalogRequest.FromJson, r => PortableCore.PortableTestFileCatalog(r, options).ToJson()),
                PortableCoreOperations.GetArtifactSigningIdentity => Run(
                    requestJson,
                    PortableArtifactSigningIdentityRequest.FromJson,
                    r => PortableCore.PortableGetArtifactSigningIdentity(r).ToJson()),
                PortableCoreOperations.ValidatePowerShellScript => Run(
                    requestJson,
                    PortableValidatePowerShellRequest.FromJson,
                    r => PortableCore.PortableValidatePowerShellScript(r, options).ToJson()),
                PortableCoreOperations.Sign => Run(requestJson, PortableSignRequest.FromJson, r => PortableCore.PortableSign(r, options).ToJson()),
                PortableCoreOperations.ClearSignature => Run(requestJson, PortableClearSignatureRequest.FromJson, r => PortableCore.PortableClearSignature(r).ToJson()),
                _ => Error(StatusInvalidRequest, PortableErrorCode.InvalidRequest, $"unknown psign portable operation `{operation}`"),
            };
        }
        catch (Exception e)
        {
            _ = e;
            return Error(StatusPanic, PortableErrorCode.Panic, "panic crossing psign portable FFI boundary");
        }
    }


    private static (uint, string) Run<TRequest>(string? requestJson, Func<string, TRequest> parse, Func<TRequest, string> execute)
    {
        if (requestJson is null)
        {
            return Error(StatusInvalidRequest, PortableErrorCode.InvalidRequest, "request JSON pointer is null");
        }

        TRequest request;
        try
        {
            request = parse(requestJson);
        }
        catch (PortableRequestException e)
        {
            return Error(StatusInvalidRequest, PortableErrorCode.InvalidRequest, e.Message);
        }

        try
        {
            return Ok(execute(request));
        }
        catch (Exception e) when (PortableCore.IsOperationError(e))
        {
            return Error(StatusOperationFailed, PortableErrorCode.OperationFailed, e.Message);
        }
    }

    private static (uint, string) Ok(string json) => (StatusOk, json);

    private static (uint, string) Error(uint status, PortableErrorCode code, string message)
    {
        try
        {
            return (status, PortableCore.CreateErrorResponse(code, message).ToJson());
        }
        catch (Exception e) when (PortableCore.IsOperationError(e))
        {
            return (status, FallbackErrorJson);
        }
    }
}
