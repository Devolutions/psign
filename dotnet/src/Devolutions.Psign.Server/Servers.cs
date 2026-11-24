using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Text;

namespace Devolutions.Psign.Server;

/// <summary>RFC 3161 PKIStatus selector (Rust <c>ServerStatus</c>).</summary>
internal enum ServerStatus
{
    Granted,
    Rejection,
    Waiting,
}

/// <summary>Timestamp server response variants (Rust <c>ResponseMode</c>).</summary>
internal enum ResponseMode
{
    Valid,
    BadAlg,
    HttpError,
    MalformedDer,
    MismatchedImprint,
    InvalidSignature,
}

/// <summary>Artifact Signing server response variants (Rust <c>ArtifactResponseMode</c>).</summary>
internal enum ArtifactResponseMode
{
    Valid,
    SyncSuccess,
    BodyId,
    BodyOperationId,
    PemChain,
    HttpError,
    PollHttpError,
    Failed,
    Canceled,
    MalformedJson,
    PollMalformedJson,
}

internal sealed record TimestampServerArgs(string Listen, ServerStatus Status, ResponseMode ResponseMode, string GenTime, string? CertOutput, string? TsaCertOutput, ulong MaxRequests);

internal sealed record PkiServerArgs(string Listen, string? RootCertOutput, string? LeafCertOutput, string? LeafKeyOutput, bool CrlRevokeLeaf, PkiOcspStatus OcspStatus, ulong MaxRequests);

internal sealed record AzureKeyVaultServerArgs(string Listen, string CertificateName, string KeyName, string Version, string? RootCertOutput, string? LeafCertOutput, ulong MaxRequests);

internal sealed record ArtifactSigningServerArgs(
    string Listen,
    ArtifactResponseMode ResponseMode,
    string? ExpectSignatureAlgorithm,
    string? ExpectApiVersion,
    string? ExpectCorrelationId,
    string? RootCertOutput,
    string? LeafCertOutput,
    ulong MaxRequests);

/// <summary>
/// The four psign-server services (port of <c>run_*_server</c> / <c>handle_*_client</c> in <c>psign-server.rs</c>):
/// a sequential accept loop on one listener, one request per connection, request errors reported on stderr as
/// <c>request failed: ...</c> with the connection closed without a response.
/// </summary>
internal static class Servers
{
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Stdout sink (Rust <c>println!</c> + flush).</summary>
    internal static TextWriter Stdout { get; set; } = Console.Out;

    /// <summary>Stderr sink (Rust <c>eprintln!</c>).</summary>
    internal static TextWriter Stderr { get; set; } = Console.Error;

    private static void PrintLine(string line)
    {
        Stdout.Write(line + "\n");
        Stdout.Flush();
    }

    private static Socket BindListener(string listen)
    {
        try
        {
            return RustNet.Bind(listen);
        }
        catch (PsignException e)
        {
            throw new PsignException($"bind {listen}", e);
        }
    }

    private static string LocalAddress(Socket listener) => RustNet.FormatEndPoint((IPEndPoint)listener.LocalEndPoint!);

    private static void WriteFile(string path, byte[] data, string context)
    {
        try
        {
            File.WriteAllBytes(path, data);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"{context} {path}", IoErrorText.Inner(e));
        }
    }

    private static void ServeLoop(Socket listener, ulong maxRequests, Action<Socket> handle)
    {
        using (listener)
        {
            ulong served = 0;
            while (true)
            {
                Socket client;
                try
                {
                    client = listener.Accept();
                }
                catch (SocketException e)
                {
                    throw new PsignException("accept HTTP client", new PsignException(RustNet.SocketErrorText(e)));
                }

                using (client)
                {
                    try
                    {
                        client.ReceiveTimeout = (int)ReadTimeout.TotalMilliseconds;
                        client.SendTimeout = (int)ReadTimeout.TotalMilliseconds;
                        handle(client);
                    }
                    catch (PsignException e)
                    {
                        Stderr.Write($"request failed: {e.FullMessage}\n");
                        Stderr.Flush();
                    }
                    catch (Exception e) when (e is IOException or ObjectDisposedException or SocketException)
                    {
                        Stderr.Write($"request failed: {PsignException.Render(e)}\n");
                        Stderr.Flush();
                    }

                    // Like dropping the Rust TcpStream: close without an explicit shutdown.
                }

                served++;
                if (maxRequests != 0 && served >= maxRequests)
                {
                    break;
                }
            }
        }
    }

    // ------------------------------------------------------------------ timestamp-server

    public static void RunTimestampServer(TimestampServerArgs args)
    {
        DerPush.ValidateGeneralizedTimeZ(args.GenTime);
        using var listener = BindListener(args.Listen);
        var local = LocalAddress(listener);
        using var tsa = new TimestampAuthority();
        if (args.CertOutput is { } certOut)
        {
            WriteFile(certOut, tsa.RootCertDer, "write generated TSA root certificate");
        }

        if (args.TsaCertOutput is { } tsaOut)
        {
            WriteFile(tsaOut, tsa.CertDer, "write generated TSA leaf certificate");
        }

        PrintLine($"psign-server timestamp-server listening on http://{local}/");
        ServeLoop(listener, args.MaxRequests, s => HandleTimestampClient(s, tsa, args));
    }

    internal static uint PkiStatus(ServerStatus s) => s switch
    {
        ServerStatus.Granted => 0,
        ServerStatus.Rejection => 2,
        _ => 3,
    };

    private static void HandleTimestampClient(Socket stream, TimestampAuthority tsa, TimestampServerArgs args)
    {
        var request = HttpWire.ReadRequest(stream);
        if (request.Method != "POST")
        {
            HttpWire.WriteText(stream, 405, "Method Not Allowed", "timestamp server expects POST");
            return;
        }

        if (args.ResponseMode == ResponseMode.HttpError)
        {
            HttpWire.WriteText(stream, 500, "Internal Server Error", "psign-server configured HTTP error");
            return;
        }

        byte[] responseDer;
        switch (args.ResponseMode)
        {
            case ResponseMode.Valid:
                responseDer = PkiStatus(args.Status) == 0
                    ? tsa.BuildTimeStampResponse(TimestampRequest.Parse(request.Body), args.GenTime)
                    : TimestampAuthority.BuildStatusOnlyResponse(PkiStatus(args.Status), "psign-server configured failure", null);
                break;
            case ResponseMode.BadAlg:
                responseDer = TimestampAuthority.BuildStatusOnlyResponse(2, "psign-server configured badAlg", 0);
                break;
            case ResponseMode.MalformedDer:
                responseDer = [0x30, 0x80, 0x00, 0x00];
                break;
            case ResponseMode.MismatchedImprint:
                {
                    var req = TimestampRequest.Parse(request.Body);
                    if (req.HashedMessage.Length > 0)
                    {
                        req.HashedMessage[0] ^= 0xff;
                    }

                    responseDer = tsa.BuildTimeStampResponse(req, args.GenTime);
                    break;
                }

            default:
                {
                    var der = tsa.BuildTimeStampResponse(TimestampRequest.Parse(request.Body), args.GenTime);
                    if (der.Length > 0)
                    {
                        der[^1] ^= 0x01;
                    }

                    responseDer = der;
                    break;
                }
        }

        HttpWire.WriteResponse(stream, 200, "OK", "application/timestamp-reply", responseDer);
    }

    // ------------------------------------------------------------------ pki-server

    public static void RunPkiServer(PkiServerArgs args)
    {
        using var listener = BindListener(args.Listen);
        var local = LocalAddress(listener);
        var pki = new PkiAuthority(args.CrlRevokeLeaf, args.OcspStatus);
        if (args.RootCertOutput is { } rootOut)
        {
            WriteFile(rootOut, pki.RootCertDer, "write generated PKI root certificate");
        }

        if (args.LeafCertOutput is { } leafOut)
        {
            WriteFile(leafOut, pki.LeafCertDer, "write generated PKI leaf certificate");
        }

        if (args.LeafKeyOutput is { } keyOut)
        {
            WriteFile(keyOut, pki.LeafKeyDer, "write generated PKI leaf private key");
        }

        PrintLine($"psign-server pki-server listening on http://{local}/");
        PrintLine($"psign-server pki-server root http://{local}/root.der");
        PrintLine($"psign-server pki-server issuer http://{local}/issuer.der");
        PrintLine($"psign-server pki-server leaf http://{local}/leaf.der");
        PrintLine($"psign-server pki-server crl http://{local}/crl.der");
        PrintLine($"psign-server pki-server ocsp http://{local}/ocsp");
        ServeLoop(listener, args.MaxRequests, s => HandlePkiClient(s, pki));
    }

    private static void HandlePkiClient(Socket stream, PkiAuthority pki)
    {
        var request = HttpWire.ReadRequest(stream);
        switch (request.Method, request.Path)
        {
            case ("GET", "/" or "/health"):
                HttpWire.WriteText(stream, 200, "OK", "ok\n");
                break;
            case ("GET", "/root.der" or "/issuer.der"):
                HttpWire.WriteResponse(stream, 200, "OK", "application/pkix-cert", pki.RootCertDer);
                break;
            case ("GET", "/leaf.der"):
                HttpWire.WriteResponse(stream, 200, "OK", "application/pkix-cert", pki.LeafCertDer);
                break;
            case ("GET", "/crl.der"):
                HttpWire.WriteResponse(stream, 200, "OK", "application/pkix-crl", pki.CrlDer);
                break;
            case ("POST", "/ocsp"):
                HttpWire.WriteResponse(stream, 200, "OK", "application/ocsp-response", pki.OcspDer);
                break;
            default:
                HttpWire.WriteText(stream, 404, "Not Found", "not found\n");
                break;
        }
    }

    // ------------------------------------------------------------------ azure-key-vault-server

    private static void WriteGeneratedAzureCerts(AzureSigningIdentity identity, string? rootOutput, string? leafOutput)
    {
        if (rootOutput is not null)
        {
            WriteFile(rootOutput, identity.RootCertDer, "write generated Azure test root certificate");
        }

        if (leafOutput is not null)
        {
            WriteFile(leafOutput, identity.LeafCertDer, "write generated Azure test leaf certificate");
        }
    }

    public static void RunAzureKeyVaultServer(AzureKeyVaultServerArgs args)
    {
        using var listener = BindListener(args.Listen);
        var baseUrl = $"http://{LocalAddress(listener)}/";
        using var identity = new AzureSigningIdentity(
            "psign local Azure Key Vault test root CA",
            "psign local Azure Key Vault code signing leaf",
            20,
            21);
        WriteGeneratedAzureCerts(identity, args.RootCertOutput, args.LeafCertOutput);
        PrintLine($"psign-server azure-key-vault-server listening on {baseUrl}");
        PrintLine($"psign-server azure-key-vault-server certificate {args.CertificateName}");
        PrintLine($"psign-server azure-key-vault-server leaf {baseUrl}certificates/{args.CertificateName}");
        ServeLoop(listener, args.MaxRequests, s => HandleAzureKeyVaultClient(s, identity, args, baseUrl));
    }

    private static JsonObject Obj(params (string Key, JsonNode? Value)[] props)
    {
        var o = new JsonObject();
        foreach (var (k, v) in props)
        {
            o[k] = v;
        }

        return o;
    }

    private static JsonObject UnauthorizedBody() =>
        Obj(("error", Obj(("code", "Unauthorized"), ("message", "missing bearer token"))));

    private static void HandleAzureKeyVaultClient(Socket stream, AzureSigningIdentity identity, AzureKeyVaultServerArgs args, string baseUrl)
    {
        var request = HttpWire.ReadRequest(stream);
        if (!HasBearerToken(request))
        {
            HttpWire.WriteJson(stream, 401, "Unauthorized", UnauthorizedBody());
            return;
        }

        var path = PathWithoutQuery(request.Path);
        var certPath = $"/certificates/{args.CertificateName}";
        var certVersionPath = $"{certPath}/{args.Version}";
        var signPath = $"/keys/{args.KeyName}/versions/{args.Version}/sign";
        var kid = $"{baseUrl}keys/{args.KeyName}/versions/{args.Version}";

        if (request.Method == "GET" && (path == certPath || path == certVersionPath))
        {
            HttpWire.WriteJson(stream, 200, "OK", Obj(
                ("id", $"{baseUrl}certificates/{args.CertificateName}/{args.Version}"),
                ("kid", kid),
                ("cer", Convert.ToBase64String(identity.LeafCertDer))));
            return;
        }

        if (request.Method == "POST" && path == signPath)
        {
            object? body;
            try
            {
                body = SerdeJson.Parse(request.Body);
            }
            catch (PsignException e)
            {
                throw new PsignException("Key Vault sign JSON", e);
            }

            var alg = SerdeJson.GetString(body, "alg") ?? throw new PsignException("Key Vault sign body missing alg");
            var digestB64 = SerdeJson.GetString(body, "value") ?? throw new PsignException("Key Vault sign body missing value");
            byte[] digest;
            try
            {
                digest = Base64UrlNoPad.Decode(digestB64.Trim());
            }
            catch (FormatException e)
            {
                throw new PsignException("decode Key Vault sign digest", new PsignException(e.Message));
            }

            var signature = identity.SignDigest(alg, digest);
            HttpWire.WriteJson(stream, 200, "OK", Obj(("kid", kid), ("value", Base64UrlNoPad.Encode(signature))));
            return;
        }

        HttpWire.WriteText(stream, 404, "Not Found", "not found\n");
    }

    // ------------------------------------------------------------------ artifact-signing-server

    private sealed class ArtifactState
    {
        public long NextOperation = 1;

        public readonly Dictionary<string, JsonObject> Operations = new(StringComparer.Ordinal);
    }

    public static void RunArtifactSigningServer(ArtifactSigningServerArgs args)
    {
        using var listener = BindListener(args.Listen);
        var baseUrl = $"http://{LocalAddress(listener)}/";
        using var identity = new AzureSigningIdentity(
            "psign local Artifact Signing test root CA",
            "psign local Artifact Signing code signing leaf",
            30,
            31);
        WriteGeneratedAzureCerts(identity, args.RootCertOutput, args.LeafCertOutput);
        PrintLine($"psign-server artifact-signing-server listening on {baseUrl}");
        PrintLine($"psign-server artifact-signing-server endpoint {baseUrl}");
        var state = new ArtifactState();
        ServeLoop(listener, args.MaxRequests, s => HandleArtifactSigningClient(s, identity, args, baseUrl, state));
    }

    private static bool PollFailureResponse(Socket stream, ArtifactResponseMode mode)
    {
        switch (mode)
        {
            case ArtifactResponseMode.PollHttpError:
                HttpWire.WriteJson(stream, 503, "Service Unavailable", Obj(("error", Obj(("code", "InjectedPollFailure")))));
                return true;
            case ArtifactResponseMode.PollMalformedJson:
                HttpWire.WriteResponse(stream, 200, "OK", "application/json", "{not-json"u8.ToArray());
                return true;
            default:
                return false;
        }
    }

    private static void HandleArtifactSigningClient(Socket stream, AzureSigningIdentity identity, ArtifactSigningServerArgs args, string baseUrl, ArtifactState state)
    {
        var request = HttpWire.ReadRequest(stream);
        var path = PathWithoutQuery(request.Path);
        if (request.Method == "GET" && path == "/metadata/identity/oauth2/token")
        {
            HttpWire.WriteJson(stream, 200, "OK", Obj(
                ("access_token", "psign-server-managed-identity-token"),
                ("expires_in", "3600"),
                ("resource", "https://codesigning.azure.net"),
                ("token_type", "Bearer")));
            return;
        }

        if (request.Method == "POST" && path.EndsWith("/oauth2/v2.0/token", StringComparison.Ordinal))
        {
            HttpWire.WriteJson(stream, 200, "OK", Obj(
                ("access_token", "psign-server-client-credentials-token"),
                ("expires_in", 3600),
                ("token_type", "Bearer")));
            return;
        }

        if (!HasBearerToken(request))
        {
            HttpWire.WriteJson(stream, 401, "Unauthorized", UnauthorizedBody());
            return;
        }

        if (request.Method == "GET")
        {
            if (path.StartsWith("/operations/", StringComparison.Ordinal))
            {
                var id = path["/operations/".Length..];
                if (PollFailureResponse(stream, args.ResponseMode))
                {
                    return;
                }

                lock (state)
                {
                    if (state.Operations.TryGetValue(id, out var body))
                    {
                        HttpWire.WriteJson(stream, 200, "OK", body);
                        return;
                    }
                }
            }

            if (ParseArtifactPollPath(path) is { } pollId)
            {
                if (PollFailureResponse(stream, args.ResponseMode))
                {
                    return;
                }

                lock (state)
                {
                    if (state.Operations.TryGetValue(pollId, out var body))
                    {
                        HttpWire.WriteJson(stream, 200, "OK", body);
                        return;
                    }
                }
            }

            HttpWire.WriteText(stream, 404, "Not Found", "not found\n");
            return;
        }

        if (request.Method != "POST")
        {
            HttpWire.WriteText(stream, 405, "Method Not Allowed", "method not allowed\n");
            return;
        }

        if (ParseArtifactSignPath(path) is not { } signTarget)
        {
            HttpWire.WriteText(stream, 404, "Not Found", "not found\n");
            return;
        }

        var (account, profile) = signTarget;
        switch (args.ResponseMode)
        {
            case ArtifactResponseMode.HttpError:
                HttpWire.WriteJson(stream, 500, "Internal Server Error", Obj(("error", Obj(("code", "InjectedFailure")))));
                return;
            case ArtifactResponseMode.MalformedJson:
                HttpWire.WriteResponse(stream, 200, "OK", "application/json", "{not-json"u8.ToArray());
                return;
        }

        if (args.ExpectApiVersion is { } expectedApi)
        {
            var actual = QueryParam(request.Path, "api-version") ?? string.Empty;
            if (actual != expectedApi.Trim())
            {
                HttpWire.WriteJson(stream, 400, "Bad Request", Obj(("error", Obj(
                    ("code", "UnexpectedApiVersion"),
                    ("expected", expectedApi),
                    ("actual", actual)))));
                return;
            }
        }

        if (args.ExpectCorrelationId is { } expectedCorrelationRaw)
        {
            var expected = expectedCorrelationRaw.Trim();
            var stable = request.Header("x-correlation-id") ?? string.Empty;
            var azure = request.Header("x-ms-correlation-id") ?? string.Empty;
            if (stable != expected || azure != expected)
            {
                HttpWire.WriteJson(stream, 400, "Bad Request", Obj(("error", Obj(
                    ("code", "UnexpectedCorrelationId"),
                    ("expected", expected),
                    ("x-correlation-id", stable),
                    ("x-ms-correlation-id", azure)))));
                return;
            }
        }

        object? submit;
        try
        {
            submit = SerdeJson.Parse(request.Body);
        }
        catch (PsignException e)
        {
            throw new PsignException("Artifact Signing submit JSON", e);
        }

        var alg = SerdeJson.GetString(submit, "signatureAlgorithm")
            ?? throw new PsignException("Artifact Signing submit body missing signatureAlgorithm");
        if (args.ExpectSignatureAlgorithm is { } expectedAlg && alg != expectedAlg.Trim())
        {
            HttpWire.WriteJson(stream, 400, "Bad Request", Obj(("error", Obj(
                ("code", "UnexpectedSignatureAlgorithm"),
                ("expected", expectedAlg),
                ("actual", alg)))));
            return;
        }

        var digestB64 = SerdeJson.GetString(submit, "digest")
            ?? throw new PsignException("Artifact Signing submit body missing digest");
        byte[] digest;
        try
        {
            digest = Base64Standard.Decode(digestB64.Trim());
        }
        catch (FormatException e)
        {
            throw new PsignException("decode Artifact Signing digest", new PsignException(e.Message));
        }

        string operationId;
        lock (state)
        {
            operationId = $"op-{state.NextOperation++}";
        }

        JsonObject operationBody;
        switch (args.ResponseMode)
        {
            case ArtifactResponseMode.Failed:
                operationBody = Obj(
                    ("id", operationId),
                    ("status", "Failed"),
                    ("error", Obj(("code", "InjectedFailure"), ("message", "psign-server injected failure"))));
                break;
            case ArtifactResponseMode.Canceled:
                operationBody = Obj(("id", operationId), ("status", "Canceled"));
                break;
            default:
                {
                    var signature = identity.SignDigest(alg, digest);
                    var certPayload = args.ResponseMode == ArtifactResponseMode.PemChain
                        ? identity.LeafRootPemBundle()
                        : identity.LeafCertDer;
                    operationBody = Obj(
                        ("id", operationId),
                        ("status", "Succeeded"),
                        ("result", Obj(
                            ("signature", Convert.ToBase64String(signature)),
                            ("signingCertificate", Convert.ToBase64String(certPayload)),
                            ("codeSigningAccountName", account),
                            ("certificateProfileName", profile))));
                    break;
                }
        }

        if (args.ResponseMode == ArtifactResponseMode.SyncSuccess)
        {
            HttpWire.WriteJson(stream, 200, "OK", operationBody);
            return;
        }

        lock (state)
        {
            state.Operations[operationId] = operationBody;
        }

        if (args.ResponseMode is ArtifactResponseMode.BodyId or ArtifactResponseMode.BodyOperationId)
        {
            var acceptBody = args.ResponseMode == ArtifactResponseMode.BodyId
                ? Obj(("id", operationId), ("status", "InProgress"))
                : Obj(("operationId", operationId), ("status", "InProgress"));
            HttpWire.WriteJson(stream, 200, "OK", acceptBody);
            return;
        }

        HttpWire.WriteResponse(
            stream,
            202,
            "Accepted",
            "application/json",
            Encoding.UTF8.GetBytes("{\"status\":\"InProgress\"}"),
            ("Operation-Location", $"{baseUrl}operations/{operationId}"));
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Rust <c>path_without_query</c>.</summary>
    internal static string PathWithoutQuery(string path)
    {
        int q = path.IndexOf('?');
        return q >= 0 ? path[..q] : path;
    }

    /// <summary>Rust <c>query_param</c> (no percent-decoding).</summary>
    internal static string? QueryParam(string path, string name)
    {
        int q = path.IndexOf('?');
        if (q < 0)
        {
            return null;
        }

        foreach (var pair in path[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=');
            var (key, value) = eq >= 0 ? (pair[..eq], pair[(eq + 1)..]) : (pair, string.Empty);
            if (key == name)
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>Rust <c>has_bearer_token</c>.</summary>
    internal static bool HasBearerToken(HttpRequest request)
    {
        var h = request.Header("authorization");
        if (h is null)
        {
            return false;
        }

        var trimmed = h.Trim();
        return trimmed.StartsWith("Bearer ", StringComparison.Ordinal) && trimmed["Bearer ".Length..].Trim().Length != 0;
    }

    /// <summary>Rust <c>parse_artifact_sign_path</c>.</summary>
    internal static (string Account, string Profile)? ParseArtifactSignPath(string path)
    {
        var segments = path.Trim('/').Split('/');
        if (segments.Length != 4 || segments[0] != "codesigningaccounts" || segments[2] != "certificateprofiles")
        {
            return null;
        }

        return segments[3].EndsWith(":sign", StringComparison.Ordinal)
            ? (segments[1], segments[3][..^":sign".Length])
            : null;
    }

    /// <summary>Rust <c>parse_artifact_poll_path</c>.</summary>
    internal static string? ParseArtifactPollPath(string path)
    {
        var segments = path.Trim('/').Split('/');
        if (segments.Length != 6 || segments[0] != "codesigningaccounts" || segments[2] != "certificateprofiles" || segments[4] != "sign")
        {
            return null;
        }

        return segments[5];
    }
}
