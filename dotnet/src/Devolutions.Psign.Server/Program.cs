using Devolutions.Psign.Core;

namespace Devolutions.Psign.Server;

/// <summary>
/// Pure C# port of <c>src/bin/psign-server.rs</c>: local psign test services (<c>timestamp-server</c>,
/// <c>pki-server</c>, <c>azure-key-vault-server</c>, <c>artifact-signing-server</c>).
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        var outcome = Cli.Parse(args);
        if (!outcome.IsCommand)
        {
            if (outcome.Stdout is not null)
            {
                Console.Out.Write(outcome.Stdout);
                Console.Out.Flush();
            }

            if (outcome.Stderr is not null)
            {
                Console.Error.Write(outcome.Stderr);
                Console.Error.Flush();
            }

            return outcome.ExitCode;
        }

        try
        {
            Run(outcome);
            return 0;
        }
        catch (Exception e) when (e is PsignException or IOException or UnauthorizedAccessException or System.Net.Sockets.SocketException)
        {
            Console.Error.Write(PsignException.Render(e) + "\n");
            Console.Error.Flush();
            return 1;
        }
    }

    internal static void Run(CliOutcome parsed)
    {
        var v = parsed.Values;
        string? Get(string name) => v.TryGetValue(name, out var value) ? value : null;
        string Str(string name, string defaultValue) => Get(name) ?? defaultValue;
        ulong MaxRequests() => Get("max-requests") is { } s ? ulong.Parse(s.TrimStart('+'), System.Globalization.CultureInfo.InvariantCulture) : 0;

        switch (parsed.Command)
        {
            case "timestamp-server":
                Servers.RunTimestampServer(new TimestampServerArgs(
                    Str("listen", "127.0.0.1:0"),
                    Enum<ServerStatus>(Str("status", "granted"), Cli.ServerStatusValues),
                    Enum<ResponseMode>(Str("response-mode", "valid"), Cli.ResponseModeValues),
                    Str("gen-time", "20240102030405Z"),
                    Get("cert-output"),
                    Get("tsa-cert-output"),
                    MaxRequests()));
                break;
            case "pki-server":
                Servers.RunPkiServer(new PkiServerArgs(
                    Str("listen", "127.0.0.1:0"),
                    Get("root-cert-output"),
                    Get("leaf-cert-output"),
                    Get("leaf-key-output"),
                    v.ContainsKey("crl-revoke-leaf"),
                    Enum<PkiOcspStatus>(Str("ocsp-status", "good"), Cli.OcspStatusValues),
                    MaxRequests()));
                break;
            case "azure-key-vault-server":
                Servers.RunAzureKeyVaultServer(new AzureKeyVaultServerArgs(
                    Str("listen", "127.0.0.1:0"),
                    Str("certificate-name", "psign-test-cert"),
                    Str("key-name", "psign-test-key"),
                    Str("version", "v1"),
                    Get("root-cert-output"),
                    Get("leaf-cert-output"),
                    MaxRequests()));
                break;
            default:
                Servers.RunArtifactSigningServer(new ArtifactSigningServerArgs(
                    Str("listen", "127.0.0.1:0"),
                    Enum<ArtifactResponseMode>(Str("response-mode", "valid"), Cli.ArtifactResponseModeValues),
                    Get("expect-signature-algorithm"),
                    Get("expect-api-version"),
                    Get("expect-correlation-id"),
                    Get("root-cert-output"),
                    Get("leaf-cert-output"),
                    MaxRequests()));
                break;
        }
    }

    /// <summary>Map a clap kebab-case value to the enum member at the same index.</summary>
    private static T Enum<T>(string value, string[] names)
        where T : struct, System.Enum => System.Enum.GetValues<T>()[Array.IndexOf(names, value)];
}
