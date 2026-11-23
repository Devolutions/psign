using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Cli.Portable;
using Devolutions.Psign.Core;

namespace Devolutions.Psign.Cli.TopLevel;

/// <summary>
/// Top-level <c>psign-tool artifact-signing-submit</c> (Rust <c>ArtifactSigningSubmitArgs</c> in <c>src/cli.rs</c>). The
/// managed tool only has the portable backend, where Rust <c>execute_portable</c> points callers at
/// <c>psign-tool portable artifact-signing-submit</c>.
/// </summary>
internal static class ArtifactSigningSubmitCommand
{
    public static void Register(CommandSpec root)
    {
        root.Sub("artifact-signing-submit", "Submit a digest to Azure Code Signing data-plane REST (`:sign` LRO). Prints signature + operation JSON on success.", c =>
        {
            c.Value("region", null, "Regional hostname segment (e.g. `westus`) for `https://{region}.codesigning.azure.net/`.").Req();
            c.Value("account-name").Req();
            c.Value("profile-name").Req();
            c.Value("digest-file", null, "Raw digest bytes file (same length as hash algorithm, e.g. 32 for SHA-256).").Req();
            c.Value("signature-algorithm", null, null, "RS256");
            c.Value("api-version", null, null, "2024-06-15");
            c.Value("correlation-id");
            c.Value("access-token");
            c.Flag("managed-identity");
            c.Value("managed-identity-resource-id");
            c.Choice("credential-type", SigningCommands.CredentialTypeValues);
            c.Value("tenant-id");
            c.Value("client-id");
            c.Value("client-secret");
            c.Value("federated-token-file");
            c.Value("authority");
            c.Value("endpoint-base-url", null, "Override data-plane origin for deterministic local tests.").Hide();
            c.Handler = p =>
            {
                PsignTool.RequirePortableMode(p);
                throw new PsignException("--mode portable artifact-signing-submit is available as `psign-tool portable artifact-signing-submit ...`");
            };
        });
    }
}
