using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core.X509;
using Xunit;

namespace Devolutions.Psign.Tests.Server;

/// <summary>Rust vs managed <c>azure-key-vault-server</c> and <c>artifact-signing-server</c> over loopback.</summary>
public sealed class AzureServerParityTests
{
    private const string Bearer = "Bearer test-token";

    private static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record Run(List<string> Lines, List<byte[]> Responses, byte[] Root, byte[] Leaf, string Stderr, ServerProcess Server);

    private static List<Run> RunBoth(string subcommand, int startupLines, string[] args, Func<ServerProcess, byte[][]> requests)
    {
        var rust = RustBinaries.RequireServer();
        using var dir = new TempDir();
        var runs = new List<Run>();
        foreach (var (exe, tag) in new[] { (rust, "rs"), (RustBinaries.ManagedServer, "cs") })
        {
            string root = dir.File($"{tag}-root.der"), leaf = dir.File($"{tag}-leaf.der");
            var probe = requests(null!);
            using var server = ServerProcess.Start(
                exe,
                startupLines,
                [subcommand, "--max-requests", probe.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), "--root-cert-output", root, "--leaf-cert-output", leaf, .. args]);
            var responses = new List<byte[]>();
            foreach (var r in requests(server))
            {
                responses.Add(RawHttp.Exchange(server.Port, r));
            }

            var (code, err) = server.WaitForExit();
            Assert.Equal(0, code);
            runs.Add(new Run(server.Lines.Select(l => RawHttp.NormalizePort(l, server)).ToList(), responses, File.ReadAllBytes(root), File.ReadAllBytes(leaf), RawHttp.NormalizePort(err, server), server));
        }

        return runs;
    }

    /// <summary>Compare one response pair: identical heads and bodies after port normalization, except base64 DER / signatures.</summary>
    private static void AssertResponsesMatch(Run rs, Run cs, int i, Func<JsonNode, JsonNode, bool>? jsonFieldsCompared = null)
    {
        var (rh, rb) = RawHttp.Split(rs.Responses[i]);
        var (ch, cb) = RawHttp.Split(cs.Responses[i]);
        string rBody = RawHttp.NormalizePort(Encoding.UTF8.GetString(rb), rs.Server);
        string cBody = RawHttp.NormalizePort(Encoding.UTF8.GetString(cb), cs.Server);
        if (rBody == cBody && rb.Length == cb.Length)
        {
            Assert.Equal(RawHttp.NormalizePort(rh, rs.Server), RawHttp.NormalizePort(ch, cs.Server));
            return;
        }

        // Bodies embedding generated certificates or signatures: same JSON shape (key order included).
        Assert.Equal(StripLength(RawHttp.NormalizePort(rh, rs.Server)), StripLength(RawHttp.NormalizePort(ch, cs.Server)));
        Assert.Equal(Mask(rBody), Mask(cBody));
    }

    private static string StripLength(string head) =>
        System.Text.RegularExpressions.Regex.Replace(head, "Content-Length: \\d+", "Content-Length: N");

    /// <summary>Mask long base64 payloads (certificates, signatures) while keeping everything else.</summary>
    private static string Mask(string json) =>
        System.Text.RegularExpressions.Regex.Replace(json, "\"[A-Za-z0-9+/_=-]{120,}\"", m => $"\"<b64:{m.Length > 400}>\"");

    [SkippableFact]
    public void KeyVaultServerMatchesRust()
    {
        var digest = SHA256.HashData("psign"u8);
        byte[][] Requests(ServerProcess s) =>
        [
            RawHttp.Request("GET", "/certificates/psign-test-cert"),
            RawHttp.Request("GET", "/certificates/psign-test-cert", null, ("Authorization", Bearer)),
            RawHttp.Request("GET", "/certificates/psign-test-cert/v1?api-version=7.4", null, ("authorization", "  Bearer   tok  ")),
            RawHttp.Request("GET", "/certificates/psign-test-cert/v2", null, ("Authorization", Bearer)),
            RawHttp.Request("GET", "/certificates/other", null, ("Authorization", "Bearer ")),
            RawHttp.Request("GET", "/certificates/other", null, ("Authorization", "bearer x")),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign?api-version=7.4", $"{{\"alg\":\"RS256\",\"value\":\"{B64Url(digest)}\"}}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", $"{{\"alg\":\" RS384 \",\"value\":\" {B64Url(SHA384.HashData("x"u8))} \"}}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", $"{{\"alg\":\"RS512\",\"value\":\"{B64Url(SHA512.HashData("x"u8))}\",\"alg\":\"RS512\"}}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"RS256\",\"value\":\"AAAA\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"ES256\",\"value\":\"AAAA\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"RS256\",\"value\":\"AA==\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"RS256\",\"value\":\"A*\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"RS256\",\"value\":\"AB\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"RS256\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"value\":\"AAAA\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "[1,2]", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{alg:1}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"RS256\",\n \"value\": tru}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":1e999}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"alg\":\"\\ud800x\"}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"a\":[1,]}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{\"a\":01}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "{} x", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v1/sign", "", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/keys/psign-test-key/versions/v2/sign", "{}", ("Authorization", Bearer)),
            RawHttp.Request("DELETE", "/certificates/psign-test-cert", null, ("Authorization", Bearer)),
        ];

        var runs = RunBoth("azure-key-vault-server", 3, [], Requests);
        var (rs, cs) = (runs[0], runs[1]);
        Assert.Equal(rs.Lines, cs.Lines);
        Assert.Equal(
            new[]
            {
                "psign-server azure-key-vault-server listening on http://127.0.0.1:PORT/",
                "psign-server azure-key-vault-server certificate psign-test-cert",
                "psign-server azure-key-vault-server leaf http://127.0.0.1:PORT/certificates/psign-test-cert",
            },
            cs.Lines);
        Assert.Equal(rs.Stderr, cs.Stderr);
        Assert.True(cs.Stderr.Contains("request failed: Key Vault sign JSON: key must be a string at line 1 column 2\n", StringComparison.Ordinal), cs.Stderr);
        Assert.True(cs.Stderr.Contains("request failed: Key Vault sign JSON: expected ident at line 2 column 14\n", StringComparison.Ordinal), cs.Stderr);
        Assert.True(cs.Stderr.Contains("request failed: decode Key Vault sign digest: Invalid padding\n", StringComparison.Ordinal), cs.Stderr);
        Assert.True(cs.Stderr.Contains("request failed: RS256 requires a 32-byte SHA-256 digest\n", StringComparison.Ordinal), cs.Stderr);
        DerShape.AssertSame(rs.Root, cs.Root, "Key Vault root");
        DerShape.AssertSame(rs.Leaf, cs.Leaf, "Key Vault leaf");
        for (int i = 0; i < rs.Responses.Count; i++)
        {
            AssertResponsesMatch(rs, cs, i);
        }

        // Certificate response carries the leaf, and the sign response verifies with it.
        var certJson = JsonNode.Parse(RawHttp.Split(cs.Responses[1]).Body)!;
        Assert.Equal(cs.Leaf, Convert.FromBase64String(certJson["cer"]!.GetValue<string>()));
        var signJson = JsonNode.Parse(RawHttp.Split(cs.Responses[6]).Body)!;
        var sig = Convert.FromBase64String(Pad(signJson["value"]!.GetValue<string>().Replace('-', '+').Replace('_', '/')));
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(CertificateInfo.Parse(cs.Leaf).SubjectPublicKeyInfo, out _);
        Assert.True(rsa.VerifyHash(digest, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    private static string Pad(string s) => s + new string('=', (4 - (s.Length % 4)) % 4);

    public static TheoryData<string[]> ArtifactModes() => new()
    {
        new[] { "--response-mode", "valid" },
        new[] { "--response-mode", "sync-success" },
        new[] { "--response-mode", "body-id" },
        new[] { "--response-mode", "body-operation-id" },
        new[] { "--response-mode", "pem-chain" },
        new[] { "--response-mode", "http-error" },
        new[] { "--response-mode", "poll-http-error" },
        new[] { "--response-mode", "failed" },
        new[] { "--response-mode", "canceled" },
        new[] { "--response-mode", "malformed-json" },
        new[] { "--response-mode", "poll-malformed-json" },
        new[] { "--expect-signature-algorithm", " RS256 ", "--expect-api-version", "2023-06-15-preview", "--expect-correlation-id", " corr-1 " },
    };

    [SkippableTheory]
    [MemberData(nameof(ArtifactModes))]
    public void ArtifactSigningServerMatchesRust(string[] args)
    {
        var digest = SHA256.HashData("artifact"u8);
        string submit(string alg, string d) => $"{{\"signatureAlgorithm\":\"{alg}\",\"digest\":\"{d}\"}}";
        const string signPath = "/codesigningaccounts/acct/certificateprofiles/prof:sign?api-version=2023-06-15-preview";
        byte[][] Requests(ServerProcess s) =>
        [
            RawHttp.Request("GET", "/metadata/identity/oauth2/token?resource=x"),
            RawHttp.Request("POST", "/tenant/oauth2/v2.0/token", "grant_type=client_credentials"u8.ToArray()),
            RawHttp.Request("GET", "/operations/op-1"),
            RawHttp.JsonRequest("POST", signPath, submit("RS256", Convert.ToBase64String(digest)), ("Authorization", Bearer), ("x-correlation-id", "corr-1"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.Request("GET", "/operations/op-1", null, ("Authorization", Bearer)),
            RawHttp.Request("GET", "/codesigningaccounts/acct/certificateprofiles/prof/sign/op-1?api-version=x", null, ("Authorization", Bearer)),
            RawHttp.Request("GET", "/operations/op-404", null, ("Authorization", Bearer)),
            RawHttp.Request("GET", "/codesigningaccounts/acct/certificateprofiles/prof/sign/op-404", null, ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "/codesigningaccounts/acct/certificateprofiles/prof:sign", submit("RS384", Convert.ToBase64String(SHA384.HashData("x"u8))), ("Authorization", Bearer), ("X-Correlation-Id", "corr-2"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.JsonRequest("POST", signPath, submit("RS512", Convert.ToBase64String(SHA512.HashData("x"u8))), ("Authorization", Bearer), ("x-correlation-id", "corr-1"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.JsonRequest("POST", signPath, submit("RS256", "AAAA"), ("Authorization", Bearer), ("x-correlation-id", "corr-1"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.JsonRequest("POST", signPath, submit("RS256", "AAA"), ("Authorization", Bearer), ("x-correlation-id", "corr-1"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.JsonRequest("POST", signPath, "{\"digest\":\"AAAA\"}", ("Authorization", Bearer), ("x-correlation-id", "corr-1"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.JsonRequest("POST", signPath, "{\"signatureAlgorithm\":\"RS256\"}", ("Authorization", Bearer), ("x-correlation-id", "corr-1"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.JsonRequest("POST", signPath, "{\"signatureAlgorithm\":\"RS256\",", ("Authorization", Bearer), ("x-correlation-id", "corr-1"), ("x-ms-correlation-id", "corr-1")),
            RawHttp.JsonRequest("POST", "/codesigningaccounts/acct/certificateprofiles/prof", "{}", ("Authorization", Bearer)),
            RawHttp.JsonRequest("POST", "//codesigningaccounts/acct/certificateprofiles/p2:sign//", submit("PS256", "AAAA"), ("Authorization", Bearer)),
            RawHttp.Request("PATCH", signPath, null, ("Authorization", Bearer)),
            RawHttp.Request("GET", "/", null, ("Authorization", Bearer)),
            RawHttp.Request("GET", "/operations/op-2", null, ("Authorization", Bearer)),
        ];

        var runs = RunBoth("artifact-signing-server", 2, args, Requests);
        var (rs, cs) = (runs[0], runs[1]);
        Assert.Equal(rs.Lines, cs.Lines);
        Assert.Equal("psign-server artifact-signing-server endpoint http://127.0.0.1:PORT/", cs.Lines[1]);
        Assert.Equal(rs.Stderr, cs.Stderr);
        if (args is ["--response-mode", "valid"])
        {
            Assert.True(cs.Stderr.Contains("request failed: Artifact Signing submit JSON: EOF while parsing a value at line 1 column 30\n", StringComparison.Ordinal), cs.Stderr);
            Assert.True(cs.Stderr.Contains("request failed: Artifact Signing submit body missing signatureAlgorithm\n", StringComparison.Ordinal), cs.Stderr);
            Assert.True(cs.Stderr.Contains("request failed: decode Artifact Signing digest: Invalid padding\n", StringComparison.Ordinal), cs.Stderr);
        }

        DerShape.AssertSame(rs.Root, cs.Root, "Artifact Signing root");
        DerShape.AssertSame(rs.Leaf, cs.Leaf, "Artifact Signing leaf");
        for (int i = 0; i < rs.Responses.Count; i++)
        {
            AssertResponsesMatch(rs, cs, i);
        }
    }
}
