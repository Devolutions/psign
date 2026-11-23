namespace Devolutions.Psign.Server;

/// <summary>clap 4 help output of the Rust <c>psign-server</c> (captured verbatim; <c>{bin}</c> is the binary name).</summary>
internal static class HelpTexts
{
    public const string Top =
        "Local psign test services\n" +
        "\n" +
        "Usage: {bin} <COMMAND>\n" +
        "\n" +
        "Commands:\n" +
        "  timestamp-server         Serve a local RFC 3161 timestamp authority for deterministic tests\n" +
        "  pki-server               Serve local code-signing PKI material for online certificate feature tests\n" +
        "  azure-key-vault-server   Serve a local Azure Key Vault-compatible signing endpoint for tests\n" +
        "  artifact-signing-server  Serve a local Azure Code Signing / Trusted Signing data-plane endpoint for tests\n" +
        "  help                     Print this message or the help of the given subcommand(s)\n" +
        "\n" +
        "Options:\n" +
        "  -h, --help     Print help\n" +
        "  -V, --version  Print version\n";

    public const string TimestampLong =
        "Serve a local RFC 3161 timestamp authority for deterministic tests\n" +
        "\n" +
        "Usage: {bin} timestamp-server [OPTIONS]\n" +
        "\n" +
        "Options:\n" +
        "      --listen <LISTEN>\n" +
        "          Address to bind, for example 127.0.0.1:0 for an ephemeral port\n" +
        "          \n" +
        "          [default: 127.0.0.1:0]\n" +
        "\n" +
        "      --status <STATUS>\n" +
        "          RFC 3161 PKIStatus to return\n" +
        "          \n" +
        "          [default: granted]\n" +
        "          [possible values: granted, rejection, waiting]\n" +
        "\n" +
        "      --response-mode <RESPONSE_MODE>\n" +
        "          Deterministic response variant for negative-path tests\n" +
        "\n" +
        "          Possible values:\n" +
        "          - valid:              Return a normal RFC 3161 response for the selected PKIStatus\n" +
        "          - bad-alg:            Return rejection + PKIFailureInfo badAlg\n" +
        "          - http-error:         Return HTTP 500 instead of a TimeStampResp body\n" +
        "          - malformed-der:      Return malformed DER with HTTP 200\n" +
        "          - mismatched-imprint: Return a granted token whose TSTInfo messageImprint differs from the request\n" +
        "          - invalid-signature:  Return a granted token with one byte flipped after signing\n" +
        "          \n" +
        "          [default: valid]\n" +
        "\n" +
        "      --gen-time <GEN_TIME>\n" +
        "          Deterministic GeneralizedTime value for TSTInfo.genTime\n" +
        "          \n" +
        "          [default: 20240102030405Z]\n" +
        "\n" +
        "      --cert-output <PATH>\n" +
        "          Write the generated TSA root certificate as DER for local trust-store setup\n" +
        "\n" +
        "      --tsa-cert-output <PATH>\n" +
        "          Write the generated TSA leaf certificate as DER for local trust-store setup\n" +
        "\n" +
        "      --max-requests <MAX_REQUESTS>\n" +
        "          Exit after serving this many requests. Zero means run until interrupted\n" +
        "          \n" +
        "          [default: 0]\n" +
        "\n" +
        "  -h, --help\n" +
        "          Print help (see a summary with '-h')\n";

    public const string TimestampShort =
        "Serve a local RFC 3161 timestamp authority for deterministic tests\n" +
        "\n" +
        "Usage: {bin} timestamp-server [OPTIONS]\n" +
        "\n" +
        "Options:\n" +
        "      --listen <LISTEN>                Address to bind, for example 127.0.0.1:0 for an ephemeral port [default: 127.0.0.1:0]\n" +
        "      --status <STATUS>                RFC 3161 PKIStatus to return [default: granted] [possible values: granted, rejection, waiting]\n" +
        "      --response-mode <RESPONSE_MODE>  Deterministic response variant for negative-path tests [default: valid] [possible values: valid, bad-alg, http-error, malformed-der, mismatched-imprint, invalid-signature]\n" +
        "      --gen-time <GEN_TIME>            Deterministic GeneralizedTime value for TSTInfo.genTime [default: 20240102030405Z]\n" +
        "      --cert-output <PATH>             Write the generated TSA root certificate as DER for local trust-store setup\n" +
        "      --tsa-cert-output <PATH>         Write the generated TSA leaf certificate as DER for local trust-store setup\n" +
        "      --max-requests <MAX_REQUESTS>    Exit after serving this many requests. Zero means run until interrupted [default: 0]\n" +
        "  -h, --help                           Print help (see more with '--help')\n";

    public const string Pki =
        "Serve local code-signing PKI material for online certificate feature tests\n" +
        "\n" +
        "Usage: {bin} pki-server [OPTIONS]\n" +
        "\n" +
        "Options:\n" +
        "      --listen <LISTEN>              Address to bind, for example 127.0.0.1:0 for an ephemeral port [default: 127.0.0.1:0]\n" +
        "      --root-cert-output <PATH>      Write the generated root certificate as DER for local trust-anchor setup\n" +
        "      --leaf-cert-output <PATH>      Write the generated code-signing leaf certificate as DER\n" +
        "      --leaf-key-output <PATH>       Write the generated code-signing leaf private key as unencrypted PKCS#8 DER\n" +
        "      --crl-revoke-leaf              Include the generated code-signing leaf serial in the served CRL\n" +
        "      --ocsp-status <OCSP_STATUS>    OCSP certificate status to return for the generated code-signing leaf [default: good] [possible values: good, revoked, unknown]\n" +
        "      --max-requests <MAX_REQUESTS>  Exit after serving this many requests. Zero means run until interrupted [default: 0]\n" +
        "  -h, --help                         Print help\n";

    public const string KeyVault =
        "Serve a local Azure Key Vault-compatible signing endpoint for tests\n" +
        "\n" +
        "Usage: {bin} azure-key-vault-server [OPTIONS]\n" +
        "\n" +
        "Options:\n" +
        "      --listen <LISTEN>\n" +
        "          Address to bind, for example 127.0.0.1:0 for an ephemeral port [default: 127.0.0.1:0]\n" +
        "      --certificate-name <CERTIFICATE_NAME>\n" +
        "          Certificate name accepted under /certificates/{name} [default: psign-test-cert]\n" +
        "      --key-name <KEY_NAME>\n" +
        "          Key name embedded in the returned certificate kid [default: psign-test-key]\n" +
        "      --version <VERSION>\n" +
        "          Key/certificate version accepted in versioned URLs [default: v1]\n" +
        "      --root-cert-output <PATH>\n" +
        "          Write the generated root certificate as DER for local trust-anchor setup\n" +
        "      --leaf-cert-output <PATH>\n" +
        "          Write the generated code-signing leaf certificate as DER\n" +
        "      --max-requests <MAX_REQUESTS>\n" +
        "          Exit after serving this many requests. Zero means run until interrupted [default: 0]\n" +
        "  -h, --help\n" +
        "          Print help\n";

    public const string ArtifactLong =
        "Serve a local Azure Code Signing / Trusted Signing data-plane endpoint for tests\n" +
        "\n" +
        "Usage: {bin} artifact-signing-server [OPTIONS]\n" +
        "\n" +
        "Options:\n" +
        "      --listen <LISTEN>\n" +
        "          Address to bind, for example 127.0.0.1:0 for an ephemeral port\n" +
        "          \n" +
        "          [default: 127.0.0.1:0]\n" +
        "\n" +
        "      --response-mode <RESPONSE_MODE>\n" +
        "          Deterministic response variant for positive and negative-path tests\n" +
        "\n" +
        "          Possible values:\n" +
        "          - valid:               Return a normal accepted operation followed by a Succeeded poll body\n" +
        "          - sync-success:        Return HTTP 200 with a Succeeded body from the submit request\n" +
        "          - body-id:             Return HTTP 200 with an id field, then require polling through the id fallback URL\n" +
        "          - body-operation-id:   Return HTTP 200 with an operationId field, then require polling through the id fallback URL\n" +
        "          - pem-chain:           Return a normal success whose signingCertificate field is a PEM leaf+root bundle\n" +
        "          - http-error:          Return HTTP 500 for the submit request\n" +
        "          - poll-http-error:     Return HTTP 503 for the poll request\n" +
        "          - failed:              Return an accepted operation whose poll body is Failed\n" +
        "          - canceled:            Return an accepted operation whose poll body is Canceled\n" +
        "          - malformed-json:      Return HTTP 200 with malformed JSON for the submit request\n" +
        "          - poll-malformed-json: Return HTTP 200 with malformed JSON for the poll request\n" +
        "          \n" +
        "          [default: valid]\n" +
        "\n" +
        "      --expect-signature-algorithm <EXPECT_SIGNATURE_ALGORITHM>\n" +
        "          Require this signatureAlgorithm value in Artifact Signing submit JSON\n" +
        "\n" +
        "      --expect-api-version <EXPECT_API_VERSION>\n" +
        "          Require this api-version query value on Artifact Signing submit requests\n" +
        "\n" +
        "      --expect-correlation-id <EXPECT_CORRELATION_ID>\n" +
        "          Require this correlation ID in both Artifact Signing correlation headers\n" +
        "\n" +
        "      --root-cert-output <PATH>\n" +
        "          Write the generated root certificate as DER for local trust-anchor setup\n" +
        "\n" +
        "      --leaf-cert-output <PATH>\n" +
        "          Write the generated code-signing leaf certificate as DER\n" +
        "\n" +
        "      --max-requests <MAX_REQUESTS>\n" +
        "          Exit after serving this many requests. Zero means run until interrupted\n" +
        "          \n" +
        "          [default: 0]\n" +
        "\n" +
        "  -h, --help\n" +
        "          Print help (see a summary with '-h')\n";

    public const string ArtifactShort =
        "Serve a local Azure Code Signing / Trusted Signing data-plane endpoint for tests\n" +
        "\n" +
        "Usage: {bin} artifact-signing-server [OPTIONS]\n" +
        "\n" +
        "Options:\n" +
        "      --listen <LISTEN>\n" +
        "          Address to bind, for example 127.0.0.1:0 for an ephemeral port [default: 127.0.0.1:0]\n" +
        "      --response-mode <RESPONSE_MODE>\n" +
        "          Deterministic response variant for positive and negative-path tests [default: valid] [possible values: valid, sync-success, body-id, body-operation-id, pem-chain, http-error, poll-http-error, failed, canceled, malformed-json, poll-malformed-json]\n" +
        "      --expect-signature-algorithm <EXPECT_SIGNATURE_ALGORITHM>\n" +
        "          Require this signatureAlgorithm value in Artifact Signing submit JSON\n" +
        "      --expect-api-version <EXPECT_API_VERSION>\n" +
        "          Require this api-version query value on Artifact Signing submit requests\n" +
        "      --expect-correlation-id <EXPECT_CORRELATION_ID>\n" +
        "          Require this correlation ID in both Artifact Signing correlation headers\n" +
        "      --root-cert-output <PATH>\n" +
        "          Write the generated root certificate as DER for local trust-anchor setup\n" +
        "      --leaf-cert-output <PATH>\n" +
        "          Write the generated code-signing leaf certificate as DER\n" +
        "      --max-requests <MAX_REQUESTS>\n" +
        "          Exit after serving this many requests. Zero means run until interrupted [default: 0]\n" +
        "  -h, --help\n" +
        "          Print help (see more with '--help')\n";

    public const string HelpHelp =
        "Print this message or the help of the given subcommand(s)\n" +
        "\n" +
        "Usage: {bin} help [COMMAND]...\n" +
        "\n" +
        "Arguments:\n" +
        "  [COMMAND]...  Print help for the subcommand(s)\n";
}
