using Devolutions.Psign.Core;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.ArtifactSigning;

/// <summary>
/// <see cref="IDigestSigner"/> backed by Azure Artifact Signing <c>:sign</c>. Each call submits the signed-attributes
/// digest and returns the RSA signature; the service-issued signing certificate of the last call is available through
/// <see cref="LastResult"/> (Artifact Signing issues short-lived certificates per request, so the certificate is only
/// known after signing).
/// </summary>
public sealed class ArtifactSigningDigestSigner : IDigestSigner
{
    private readonly ArtifactSigningClient _client;
    private readonly CodesigningSubmitParams _template;
    private readonly string? _signatureAlgorithm;
    private readonly Action<string>? _debug;

    /// <param name="client">REST client.</param>
    /// <param name="template">Submit parameters; <see cref="CodesigningSubmitParams.Digest"/> is replaced per call.</param>
    /// <param name="signatureAlgorithm">
    /// Explicit JWS algorithm; when <c>null</c> it is derived from the digest hash (<c>RS256</c> / <c>RS384</c> / <c>RS512</c>).
    /// </param>
    /// <param name="debug">Optional debug sink (poll URL).</param>
    public ArtifactSigningDigestSigner(ArtifactSigningClient client, CodesigningSubmitParams template, string? signatureAlgorithm = null, Action<string>? debug = null)
    {
        _client = client;
        _template = template;
        _signatureAlgorithm = signatureAlgorithm;
        _debug = debug;
    }

    /// <summary>Result of the most recent <see cref="SignDigest"/> call.</summary>
    public CodesigningSignatureResult? LastResult { get; private set; }

    public byte[] SignDigest(byte[] digest, AuthenticodeHashKind hash)
    {
        var alg = _signatureAlgorithm ?? ArtifactSigningClient.SignatureAlgorithmForDigest(hash);
        LastResult = _client.SubmitCodesignHashSignature(_template.WithDigest(digest, alg), _debug);
        return LastResult.Signature;
    }
}
