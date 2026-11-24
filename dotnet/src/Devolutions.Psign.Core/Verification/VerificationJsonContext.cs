using System.Text.Json.Serialization;
using Devolutions.Psign.Verification.AuthRoot;

namespace Devolutions.Psign.Verification;

/// <summary>
/// Source-generated System.Text.Json contracts for the verification report models and the AuthRoot cache metadata, so
/// serialization needs no reflection (trimming / NativeAOT safe). Use with
/// <see cref="Core.Json.RustJson.ToStringPretty{T}(T, System.Text.Json.Serialization.Metadata.JsonTypeInfo{T})"/>.
/// </summary>
[JsonSerializable(typeof(InspectPkcs7Report))]
[JsonSerializable(typeof(InspectPeFileReport))]
[JsonSerializable(typeof(ArtifactSigningIdentity))]
[JsonSerializable(typeof(List<ArtifactSigningSignerIdentity>))]
[JsonSerializable(typeof(AuthRootCache.AuthRootMeta))]
internal sealed partial class VerificationJsonContext : JsonSerializerContext
{
}
