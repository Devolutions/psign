using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;

namespace Devolutions.Psign.PowerShell.Utilities;

internal static class ArtifactSigningOptions
{
    /// <summary>
    /// Build the portable-core Artifact Signing options; <c>null</c> when validation is not requested.
    /// Any publisher ID, private trust root, or missing-timestamp opt-in implies validation.
    /// </summary>
    internal static PortableArtifactSigningOptions? Create(
        PSCmdlet cmdlet,
        bool requested,
        string[] publisherIds,
        string[] privateTrustRootPaths,
        bool allowMissingTimestamp)
    {
        if (!requested && publisherIds.Length == 0 && privateTrustRootPaths.Length == 0 && !allowMissingTimestamp)
        {
            return null;
        }

        return new PortableArtifactSigningOptions
        {
            PublisherIds = publisherIds.Select(id => id.Trim()).ToArray(),
            PrivateTrustRootPaths = privateTrustRootPaths
                .Select(p => cmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath(p))
                .ToArray(),
            AllowMissingTimestamp = allowMissingTimestamp,
        };
    }
}
