using System.Collections.ObjectModel;
using System.Management.Automation;

namespace Devolutions.Psign.PowerShell.Utilities;

internal static class PathResolution
{
    internal static IReadOnlyList<string> ResolveFilePaths(PSCmdlet cmdlet, string path, bool literal)
    {
        if (literal)
        {
            return [cmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath(path)];
        }

        Collection<string> resolved = cmdlet.SessionState.Path.GetResolvedProviderPathFromPSPath(
            path,
            out ProviderInfo provider);
        if (!StringComparer.OrdinalIgnoreCase.Equals(provider.Name, "FileSystem"))
        {
            throw new PSInvalidOperationException($"Only FileSystem paths are supported; provider was '{provider.Name}'.");
        }

        return resolved;
    }
}
