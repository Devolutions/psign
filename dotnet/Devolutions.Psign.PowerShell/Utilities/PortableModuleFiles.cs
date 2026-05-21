namespace Devolutions.Psign.PowerShell.Utilities;

internal static class PortableModuleFiles
{
    private static readonly HashSet<string> SignablePowerShellExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1",
        ".psm1",
        ".psd1",
    };

    internal static IReadOnlyList<string> Enumerate(string directory)
    {
        return Directory
            .EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Where(path => SignablePowerShellExtensions.Contains(Path.GetExtension(path)))
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
