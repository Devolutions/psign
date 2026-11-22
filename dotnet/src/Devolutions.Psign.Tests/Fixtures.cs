namespace Devolutions.Psign.Tests;

/// <summary>Locates the shared Rust test fixtures under <c>tests/fixtures</c> at the repository root.</summary>
internal static class Fixtures
{
    private static readonly Lazy<string> Root = new(() =>
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = System.IO.Path.Combine(dir.FullName, "tests", "fixtures");
            if (Directory.Exists(candidate) && File.Exists(System.IO.Path.Combine(dir.FullName, "Cargo.toml")))
            {
                return candidate;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("could not locate repository tests/fixtures directory");
    });

    /// <summary>Absolute path to the fixtures root.</summary>
    public static string Dir => Root.Value;

    /// <summary>Absolute path to a fixture relative to <c>tests/fixtures</c>.</summary>
    public static string Path(string relative) => System.IO.Path.Combine(Dir, relative.Replace('/', System.IO.Path.DirectorySeparatorChar));

    /// <summary>Read a fixture's bytes.</summary>
    public static byte[] Bytes(string relative) => File.ReadAllBytes(Path(relative));

    /// <summary>Repository root.</summary>
    public static string RepoRoot => Directory.GetParent(Directory.GetParent(Dir)!.FullName)!.FullName;
}
