using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Tests.Server;
using Xunit;

namespace Devolutions.Psign.Tests.DepGraph;

/// <summary>Rust <c>psign-depgraph</c> vs managed <c>psign-depgraph</c>: stdout / stderr / exit code and both JSON files.</summary>
public sealed class DepGraphParityTests
{
    private static readonly string[] OutputFiles = ["binary-manifest.json", "dependency-graph.json"];

    /// <summary>Run both tools in fresh working directories (prepared by <paramref name="prepare"/>) and compare everything.</summary>
    private static void AssertSame(string[] args, Action<string>? prepare = null)
    {
        var rust = RustBinaries.RequireDepGraph();
        using var dir = new TempDir();
        var results = new List<(int Code, string Stdout, string Stderr, Dictionary<string, byte[]?> Files)>();
        // Same working directory for both runs (recreated in between) so absolute paths in the outputs coincide.
        var cwd = Path.Combine(dir.DirPath, "work");
        foreach (var exe in new[] { rust, RustBinaries.ManagedDepGraph })
        {
            if (Directory.Exists(cwd))
            {
                Directory.Delete(cwd, recursive: true);
            }

            Directory.CreateDirectory(cwd);
            prepare?.Invoke(cwd);
            var (code, stdout, stderr) = RustBinaries.Run(exe, args, cwd);
            var files = OutputFiles.ToDictionary(f => f, f =>
            {
                var p = Path.Combine(cwd, "parity-output", f);
                return File.Exists(p) ? File.ReadAllBytes(p) : null;
            });
            results.Add((code, stdout, stderr, files));
        }

        var (rs, cs) = (results[0], results[1]);
        Assert.Equal(rs.Stderr, cs.Stderr);
        Assert.Equal(rs.Stdout, cs.Stdout);
        Assert.Equal(rs.Code, cs.Code);
        foreach (var f in OutputFiles)
        {
            Assert.Equal(rs.Files[f] is null, cs.Files[f] is null);
            if (rs.Files[f] is { } expected)
            {
                Assert.Equal(System.Text.Encoding.UTF8.GetString(expected), System.Text.Encoding.UTF8.GetString(cs.Files[f]!));
                Assert.Equal(expected, cs.Files[f]);
            }
        }
    }

    [SkippableFact]
    public void DefaultSigntoolMatches() => AssertSame([]);

    [SkippableFact]
    public void IgnoredFirstArgumentFallsBackToDefault() => AssertSame(["--other", "x"]);

    [SkippableFact]
    public void MissingSigntoolValueMatches() => AssertSame(["--signtool"]);

    [SkippableFact]
    public void MissingFileMatches() => AssertSame(["--signtool", Path.Combine(Path.GetTempPath(), "psign-no-such-dir", "signtool.exe")]);

    [SkippableFact]
    public void MissingFileInExistingDirectoryMatches() => AssertSame(["--signtool", Path.Combine(Path.GetTempPath(), "psign-no-such-signtool.exe")]);

    [SkippableFact]
    public void RustServerBinaryGraphMatches() => AssertSame(["--signtool", RustBinaries.RequireServer()]);

    [SkippableFact]
    public void ManagedApphostGraphMatches() => AssertSame(["--signtool", RustBinaries.ManagedDepGraph]);

    public static TheoryData<string> PeFixtures() => new()
    {
        "generated-unsigned/pe/tiny32-pe-alias.exe",
        "generated-unsigned/pe/tiny64-pe-alias.dll",
        "generated-signed/pe/tiny64-pe-alias.exe",
        "generated-signed/winmd/tiny32-pe-copy.winmd",
    };

    [SkippableTheory]
    [MemberData(nameof(PeFixtures))]
    public void FixtureGraphMatches(string fixture) => AssertSame(["--signtool", Fixtures.Path(fixture)]);

    [SkippableFact]
    public void RelativeRootAndSiblingImportsMatch()
    {
        // Copy a real PE next to a copy of one of its imported DLLs so that sibling resolution (the canonical \\?\ parent)
        // wins over System32 / PATH, and pass the root as a path relative to the working directory.
        // On Windows the Rust psign-server binary imports real system DLLs; elsewhere use a PE fixture and stand in a
        // copy of it for the sibling DLL. Unix file names are case-sensitive, so keep the root's casing there.
        var source = OperatingSystem.IsWindows() ? RustBinaries.RequireServer() : Fixtures.Path("generated-signed/pe/tiny64-pe-alias.exe");
        RustBinaries.RequireDepGraph();
        var imports = PeFile.Parse(File.ReadAllBytes(source)).ImportedLibraries();
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var sibling = imports.FirstOrDefault(i => File.Exists(Path.Combine(system32, i))) ?? imports.FirstOrDefault();
        var rootName = OperatingSystem.IsWindows() ? "Root.EXE" : "root.exe";
        AssertSame(["--signtool", Path.Combine("bin", rootName)], cwd =>
        {
            var bin = Directory.CreateDirectory(Path.Combine(cwd, "bin")).FullName;
            File.Copy(source, Path.Combine(bin, "root.exe"));
            if (sibling is not null)
            {
                var systemCopy = Path.Combine(system32, sibling);
                File.Copy(File.Exists(systemCopy) ? systemCopy : source, Path.Combine(bin, OperatingSystem.IsWindows() ? sibling.ToUpperInvariant() : sibling.ToLowerInvariant()));
            }
        });
    }

    [SkippableFact]
    public void NonPeRootMatches() =>
        AssertSame(["--signtool", "notes.txt"], cwd => File.WriteAllText(Path.Combine(cwd, "notes.txt"), "this is not a portable executable at all\n"));

    [SkippableFact]
    public void DirectoryRootMatches() =>
        AssertSame(["--signtool", "folder"], cwd => Directory.CreateDirectory(Path.Combine(cwd, "folder")));

    [Fact]
    public void ImportedLibrariesOfFixtures()
    {
        Assert.DoesNotContain(PeFile.Parse(Fixtures.Bytes("generated-unsigned/pe/tiny32-pe-alias.exe")).ImportedLibraries(), string.IsNullOrEmpty);
        // The managed assembly itself is a PE on every OS (IL image importing mscoree.dll).
        var managedDll = Path.Combine(AppContext.BaseDirectory, "psign-depgraph.dll");
        var libs = PeFile.Parse(File.ReadAllBytes(managedDll)).ImportedLibraries();
        Assert.Equal(["mscoree.dll"], libs.Select(l => l.ToLowerInvariant()));
        if (OperatingSystem.IsWindows())
        {
            var apphost = PeFile.Parse(File.ReadAllBytes(RustBinaries.ManagedDepGraph)).ImportedLibraries();
            Assert.Equal(apphost.OrderBy(l => l, StringComparer.Ordinal), apphost);
            Assert.Equal(apphost.Distinct(), apphost);
            Assert.Contains(apphost, l => l.Equals("KERNEL32.dll", StringComparison.OrdinalIgnoreCase));
        }
    }
}
