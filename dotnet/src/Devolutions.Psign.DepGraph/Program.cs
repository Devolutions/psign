using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.Pe;

namespace Devolutions.Psign.DepGraph;

/// <summary>
/// Pure C# port of <c>src/bin/depgraph.rs</c> (<c>psign-depgraph</c>): breadth-first walk of PE imports starting from
/// <c>signtool.exe</c>, writing <c>parity-output/binary-manifest.json</c> and <c>parity-output/dependency-graph.json</c>
/// with the same paths, ordering and <c>serde_json</c> pretty formatting as the Rust tool.
/// </summary>
internal static class Program
{
    internal const string DefaultSigntool = @"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe";

    private static int Main(string[] args)
    {
        try
        {
            Run(args, Console.Out);
            return 0;
        }
        catch (Exception e)
        {
            Console.Error.Write(RenderAnyhowDebug(e));
            return 1;
        }
    }

    internal static void Run(string[] args, TextWriter stdout)
    {
        string signtool;
        if (args.Length > 0 && args[0] == "--signtool")
        {
            signtool = args.Length > 1 ? args[1] : throw new PsignException("missing value for --signtool argument");
        }
        else
        {
            signtool = DefaultSigntool;
        }

        string root;
        try
        {
            root = RustFs.Canonicalize(signtool);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"failed to resolve {signtool}", IoErrorText.Inner(e));
        }

        const string outputDir = "parity-output";
        try
        {
            Directory.CreateDirectory(outputDir);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException("failed to create parity-output directory", IoErrorText.Inner(e));
        }

        var queue = new Queue<string>();
        queue.Enqueue(root);
        var visited = new HashSet<string>(StringComparer.Ordinal);
        var nodes = new List<(string Path, string Sha256, List<string> Imports)>();
        var edges = new SortedDictionary<string, List<string>>(RustJson.Utf8Comparer);

        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            if (!visited.Add(current))
            {
                continue;
            }

            var imports = PeImportsOf(current);
            var parent = RustFs.Parent(current) ?? ".";
            var resolvedChildren = new List<string>();
            foreach (var import in imports)
            {
                if (ResolveBinary(import, parent) is { } resolved)
                {
                    resolvedChildren.Add(resolved);
                    if (!visited.Contains(resolved))
                    {
                        queue.Enqueue(resolved);
                    }
                }
            }

            var sha256 = ReadSha256(current);
            nodes.Add((current, sha256, imports));
            edges[current] = resolvedChildren;
        }

        nodes.Sort((a, b) => RustJson.CompareUtf8(a.Path, b.Path));

        var nodeArray = new JsonArray();
        foreach (var n in nodes)
        {
            nodeArray.Add((JsonNode)new JsonObject
            {
                ["path"] = n.Path,
                ["sha256"] = n.Sha256,
                ["imports"] = new JsonArray(n.Imports.Select(i => (JsonNode?)JsonValue.Create(i)).ToArray()),
            });
        }

        var manifest = new JsonObject { ["root"] = root, ["nodes"] = nodeArray };
        var edgeObject = new JsonObject();
        foreach (var (key, children) in edges)
        {
            edgeObject[key] = new JsonArray(children.Select(c => (JsonNode?)JsonValue.Create(c)).ToArray());
        }

        var graph = new JsonObject { ["root"] = root, ["edges"] = edgeObject };

        WriteOutput(Path.Combine(outputDir, "binary-manifest.json"), RustJson.Pretty(manifest), "failed to write binary-manifest.json");
        WriteOutput(Path.Combine(outputDir, "dependency-graph.json"), RustJson.Pretty(graph), "failed to write dependency-graph.json");

        stdout.Write($"wrote {nodes.Count} nodes to parity-output/binary-manifest.json\n");
        stdout.Write("wrote dependency graph to parity-output/dependency-graph.json\n");
        stdout.Flush();
    }

    private static void WriteOutput(string path, string text, string context)
    {
        try
        {
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(text));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException(context, IoErrorText.Inner(e));
        }
    }

    /// <summary>Rust <c>read_sha256</c>: lowercase hex SHA-256 of the file.</summary>
    internal static string ReadSha256(string path)
    {
        FileStream stream;
        try
        {
            stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"failed to open {path}", IoErrorText.Inner(e));
        }

        using (stream)
        {
            try
            {
                return Hex.Lower(SHA256.HashData(stream));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new PsignException($"failed to read {path}", IoErrorText.Inner(e));
            }
        }
    }

    /// <summary>Rust <c>pe_imports</c>: lowercase, sorted, deduplicated imported library names (empty for non-PE objects).</summary>
    internal static List<string> PeImportsOf(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Unix read(2) on a directory fails with EISDIR (Windows reports access denied, as IoErrorText does).
            var inner = !OperatingSystem.IsWindows() && Directory.Exists(path)
                ? new PsignException("Is a directory (os error 21)")
                : IoErrorText.Inner(e);
            throw new PsignException($"failed to read {path}", inner);
        }

        List<string> libraries;
        try
        {
            libraries = GoblinLibraries(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"failed to parse PE {path}", e);
        }

        var imports = libraries.Select(ToAsciiLowercase).ToList();
        imports.Sort(RustJson.CompareUtf8);
        var dedup = new List<string>(imports.Count);
        foreach (var i in imports)
        {
            if (dedup.Count == 0 || dedup[^1] != i)
            {
                dedup.Add(i);
            }
        }

        return dedup;
    }

    /// <summary>goblin <c>Object::parse</c> + <c>pe.libraries</c>; non-PE objects yield no libraries.</summary>
    private static List<string> GoblinLibraries(byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            throw new PsignException("bad offset 0");
        }

        if (bytes.Length < 16)
        {
            throw new PsignException($"type is too big (16) for {bytes.Length}");
        }

        if (bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
        {
            return [];
        }

        PeFile pe;
        try
        {
            pe = PeFile.Parse(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"Malformed entity: {e.Message}");
        }

        return pe.ImportedLibraries();
    }

    private static string ToAsciiLowercase(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            if (chars[i] is >= 'A' and <= 'Z')
            {
                chars[i] = (char)(chars[i] + 32);
            }
        }

        return new string(chars);
    }

    /// <summary>Rust <c>candidate_paths</c>: sibling, <c>C:\Windows\System32</c>, then each <c>PATH</c> segment split on <c>;</c>.</summary>
    internal static List<string> CandidatePaths(string name, string parent)
    {
        var output = new List<string>
        {
            RustFs.Join(parent, name),
            RustFs.Join(@"C:\Windows\System32", name),
        };
        var pathVar = Environment.GetEnvironmentVariable("PATH");
        if (pathVar is not null)
        {
            foreach (var segment in pathVar.Split(';'))
            {
                var seg = segment.Trim();
                if (seg.Length != 0)
                {
                    output.Add(RustFs.Join(seg, name));
                }
            }
        }

        return output;
    }

    private static string? ResolveBinary(string name, string parent) =>
        CandidatePaths(name, parent).FirstOrDefault(RustFs.Exists);

    /// <summary>anyhow's <c>Debug</c> rendering used when <c>main</c> returns an error (<c>Error: ...</c> + causes).</summary>
    internal static string RenderAnyhowDebug(Exception e)
    {
        var parts = new List<string>();
        for (Exception? cur = e; cur is not null; cur = cur.InnerException)
        {
            parts.Add(cur is IOException or UnauthorizedAccessException ? IoErrorText.Message(cur) : cur.Message);
        }

        var sb = new StringBuilder();
        sb.Append("Error: ").Append(parts[0]).Append('\n');
        if (parts.Count == 2)
        {
            sb.Append("\nCaused by:\n    ").Append(parts[1]).Append('\n');
        }
        else if (parts.Count > 2)
        {
            sb.Append("\nCaused by:\n");
            for (int i = 1; i < parts.Count; i++)
            {
                sb.Append("    ").Append(i - 1).Append(": ").Append(parts[i]).Append('\n');
            }
        }

        return sb.ToString();
    }
}
