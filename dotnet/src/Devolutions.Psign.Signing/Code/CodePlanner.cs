using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Signing.Code;

/// <summary>
/// Builds the inside-out signing graph over files, globs, file lists and nested ZIP/OPC containers (ported from
/// <c>build_code_plan</c>, <c>selection_rules</c>, <c>select_inputs</c>, <c>resolve_rule</c>, <c>walk_files</c> and
/// <c>PlanBuilder</c> in Rust <c>src/code.rs</c>).
/// </summary>
public static class CodePlanner
{
    /// <summary>A selected top-level file: full path plus normal components relative to the base directory.</summary>
    internal sealed record InputPath(string FullPath, IReadOnlyList<string> Relative);

    /// <summary>Rust <c>build_code_plan</c>.</summary>
    public static CodePlan BuildPlan(CodeOptions options)
    {
        if (options.MaxConcurrency == 0)
        {
            throw new PsignException("--max-concurrency must be greater than zero");
        }

        if (options.TimestampUrl is not null && options.TimestampDigest is null)
        {
            throw new PsignException("`psign-tool code` requires --timestamp-digest with --timestamp-url");
        }

        if (options.TimestampUrl is null && options.TimestampDigest is not null)
        {
            throw new PsignException("`psign-tool code` requires --timestamp-url with --timestamp-digest");
        }

        var baseArg = options.BaseDirectory ?? ".";
        string baseDir;
        try
        {
            baseDir = RustPath.Canonicalize(baseArg);
        }
        catch (PsignException e)
        {
            throw new PsignException($"resolve base directory {baseArg}", e);
        }

        if (!Directory.Exists(baseDir))
        {
            throw new PsignException($"base directory is not a directory: {baseDir}");
        }

        var rules = SelectionRules(baseDir, options);
        var selected = SelectInputs(baseDir, rules);
        var builder = new PlanBuilder(rules.Where(r => !r.Include).Select(r => r.Pattern).ToList(), options.Output, selected.Count);
        foreach (var path in selected)
        {
            builder.AddPath(path, options.RecurseContainers);
        }

        return new CodePlan
        {
            BaseDirectory = baseDir,
            Output = options.Output,
            RecurseContainers = options.RecurseContainers,
            MaxConcurrency = options.MaxConcurrency,
            FileDigest = DigestName(options.FileDigest),
            TimestampDigest = options.TimestampDigest is { } td ? DigestName(td) : null,
            TimestampUrl = options.TimestampUrl,
            ContinueOnError = options.ContinueOnError,
            SkipSigned = options.SkipSigned,
            Nodes = builder.Nodes,
            Edges = builder.Edges,
        };
    }

    /// <summary>Rust <c>digest_name</c>.</summary>
    public static string DigestName(CodeDigestAlgorithm digest) => digest switch
    {
        CodeDigestAlgorithm.Sha1 => "sha1",
        CodeDigestAlgorithm.Sha256 => "sha256",
        CodeDigestAlgorithm.Sha384 => "sha384",
        CodeDigestAlgorithm.Sha512 => "sha512",
        _ => "cert-hash",
    };

    /// <summary>Include / exclude rules from positional inputs and the file list (Rust <c>selection_rules</c>).</summary>
    internal static List<CodePatternRule> SelectionRules(string baseDir, CodeOptions options)
    {
        var rules = new List<CodePatternRule>();
        foreach (var input in options.Inputs)
        {
            rules.AddRange(CodePatterns.PatternRules(input));
        }

        if (options.FileList is { } fileList)
        {
            var path = RustPath.IsAbsolute(fileList) ? fileList : RustPath.Join(baseDir, fileList);
            var text = RustIo.ReadToString(path, $"read file list {path}");
            int lineNo = 0;
            foreach (var raw in RustText.Lines(text))
            {
                lineNo++;
                var trimmed = raw.Trim();
                if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                {
                    continue;
                }

                try
                {
                    rules.AddRange(CodePatterns.PatternRules(trimmed));
                }
                catch (PsignException e)
                {
                    throw new PsignException($"parse {path} line {lineNo}", e);
                }
            }
        }

        if (rules.Count == 0)
        {
            throw new PsignException("code dry-run requires at least one input or --file-list entry");
        }

        return rules;
    }

    /// <summary>Exclude patterns applied inside containers (Rust <c>nested_exclude_patterns</c>).</summary>
    internal static List<string> NestedExcludePatterns(string baseDir, CodeOptions options) =>
        SelectionRules(baseDir, options).Where(r => !r.Include).Select(r => r.Pattern).ToList();

    /// <summary>Apply rules in order over a component-ordered set (Rust <c>select_inputs</c> over <c>BTreeSet&lt;PathBuf&gt;</c>).</summary>
    internal static List<InputPath> SelectInputs(string baseDir, List<CodePatternRule> rules)
    {
        var selected = new SortedSet<InputPath>(InputPathComparer.Instance);
        List<InputPath>? walked = null;
        foreach (var rule in rules)
        {
            var matches = ResolveRule(baseDir, rule, ref walked);
            foreach (var m in matches)
            {
                if (rule.Include)
                {
                    selected.Add(m);
                }
                else
                {
                    selected.Remove(m);
                }
            }
        }

        return selected.ToList();
    }

    private static List<InputPath> ResolveRule(string baseDir, CodePatternRule rule, ref List<InputPath>? walked)
    {
        if (CodePatterns.HasGlobMeta(rule.Pattern))
        {
            walked ??= WalkFiles(baseDir);
            return walked.Where(c => CodePatterns.GlobMatch(rule.Pattern, NormalizeMatchPath(c.Relative))).ToList();
        }

        var native = CodePatterns.PatternToNativePath(rule.Pattern);
        var full = RustPath.Join(baseDir, native);
        if (!File.Exists(full))
        {
            return [];
        }

        return [new InputPath(full, RustPath.NormalComponents(native).ToArray())];
    }

    /// <summary>Recursive file listing under <paramref name="root"/>, skipping symlinks (Rust <c>walk_files</c>).</summary>
    internal static List<InputPath> WalkFiles(string root)
    {
        var output = new List<InputPath>();
        var stack = new Stack<(string Dir, string[] Rel)>();
        stack.Push((root, []));
        while (stack.Count > 0)
        {
            var (dir, rel) = stack.Pop();
            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(dir).EnumerateFileSystemInfos().ToList();
            }
            catch (Exception e) when (RustIo.IsIo(e))
            {
                throw new PsignException($"read {dir}", IoErrorText.Inner(e));
            }

            foreach (var entry in entries)
            {
                if (entry.LinkTarget is not null)
                {
                    continue;
                }

                string[] childRel = [.. rel, entry.Name];
                var childPath = RustPath.Join(dir, entry.Name);
                if (entry is DirectoryInfo)
                {
                    stack.Push((childPath, childRel));
                }
                else
                {
                    output.Add(new InputPath(childPath, childRel));
                }
            }
        }

        output.Sort(InputPathComparer.Instance);
        return output;
    }

    /// <summary>Rust <c>normalize_match_path</c>: normal components joined with <c>/</c>.</summary>
    internal static string NormalizeMatchPath(IReadOnlyList<string> relative) => string.Join('/', relative.Select(s => s.Replace('\\', '/')));

    private sealed class InputPathComparer : IComparer<InputPath>
    {
        public static readonly InputPathComparer Instance = new();

        public int Compare(InputPath? x, InputPath? y)
        {
            var a = x!.Relative;
            var b = y!.Relative;
            for (int i = 0; i < Math.Min(a.Count, b.Count); i++)
            {
                int c = Utf8Ordinal.Comparer.Compare(a[i], b[i]);
                if (c != 0)
                {
                    return c;
                }
            }

            return a.Count.CompareTo(b.Count);
        }
    }

    private sealed class PlanBuilder
    {
        private readonly Dictionary<string, int> _nodeIds = new(StringComparer.Ordinal);
        private readonly List<string> _nestedExcludes;
        private readonly string? _output;
        private readonly int _topLevelCount;

        public PlanBuilder(List<string> nestedExcludes, string? output, int topLevelCount)
        {
            _nestedExcludes = nestedExcludes;
            _output = output;
            _topLevelCount = topLevelCount;
        }

        public List<CodePlanNode> Nodes { get; } = [];

        public List<CodePlanEdge> Edges { get; } = [];

        public int AddPath(InputPath path, bool recurseContainers)
        {
            var display = NormalizeMatchPath(path.Relative);
            var outputDisplay = TopLevelOutputPath(display);
            return AddNodeFromReader(path.FullPath, display, outputDisplay, 0, recurseContainers, null);
        }

        private int AddNodeFromReader(string path, string display, string outputDisplay, int depth, bool recurseContainers, byte[]? bytes)
        {
            if (_nodeIds.TryGetValue(display, out var existing))
            {
                return existing;
            }

            byte[]? ownedPrefix = null;
            if (bytes is null && RustPath.IsExtension(path, "app") && File.Exists(path))
            {
                ownedPrefix = ReadPrefix(path, 4);
            }

            var content = bytes ?? ownedPrefix;
            var format = CodeFormats.Detect(path, content, content is not null);
            int id = Nodes.Count;
            _nodeIds[display] = id;
            Nodes.Add(new CodePlanNode(id, display, outputDisplay, format, depth, format.IsContainer(), format.SignerName()));

            if (recurseContainers && format.IsContainer())
            {
                var data = bytes ?? RustIo.Read(path, $"open {path}");
                var nested = InspectZipEntries(data, display, outputDisplay, depth + 1);
                foreach (var entry in nested)
                {
                    int child = AddNodeFromReader(entry.Display, entry.Display, entry.OutputDisplay, entry.Depth, recurseContainers, entry.Bytes);
                    Edges.Add(new CodePlanEdge(child, id));
                }
            }

            return id;
        }

        private static byte[] ReadPrefix(string path, int len)
        {
            try
            {
                using var stream = File.OpenRead(path);
                var buf = new byte[len];
                int read = stream.Read(buf, 0, len);
                return buf[..read];
            }
            catch (Exception e) when (RustIo.IsIo(e))
            {
                throw new PsignException($"open {path}", IoErrorText.Inner(e));
            }
        }

        private string TopLevelOutputPath(string display)
        {
            if (_output is null)
            {
                return display;
            }

            var outputDisplay = _output.Replace('\\', '/');
            return _topLevelCount == 1 && !IsOutputDirectoryTarget(_output)
                ? outputDisplay
                : JoinDisplayPath(outputDisplay, display);
        }

        private sealed record NestedEntry(string Display, string OutputDisplay, int Depth, byte[] Bytes);

        private List<NestedEntry> InspectZipEntries(byte[] data, string container, string containerOutput, int depth)
        {
            var archive = CodeZip.Open(data, $"open ZIP container {container}");
            var entries = new List<NestedEntry>();
            foreach (var file in archive.Entries)
            {
                archive.EnsureReadable(file);
                if (file.IsDir)
                {
                    continue;
                }

                var name = CodeZip.NormalizeZipName(file.Name);
                var display = $"{container}!{name}";
                var outputDisplay = $"{containerOutput}!{name}";
                var slashDisplay = display.Replace('!', '/');
                if (_nestedExcludes.Any(p => CodePatterns.GlobMatch(p, name) || CodePatterns.GlobMatch(p, slashDisplay)))
                {
                    continue;
                }

                if (CodeFormats.Detect(name) == CodeFormat.Unknown)
                {
                    continue;
                }

                entries.Add(new NestedEntry(display, outputDisplay, depth, archive.Read(file)));
            }

            return entries.OrderBy(e => e.Display, Utf8Ordinal.Comparer).ToList();
        }
    }

    /// <summary>Rust <c>is_output_directory_target</c>.</summary>
    internal static bool IsOutputDirectoryTarget(string path) =>
        Directory.Exists(path) || path.EndsWith('/') || path.EndsWith('\\');

    /// <summary>Rust <c>join_display_path</c>.</summary>
    internal static string JoinDisplayPath(string basePath, string rel) =>
        basePath.Length == 0 ? rel : basePath.EndsWith('/') ? basePath + rel : basePath + "/" + rel;
}
