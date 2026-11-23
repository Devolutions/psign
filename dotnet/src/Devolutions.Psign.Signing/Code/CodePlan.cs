using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core.Json;

namespace Devolutions.Psign.Signing.Code;

/// <summary>A planned input (Rust <c>CodePlanNode</c>).</summary>
public sealed record CodePlanNode(int Id, string Path, string OutputPath, CodeFormat Format, int Depth, bool Container, string Signer);

/// <summary>Inside-out ordering edge: <see cref="Before"/> (nested entry) is signed before <see cref="After"/> (its container).</summary>
public sealed record CodePlanEdge(int Before, int After);

/// <summary>Signing graph produced by the planner (Rust <c>CodePlan</c>).</summary>
public sealed class CodePlan
{
    public required string BaseDirectory { get; init; }

    public string? Output { get; init; }

    public bool RecurseContainers { get; init; }

    public int? MaxConcurrency { get; init; }

    public required string FileDigest { get; init; }

    public string? TimestampDigest { get; init; }

    public string? TimestampUrl { get; init; }

    public bool ContinueOnError { get; init; }

    public bool SkipSigned { get; init; }

    public required IReadOnlyList<CodePlanNode> Nodes { get; init; }

    public required IReadOnlyList<CodePlanEdge> Edges { get; init; }

    /// <summary>Serialize like <c>serde_json::to_string_pretty(&amp;plan)</c> (struct field order, no trailing newline).</summary>
    public string ToJson()
    {
        var nodes = new JsonArray();
        foreach (var n in Nodes)
        {
            nodes.Add((JsonNode)new JsonObject
            {
                ["id"] = n.Id,
                ["path"] = n.Path,
                ["output_path"] = n.OutputPath,
                ["format"] = n.Format.KebabName(),
                ["depth"] = n.Depth,
                ["container"] = n.Container,
                ["signer"] = n.Signer,
            });
        }

        var edges = new JsonArray();
        foreach (var e in Edges)
        {
            edges.Add((JsonNode)new JsonObject { ["before"] = e.Before, ["after"] = e.After });
        }

        var root = new JsonObject
        {
            ["base_directory"] = BaseDirectory,
            ["output"] = Output,
            ["recurse_containers"] = RecurseContainers,
            ["max_concurrency"] = MaxConcurrency,
            ["file_digest"] = FileDigest,
            ["timestamp_digest"] = TimestampDigest,
            ["timestamp_url"] = TimestampUrl,
            ["continue_on_error"] = ContinueOnError,
            ["skip_signed"] = SkipSigned,
            ["nodes"] = nodes,
            ["edges"] = edges,
        };
        return RustJson.Pretty(root);
    }

    /// <summary>Human-readable dry-run output (Rust <c>render_text_plan</c>).</summary>
    public string RenderText()
    {
        var sb = new StringBuilder();
        sb.Append("psign code dry-run plan\n");
        sb.Append("base_directory=").Append(BaseDirectory).Append('\n');
        sb.Append("nodes=").Append(Nodes.Count.ToString(CultureInfo.InvariantCulture)).Append('\n');
        foreach (var n in Nodes)
        {
            sb.Append('#').Append(n.Id.ToString("D3", CultureInfo.InvariantCulture))
                .Append(" depth=").Append(n.Depth.ToString(CultureInfo.InvariantCulture))
                .Append(" format=").Append(n.Format.DebugName())
                .Append(" signer=").Append(n.Signer)
                .Append(" path=").Append(n.Path)
                .Append(" output=").Append(n.OutputPath)
                .Append('\n');
        }

        return sb.ToString();
    }
}
