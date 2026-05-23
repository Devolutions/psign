using System.Management.Automation.Language;

namespace Devolutions.Psign.PowerShell.Utilities;

/// <summary>
/// Parses a PowerShell module manifest (.psd1) and extracts the fields relevant
/// to execution policy enforcement during Import-Module.
/// </summary>
internal sealed class ModuleManifestInfo
{
    public string? RootModule { get; private set; }
    public string[] ScriptsToProcess { get; private set; } = [];
    public string[] NestedModules { get; private set; } = [];
    public string[] TypesToProcess { get; private set; } = [];
    public string[] FormatsToProcess { get; private set; } = [];
    public string[] RequiredAssemblies { get; private set; } = [];
    public string[] FileList { get; private set; } = [];

    /// <summary>
    /// Parse a .psd1 manifest file using the PowerShell AST parser (safe restricted-language parse).
    /// </summary>
    public static ModuleManifestInfo Parse(string psd1Path)
    {
        var info = new ModuleManifestInfo();
        string content = File.ReadAllText(psd1Path);

        // Use PowerShell's AST parser in RestrictedLanguage mode (same as Import-Module)
        var ast = Parser.ParseInput(content, out _, out ParseError[] errors);
        if (errors.Length > 0)
        {
            throw new InvalidDataException($"Failed to parse manifest: {errors[0].Message}");
        }

        // The manifest is a single HashtableAst at the pipeline level
        var hashtable = ast.Find(a => a is HashtableAst, searchNestedScriptBlocks: false) as HashtableAst;
        if (hashtable is null)
        {
            throw new InvalidDataException("Manifest does not contain a hashtable expression.");
        }

        foreach (var kvp in hashtable.KeyValuePairs)
        {
            string key = kvp.Item1.SafeGetValue()?.ToString() ?? string.Empty;

            switch (key.ToUpperInvariant())
            {
                case "ROOTMODULE":
                case "MODULETOPROCESS":
                    info.RootModule = ExtractString(kvp.Item2);
                    break;
                case "SCRIPTSTOPROCESS":
                    info.ScriptsToProcess = ExtractStringArray(kvp.Item2);
                    break;
                case "NESTEDMODULES":
                    info.NestedModules = ExtractStringArray(kvp.Item2);
                    break;
                case "TYPOSTOPROCESS":
                case "TYPESTOPROCESS":
                    info.TypesToProcess = ExtractStringArray(kvp.Item2);
                    break;
                case "FORMATSTOPROCESS":
                    info.FormatsToProcess = ExtractStringArray(kvp.Item2);
                    break;
                case "REQUIREDASSEMBLIES":
                    info.RequiredAssemblies = ExtractStringArray(kvp.Item2);
                    break;
                case "FILELIST":
                    info.FileList = ExtractStringArray(kvp.Item2);
                    break;
            }
        }

        return info;
    }

    private static string? ExtractString(StatementAst valueAst)
    {
        var pipeline = valueAst as PipelineAst;
        if (pipeline?.PipelineElements.Count == 1 &&
            pipeline.PipelineElements[0] is CommandExpressionAst cmdExpr)
        {
            return cmdExpr.Expression.SafeGetValue()?.ToString();
        }
        return valueAst.ToString().Trim('\'', '"');
    }

    private static string[] ExtractStringArray(StatementAst valueAst)
    {
        var pipeline = valueAst as PipelineAst;
        if (pipeline?.PipelineElements.Count != 1)
            return [];

        var cmdExpr = pipeline.PipelineElements[0] as CommandExpressionAst;
        if (cmdExpr is null)
            return [];

        // @('item1', 'item2') or @('single')
        if (cmdExpr.Expression is ArrayExpressionAst arrayExpr)
        {
            return ExtractFromStatementBlock(arrayExpr.SubExpression);
        }

        // ('item1', 'item2') — ArrayLiteralAst
        if (cmdExpr.Expression is ArrayLiteralAst arrayLiteral)
        {
            return arrayLiteral.Elements
                .Select(e => e.SafeGetValue()?.ToString() ?? e.ToString().Trim('\'', '"'))
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToArray();
        }

        // Single string value
        string? single = cmdExpr.Expression.SafeGetValue()?.ToString();
        if (!string.IsNullOrWhiteSpace(single))
            return [single];

        return [];
    }

    private static string[] ExtractFromStatementBlock(StatementBlockAst block)
    {
        var results = new List<string>();
        foreach (var stmt in block.Statements)
        {
            if (stmt is PipelineAst pipeline &&
                pipeline.PipelineElements.Count == 1 &&
                pipeline.PipelineElements[0] is CommandExpressionAst cmdExpr)
            {
                if (cmdExpr.Expression is ArrayLiteralAst arrayLit)
                {
                    results.AddRange(arrayLit.Elements
                        .Select(e => e.SafeGetValue()?.ToString() ?? e.ToString().Trim('\'', '"'))
                        .Where(s => !string.IsNullOrWhiteSpace(s)));
                }
                else
                {
                    string? val = cmdExpr.Expression.SafeGetValue()?.ToString();
                    if (!string.IsNullOrWhiteSpace(val))
                        results.Add(val);
                }
            }
        }
        return results.ToArray();
    }
}
