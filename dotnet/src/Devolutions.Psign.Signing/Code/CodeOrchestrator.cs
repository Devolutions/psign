namespace Devolutions.Psign.Signing.Code;

/// <summary>
/// dotnet/sign-style code-signing orchestration (port of Rust <c>src/code.rs</c> <c>code_command</c>): plan inputs, file
/// lists, globs and nested ZIP/OPC containers, then either print the plan (<c>--dry-run</c> / <c>--plan-json</c>) or sign
/// the top-level inputs inside-out.
/// </summary>
public static class CodeOrchestrator
{
    /// <summary>
    /// Run the orchestrator. Returns stdout and the exit code (1 when <see cref="CodeOptions.ContinueOnError"/> recorded
    /// failures); throws <see cref="Devolutions.Psign.Core.PsignException"/> on fatal errors.
    /// </summary>
    public static CodeCommandResult Run(CodeOptions options)
    {
        var plan = CodePlanner.BuildPlan(options);
        if (options.DryRun)
        {
            return new CodeCommandResult(options.PlanJson ? plan.ToJson() + "\n" : plan.RenderText(), 0);
        }

        return CodeExecutor.Execute(options, plan);
    }

    /// <summary>Build the signing graph only (Rust <c>build_code_plan</c>).</summary>
    public static CodePlan BuildPlan(CodeOptions options) => CodePlanner.BuildPlan(options);
}
