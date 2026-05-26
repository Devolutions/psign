using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;

namespace Devolutions.Psign.PowerShell.Cmdlets;

[Cmdlet(VerbsCommon.New, "PsignFileCatalog", SupportsShouldProcess = true)]
[OutputType(typeof(FileInfo))]
public sealed class NewPsignFileCatalogCommand : PSCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string CatalogFilePath { get; set; } = string.Empty;

    [Parameter(Position = 1, ValueFromPipelineByPropertyName = true)]
    public string[] Path { get; set; } = [];

    [Parameter]
    [ValidateRange(1, 2)]
    public int CatalogVersion { get; set; } = 2;

    protected override void ProcessRecord()
    {
        string catalogPath = ResolveCatalogPath(CatalogFilePath);
        string[] paths = ResolveInputPaths();
        if (!ShouldProcess(catalogPath, $"Create portable file catalog from {paths.Length} path(s)"))
        {
            return;
        }

        try
        {
            PortableNewFileCatalogResponse response = PsignNative.NewFileCatalog(new PortableNewFileCatalogRequest
            {
                CatalogFilePath = catalogPath,
                Paths = paths,
                CatalogVersion = CatalogVersion,
            });
            WriteObject(new FileInfo(response.CatalogFilePath));
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "NewPsignFileCatalogFailed", ErrorCategory.NotSpecified, catalogPath));
        }
    }

    private string[] ResolveInputPaths()
    {
        string[] inputs = Path.Length == 0
            ? [SessionState.Path.CurrentFileSystemLocation.ProviderPath]
            : Path;
        return inputs
            .Select(p => SessionState.Path.GetUnresolvedProviderPathFromPSPath(p))
            .ToArray();
    }

    private string ResolveCatalogPath(string catalogFilePath)
    {
        string resolved = SessionState.Path.GetUnresolvedProviderPathFromPSPath(catalogFilePath);
        return Directory.Exists(resolved)
            ? System.IO.Path.Combine(resolved, "catalog.cat")
            : resolved;
    }
}
