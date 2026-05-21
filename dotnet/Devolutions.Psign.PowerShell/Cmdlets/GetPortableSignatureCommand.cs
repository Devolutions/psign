using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Utilities;

namespace Devolutions.Psign.PowerShell.Cmdlets;

[Cmdlet(VerbsCommon.Get, "PortableSignature", DefaultParameterSetName = FilePathParameterSet)]
[OutputType(typeof(PortableSignature))]
public sealed class GetPortableSignatureCommand : PSCmdlet
{
    private const string FilePathParameterSet = "FilePath";
    private const string LiteralPathParameterSet = "LiteralPath";

    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = FilePathParameterSet)]
    [Alias("Path")]
    public string[] FilePath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
    [Alias("PSPath")]
    public string[] LiteralPath { get; set; } = [];

    protected override void ProcessRecord()
    {
        bool literal = ParameterSetName == LiteralPathParameterSet;
        string[] inputs = literal ? LiteralPath : FilePath;
        foreach (string input in inputs)
        {
            foreach (string resolved in PathResolution.ResolveFilePaths(this, input, literal))
            {
                WriteSignature(resolved);
            }
        }
    }

    private void WriteSignature(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                foreach (string moduleFile in PortableModuleFiles.Enumerate(path))
                {
                    WriteSignature(moduleFile);
                }
                return;
            }

            WriteObject(PsignNative.GetSignature(new PortableGetSignatureRequest { Path = path }));
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "GetPortableSignatureFailed", ErrorCategory.NotSpecified, path));
        }
    }
}
