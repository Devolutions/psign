using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Portable;

namespace Devolutions.Psign.PowerShell.Cmdlets;

/// <summary>
/// Removes Authenticode signatures from supported files.
/// This is the reverse of Set-PsignSignature for script and PE files.
/// </summary>
[Cmdlet(VerbsSecurity.Unprotect, "PsignSignature", SupportsShouldProcess = true)]
[OutputType(typeof(PsignUnprotectResult))]
public sealed class UnprotectPsignSignatureCommand : PSCmdlet
{
    private const string FilePathParameterSet = "FilePath";
    private const string LiteralPathParameterSet = "LiteralPath";

    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = FilePathParameterSet, HelpMessage = "Path(s) to files to strip signatures from.")]
    [Alias("Path")]
    public string[] FilePath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet, HelpMessage = "Literal path(s) to files. No wildcard expansion.")]
    [Alias("PSPath", "LP")]
    public string[] LiteralPath { get; set; } = [];

    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".psm1", ".psd1", ".ps1xml", ".psc1", ".cdxml", ".mof",
    };

    protected override void ProcessRecord()
    {
        bool literal = ParameterSetName == LiteralPathParameterSet;
        string[] inputs = literal ? LiteralPath : FilePath;

        foreach (string input in inputs)
        {
            foreach (string resolved in Utilities.PathResolution.ResolveFilePaths(this, input, literal))
            {
                RemoveSignature(resolved);
            }
        }
    }

    private void RemoveSignature(string path)
    {
        if (!File.Exists(path))
        {
            WriteError(new ErrorRecord(
                new FileNotFoundException($"File not found: {path}"),
                "FileNotFound", ErrorCategory.ObjectNotFound, path));
            return;
        }

        string ext = System.IO.Path.GetExtension(path);
        if (!SupportedExtensions.Contains(ext))
        {
            RemovePeSignature(path);
            return;
        }

        try
        {
            byte[] rawBytes = File.ReadAllBytes(path);
            var (content, encoding) = Devolutions.Psign.Signing.Remove.ScriptEncodingExtensions.Decode(rawBytes);
            string? stripped = Devolutions.Psign.Signing.Remove.PortableRemove.RemoveScriptSignatureBlock(content, ext);

            if (stripped is null)
            {
                WriteObject(new PsignUnprotectResult
                {
                    Path = path,
                    SignatureRemoved = false,
                    Message = "No signature block found.",
                });
                return;
            }

            if (!ShouldProcess(path, "Remove Authenticode signature"))
            {
                return;
            }

            byte[] updatedBytes = Devolutions.Psign.Signing.Remove.ScriptEncodingExtensions.Encode(encoding, stripped);
            File.WriteAllBytes(path, updatedBytes);

            WriteObject(new PsignUnprotectResult
            {
                Path = path,
                SignatureRemoved = true,
                BytesRemoved = Math.Max(0, rawBytes.Length - updatedBytes.Length),
                Message = "Signature block removed.",
            });
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "UnprotectPsignSignatureFailed", ErrorCategory.NotSpecified, path));
        }
    }

    private void RemovePeSignature(string path)
    {
        if (!File.Exists(path))
        {
            WriteError(new ErrorRecord(
                new FileNotFoundException($"File not found: {path}"),
                "FileNotFound", ErrorCategory.ObjectNotFound, path));
            return;
        }

        try
        {
            if (!ShouldProcess(path, "Remove PE Authenticode signature"))
            {
                return;
            }

            PortableClearSignatureResponse response = PsignPortable.ClearSignature(new PortableClearSignatureRequest
            {
                Path = path,
            });
            WriteObject(new PsignUnprotectResult
            {
                Path = response.Path,
                SignatureRemoved = response.SignatureRemoved,
                BytesRemoved = response.BytesRemoved,
                Message = response.Message,
            });
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "UnprotectPsignPeSignatureFailed", ErrorCategory.NotSpecified, path));
        }
    }
}

public sealed class PsignUnprotectResult
{
    public string Path { get; init; } = string.Empty;
    public bool SignatureRemoved { get; init; }
    public int BytesRemoved { get; init; }
    public string Message { get; init; } = string.Empty;
}
