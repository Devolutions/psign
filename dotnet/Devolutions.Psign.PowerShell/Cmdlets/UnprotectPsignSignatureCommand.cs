using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;

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

    // PowerShell SIG block pattern:
    // Starts with "# SIG # Begin signature block" and ends with "# SIG # End signature block"
    private static readonly Regex ScriptSigBlockRegex = new(
        @"(\r?\n)?# SIG # Begin signature block\r?\n[\s\S]*?# SIG # End signature block\r?\n?",
        RegexOptions.Compiled);

    // XML SIG block: <!-- SIG # Begin signature block --> ... <!-- SIG # End signature block -->
    private static readonly Regex XmlSigBlockRegex = new(
        @"(\r?\n)?<!-- SIG # Begin signature block -->\r?\n[\s\S]*?<!-- SIG # End signature block -->\r?\n?",
        RegexOptions.Compiled);

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
            string content = File.ReadAllText(path);
            bool isXml = ext.Equals(".ps1xml", StringComparison.OrdinalIgnoreCase)
                      || ext.Equals(".psc1", StringComparison.OrdinalIgnoreCase)
                      || ext.Equals(".cdxml", StringComparison.OrdinalIgnoreCase);

            Regex regex = isXml ? XmlSigBlockRegex : ScriptSigBlockRegex;
            string stripped = regex.Replace(content, string.Empty);

            if (stripped.Length == content.Length)
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

            // Preserve original encoding (detect BOM)
            Encoding encoding = DetectEncoding(path);
            File.WriteAllText(path, stripped, encoding);

            WriteObject(new PsignUnprotectResult
            {
                Path = path,
                SignatureRemoved = true,
                BytesRemoved = content.Length - stripped.Length,
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

            PortableClearSignatureResponse response = PsignNative.ClearSignature(new PortableClearSignatureRequest
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

    private static Encoding DetectEncoding(string path)
    {
        byte[] bom = new byte[4];
        using var fs = File.OpenRead(path);
        int read = fs.Read(bom, 0, 4);

        if (read >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF)
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);
        if (read >= 2 && bom[0] == 0xFF && bom[1] == 0xFE)
            return Encoding.Unicode; // UTF-16 LE
        if (read >= 2 && bom[0] == 0xFE && bom[1] == 0xFF)
            return Encoding.BigEndianUnicode; // UTF-16 BE

        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
    }
}

public sealed class PsignUnprotectResult
{
    public string Path { get; init; } = string.Empty;
    public bool SignatureRemoved { get; init; }
    public int BytesRemoved { get; init; }
    public string Message { get; init; } = string.Empty;
}
