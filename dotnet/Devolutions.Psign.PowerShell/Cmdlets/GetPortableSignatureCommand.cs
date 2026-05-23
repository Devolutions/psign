using System.Globalization;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
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
    private const string ContentParameterSet = "Content";

    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = FilePathParameterSet)]
    [Alias("Path")]
    public string[] FilePath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
    [Alias("PSPath", "LP")]
    public string[] LiteralPath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = ContentParameterSet)]
    public string[] SourcePathOrExtension { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = ContentParameterSet)]
    [ValidateNotNullOrEmpty]
    public byte[] Content { get; set; } = [];

    [Parameter]
    public X509Certificate2[] TrustedCertificate { get; set; } = [];

    [Parameter]
    public string[] TrustedCertificatePath { get; set; } = [];

    [Parameter]
    public string? AnchorDirectory { get; set; }

    [Parameter]
    public string? AuthRootCab { get; set; }

    [Parameter]
    public DateTime? AsOf { get; set; }

    [Parameter]
    public SwitchParameter PreferTimestampSigningTime { get; set; }

    [Parameter]
    public SwitchParameter RequireValidTimestamp { get; set; }

    [Parameter]
    public SwitchParameter OnlineAia { get; set; }

    [Parameter]
    public SwitchParameter OnlineOcsp { get; set; }

    [Parameter]
    [ValidateSet("Off", "BestEffort", "Require")]
    public string RevocationMode { get; set; } = "Off";

    protected override void ProcessRecord()
    {
        bool literal = ParameterSetName == LiteralPathParameterSet;
        if (ParameterSetName == ContentParameterSet)
        {
            foreach (string source in SourcePathOrExtension)
            {
                WriteContentSignature(source);
            }
            return;
        }

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

            WriteObject(PsignNative.GetSignature(CreateRequest(path)));
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "GetPortableSignatureFailed", ErrorCategory.NotSpecified, path));
        }
    }

    private void WriteContentSignature(string sourcePathOrExtension)
    {
        string tempDirectory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDirectory);
        string tempPath = System.IO.Path.Combine(tempDirectory, ContentFileName(sourcePathOrExtension));
        try
        {
            File.WriteAllBytes(tempPath, Content);
            PortableSignature signature = PsignNative.GetSignature(CreateRequest(tempPath));
            signature.SourcePathOrExtension = sourcePathOrExtension;
            WriteObject(signature);
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "GetPortableSignatureContentFailed", ErrorCategory.NotSpecified, sourcePathOrExtension));
        }
        finally
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    private PortableGetSignatureRequest CreateRequest(string path)
    {
        return new PortableGetSignatureRequest
        {
            Path = path,
            TrustedCertificatePaths = TrustedCertificatePath
                .Select(p => SessionState.Path.GetUnresolvedProviderPathFromPSPath(p))
                .ToArray(),
            TrustedCertificatesDerBase64 = TrustedCertificate
                .Select(c => Convert.ToBase64String(c.Export(X509ContentType.Cert)))
                .ToArray(),
            AnchorDirectory = AnchorDirectory is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(AnchorDirectory),
            AuthRootCab = AuthRootCab is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(AuthRootCab),
            AsOf = AsOf is null
                ? null
                : AsOf.Value.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            PreferTimestampSigningTime = PreferTimestampSigningTime.IsPresent || RequireValidTimestamp.IsPresent,
            RequireValidTimestamp = RequireValidTimestamp.IsPresent,
            OnlineAia = OnlineAia.IsPresent,
            OnlineOcsp = OnlineOcsp.IsPresent,
            RevocationMode = RevocationMode,
        };
    }

    private static string ContentFileName(string sourcePathOrExtension)
    {
        string fileName = System.IO.Path.GetFileName(sourcePathOrExtension);
        if (!string.IsNullOrWhiteSpace(fileName)
            && System.IO.Path.HasExtension(fileName)
            && !string.IsNullOrWhiteSpace(System.IO.Path.GetFileNameWithoutExtension(fileName)))
        {
            return fileName;
        }

        string extension = sourcePathOrExtension.Trim();
        if (!extension.StartsWith('.'))
        {
            extension = "." + extension;
        }
        return "content" + extension;
    }
}
