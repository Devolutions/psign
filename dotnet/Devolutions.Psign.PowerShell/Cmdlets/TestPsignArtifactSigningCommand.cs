using System.Globalization;
using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Utilities;

namespace Devolutions.Psign.PowerShell.Cmdlets;

/// <summary>
/// Tests whether files carry a valid Azure Artifact Signing signature: identity EKU, signer and
/// timestamp chains pinned to Microsoft Identity Verification Root CA 2020, certificate validity at
/// the trusted timestamp, and optionally one of the expected publisher IDs. Same policy as
/// <c>psign-tool verify --artifact-signing</c> in both tool modes.
/// </summary>
[Cmdlet(VerbsDiagnostic.Test, "PsignArtifactSigning", DefaultParameterSetName = FilePathParameterSet)]
[OutputType(typeof(bool), typeof(PortableSignature))]
public sealed class TestPsignArtifactSigningCommand : PSCmdlet
{
    private const string FilePathParameterSet = "FilePath";
    private const string LiteralPathParameterSet = "LiteralPath";

    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = FilePathParameterSet, HelpMessage = "Path(s) to signed files. Wildcards are supported.")]
    [Alias("Path")]
    public string[] FilePath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet, HelpMessage = "Literal path(s) to signed files. No wildcard expansion.")]
    [Alias("PSPath", "LP")]
    public string[] LiteralPath { get; set; } = [];

    [Parameter(Position = 1, HelpMessage = "Require one of these publisher IDs (certificate profile EKU suffix).")]
    [ValidateNotNullOrEmpty]
    public string[] PublisherId { get; set; } = [];

    [Parameter(HelpMessage = "Subscriber root certificate for Private Trust / Public Trust Test signatures.")]
    public string[] PrivateTrustRoot { get; set; } = [];

    [Parameter(HelpMessage = "Accept signatures without a timestamp (validated at the current time).")]
    public SwitchParameter AllowMissingTimestamp { get; set; }

    [Parameter(HelpMessage = "Validate certificates at this date instead of the timestamp time.")]
    public DateTime? AsOf { get; set; }

    [Parameter]
    public SwitchParameter OnlineOcsp { get; set; }

    [Parameter]
    [ValidateSet("Off", "BestEffort", "Require")]
    public string RevocationMode { get; set; } = "Off";

    [Parameter(HelpMessage = "Return the full signature object instead of a Boolean.")]
    public SwitchParameter Detailed { get; set; }

    protected override void ProcessRecord()
    {
        bool literal = ParameterSetName == LiteralPathParameterSet;
        foreach (string input in literal ? LiteralPath : FilePath)
        {
            foreach (string resolved in PathResolution.ResolveFilePaths(this, input, literal))
            {
                TestFile(resolved);
            }
        }
    }

    private void TestFile(string path)
    {
        try
        {
            PortableSignature signature = PsignNative.GetSignature(new PortableGetSignatureRequest
            {
                Path = path,
                AsOf = AsOf?.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                OnlineOcsp = OnlineOcsp.IsPresent,
                RevocationMode = RevocationMode,
                ArtifactSigning = ArtifactSigningOptions.Create(
                    this,
                    requested: true,
                    PublisherId,
                    PrivateTrustRoot,
                    AllowMissingTimestamp.IsPresent),
            });
            bool valid = signature.Status == SignatureStatus.Valid
                && signature.ArtifactSigningVerification is not null;
            if (!valid)
            {
                WriteVerbose($"{path}: {signature.Status}: {signature.StatusMessage}");
            }
            WriteObject(Detailed.IsPresent ? signature : valid);
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "TestPsignArtifactSigningFailed", ErrorCategory.NotSpecified, path));
        }
    }
}
