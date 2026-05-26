using System.Globalization;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Trust;

namespace Devolutions.Psign.PowerShell.Cmdlets;

[Cmdlet(VerbsDiagnostic.Test, "PsignFileCatalog", SupportsShouldProcess = true)]
[OutputType(typeof(PsignCatalogValidationStatus), typeof(PortableTestFileCatalogResponse))]
public sealed class TestPsignFileCatalogCommand : PSCmdlet
{
    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true)]
    public string CatalogFilePath { get; set; } = string.Empty;

    [Parameter(Position = 1, ValueFromPipelineByPropertyName = true)]
    public string[] Path { get; set; } = [];

    [Parameter]
    public SwitchParameter Detailed { get; set; }

    [Parameter]
    public string[] FilesToSkip { get; set; } = [];

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

    [Parameter]
    public SwitchParameter SkipTrust { get; set; }

    protected override void ProcessRecord()
    {
        string catalogPath = SessionState.Path.GetUnresolvedProviderPathFromPSPath(CatalogFilePath);
        if (!ShouldProcess(catalogPath, "Test portable file catalog"))
        {
            return;
        }

        try
        {
            PortableTestFileCatalogResponse response = PsignNative.TestFileCatalog(CreateRequest(catalogPath));
            WriteObject(Detailed.IsPresent ? response : response.Status);
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "TestPsignFileCatalogFailed", ErrorCategory.NotSpecified, catalogPath));
        }
    }

    private PortableTestFileCatalogRequest CreateRequest(string catalogPath)
    {
        string[] paths = Path.Length == 0
            ? [SessionState.Path.CurrentFileSystemLocation.ProviderPath]
            : Path.Select(p => SessionState.Path.GetUnresolvedProviderPathFromPSPath(p)).ToArray();

        string? resolvedAuthRootCab = AuthRootCab is null
            ? null
            : SessionState.Path.GetUnresolvedProviderPathFromPSPath(AuthRootCab);
        if (!SkipTrust.IsPresent
            && resolvedAuthRootCab is null
            && AnchorDirectory is null
            && TrustedCertificatePath.Length == 0
            && TrustedCertificate.Length == 0)
        {
            resolvedAuthRootCab = AuthRootCache.GetOrDownloadAuthRootCab(msg => WriteVerbose(msg));
        }

        return new PortableTestFileCatalogRequest
        {
            CatalogFilePath = catalogPath,
            Paths = paths,
            FilesToSkip = FilesToSkip,
            TrustedCertificatePaths = TrustedCertificatePath
                .Select(p => SessionState.Path.GetUnresolvedProviderPathFromPSPath(p))
                .ToArray(),
            TrustedCertificatesDerBase64 = TrustedCertificate
                .Select(c => Convert.ToBase64String(c.Export(X509ContentType.Cert)))
                .ToArray(),
            AnchorDirectory = AnchorDirectory is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(AnchorDirectory),
            AuthRootCab = resolvedAuthRootCab,
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
}
