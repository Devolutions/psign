using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Utilities;

namespace Devolutions.Psign.PowerShell.Cmdlets;

/// <summary>
/// Reads the Azure Artifact Signing publisher ID (certificate profile EKU) from a signed file's
/// signer certificate or from a certificate. This does not validate the signature; use
/// Test-PsignArtifactSigning or Get-PsignSignature -ArtifactSigningPublisherId for that.
/// </summary>
[Cmdlet(VerbsCommon.Get, "PsignArtifactSigningPublisherId", DefaultParameterSetName = FilePathParameterSet)]
[OutputType(typeof(PsignArtifactSigningIdentity))]
public sealed class GetPsignArtifactSigningPublisherIdCommand : PSCmdlet
{
    private const string FilePathParameterSet = "FilePath";
    private const string LiteralPathParameterSet = "LiteralPath";
    private const string CertificateParameterSet = "Certificate";

    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = FilePathParameterSet, HelpMessage = "Path(s) to signed files. Wildcards are supported.")]
    [Alias("Path")]
    public string[] FilePath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet, HelpMessage = "Literal path(s) to signed files. No wildcard expansion.")]
    [Alias("PSPath", "LP")]
    public string[] LiteralPath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipeline = true, ParameterSetName = CertificateParameterSet, HelpMessage = "Signer certificate(s) to decode.")]
    public X509Certificate2[] Certificate { get; set; } = [];

    protected override void ProcessRecord()
    {
        if (ParameterSetName == CertificateParameterSet)
        {
            foreach (X509Certificate2 certificate in Certificate)
            {
                WriteCertificateIdentity(certificate);
            }
            return;
        }

        bool literal = ParameterSetName == LiteralPathParameterSet;
        foreach (string input in literal ? LiteralPath : FilePath)
        {
            foreach (string resolved in PathResolution.ResolveFilePaths(this, input, literal))
            {
                WriteFileIdentity(resolved);
            }
        }
    }

    private void WriteFileIdentity(string path)
    {
        try
        {
            PortableSignature signature = PsignNative.GetSignature(new PortableGetSignatureRequest { Path = path });
            if (signature.ArtifactSigning is null)
            {
                WriteNotArtifactSigningError(signature.SignerCertificate is null
                    ? $"'{path}' has no signer certificate ({signature.Status}: {signature.StatusMessage})."
                    : $"The signer of '{path}' has no Azure Artifact Signing identity EKU (1.3.6.1.4.1.311.97.*).", path);
                return;
            }

            signature.ArtifactSigning.Path = path;
            signature.ArtifactSigning.Subject = signature.SignerCertificate?.Subject;
            WriteObject(signature.ArtifactSigning);
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "GetPsignArtifactSigningPublisherIdFailed", ErrorCategory.NotSpecified, path));
        }
    }

    private void WriteCertificateIdentity(X509Certificate2 certificate)
    {
        try
        {
            PortableArtifactSigningIdentityResponse response = PsignNative.GetArtifactSigningIdentity(
                new PortableArtifactSigningIdentityRequest
                {
                    CertificateDerBase64 = Convert.ToBase64String(certificate.Export(X509ContentType.Cert)),
                });
            if (response.Identity is null)
            {
                WriteNotArtifactSigningError(
                    $"Certificate '{certificate.Subject}' has no Azure Artifact Signing identity EKU (1.3.6.1.4.1.311.97.*).",
                    certificate);
                return;
            }

            response.Identity.Subject = certificate.Subject;
            WriteObject(response.Identity);
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "GetPsignArtifactSigningPublisherIdFailed", ErrorCategory.NotSpecified, certificate));
        }
    }

    private void WriteNotArtifactSigningError(string message, object target)
    {
        WriteError(new ErrorRecord(
            new InvalidOperationException(message),
            "NotArtifactSigningCertificate",
            ErrorCategory.InvalidData,
            target));
    }
}
