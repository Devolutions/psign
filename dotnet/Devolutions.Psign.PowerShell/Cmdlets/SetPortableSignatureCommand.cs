using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Management.Automation;
using Devolutions.Psign.PowerShell.Models;
using Devolutions.Psign.PowerShell.Native;
using Devolutions.Psign.PowerShell.Utilities;

namespace Devolutions.Psign.PowerShell.Cmdlets;

[Cmdlet(VerbsCommon.Set, "PortableSignature", SupportsShouldProcess = true, DefaultParameterSetName = FilePathParameterSet)]
[OutputType(typeof(PortableSignature))]
public sealed class SetPortableSignatureCommand : PSCmdlet
{
    private const string FilePathParameterSet = "FilePath";
    private const string LiteralPathParameterSet = "LiteralPath";

    [Parameter(Mandatory = true, Position = 0, ValueFromPipeline = true, ValueFromPipelineByPropertyName = true, ParameterSetName = FilePathParameterSet)]
    [Alias("Path")]
    public string[] FilePath { get; set; } = [];

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true, ParameterSetName = LiteralPathParameterSet)]
    [Alias("PSPath")]
    public string[] LiteralPath { get; set; } = [];

    [Parameter]
    public X509Certificate2? Certificate { get; set; }

    [Parameter]
    public string? CertificatePath { get; set; }

    [Parameter]
    public string? PrivateKeyPath { get; set; }

    [Parameter]
    public string? PfxPath { get; set; }

    [Parameter]
    public SecureString? Password { get; set; }

    [Parameter]
    [ValidateSet("Sha256", "Sha384", "Sha512")]
    public string HashAlgorithm { get; set; } = "Sha256";

    [Parameter]
    public string? OutputPath { get; set; }

    [Parameter]
    public SwitchParameter Force { get; set; }

    protected override void ProcessRecord()
    {
        ValidateSigningMaterial();
        bool literal = ParameterSetName == LiteralPathParameterSet;
        string[] inputs = literal ? LiteralPath : FilePath;
        if (OutputPath is not null && inputs.Length != 1)
        {
            ThrowTerminatingError(new ErrorRecord(
                new PSInvalidOperationException("-OutputPath can only be used with a single input file."),
                "PortableSignatureOutputPathRequiresSingleInput",
                ErrorCategory.InvalidArgument,
                OutputPath));
        }

        foreach (string input in inputs)
        {
            IReadOnlyList<string> resolvedPaths = PathResolution.ResolveFilePaths(this, input, literal);
            if (OutputPath is not null
                && (resolvedPaths.Count != 1 || Directory.Exists(resolvedPaths[0])))
            {
                ThrowTerminatingError(new ErrorRecord(
                    new PSInvalidOperationException("-OutputPath can only be used with a single input file, not module directories or wildcard groups."),
                    "PortableSignatureOutputPathRequiresSingleInput",
                    ErrorCategory.InvalidArgument,
                    input));
            }

            foreach (string resolved in resolvedPaths)
            {
                SignPath(resolved);
            }
        }
    }

    private void SignPath(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                foreach (string moduleFile in PortableModuleFiles.Enumerate(path))
                {
                    SignPath(moduleFile);
                }
                return;
            }

            string? outputPath = OutputPath is null
                ? null
                : SessionState.Path.GetUnresolvedProviderPathFromPSPath(OutputPath);
            string target = outputPath ?? path;
            if (!ShouldProcess(target, "Set portable Authenticode signature"))
            {
                return;
            }

            FileAttributes? restoreAttributes = PrepareWritableTarget(path, target);
            try
            {
                PortableSignResponse response = PsignNative.Sign(new PortableSignRequest
                {
                    Path = path,
                    OutputPath = outputPath,
                    HashAlgorithm = HashAlgorithm,
                    CertificatePath = CertificatePath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(CertificatePath),
                    PrivateKeyPath = PrivateKeyPath is null
                        ? null
                        : SessionState.Path.GetUnresolvedProviderPathFromPSPath(PrivateKeyPath),
                    CertificateDerBase64 = GetCertificateDerBase64(),
                    PrivateKeyDerBase64 = GetPrivateKeyDerBase64(),
                });
                WriteObject(response.Signature);
            }
            finally
            {
                if (restoreAttributes is not null)
                {
                    File.SetAttributes(target, restoreAttributes.Value);
                }
            }
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "SetPortableSignatureFailed", ErrorCategory.NotSpecified, path));
        }
    }

    private FileAttributes? PrepareWritableTarget(string inputPath, string targetPath)
    {
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(targetPath)))
        {
            return null;
        }

        FileAttributes attributes = File.GetAttributes(targetPath);
        if ((attributes & FileAttributes.ReadOnly) == 0)
        {
            return null;
        }

        if (!Force)
        {
            throw new UnauthorizedAccessException(
                $"File '{targetPath}' is read-only. Use -Force to sign it in place.");
        }

        File.SetAttributes(targetPath, attributes & ~FileAttributes.ReadOnly);
        return attributes;
    }

    private void ValidateSigningMaterial()
    {
        int materialCount = 0;
        if (Certificate is not null)
        {
            materialCount++;
        }
        if (CertificatePath is not null || PrivateKeyPath is not null)
        {
            if (CertificatePath is null || PrivateKeyPath is null)
            {
                ThrowTerminatingError(new ErrorRecord(
                    new PSInvalidOperationException("-CertificatePath and -PrivateKeyPath must be supplied together."),
                    "PortableSignatureIncompleteKeyPair",
                    ErrorCategory.InvalidArgument,
                    this));
            }
            materialCount++;
        }
        if (PfxPath is not null)
        {
            materialCount++;
        }

        if (materialCount != 1)
        {
            ThrowTerminatingError(new ErrorRecord(
                new PSInvalidOperationException("Supply exactly one signing source: -Certificate, -CertificatePath/-PrivateKeyPath, or -PfxPath."),
                "PortableSignatureSigningMaterialRequired",
                ErrorCategory.InvalidArgument,
                this));
        }
    }

    private X509Certificate2? LoadPfxCertificate()
    {
        if (PfxPath is null)
        {
            return null;
        }

        string resolved = SessionState.Path.GetUnresolvedProviderPathFromPSPath(PfxPath);
        string? password = Password is null ? null : SecureStringToString(Password);
        try
        {
            return new X509Certificate2(
                resolved,
                password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        }
        finally
        {
            if (password is not null)
            {
                password = null;
            }
        }
    }

    private string? GetCertificateDerBase64()
    {
        X509Certificate2? cert = Certificate ?? LoadPfxCertificate();
        if (cert is null)
        {
            return null;
        }
        return Convert.ToBase64String(cert.Export(X509ContentType.Cert));
    }

    private string? GetPrivateKeyDerBase64()
    {
        X509Certificate2? cert = Certificate ?? LoadPfxCertificate();
        if (cert is null)
        {
            return null;
        }

        using RSA? rsa = cert.GetRSAPrivateKey();
        if (rsa is null)
        {
            throw new PSInvalidOperationException("Portable signing requires an exportable RSA private key.");
        }
        try
        {
            return Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
        }
        catch (CryptographicException ex)
        {
            throw new PSInvalidOperationException(
                "Portable signing requires exportable key material. Use -CertificatePath/-PrivateKeyPath, -PfxPath with an exportable key, or a remote signer.",
                ex);
        }
    }

    private static string SecureStringToString(SecureString value)
    {
        IntPtr ptr = Marshal.SecureStringToBSTR(value);
        try
        {
            return Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            Marshal.ZeroFreeBSTR(ptr);
        }
    }
}
