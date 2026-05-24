using System.Management.Automation;

namespace Devolutions.Psign.PowerShell.Provider;

/// <summary>
/// PSDriveInfo subclass that carries the resolved base directory for the portable cert store.
/// </summary>
public sealed class PortableCertStoreDriveInfo : PSDriveInfo
{
    /// <summary>
    /// The resolved filesystem path to the cert store root directory.
    /// </summary>
    public string BaseDirectory { get; }

    public PortableCertStoreDriveInfo(PSDriveInfo driveInfo, string baseDirectory)
        : base(driveInfo)
    {
        BaseDirectory = baseDirectory;
    }
}
