using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Management.Automation.Provider;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.Psign.PowerShell.Provider;

/// <summary>
/// PowerShell navigation provider that exposes the portable file-based certificate store
/// as a pcert:\ drive, mirroring the Windows cert:\ provider hierarchy.
/// </summary>
[CmdletProvider("PortableCertStore", ProviderCapabilities.ShouldProcess)]
public sealed class PortableCertStoreProvider : NavigationCmdletProvider
{
    private PortableCertStoreDriveInfo CurrentDrive =>
        (PortableCertStoreDriveInfo)PSDriveInfo;

    #region DriveCmdletProvider

    protected override Collection<PSDriveInfo> InitializeDefaultDrives()
    {
        string baseDir = CertStorePathHelper.ResolveBaseDirectory();
        var driveInfo = new PSDriveInfo(
            name: "pcert",
            provider: ProviderInfo,
            root: "",
            description: "Portable certificate store backed by ~/.psign/cert-store",
            credential: null);
        var drive = new PortableCertStoreDriveInfo(driveInfo, baseDir);
        return [drive];
    }

    protected override PSDriveInfo NewDrive(PSDriveInfo drive)
    {
        if (drive is PortableCertStoreDriveInfo)
        {
            return drive;
        }

        // The Root is treated as the explicit base directory for the store.
        // We store it in BaseDirectory and set the drive Root to empty so PowerShell
        // doesn't prepend the filesystem path to provider-relative paths.
        string baseDir = string.IsNullOrWhiteSpace(drive.Root)
            ? CertStorePathHelper.ResolveBaseDirectory()
            : drive.Root;

        var newDriveInfo = new PSDriveInfo(
            name: drive.Name,
            provider: drive.Provider,
            root: "",
            description: drive.Description ?? $"Portable certificate store at {baseDir}",
            credential: drive.Credential);

        return new PortableCertStoreDriveInfo(newDriveInfo, baseDir);
    }

    protected override PSDriveInfo RemoveDrive(PSDriveInfo drive) => drive;

    #endregion

    #region ItemCmdletProvider

    protected override bool IsValidPath(string path) => true;

    protected override void GetItem(string path)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, thumbprint) = CertStorePathHelper.ParseProviderPath(path);

        switch (depth)
        {
            case 0:
                // Root — write the drive info itself
                WriteItemObject(PSDriveInfo, path, isContainer: true);
                break;
            case 1:
                // Scope level (CurrentUser / LocalMachine)
                if (scope != null)
                {
                    string scopeDir = Path.Combine(CurrentDrive.BaseDirectory, scope);
                    var item = new PSObject();
                    item.Properties.Add(new PSNoteProperty("PSChildName", scope));
                    item.Properties.Add(new PSNoteProperty("Location", scope));
                    item.Properties.Add(new PSNoteProperty("StoreDirectory", scopeDir));
                    WriteItemObject(item, path, isContainer: true);
                }
                break;
            case 2:
                // Store level
                if (scope != null && store != null)
                {
                    string normalized = CertStorePathHelper.NormalizeStoreName(store);
                    string storeDir = Path.Combine(CurrentDrive.BaseDirectory, scope, normalized);
                    var item = new PSObject();
                    item.Properties.Add(new PSNoteProperty("PSChildName", normalized));
                    item.Properties.Add(new PSNoteProperty("Name", normalized));
                    item.Properties.Add(new PSNoteProperty("Location", scope));
                    item.Properties.Add(new PSNoteProperty("StoreDirectory", storeDir));
                    int certCount = Directory.Exists(storeDir)
                        ? Directory.GetFiles(storeDir, "*.der").Length
                        : 0;
                    item.Properties.Add(new PSNoteProperty("CertificateCount", certCount));
                    WriteItemObject(item, path, isContainer: true);
                }
                break;
            case 3:
            default:
                // Certificate level
                if (scope != null && store != null && thumbprint != null)
                {
                    string normalized = CertStorePathHelper.NormalizeStoreName(store);
                    string normalThumb = CertStorePathHelper.NormalizeThumbprint(thumbprint);
                    string derPath = Path.Combine(
                        CurrentDrive.BaseDirectory, scope, normalized, normalThumb + ".der");
                    if (File.Exists(derPath))
                    {
                        var cert = CertStorePathHelper.LoadCertificate(derPath);
                        WriteItemObject(cert, path, isContainer: false);
                    }
                    else
                    {
                        WriteError(new ErrorRecord(
                            new ItemNotFoundException($"Certificate '{normalThumb}' not found in {scope}\\{normalized}."),
                            "CertificateNotFound",
                            ErrorCategory.ObjectNotFound,
                            path));
                    }
                }
                break;
        }
    }

    protected override bool ItemExists(string path)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, thumbprint) = CertStorePathHelper.ParseProviderPath(path);

        switch (depth)
        {
            case 0:
                return true;
            case 1:
                // Scopes always exist conceptually
                return scope != null;
            case 2:
                // Well-known stores always exist; custom stores require the directory
                if (scope == null || store == null) return false;
                string normalizedStore = CertStorePathHelper.NormalizeStoreName(store);
                if (CertStorePathHelper.WellKnownStores.Contains(normalizedStore))
                {
                    return true;
                }
                string storeDir = Path.Combine(CurrentDrive.BaseDirectory, scope, normalizedStore);
                return Directory.Exists(storeDir);
            case 3:
            default:
                if (scope == null || store == null || thumbprint == null) return false;
                try
                {
                    string ns = CertStorePathHelper.NormalizeStoreName(store);
                    string nt = CertStorePathHelper.NormalizeThumbprint(thumbprint);
                    string derPath = Path.Combine(CurrentDrive.BaseDirectory, scope, ns, nt + ".der");
                    return File.Exists(derPath);
                }
                catch
                {
                    return false;
                }
        }
    }

    #endregion

    #region ContainerCmdletProvider

    protected override void GetChildItems(string path, bool recurse)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, _) = CertStorePathHelper.ParseProviderPath(path);

        switch (depth)
        {
            case 0:
                // Root — list scopes
                foreach (string s in CertStorePathHelper.WellKnownScopes)
                {
                    string scopeDir = Path.Combine(CurrentDrive.BaseDirectory, s);
                    var item = new PSObject();
                    item.Properties.Add(new PSNoteProperty("PSChildName", s));
                    item.Properties.Add(new PSNoteProperty("Location", s));
                    item.Properties.Add(new PSNoteProperty("StoreDirectory", scopeDir));
                    WriteItemObject(item, MakePath(path, s), isContainer: true);
                    if (recurse)
                    {
                        GetChildItems(MakePath(path, s), true);
                    }
                }
                break;
            case 1:
                // Scope — list stores
                if (scope == null) break;
                string scopePath = Path.Combine(CurrentDrive.BaseDirectory, scope);
                var stores = GetStoresForScope(scopePath);
                foreach (string storeName in stores)
                {
                    string stDir = Path.Combine(scopePath, storeName);
                    var item = new PSObject();
                    item.Properties.Add(new PSNoteProperty("PSChildName", storeName));
                    item.Properties.Add(new PSNoteProperty("Name", storeName));
                    item.Properties.Add(new PSNoteProperty("Location", scope));
                    item.Properties.Add(new PSNoteProperty("StoreDirectory", stDir));
                    int certCount = Directory.Exists(stDir)
                        ? Directory.GetFiles(stDir, "*.der").Length
                        : 0;
                    item.Properties.Add(new PSNoteProperty("CertificateCount", certCount));
                    WriteItemObject(item, MakePath(path, storeName), isContainer: true);
                    if (recurse)
                    {
                        GetChildItems(MakePath(path, storeName), true);
                    }
                }
                break;
            case 2:
                // Store — list certificates
                if (scope == null || store == null) break;
                string normalizedStore = CertStorePathHelper.NormalizeStoreName(store);
                string storeDirectory = Path.Combine(CurrentDrive.BaseDirectory, scope, normalizedStore);
                if (!Directory.Exists(storeDirectory)) break;
                foreach (string derFile in Directory.GetFiles(storeDirectory, "*.der"))
                {
                    string thumb = Path.GetFileNameWithoutExtension(derFile);
                    try
                    {
                        var cert = CertStorePathHelper.LoadCertificate(derFile);
                        WriteItemObject(cert, MakePath(path, thumb), isContainer: false);
                    }
                    catch (Exception ex)
                    {
                        WriteWarning($"Failed to load certificate {derFile}: {ex.Message}");
                    }
                }
                break;
        }
    }

    protected override void GetChildNames(string path, ReturnContainers returnContainers)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, _) = CertStorePathHelper.ParseProviderPath(path);

        switch (depth)
        {
            case 0:
                foreach (string s in CertStorePathHelper.WellKnownScopes)
                {
                    WriteItemObject(s, MakePath(path, s), isContainer: true);
                }
                break;
            case 1:
                if (scope == null) break;
                string scopePath = Path.Combine(CurrentDrive.BaseDirectory, scope);
                foreach (string storeName in GetStoresForScope(scopePath))
                {
                    WriteItemObject(storeName, MakePath(path, storeName), isContainer: true);
                }
                break;
            case 2:
                if (scope == null || store == null) break;
                string ns = CertStorePathHelper.NormalizeStoreName(store);
                string storeDir = Path.Combine(CurrentDrive.BaseDirectory, scope, ns);
                if (!Directory.Exists(storeDir)) break;
                foreach (string derFile in Directory.GetFiles(storeDir, "*.der"))
                {
                    string thumb = Path.GetFileNameWithoutExtension(derFile);
                    WriteItemObject(thumb, MakePath(path, thumb), isContainer: false);
                }
                break;
        }
    }

    protected override bool HasChildItems(string path)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, _) = CertStorePathHelper.ParseProviderPath(path);

        switch (depth)
        {
            case 0:
                return true;
            case 1:
                return true; // scopes always have child stores (at least conceptually)
            case 2:
                if (scope == null || store == null) return false;
                string ns = CertStorePathHelper.NormalizeStoreName(store);
                string storeDir = Path.Combine(CurrentDrive.BaseDirectory, scope, ns);
                return Directory.Exists(storeDir) && Directory.GetFiles(storeDir, "*.der").Length > 0;
            default:
                return false;
        }
    }

    protected override bool IsItemContainer(string path)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        // Root (0), Scope (1), Store (2) are containers; Certificate (3+) is a leaf.
        return depth < 3;
    }

    protected override void NewItem(string path, string itemTypeName, object? newItemValue)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, thumbprint) = CertStorePathHelper.ParseProviderPath(path);

        if (depth == 2 && scope != null && store != null)
        {
            // Create a store directory
            string ns = CertStorePathHelper.NormalizeStoreName(store);
            string storeDir = Path.Combine(CurrentDrive.BaseDirectory, scope, ns);
            if (ShouldProcess(storeDir, "Create store directory"))
            {
                Directory.CreateDirectory(storeDir);
                var item = new PSObject();
                item.Properties.Add(new PSNoteProperty("PSChildName", ns));
                item.Properties.Add(new PSNoteProperty("Name", ns));
                item.Properties.Add(new PSNoteProperty("Location", scope));
                item.Properties.Add(new PSNoteProperty("StoreDirectory", storeDir));
                WriteItemObject(item, path, isContainer: true);
            }
            return;
        }

        if (depth >= 3 && scope != null && store != null)
        {
            // Import a certificate
            string ns = CertStorePathHelper.NormalizeStoreName(store);
            string storeDir = Path.Combine(CurrentDrive.BaseDirectory, scope, ns);
            byte[]? certDer = ResolveCertificateBytes(newItemValue);
            if (certDer == null)
            {
                WriteError(new ErrorRecord(
                    new ArgumentException(
                        "New-Item -Value must be an X509Certificate2, byte[] (DER), or a file path string."),
                    "InvalidCertificateValue",
                    ErrorCategory.InvalidArgument,
                    newItemValue));
                return;
            }

            string computedThumb = CertStorePathHelper.ComputeThumbprint(certDer);
            string derPath = Path.Combine(storeDir, computedThumb + ".der");

            if (ShouldProcess(derPath, "Import certificate"))
            {
                Directory.CreateDirectory(storeDir);
                File.WriteAllBytes(derPath, certDer);

                var cert = new X509Certificate2(certDer);
                WriteItemObject(cert, MakePath(path, computedThumb), isContainer: false);
            }
            return;
        }

        WriteError(new ErrorRecord(
            new InvalidOperationException("New-Item is supported at the store level (to create a store) or certificate level (to import a cert)."),
            "UnsupportedNewItemPath",
            ErrorCategory.InvalidOperation,
            path));
    }

    protected override void RemoveItem(string path, bool recurse)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, thumbprint) = CertStorePathHelper.ParseProviderPath(path);

        if (depth == 3 && scope != null && store != null && thumbprint != null)
        {
            string ns = CertStorePathHelper.NormalizeStoreName(store);
            string nt = CertStorePathHelper.NormalizeThumbprint(thumbprint);
            string derPath = Path.Combine(CurrentDrive.BaseDirectory, scope, ns, nt + ".der");
            string keyPath = Path.Combine(CurrentDrive.BaseDirectory, scope, ns, nt + ".key");

            if (!File.Exists(derPath))
            {
                WriteError(new ErrorRecord(
                    new ItemNotFoundException($"Certificate '{nt}' not found in {scope}\\{ns}."),
                    "CertificateNotFound",
                    ErrorCategory.ObjectNotFound,
                    path));
                return;
            }

            if (ShouldProcess($"{scope}\\{ns}\\{nt}", "Remove certificate"))
            {
                File.Delete(derPath);
                if (File.Exists(keyPath))
                {
                    File.Delete(keyPath);
                }
            }
            return;
        }

        if (depth == 2 && scope != null && store != null && recurse)
        {
            string ns = CertStorePathHelper.NormalizeStoreName(store);
            string storeDir = Path.Combine(CurrentDrive.BaseDirectory, scope, ns);
            if (Directory.Exists(storeDir) && ShouldProcess(storeDir, "Remove store directory"))
            {
                Directory.Delete(storeDir, recursive: true);
            }
            return;
        }

        WriteError(new ErrorRecord(
            new InvalidOperationException(
                "Remove-Item is supported for individual certificates (by thumbprint) or store directories (with -Recurse)."),
            "UnsupportedRemoveItemPath",
            ErrorCategory.InvalidOperation,
            path));
    }

    protected override void CopyItem(string path, string copyPath, bool recurse)
    {
        int depth = CertStorePathHelper.PathDepth(path);
        var (scope, store, thumbprint) = CertStorePathHelper.ParseProviderPath(path);

        if (depth != 3 || scope == null || store == null || thumbprint == null)
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException("Copy-Item is supported only for individual certificates."),
                "UnsupportedCopyItemPath",
                ErrorCategory.InvalidOperation,
                path));
            return;
        }

        string srcNs = CertStorePathHelper.NormalizeStoreName(store);
        string srcNt = CertStorePathHelper.NormalizeThumbprint(thumbprint);
        string srcDer = Path.Combine(CurrentDrive.BaseDirectory, scope, srcNs, srcNt + ".der");
        string srcKey = Path.Combine(CurrentDrive.BaseDirectory, scope, srcNs, srcNt + ".key");

        if (!File.Exists(srcDer))
        {
            WriteError(new ErrorRecord(
                new ItemNotFoundException($"Source certificate '{srcNt}' not found in {scope}\\{srcNs}."),
                "CertificateNotFound",
                ErrorCategory.ObjectNotFound,
                path));
            return;
        }

        // Determine destination
        var (destScope, destStore, _) = CertStorePathHelper.ParseProviderPath(copyPath);
        if (destScope == null || destStore == null)
        {
            WriteError(new ErrorRecord(
                new ArgumentException("Destination must be a store path (e.g., pcert:\\CurrentUser\\Root)."),
                "InvalidDestination",
                ErrorCategory.InvalidArgument,
                copyPath));
            return;
        }

        string destNs = CertStorePathHelper.NormalizeStoreName(destStore);
        string destDir = Path.Combine(CurrentDrive.BaseDirectory, destScope, destNs);
        string destDer = Path.Combine(destDir, srcNt + ".der");
        string destKey = Path.Combine(destDir, srcNt + ".key");

        if (ShouldProcess($"{scope}\\{srcNs}\\{srcNt} → {destScope}\\{destNs}", "Copy certificate"))
        {
            Directory.CreateDirectory(destDir);
            File.Copy(srcDer, destDer, overwrite: true);
            if (File.Exists(srcKey))
            {
                File.Copy(srcKey, destKey, overwrite: true);
            }

            var cert = CertStorePathHelper.LoadCertificate(destDer);
            WriteItemObject(cert, MakePath(copyPath, srcNt), isContainer: false);
        }
    }

    #endregion

    #region NavigationCmdletProvider

    protected override string GetChildName(string path)
    {
        string normalized = path.Replace('/', '\\').TrimEnd('\\');
        int lastSep = normalized.LastIndexOf('\\');
        return lastSep < 0 ? normalized : normalized[(lastSep + 1)..];
    }

    protected override string GetParentPath(string path, string? root)
    {
        string normalized = path.Replace('/', '\\').TrimEnd('\\');
        int lastSep = normalized.LastIndexOf('\\');
        if (lastSep <= 0) return "";
        return normalized[..lastSep];
    }

    protected override string MakePath(string parent, string child)
    {
        if (string.IsNullOrEmpty(parent)) return child;
        if (string.IsNullOrEmpty(child)) return parent;
        string sep = System.IO.Path.DirectorySeparatorChar.ToString();
        return parent.TrimEnd('\\', '/') + sep + child.TrimStart('\\', '/');
    }

    protected override string NormalizeRelativePath(string path, string basePath)
    {
        return path.Replace('/', '\\').Trim('\\');
    }

    #endregion

    #region Helpers

    private string[] GetStoresForScope(string scopeDirectory)
    {
        // Start with well-known stores, add any custom store directories that exist
        var stores = new HashSet<string>(CertStorePathHelper.WellKnownStores);
        if (Directory.Exists(scopeDirectory))
        {
            foreach (string dir in Directory.GetDirectories(scopeDirectory))
            {
                stores.Add(Path.GetFileName(dir));
            }
        }
        return [.. stores.Order()];
    }

    private static byte[]? ResolveCertificateBytes(object? value)
    {
        // Unwrap PSObject if necessary
        if (value is PSObject psObj)
        {
            value = psObj.BaseObject;
        }

        if (value is X509Certificate2 cert)
        {
            return cert.RawData;
        }

        if (value is byte[] bytes)
        {
            return bytes;
        }

        if (value is string str)
        {
            // Try as file path first
            if (File.Exists(str))
            {
                return File.ReadAllBytes(str);
            }

            // Try as base64
            try
            {
                return Convert.FromBase64String(str);
            }
            catch
            {
                // Try as PEM
                if (str.Contains("-----BEGIN CERTIFICATE-----"))
                {
                    var tempCert = new X509Certificate2(
                        System.Text.Encoding.ASCII.GetBytes(str));
                    byte[] raw = tempCert.RawData;
                    tempCert.Dispose();
                    return raw;
                }
            }
        }

        return null;
    }

    #endregion
}
