using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.Psign.PowerShell.Provider;

/// <summary>
/// Shared helpers for the portable file-based certificate store.
/// Store layout: &lt;base&gt;/&lt;Scope&gt;/&lt;Store&gt;/&lt;SHA1_THUMBPRINT&gt;.der (+ optional .key)
/// </summary>
internal static class CertStorePathHelper
{
    internal static readonly string[] WellKnownScopes = ["CurrentUser", "LocalMachine"];

    internal static readonly string[] WellKnownStores = ["MY", "Root", "CA", "Trust", "TrustedPublisher", "Disallowed"];

    /// <summary>
    /// Resolve the base directory for the portable certificate store.
    /// Priority: explicit parameter → PSIGN_CERT_STORE env → ~/.psign/cert-store
    /// </summary>
    internal static string ResolveBaseDirectory(string? explicitPath = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return explicitPath;
        }

        string? envStore = Environment.GetEnvironmentVariable("PSIGN_CERT_STORE");
        if (!string.IsNullOrWhiteSpace(envStore))
        {
            return envStore;
        }

        string? home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetEnvironmentVariable("USERPROFILE");
        if (string.IsNullOrWhiteSpace(home))
        {
            throw new PSInvalidOperationException(
                "Cannot resolve the default portable cert-store path. Set PSIGN_CERT_STORE or pass an explicit root.");
        }

        return Path.Combine(home, ".psign", "cert-store");
    }

    /// <summary>
    /// Normalize a store name to its canonical form.
    /// </summary>
    internal static string NormalizeStoreName(string storeName)
    {
        string trimmed = storeName.Trim();
        if (trimmed.Length == 0 || trimmed.Contains('/') || trimmed.Contains('\\') || trimmed.Contains('\0'))
        {
            throw new PSInvalidOperationException(
                "Portable certificate store name must not be empty or contain path separators.");
        }

        return trimmed.ToLowerInvariant() switch
        {
            "my" => "MY",
            "root" => "Root",
            "ca" => "CA",
            "trust" => "Trust",
            "trustedpublisher" => "TrustedPublisher",
            "disallowed" => "Disallowed",
            _ => trimmed,
        };
    }

    /// <summary>
    /// Normalize and validate a SHA-1 thumbprint string (40 hex chars, uppercase).
    /// </summary>
    internal static string NormalizeThumbprint(string thumbprint)
    {
        string clean = new(thumbprint.Where(c => c != ':' && !char.IsWhiteSpace(c)).ToArray());
        if (clean.Length != 40 || clean.Any(c => !Uri.IsHexDigit(c)))
        {
            throw new PSInvalidOperationException("SHA1 thumbprint must be 40 hexadecimal characters.");
        }

        return clean.ToUpperInvariant();
    }

    /// <summary>
    /// Read a PKCS#8 PEM private key file and return the DER bytes.
    /// </summary>
    internal static byte[] ReadPkcs8PrivateKeyDer(string keyPath)
    {
        string text = File.ReadAllText(keyPath);
        const string begin = "-----BEGIN PRIVATE KEY-----";
        const string end = "-----END PRIVATE KEY-----";
        int beginIndex = text.IndexOf(begin, StringComparison.Ordinal);
        int endIndex = text.IndexOf(end, StringComparison.Ordinal);
        if (beginIndex < 0 || endIndex < 0 || endIndex <= beginIndex)
        {
            throw new PSInvalidOperationException(
                $"Portable cert-store key '{keyPath}' must be unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY).");
        }

        int base64Start = beginIndex + begin.Length;
        string base64 = text[base64Start..endIndex];
        string compact = new(base64.Where(c => !char.IsWhiteSpace(c)).ToArray());
        try
        {
            return Convert.FromBase64String(compact);
        }
        catch (FormatException ex)
        {
            throw new PSInvalidOperationException(
                $"Portable cert-store key '{keyPath}' contains invalid PKCS#8 PEM base64.", ex);
        }
    }

    /// <summary>
    /// Compute the SHA-1 thumbprint of a DER-encoded certificate (uppercase hex).
    /// </summary>
    internal static string ComputeThumbprint(byte[] derBytes)
    {
        byte[] hash = SHA1.HashData(derBytes);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// Load an X509Certificate2 from a .der file, optionally associating a private key.
    /// </summary>
    internal static X509Certificate2 LoadCertificate(string derPath)
    {
        byte[] certBytes = File.ReadAllBytes(derPath);
        var cert = new X509Certificate2(certBytes);
        string keyPath = Path.ChangeExtension(derPath, ".key");
        if (File.Exists(keyPath))
        {
            try
            {
                byte[] keyDer = ReadPkcs8PrivateKeyDer(keyPath);
                using var certWithKey = cert;
                using RSA rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(keyDer, out _);
                cert = certWithKey.CopyWithPrivateKey(rsa);
            }
            catch (CryptographicException)
            {
                // RSA import failed — try ECDSA
                try
                {
                    byte[] keyDer = ReadPkcs8PrivateKeyDer(keyPath);
                    using var certWithKey = cert;
                    using ECDsa ecdsa = ECDsa.Create();
                    ecdsa.ImportPkcs8PrivateKey(keyDer, out _);
                    cert = certWithKey.CopyWithPrivateKey(ecdsa);
                }
                catch
                {
                    // If both fail, return the cert without the private key
                }
            }
        }
        return cert;
    }

    /// <summary>
    /// Check if a .key file exists alongside a .der file.
    /// </summary>
    internal static bool HasPrivateKey(string derPath)
    {
        return File.Exists(Path.ChangeExtension(derPath, ".key"));
    }

    /// <summary>
    /// Parse a provider-relative path into its components.
    /// Returns (scope, storeName, thumbprint) — any component may be null if the path is shorter.
    /// </summary>
    internal static (string? Scope, string? Store, string? Thumbprint) ParseProviderPath(string path)
    {
        // Normalize separators and trim
        string normalized = path.Replace('/', '\\').Trim('\\').Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            return (null, null, null);
        }

        string[] parts = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        string? scope = parts.Length >= 1 ? parts[0] : null;
        string? store = parts.Length >= 2 ? parts[1] : null;
        string? thumbprint = parts.Length >= 3 ? parts[2] : null;
        return (scope, store, thumbprint);
    }

    /// <summary>
    /// Determine the depth of a provider-relative path (0=root, 1=scope, 2=store, 3=cert).
    /// </summary>
    internal static int PathDepth(string path)
    {
        string normalized = path.Replace('/', '\\').Trim('\\').Trim();
        if (string.IsNullOrEmpty(normalized))
        {
            return 0;
        }

        return normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries).Length;
    }

    /// <summary>
    /// Load a certificate and its private key DER bytes from the portable store by thumbprint.
    /// </summary>
    internal static (X509Certificate2 Certificate, byte[]? PrivateKeyDer) LoadCertificateAndKey(
        string? explicitBaseDir, string scope, string storeName, string thumbprint)
    {
        string baseDir = ResolveBaseDirectory(explicitBaseDir);
        string normalizedStore = NormalizeStoreName(storeName);
        string normalizedThumb = NormalizeThumbprint(thumbprint);
        string derPath = Path.Combine(baseDir, scope, normalizedStore, normalizedThumb + ".der");

        if (!File.Exists(derPath))
        {
            throw new FileNotFoundException(
                $"Certificate '{normalizedThumb}' not found in {scope}\\{normalizedStore}.", derPath);
        }

        byte[] certBytes = File.ReadAllBytes(derPath);
        var cert = new X509Certificate2(certBytes);

        string keyPath = Path.ChangeExtension(derPath, ".key");
        byte[]? keyDer = null;
        if (File.Exists(keyPath))
        {
            keyDer = ReadPkcs8PrivateKeyDer(keyPath);
        }

        return (cert, keyDer);
    }
}
