using System.Security.Cryptography.X509Certificates;

namespace Devolutions.Psign.Core.X509;

/// <summary>Cross-target certificate loading (uses <c>X509CertificateLoader</c> on .NET 9+).</summary>
public static class X509CertificateLoaderCompat
{
    /// <summary>Load a single DER or PEM certificate.</summary>
    public static X509Certificate2 LoadCertificate(byte[] data)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(data);
#else
        return new X509Certificate2(data);
#endif
    }

    /// <summary>Load a PKCS#12 / PFX blob.</summary>
    public static X509Certificate2 LoadPkcs12(byte[] data, string? password, X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet)
    {
        if (OperatingSystem.IsMacOS())
        {
            flags &= ~X509KeyStorageFlags.EphemeralKeySet;
        }

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(data, password, flags);
#else
        return new X509Certificate2(data, password, flags);
#endif
    }

    /// <summary>Load every certificate in a PKCS#12 / PFX blob.</summary>
    public static X509Certificate2Collection LoadPkcs12Collection(byte[] data, string? password, X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet)
    {
        if (OperatingSystem.IsMacOS())
        {
            flags &= ~X509KeyStorageFlags.EphemeralKeySet;
        }

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12Collection(data, password, flags);
#else
        var c = new X509Certificate2Collection();
        c.Import(data, password, flags);
        return c;
#endif
    }
}
