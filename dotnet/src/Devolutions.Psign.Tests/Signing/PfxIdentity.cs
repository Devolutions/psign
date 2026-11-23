using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>
/// A test PFX (by default the vendored Devolutions test PFX shared with the Rust tool,
/// <c>tests/fixtures/devolutions-authenticode</c>) loaded the way Rust <c>parse_pfx_identity</c> does: the certificate with
/// a private key is the signer, every other distinct certificate is a chain certificate.
/// </summary>
internal sealed class PfxIdentity : IDisposable
{
    public const string Password = "CodeSign123!";

    public PfxIdentity(string? pfxPath = null, string password = Password)
    {
        PfxPath = pfxPath ?? Fixtures.Path("devolutions-authenticode/authenticode-test-cert.pfx");
        PfxPasswordText = password;
        var collection = X509CertificateLoaderCompat.LoadPkcs12Collection(File.ReadAllBytes(PfxPath), password);
        var signer = collection.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
        Key = signer.GetRSAPrivateKey()!;
        Signer = CertificateInfo.Parse(signer.RawData);
        Chain = collection.Cast<X509Certificate2>()
            .Where(c => !c.RawData.AsSpan().SequenceEqual(signer.RawData))
            .Select(c => CertificateInfo.Parse(c.RawData))
            .DistinctBy(c => Convert.ToHexString(c.RawData))
            .ToList();
        foreach (var c in collection)
        {
            c.Dispose();
        }
    }

    /// <summary>The vendored Devolutions test PFX.</summary>
    public static PfxIdentity Default() => new();

    public string PfxPath { get; }

    public string PfxPasswordText { get; }

    public RSA Key { get; }

    public CertificateInfo Signer { get; }

    public List<CertificateInfo> Chain { get; }

    public void Dispose() => Key.Dispose();
}
