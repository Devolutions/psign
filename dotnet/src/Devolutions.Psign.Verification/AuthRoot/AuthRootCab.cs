using Devolutions.Psign.Core;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Verification.Picky;

namespace Devolutions.Psign.Verification.AuthRoot;

/// <summary>Extract root certificates and CTL thumbprints from <c>authrootstl</c>-style CAB files (Rust <c>authroot_cab.rs</c>).</summary>
public static class AuthRootCab
{
    /// <summary>Returns embedded certificates plus CTL <c>SubjectIdentifier</c> SHA-1 entries harvested from <c>*.stl</c> members.</summary>
    public static (List<CertificateInfo> Certs, List<byte[]> CtlThumbs) IngestAuthRootCabBytes(byte[] cabBytes)
    {
        CabinetReader cab;
        try
        {
            cab = CabinetReader.Open(cabBytes);
        }
        catch (Exception e) when (e is InvalidDataException or EndOfStreamException or OverflowException)
        {
            throw new PsignException($"CAB open failed: {e.Message}");
        }

        var names = cab.Files.Select(f => f.Name).Distinct().ToList();
        names.Sort(StringComparer.Ordinal);
        var certs = new List<CertificateInfo>();
        var thumbs = new List<byte[]>();
        foreach (var name in names)
        {
            if (!name.ToLowerInvariant().EndsWith(".stl", StringComparison.Ordinal))
            {
                continue;
            }

            byte[] buf;
            try
            {
                buf = cab.ReadFile(name);
            }
            catch (Exception e) when (e is InvalidDataException or EndOfStreamException or FileNotFoundException or OverflowException)
            {
                throw new PsignException($"CAB read_file {name}: {e.Message}");
            }

            certs.AddRange(CertsFromMaybePkcs7Der(buf));
            thumbs.AddRange(AuthRootCtl.CtlSubjectSha1ThumbprintsFromStlBytes(buf));
        }

        return (certs, AuthRootCtl.SortDedup(thumbs));
    }

    /// <summary>Certificates only (no CTL thumbprints) from a CAB file on disk.</summary>
    public static List<CertificateInfo> CertsFromAuthRootCab(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw PsignException.Context($"open CAB {path}", e);
        }

        return IngestAuthRootCabBytes(bytes).Certs;
    }

    /// <summary>
    /// picky <c>Pkcs7::from_der(..).decode_certificates()</c>; empty when picky would reject the blob. picky is built
    /// without its <c>ctl</c> feature in Rust, so CTL <c>eContent</c> (a SEQUENCE, not an OCTET STRING) is rejected.
    /// </summary>
    private static List<CertificateInfo> CertsFromMaybePkcs7Der(byte[] bytes) =>
        PickyAuthenticode.TryParsePkcs7(bytes)?.GetCertificates() ?? [];
}
