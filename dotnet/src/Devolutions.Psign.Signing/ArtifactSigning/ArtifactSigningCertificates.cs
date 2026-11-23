using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Keys;

namespace Devolutions.Psign.Signing.ArtifactSigning;

/// <summary>
/// Decodes the Azure Artifact Signing <c>signingCertificate</c> into the signer certificate and chain (port of Rust
/// <c>pkcs7::parse_artifact_signing_certificates</c>). The service may return a PEM / DER certificate, a PKCS#7
/// certificate bag, or base64 text wrapping either representation.
/// </summary>
public static class ArtifactSigningCertificates
{
    private const int MaxBase64Depth = 4;
    private const string PemBegin = "-----BEGIN CERTIFICATE-----";
    private const string PemEnd = "-----END CERTIFICATE-----";

    /// <summary>Signer certificate and remaining chain certificates.</summary>
    public static (CertificateInfo Signer, List<CertificateInfo> Chain) Parse(byte[] bytes) => Parse(bytes, 0);

    private static (CertificateInfo Signer, List<CertificateInfo> Chain) Parse(byte[] bytes, int base64Depth)
    {
        var text = TryUtf8(bytes);
        if (text is not null && text.Contains(PemBegin, StringComparison.Ordinal))
        {
            var certs = new List<CertificateInfo>();
            var rest = text;
            int start;
            while ((start = rest.IndexOf(PemBegin, StringComparison.Ordinal)) >= 0)
            {
                rest = rest[start..];
                var end = rest.IndexOf(PemEnd, StringComparison.Ordinal);
                if (end < 0)
                {
                    throw new PsignException("unterminated PEM certificate in Artifact Signing signingCertificate");
                }

                end += PemEnd.Length;
                try
                {
                    certs.Add(CertificateLoader.ParseCertificate(Encoding.UTF8.GetBytes(rest[..end])));
                }
                catch (PsignException e)
                {
                    throw new PsignException("parse Artifact Signing PEM certificate", e);
                }

                rest = rest[end..];
            }

            try
            {
                return SignerAndChainFromCertificateBag(certs);
            }
            catch (PsignException e)
            {
                throw new PsignException("select signer from Artifact Signing PEM signingCertificate", e);
            }
        }

        if (text is not null)
        {
            var compact = new string(text.Where(c => c is not (' ' or '\t' or '\n' or '\r' or '\f')).ToArray());
            if (compact.Length > 0 && compact.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='))
            {
                byte[] decoded;
                try
                {
                    decoded = Convert.FromBase64String(compact);
                }
                catch (FormatException e)
                {
                    throw new PsignException("decode nested base64 Artifact Signing signingCertificate", new PsignException(e.Message));
                }

                if (base64Depth >= MaxBase64Depth)
                {
                    throw new PsignException("Artifact Signing signingCertificate has too many nested base64 layers");
                }

                return Parse(decoded, base64Depth + 1);
            }
        }

        PsignException derError;
        try
        {
            return (CertificateLoader.ParseCertificate(bytes), []);
        }
        catch (PsignException e)
        {
            derError = new PsignException("parse Artifact Signing DER signing certificate", e);
        }

        PsignException pkcs7Error;
        try
        {
            return Pkcs7SignerAndChain(bytes);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException)
        {
            pkcs7Error = new PsignException("parse Artifact Signing PKCS#7 signingCertificate bundle", e);
        }

        throw new PsignException($"{derError.FullMessage}; {pkcs7Error.FullMessage}");
    }

    /// <summary>
    /// Primary signer certificate (resolved from the first <c>SignerInfo.sid</c>) plus remaining certificates of a PKCS#7
    /// (Rust <c>parse_pkcs7_signer_and_chain_certificates</c>).
    /// </summary>
    public static (CertificateInfo Signer, List<CertificateInfo> Chain) Pkcs7SignerAndChain(byte[] pkcs7Der)
    {
        var sd = CmsSignedData.Parse(pkcs7Der);
        if (sd.Certificates is null)
        {
            throw new PsignException("SignedData has no certificates");
        }

        var certs = sd.GetCertificates();
        if (sd.SignerInfos.Count > 0)
        {
            CertificateInfo signer;
            try
            {
                signer = sd.CertificateForSigner(sd.SignerInfos[0]);
            }
            catch (PsignException e)
            {
                throw new PsignException("resolve signer certificate from SignedData", e);
            }

            return (signer, certs.Where(c => !c.SameIssuerAndSerial(signer)).ToList());
        }

        return SignerAndChainFromCertificateBag(certs);
    }

    private static (CertificateInfo Signer, List<CertificateInfo> Chain) SignerAndChainFromCertificateBag(List<CertificateInfo> certs)
    {
        var signer = SelectCertificateBagSigner(certs);
        return (signer, certs.Where(c => !c.SameIssuerAndSerial(signer)).ToList());
    }

    private static CertificateInfo SelectCertificateBagSigner(List<CertificateInfo> certs)
    {
        if (certs.Count == 0)
        {
            throw new PsignException("SignedData has no X.509 certificates");
        }

        if (certs.Count == 1)
        {
            return certs[0];
        }

        var leaves = certs.Where(c => !IssuesAnother(c, certs)).ToList();
        var codeSigningLeaves = leaves.Where(HasCodeSigningEku).ToList();
        if (codeSigningLeaves.Count == 1)
        {
            return codeSigningLeaves[0];
        }

        if (leaves.Count == 1)
        {
            return leaves[0];
        }

        var nonCa = certs.Where(c => !IsCa(c) && HasCodeSigningEku(c)).ToList();
        if (nonCa.Count == 1)
        {
            return nonCa[0];
        }

        throw new PsignException("PKCS#7 certificate bag has no SignerInfo and signer certificate is ambiguous");
    }

    private static bool IssuesAnother(CertificateInfo candidate, List<CertificateInfo> certs) =>
        certs.Any(other => !candidate.SameIssuerAndSerial(other) && other.Issuer.AsSpan().SequenceEqual(candidate.Subject));

    // Rust x509_cert_is_ca / x509_cert_has_code_signing_eku treat extension parse failures as "not asserted".
    private static bool IsCa(CertificateInfo cert)
    {
        try
        {
            return cert.IsCa;
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            return false;
        }
    }

    private static bool HasCodeSigningEku(CertificateInfo cert)
    {
        try
        {
            return cert.ExtendedKeyUsages?.Contains(Oids.EkuCodeSigning) == true;
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            return false;
        }
    }

    private static string? TryUtf8(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }
}
