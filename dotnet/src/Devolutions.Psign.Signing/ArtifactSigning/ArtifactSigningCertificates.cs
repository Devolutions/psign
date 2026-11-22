using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Keys;

namespace Devolutions.Psign.Signing.ArtifactSigning;

/// <summary>
/// Decoding of the Azure Artifact Signing <c>signingCertificate</c> value into the signer certificate and chain (port of
/// Rust <c>pkcs7::parse_artifact_signing_certificates</c> and its certificate-bag signer selection).
/// </summary>
public static class ArtifactSigningCertificates
{
    private const int MaxBase64Depth = 4;
    private const string BeginCertificate = "-----BEGIN CERTIFICATE-----";
    private const string EndCertificate = "-----END CERTIFICATE-----";

    /// <summary>
    /// Decode <c>signingCertificate</c> bytes: a PEM/DER certificate, a PKCS#7 certificate bag, or base64 text wrapping
    /// either representation (at most four nested base64 layers).
    /// </summary>
    public static (CertificateInfo Signer, List<CertificateInfo> Chain) Parse(byte[] bytes) => ParseInner(bytes, 0);

    private static (CertificateInfo Signer, List<CertificateInfo> Chain) ParseInner(byte[] bytes, int base64Depth)
    {
        var text = RustText.TryFromUtf8(bytes);
        if (text is not null && text.Contains(BeginCertificate, StringComparison.Ordinal))
        {
            var certs = new List<CertificateInfo>();
            var rest = text;
            int start;
            while ((start = rest.IndexOf(BeginCertificate, StringComparison.Ordinal)) >= 0)
            {
                rest = rest[start..];
                int end = rest.IndexOf(EndCertificate, StringComparison.Ordinal);
                if (end < 0)
                {
                    throw new PsignException("unterminated PEM certificate in Artifact Signing signingCertificate");
                }

                end += EndCertificate.Length;
                try
                {
                    certs.Add(SigningMaterialLoader.ParseCertificate(Encoding.UTF8.GetBytes(rest[..end])));
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
            var compact = new string(text.Where(c => !(c is ' ' or '\t' or '\n' or '\r' or '\f')).ToArray());
            if (compact.Length > 0 && compact.All(c => RustText.IsAsciiAlphanumeric(c) || c is '+' or '/' or '='))
            {
                byte[] decoded;
                try
                {
                    decoded = Base64Standard.Decode(compact);
                }
                catch (FormatException e)
                {
                    throw new PsignException("decode nested base64 Artifact Signing signingCertificate", e);
                }

                if (base64Depth >= MaxBase64Depth)
                {
                    throw new PsignException("Artifact Signing signingCertificate has too many nested base64 layers");
                }

                return ParseInner(decoded, base64Depth + 1);
            }
        }

        PsignException derError;
        try
        {
            return (SigningMaterialLoader.ParseCertificate(bytes), []);
        }
        catch (PsignException e)
        {
            derError = new PsignException("parse Artifact Signing DER signing certificate", e);
        }

        PsignException pkcs7Error;
        try
        {
            return SignerAndChainFromPkcs7(bytes);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException)
        {
            pkcs7Error = new PsignException("parse Artifact Signing PKCS#7 signingCertificate bundle", e);
        }

        throw new PsignException($"{derError.FullMessage}; {pkcs7Error.FullMessage}");
    }

    /// <summary>
    /// Primary signer (resolved from the first <c>SignerInfo.sid</c>, or by bag topology without signer infos) plus the other
    /// certificates (Rust <c>parse_pkcs7_signer_and_chain_certificates</c>).
    /// </summary>
    public static (CertificateInfo Signer, List<CertificateInfo> Chain) SignerAndChainFromPkcs7(byte[] pkcs7Der)
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

        var leafCandidates = certs.Where(c => !IssuesAnotherCert(c, certs)).ToList();
        if (OnlyCandidate(leafCandidates.Where(HasCodeSigningEku).ToList()) is { } codeSigningLeaf)
        {
            return codeSigningLeaf;
        }

        if (OnlyCandidate(leafCandidates) is { } leaf)
        {
            return leaf;
        }

        if (OnlyCandidate(certs.Where(c => !IsCa(c) && HasCodeSigningEku(c)).ToList()) is { } nonCa)
        {
            return nonCa;
        }

        throw new PsignException("PKCS#7 certificate bag has no SignerInfo and signer certificate is ambiguous");
    }

    private static CertificateInfo? OnlyCandidate(List<CertificateInfo> candidates) => candidates.Count == 1 ? candidates[0] : null;

    private static bool IssuesAnotherCert(CertificateInfo candidate, List<CertificateInfo> certs) =>
        certs.Any(other => !candidate.SameIssuerAndSerial(other) && other.Issuer.AsSpan().SequenceEqual(candidate.Subject));

    // Extension parse failures count as "not asserted" (Rust x509_cert_is_ca / x509_cert_has_code_signing_eku).
    private static bool IsCa(CertificateInfo cert)
    {
        try
        {
            return cert.IsCa;
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException)
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
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
    }
}
