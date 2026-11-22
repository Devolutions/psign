using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Keys;

namespace Devolutions.Psign.Signing.Code;

/// <summary>
/// Decode Azure Artifact Signing <c>signingCertificate</c> bytes (PEM / DER certificate, PKCS#7 certificate bag, or base64
/// text wrapping either) into the signer certificate and chain (Rust <c>pkcs7::parse_artifact_signing_certificates</c>).
/// </summary>
internal static class ArtifactSigningCertificates
{
    private const int MaxBase64Depth = 4;
    private const string BeginCert = "-----BEGIN CERTIFICATE-----";
    private const string EndCert = "-----END CERTIFICATE-----";
    private const string CodeSigningEku = "1.3.6.1.5.5.7.3.3";

    public static (CertificateInfo Signer, List<CertificateInfo> Chain) Parse(byte[] bytes) => ParseInner(bytes, 0);

    private static (CertificateInfo Signer, List<CertificateInfo> Chain) ParseInner(byte[] bytes, int depth)
    {
        var text = RustText.TryFromUtf8(bytes);
        if (text is not null && text.Contains(BeginCert, StringComparison.Ordinal))
        {
            var certs = new List<CertificateInfo>();
            var rest = text;
            int start;
            while ((start = rest.IndexOf(BeginCert, StringComparison.Ordinal)) >= 0)
            {
                rest = rest[start..];
                int end = rest.IndexOf(EndCert, StringComparison.Ordinal);
                if (end < 0)
                {
                    throw new PsignException("unterminated PEM certificate in Artifact Signing signingCertificate");
                }

                end += EndCert.Length;
                try
                {
                    certs.Add(SigningMaterialLoader.ParseCertificate(System.Text.Encoding.UTF8.GetBytes(rest[..end])));
                }
                catch (PsignException e)
                {
                    throw new PsignException("parse Artifact Signing PEM certificate", e);
                }

                rest = rest[end..];
            }

            try
            {
                return SignerAndChainFromBag(certs);
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
                    throw new PsignException("decode nested base64 Artifact Signing signingCertificate", e);
                }

                if (depth >= MaxBase64Depth)
                {
                    throw new PsignException("Artifact Signing signingCertificate has too many nested base64 layers");
                }

                return ParseInner(decoded, depth + 1);
            }
        }

        string derError;
        try
        {
            return (SigningMaterialLoader.ParseCertificate(bytes), []);
        }
        catch (PsignException e)
        {
            derError = PsignException.Render(new PsignException("parse Artifact Signing DER signing certificate", e));
        }

        string pkcs7Error;
        try
        {
            return Pkcs7SignerAndChain(bytes);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            pkcs7Error = PsignException.Render(new PsignException("parse Artifact Signing PKCS#7 signingCertificate bundle", e));
        }

        throw new PsignException($"{derError}; {pkcs7Error}");
    }

    private static (CertificateInfo, List<CertificateInfo>) Pkcs7SignerAndChain(byte[] der)
    {
        var sd = CmsSignedData.Parse(der);
        var certs = (sd.Certificates ?? throw new PsignException("SignedData has no certificates"))
            .Select(c => CertificateInfo.TryParse(c))
            .Where(c => c is not null)
            .Select(c => c!)
            .ToList();
        if (sd.SignerInfos.Count > 0)
        {
            var sid = sd.SignerInfos[0];
            var signer = certs.FirstOrDefault(c => sid.MatchesCertificate(c))
                ?? throw new PsignException("resolve signer certificate from SignedData", new PsignException("signer certificate not found in SignedData"));
            return (signer, certs.Where(c => !c.SameIssuerAndSerial(signer)).ToList());
        }

        return SignerAndChainFromBag(certs);
    }

    private static (CertificateInfo, List<CertificateInfo>) SignerAndChainFromBag(List<CertificateInfo> certs)
    {
        var signer = SelectBagSigner(certs);
        return (signer, certs.Where(c => !c.SameIssuerAndSerial(signer)).ToList());
    }

    private static CertificateInfo SelectBagSigner(List<CertificateInfo> certs)
    {
        if (certs.Count == 0)
        {
            throw new PsignException("SignedData has no X.509 certificates");
        }

        if (certs.Count == 1)
        {
            return certs[0];
        }

        var leaves = certs.Where(c => !certs.Any(o => !o.SameIssuerAndSerial(c) && o.Issuer.AsSpan().SequenceEqual(c.Subject))).ToList();
        var codeSigningLeaves = leaves.Where(HasCodeSigningEku).ToList();
        if (codeSigningLeaves.Count == 1)
        {
            return codeSigningLeaves[0];
        }

        if (leaves.Count == 1)
        {
            return leaves[0];
        }

        var nonCa = certs.Where(c => !SafeIsCa(c) && HasCodeSigningEku(c)).ToList();
        if (nonCa.Count == 1)
        {
            return nonCa[0];
        }

        throw new PsignException("PKCS#7 certificate bag has no SignerInfo and signer certificate is ambiguous");
    }

    private static bool SafeIsCa(CertificateInfo c)
    {
        try
        {
            return c.IsCa;
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            return false;
        }
    }

    private static bool HasCodeSigningEku(CertificateInfo c)
    {
        try
        {
            return c.ExtendedKeyUsages?.Contains(CodeSigningEku) == true;
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
        {
            return false;
        }
    }
}
