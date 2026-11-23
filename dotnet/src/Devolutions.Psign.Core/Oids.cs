namespace Devolutions.Psign.Core;

/// <summary>Object identifiers used across psign (dotted-decimal strings).</summary>
public static class Oids
{
    // Digest algorithms
    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    public const string Md5 = "1.2.840.113549.2.5";

    // Signature algorithms
    public const string RsaEncryption = "1.2.840.113549.1.1.1";
    public const string Md5WithRsa = "1.2.840.113549.1.1.4";
    public const string Sha1WithRsa = "1.2.840.113549.1.1.5";
    public const string RsaPss = "1.2.840.113549.1.1.10";
    public const string Sha256WithRsa = "1.2.840.113549.1.1.11";
    public const string Sha384WithRsa = "1.2.840.113549.1.1.12";
    public const string Sha512WithRsa = "1.2.840.113549.1.1.13";
    public const string EcPublicKey = "1.2.840.10045.2.1";
    public const string EcdsaWithSha1 = "1.2.840.10045.4.1";
    public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    public const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";
    public const string EcdsaWithSha512 = "1.2.840.10045.4.3.4";

    // PKCS#7 / CMS content types
    public const string Pkcs7Data = "1.2.840.113549.1.7.1";
    public const string Pkcs7SignedData = "1.2.840.113549.1.7.2";
    public const string TstInfo = "1.2.840.113549.1.9.16.1.4";

    // PKCS#9 attributes
    public const string Pkcs9ContentType = "1.2.840.113549.1.9.3";
    public const string Pkcs9MessageDigest = "1.2.840.113549.1.9.4";
    public const string Pkcs9SigningTime = "1.2.840.113549.1.9.5";
    public const string Pkcs9CounterSignature = "1.2.840.113549.1.9.6";
    public const string Pkcs9Rfc3161TimestampToken = "1.2.840.113549.1.9.16.2.14";
    public const string Pkcs9CommitmentTypeIndication = "1.2.840.113549.1.9.16.2.16";
    public const string Pkcs9SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    public const string Pkcs9SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    public const string CommitmentTypeProofOfOrigin = "1.2.840.113549.1.9.16.6.1";
    public const string CommitmentTypeProofOfReceipt = "1.2.840.113549.1.9.16.6.2";

    // Microsoft Authenticode
    public const string SpcIndirectData = "1.3.6.1.4.1.311.2.1.4";
    public const string SpcStatementType = "1.3.6.1.4.1.311.2.1.11";
    public const string SpcSpOpusInfo = "1.3.6.1.4.1.311.2.1.12";
    public const string SpcPeImageData = "1.3.6.1.4.1.311.2.1.15";
    public const string SpcIndividualCodeSigning = "1.3.6.1.4.1.311.2.1.21";
    public const string SpcCommercialCodeSigning = "1.3.6.1.4.1.311.2.1.22";
    public const string SpcCabData = "1.3.6.1.4.1.311.2.1.25";
    public const string SpcLink = "1.3.6.1.4.1.311.2.1.28";
    public const string SpcSigInfo = "1.3.6.1.4.1.311.2.1.30";
    public const string SpcPeImagePageHashesV1 = "1.3.6.1.4.1.311.2.3.1";
    public const string SpcPeImagePageHashesV2 = "1.3.6.1.4.1.311.2.3.2";
    public const string SpcNestedSignature = "1.3.6.1.4.1.311.2.4.1";
    public const string MsRfc3161TimestampToken = "1.3.6.1.4.1.311.3.3.1";
    public const string MsCtl = "1.3.6.1.4.1.311.10.1";
    public const string MsCatalogList = "1.3.6.1.4.1.311.12.1.1";
    public const string MsCatalogListMember = "1.3.6.1.4.1.311.12.1.2";
    public const string MsCatalogListMemberV2 = "1.3.6.1.4.1.311.12.1.3";
    public const string MsCatNameValue = "1.3.6.1.4.1.311.12.2.1";
    public const string MsCatMemberInfo = "1.3.6.1.4.1.311.12.2.2";
    public const string MsCatMemberInfo2 = "1.3.6.1.4.1.311.12.2.3";
    public const string MsCertTrustListSigning = "1.3.6.1.4.1.311.10.3.1";
    public const string MsTimeStampSigning = "1.3.6.1.4.1.311.10.3.2";
    public const string MsLifetimeSigning = "1.3.6.1.4.1.311.10.3.13";
    public const string MsRootListSigner = "1.3.6.1.4.1.311.10.3.9";

    // X.509 extensions
    public const string SubjectKeyIdentifier = "2.5.29.14";
    public const string KeyUsage = "2.5.29.15";
    public const string SubjectAltName = "2.5.29.17";
    public const string BasicConstraints = "2.5.29.19";
    public const string CrlDistributionPoints = "2.5.29.31";
    public const string CertificatePolicies = "2.5.29.32";
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    public const string ExtendedKeyUsage = "2.5.29.37";
    public const string AuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";

    // EKUs
    public const string EkuServerAuth = "1.3.6.1.5.5.7.3.1";
    public const string EkuClientAuth = "1.3.6.1.5.5.7.3.2";
    public const string EkuCodeSigning = "1.3.6.1.5.5.7.3.3";
    public const string EkuTimeStamping = "1.3.6.1.5.5.7.3.8";
    public const string AnyExtendedKeyUsage = "2.5.29.37.0";
}
