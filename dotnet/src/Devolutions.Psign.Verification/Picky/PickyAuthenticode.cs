using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.X509;

namespace Devolutions.Psign.Verification.Picky;

/// <summary>
/// Port of the parts of <c>picky::x509::pkcs7::authenticode::AuthenticodeSignature</c> used by portable trust:
/// structural acceptance (<c>from_der</c>), <c>signing_certificate</c>, and the
/// <c>authenticode_verifier().require_basic_authenticode_validation(..).ignore_chain_check()</c> checks.
/// </summary>
internal sealed class PickyAuthenticode
{
    private const string SpcSipInfo = "1.3.6.1.4.1.311.2.1.30";

    private PickyAuthenticode(CmsSignedData sd)
    {
        SignedData = sd;
    }

    public CmsSignedData SignedData { get; }

    /// <summary>
    /// Mirror <c>AuthenticodeSignature::from_der</c> acceptance: returns <c>null</c> where picky's serde model would
    /// reject the structure (so callers take the Rust CMS fallback path). This is an approximation of the picky
    /// deserializer covering the rules that matter for Authenticode: encapsulated <c>SpcIndirectDataContent</c> data
    /// types, <c>SignerInfo</c> version 1, typed signed attributes and the unsigned attribute OIDs picky models.
    /// </summary>
    public static PickyAuthenticode? TryParse(ReadOnlySpan<byte> der)
    {
        var sd = TryParseSignedDataContentInfo(der);
        if (sd is null || !SignedDataAcceptable(sd, topLevel: true))
        {
            return null;
        }

        return new PickyAuthenticode(sd);
    }

    /// <summary>picky <c>Pkcs7::from_der</c> acceptance (same structural rules as <see cref="TryParse"/>).</summary>
    public static CmsSignedData? TryParsePkcs7(ReadOnlySpan<byte> der)
    {
        var sd = TryParseSignedDataContentInfo(der);
        return sd is not null && SignedDataAcceptable(sd, topLevel: true) ? sd : null;
    }

    private static CmsSignedData? TryParseSignedDataContentInfo(ReadOnlySpan<byte> der)
    {
        var outer = Der.First(der);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            return null;
        }

        var ci = Der.Children(der, outer.Value);
        if (ci is not { Count: 2 } || ci[0].Tag != 0x06 || ci[1].Tag != 0xA0)
        {
            return null;
        }

        if (Der.DecodeOid(ci[0].Encoded(der)) != Oids.Pkcs7SignedData)
        {
            return null;
        }

        var inner = Der.Children(der, ci[1]);
        if (inner is not { Count: 1 })
        {
            return null;
        }

        try
        {
            return CmsSignedData.ParseSignedData(inner[0].Encoded(der));
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            return null;
        }
    }

    private static bool SignedDataAcceptable(CmsSignedData sd, bool topLevel)
    {
        if (sd.EncapContentType == Oids.SpcIndirectData)
        {
            if (sd.EncapContent is null)
            {
                return false;
            }

            var spc = Der.First(sd.EncapContent);
            if (spc is null || spc.Value.Tag != 0x30)
            {
                return false;
            }

            var parts = Der.Children(sd.EncapContent, spc.Value);
            if (parts is not { Count: 2 } || parts[0].Tag != 0x30)
            {
                return false;
            }

            var data = Der.Children(sd.EncapContent, parts[0]);
            if (data is not { Count: >= 1 } || data[0].Tag != 0x06)
            {
                return false;
            }

            var dataType = Der.DecodeOid(data[0].Encoded(sd.EncapContent));
            if (dataType is not (Oids.SpcPeImageData or SpcSipInfo))
            {
                return false;
            }
        }
        else if (sd.EncapContentType != Oids.Pkcs7Data)
        {
            if (sd.EncapContent is null || sd.EncapContent.Length == 0 || sd.EncapContent[0] != 0x04)
            {
                return false;
            }
        }
        else if (sd.EncapContent is not null && (sd.EncapContent.Length == 0 || sd.EncapContent[0] != 0x04))
        {
            return false;
        }

        foreach (var si in sd.SignerInfos)
        {
            if (!SignerInfoAcceptable(si))
            {
                return false;
            }
        }

        return true;
    }

    private static bool SignerInfoAcceptable(CmsSignerInfo si)
    {
        if (si.Version != 1)
        {
            return false;
        }

        foreach (var attr in si.SignedAttributes ?? [])
        {
            byte? want = attr.Oid switch
            {
                Oids.Pkcs9ContentType => 0x06,
                Oids.Pkcs9MessageDigest => 0x04,
                Oids.Pkcs9SigningTime => 0x17,
                _ => null,
            };
            if (want is { } tag && attr.Values.Any(v => v.Length == 0 || v[0] != tag))
            {
                return false;
            }
        }

        foreach (var attr in si.UnsignedAttributes ?? [])
        {
            if (attr.Oid == Oids.MsRfc3161TimestampToken)
            {
                foreach (var v in attr.Values)
                {
                    var token = TryParseSignedDataContentInfo(v);
                    if (token is null || !SignedDataAcceptable(token, topLevel: false))
                    {
                        return false;
                    }
                }
            }
            else if (attr.Oid == Oids.Pkcs9CounterSignature)
            {
                foreach (var v in attr.Values)
                {
                    try
                    {
                        if (CmsSignerInfo.Parse(v).Version != 1)
                        {
                            return false;
                        }
                    }
                    catch (PsignException)
                    {
                        return false;
                    }
                }
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    /// <summary><c>Pkcs7::decode_certificates</c> (certificates that parse; other choices skipped).</summary>
    public List<CertificateInfo> DecodeCertificates() => SignedData.GetCertificates();

    /// <summary><c>AuthenticodeSignature::signing_certificate</c>.</summary>
    public CertificateInfo SigningCertificate(IReadOnlyList<CertificateInfo> certificates)
    {
        var signerInfos = SignedData.SignerInfos;
        if (signerInfos.Count == 0)
        {
            throw new PickyException($"Authenticode must contain only one SignerInfo, but got {signerInfos.Count}");
        }

        var si = signerInfos[0];
        if (si.SidIssuerAndSerial is not { } ias)
        {
            throw new PickyException(
                "Authenticode uses issuerAndSerialNumber to identify the signer, but got subjectKeyIdentifier identification");
        }

        foreach (var c in certificates)
        {
            if (c.Issuer.AsSpan().SequenceEqual(ias.Issuer) && c.SerialNumber.AsSpan().SequenceEqual(ias.Serial))
            {
                return c;
            }
        }

        throw new PickyException(
            $"Can't find certificate for issuer: {PickyFormat.NameDisplay(ias.Issuer)}, and serial_number:  {PickyFormat.ByteVecPrettyDebug(ias.Serial)}");
    }

    private static IEnumerable<CertificateInfo> SignatureCertificates(CertificateInfo signing, IEnumerable<CertificateInfo> certificates)
    {
        byte[] prev = signing.Subject;
        foreach (var c in certificates)
        {
            if (c.Subject.AsSpan().SequenceEqual(prev))
            {
                prev = c.Issuer;
                yield return c;
            }
        }
    }

    private static HashAlgorithmName? HashFromDigestOid(string oid) => oid switch
    {
        Oids.Sha1 => HashAlgorithmName.SHA1,
        Oids.Sha256 => HashAlgorithmName.SHA256,
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        _ => null,
    };

    /// <summary>Signed attributes re-encoded in parsed order with a SET tag (picky <c>to_vec(authenticated_attributes)</c>).</summary>
    private static byte[] RawAttributes(CmsSignerInfo si)
    {
        var parts = (si.SignedAttributes ?? []).Select(a => a.Encode()).ToArray();
        return Der.EncodeTlv(0x31, parts);
    }

    /// <summary><c>h_verify_authenticode_basic</c>.</summary>
    public void VerifyBasic(ReadOnlySpan<byte> expectedFileHash)
    {
        var sd = SignedData;
        if (sd.Version != 1)
        {
            throw new PickyException($"Incorrect version. Expected: 1, but got {sd.Version}");
        }

        if (sd.SignerInfos.Count != 1)
        {
            throw new PickyException($"Authenticode must contain only one SignerInfo, but got {sd.SignerInfos.Count}");
        }

        if (sd.DigestAlgorithms.Count != 1)
        {
            throw new PickyException(
                $"Authenticode signatures support only one signer, digestAlgorithms must contain only one digestAlgorithmIdentifier, but {sd.DigestAlgorithms.Count} entries present");
        }

        if (sd.EncapContentType != Oids.SpcIndirectData)
        {
            throw new PickyException(sd.EncapContent is null && sd.EncapContentType == Oids.Pkcs7Data
                ? "EncapsulatedContentInfo is missing"
                : "EncapsulatedContentInfo should contain SpcIndirectDataContent");
        }

        var spcTlv = Der.First(sd.EncapContent!)!.Value;
        var spcValue = spcTlv.Value(sd.EncapContent!).ToArray();
        var spcParts = Der.Children(sd.EncapContent!, spcTlv)!;
        var digestInfo = spcParts[1].Encoded(sd.EncapContent!).ToArray();
        var digestInfoParts = Der.Children(digestInfo, Der.First(digestInfo)!.Value)
            ?? throw new PickyException("(ASN1) couldn't deserialize DigestInfo");
        var messageDigestAlg = AlgorithmIdentifier.Parse(digestInfoParts[0].Encoded(digestInfo));
        var actualFileHash = digestInfoParts[1].Value(digestInfo).ToArray();

        var digestAlgorithm = sd.DigestAlgorithms[0];
        if (!digestAlgorithm.Equals(messageDigestAlg))
        {
            throw new PickyException(
                "Digest algorithm mismatch: Signature digest algorithm does not match EncapsulatedContentInfo digest algorithm");
        }

        var si = sd.SignerInfos[0];
        if (!digestAlgorithm.Equals(si.DigestAlgorithm))
        {
            throw new PickyException("Digest algorithm mismatch: Signature digest algorithm does not match SignerInfo digest algorithm");
        }

        if (!actualFileHash.AsSpan().SequenceEqual(expectedFileHash))
        {
            throw new PickyException(
                $"Actual file hash is {PickyFormat.ByteVecDebug(actualFileHash)}, but expected {PickyFormat.ByteVecDebug(expectedFileHash)}");
        }

        var certificates = DecodeCertificates();
        var signing = SigningCertificate(certificates);

        var hash = HashFromDigestOid(digestAlgorithm.Oid);
        var sigOid = PickySignature.RsaSignatureOidForDigest(digestAlgorithm.Oid);
        if (hash is null || sigOid is null)
        {
            throw new PickyException($"unsupported algorithm: {digestAlgorithm.Oid}");
        }

        var sigErr = PickySignature.Verify(sigOid, signing.SubjectPublicKeyInfo, RawAttributes(si), si.Signature);
        if (sigErr is not null)
        {
            throw new PickyException(sigErr);
        }

        var md = si.GetSignedAttribute(Oids.Pkcs9MessageDigest)
            ?? throw new PickyException("PKCS9_MESSAGE_DIGEST attribute is absent");
        using var hasher = IncrementalHash.CreateHash(hash.Value);
        hasher.AppendData(spcValue);
        var contentHash = hasher.GetHashAndReset();
        var first = md.Values.FirstOrDefault();
        var firstTlv = first is null ? null : Der.First(first);
        if (first is null || firstTlv is null || !firstTlv.Value.Value(first).SequenceEqual(contentHash))
        {
            throw new PickyException("PKCS9_MESSAGE_DIGEST does not match ContentInfo hash");
        }

        // The signing certificate must contain the code signing EKU, or the chain must contain no EKUs.
        if (SignatureCertificates(signing, certificates).Any(PickyCert.HasEkuExtension)
            && !PickyCert.EkuContains(signing, Oids.EkuCodeSigning))
        {
            throw new PickyException("The signing certificate must contain the extended key usage (EKU) value for code signing");
        }
    }

    /// <summary><c>h_verify_signing_certificate</c> with <c>ignore_chain_check()</c> and an exact date.</summary>
    public void VerifySigningCertificate(DateTimeOffset now)
    {
        var certificates = DecodeCertificates();
        var signing = SigningCertificate(certificates);
        try
        {
            PickyCert.Verify(signing, [], new PickyValidatorOptions { Now = PickyFormat.Truncate(now), RequireChainCheck = false });
        }
        catch (PickyException err) when (err.ExpiredSubjectId is { } id && id == PickyCert.SubjectDisplay(signing))
        {
            // A timestamped signature outlives the signing certificate unless it carries the lifetime signing EKU.
            bool lifetime = PickyCert.EkuContains(signing, Oids.MsLifetimeSigning);
            static bool HasTimeStamping(IEnumerable<CertificateInfo> certs) =>
                certs.Any(c => PickyCert.EkuContains(c, Oids.EkuTimeStamping));

            if (HasTimeStamping(certificates) && !lifetime)
            {
                return;
            }

            var unsigned = SignedData.SignerInfos[0].UnsignedAttributes;
            if (unsigned is { Count: > 0 } && unsigned[0].Oid == Oids.MsRfc3161TimestampToken && unsigned[0].Values.Count > 0)
            {
                var token = TryParseSignedDataContentInfo(unsigned[0].Values[0]);
                var tsCerts = token?.GetCertificates() ?? [];
                if (HasTimeStamping(tsCerts) && !lifetime)
                {
                    if (tsCerts.Count > 0)
                    {
                        var leaf = tsCerts[0];
                        var chain = tsCerts.Where(c => !c.Subject.AsSpan().SequenceEqual(leaf.Subject));
                        try
                        {
                            PickyCert.Verify(leaf, chain, new PickyValidatorOptions
                            {
                                RequireNotAfter = false,
                                RequireNotBefore = false,
                                ChainShouldContainRoot = false,
                            });
                        }
                        catch (PickyException tsErr)
                        {
                            throw new PickyException($"Timestamp has invalid certificate: {tsErr.Message}");
                        }
                    }

                    return;
                }
            }

            throw;
        }
    }
}
