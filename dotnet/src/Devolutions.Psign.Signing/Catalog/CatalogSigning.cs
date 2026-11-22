using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;

namespace Devolutions.Psign.Signing.Catalog;

/// <summary>Result of portable catalog authoring (Rust <c>CatalogSignResult</c>).</summary>
/// <param name="Pkcs7Der">Catalog <c>ContentInfo(SignedData)</c> DER (the <c>.cat</c> file bytes).</param>
/// <param name="Members">Authored CTL members in subject order.</param>
public sealed record CatalogSignResult(byte[] Pkcs7Der, List<CatalogMember> Members);

/// <summary>
/// Portable generic catalog (<c>.cat</c>) authoring: Microsoft CTL <c>eContent</c> and CMS <c>SignedData</c> (port of the
/// producer half of <c>catalog_digest.rs</c>).
/// </summary>
public static class CatalogSigning
{
    /// <summary>Generic <c>SpcLink</c>-style value used for non-PE members (<c>[2] { [0] "" }</c>).</summary>
    private static readonly byte[] CatalogGenericLinkValueDer = [0xa2, 0x02, 0x80, 0x00];

    /// <summary><c>CTL.thisUpdate</c> literal (UTCTime 1970-01-01T00:00:00Z) so authoring is deterministic.</summary>
    private const string CatalogThisUpdateUtc = "700101000000Z";

    private static byte[] DerSet(params byte[][] items) => Der.EncodeTlv(0x31, items);

    private static byte[] DerOctetString(ReadOnlySpan<byte> bytes) => Der.EncodeTlv(0x04, bytes);

    private static byte[] DerUtcTimeLiteral(string literal)
    {
        if (literal.Length != 13 || literal[^1] != 'Z')
        {
            throw new PsignException("catalog UTC_TIME literal must be YYMMDDHHMMSSZ");
        }

        return Der.EncodeTlv(0x17, Encoding.ASCII.GetBytes(literal));
    }

    private static byte[] SubjectIdentifier(string name)
    {
        if (name.Length == 0)
        {
            throw new PsignException("catalog subject name must not be empty");
        }

        if (name.Contains('\0', StringComparison.Ordinal))
        {
            throw new PsignException("catalog subject name must not contain NUL bytes");
        }

        return Encoding.Unicode.GetBytes($"<{name}>\0");
    }

    private static byte[] ListIdentifier(IEnumerable<CatalogMember> members)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var member in members)
        {
            h.AppendData(member.SubjectIdentifier);
            h.AppendData(member.Digest);
        }

        return h.GetHashAndReset()[..16];
    }

    private static void CheckDigestLength(AuthenticodeHashKind kind, byte[] digest, string label)
    {
        if (digest.Length != kind.DigestLength())
        {
            throw new PsignException(
                $"{label} digest length {digest.Length} does not match {Display(kind)} ({kind.DigestLength()} octets)");
        }
    }

    private static string Display(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => "Sha1",
        AuthenticodeHashKind.Sha256 => "Sha256",
        AuthenticodeHashKind.Sha384 => "Sha384",
        _ => "Sha512",
    };

    /// <summary>Generic (non-PE) member <c>SpcIndirectDataContent</c> (Rust <c>catalog_generic_spc_indirect_data</c>).</summary>
    public static SpcIndirectDataContent GenericSpcIndirectData(AuthenticodeHashKind kind, byte[] subjectDigest)
    {
        CheckDigestLength(kind, subjectDigest, "catalog subject");
        return new SpcIndirectDataContent(Oids.SpcCabData, CatalogGenericLinkValueDer.ToArray(), AlgorithmIdentifier.Absent(kind.Oid()), subjectDigest);
    }

    /// <summary>PE member <c>SpcIndirectDataContent</c> (Rust <c>catalog_pe_spc_indirect_data</c>).</summary>
    public static SpcIndirectDataContent PeSpcIndirectData(AuthenticodeHashKind kind, byte[] peDigest)
    {
        CheckDigestLength(kind, peDigest, "catalog PE");
        return new SpcIndirectDataContent(
            Oids.SpcPeImageData,
            Der.EncodeTlv(0x30, SpcIndirectDataContent.SpcPeImageDataValue),
            AlgorithmIdentifier.Absent(kind.Oid()),
            peDigest);
    }

    private static (SpcIndirectDataContent Indirect, string DataOid, byte[] Digest) SubjectIndirectData(AuthenticodeHashKind kind, byte[] subject)
    {
        byte[]? peDigest = null;
        try
        {
            peDigest = PeAuthenticode.Digest(subject, kind);
        }
        catch (Exception e) when (e is PsignException or ArgumentException or IndexOutOfRangeException or OverflowException)
        {
        }

        if (peDigest is not null)
        {
            return (PeSpcIndirectData(kind, peDigest), Oids.SpcPeImageData, peDigest);
        }

        var digest = kind.Hash(subject);
        return (GenericSpcIndirectData(kind, digest), Oids.SpcCabData, digest);
    }

    private static byte[] CtlEntryDer(byte[] subjectIdentifier, SpcIndirectDataContent indirect)
    {
        var attr = Der.EncodeSequence(Der.EncodeOid(Oids.SpcIndirectData), DerSet(indirect.Encode()));
        return Der.EncodeSequence(DerOctetString(subjectIdentifier), DerSet(attr));
    }

    private static string AsciiLower(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            if (chars[i] is >= 'A' and <= 'Z')
            {
                chars[i] = (char)(chars[i] + 32);
            }
        }

        return new string(chars);
    }

    /// <summary>
    /// Build Microsoft CTL <c>eContent</c> DER for a portable generic catalog (Rust
    /// <c>create_catalog_ctl_econtent_der_with_hash</c>). Accepts SHA-1 for unsigned catalogs.
    /// </summary>
    public static (byte[] EContentDer, List<CatalogMember> Members) CreateCtlEContentDerWithHash(
        IReadOnlyList<CatalogSubjectInput> subjects,
        AuthenticodeHashKind kind)
    {
        if (subjects.Count == 0)
        {
            throw new PsignException("catalog signing requires at least one subject file");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var members = new List<CatalogMember>(subjects.Count);
        var entries = new List<byte[]>(subjects.Count);
        foreach (var subject in subjects)
        {
            if (!seen.Add(AsciiLower(subject.Name)))
            {
                throw new PsignException($"catalog contains duplicate subject file name {subject.Name}");
            }

            var subjectIdentifier = SubjectIdentifier(subject.Name);
            var (indirect, dataOid, digest) = SubjectIndirectData(kind, subject.Bytes);
            entries.Add(CtlEntryDer(subjectIdentifier, indirect));
            members.Add(new CatalogMember(
                subjectIdentifier,
                CatalogDigest.DecodeUtf16LeSubjectIdentifier(subjectIdentifier),
                dataOid,
                kind.Oid(),
                digest));
        }

        var trustedSubjects = Der.EncodeSequence(entries.ToArray());
        var ctlInfo = Der.EncodeSequence(
            Der.EncodeSequence(Der.EncodeOid(Oids.MsCatalogList)),
            DerOctetString(ListIdentifier(members)),
            DerUtcTimeLiteral(CatalogThisUpdateUtc),
            Der.EncodeSequence(Der.EncodeOid(Oids.MsCatalogListMember), Der.Null),
            trustedSubjects);
        return (ctlInfo, members);
    }

    /// <summary>
    /// Build Microsoft CTL <c>eContent</c> DER for a signed portable catalog (Rust <c>create_catalog_ctl_econtent_der</c>;
    /// SHA-256/384/512 only).
    /// </summary>
    public static (byte[] EContentDer, List<CatalogMember> Members) CreateCtlEContentDer(
        IReadOnlyList<CatalogSubjectInput> subjects,
        AuthenticodeHashKind kind)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return CreateCtlEContentDerWithHash(subjects, kind);
    }

    /// <summary>Create an unsigned portable generic catalog (Rust <c>create_unsigned_catalog_pkcs7_der</c>).</summary>
    public static CatalogSignResult CreateUnsigned(IReadOnlyList<CatalogSubjectInput> subjects, AuthenticodeHashKind kind)
    {
        var (econtent, members) = CreateCtlEContentDerWithHash(subjects, kind);
        var pkcs7 = Pkcs7Builder.CreateUnsignedSignedData(Oids.MsCtl, econtent, AlgorithmIdentifier.Absent(kind.Oid()));
        return new CatalogSignResult(pkcs7, members);
    }

    /// <summary>
    /// Digest a remote signer must sign for a catalog over <paramref name="econtentDer"/> (basic CMS signed attributes;
    /// used by the Artifact Signing / Key Vault flows).
    /// </summary>
    public static byte[] RemoteSignedAttributesDigest(byte[] econtentDer, AuthenticodeHashKind kind)
    {
        Pkcs7Builder.RequireSigningDigest(kind);
        return Pkcs7Builder.RemoteSignedAttributesDigest(Oids.MsCtl, econtentDer, kind);
    }

    /// <summary>Create a signed portable generic catalog (Rust <c>create_catalog_pkcs7_der_rsa</c> with a pluggable signer).</summary>
    public static CatalogSignResult Create(
        IReadOnlyList<CatalogSubjectInput> subjects,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        IDigestSigner signer)
    {
        var (econtent, members) = CreateCtlEContentDer(subjects, kind);
        var pkcs7 = Pkcs7Builder.CreateSignedData(Oids.MsCtl, econtent, kind, signerCert, chainCerts, signer);
        return new CatalogSignResult(pkcs7, members);
    }

    /// <summary>Create a signed portable generic catalog using an RSA private key (Rust <c>create_catalog_pkcs7_der_rsa</c>).</summary>
    public static CatalogSignResult Create(
        IReadOnlyList<CatalogSubjectInput> subjects,
        AuthenticodeHashKind kind,
        CertificateInfo signerCert,
        IEnumerable<CertificateInfo> chainCerts,
        RSA key) =>
        Create(subjects, kind, signerCert, chainCerts, new RsaDigestSigner(key));
}
