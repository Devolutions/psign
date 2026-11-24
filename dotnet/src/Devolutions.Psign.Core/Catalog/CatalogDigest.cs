using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;

namespace Devolutions.Psign.Core.Catalog;

/// <summary>One MakeCat-style CTL member entry (Rust <c>CatalogMember</c>).</summary>
/// <param name="SubjectIdentifier">Raw CTL <c>SubjectIdentifier</c> octets (UTF-16LE <c>&lt;name&gt;\0</c> for portable catalogs).</param>
/// <param name="SubjectName">Decoded subject name (angle brackets stripped), or <c>null</c> when not valid UTF-16.</param>
/// <param name="DataOid"><c>SpcIndirectDataContent.data.type</c> (PE image data or generic CAB data).</param>
/// <param name="DigestAlgorithmOid">Member digest algorithm OID.</param>
/// <param name="Digest">Member digest octets.</param>
public sealed record CatalogMember(
    byte[] SubjectIdentifier,
    string? SubjectName,
    string DataOid,
    string DigestAlgorithmOid,
    byte[] Digest)
{
    public bool Equals(CatalogMember? other) =>
        other is not null &&
        SubjectIdentifier.AsSpan().SequenceEqual(other.SubjectIdentifier) &&
        SubjectName == other.SubjectName &&
        DataOid == other.DataOid &&
        DigestAlgorithmOid == other.DigestAlgorithmOid &&
        Digest.AsSpan().SequenceEqual(other.Digest);

    public override int GetHashCode() => HashCode.Combine(SubjectName, DataOid, DigestAlgorithmOid, Digest.Length);
}

/// <summary>Successful catalog membership lookup (Rust <c>CatalogMemberMatch</c>).</summary>
public sealed record CatalogMemberMatch(int MemberIndex, CatalogMember Member, byte[] ComputedDigest)
{
    public bool Equals(CatalogMemberMatch? other) =>
        other is not null && MemberIndex == other.MemberIndex && Member.Equals(other.Member) &&
        ComputedDigest.AsSpan().SequenceEqual(other.ComputedDigest);

    public override int GetHashCode() => HashCode.Combine(MemberIndex, Member);
}

/// <summary>A subject file to author into a catalog (Rust <c>CatalogSubjectInput</c>).</summary>
public sealed record CatalogSubjectInput(string Name, byte[] Bytes);

/// <summary>
/// Windows <c>.cat</c> catalog digest / membership checks (port of the parsing half of <c>catalog_digest.rs</c>).
/// <para>
/// Catalogs are a single PKCS#7 <c>SignedData</c> whose encapsulated content type is Microsoft CTL
/// (<c>1.3.6.1.4.1.311.10.1</c>). CMS signing uses the PKCS#9 <c>messageDigest</c> authenticated attribute over the
/// <c>eContent</c> payload octets; the digest is located by scanning Microsoft's wrapped attribute values for a DER
/// <c>OCTET STRING</c> whose contents equal that hash.
/// </para>
/// </summary>
public static class CatalogDigest
{
    private const byte TagSequence = 0x30;
    private const byte TagSet = 0x31;
    private const byte TagObjectIdentifier = 0x06;
    private const byte TagOctetString = 0x04;

    private readonly record struct Tlv(byte Tag, int Start, int ValueStart, int End)
    {
        public ReadOnlySpan<byte> Value(ReadOnlySpan<byte> data) => data[ValueStart..End];

        public ReadOnlySpan<byte> Full(ReadOnlySpan<byte> data) => data[Start..End];
    }

    internal static AuthenticodeHashKind DigestKindFromDigestAlgOid(string oid) =>
        AuthenticodeHashKinds.FromOid(oid)
        ?? throw new PsignException($"unsupported digest algorithm OID {oid} in catalog SignedData");

    // ------------------------------------------------------------------ strict TLV reader (Rust tlv_at / children)

    private static (int Length, int LengthLength) DerLenAt(ReadOnlySpan<byte> data, int lenOff)
    {
        if (lenOff >= data.Length)
        {
            throw new PsignException("truncated DER length");
        }

        byte first = data[lenOff];
        if ((first & 0x80) == 0)
        {
            return (first, 1);
        }

        int n = first & 0x7F;
        if (n == 0)
        {
            throw new PsignException("indefinite DER length is not allowed");
        }

        if (n > 8)
        {
            throw new PsignException("DER length too large");
        }

        if (lenOff + 1 + n > data.Length)
        {
            throw new PsignException("truncated DER long-form length");
        }

        if (data[lenOff + 1] == 0 || (n == 1 && data[lenOff + 1] < 0x80))
        {
            throw new PsignException("non-minimal DER length");
        }

        ulong len = 0;
        for (int i = 0; i < n; i++)
        {
            if (len > (ulong.MaxValue >> 8))
            {
                throw new PsignException("DER length overflow");
            }

            len = (len << 8) | data[lenOff + 1 + i];
        }

        if (len > int.MaxValue)
        {
            throw new PsignException("truncated DER value");
        }

        return ((int)len, 1 + n);
    }

    private static (Tlv Tlv, int Next) TlvAt(ReadOnlySpan<byte> data, int off)
    {
        if (off >= data.Length)
        {
            throw new PsignException("truncated DER tag");
        }

        byte tag = data[off];
        var (len, lenLen) = DerLenAt(data, off + 1);
        long valueStart = (long)off + 1 + lenLen;
        long valueEnd = valueStart + len;
        if (valueEnd > data.Length)
        {
            throw new PsignException("truncated DER value");
        }

        return (new Tlv(tag, off, (int)valueStart, (int)valueEnd), (int)valueEnd);
    }

    private static List<Tlv> Children(ReadOnlySpan<byte> data)
    {
        var output = new List<Tlv>();
        int off = 0;
        while (off < data.Length)
        {
            var (tlv, next) = TlvAt(data, off);
            output.Add(tlv);
            off = next;
        }

        return output;
    }

    /// <summary>
    /// Decode a CTL <c>SubjectIdentifier</c> as UTF-16LE up to the first NUL and strip a surrounding <c>&lt;...&gt;</c>
    /// (Rust <c>decode_utf16le_subject_identifier</c>).
    /// </summary>
    public static string? DecodeUtf16LeSubjectIdentifier(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length % 2 != 0)
        {
            return null;
        }

        var units = new List<char>(bytes.Length / 2);
        for (int i = 0; i + 1 < bytes.Length; i += 2)
        {
            char u = (char)(bytes[i] | (bytes[i + 1] << 8));
            if (u == 0)
            {
                break;
            }

            units.Add(u);
        }

        // String::from_utf16 rejects unpaired surrogates.
        for (int i = 0; i < units.Count; i++)
        {
            if (char.IsHighSurrogate(units[i]))
            {
                if (i + 1 >= units.Count || !char.IsLowSurrogate(units[i + 1]))
                {
                    return null;
                }

                i++;
            }
            else if (char.IsLowSurrogate(units[i]))
            {
                return null;
            }
        }

        var s = new string(units.ToArray());
        return s.Length >= 2 && s.StartsWith('<') && s.EndsWith('>') ? s[1..^1] : s;
    }

    private static SpcIndirectDataContent? SpcIndirectFromAttributeSequence(ReadOnlySpan<byte> seqValue, ReadOnlySpan<byte> spcIndirectOid)
    {
        var items = Children(seqValue);
        if (items.Count < 2 ||
            items[0].Tag != TagObjectIdentifier ||
            !items[0].Value(seqValue).SequenceEqual(spcIndirectOid) ||
            items[1].Tag != TagSet)
        {
            return null;
        }

        var setValue = items[1].Value(seqValue);
        foreach (var value in Children(setValue))
        {
            if (value.Tag == TagSequence)
            {
                try
                {
                    return SpcIndirectDataContent.Parse(value.Full(setValue));
                }
                catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException)
                {
                    throw new PsignException($"catalog SpcIndirectDataContent: {e.Message}", e);
                }
            }
        }

        throw new PsignException("catalog SPC_INDIRECT_DATA attribute has no SEQUENCE value");
    }

    private static SpcIndirectDataContent? FindSpcIndirectInMemberSequence(ReadOnlySpan<byte> memberValue, ReadOnlySpan<byte> spcIndirectOid)
    {
        foreach (var child in Children(memberValue))
        {
            if (child.Tag == TagSequence &&
                SpcIndirectFromAttributeSequence(child.Value(memberValue), spcIndirectOid) is { } indirect)
            {
                return indirect;
            }

            if ((child.Tag == TagSequence || child.Tag == TagSet) &&
                FindSpcIndirectInMemberSequence(child.Value(memberValue), spcIndirectOid) is { } nested)
            {
                return nested;
            }
        }

        return null;
    }

    private static void CollectMembersFromSequence(ReadOnlySpan<byte> seqValue, ReadOnlySpan<byte> spcIndirectOid, List<CatalogMember> members)
    {
        foreach (var seq in Children(seqValue))
        {
            if (seq.Tag != TagSequence)
            {
                continue;
            }

            var body = seq.Value(seqValue);
            var seqChildren = Children(body);
            if (seqChildren.Count > 0 &&
                seqChildren[0].Tag == TagOctetString &&
                FindSpcIndirectInMemberSequence(body, spcIndirectOid) is { } indirect)
            {
                var subject = seqChildren[0].Value(body);
                members.Add(new CatalogMember(
                    subject.ToArray(),
                    DecodeUtf16LeSubjectIdentifier(subject),
                    indirect.DataType,
                    indirect.DigestAlgorithm.Oid,
                    indirect.Digest));
                continue;
            }

            CollectMembersFromSequence(body, spcIndirectOid, members);
        }
    }

    /// <summary>True if <paramref name="blob"/> contains a DER <c>OCTET STRING</c> whose value equals <paramref name="expected"/>.</summary>
    internal static bool BlobContainsOctetStringDigest(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> expected)
    {
        int len = expected.Length;
        for (int i = 0; i + 2 + len <= blob.Length; i++)
        {
            if (blob[i] != 0x04)
            {
                continue;
            }

            byte lb = blob[i + 1];
            if (lb == len && blob.Slice(i + 2, len).SequenceEqual(expected))
            {
                return true;
            }

            // Two-byte length form 0x81 <len> for digest sizes <= 255 (e.g. SHA-384/512).
            if (lb == 0x81 && i + 2 < blob.Length && blob[i + 2] == len && i + 3 + len <= blob.Length && blob.Slice(i + 3, len).SequenceEqual(expected))
            {
                return true;
            }
        }

        return false;
    }

    private static void Pkcs9MessageDigestMatches(List<CmsAttribute> attrs, ReadOnlySpan<byte> computed)
    {
        foreach (var attr in attrs)
        {
            if (attr.Oid != Oids.Pkcs9MessageDigest)
            {
                continue;
            }

            foreach (var val in attr.Values)
            {
                var tlv = Der.First(val);
                if (tlv is null)
                {
                    continue;
                }

                var payload = tlv.Value.Value(val);
                if (tlv.Value.Tag == TagOctetString && payload.SequenceEqual(computed))
                {
                    return;
                }

                if (BlobContainsOctetStringDigest(payload, computed))
                {
                    return;
                }
            }

            throw new PsignException(
                "PKCS#9 messageDigest signed attribute present but no OCTET STRING matched eContent hash");
        }

        throw new PsignException("catalog SignerInfo is missing PKCS#9 messageDigest authenticated attribute");
    }

    /// <summary>
    /// RS256 prehash (SHA-256 over authenticated <c>signedAttrs</c>) for a <c>.cat</c>-style PKCS#7 file (Rust
    /// <c>catalog_rsa_sha256_signer_prehash_digest</c>; input is normalized like <c>pkcs7-signer-rs256-prehash</c>).
    /// </summary>
    public static byte[] RsaSha256SignerPrehashDigest(ReadOnlySpan<byte> data, int signerIndex) =>
        SignerPrehash.Rs256(CmsSignedData.Parse(data), signerIndex);

    /// <summary>Decode the catalog <c>ContentInfo(SignedData)</c> with a Microsoft CTL payload (Rust <c>catalog_signed_data</c>).</summary>
    public static CmsSignedData ParseSignedData(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            throw new PsignException("empty catalog file");
        }

        var outer = Der.First(data);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            throw new PsignException("catalog PKCS#7 ContentInfo: expected SEQUENCE");
        }

        var ci = Der.Children(data, outer.Value);
        if (ci is not { Count: 2 } || ci[0].Tag != 0x06 || ci[1].Tag != 0xA0)
        {
            throw new PsignException("catalog PKCS#7 ContentInfo: malformed ContentInfo");
        }

        string contentType = Der.DecodeOid(ci[0].Encoded(data))
            ?? throw new PsignException("catalog PKCS#7 ContentInfo: malformed OBJECT IDENTIFIER");
        if (contentType != Oids.Pkcs7SignedData)
        {
            throw new PsignException($"catalog root content type is not SignedData (got {contentType})");
        }

        var inner = Der.Children(data, ci[1]);
        if (inner is not { Count: 1 })
        {
            throw new PsignException("catalog SignedData: malformed [0] EXPLICIT content");
        }

        CmsSignedData sd;
        try
        {
            sd = CmsSignedData.ParseSignedData(inner[0].Encoded(data));
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException or OverflowException)
        {
            throw new PsignException($"catalog SignedData: {e.Message}", e);
        }

        if (sd.EncapContentType != Oids.MsCtl)
        {
            throw new PsignException(
                $"catalog encapsulated content type is not Microsoft CTL (got {sd.EncapContentType})");
        }

        return sd;
    }

    private static byte[]? EContentValue(CmsSignedData sd)
    {
        if (sd.EncapContent is null)
        {
            return null;
        }

        var t = Der.First(sd.EncapContent) ?? throw new PsignException("catalog SignedData: malformed eContent");
        return t.Value(sd.EncapContent).ToArray();
    }

    /// <summary>
    /// CMS digest over the encapsulated catalog <c>eContent</c> using the first signer's digest algorithm (Rust
    /// <c>catalog_econtent_digest</c>).
    /// </summary>
    public static byte[] EContentDigest(ReadOnlySpan<byte> data)
    {
        var sd = ParseSignedData(data);
        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("catalog SignedData has no SignerInfo");
        }

        var kind = DigestKindFromDigestAlgOid(sd.SignerInfos[0].DigestAlgorithm.Oid);
        return kind.Hash(EContentValue(sd) ?? []);
    }

    /// <summary>Parse MakeCat-style CTL member entries from a catalog (Rust <c>catalog_members_bytes</c>).</summary>
    public static List<CatalogMember> Members(ReadOnlySpan<byte> data)
    {
        var sd = ParseSignedData(data);
        var econtent = EContentValue(sd) ?? throw new PsignException("catalog SignedData has no CTL eContent");
        var spcIndirectOid = Der.EncodeOid(Oids.SpcIndirectData).AsSpan(2).ToArray();
        var members = new List<CatalogMember>();
        CollectMembersFromSequence(econtent, spcIndirectOid, members);
        if (members.Count == 0)
        {
            throw new PsignException("catalog CTL contains no SPC_INDIRECT_DATA member entries");
        }

        return members;
    }

    /// <summary>
    /// Digest of <paramref name="subject"/> as recorded for <paramref name="member"/>: PE Authenticode digest for
    /// <c>SPC_PE_IMAGE_DATA</c> members, otherwise a flat file hash (Rust <c>catalog_member_digest_for_subject</c>).
    /// </summary>
    public static byte[] MemberDigestForSubject(CatalogMember member, byte[] subject)
    {
        var kind = DigestKindFromDigestAlgOid(member.DigestAlgorithmOid);
        if (member.DataOid == Oids.SpcPeImageData)
        {
            try
            {
                return PeAuthenticode.Digest(subject, kind);
            }
            catch (Exception e) when (e is PsignException or ArgumentException or IndexOutOfRangeException or OverflowException)
            {
                throw new PsignException("compute PE Authenticode digest for catalog member", e);
            }
        }

        return kind.Hash(subject);
    }

    /// <summary>Verify that <paramref name="subject"/> is represented by one CTL member entry in <paramref name="catalog"/> (Rust <c>verify_catalog_member_bytes</c>).</summary>
    public static CatalogMemberMatch VerifyMember(ReadOnlySpan<byte> catalog, byte[] subject)
    {
        var members = Members(catalog);
        var digestErrors = new List<string>();
        for (int idx = 0; idx < members.Count; idx++)
        {
            var member = members[idx];
            try
            {
                var computed = MemberDigestForSubject(member, subject);
                if (computed.AsSpan().SequenceEqual(member.Digest))
                {
                    return new CatalogMemberMatch(idx, member, computed);
                }
            }
            catch (PsignException e)
            {
                digestErrors.Add($"{member.SubjectName ?? "<unnamed>"}: {PsignException.Render(e)}");
            }
        }

        if (digestErrors.Count == 0)
        {
            throw new PsignException(
                $"subject file is not a member of the catalog ({members.Count} member entr{(members.Count == 1 ? "y" : "ies")} checked)");
        }

        throw new PsignException(
            $"subject file is not a member of the catalog; digest errors while checking members: {string.Join("; ", digestErrors)}");
    }

    /// <summary>Verify a file's membership in a catalog by path (Rust <c>verify_catalog_member</c>).</summary>
    public static CatalogMemberMatch VerifyMember(string catalogPath, string subjectPath)
    {
        byte[] catalog;
        try
        {
            catalog = File.ReadAllBytes(catalogPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read catalog {catalogPath}", e);
        }

        byte[] subject;
        try
        {
            subject = File.ReadAllBytes(subjectPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException($"read subject {subjectPath}", e);
        }

        return VerifyMember(catalog, subject);
    }

    /// <summary>
    /// Verify each <c>SignerInfo</c>'s PKCS#9 <c>messageDigest</c> matches the CMS digest over the encapsulated
    /// <c>eContent</c> (Rust <c>verify_catalog_digest_consistency_bytes</c>).
    /// </summary>
    public static void VerifyDigestConsistency(ReadOnlySpan<byte> data)
    {
        var sd = ParseSignedData(data);
        if (sd.DigestAlgorithms.Count != 1)
        {
            throw new PsignException($"expected one digest algorithm in SignedData, got {sd.DigestAlgorithms.Count}");
        }

        var refAlg = sd.DigestAlgorithms[0];
        var econtent = EContentValue(sd) ?? [];
        if (sd.SignerInfos.Count == 0)
        {
            throw new PsignException("catalog SignedData has no SignerInfo");
        }

        foreach (var si in sd.SignerInfos)
        {
            if (!si.DigestAlgorithm.Equals(refAlg))
            {
                throw new PsignException("SignerInfo digestAlgorithm does not match SignedData.digestAlgorithms");
            }

            var kind = DigestKindFromDigestAlgOid(si.DigestAlgorithm.Oid);
            var computed = kind.Hash(econtent);
            var attrs = si.SignedAttributes
                ?? throw new PsignException("catalog SignerInfo missing authenticated attributes");
            Pkcs9MessageDigestMatches(attrs, computed);
        }
    }

    /// <summary>File-path overload of <see cref="VerifyDigestConsistency(ReadOnlySpan{byte})"/> (Rust <c>verify_catalog_digest_consistency</c>).</summary>
    public static void VerifyDigestConsistency(string path) => VerifyDigestConsistency(File.ReadAllBytes(path));
}
