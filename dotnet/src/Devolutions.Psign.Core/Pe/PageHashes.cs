using System.Buffers.Binary;
using System.Security.Cryptography;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.Pe;

/// <summary>Which Microsoft page-hash attribute OID matched (Rust <c>PageHashAttrKind</c>).</summary>
public enum PageHashAttrKind
{
    /// <summary><c>SPC_PE_IMAGE_PAGE_HASHES</c> V1 (<c>1.3.6.1.4.1.311.2.3.1</c>, SHA-1).</summary>
    V1,

    /// <summary><c>SPC_PE_IMAGE_PAGE_HASHES</c> V2 (<c>1.3.6.1.4.1.311.2.3.2</c>, SHA-256).</summary>
    V2,
}

/// <summary>One <c>(kind, raw attribute value)</c> from a <c>SignerInfo</c>'s signed attributes (Rust <c>PageHashAttrValue</c>).</summary>
/// <param name="Kind">Attribute OID variant.</param>
/// <param name="ValueDer">Content octets of the attribute value (the Rust <c>Any::value()</c> bytes).</param>
public sealed record PageHashAttrValue(PageHashAttrKind Kind, byte[] ValueDer)
{
    public bool Equals(PageHashAttrValue? other) =>
        other is not null && Kind == other.Kind && ValueDer.AsSpan().SequenceEqual(other.ValueDer);

    public override int GetHashCode() => HashCode.Combine(Kind, ValueDer.Length);
}

/// <summary>Page-hash attributes grouped by PKCS#7 blob index and signer index (Rust <c>PePageHashAttrLocation</c>).</summary>
public sealed record PePageHashAttrLocation(int Pkcs7Index, int SignerIndex, List<PageHashAttrValue> Values);

/// <summary>
/// One slot in the flat Authenticode page-hash table (<c>u32</c> LE then digest bytes; Rust <c>PageHashTableEntry</c>).
/// <see cref="PageEndOffset"/> is the end offset within the PE image for the hashed range of this slot.
/// </summary>
public sealed record PageHashTableEntry(uint PageEndOffset, byte[] Digest)
{
    public bool Equals(PageHashTableEntry? other) =>
        other is not null && PageEndOffset == other.PageEndOffset && Digest.AsSpan().SequenceEqual(other.Digest);

    public override int GetHashCode() => HashCode.Combine(PageEndOffset, Digest.Length);
}

/// <summary>
/// Authenticode PE page hashes (<c>SPC_PE_IMAGE_PAGE_HASHES</c> authenticated attributes) — port of
/// <c>page_hashes.rs</c>.
/// <para>
/// Provides CMS-aware extraction of page-hash attributes from embedded PKCS#7 <c>SignedData</c>, a substring OID TLV
/// fallback, DER peeling + flat table parsing, and an experimental contiguous-range verifier. Native
/// <c>WinVerifyTrust</c> remains authoritative for exact <c>/ph</c> behavior.
/// </para>
/// </summary>
public static class PageHashes
{
    /// <summary>Authenticated-attribute OID <c>1.3.6.1.4.1.311.2.3.1</c> (V1).</summary>
    public const string OidPePageHashesV1 = Oids.SpcPeImagePageHashesV1;

    /// <summary>Authenticated-attribute OID <c>1.3.6.1.4.1.311.2.3.2</c> (V2).</summary>
    public const string OidPePageHashesV2 = Oids.SpcPeImagePageHashesV2;

    /// <summary>V1 OID as a DER <c>OBJECT IDENTIFIER</c> TLV.</summary>
    public static ReadOnlySpan<byte> SpcPeImagePageHashesV1OidDer =>
        [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x01];

    /// <summary>V2 OID as a DER <c>OBJECT IDENTIFIER</c> TLV.</summary>
    public static ReadOnlySpan<byte> SpcPeImagePageHashesV2OidDer =>
        [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x03, 0x02];

    /// <summary>Digest width implied by the attribute OID variant (V1 → SHA-1, V2 → SHA-256).</summary>
    public static int DigestByteLength(PageHashAttrKind kind) => kind switch
    {
        PageHashAttrKind.V1 => 20,
        _ => 32,
    };

    // ------------------------------------------------------------------ strict DER header (der crate semantics)

    private static (byte Tag, int Length, int HeaderLength) DecodeHeader(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            throw new PsignException("ASN.1 DER message is incomplete");
        }

        byte tag = data[0];
        if ((tag & 0x1F) == 0x1F)
        {
            throw new PsignException("unsupported multi-byte ASN.1 tag");
        }

        if (data.Length < 2)
        {
            throw new PsignException("ASN.1 DER message is incomplete");
        }

        byte first = data[1];
        if (first < 0x80)
        {
            return (tag, first, 2);
        }

        int n = first & 0x7F;
        if (n == 0)
        {
            throw new PsignException("indefinite length disallowed");
        }

        if (n > 4)
        {
            throw new PsignException("incorrect length");
        }

        if (data.Length < 2 + n)
        {
            throw new PsignException("ASN.1 DER message is incomplete");
        }

        long len = 0;
        for (int i = 0; i < n; i++)
        {
            len = (len << 8) | data[2 + i];
        }

        // DER minimal-length rules: long form only for >= 0x80 and without redundant leading octets.
        long minForN = n == 1 ? 0x80 : 1L << (8 * (n - 1));
        if (len < minForN || len > 0x0FFF_FFFF)
        {
            throw new PsignException("incorrect length");
        }

        return (tag, (int)len, 2 + n);
    }

    /// <summary>Decode one TLV at the start of <paramref name="data"/>, requiring the value to be present.</summary>
    private static (byte Tag, int ValueStart, int ValueEnd) DecodeTlv(ReadOnlySpan<byte> data)
    {
        var (tag, len, hdr) = DecodeHeader(data);
        if ((long)hdr + len > data.Length)
        {
            throw new PsignException("ASN.1 DER message is incomplete");
        }

        return (tag, hdr, hdr + len);
    }

    private static ReadOnlySpan<byte> DecodeOctetString(ReadOnlySpan<byte> data, out int consumed)
    {
        var (tag, start, end) = DecodeTlv(data);
        if (tag != 0x04)
        {
            throw new PsignException($"unexpected ASN.1 DER tag: expected OCTET STRING, got 0x{tag:x2}");
        }

        consumed = end;
        return data[start..end];
    }

    private static byte[]? TrySpcSerializedObjectData(ReadOnlySpan<byte> seqDer)
    {
        if (seqDer.IsEmpty || seqDer[0] != 0x30)
        {
            return null;
        }

        var (tag, start, end) = DecodeTlv(seqDer);
        if (tag != 0x30)
        {
            return null;
        }

        var body = seqDer[start..end];
        var classId = DecodeOctetString(body, out int used);
        if (classId.Length != 16)
        {
            return null;
        }

        return DecodeOctetString(body[used..], out _).ToArray();
    }

    private static byte[] ConcatOctetsFromSetOfTypeAndOptionalValue(byte[] data)
    {
        // Flat page-hash tables start with a little-endian offset (often 0x00); never DER-decode those.
        if (data.Length == 0 || data[0] != 0x31)
        {
            return data;
        }

        var (tag, start, end) = DecodeTlv(data);
        if (tag != 0x31)
        {
            return data;
        }

        ReadOnlySpan<byte> setBody = data.AsSpan(start, end - start);
        using var concat = new MemoryStream();
        while (!setBody.IsEmpty)
        {
            var (seqTag, seqStart, seqEnd) = DecodeTlv(setBody);
            if (seqTag != 0x30)
            {
                throw new PsignException("SET OF member is not SEQUENCE");
            }

            var seqBody = setBody[seqStart..seqEnd];
            var (oidTag, _, oidEnd) = DecodeTlv(seqBody);
            if (oidTag != 0x06)
            {
                throw new PsignException($"unexpected ASN.1 DER tag: expected OBJECT IDENTIFIER, got 0x{oidTag:x2}");
            }

            if (Der.DecodeOid(seqBody[..oidEnd]) is null)
            {
                throw new PsignException("malformed OBJECT IDENTIFIER");
            }

            var oct = DecodeOctetString(seqBody[oidEnd..], out _);
            concat.Write(oct);
            setBody = setBody[seqEnd..];
        }

        return concat.ToArray();
    }

    /// <summary>
    /// Peel OCTET STRING wrappers and <c>SPC_SERIALIZED_OBJECT</c> (<c>SEQUENCE { OCTET STRING classId, OCTET STRING data }</c>)
    /// layers, then flatten an optional outer <c>SET OF { OID, OCTET STRING }</c> wrapper (Rust
    /// <c>peel_authenticode_page_hash_attribute_payload</c>).
    /// </summary>
    public static byte[] PeelAttributePayload(ReadOnlySpan<byte> valueDer)
    {
        byte[] cur = valueDer.ToArray();
        for (int i = 0; i < 8; i++)
        {
            if (cur.Length == 0)
            {
                throw new PsignException("empty page-hash attribute payload");
            }

            if (cur[0] == 0x04)
            {
                cur = DecodeOctetString(cur, out _).ToArray();
            }
            else if (cur[0] == 0x30)
            {
                var inner = TrySpcSerializedObjectData(cur);
                if (inner is not null)
                {
                    cur = inner;
                    continue;
                }

                break;
            }
            else
            {
                break;
            }
        }

        return ConcatOctetsFromSetOfTypeAndOptionalValue(cur);
    }

    /// <summary>
    /// Parse the flat <c>offset_le ‖ digest</c> repetition (Rust <c>parse_page_hash_flat_pairs_le</c>). Stops at the
    /// first all-zero digest (terminator row) or end of input; fails on trailing non-padding bytes.
    /// </summary>
    public static List<PageHashTableEntry> ParseFlatPairsLe(ReadOnlySpan<byte> data, int digestLength)
    {
        if (digestLength <= 0)
        {
            throw new PsignException("digest_len must be non-zero");
        }

        int i = 0;
        var output = new List<PageHashTableEntry>();
        while ((long)i + 4 + digestLength <= data.Length)
        {
            uint pageEnd = BinaryPrimitives.ReadUInt32LittleEndian(data[i..]);
            var digest = data.Slice(i + 4, digestLength).ToArray();
            i += 4 + digestLength;
            if (digest.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                break;
            }

            output.Add(new PageHashTableEntry(pageEnd, digest));
        }

        if (i < data.Length && data[i..].IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new PsignException($"trailing bytes after PE page-hash table (offset {i})");
        }

        return output;
    }

    /// <summary>Peel wrappers then parse flat pairs using the digest width implied by <paramref name="kind"/>.</summary>
    public static List<PageHashTableEntry> ParseAttributeEntries(ReadOnlySpan<byte> valueDer, PageHashAttrKind kind) =>
        ParseFlatPairsLe(PeelAttributePayload(valueDer), DigestByteLength(kind));

    /// <summary>
    /// Experimental portable check: contiguous raw-file ranges implied by the parsed page-hash table (Rust
    /// <c>verify_page_hash_entries_contiguous_file_offsets</c>). Rows are sorted by end offset; each row hashes
    /// <c>pe_image[prev_end..end)</c> with SHA-1 (V1) or SHA-256 (V2).
    /// </summary>
    public static void VerifyEntriesContiguousFileOffsets(ReadOnlySpan<byte> peImage, IEnumerable<PageHashTableEntry> entries, PageHashAttrKind kind)
    {
        int expectedDigestLength = DigestByteLength(kind);
        var sorted = entries.OrderBy(e => e.PageEndOffset).ToList();
        long start = 0;
        foreach (var e in sorted)
        {
            if (e.Digest.Length != expectedDigestLength)
            {
                throw new PsignException(
                    $"page-hash digest length {e.Digest.Length} does not match {kind} expectation {expectedDigestLength}");
            }

            long end = e.PageEndOffset;
            if (end > peImage.Length)
            {
                throw new PsignException($"page_end_offset {end} exceeds PE image length {peImage.Length}");
            }

            if (end <= start)
            {
                throw new PsignException($"non-increasing or empty page-hash range (start={start} end={end})");
            }

            var slice = peImage[(int)start..(int)end];
            byte[] computed = kind == PageHashAttrKind.V1 ? SHA1.HashData(slice) : SHA256.HashData(slice);
            if (!computed.AsSpan().SequenceEqual(e.Digest))
            {
                throw new PsignException($"page-hash digest mismatch for file range [{start},{end}) (kind {kind})");
            }

            start = end;
        }
    }

    /// <summary>
    /// Parse every embedded page-hash attribute table and run <see cref="VerifyEntriesContiguousFileOffsets"/> (Rust
    /// <c>verify_pe_embedded_page_hash_tables</c>).
    /// </summary>
    public static void VerifyPeEmbeddedTables(byte[] peImage)
    {
        var locations = CollectPageHashAuthAttributes(peImage);
        if (locations.Count == 0)
        {
            throw new PsignException("no CMS signed_attributes carrying SPC_PE_IMAGE_PAGE_HASHES in embedded PKCS#7");
        }

        bool verifiedTable = false;
        foreach (var loc in locations)
        {
            foreach (var v in loc.Values)
            {
                var entries = ParseAttributeEntries(v.ValueDer, v.Kind);
                if (entries.Count == 0)
                {
                    continue;
                }

                try
                {
                    VerifyEntriesContiguousFileOffsets(peImage, entries, v.Kind);
                }
                catch (PsignException e)
                {
                    throw new PsignException(
                        $"pkcs7_index={loc.Pkcs7Index} signer_index={loc.SignerIndex} kind {v.Kind}", e);
                }

                verifiedTable = true;
            }
        }

        if (!verifiedTable)
        {
            throw new PsignException("PE page-hash attributes present but no non-empty parsable tables");
        }
    }

    /// <summary>Decode <c>ContentInfo(SignedData)</c> without normalization (Rust <c>decode_signed_data</c>).</summary>
    private static CmsSignedData? TryDecodeSignedData(ReadOnlySpan<byte> pkcs7)
    {
        try
        {
            var outer = Der.First(pkcs7);
            if (outer is null || outer.Value.Tag != 0x30)
            {
                return null;
            }

            var ci = Der.Children(pkcs7, outer.Value);
            if (ci is not { Count: 2 } || ci[0].Tag != 0x06 || ci[1].Tag != 0xA0)
            {
                return null;
            }

            if (Der.DecodeOid(ci[0].Encoded(pkcs7)) != Oids.Pkcs7SignedData)
            {
                return null;
            }

            var inner = Der.Children(pkcs7, ci[1]);
            if (inner is not { Count: 1 })
            {
                return null;
            }

            return CmsSignedData.ParseSignedData(inner[0].Encoded(pkcs7));
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException or OverflowException)
        {
            return null;
        }
    }

    private static List<List<PageHashAttrValue>> PageHashValuesFromSignedData(CmsSignedData sd)
    {
        var perSigner = new List<List<PageHashAttrValue>>(sd.SignerInfos.Count);
        foreach (var si in sd.SignerInfos)
        {
            var row = new List<PageHashAttrValue>();
            if (si.SignedAttributes is not null)
            {
                foreach (var attr in si.SignedAttributes)
                {
                    PageHashAttrKind? kind = attr.Oid switch
                    {
                        OidPePageHashesV1 => PageHashAttrKind.V1,
                        OidPePageHashesV2 => PageHashAttrKind.V2,
                        _ => null,
                    };
                    if (kind is null)
                    {
                        continue;
                    }

                    foreach (var val in attr.Values)
                    {
                        var tlv = Der.First(val) ?? throw new PsignException("malformed attribute value");
                        row.Add(new PageHashAttrValue(kind.Value, tlv.Value(val).ToArray()));
                    }
                }
            }

            perSigner.Add(row);
        }

        return perSigner;
    }

    /// <summary>
    /// Parse each embedded PKCS#7 and return non-empty page-hash attribute rows (CMS path only; Rust
    /// <c>pe_collect_page_hash_auth_attributes</c>). Blobs that fail <c>ContentInfo</c>/<c>SignedData</c> decoding are skipped.
    /// </summary>
    public static List<PePageHashAttrLocation> CollectPageHashAuthAttributes(byte[] image)
    {
        var pe = PeFile.Parse(image);
        var certs = pe.AttributeCertificates();
        var output = new List<PePageHashAttrLocation>();
        if (certs is null)
        {
            return output;
        }

        for (int pkcs7Index = 0; pkcs7Index < certs.Count; pkcs7Index++)
        {
            var attr = certs[pkcs7Index];
            if (attr.CertificateType != AttributeCertificate.WinCertTypePkcsSignedData)
            {
                continue;
            }

            var sd = TryDecodeSignedData(pe.CertificateData(attr));
            if (sd is null)
            {
                continue;
            }

            var rows = PageHashValuesFromSignedData(sd);
            for (int signerIndex = 0; signerIndex < rows.Count; signerIndex++)
            {
                if (rows[signerIndex].Count == 0)
                {
                    continue;
                }

                output.Add(new PePageHashAttrLocation(pkcs7Index, signerIndex, rows[signerIndex]));
            }
        }

        return output;
    }

    /// <summary>
    /// True if <paramref name="pkcs7Der"/> contains a DER OID TLV matching the V1 or V2 page-hash attributes (raw byte
    /// scan; Rust <c>pkcs7_signed_data_contains_page_hash_oid</c>).
    /// </summary>
    public static bool Pkcs7ContainsPageHashOid(ReadOnlySpan<byte> pkcs7Der) =>
        pkcs7Der.IndexOf(SpcPeImagePageHashesV1OidDer) >= 0 || pkcs7Der.IndexOf(SpcPeImagePageHashesV2OidDer) >= 0;

    /// <summary>
    /// Scan every embedded <c>WIN_CERT_TYPE_PKCS_SIGNED_DATA</c> entry (Rust
    /// <c>pe_embedded_pkcs7_contains_page_hash_attribute</c>): true when CMS parsing finds page-hash signed attributes
    /// or the raw OID scan matches; false when there is no certificate table or no match.
    /// </summary>
    public static bool PeEmbeddedPkcs7ContainsPageHashAttribute(byte[] image)
    {
        var pe = PeFile.Parse(image);
        var certs = pe.AttributeCertificates();
        if (certs is null)
        {
            return false;
        }

        foreach (var attr in certs)
        {
            if (attr.CertificateType != AttributeCertificate.WinCertTypePkcsSignedData)
            {
                continue;
            }

            var data = pe.CertificateData(attr);
            if (TryDecodeSignedData(data) is { } sd && PageHashValuesFromSignedData(sd).Any(r => r.Count != 0))
            {
                return true;
            }

            if (Pkcs7ContainsPageHashOid(data))
            {
                return true;
            }
        }

        return false;
    }
}
