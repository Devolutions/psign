using System.Text.Json.Serialization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Pe;

namespace Devolutions.Psign.Verification;

/// <summary>One PKCS#7 <c>SignedData</c> layer (outer or nested).</summary>
public sealed record InspectPkcs7Report
{
    [JsonPropertyName("content_type_oid")]
    public string ContentTypeOid { get; init; } = Oids.Pkcs7SignedData;

    [JsonPropertyName("encap_content_type_oid")]
    public string? EncapContentTypeOid { get; init; }

    [JsonPropertyName("certificate_count")]
    public int CertificateCount { get; init; }

    [JsonPropertyName("authenticode_digest")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public InspectAuthenticodeDigest? AuthenticodeDigest { get; init; }

    [JsonPropertyName("timestamp_signing_time")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TimestampSigningTime { get; init; }

    [JsonPropertyName("signers")]
    public List<InspectSigner> Signers { get; init; } = [];

    /// <summary>PKCS#7 blobs found under OID <c>1.3.6.1.4.1.311.2.4.1</c> (Microsoft nested signature).</summary>
    [JsonPropertyName("nested_signatures")]
    public List<InspectPkcs7Report> NestedSignatures { get; init; } = [];
}

/// <summary>Embedded Authenticode digest.</summary>
public sealed record InspectAuthenticodeDigest
{
    [JsonPropertyName("digest_algorithm_oid")]
    public string DigestAlgorithmOid { get; init; } = string.Empty;

    /// <summary>Lowercase hex of the embedded Authenticode message digest.</summary>
    [JsonPropertyName("digest_hex")]
    public string DigestHex { get; init; } = string.Empty;
}

/// <summary>One <c>SignerInfo</c>.</summary>
public sealed record InspectSigner
{
    [JsonPropertyName("signer_index")]
    public int SignerIndex { get; init; }

    [JsonPropertyName("digest_algorithm_oid")]
    public string DigestAlgorithmOid { get; init; } = string.Empty;

    [JsonPropertyName("signer_certificate_der_base64")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SignerCertificateDerBase64 { get; init; }

    [JsonPropertyName("timestamp_signer_certificate_der_base64")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TimestampSignerCertificateDerBase64 { get; init; }

    [JsonPropertyName("signed_attribute_oids")]
    public List<string> SignedAttributeOids { get; init; } = [];

    [JsonPropertyName("unsigned_attribute_oids")]
    public List<string> UnsignedAttributeOids { get; init; } = [];

    [JsonPropertyName("timestamp_hints")]
    public List<TimestampHint> TimestampHints { get; init; } = [];
}

/// <summary>Timestamp-related attribute hint.</summary>
public sealed record TimestampHint
{
    [JsonPropertyName("kind")]
    public string Kind { get; init; } = string.Empty;

    [JsonPropertyName("attribute_oid")]
    public string AttributeOid { get; init; } = string.Empty;
}

/// <summary>One PE attribute certificate.</summary>
public sealed record InspectPeEntry
{
    [JsonPropertyName("attribute_certificate_index")]
    public int AttributeCertificateIndex { get; init; }

    [JsonPropertyName("pkcs7")]
    public InspectPkcs7Report Pkcs7 { get; init; } = new();
}

/// <summary>All PKCS#7 attribute certificates of a PE image.</summary>
public sealed record InspectPeFileReport
{
    [JsonPropertyName("entries")]
    public List<InspectPeEntry> Entries { get; init; } = [];
}

/// <summary>
/// Portable Authenticode PKCS#7 inspection (nested signatures, timestamp OIDs) — Rust <c>inspect.rs</c>. Serialize the
/// reports with <see cref="RustJson.ToStringPretty{T}"/> for output identical to <c>psign-tool portable inspect-authenticode</c>.
/// </summary>
public static class AuthenticodeInspector
{
    private const string OidMsNestedSignature = "1.3.6.1.4.1.311.2.4.1";
    private const int DefaultMaxNestDepth = 16;

    /// <summary>Inspect a single PKCS#7 blob (embedded or detached), including nested signatures.</summary>
    public static InspectPkcs7Report InspectAuthenticodePkcs7Der(ReadOnlySpan<byte> pkcs7Der) =>
        InspectRecursive(pkcs7Der, 0, DefaultMaxNestDepth);

    /// <summary>Inspect every <c>WIN_CERT_TYPE_PKCS_SIGNED_DATA</c> attribute certificate on a PE image.</summary>
    public static InspectPeFileReport InspectPeAuthenticode(byte[] peBytes)
    {
        var entries = new List<InspectPeEntry>();
        PeAuthenticode.ForEachPkcs7(peBytes, (idx, der) =>
            entries.Add(new InspectPeEntry { AttributeCertificateIndex = idx, Pkcs7 = InspectRecursive(der, 0, DefaultMaxNestDepth) }));
        return new InspectPeFileReport { Entries = entries };
    }

    private static InspectPkcs7Report InspectRecursive(ReadOnlySpan<byte> pkcs7Der, int depth, int maxDepth)
    {
        if (depth > maxDepth)
        {
            throw new PsignException($"nested PKCS#7 depth exceeds limit ({maxDepth}); possible corrupt or cyclic structure");
        }

        var slice = Pkcs7Wire.NormalizeForAuthenticode(pkcs7Der);
        CmsSignedData sd;
        try
        {
            sd = DecodeSignedData(slice);
        }
        catch (PsignException e)
        {
            throw new PsignException($"decode SignedData: {e.Message}");
        }

        InspectAuthenticodeDigest? digest = null;
        try
        {
            var sig = AuthenticodeSignature.Parse(slice);
            var d = sig.Digest;
            digest = new InspectAuthenticodeDigest
            {
                DigestAlgorithmOid = d.Length switch
                {
                    20 => Oids.Sha1,
                    32 => Oids.Sha256,
                    48 => Oids.Sha384,
                    64 => Oids.Sha512,
                    var n => $"unknown_digest_length_{n}_bytes",
                },
                DigestHex = Hex.Lower(d),
            };
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
        }

        string? signingTime = Rfc3161Extract.UtcDateFromAuthenticodeTimestampToken(slice) is { } t
            ? $"{t.Year:0000}-{t.Month:00}-{t.Day:00}T00:00:00Z"
            : null;

        var signers = new List<InspectSigner>();
        var nested = new List<InspectPkcs7Report>();
        for (int i = 0; i < sd.SignerInfos.Count; i++)
        {
            var si = sd.SignerInfos[i];
            signers.Add(InspectSignerInfo(sd, i, si));
            foreach (var attr in si.UnsignedAttributes ?? [])
            {
                if (attr.Oid != OidMsNestedSignature)
                {
                    continue;
                }

                foreach (var val in attr.Values)
                {
                    var payload = ValueOctets(val);
                    var der = DecodeNestedPkcs7Payload(payload);
                    if (der is null)
                    {
                        continue;
                    }

                    try
                    {
                        nested.Add(InspectRecursive(der, depth + 1, maxDepth));
                    }
                    catch (PsignException)
                    {
                    }
                }
            }
        }

        return new InspectPkcs7Report
        {
            ContentTypeOid = Oids.Pkcs7SignedData,
            EncapContentTypeOid = sd.EncapContentType,
            CertificateCount = sd.Certificates?.Count ?? 0,
            AuthenticodeDigest = digest,
            TimestampSigningTime = signingTime,
            Signers = signers,
            NestedSignatures = nested,
        };
    }

    private static byte[] ValueOctets(byte[] tlv)
    {
        var t = Core.Asn1.Der.First(tlv);
        return t is null ? [] : t.Value.Value(tlv).ToArray();
    }

    private static CmsSignedData DecodeSignedData(ReadOnlySpan<byte> pkcs7Der)
    {
        if (pkcs7Der.IsEmpty)
        {
            throw new PsignException("empty PKCS#7");
        }

        var ci = Rfc3161Extract.DecodeContentInfo(pkcs7Der) ?? throw new PsignException("ContentInfo: malformed ContentInfo");
        if (ci.ContentType != Oids.Pkcs7SignedData)
        {
            throw new PsignException($"expected SignedData ContentInfo, got OID {ci.ContentType}");
        }

        try
        {
            return CmsSignedData.ParseSignedData(ci.Content);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            throw new PsignException($"SignedData: {e.Message}");
        }
    }

    private static byte[]? DecodeNestedPkcs7Payload(byte[] payload)
    {
        if (TryDecode(payload))
        {
            return payload;
        }

        var inner = Rfc3161Extract.PeelOctetStringOuter(payload);
        return inner is not null && TryDecode(inner) ? inner : null;

        static bool TryDecode(byte[] b)
        {
            try
            {
                DecodeSignedData(b);
                return true;
            }
            catch (PsignException)
            {
                return false;
            }
        }
    }

    private static string? CertificateDerBase64ForSigner(CmsSignedData sd, CmsSignerInfo si)
    {
        try
        {
            return Convert.ToBase64String(sd.CertificateForSigner(si).RawData);
        }
        catch (PsignException)
        {
            return null;
        }
    }

    private static string? TimestampSignerCertDerBase64(byte[] payload)
    {
        var der = DecodeNestedPkcs7Payload(payload);
        if (der is null)
        {
            return null;
        }

        var sd = DecodeSignedData(der);
        return sd.SignerInfos.Count == 0 ? null : CertificateDerBase64ForSigner(sd, sd.SignerInfos[0]);
    }

    private static InspectSigner InspectSignerInfo(CmsSignedData sd, int index, CmsSignerInfo si)
    {
        var hints = new List<TimestampHint>();
        string? tsCert = null;
        foreach (var attr in si.SignedAttributes ?? [])
        {
            if (attr.Oid == Oids.Pkcs9SigningTime)
            {
                hints.Add(new TimestampHint { Kind = "pkcs9_signing_time", AttributeOid = attr.Oid });
            }
        }

        foreach (var attr in si.UnsignedAttributes ?? [])
        {
            string? kind = attr.Oid switch
            {
                Oids.Pkcs9Rfc3161TimestampToken => "id_aa_time_stamp_token",
                Oids.MsRfc3161TimestampToken => "microsoft_nested_rfc3161_attribute",
                _ => null,
            };
            if (kind is null)
            {
                continue;
            }

            hints.Add(new TimestampHint { Kind = kind, AttributeOid = attr.Oid });
            tsCert ??= attr.Values.Select(TimestampSignerCertDerBase64).FirstOrDefault(v => v is not null);
        }

        return new InspectSigner
        {
            SignerIndex = index,
            DigestAlgorithmOid = si.DigestAlgorithm.Oid,
            SignerCertificateDerBase64 = CertificateDerBase64ForSigner(sd, si),
            TimestampSignerCertificateDerBase64 = tsCert,
            SignedAttributeOids = si.SignedAttributes?.Select(a => a.Oid).ToList() ?? [],
            UnsignedAttributeOids = si.UnsignedAttributes?.Select(a => a.Oid).ToList() ?? [],
            TimestampHints = hints,
        };
    }
}
