using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Verification.AuthRoot;

/// <summary>Parse Microsoft CTL <c>eContent</c> bodies for SHA-1 <c>SubjectIdentifier</c> thumbprints (Rust <c>authroot_ctl.rs</c>).</summary>
public static class AuthRootCtl
{
    /// <summary>
    /// Extract trusted-subject SHA-1 identifiers from an AuthRoot-style <c>.stl</c> blob (PKCS#7 <c>ContentInfo</c> →
    /// <c>SignedData</c>). Returns an empty list on parse failure. The result is sorted and de-duplicated.
    /// </summary>
    public static List<byte[]> CtlSubjectSha1ThumbprintsFromStlBytes(ReadOnlySpan<byte> buf)
    {
        List<byte[]> thumbs;
        try
        {
            thumbs = CtlThumbsFromSignedDataEContent(buf);
        }
        catch (PsignException)
        {
            thumbs = [];
        }

        return SortDedup(thumbs);
    }

    internal static List<byte[]> SortDedup(IEnumerable<byte[]> thumbs)
    {
        var sorted = thumbs.ToList();
        sorted.Sort((a, b) => a.AsSpan().SequenceCompareTo(b));
        var output = new List<byte[]>();
        foreach (var t in sorted)
        {
            if (output.Count == 0 || !output[^1].AsSpan().SequenceEqual(t))
            {
                output.Add(t);
            }
        }

        return output;
    }

    private static List<byte[]> CtlThumbsFromSignedDataEContent(ReadOnlySpan<byte> buf)
    {
        if (buf.IsEmpty)
        {
            throw new PsignException("empty STL buffer");
        }

        var ci = Rfc3161Extract.DecodeContentInfo(buf) ?? throw new PsignException("STL is not PKCS#7 ContentInfo");
        if (ci.ContentType != Oids.Pkcs7SignedData)
        {
            throw new PsignException("STL ContentInfo is not SignedData");
        }

        CmsSignedData sd;
        try
        {
            sd = CmsSignedData.ParseSignedData(ci.Content);
        }
        catch (Exception e) when (e is PsignException or System.Formats.Asn1.AsnContentException or FormatException)
        {
            throw new PsignException($"STL SignedData decode: {e.Message}");
        }

        byte[] econtent = [];
        if (sd.EncapContent is { } ec && Der.First(ec) is { } t)
        {
            econtent = t.Value(ec).ToArray();
        }

        return ParseCtlInnerSubjectSha1s(econtent);
    }

    private static List<byte[]> ParseCtlInnerSubjectSha1s(byte[] econtent)
    {
        var output = new List<byte[]>();
        var seqContent = TlvSequencePayload(econtent);
        if (seqContent is not null)
        {
            if (seqContent.Length > econtent.Length / 2)
            {
                output.AddRange(ExtractSubjectsFromCtlChildren(seqContent));
            }
            else
            {
                foreach (var child in TlvCollectChildren(econtent) ?? [])
                {
                    if (ParseSubjectList(child) is { } ts)
                    {
                        output.AddRange(ts);
                    }
                }
            }
        }

        if (output.Count == 0)
        {
            output.AddRange(ExtractSubjectsFromCtlChildren(econtent));
        }

        if (output.Count == 0)
        {
            output.AddRange(ParseSubjectList(econtent) ?? []);
        }

        return output;
    }

    private static List<byte[]> ExtractSubjectsFromCtlChildren(byte[] content)
    {
        var output = new List<byte[]>();
        foreach (var child in TlvCollectChildren(content) ?? [])
        {
            if (ParseSubjectList(child) is { } ts)
            {
                output.AddRange(ts);
            }
        }

        return output;
    }

    /// <summary>Parse a <c>SEQUENCE OF TrustedSubject</c>; <c>null</c> on structural error.</summary>
    internal static List<byte[]>? ParseSubjectList(byte[] seqTlv)
    {
        var content = TlvSequencePayload(seqTlv);
        if (content is null)
        {
            return null;
        }

        var els = TlvCollectChildren(content);
        if (els is null)
        {
            return null;
        }

        var thumbs = new List<byte[]>();
        foreach (var el in els)
        {
            if (el.Length == 0 || el[0] != 0x30)
            {
                continue;
            }

            var inner = TlvSequencePayload(el);
            if (inner is null)
            {
                return null;
            }

            var parts = TlvCollectChildren(inner);
            if (parts is null)
            {
                return null;
            }

            if (parts.Count > 0 && TlvOctetStringFixed(parts[0], 20) is { } t)
            {
                thumbs.Add(t);
            }
        }

        return thumbs;
    }

    private static byte[]? TlvSequencePayload(byte[] input)
    {
        if (input.Length == 0 || input[0] != 0x30)
        {
            return null;
        }

        var parsed = ParseDerLen(input.AsSpan(1));
        if (parsed is null)
        {
            return null;
        }

        long end = 1L + parsed.Value.Header + parsed.Value.Len;
        if (end > input.Length)
        {
            return null;
        }

        return input[(1 + parsed.Value.Header)..(int)end];
    }

    private static (int Len, int Header)? ParseDerLen(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty)
        {
            return null;
        }

        byte first = bytes[0];
        if ((first & 0x80) == 0)
        {
            return (first, 1);
        }

        int n = first & 0x7f;
        if (n == 0 || n > 4 || bytes.Length < 1 + n)
        {
            return null;
        }

        long len = 0;
        for (int i = 0; i < n; i++)
        {
            len = (len << 8) | bytes[1 + i];
        }

        return len > int.MaxValue ? null : ((int)len, 1 + n);
    }

    private static List<byte[]>? TlvCollectChildren(byte[] content)
    {
        var v = new List<byte[]>();
        int i = 0;
        while (i < content.Length)
        {
            var parsed = ParseDerLen(content.AsSpan(i + 1));
            if (parsed is null)
            {
                return null;
            }

            long total = 1L + parsed.Value.Header + parsed.Value.Len;
            if (i + total > content.Length)
            {
                // Rust slices `content[i..i + total]` here, which panics on overrun; treat as malformed.
                return null;
            }

            v.Add(content[i..(int)(i + total)]);
            i += (int)total;
        }

        return v;
    }

    private static byte[]? TlvOctetStringFixed(byte[] input, int expectedLen)
    {
        if (input.Length == 0 || input[0] != 0x04)
        {
            return null;
        }

        var parsed = ParseDerLen(input.AsSpan(1));
        if (parsed is null || parsed.Value.Len != expectedLen || input.Length < 1 + parsed.Value.Header + parsed.Value.Len)
        {
            return null;
        }

        return input[(1 + parsed.Value.Header)..(1 + parsed.Value.Header + expectedLen)];
    }
}
