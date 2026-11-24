using Devolutions.Psign.Core.Asn1;

namespace Devolutions.Psign.Core.Cms;

/// <summary>PKCS#7 / CMS wire normalization (port of <c>pkcs7_wire.rs</c>).</summary>
public static class Pkcs7Wire
{
    private static readonly byte[] SignedDataOidDer = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

    /// <summary>PKCS#7 <c>ContentInfo</c> bytes at the start of <paramref name="data"/>, trimming trailing octets.</summary>
    public static ReadOnlySpan<byte> OuterSequencePrefix(ReadOnlySpan<byte> data)
    {
        var n = Der.SequenceTotalLength(data);
        if (n is null || n.Value > data.Length)
        {
            return data;
        }

        return data[..n.Value];
    }

    /// <summary>Same as <see cref="OuterSequencePrefix"/> but returns <c>null</c> when the input does not start with a SEQUENCE.</summary>
    public static byte[]? TryOuterSequencePrefix(ReadOnlySpan<byte> data)
    {
        var n = Der.SequenceTotalLength(data);
        if (n is null || n.Value > data.Length)
        {
            return null;
        }

        return data[..n.Value].ToArray();
    }

    /// <summary>Strip the AppX <c>PKCX</c> wrapper used by <c>AppxSignature.p7x</c>.</summary>
    public static ReadOnlySpan<byte> StripPkcx(ReadOnlySpan<byte> data) =>
        data.StartsWith("PKCX"u8) ? data[4..] : data;

    /// <summary>True when <paramref name="data"/> begins with the <c>PKCX</c> magic.</summary>
    public static bool HasPkcxWrapper(ReadOnlySpan<byte> data) => data.StartsWith("PKCX"u8);

    /// <summary>Wrap a bare <c>SignedData</c> SEQUENCE in a PKCS#7 <c>ContentInfo</c>.</summary>
    public static byte[] WrapSignedDataInContentInfo(ReadOnlySpan<byte> signedDataDer)
    {
        var explicitTag = Der.EncodeTlv(0xA0, signedDataDer);
        return Der.EncodeTlv(0x30, SignedDataOidDer, explicitTag);
    }

    /// <summary>
    /// Normalize detached PKCS#7 blobs: strip the PKCX wrapper, wrap bare <c>SignedData</c> as <c>ContentInfo</c>, and
    /// remove exact-duplicate certificates from the <c>SignedData.certificates</c> set.
    /// </summary>
    public static byte[] NormalizeForAuthenticode(ReadOnlySpan<byte> blob)
    {
        blob = StripPkcx(blob);
        var outer = Der.First(blob);
        byte[] normalized;
        if (outer is null || outer.Value.Tag != 0x30)
        {
            return blob.ToArray();
        }

        // Only wrap the outer SEQUENCE TLV itself so trailing padding (e.g. PE WIN_CERTIFICATE alignment) does not break [0] EXPLICIT parsing.
        var inner = blob[outer.Value.ValueStart..outer.Value.ValueEnd];
        if (!inner.IsEmpty && inner[0] == 0x02)
        {
            normalized = WrapSignedDataInContentInfo(outer.Value.Encoded(blob));
        }
        else
        {
            normalized = blob.ToArray();
        }

        return DedupeSignedDataCertificateSet(normalized) ?? normalized;
    }

    private static byte[]? DedupeSignedDataCertificateSet(byte[] contentInfo)
    {
        ReadOnlySpan<byte> d = contentInfo;
        var outer = Der.TlvAt(d, 0, d.Length);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            return null;
        }

        var outerChildren = Der.Children(d, outer.Value);
        if (outerChildren is null || outerChildren.Count < 2)
        {
            return null;
        }

        if (!outerChildren[0].Encoded(d).SequenceEqual(SignedDataOidDer))
        {
            return null;
        }

        var explicitTlv = outerChildren[1];
        if (explicitTlv.Tag != 0xA0)
        {
            return null;
        }

        var explicitChildren = Der.Children(d, explicitTlv);
        if (explicitChildren is null || explicitChildren.Count < 1 || explicitChildren[0].Tag != 0x30)
        {
            return null;
        }

        var signedData = explicitChildren[0];
        var signedChildren = Der.Children(d, signedData);
        if (signedChildren is null)
        {
            return null;
        }

        DerTlv? certificates = null;
        foreach (var child in signedChildren.Skip(3))
        {
            if (child.Tag == 0xA0)
            {
                certificates = child;
                break;
            }
        }

        if (certificates is null)
        {
            return null;
        }

        var certChildren = Der.Children(d, certificates.Value);
        if (certChildren is null)
        {
            return null;
        }

        var unique = new List<byte[]>();
        bool removed = false;
        using var content = new MemoryStream();
        foreach (var child in certChildren)
        {
            var encoded = child.Encoded(d).ToArray();
            if (unique.Any(u => u.AsSpan().SequenceEqual(encoded)))
            {
                removed = true;
                continue;
            }

            unique.Add(encoded);
            content.Write(encoded);
        }

        if (!removed)
        {
            return null;
        }

        var certsDeduped = Der.EncodeTlv(certificates.Value.Tag, content.ToArray());
        var signedDeduped = ReplaceChild(d, signedData, certificates.Value, certsDeduped);
        var explicitDeduped = ReplaceChild(d, explicitTlv, signedData, signedDeduped);
        return ReplaceChild(d, outer.Value, explicitTlv, explicitDeduped);
    }

    private static byte[] ReplaceChild(ReadOnlySpan<byte> data, DerTlv parent, DerTlv child, byte[] replacement)
    {
        using var ms = new MemoryStream();
        ms.Write(data[parent.ValueStart..child.TagStart]);
        ms.Write(replacement);
        ms.Write(data[child.End..parent.ValueEnd]);
        return Der.EncodeTlv(parent.Tag, ms.ToArray());
    }
}
