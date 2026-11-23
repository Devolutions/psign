using Devolutions.Psign.Core.Asn1;

namespace Devolutions.Psign.Core.Cms;

/// <summary>CMS <c>Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }</c> with raw values.</summary>
public sealed class CmsAttribute
{
    public CmsAttribute(string oid, IEnumerable<byte[]> values)
    {
        Oid = oid;
        Values = values.ToList();
    }

    public CmsAttribute(string oid, byte[] value)
        : this(oid, [value])
    {
    }

    /// <summary>Attribute type OID.</summary>
    public string Oid { get; }

    /// <summary>Encoded attribute value TLVs (in parse order; encoding sorts them).</summary>
    public List<byte[]> Values { get; }

    /// <summary>DER encoding (values sorted per SET OF rules).</summary>
    public byte[] Encode() => Der.EncodeSequence(Der.EncodeOid(Oid), Der.EncodeSetOf(0x31, Values));

    /// <summary>Parse an encoded <c>Attribute</c>.</summary>
    public static CmsAttribute Parse(ReadOnlySpan<byte> der)
    {
        var outer = Der.First(der);
        if (outer is null || outer.Value.Tag != 0x30 || outer.Value.End != der.Length)
        {
            throw new PsignException("Attribute: expected SEQUENCE");
        }

        var children = Der.Children(der, outer.Value);
        if (children is null || children.Count != 2 || children[0].Tag != 0x06 || children[1].Tag != 0x31)
        {
            throw new PsignException("Attribute: expected OID and SET OF values");
        }

        string oid = Der.DecodeOid(children[0].Encoded(der)) ?? throw new PsignException("Attribute: invalid OID");
        var values = Der.Children(der, children[1]) ?? throw new PsignException("Attribute: malformed values");
        var list = new List<byte[]>(values.Count);
        foreach (var v in values)
        {
            list.Add(v.Encoded(der).ToArray());
        }

        return new CmsAttribute(oid, list);
    }

    /// <summary>Parse the content of an attribute SET (the octets inside <c>[0]</c>/<c>[1]</c>/<c>SET</c>).</summary>
    public static List<CmsAttribute> ParseSetContent(ReadOnlySpan<byte> content)
    {
        var children = Der.Children(content, 0, content.Length)
            ?? throw new PsignException("Attributes: malformed SET content");
        var result = new List<CmsAttribute>(children.Count);
        foreach (var c in children)
        {
            result.Add(Parse(c.Encoded(content)));
        }

        return result;
    }

    /// <summary>Encode a list of attributes as a DER SET with <paramref name="tag"/> (0x31, 0xA0, 0xA1).</summary>
    public static byte[] EncodeSet(byte tag, IEnumerable<CmsAttribute> attributes) =>
        Der.EncodeSetOf(tag, attributes.Select(a => a.Encode()));
}
