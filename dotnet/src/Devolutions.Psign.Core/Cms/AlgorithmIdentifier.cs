using Devolutions.Psign.Core.Asn1;

namespace Devolutions.Psign.Core.Cms;

/// <summary>X.509 <c>AlgorithmIdentifier</c> with raw (DER) parameters.</summary>
public sealed class AlgorithmIdentifier : IEquatable<AlgorithmIdentifier>
{
    public AlgorithmIdentifier(string oid, byte[]? parameters = null)
    {
        Oid = oid;
        Parameters = parameters;
    }

    /// <summary>Algorithm OID.</summary>
    public string Oid { get; }

    /// <summary>Encoded parameters TLV, or <c>null</c> when absent.</summary>
    public byte[]? Parameters { get; }

    /// <summary>True when parameters are an explicit ASN.1 NULL.</summary>
    public bool HasNullParameters => Parameters is { Length: 2 } p && p[0] == 0x05 && p[1] == 0x00;

    /// <summary>Create an identifier with explicit NULL parameters.</summary>
    public static AlgorithmIdentifier WithNull(string oid) => new(oid, Der.Null);

    /// <summary>Create an identifier with absent parameters.</summary>
    public static AlgorithmIdentifier Absent(string oid) => new(oid);

    /// <summary>DER encoding.</summary>
    public byte[] Encode() => Parameters is null
        ? Der.EncodeSequence(Der.EncodeOid(Oid))
        : Der.EncodeSequence(Der.EncodeOid(Oid), Parameters);

    /// <summary>Parse an encoded <c>AlgorithmIdentifier</c> SEQUENCE.</summary>
    public static AlgorithmIdentifier Parse(ReadOnlySpan<byte> der)
    {
        var outer = Der.First(der);
        if (outer is null || outer.Value.Tag != 0x30 || outer.Value.End != der.Length)
        {
            throw new PsignException("AlgorithmIdentifier: expected SEQUENCE");
        }

        var children = Der.Children(der, outer.Value)
            ?? throw new PsignException("AlgorithmIdentifier: malformed content");
        if (children.Count is < 1 or > 2 || children[0].Tag != 0x06)
        {
            throw new PsignException("AlgorithmIdentifier: expected OID and optional parameters");
        }

        string oid = Der.DecodeOid(children[0].Encoded(der))
            ?? throw new PsignException("AlgorithmIdentifier: invalid OID");
        byte[]? parameters = children.Count == 2 ? children[1].Encoded(der).ToArray() : null;
        return new AlgorithmIdentifier(oid, parameters);
    }

    public bool Equals(AlgorithmIdentifier? other) =>
        other is not null && Oid == other.Oid &&
        (Parameters is null ? other.Parameters is null : other.Parameters is not null && Parameters.AsSpan().SequenceEqual(other.Parameters));

    public override bool Equals(object? obj) => obj is AlgorithmIdentifier a && Equals(a);

    public override int GetHashCode() => Oid.GetHashCode(StringComparison.Ordinal);

    public override string ToString() => Oid;
}
