using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;

namespace Devolutions.Psign.Core.Authenticode;

/// <summary>
/// Authenticode <c>SpcIndirectDataContent ::= SEQUENCE { data SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }</c>.
/// </summary>
public sealed class SpcIndirectDataContent
{
    /// <summary>Stable minimal <c>SpcPeImageData</c> SEQUENCE body used by SignTool for PE Authenticode.</summary>
    public static ReadOnlySpan<byte> SpcPeImageDataValue =>
    [
        0x03, 0x01, 0x00, 0xa0, 0x20, 0xa2, 0x1e, 0x80, 0x1c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00,
        0x4f, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00,
        0x3e, 0x00, 0x3e, 0x00, 0x3e,
    ];

    /// <summary>Stable CAB <c>SpcLink</c> value DER observed in Windows CAB Authenticode signatures.</summary>
    public static ReadOnlySpan<byte> SpcCabLinkValueDer =>
    [
        0xa1, 0x48, 0x04, 0x10, 0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17,
        0xda, 0x8e, 0x60, 0xd6, 0x04, 0x34, 0x31, 0x32, 0x30, 0x30, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
        0x01, 0x82, 0x37, 0x02, 0x05, 0x01, 0x31, 0x22, 0x04, 0x20, 0x1f, 0xa1, 0x2d, 0xdc, 0xd1, 0x11,
        0x50, 0x32, 0xe8, 0x90, 0x3f, 0x91, 0x52, 0x54, 0xb2, 0x19, 0x3a, 0x87, 0x34, 0xb1, 0x7e, 0x92,
        0x10, 0xd5, 0x52, 0x10, 0x8b, 0x77, 0x16, 0xee, 0x52, 0x9b,
    ];

    /// <summary>Stable MSI / MSIX <c>SpcSigInfo</c> value DER.</summary>
    public static ReadOnlySpan<byte> SpcMsiSigInfoValueDer =>
    [
        0x30, 0x24, 0x02, 0x01, 0x02, 0x04, 0x10, 0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    ];

    /// <summary>Stable PowerShell <c>SpcSigInfo</c> value DER observed in <c>signtool sign</c> script signatures.</summary>
    public static ReadOnlySpan<byte> SpcScriptSigInfoValueDer =>
    [
        0x30, 0x26, 0x02, 0x03, 0x01, 0x00, 0x00, 0x04, 0x10, 0x1f, 0xcc, 0x3b, 0x60, 0x59, 0x4b, 0x08,
        0x4e, 0xb7, 0x24, 0xd2, 0xc6, 0x29, 0x7e, 0xf3, 0x51, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02,
        0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    ];

    public SpcIndirectDataContent(string dataType, byte[]? dataValue, AlgorithmIdentifier digestAlgorithm, byte[] digest)
    {
        DataType = dataType;
        DataValue = dataValue;
        DigestAlgorithm = digestAlgorithm;
        Digest = digest;
    }

    /// <summary><c>data.type</c> OID (for example <c>SPC_PE_IMAGE_DATA_OBJID</c>).</summary>
    public string DataType { get; }

    /// <summary>Encoded <c>data.value</c> TLV, or <c>null</c> when absent.</summary>
    public byte[]? DataValue { get; }

    /// <summary><c>messageDigest.digestAlgorithm</c>.</summary>
    public AlgorithmIdentifier DigestAlgorithm { get; }

    /// <summary><c>messageDigest.digest</c> octets (the subject digest or MSIX AppX blob).</summary>
    public byte[] Digest { get; }

    /// <summary>Hash kind implied by <see cref="DigestAlgorithm"/>, if supported.</summary>
    public AuthenticodeHashKind? HashKind => AuthenticodeHashKinds.FromOid(DigestAlgorithm.Oid);

    /// <summary>DER encoding.</summary>
    public byte[] Encode()
    {
        var data = DataValue is null
            ? Der.EncodeSequence(Der.EncodeOid(DataType))
            : Der.EncodeSequence(Der.EncodeOid(DataType), DataValue);
        var digestInfo = Der.EncodeSequence(DigestAlgorithm.Encode(), Der.EncodeTlv(0x04, Digest));
        return Der.EncodeSequence(data, digestInfo);
    }

    /// <summary>Clone with a replaced digest of the same length (Rust <c>spc_indirect_data_replace_message_digest</c>).</summary>
    public SpcIndirectDataContent WithDigest(byte[] newDigest)
    {
        if (newDigest.Length != Digest.Length)
        {
            throw new PsignException(
                $"digest length {newDigest.Length} does not match template Authenticode digest field ({Digest.Length} octets)");
        }

        return new SpcIndirectDataContent(DataType, DataValue, DigestAlgorithm, newDigest);
    }

    /// <summary>Parse an encoded <c>SpcIndirectDataContent</c>.</summary>
    public static SpcIndirectDataContent Parse(ReadOnlySpan<byte> der)
    {
        var outer = Der.First(der);
        if (outer is null || outer.Value.Tag != 0x30)
        {
            throw new PsignException("SpcIndirectDataContent: expected SEQUENCE");
        }

        var c = Der.Children(der, outer.Value);
        if (c is null || c.Count != 2 || c[0].Tag != 0x30 || c[1].Tag != 0x30)
        {
            throw new PsignException("SpcIndirectDataContent: expected data and messageDigest");
        }

        var data = Der.Children(der, c[0]);
        if (data is null || data.Count is < 1 or > 2 || data[0].Tag != 0x06)
        {
            throw new PsignException("SpcIndirectDataContent: malformed SpcAttributeTypeAndOptionalValue");
        }

        string type = Der.DecodeOid(data[0].Encoded(der)) ?? throw new PsignException("SpcIndirectDataContent: bad type OID");
        byte[]? value = data.Count == 2 ? data[1].Encoded(der).ToArray() : null;

        var di = Der.Children(der, c[1]);
        if (di is null || di.Count != 2 || di[1].Tag != 0x04)
        {
            throw new PsignException("SpcIndirectDataContent: malformed DigestInfo");
        }

        var alg = AlgorithmIdentifier.Parse(di[0].Encoded(der));
        return new SpcIndirectDataContent(type, value, alg, di[1].Value(der).ToArray());
    }

    /// <summary>Decode <c>SpcIndirectDataContent</c> from a <see cref="CmsSignedData"/>'s encapsulated content.</summary>
    public static SpcIndirectDataContent FromSignedData(CmsSignedData sd)
    {
        if (sd.EncapContent is null)
        {
            throw new PsignException("SignedData missing encapsulated content");
        }

        try
        {
            return Parse(sd.EncapContent);
        }
        catch (PsignException e)
        {
            throw new PsignException($"SpcIndirectDataContent: {e.Message}", e);
        }
    }

    private static SpcIndirectDataContent Build(AuthenticodeHashKind kind, byte[] digest, string type, byte[] value, string label)
    {
        if (digest.Length != kind.DigestLength())
        {
            throw new PsignException(
                $"{label} digest length {digest.Length} does not match {Display(kind)} ({kind.DigestLength()} octets)");
        }

        return new SpcIndirectDataContent(type, value, AlgorithmIdentifier.WithNull(kind.Oid()), digest);
    }

    internal static string Display(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => "Sha1",
        AuthenticodeHashKind.Sha256 => "Sha256",
        AuthenticodeHashKind.Sha384 => "Sha384",
        _ => "Sha512",
    };

    /// <summary>PE image <c>SpcIndirectDataContent</c>.</summary>
    public static SpcIndirectDataContent ForPe(AuthenticodeHashKind kind, byte[] digest) =>
        Build(kind, digest, Oids.SpcPeImageData, Der.EncodeTlv(0x30, SpcPeImageDataValue), "PE");

    /// <summary>CAB <c>SpcIndirectDataContent</c>.</summary>
    public static SpcIndirectDataContent ForCab(AuthenticodeHashKind kind, byte[] digest) =>
        Build(kind, digest, Oids.SpcLink, SpcCabLinkValueDer.ToArray(), "CAB");

    /// <summary>MSI / MSP <c>SpcIndirectDataContent</c>.</summary>
    public static SpcIndirectDataContent ForMsi(AuthenticodeHashKind kind, byte[] digest) =>
        Build(kind, digest, Oids.SpcSigInfo, SpcMsiSigInfoValueDer.ToArray(), "MSI");

    /// <summary>PowerShell-class script <c>SpcIndirectDataContent</c>.</summary>
    public static SpcIndirectDataContent ForScript(AuthenticodeHashKind kind, byte[] digest) =>
        Build(kind, digest, Oids.SpcSigInfo, SpcScriptSigInfoValueDer.ToArray(), "script");

    /// <summary>MSIX / APPX <c>SpcIndirectDataContent</c> carrying the AppX digest blob (any length).</summary>
    public static SpcIndirectDataContent ForMsix(AuthenticodeHashKind kind, byte[] appxBlob) =>
        new(Oids.SpcSigInfo, SpcMsiSigInfoValueDer.ToArray(), AlgorithmIdentifier.WithNull(kind.Oid()), appxBlob);
}
