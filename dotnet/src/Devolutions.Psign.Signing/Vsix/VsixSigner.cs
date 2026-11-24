using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Vsix;

namespace Devolutions.Psign.Signing.Vsix;

/// <summary>Result of <c>VsixSigner.SignPackage</c>.</summary>
public sealed record VsixSignResult(byte[] SignedPackage, byte[] SignatureXml, VsixSignatureTemplate Template);

/// <summary>
/// VSIX OPC XMLDSig signing (ported from the <c>vsix-signature-xml</c> / <c>vsix-sign</c> handlers in Rust
/// <c>psign-digest-cli/src/main.rs</c>, <c>sign_vsix_bytes</c> in <c>src/code.rs</c> and
/// <c>vsix::add_signature_timestamp</c>).
/// </summary>
public static class VsixSigner
{
    /// <summary>RSA PKCS#1 v1.5 signature over the canonical <c>SignedInfo</c> (Rust <c>sign_xml_signed_info</c>).</summary>
    public static byte[] SignSignedInfo(VsixHashAlgorithm algorithm, RSA key, byte[] signedInfo) =>
        key.SignData(signedInfo, algorithm.ToHashKind().HashAlgorithmName(), RSASignaturePadding.Pkcs1);

    /// <summary>Digest a remote signer must sign (Rust <c>xml_signed_info_remote_prehash</c>).</summary>
    public static byte[] SignedInfoRemotePrehash(VsixHashAlgorithm algorithm, byte[] signedInfo) => algorithm.Hash(signedInfo);

    /// <summary>
    /// Signature XML for a package (Rust <c>vsix-signature-xml</c> uses <see cref="VsixSigningTime.FromPackage"/>;
    /// <c>vsix-sign</c> uses <see cref="VsixSigningTime.Now"/>). <paramref name="signSignedInfo"/> returns the RSA
    /// signature over the canonical <c>SignedInfo</c> octets.
    /// </summary>
    public static (byte[] SignatureXml, VsixSignatureTemplate Template) CreateSignatureXml(
        byte[] package,
        VsixHashAlgorithm algorithm,
        byte[] signerCertDer,
        Func<byte[], byte[]> signSignedInfo,
        VsixSigningTime signingTime,
        DateTimeOffset? now = null)
    {
        var template = VsixPackage.SignatureTemplate(package, algorithm, signingTime, now);
        var signature = signSignedInfo(template.SignedInfo);
        return (template.SignatureXmlBytes(signature, signerCertDer), template);
    }

    /// <summary><see cref="CreateSignatureXml(byte[], VsixHashAlgorithm, byte[], Func{byte[], byte[]}, VsixSigningTime, DateTimeOffset?)"/> with a local RSA key.</summary>
    public static (byte[] SignatureXml, VsixSignatureTemplate Template) CreateSignatureXml(
        byte[] package,
        VsixHashAlgorithm algorithm,
        byte[] signerCertDer,
        RSA key,
        VsixSigningTime signingTime,
        DateTimeOffset? now = null) =>
        CreateSignatureXml(package, algorithm, signerCertDer, si => SignSignedInfo(algorithm, key, si), signingTime, now);

    /// <summary>
    /// Insert an RFC 3161 timestamp token (DER <c>ContentInfo</c> over the <c>SignatureValue</c> octets) as the
    /// dotnet/sign <c>&lt;Object&gt;&lt;TimeStamp&gt;&lt;EncodedTime&gt;</c> element (Rust <c>add_signature_timestamp</c>).
    /// </summary>
    public static byte[] AddSignatureTimestamp(byte[] signatureXml, byte[] tokenDer)
    {
        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(signatureXml);
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("VSIX signature XML is not UTF-8", e);
        }

        if (Core.Xml.XmlTextScan.FindXmlStartTagByLocalName(text, "EncodedTime", 0) is not null)
        {
            throw new PsignException("VSIX signature XML is already timestamped");
        }

        var root = Core.Xml.XmlTextScan.FindXmlRootStartTag(text);
        string closeTag = $"</{root.Name}>";
        int end = text.LastIndexOf(closeTag, StringComparison.Ordinal);
        if (end < 0)
        {
            throw new PsignException("VSIX signature XML is missing </Signature>");
        }

        string stamp = $"<Object><TimeStamp Id=\"idSignatureTimestamp\" xmlns=\"{VsixPackage.OpcDigitalSignatureNs}\"><Comment>Timestamp got from the time stamp server</Comment><EncodedTime>{Convert.ToBase64String(tokenDer)}</EncodedTime></TimeStamp></Object>";
        return Encoding.UTF8.GetBytes(text[..end] + stamp + text[end..]);
    }

    /// <summary>Octets an RFC 3161 imprint is computed over: the decoded <c>SignatureValue</c>.</summary>
    public static byte[] TimestampImprintInput(byte[] signatureXml) => VsixPackage.SignatureValueFromSignatureXml(signatureXml);

    /// <summary>
    /// Sign a package end-to-end (Rust <c>vsix-sign</c>): template with the current time, RSA signature, optional
    /// timestamp through <paramref name="timestampToken"/> (receives the signature value, returns the token DER), and
    /// embedding.
    /// </summary>
    public static VsixSignResult SignPackage(
        byte[] package,
        VsixHashAlgorithm algorithm,
        byte[] signerCertDer,
        Func<byte[], byte[]> signSignedInfo,
        bool overwrite,
        DateTimeOffset? now = null,
        Func<byte[], byte[]>? timestampToken = null)
    {
        var info = VsixPackage.InspectVsix(package);
        if (info.HasOpcSignature && !overwrite)
        {
            throw new PsignException("package already contains OPC signature parts; pass overwrite to replace them");
        }

        var (xml, template) = CreateSignatureXml(package, algorithm, signerCertDer, signSignedInfo, VsixSigningTime.Now, now);
        if (timestampToken is not null)
        {
            xml = AddSignatureTimestamp(xml, timestampToken(TimestampImprintInput(xml)));
        }

        return new VsixSignResult(VsixPackage.EmbedSignatureXml(package, xml, overwrite), xml, template);
    }

    /// <summary><see cref="SignPackage(byte[], VsixHashAlgorithm, byte[], Func{byte[], byte[]}, bool, DateTimeOffset?, Func{byte[], byte[]}?)"/> with a local RSA key.</summary>
    public static VsixSignResult SignPackage(
        byte[] package,
        VsixHashAlgorithm algorithm,
        byte[] signerCertDer,
        RSA key,
        bool overwrite,
        DateTimeOffset? now = null,
        Func<byte[], byte[]>? timestampToken = null) =>
        SignPackage(package, algorithm, signerCertDer, si => SignSignedInfo(algorithm, key, si), overwrite, now, timestampToken);
}
