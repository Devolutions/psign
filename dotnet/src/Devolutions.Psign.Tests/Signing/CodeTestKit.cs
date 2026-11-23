using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.ClickOnce;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.AzureKeyVault;
using Devolutions.Psign.Signing.Internal;
using Xunit;

namespace Devolutions.Psign.Tests.Signing;

/// <summary>Shared helpers for the <c>psign-tool code</c> tests (port of the helpers in Rust <c>tests/code_command.rs</c>).</summary>
internal static class CodeTestKit
{
    public const string SampleClickOnceManifest = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n  <assemblyIdentity name=\"ClickOnce.Sample\" version=\"1.0.0.0\" />\n  <description asmv2:publisher=\"Example\" xmlns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" />\n</assembly>";

    public const string FlatContentTypes = "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\"/><Default Extension=\"exe\" ContentType=\"application/octet-stream\"/><Override PartName=\"/AppxManifest.xml\" ContentType=\"application/vnd.ms-appx.manifest+xml\"/><Override PartName=\"/AppxBlockMap.xml\" ContentType=\"application/vnd.ms-appx.blockmap+xml\"/></Types>";

    public const string BlockMap = "<BlockMap HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>";

    // A fake (unsigned) RFC 3161 token ContentInfo: SEQUENCE { OID signedData, [0] { SEQUENCE {} } }.
    public static readonly byte[] FakeTimestampToken = Der.EncodeSequence(Der.EncodeOid("1.2.840.113549.1.7.2"), Der.EncodeTlv(0xA0, Der.EncodeSequence()));

    public static string Repo => Fixtures.RepoRoot;

    public static string TinyPe => Fixtures.Path("pe-authenticode-upstream/tiny32.efi");

    public static string TinySignedPe => Fixtures.Path("pe-authenticode-upstream/tiny32.signed.efi");

    public static string Pkg(string rel) => Fixtures.Path("package-signing/" + rel);

    public static void WriteFile(string path, byte[] bytes)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
    }

    public static void WriteZip(string path, params (string Name, byte[] Data)[] entries)
    {
        var writer = new ZipCrateWriter();
        foreach (var (name, data) in entries)
        {
            writer.StartFile(name, data);
        }

        WriteFile(path, writer.Finish());
    }

    public static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    public static byte[] ReadZipEntry(string zipPath, string name)
    {
        var archive = ZipCrateArchive.Open(File.ReadAllBytes(zipPath));
        return archive.Read(archive.RequireByName(name));
    }

    public static string ExtractZipEntry(string zipPath, string name, string output)
    {
        File.WriteAllBytes(output, ReadZipEntry(zipPath, name));
        return output;
    }

    /// <summary>Flat MSIX with an unsigned PE payload.</summary>
    public static (string Name, byte[] Data)[] FlatMsixEntries(string identityName, string arch) =>
    [
        ("[Content_Types].xml", Utf8(FlatContentTypes)),
        ("AppxManifest.xml", Utf8($"<Package><Identity Name=\"{identityName}\" Publisher=\"CN=Old\" Version=\"1.0.0.0\" ProcessorArchitecture=\"{arch}\"/></Package>")),
        ("AppxBlockMap.xml", Utf8(BlockMap)),
        ("app.exe", File.ReadAllBytes(TinyPe)),
    ];

    // ------------------------------------------------------------------ verification

    public static void AssertPeVerifies(string path) => PeAuthenticode.VerifyDigestConsistency(File.ReadAllBytes(path));

    public static void AssertNuGetSigned(string path)
    {
        var info = NuGetPackage.InspectNupkgPath(path);
        Assert.True(info.Signed, $"{path} should be signed");
        Assert.True(info.SignatureIsStored, $"{path} signature should be stored");
    }

    /// <summary>Verify the NuGet CMS: content matches the package, RSA signature over the signed attributes is valid.</summary>
    public static CmsSignedData AssertNuGetSignatureValid(string path)
    {
        AssertNuGetSigned(path);
        var der = NuGetPackage.ExtractSignaturePath(path);
        var sd = AssertCmsSignatureValid(der, null);
        Assert.Equal(Oids.Pkcs7Data, sd.EncapContentType);
        var content = NuGetPackage.SignedPackageSignatureContentPath(path, NuGetHashAlgorithm.Sha256);
        Assert.Equal(Der.EncodeTlv(0x04, content), sd.EncapContent);
        return sd;
    }

    /// <summary>Check NuGet author attributes (commitment-type proofOfOrigin, signing-time, signing-certificate-v2).</summary>
    public static void AssertNuGetAuthorAttributes(string path)
    {
        var sd = AssertNuGetSignatureValid(path);
        var si = sd.SignerInfos[0];
        var commitment = si.GetSignedAttribute(Oids.Pkcs9CommitmentTypeIndication);
        Assert.NotNull(commitment);
        var value = Assert.Single(commitment!.Values);
        Assert.Equal(Der.EncodeSequence(Der.EncodeOid(Oids.CommitmentTypeProofOfOrigin)), value);
        Assert.NotNull(si.GetSignedAttribute(Oids.Pkcs9SigningTime));
        Assert.Single(si.GetSignedAttribute(Oids.Pkcs9SigningCertificateV2)!.Values);
    }

    /// <summary>Verify messageDigest and the RSA PKCS#1 v1.5 signature of the first signer; returns the parsed CMS.</summary>
    public static CmsSignedData AssertCmsSignatureValid(byte[] pkcs7, byte[]? detachedContent)
    {
        var sd = CmsSignedData.Parse(pkcs7);
        var si = sd.SignerInfos[0];
        var signer = sd.Certificates!.Select(c => CertificateInfo.Parse(c)).First(si.MatchesCertificate);
        var kind = AuthenticodeHashKinds.FromOid(si.DigestAlgorithm.Oid)!.Value;
        byte[] content;
        if (detachedContent is not null)
        {
            content = detachedContent;
        }
        else
        {
            var t = Der.First(sd.EncapContent!)!.Value;
            content = t.Value(sd.EncapContent!).ToArray();
        }

        Assert.Equal(kind.Hash(content), si.MessageDigest());
        using var rsa = signer.X509.GetRSAPublicKey()!;
        Assert.True(rsa.VerifyData(si.SignedAttributesSetDer(), si.Signature, kind.HashAlgorithmName(), RSASignaturePadding.Pkcs1));
        return sd;
    }

    public static bool HasUnsignedAttribute(byte[] pkcs7, string oid) =>
        CmsSignedData.Parse(pkcs7).SignerInfos[0].UnsignedAttributes?.Any(a => a.Oid == oid) == true;

    /// <summary>Verify the package's OPC XMLDSig: references match the package and the SignatureValue verifies.</summary>
    public static void AssertVsixSignatureValid(byte[] package, byte[]? expectedCertDer = null)
    {
        var xml = VsixPackage.ExtractSignatureXml(package);
        Assert.True(VsixPackage.VerifySignatureReferenceXml(package, xml, VsixHashAlgorithm.Sha256) > 0);
        var certDer = VsixPackage.SignerCertificateFromSignatureXml(xml);
        if (expectedCertDer is not null)
        {
            Assert.Equal(expectedCertDer, certDer);
        }

        ClickOnceManifest.VerifySignedInfo(
            AuthenticodeHashKind.Sha256,
            CertificateInfo.Parse(certDer),
            CanonicalSignedInfo(xml),
            VsixPackage.SignatureValueFromSignatureXml(xml),
            "VSIX");
    }

    private static byte[] CanonicalSignedInfo(byte[] signatureXml)
    {
        var root = Devolutions.Psign.Core.Xml.XmlC14n.ParseDocument(signatureXml);
        var signedInfo = root.Children.OfType<Devolutions.Psign.Core.Xml.XmlC14nElement>().First(e => e.LocalName == "SignedInfo");
        return Devolutions.Psign.Core.Xml.XmlC14n.Canonicalize(signedInfo, Devolutions.Psign.Core.Xml.C14nMode.Inclusive);
    }

    public static void AssertClickOnceSignatureValid(string path, byte[]? certDer = null) =>
        ClickOnceManifest.VerifyManifestSignature(File.ReadAllText(path), AuthenticodeHashKind.Sha256, certDer);

    // ------------------------------------------------------------------ mock services

    /// <summary>In-memory HTTP handler driven by a delegate.</summary>
    internal sealed class LambdaHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, byte[], HttpResponseMessage> _respond;

        public LambdaHandler(Func<HttpRequestMessage, byte[], HttpResponseMessage> respond) => _respond = respond;

        public int Requests { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            lock (this)
            {
                Requests++;
            }

            return _respond(request, body);
        }
    }

    public static HttpResponseMessage Json(JsonObject body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(RustJson.Compact(body), Encoding.UTF8, "application/json") };

    /// <summary>Mock TSA returning a granted <c>TimeStampResp</c> with <see cref="FakeTimestampToken"/>.</summary>
    public static LambdaHandler TimestampServer() => new((request, body) =>
    {
        Assert.Equal("application/timestamp-query", request.Content!.Headers.ContentType!.MediaType);
        var resp = Der.EncodeSequence(Der.EncodeSequence(Der.EncodeTlv(0x02, [0])), FakeTimestampToken);
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(resp) };
    });

    /// <summary>Mock Azure Key Vault (certificate metadata + <c>keys/sign</c> with <paramref name="key"/>).</summary>
    public static LambdaHandler KeyVault(RSA key, byte[] certDer, string vault) => new((request, body) =>
    {
        var url = request.RequestUri!.AbsoluteUri;
        if (request.Method == HttpMethod.Get && url.Contains("/certificates/code-cert", StringComparison.Ordinal))
        {
            return Json(new JsonObject { ["kid"] = vault + "/keys/code-cert/v1", ["cer"] = Convert.ToBase64String(certDer) });
        }

        if (request.Method == HttpMethod.Post && url.Contains("/keys/code-cert/v1/sign", StringComparison.Ordinal))
        {
            var json = JsonNode.Parse(body)!;
            var alg = json["alg"]!.GetValue<string>();
            var digest = AzureKeyVaultClient.Base64UrlDecode(json["value"]!.GetValue<string>());
            var hash = alg switch
            {
                "RS384" => HashAlgorithmName.SHA384,
                "RS512" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256,
            };
            var sig = key.SignHash(digest, hash, RSASignaturePadding.Pkcs1);
            return Json(new JsonObject { ["kid"] = vault + "/keys/code-cert/v1", ["value"] = AzureKeyVaultClient.Base64UrlEncode(sig) });
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("unexpected " + url) };
    });

    /// <summary>Mock Artifact Signing data plane: <c>:sign</c> answers synchronously with the signature and certificate.</summary>
    public static LambdaHandler ArtifactSigning(RSA key, byte[] certDer) => new((request, body) =>
    {
        var json = JsonNode.Parse(body)!;
        var digest = Convert.FromBase64String(json["digest"]!.GetValue<string>());
        var hash = json["signatureAlgorithm"]!.GetValue<string>() switch
        {
            "RS384" => HashAlgorithmName.SHA384,
            "RS512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };
        return Json(new JsonObject
        {
            ["status"] = "Succeeded",
            ["signature"] = Convert.ToBase64String(key.SignHash(digest, hash, RSASignaturePadding.Pkcs1)),
            ["signingCertificate"] = Convert.ToBase64String(certDer),
        });
    });
}
