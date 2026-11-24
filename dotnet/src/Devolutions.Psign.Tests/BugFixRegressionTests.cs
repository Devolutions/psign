using System.Buffers.Binary;
using System.Security.Cryptography;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.ClickOnce;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.Pe;
using Devolutions.Psign.Core.Rdp;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Text;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Core.Xml;
using Devolutions.Psign.Core.Zip;
using Xunit;

namespace Devolutions.Psign.Tests;

public class BugFixRegressionTests
{
    // ---- Round 1 ----

    [Fact]
    public void R1_DerSequenceTotalLength_RejectsOverflow()
    {
        byte[] huge = [0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF];
        Assert.Null(Der.SequenceTotalLength(huge));
        Assert.Equal(huge, Pkcs7Wire.OuterSequencePrefix(huge).ToArray());
    }

    [Fact]
    public void R1_Asn1TimeDecode_RejectsTrailingData()
    {
        byte[] utcWithTrailing = [0x17, 0x0D, .. "240102030405Z"u8, 0x00];
        Assert.Throws<PsignException>(() => Asn1Time.Decode(utcWithTrailing));
    }

    [Fact]
    public void R1_Pkcs7WireNormalize_StripsTrailingPaddingOnBareSignedData()
    {
        byte[] signedData = Der.EncodeSequence(
            [0x02, 0x01, 0x01],
            [0x31, 0x00],
            Der.EncodeSequence(Der.EncodeOid(Oids.Pkcs7Data)),
            [0x31, 0x00]);
        byte[] withPadding = [.. signedData, 0x00, 0x00, 0x00, 0x00];
        byte[] normalized = Pkcs7Wire.NormalizeForAuthenticode(withPadding);
        var parsed = CmsSignedData.Parse(normalized);
        Assert.Equal(1, parsed.Version);
    }

    [Fact]
    public void R1_CertificateInfoTryParse_DoesNotThrowOverflowOnHugeVersion()
    {
        byte[] hugeInt = [0x02, 0x06, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        byte[] tbs = Der.EncodeSequence(Der.EncodeTlv(0xA0, hugeInt));
        byte[] cert = Der.EncodeSequence(tbs, AlgorithmIdentifier.WithNull(Oids.Sha256WithRsa).Encode(), [0x03, 0x02, 0x00, 0x01]);
        Assert.Null(CertificateInfo.TryParse(cert));
    }

    [Fact]
    public void R1_SignatureVerifier_HandlesMalformedSpkiAndRejectsAlgConfusion()
    {
        Assert.False(SignatureVerifier.Verify([0xFF, 0x00], AlgorithmIdentifier.WithNull(Oids.Sha256WithRsa), "hi"u8, [0x01]));
        Assert.False(SignatureVerifier.VerifyHash([0xFF, 0x00], AlgorithmIdentifier.WithNull(Oids.Sha256WithRsa), new byte[32], [0x01], AuthenticodeHashKind.Sha256));

        using var rsa = RSA.Create(2048);
        byte[] rsaSpki = rsa.ExportSubjectPublicKeyInfo();
        byte[] data = "test"u8.ToArray();
        byte[] sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.True(SignatureVerifier.Verify(rsaSpki, AlgorithmIdentifier.WithNull(Oids.Sha256WithRsa), data, sig));
        Assert.False(SignatureVerifier.Verify(rsaSpki, AlgorithmIdentifier.Absent(Oids.EcdsaWithSha256), data, sig));
        Assert.Null(SignatureVerifier.ResolveHash(new AlgorithmIdentifier(Oids.RsaPss, [0xFF]), AuthenticodeHashKind.Sha256));
    }

    [Fact]
    public void R1_Rfc3161_EmptyBitStringNonZeroUnusedAndLargeTlv()
    {
        Assert.Null(Rfc3161.PkiFailureInfoFlagLabelsFromBitStringTlv([0x03, 0x01, 0x05]));
        Assert.Empty(Rfc3161.PkiFailureInfoFlagLabelsFromBitStringTlv([0x03, 0x01, 0x00])!);
        Assert.Null(Rfc3161.PkiFailureInfoFlagLabelsFromBitStringTlv([0x03, 0x01, 0x00, 0x00]));

        // Large (>64KiB) TimeStampResp with 0x83 definite length
        byte[] statusInfo = Der.EncodeSequence([0x02, 0x01, 0x00]);
        byte[] bigToken = Der.EncodeTlv(0x30, new byte[70_000]);
        byte[] resp = Der.EncodeSequence(statusInfo, bigToken);
        var parsed = Rfc3161.ParseTimeStampRespDer(resp);
        Assert.NotNull(parsed);
        Assert.True(parsed!.PkiStatus.Granted);
        Assert.Equal(bigToken.Length, parsed.TimeStampToken!.Length);
    }

    [Fact]
    public void R1_Base64Standard_XmlDsigInvalidPaddingAndOffsetOrder()
    {
        Assert.Throws<PsignException>(() => Base64Standard.DecodeXmlDsig("===="));
        Assert.Throws<PsignException>(() => Base64Standard.DecodeXmlDsig("A==="));
        Assert.Throws<PsignException>(() => Base64Standard.DecodeXmlDsig("AA==AAAA"));
        Assert.Throws<PsignException>(() => Base64Standard.DecodeXmlDsig("=AAA"));
        var ex = Assert.Throws<FormatException>(() => Base64Standard.Decode("!AAA!"u8));
        Assert.Contains("offset 0", ex.Message);
    }

    // ---- Round 2 ----

    [Fact]
    public void R2_PsScript_Utf16LeBomSignDigestMatchesVerifierDigest()
    {
        byte[] utf16Script = [0xFF, 0xFE, .. RustText.Utf16LeBytes("Write-Host 'hi'\r\n")];
        byte[] signDigest = PsScript.SigningDigest(utf16Script, AuthenticodeHashKind.Sha256);

        using var pfx = Signing.PfxIdentity.Default();
        var indirect = SpcIndirectDataContent.ForScript(AuthenticodeHashKind.Sha256, signDigest);
        byte[] pkcs7 = Devolutions.Psign.Signing.Cms.Pkcs7Builder.CreateAuthenticode(indirect, AuthenticodeHashKind.Sha256, pfx.Signer, [], pfx.Key);
        byte[] signed = ScriptSignatureBlock.Embed(utf16Script, pkcs7, "ps1");

        var report = PsScript.PowerShellClassDigestReport(signed, "ps1");
        Assert.Equal(signDigest, report.ComputedDigest);
    }

    [Fact]
    public void R2_PageHashes_NonSerializedObject0x30DoesNotThrowInPeel()
    {
        // A flat page-hash entry starting with pageEnd = 0x00001030 (first byte 0x30) + 20-byte SHA-1 digest.
        byte[] flat = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(flat, 0x00001030);
        flat[4] = 0xAA;
        byte[] peeled = PageHashes.PeelAttributePayload(flat);
        Assert.Equal(flat, peeled);
    }

    [Fact]
    public void R2_RdpFile_DecodeRdpTextStripsUtf8BomOnLossyFallback()
    {
        // UTF-8 BOM + valid ASCII + invalid UTF-8 byte 0xFF later in a comment
        byte[] rdp = [0xEF, 0xBB, 0xBF, .. "full address:s:example.com\r\ncomment:s:bad"u8, 0xFF, .. "\r\n"u8];
        string text = RdpFile.DecodeRdpText(rdp);
        Assert.False(text.StartsWith('\uFEFF'));
        var records = RdpFile.ParseRecords(text);
        var prepared = RdpFile.PrepareForSignature(records);
        Assert.Contains("Full Address", prepared.SignScope);
    }

    // ---- Round 3 ----

    [Fact]
    public void R3_ZipCrateArchive_HandlesEocdMagicInsideComment()
    {
        var w = new ZipCrateWriter();
        w.StartFile("hello.txt", "world"u8.ToArray(), ZipCrateWriter.Stored, ZipDateTime.Default);
        byte[] zip = w.Finish();
        byte[] withTrickyComment = ZipAuthenticode.SetZipComment(zip, [.. "prefix "u8, 0x50, 0x4b, 0x05, 0x06, .. " suffix"u8]);
        var archive = ZipCrateArchive.Open(withTrickyComment);
        Assert.Equal("world"u8.ToArray(), archive.Read("hello.txt"));
    }

    [Fact]
    public void R3_ClickOnce_ResolveManifestPathRejectsColonAndTraversal()
    {
        Assert.Throws<PsignException>(() => ClickOnceManifest.ResolveManifestPath("C:\\base", "sub/C:/Windows/win.ini"));
        Assert.Throws<PsignException>(() => ClickOnceManifest.ResolveManifestPath("/base", "..\\secret.txt"));
        Assert.Throws<PsignException>(() => ClickOnceManifest.ResolveManifestPath("/base", "\\etc\\passwd"));
    }

    [Fact]
    public void R3_XmlTextScan_SkipsCommentsAndRespectsAttributeWordBoundaries()
    {
        string xml = "<!-- <MainPackage Publisher=\"evil\"/> --><AppInstaller><MainPackage OtherPublisher=\"x\" Publisher='old'/></AppInstaller>";
        var root = XmlTextScan.FindXmlRootStartTag(xml);
        Assert.Equal("AppInstaller", root.Name);
        var mp = XmlTextScan.FirstStartTagByLocalName(xml, "MainPackage");
        Assert.Equal("<MainPackage OtherPublisher=\"x\" Publisher='old'/>", mp);
        string updated = XmlTextScan.ReplaceOrInsertXmlAttr(mp!, "Publisher", "new");
        Assert.Equal("<MainPackage OtherPublisher=\"x\" Publisher=\"new\"/>", updated);
    }

    [Fact]
    public void R3_MsixDigest_RejectsNestedEmptyFileInBlockMap()
    {
        byte[] badBlockMap = """
            <?xml version="1.0" encoding="UTF-8"?>
            <BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="http://www.w3.org/2001/04/xmlenc#sha256">
              <File Name="a.txt" Size="0"><File Name="b.txt" Size="0"/></File>
            </BlockMap>
            """u8.ToArray();
        Assert.Throws<PsignException>(() => MsixDigest.ParseBlockMapXml(badBlockMap));
    }

    // ---- Round 4 ----

    [Fact]
    public void R4_OnlineTrust_ParseHttpUriGeneralNamesIgnores0x86InsideNonUriPrimitives()
    {
        // A SEQUENCE containing an OID with 0x86 byte (e.g. 2.16.840... has 0x86 0x48) followed by a real [6] URI
        byte[] oidWith0x86 = Der.EncodeOid(Oids.Sha256); // contains 0x86 0x48
        byte[] uriTlv = Der.EncodeTlv(0x86, "http://example.test/ca.crl"u8);
        byte[] cdp = Der.EncodeSequence(oidWith0x86, Der.EncodeTlv(0xA0, Der.EncodeTlv(0xA0, uriTlv)));
        var urls = Devolutions.Psign.Verification.OnlineTrust.ParseHttpUriGeneralNames(cdp);
        Assert.Equal(["http://example.test/ca.crl"], urls);
    }

    [Fact]
    public void R4_PickySignature_SupportsEcdsaP521WithSha512()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        byte[] spki = ec.ExportSubjectPublicKeyInfo();
        byte[] data = "p521-test"u8.ToArray();
        byte[] sig = ec.SignData(data, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
        Assert.Null(Devolutions.Psign.Verification.Picky.PickySignature.Verify(Oids.EcdsaWithSha512, spki, data, sig));
    }

    [Fact]
    public void R4_AuthRootCache_HugeMaxAgeDaysDoesNotOverflow()
    {
        var prev = Environment.GetEnvironmentVariable("PSIGN_AUTHROOT_MAX_AGE_DAYS");
        try
        {
            Environment.SetEnvironmentVariable("PSIGN_AUTHROOT_MAX_AGE_DAYS", "999999999999999");
            var opts = Devolutions.Psign.Verification.AuthRoot.AuthRootCacheOptions.FromEnv();
            Assert.True(opts.MaxAge > TimeSpan.Zero);
        }
        finally
        {
            Environment.SetEnvironmentVariable("PSIGN_AUTHROOT_MAX_AGE_DAYS", prev);
        }
    }

    // ---- Round 5 ----

    [Fact]
    public void R5_CmsTrustHelpers_RejectsTamperedSpcIndirectDataWithOriginalSignature()
    {
        using var pfx = Signing.PfxIdentity.Default();
        byte[] origDigest = SHA256.HashData("original"u8);
        var origIndirect = SpcIndirectDataContent.ForCab(AuthenticodeHashKind.Sha256, origDigest);
        byte[] pkcs7 = Devolutions.Psign.Signing.Cms.Pkcs7Builder.CreateAuthenticode(origIndirect, AuthenticodeHashKind.Sha256, pfx.Signer, [], pfx.Key);

        // Tamper eContent to claim a different subject digest while keeping signedAttrs + RSA signature untouched
        var sd = CmsSignedData.Parse(pkcs7);
        byte[] tamperedDigest = SHA256.HashData("tampered"u8);
        sd.EncapContent = SpcIndirectDataContent.ForCab(AuthenticodeHashKind.Sha256, tamperedDigest).Encode();

        Assert.Throws<PsignException>(() =>
            Devolutions.Psign.Verification.CmsTrustHelpers.VerifyAuthenticodeIndirectDigestAndRsaSha256(sd, 0, tamperedDigest));
    }

    [Fact]
    public void R5_TrustVerifySharedArgs_RejectsDoublePrefixAndHugeTimeout()
    {
        string doublePrefixed = "0x0X" + new string('a', 64);
        Assert.Throws<PsignException>(() => Devolutions.Psign.Verification.TrustVerifySharedArgs.ParseSha256Hex(doublePrefixed));

        var args = new Devolutions.Psign.Verification.TrustVerifySharedArgs
        {
            TrustedCa = ["dummy.crt"],
            OnlineTimeoutSecs = ulong.MaxValue,
        };
        var opts = args.ToOptions();
        Assert.True(opts.Online.Timeout > TimeSpan.Zero);
    }

    [Fact]
    public void R5_Rfc3161Extract_SigningTimeRejectsTrailingBytes()
    {
        byte[] utcWithTrailing = [0x17, 0x0D, .. "240102030405Z"u8, 0x00];
        Assert.Null(Devolutions.Psign.Verification.Rfc3161Extract.UtcDateFromSigningTimeAny(utcWithTrailing));
    }

    // ---- Round 6 ----

    [Fact]
    public void R6_PortableCertStore_RejectsDotTraversalStoreNames()
    {
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.CertStore.PortableCertStore.NormalizeStoreName("."));
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.CertStore.PortableCertStore.NormalizeStoreName(".."));
    }

    [Fact]
    public void R6_Pkcs7Builder_SigningTimeHandlesPost2049GeneralizedTime()
    {
        var future = new DateTimeOffset(2055, 6, 15, 12, 30, 0, TimeSpan.Zero);
        var attr = Devolutions.Psign.Signing.Cms.Pkcs7Builder.SigningTimeAttribute(future);
        Assert.Single(attr.Values);
        Assert.Equal(0x18, attr.Values[0][0]); // GeneralizedTime tag
        Assert.Equal(future, Asn1Time.Decode(attr.Values[0]));
    }

    [Fact]
    public void R6_TimestampClient_InvalidUrlThrowsPsignException()
    {
        using var client = new Devolutions.Psign.Signing.Timestamp.TimestampClient();
        Assert.Throws<PsignException>(() => client.PostTimestampRequest("not a url", [0x30, 0x00]));
        Assert.Throws<PsignException>(() => client.RequestToken("not a url", AuthenticodeHashKind.Sha256, [1, 2, 3]));
    }

    // ---- Round 7 ----

    [Fact]
    public void R7_AzureKeyVault_Base64UrlDecodeRejectsNonZeroTrailingBits()
    {
        // "AB" has non-zero unused trailing bits (0x01 in bottom 4 bits)
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.AzureKeyVault.AzureKeyVaultClient.Base64UrlDecode("AB"));
        Assert.Equal([0x00], Devolutions.Psign.Signing.AzureKeyVault.AzureKeyVaultClient.Base64UrlDecode("AA"));
    }

    [Fact]
    public void R7_RdpSigner_ParseThumbprintRejectsPlusSign()
    {
        string bogus = string.Concat(Enumerable.Repeat("+a", 20));
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.Rdp.RdpSigner.ParseThumbprint(bogus, 20, "SHA1"));
    }

    [Fact]
    public void R7_PortableRemove_HandlesUppercaseAndDotPrefixedExtensions()
    {
        string signed = "<root/>\r\n<!-- SIG # Begin signature block -->\r\n<!-- AAAA -->\r\n<!-- SIG # End signature block -->\r\n";
        Assert.Equal("<root/>", Devolutions.Psign.Signing.Remove.PortableRemove.RemoveScriptSignatureBlock(signed, ".PS1XML"));
    }

    [Fact]
    public void R7_VsixSigner_AddSignatureTimestampHandlesPrefixedSignatureAndEncodedTime()
    {
        byte[] xml = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></ds:Signature>"u8.ToArray();
        byte[] stamped = Devolutions.Psign.Signing.Vsix.VsixSigner.AddSignatureTimestamp(xml, [0x30, 0x00]);
        Assert.Contains("EncodedTime", System.Text.Encoding.UTF8.GetString(stamped));
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.Vsix.VsixSigner.AddSignatureTimestamp(stamped, [0x30, 0x00]));
    }

    // ---- Round 8 ----

    [Fact]
    public void R8_CodePatterns_BoundsHugeBraceRangesAndPreservesEscapedBraces()
    {
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.Code.CodePatterns.ExpandBraces("{0..1000000}"));
        var rules = Devolutions.Psign.Signing.Code.CodePatterns.PatternRules(@"dir/\{a,b\}.dll");
        Assert.Single(rules);
        Assert.Equal("dir/{a,b}.dll", rules[0].Pattern);
    }

    [Fact]
    public void R8_PortableCore_RemoveClickOnceXmlSignatureHandlesCommentsAndPrefix()
    {
        string xml = "<asm><!-- <Signature>comment</Signature> --><ds:Signature>sig</ds:Signature></asm>";
        string cleaned = Devolutions.Psign.Signing.Portable.PortableCore.RemoveClickOnceXmlSignature(xml);
        Assert.Equal("<asm><!-- <Signature>comment</Signature> --></asm>", cleaned);
    }

    // ---- Round 9 ----

    [Fact]
    public void R9_CommandLineParser_RejectsDuplicateCombinedShortFlags()
    {
        var root = Devolutions.Psign.Cli.PsignTool.BuildRoot();
        Assert.Throws<Devolutions.Psign.Cli.Framework.UsageException>(() =>
            Devolutions.Psign.Cli.Framework.CommandLineParser.Parse(root, ["-qq", "portable"], "psign-tool"));
    }

    [Fact]
    public void R9_ResponseArgv_UnescapesDoubleAtInsideResponseFile()
    {
        using var dir = new TempDir();
        var rsp = dir.File("escaped.rsp");
        File.WriteAllText(rsp, "verify\n@@literal\n@@\n");
        var expanded = Devolutions.Psign.Cli.Framework.ResponseArgv.ExpandInvocations(["@" + rsp]);
        Assert.Single(expanded);
        Assert.Equal(["verify", "@literal", "@"], expanded[0]);
    }

    [Fact]
    public void R9_NativeArgv_DoesNotRewriteArgumentsAfterCodeSubcommand()
    {
        var normalized = Devolutions.Psign.Cli.Framework.NativeArgv.Normalize(["code", "--output", "sign", "/fd", "sha256"]);
        Assert.Equal(["code", "--output", "sign", "/fd", "sha256"], normalized);
    }

    // ---- Rounds 11–20 ----

    [Fact]
    public void R12_ZipDateTime_RejectsInvalidCalendarDayAndClampsDefault()
    {
        Assert.Null(Devolutions.Psign.Core.Zip.ZipDateTime.FromDateAndTime(2025, 2, 30, 12, 0, 0));
        Assert.NotNull(Devolutions.Psign.Core.Zip.ZipDateTime.FromDateAndTime(2024, 2, 29, 12, 0, 0));
        var def = default(Devolutions.Psign.Core.Zip.ZipDateTime);
        Assert.Equal((ushort)0, def.DatePart);
        Assert.Equal((ushort)0, def.TimePart);
        Assert.Equal((ushort)0x0021, Devolutions.Psign.Core.Zip.ZipDateTime.Default.DatePart);
    }

    [Fact]
    public void R12_PsignException_RenderIncludesAllAggregateExceptionInners()
    {
        var agg = new AggregateException(new InvalidOperationException("first failure"), new IOException("second failure"));
        var rendered = PsignException.Render(agg);
        Assert.Contains("first failure", rendered);
        Assert.Contains("second failure", rendered);
    }

    [Fact]
    public void R13_MsZipInflater_RejectsOutputExceedingExpectedBlockSize()
    {
        // Stored DEFLATE block claiming 10 bytes of output when uncompressedSize is 4.
        byte[] payload = [(byte)'C', (byte)'K', 0x01, 0x0A, 0x00, 0xF5, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        var inflater = new Devolutions.Psign.Verification.AuthRoot.MsZipInflater();
        Assert.Throws<InvalidDataException>(() => inflater.DecompressBlock(payload, 4));
        Assert.Throws<InvalidDataException>(() => inflater.DecompressBlock(payload, -1));
    }

    [Fact]
    public void R13_Anchors_ParsesUtf8BomPrefixedPemCertificate()
    {
        var ca = Devolutions.Psign.Signing.Pki.TestPki.GenerateRootCa(new("CN=BOM Test Root"));
        var pem = Devolutions.Psign.Signing.Pki.TestPki.EncodePemCertificateBundle([ca.CertificateDer]);
        var withBom = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(System.Text.Encoding.UTF8.GetBytes(pem)).ToArray();
        var parsed = Devolutions.Psign.Verification.Anchors.ParseCertBytes(withBom);
        Assert.Equal(ca.CertificateDer, parsed.RawData);
    }

    [Fact]
    public void R13_AuthRootCache_TreatsOverflowingUnixTimestampAsStale()
    {
        using var dir = new TempDir();
        var cabPath = Path.Combine(dir.DirPath, Devolutions.Psign.Verification.AuthRoot.AuthRootCache.AuthRootCabFileName);
        var metaPath = Path.Combine(dir.DirPath, Devolutions.Psign.Verification.AuthRoot.AuthRootCache.AuthRootMetaFileName);
        File.WriteAllBytes(cabPath, [1, 2, 3]);
        File.WriteAllText(metaPath, "{\"downloaded_at_unix_secs\": 999999999999999}");
        bool fetched = false;
        var opts = new Devolutions.Psign.Verification.AuthRoot.AuthRootCacheOptions { CacheDir = dir.DirPath };
        var res = Devolutions.Psign.Verification.AuthRoot.AuthRootCache.GetOrDownloadAuthRootCabWith(opts, _ =>
        {
            fetched = true;
            return [9, 8, 7];
        });
        Assert.True(fetched);
        Assert.True(res.Refreshed);
    }

    [Fact]
    public void R14_DistinguishedName_RejectsLeadingZeroAndOverflowOidArcs()
    {
        Assert.False(Devolutions.Psign.Signing.Pki.DistinguishedName.IsValidOid("1.2.0840"));
        Assert.False(Devolutions.Psign.Signing.Pki.DistinguishedName.IsValidOid("01.2.3"));
        Assert.False(Devolutions.Psign.Signing.Pki.DistinguishedName.IsValidOid("1.2.999999999999999999999999999"));
        Assert.True(Devolutions.Psign.Signing.Pki.DistinguishedName.IsValidOid("1.2.840.113549"));
    }

    [Fact]
    public void R14_TestPki_RejectsOverflowingValidityDaysWithPsignException()
    {
        Assert.Throws<PsignException>(() =>
            Devolutions.Psign.Signing.Pki.TestPki.GenerateRootCa(new("CN=Overflow Test", ValidityDays: uint.MaxValue)));
    }

    [Fact]
    public void R14_ArtifactSigningClient_OperationLocationUrlIsCaseInsensitiveOnScheme()
    {
        var url = Devolutions.Psign.Signing.ArtifactSigning.ArtifactSigningClient.OperationLocationUrl(
            "https://eus.codesigning.azure.net",
            "HTTPS://eus.codesigning.azure.net/operations/123");
        Assert.Equal("HTTPS://eus.codesigning.azure.net/operations/123", url);
    }

    [Fact]
    public void R15_PortableCore_ScriptExtensionForSupportsBareExtensions()
    {
        Assert.Equal("mof", Devolutions.Psign.Signing.Portable.PortableCore.ScriptExtensionFor("mof"));
        Assert.Equal("ps1xml", Devolutions.Psign.Signing.Portable.PortableCore.ScriptExtensionFor(".ps1xml"));
        Assert.Equal("cdxml", Devolutions.Psign.Signing.Portable.PortableCore.ScriptExtensionFor("CDXML"));
    }

    [Fact]
    public void R15_PortableCore_InsertClickOnceSignatureIgnoresTrailingComment()
    {
        const string manifest = "<assembly><identity/></assembly><!-- </fake> -->";
        var signed = Devolutions.Psign.Signing.Portable.PortableCore.InsertClickOnceSignatureInManifest(manifest, "<Signature/>");
        Assert.Equal("<assembly><identity/><Signature/></assembly><!-- </fake> -->", signed);
    }

    [Fact]
    public void R15_PortableCertStore_RejectsColonInStoreName()
    {
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.CertStore.PortableCertStore.NormalizeStoreName("MY:stream"));
        Assert.Throws<PsignException>(() => Devolutions.Psign.Signing.CertStore.PortableCertStore.NormalizeStoreName("C:"));
    }

    [Fact]
    public void R15_PortableRemove_IgnoresMidLineSignatureMarker()
    {
        var body = "Write-Host \"# SIG # Begin signature block\n# AAAA\n# SIG # End signature block\"";
        Assert.Null(Devolutions.Psign.Signing.Remove.PortableRemove.RemoveScriptSignatureBlock(body, "ps1"));
    }

    [Fact]
    public void R18_CommandLineParser_RejectsShortFlagEqualsAndSupportsHelpSubcommand()
    {
        var root = Devolutions.Psign.Cli.PsignTool.BuildRoot();
        Assert.Throws<Devolutions.Psign.Cli.Framework.UsageException>(() =>
            Devolutions.Psign.Cli.Framework.CommandLineParser.Parse(root, ["-q=true", "portable"], "psign-tool"));

        var help = Assert.Throws<Devolutions.Psign.Cli.Framework.HelpRequestedException>(() =>
            Devolutions.Psign.Cli.Framework.CommandLineParser.Parse(root, ["help", "verify"], "psign-tool"));
        Assert.Contains("psign-tool verify", help.Text);
    }

    [Fact]
    public void R19_ServerDerPush_SupportsFourByteLengthAndRejectsInvalidCalendarDate()
    {
        var buf = new List<byte>();
        Devolutions.Psign.Server.DerPush.PushLen(buf, 0x01020304);
        Assert.Equal(new byte[] { 0x84, 0x01, 0x02, 0x03, 0x04 }, buf.ToArray());

        Assert.Throws<PsignException>(() => Devolutions.Psign.Server.DerPush.ValidateGeneralizedTimeZ("20269999999999Z"));
        Assert.Throws<PsignException>(() => Devolutions.Psign.Server.DerPush.ValidateGeneralizedTimeZ("20250229000000Z"));
        Devolutions.Psign.Server.DerPush.ValidateGeneralizedTimeZ("20240229235959Z");
    }

    [Fact]
    public void R19_ServerTimestampAuthority_EncodesHighFailInfoBitAcrossMultipleBytes()
    {
        var resp = Devolutions.Psign.Server.TimestampAuthority.BuildStatusOnlyResponse(2, null, 15);
        // Bit 15 -> byte index 1, bit 7 (LSB of 2nd byte = 0x01), 0 unused bits -> 03 03 00 00 01.
        Assert.Contains(new byte[] { 0x03, 0x03, 0x00, 0x00, 0x01 }, FindSubsequence(resp, [0x03, 0x03, 0x00, 0x00, 0x01]));
    }

    [Fact]
    public void RubberDuck_ExistingBracketedFilenameIsNotExpandedAsGlob()
    {
        using var dir = new TempDir();
        var literal = dir.File("invoice[1].ps1");
        var other = dir.File("invoice1.ps1");
        File.WriteAllText(literal, "Write-Host 'literal'\n");
        File.WriteAllText(other, "Write-Host 'other'\n");
        var targets = Devolutions.Psign.Cli.TopLevel.SignCommand.ExpandSignTargets(
            new Devolutions.Psign.Cli.TopLevel.SignArgs { Files = [literal] });
        Assert.Equal([literal], targets);
    }

    private static IEnumerable<byte[]> FindSubsequence(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                yield return needle;
            }
        }
    }
}
