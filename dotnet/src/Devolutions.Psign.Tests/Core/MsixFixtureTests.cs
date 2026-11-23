using System.Text.Json;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.Zip;
using Xunit;

namespace Devolutions.Psign.Tests.Core;

/// <summary>Fixture-driven MSIX tests (ports of <c>tests/msix_edge_cases_portable.rs</c> digest-level checks).</summary>
public class MsixFixtureTests
{
    internal sealed record EdgeEntry(
        string Id,
        string Extension,
        string Digest,
        bool IsSparseBundle,
        bool IsEncrypted,
        bool IsUploadContainer,
        string ExpectedPortableVerify,
        string? UnsignedPath,
        string? SignedPath);

    internal static List<EdgeEntry> LoadManifest()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Fixtures.Path("msix-edge-cases/msix-edge-case-fixtures.json")));
        var list = new List<EdgeEntry>();
        foreach (var e in doc.RootElement.GetProperty("entries").EnumerateArray())
        {
            static string? Opt(JsonElement e, string name) =>
                e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            list.Add(new EdgeEntry(
                e.GetProperty("id").GetString()!,
                e.GetProperty("extension").GetString()!,
                e.GetProperty("digest").GetString()!,
                e.GetProperty("is_sparse_bundle").GetBoolean(),
                e.GetProperty("is_encrypted").GetBoolean(),
                e.GetProperty("is_upload_container").GetBoolean(),
                e.GetProperty("expected_portable_verify").GetString()!,
                Opt(e, "unsigned_path"),
                Opt(e, "signed_path")));
        }

        return list;
    }

    internal static string RepoFixture(string repoRelative) => Path.Combine(Fixtures.RepoRoot, repoRelative.Replace('/', Path.DirectorySeparatorChar));

    [Fact]
    public void EdgeCaseCorpusVerifiesOrRejectsAsDeclared()
    {
        foreach (var entry in LoadManifest())
        {
            switch (entry.ExpectedPortableVerify)
            {
                case "valid":
                    {
                        var signed = RepoFixture(entry.SignedPath!);
                        MsixDigest.VerifyMsixDigestConsistency(signed);
                        var ext = Path.GetExtension(signed)[1..];
                        var (pkcs7, digest) = MsixDigest.MsixVerifiedSignature(File.ReadAllBytes(signed), ext);
                        Assert.Equal(AuthenticodeSignature.Parse(pkcs7).Digest, digest);
                        var (len, _) = MsixDigest.ParseSignedAppxBlob(digest);
                        Assert.Equal(AuthenticodeHashKinds.Parse(entry.Digest.ToLowerInvariant()).DigestLength(), len);
                        break;
                    }

                case "reject-encrypted":
                    foreach (var rel in new[] { entry.UnsignedPath, entry.SignedPath }.Where(p => p is not null))
                    {
                        var target = RepoFixture(rel!);
                        var e = Assert.Throws<PsignException>(() => MsixDigest.VerifyMsixDigestConsistency(target));
                        Assert.Contains("encrypted", e.Message);
                        Assert.Contains("encrypted MSIX/AppX", Assert.Throws<PsignException>(() =>
                            AppxPackage.SetUnsignedMsixFamilyPublisherBytes(File.ReadAllBytes(target), Path.GetExtension(target)[1..], "CN=X")).Message);
                    }

                    break;
                case "reject-upload-container":
                    Assert.Contains("applies only to", Assert.Throws<PsignException>(() =>
                        MsixDigest.VerifyMsixDigestConsistency(RepoFixture(entry.UnsignedPath!))).Message);
                    break;
                case "detached-valid":
                    break;
                case "inspect-pkcs7":
                    {
                        var p7x = File.ReadAllBytes(RepoFixture(entry.SignedPath!));
                        var inner = MsixDigest.TryStripPkcxWrapper(p7x);
                        Assert.NotNull(inner);
                        Assert.NotEmpty(CmsSignedData.Parse(inner).GetCertificates());
                        break;
                    }

                default:
                    Assert.Fail($"unexpected expected_portable_verify `{entry.ExpectedPortableVerify}` for {entry.Id}");
                    break;
            }
        }
    }

    [Theory]
    [InlineData("generated-signed/msix/sample.msix")]
    [InlineData("generated-signed/msix/sample.appx")]
    [InlineData("generated-signed/msix/sample.msixbundle")]
    [InlineData("generated-signed/msix/sample.appxbundle")]
    public void GeneratedSignedPackagesVerify(string fixture) => MsixDigest.VerifyMsixDigestConsistency(Fixtures.Path(fixture));

    [Theory]
    [InlineData("generated-unsigned/msix/sample.msix")]
    [InlineData("generated-unsigned/msix/sample.appx")]
    [InlineData("generated-unsigned/msix/sample.msixbundle")]
    [InlineData("generated-unsigned/msix/sample.appxbundle")]
    public void GeneratedUnsignedPackagesFailVerification(string fixture)
    {
        Assert.False(MsixDigest.MsixSignaturePartPresent(Fixtures.Bytes(fixture)));
        Assert.ThrowsAny<PsignException>(() => MsixDigest.VerifyMsixDigestConsistency(Fixtures.Path(fixture)));
    }

    [Theory]
    [InlineData("placeholder.eappx")]
    [InlineData("placeholder.eappxbundle")]
    [InlineData("placeholder.emsix")]
    [InlineData("placeholder.emsixbundle")]
    public void EncryptedNegativeFixturesAreRejected(string name)
    {
        var path = Fixtures.Path("generated-unsigned/msix-encrypted-negative/" + name);
        var msg = Assert.Throws<PsignException>(() => MsixDigest.VerifyMsixDigestConsistency(path)).Message;
        Assert.Contains("encrypted", msg);
        Assert.Contains("Eappx", msg);
        Assert.Throws<PsignException>(() => MsixDigest.MsixAuthenticodeDigestBlob(File.ReadAllBytes(path), Path.GetExtension(path)[1..]));
    }

    [Fact]
    public void StandaloneP7xMatchesSignedSamplePackage()
    {
        var p7x = Fixtures.Bytes("generated-signed/p7x/appxsignature-from-sample-msix.p7x");
        var fromPackage = ZipCrateArchive.Open(Fixtures.Bytes("generated-signed/msix/sample.msix")).Read("AppxSignature.p7x");
        Assert.Equal(fromPackage, p7x);
        var pkcs7 = MsixDigest.StripPkcx(p7x);
        var (embeddedPkcs7, digest) = MsixDigest.MsixVerifiedSignature(Fixtures.Bytes("generated-signed/msix/sample.msix"), "MSIX");
        Assert.Equal(pkcs7, embeddedPkcs7);
        Assert.Equal(AuthenticodeSignature.Parse(pkcs7).Digest, digest);
        Assert.Null(MsixDigest.TryStripPkcxWrapper(pkcs7));
        Assert.Contains("PKCX", Assert.Throws<PsignException>(() => MsixDigest.StripPkcx(pkcs7)).Message);
        Assert.Equal(pkcs7, MsixDigest.MsixSignaturePkcs7Der(Fixtures.Bytes("generated-signed/msix/sample.msix")));
        Assert.Equal(
            "read AppxSignature.p7x: specified file not found in archive",
            Assert.Throws<PsignException>(() => MsixDigest.MsixSignaturePkcs7Der(Fixtures.Bytes("generated-unsigned/msix/sample.msix"))).FullMessage);
    }

    [Fact]
    public void MinimalManifestFixtureAppearsInGeneratedPackage()
    {
        var manifest = Fixtures.Bytes("msix-minimal/AppxManifest.xml");
        var fromPackage = ZipCrateArchive.Open(Fixtures.Bytes("generated-unsigned/msix/sample.msix")).Read("AppxManifest.xml");
        Assert.Contains("Identity", System.Text.Encoding.UTF8.GetString(fromPackage));
        Assert.Contains("Identity", System.Text.Encoding.UTF8.GetString(manifest));
    }

    [Fact]
    public void TamperedSignedPackageReportsDigestMismatch()
    {
        var signed = Fixtures.Bytes("generated-signed/msix/sample.msix");
        var archive = ZipCrateArchive.Open(signed);
        var tail = MsixDigest.ParseZipTail(signed);

        // Flip one byte of a stored/deflated payload: block map or digest mismatch must be reported.
        var target = archive.Entries.First(e => e.Name == "AppxManifest.xml");
        long dataStart = (long)archive.DataStart(target);
        var tampered = (byte[])signed.Clone();
        tampered[dataStart] ^= 0xFF;
        Assert.ThrowsAny<PsignException>(() => MsixDigest.MsixVerifiedSignature(tampered, "msix"));
        Assert.NotNull(tail.Zip64Eocd);
    }

    [Fact]
    public void SignaturePartPresenceAndBlockMapDetection()
    {
        Assert.True(MsixDigest.MsixSignaturePartPresent(Fixtures.Bytes("generated-signed/msix/sample.msix")));
        Assert.Equal(AuthenticodeHashKind.Sha384, MsixDigest.DetectBlockMapHashKind(Fixtures.Bytes("msix-edge-cases/unsigned/flat-sha384.msix")));
        Assert.Equal(AuthenticodeHashKind.Sha512, MsixDigest.DetectBlockMapHashKind(Fixtures.Bytes("msix-edge-cases/unsigned/flat-sha512.msix")));
        Assert.Null(MsixDigest.DetectBlockMapHashKind(ZipTestHelpers.ZipWithEntries(("a.txt", "a"u8.ToArray()))));
    }
}
