using System.Security.Cryptography;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.X509;
using Xunit;

namespace Devolutions.Psign.Tests.Server;

/// <summary>Rust vs managed <c>psign-server pki-server</c> (AIA / CRL / OCSP endpoints) over loopback.</summary>
public sealed class PkiServerParityTests
{
    private static readonly byte[][] Requests =
    [
        RawHttp.Request("GET", "/"),
        RawHttp.Request("GET", "/health"),
        RawHttp.Request("GET", "/root.der"),
        RawHttp.Request("GET", "/issuer.der"),
        RawHttp.Request("GET", "/leaf.der"),
        RawHttp.Request("GET", "/crl.der"),
        RawHttp.Request("POST", "/ocsp", [0x30, 0x00], ("Content-Type", "application/ocsp-request")),
        RawHttp.Request("GET", "/ocsp"),
        RawHttp.Request("POST", "/crl.der", []),
        RawHttp.Request("GET", "/health?x=1"),
        RawHttp.Request("PUT", "/"),
        RawHttp.Request("get", "/"),
    ];

    private sealed record Run(List<string> Lines, List<byte[]> Responses, byte[] Root, byte[] Leaf, byte[] Key, string Stderr);

    private static List<Run> RunBoth(params string[] args)
    {
        var rust = RustBinaries.RequireServer();
        using var dir = new TempDir();
        var runs = new List<Run>();
        foreach (var (exe, tag) in new[] { (rust, "rs"), (RustBinaries.ManagedServer, "cs") })
        {
            string root = dir.File($"{tag}-root.der"), leaf = dir.File($"{tag}-leaf.der"), key = dir.File($"{tag}-leaf.pk8");
            using var server = ServerProcess.Start(
                exe,
                6,
                ["pki-server", "--max-requests", Requests.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), "--root-cert-output", root, "--leaf-cert-output", leaf, "--leaf-key-output", key, .. args]);
            var responses = Requests.Select(r => RawHttp.Exchange(server.Port, r)).ToList();
            var (code, err) = server.WaitForExit();
            Assert.Equal(0, code);
            runs.Add(new Run(server.Lines.Select(l => RawHttp.NormalizePort(l, server)).ToList(), responses, File.ReadAllBytes(root), File.ReadAllBytes(leaf), File.ReadAllBytes(key), err));
        }

        return runs;
    }

    public static TheoryData<string[]> Modes() => new()
    {
        Array.Empty<string>(),
        new[] { "--crl-revoke-leaf" },
        new[] { "--ocsp-status", "revoked" },
        new[] { "--ocsp-status", "unknown", "--crl-revoke-leaf" },
    };

    [SkippableTheory]
    [MemberData(nameof(Modes))]
    public void PkiServerMatchesRust(string[] args)
    {
        var runs = RunBoth(args);
        var (rs, cs) = (runs[0], runs[1]);
        Assert.Equal(rs.Lines, cs.Lines);
        Assert.Equal("psign-server pki-server ocsp http://127.0.0.1:PORT/ocsp", cs.Lines[^1]);
        Assert.Equal(rs.Stderr, cs.Stderr);
        DerShape.AssertSame(rs.Root, cs.Root, "root output");
        DerShape.AssertSame(rs.Leaf, cs.Leaf, "leaf output");

        var root = CertificateInfo.Parse(cs.Root);
        var leaf = CertificateInfo.Parse(cs.Leaf);
        Assert.True(leaf.VerifySignatureBy(root));
        Assert.Equal(new[] { "1.3.6.1.5.5.7.3.3" }, leaf.ExtendedKeyUsages);

        // PKCS#8 key: same PrivateKeyInfo framing as the rsa crate, and it matches the leaf certificate.
        foreach (var key in new[] { rs.Key, cs.Key })
        {
            Assert.StartsWith("020100300d06092a864886f70d0101010500", Devolutions.Psign.Core.Hex.Lower(Der.Children(key, Der.First(key)!.Value)!.Take(2).SelectMany(c => c.Encoded(key).ToArray()).ToArray()));
        }

        using (var rsa = RSA.Create())
        {
            rsa.ImportPkcs8PrivateKey(cs.Key, out _);
            Assert.Equal(leaf.SubjectPublicKeyInfo, rsa.ExportSubjectPublicKeyInfo());
        }

        for (int i = 0; i < Requests.Length; i++)
        {
            var (rh, rb) = RawHttp.Split(rs.Responses[i]);
            var (ch, cb) = RawHttp.Split(cs.Responses[i]);
            Assert.Equal(rh, ch);
            if (rh.Contains("application/pkix", StringComparison.Ordinal) || rh.Contains("application/ocsp-response", StringComparison.Ordinal))
            {
                DerShape.AssertSame(rb, cb, $"response #{i}");
            }
            else
            {
                Assert.Equal(rb, cb);
            }
        }

        Assert.Equal(cs.Root, RawHttp.Split(cs.Responses[2]).Body);
        Assert.Equal(cs.Root, RawHttp.Split(cs.Responses[3]).Body);
        Assert.Equal(cs.Leaf, RawHttp.Split(cs.Responses[4]).Body);

        // The CRL TBS is fully deterministic except its signature: compare it byte-for-byte.
        var rsCrl = RawHttp.Split(rs.Responses[5]).Body;
        var csCrl = RawHttp.Split(cs.Responses[5]).Body;
        Assert.Equal(FirstChild(rsCrl), FirstChild(csCrl));
        var crl = Devolutions.Psign.Verification.OnlineTrust.ParseCertificateListDer(csCrl);
        Devolutions.Psign.Verification.OnlineTrust.VerifyCrlSignature(crl, root);
        Assert.Equal(args.Contains("--crl-revoke-leaf") ? 1 : 0, crl.RevokedSerialTlvs.Count);

        var ocsp = Devolutions.Psign.Verification.OnlineTrust.ParseOcspResponseDer(RawHttp.Split(cs.Responses[6]).Body);
        var entry = Devolutions.Psign.Verification.OnlineTrust.OcspResponseForCertId(ocsp, Devolutions.Psign.Verification.OnlineTrust.BuildOcspCertIdDer(leaf, root));
        var expected = args.Contains("revoked") ? "Revoked" : args.Contains("unknown") ? "Unknown" : "Good";
        Assert.Equal(expected, entry.Status.ToString());
    }

    private static byte[] FirstChild(byte[] der)
    {
        var outer = Der.First(der)!.Value;
        return Der.Children(der, outer)![0].Encoded(der).ToArray();
    }
}
