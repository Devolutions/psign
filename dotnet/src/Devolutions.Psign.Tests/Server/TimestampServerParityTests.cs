using System.Security.Cryptography;
using System.Text;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Asn1;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Core.X509;
using Xunit;

namespace Devolutions.Psign.Tests.Server;

/// <summary>Rust vs managed <c>psign-server timestamp-server</c> over loopback.</summary>
public sealed class TimestampServerParityTests
{
    private static byte[] TsRequest(byte fill = 0x5a, ulong? nonce = 7, bool certReq = true) =>
        Rfc3161.BuildTimestampRequestBytes(new Rfc3161TimestampRequestPlan { DigestAlgOid = Oids.Sha256, Nonce = nonce, CertReq = certReq }, Enumerable.Repeat(fill, 32).ToArray())!;

    private static byte[] Post(byte[] body) =>
        RawHttp.Request("POST", "/", body, ("Content-Type", "application/timestamp-query"));

    /// <summary>Run the same requests against both servers; returns (rust responses, managed responses, rust stderr, managed stderr).</summary>
    private static (List<byte[]> Rust, List<byte[]> Managed, string RustErr, string ManagedErr) Exchange(string[] args, params byte[][] requests)
    {
        var rust = RustBinaries.RequireServer();
        var results = new List<(List<byte[]>, string)>();
        foreach (var exe in new[] { rust, RustBinaries.ManagedServer })
        {
            using var server = ServerProcess.Start(exe, 1, ["timestamp-server", "--max-requests", requests.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), .. args]);
            var responses = requests.Select(r => RawHttp.Exchange(server.Port, r)).ToList();
            var (code, err) = server.WaitForExit();
            Assert.Equal(0, code);
            results.Add((responses, RawHttp.NormalizePort(err, server)));
        }

        return (results[0].Item1, results[1].Item1, results[0].Item2, results[1].Item2);
    }

    [SkippableFact]
    public void StartupLineAndCertificateOutputsMatch()
    {
        var rust = RustBinaries.RequireServer();
        using var dir = new TempDir();
        var outputs = new List<(string Line, byte[] Root, byte[] Leaf)>();
        foreach (var (exe, tag) in new[] { (rust, "rs"), (RustBinaries.ManagedServer, "cs") })
        {
            var root = dir.File($"{tag}-root.der");
            var leaf = dir.File($"{tag}-leaf.der");
            using var server = ServerProcess.Start(exe, 1, "timestamp-server", "--cert-output", root, "--tsa-cert-output", leaf);
            outputs.Add((RawHttp.NormalizePort(server.Lines[0], server), File.ReadAllBytes(root), File.ReadAllBytes(leaf)));
        }

        Assert.Equal("psign-server timestamp-server listening on http://127.0.0.1:PORT/", outputs[1].Line);
        Assert.Equal(outputs[0].Line, outputs[1].Line);
        DerShape.AssertSame(outputs[0].Root, outputs[1].Root, "TSA root");
        DerShape.AssertSame(outputs[0].Leaf, outputs[1].Leaf, "TSA leaf");
        var root2 = CertificateInfo.Parse(outputs[1].Root);
        var leaf2 = CertificateInfo.Parse(outputs[1].Leaf);
        Assert.True(root2.VerifySignatureBy(root2));
        Assert.True(leaf2.VerifySignatureBy(root2));
        Assert.Equal(new[] { "1.3.6.1.5.5.7.3.8" }, leaf2.ExtendedKeyUsages);
        Assert.Equal(TimeSpan.FromDays(365), leaf2.NotAfter - leaf2.NotBefore);
    }

    [SkippableFact]
    public void GrantedTokensMatchStructurallyAndTstInfoByteForByte()
    {
        var (rust, managed, rustErr, managedErr) = Exchange(
            ["--gen-time", "20250607080910Z"],
            Post(TsRequest(0x11)),
            Post(TsRequest(0x22, nonce: null, certReq: false)),
            Post(TsRequest(0x33, nonce: 0x80)));
        Assert.Equal(rustErr, managedErr);
        Assert.Equal(string.Empty, managedErr);
        for (int i = 0; i < rust.Count; i++)
        {
            var (rh, rb) = RawHttp.Split(rust[i]);
            var (mh, mb) = RawHttp.Split(managed[i]);
            Assert.Equal(rh, mh);
            Assert.StartsWith("HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: ", mh);
            DerShape.AssertSame(rb, mb, $"TimeStampResp #{i}");

            var rp = Rfc3161.ParseTimeStampRespDer(rb)!;
            var mp = Rfc3161.ParseTimeStampRespDer(mb)!;
            Assert.Equal(0u, mp.PkiStatus.AsRawInteger());
            var rTst = TstInfoBytes(rp.TimeStampToken!);
            var mTst = TstInfoBytes(mp.TimeStampToken!);
            Assert.Equal(rTst, mTst);
            var tst = Rfc3161.ParseTimeStampTokenTstInfo(mp.TimeStampToken!)!;
            Assert.Equal("20250607080910Z", tst.GenTime);
            Assert.Equal((i + 1).ToString("x2", System.Globalization.CultureInfo.InvariantCulture), tst.SerialNumberHex.ToLowerInvariant());
            VerifyToken(mp.TimeStampToken!);
            VerifyToken(rp.TimeStampToken!);
        }
    }

    private static byte[] TstInfoBytes(byte[] token)
    {
        var sd = CmsSignedData.Parse(token);
        return Der.First(sd.EncapContent!)!.Value.Value(sd.EncapContent!).ToArray();
    }

    /// <summary>The token's signer certificate verifies the signed attributes, which carry the TSTInfo digest.</summary>
    private static void VerifyToken(byte[] token)
    {
        var sd = CmsSignedData.Parse(token);
        Assert.Equal(3, sd.Version);
        Assert.Equal(TimestampOid, sd.EncapContentType);
        var signer = sd.SignerInfos.Single();
        Assert.Equal(
            new[] { Oids.Pkcs9ContentType, Oids.Pkcs9MessageDigest, "1.2.840.113549.1.9.16.2.47" },
            signer.SignedAttributes!.Select(a => a.Oid).ToArray());
        var certs = sd.Certificates!.Select(c => CertificateInfo.Parse(c)).ToList();
        var leaf = certs.Single(c => signer.MatchesCertificate(c));
        Assert.Equal(SHA256.HashData(TstInfoBytes(token)), signer.MessageDigest());
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(leaf.SubjectPublicKeyInfo, out _);
        Assert.True(rsa.VerifyData(signer.SignedAttributesSetDer(), signer.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    private const string TimestampOid = "1.2.840.113549.1.9.16.1.4";

    public static TheoryData<string[]> DeterministicModes() => new()
    {
        new[] { "--status", "rejection" },
        new[] { "--status", "waiting" },
        new[] { "--response-mode", "bad-alg" },
        new[] { "--response-mode", "http-error" },
        new[] { "--response-mode", "malformed-der" },
        new[] { "--status", "rejection", "--response-mode", "bad-alg" },
    };

    [SkippableTheory]
    [MemberData(nameof(DeterministicModes))]
    public void DeterministicModesAreByteIdentical(string[] args)
    {
        var (rust, managed, rustErr, managedErr) = Exchange(args, Post(TsRequest()), RawHttp.Request("GET", "/"));
        Assert.Equal(rust, managed);
        Assert.Equal(rustErr, managedErr);
    }

    public static TheoryData<string> TamperedModes() => new() { "mismatched-imprint", "invalid-signature" };

    [SkippableTheory]
    [MemberData(nameof(TamperedModes))]
    public void TamperedModesMatchStructurally(string mode)
    {
        var (rust, managed, _, _) = Exchange(["--response-mode", mode], Post(TsRequest(0x44)));
        var (rh, rb) = RawHttp.Split(rust[0]);
        var (mh, mb) = RawHttp.Split(managed[0]);
        Assert.Equal(rh, mh);
        DerShape.AssertSame(rb, mb, mode);
        if (mode == "mismatched-imprint")
        {
            var tst = Rfc3161.ParseTimeStampTokenTstInfo(Rfc3161.ParseTimeStampRespDer(mb)!.TimeStampToken!)!;
            Assert.Equal(0x44 ^ 0xff, tst.MessageImprintHashedMessage[0]);
            Assert.Equal(TstInfoBytes(Rfc3161.ParseTimeStampRespDer(rb)!.TimeStampToken!), TstInfoBytes(Rfc3161.ParseTimeStampRespDer(mb)!.TimeStampToken!));
        }
        else
        {
            var sd = CmsSignedData.Parse(Rfc3161.ParseTimeStampRespDer(mb)!.TimeStampToken!);
            var signer = sd.SignerInfos.Single();
            var leaf = sd.Certificates!.Select(c => CertificateInfo.Parse(c)).Single(c => signer.MatchesCertificate(c));
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(leaf.SubjectPublicKeyInfo, out _);
            Assert.False(rsa.VerifyData(signer.SignedAttributesSetDer(), signer.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }

    public static TheoryData<string> MalformedRequests() => new()
    {
        "empty",
        "not-der",
        "bad-version",
        "trailing-imprint",
        "unsupported-optional",
        "truncated-headers",
        "truncated-body",
        "non-utf8-headers",
        "no-path",
    };

    [SkippableTheory]
    [MemberData(nameof(MalformedRequests))]
    public void MalformedRequestsFailIdentically(string kind)
    {
        var good = TsRequest();
        byte[] request = kind switch
        {
            "empty" => Post([]),
            "not-der" => Post(Encoding.ASCII.GetBytes("hello")),
            "bad-version" => Post([0x30, 0x03, 0x02, 0x01, 0x02]),
            "trailing-imprint" => Post(Der.EncodeSequence([0x02, 0x01, 0x01], Der.EncodeSequence(Der.EncodeSequence(Der.EncodeOid(Oids.Sha256)), Der.EncodeTlv(0x04, new byte[32]), [0x05, 0x00]))),
            "unsupported-optional" => Post(Der.EncodeSequence([0x02, 0x01, 0x01], Der.EncodeSequence(Der.EncodeSequence(Der.EncodeOid(Oids.Sha256)), Der.EncodeTlv(0x04, new byte[32])), [0x0c, 0x01, 0x41])),
            "truncated-headers" => Encoding.ASCII.GetBytes("POST / HTTP/1.1\r\nHost: x\r\n"),
            "truncated-body" => [.. Encoding.ASCII.GetBytes("POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n"), .. good],
            "non-utf8-headers" => [.. Encoding.ASCII.GetBytes("POST / HTTP/1.1\r\nX-Bad: "), 0xc3, 0x28, .. Encoding.ASCII.GetBytes("\r\n\r\n")],
            _ => Encoding.ASCII.GetBytes("POST\r\n\r\n"),
        };
        var (rust, managed, rustErr, managedErr) = Exchange([], request);
        Assert.Equal(rust, managed);
        Assert.Empty(managed[0]);
        Assert.Equal(rustErr, managedErr);
        Assert.StartsWith("request failed: ", managedErr);
    }

    [Fact]
    public void OverflowingContentLengthIsRejectedAndServerKeepsServing()
    {
        // The Rust server panics on `body_start + content_len` overflow; the managed one logs the request failure and
        // serves the next request.
        var huge = Encoding.ASCII.GetBytes("POST / HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n");
        using var server = ServerProcess.Start(RustBinaries.ManagedServer, 1, ["timestamp-server", "--max-requests", "2"]);
        Assert.Empty(RawHttp.Exchange(server.Port, huge));
        var (head, body) = RawHttp.Split(RawHttp.Exchange(server.Port, Post(TsRequest())));
        Assert.StartsWith("HTTP/1.1 200", head);
        Assert.NotEmpty(body);
        var (code, err) = server.WaitForExit();
        Assert.Equal(0, code);
        Assert.Contains("request failed: HTTP Content-Length 18446744073709551615 is too large", err);
    }
}
