using System.Security.Cryptography;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.NuGet;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Signing.Keys;
using Devolutions.Psign.Verification;
using static Devolutions.Psign.Cli.Portable.PeCommands;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>NuGet package signature commands (port of the <c>nupkg-*</c> handlers in <c>psign-digest-cli</c>).</summary>
internal static class NuGetCommands
{
    internal static readonly string[] Sha2Values = ["sha256", "sha384", "sha512"];

    public static void Register(CommandSpec portable)
    {
        portable.Sub("nupkg-signature-info", "Inspect NuGet package-signature marker state (.signature.p7s) without validating CMS.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var info = Wrap($"nupkg-signature-info {path}", () => NuGetPackage.InspectNupkgPath(path));
                Output.Line($"signed={(info.Signed ? "yes" : "no")}");
                Output.Line($"signature_file={(info.Signed ? NuGetPackage.PackageSignatureFileName : "-")}");
                Output.Line($"signature_len={(info.SignatureLen is { } n ? n.ToString(System.Globalization.CultureInfo.InvariantCulture) : "-")}");
                Output.Line($"signature_stored={(info.SignatureIsStored is { } s ? (s ? "yes" : "no") : "-")}");
                Output.Line($"entries={info.Package.Entries.Count}");
                return 0;
            };
        });

        portable.Sub("nupkg-digest", "Hash an unsigned NuGet package exactly as the package-signature properties document records it.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", Sha2Values, "sha256");
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var digest = Wrap($"nupkg-digest {path}", () => NuGetPackage.UnsignedPackageDigestPath(path, Alg(p)));
                Output.Digest(p.Required("encoding"), digest, p.Value("output"));
                return 0;
            };
        });

        portable.Sub("nupkg-signature-content", "Write NuGet signature content bytes (Version + package hash property) for an unsigned package.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", Sha2Values, "sha256");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var content = Wrap($"nupkg-signature-content {path}", () => NuGetPackage.UnsignedPackageSignatureContentPath(path, Alg(p)));
                CliIo.WriteOutputOrStdout(p.Value("output"), content);
                return 0;
            };
        });

        portable.Sub("nupkg-signature-pkcs7", "Create local RSA/SHA-2 CMS for NuGet signature content bytes.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", Sha2Values, "sha256", "Package hash and CMS signer digest algorithm.");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.").Req();
            ChainCert(c);
            TimestampOptions(c, "to timestamp the NuGet CMS signature after signing");
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var output = p.Required("output");
                var content = Wrap($"nupkg-signature-pkcs7 {path}", () => NuGetPackage.UnsignedPackageSignatureContentPath(path, alg));
                var pkcs7 = Wrap($"nupkg-signature-pkcs7 create CMS for {path}", () => SignIdData(
                    content, p.Required("cert"), p.Required("key"), p.Values("chain-cert"), alg.ToHashKind(), Pkcs7ContentMode.Attached, Pkcs7SignedAttributeProfile.NuGetAuthor));
                pkcs7 = CliTimestamp.TimestampPkcs7IfRequested(pkcs7, p.Value("timestamp-url"), p.Value("timestamp-digest"), Rfc3161TimestampAttribute.CmsTimeStampToken, "nupkg-signature-pkcs7");
                CliIo.Write(output, pkcs7);
                Output.Line($"output={output}");
                Output.Line($"package_hash_algorithm={alg.Label()}");
                Output.Line($"signature_len={pkcs7.Length}");
                return 0;
            };
        });

        portable.Sub("nupkg-signature-pkcs7-prehash", "Compute the signed-attributes digest for externally signing NuGet CMS.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", Sha2Values, "sha256", "Package hash and CMS signer digest algorithm.");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM. Required because NuGet author signatures sign ESSCertIDv2.").Req();
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var content = Wrap($"nupkg-signature-pkcs7-prehash {path}", () => NuGetPackage.UnsignedPackageSignatureContentPath(path, alg));
                var cert = p.Required("cert");
                var signerCert = LoadCertificate(cert, $"parse signer certificate {cert}");
                var prehash = Pkcs7IdData.RemotePrehash(content, alg.ToHashKind(), Pkcs7SignedAttributeProfile.NuGetAuthorWithoutSigningTime, signerCert);
                Output.Digest(p.Required("encoding"), prehash, p.Value("output"));
                return 0;
            };
        });

        portable.Sub("nupkg-signature-pkcs7-from-signature", "Create NuGet CMS from externally produced RSA PKCS#1 v1.5 signature bytes.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", Sha2Values, "sha256", "Package hash and CMS signer digest algorithm.");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            ChainCert(c);
            c.Value("signature", "PATH", "Raw RSA PKCS#1 v1.5 signature bytes produced over nupkg-signature-pkcs7-prehash.").Req();
            TimestampOptions(c, "to timestamp the NuGet CMS signature after assembly");
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var output = p.Required("output");
                var content = Wrap($"nupkg-signature-pkcs7-from-signature {path}", () => NuGetPackage.UnsignedPackageSignatureContentPath(path, alg));
                var signature = Output.ReadFile(p.Required("signature"));
                var pkcs7 = Wrap($"nupkg-signature-pkcs7-from-signature create CMS for {path}", () => SignIdDataWithExternalSignature(
                    content, p.Required("cert"), p.Values("chain-cert"), alg.ToHashKind(), signature, Pkcs7ContentMode.Attached, Pkcs7SignedAttributeProfile.NuGetAuthorWithoutSigningTime));
                pkcs7 = CliTimestamp.TimestampPkcs7IfRequested(pkcs7, p.Value("timestamp-url"), p.Value("timestamp-digest"), Rfc3161TimestampAttribute.CmsTimeStampToken, "nupkg-signature-pkcs7-from-signature");
                CliIo.Write(output, pkcs7);
                Output.Line($"output={output}");
                Output.Line($"package_hash_algorithm={alg.Label()}");
                Output.Line($"signature_len={pkcs7.Length}");
                return 0;
            };
        });

        portable.Sub("nupkg-sign", "Create and embed a local RSA/SHA-2 NuGet .signature.p7s signature.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", Sha2Values, "sha256", "Package hash and CMS signer digest algorithm.");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.").Req();
            ChainCert(c);
            TimestampOptions(c, "to timestamp the NuGet CMS signature after signing");
            c.Value("output", "PATH").Req();
            c.Flag("overwrite");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var output = p.Required("output");
                var content = Wrap($"nupkg-sign {path}", () => NuGetPackage.UnsignedPackageSignatureContentPath(path, alg));
                var pkcs7 = Wrap($"nupkg-sign create CMS for {path}", () => SignIdData(
                    content, p.Required("cert"), p.Required("key"), p.Values("chain-cert"), alg.ToHashKind(), Pkcs7ContentMode.Attached, Pkcs7SignedAttributeProfile.NuGetAuthor));
                pkcs7 = CliTimestamp.TimestampPkcs7IfRequested(pkcs7, p.Value("timestamp-url"), p.Value("timestamp-digest"), Rfc3161TimestampAttribute.CmsTimeStampToken, "nupkg-sign");
                Wrap($"nupkg-sign embed signature into {output}", () => NuGetPackage.EmbedSignaturePath(path, output, pkcs7, p.Flag("overwrite")));
                Output.Line($"output={output}");
                Output.Line($"package_hash_algorithm={alg.Label()}");
                Output.Line($"embedded_signature={NuGetPackage.PackageSignatureFileName}");
                Output.Line($"signature_len={pkcs7.Length}");
                return 0;
            };
        });

        portable.Sub("nupkg-verify-signature-content", "Verify NuGet signature content bytes against an unsigned package hash.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("content", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var contentBytes = Output.ReadFile(p.Required("content"));
                var parsed = Wrap($"nupkg-verify-signature-content {path}", () => NuGetPackage.VerifyUnsignedPackageSignatureContentPath(path, contentBytes));
                Output.Line($"package_hash_algorithm={parsed.HashAlgorithm.Label()}");
                Output.Line($"package_hash={Hex.Lower(parsed.PackageHash)}");
                Output.Line("package_hash_match=yes");
                return 0;
            };
        });

        portable.Sub("nupkg-verify-signature", "Verify an embedded NuGet .signature.p7s against package content and explicit trust anchors.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", Sha2Values, "sha256", "Package hash and CMS signer digest algorithm used to reconstruct NuGet signature content.");
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var package = Output.ReadFile(path);
                var signatureDer = Wrap($"nupkg-verify-signature {path}", () => Wrap($"extract NuGet signature from {path}", () => NuGetPackage.ExtractSignature(package)));
                var content = Wrap($"nupkg-verify-signature {path}", () => Wrap($"compute signed NuGet package signature content for {path}", () => NuGetPackage.SignedPackageSignatureContent(package, alg)));
                var parsed = Wrap("parse reconstructed NuGet signature content", () => NuGetPackage.ParseSignatureContent(content));
                var opts = TrustArgs.Options(TrustArgs.From(p));
                var report = Wrap($"nupkg-verify-signature {path}", () => TrustVerifyDetached.TrustVerifyDetachedBytes(content, signatureDer, opts));
                TrustArgs.PrintOk("nupkg-verify-signature", report);
                Output.Line("signature_present=yes");
                Output.Line($"package_hash_algorithm={alg.Label()}");
                Output.Line($"package_hash={Hex.Lower(parsed.PackageHash)}");
                Output.Line("package_hash_match=yes");
                Output.Line($"signature_len={signatureDer.Length}");
                return 0;
            };
        });

        portable.Sub("nupkg-embed-signature", "Embed a NuGet package author signature blob as root .signature.p7s.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signature", "PATH").Req();
            c.Value("output", "PATH").Req();
            c.Flag("overwrite");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var signatureDer = Output.ReadFile(p.Required("signature"));
                Wrap($"nupkg-embed-signature {path}", () => NuGetPackage.EmbedSignaturePath(path, output, signatureDer, p.Flag("overwrite")));
                Output.Line($"embedded_signature={NuGetPackage.PackageSignatureFileName}\noutput={output}\nsignature_len={signatureDer.Length}");
                return 0;
            };
        });
    }

    private static NuGetHashAlgorithm Alg(ParsedCommand p) => p.Required("algorithm") switch
    {
        "sha384" => NuGetHashAlgorithm.Sha384,
        "sha512" => NuGetHashAlgorithm.Sha512,
        _ => NuGetHashAlgorithm.Sha256,
    };

    internal static void ChainCert(CommandSpec c) =>
        c.Multi("chain-cert", "PATH", "Additional certificate to include in the PKCS#7 certificate set.");

    internal static void TimestampOptions(CommandSpec c, string purpose)
    {
        c.Value("timestamp-url", null, $"RFC3161 timestamp URL {purpose}.").Alias("tr");
        c.Choice("timestamp-digest", CliTimestamp.HashAlgValues, null, "RFC3161 timestamp digest algorithm.").Alias("td");
    }

    /// <summary>Read and parse a DER/PEM certificate (Rust <c>rdp::parse_certificate</c> with <c>read {path}</c> context).</summary>
    internal static CertificateInfo LoadCertificate(string path, string parseContext)
    {
        var bytes = Output.ReadFile(path);
        try
        {
            return CertificateLoader.ParseCertificate(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException(parseContext, e);
        }
    }

    /// <summary>Read and parse an RSA private key (Rust <c>rdp::parse_rsa_private_key</c> with contexts).</summary>
    internal static RSA LoadKey(string path)
    {
        var bytes = Output.ReadFile(path);
        try
        {
            return PrivateKeyLoader.ParseRsaPrivateKey(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse RSA private key {path}", e);
        }
    }

    /// <summary>Rust <c>load_cms_signer_material</c>.</summary>
    internal static (CertificateInfo Signer, List<CertificateInfo> Chain) LoadSignerMaterial(string cert, IReadOnlyList<string> chainCerts)
    {
        var signer = LoadCertificate(cert, $"parse signer certificate {cert}");
        var chain = chainCerts.Select(c => LoadCertificate(c, $"parse chain certificate {c}")).ToList();
        return (signer, chain);
    }

    /// <summary>Rust <c>sign_pkcs7_id_data</c>.</summary>
    internal static byte[] SignIdData(
        byte[] content,
        string cert,
        string key,
        IReadOnlyList<string> chainCerts,
        AuthenticodeHashKind digest,
        Pkcs7ContentMode mode,
        Pkcs7SignedAttributeProfile profile)
    {
        var (signer, chain) = LoadSignerMaterial(cert, chainCerts);
        using var rsa = LoadKey(key);
        return Pkcs7IdData.Sign(content, signer, chain, rsa, digest, mode, profile);
    }

    /// <summary>Rust <c>sign_pkcs7_id_data_with_external_signature</c>.</summary>
    internal static byte[] SignIdDataWithExternalSignature(
        byte[] content,
        string cert,
        IReadOnlyList<string> chainCerts,
        AuthenticodeHashKind digest,
        byte[] signature,
        Pkcs7ContentMode mode,
        Pkcs7SignedAttributeProfile profile)
    {
        var (signer, chain) = LoadSignerMaterial(cert, chainCerts);
        return Pkcs7IdData.SignWithExternalSignature(content, signer, chain, digest, signature, mode, profile);
    }
}
