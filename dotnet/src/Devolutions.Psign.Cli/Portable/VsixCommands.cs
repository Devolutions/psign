using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Vsix;
using Devolutions.Psign.Signing.Vsix;
using Devolutions.Psign.Verification;
using static Devolutions.Psign.Cli.Portable.NuGetCommands;
using static Devolutions.Psign.Cli.Portable.PeCommands;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>VSIX OPC XMLDSig commands (port of the <c>vsix-*</c> handlers in <c>psign-digest-cli</c>).</summary>
internal static class VsixCommands
{
    public static void Register(CommandSpec portable)
    {
        portable.Sub("vsix-signature-info", "Inspect VSIX OPC signature marker state without validating XMLDSig.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var info = Wrap($"vsix-signature-info {path}", () => VsixPackage.InspectVsixPath(path));
                Output.Line($"opc_signature={(info.HasOpcSignature ? "yes" : "no")}");
                Output.Line($"signature_origin={(info.Package.HasOpcSignatureOrigin ? OpcPackage.OpcSignatureOriginPart : "-")}");
                Output.Line($"signature_parts={info.Package.OpcSignatureParts.Count}");
                foreach (var part in info.Package.OpcSignatureParts)
                {
                    Output.Line($"signature_part={part}");
                }

                Output.Line($"entries={info.Package.Entries.Count}");
                return 0;
            };
        });

        portable.Sub("vsix-embed-signature-xml", "Embed a VSIX OPC signature XML part and signature-origin marker.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signature-xml", "PATH").Req();
            c.Value("output", "PATH").Req();
            c.Flag("overwrite");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var xml = Output.ReadFile(p.Required("signature-xml"));
                Wrap($"vsix-embed-signature-xml {path}", () => VsixPackage.EmbedSignatureXmlPath(path, output, xml, p.Flag("overwrite")));
                Output.Line($"embedded_signature_xml={VsixPackage.DefaultVsixSignaturePart}\noutput={output}\nsignature_xml_len={xml.Length}");
                return 0;
            };
        });

        portable.Sub("vsix-signature-reference-xml", "Write the unsigned OPC signature skeleton (package manifest + SignedInfo).", c =>
        {
            c.Positional("path", valueName: "PATH");
            AlgorithmOption(c);
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var xml = Wrap($"vsix-signature-reference-xml {path}", () => VsixPackage.SignatureReferenceXmlPath(path, Alg(p)));
                CliIo.WriteOutputOrStdout(p.Value("output"), xml);
                return 0;
            };
        });

        portable.Sub("vsix-signature-xml", "Create OPC XMLDSig XML (package-derived SignatureTime) with a local RSA/SHA-2 SignatureValue.", c =>
        {
            c.Positional("path", valueName: "PATH");
            AlgorithmOption(c);
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.").Req();
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var certBytes = ReadCertBytes(p.Required("cert"));
                using var key = LoadKey(p.Required("key"));
                var template = Wrap($"vsix-signature-xml {path}", () => VsixPackage.SignatureTemplatePath(path, alg, VsixSigningTime.FromPackage));
                var signature = VsixSigner.SignSignedInfo(alg, key, template.SignedInfo);
                CliIo.WriteOutputOrStdout(p.Value("output"), template.SignatureXmlBytes(signature, certBytes));
                return 0;
            };
        });

        portable.Sub("vsix-signature-xml-prehash", "Compute the SignedInfo digest for externally signing VSIX XMLDSig.", c =>
        {
            c.Positional("path", valueName: "PATH");
            AlgorithmOption(c);
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var signedInfo = Wrap($"vsix-signature-xml-prehash {path}", () => VsixPackage.SignedInfoXmlPath(path, alg));
                Output.Digest(p.Required("encoding"), VsixSigner.SignedInfoRemotePrehash(alg, signedInfo), p.Value("output"));
                return 0;
            };
        });

        portable.Sub("vsix-signature-xml-from-signature", "Create deterministic VSIX XMLDSig XML from externally produced RSA signature bytes.", c =>
        {
            c.Positional("path", valueName: "PATH");
            AlgorithmOption(c);
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("signature", "PATH", "Raw RSA PKCS#1 v1.5 signature bytes produced over vsix-signature-xml-prehash.").Req();
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var certBytes = ReadCertBytes(p.Required("cert"));
                var signature = Output.ReadFile(p.Required("signature"));
                var xml = Wrap($"vsix-signature-xml-from-signature {path}", () => VsixPackage.SignatureXmlPath(path, alg, signature, certBytes));
                CliIo.WriteOutputOrStdout(p.Value("output"), xml);
                return 0;
            };
        });

        portable.Sub("vsix-sign", "Sign a VSIX with a local RSA/SHA-2 key: OPC XMLDSig verifiable by System.IO.Packaging / Visual Studio, optionally RFC3161-timestamped.", c =>
        {
            c.Positional("path", valueName: "PATH");
            AlgorithmOption(c);
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.").Req();
            c.Value("output", "PATH").Req();
            c.Flag("overwrite");
            c.Value("timestamp-url", null, "RFC3161 timestamp URL; the token covers the SignatureValue and is stored as the OPC <EncodedTime> element.").Alias("tr");
            c.Choice("timestamp-digest", CliTimestamp.HashAlgValues, null, "RFC3161 timestamp digest algorithm.").Alias("td");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var output = p.Required("output");
                var certBytes = ReadCertBytes(p.Required("cert"));
                using var key = LoadKey(p.Required("key"));
                var template = Wrap($"vsix-sign {path}", () => VsixPackage.SignatureTemplatePath(path, alg, VsixSigningTime.Now));
                var signature = VsixSigner.SignSignedInfo(alg, key, template.SignedInfo);
                var xml = template.SignatureXmlBytes(signature, certBytes);
                xml = CliTimestamp.VsixTimestampIfRequested(xml, p.Value("timestamp-url"), p.Value("timestamp-digest"));
                Wrap($"vsix-sign embed signature XML into {output}", () => VsixPackage.EmbedSignatureXmlPath(path, output, xml, p.Flag("overwrite")));
                Output.Line($"output={output}");
                Output.Line($"signature_xml_part={VsixPackage.DefaultVsixSignaturePart}");
                Output.Line($"reference_digest_algorithm={alg.Label()}");
                Output.Line($"reference_count={template.ReferenceCount}");
                Output.Line($"signature_xml_len={xml.Length}");
                return 0;
            };
        });

        portable.Sub("vsix-verify-signature-reference-xml", "Verify VSIX XMLDSig Reference/DigestValue XML against package parts.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signature-xml", "PATH").Req();
            AlgorithmOption(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var xml = Output.ReadFile(p.Required("signature-xml"));
                int references = Wrap($"vsix-verify-signature-reference-xml {path}", () => VsixPackage.VerifySignatureReferenceXmlPath(path, xml, alg));
                Output.Line($"reference_digest_algorithm={alg.Label()}");
                Output.Line($"reference_count={references}");
                Output.Line("reference_digest_match=yes");
                return 0;
            };
        });

        portable.Sub("vsix-verify-signature-xml", "Verify deterministic VSIX XMLDSig references and local RSA/SHA-2 SignatureValue.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signature-xml", "PATH").Req();
            c.Value("cert", "PATH").Req();
            AlgorithmOption(c);
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var xml = Output.ReadFile(p.Required("signature-xml"));
                var package = Output.ReadFile(path);
                var embedded = Wrap($"vsix-verify-signature-xml {path}", () => VsixPackage.EmbedSignatureXml(package, xml, overwrite: true));
                var certBytes = Output.ReadFile(p.Required("cert"));
                var shared = TrustArgs.From(p);
                var (references, anchors) = Wrap($"vsix-verify-signature-xml {path}", () => VerifyPackageSignature(embedded, certBytes, shared));
                Output.Line($"reference_digest_algorithm={alg.Label()}");
                Output.Line($"reference_count={references}");
                Output.Line("reference_digest_match=yes");
                Output.Line("signature_value_match=yes");
                if (anchors is { } count)
                {
                    Output.Line("signer_trust_chain=yes");
                    Output.Line($"trust_anchor_count={count}");
                }

                return 0;
            };
        });

        portable.Sub("vsix-verify-signature", "Verify an embedded VSIX OPC XMLDSig signature part.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("cert", "PATH");
            AlgorithmOption(c);
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var alg = Alg(p);
                var package = Output.ReadFile(path);
                Wrap($"vsix-verify-signature {path}", () => VsixPackage.ExtractSignatureXml(package));
                var expected = p.Value("cert") is { } cert ? Output.ReadFile(cert) : null;
                var shared = TrustArgs.From(p);
                var (references, anchors) = Wrap($"vsix-verify-signature {path}", () => VerifyPackageSignature(package, expected, shared));
                Output.Line("vsix-verify-signature: ok");
                Output.Line("signature_xml_present=yes");
                Output.Line($"signature_xml_part={VsixPackage.DefaultVsixSignaturePart}");
                Output.Line($"reference_digest_algorithm={alg.Label()}");
                Output.Line($"reference_count={references}");
                Output.Line("reference_digest_match=yes");
                Output.Line("signature_value_match=yes");
                if (anchors is { } count)
                {
                    Output.Line("signer_trust_chain=yes");
                    Output.Line($"trust_anchor_count={count}");
                }

                return 0;
            };
        });
    }

    private static void AlgorithmOption(CommandSpec c) => c.Choice("algorithm", Sha2Values, "sha256");

    private static VsixHashAlgorithm Alg(ParsedCommand p) => p.Required("algorithm") switch
    {
        "sha384" => VsixHashAlgorithm.Sha384,
        "sha512" => VsixHashAlgorithm.Sha512,
        _ => VsixHashAlgorithm.Sha256,
    };

    /// <summary>Read <c>--cert</c> and require it to parse (Rust <c>rdp::parse_certificate</c>); returns the raw bytes.</summary>
    private static byte[] ReadCertBytes(string cert)
    {
        var bytes = Output.ReadFile(cert);
        try
        {
            Core.X509.CertificateLoader.ParseCertificate(bytes);
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse signer certificate {cert}", e);
        }

        return bytes;
    }

    /// <summary>
    /// Rust <c>verify_vsix_package_signature</c>: standard OPC XMLDSig verification, optionally requiring a specific signer
    /// certificate and applying the shared trust options. Returns the referenced part count and, when trust ran, the anchor
    /// count.
    /// </summary>
    private static (int References, int? Anchors) VerifyPackageSignature(byte[] package, byte[]? expectedCert, TrustVerifySharedArgs shared)
    {
        var signature = TrustVerifyVsix.VerifyVsixSignatureBytes(package);
        if (expectedCert is not null)
        {
            byte[] expected;
            try
            {
                expected = Anchors.ParseCertBytes(expectedCert).RawData;
            }
            catch (PsignException e)
            {
                throw new PsignException("parse expected VSIX signer certificate", e);
            }

            if (!expected.AsSpan().SequenceEqual(signature.SignerCertificateDer))
            {
                throw new PsignException("VSIX SignatureValue was not produced by the expected signer certificate");
            }
        }

        int? trust = null;
        if (shared.TrustVerifyArgsPresent)
        {
            var report = TrustVerifyVsix.TrustVerifyVsixBytes(package, TrustArgs.Options(shared));
            trust = report.AnchorThumbprints;
        }

        return (signature.ReferenceCount, trust);
    }
}
