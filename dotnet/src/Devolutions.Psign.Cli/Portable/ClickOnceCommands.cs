using System.Globalization;
using System.Text;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.AppInstaller;
using Devolutions.Psign.Core.BusinessCentral;
using Devolutions.Psign.Core.ClickOnce;
using Devolutions.Psign.Core.X509;
using Devolutions.Psign.Signing.ClickOnce;
using Devolutions.Psign.Signing.Cms;
using Devolutions.Psign.Verification;
using static Devolutions.Psign.Cli.Portable.NuGetCommands;
using static Devolutions.Psign.Cli.Portable.PeCommands;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>
/// ClickOnce, App Installer, and Business Central commands (port of the <c>clickonce-*</c>, <c>appinstaller-*</c>, and
/// <c>business-central-app-info</c> handlers in <c>psign-digest-cli</c>).
/// </summary>
internal static class ClickOnceCommands
{
    public static void Register(CommandSpec portable)
    {
        RegisterClickOnce(portable);
        RegisterAppInstaller(portable);

        portable.Sub("business-central-app-info", "Inspect a Dynamics 365 Business Central .app package header.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Wrap($"business-central-app-info {path}", () => Output.ReadFile(path));
                var info = BusinessCentralApp.Inspect(bytes);
                Output.Line($"business_central_app={(info.IsNavx ? "yes" : "no")}");
                Output.Line($"header={info.Header}");
                Output.Line($"len={info.Len}");
                return 0;
            };
        });
    }

    private static void RegisterClickOnce(CommandSpec portable)
    {
        portable.Sub("clickonce-deploy-info", "Inspect a ClickOnce .deploy payload and report the undeployed content name.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var info = Wrap($"clickonce-deploy-info {path}", () => InspectDeployPayload(path));
                Output.Line($"deployed={(info.Deployed ? "yes" : "no")}");
                Output.Line($"content_name={info.ContentName ?? "-"}");
                Output.Line($"len={info.Len}");
                return 0;
            };
        });

        portable.Sub("clickonce-copy-deploy-payload", "Copy a ClickOnce .deploy payload to an explicit undeployed output path.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var contentName = ClickOnceManifest.DeployContentName(path)
                    ?? throw new PsignException($"ClickOnce deploy payload name must end with .deploy: {path}");
                long bytes = Wrap($"clickonce-copy-deploy-payload {path}", () => CopyDeployPayload(path, output));
                Output.Line($"content_name={contentName}");
                Output.Line($"output={output}");
                Output.Line($"bytes={bytes}");
                return 0;
            };
        });

        portable.Sub("clickonce-manifest-hashes", "Verify file hashes recorded in a ClickOnce application or deployment manifest.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("base-directory", "DIR");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var entries = Wrap($"clickonce-manifest-hashes {path}", () =>
                    ClickOnceManifest.ManifestHashesFromText(ReadManifest(path), BaseDirectory(path, p.Value("base-directory"))));
                Output.Line($"references={entries.Count}");
                int mismatches = 0;
                foreach (var entry in entries)
                {
                    if (entry.Status != "valid")
                    {
                        mismatches++;
                    }

                    var expectedSize = entry.ExpectedSize is { } size ? size.ToString(CultureInfo.InvariantCulture) : "-";
                    Output.Line($"path={entry.Path} algorithm={ClickOnceManifest.HashAlgLabel(entry.Algorithm)} expected_size={expectedSize} actual_size={entry.ActualSize} status={entry.Status}");
                    Output.Line($"expected_digest_b64={entry.ExpectedDigestB64}");
                    Output.Line($"actual_digest_b64={entry.ActualDigestB64}");
                }

                Output.Line($"mismatches={mismatches}");
                if (mismatches > 0)
                {
                    throw new PsignException($"ClickOnce manifest file hash verification failed ({mismatches} mismatch(es))");
                }

                return 0;
            };
        });

        portable.Sub("clickonce-update-manifest-hashes", "Update file size and digest values in a ClickOnce application or deployment manifest.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("base-directory", "DIR");
            c.Choice("algorithm", HashAlgValues, "sha256");
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var alg = AuthenticodeHashKinds.Parse(p.Required("algorithm"));
                int updated = Wrap($"clickonce-update-manifest-hashes {path}", () =>
                {
                    var result = ClickOnceManifest.UpdateManifestHashesInText(ReadManifest(path), BaseDirectory(path, p.Value("base-directory")), alg);
                    CliIo.Write(output, Encoding.UTF8.GetBytes(result.Text), $"write ClickOnce manifest {output}");
                    return result.Updated;
                });
                Output.Line($"output={output}");
                Output.Line($"updated={updated}");
                Output.Line($"algorithm={ClickOnceManifest.HashAlgLabel(alg)}");
                return 0;
            };
        });

        portable.Sub("clickonce-sign-manifest", "Add a deterministic portable XMLDSig signature to a ClickOnce manifest.", c =>
        {
            c.Positional("path", valueName: "PATH");
            DigestOption(c);
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.").Req();
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var digest = Digest(p);
                var report = Wrap($"clickonce-sign-manifest {path}", () =>
                {
                    var text = ReadManifest(path);
                    _ = ClickOnceManifest.UnsignedManifestText(text);
                    var cert = p.Required("cert");
                    var certBytes = ReadAndParseCert(cert);
                    using var key = LoadKey(p.Required("key"));
                    var (signed, r) = ClickOnceSigner.SignManifest(text, digest, certBytes, key, cert);
                    CliIo.Write(output, Encoding.UTF8.GetBytes(signed), $"write ClickOnce manifest {output}");
                    return r;
                });
                PrintSignReport(output, report);
                return 0;
            };
        });

        portable.Sub("clickonce-sign-manifest-prehash", "Compute the SignedInfo digest for externally signing ClickOnce manifest XMLDSig.", c =>
        {
            c.Positional("path", valueName: "PATH");
            DigestOption(c);
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var digest = Digest(p);
                var text = ReadManifest(path);
                var prehash = ClickOnceManifest.SignManifestPrehash(text, digest);
                Wrap($"clickonce-sign-manifest-prehash {path}", () => Output.Digest(p.Required("encoding"), prehash, p.Value("output")));
                return 0;
            };
        });

        portable.Sub("clickonce-sign-manifest-from-signature", "Add a deterministic ClickOnce manifest XMLDSig from externally produced RSA signature bytes.", c =>
        {
            c.Positional("path", valueName: "PATH");
            DigestOption(c);
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("signature", "PATH", "Raw RSA PKCS#1 v1.5 signature bytes produced over clickonce-sign-manifest-prehash.").Req();
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var digest = Digest(p);
                var report = Wrap($"clickonce-sign-manifest-from-signature {path}", () =>
                {
                    var text = ReadManifest(path);
                    _ = ClickOnceManifest.UnsignedManifestText(text);
                    var cert = p.Required("cert");
                    var certBytes = ReadAndParseCert(cert);
                    var signature = Output.ReadFile(p.Required("signature"));
                    var (signed, r) = ClickOnceManifest.AssembleSignedManifest(text, digest, certBytes, signature, cert);
                    CliIo.Write(output, Encoding.UTF8.GetBytes(signed), $"write ClickOnce manifest {output}");
                    return r;
                });
                PrintSignReport(output, report);
                return 0;
            };
        });

        portable.Sub("clickonce-verify-manifest-signature", "Verify the deterministic portable XMLDSig signature in a ClickOnce manifest.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM. Defaults to the embedded KeyInfo certificate.");
            DigestOption(c);
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var digest = Digest(p);
                var shared = TrustArgs.From(p);
                bool trust = shared.TrustVerifyArgsPresent;
                var report = Wrap($"clickonce-verify-manifest-signature {path}", () =>
                {
                    var text = ReadManifest(path);
                    var cert = p.Value("cert") is { } certPath ? Output.ReadFile(certPath) : null;
                    return ClickOnceManifest.VerifyManifestSignature(
                        text,
                        digest,
                        cert,
                        trust ? certBytes => TrustArgs.VerifyXmlSignerTrust(certBytes, shared) : null);
                });
                Output.Line("clickonce-verify-manifest-signature: ok");
                Output.Line($"digest={report.DigestDebugName}");
                Output.Line($"manifest_digest_b64={report.ManifestDigestB64}");
                Output.Line("manifest_digest_match=yes");
                Output.Line("signature_value_match=yes");
                Output.Line($"signature_len={report.SignatureLen}");
                if (trust)
                {
                    Output.Line("signer_trust_chain=yes");
                }

                return 0;
            };
        });
    }

    private static void RegisterAppInstaller(CommandSpec portable)
    {
        portable.Sub("appinstaller-info", "Inspect an App Installer descriptor and optional detached PKCS#7 companion signature.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signature", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var text = CliIo.ReadText(path);
                var info = Wrap($"appinstaller-info {path}", () => AppInstallerDescriptor.Parse(text));
                Output.Line($"root={info.Root}");
                Output.Line($"namespace={info.Namespace ?? "-"}");
                Output.Line($"main_package={(info.HasMainPackage ? "yes" : "no")}");
                Output.Line($"main_bundle={(info.HasMainBundle ? "yes" : "no")}");
                Output.Line($"publisher={info.Publisher ?? "-"}");
                if (p.Value("signature") is { } signature)
                {
                    long len = StatLength(signature);
                    Output.Line($"companion_signature={signature}");
                    Output.Line($"companion_signature_len={len}");
                }
                else
                {
                    Output.Line("companion_signature=-");
                    Output.Line("companion_signature_len=-");
                }

                return 0;
            };
        });

        portable.Sub("appinstaller-verify-companion", "Verify an App Installer XML descriptor against its detached PKCS#7 companion signature.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signature", "PATH").Req();
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var text = CliIo.ReadText(path);
                Wrap($"appinstaller-verify-companion {path}", () => AppInstallerDescriptor.Parse(text));
                var sigBytes = Output.ReadFile(p.Required("signature"));
                var opts = TrustArgs.Options(TrustArgs.From(p));
                var report = Wrap($"appinstaller-verify-companion {path}", () =>
                    TrustVerifyDetached.TrustVerifyDetachedBytes(AppInstallerDescriptor.CompanionSignedContent(text), sigBytes, opts));
                TrustArgs.PrintOk("appinstaller-verify-companion", report);
                return 0;
            };
        });

        portable.Sub("appinstaller-sign-companion", "Create a detached PKCS#7 companion signature for an App Installer XML descriptor.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.").Req();
            ChainCert(c);
            DigestOption(c, "CMS signer digest algorithm.");
            TimestampOptions(c, "to timestamp the companion CMS signature after signing");
            c.Value("output", "PATH", "Output detached PKCS#7 companion path.").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var digest = Digest(p);
                var text = CliIo.ReadText(path);
                Wrap($"appinstaller-sign-companion {path}", () => AppInstallerDescriptor.Parse(text));
                var pkcs7 = Wrap($"appinstaller-sign-companion create detached PKCS#7 for {path}", () => SignIdData(
                    AppInstallerDescriptor.CompanionSignedContent(text), p.Required("cert"), p.Required("key"), p.Values("chain-cert"), digest, Pkcs7ContentMode.Detached, Pkcs7SignedAttributeProfile.Basic));
                pkcs7 = CliTimestamp.TimestampPkcs7IfRequested(pkcs7, p.Value("timestamp-url"), p.Value("timestamp-digest"), Rfc3161TimestampAttribute.MicrosoftAuthenticode, "appinstaller-sign-companion");
                CliIo.Write(output, pkcs7);
                Output.Line($"output={output}");
                Output.Line($"digest={ClickOnceManifest.DigestDebugName(digest)}");
                Output.Line($"companion_signature_len={pkcs7.Length}");
                return 0;
            };
        });

        portable.Sub("appinstaller-sign-companion-prehash", "Compute the CMS authenticated-attributes digest for externally signing an App Installer companion.", c =>
        {
            c.Positional("path", valueName: "PATH");
            DigestOption(c, "CMS signer digest algorithm.");
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var digest = Digest(p);
                var text = CliIo.ReadText(path);
                Wrap($"appinstaller-sign-companion-prehash {path}", () => AppInstallerDescriptor.Parse(text));
                var prehash = Pkcs7IdData.RemotePrehash(AppInstallerDescriptor.CompanionSignedContent(text), digest, Pkcs7SignedAttributeProfile.Basic, null);
                Output.Digest(p.Required("encoding"), prehash, p.Value("output"));
                return 0;
            };
        });

        portable.Sub("appinstaller-sign-companion-from-signature", "Create an App Installer companion PKCS#7 from externally produced RSA signature bytes.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Req();
            ChainCert(c);
            DigestOption(c, "CMS signer digest algorithm.");
            c.Value("signature", "PATH", "Raw RSA PKCS#1 v1.5 signature bytes produced over appinstaller-sign-companion-prehash.").Req();
            TimestampOptions(c, "to timestamp the companion CMS signature after assembly");
            c.Value("output", "PATH", "Output detached PKCS#7 companion path.").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var output = p.Required("output");
                var digest = Digest(p);
                var text = CliIo.ReadText(path);
                Wrap($"appinstaller-sign-companion-from-signature {path}", () => AppInstallerDescriptor.Parse(text));
                var signature = Output.ReadFile(p.Required("signature"));
                var pkcs7 = Wrap($"appinstaller-sign-companion-from-signature create detached PKCS#7 for {path}", () => SignIdDataWithExternalSignature(
                    AppInstallerDescriptor.CompanionSignedContent(text), p.Required("cert"), p.Values("chain-cert"), digest, signature, Pkcs7ContentMode.Detached, Pkcs7SignedAttributeProfile.Basic));
                pkcs7 = CliTimestamp.TimestampPkcs7IfRequested(pkcs7, p.Value("timestamp-url"), p.Value("timestamp-digest"), Rfc3161TimestampAttribute.MicrosoftAuthenticode, "appinstaller-sign-companion-from-signature");
                CliIo.Write(output, pkcs7);
                Output.Line($"output={output}");
                Output.Line($"digest={ClickOnceManifest.DigestDebugName(digest)}");
                Output.Line($"companion_signature_len={pkcs7.Length}");
                return 0;
            };
        });

        portable.Sub("appinstaller-set-publisher", "Update MainPackage/MainBundle Publisher attributes in an App Installer descriptor.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("publisher", "SUBJECT").Req();
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var publisher = p.Required("publisher");
                var output = p.Required("output");
                var text = CliIo.ReadText(path);
                var updated = Wrap($"appinstaller-set-publisher {path}", () => AppInstallerDescriptor.UpdatePublisher(text, publisher));
                CliIo.Write(output, Encoding.UTF8.GetBytes(updated));
                Output.Line($"output={output}");
                Output.Line($"publisher={publisher}");
                return 0;
            };
        });
    }

    private static readonly string[] SignDigestValues = ["sha256", "sha384", "sha512"];

    private static void DigestOption(CommandSpec c, string? help = null) => c.Choice("digest", SignDigestValues, "sha256", help);

    private static AuthenticodeHashKind Digest(ParsedCommand p) => AuthenticodeHashKinds.Parse(p.Required("digest"));

    private static void PrintSignReport(string output, ClickOnceManifestSignatureReport report)
    {
        Output.Line($"output={output}");
        Output.Line($"digest={report.DigestDebugName}");
        Output.Line($"manifest_digest_b64={report.ManifestDigestB64}");
        Output.Line($"signature_len={report.SignatureLen}");
    }

    /// <summary><c>std::fs::read_to_string</c> with the <c>read ClickOnce manifest {path}</c> context.</summary>
    private static string ReadManifest(string path) => CliIo.ReadText(path, $"read ClickOnce manifest {path}");

    private static string BaseDirectory(string manifestPath, string? baseDirectory)
    {
        if (baseDirectory is not null)
        {
            return baseDirectory;
        }

        var parent = Path.GetDirectoryName(manifestPath);
        return string.IsNullOrEmpty(parent) ? "." : parent;
    }

    private static byte[] ReadAndParseCert(string cert)
    {
        var bytes = Output.ReadFile(cert);
        try
        {
            return CertificateLoader.ParseCertificate(bytes).RawData;
        }
        catch (PsignException e)
        {
            throw new PsignException($"parse signer certificate {cert}", e);
        }
    }

    private static long StatLength(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                return 0;
            }

            return new FileInfo(path).Length;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"stat {path}", new PsignException(IoErrorText.Message(e)));
        }
    }

    private static ClickOnceDeployInfo InspectDeployPayload(string path)
    {
        long len = StatLength(path);
        var name = ClickOnceManifest.DeployContentName(path);
        return new ClickOnceDeployInfo(name is not null, name, (ulong)len);
    }

    private static long CopyDeployPayload(string input, string output)
    {
        try
        {
            File.Copy(input, output, overwrite: true);
            return new FileInfo(output).Length;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"copy {input} to {output}", new PsignException(IoErrorText.Message(e)));
        }
    }
}
