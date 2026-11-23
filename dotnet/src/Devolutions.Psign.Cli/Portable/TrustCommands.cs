using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Verification;
using static Devolutions.Psign.Cli.Portable.PeCommands;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>
/// Portable trust commands (<c>trust-verify-*</c>), PKCS#7 inspection, and the Artifact Signing publisher ID helper (port
/// of the matching <c>psign-digest-cli</c> handlers).
/// </summary>
internal static class TrustCommands
{
    public static void Register(CommandSpec portable)
    {
        portable.Sub("trust-verify-pe", "Verify PE Authenticode trust: PKCS#7 CMS validation + certificate chain to portable anchors (no OS store).", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p => BytesVerifier(p, "trust-verify-pe", TrustVerifyPe.TrustVerifyPeBytes);
        });

        portable.Sub("artifact-signing-publisher-id", "Print the Azure Artifact Signing publisher ID (certificate profile identity EKU).", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("input", ["pe", "pkcs7", "cert"], "pe");
            c.Choice("format", ["json", "publisher-id"], "json");
            c.Handler = ArtifactSigningPublisherId;
        });

        portable.Sub("trust-verify-cab", "Same trust pipeline as trust-verify-pe after CAB SIP digest consistency (verify-cab).", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p => BytesVerifier(p, "trust-verify-cab", TrustVerifyCab.TrustVerifyCabBytes);
        });

        portable.Sub("trust-verify-msi", "Same trust pipeline as trust-verify-pe after MSI/MSP SIP digest consistency (verify-msi).", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p => BytesVerifier(p, "trust-verify-msi", TrustVerifyMsi.TrustVerifyMsiBytes);
        });

        portable.Sub("trust-verify-esd", "Same trust pipeline as trust-verify-pe after WIM/ESD SIP digest consistency (verify-esd).", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var opts = TrustArgs.Options(TrustArgs.From(p));
                var report = Wrap($"trust-verify-esd {path}", () => TrustVerifyEsd.TrustVerifyWimEsdPath(path, opts));
                TrustArgs.PrintOk("trust-verify-esd", report);
                return 0;
            };
        });

        portable.Sub("trust-verify-catalog", "CMS catalog digest consistency (verify-catalog) plus PKCS#7 chain to anchors when Authenticode-wrapped.", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p => BytesVerifier(p, "trust-verify-catalog", TrustVerifyCatalog.TrustVerifyCatalogBytes);
        });

        portable.Sub("trust-verify-detached", "Detached PKCS#7 vs raw content bytes (digest inferred from PKCS#7 indirect length).", c =>
        {
            c.Positional("content", valueName: "CONTENT");
            c.Positional("signature", valueName: "SIGNATURE");
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var content = p.Pos("content")!;
                var signature = p.Pos("signature")!;
                var contentBytes = Output.ReadFile(content);
                var sigBytes = Output.ReadFile(signature);
                var opts = TrustArgs.Options(TrustArgs.From(p));
                var report = Wrap($"trust-verify-detached {content}", () => TrustVerifyDetached.TrustVerifyDetachedBytes(contentBytes, sigBytes, opts));
                TrustArgs.PrintOk("trust-verify-detached", report);
                return 0;
            };
        });

        portable.Sub("trust-verify-zip", "Custom ZIP Authenticode comment signature: verify ZIP digest binding plus PKCS#7 chain to anchors.", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p => BytesVerifier(p, "trust-verify-zip", TrustVerifyZip.TrustVerifyZipBytes);
        });

        portable.Sub("trust-verify-script", "PowerShell-class or WSH script SIP digest plus PKCS#7 chain to anchors.", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var opts = TrustArgs.Options(TrustArgs.From(p));
                var ext = CliIo.RustExtension(path);
                if (string.IsNullOrEmpty(ext))
                {
                    throw new PsignException($"could not infer script extension from {path}");
                }

                var report = Wrap($"trust-verify-script {path}", () => TrustVerifyScript.TrustVerifyScriptBytes(bytes, ext, opts));
                TrustArgs.PrintOk("trust-verify-script", report);
                return 0;
            };
        });

        portable.Sub("trust-verify-msix", "Cleartext MSIX / AppX (and bundle) APPX SIP digest (verify-msix) plus PKCS#7 chain to anchors.", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var opts = TrustArgs.Options(TrustArgs.From(p));
                var ext = Core.Text.RustText.ToAsciiLowercase(CliIo.RustExtension(path) ?? string.Empty);
                var report = Wrap($"trust-verify-msix {path}", () => TrustVerifyMsix.TrustVerifyMsixBytes(bytes, ext, opts));
                TrustArgs.PrintOk("trust-verify-msix", report);
                return 0;
            };
        });

        portable.Sub("trust-verify-nupkg", "NuGet .nupkg / .snupkg author signature: package hash over the exact unsigned bytes plus .signature.p7s chain to anchors.", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p => BytesVerifier(p, "trust-verify-nupkg", TrustVerifyNuGet.TrustVerifyNuGetBytes);
        });

        portable.Sub("trust-verify-vsix", "VSIX OPC XML signature: C14N SignedInfo, part digests and coverage, SignatureValue, <EncodedTime> RFC 3161 timestamp, plus signer chain to anchors.", c =>
        {
            c.Positional("path", valueName: "PATH");
            TrustArgs.Declare(c);
            c.Handler = p => BytesVerifier(p, "trust-verify-vsix", TrustVerifyVsix.TrustVerifyVsixBytes);
        });

        portable.Sub("inspect-authenticode", "Inspect PKCS#7 layers: signers, timestamp-related attribute OIDs, nested signatures (1.3.6.1.4.1.311.2.4.1). JSON to stdout.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("input", ["pe", "pkcs7"], "pe", "Treat path as a PE image (embedded attribute certs) vs raw PKCS#7 bytes.");
            c.Handler = p =>
            {
                var bytes = Output.ReadFile(p.Pos("path")!);
                var json = p.Value("input") == "pkcs7"
                    ? RustJson.ToStringPretty(AuthenticodeInspector.InspectAuthenticodePkcs7Der(bytes), VerificationJsonContext.Default.InspectPkcs7Report)
                    : RustJson.ToStringPretty(AuthenticodeInspector.InspectPeAuthenticode(bytes), VerificationJsonContext.Default.InspectPeFileReport);
                Output.Line(json);
                return 0;
            };
        });

        portable.Sub("inspect-pkcs7", "Inspect standalone PKCS#7 / P7X bytes as JSON.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var bytes = Output.ReadFile(p.Pos("path")!);
                Output.Line(RustJson.ToStringPretty(AuthenticodeInspector.InspectAuthenticodePkcs7Der(bytes), VerificationJsonContext.Default.InspectPkcs7Report));
                return 0;
            };
        });
    }

    private static int BytesVerifier(ParsedCommand p, string prefix, Func<byte[], TrustVerifyPeOptions, TrustVerifyPeReport> verify)
    {
        var path = p.Pos("path")!;
        var bytes = Output.ReadFile(path);
        var opts = TrustArgs.Options(TrustArgs.From(p));
        var report = Wrap($"{prefix} {path}", () => verify(bytes, opts));
        TrustArgs.PrintOk(prefix, report);
        return 0;
    }

    private static int ArtifactSigningPublisherId(ParsedCommand p)
    {
        var path = p.Pos("path")!;
        var bytes = Output.ReadFile(path);
        var input = p.Value("input");
        if (p.Value("format") == "publisher-id")
        {
            List<string> ids = input switch
            {
                "pkcs7" => ArtifactSigning.IdentityFromPkcs7Der(bytes) is { } i ? [i.PublisherId] : [],
                "cert" => ArtifactSigning.IdentityFromCertBytes(bytes) is { } i ? [i.PublisherId] : [],
                _ => ArtifactSigning.IdentitiesFromPe(bytes).Where(s => s.Identity is not null).Select(s => s.Identity!.PublisherId).ToList(),
            };
            if (ids.Count == 0)
            {
                throw new PsignException($"{path}: no Azure Artifact Signing identity EKU (1.3.6.1.4.1.311.97.*) on the signer");
            }

            foreach (var id in ids)
            {
                Output.Line(id);
            }

            return 0;
        }

        var json = input switch
        {
            "pkcs7" => RustJson.ToStringPretty(ArtifactSigning.IdentityFromPkcs7Der(bytes), VerificationJsonContext.Default.ArtifactSigningIdentity),
            "cert" => RustJson.ToStringPretty(ArtifactSigning.IdentityFromCertBytes(bytes), VerificationJsonContext.Default.ArtifactSigningIdentity),
            _ => RustJson.ToStringPretty(ArtifactSigning.IdentitiesFromPe(bytes), VerificationJsonContext.Default.ListArtifactSigningSignerIdentity),
        };
        Output.Line(json);
        return 0;
    }
}
