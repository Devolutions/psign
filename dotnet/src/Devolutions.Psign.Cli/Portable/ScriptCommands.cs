using System.Globalization;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Scripts;
using Devolutions.Psign.Core.Timestamp;
using Devolutions.Psign.Core.Zip;
using Devolutions.Psign.Signing.Rdp;
using static Devolutions.Psign.Cli.Portable.PeCommands;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>Script / ZIP / RDP / RFC 3161 portable commands.</summary>
internal static class ScriptCommands
{
    public static void Register(CommandSpec portable)
    {
        portable.Sub("verify-script", "Script signed file (PowerShell-class or WSH): compare PKCS#7 indirect digest to the recomputed script hash.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var raw = Output.ReadFile(path);
                var ext = ScriptExtFromPath(path);
                Wrap($"verify-script {path}", () => ScriptDigest.VerifyScriptDigestConsistency(raw, ext));
                return 0;
            };
        });

        portable.Sub("verify-zip", "Custom ZIP Authenticode comment signature: compare ZIP digest binding and reconstructed script digest.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var sig = Wrap($"verify-zip {path}", () => ZipAuthenticode.VerifyZipDigestBinding(bytes));
                var script = ZipAuthenticode.SignatureScriptFromParts(sig.Digest, sig.Pkcs7Base64);
                Wrap($"verify-zip reconstructed signature {path}", () => ScriptDigest.VerifyScriptDigestConsistency(System.Text.Encoding.UTF8.GetBytes(script), "ps1"));
                return 0;
            };
        });

        portable.Sub("rdp", "Sign .rdp files using portable RDP SignScope/SecureSettingsBlob logic.", c =>
        {
            c.Value("cert", "PATH", "Signer certificate as DER or PEM.").Requiring("key").Conflicts("signature-pkcs7");
            c.Value("key", "PATH", "RSA private key as PKCS#8 or PKCS#1, DER or unencrypted PEM.").Requiring("cert").Conflicts("signature-pkcs7");
            c.Multi("chain-cert", "PATH", "Additional certificate to include in the PKCS#7 certificate set.").Requiring("cert").Conflicts("signature-pkcs7");
            c.Value("signature-pkcs7", "PATH", "Detached PKCS#7 DER to serialize into the RDP Signature record.");
            c.Flag("dry-run", "Build and validate the signed shape without writing files.");
            c.Value("output", "PATH", "Write output here instead of overwriting the input. Only valid with one input file.");
            c.Positionals.Add(new PositionalSpec("files", required: true, multiple: true));
            c.Handler = p =>
            {
                RdpSigner.Run(
                    new RdpPortableSignOptions
                    {
                        CertPath = p.Value("cert"),
                        KeyPath = p.Value("key"),
                        ChainCertPaths = p.Values("chain-cert"),
                        SignaturePkcs7Path = p.Value("signature-pkcs7"),
                        DryRun = p.Flag("dry-run"),
                        OutputPath = p.Value("output"),
                        Files = p.PosAll("files"),
                    },
                    line => Output.Line(line));
                return 0;
            };
        });

        portable.Sub("rfc3161-timestamp-req", "Build an RFC 3161 TimeStampReq DER for a precomputed digest.", c =>
        {
            c.Choice("algorithm", HashAlgValues, "sha256");
            c.Value("digest-file", "PATH", "Raw digest bytes; length must match --algorithm.");
            c.Value("digest-hex", "HEX", "Lowercase hex digest; length must match --algorithm.");
            c.Value("nonce", null, "Optional nonce (INTEGER) in the request.");
            c.Flag("cert-req", "Set certReq to TRUE.");
            c.Choice("output", ["der", "hex"], "der");
            c.Handler = p =>
            {
                var kind = AuthenticodeHashKinds.Parse(p.Required("algorithm"));
                var preimage = LoadTimestampImprintPreimage(p.Value("digest-hex"), p.Value("digest-file"), kind);
                ulong? nonce = ParseOptionalNonce(p.Value("nonce"), "--nonce");
                var plan = new Rfc3161TimestampRequestPlan { DigestAlgOid = kind.Oid(), Nonce = nonce, CertReq = p.Flag("cert-req") };
                var der = Rfc3161.BuildTimestampRequestBytes(plan, preimage)
                    ?? throw new PsignException("unsupported digest OID / preimage length for RFC3161 TimeStampReq");
                if (p.Required("output") == "hex")
                {
                    Output.Line(Hex.Lower(der));
                }
                else
                {
                    Output.Raw(der);
                }

                return 0;
            };
        });

        portable.Sub("rfc3161-timestamp-resp-inspect", "Parse RFC 3161 TimeStampResp DER and print status / token diagnostics.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("expect-digest-hex", "HEX", "Expected TSTInfo.messageImprint.hashedMessage hex.");
            c.Value("expect-nonce", null, "Expected TSTInfo.nonce integer.");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                ulong? nonce = ParseOptionalNonce(p.Value("expect-nonce"), "--expect-nonce");
                Output.Write(Rfc3161.FormatTimeStampRespInspection(bytes, p.Value("expect-digest-hex"), nonce));
                return 0;
            };
        });
    }

    internal static ulong? ParseOptionalNonce(string? raw, string flagName)
    {
        if (raw is null)
        {
            return null;
        }

        if (!ulong.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out ulong value))
        {
            throw new PsignException($"invalid {flagName} value '{raw}': expected an unsigned 64-bit integer");
        }

        return value;
    }

    internal static string ScriptExtFromPath(string path)
    {
        var ext = Path.GetExtension(path);
        if (string.IsNullOrEmpty(ext) || ext.Length < 2)
        {
            throw new PsignException($"could not infer script extension from {path}");
        }

        return ext[1..];
    }

    internal static byte[] LoadTimestampImprintPreimage(string? digestHex, string? digestFile, AuthenticodeHashKind kind)
    {
        int n = kind.DigestLength();
        if (digestHex is not null && digestFile is null)
        {
            return Rfc3161.ParseHexDigestFixed(digestHex, n);
        }

        if (digestHex is null && digestFile is not null)
        {
            var b = Output.ReadFile(digestFile);
            if (b.Length != n)
            {
                throw new PsignException($"digest file must be exactly {n} bytes for {SpcName(kind)}, got {b.Length}");
            }

            return b;
        }

        throw new PsignException("provide exactly one of --digest-hex or --digest-file");
    }

    internal static string SpcName(AuthenticodeHashKind kind) => kind switch
    {
        AuthenticodeHashKind.Sha1 => "Sha1",
        AuthenticodeHashKind.Sha256 => "Sha256",
        AuthenticodeHashKind.Sha384 => "Sha384",
        _ => "Sha512",
    };
}
