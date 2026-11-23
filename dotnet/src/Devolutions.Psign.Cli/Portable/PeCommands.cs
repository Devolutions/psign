using System.Text.Json.Nodes;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Authenticode;
using Devolutions.Psign.Core.Cms;
using Devolutions.Psign.Core.Json;
using Devolutions.Psign.Core.Pe;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>PE-only portable commands (port of the matching <c>psign-digest-cli</c> handlers).</summary>
internal static class PeCommands
{
    internal static readonly string[] HashAlgValues = ["sha1", "sha256", "sha384", "sha512"];
    internal static readonly string[] DigestEncodingValues = ["hex", "raw"];

    public static void Register(CommandSpec portable)
    {
        portable.Sub("pe-digest", "Print lowercase hex of the PE/WinMD Authenticode image digest (unsigned PE is OK).", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", HashAlgValues, "sha256");
            c.Choice("encoding", DigestEncodingValues, "hex", "hex (default): one lowercase hex line. raw: raw digest bytes.");
            c.Value("output", "PATH", "Write output here instead of stdout.");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var digest = PeAuthenticode.Digest(bytes, AuthenticodeHashKinds.Parse(p.Required("algorithm")));
                Output.Digest(p.Required("encoding"), digest, p.Value("output"));
                return 0;
            };
        });

        portable.Sub("pe-checksum", "Compare PE Optional Header.CheckSum to the computed image checksum.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Flag("strict");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                uint stored = Wrap($"pe-checksum {path}", () => PeEmbed.ReadImageChecksum(bytes));
                uint computed = Wrap($"pe-checksum {path}", () => PeEmbed.ComputeImageChecksum(bytes));
                bool matches = stored == computed;
                Output.Line($"stored=0x{stored:x8}");
                Output.Line($"computed=0x{computed:x8}");
                Output.Line($"match={(matches ? "yes" : "no")}");
                Output.Line($"file_bytes={bytes.Length}");
                if (p.Flag("strict") && !matches)
                {
                    throw new PsignException($"pe-checksum {path}: stored != computed (pass without --strict to only print)");
                }

                return 0;
            };
        });

        portable.Sub("verify-pe", "Require embedded PKCS#7; compare indirect digest to the recomputed PE digest for each Authenticode cert.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                Wrap($"verify-pe {path}", () => PeAuthenticode.VerifyDigestConsistency(bytes));
                return 0;
            };
        });

        portable.Sub("pe-authenticode-ranges", "Print ordered [start,end) file byte ranges included in the PE Authenticode image digest.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var ranges = Wrap($"pe-authenticode-ranges {path}", () => PeAuthenticode.DigestFileRanges(bytes));
                foreach (var r in ranges)
                {
                    Output.Line($"start={r.Start} end={r.End}");
                }

                return 0;
            };
        });

        portable.Sub("inspect-pe-spc-indirect", "Decode SpcIndirectDataContent from an embedded Authenticode PKCS#7 (JSON).", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("index", null, "WIN_CERT_TYPE_PKCS_SIGNED_DATA row index (0 = first).", "0");
            c.Flag("include-image-value-der-hex", "Include lowercase hex of image_data.value DER.");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                int index = p.Int("index");
                var bytes = Output.ReadFile(path);
                var indirect = Wrap(
                    $"inspect-pe-spc-indirect {path} --index {index} (need PKCS#7 row and SpcIndirectData)",
                    () => PeAuthenticode.SpcIndirectDataAt(bytes, index));
                var kind = Wrap($"inspect-pe-spc-indirect {path}", () => AuthenticodeHashKinds.FromDigestLength(indirect.Digest.Length));
                var sip = Wrap($"inspect-pe-spc-indirect {path}", () => PeAuthenticode.Digest(bytes, kind));
                var props = new List<KeyValuePair<string, JsonNode?>>
                {
                    new("image_data_value_type_oid", indirect.DataType),
                    new("digest_algorithm_oid", indirect.DigestAlgorithm.Oid),
                    new("message_digest_hex", Hex.Lower(indirect.Digest)),
                    new("message_digest_byte_len", indirect.Digest.Length),
                    new("spc_indirect_der_byte_len", indirect.Encode().Length),
                    new("pe_image_digest_hex", Hex.Lower(sip)),
                    new("message_digest_matches_pe_image_digest", sip.AsSpan().SequenceEqual(indirect.Digest)),
                };
                if (p.Flag("include-image-value-der-hex"))
                {
                    var value = indirect.DataValue ?? [];
                    var tlv = Devolutions.Psign.Core.Asn1.Der.First(value);
                    var inner = tlv is null ? value : tlv.Value.Value(value).ToArray();
                    props.Add(new("image_data_value_der_hex", Hex.Lower(inner)));
                }

                Output.Line(RustJson.Pretty(RustJson.SortedObject(props)));
                return 0;
            };
        });

        portable.Sub("extract-pe-pkcs7", "Write an embedded Authenticode PKCS#7 (raw DER) to stdout or --output.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("index", null, "WIN_CERT_TYPE_PKCS_SIGNED_DATA row index (0 = first).", "0");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                int index = p.Int("index");
                var bytes = Output.ReadFile(path);
                var der = Wrap(
                    $"extract-pe-pkcs7 {path} --index {index} (need PKCS#7 row at this index)",
                    () => PeAuthenticode.NthPkcs7(bytes, index));
                var output = p.Value("output");
                if (output is not null)
                {
                    Output.WriteFile(output, der, $"write PKCS#7 to {output}");
                }
                else
                {
                    Output.Raw(der);
                }

                return 0;
            };
        });

        portable.Sub("list-pe-pkcs7", "List WIN_CERT_TYPE_PKCS_SIGNED_DATA PKCS#7 rows in the PE certificate table.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var lens = Wrap($"list-pe-pkcs7 {path}", () => PeAuthenticode.Pkcs7ByteLengths(bytes));
                Output.Line($"pkcs7_entries={lens.Count}");
                for (int i = 0; i < lens.Count; i++)
                {
                    Output.Line($"index={i} byte_len={lens[i]}");
                }

                return 0;
            };
        });

        portable.Sub("pe-signer-rs256-prehash", "SHA-256 over a signer's authenticated-attribute SET OF Attribute DER (RFC 5652 §5.4).", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("index", null, null, "0");
            c.Value("signer-index", null, null, "0");
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                int index = p.Int("index");
                int signerIndex = p.Int("signer-index");
                var bytes = Output.ReadFile(path);
                var pkcs7 = Wrap($"pe-signer-rs256-prehash {path} --index {index} (need PKCS#7 row)", () => PeAuthenticode.NthPkcs7(bytes, index));
                var sd = Wrap($"parse PKCS#7 SignedData ({path})", () => CmsSignedData.Parse(pkcs7));
                var prehash = Wrap($"pe-signer-rs256-prehash {path} --signer-index {signerIndex}", () => SignerPrehash.Rs256(sd, signerIndex));
                Wrap($"write pe-signer-rs256-prehash output ({path})", () => Output.Digest(p.Required("encoding"), prehash, p.Value("output")));
                return 0;
            };
        });

        portable.Sub("pkcs7-signer-rs256-prehash", "Same digest as pe-signer-rs256-prehash, but path is PKCS#7 DER.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signer-index", null, null, "0");
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                int signerIndex = p.Int("signer-index");
                var raw = Output.ReadFile(path);
                var sd = Wrap($"pkcs7-signer-rs256-prehash {path} (need PKCS#7 SignedData)", () => CmsSignedData.Parse(Pkcs7Wire.NormalizeForAuthenticode(raw)));
                var prehash = Wrap($"pkcs7-signer-rs256-prehash {path}", () => SignerPrehash.Rs256(sd, signerIndex));
                Wrap($"write pkcs7-signer-rs256-prehash output ({path})", () => Output.Digest(p.Required("encoding"), prehash, p.Value("output")));
                return 0;
            };
        });

        portable.Sub("append-pe-pkcs7", "Experimental: append raw PKCS#7 (SignedData) DER as a new WIN_CERTIFICATE row.", c =>
        {
            c.Value("pe", "PATH", "Input PE path.").Req();
            c.Value("pkcs7", "PATH", "PKCS#7 DER file.").Req();
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var pePath = p.Required("pe");
                var pkcs7Path = p.Required("pkcs7");
                var output = p.Required("output");
                var image = Output.ReadFile(pePath, $"read PE {pePath}");
                var pkcs7Raw = Output.ReadFile(pkcs7Path);
                var pkcs7 = Pkcs7Wire.NormalizeForAuthenticode(pkcs7Raw);
                var outImage = Wrap($"append-pe-pkcs7 {pePath} + {pkcs7Path}", () => PeEmbed.AppendPkcs7Certificate(image, pkcs7));
                Output.WriteFile(output, outImage);
                return 0;
            };
        });
    }

    /// <summary>Run <paramref name="f"/> and wrap failures with Rust-style context.</summary>
    internal static T Wrap<T>(string context, Func<T> f)
    {
        try
        {
            return f();
        }
        catch (Exception e) when (e is PsignException or IOException or FormatException or System.Security.Cryptography.CryptographicException or System.Formats.Asn1.AsnContentException or InvalidDataException or ArgumentException)
        {
            throw new PsignException(context, e);
        }
    }

    internal static void Wrap(string context, Action f) => Wrap<object?>(context, () =>
    {
        f();
        return null;
    });
}
