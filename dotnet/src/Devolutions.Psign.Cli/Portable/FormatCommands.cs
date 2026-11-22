using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Cab;
using Devolutions.Psign.Core.Catalog;
using Devolutions.Psign.Core.Esd;
using Devolutions.Psign.Core.Msi;
using Devolutions.Psign.Core.Pe;
using static Devolutions.Psign.Cli.Portable.PeCommands;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>CAB / MSI / catalog / ESD / page-hash read-only portable commands.</summary>
internal static class FormatCommands
{
    public static void Register(CommandSpec portable)
    {
        portable.Sub("pe-has-page-hashes", "Print whether embedded PKCS#7 bytes contain SPC_PE_IMAGE_PAGE_HASHES attribute OIDs.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                bool present = Wrap($"pe-has-page-hashes {path}", () => PageHashes.PeEmbeddedPkcs7ContainsPageHashAttribute(bytes));
                Output.Line(present ? "yes" : "no");
                return 0;
            };
        });

        portable.Sub("pe-page-hash-info", "Print structured SPC_PE_IMAGE_PAGE_HASHES rows from CMS signed attributes.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var rows = Wrap($"pe-page-hash-info {path}", () => PageHashes.CollectPageHashAuthAttributes(bytes));
                foreach (var loc in rows)
                {
                    int v1 = loc.Values.Count(v => v.Kind == PageHashAttrKind.V1);
                    int v2 = loc.Values.Count(v => v.Kind == PageHashAttrKind.V2);
                    int total = loc.Values.Sum(v => v.ValueDer.Length);
                    int pairs = 0;
                    bool ok = true;
                    foreach (var v in loc.Values)
                    {
                        try
                        {
                            pairs += PageHashes.ParseAttributeEntries(v.ValueDer, v.Kind).Count;
                        }
                        catch (PsignException)
                        {
                            ok = false;
                        }
                    }

                    Output.Line($"pkcs7_index={loc.Pkcs7Index} signer_index={loc.SignerIndex} v1_values={v1} v2_values={v2} value_bytes_total={total} parsed_page_hash_pairs={(ok ? pairs.ToString(System.Globalization.CultureInfo.InvariantCulture) : "-")}");
                }

                return 0;
            };
        });

        portable.Sub("verify-pe-page-hashes", "Experimental: parse embedded page-hash tables and verify contiguous raw file ranges.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                Wrap($"verify-pe-page-hashes {path}", () => PageHashes.VerifyPeEmbeddedTables(bytes));
                return 0;
            };
        });

        portable.Sub("cab-digest", "Print CAB Authenticode digest without requiring PKCS#7.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Choice("algorithm", HashAlgValues, "sha256");
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var data = Output.ReadFile(path);
                var ctx = CabDigest.ParseContext(data);
                var digest = CabDigest.ComputeAuthenticodeDigest(data, ctx, AuthenticodeHashKinds.Parse(p.Required("algorithm")));
                Output.Digest(p.Required("encoding"), digest, p.Value("output"));
                return 0;
            };
        });

        RegisterExtract(portable, "extract-cab-pkcs7", "Write embedded Authenticode PKCS#7 (raw DER) from a signed .cab tail.",
            (path, b) => Wrap($"extract-cab-pkcs7 {path} (need signed CAB with PKCS#7 tail)", () => CabDigest.SignaturePkcs7Der(b).ToArray()));
        RegisterExtract(portable, "extract-msi-pkcs7", "Write the DigitalSignature stream (raw PKCS#7 DER) from an .msi.",
            (path, b) => Wrap($"extract-msi-pkcs7 {path} (need OLE compound with DigitalSignature stream)", () => MsiDigest.DigitalSignaturePkcs7Der(b)));

        RegisterPrehash(portable, "cab-signer-rs256-prehash", (b, i) => CabDigest.RsaSha256SignerPrehashDigest(b, i));
        RegisterPrehash(portable, "msi-signer-rs256-prehash", (b, i) => MsiDigest.RsaSha256SignerPrehashDigest(b, i));
        RegisterPrehash(portable, "catalog-signer-rs256-prehash", (b, i) => CatalogDigest.RsaSha256SignerPrehashDigest(b, i));

        RegisterVerify(portable, "verify-cab", "CAB with embedded PKCS#7: compare indirect digest to the recomputed CAB hash.", path => CabDigest.VerifyDigestConsistency(ReadForVerify(path)));
        RegisterVerify(portable, "verify-msi", "Signed MSI: compare PKCS#7 indirect digest to the OLE fingerprint.", path => MsiDigest.VerifyDigestConsistency(ReadForVerify(path)));
        RegisterVerify(portable, "verify-esd", "Signed WIM/ESD: compare PKCS#7 indirect digest to the prefix hash.", path => EsdDigest.VerifyWimEsdDigestConsistency(ReadForVerify(path)));
        RegisterVerify(portable, "verify-catalog", "Signed catalog .cat: compare PKCS#7 indirect digest to the catalog digest scan.", path => CatalogDigest.VerifyDigestConsistency(ReadForVerify(path)));

        portable.Sub("verify-catalog-member", "Verify that a subject file is represented by a MakeCat-style CTL member in a signed catalog.", c =>
        {
            c.Value("catalog", "PATH", "Catalog .cat file.").Req();
            c.Positional("subject", valueName: "PATH");
            c.Handler = p =>
            {
                var catalog = p.Required("catalog");
                var subject = p.Pos("subject")!;
                var m = Wrap($"verify-catalog-member --catalog {catalog} {subject}", () => CatalogDigest.VerifyMember(catalog, subject));
                Output.Line($"verify-catalog-member: ok catalog={catalog} subject={subject} member_index={m.MemberIndex} member_name={m.Member.SubjectName ?? "-"} digest_alg_oid={m.Member.DigestAlgorithmOid} data_oid={m.Member.DataOid} digest={Hex.Lower(m.ComputedDigest)}");
                return 0;
            };
        });
    }

    /// <summary>Read a file inside the verify context (Rust path-based verifiers report read errors under the command context).</summary>
    private static byte[] ReadForVerify(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new PsignException(Output.IoMessage(e));
        }
    }

    private static void RegisterVerify(CommandSpec portable, string name, string about, Action<string> verify)
    {
        portable.Sub(name, about, c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                Wrap($"{name} {path}", () => verify(path));
                return 0;
            };
        });
    }

    private static void RegisterExtract(CommandSpec portable, string name, string about, Func<string, byte[], byte[]> extract)
    {
        portable.Sub(name, about, c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var bytes = Output.ReadFile(path);
                var der = extract(path, bytes);
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
    }

    private static void RegisterPrehash(CommandSpec portable, string name, Func<byte[], int, byte[]> prehash)
    {
        portable.Sub(name, "SHA-256 over the authenticated-attribute SET of the embedded PKCS#7 signer (RFC 5652 §5.4).", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("signer-index", null, null, "0");
            c.Choice("encoding", DigestEncodingValues, "hex");
            c.Value("output", "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                int signerIndex = p.Int("signer-index");
                var bytes = Output.ReadFile(path);
                var digest = Wrap($"{name} {path} --signer-index {signerIndex}", () => prehash(bytes, signerIndex));
                Wrap($"write {name} output ({path})", () => Output.Digest(p.Required("encoding"), digest, p.Value("output")));
                return 0;
            };
        });
    }
}
