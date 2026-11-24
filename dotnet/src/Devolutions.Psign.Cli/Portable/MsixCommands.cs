using System.Text;
using Devolutions.Psign.Cli.Framework;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Msix;
using Devolutions.Psign.Core.Xml;
using Devolutions.Psign.Core.Zip;
using static Devolutions.Psign.Cli.Portable.PeCommands;

namespace Devolutions.Psign.Cli.Portable;

/// <summary>Cleartext MSIX / AppX portable commands.</summary>
internal static class MsixCommands
{
    public static void Register(CommandSpec portable)
    {
        portable.Sub("verify-msix", "Cleartext MSIX/APPX/bundle: compare PKCS#7 indirect digest to the ZIP rehash (encrypted extensions rejected).", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                Wrap($"verify-msix {path}", () => MsixDigest.VerifyMsixDigestConsistency(path));
                return 0;
            };
        });

        portable.Sub("msix-manifest-info", "Inspect cleartext MSIX/AppX AppxManifest.xml Identity metadata.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var info = Wrap($"msix-manifest-info {path}", () => InspectManifest(path));
                Output.Line($"package_name={info.PackageName ?? "-"}");
                Output.Line($"publisher={info.Publisher ?? "-"}");
                Output.Line($"version={info.Version ?? "-"}");
                Output.Line($"processor_architecture={info.ProcessorArchitecture ?? "-"}");
                if (info.PackagePublisher is not null)
                {
                    Output.Line($"package_publisher={info.PackagePublisher}");
                }

                return 0;
            };
        });

        portable.Sub("msix-set-publisher", "Update cleartext MSIX/AppX AppxManifest.xml Identity Publisher before final signing.", c =>
        {
            c.Positional("path", valueName: "PATH");
            c.Value("publisher", "SUBJECT").Req();
            c.Value("output", "PATH").Req();
            c.Handler = p =>
            {
                var path = p.Pos("path")!;
                var publisher = p.Required("publisher");
                var output = p.Required("output");
                Wrap($"msix-set-publisher {path}", () => SetPublisher(path, output, publisher));
                Output.Line($"output={output}");
                Output.Line($"publisher={publisher}");
                return 0;
            };
        });
    }

    internal sealed record ManifestInfo(string? PackageName, string? Publisher, string? Version, string? ProcessorArchitecture, string? PackagePublisher);

    private static string Ext(string path)
    {
        var e = Path.GetExtension(path);
        return string.IsNullOrEmpty(e) ? string.Empty : e[1..].ToLowerInvariant();
    }

    private static void RejectEncrypted(string path)
    {
        if (MsixDigest.IsEncryptedMsixExtension(Ext(path)))
        {
            throw new PsignException(
                $"encrypted MSIX/AppX packages (.eappx/.emsix) require Windows AppxSip OS delegation; portable cleartext package helpers cannot inspect or update {path}");
        }
    }

    internal static ManifestInfo InspectManifest(string path)
    {
        RejectEncrypted(path);
        var manifest = ReadManifest(path);
        var identity = XmlTextScan.FirstTag(manifest, "Identity")
            ?? throw new PsignException("MSIX/AppX package manifest is missing Identity");
        string? packagePublisher = null;
        if (XmlTextScan.FirstStartTagByLocalName(manifest, "Package") is { } package)
        {
            packagePublisher = XmlTextScan.XmlAttr(package, "Publisher");
        }

        return new ManifestInfo(
            XmlTextScan.XmlAttr(identity, "Name"),
            XmlTextScan.XmlAttr(identity, "Publisher"),
            XmlTextScan.XmlAttr(identity, "Version"),
            XmlTextScan.XmlAttr(identity, "ProcessorArchitecture"),
            packagePublisher);
    }

    private static string ReadManifest(string path)
    {
        byte[] data;
        try
        {
            data = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new PsignException($"open {path}", new PsignException(IoErrorText.Message(e)));
        }

        ZipCrateArchive archive;
        try
        {
            archive = ZipCrateArchive.Open(data);
        }
        catch (Exception e) when (e is PsignException or InvalidDataException)
        {
            throw new PsignException("open MSIX/AppX ZIP", e);
        }

        var strict = new UTF8Encoding(false, true);
        if (archive.ByName("AppxManifest.xml") is { } m)
        {
            try
            {
                return strict.GetString(archive.Read(m));
            }
            catch (DecoderFallbackException e)
            {
                throw new PsignException("read AppxManifest.xml as UTF-8", new PsignException("stream did not contain valid UTF-8", e));
            }
            catch (InvalidDataException e)
            {
                throw new PsignException("read AppxManifest.xml", e);
            }
        }

        var bundle = archive.ByName("AppxMetadata/AppxBundleManifest.xml")
            ?? throw new PsignException("read AppxManifest.xml or AppxMetadata/AppxBundleManifest.xml", new PsignException("specified file not found in archive"));
        try
        {
            return strict.GetString(archive.Read(bundle));
        }
        catch (DecoderFallbackException e)
        {
            throw new PsignException("read AppxMetadata/AppxBundleManifest.xml as UTF-8", new PsignException("stream did not contain valid UTF-8", e));
        }
        catch (InvalidDataException e)
        {
            throw new PsignException("read AppxMetadata/AppxBundleManifest.xml", e);
        }
    }

    private static void SetPublisher(string input, string output, string publisher)
    {
        RejectEncrypted(input);
        if (publisher.Length == 0)
        {
            throw new PsignException("MSIX/AppX publisher cannot be empty");
        }

        var bytes = Output.ReadFile(input);
        var updated = Wrap($"set MSIX/AppX manifest publisher in {input}", () => AppxPackage.SetUnsignedMsixFamilyPublisherBytes(bytes, Ext(input), publisher));
        Output.WriteFile(output, updated);
    }
}
