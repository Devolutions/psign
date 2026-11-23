using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Opc;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Signing.Code;

/// <summary>Replacement or new ZIP entry (Rust <c>ZipEntryUpdate</c>); <see cref="Compression"/> is the raw method (0 stored, 8 deflated).</summary>
public sealed record ZipEntryUpdate(string Name, byte[] Bytes, ushort Compression);

/// <summary>ZIP helpers of the <c>code</c> orchestrator (Rust <c>repack_zip_with_updates</c>, <c>normalize_zip_name</c>, <c>zip_contains_entry</c>).</summary>
public static class CodeZip
{
    /// <summary>Reject absolute, backslash and <c>.</c> / <c>..</c> entry names (Rust <c>normalize_zip_name</c>).</summary>
    public static string NormalizeZipName(string name)
    {
        if (name.Length == 0 || name.StartsWith('/') || name.Contains('\\'))
        {
            throw new PsignException($"unsafe ZIP entry path: {name}");
        }

        if (name.Split('/').Any(part => part is "." or ".."))
        {
            throw new PsignException($"unsafe ZIP entry path: {name}");
        }

        return name;
    }

    /// <summary>Open a ZIP archive, wrapping failures with <paramref name="context"/>.</summary>
    internal static ZipCrateArchive Open(byte[] bytes, string context)
    {
        try
        {
            return ZipCrateArchive.Open(bytes);
        }
        catch (Exception e) when (e is PsignException or InvalidDataException or IOException or ArgumentException)
        {
            throw new PsignException(context, e);
        }
    }

    /// <summary>Whether the archive has an entry named exactly <paramref name="entryName"/> (Rust <c>zip_contains_entry</c>).</summary>
    public static bool ContainsEntry(byte[] bytes, string entryName) => Open(bytes, "open ZIP").ByName(entryName) is not null;

    /// <summary>
    /// Copy the archive, replacing entries named in <paramref name="updates"/> (stamped with the current local time)
    /// and appending the remaining updates in name order (Rust <c>repack_zip_with_updates</c>). Unchanged entries keep
    /// their compression method and timestamp.
    /// </summary>
    public static byte[] RepackWithUpdates(byte[] input, IEnumerable<ZipEntryUpdate> updates, ZipDateTime? updatedTimestamp = null)
    {
        ZipDateTime timestamp;
        try
        {
            timestamp = updatedTimestamp ?? OpcPackage.CurrentZipDateTime();
        }
        catch (PsignException e)
        {
            throw new PsignException("determine local ZIP timestamp for rewritten entries", e);
        }

        var pending = new SortedDictionary<string, ZipEntryUpdate>(Utf8Ordinal.Comparer);
        foreach (var update in updates)
        {
            var name = NormalizeZipName(update.Name);
            if (!pending.TryAdd(name, update))
            {
                throw new PsignException($"duplicate ZIP update entry: {name}");
            }
        }

        var archive = Open(input, "open ZIP for repack");
        var output = new ZipCrateWriter();
        foreach (var entry in archive.Entries)
        {
            try
            {
                archive.EnsureReadable(entry);
            }
            catch (PsignException e)
            {
                throw new PsignException("read ZIP entry for repack", e);
            }

            var name = NormalizeZipName(entry.Name);
            if (pending.Remove(name, out var update))
            {
                output.StartFile(name, update.Bytes, update.Compression, timestamp);
            }
            else if (entry.IsDir)
            {
                output.AddDirectory(name, entry.LastModified);
            }
            else
            {
                output.StartFile(name, archive.Read(entry), entry.CompressionMethod, entry.LastModified);
            }
        }

        foreach (var (name, update) in pending)
        {
            output.StartFile(name, update.Bytes, update.Compression, timestamp);
        }

        return output.Finish();
    }
}
