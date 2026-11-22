using System.IO.Compression;
using System.Text;
using Devolutions.Psign.Core.Zip;

namespace Devolutions.Psign.Tests.Core;

/// <summary>Helpers shared by the OPC / NuGet / VSIX tests.</summary>
internal static class PackageTestUtil
{
    /// <summary>Rust test helper <c>zip_with</c>: <c>FileOptions::default()</c> entries.</summary>
    public static byte[] ZipWith(params (string Name, byte[] Data)[] entries)
    {
        var w = new ZipCrateWriter();
        foreach (var (name, data) in entries)
        {
            w.StartFile(name, data);
        }

        return w.Finish();
    }

    /// <summary>Rust nuget test helper <c>zip_with_timestamps</c> (signature entry stored).</summary>
    public static byte[] ZipWithTimestamps(params (string Name, byte[] Data, ZipDateTime Modified)[] entries)
    {
        var w = new ZipCrateWriter();
        foreach (var (name, data, modified) in entries)
        {
            w.StartFile(name, data, name == ".signature.p7s" ? ZipCrateWriter.Stored : ZipCrateWriter.Deflated, modified);
        }

        return w.Finish();
    }

    public static byte[] B(string s) => Encoding.UTF8.GetBytes(s);

    /// <summary>A ZIP produced by System.IO.Compression (different deflate encoder, timestamps, attributes).</summary>
    public static byte[] BclZip(params (string Name, byte[] Data, bool Stored)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data, stored) in entries)
            {
                var e = zip.CreateEntry(name, stored ? CompressionLevel.NoCompression : CompressionLevel.Optimal);
                e.LastWriteTime = new DateTimeOffset(2024, 3, 4, 5, 6, 8, TimeSpan.Zero);
                using var s = e.Open();
                s.Write(data);
            }
        }

        return ms.ToArray();
    }

    /// <summary>Deterministic pseudo-random payloads that exercise stored / static / dynamic deflate blocks.</summary>
    public static IEnumerable<(string Name, byte[] Data)> StressPayloads()
    {
        var rng = new Random(12345);
        byte[] random = new byte[150_000];
        rng.NextBytes(random);
        yield return ("bin/random.bin", random);

        var sb = new StringBuilder();
        string[] words = ["alpha", "beta", "gamma", "delta", "psign", "nuget", "signature", "<xml/>", "\r\n", "    ", "Authenticode", "0123456789"];
        for (int i = 0; i < 90_000; i++)
        {
            sb.Append(words[rng.Next(words.Length)]);
            if (rng.Next(7) == 0)
            {
                sb.Append((char)('A' + rng.Next(26)));
            }
        }

        yield return ("content/text.txt", Encoding.UTF8.GetBytes(sb.ToString()));
        yield return ("content/repeat.txt", Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("abcabcabcabd", 40_000))));
        yield return ("content/zeros.bin", new byte[300_000]);
        yield return ("content/empty.txt", []);
        yield return ("content/tiny.txt", "a"u8.ToArray());
        yield return ("content/short.txt", "hello hello hello hello hello hello hello world"u8.ToArray());

        var mixed = new byte[200_000];
        for (int i = 0; i < mixed.Length; i++)
        {
            mixed[i] = (byte)(i % 1000 < 500 ? rng.Next(4) : (i * 7) & 0xFF);
        }

        yield return ("lib/net8.0/mixed.dll", mixed);
    }
}
