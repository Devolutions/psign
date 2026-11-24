using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Psign.PowerShell.Trust;

/// <summary>
/// Manages automatic download and caching of the Microsoft AuthRoot CAB
/// (Certificate Trust List) for portable trust verification on non-Windows platforms.
/// </summary>
internal static class AuthRootCache
{
    private const string AuthRootCabUrl = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
    private const string CabFileName = "authrootstl.cab";
    private const string MetaFileName = "authrootstl.cab.json";
    private const int DefaultMaxAgeDays = 7;
    private const string MaxAgeEnvVar = "PSIGN_AUTHROOT_MAX_AGE_DAYS";
    private const string NoAutoTrustEnvVar = "PSIGN_NO_AUTO_TRUST";
    private const string CacheDirEnvVar = "PSIGN_AUTHROOT_CACHE_DIR";
    private const string SourceUrlEnvVar = "PSIGN_AUTHROOT_URL";

    private static readonly HttpClient SharedClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30),
    };

    /// <summary>
    /// Returns true if auto-trust is disabled via environment variable.
    /// </summary>
    internal static bool IsAutoTrustDisabled()
    {
        string? value = Environment.GetEnvironmentVariable(NoAutoTrustEnvVar)?.Trim();
        return value == "1"
            || string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns the path to a cached AuthRoot CAB, downloading it if missing or stale.
    /// Returns null if the download fails or auto-trust is disabled.
    /// </summary>
    internal static string? GetOrDownloadAuthRootCab(Action<string>? writeVerbose = null)
    {
        if (IsAutoTrustDisabled())
        {
            return null;
        }

        string cacheDir = GetCacheDirectory();
        string cabPath = Path.Combine(cacheDir, CabFileName);
        string metaPath = Path.Combine(cacheDir, MetaFileName);

        if (File.Exists(cabPath) && !IsStale(metaPath))
        {
            writeVerbose?.Invoke($"Using cached AuthRoot CAB: {cabPath}");
            return cabPath;
        }

        try
        {
            Directory.CreateDirectory(cacheDir);
            string sourceUrl = GetSourceUrl();
            writeVerbose?.Invoke($"Downloading AuthRoot CAB from {sourceUrl}...");
            DownloadCab(cabPath, metaPath, sourceUrl);
            writeVerbose?.Invoke($"AuthRoot CAB cached at: {cabPath}");
            return cabPath;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException)
        {
            writeVerbose?.Invoke($"AuthRoot CAB download failed: {ex.Message}");

            // Fall back to existing cached copy if available (even if stale)
            if (File.Exists(cabPath))
            {
                writeVerbose?.Invoke($"Using stale cached AuthRoot CAB: {cabPath}");
                return cabPath;
            }

            return null;
        }
    }

    /// <summary>
    /// Forces a refresh of the cached AuthRoot CAB regardless of staleness.
    /// </summary>
    internal static string? RefreshAuthRootCab(Action<string>? writeVerbose = null)
    {
        string cacheDir = GetCacheDirectory();
        string cabPath = Path.Combine(cacheDir, CabFileName);
        string metaPath = Path.Combine(cacheDir, MetaFileName);
        string sourceUrl = GetSourceUrl();

        Directory.CreateDirectory(cacheDir);
        writeVerbose?.Invoke($"Downloading AuthRoot CAB from {sourceUrl}...");
        DownloadCab(cabPath, metaPath, sourceUrl);
        writeVerbose?.Invoke($"AuthRoot CAB cached at: {cabPath}");
        return cabPath;
    }

    private static string GetCacheDirectory()
    {
        string? configured = Environment.GetEnvironmentVariable(CacheDirEnvVar);
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        string home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetEnvironmentVariable("USERPROFILE")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        return Path.Combine(home, ".psign", "authroot");
    }

    private static string GetSourceUrl()
    {
        string? configured = Environment.GetEnvironmentVariable(SourceUrlEnvVar);
        return string.IsNullOrWhiteSpace(configured)
            ? AuthRootCabUrl
            : configured;
    }

    private static bool IsStale(string metaPath)
    {
        if (!File.Exists(metaPath))
        {
            return true;
        }

        try
        {
            string json = File.ReadAllText(metaPath);
            AuthRootMeta? meta = JsonSerializer.Deserialize<AuthRootMeta>(json);
            if (meta is null)
            {
                return true;
            }

            DateTimeOffset? downloadedAt = meta.DownloadedAtUnixSecs is { } secs && secs >= 0
                ? DateTimeOffset.FromUnixTimeSeconds(secs)
                : meta.DownloadedAtUtc is { } dt
                    ? new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc))
                    : null;
            if (downloadedAt is null)
            {
                return true;
            }

            int maxAgeDays = GetMaxAgeDays();
            return (DateTimeOffset.UtcNow - downloadedAt.Value).TotalDays > maxAgeDays;
        }
        catch
        {
            return true;
        }
    }

    private static int GetMaxAgeDays()
    {
        string? envValue = Environment.GetEnvironmentVariable(MaxAgeEnvVar);
        if (envValue is not null
            && int.TryParse(envValue.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int days)
            && days > 0)
        {
            return days;
        }
        return DefaultMaxAgeDays;
    }

    private const int DefaultMaxDownloadBytes = 2 * 1024 * 1024;

    private static void DownloadCab(string cabPath, string metaPath, string sourceUrl)
    {
        byte[] bytes = Task.Run(async () =>
        {
            using CancellationTokenSource cts = new(TimeSpan.FromSeconds(30));
            using HttpResponseMessage response = await SharedClient
                .GetAsync(sourceUrl, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                .ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            await using Stream stream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            using MemoryStream ms = new();
            byte[] buffer = new byte[16 * 1024];
            int read;
            while ((read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false)) > 0)
            {
                ms.Write(buffer, 0, read);
                if (ms.Length > DefaultMaxDownloadBytes)
                {
                    throw new IOException($"AuthRoot CAB download exceeded {DefaultMaxDownloadBytes} bytes.");
                }
            }

            return ms.ToArray();
        }).GetAwaiter().GetResult();

        if (bytes.Length == 0)
        {
            throw new IOException("AuthRoot CAB download returned an empty response.");
        }

        string tempCab = $"{cabPath}.tmp-{Environment.ProcessId}-{Guid.NewGuid():N}";
        try
        {
            File.WriteAllBytes(tempCab, bytes);
            File.Move(tempCab, cabPath, overwrite: true);
        }
        catch
        {
            try
            {
                File.Delete(tempCab);
            }
            catch
            {
            }

            throw;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        AuthRootMeta meta = new()
        {
            DownloadedAtUtc = now.UtcDateTime,
            DownloadedAtUnixSecs = now.ToUnixTimeSeconds(),
            SourceUrl = sourceUrl,
            SizeBytes = bytes.Length,
        };

        string metaJson = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
        string tempMeta = $"{metaPath}.tmp-{Environment.ProcessId}-{Guid.NewGuid():N}";
        try
        {
            File.WriteAllText(tempMeta, metaJson);
            File.Move(tempMeta, metaPath, overwrite: true);
        }
        catch
        {
            try
            {
                File.Delete(tempMeta);
            }
            catch
            {
            }

            throw;
        }
    }

    private sealed class AuthRootMeta
    {
        [JsonPropertyName("downloaded_at_utc")]
        public DateTime? DownloadedAtUtc { get; init; }

        [JsonPropertyName("downloaded_at_unix_secs")]
        public long? DownloadedAtUnixSecs { get; init; }

        [JsonPropertyName("source_url")]
        public string SourceUrl { get; init; } = string.Empty;

        [JsonPropertyName("size_bytes")]
        public long SizeBytes { get; init; }
    }
}
