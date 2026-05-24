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
    private const int DefaultMaxAgeDays = 30;
    private const string MaxAgeEnvVar = "PSIGN_AUTHROOT_MAX_AGE_DAYS";
    private const string NoAutoTrustEnvVar = "PSIGN_NO_AUTO_TRUST";

    private static readonly HttpClient SharedClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30),
    };

    /// <summary>
    /// Returns true if auto-trust is disabled via environment variable.
    /// </summary>
    internal static bool IsAutoTrustDisabled()
    {
        string? value = Environment.GetEnvironmentVariable(NoAutoTrustEnvVar);
        return value is "1" or "true" or "yes";
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
            writeVerbose?.Invoke($"Downloading AuthRoot CAB from {AuthRootCabUrl}...");
            DownloadCab(cabPath, metaPath);
            writeVerbose?.Invoke($"AuthRoot CAB cached at: {cabPath}");
            return cabPath;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
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

        Directory.CreateDirectory(cacheDir);
        writeVerbose?.Invoke($"Downloading AuthRoot CAB from {AuthRootCabUrl}...");
        DownloadCab(cabPath, metaPath);
        writeVerbose?.Invoke($"AuthRoot CAB cached at: {cabPath}");
        return cabPath;
    }

    private static string GetCacheDirectory()
    {
        string home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetEnvironmentVariable("USERPROFILE")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        return Path.Combine(home, ".psign", "authroot");
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

            int maxAgeDays = GetMaxAgeDays();
            return (DateTime.UtcNow - meta.DownloadedAtUtc).TotalDays > maxAgeDays;
        }
        catch
        {
            return true;
        }
    }

    private static int GetMaxAgeDays()
    {
        string? envValue = Environment.GetEnvironmentVariable(MaxAgeEnvVar);
        if (envValue is not null && int.TryParse(envValue, out int days) && days > 0)
        {
            return days;
        }
        return DefaultMaxAgeDays;
    }

    private static void DownloadCab(string cabPath, string metaPath)
    {
        using HttpResponseMessage response = SharedClient.GetAsync(AuthRootCabUrl).GetAwaiter().GetResult();
        response.EnsureSuccessStatusCode();

        byte[] bytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();

        string tempCab = cabPath + ".tmp";
        File.WriteAllBytes(tempCab, bytes);
        File.Move(tempCab, cabPath, overwrite: true);

        AuthRootMeta meta = new()
        {
            DownloadedAtUtc = DateTime.UtcNow,
            SourceUrl = AuthRootCabUrl,
            SizeBytes = bytes.Length,
        };

        string metaJson = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(metaPath, metaJson);
    }

    private sealed class AuthRootMeta
    {
        [JsonPropertyName("downloaded_at_utc")]
        public DateTime DownloadedAtUtc { get; init; }

        [JsonPropertyName("source_url")]
        public string SourceUrl { get; init; } = string.Empty;

        [JsonPropertyName("size_bytes")]
        public long SizeBytes { get; init; }
    }
}
