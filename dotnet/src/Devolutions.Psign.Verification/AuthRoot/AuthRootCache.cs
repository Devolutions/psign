using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Devolutions.Psign.Core;
using Devolutions.Psign.Core.Json;

namespace Devolutions.Psign.Verification.AuthRoot;

/// <summary>AuthRoot cache options (Rust <c>authroot_cache::AuthRootCacheOptions</c>).</summary>
public sealed record AuthRootCacheOptions
{
    public required string CacheDir { get; init; }

    public string SourceUrl { get; init; } = AuthRootCache.AuthRootCabUrl;

    public TimeSpan MaxAge { get; init; } = TimeSpan.FromDays(AuthRootCache.DefaultMaxAgeDays);

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(AuthRootCache.DefaultTimeoutSecs);

    public int MaxDownloadBytes { get; init; } = AuthRootCache.DefaultMaxDownloadBytes;

    /// <summary>Options from <c>PSIGN_AUTHROOT_CACHE_DIR</c>, <c>PSIGN_AUTHROOT_URL</c>, <c>PSIGN_AUTHROOT_MAX_AGE_DAYS</c>.</summary>
    public static AuthRootCacheOptions FromEnv()
    {
        var url = Environment.GetEnvironmentVariable(AuthRootCache.SourceUrlEnv);
        return new AuthRootCacheOptions
        {
            CacheDir = AuthRootCache.CacheDirFromEnv(),
            SourceUrl = string.IsNullOrWhiteSpace(url) ? AuthRootCache.AuthRootCabUrl : url,
            MaxAge = TimeSpan.FromSeconds(AuthRootCache.MaxAgeDaysFromEnv() * 24 * 60 * 60),
            Timeout = TimeSpan.FromSeconds(AuthRootCache.DefaultTimeoutSecs),
            MaxDownloadBytes = AuthRootCache.DefaultMaxDownloadBytes,
        };
    }
}

/// <summary>Outcome of resolving the AuthRoot CAB cache.</summary>
public sealed record AuthRootCacheResolution(string Path, bool Refreshed, bool StaleFallback, string? RefreshError);

/// <summary>
/// Automatic Microsoft AuthRoot CAB cache for portable trust verification (Rust <c>authroot_cache.rs</c>). The cache
/// directory layout (<c>~/.psign/authroot/authrootstl.cab</c> + <c>authrootstl.cab.json</c>), metadata format, expiry and
/// download URL are identical to the Rust tool so both share the same cache.
/// </summary>
public static class AuthRootCache
{
    public const string AuthRootCabUrl = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
    public const string AuthRootCabFileName = "authrootstl.cab";
    public const string AuthRootMetaFileName = "authrootstl.cab.json";
    public const ulong DefaultMaxAgeDays = 7;
    public const int DefaultTimeoutSecs = 30;
    public const int DefaultMaxDownloadBytes = 2 * 1024 * 1024;

    internal const string NoAutoTrustEnv = "PSIGN_NO_AUTO_TRUST";
    internal const string MaxAgeDaysEnv = "PSIGN_AUTHROOT_MAX_AGE_DAYS";
    internal const string CacheDirEnv = "PSIGN_AUTHROOT_CACHE_DIR";
    internal const string SourceUrlEnv = "PSIGN_AUTHROOT_URL";

    internal sealed class AuthRootMeta
    {
        [JsonPropertyName("downloaded_at_utc")]
        public string? DownloadedAtUtc { get; set; }

        [JsonPropertyName("downloaded_at_unix_secs")]
        public long? DownloadedAtUnixSecs { get; set; }

        [JsonPropertyName("source_url")]
        public string SourceUrl { get; set; } = string.Empty;

        [JsonPropertyName("size_bytes")]
        public ulong SizeBytes { get; set; }

        [JsonPropertyName("sha256")]
        public string? Sha256 { get; set; }
    }

    /// <summary><c>PSIGN_NO_AUTO_TRUST</c> is <c>1</c>, <c>true</c> or <c>yes</c>.</summary>
    public static bool IsAutoTrustDisabled() =>
        Environment.GetEnvironmentVariable(NoAutoTrustEnv) is { } v && IsAutoTrustDisabledValue(v);

    internal static bool IsAutoTrustDisabledValue(string value)
    {
        value = value.Trim();
        return value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Resolve the cache from the environment; <c>null</c> when automatic trust is disabled.</summary>
    public static AuthRootCacheResolution? GetOrDownloadAuthRootCabFromEnv()
    {
        if (IsAutoTrustDisabled())
        {
            return null;
        }

        return GetOrDownloadAuthRootCab(AuthRootCacheOptions.FromEnv());
    }

    /// <summary>Use a fresh cached CAB, otherwise download it (falling back to a stale copy when the refresh fails).</summary>
    public static AuthRootCacheResolution GetOrDownloadAuthRootCab(AuthRootCacheOptions options) =>
        GetOrDownloadAuthRootCabWith(options, FetchAuthRootCabBytes);

    internal static AuthRootCacheResolution GetOrDownloadAuthRootCabWith(AuthRootCacheOptions options, Func<AuthRootCacheOptions, byte[]> fetch)
    {
        var cabPath = Path.Combine(options.CacheDir, AuthRootCabFileName);
        var metaPath = Path.Combine(options.CacheDir, AuthRootMetaFileName);
        if (File.Exists(cabPath) && !IsStale(cabPath, metaPath, options.MaxAge))
        {
            return new AuthRootCacheResolution(cabPath, false, false, null);
        }

        byte[] cabBytes;
        try
        {
            try
            {
                cabBytes = fetch(options);
            }
            catch (Exception e) when (e is PsignException or IOException or HttpRequestException)
            {
                throw PsignException.Context($"download AuthRoot CAB from {options.SourceUrl}", e);
            }

            if (cabBytes.Length == 0)
            {
                throw new PsignException($"download AuthRoot CAB from {options.SourceUrl} returned an empty response");
            }
        }
        catch (PsignException e) when (File.Exists(cabPath))
        {
            return new AuthRootCacheResolution(cabPath, false, true, e.Message);
        }

        CacheAuthRootCabBytes(options, cabPath, metaPath, cabBytes);
        return new AuthRootCacheResolution(cabPath, true, false, null);
    }

    internal static ulong MaxAgeDaysFromEnv() =>
        Environment.GetEnvironmentVariable(MaxAgeDaysEnv) is { } v && MaxAgeDaysFromValue(v) is { } d ? d : DefaultMaxAgeDays;

    internal static ulong? MaxAgeDaysFromValue(string value) =>
        ulong.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var days) && days > 0 ? days : null;

    internal static string CacheDirFromEnv()
    {
        var dir = Environment.GetEnvironmentVariable(CacheDirEnv);
        if (!string.IsNullOrEmpty(dir))
        {
            return dir;
        }

        var home = Environment.GetEnvironmentVariable("HOME") ?? Environment.GetEnvironmentVariable("USERPROFILE")
            ?? throw new PsignException($"could not determine home directory for AuthRoot cache (set {CacheDirEnv})");
        return Path.Combine(home, ".psign", "authroot");
    }

    private static bool IsStale(string cabPath, string metaPath, TimeSpan maxAge)
    {
        if (!File.Exists(cabPath) || !File.Exists(metaPath))
        {
            return true;
        }

        AuthRootMeta? meta;
        try
        {
            meta = JsonSerializer.Deserialize<AuthRootMeta>(File.ReadAllText(metaPath));
        }
        catch (Exception e) when (e is JsonException or IOException or UnauthorizedAccessException)
        {
            return true;
        }

        if (meta is null || MetaDownloadedAt(meta) is not { } downloadedAt)
        {
            return true;
        }

        var age = DateTimeOffset.UtcNow - downloadedAt;
        if (age < TimeSpan.Zero)
        {
            return false;
        }

        return age > maxAge;
    }

    private static DateTimeOffset? MetaDownloadedAt(AuthRootMeta meta)
    {
        if (meta.DownloadedAtUnixSecs is { } secs && secs >= 0)
        {
            return DateTimeOffset.FromUnixTimeSeconds(secs);
        }

        if (meta.DownloadedAtUtc is not { } text)
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) || !text.Contains('T', StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return parsed.ToUnixTimeSeconds() >= 0 ? DateTimeOffset.FromUnixTimeSeconds(parsed.ToUnixTimeSeconds()) : null;
    }

    private static void CacheAuthRootCabBytes(AuthRootCacheOptions options, string cabPath, string metaPath, byte[] cabBytes)
    {
        try
        {
            Directory.CreateDirectory(options.CacheDir);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw PsignException.Context($"create AuthRoot cache directory {options.CacheDir}", e);
        }

        var digest = SHA256.HashData(cabBytes);
        var tmpPath = Path.Combine(Path.GetDirectoryName(cabPath) ?? options.CacheDir, $"{AuthRootCabFileName}.tmp-{Environment.ProcessId}");
        try
        {
            File.WriteAllBytes(tmpPath, cabBytes);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw PsignException.Context($"write temporary AuthRoot CAB {tmpPath}", e);
        }

        try
        {
            File.Move(tmpPath, cabPath, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw PsignException.Context($"cache AuthRoot CAB at {cabPath}", e);
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var meta = new AuthRootMeta
        {
            DownloadedAtUtc = DateTimeOffset.FromUnixTimeSeconds(now).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            DownloadedAtUnixSecs = now,
            SourceUrl = options.SourceUrl,
            SizeBytes = (ulong)cabBytes.Length,
            Sha256 = Hex.Lower(digest),
        };
        try
        {
            File.WriteAllText(metaPath, RustJson.ToStringPretty(meta));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw PsignException.Context($"write AuthRoot cache metadata {metaPath}", e);
        }
    }

    private static byte[] FetchAuthRootCabBytes(AuthRootCacheOptions options) =>
        OnlineTrust.HttpGetLimited(options.SourceUrl, new OnlineTrustOptions { Timeout = options.Timeout, MaxDownloadBytes = options.MaxDownloadBytes });
}
