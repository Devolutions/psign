//! Automatic Microsoft AuthRoot CAB cache for portable trust verification.

use crate::policy::OnlineTrustOptions;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const AUTHROOT_CAB_URL: &str =
    "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";
pub const AUTHROOT_CAB_FILE_NAME: &str = "authrootstl.cab";
pub const AUTHROOT_META_FILE_NAME: &str = "authrootstl.cab.json";
pub const DEFAULT_MAX_AGE_DAYS: u64 = 7;
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_DOWNLOAD_BYTES: usize = 2 * 1024 * 1024;

const NO_AUTO_TRUST_ENV: &str = "PSIGN_NO_AUTO_TRUST";
const MAX_AGE_DAYS_ENV: &str = "PSIGN_AUTHROOT_MAX_AGE_DAYS";
const CACHE_DIR_ENV: &str = "PSIGN_AUTHROOT_CACHE_DIR";
const SOURCE_URL_ENV: &str = "PSIGN_AUTHROOT_URL";

#[derive(Debug, Clone)]
pub struct AuthRootCacheOptions {
    pub cache_dir: PathBuf,
    pub source_url: String,
    pub max_age: Duration,
    pub timeout: Duration,
    pub max_download_bytes: usize,
}

impl AuthRootCacheOptions {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            cache_dir: authroot_cache_dir_from_env()?,
            source_url: std::env::var(SOURCE_URL_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| AUTHROOT_CAB_URL.to_string()),
            max_age: Duration::from_secs(max_age_days_from_env() * 24 * 60 * 60),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_download_bytes: DEFAULT_MAX_DOWNLOAD_BYTES,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthRootCacheResolution {
    pub path: PathBuf,
    pub refreshed: bool,
    pub stale_fallback: bool,
    pub refresh_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthRootMeta {
    #[serde(default)]
    downloaded_at_utc: Option<String>,
    #[serde(default)]
    downloaded_at_unix_secs: Option<i64>,
    #[serde(default)]
    source_url: String,
    #[serde(default)]
    size_bytes: u64,
    #[serde(default)]
    sha256: Option<String>,
}

pub fn is_auto_trust_disabled() -> bool {
    std::env::var(NO_AUTO_TRUST_ENV)
        .ok()
        .is_some_and(|value| is_auto_trust_disabled_value(&value))
}

pub fn get_or_download_authroot_cab_from_env() -> Result<Option<AuthRootCacheResolution>> {
    if is_auto_trust_disabled() {
        return Ok(None);
    }
    let options = AuthRootCacheOptions::from_env()?;
    Ok(Some(get_or_download_authroot_cab(&options)?))
}

pub fn get_or_download_authroot_cab(
    options: &AuthRootCacheOptions,
) -> Result<AuthRootCacheResolution> {
    get_or_download_authroot_cab_with(options, fetch_authroot_cab_bytes)
}

fn get_or_download_authroot_cab_with<F>(
    options: &AuthRootCacheOptions,
    fetch: F,
) -> Result<AuthRootCacheResolution>
where
    F: Fn(&AuthRootCacheOptions) -> Result<Vec<u8>>,
{
    let cab_path = options.cache_dir.join(AUTHROOT_CAB_FILE_NAME);
    let meta_path = options.cache_dir.join(AUTHROOT_META_FILE_NAME);

    if cab_path.exists() && !is_stale(&cab_path, &meta_path, options.max_age)? {
        return Ok(AuthRootCacheResolution {
            path: cab_path,
            refreshed: false,
            stale_fallback: false,
            refresh_error: None,
        });
    }

    let cab_bytes = match fetch(options)
        .with_context(|| format!("download AuthRoot CAB from {}", options.source_url))
        .and_then(|bytes| {
            if bytes.is_empty() {
                Err(anyhow!(
                    "download AuthRoot CAB from {} returned an empty response",
                    options.source_url
                ))
            } else {
                Ok(bytes)
            }
        }) {
        Ok(bytes) => bytes,
        Err(error) if cab_path.exists() => {
            return Ok(AuthRootCacheResolution {
                path: cab_path,
                refreshed: false,
                stale_fallback: true,
                refresh_error: Some(error.to_string()),
            });
        }
        Err(error) => return Err(error),
    };

    cache_authroot_cab_bytes(options, &cab_path, &meta_path, &cab_bytes)?;
    Ok(AuthRootCacheResolution {
        path: cab_path,
        refreshed: true,
        stale_fallback: false,
        refresh_error: None,
    })
}

fn is_auto_trust_disabled_value(value: &str) -> bool {
    let value = value.trim();
    value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
}

fn max_age_days_from_env() -> u64 {
    std::env::var(MAX_AGE_DAYS_ENV)
        .ok()
        .and_then(|value| max_age_days_from_value(&value))
        .unwrap_or(DEFAULT_MAX_AGE_DAYS)
}

fn max_age_days_from_value(value: &str) -> Option<u64> {
    let days = value.trim().parse::<u64>().ok()?;
    (days > 0).then_some(days)
}

fn authroot_cache_dir_from_env() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(CACHE_DIR_ENV).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| {
            anyhow!("could not determine home directory for AuthRoot cache (set {CACHE_DIR_ENV})")
        })?;
    Ok(PathBuf::from(home).join(".psign").join("authroot"))
}

fn is_stale(cab_path: &Path, meta_path: &Path, max_age: Duration) -> Result<bool> {
    if !cab_path.exists() || !meta_path.exists() {
        return Ok(true);
    }
    let Ok(meta) = read_meta(meta_path) else {
        return Ok(true);
    };
    let Some(downloaded_at) = meta_downloaded_at(&meta) else {
        return Ok(true);
    };
    let Ok(age) = SystemTime::now().duration_since(downloaded_at) else {
        return Ok(false);
    };
    Ok(age > max_age)
}

fn read_meta(meta_path: &Path) -> Result<AuthRootMeta> {
    let text = std::fs::read_to_string(meta_path)
        .with_context(|| format!("read AuthRoot cache metadata {}", meta_path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("parse AuthRoot cache metadata {}", meta_path.display()))
}

fn meta_downloaded_at(meta: &AuthRootMeta) -> Option<SystemTime> {
    if let Some(secs) = meta.downloaded_at_unix_secs
        && secs >= 0
    {
        return Some(UNIX_EPOCH + Duration::from_secs(secs as u64));
    }
    let downloaded_at = meta.downloaded_at_utc.as_deref()?;
    let parsed = OffsetDateTime::parse(downloaded_at, &Rfc3339).ok()?;
    let secs = parsed.unix_timestamp();
    (secs >= 0).then_some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

fn cache_authroot_cab_bytes(
    options: &AuthRootCacheOptions,
    cab_path: &Path,
    meta_path: &Path,
    cab_bytes: &[u8],
) -> Result<()> {
    std::fs::create_dir_all(&options.cache_dir).with_context(|| {
        format!(
            "create AuthRoot cache directory {}",
            options.cache_dir.display()
        )
    })?;

    let digest = Sha256::digest(cab_bytes);
    let tmp_path = cab_path.with_file_name(format!(
        "{AUTHROOT_CAB_FILE_NAME}.tmp-{}",
        std::process::id()
    ));
    std::fs::write(&tmp_path, cab_bytes)
        .with_context(|| format!("write temporary AuthRoot CAB {}", tmp_path.display()))?;
    replace_file(&tmp_path, cab_path)
        .with_context(|| format!("cache AuthRoot CAB at {}", cab_path.display()))?;

    let meta = AuthRootMeta {
        downloaded_at_utc: Some(rfc3339_now()),
        downloaded_at_unix_secs: Some(current_unix_secs()),
        source_url: options.source_url.clone(),
        size_bytes: cab_bytes.len() as u64,
        sha256: Some(hex_lower(&digest)),
    };
    let meta_json =
        serde_json::to_string_pretty(&meta).context("serialize AuthRoot cache metadata")?;
    std::fs::write(meta_path, meta_json)
        .with_context(|| format!("write AuthRoot cache metadata {}", meta_path.display()))?;
    Ok(())
}

fn fetch_authroot_cab_bytes(options: &AuthRootCacheOptions) -> Result<Vec<u8>> {
    let online = OnlineTrustOptions {
        timeout: options.timeout,
        max_download_bytes: options.max_download_bytes,
        ..OnlineTrustOptions::default()
    };
    crate::online::http_get_limited(&options.source_url, &online)
}

fn replace_file(tmp_path: &Path, dest_path: &Path) -> Result<()> {
    match std::fs::rename(tmp_path, dest_path) {
        Ok(()) => Ok(()),
        Err(first_error) if dest_path.exists() => {
            std::fs::remove_file(dest_path)
                .with_context(|| format!("remove old {}", dest_path.display()))?;
            std::fs::rename(tmp_path, dest_path).map_err(|second_error| {
                anyhow!(
                    "rename {} to {} failed after removing old file (first: {first_error}; second: {second_error})",
                    tmp_path.display(),
                    dest_path.display()
                )
            })
        }
        Err(error) => Err(error)
            .with_context(|| format!("rename {} to {}", tmp_path.display(), dest_path.display())),
    }
}

fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn rfc3339_now() -> String {
    OffsetDateTime::from_unix_timestamp(current_unix_secs())
        .ok()
        .and_then(|instant| instant.format(&Rfc3339).ok())
        .unwrap_or_else(|| current_unix_secs().to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(cache_dir: PathBuf, source_url: String) -> AuthRootCacheOptions {
        AuthRootCacheOptions {
            cache_dir,
            source_url,
            max_age: Duration::from_secs(24 * 60 * 60),
            timeout: Duration::from_secs(2),
            max_download_bytes: 1024 * 1024,
        }
    }

    fn test_url() -> String {
        "http://example.invalid/authrootstl.cab".to_string()
    }

    fn write_meta(path: &Path, downloaded_at: SystemTime) {
        let secs = downloaded_at
            .duration_since(UNIX_EPOCH)
            .expect("downloaded_at before epoch")
            .as_secs() as i64;
        let meta = AuthRootMeta {
            downloaded_at_utc: Some(
                OffsetDateTime::from_unix_timestamp(secs)
                    .expect("timestamp")
                    .format(&Rfc3339)
                    .expect("format"),
            ),
            downloaded_at_unix_secs: Some(secs),
            source_url: AUTHROOT_CAB_URL.to_string(),
            size_bytes: 3,
            sha256: Some("00".repeat(32)),
        };
        std::fs::write(
            path,
            serde_json::to_string_pretty(&meta).expect("meta json"),
        )
        .expect("write meta");
    }

    #[test]
    fn auto_trust_disabled_value_matches_powershell_values() {
        assert!(is_auto_trust_disabled_value("1"));
        assert!(is_auto_trust_disabled_value("true"));
        assert!(is_auto_trust_disabled_value("YES"));
        assert!(!is_auto_trust_disabled_value("0"));
        assert!(!is_auto_trust_disabled_value("false"));
    }

    #[test]
    fn invalid_max_age_values_are_ignored() {
        assert_eq!(max_age_days_from_value("7"), Some(7));
        assert_eq!(max_age_days_from_value("0"), None);
        assert_eq!(max_age_days_from_value("-1"), None);
        assert_eq!(max_age_days_from_value("abc"), None);
    }

    #[test]
    fn fresh_cache_is_used_without_download() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cab_path = dir.path().join(AUTHROOT_CAB_FILE_NAME);
        let meta_path = dir.path().join(AUTHROOT_META_FILE_NAME);
        std::fs::write(&cab_path, b"old").expect("write cab");
        write_meta(&meta_path, SystemTime::now());

        let resolved = get_or_download_authroot_cab_with(
            &options(dir.path().to_path_buf(), test_url()),
            |_| panic!("fresh cache should not download"),
        )
        .expect("resolve");

        assert_eq!(resolved.path, cab_path);
        assert!(!resolved.refreshed);
        assert!(!resolved.stale_fallback);
        assert_eq!(std::fs::read(&resolved.path).expect("read cab"), b"old");
    }

    #[test]
    fn stale_cache_refreshes_from_source_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cab_path = dir.path().join(AUTHROOT_CAB_FILE_NAME);
        let meta_path = dir.path().join(AUTHROOT_META_FILE_NAME);
        std::fs::write(&cab_path, b"old").expect("write cab");
        write_meta(
            &meta_path,
            SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60),
        );

        let resolved = get_or_download_authroot_cab_with(
            &options(dir.path().to_path_buf(), test_url()),
            |_| Ok(b"new".to_vec()),
        )
        .expect("resolve");

        assert!(resolved.refreshed);
        assert!(!resolved.stale_fallback);
        assert_eq!(std::fs::read(&resolved.path).expect("read cab"), b"new");
    }

    #[test]
    fn malformed_metadata_is_treated_as_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cab_path = dir.path().join(AUTHROOT_CAB_FILE_NAME);
        let meta_path = dir.path().join(AUTHROOT_META_FILE_NAME);
        std::fs::write(&cab_path, b"old").expect("write cab");
        std::fs::write(&meta_path, b"not json").expect("write bad meta");

        let resolved = get_or_download_authroot_cab_with(
            &options(dir.path().to_path_buf(), test_url()),
            |_| Ok(b"new".to_vec()),
        )
        .expect("resolve");

        assert!(resolved.refreshed);
        assert!(!resolved.stale_fallback);
        assert_eq!(std::fs::read(&resolved.path).expect("read cab"), b"new");
    }

    #[test]
    fn stale_cache_falls_back_when_refresh_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cab_path = dir.path().join(AUTHROOT_CAB_FILE_NAME);
        let meta_path = dir.path().join(AUTHROOT_META_FILE_NAME);
        std::fs::write(&cab_path, b"old").expect("write cab");
        write_meta(
            &meta_path,
            SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60),
        );

        let resolved = get_or_download_authroot_cab_with(
            &options(dir.path().to_path_buf(), test_url()),
            |_| Err(anyhow::anyhow!("download failed")),
        )
        .expect("resolve");

        assert!(!resolved.refreshed);
        assert!(resolved.stale_fallback);
        assert!(resolved.refresh_error.is_some());
        assert_eq!(std::fs::read(&resolved.path).expect("read cab"), b"old");
    }
}
