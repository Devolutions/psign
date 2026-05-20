//! Resolve picky **`exact_date`** instant from policy (wall clock vs timestamp token).

use crate::policy::AuthenticodeTrustPolicy;
use crate::rfc3161_extract::{
    trusted_utc_date_from_authenticode_timestamp_token, utc_date_from_authenticode_timestamp_token,
};
use anyhow::{Result, anyhow};
use picky::x509::date::UtcDate;

/// Calendar date at UTC midnight for **`exact_date`** (fixtures / reproducible CI).
pub fn parse_verification_date_ymd(s: &str) -> Result<UtcDate> {
    let p: Vec<&str> = s.trim().split('-').collect();
    if p.len() != 3 {
        return Err(anyhow!("expected YYYY-MM-DD"));
    }
    let y: u16 = p[0].parse().map_err(|_| anyhow!("invalid year"))?;
    let m: u8 = p[1].parse().map_err(|_| anyhow!("invalid month"))?;
    let d: u8 = p[2].parse().map_err(|_| anyhow!("invalid day"))?;
    UtcDate::ymd(y, m, d).ok_or_else(|| anyhow!("invalid calendar date {y}-{m:02}-{d:02}"))
}

pub fn resolve_verification_utc_date(
    pkcs7_der: &[u8],
    policy: &AuthenticodeTrustPolicy,
) -> Result<UtcDate> {
    if !policy.prefer_timestamp_signing_time {
        return Ok(UtcDate::now());
    }
    match utc_date_from_authenticode_timestamp_token(pkcs7_der) {
        Some(d) => Ok(d),
        None if policy.require_valid_timestamp => Err(anyhow!(
            "timestamp required by policy but no usable RFC3161 / Authenticode timestamp token or PKCS#9 signing-time was found"
        )),
        None => Ok(UtcDate::now()),
    }
}

pub fn resolve_verification_instant_for_pkcs7(
    pkcs7_der: &[u8],
    policy: &AuthenticodeTrustPolicy,
    instant_override: Option<&UtcDate>,
) -> Result<UtcDate> {
    if let Some(d) = instant_override {
        return Ok(d.clone());
    }
    resolve_verification_utc_date(pkcs7_der, policy)
}

pub fn resolve_verification_instant_for_pkcs7_with_trust(
    pkcs7_der: &[u8],
    policy: &AuthenticodeTrustPolicy,
    instant_override: Option<&UtcDate>,
    anchors: &crate::anchor::AnchorStore,
    anchor_certs: &[picky::x509::certificate::Cert],
    online: &crate::policy::OnlineTrustOptions,
    verbose_chain: bool,
) -> Result<UtcDate> {
    if let Some(d) = instant_override {
        return Ok(d.clone());
    }
    if !policy.prefer_timestamp_signing_time {
        return Ok(UtcDate::now());
    }
    if policy.require_valid_timestamp {
        return match trusted_utc_date_from_authenticode_timestamp_token(
            pkcs7_der,
            anchors,
            anchor_certs,
            online,
            verbose_chain,
        )? {
            Some(d) => Ok(d),
            None => Err(anyhow!(
                "timestamp required by policy but no cryptographically valid trusted RFC3161 timestamp token was found"
            )),
        };
    }
    resolve_verification_utc_date(pkcs7_der, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verification_date_ymd_accepts_iso_day() {
        parse_verification_date_ymd("2023-07-01").unwrap();
        assert!(parse_verification_date_ymd("not-a-date").is_err());
        assert!(parse_verification_date_ymd("2023-13-01").is_err());
    }

    #[test]
    fn resolve_verification_utc_date_require_timestamp_errors_without_token() {
        let policy = AuthenticodeTrustPolicy {
            prefer_timestamp_signing_time: true,
            require_valid_timestamp: true,
            ..Default::default()
        };
        let err = resolve_verification_utc_date(b"", &policy).unwrap_err();
        assert!(err.to_string().contains("timestamp required"), "{err}");
    }

    #[test]
    fn resolve_verification_utc_date_require_timestamp_ok_when_prefer_off() {
        let policy = AuthenticodeTrustPolicy {
            prefer_timestamp_signing_time: false,
            require_valid_timestamp: true,
            ..Default::default()
        };
        assert!(resolve_verification_utc_date(b"", &policy).is_ok());
    }

    #[test]
    fn resolve_verification_utc_date_prefer_timestamp_without_require_does_not_error_on_empty() {
        let policy = AuthenticodeTrustPolicy {
            prefer_timestamp_signing_time: true,
            require_valid_timestamp: false,
            ..Default::default()
        };
        assert!(resolve_verification_utc_date(b"", &policy).is_ok());
    }

    #[test]
    fn resolve_verification_instant_override_skips_timestamp_requirement() {
        let policy = AuthenticodeTrustPolicy {
            prefer_timestamp_signing_time: true,
            require_valid_timestamp: true,
            ..Default::default()
        };
        let d = parse_verification_date_ymd("2020-01-01").unwrap();
        let got =
            resolve_verification_instant_for_pkcs7(b"not-valid-pkcs7", &policy, Some(&d)).unwrap();
        assert_eq!(got.year(), 2020);
        assert_eq!(got.month(), 1);
        assert_eq!(got.day(), 1);
    }
}
