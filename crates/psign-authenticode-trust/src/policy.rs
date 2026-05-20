//! Trust policy knobs (Authenticode EKU strictness, explicit online retrieval).

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct AuthenticodeTrustPolicy {
    /// When true (default), picky enforces Authenticode **code signing** EKU rules on the signer.
    pub strict_code_signing_eku: bool,
    /// Prefer RFC3161 / Authenticode nested timestamp signing time for **`exact_date`** when present.
    pub prefer_timestamp_signing_time: bool,
    /// When **`prefer_timestamp_signing_time`** is set, fail if no usable timestamp token is found.
    pub require_valid_timestamp: bool,
}

impl Default for AuthenticodeTrustPolicy {
    fn default() -> Self {
        Self {
            strict_code_signing_eku: true,
            prefer_timestamp_signing_time: false,
            require_valid_timestamp: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OnlineTrustOptions {
    /// Fetch issuer certificates from AIA caIssuers URLs when the PKCS#7/anchor pool lacks an issuer.
    pub enable_aia: bool,
    /// Deterministic test override used before certificate AIA URLs.
    pub aia_url_override: Option<String>,
    /// Query OCSP responders for signer/intermediate revocation status.
    pub enable_ocsp: bool,
    /// Deterministic OCSP responder URL override used before certificate AIA OCSP URLs.
    pub ocsp_url_override: Option<String>,
    /// Revocation checking mode for explicit online checks.
    pub revocation_mode: RevocationMode,
    /// Deterministic CRL URL override used before certificate CDP parsing.
    pub crl_url_override: Option<String>,
    /// Per-request timeout for online certificate retrieval.
    pub timeout: Duration,
    /// Maximum downloaded response size for online certificate retrieval.
    pub max_download_bytes: usize,
}

impl Default for OnlineTrustOptions {
    fn default() -> Self {
        Self {
            enable_aia: false,
            aia_url_override: None,
            enable_ocsp: false,
            ocsp_url_override: None,
            revocation_mode: RevocationMode::Off,
            crl_url_override: None,
            timeout: Duration::from_secs(5),
            max_download_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RevocationMode {
    Off,
    BestEffort,
    Require,
}
