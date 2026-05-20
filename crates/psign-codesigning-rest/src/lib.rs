//! Azure Code Signing **data-plane** REST (`CertificateProfileOperations_Sign` LRO).
//! Portable (`reqwest` + **rustls**); safe to call from Linux or Windows.

use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use std::thread;
use std::time::Duration;

const DEFAULT_SCOPE: &str = "https://codesigning.azure.net/.default";
const MI_RESOURCE: &str = "https://codesigning.azure.net";

/// Authentication mode for **`codesigning.azure.net`**.
#[derive(Debug, Clone)]
pub enum CodesigningAuth {
    ManagedIdentity,
    Bearer(String),
    ClientCredentials {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
}

/// Parameters for **`…/certificateprofiles/{profile}:sign`** (blocking).
#[derive(Debug, Clone)]
pub struct CodesigningSubmitParams {
    pub region: String,
    pub account_name: String,
    pub profile_name: String,
    pub digest: Vec<u8>,
    pub signature_algorithm: String,
    pub api_version: String,
    pub correlation_id: Option<String>,
    pub authority: Option<String>,
    pub auth: CodesigningAuth,
    /// Override data-plane origin (scheme + host and optional port), no trailing slash.
    /// Default: `https://{region}.codesigning.azure.net`. Used by integration tests;
    /// omit in production unless pointing at a non-standard endpoint.
    pub endpoint_base_url: Option<String>,
}

fn data_plane_base_url(params: &CodesigningSubmitParams) -> String {
    if let Some(ref u) = params.endpoint_base_url {
        let t = u.trim().trim_end_matches('/');
        if !t.is_empty() {
            return t.to_string();
        }
    }
    format!("https://{}.codesigning.azure.net", params.region.trim())
}

fn normalize_authority(authority: Option<&str>) -> String {
    authority
        .unwrap_or("https://login.microsoftonline.com")
        .trim_end_matches('/')
        .to_string()
}

fn acquire_codesigning_token(params: &CodesigningSubmitParams) -> Result<String> {
    match &params.auth {
        CodesigningAuth::Bearer(tok) => {
            let t = tok.trim();
            if t.is_empty() {
                return Err(anyhow!("access token must not be empty"));
            }
            Ok(t.to_string())
        }
        CodesigningAuth::ManagedIdentity => {
            let http = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .map_err(|e| anyhow!("HTTP client: {e}"))?;
            let rsp = http
                .get("http://169.254.169.254/metadata/identity/oauth2/token")
                .query(&[("api-version", "2018-02-01"), ("resource", MI_RESOURCE)])
                .header("Metadata", "true")
                .send()
                .context("managed identity token (IMDS) for codesigning.azure.net")?;
            if !rsp.status().is_success() {
                return Err(anyhow!(
                    "managed identity token HTTP {}: {}",
                    rsp.status(),
                    rsp.text().unwrap_or_default()
                ));
            }
            #[derive(Deserialize)]
            struct MiJson {
                access_token: String,
            }
            let j: MiJson = rsp.json().context("managed identity JSON")?;
            Ok(j.access_token)
        }
        CodesigningAuth::ClientCredentials {
            tenant_id,
            client_id,
            client_secret,
        } => {
            let tenant = tenant_id.trim();
            let cid = client_id.trim();
            let sec = client_secret.trim();
            if tenant.is_empty() || cid.is_empty() || sec.is_empty() {
                return Err(anyhow!(
                    "client credentials require non-empty tenant_id, client_id, client_secret"
                ));
            }
            let http = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .map_err(|e| anyhow!("HTTP client: {e}"))?;
            let token_url = format!(
                "{}/{tenant}/oauth2/v2.0/token",
                normalize_authority(params.authority.as_deref())
            );
            let rsp = http
                .post(&token_url)
                .form(&[
                    ("client_id", cid),
                    ("client_secret", sec),
                    ("grant_type", "client_credentials"),
                    ("scope", DEFAULT_SCOPE),
                ])
                .send()
                .context("OAuth token request (codesigning.azure.net)")?;
            if !rsp.status().is_success() {
                return Err(anyhow!(
                    "OAuth HTTP {}: {}",
                    rsp.status(),
                    rsp.text().unwrap_or_default()
                ));
            }
            #[derive(Deserialize)]
            struct TokenJson {
                access_token: String,
            }
            let j: TokenJson = rsp.json().context("OAuth JSON")?;
            Ok(j.access_token)
        }
    }
}

fn poll_operation(http: &reqwest::blocking::Client, token: &str, poll_url: &str) -> Result<Value> {
    let url_str = poll_url.to_string();
    for _ in 0..90 {
        let rsp = http
            .get(&url_str)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .context("poll codesign operation")?;
        if !rsp.status().is_success() {
            return Err(anyhow!(
                "poll HTTP {}: {}",
                rsp.status(),
                rsp.text().unwrap_or_default()
            ));
        }
        let v: Value = rsp.json().context("poll JSON")?;
        let status = v.get("status").and_then(|s| s.as_str()).unwrap_or_default();
        match status {
            "Succeeded" => return Ok(v),
            "Failed" => {
                return Err(anyhow!(
                    "codesign operation failed: {}",
                    serde_json::to_string(&v).unwrap_or_default()
                ));
            }
            "Canceled" => return Err(anyhow!("codesign operation canceled")),
            _ => thread::sleep(Duration::from_secs(2)),
        }
    }
    Err(anyhow!("codesign operation timed out polling {url_str}"))
}

/// Submit hash to **`…:sign`**, poll LRO, return final JSON (**`Succeeded`** body).
pub fn submit_codesign_hash_blocking(
    params: &CodesigningSubmitParams,
    debug: impl Fn(&str),
) -> Result<Value> {
    if params.digest.is_empty() {
        return Err(anyhow!("digest is empty"));
    }

    let token = acquire_codesigning_token(params)?;
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;

    let base = data_plane_base_url(params);
    let account = params.account_name.trim();
    let profile = params.profile_name.trim();
    let api = params.api_version.trim();
    let submit_url = format!(
        "{base}/codesigningaccounts/{account}/certificateprofiles/{profile}:sign?api-version={api}",
    );

    let body = serde_json::json!({
        "signatureAlgorithm": params.signature_algorithm.trim(),
        "digest": base64::engine::general_purpose::STANDARD.encode(&params.digest),
    });

    let mut req = http
        .post(&submit_url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&body);
    if let Some(c) = params
        .correlation_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        req = req.header("x-ms-correlation-id", c);
    }

    let rsp = req.send().context("codesign :sign POST")?;
    let status = rsp.status();
    let op_location = rsp
        .headers()
        .get("Operation-Location")
        .or_else(|| rsp.headers().get("operation-location"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let body_bytes = rsp.bytes().context(":sign body")?;
    let accept_json: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);

    if !status.is_success() {
        return Err(anyhow!(
            ":sign HTTP {}: {}",
            status,
            String::from_utf8_lossy(&body_bytes)
        ));
    }

    let poll_url = if let Some(loc) = op_location {
        loc
    } else if let Some(id) = accept_json.get("id").and_then(|v| v.as_str()) {
        format!(
            "{base}/codesigningaccounts/{account}/certificateprofiles/{profile}/sign/{id}?api-version={api}",
        )
    } else {
        return Ok(accept_json);
    };

    debug(&format!("artifact-signing poll URL={poll_url}"));

    poll_operation(&http, &token, &poll_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_empty_rejected() {
        let p = CodesigningSubmitParams {
            region: "x".into(),
            account_name: "a".into(),
            profile_name: "p".into(),
            digest: vec![1, 2, 3],
            signature_algorithm: "RS256".into(),
            api_version: "2023-06-15-preview".into(),
            correlation_id: None,
            authority: None,
            auth: CodesigningAuth::Bearer("  ".into()),
            endpoint_base_url: None,
        };
        assert!(acquire_codesigning_token(&p).is_err());
    }

    #[test]
    fn data_plane_base_url_default_from_region() {
        let p = CodesigningSubmitParams {
            region: "westus2".into(),
            account_name: "a".into(),
            profile_name: "p".into(),
            digest: vec![],
            signature_algorithm: "RS256".into(),
            api_version: "2023-06-15-preview".into(),
            correlation_id: None,
            authority: None,
            auth: CodesigningAuth::Bearer("tok".into()),
            endpoint_base_url: None,
        };
        assert_eq!(
            data_plane_base_url(&p),
            "https://westus2.codesigning.azure.net"
        );
    }

    #[test]
    fn data_plane_base_url_override_trims_slash() {
        let p = CodesigningSubmitParams {
            region: "ignored".into(),
            account_name: "a".into(),
            profile_name: "p".into(),
            digest: vec![],
            signature_algorithm: "RS256".into(),
            api_version: "2023-06-15-preview".into(),
            correlation_id: None,
            authority: None,
            auth: CodesigningAuth::Bearer("tok".into()),
            endpoint_base_url: Some("https://mock.codesigning.test/".into()),
        };
        assert_eq!(data_plane_base_url(&p), "https://mock.codesigning.test");
    }

    #[test]
    fn data_plane_base_url_override_empty_falls_back_to_region() {
        let p = CodesigningSubmitParams {
            region: "eastus".into(),
            account_name: "a".into(),
            profile_name: "p".into(),
            digest: vec![],
            signature_algorithm: "RS256".into(),
            api_version: "2023-06-15-preview".into(),
            correlation_id: None,
            authority: None,
            auth: CodesigningAuth::Bearer("tok".into()),
            endpoint_base_url: Some("   ".into()),
        };
        assert_eq!(
            data_plane_base_url(&p),
            "https://eastus.codesigning.azure.net"
        );
    }

    #[test]
    fn submit_codesign_hash_blocking_rejects_empty_digest() {
        let p = CodesigningSubmitParams {
            region: "westus2".into(),
            account_name: "a".into(),
            profile_name: "p".into(),
            digest: vec![],
            signature_algorithm: "RS256".into(),
            api_version: "2023-06-15-preview".into(),
            correlation_id: None,
            authority: None,
            auth: CodesigningAuth::Bearer("tok".into()),
            endpoint_base_url: None,
        };
        let err = submit_codesign_hash_blocking(&p, |_| {}).unwrap_err();
        assert!(err.to_string().contains("digest is empty"), "{err}");
    }
}
