//! Azure Code Signing **data-plane** REST (`CertificateProfileOperations_Sign` LRO).
//! Portable (`reqwest` + **rustls**); safe to call from Linux or Windows.

use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use std::thread;
use std::time::Duration;

pub const DEFAULT_API_VERSION: &str = "2024-06-15";
const DEFAULT_SCOPE: &str = "https://codesigning.azure.net/.default";
const MI_RESOURCE: &str = "https://codesigning.azure.net";

/// Authentication mode for **`codesigning.azure.net`**.
#[derive(Debug, Clone)]
pub enum CodesigningAuth {
    ManagedIdentity {
        client_id: Option<String>,
        resource_id: Option<String>,
    },
    Bearer(String),
    ClientCredentials {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    WorkloadIdentity {
        tenant_id: String,
        client_id: String,
        federated_token_file: String,
    },
    DefaultChain {
        exclude_credentials: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CodesigningCredentialType {
    Default,
    ManagedIdentity,
    AccessToken,
    ClientSecret,
    WorkloadIdentity,
}

#[derive(Debug, Clone, Default)]
pub struct CodesigningAuthInput {
    pub access_token: Option<String>,
    pub managed_identity: bool,
    pub managed_identity_resource_id: Option<String>,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub federated_token_file: Option<String>,
    pub credential_type: Option<CodesigningCredentialType>,
    pub exclude_credentials: Vec<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodesigningSignatureResult {
    pub signature: Vec<u8>,
    pub signing_certificate: Vec<u8>,
    pub final_json: Value,
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

fn operation_location_url(base: &str, location: &str) -> String {
    let trimmed = location.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    if trimmed.starts_with('/') {
        return format!("{}{}", base.trim_end_matches('/'), trimmed);
    }
    format!("{}/{}", base.trim_end_matches('/'), trimmed)
}

fn normalize_authority(authority: Option<&str>) -> String {
    authority
        .unwrap_or("https://login.microsoftonline.com")
        .trim_end_matches('/')
        .to_string()
}

fn text_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn env_text(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|v| text_opt(Some(&v)))
}

fn credential_excluded(exclude_credentials: &[String], names: &[&str]) -> bool {
    exclude_credentials.iter().any(|value| {
        let normalized = value.trim().replace(['-', '_', ' '], "");
        names
            .iter()
            .any(|name| normalized.eq_ignore_ascii_case(&name.replace(['-', '_', ' '], "")))
    })
}

pub fn resolve_codesigning_auth(input: &CodesigningAuthInput) -> Result<CodesigningAuth> {
    let token = text_opt(input.access_token.as_deref());
    let tenant = text_opt(input.tenant_id.as_deref());
    let client = text_opt(input.client_id.as_deref());
    let secret = text_opt(input.client_secret.as_deref());
    let federated_token_file = text_opt(input.federated_token_file.as_deref());
    let resource_id = text_opt(input.managed_identity_resource_id.as_deref());
    let client_parts = tenant.is_some() as u8 + client.is_some() as u8 + secret.is_some() as u8;

    match input
        .credential_type
        .unwrap_or(CodesigningCredentialType::Default)
    {
        CodesigningCredentialType::AccessToken => {
            if client_parts != 0 || input.managed_identity || federated_token_file.is_some() {
                return Err(anyhow!(
                    "Artifact Signing access-token credential cannot be combined with managed identity, workload identity, or client credentials"
                ));
            }
            return token.map(CodesigningAuth::Bearer).ok_or_else(|| {
                anyhow!("Artifact Signing access-token credential requires access-token")
            });
        }
        CodesigningCredentialType::ClientSecret => {
            if token.is_some() || input.managed_identity || federated_token_file.is_some() {
                return Err(anyhow!(
                    "Artifact Signing client-secret credential cannot be combined with access token, managed identity, or workload identity"
                ));
            }
            if client_parts != 3 {
                return Err(anyhow!(
                    "Artifact Signing client-secret credential requires tenant-id, client-id, and client-secret"
                ));
            }
            return Ok(CodesigningAuth::ClientCredentials {
                tenant_id: tenant.unwrap(),
                client_id: client.unwrap(),
                client_secret: secret.unwrap(),
            });
        }
        CodesigningCredentialType::ManagedIdentity => {
            if token.is_some()
                || tenant.is_some()
                || secret.is_some()
                || federated_token_file.is_some()
            {
                return Err(anyhow!(
                    "Artifact Signing managed identity credential cannot be combined with access token, tenant/client-secret, or workload identity"
                ));
            }
            return Ok(CodesigningAuth::ManagedIdentity {
                client_id: client,
                resource_id,
            });
        }
        CodesigningCredentialType::WorkloadIdentity => {
            if token.is_some()
                || secret.is_some()
                || input.managed_identity
                || resource_id.is_some()
            {
                return Err(anyhow!(
                    "Artifact Signing workload identity credential cannot be combined with access token, client secret, or managed identity"
                ));
            }
            let tenant_id = tenant
                .or_else(|| env_text("AZURE_TENANT_ID"))
                .ok_or_else(|| {
                    anyhow!(
                        "Artifact Signing workload identity requires tenant-id or AZURE_TENANT_ID"
                    )
                })?;
            let client_id = client
                .or_else(|| env_text("AZURE_CLIENT_ID"))
                .ok_or_else(|| {
                    anyhow!(
                        "Artifact Signing workload identity requires client-id or AZURE_CLIENT_ID"
                    )
                })?;
            let token_file = federated_token_file
                .or_else(|| env_text("AZURE_FEDERATED_TOKEN_FILE"))
                .ok_or_else(|| {
                    anyhow!("Artifact Signing workload identity requires federated-token-file or AZURE_FEDERATED_TOKEN_FILE")
                })?;
            return Ok(CodesigningAuth::WorkloadIdentity {
                tenant_id,
                client_id,
                federated_token_file: token_file,
            });
        }
        CodesigningCredentialType::Default => {}
    }

    if input.managed_identity {
        if token.is_some() || tenant.is_some() || secret.is_some() || federated_token_file.is_some()
        {
            return Err(anyhow!(
                "use either Artifact Signing managed identity, access token, workload identity, or client credentials, not multiple"
            ));
        }
        return Ok(CodesigningAuth::ManagedIdentity {
            client_id: client,
            resource_id,
        });
    }
    if let Some(token) = token {
        if client_parts != 0 || federated_token_file.is_some() {
            return Err(anyhow!(
                "use either Artifact Signing access token, workload identity, or client credentials, not multiple"
            ));
        }
        return Ok(CodesigningAuth::Bearer(token));
    }
    if let Some(federated_token_file) = federated_token_file {
        if secret.is_some() {
            return Err(anyhow!(
                "use either Artifact Signing workload identity or client credentials, not both"
            ));
        }
        if tenant.is_none() || client.is_none() {
            return Err(anyhow!(
                "Artifact Signing workload identity requires tenant-id, client-id, and federated-token-file"
            ));
        }
        return Ok(CodesigningAuth::WorkloadIdentity {
            tenant_id: tenant.unwrap(),
            client_id: client.unwrap(),
            federated_token_file,
        });
    }
    if client_parts != 0 && client_parts != 3 {
        return Err(anyhow!(
            "Artifact Signing client credentials require all of tenant-id, client-id, and client-secret"
        ));
    }
    if client_parts == 3 {
        return Ok(CodesigningAuth::ClientCredentials {
            tenant_id: tenant.unwrap(),
            client_id: client.unwrap(),
            client_secret: secret.unwrap(),
        });
    }
    Ok(CodesigningAuth::DefaultChain {
        exclude_credentials: input.exclude_credentials.clone(),
    })
}

fn acquire_managed_identity_token(
    client_id: Option<&str>,
    resource_id: Option<&str>,
) -> Result<String> {
    let endpoint = std::env::var("PSIGN_CODESIGNING_IMDS_ENDPOINT")
        .unwrap_or_else(|_| "http://169.254.169.254/metadata/identity/oauth2/token".to_string());
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let mut query = vec![
        ("api-version".to_string(), "2018-02-01".to_string()),
        ("resource".to_string(), MI_RESOURCE.to_string()),
    ];
    if let Some(client_id) = text_opt(client_id) {
        query.push(("client_id".to_string(), client_id));
    }
    if let Some(resource_id) = text_opt(resource_id) {
        query.push(("mi_res_id".to_string(), resource_id));
    }
    let rsp = http
        .get(endpoint)
        .query(&query)
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

fn acquire_client_credentials_token(
    authority: Option<&str>,
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String> {
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
        normalize_authority(authority)
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

fn acquire_workload_identity_token(
    authority: Option<&str>,
    tenant_id: &str,
    client_id: &str,
    federated_token_file: &str,
) -> Result<String> {
    let assertion = std::fs::read_to_string(federated_token_file)
        .with_context(|| format!("read federated token file {federated_token_file}"))?;
    let tenant = tenant_id.trim();
    let cid = client_id.trim();
    let assertion = assertion.trim();
    if tenant.is_empty() || cid.is_empty() || assertion.is_empty() {
        return Err(anyhow!(
            "workload identity requires non-empty tenant_id, client_id, and federated token file"
        ));
    }
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let token_url = format!(
        "{}/{tenant}/oauth2/v2.0/token",
        normalize_authority(authority)
    );
    let rsp = http
        .post(&token_url)
        .form(&[
            ("client_id", cid),
            ("client_assertion", assertion),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("grant_type", "client_credentials"),
            ("scope", DEFAULT_SCOPE),
        ])
        .send()
        .context("OAuth workload identity token request (codesigning.azure.net)")?;
    if !rsp.status().is_success() {
        return Err(anyhow!(
            "OAuth workload identity HTTP {}: {}",
            rsp.status(),
            rsp.text().unwrap_or_default()
        ));
    }
    #[derive(Deserialize)]
    struct TokenJson {
        access_token: String,
    }
    let j: TokenJson = rsp.json().context("OAuth workload identity JSON")?;
    Ok(j.access_token)
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
        CodesigningAuth::ManagedIdentity {
            client_id,
            resource_id,
        } => acquire_managed_identity_token(client_id.as_deref(), resource_id.as_deref()),
        CodesigningAuth::ClientCredentials {
            tenant_id,
            client_id,
            client_secret,
        } => acquire_client_credentials_token(
            params.authority.as_deref(),
            tenant_id,
            client_id,
            client_secret,
        ),
        CodesigningAuth::WorkloadIdentity {
            tenant_id,
            client_id,
            federated_token_file,
        } => acquire_workload_identity_token(
            params.authority.as_deref(),
            tenant_id,
            client_id,
            federated_token_file,
        ),
        CodesigningAuth::DefaultChain {
            exclude_credentials,
        } => {
            let mut errors = Vec::new();
            if !credential_excluded(
                exclude_credentials,
                &["EnvironmentCredential", "ClientSecretCredential"],
            ) && let (Some(tenant), Some(client), Some(secret)) = (
                env_text("AZURE_TENANT_ID"),
                env_text("AZURE_CLIENT_ID"),
                env_text("AZURE_CLIENT_SECRET"),
            ) {
                match acquire_client_credentials_token(
                    params.authority.as_deref(),
                    &tenant,
                    &client,
                    &secret,
                ) {
                    Ok(token) => return Ok(token),
                    Err(e) => errors.push(format!("EnvironmentCredential: {e:#}")),
                }
            }
            if !credential_excluded(exclude_credentials, &["WorkloadIdentityCredential"])
                && let (Some(tenant), Some(client), Some(token_file)) = (
                    env_text("AZURE_TENANT_ID"),
                    env_text("AZURE_CLIENT_ID"),
                    env_text("AZURE_FEDERATED_TOKEN_FILE"),
                )
            {
                match acquire_workload_identity_token(
                    params.authority.as_deref(),
                    &tenant,
                    &client,
                    &token_file,
                ) {
                    Ok(token) => return Ok(token),
                    Err(e) => errors.push(format!("WorkloadIdentityCredential: {e:#}")),
                }
            }
            if !credential_excluded(exclude_credentials, &["ManagedIdentityCredential"]) {
                let client_id = env_text("AZURE_MANAGED_IDENTITY_CLIENT_ID")
                    .or_else(|| env_text("AZURE_CLIENT_ID"));
                match acquire_managed_identity_token(client_id.as_deref(), None) {
                    Ok(token) => return Ok(token),
                    Err(e) => errors.push(format!("ManagedIdentityCredential: {e:#}")),
                }
            }
            if errors.is_empty() {
                Err(anyhow!(
                    "no Artifact Signing credential was available in the Rust default chain"
                ))
            } else {
                Err(anyhow!(
                    "Artifact Signing Rust default credential chain failed: {}",
                    errors.join("; ")
                ))
            }
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
        req = req
            .header("x-correlation-id", c)
            .header("x-ms-correlation-id", c);
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

    if !status.is_success() {
        return Err(anyhow!(
            ":sign HTTP {}: {}",
            status,
            String::from_utf8_lossy(&body_bytes)
        ));
    }
    let accept_json: Value = if body_bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body_bytes).context(":sign JSON")?
    };

    let poll_url = if let Some(loc) = op_location {
        operation_location_url(&base, &loc)
    } else if accept_json.get("status").and_then(Value::as_str) == Some("Succeeded") {
        return Ok(accept_json);
    } else if let Some(id) = accept_json
        .get("id")
        .or_else(|| accept_json.get("operationId"))
        .and_then(Value::as_str)
    {
        format!(
            "{base}/codesigningaccounts/{account}/certificateprofiles/{profile}/sign/{id}?api-version={api}",
        )
    } else {
        return Ok(accept_json);
    };

    debug(&format!("artifact-signing poll URL={poll_url}"));

    poll_operation(&http, &token, &poll_url)
}

fn sign_result_object(v: &Value) -> &Value {
    v.get("result").unwrap_or(v)
}

fn decode_standard_base64_field(obj: &Value, field: &str) -> Result<Vec<u8>> {
    let s = obj
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("codesign result missing {field}"))?;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .with_context(|| format!("decode codesign result {field}"))
}

pub fn codesign_signature_result_from_json(
    final_json: Value,
) -> Result<CodesigningSignatureResult> {
    let result = sign_result_object(&final_json);
    Ok(CodesigningSignatureResult {
        signature: decode_standard_base64_field(result, "signature")?,
        signing_certificate: decode_standard_base64_field(result, "signingCertificate")?,
        final_json,
    })
}

pub fn submit_codesign_hash_signature_blocking(
    params: &CodesigningSubmitParams,
    debug: impl Fn(&str),
) -> Result<CodesigningSignatureResult> {
    let final_json = submit_codesign_hash_blocking(params, debug)?;
    codesign_signature_result_from_json(final_json)
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

    #[test]
    fn resolver_accepts_user_assigned_managed_identity() {
        let auth = resolve_codesigning_auth(&CodesigningAuthInput {
            managed_identity: true,
            client_id: Some("client-id".into()),
            managed_identity_resource_id: Some("/subscriptions/s/resourceGroups/g/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id".into()),
            ..Default::default()
        })
        .unwrap();
        match auth {
            CodesigningAuth::ManagedIdentity {
                client_id,
                resource_id,
            } => {
                assert_eq!(client_id.as_deref(), Some("client-id"));
                assert_eq!(
                    resource_id.as_deref(),
                    Some(
                        "/subscriptions/s/resourceGroups/g/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id"
                    )
                );
            }
            other => panic!("unexpected auth: {other:?}"),
        }
    }

    #[test]
    fn resolver_accepts_workload_identity_inputs() {
        let auth = resolve_codesigning_auth(&CodesigningAuthInput {
            tenant_id: Some("tenant".into()),
            client_id: Some("client".into()),
            federated_token_file: Some("token.jwt".into()),
            credential_type: Some(CodesigningCredentialType::WorkloadIdentity),
            ..Default::default()
        })
        .unwrap();
        match auth {
            CodesigningAuth::WorkloadIdentity {
                tenant_id,
                client_id,
                federated_token_file,
            } => {
                assert_eq!(tenant_id, "tenant");
                assert_eq!(client_id, "client");
                assert_eq!(federated_token_file, "token.jwt");
            }
            other => panic!("unexpected auth: {other:?}"),
        }
    }

    #[test]
    fn resolver_keeps_metadata_excludes_on_default_chain() {
        let auth = resolve_codesigning_auth(&CodesigningAuthInput {
            exclude_credentials: vec![
                "EnvironmentCredential".into(),
                "ManagedIdentityCredential".into(),
            ],
            ..Default::default()
        })
        .unwrap();
        match auth {
            CodesigningAuth::DefaultChain {
                exclude_credentials,
            } => assert_eq!(
                exclude_credentials,
                vec!["EnvironmentCredential", "ManagedIdentityCredential"]
            ),
            other => panic!("unexpected auth: {other:?}"),
        }
    }

    #[test]
    fn resolver_rejects_mixed_explicit_credentials() {
        let err = resolve_codesigning_auth(&CodesigningAuthInput {
            access_token: Some("token".into()),
            tenant_id: Some("tenant".into()),
            client_id: Some("client".into()),
            client_secret: Some("secret".into()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("not multiple"), "{err}");
    }
}
