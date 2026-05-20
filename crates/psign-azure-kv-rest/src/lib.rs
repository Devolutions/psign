//! Azure Key Vault **REST** helpers: OAuth token, GET certificate (**`kid`** + **`cer`**), **`keys/sign`** POST.
//! Portable (`reqwest` + **rustls**); usable from Linux for digest signing (AzureSignTool-style remote step).

use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use serde::Deserialize;
use url::Url;
use x509_cert::der::Decode;

#[derive(Debug, Deserialize)]
pub struct KeyVaultCertificate {
    pub kid: String,
    pub cer: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KvPublicKeyKind {
    Rsa,
    Ec,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KvHashAlg {
    Sha256,
    Sha384,
    Sha512,
}

/// Authentication inputs (same modes as **`psign-tool`** Azure KV signing).
#[derive(Debug, Clone, Copy)]
pub struct KvAuthParams<'a> {
    pub access_token: Option<&'a str>,
    pub managed_identity: bool,
    pub tenant_id: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub client_secret: Option<&'a str>,
    pub authority: Option<&'a str>,
}

pub fn normalize_vault_base(url: &str) -> Result<String> {
    let u = url.trim();
    if u.is_empty() {
        return Err(anyhow!("Azure Key Vault URL must not be empty"));
    }
    Ok(u.trim_end_matches('/').to_string())
}

pub fn acquire_kv_access_token(params: &KvAuthParams<'_>) -> Result<String> {
    if let Some(tok) = params.access_token.map(str::trim) {
        if tok.is_empty() {
            return Err(anyhow!("access token must not be empty"));
        }
        return Ok(tok.to_string());
    }
    if params.managed_identity {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| anyhow!("HTTP client: {e}"))?;
        let rsp = client
            .get("http://169.254.169.254/metadata/identity/oauth2/token")
            .query(&[
                ("api-version", "2018-02-01"),
                ("resource", "https://vault.azure.net"),
            ])
            .header("Metadata", "true")
            .send()
            .context("managed identity token request (IMDS)")?;
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
        let j: MiJson = rsp.json().context("managed identity token JSON")?;
        return Ok(j.access_token);
    }

    let tenant = params
        .tenant_id
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("client credentials require tenant id"))?;
    let client_id = params
        .client_id
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("client credentials require client id"))?;
    let secret = params
        .client_secret
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("client credentials require client secret"))?;

    let authority = params
        .authority
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("https://login.microsoftonline.com");
    let token_url = format!("{authority}/{tenant}/oauth2/v2.0/token");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let rsp = client
        .post(&token_url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", secret),
            ("scope", "https://vault.azure.net/.default"),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .context("Azure AD token request")?;
    if !rsp.status().is_success() {
        return Err(anyhow!(
            "Azure AD token HTTP {}: {}",
            rsp.status(),
            rsp.text().unwrap_or_default()
        ));
    }
    #[derive(Deserialize)]
    struct TokenJson {
        access_token: String,
    }
    let j: TokenJson = rsp.json().context("Azure AD token JSON")?;
    Ok(j.access_token)
}

pub fn fetch_kv_certificate(
    http: &reqwest::blocking::Client,
    vault_base: &str,
    cert_name: &str,
    cert_version: Option<&str>,
    token: &str,
) -> Result<KeyVaultCertificate> {
    let base = normalize_vault_base(vault_base)?;
    let mut url = Url::parse(&base).map_err(|e| anyhow!("invalid vault URL: {e}"))?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("vault URL must be hierarchical https"))?
        .push("certificates")
        .push(cert_name.trim());
    if let Some(v) = cert_version.map(str::trim).filter(|s| !s.is_empty()) {
        url.path_segments_mut()
            .map_err(|_| anyhow!("vault URL cannot be a base"))?
            .push(v);
    }
    url.query_pairs_mut().append_pair("api-version", "7.4");

    let rsp = http
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .context("Key Vault GET certificate")?;
    if !rsp.status().is_success() {
        return Err(anyhow!(
            "Key Vault certificate HTTP {}: {}",
            rsp.status(),
            rsp.text().unwrap_or_default()
        ));
    }
    rsp.json().context("Key Vault certificate JSON")
}

/// Build **`…/keys/…/versions/…/sign`** URL from certificate **`kid`** (Key Vault returns full key version URL).
pub fn kv_sign_url_from_kid(kid: &str) -> Result<String> {
    let mut sign_url =
        Url::parse(kid.trim()).map_err(|e| anyhow!("invalid certificate kid URL: {e}"))?;
    sign_url
        .path_segments_mut()
        .map_err(|_| anyhow!("kid URL cannot be a base"))?
        .pop_if_empty()
        .push("sign");
    sign_url.query_pairs_mut().append_pair("api-version", "7.4");
    Ok(sign_url.to_string())
}

pub fn kv_decode_cer_b64(cer_b64: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(cer_b64.trim())
        .context("decode certificate cer (base64)")
}

pub fn kv_public_key_kind_from_cer_der(cer_der: &[u8]) -> Result<KvPublicKeyKind> {
    let cert = x509_cert::Certificate::from_der(cer_der)
        .map_err(|e| anyhow!("certificate DER (public key): {e}"))?;
    match cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string()
        .as_str()
    {
        "1.2.840.113549.1.1.1" => Ok(KvPublicKeyKind::Rsa),
        "1.2.840.10045.2.1" => Ok(KvPublicKeyKind::Ec),
        other => Err(anyhow!(
            "Key Vault signing is not implemented for certificate public key OID {other}"
        )),
    }
}

pub fn kv_jws_alg(kind: KvPublicKeyKind, hash: KvHashAlg) -> Result<String> {
    match kind {
        KvPublicKeyKind::Rsa => match hash {
            KvHashAlg::Sha256 => Ok("RS256".into()),
            KvHashAlg::Sha384 => Ok("RS384".into()),
            KvHashAlg::Sha512 => Ok("RS512".into()),
        },
        KvPublicKeyKind::Ec => match hash {
            KvHashAlg::Sha256 => Ok("ES256".into()),
            KvHashAlg::Sha384 => Ok("ES384".into()),
            KvHashAlg::Sha512 => Ok("ES512".into()),
        },
    }
}

#[derive(Deserialize)]
struct KeyVaultSignResponse {
    value: String,
}

pub fn kv_sign_digest(
    http: &reqwest::blocking::Client,
    token: &str,
    sign_url: &str,
    jws_alg: &str,
    digest: &[u8],
) -> Result<Vec<u8>> {
    let body = serde_json::json!({
        "alg": jws_alg,
        "value": base64::engine::general_purpose::STANDARD.encode(digest),
    });
    let rsp = http
        .post(sign_url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .context("Key Vault POST sign")?;
    if !rsp.status().is_success() {
        return Err(anyhow!(
            "Key Vault sign HTTP {}: {}",
            rsp.status(),
            rsp.text().unwrap_or_default()
        ));
    }
    let parsed: KeyVaultSignResponse = rsp.json().context("Key Vault sign JSON")?;
    base64::engine::general_purpose::STANDARD
        .decode(parsed.value.trim())
        .context("signature base64 decode")
}

/// Resolve **`kid`**, infer JWS alg from certificate **`cer`**, POST **`sign`**.
pub fn kv_sign_digest_from_certificate(
    http: &reqwest::blocking::Client,
    token: &str,
    cert: &KeyVaultCertificate,
    hash: KvHashAlg,
    digest: &[u8],
) -> Result<Vec<u8>> {
    let sign_url = kv_sign_url_from_kid(cert.kid.trim())?;
    let cer_der = base64::engine::general_purpose::STANDARD
        .decode(cert.cer.trim())
        .context("decode certificate cer (base64)")?;
    let kind = kv_public_key_kind_from_cer_der(&cer_der)?;
    let alg = kv_jws_alg(kind, hash)?;
    kv_sign_digest(http, token, &sign_url, &alg, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jws_alg_rsa_sha256() {
        assert_eq!(
            kv_jws_alg(KvPublicKeyKind::Rsa, KvHashAlg::Sha256).unwrap(),
            "RS256"
        );
    }

    #[test]
    fn jws_alg_ec_sha384() {
        assert_eq!(
            kv_jws_alg(KvPublicKeyKind::Ec, KvHashAlg::Sha384).unwrap(),
            "ES384"
        );
    }

    #[test]
    fn normalize_vault_base_rejects_empty() {
        assert!(normalize_vault_base("").is_err());
        assert!(normalize_vault_base("   ").is_err());
    }

    #[test]
    fn normalize_vault_base_trims_whitespace_and_trailing_slashes() {
        assert_eq!(
            normalize_vault_base("  https://ex.vault.azure.net/  ").unwrap(),
            "https://ex.vault.azure.net"
        );
    }

    #[test]
    fn normalize_vault_base_preserves_explicit_port() {
        assert_eq!(
            normalize_vault_base("https://kv-test.vault.azure.net:8443/").unwrap(),
            "https://kv-test.vault.azure.net:8443"
        );
    }

    #[test]
    fn kv_sign_url_from_kid_appends_sign_and_api_version() {
        let kid =
            "https://contoso.vault.azure.net/keys/mycert/versions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let u = kv_sign_url_from_kid(kid).unwrap();
        assert!(
            u.ends_with("/sign?api-version=7.4"),
            "unexpected sign URL: {u}"
        );
        assert!(u.contains("/keys/mycert/versions/"), "{u}");
    }

    #[test]
    fn kv_sign_url_from_kid_rejects_invalid_url() {
        assert!(kv_sign_url_from_kid("not-a-url").is_err());
    }

    #[test]
    fn jws_alg_rsa_sha384_sha512_and_ec_sha256_sha512() {
        assert_eq!(
            kv_jws_alg(KvPublicKeyKind::Rsa, KvHashAlg::Sha384).unwrap(),
            "RS384"
        );
        assert_eq!(
            kv_jws_alg(KvPublicKeyKind::Rsa, KvHashAlg::Sha512).unwrap(),
            "RS512"
        );
        assert_eq!(
            kv_jws_alg(KvPublicKeyKind::Ec, KvHashAlg::Sha256).unwrap(),
            "ES256"
        );
        assert_eq!(
            kv_jws_alg(KvPublicKeyKind::Ec, KvHashAlg::Sha512).unwrap(),
            "ES512"
        );
    }
}
