//! HTTP-level tests for Key Vault certificate GET + keys/sign POST (no real Azure).

use base64::Engine as _;
use mockito::{Matcher, Server};
use psign_azure_kv_rest::{KvHashAlg, fetch_kv_certificate, kv_sign_digest_from_certificate};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

#[test]
fn fetch_certificate_and_sign_digest_against_mock_kv() {
    let mut server = Server::new();
    let vault_base = server.url().trim_end_matches('/').to_string();

    // Default EC key (portable CI); RSA generation can fail where `ring` lacks RSA keygen.
    let ec_key = KeyPair::generate().expect("ec key");
    let mut params = CertificateParams::new(vec!["kv-mock.test".into()]).expect("params");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "KV mock leaf");
    let leaf = params.self_signed(&ec_key).expect("self-signed");
    let cer_b64 = base64::engine::general_purpose::STANDARD.encode(leaf.der());

    let kid = format!("{vault_base}/keys/mykey/versions/v1");

    let _m_cert = server
        .mock(
            "GET",
            Matcher::Regex(r"/certificates/my-cert(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            serde_json::json!({
                "kid": kid,
                "cer": cer_b64,
            })
            .to_string(),
        )
        .create();

    let sig_bytes = vec![0xdeu8, 0xad, 0xbe, 0xef];
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

    let _m_sign = server
        .mock(
            "POST",
            Matcher::Regex(r"/keys/mykey/versions/v1/sign(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::json!({ "value": sig_b64 }).to_string())
        .create();

    let http = reqwest::blocking::Client::new();
    let token = "test-bearer-token";
    let cert_meta =
        fetch_kv_certificate(&http, &vault_base, "my-cert", None, token).expect("GET cert");
    assert_eq!(cert_meta.kid, kid);

    let digest = [0xabu8; 32];
    let out = kv_sign_digest_from_certificate(&http, token, &cert_meta, KvHashAlg::Sha256, &digest)
        .expect("POST sign");
    assert_eq!(out, sig_bytes);

    _m_cert.assert();
    _m_sign.assert();
}
