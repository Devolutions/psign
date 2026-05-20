//! Mock Azure Code Signing `:sign` POST + LRO GET (no real `codesigning.azure.net`).

use base64::Engine as _;
use mockito::{Matcher, Server};
use psign_codesigning_rest::{
    CodesigningAuth, CodesigningSubmitParams, submit_codesign_hash_blocking,
};
use serde_json::json;

#[test]
fn submit_poll_via_operation_location_header() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/abc123");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/theacct/certificateprofiles/theprof:sign(\?.*)?$"
                    .to_string(),
            ),
        )
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/abc123(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded","signature":"mock-sig-field"}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused-for-mock".into(),
        account_name: "theacct".into(),
        profile_name: "theprof".into(),
        digest: vec![0x01, 0x02, 0x03],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("fake-token".into()),
        endpoint_base_url: Some(base),
    };

    let out = submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    assert_eq!(
        out.get("status").and_then(|v| v.as_str()),
        Some("Succeeded")
    );
    assert_eq!(
        out.get("signature").and_then(|v| v.as_str()),
        Some("mock-sig-field")
    );

    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_poll_via_accept_body_id_field() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/acct/certificateprofiles/prof:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"job-from-body"}"#)
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(
                r"/codesigningaccounts/acct/certificateprofiles/prof/sign/job-from-body(\?.*)?$"
                    .to_string(),
            ),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded","done":true}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused-for-mock".into(),
        account_name: "acct".into(),
        profile_name: "prof".into(),
        digest: vec![0xff],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let out = submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    assert_eq!(
        out.get("status").and_then(|v| v.as_str()),
        Some("Succeeded")
    );
    assert_eq!(out.get("done").and_then(|v| v.as_bool()), Some(true));

    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_sign_post_body_base64_digest_and_signature_algorithm() {
    let digest: Vec<u8> = (0u8..32).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&digest);

    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/body-check");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/acct2/certificateprofiles/prof2:sign(\?.*)?$".to_string(),
            ),
        )
        .match_body(Matcher::PartialJson(json!({
            "signatureAlgorithm": "ES256",
            "digest": b64,
        })))
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/body-check(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded"}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "acct2".into(),
        profile_name: "prof2".into(),
        digest,
        signature_algorithm: "ES256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_sign_sends_x_ms_correlation_id_when_set() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/corr");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/c/certificateprofiles/p:sign(\?.*)?$".to_string(),
            ),
        )
        .match_header("x-ms-correlation-id", "trace-abc-123")
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/corr(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded"}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "c".into(),
        profile_name: "p".into(),
        digest: vec![1, 2, 3],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: Some("  trace-abc-123  ".into()),
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_poll_failed_status_returns_error() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/fail1");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/f/certificateprofiles/g:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/fail1(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Failed","error":{"code":"bad"}}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "f".into(),
        profile_name: "g".into(),
        digest: vec![9],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let err = submit_codesign_hash_blocking(&params, |_| {}).unwrap_err();
    assert!(
        err.to_string().contains("codesign operation failed"),
        "{err}"
    );
    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_sign_post_trims_signature_algorithm_in_json_body() {
    let digest = vec![0xabu8; 32];
    let b64 = base64::engine::general_purpose::STANDARD.encode(&digest);

    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/trim-alg");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/trim/certificateprofiles/alg:sign(\?.*)?$".to_string(),
            ),
        )
        .match_body(Matcher::PartialJson(json!({
            "signatureAlgorithm": "RS256",
            "digest": b64,
        })))
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/trim-alg(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded"}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "trim".into(),
        profile_name: "alg".into(),
        digest,
        signature_algorithm: "  RS256  \t".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_poll_canceled_status_returns_error() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/canceled-op");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/can/certificateprofiles/celed:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/canceled-op(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Canceled"}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "can".into(),
        profile_name: "celed".into(),
        digest: vec![8],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let err = submit_codesign_hash_blocking(&params, |_| {}).unwrap_err();
    assert!(
        err.to_string().contains("codesign operation canceled"),
        "{err}"
    );
    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_sign_non_success_http_includes_status_and_body() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/bad/certificateprofiles/http:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"nope"}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "bad".into(),
        profile_name: "http".into(),
        digest: vec![1],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let err = submit_codesign_hash_blocking(&params, |_| {}).unwrap_err();
    let s = err.to_string();
    assert!(s.contains(":sign HTTP"), "{s}");
    assert!(s.contains("403"), "{s}");
    assert!(s.contains("nope"), "{s}");
    post_mock.assert();
}

/// **`Operation-Location`** and synchronous **`id`** absent: return **`POST`** JSON as-is (no polling).
#[test]
fn submit_sign_success_without_lro_returns_post_body() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/sync/certificateprofiles/now:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded","inline":true}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "sync".into(),
        profile_name: "now".into(),
        digest: vec![2],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let out = submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    assert_eq!(
        out.get("status").and_then(|v| v.as_str()),
        Some("Succeeded")
    );
    assert_eq!(out.get("inline").and_then(|v| v.as_bool()), Some(true));
    post_mock.assert();
}

#[test]
fn submit_poll_non_success_http_returns_error() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/poll-503");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/poll/certificateprofiles/http500:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/poll-503(\?.*)?$".to_string()),
        )
        .with_status(503)
        .with_body("upstream unavailable")
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "poll".into(),
        profile_name: "http500".into(),
        digest: vec![3],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let err = submit_codesign_hash_blocking(&params, |_| {}).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("poll HTTP"), "{s}");
    assert!(s.contains("503"), "{s}");
    assert!(s.contains("upstream unavailable"), "{s}");
    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_poll_non_json_success_body_returns_error() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/poll-plain");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/plain/certificateprofiles/badjson:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/poll-plain(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "text/plain")
        .with_body("not-json")
        .create();

    let params = CodesigningSubmitParams {
        region: "unused".into(),
        account_name: "plain".into(),
        profile_name: "badjson".into(),
        digest: vec![4],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let err = submit_codesign_hash_blocking(&params, |_| {}).unwrap_err();
    assert!(
        err.to_string().contains("poll JSON"),
        "expected JSON parse context: {err}"
    );
    post_mock.assert();
    poll_mock.assert();
}
