//! Explicit online certificate retrieval for portable trust verification.

use crate::policy::{OnlineTrustOptions, RevocationMode};
use anyhow::{Context, Result, anyhow};
use der::{Decode, Encode, SliceReader};
use digest::Digest;
use picky::x509::certificate::Cert;
use picky::x509::date::UtcDate;
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::TcpStream;
use x509_cert::Certificate;
use x509_cert::time::Time;

const AIA_OID: &str = "1.3.6.1.5.5.7.1.1";
const CRL_DISTRIBUTION_POINTS_OID: &str = "2.5.29.31";
const CA_ISSUERS_OID_DER: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
const OCSP_OID_DER: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
const OCSP_BASIC_OID_DER: &[u8] = &[
    0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
];
const SHA1_ALGORITHM_IDENTIFIER_DER: &[u8] = &[
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
];
const SHA256_WITH_RSA_ENCRYPTION_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];

pub fn issuer_candidates_from_aia(cert: &Cert, options: &OnlineTrustOptions) -> Result<Vec<Cert>> {
    if !options.enable_aia && options.aia_url_override.is_none() {
        return Ok(Vec::new());
    }

    let mut urls = Vec::new();
    if let Some(url) = &options.aia_url_override {
        urls.push(url.clone());
    }
    if options.enable_aia {
        urls.extend(aia_ca_issuers_urls(cert)?);
    }

    let mut out = Vec::new();
    for url in urls {
        let bytes = http_get_limited(&url, options)
            .with_context(|| format!("fetch AIA issuer certificate from {url}"))?;
        out.push(parse_cert_bytes(&bytes).with_context(|| format!("parse AIA issuer {url}"))?);
    }
    Ok(out)
}

pub fn aia_ca_issuers_urls(cert: &Cert) -> Result<Vec<String>> {
    let der = cert
        .to_der()
        .map_err(|e| anyhow!("certificate DER encode failed: {e}"))?;
    let cert =
        Certificate::from_der(&der).map_err(|e| anyhow!("certificate DER parse failed: {e}"))?;
    let Some(exts) = cert.tbs_certificate.extensions else {
        return Ok(Vec::new());
    };

    let mut urls = Vec::new();
    for ext in exts.iter().filter(|e| e.extn_id.to_string() == AIA_OID) {
        urls.extend(parse_aia_ca_issuers(ext.extn_value.as_bytes())?);
    }
    Ok(urls)
}

fn parse_cert_bytes(raw: &[u8]) -> Result<Cert> {
    let trimmed = raw.trim_ascii_start();
    if trimmed.starts_with(b"-----BEGIN ") {
        let s = std::str::from_utf8(trimmed).map_err(|e| anyhow!("PEM is not UTF-8: {e}"))?;
        Cert::from_pem_str(s).map_err(|e| anyhow!("PEM parse failed: {e}"))
    } else {
        Cert::from_der(trimmed).map_err(|e| anyhow!("DER parse failed: {e}"))
    }
}

pub fn check_revocation_chain(
    leaf: &Cert,
    chain: &[Cert],
    options: &OnlineTrustOptions,
) -> Result<()> {
    if options.revocation_mode == RevocationMode::Off {
        return Ok(());
    }

    let mut subjects = Vec::with_capacity(chain.len() + 1);
    subjects.push(leaf.clone());
    subjects.extend(chain.iter().cloned());

    for (idx, cert) in subjects.iter().enumerate() {
        let Some(issuer) = subjects.get(idx + 1) else {
            break;
        };
        match check_one_cert_ocsp(cert, issuer, options) {
            Ok(OcspCheckOutcome::Good) => continue,
            Ok(OcspCheckOutcome::NotConfigured) => {}
            Ok(OcspCheckOutcome::Unknown)
                if options.revocation_mode == RevocationMode::BestEffort => {}
            Ok(OcspCheckOutcome::Unknown) => return Err(anyhow!("OCSP status is unknown")),
            Ok(OcspCheckOutcome::Revoked) => return Err(anyhow!("OCSP status is revoked")),
            Err(_) if options.revocation_mode == RevocationMode::BestEffort => {}
            Err(e) => return Err(e),
        }
        match check_one_cert_crl(cert, issuer, options) {
            Ok(()) => {}
            Err(e) if options.revocation_mode == RevocationMode::BestEffort => {
                if e.to_string().contains("revoked") {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OcspCheckOutcome {
    NotConfigured,
    Good,
    Revoked,
    Unknown,
}

fn check_one_cert_ocsp(
    cert: &Cert,
    issuer: &Cert,
    options: &OnlineTrustOptions,
) -> Result<OcspCheckOutcome> {
    if !options.enable_ocsp && options.ocsp_url_override.is_none() {
        return Ok(OcspCheckOutcome::NotConfigured);
    }
    let url = options
        .ocsp_url_override
        .clone()
        .or_else(|| ocsp_urls(cert).ok()?.into_iter().next())
        .ok_or_else(|| {
            anyhow!("OCSP checking requires --ocsp-url-override or a certificate AIA OCSP HTTP URL")
        })?;
    let request = build_ocsp_request_der(cert, issuer)?;
    let response = http_post_limited(
        &url,
        "application/ocsp-request",
        "application/ocsp-response",
        &request,
        options,
    )
    .with_context(|| format!("POST OCSP request to {url}"))?;
    let parsed = parse_ocsp_response_der(&response)
        .with_context(|| format!("parse OCSP response from {url}"))?;
    verify_rsa_sha256_signature(
        &parsed.tbs_response_data_tlv,
        &parsed.signature,
        issuer,
        "OCSP",
    )?;
    let cert_id = build_ocsp_cert_id_der(cert, issuer)?;
    let entry = ocsp_response_for_cert_id(&parsed, &cert_id)?;
    ensure_time_window_fresh(
        "OCSP SingleResponse",
        &entry.this_update,
        Some(&entry.next_update),
    )?;
    Ok(entry.status)
}

fn ocsp_response_for_cert_id<'a>(
    parsed: &'a ParsedOcspResponse,
    cert_id_tlv: &[u8],
) -> Result<&'a ParsedOcspSingleResponse> {
    parsed
        .responses
        .iter()
        .find(|entry| entry.cert_id_tlv == cert_id_tlv)
        .ok_or_else(|| anyhow!("OCSP response does not contain the requested certificate ID"))
}

fn check_one_cert_crl(cert: &Cert, issuer: &Cert, options: &OnlineTrustOptions) -> Result<()> {
    let url = options
        .crl_url_override
        .clone()
        .or_else(|| crl_distribution_point_urls(cert).ok()?.into_iter().next())
        .ok_or_else(|| anyhow!("revocation checking requires --crl-url-override or a certificate CRL distribution point HTTP URL"))?;
    let crl_bytes =
        http_get_limited(&url, options).with_context(|| format!("fetch CRL from {url}"))?;
    let crl =
        parse_certificate_list_der(&crl_bytes).with_context(|| format!("parse CRL from {url}"))?;
    verify_crl_signature(&crl, issuer)?;
    ensure_time_window_fresh("CRL", &crl.this_update, Some(&crl.next_update))?;
    let cert_serial = cert_serial_tlv(cert)?;
    if crl.revoked_serial_tlvs.iter().any(|s| s == &cert_serial) {
        return Err(anyhow!("certificate is revoked by CRL {url}"));
    }
    Ok(())
}

pub fn crl_distribution_point_urls(cert: &Cert) -> Result<Vec<String>> {
    let der = cert
        .to_der()
        .map_err(|e| anyhow!("certificate DER encode failed: {e}"))?;
    let cert =
        Certificate::from_der(&der).map_err(|e| anyhow!("certificate DER parse failed: {e}"))?;
    let Some(exts) = cert.tbs_certificate.extensions else {
        return Ok(Vec::new());
    };

    let mut urls = Vec::new();
    for ext in exts
        .iter()
        .filter(|e| e.extn_id.to_string() == CRL_DISTRIBUTION_POINTS_OID)
    {
        urls.extend(parse_http_uri_general_names(ext.extn_value.as_bytes())?);
    }
    Ok(urls)
}

pub fn ocsp_urls(cert: &Cert) -> Result<Vec<String>> {
    let der = cert
        .to_der()
        .map_err(|e| anyhow!("certificate DER encode failed: {e}"))?;
    let cert =
        Certificate::from_der(&der).map_err(|e| anyhow!("certificate DER parse failed: {e}"))?;
    let Some(exts) = cert.tbs_certificate.extensions else {
        return Ok(Vec::new());
    };

    let mut urls = Vec::new();
    for ext in exts.iter().filter(|e| e.extn_id.to_string() == AIA_OID) {
        urls.extend(parse_aia_ocsp(ext.extn_value.as_bytes())?);
    }
    Ok(urls)
}

struct ParsedOcspResponse {
    tbs_response_data_tlv: Vec<u8>,
    signature: Vec<u8>,
    responses: Vec<ParsedOcspSingleResponse>,
}

struct ParsedOcspSingleResponse {
    cert_id_tlv: Vec<u8>,
    status: OcspCheckOutcome,
    this_update: UtcDate,
    next_update: UtcDate,
}

fn parse_ocsp_response_der(input: &[u8]) -> Result<ParsedOcspResponse> {
    let outer = expect_tlv(input, 0x30).context("OCSPResponse")?;
    let mut pos = 0usize;
    let status = expect_tlv(read_tlv(outer, &mut pos)?, 0x0a).context("OCSPResponseStatus")?;
    if status != [0] {
        return Err(anyhow!("OCSP responder returned non-success status"));
    }
    let response_bytes = expect_tlv(read_tlv(outer, &mut pos)?, 0xa0).context("responseBytes")?;
    let rb = expect_tlv(response_bytes, 0x30).context("ResponseBytes")?;
    let mut rb_pos = 0usize;
    let response_type = read_tlv(rb, &mut rb_pos).context("ResponseBytes.responseType")?;
    if response_type != OCSP_BASIC_OID_DER {
        return Err(anyhow!("unsupported OCSP response type"));
    }
    let basic_octets = expect_tlv(
        read_tlv(rb, &mut rb_pos).context("ResponseBytes.response")?,
        0x04,
    )
    .context("ResponseBytes.response OCTET STRING")?;
    parse_basic_ocsp_response_der(basic_octets)
}

fn parse_basic_ocsp_response_der(input: &[u8]) -> Result<ParsedOcspResponse> {
    let outer = expect_tlv(input, 0x30).context("BasicOCSPResponse")?;
    let mut pos = 0usize;
    let tbs_response_data_tlv = read_tlv(outer, &mut pos)
        .context("BasicOCSPResponse.tbsResponseData")?
        .to_vec();
    let sig_alg = read_tlv(outer, &mut pos).context("BasicOCSPResponse.signatureAlgorithm")?;
    if sig_alg != SHA256_WITH_RSA_ENCRYPTION_DER {
        return Err(anyhow!("unsupported OCSP signature algorithm"));
    }
    let signature_body = expect_tlv(
        read_tlv(outer, &mut pos).context("BasicOCSPResponse.signature")?,
        0x03,
    )
    .context("OCSP signature BIT STRING")?;
    if signature_body.first().copied() != Some(0) {
        return Err(anyhow!("OCSP signature BIT STRING has unused bits"));
    }

    let tbs = expect_tlv(&tbs_response_data_tlv, 0x30).context("ResponseData")?;
    let mut tbs_pos = 0usize;
    if tbs.get(tbs_pos).copied() == Some(0xa0) {
        read_tlv(tbs, &mut tbs_pos).context("ResponseData.version")?;
    }
    read_tlv(tbs, &mut tbs_pos).context("ResponseData.responderID")?;
    read_tlv(tbs, &mut tbs_pos).context("ResponseData.producedAt")?;
    let responses =
        expect_tlv(read_tlv(tbs, &mut tbs_pos)?, 0x30).context("ResponseData.responses")?;
    let mut responses_pos = 0usize;
    let mut parsed_responses = Vec::new();
    while responses_pos < responses.len() {
        let single =
            expect_tlv(read_tlv(responses, &mut responses_pos)?, 0x30).context("SingleResponse")?;
        let mut single_pos = 0usize;
        let cert_id_tlv = read_tlv(single, &mut single_pos)
            .context("SingleResponse.certID")?
            .to_vec();
        expect_tlv(&cert_id_tlv, 0x30).context("CertID")?;
        let cert_status = read_tlv(single, &mut single_pos).context("SingleResponse.certStatus")?;
        let status = match cert_status.first().copied() {
            Some(0x80) => OcspCheckOutcome::Good,
            Some(0xa1) => OcspCheckOutcome::Revoked,
            Some(0x82) => OcspCheckOutcome::Unknown,
            Some(tag) => return Err(anyhow!("unsupported OCSP CertStatus tag 0x{tag:02x}")),
            None => return Err(anyhow!("missing OCSP CertStatus")),
        };
        let this_update = parse_der_time_tlv(
            read_tlv(single, &mut single_pos).context("SingleResponse.thisUpdate")?,
        )
        .context("SingleResponse.thisUpdate")?;
        let next_update_tlv = read_tlv(single, &mut single_pos)
            .context("SingleResponse.nextUpdate is required for revocation freshness")?;
        if next_update_tlv.first().copied() != Some(0xa0) {
            return Err(anyhow!("SingleResponse.nextUpdate is required"));
        }
        let next_update_inner =
            expect_tlv(next_update_tlv, 0xa0).context("SingleResponse.nextUpdate")?;
        let mut next_pos = 0usize;
        let next_update = parse_der_time_tlv(
            read_tlv(next_update_inner, &mut next_pos).context("nextUpdate time")?,
        )
        .context("SingleResponse.nextUpdate")?;
        if next_pos != next_update_inner.len() {
            return Err(anyhow!("SingleResponse.nextUpdate has trailing fields"));
        }
        parsed_responses.push(ParsedOcspSingleResponse {
            cert_id_tlv,
            status,
            this_update,
            next_update,
        });
    }

    Ok(ParsedOcspResponse {
        tbs_response_data_tlv,
        signature: signature_body[1..].to_vec(),
        responses: parsed_responses,
    })
}

struct ParsedCrl {
    tbs_tlv: Vec<u8>,
    signature_algorithm_tlv: Vec<u8>,
    signature: Vec<u8>,
    this_update: UtcDate,
    next_update: UtcDate,
    revoked_serial_tlvs: Vec<Vec<u8>>,
}

fn parse_certificate_list_der(input: &[u8]) -> Result<ParsedCrl> {
    let outer = expect_tlv(input, 0x30).context("CertificateList")?;
    let mut pos = 0usize;
    let tbs_tlv = read_tlv(outer, &mut pos)
        .context("CertificateList.tbsCertList")?
        .to_vec();
    let signature_algorithm_tlv = read_tlv(outer, &mut pos)
        .context("CertificateList.signatureAlgorithm")?
        .to_vec();
    let signature_tlv = read_tlv(outer, &mut pos).context("CertificateList.signatureValue")?;
    if pos != outer.len() {
        return Err(anyhow!("CertificateList has trailing fields"));
    }
    if signature_algorithm_tlv != SHA256_WITH_RSA_ENCRYPTION_DER {
        return Err(anyhow!("unsupported CRL signature algorithm"));
    }
    let signature_body = expect_tlv(signature_tlv, 0x03).context("CRL signature BIT STRING")?;
    if signature_body.first().copied() != Some(0) {
        return Err(anyhow!("CRL signature BIT STRING has unused bits"));
    }

    let tbs = expect_tlv(&tbs_tlv, 0x30).context("TBSCertList")?;
    let mut tbs_pos = 0usize;
    if tbs.get(tbs_pos).copied() == Some(0x02) {
        read_tlv(tbs, &mut tbs_pos).context("TBSCertList.version")?;
    }
    read_tlv(tbs, &mut tbs_pos).context("TBSCertList.signature")?;
    read_tlv(tbs, &mut tbs_pos).context("TBSCertList.issuer")?;
    let this_update =
        parse_der_time_tlv(read_tlv(tbs, &mut tbs_pos).context("TBSCertList.thisUpdate")?)
            .context("TBSCertList.thisUpdate")?;
    let next_update = if matches!(tbs.get(tbs_pos).copied(), Some(0x17 | 0x18)) {
        parse_der_time_tlv(read_tlv(tbs, &mut tbs_pos).context("TBSCertList.nextUpdate")?)
            .context("TBSCertList.nextUpdate")?
    } else {
        return Err(anyhow!(
            "TBSCertList.nextUpdate is required for revocation freshness"
        ));
    };

    let mut revoked_serial_tlvs = Vec::new();
    if tbs.get(tbs_pos).copied() == Some(0x30) {
        let revoked = expect_tlv(read_tlv(tbs, &mut tbs_pos)?, 0x30)
            .context("TBSCertList.revokedCertificates")?;
        let mut rpos = 0usize;
        while rpos < revoked.len() {
            let entry =
                expect_tlv(read_tlv(revoked, &mut rpos)?, 0x30).context("RevokedCertificate")?;
            let mut epos = 0usize;
            revoked_serial_tlvs.push(
                read_tlv(entry, &mut epos)
                    .context("RevokedCertificate.userCertificate")?
                    .to_vec(),
            );
        }
    }

    Ok(ParsedCrl {
        tbs_tlv,
        signature_algorithm_tlv,
        signature: signature_body[1..].to_vec(),
        this_update,
        next_update,
        revoked_serial_tlvs,
    })
}

fn verify_crl_signature(crl: &ParsedCrl, issuer: &Cert) -> Result<()> {
    if crl.signature_algorithm_tlv != SHA256_WITH_RSA_ENCRYPTION_DER {
        return Err(anyhow!("unsupported CRL signature algorithm"));
    }
    verify_rsa_sha256_signature(&crl.tbs_tlv, &crl.signature, issuer, "CRL")
}

fn verify_rsa_sha256_signature(
    signed_tlv: &[u8],
    signature: &[u8],
    issuer: &Cert,
    label: &str,
) -> Result<()> {
    let issuer_der = issuer
        .to_der()
        .map_err(|e| anyhow!("{label} issuer certificate DER encode failed: {e}"))?;
    let issuer = Certificate::from_der(&issuer_der)
        .map_err(|e| anyhow!("{label} issuer certificate DER parse failed: {e}"))?;
    let spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| anyhow!("{label} issuer SPKI DER encode failed: {e}"))?;
    let public_key = rsa::RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| anyhow!("{label} issuer RSA public key parse failed: {e}"))?;
    let signature = RsaPkcs1v15Signature::try_from(signature)
        .map_err(|e| anyhow!("{label} RSA signature parse failed: {e}"))?;
    VerifyingKey::<Sha256>::new(public_key)
        .verify(signed_tlv, &signature)
        .map_err(|e| anyhow!("{label} signature verification failed: {e}"))
}

fn cert_serial_tlv(cert: &Cert) -> Result<Vec<u8>> {
    let der = cert
        .to_der()
        .map_err(|e| anyhow!("certificate DER encode failed: {e}"))?;
    let cert =
        Certificate::from_der(&der).map_err(|e| anyhow!("certificate DER parse failed: {e}"))?;
    cert.tbs_certificate
        .serial_number
        .to_der()
        .map_err(|e| anyhow!("certificate serial DER encode failed: {e}"))
}

fn parse_der_time_tlv(tlv: &[u8]) -> Result<UtcDate> {
    let time = Time::decode(&mut SliceReader::new(tlv).map_err(|e| anyhow!("time reader: {e}"))?)
        .map_err(|e| anyhow!("DER time decode failed: {e}"))?;
    let secs = i64::try_from(time.to_unix_duration().as_secs())
        .map_err(|e| anyhow!("DER time conversion failed: {e}"))?;
    let odt = time::OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| anyhow!("DER time unix timestamp failed: {e}"))?;
    Ok(UtcDate::from(odt))
}

fn ensure_time_window_fresh(
    label: &str,
    this_update: &UtcDate,
    next_update: Option<&UtcDate>,
) -> Result<()> {
    let now = UtcDate::now();
    if utc_date_key(this_update) > utc_date_key(&now) {
        return Err(anyhow!("{label} thisUpdate is in the future"));
    }
    let Some(next_update) = next_update else {
        return Err(anyhow!(
            "{label} nextUpdate is required for revocation freshness"
        ));
    };
    if utc_date_key(next_update) < utc_date_key(&now) {
        return Err(anyhow!("{label} nextUpdate is stale"));
    }
    Ok(())
}

fn utc_date_key(d: &UtcDate) -> (u16, u8, u8) {
    (d.year(), d.month(), d.day())
}

fn parse_aia_ca_issuers(input: &[u8]) -> Result<Vec<String>> {
    let outer = expect_tlv(input, 0x30).context("AuthorityInfoAccessSyntax")?;
    let mut pos = 0usize;
    let mut urls = Vec::new();
    while pos < outer.len() {
        let ad = expect_tlv(read_tlv(outer, &mut pos)?, 0x30).context("AccessDescription")?;
        let mut ad_pos = 0usize;
        let method = read_tlv(ad, &mut ad_pos).context("AccessDescription.accessMethod")?;
        let location = read_tlv(ad, &mut ad_pos).context("AccessDescription.accessLocation")?;
        if ad_pos != ad.len() {
            return Err(anyhow!("AccessDescription has trailing fields"));
        }
        if method == CA_ISSUERS_OID_DER && location.first().copied() == Some(0x86) {
            let body = expect_tlv(location, 0x86).context("uniformResourceIdentifier")?;
            urls.push(
                std::str::from_utf8(body)
                    .map_err(|e| anyhow!("AIA URL is not UTF-8: {e}"))?
                    .to_string(),
            );
        }
    }
    Ok(urls)
}

fn parse_aia_ocsp(input: &[u8]) -> Result<Vec<String>> {
    let outer = expect_tlv(input, 0x30).context("AuthorityInfoAccessSyntax")?;
    let mut pos = 0usize;
    let mut urls = Vec::new();
    while pos < outer.len() {
        let ad = expect_tlv(read_tlv(outer, &mut pos)?, 0x30).context("AccessDescription")?;
        let mut ad_pos = 0usize;
        let method = read_tlv(ad, &mut ad_pos).context("AccessDescription.accessMethod")?;
        let location = read_tlv(ad, &mut ad_pos).context("AccessDescription.accessLocation")?;
        if method == OCSP_OID_DER && location.first().copied() == Some(0x86) {
            let body = expect_tlv(location, 0x86).context("uniformResourceIdentifier")?;
            let uri =
                std::str::from_utf8(body).map_err(|e| anyhow!("AIA OCSP URL is not UTF-8: {e}"))?;
            if uri.starts_with("http://") {
                urls.push(uri.to_string());
            }
        }
    }
    Ok(urls)
}

fn build_ocsp_request_der(cert: &Cert, issuer: &Cert) -> Result<Vec<u8>> {
    let cert_id = build_ocsp_cert_id_der(cert, issuer)?;
    let mut request = Vec::new();
    push_der_sequence(&mut request, &cert_id);
    let mut request_list = Vec::new();
    push_der_sequence(&mut request_list, &request);
    let mut tbs_request = Vec::new();
    push_der_sequence(&mut tbs_request, &request_list);
    let mut ocsp_request = Vec::new();
    push_der_sequence(&mut ocsp_request, &tbs_request);
    Ok(ocsp_request)
}

fn build_ocsp_cert_id_der(cert: &Cert, issuer: &Cert) -> Result<Vec<u8>> {
    let cert_der = cert
        .to_der()
        .map_err(|e| anyhow!("certificate DER encode failed: {e}"))?;
    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| anyhow!("certificate DER parse failed: {e}"))?;
    let issuer_der = issuer
        .to_der()
        .map_err(|e| anyhow!("issuer certificate DER encode failed: {e}"))?;
    let issuer = Certificate::from_der(&issuer_der)
        .map_err(|e| anyhow!("issuer certificate DER parse failed: {e}"))?;
    let issuer_name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| anyhow!("issuer Name DER encode failed: {e}"))?;
    let issuer_key_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let mut cert_id_body = Vec::new();
    cert_id_body.extend_from_slice(SHA1_ALGORITHM_IDENTIFIER_DER);
    push_der_tlv(
        &mut cert_id_body,
        0x04,
        &sha1::Sha1::digest(&issuer_name_der),
    );
    push_der_tlv(
        &mut cert_id_body,
        0x04,
        &sha1::Sha1::digest(issuer_key_bytes),
    );
    cert_id_body.extend_from_slice(
        &cert
            .tbs_certificate
            .serial_number
            .to_der()
            .map_err(|e| anyhow!("certificate serial DER encode failed: {e}"))?,
    );
    let mut cert_id = Vec::new();
    push_der_sequence(&mut cert_id, &cert_id_body);
    Ok(cert_id)
}

fn parse_http_uri_general_names(input: &[u8]) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    let mut pos = 0usize;
    while pos < input.len() {
        if input[pos] == 0x86 {
            let (body_start, len) = read_len(input, pos + 1)?;
            let end = body_start
                .checked_add(len)
                .ok_or_else(|| anyhow!("URI length overflow"))?;
            if end <= input.len() {
                let uri = std::str::from_utf8(&input[body_start..end])
                    .map_err(|e| anyhow!("URI is not UTF-8: {e}"))?;
                if uri.starts_with("http://") {
                    urls.push(uri.to_string());
                }
                pos = end;
                continue;
            }
        }
        pos += 1;
    }
    Ok(urls)
}

fn http_get_limited(url: &str, options: &OnlineTrustOptions) -> Result<Vec<u8>> {
    http_request_limited(url, "GET", None, options)
}

fn http_post_limited(
    url: &str,
    content_type: &str,
    accept: &str,
    body: &[u8],
    options: &OnlineTrustOptions,
) -> Result<Vec<u8>> {
    http_request_limited(url, "POST", Some((content_type, accept, body)), options)
}

fn http_request_limited(
    url: &str,
    method: &str,
    body: Option<(&str, &str, &[u8])>,
    options: &OnlineTrustOptions,
) -> Result<Vec<u8>> {
    let without_scheme = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("only http:// AIA URLs are supported by portable online trust"))?;
    let (authority, path) = without_scheme
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((without_scheme, "/".to_string()));
    let (host, port) = authority
        .rsplit_once(':')
        .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
        .unwrap_or((authority, 80));
    if host.is_empty() {
        return Err(anyhow!("AIA URL host is empty"));
    }

    let mut stream =
        TcpStream::connect((host, port)).with_context(|| format!("connect {host}:{port}"))?;
    stream
        .set_read_timeout(Some(options.timeout))
        .context("set AIA read timeout")?;
    stream
        .set_write_timeout(Some(options.timeout))
        .context("set AIA write timeout")?;
    match body {
        Some((content_type, accept, body)) => {
            write!(
                stream,
                "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Type: {content_type}\r\nAccept: {accept}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .context("write online HTTP request headers")?;
            stream
                .write_all(body)
                .context("write online HTTP request body")?;
        }
        None => {
            write!(
                stream,
                "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/pkix-cert, application/octet-stream, */*\r\n\r\n"
            )
            .context("write online HTTP request")?;
        }
    }

    let mut response = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = stream.read(&mut tmp).context("read AIA HTTP response")?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&tmp[..n]);
        if response.len() > options.max_download_bytes + 64 * 1024 {
            return Err(anyhow!("AIA HTTP response exceeds configured size limit"));
        }
    }

    let header_end = find_header_end(&response)
        .ok_or_else(|| anyhow!("AIA HTTP response has no header terminator"))?;
    let headers =
        std::str::from_utf8(&response[..header_end]).context("AIA HTTP headers are not UTF-8")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("AIA HTTP response has no status code"))?;
    if status != 200 {
        return Err(anyhow!("AIA HTTP GET returned status {status}"));
    }
    let body_start = header_end + 4;
    let body = response[body_start..].to_vec();
    if body.len() > options.max_download_bytes {
        return Err(anyhow!(
            "AIA issuer certificate exceeds configured size limit"
        ));
    }
    Ok(body)
}

fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

fn push_der_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    push_der_len(out, body.len());
    out.extend_from_slice(body);
}

fn push_der_sequence(out: &mut Vec<u8>, body: &[u8]) {
    push_der_tlv(out, 0x30, body);
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn expect_tlv(input: &[u8], tag: u8) -> Result<&[u8]> {
    if input.first().copied() != Some(tag) {
        return Err(anyhow!("unexpected tag"));
    }
    let (body_start, len) = read_len(input, 1)?;
    let end = body_start
        .checked_add(len)
        .ok_or_else(|| anyhow!("TLV length overflow"))?;
    if end != input.len() {
        return Err(anyhow!("TLV trailing bytes"));
    }
    Ok(&input[body_start..end])
}

fn read_tlv<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let start = *pos;
    if start >= input.len() {
        return Err(anyhow!("missing TLV tag"));
    }
    *pos += 1;
    let (body_start, len) = read_len(input, *pos)?;
    let end = body_start
        .checked_add(len)
        .ok_or_else(|| anyhow!("TLV length overflow"))?;
    if end > input.len() {
        return Err(anyhow!("TLV length exceeds input"));
    }
    *pos = end;
    Ok(&input[start..end])
}

fn read_len(input: &[u8], mut pos: usize) -> Result<(usize, usize)> {
    let first = *input.get(pos).ok_or_else(|| anyhow!("missing length"))?;
    pos += 1;
    if first < 0x80 {
        return Ok((pos, first as usize));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 3 {
        return Err(anyhow!("unsupported DER length form"));
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | (*input.get(pos).ok_or_else(|| anyhow!("truncated length"))? as usize);
        pos += 1;
    }
    Ok((pos, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else {
            out.extend_from_slice(&[0x81, len as u8]);
        }
    }

    fn push_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
        out.push(tag);
        push_len(out, body.len());
        out.extend_from_slice(body);
    }

    #[test]
    fn parses_ca_issuers_uri_from_aia_der() {
        let mut uri = Vec::new();
        push_tlv(&mut uri, 0x86, b"http://127.0.0.1:1/issuer.der");
        let mut access_description = Vec::new();
        access_description.extend_from_slice(CA_ISSUERS_OID_DER);
        access_description.extend_from_slice(&uri);
        let mut ad = Vec::new();
        push_tlv(&mut ad, 0x30, &access_description);
        let mut aia = Vec::new();
        push_tlv(&mut aia, 0x30, &ad);

        let urls = parse_aia_ca_issuers(&aia).expect("parse AIA");
        assert_eq!(urls, vec!["http://127.0.0.1:1/issuer.der"]);
    }

    #[test]
    fn parses_minimal_empty_crl() {
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&[0x02, 0x01, 0x01]);
        tbs.extend_from_slice(SHA256_WITH_RSA_ENCRYPTION_DER);
        tbs.extend_from_slice(&[0x30, 0x00]);
        push_tlv(&mut tbs, 0x17, b"240101000000Z");
        push_tlv(&mut tbs, 0x17, b"250101000000Z");
        let mut tbs_tlv = Vec::new();
        push_tlv(&mut tbs_tlv, 0x30, &tbs);

        let mut sig = vec![0u8];
        sig.extend_from_slice(&[0x11; 8]);
        let mut crl_body = Vec::new();
        crl_body.extend_from_slice(&tbs_tlv);
        crl_body.extend_from_slice(SHA256_WITH_RSA_ENCRYPTION_DER);
        push_tlv(&mut crl_body, 0x03, &sig);
        let mut crl = Vec::new();
        push_tlv(&mut crl, 0x30, &crl_body);

        let parsed = parse_certificate_list_der(&crl).expect("parse CRL");
        assert!(parsed.revoked_serial_tlvs.is_empty());
    }

    #[test]
    fn ocsp_lookup_uses_status_from_matching_cert_id_only() {
        let d1 = UtcDate::ymd(2024, 1, 1).unwrap();
        let d2 = UtcDate::ymd(2049, 1, 1).unwrap();
        let parsed = ParsedOcspResponse {
            tbs_response_data_tlv: Vec::new(),
            signature: Vec::new(),
            responses: vec![
                ParsedOcspSingleResponse {
                    cert_id_tlv: vec![0x30, 0x01, 0x01],
                    status: OcspCheckOutcome::Revoked,
                    this_update: d1.clone(),
                    next_update: d2.clone(),
                },
                ParsedOcspSingleResponse {
                    cert_id_tlv: vec![0x30, 0x01, 0x02],
                    status: OcspCheckOutcome::Good,
                    this_update: d1,
                    next_update: d2,
                },
            ],
        };

        let entry = ocsp_response_for_cert_id(&parsed, &[0x30, 0x01, 0x01]).unwrap();
        assert_eq!(entry.status, OcspCheckOutcome::Revoked);
    }

    #[test]
    fn revocation_freshness_rejects_stale_or_future_windows() {
        let stale_this = UtcDate::ymd(2000, 1, 1).unwrap();
        let stale_next = UtcDate::ymd(2001, 1, 1).unwrap();
        let err = ensure_time_window_fresh("test", &stale_this, Some(&stale_next)).unwrap_err();
        assert!(err.to_string().contains("stale"));

        let now = UtcDate::now();
        let future_this =
            UtcDate::ymd(now.year() + 1, now.month(), now.day()).expect("future date");
        let future_next =
            UtcDate::ymd(now.year() + 2, now.month(), now.day()).expect("future next date");
        let err = ensure_time_window_fresh("test", &future_this, Some(&future_next)).unwrap_err();
        assert!(err.to_string().contains("future"));
    }

    #[test]
    fn parses_http_uri_general_names_from_crl_dp_shape() {
        let mut uri = Vec::new();
        push_tlv(&mut uri, 0x86, b"http://127.0.0.1:1/crl.der");
        let mut full_name = Vec::new();
        push_tlv(&mut full_name, 0xa0, &uri);
        let mut dp_name = Vec::new();
        push_tlv(&mut dp_name, 0xa0, &full_name);
        let mut dp = Vec::new();
        push_tlv(&mut dp, 0x30, &dp_name);
        let mut ext = Vec::new();
        push_tlv(&mut ext, 0x30, &dp);

        let urls = parse_http_uri_general_names(&ext).expect("parse CDP URLs");
        assert_eq!(urls, vec!["http://127.0.0.1:1/crl.der"]);
    }
}
