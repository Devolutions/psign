use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::ObjectIdentifier;
use der::{Decode, DecodePem, Encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use x509_cert::spki::AlgorithmIdentifierOwned;

const SIGNATURE_VERSION: u32 = 0x0001_0001;
const CERT_SIGNATURE_TYPE: u32 = 1;
const OID_ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RdpValueKind {
    Integer,
    String,
    Binary,
}

impl RdpValueKind {
    fn as_char(self) -> char {
        match self {
            Self::Integer => 'i',
            Self::String => 's',
            Self::Binary => 'b',
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RdpRecord {
    pub name: String,
    pub kind: RdpValueKind,
    pub value: String,
}

impl RdpRecord {
    pub fn string(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: RdpValueKind::String,
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedRdpSignature {
    pub records: Vec<RdpRecord>,
    pub sign_scope: String,
    pub secure_blob: Vec<u8>,
}

const SENSITIVE_SETTINGS: &[(&str, bool)] = &[
    ("Full Address", true),
    ("Alternate Full Address", false),
    ("PCB", false),
    ("Use Redirection Server Name", false),
    ("Server Port", false),
    ("Negotiate Security Layer", false),
    ("EnableCredSspSupport", false),
    ("DisableConnectionSharing", false),
    ("AutoReconnection Enabled", false),
    ("GatewayHostname", false),
    ("GatewayUsageMethod", false),
    ("GatewayProfileUsageMethod", false),
    ("GatewayCredentialsSource", false),
    ("Support URL", false),
    ("PromptCredentialOnce", false),
    ("Require pre-authentication", false),
    ("Pre-authentication server address", false),
    ("Alternate Shell", false),
    ("Shell Working Directory", false),
    ("RemoteApplicationProgram", false),
    ("RemoteApplicationExpandWorkingdir", false),
    ("RemoteApplicationMode", false),
    ("RemoteApplicationGuid", false),
    ("RemoteApplicationName", false),
    ("RemoteApplicationIcon", false),
    ("RemoteApplicationFile", false),
    ("RemoteApplicationFileExtensions", false),
    ("RemoteApplicationCmdLine", false),
    ("RemoteApplicationExpandCmdLine", false),
    ("Prompt For Credentials", false),
    ("Authentication Level", false),
    ("AudioMode", false),
    ("RedirectDrives", false),
    ("RedirectPrinters", false),
    ("RedirectCOMPorts", false),
    ("RedirectSmartCards", false),
    ("RedirectPOSDevices", false),
    ("RedirectClipboard", false),
    ("DevicesToRedirect", false),
    ("DrivesToRedirect", false),
    ("LoadBalanceInfo", false),
    ("RedirectDirectX", false),
    ("RDGIsKDCProxy", false),
    ("KDCProxyName", false),
    ("EnableRdsAadAuth", false),
    ("RedirectWebAuthn", false),
    ("RedirectTextProcessing", false),
    ("allowed security protocols", false),
];

pub fn decode_rdp_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return String::from_utf16_lossy(&le_u16s(&bytes[2..]));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return String::from_utf16_lossy(&be_u16s(&bytes[2..]));
    }
    if let Some(text) = decode_bomless_utf16(bytes) {
        return text;
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.trim_start_matches('\u{feff}').to_owned(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

pub fn encode_native_unicode(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for w in text.encode_utf16() {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

pub fn parse_records(text: &str) -> Vec<RdpRecord> {
    text.lines().filter_map(parse_line).collect()
}

pub fn prepare_for_signature(mut records: Vec<RdpRecord>) -> Result<PreparedRdpSignature> {
    remove_record(&mut records, "SignScope");
    remove_record(&mut records, "Signature");

    let full_address = find_record(&records, "Full Address")
        .filter(|r| !r.value.is_empty())
        .ok_or_else(|| anyhow!("RDP file is missing required Full Address setting"))?
        .value
        .clone();

    if find_record(&records, "Alternate Full Address").is_none() {
        insert_or_replace(
            &mut records,
            RdpRecord::string("Alternate Full Address", full_address),
        );
    }

    let mut scope_names = Vec::new();
    for (name, required) in SENSITIVE_SETTINGS {
        let Some(record) = find_record(&records, name) else {
            if *required {
                return Err(anyhow!("RDP file is missing required {name} setting"));
            }
            continue;
        };
        if *required && record.value.is_empty() {
            return Err(anyhow!("RDP file has an empty required {name} setting"));
        }
        scope_names.push(*name);
    }

    let sign_scope = scope_names.join(",");
    insert_or_replace(
        &mut records,
        RdpRecord::string("SignScope", sign_scope.clone()),
    );
    let secure_blob = secure_settings_blob(&records, &sign_scope)?;

    Ok(PreparedRdpSignature {
        records,
        sign_scope,
        secure_blob,
    })
}

pub fn apply_pkcs7_signature(records: &mut Vec<RdpRecord>, pkcs7: &[u8]) {
    let serialized = serialize_signature(pkcs7);
    let encoded = base64::engine::general_purpose::STANDARD.encode(serialized);
    insert_or_replace(records, RdpRecord::string("Signature", encoded));
}

pub fn records_to_text(records: &[RdpRecord]) -> String {
    let mut out = String::new();
    for record in records {
        out.push_str(&record_to_line(record));
    }
    out
}

pub fn serialize_signature(pkcs7: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + pkcs7.len());
    out.extend_from_slice(&SIGNATURE_VERSION.to_le_bytes());
    out.extend_from_slice(&CERT_SIGNATURE_TYPE.to_le_bytes());
    out.extend_from_slice(&(pkcs7.len() as u32).to_le_bytes());
    out.extend_from_slice(pkcs7);
    out
}

pub fn signature_pkcs7_from_base64(value: &str) -> Result<Vec<u8>> {
    let serialized = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .context("decode RDP Signature base64")?;
    signature_pkcs7_from_serialized(&serialized)
}

pub fn signature_record_pkcs7(records: &[RdpRecord]) -> Result<Vec<u8>> {
    let record = find_record(records, "Signature")
        .ok_or_else(|| anyhow!("RDP file does not contain a Signature record"))?;
    signature_pkcs7_from_base64(&record.value)
}

pub fn signature_pkcs7_from_serialized(serialized: &[u8]) -> Result<Vec<u8>> {
    if serialized.len() < 12 {
        return Err(anyhow!(
            "RDP Signature payload is shorter than 12-byte header"
        ));
    }
    let version = u32::from_le_bytes(serialized[0..4].try_into().expect("slice length"));
    let signature_type = u32::from_le_bytes(serialized[4..8].try_into().expect("slice length"));
    let len = u32::from_le_bytes(serialized[8..12].try_into().expect("slice length")) as usize;
    if version != SIGNATURE_VERSION {
        return Err(anyhow!("unsupported RDP Signature version 0x{version:08x}"));
    }
    if signature_type != CERT_SIGNATURE_TYPE {
        return Err(anyhow!("unsupported RDP Signature type {signature_type}"));
    }
    if serialized.len() - 12 != len {
        return Err(anyhow!(
            "RDP Signature length header says {len} byte(s), payload has {}",
            serialized.len() - 12
        ));
    }
    Ok(serialized[12..].to_vec())
}

pub fn secure_settings_blob(records: &[RdpRecord], sign_scope: &str) -> Result<Vec<u8>> {
    let mut text = String::new();
    for name in sign_scope.split(',').filter(|s| !s.is_empty()) {
        let record = find_record(records, name)
            .ok_or_else(|| anyhow!("field '{name}' in SignScope was not found in RDP file"))?;
        text.push_str(&record_to_line(record));
    }
    let sign_scope_record = find_record(records, "SignScope")
        .ok_or_else(|| anyhow!("SignScope field was not found in RDP file"))?;
    text.push_str(&record_to_line(sign_scope_record));

    let mut bytes = Vec::with_capacity((text.encode_utf16().count() + 1) * 2);
    for w in text.encode_utf16().chain(std::iter::once(0)) {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    Ok(bytes)
}

pub fn parse_certificate(bytes: &[u8]) -> Result<Certificate> {
    if let Some(pem) = pem_text(bytes)? {
        Certificate::from_pem(pem.as_bytes()).context("parse PEM certificate")
    } else {
        Certificate::from_der(bytes).context("parse DER certificate")
    }
}

pub fn parse_rsa_private_key(bytes: &[u8]) -> Result<RsaPrivateKey> {
    if let Some(pem) = pem_text(bytes)? {
        if pem.contains("BEGIN RSA PRIVATE KEY") {
            return RsaPrivateKey::from_pkcs1_pem(pem).context("parse PKCS#1 RSA private key PEM");
        }
        return RsaPrivateKey::from_pkcs8_pem(pem).context("parse PKCS#8 RSA private key PEM");
    }

    RsaPrivateKey::from_pkcs8_der(bytes)
        .or_else(|_| RsaPrivateKey::from_pkcs1_der(bytes))
        .context("parse DER RSA private key")
}

pub fn sign_secure_blob_rsa_sha256(
    secure_blob: &[u8],
    signer_cert: Certificate,
    chain_certs: Vec<Certificate>,
    private_key: RsaPrivateKey,
) -> Result<Vec<u8>> {
    let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: None,
    };
    let content = EncapsulatedContentInfo {
        econtent_type: OID_ID_DATA,
        econtent: None,
    };
    let message_digest: [u8; 32] = Sha256::digest(secure_blob).into();
    let signer_id = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });
    let signer_info = SignerInfoBuilder::new(
        &signer,
        signer_id,
        digest_algorithm.clone(),
        &content,
        Some(&message_digest),
    )
    .map_err(|e| anyhow!("build PKCS#7 signer info: {e}"))?;

    let mut builder = SignedDataBuilder::new(&content);
    builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(|e| anyhow!("add PKCS#7 digest algorithm: {e}"))?
        .add_certificate(CertificateChoices::Certificate(signer_cert))
        .map_err(|e| anyhow!("add PKCS#7 signer certificate: {e}"))?;
    for cert in chain_certs {
        builder
            .add_certificate(CertificateChoices::Certificate(cert))
            .map_err(|e| anyhow!("add PKCS#7 chain certificate: {e}"))?;
    }
    let pkcs7 = builder
        .add_signer_info::<rsa::pkcs1v15::SigningKey<Sha256>, rsa::pkcs1v15::Signature>(signer_info)
        .map_err(|e| anyhow!("sign PKCS#7 signed attributes: {e}"))?
        .build()
        .map_err(|e| anyhow!("build PKCS#7 SignedData: {e}"))?
        .to_der()
        .context("encode PKCS#7 SignedData")?;
    Ok(pkcs7)
}

fn pem_text(bytes: &[u8]) -> Result<Option<&str>> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim_start_matches('\u{feff}').trim_start();
        if trimmed.starts_with("-----BEGIN ") {
            return Ok(Some(trimmed));
        }
    } else if bytes.starts_with(b"-----BEGIN ") || bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(anyhow!("PEM input is not valid UTF-8"));
    }
    Ok(None)
}

fn decode_bomless_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let pairs = bytes.len() / 2;
    let even_nuls = bytes.iter().step_by(2).filter(|&&b| b == 0).count();
    let odd_nuls = bytes.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    if odd_nuls * 2 >= pairs {
        return Some(String::from_utf16_lossy(&le_u16s(bytes)));
    }
    if even_nuls * 2 >= pairs {
        return Some(String::from_utf16_lossy(&be_u16s(bytes)));
    }
    None
}

fn parse_line(line: &str) -> Option<RdpRecord> {
    let trimmed = line.trim_start_matches([' ', '\t']);
    if trimmed.is_empty() {
        return None;
    }
    let (name, rest) = trimmed.split_once(':')?;
    let rest = rest.trim_start_matches([' ', '\t']);
    let mut chars = rest.chars();
    let kind = match chars.next()?.to_ascii_lowercase() {
        'i' => RdpValueKind::Integer,
        's' => RdpValueKind::String,
        'b' => RdpValueKind::Binary,
        _ => return None,
    };
    let rest = chars.as_str().trim_start_matches([' ', '\t']);
    let value = rest.strip_prefix(':')?.trim_start_matches([' ', '\t']);
    Some(RdpRecord {
        name: name.trim_end_matches([' ', '\t']).to_owned(),
        kind,
        value: value.trim_end_matches(['\r', '\n']).to_owned(),
    })
}

fn record_to_line(record: &RdpRecord) -> String {
    format!(
        "{}:{}:{}\r\n",
        record.name,
        record.kind.as_char(),
        record.value
    )
}

fn find_record<'a>(records: &'a [RdpRecord], name: &str) -> Option<&'a RdpRecord> {
    records.iter().find(|r| r.name.eq_ignore_ascii_case(name))
}

fn insert_or_replace(records: &mut Vec<RdpRecord>, record: RdpRecord) {
    if let Some(existing) = records
        .iter_mut()
        .find(|r| r.name.eq_ignore_ascii_case(&record.name))
    {
        *existing = record;
    } else {
        records.push(record);
    }
}

fn remove_record(records: &mut Vec<RdpRecord>, name: &str) {
    records.retain(|r| !r.name.eq_ignore_ascii_case(name));
}

fn le_u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn be_u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs7;
    use sha2::Sha256;

    fn fixture_text(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/rdp")
            .join(name);
        decode_rdp_text(&std::fs::read(path).unwrap())
    }

    #[test]
    fn parses_fixture_and_builds_native_scope() {
        let records = parse_records(include_str!("../../../tests/fixtures/rdp/minimal.rdp"));
        let prepared = prepare_for_signature(records).expect("prepare");
        assert_eq!(
            prepared.sign_scope,
            "Full Address,Alternate Full Address,Server Port,EnableCredSspSupport"
        );
        assert!(find_record(&prepared.records, "Signature").is_none());
        assert_eq!(
            find_record(&prepared.records, "Alternate Full Address")
                .expect("alternate")
                .value,
            "server.example.test"
        );
    }

    #[test]
    fn decodes_fixture_text_encodings() {
        let expected = fixture_text("unsigned-utf8.rdp");
        for name in [
            "unsigned-utf8-bom.rdp",
            "unsigned-utf16le-bom.rdp",
            "unsigned-utf16le-nobom.rdp",
            "unsigned-utf16be-bom.rdp",
            "unsigned-utf16be-nobom.rdp",
        ] {
            assert_eq!(fixture_text(name), expected, "encoding fixture {name}");
        }
    }

    #[test]
    fn partial_signed_scope_and_stale_signature_are_replaced() {
        let records = parse_records(&fixture_text("partial-signed-scope.rdp"));
        let mut prepared = prepare_for_signature(records).expect("prepare");
        assert_eq!(
            prepared.sign_scope,
            "Full Address,Alternate Full Address,Server Port,GatewayHostname,Prompt For Credentials"
        );
        apply_pkcs7_signature(&mut prepared.records, b"fresh");
        let text = records_to_text(&prepared.records);
        assert!(!text.contains("signscope:s:Full Address,Server Port\r\n"));
        assert!(!text.contains("AQABAAEAAAAFAAAAc3RhbGU="));
        assert!(text.contains("gatewayhostname:s:gateway.example.test"));
        assert!(text.contains("Signature:s:AQABAAEAAAAFAAAAZnJlc2g="));
    }

    #[test]
    fn secure_blob_is_utf16le_lines_plus_nul() {
        let records = parse_records(include_str!("../../../tests/fixtures/rdp/minimal.rdp"));
        let prepared = prepare_for_signature(records).expect("prepare");
        let expected = concat!(
            "full address:s:server.example.test\r\n",
            "Alternate Full Address:s:server.example.test\r\n",
            "server port:i:3389\r\n",
            "enablecredsspsupport:i:1\r\n",
            "SignScope:s:Full Address,Alternate Full Address,Server Port,EnableCredSspSupport\r\n",
            "\0"
        );
        let mut expected_bytes = Vec::new();
        for w in expected.encode_utf16() {
            expected_bytes.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(prepared.secure_blob, expected_bytes);
    }

    #[test]
    fn stale_signature_records_are_replaced() {
        let records = parse_records(include_str!(
            "../../../tests/fixtures/rdp/with-stale-signature.rdp"
        ));
        let mut prepared = prepare_for_signature(records).expect("prepare");
        apply_pkcs7_signature(&mut prepared.records, b"pkcs7");
        let text = records_to_text(&prepared.records);
        assert_eq!(text.matches("SignScope:s:").count(), 1);
        assert_eq!(text.matches("Signature:s:").count(), 1);
        assert!(!text.contains("stale"));
        assert!(text.contains("Signature:s:AQABAAEAAAAFAAAAcGtjczc="));
    }

    #[test]
    fn missing_full_address_is_an_error() {
        let records = parse_records("server port:i:3389\r\n");
        let err = prepare_for_signature(records).expect_err("missing Full Address");
        assert!(err.to_string().contains("Full Address"));
    }

    #[test]
    fn native_unicode_encoding_uses_utf16le_bom() {
        let bytes = encode_native_unicode("full address:s:x\r\n");
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        assert_eq!(decode_rdp_text(&bytes), "full address:s:x\r\n");
    }

    #[test]
    fn serialized_signature_is_native_header_plus_blob() {
        let serialized = serialize_signature(&[0xAA, 0xBB]);
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&serialized),
            "AQABAAEAAAACAAAAqrs="
        );
        assert_eq!(
            signature_pkcs7_from_serialized(&serialized).expect("deserialize"),
            vec![0xAA, 0xBB]
        );
    }

    #[test]
    fn malformed_signature_payloads_are_rejected() {
        assert!(signature_pkcs7_from_serialized(&[0; 11]).is_err());
        let mut wrong_version = serialize_signature(b"pkcs7");
        wrong_version[0] = 0;
        assert!(signature_pkcs7_from_serialized(&wrong_version).is_err());
        let mut wrong_len = serialize_signature(b"pkcs7");
        wrong_len[8] = 0xFF;
        assert!(signature_pkcs7_from_serialized(&wrong_len).is_err());
        assert!(signature_pkcs7_from_base64("not base64").is_err());
    }

    #[test]
    fn signscope_references_missing_field_is_malformed() {
        let records = parse_records(&fixture_text("signscope-missing-field.rdp"));
        let sign_scope = records
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case("SignScope"))
            .expect("SignScope")
            .value
            .clone();
        let err = secure_settings_blob(&records, &sign_scope).expect_err("missing SignScope field");
        assert!(err.to_string().contains("NoSuch"));
    }

    #[test]
    fn malformed_lines_are_ignored_but_valid_records_are_kept() {
        let records = parse_records(&fixture_text("malformed-lines.rdp"));
        assert_eq!(records.len(), 2);
        let prepared = prepare_for_signature(records).expect("prepare valid subset");
        assert_eq!(
            prepared.sign_scope,
            "Full Address,Alternate Full Address,Server Port"
        );
    }

    #[test]
    fn malformed_missing_required_full_address_fixture_errors() {
        let records = parse_records(&fixture_text("missing-full-address.rdp"));
        let err = prepare_for_signature(records).expect_err("missing Full Address");
        assert!(err.to_string().contains("Full Address"));
    }

    #[test]
    fn signed_fixture_uses_repo_test_certificate_over_secure_blob() {
        let records = parse_records(&fixture_text("signed-test-cert.rdp"));
        let pkcs7_der = signature_record_pkcs7(&records).expect("signature record");
        let sd = pkcs7::parse_pkcs7_signed_data_der(&pkcs7_der).expect("signed data");
        let si = sd.signer_infos.0.as_slice().first().expect("signer info");
        let message_digest =
            pkcs7::signer_info_pkcs9_message_digest_octets(si).expect("messageDigest attribute");

        let mut unsigned = records.clone();
        remove_record(&mut unsigned, "Signature");
        let sign_scope = unsigned
            .iter()
            .find(|r| r.name.eq_ignore_ascii_case("SignScope"))
            .expect("SignScope")
            .value
            .clone();
        let secure_blob = secure_settings_blob(&unsigned, &sign_scope).expect("secure blob");
        assert_eq!(message_digest, Sha256::digest(&secure_blob).as_slice());
    }
}
