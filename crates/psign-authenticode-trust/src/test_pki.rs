//! Portable test PKI generation and PKCS#12 chain extraction for local and VM test environments.
//!
//! Produces RFC 5280 / Windows CryptoAPI-compatible X.509 v3 Root CA, Code Signing, and TLS Server
//! certificates and PKCS#12 (`.pfx`) bundles without modifying OS certificate stores.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

pub use crate::pkcs12::{ParsedPfxIdentity, parse_pfx_identity};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use der::asn1::{
    Any, AnyRef, BitString, GeneralizedTime, Ia5String, Ia5StringRef, ObjectIdentifier,
    OctetString, PrintableStringRef, SetOfVec, TeletexStringRef, UtcTime, Utf8StringRef,
};
use der::{Decode, Encode, Tag, Tagged};
use picky::key::PrivateKey;
use picky::pkcs12::{
    Pbes2Cipher, Pbes2Encryption, Pfx, Pkcs12Attribute, Pkcs12CryptoContext, Pkcs12Encryption,
    Pkcs12HashAlgorithm, Pkcs12MacAlgorithmHmac, SafeBag, SafeContents,
};
use picky::x509::Cert as PickyCert;
use psign_sip_digest::rdp;
use rand::RngCore as _;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::signature::{Keypair, SignatureEncoding, Signer};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_SURNAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.4");
const OID_SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
const OID_COUNTRY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const OID_STATE_OR_PROVINCE_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
const OID_STREET_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.9");
const OID_ORGANIZATION_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_ORGANIZATIONAL_UNIT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_TITLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.12");
const OID_GIVEN_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.42");
const OID_EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");
const OID_USER_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.1");
const OID_DOMAIN_COMPONENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25");

const OID_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_EKU_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const OID_EKU_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Backdate generated certificates by 24 hours so guest/host VM clock skew does not reject fresh certs.
const NOT_BEFORE_CLOCK_SKEW_SECS: u64 = 86_400;

/// Parameters for generating a self-signed test Root CA.
#[derive(Debug, Clone)]
pub struct RootCaSpec {
    pub subject: String,
    pub validity_days: u32,
    pub key_bits: usize,
}

/// Input CA signing material used to issue leaf certificates.
#[derive(Debug, Clone)]
pub struct CaIssuerMaterial {
    pub cert: Certificate,
    pub cert_der: Vec<u8>,
    pub private_key: RsaPrivateKey,
    pub extra_chain_certs_der: Vec<Vec<u8>>,
}

/// Parameters for issuing a Code Signing leaf certificate.
#[derive(Debug, Clone)]
pub struct CodeSigningCertSpec {
    pub subject: String,
    pub validity_days: u32,
    pub key_bits: usize,
    pub extra_eku_oids: Vec<String>,
}

/// Parameters for issuing a TLS Server leaf certificate.
#[derive(Debug, Clone)]
pub struct TlsServerCertSpec {
    pub subject: Option<String>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub validity_days: u32,
    pub key_bits: usize,
}

/// Generated certificate, private key, and chain ready to serialize to DER, PEM, or PKCS#12 (`.pfx`).
#[derive(Debug, Clone)]
pub struct GeneratedCertMaterial {
    pub cert: Certificate,
    pub cert_der: Vec<u8>,
    pub private_key_pem: String,
    pub chain_certs_der: Vec<Vec<u8>>,
    pub summary: GeneratedCertSummary,
}

/// Machine-readable metadata describing a generated X.509 certificate.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedCertSummary {
    pub subject: String,
    pub issuer: String,
    pub thumbprint_sha1: String,
    pub thumbprint_sha256: String,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub eku_oids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_names: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_addresses: Vec<String>,
    pub chain_certificate_count: usize,
}

/// Parse a Windows `X500DistinguishedName` or RFC 4514 distinguished name string into an X.509 [`Name`].
///
/// Supports standard Windows attribute aliases (`S=`, `E=`, `SN=`, spaces after commas, double-quoted
/// values containing commas or backslashes) as well as RFC 4514 escaping (`\,`, `\\`, `\ `, `\XX`),
/// reversing the RDN list into ASN.1 `RDNSequence` order so Windows `X509Certificate2.Subject`
/// formats it back in the exact input order.
///
/// # Errors
///
/// Returns an error if `input` is empty, contains malformed `KEY=VALUE` components, violates
/// `PrintableString` / `IA5String` character-set rules, or uses an unknown attribute name.
pub fn parse_distinguished_name(input: &str) -> Result<Name> {
    let trimmed = trim_unescaped_spaces(input);
    if trimmed.is_empty() {
        bail!("distinguished name must not be empty");
    }
    let rdn_tokens = split_unescaped(trimmed, ',')?;
    let mut rdns = Vec::with_capacity(rdn_tokens.len());
    for token in rdn_tokens {
        let token = trim_unescaped_spaces(token);
        if token.is_empty() {
            bail!("distinguished name '{input}' contains an empty RDN component");
        }
        let atv_tokens = split_unescaped(token, '+')?;
        let mut atvs = Vec::with_capacity(atv_tokens.len());
        for atv_str in atv_tokens {
            atvs.push(parse_atv(trim_unescaped_spaces(atv_str))?);
        }
        let set = SetOfVec::try_from(atvs)
            .map_err(|e| anyhow!("encode RDN attribute set for '{token}': {e}"))?;
        rdns.push(RelativeDistinguishedName(set));
    }
    // Both RFC 4514 and Windows X500DistinguishedName list most-specific (CN) first in text and
    // most-general (C) first in ASN.1 RDNSequence.
    rdns.reverse();
    Ok(RdnSequence(rdns))
}

/// Trim surrounding ASCII whitespace while preserving an RFC 4514 escaped trailing space (`\ `).
fn trim_unescaped_spaces(raw: &str) -> &str {
    let bytes = raw.as_bytes();
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        let backslashes = bytes[start..end - 1]
            .iter()
            .rev()
            .take_while(|&&c| c == b'\\')
            .count();
        if bytes[end - 1] == b' ' && backslashes % 2 == 1 {
            break;
        }
        end -= 1;
    }
    &raw[start..end]
}

fn split_unescaped(input: &str, delimiter: char) -> Result<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            if in_quotes && chars.peek().is_some_and(|(_, next)| *next == '"') {
                let _ = chars.next();
                continue;
            }
            in_quotes = !in_quotes;
            continue;
        }
        if ch == delimiter && !in_quotes {
            parts.push(&input[start..idx]);
            start = idx + ch.len_utf8();
        }
    }
    if in_quotes {
        bail!("unterminated double quote in distinguished name '{input}'");
    }
    if escaped {
        bail!("trailing backslash escape in distinguished name '{input}'");
    }
    parts.push(&input[start..]);
    Ok(parts)
}

fn parse_atv(token: &str) -> Result<AttributeTypeAndValue> {
    let Some((raw_key, raw_val)) = token.split_once('=') else {
        bail!(
            "distinguished name component '{token}' must be in KEY=VALUE form (for example, CN=Example)"
        );
    };
    let key = raw_key.trim();
    if key.is_empty() {
        bail!("distinguished name component '{token}' has an empty attribute name");
    }
    let oid = resolve_dn_attribute_oid(key)?;
    let val_trimmed = trim_unescaped_spaces(raw_val);
    if let Some(hex_body) = val_trimmed.strip_prefix('#') {
        let raw_der = decode_hex(hex_body)
            .with_context(|| format!("decode hex DER value in RDN '{token}'"))?;
        let value = Any::from_der(&raw_der)
            .map_err(|e| anyhow!("decode DER value in RDN '{token}': {e}"))?;
        return Ok(AttributeTypeAndValue { oid, value });
    }

    let unescaped = unescape_dn_value(val_trimmed)?;
    let value = if oid == OID_COUNTRY_NAME {
        if unescaped.len() != 2 {
            bail!("RDN '{key}' must be a 2-character ISO 3166 country code, got '{unescaped}'");
        }
        let ps = PrintableStringRef::new(unescaped.as_bytes())
            .map_err(|e| anyhow!("RDN '{key}' must be PrintableString: {e}"))?;
        Any::from(ps)
    } else if oid == OID_SERIAL_NUMBER {
        if unescaped.is_empty() {
            bail!("RDN '{key}' must not be empty");
        }
        let ps = PrintableStringRef::new(unescaped.as_bytes())
            .map_err(|e| anyhow!("RDN '{key}' must be PrintableString: {e}"))?;
        Any::from(ps)
    } else if oid == OID_DOMAIN_COMPONENT || oid == OID_EMAIL_ADDRESS {
        if unescaped.is_empty() {
            bail!("RDN '{key}' must not be empty");
        }
        let ia5 = Ia5String::new(&unescaped)
            .map_err(|e| anyhow!("RDN '{key}' must be ASCII IA5String: {e}"))?;
        Any::from(&ia5)
    } else {
        Any::new(Tag::Utf8String, unescaped.as_bytes())
            .map_err(|e| anyhow!("encode RDN '{key}={unescaped}' as Utf8String: {e}"))?
    };
    Ok(AttributeTypeAndValue { oid, value })
}

fn resolve_dn_attribute_oid(key: &str) -> Result<ObjectIdentifier> {
    match key.to_ascii_uppercase().as_str() {
        "CN" | "COMMONNAME" => Ok(OID_COMMON_NAME),
        "O" | "ORG" | "ORGANIZATION" | "ORGANIZATIONNAME" => Ok(OID_ORGANIZATION_NAME),
        "OU" | "ORGANIZATIONALUNIT" | "ORGANIZATIONALUNITNAME" => Ok(OID_ORGANIZATIONAL_UNIT_NAME),
        "L" | "LOCALITY" | "LOCALITYNAME" => Ok(OID_LOCALITY_NAME),
        "S" | "ST" | "STATE" | "PROVINCE" | "STATEORPROVINCENAME" => Ok(OID_STATE_OR_PROVINCE_NAME),
        "C" | "COUNTRY" | "COUNTRYNAME" => Ok(OID_COUNTRY_NAME),
        "STREET" | "STREETADDRESS" => Ok(OID_STREET_ADDRESS),
        "E" | "EMAIL" | "EMAILADDRESS" => Ok(OID_EMAIL_ADDRESS),
        "DC" | "DOMAINCOMPONENT" => Ok(OID_DOMAIN_COMPONENT),
        "SERIALNUMBER" => Ok(OID_SERIAL_NUMBER),
        "UID" | "USERID" => Ok(OID_USER_ID),
        "T" | "TITLE" => Ok(OID_TITLE),
        "G" | "GN" | "GIVENNAME" => Ok(OID_GIVEN_NAME),
        "SN" | "SURNAME" => Ok(OID_SURNAME),
        other => {
            let dotted = other.strip_prefix("OID.").unwrap_or(other);
            ObjectIdentifier::new(dotted)
                .map_err(|_| anyhow!("unsupported X.500 attribute '{key}'"))
        }
    }
}

fn unescape_dn_value(raw: &str) -> Result<String> {
    if raw.starts_with('"') {
        if !raw.ends_with('"') || raw.len() < 2 {
            bail!("improperly quoted RDN value '{raw}'");
        }
        let inner = &raw[1..raw.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    let _ = chars.next();
                    out.push('"');
                } else {
                    bail!("unescaped double quote inside quoted RDN value '{raw}'");
                }
            } else {
                // Inside Windows CERT_X500_NAME_STR quotes, only `""` is an escape; `\` is literal.
                out.push(ch);
            }
        }
        return Ok(out);
    }

    let mut bytes = Vec::with_capacity(raw.len());
    let mut iter = raw.as_bytes().iter().copied();
    while let Some(b) = iter.next() {
        if b == b'"' {
            bail!("unescaped double quote in RDN value '{raw}'");
        }
        if b != b'\\' {
            bytes.push(b);
            continue;
        }
        let esc = iter
            .next()
            .ok_or_else(|| anyhow!("trailing backslash in RDN value '{raw}'"))?;
        if matches!(
            esc,
            b' ' | b'"' | b'#' | b'+' | b',' | b';' | b'<' | b'=' | b'>' | b'\\'
        ) {
            bytes.push(esc);
        } else if esc.is_ascii_hexdigit() {
            let lo = iter.next().ok_or_else(|| {
                anyhow!(
                    "incomplete hex escape '\\{}' in RDN value '{raw}'; escape literal backslashes as '\\\\' or quote the value",
                    esc as char
                )
            })?;
            let byte = decode_hex_pair(esc, lo)
                .ok_or_else(|| anyhow!("invalid hex escape in RDN value '{raw}'"))?;
            bytes.push(byte);
        } else {
            bail!(
                "invalid backslash escape '\\{}' in RDN value '{raw}'; escape literal backslashes as '\\\\' or quote the value",
                esc as char
            );
        }
    }
    String::from_utf8(bytes).context("RDN value is not valid UTF-8")
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let clean: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.is_empty() || !clean.len().is_multiple_of(2) {
        bail!("hex string must have a non-zero even number of hex digits");
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for &[hi, lo] in clean.as_chunks::<2>().0 {
        let byte =
            decode_hex_pair(hi, lo).ok_or_else(|| anyhow!("invalid hex digit in '{hex}'"))?;
        out.push(byte);
    }
    Ok(out)
}

fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    Some((nibble(hi)? << 4) | nibble(lo)?)
}

/// Format an X.509 [`Name`] using Windows `X500DistinguishedName` order (`CN=..., O=..., S=..., C=...`).
///
/// Matches `X509Certificate2.Subject` and MSIX `Identity/@Publisher` string formatting.
#[must_use]
pub fn format_windows_dn(name: &Name) -> String {
    let mut parts = Vec::with_capacity(name.0.len());
    for rdn in name.0.iter().rev() {
        let mut rdn_parts = Vec::with_capacity(rdn.0.len());
        for atv in rdn.0.iter() {
            rdn_parts.push(format_windows_atv(atv));
        }
        parts.push(rdn_parts.join(" + "));
    }
    parts.join(", ")
}

fn format_windows_atv(atv: &AttributeTypeAndValue) -> String {
    let key = match atv.oid {
        OID_COMMON_NAME => "CN".to_string(),
        OID_ORGANIZATION_NAME => "O".to_string(),
        OID_ORGANIZATIONAL_UNIT_NAME => "OU".to_string(),
        OID_LOCALITY_NAME => "L".to_string(),
        OID_STATE_OR_PROVINCE_NAME => "S".to_string(),
        OID_COUNTRY_NAME => "C".to_string(),
        OID_STREET_ADDRESS => "STREET".to_string(),
        OID_EMAIL_ADDRESS => "E".to_string(),
        OID_DOMAIN_COMPONENT => "DC".to_string(),
        OID_SERIAL_NUMBER => "SERIALNUMBER".to_string(),
        OID_USER_ID => "UID".to_string(),
        OID_TITLE => "T".to_string(),
        OID_GIVEN_NAME => "G".to_string(),
        OID_SURNAME => "SN".to_string(),
        other => format!("OID.{other}"),
    };
    let decoded = match atv.value.tag() {
        Tag::PrintableString => PrintableStringRef::try_from(&atv.value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::Utf8String => Utf8StringRef::try_from(&atv.value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::Ia5String => Ia5StringRef::try_from(&atv.value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::TeletexString => TeletexStringRef::try_from(&atv.value)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::BmpString => decode_bmp_string(atv.value.value()),
        _ => None,
    };
    match decoded {
        Some(val) => format!("{key}={}", quote_windows_dn_value(&val)),
        None => {
            let der = atv.value.to_der().unwrap_or_default();
            format!("{key}=#{}", hex_upper(&der))
        }
    }
}

fn decode_bmp_string(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = String::with_capacity(bytes.len() / 2);
    for &[hi, lo] in bytes.as_chunks::<2>().0 {
        let unit = u16::from_be_bytes([hi, lo]);
        out.push(char::from_u32(u32::from(unit))?);
    }
    Some(out)
}

fn quote_windows_dn_value(val: &str) -> String {
    let needs_quotes = val.is_empty()
        || val.starts_with(' ')
        || val.ends_with(' ')
        || val.starts_with('#')
        || val.contains([',', '+', '=', '"', '<', '>', ';', '\\', '\r', '\n']);
    if !needs_quotes {
        return val.to_owned();
    }
    format!("\"{}\"", val.replace('"', "\"\""))
}

/// Load CA signing material from a PKCS#12 (`.pfx`) archive.
///
/// # Errors
///
/// Returns an error if the PFX is invalid or the matched certificate is not a CA certificate.
pub fn load_ca_issuer_from_pfx(pfx_bytes: &[u8], password: &str) -> Result<CaIssuerMaterial> {
    let parsed = parse_pfx_identity(pfx_bytes, password)?;
    build_ca_issuer_material(
        parsed.signer_cert_der,
        parsed.private_key_pem.as_bytes(),
        parsed.chain_certs_der,
    )
}

/// Load CA signing material from separate certificate (DER or PEM) and RSA private key (DER or PEM) bytes.
///
/// # Errors
///
/// Returns an error if the certificate or key cannot be parsed, do not match, or the certificate is not a CA.
pub fn load_ca_issuer_from_cert_and_key(
    cert_bytes: &[u8],
    key_bytes: &[u8],
    extra_chain_certs_der: Vec<Vec<u8>>,
) -> Result<CaIssuerMaterial> {
    let cert = rdp::parse_certificate(cert_bytes).context("parse CA certificate")?;
    let cert_der = cert.to_der().context("encode CA certificate DER")?;
    build_ca_issuer_material(cert_der, key_bytes, extra_chain_certs_der)
}

fn build_ca_issuer_material(
    cert_der: Vec<u8>,
    key_bytes: &[u8],
    extra_chain_certs_der: Vec<Vec<u8>>,
) -> Result<CaIssuerMaterial> {
    let cert = Certificate::from_der(&cert_der).context("parse CA X.509 certificate")?;
    let is_ca = cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, bc)| bc.ca);
    if !is_ca {
        bail!(
            "issuer certificate '{}' is not a CA certificate (BasicConstraints CA=true required)",
            format_windows_dn(&cert.tbs_certificate.subject)
        );
    }
    let private_key = rdp::parse_rsa_private_key(key_bytes).context("parse CA RSA private key")?;
    let key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode CA private key PKCS#8 PEM")?;
    let picky_key = PrivateKey::from_pem_str(&key_pem).context("parse CA key for verification")?;
    crate::pkcs12::key_matches_cert(&cert_der, &picky_key)
        .context("verify CA private key matches CA certificate")?;
    Ok(CaIssuerMaterial {
        cert,
        cert_der,
        private_key,
        extra_chain_certs_der,
    })
}

/// Generate a self-signed X.509 v3 Root CA certificate and RSA private key.
///
/// # Errors
///
/// Returns an error if `spec.subject` is invalid, `spec.key_bits` is unsupported, or key generation fails.
pub fn generate_root_ca(spec: &RootCaSpec) -> Result<GeneratedCertMaterial> {
    validate_key_bits(spec.key_bits)?;
    if spec.validity_days == 0 {
        bail!("validity_days must be at least 1");
    }
    let subject = parse_distinguished_name(&spec.subject)?;
    let private_key =
        RsaPrivateKey::new(&mut OsRng, spec.key_bits).context("generate Root CA RSA key")?;
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key())
        .context("encode Root CA SubjectPublicKeyInfo")?;

    let now = SystemTime::now();
    let not_before = now
        .checked_sub(Duration::from_secs(NOT_BEFORE_CLOCK_SKEW_SECS))
        .unwrap_or(now);
    let not_after = now
        .checked_add(Duration::from_secs(u64::from(spec.validity_days) * 86_400))
        .ok_or_else(|| anyhow!("validity_days overflow"))?;
    let validity = build_validity(not_before, not_after)?;

    let ski = SubjectKeyIdentifier(compute_ski_octet_string(&spki)?);
    let bc = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    let ku = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign);
    let mut extensions = Vec::with_capacity(3);
    push_extension(&mut extensions, &ski, &subject)?;
    push_extension(&mut extensions, &bc, &subject)?;
    push_extension(&mut extensions, &ku, &subject)?;

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: random_serial_number()?,
        signature: sha256_with_rsa_alg_id(),
        issuer: subject.clone(),
        validity,
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let cert = sign_tbs_certificate(tbs, &signing_key)?;
    finalize_generated_material(
        cert,
        &private_key,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

/// Issue an X.509 v3 Code Signing leaf certificate chained to `ca`.
///
/// Includes `BasicConstraints(CA=false)`, `KeyUsage(DigitalSignature)`, and
/// `ExtendedKeyUsage(1.3.6.1.5.5.7.3.3)` (plus any `spec.extra_eku_oids`).
///
/// # Errors
///
/// Returns an error if parameters are invalid, the CA is expired, or signing fails.
pub fn issue_code_signing_cert(
    ca: &CaIssuerMaterial,
    spec: &CodeSigningCertSpec,
) -> Result<GeneratedCertMaterial> {
    validate_key_bits(spec.key_bits)?;
    if spec.validity_days == 0 {
        bail!("validity_days must be at least 1");
    }
    let subject = parse_distinguished_name(&spec.subject)?;
    let mut eku_oids = vec![OID_EKU_CODE_SIGNING];
    for extra in &spec.extra_eku_oids {
        let oid = ObjectIdentifier::new(extra.trim())
            .map_err(|e| anyhow!("invalid extra EKU OID '{extra}': {e}"))?;
        if !eku_oids.contains(&oid) {
            eku_oids.push(oid);
        }
    }

    let leaf_private_key =
        RsaPrivateKey::new(&mut OsRng, spec.key_bits).context("generate Code Signing RSA key")?;
    let leaf_signing_key = SigningKey::<Sha256>::new(leaf_private_key.clone());
    let leaf_spki = SubjectPublicKeyInfoOwned::from_key(leaf_signing_key.verifying_key())
        .context("encode Code Signing SubjectPublicKeyInfo")?;
    let validity = leaf_validity_clamped_to_ca(ca, spec.validity_days)?;

    let ski = SubjectKeyIdentifier(compute_ski_octet_string(&leaf_spki)?);
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(extract_or_compute_ca_ski(&ca.cert)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    let bc = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    };
    let ku = KeyUsage(KeyUsages::DigitalSignature.into());
    let eku = ExtendedKeyUsage(eku_oids.clone());

    let mut extensions = Vec::with_capacity(5);
    push_extension(&mut extensions, &ski, &subject)?;
    push_extension(&mut extensions, &aki, &subject)?;
    push_extension(&mut extensions, &bc, &subject)?;
    push_extension(&mut extensions, &ku, &subject)?;
    push_extension(&mut extensions, &eku, &subject)?;

    let ca_signing_key = SigningKey::<Sha256>::new(ca.private_key.clone());
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: random_serial_number()?,
        signature: sha256_with_rsa_alg_id(),
        issuer: ca.cert.tbs_certificate.subject.clone(),
        validity,
        subject,
        subject_public_key_info: leaf_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let cert = sign_tbs_certificate(tbs, &ca_signing_key)?;
    let mut chain = Vec::with_capacity(1 + ca.extra_chain_certs_der.len());
    chain.push(ca.cert_der.clone());
    chain.extend(ca.extra_chain_certs_der.iter().cloned());
    let eku_strings = eku_oids.iter().map(ToString::to_string).collect();

    finalize_generated_material(
        cert,
        &leaf_private_key,
        chain,
        eku_strings,
        Vec::new(),
        Vec::new(),
    )
}

/// Issue an X.509 v3 TLS Server leaf certificate with DNS and/or IP SANs chained to `ca`.
///
/// Includes `BasicConstraints(CA=false)`, `KeyUsage(DigitalSignature | KeyEncipherment)`,
/// `ExtendedKeyUsage(1.3.6.1.5.5.7.3.1)`, and `SubjectAltName`.
///
/// # Errors
///
/// Returns an error if neither DNS nor IP SANs are provided, parameters are invalid, or signing fails.
pub fn issue_tls_server_cert(
    ca: &CaIssuerMaterial,
    spec: &TlsServerCertSpec,
) -> Result<GeneratedCertMaterial> {
    validate_key_bits(spec.key_bits)?;
    if spec.validity_days == 0 {
        bail!("validity_days must be at least 1");
    }
    if spec.dns_names.is_empty() && spec.ip_addresses.is_empty() {
        bail!(
            "TLS server certificate requires at least one --dns or --ip Subject Alternative Name"
        );
    }

    let mut san_entries = Vec::with_capacity(spec.dns_names.len() + spec.ip_addresses.len());
    let mut normalized_dns = Vec::with_capacity(spec.dns_names.len());
    for dns in &spec.dns_names {
        let host = dns.trim();
        if host.is_empty() {
            bail!("DNS Subject Alternative Name must not be empty");
        }
        let ia5 = Ia5String::new(host).map_err(|e| {
            anyhow!("DNS Subject Alternative Name '{host}' must be ASCII IA5String: {e}")
        })?;
        san_entries.push(GeneralName::DnsName(ia5));
        normalized_dns.push(host.to_owned());
    }
    let mut normalized_ips = Vec::with_capacity(spec.ip_addresses.len());
    for &ip in &spec.ip_addresses {
        san_entries.push(GeneralName::from(ip));
        normalized_ips.push(ip.to_string());
    }

    let default_subject;
    let subject_str = match spec
        .subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(explicit) => explicit,
        None => {
            let primary = normalized_dns
                .first()
                .map(String::as_str)
                .or_else(|| normalized_ips.first().map(String::as_str))
                .expect("at least one SAN was validated");
            default_subject = format!("CN={}", quote_windows_dn_value(primary));
            &default_subject
        }
    };
    let subject = parse_distinguished_name(subject_str)?;

    let leaf_private_key =
        RsaPrivateKey::new(&mut OsRng, spec.key_bits).context("generate TLS Server RSA key")?;
    let leaf_signing_key = SigningKey::<Sha256>::new(leaf_private_key.clone());
    let leaf_spki = SubjectPublicKeyInfoOwned::from_key(leaf_signing_key.verifying_key())
        .context("encode TLS Server SubjectPublicKeyInfo")?;
    let validity = leaf_validity_clamped_to_ca(ca, spec.validity_days)?;

    let ski = SubjectKeyIdentifier(compute_ski_octet_string(&leaf_spki)?);
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(extract_or_compute_ca_ski(&ca.cert)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    let bc = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    };
    let ku = KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment);
    let eku = ExtendedKeyUsage(vec![OID_EKU_SERVER_AUTH]);
    let san = SubjectAltName(san_entries);

    let mut extensions = Vec::with_capacity(6);
    push_extension(&mut extensions, &ski, &subject)?;
    push_extension(&mut extensions, &aki, &subject)?;
    push_extension(&mut extensions, &bc, &subject)?;
    push_extension(&mut extensions, &ku, &subject)?;
    push_extension(&mut extensions, &eku, &subject)?;
    push_extension(&mut extensions, &san, &subject)?;

    let ca_signing_key = SigningKey::<Sha256>::new(ca.private_key.clone());
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: random_serial_number()?,
        signature: sha256_with_rsa_alg_id(),
        issuer: ca.cert.tbs_certificate.subject.clone(),
        validity,
        subject,
        subject_public_key_info: leaf_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let cert = sign_tbs_certificate(tbs, &ca_signing_key)?;
    let mut chain = Vec::with_capacity(1 + ca.extra_chain_certs_der.len());
    chain.push(ca.cert_der.clone());
    chain.extend(ca.extra_chain_certs_der.iter().cloned());

    finalize_generated_material(
        cert,
        &leaf_private_key,
        chain,
        vec![OID_EKU_SERVER_AUTH.to_string()],
        normalized_dns,
        normalized_ips,
    )
}

/// Encode a [`GeneratedCertMaterial`] (leaf certificate, private key, and any CA chain certificates)
/// as a password-protected PKCS#12 (`.pfx`) archive using PBES2 (`AES-256-CBC` + `PBKDF2-HMAC-SHA256`)
/// and `HMAC-SHA256` MAC integrity (tested with `psign`, `.NET`, and Windows 10/11/Server 2022+ `PFXImportCertStore`).
///
/// # Errors
///
/// Returns an error if PKCS#12 encryption or DER serialization fails.
pub fn encode_pfx_der(material: &GeneratedCertMaterial, password: &str) -> Result<Vec<u8>> {
    let leaf_cert =
        PickyCert::from_der(&material.cert_der).context("parse generated certificate for PFX")?;
    let private_key = PrivateKey::from_pem_str(&material.private_key_pem)
        .context("parse generated PKCS#8 private key for PFX")?;
    let local_key_id = Sha1::digest(
        material
            .cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .to_vec();

    let mut context =
        Pkcs12CryptoContext::new_with_password(password).context("initialize PKCS#12 context")?;

    let mut cert_bags = Vec::with_capacity(1 + material.chain_certs_der.len());
    cert_bags.push(
        SafeBag::new_certificate(
            leaf_cert,
            vec![Pkcs12Attribute::new_local_key_id(local_key_id.clone())],
        )
        .context("create PFX leaf certificate bag")?,
    );
    for chain_der in &material.chain_certs_der {
        let chain_cert =
            PickyCert::from_der(chain_der).context("parse chain certificate for PFX")?;
        cert_bags.push(
            SafeBag::new_certificate(chain_cert, Vec::new())
                .context("create PFX chain certificate bag")?,
        );
    }

    let cert_encryption = Pkcs12Encryption::new_pbes2(
        Pbes2Encryption::new(Pbes2Cipher::Aes256Cbc, Pkcs12HashAlgorithm::Sha256),
        &mut context,
    );
    let cert_contents = SafeContents::new_encrypted(cert_bags, cert_encryption, &context)
        .context("encrypt PFX certificate SafeContents")?;

    let key_encryption = Pkcs12Encryption::new_pbes2(
        Pbes2Encryption::new(Pbes2Cipher::Aes256Cbc, Pkcs12HashAlgorithm::Sha256),
        &mut context,
    );
    let key_bag = SafeBag::new_encrypted_key(
        private_key,
        vec![Pkcs12Attribute::new_local_key_id(local_key_id)],
        key_encryption,
        &context,
    )
    .context("encrypt PFX private key SafeBag")?;
    let key_contents = SafeContents::new(vec![key_bag]);

    Pfx::new_with_hmac(
        vec![cert_contents, key_contents],
        Pkcs12MacAlgorithmHmac::new(Pkcs12HashAlgorithm::Sha256),
        &mut context,
    )
    .context("create PKCS#12 MAC")?
    .to_der()
    .context("serialize PKCS#12 PFX as DER")
}

/// Encode one or more DER certificates (for example `[leaf, ca...]`) as a PEM bundle.
#[must_use]
pub fn encode_pem_certificate_bundle(cert_ders: &[&[u8]]) -> String {
    let mut out = String::new();
    for der in cert_ders {
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    out
}

fn validate_key_bits(key_bits: usize) -> Result<()> {
    if !matches!(key_bits, 2048 | 3072 | 4096) {
        bail!("unsupported RSA key size {key_bits}; supported values are 2048, 3072, or 4096");
    }
    Ok(())
}

fn random_serial_number() -> Result<SerialNumber> {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    if bytes.iter().all(|&b| b == 0) {
        bytes[15] = 1;
    }
    // Ensure minimal positive ASN.1 INTEGER encoding (guaranteed non-zero high bit or non-zero byte).
    bytes[0] |= 0x40;
    SerialNumber::new(&bytes).map_err(|e| anyhow!("construct X.509 SerialNumber: {e}"))
}

fn sha256_with_rsa_alg_id() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_SHA256_WITH_RSA_ENCRYPTION,
        parameters: Some(Any::from(AnyRef::NULL)),
    }
}

fn compute_ski_octet_string(spki: &SubjectPublicKeyInfoOwned) -> Result<OctetString> {
    let digest = Sha1::digest(spki.subject_public_key.raw_bytes());
    OctetString::new(digest.to_vec()).map_err(|e| anyhow!("encode SubjectKeyIdentifier: {e}"))
}

fn extract_or_compute_ca_ski(ca_cert: &Certificate) -> Result<OctetString> {
    if let Ok(Some((_, ski))) = ca_cert.tbs_certificate.get::<SubjectKeyIdentifier>() {
        return Ok(ski.0);
    }
    compute_ski_octet_string(&ca_cert.tbs_certificate.subject_public_key_info)
}

fn push_extension<E: AsExtension>(
    extensions: &mut Vec<Extension>,
    ext: &E,
    subject: &Name,
) -> Result<()> {
    let encoded = ext
        .to_extension(subject, extensions)
        .map_err(|e| anyhow!("encode X.509 extension {}: {e}", E::OID))?;
    extensions.push(encoded);
    Ok(())
}

fn rfc5280_time_from_system_time(time: SystemTime) -> Result<Time> {
    let generalized = GeneralizedTime::try_from(time)
        .map_err(|e| anyhow!("convert SystemTime to GeneralizedTime: {e}"))?;
    let dt = generalized.to_date_time();
    if dt.year() <= UtcTime::MAX_YEAR {
        Ok(Time::UtcTime(
            UtcTime::from_date_time(dt).map_err(|e| anyhow!("encode RFC 5280 UtcTime: {e}"))?,
        ))
    } else {
        Ok(Time::GeneralTime(generalized))
    }
}

fn build_validity(not_before: SystemTime, not_after: SystemTime) -> Result<Validity> {
    if not_after <= not_before {
        bail!("certificate not_after must be strictly after not_before");
    }
    Ok(Validity {
        not_before: rfc5280_time_from_system_time(not_before)?,
        not_after: rfc5280_time_from_system_time(not_after)?,
    })
}

fn leaf_validity_clamped_to_ca(ca: &CaIssuerMaterial, validity_days: u32) -> Result<Validity> {
    let now = SystemTime::now();
    let ca_not_before = ca.cert.tbs_certificate.validity.not_before.to_system_time();
    let ca_not_after = ca.cert.tbs_certificate.validity.not_after.to_system_time();
    if ca_not_after <= now {
        bail!(
            "CA certificate is expired (not_after={})",
            ca.cert.tbs_certificate.validity.not_after
        );
    }
    let desired_not_before = now
        .checked_sub(Duration::from_secs(NOT_BEFORE_CLOCK_SKEW_SECS))
        .unwrap_or(now);
    let not_before = desired_not_before.max(ca_not_before);
    let desired_not_after = now
        .checked_add(Duration::from_secs(u64::from(validity_days) * 86_400))
        .ok_or_else(|| anyhow!("validity_days overflow"))?;
    let not_after = desired_not_after.min(ca_not_after);
    build_validity(not_before, not_after)
}

fn sign_tbs_certificate(
    tbs: TbsCertificate,
    signing_key: &SigningKey<Sha256>,
) -> Result<Certificate> {
    let tbs_der = tbs.to_der().context("encode TBSCertificate DER")?;
    let sig = signing_key.sign(&tbs_der);
    let signature = BitString::from_bytes(&sig.to_bytes())
        .map_err(|e| anyhow!("encode X.509 signature BIT STRING: {e}"))?;
    Ok(Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sha256_with_rsa_alg_id(),
        signature,
    })
}

fn finalize_generated_material(
    cert: Certificate,
    private_key: &RsaPrivateKey,
    chain_certs_der: Vec<Vec<u8>>,
    eku_oids: Vec<String>,
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
) -> Result<GeneratedCertMaterial> {
    let is_ca = cert
        .tbs_certificate
        .get::<BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, bc)| bc.ca);
    let cert_der = cert
        .to_der()
        .context("encode generated X.509 certificate DER")?;
    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode generated private key PKCS#8 PEM")?
        .to_string();
    let summary = GeneratedCertSummary {
        subject: format_windows_dn(&cert.tbs_certificate.subject),
        issuer: format_windows_dn(&cert.tbs_certificate.issuer),
        thumbprint_sha1: hex_upper(&Sha1::digest(&cert_der)),
        thumbprint_sha256: hex_upper(&Sha256::digest(&cert_der)),
        serial_hex: hex_upper(cert.tbs_certificate.serial_number.as_bytes()),
        not_before: cert.tbs_certificate.validity.not_before.to_string(),
        not_after: cert.tbs_certificate.validity.not_after.to_string(),
        is_ca,
        eku_oids,
        dns_names,
        ip_addresses,
        chain_certificate_count: chain_certs_der.len(),
    };
    Ok(GeneratedCertMaterial {
        cert,
        cert_der,
        private_key_pem,
        chain_certs_der,
        summary,
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02X}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::AnchorStore;
    use crate::chain::verify_certificate_chain_to_anchors;
    use crate::policy::OnlineTrustOptions;
    use picky::x509::date::UtcDate;

    #[test]
    fn windows_dn_roundtrips_order_and_state_alias() {
        let input = "CN=Devolutions Test, O=\"Devolutions, Inc.\", L=Lavaltrie, S=Quebec, C=CA";
        let parsed = parse_distinguished_name(input).expect("parse Windows DN");
        // ASN.1 RDNSequence must start with C=CA and end with CN=Devolutions Test.
        assert_eq!(parsed.0.len(), 5);
        let first_atv = parsed.0[0].0.iter().next().expect("first ATV");
        let last_atv = parsed.0[4].0.iter().next().expect("last ATV");
        assert_eq!(first_atv.oid, OID_COUNTRY_NAME);
        assert_eq!(last_atv.oid, OID_COMMON_NAME);
        assert_eq!(format_windows_dn(&parsed), input);
    }

    #[test]
    fn dn_distinguishes_sn_surname_from_serialnumber() {
        let input = "SN=Doe, SERIALNUMBER=ABC-12345, CN=Jane Doe, C=CA";
        let parsed = parse_distinguished_name(input).expect("parse SN + SERIALNUMBER");
        // Reversed RDNSequence: [C=CA, CN=Jane Doe, SERIALNUMBER=ABC-12345, SN=Doe]
        let serial_atv = parsed.0[2].0.iter().next().expect("serialnumber ATV");
        let surname_atv = parsed.0[3].0.iter().next().expect("surname ATV");
        assert_eq!(serial_atv.oid, OID_SERIAL_NUMBER);
        assert_eq!(surname_atv.oid, OID_SURNAME);
        assert_eq!(format_windows_dn(&parsed), input);
    }

    #[test]
    fn dn_handles_backslashes_escaped_spaces_and_bmp_string_roundtrips() {
        // Quoted backslash + comma matches Windows X509Certificate2.Subject formatting.
        let quoted_bs = "CN=\"ACME\\Engineering, Corp.\", O=\"Div\\Unit\", C=US";
        let parsed_bs = parse_distinguished_name(quoted_bs).expect("parse quoted backslashes");
        assert_eq!(format_windows_dn(&parsed_bs), quoted_bs);

        // RFC 4514 unquoted `\\` produces the exact same RDN value as Windows quoted `"a\b"`.
        let rfc_bs = parse_distinguished_name("CN=a\\\\b, C=US").expect("parse RFC 4514 \\\\");
        assert_eq!(format_windows_dn(&rfc_bs), "CN=\"a\\b\", C=US");
        assert_eq!(
            parse_distinguished_name(&format_windows_dn(&rfc_bs)).expect("reparse formatted"),
            rfc_bs
        );

        // Unquoted single `\b` / `\z` must be rejected rather than silently dropping `\`.
        assert!(parse_distinguished_name("CN=a\\b").is_err());
        assert!(parse_distinguished_name("CN=a\\z").is_err());

        // RFC 4514 escaped leading and trailing spaces (`\ foo\ `) are preserved despite trimming.
        let spaced =
            parse_distinguished_name("  CN=\\ foo\\   ,  O=Trailing\\   ").expect("spaced");
        assert_eq!(format_windows_dn(&spaced), "CN=\" foo \", O=\"Trailing \"");
        assert_eq!(
            parse_distinguished_name(&format_windows_dn(&spaced)).expect("reparse spaced"),
            spaced
        );

        // External Windows CA BMPString RDN (`0x1E` big-endian UTF-16) decodes cleanly instead of #1E...
        let bmp_bytes = [0x00, b'a', 0x00, b'\\', 0x00, b'b'];
        let bmp_atv = AttributeTypeAndValue {
            oid: OID_COMMON_NAME,
            value: Any::new(Tag::BmpString, bmp_bytes.as_slice()).expect("BMPString Any"),
        };
        let bmp_name = RdnSequence(vec![RelativeDistinguishedName(
            SetOfVec::try_from(vec![bmp_atv]).expect("RDN set"),
        )]);
        assert_eq!(format_windows_dn(&bmp_name), "CN=\"a\\b\"");
    }

    #[test]
    fn dn_validates_country_code_printablestring_and_ia5string() {
        assert!(parse_distinguished_name("C=USA, CN=Test").is_err());
        assert!(parse_distinguished_name("C=U, CN=Test").is_err());
        assert!(parse_distinguished_name("C=U$, CN=Test").is_err());
        assert!(parse_distinguished_name("SERIALNUMBER=bad$char, CN=Test").is_err());
        assert!(parse_distinguished_name("E=user@ex\u{00e4}mple.com, CN=Test").is_err());
        assert!(parse_distinguished_name("DC=ex\u{00e4}mple, CN=Test").is_err());

        let valid =
            parse_distinguished_name("CN=Test, E=ops@devolutions.net, DC=devolutions, C=CA")
                .expect("valid PrintableString and IA5String");
        assert_eq!(
            format_windows_dn(&valid),
            "CN=Test, E=ops@devolutions.net, DC=devolutions, C=CA"
        );
    }

    #[test]
    fn generated_root_codesign_and_tls_pfx_preserve_chains_and_verify() {
        let root = generate_root_ca(&RootCaSpec {
            subject: "CN=Devolutions Static Feed Test Root CA, O=Devolutions Inc., C=CA".into(),
            validity_days: 3650,
            key_bits: 2048,
        })
        .expect("generate root CA");
        let root_pfx = encode_pfx_der(&root, "RootPass123!").expect("encode root PFX");

        let ca_issuer = load_ca_issuer_from_pfx(&root_pfx, "RootPass123!").expect("load CA PFX");
        let codesign = issue_code_signing_cert(
            &ca_issuer,
            &CodeSigningCertSpec {
                subject: "CN=Devolutions Inc., O=Devolutions Inc., L=Lavaltrie, S=Quebec, C=CA"
                    .into(),
                validity_days: 365,
                key_bits: 2048,
                extra_eku_oids: Vec::new(),
            },
        )
        .expect("issue code signing cert");
        assert_eq!(codesign.chain_certs_der.len(), 1);
        assert_eq!(codesign.chain_certs_der[0], root.cert_der);

        let codesign_pfx =
            encode_pfx_der(&codesign, "SignPass123!").expect("encode code signing PFX");
        let extracted = parse_pfx_identity(&codesign_pfx, "SignPass123!").expect("parse PFX");
        assert_eq!(extracted.signer_cert_der, codesign.cert_der);
        assert_eq!(extracted.chain_certs_der, vec![root.cert_der.clone()]);

        let tls = issue_tls_server_cert(
            &ca_issuer,
            &TlsServerCertSpec {
                subject: None,
                dns_names: vec!["winget.devolutions.test".into(), "localhost".into()],
                ip_addresses: vec!["127.0.0.1".parse().expect("ipv4")],
                validity_days: 365,
                key_bits: 2048,
            },
        )
        .expect("issue TLS server cert");
        assert_eq!(tls.summary.subject, "CN=winget.devolutions.test");
        let tls_pfx = encode_pfx_der(&tls, "TlsPass123!").expect("encode TLS PFX");
        let extracted_tls = parse_pfx_identity(&tls_pfx, "TlsPass123!").expect("parse TLS PFX");
        assert_eq!(extracted_tls.signer_cert_der, tls.cert_der);
        assert_eq!(extracted_tls.chain_certs_der, vec![root.cert_der.clone()]);

        let root_picky = PickyCert::from_der(&root.cert_der).expect("picky root");
        let mut anchors = AnchorStore::empty();
        anchors
            .merge_cert_thumbprints(std::slice::from_ref(&root_picky))
            .expect("merge anchor");
        let now = UtcDate::now();
        for leaf_der in [&codesign.cert_der, &tls.cert_der] {
            let leaf_picky = PickyCert::from_der(leaf_der).expect("picky leaf");
            verify_certificate_chain_to_anchors(
                &leaf_picky,
                Vec::new(),
                &anchors,
                std::slice::from_ref(&root_picky),
                &OnlineTrustOptions::default(),
                &now,
                false,
            )
            .expect("verify picky chain to generated root");
        }
    }
}
