use crate::opc::{
    CONTENT_TYPES_PART, OPC_SIGNATURE_ORIGIN_PART, OPC_SIGNATURES_PREFIX, PackageSummary,
    ROOT_RELATIONSHIPS_PART, inspect_package_path, normalize_zip_part_name,
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;
use zip::write::FileOptions;

pub const DEFAULT_VSIX_SIGNATURE_PART: &str =
    "package/services/digital-signature/xml-signature/psign-signature.psdsxs";
const OPC_SIGNATURE_ORIGIN_RELS_PART: &str =
    "package/services/digital-signature/_rels/origin.psdsor.rels";
const OPC_SIGNATURE_ORIGIN_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-package.digital-signature-origin";
const OPC_SIGNATURE_XML_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml";
const OPC_SIGNATURE_ORIGIN_REL_TYPE: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
const OPC_SIGNATURE_REL_TYPE: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VsixPackageInfo {
    pub package: PackageSummary,
    pub has_opc_signature: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VsixHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl VsixHashAlgorithm {
    pub fn digest_uri(self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    pub fn signature_uri(self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        }
    }

    pub fn hash(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
}

pub fn inspect_vsix_path(path: &Path) -> Result<VsixPackageInfo> {
    let package = inspect_package_path(path)?;
    let has_opc_signature =
        package.has_opc_signature_origin || !package.opc_signature_parts.is_empty();
    Ok(VsixPackageInfo {
        package,
        has_opc_signature,
    })
}

pub fn signature_reference_xml_path(path: &Path, algorithm: VsixHashAlgorithm) -> Result<Vec<u8>> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    signature_reference_xml(reader, algorithm)
        .with_context(|| format!("create VSIX signature reference XML for {}", path.display()))
}

/// Unsigned signature skeleton (SignedInfo + package `Object`, empty `SignatureValue`) for review
/// or for [`verify_signature_reference_xml`].
pub fn signature_reference_xml<R>(reader: R, algorithm: VsixHashAlgorithm) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    Ok(
        signature_template(reader, algorithm, VsixSigningTime::FromPackage)?
            .signature_xml(&[], None)
            .into_bytes(),
    )
}

/// Canonical `SignedInfo` octets to sign (see [`signature_template`]; package-derived signing time).
pub fn signed_info_xml_path(path: &Path, algorithm: VsixHashAlgorithm) -> Result<Vec<u8>> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    signed_info_xml(reader, algorithm)
        .with_context(|| format!("create VSIX SignedInfo XML for {}", path.display()))
}

/// Canonical `SignedInfo` octets to sign (see [`signature_template`]; package-derived signing time).
pub fn signed_info_xml<R>(reader: R, algorithm: VsixHashAlgorithm) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    Ok(signature_template(reader, algorithm, VsixSigningTime::FromPackage)?.signed_info)
}

/// Complete signature XML for `path` with a package-derived signing time, so split
/// prehash / from-signature steps produce the same `SignedInfo`.
pub fn signature_xml_path(
    path: &Path,
    algorithm: VsixHashAlgorithm,
    signature_value: &[u8],
    signer_cert_der: Option<&[u8]>,
) -> Result<Vec<u8>> {
    Ok(
        signature_template_path(path, algorithm, VsixSigningTime::FromPackage)?
            .signature_xml(signature_value, signer_cert_der)
            .into_bytes(),
    )
}

const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const OPC_DIGITAL_SIGNATURE_NS: &str =
    "http://schemas.openxmlformats.org/package/2006/digital-signature";
const C14N_URI: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const XMLDSIG_OBJECT_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Object";
const RELATIONSHIPS_CONTENT_TYPE: &str = "application/vnd.openxmlformats-package.relationships+xml";
/// OPC `SignatureTime/Format` value (ECMA-376 Part 2); `Value` uses `yyyy-MM-ddTHH:mm:ss.f+00:00`.
pub const VSIX_SIGNATURE_TIME_FORMAT: &str = "YYYY-MM-DDThh:mm:ss.sTZD";

/// OPC package signature ready to be signed, in the layout `System.IO.Packaging` /
/// `PackageDigitalSignatureManager` and dotnet/sign produce:
///
/// - `<Object Id="idPackageObject">` holds a `Manifest` with one `Reference` per package part
///   (everything except `[Content_Types].xml` and the signature part itself, including
///   `_rels/.rels` and the signature origin parts as they will exist after embedding), each
///   `/part?ContentType=<type>` with a raw-octet digest, plus `SignatureProperties/SignatureTime`.
/// - `SignedInfo` (inclusive C14N 1.0, RSA PKCS#1 v1.5) references `#idPackageObject`.
///
/// Both elements are written directly in canonical form, so [`Self::signed_info`] is exactly the
/// octet string the RSA signature covers.
#[derive(Clone, Debug)]
pub struct VsixSignatureTemplate {
    /// Canonical `SignedInfo` octets to sign.
    pub signed_info: Vec<u8>,
    signed_info_in_document: String,
    object_in_document: String,
    references: usize,
}

impl VsixSignatureTemplate {
    /// Number of package parts referenced by the manifest.
    pub fn reference_count(&self) -> usize {
        self.references
    }

    /// Signature part XML carrying `signature_value` (RSA over [`Self::signed_info`]).
    pub fn signature_xml(&self, signature_value: &[u8], signer_cert_der: Option<&[u8]>) -> String {
        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
        xml.push_str(&format!(
            r#"<Signature Id="SignatureIdValue" xmlns="{XMLDSIG_NS}">"#
        ));
        xml.push_str(&self.signed_info_in_document);
        xml.push_str("<SignatureValue>");
        xml.push_str(&BASE64_STANDARD.encode(signature_value));
        xml.push_str("</SignatureValue>");
        if let Some(cert) = signer_cert_der {
            xml.push_str("<KeyInfo><X509Data><X509Certificate>");
            xml.push_str(&BASE64_STANDARD.encode(cert));
            xml.push_str("</X509Certificate></X509Data></KeyInfo>");
        }
        xml.push_str(&self.object_in_document);
        xml.push_str("</Signature>");
        xml
    }
}

fn c14n_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// Document form of canonical XML: empty `Algorithm` elements written self-closing, as
/// `XmlWriter` does (`System.IO.Packaging` rejects explicit end tags there). Canonicalization maps
/// both spellings to the same octets.
fn document_form(canonical: &str) -> String {
    let mut out = canonical.to_string();
    for name in ["CanonicalizationMethod", "SignatureMethod", "DigestMethod"] {
        out = out.replace(&format!("></{name}>"), " />");
    }
    out
}

fn c14n_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// `SignatureTime/Value` text for `time` (UTC).
fn signature_time_value(time: time::OffsetDateTime) -> String {
    let t = time.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{}+00:00",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond() / 100
    )
}

/// [`VsixSigningTime::FromPackage`]: newest ZIP entry modification time (DOS times carry no
/// zone; read as UTC).
fn package_signature_time_value(archive: &mut zip::ZipArchive<impl Read + Seek>) -> String {
    let mut newest: Option<(u16, u8, u8, u8, u8, u8)> = None;
    for i in 0..archive.len() {
        if let Ok(file) = archive.by_index_raw(i) {
            let d = file.last_modified();
            let key = (
                d.year(),
                d.month(),
                d.day(),
                d.hour(),
                d.minute(),
                d.second(),
            );
            if newest.is_none_or(|n| key > n) {
                newest = Some(key);
            }
        }
    }
    let (y, mo, d, h, mi, s) = newest.unwrap_or((1980, 1, 1, 0, 0, 0));
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.0+00:00")
}

struct ContentTypes {
    defaults: BTreeMap<String, String>,
    overrides: BTreeMap<String, String>,
}

impl ContentTypes {
    fn parse(xml: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(xml).context("OPC [Content_Types].xml is not UTF-8")?;
        let mut defaults = BTreeMap::new();
        let mut overrides = BTreeMap::new();
        for (tag, map, key_attr) in [
            ("<Default ", &mut defaults, "Extension"),
            ("<Override ", &mut overrides, "PartName"),
        ] {
            let mut cursor = 0;
            while let Some(start) = text[cursor..].find(tag) {
                let start = cursor + start;
                let end = text[start..]
                    .find('>')
                    .map(|e| start + e)
                    .ok_or_else(|| anyhow!("unterminated {tag} in [Content_Types].xml"))?;
                let element = &text[start..=end];
                if let (Some(key), Some(ct)) = (
                    xml_attr(element, key_attr),
                    xml_attr(element, "ContentType"),
                ) {
                    let key = key.trim_start_matches('/').to_ascii_lowercase();
                    map.insert(key, ct);
                }
                cursor = end + 1;
            }
        }
        Ok(Self {
            defaults,
            overrides,
        })
    }

    fn for_part(&self, part: &str) -> Option<&str> {
        let key = part.to_ascii_lowercase();
        self.overrides
            .get(&key)
            .or_else(|| {
                let ext = key.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
                self.defaults.get(ext)
            })
            .map(String::as_str)
    }
}

/// `SignatureTime` recorded in the signed package object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VsixSigningTime {
    /// Current UTC time, for one-shot signing.
    Now,
    /// Newest ZIP entry modification time, so independent split-signing steps (prehash, then
    /// from-signature) produce identical `SignedInfo` without passing extra inputs.
    FromPackage,
}

/// Build the OPC signature for `reader` (an unsigned or re-signed VSIX); see
/// [`VsixSignatureTemplate`].
pub fn signature_template<R>(
    reader: R,
    algorithm: VsixHashAlgorithm,
    signing_time: VsixSigningTime,
) -> Result<VsixSignatureTemplate>
where
    R: Read + Seek,
{
    let mut prepared = std::io::Cursor::new(Vec::new());
    write_signed_package(reader, &mut prepared, None, true)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(prepared.into_inner()))
        .context("open prepared VSIX ZIP")?;
    let time_value = match signing_time {
        VsixSigningTime::Now => signature_time_value(time::OffsetDateTime::now_utc()),
        VsixSigningTime::FromPackage => package_signature_time_value(&mut archive),
    };
    template_from_prepared(&mut archive, algorithm, &time_value)
}

pub fn signature_template_path(
    path: &Path,
    algorithm: VsixHashAlgorithm,
    signing_time: VsixSigningTime,
) -> Result<VsixSignatureTemplate> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    signature_template(reader, algorithm, signing_time)
        .with_context(|| format!("create VSIX signature for {}", path.display()))
}

fn template_from_prepared(
    archive: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>,
    algorithm: VsixHashAlgorithm,
    time_value: &str,
) -> Result<VsixSignatureTemplate> {
    let mut content_types_xml = Vec::new();
    archive
        .by_name(CONTENT_TYPES_PART)
        .context("prepared VSIX has no [Content_Types].xml")?
        .read_to_end(&mut content_types_xml)?;
    let content_types = ContentTypes::parse(&content_types_xml)?;

    let mut manifest = String::from("<Manifest>");
    let mut references = 0usize;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("read VSIX ZIP entry")?;
        let name = normalize_zip_part_name(file.name())?;
        if file.is_dir() || name == CONTENT_TYPES_PART || name == DEFAULT_VSIX_SIGNATURE_PART {
            continue;
        }
        let content_type = content_types
            .for_part(&name)
            .ok_or_else(|| anyhow!("VSIX part /{name} has no content type in [Content_Types].xml"))?
            .to_string();
        let mut bytes = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut bytes)?;
        manifest.push_str(&format!(
            r#"<Reference URI="{}"><DigestMethod Algorithm="{}"></DigestMethod><DigestValue>{}</DigestValue></Reference>"#,
            c14n_attr(&format!("/{name}?ContentType={content_type}")),
            algorithm.digest_uri(),
            BASE64_STANDARD.encode(algorithm.hash(&bytes))
        ));
        references += 1;
    }
    if references == 0 {
        return Err(anyhow!("VSIX package has no parts to sign"));
    }
    manifest.push_str("</Manifest>");

    let object_body = format!(
        concat!(
            "{manifest}<SignatureProperties>",
            r##"<SignatureProperty Id="idSignatureTime" Target="#SignatureIdValue">"##,
            r#"<SignatureTime xmlns="{opc}"><Format>{format}</Format><Value>{value}</Value></SignatureTime>"#,
            "</SignatureProperty></SignatureProperties></Object>"
        ),
        manifest = manifest,
        opc = OPC_DIGITAL_SIGNATURE_NS,
        format = VSIX_SIGNATURE_TIME_FORMAT,
        value = c14n_text(time_value),
    );
    let object_canonical =
        format!(r#"<Object xmlns="{XMLDSIG_NS}" Id="idPackageObject">{object_body}"#);
    let object_in_document =
        document_form(&format!(r#"<Object Id="idPackageObject">{object_body}"#));

    let signed_info_body = format!(
        concat!(
            r#"<CanonicalizationMethod Algorithm="{c14n}"></CanonicalizationMethod>"#,
            r#"<SignatureMethod Algorithm="{sig}"></SignatureMethod>"#,
            r##"<Reference Type="{object_type}" URI="#idPackageObject">"##,
            r#"<DigestMethod Algorithm="{digest}"></DigestMethod><DigestValue>{value}</DigestValue>"#,
            "</Reference></SignedInfo>"
        ),
        c14n = C14N_URI,
        sig = algorithm.signature_uri(),
        object_type = XMLDSIG_OBJECT_TYPE,
        digest = algorithm.digest_uri(),
        value = BASE64_STANDARD.encode(algorithm.hash(object_canonical.as_bytes())),
    );
    Ok(VsixSignatureTemplate {
        signed_info: format!(r#"<SignedInfo xmlns="{XMLDSIG_NS}">{signed_info_body}"#).into_bytes(),
        signed_info_in_document: document_form(&format!("<SignedInfo>{signed_info_body}")),
        object_in_document,
        references,
    })
}

/// Insert an RFC 3161 timestamp token (DER `ContentInfo` over the `SignatureValue` octets) as the
/// dotnet/sign `<Object><TimeStamp><EncodedTime>` element.
pub fn add_signature_timestamp(signature_xml: &[u8], token_der: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(signature_xml).context("VSIX signature XML is not UTF-8")?;
    if text.contains("<EncodedTime>") {
        return Err(anyhow!("VSIX signature XML is already timestamped"));
    }
    let end = text
        .rfind("</Signature>")
        .ok_or_else(|| anyhow!("VSIX signature XML is missing </Signature>"))?;
    let stamp = format!(
        r#"<Object><TimeStamp Id="idSignatureTimestamp" xmlns="{OPC_DIGITAL_SIGNATURE_NS}"><Comment>Timestamp got from the time stamp server</Comment><EncodedTime>{}</EncodedTime></TimeStamp></Object>"#,
        BASE64_STANDARD.encode(token_der)
    );
    Ok(format!("{}{stamp}{}", &text[..end], &text[end..]).into_bytes())
}

pub fn verify_signature_reference_xml_path(
    path: &Path,
    signature_xml: &[u8],
    algorithm: VsixHashAlgorithm,
) -> Result<usize> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    verify_signature_reference_xml(reader, signature_xml, algorithm)
        .with_context(|| format!("verify VSIX signature references for {}", path.display()))
}

/// Check that `signature_xml` (from [`VsixSignatureTemplate::signature_xml`]) carries the
/// `SignedInfo` and package `Object` this package produces with the same signing time, which
/// covers every part digest. Returns the number of referenced parts.
pub fn verify_signature_reference_xml<R>(
    reader: R,
    signature_xml: &[u8],
    algorithm: VsixHashAlgorithm,
) -> Result<usize>
where
    R: Read + Seek,
{
    let text = std::str::from_utf8(signature_xml).context("VSIX signature XML is not UTF-8")?;
    let time_start = text
        .find("<SignatureTime")
        .ok_or_else(|| anyhow!("VSIX signature XML has no SignatureTime"))?;
    let time_value = element_text(&text[time_start..], "Value")
        .ok_or_else(|| anyhow!("VSIX signature XML SignatureTime has no Value"))?;
    let mut prepared = std::io::Cursor::new(Vec::new());
    write_signed_package(reader, &mut prepared, None, true)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(prepared.into_inner()))
        .context("open prepared VSIX ZIP")?;
    let template = template_from_prepared(&mut archive, algorithm, time_value)?;
    if !text.contains(&template.object_in_document) {
        return Err(anyhow!(
            "VSIX signature manifest digest mismatch: package parts differ from the signed manifest"
        ));
    }
    if !text.contains(&template.signed_info_in_document) {
        return Err(anyhow!("VSIX SignedInfo digest mismatch"));
    }
    Ok(template.references)
}

/// Part digests of a signature written by psign releases before the OPC layout (direct part
/// references in `SignedInfo`). Kept only to inspect such packages; they are not valid OPC
/// signatures and cannot be trust-verified.
pub fn verify_legacy_signature_reference_xml<R>(
    reader: R,
    signature_xml: &[u8],
    algorithm: VsixHashAlgorithm,
) -> Result<usize>
where
    R: Read + Seek,
{
    let expected = legacy_reference_digests(reader, algorithm)?;
    let actual = parse_legacy_reference_digests(signature_xml, algorithm)?;
    if actual.len() != expected.len() {
        return Err(anyhow!(
            "VSIX signature reference count mismatch: expected {}, found {}",
            expected.len(),
            actual.len()
        ));
    }
    for (name, digest) in &expected {
        match actual.get(name) {
            Some(actual_digest) if actual_digest == digest => {}
            Some(_) => {
                return Err(anyhow!(
                    "VSIX signature reference digest mismatch for {name}"
                ));
            }
            None => return Err(anyhow!("VSIX signature reference missing for {name}")),
        }
    }
    Ok(expected.len())
}

pub fn extract_signature_xml_path(path: &Path) -> Result<Vec<u8>> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    extract_signature_xml(reader)
        .with_context(|| format!("extract VSIX signature XML from {}", path.display()))
}

pub fn extract_signature_xml<R>(reader: R) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    let mut archive = zip::ZipArchive::new(reader).context("open VSIX ZIP")?;
    let mut signature_part = None;
    for i in 0..archive.len() {
        let file = archive.by_index(i).context("read VSIX ZIP entry")?;
        let name = normalize_zip_part_name(file.name())?;
        if !file.is_dir()
            && name.starts_with(OPC_SIGNATURES_PREFIX)
            && signature_part.replace(name.clone()).is_some()
        {
            return Err(anyhow!(
                "VSIX package contains multiple OPC signature XML parts"
            ));
        }
    }
    let signature_part =
        signature_part.ok_or_else(|| anyhow!("VSIX package does not contain OPC signature XML"))?;
    let mut file = archive
        .by_name(&signature_part)
        .with_context(|| format!("read VSIX signature XML part {signature_part}"))?;
    let mut xml = Vec::new();
    file.read_to_end(&mut xml)
        .context("read VSIX signature XML")?;
    if xml.is_empty() {
        return Err(anyhow!("VSIX signature XML payload is empty"));
    }
    Ok(xml)
}

fn legacy_reference_digests<R>(
    reader: R,
    algorithm: VsixHashAlgorithm,
) -> Result<BTreeMap<String, Vec<u8>>>
where
    R: Read + Seek,
{
    let mut archive = zip::ZipArchive::new(reader).context("open VSIX ZIP")?;
    let mut references = BTreeMap::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("read VSIX ZIP entry")?;
        let name = normalize_zip_part_name(file.name())?;
        if file.is_dir()
            || name == CONTENT_TYPES_PART
            || name == ROOT_RELATIONSHIPS_PART
            || is_opc_signature_entry(&name)
        {
            continue;
        }
        let mut bytes = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut bytes)?;
        references.insert(name, algorithm.hash(&bytes));
    }
    Ok(references)
}

fn parse_legacy_reference_digests(
    signature_xml: &[u8],
    algorithm: VsixHashAlgorithm,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let text = std::str::from_utf8(signature_xml).context("VSIX signature XML is not UTF-8")?;
    let mut references = BTreeMap::new();
    let mut cursor = 0usize;
    while let Some(reference_start) = text[cursor..].find("<Reference ") {
        let reference_start = cursor + reference_start;
        let tag_end = text[reference_start..]
            .find('>')
            .map(|offset| reference_start + offset)
            .ok_or_else(|| anyhow!("VSIX signature XML Reference tag is not closed"))?;
        let close_start = text[tag_end..]
            .find("</Reference>")
            .map(|offset| tag_end + offset)
            .ok_or_else(|| anyhow!("VSIX signature XML Reference element is not closed"))?;
        let tag = &text[reference_start..=tag_end];
        let body = &text[tag_end + 1..close_start];
        let uri = xml_attr(tag, "URI")
            .ok_or_else(|| anyhow!("VSIX signature XML Reference is missing URI"))?;
        let name = uri
            .strip_prefix('/')
            .ok_or_else(|| anyhow!("VSIX signature XML Reference URI must be package-absolute"))?;
        let name = normalize_zip_part_name(name)?;
        if !body.contains(&format!(
            r#"<DigestMethod Algorithm="{}"/>"#,
            algorithm.digest_uri()
        )) {
            return Err(anyhow!(
                "VSIX signature XML Reference for {name} does not use expected digest algorithm"
            ));
        }
        let digest_value = element_text(body, "DigestValue").ok_or_else(|| {
            anyhow!("VSIX signature XML Reference for {name} is missing DigestValue")
        })?;
        let digest = BASE64_STANDARD
            .decode(digest_value)
            .context("VSIX signature XML DigestValue is not valid base64")?;
        if references.insert(name.clone(), digest).is_some() {
            return Err(anyhow!("duplicate VSIX signature XML Reference for {name}"));
        }
        cursor = close_start + "</Reference>".len();
    }
    Ok(references)
}

pub fn signed_info_xml_from_signature_xml(signature_xml: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(signature_xml).context("VSIX signature XML is not UTF-8")?;
    let start = text
        .find("<SignedInfo>")
        .ok_or_else(|| anyhow!("VSIX signature XML is missing SignedInfo"))?;
    let end = text[start..]
        .find("</SignedInfo>")
        .map(|offset| start + offset + "</SignedInfo>".len())
        .ok_or_else(|| anyhow!("VSIX signature XML SignedInfo element is not closed"))?;
    Ok(text.as_bytes()[start..end].to_vec())
}

pub fn signature_value_from_signature_xml(signature_xml: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(signature_xml).context("VSIX signature XML is not UTF-8")?;
    let value = element_text(text, "SignatureValue")
        .ok_or_else(|| anyhow!("VSIX signature XML is missing SignatureValue"))?;
    let signature = BASE64_STANDARD
        .decode(value)
        .context("VSIX SignatureValue is not valid base64")?;
    if signature.is_empty() {
        return Err(anyhow!("VSIX SignatureValue is empty"));
    }
    Ok(signature)
}

pub fn signer_certificate_from_signature_xml(signature_xml: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(signature_xml).context("VSIX signature XML is not UTF-8")?;
    let value = element_text(text, "X509Certificate")
        .ok_or_else(|| anyhow!("VSIX signature XML is missing X509Certificate"))?;
    let cert = BASE64_STANDARD
        .decode(value)
        .context("VSIX X509Certificate is not valid base64")?;
    if cert.is_empty() {
        return Err(anyhow!("VSIX X509Certificate is empty"));
    }
    Ok(cert)
}

fn element_text<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(&text[start..end])
}

fn xml_attr(tag: &str, name: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let needle = format!(" {name}={quote}");
        if let Some(start) = tag.find(&needle).map(|s| s + needle.len()) {
            let end = tag[start..].find(quote)? + start;
            return Some(tag[start..end].to_owned());
        }
    }
    None
}

fn is_opc_signature_entry(name: &str) -> bool {
    name == OPC_SIGNATURE_ORIGIN_PART
        || name == OPC_SIGNATURE_ORIGIN_RELS_PART
        || name.starts_with(OPC_SIGNATURES_PREFIX)
}

fn ensure_signature_content_types(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = if bytes.is_empty() {
        r#"<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>"#.to_string()
    } else {
        std::str::from_utf8(bytes)
            .context("OPC [Content_Types].xml is not UTF-8")?
            .to_string()
    };
    let mut text = ensure_content_type_default(&text, "psdsor", OPC_SIGNATURE_ORIGIN_CONTENT_TYPE)?;
    text = ensure_content_type_default(&text, "psdsxs", OPC_SIGNATURE_XML_CONTENT_TYPE)?;
    // The signature origin relationships part needs a content type to be signable.
    if !text.to_ascii_lowercase().contains(r#"extension="rels""#) {
        let insert_at = text
            .rfind("</Types>")
            .ok_or_else(|| anyhow!("OPC [Content_Types].xml is missing </Types>"))?;
        text.insert_str(
            insert_at,
            &format!(r#"<Default Extension="rels" ContentType="{RELATIONSHIPS_CONTENT_TYPE}"/>"#),
        );
    }
    Ok(text.into_bytes())
}

fn ensure_content_type_default(text: &str, extension: &str, content_type: &str) -> Result<String> {
    let text = expand_self_closing_xml_root(text, "Types");
    if text.contains(&format!(r#"Extension="{extension}""#))
        || text.contains(&format!(r#"ContentType="{content_type}""#))
    {
        return Ok(text);
    }
    let insert_at = text
        .rfind("</Types>")
        .ok_or_else(|| anyhow!("OPC [Content_Types].xml is missing </Types>"))?;
    let default = format!(r#"<Default Extension="{extension}" ContentType="{content_type}"/>"#);
    let mut out = String::with_capacity(text.len() + default.len());
    out.push_str(&text[..insert_at]);
    out.push_str(&default);
    out.push_str(&text[insert_at..]);
    Ok(out)
}

fn ensure_root_signature_origin_relationship(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure_relationship(
        bytes,
        OPC_SIGNATURE_ORIGIN_REL_TYPE,
        &format!("/{OPC_SIGNATURE_ORIGIN_PART}"),
        "PsignSignatureOrigin",
    )
}

fn signature_origin_relationships_xml() -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="PsignSignature" Type="{OPC_SIGNATURE_REL_TYPE}" Target="xml-signature/psign-signature.psdsxs"/></Relationships>"#
    )
    .into_bytes()
}

fn ensure_relationship(
    bytes: &[u8],
    rel_type: &str,
    target: &str,
    preferred_id: &str,
) -> Result<Vec<u8>> {
    let mut text = if bytes.is_empty() {
        r#"<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>"#.to_string()
    } else {
        std::str::from_utf8(bytes)
            .context("OPC relationships part is not UTF-8")?
            .to_string()
    };
    text = expand_self_closing_xml_root(&text, "Relationships");
    if text.contains(&format!(r#"Type="{rel_type}""#)) {
        return Ok(text.into_bytes());
    }
    let insert_at = text
        .rfind("</Relationships>")
        .ok_or_else(|| anyhow!("OPC relationships part is missing </Relationships>"))?;
    let id = unique_relationship_id(&text, preferred_id);
    let relationship = format!(r#"<Relationship Id="{id}" Type="{rel_type}" Target="{target}"/>"#);
    let mut out = String::with_capacity(text.len() + relationship.len());
    out.push_str(&text[..insert_at]);
    out.push_str(&relationship);
    out.push_str(&text[insert_at..]);
    Ok(out.into_bytes())
}

/// Turn a self-closing document element (`<Types/>`) into an open/close pair so children can be
/// appended; a document element that already has a separate end tag is left untouched.
fn expand_self_closing_xml_root(text: &str, root: &str) -> String {
    let Some(start) = text.find(&format!("<{root}")) else {
        return text.to_string();
    };
    // End of the document element's start tag (attribute values cannot contain a raw `>`).
    let Some(tag_end) = text[start..].find('>').map(|e| start + e) else {
        return text.to_string();
    };
    if !text[..tag_end].ends_with('/') {
        return text.to_string();
    }
    let end = tag_end - 1;
    let mut out = String::with_capacity(text.len() + root.len() + 3);
    out.push_str(&text[..end]);
    out.push('>');
    out.push_str(&format!("</{root}>"));
    out.push_str(&text[end + 2..]);
    out
}

fn unique_relationship_id(text: &str, preferred_id: &str) -> String {
    if !text.contains(&format!(r#"Id="{preferred_id}""#)) {
        return preferred_id.to_string();
    }
    for i in 2usize.. {
        let candidate = format!("{preferred_id}{i}");
        if !text.contains(&format!(r#"Id="{candidate}""#)) {
            return candidate;
        }
    }
    unreachable!()
}

pub fn embed_signature_xml_path(
    input: &Path,
    output: &Path,
    signature_xml: &[u8],
    overwrite: bool,
) -> Result<()> {
    if signature_xml.is_empty() {
        return Err(anyhow!("VSIX signature XML payload is empty"));
    }
    let info = inspect_vsix_path(input)?;
    if info.has_opc_signature && !overwrite {
        return Err(anyhow!(
            "{} already contains OPC signature parts; pass overwrite to replace them",
            input.display()
        ));
    }
    let reader = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let writer = File::create(output).with_context(|| format!("create {}", output.display()))?;
    embed_signature_xml(reader, writer, signature_xml, overwrite)
        .with_context(|| format!("embed VSIX signature XML into {}", output.display()))
}

/// Embed `signature_xml` into the package as the OPC signature part, adding the signature origin
/// and relationships exactly as [`signature_template`] assumed when digesting the parts.
pub fn embed_signature_xml<R, W>(
    reader: R,
    writer: W,
    signature_xml: &[u8],
    overwrite: bool,
) -> Result<()>
where
    R: Read + std::io::Seek,
    W: Write + std::io::Seek,
{
    if signature_xml.is_empty() {
        return Err(anyhow!("VSIX signature XML payload is empty"));
    }
    write_signed_package(reader, writer, Some(signature_xml), overwrite)
}

/// Copy the package with the OPC signature infrastructure (content types, root origin
/// relationship, origin part and its relationships) and, when given, the signature part.
fn write_signed_package<R, W>(
    reader: R,
    writer: W,
    signature_xml: Option<&[u8]>,
    overwrite: bool,
) -> Result<()>
where
    R: Read + std::io::Seek,
    W: Write + std::io::Seek,
{
    let mut input = zip::ZipArchive::new(reader).context("open VSIX ZIP")?;
    let mut output = zip::ZipWriter::new(writer);
    let mut had_signature = false;
    let mut wrote_content_types = false;
    let mut wrote_root_relationships = false;

    for i in 0..input.len() {
        let mut file = input.by_index(i).context("read VSIX ZIP entry")?;
        let name = normalize_zip_part_name(file.name())?;
        if is_opc_signature_entry(&name) {
            had_signature = true;
            if overwrite {
                continue;
            }
            return Err(anyhow!(
                "package already contains OPC signature parts; pass overwrite to replace them"
            ));
        }

        let options = FileOptions::default().compression_method(file.compression());
        if file.is_dir() {
            output.add_directory(name, options)?;
        } else {
            let mut bytes = Vec::with_capacity(file.size() as usize);
            file.read_to_end(&mut bytes)?;
            if name == CONTENT_TYPES_PART {
                wrote_content_types = true;
                bytes = ensure_signature_content_types(&bytes)?;
            } else if name == ROOT_RELATIONSHIPS_PART {
                wrote_root_relationships = true;
                bytes = ensure_root_signature_origin_relationship(&bytes)?;
            }
            output.start_file(name, options)?;
            output.write_all(&bytes)?;
        }
    }

    if !had_signature || overwrite {
        let stored = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        if !wrote_content_types {
            output.start_file(CONTENT_TYPES_PART, stored)?;
            output.write_all(&ensure_signature_content_types(b"")?)?;
        }
        if !wrote_root_relationships {
            output.start_file(ROOT_RELATIONSHIPS_PART, stored)?;
            output.write_all(&ensure_root_signature_origin_relationship(b"")?)?;
        }
        output.start_file(OPC_SIGNATURE_ORIGIN_PART, stored)?;
        output.write_all(&[])?;
        output.start_file(OPC_SIGNATURE_ORIGIN_RELS_PART, stored)?;
        output.write_all(&signature_origin_relationships_xml())?;
        if let Some(signature_xml) = signature_xml {
            output.start_file(DEFAULT_VSIX_SIGNATURE_PART, stored)?;
            output.write_all(signature_xml)?;
        }
    }
    output.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            let options = FileOptions::default();
            for (name, bytes) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        out.into_inner()
    }

    #[test]
    fn embed_signature_xml_adds_opc_signature_markers() {
        let zip = zip_with(&[("[Content_Types].xml", b"<Types/>")]);
        let mut out = Cursor::new(Vec::new());

        embed_signature_xml(Cursor::new(zip), &mut out, b"<Signature/>", false).unwrap();
        let out = out.into_inner();
        let info = crate::opc::inspect_package_reader(Cursor::new(out.clone())).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(out)).unwrap();
        let mut content_types = String::new();
        archive
            .by_name(CONTENT_TYPES_PART)
            .unwrap()
            .read_to_string(&mut content_types)
            .unwrap();
        let mut root_rels = String::new();
        archive
            .by_name(ROOT_RELATIONSHIPS_PART)
            .unwrap()
            .read_to_string(&mut root_rels)
            .unwrap();
        let mut origin_rels = String::new();
        archive
            .by_name(OPC_SIGNATURE_ORIGIN_RELS_PART)
            .unwrap()
            .read_to_string(&mut origin_rels)
            .unwrap();

        assert!(info.has_opc_signature_origin);
        assert_eq!(info.opc_signature_parts, [DEFAULT_VSIX_SIGNATURE_PART]);
        assert!(content_types.contains(OPC_SIGNATURE_ORIGIN_CONTENT_TYPE));
        assert!(content_types.contains(OPC_SIGNATURE_XML_CONTENT_TYPE));
        assert!(root_rels.contains(OPC_SIGNATURE_ORIGIN_REL_TYPE));
        assert!(origin_rels.contains(OPC_SIGNATURE_REL_TYPE));
    }

    #[test]
    fn signature_infrastructure_keeps_existing_content_types_well_formed() {
        let types = br#"<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="text/xml" /></Types>"#;
        let out = String::from_utf8(ensure_signature_content_types(types).unwrap()).unwrap();
        assert!(
            out.contains(r#"<Default Extension="xml" ContentType="text/xml" />"#),
            "{out}"
        );
        assert_eq!(out.matches("</Types>").count(), 1, "{out}");
        assert!(out.contains(r#"Extension="psdsor""#) && out.contains(r#"Extension="rels""#));

        let empty =
            String::from_utf8(ensure_signature_content_types(b"<Types/>").unwrap()).unwrap();
        assert!(
            empty.starts_with("<Types>") && empty.ends_with("</Types>"),
            "{empty}"
        );
    }

    #[test]
    fn embed_signature_xml_rejects_existing_signature_without_overwrite() {
        let zip = zip_with(&[(DEFAULT_VSIX_SIGNATURE_PART, b"<Signature/>")]);
        let err = embed_signature_xml(Cursor::new(zip), Cursor::new(Vec::new()), b"<New/>", false)
            .unwrap_err();

        assert!(err.to_string().contains("already contains OPC signature"));
    }

    const TYPES: &[u8] = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="vsixmanifest" ContentType="text/xml"/></Types>"#;

    #[test]
    fn signature_reference_xml_covers_every_part_but_the_signature() {
        let zip = zip_with(&[
            ("[Content_Types].xml", TYPES),
            ("extension.vsixmanifest", b"manifest"),
            (DEFAULT_VSIX_SIGNATURE_PART, b"<OldSignature/>"),
        ]);

        let xml = signature_reference_xml(Cursor::new(zip), VsixHashAlgorithm::Sha256).unwrap();
        let text = String::from_utf8(xml.clone()).unwrap();

        assert!(text.contains(r#"<Reference URI="/extension.vsixmanifest?ContentType=text/xml">"#));
        assert!(text.contains(r#"<Reference URI="/_rels/.rels?ContentType=application/vnd.openxmlformats-package.relationships+xml">"#));
        assert!(text.contains(&format!(r#"<Reference URI="/{OPC_SIGNATURE_ORIGIN_PART}?"#)));
        assert!(!text.contains("[Content_Types].xml?"));
        assert!(!text.contains(DEFAULT_VSIX_SIGNATURE_PART));
        assert!(text.contains(r##"<Reference Type="http://www.w3.org/2000/09/xmldsig#Object" URI="#idPackageObject">"##));
        assert_eq!(
            verify_signature_reference_xml(
                Cursor::new(zip_with(&[
                    ("[Content_Types].xml", TYPES),
                    ("extension.vsixmanifest", b"manifest"),
                ])),
                &xml,
                VsixHashAlgorithm::Sha256
            )
            .unwrap(),
            4
        );
    }

    #[test]
    fn signature_reference_xml_detects_tampered_part() {
        let zip = zip_with(&[
            ("[Content_Types].xml", TYPES),
            ("extension.vsixmanifest", b"manifest"),
        ]);
        let xml = signature_reference_xml(Cursor::new(zip), VsixHashAlgorithm::Sha256).unwrap();

        let err = verify_signature_reference_xml(
            Cursor::new(zip_with(&[
                ("[Content_Types].xml", TYPES),
                ("extension.vsixmanifest", b"changed"),
            ])),
            &xml,
            VsixHashAlgorithm::Sha256,
        )
        .unwrap_err();

        assert!(err.to_string().contains("digest mismatch"));
    }

    #[test]
    fn split_signing_steps_produce_identical_signed_info() {
        let zip = zip_with(&[
            ("[Content_Types].xml", TYPES),
            ("extension.vsixmanifest", b"m"),
        ]);
        let first = signed_info_xml(Cursor::new(zip.clone()), VsixHashAlgorithm::Sha256).unwrap();
        let second = signed_info_xml(Cursor::new(zip), VsixHashAlgorithm::Sha256).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with(br#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">"#));
    }

    #[test]
    fn timestamp_is_appended_as_encoded_time_object() {
        let xml = add_signature_timestamp(
            b"<Signature><SignatureValue>AA==</SignatureValue></Signature>",
            b"\x30\x00",
        )
        .unwrap();
        let text = String::from_utf8(xml.clone()).unwrap();
        assert!(
            text.ends_with(r#"<EncodedTime>MAA=</EncodedTime></TimeStamp></Object></Signature>"#),
            "{text}"
        );
        assert!(add_signature_timestamp(&xml, b"\x30\x00").is_err());
    }

    #[test]
    fn extract_signature_xml_returns_embedded_signature_part() {
        let zip = zip_with(&[
            ("[Content_Types].xml", b"<Types/>"),
            (DEFAULT_VSIX_SIGNATURE_PART, b"<Signature/>"),
        ]);

        let xml = extract_signature_xml(Cursor::new(zip)).unwrap();

        assert_eq!(xml, b"<Signature/>");
    }
}
