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

pub fn signature_reference_xml<R>(reader: R, algorithm: VsixHashAlgorithm) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    let signed_info = signed_info_xml(reader, algorithm)?;
    Ok(signature_xml_from_signed_info(&signed_info, &[], None).into_bytes())
}

pub fn signed_info_xml_path(path: &Path, algorithm: VsixHashAlgorithm) -> Result<Vec<u8>> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    signed_info_xml(reader, algorithm)
        .with_context(|| format!("create VSIX SignedInfo XML for {}", path.display()))
}

pub fn signed_info_xml<R>(reader: R, algorithm: VsixHashAlgorithm) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    let references = reference_digests(reader, algorithm)?;
    if references.is_empty() {
        return Err(anyhow!(
            "VSIX package has no non-signature parts to reference"
        ));
    }

    let mut xml = String::new();
    xml.push_str("<SignedInfo>");
    xml.push_str(
        r#"<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
    );
    xml.push_str(&format!(
        r#"<SignatureMethod Algorithm="{}"/>"#,
        algorithm.signature_uri()
    ));
    for (name, digest) in references {
        xml.push_str(&format!(
            r#"<Reference URI="/{}"><DigestMethod Algorithm="{}"/><DigestValue>{}</DigestValue></Reference>"#,
            xml_escape_attr(&name),
            algorithm.digest_uri(),
            BASE64_STANDARD.encode(digest)
        ));
    }
    xml.push_str("</SignedInfo>");
    Ok(xml.into_bytes())
}

pub fn signature_xml_path(
    path: &Path,
    algorithm: VsixHashAlgorithm,
    signature_value: &[u8],
    signer_cert_der: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let signed_info = signed_info_xml_path(path, algorithm)?;
    Ok(signature_xml_from_signed_info(&signed_info, signature_value, signer_cert_der).into_bytes())
}

pub fn signature_xml_from_signed_info(
    signed_info_xml: &[u8],
    signature_value: &[u8],
    signer_cert_der: Option<&[u8]>,
) -> String {
    let signed_info = String::from_utf8_lossy(signed_info_xml);
    let mut xml = String::new();
    xml.push_str(r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">"#);
    xml.push_str(&signed_info);
    xml.push_str("<SignatureValue>");
    xml.push_str(&BASE64_STANDARD.encode(signature_value));
    xml.push_str("</SignatureValue>");
    if let Some(cert) = signer_cert_der {
        xml.push_str("<KeyInfo><X509Data><X509Certificate>");
        xml.push_str(&BASE64_STANDARD.encode(cert));
        xml.push_str("</X509Certificate></X509Data></KeyInfo>");
    }
    xml.push_str("</Signature>");
    xml
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

pub fn verify_signature_reference_xml<R>(
    reader: R,
    signature_xml: &[u8],
    algorithm: VsixHashAlgorithm,
) -> Result<usize>
where
    R: Read + Seek,
{
    let expected = reference_digests(reader, algorithm)?;
    let actual = parse_reference_digests(signature_xml, algorithm)?;
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

fn reference_digests<R>(
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

fn parse_reference_digests(
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
    let needle = format!("{name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_owned())
}

fn xml_escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

fn expand_self_closing_xml_root(text: &str, root: &str) -> String {
    let Some(start) = text.find(&format!("<{root}")) else {
        return text.to_string();
    };
    let Some(end) = text[start..].find("/>") else {
        return text.to_string();
    };
    let end = start + end;
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
        output.start_file(DEFAULT_VSIX_SIGNATURE_PART, stored)?;
        output.write_all(signature_xml)?;
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
    fn embed_signature_xml_rejects_existing_signature_without_overwrite() {
        let zip = zip_with(&[(DEFAULT_VSIX_SIGNATURE_PART, b"<Signature/>")]);
        let err = embed_signature_xml(Cursor::new(zip), Cursor::new(Vec::new()), b"<New/>", false)
            .unwrap_err();

        assert!(err.to_string().contains("already contains OPC signature"));
    }

    #[test]
    fn signature_reference_xml_covers_non_signature_parts() {
        let zip = zip_with(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("extension.vsixmanifest", b"manifest"),
            (DEFAULT_VSIX_SIGNATURE_PART, b"<OldSignature/>"),
        ]);

        let xml = signature_reference_xml(Cursor::new(zip), VsixHashAlgorithm::Sha256).unwrap();
        let text = String::from_utf8(xml.clone()).unwrap();

        assert!(text.contains(r#"<Reference URI="/extension.vsixmanifest">"#));
        assert!(!text.contains(r#"<Reference URI="/[Content_Types].xml">"#));
        assert!(!text.contains(r#"<Reference URI="/_rels/.rels">"#));
        assert!(!text.contains(DEFAULT_VSIX_SIGNATURE_PART));
        assert_eq!(
            verify_signature_reference_xml(
                Cursor::new(zip_with(&[
                    ("[Content_Types].xml", b"<Types/>"),
                    ("extension.vsixmanifest", b"manifest"),
                ])),
                &xml,
                VsixHashAlgorithm::Sha256
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn signature_reference_xml_detects_tampered_part() {
        let zip = zip_with(&[("extension.vsixmanifest", b"manifest")]);
        let xml = signature_reference_xml(Cursor::new(zip), VsixHashAlgorithm::Sha256).unwrap();

        let err = verify_signature_reference_xml(
            Cursor::new(zip_with(&[("extension.vsixmanifest", b"changed")])),
            &xml,
            VsixHashAlgorithm::Sha256,
        )
        .unwrap_err();

        assert!(err.to_string().contains("digest mismatch"));
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
