//! AppxPackaging-compatible ZIP layout, block-map authoring, bundle offset rewriting,
//! and unsigned/signing staging for cleartext MSIX/AppX packages and bundles.
//!
//! Windows `AppxSip.dll` and `makeappx.exe` enforce strict archive invariants beyond
//! generic OPC/ZIP:
//! - central-directory entries must use "version made by" `45` (MS-DOS host, ZIP 4.5)
//!   and zero external file attributes;
//! - archives must end with a ZIP64 end-of-central-directory record, a ZIP64 locator,
//!   and an all-sentinel classic EOCD;
//! - deflated payloads must flush every 64 KiB block independently and declare each
//!   compressed block size in `AppxBlockMap.xml` (`Block/@Size`), with Windows backslash
//!   separators in `File/@Name`;
//! - bundle manifests (`AppxMetadata/AppxBundleManifest.xml`) sign child `Offset` and
//!   `Size` attributes addressing embedded child payload data bytes, while sparse/flat
//!   bundles (`/fb` or `Offset="0"`) reference external children without ZIP entries.

use crate::msix_digest::{self, AppxPackageLayout};
use crate::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use digest::Digest;
use flate2::{Compress, Compression, FlushCompress, Status};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use zip::CompressionMethod;
use zip::read::ZipArchive;

/// Uncompressed bytes per `AppxBlockMap.xml` `<Block>` element.
pub const APPX_BLOCK_SIZE: usize = 64 * 1024;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;
const LOCAL_HEADER_SIG: u32 = 0x0403_4b50;
const CENTRAL_HEADER_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
/// MS-DOS date for 1980-01-01 (time 00:00:00), matching deterministic ZIP defaults.
const DOS_DATE_1980: u16 = 0x21;

const HASH_URI_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const HASH_URI_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const HASH_URI_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

/// Extensions `makeappx` stores without compression because they are already compressed.
const STORED_EXTENSIONS: &[&str] = &[
    "png",
    "jpg",
    "jpeg",
    "gif",
    "zip",
    "gz",
    "7z",
    "cab",
    "appx",
    "msix",
    "appxbundle",
    "msixbundle",
    "eappx",
    "emsix",
    "eappxbundle",
    "emsixbundle",
    "mp3",
    "mp4",
    "wma",
    "wmv",
    "m4a",
];

/// Return `true` when `ext` (lowercase, without leading dot) is `.msixbundle` or `.appxbundle`.
#[must_use]
pub fn is_msix_bundle_extension(ext: &str) -> bool {
    matches!(ext, "msixbundle" | "appxbundle")
}

/// Return `true` when `ext` (lowercase, without leading dot) is a cleartext MSIX/AppX package or bundle.
#[must_use]
pub fn is_cleartext_msix_family_extension(ext: &str) -> bool {
    matches!(ext, "msix" | "appx" | "msixbundle" | "appxbundle")
}

#[derive(Debug)]
pub(crate) struct AppxZipEntry {
    pub(crate) name: String,
    method: u16,
    crc32: u32,
    uncompressed_size: u64,
    data: Vec<u8>,
    /// Compressed size of each 64 KiB block of a deflated entry (`Block/@Size`).
    pub(crate) block_sizes: Option<Vec<u64>>,
}

impl AppxZipEntry {
    /// Construct an uncompressed stored ZIP entry.
    pub(crate) fn stored(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            method: METHOD_STORED,
            crc32: crc32(&data),
            uncompressed_size: data.len() as u64,
            data,
            block_sizes: None,
        }
    }

    /// Construct a payload entry deflated in 64 KiB AppX blocks unless storing is smaller or required.
    pub(crate) fn payload(name: impl Into<String>, data: &[u8]) -> Result<Self> {
        let name = name.into();
        let extension = name
            .rsplit('/')
            .next()
            .and_then(|leaf| leaf.rsplit_once('.'))
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .unwrap_or_default();
        if data.is_empty() || STORED_EXTENSIONS.contains(&extension.as_str()) {
            return Ok(Self::stored(name, data.to_vec()));
        }
        let (compressed, block_sizes) = deflate_appx_blocks(data)?;
        if compressed.len() >= data.len() {
            return Ok(Self::stored(name, data.to_vec()));
        }
        Ok(Self {
            name,
            method: METHOD_DEFLATED,
            crc32: crc32(data),
            uncompressed_size: data.len() as u64,
            data: compressed,
            block_sizes: Some(block_sizes),
        })
    }

    /// Construct an entry copied verbatim (already compressed with `method`) from a staged package.
    pub(crate) fn raw(
        name: impl Into<String>,
        method: u16,
        crc32: u32,
        uncompressed_size: u64,
        data: Vec<u8>,
    ) -> Result<Self> {
        if !matches!(method, METHOD_STORED | METHOD_DEFLATED) {
            bail!("unsupported ZIP compression method {method} in staged MSIX package");
        }
        Ok(Self {
            name: name.into(),
            method,
            crc32,
            uncompressed_size,
            data,
            block_sizes: None,
        })
    }

    /// Local file header byte size, matching `File/@LfhSize`.
    pub(crate) fn local_header_size(&self) -> usize {
        30 + self.name.len()
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

/// Raw-deflate `data` with a full flush after every 64 KiB block so each block decodes independently.
pub(crate) fn deflate_appx_blocks(data: &[u8]) -> Result<(Vec<u8>, Vec<u64>)> {
    let mut compress = Compress::new(Compression::default(), false);
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    let mut block_sizes = Vec::with_capacity(data.len().div_ceil(APPX_BLOCK_SIZE));
    for block in data.chunks(APPX_BLOCK_SIZE) {
        let start = out.len();
        deflate_into(&mut compress, block, FlushCompress::Full, &mut out)?;
        block_sizes.push((out.len() - start) as u64);
    }
    deflate_into(&mut compress, &[], FlushCompress::Finish, &mut out)?;
    Ok((out, block_sizes))
}

fn deflate_into(
    compress: &mut Compress,
    mut input: &[u8],
    flush: FlushCompress,
    out: &mut Vec<u8>,
) -> Result<()> {
    loop {
        out.reserve(input.len() + 1024);
        let before = compress.total_in();
        let status = compress.compress_vec(input, out, flush)?;
        let consumed = usize::try_from(compress.total_in() - before)?;
        input = &input[consumed..];
        if status == Status::StreamEnd
            || (!matches!(flush, FlushCompress::Finish)
                && input.is_empty()
                && out.len() < out.capacity())
        {
            return Ok(());
        }
    }
}

fn u32_field(value: u64, what: &str) -> Result<u32> {
    u32::try_from(value)
        .ok()
        .filter(|&v| v != u32::MAX)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{what} exceeds 4 GiB; portable MSIX signing does not write ZIP64 entries"
            )
        })
}

/// Serialize `entries` in order into an AppxPackaging-layout ZIP archive.
pub(crate) fn write_appx_zip(entries: &[AppxZipEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let name = entry.name.as_bytes();
        let name_len = u16::try_from(name.len())?;
        let flags: u16 = if entry.name.is_ascii() { 0 } else { 1 << 11 };
        let offset = u32_field(out.len() as u64, "MSIX package size")?;
        let compressed_size = u32_field(entry.data.len() as u64, "MSIX entry size")?;
        let uncompressed_size = u32_field(entry.uncompressed_size, "MSIX entry size")?;

        out.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&DOS_DATE_1980.to_le_bytes());
        out.extend_from_slice(&entry.crc32.to_le_bytes());
        out.extend_from_slice(&compressed_size.to_le_bytes());
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&entry.data);

        central.extend_from_slice(&CENTRAL_HEADER_SIG.to_le_bytes());
        central.extend_from_slice(&45u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&entry.method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&DOS_DATE_1980.to_le_bytes());
        central.extend_from_slice(&entry.crc32.to_le_bytes());
        central.extend_from_slice(&compressed_size.to_le_bytes());
        central.extend_from_slice(&uncompressed_size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&[0; 8]);
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let entry_count = u16::try_from(entries.len())
        .ok()
        .filter(|&n| n != u16::MAX)
        .ok_or_else(|| anyhow::anyhow!("too many MSIX package entries"))?;
    let cd_offset = u32_field(out.len() as u64, "MSIX package size")?;
    let cd_size = u32_field(central.len() as u64, "MSIX central directory size")?;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    msix_digest::normalize_zip_for_appx_signing(out)
}

fn block_map_hash_method_uri(hash_kind: PeAuthenticodeHashKind) -> Result<&'static str> {
    match hash_kind {
        PeAuthenticodeHashKind::Sha256 => Ok(HASH_URI_SHA256),
        PeAuthenticodeHashKind::Sha384 => Ok(HASH_URI_SHA384),
        PeAuthenticodeHashKind::Sha512 => Ok(HASH_URI_SHA512),
        PeAuthenticodeHashKind::Sha1 => {
            bail!("MSIX/AppX AppxBlockMap.xml requires SHA-256, SHA-384, or SHA-512; got SHA-1")
        }
    }
}

fn hash_block(chunk: &[u8], hash_kind: PeAuthenticodeHashKind) -> Result<Vec<u8>> {
    match hash_kind {
        PeAuthenticodeHashKind::Sha256 => Ok(sha2::Sha256::digest(chunk).to_vec()),
        PeAuthenticodeHashKind::Sha384 => Ok(sha2::Sha384::digest(chunk).to_vec()),
        PeAuthenticodeHashKind::Sha512 => Ok(sha2::Sha512::digest(chunk).to_vec()),
        PeAuthenticodeHashKind::Sha1 => {
            bail!("MSIX/AppX AppxBlockMap.xml requires SHA-256, SHA-384, or SHA-512; got SHA-1")
        }
    }
}

fn xml_escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn build_flat_msix_block_map(
    payloads: &[(String, Vec<u8>)],
    entries: &[AppxZipEntry],
    hash_kind: PeAuthenticodeHashKind,
) -> Result<String> {
    let hash_method = block_map_hash_method_uri(hash_kind)?;
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="{hash_method}">"#
    );
    for ((name, data), entry) in payloads.iter().zip(entries) {
        let block_map_name = name.replace('/', "\\");
        let escaped_name = xml_escape_attr(&block_map_name);
        xml.push_str(&format!(
            r#"<File Name="{escaped_name}" Size="{}" LfhSize="{}">"#,
            data.len(),
            entry.local_header_size()
        ));
        let block_sizes = entry.block_sizes.as_deref().unwrap_or_default();
        for (index, chunk) in data.chunks(APPX_BLOCK_SIZE).enumerate() {
            let digest = hash_block(chunk, hash_kind)?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
            match block_sizes.get(index) {
                Some(size) => xml.push_str(&format!(r#"<Block Hash="{encoded}" Size="{size}"/>"#)),
                None => xml.push_str(&format!(r#"<Block Hash="{encoded}"/>"#)),
            }
        }
        xml.push_str("</File>");
    }
    xml.push_str("</BlockMap>");
    Ok(xml)
}

fn build_msix_bundle_block_map(
    manifest: &[u8],
    hash_kind: PeAuthenticodeHashKind,
) -> Result<String> {
    let hash_method = block_map_hash_method_uri(hash_kind)?;
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?><BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="{hash_method}"><File Name="AppxMetadata\AppxBundleManifest.xml" Size="{}" LfhSize="65">"#,
        manifest.len()
    );
    for chunk in manifest.chunks(APPX_BLOCK_SIZE) {
        let digest = hash_block(chunk, hash_kind)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
        xml.push_str(&format!(
            r#"<Block Hash="{encoded}" Size="{}"/>"#,
            chunk.len()
        ));
    }
    xml.push_str("</File></BlockMap>");
    Ok(xml)
}

/// Rewrite `<Package>` child `Offset` and `Size` attributes in `AppxBundleManifest.xml` to
/// match the stored local headers of `children`, while preserving external sparse/flat-bundle
/// `<Package>` references (`/fb` omits `Offset`/`Size`; flat bundles may declare `Offset="0"`).
///
/// # Errors
///
/// Returns an error if `manifest` is malformed XML, a `<Package>` lacks `FileName`, or an
/// expected embedded child (`Offset` present and non-zero) is missing from `children`.
pub fn bundle_manifest_for_stored_children(
    manifest: &[u8],
    children: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    let mut locations = HashMap::with_capacity(children.len());
    let mut offset = 0u64;
    for (name, data) in children {
        let logical_name = msix_digest::decode_opc_zip_part_name(name)?;
        let opc_name = msix_digest::encode_opc_part_name(&logical_name);
        let entry = AppxZipEntry::stored(&opc_name, Vec::new());
        offset = offset
            .checked_add(entry.local_header_size() as u64)
            .context("bundle child header offset overflow")?;
        locations.insert(logical_name, (offset, data.len() as u64));
        offset = offset
            .checked_add(data.len() as u64)
            .context("bundle child data offset overflow")?;
    }

    let mut reader = Reader::from_reader(manifest);
    let mut writer = Writer::new(Vec::with_capacity(manifest.len()));
    loop {
        let event = reader.read_event().context("read MSIX bundle manifest")?;
        let updated = match &event {
            Event::Start(element) | Event::Empty(element)
                if element.local_name().as_ref() == b"Package" =>
            {
                let mut file_name = None;
                let mut declared_offset: Option<(Vec<u8>, String)> = None;
                let mut declared_size: Option<(Vec<u8>, String)> = None;
                let mut replacement = element.to_owned();
                replacement.clear_attributes();
                for attribute in element.attributes() {
                    let attribute = attribute.context("read bundle Package attribute")?;
                    match attribute.key.as_ref() {
                        b"FileName" => {
                            file_name = Some(
                                attribute
                                    .decode_and_unescape_value(reader.decoder())?
                                    .replace('\\', "/"),
                            );
                            replacement.push_attribute(attribute);
                        }
                        b"Offset" => {
                            let val = attribute
                                .decode_and_unescape_value(reader.decoder())?
                                .into_owned();
                            declared_offset = Some((attribute.key.as_ref().to_vec(), val));
                        }
                        b"Size" => {
                            let val = attribute
                                .decode_and_unescape_value(reader.decoder())?
                                .into_owned();
                            declared_size = Some((attribute.key.as_ref().to_vec(), val));
                        }
                        _ => replacement.push_attribute(attribute),
                    }
                }
                let file_name = file_name.context("bundle Package is missing FileName")?;
                if let Some(&(child_offset, child_size)) = locations.get(file_name.as_str()) {
                    let offset_str = child_offset.to_string();
                    let size_str = child_size.to_string();
                    replacement.push_attribute(("Offset", offset_str.as_str()));
                    replacement.push_attribute(("Size", size_str.as_str()));
                } else {
                    let expects_embedded = declared_offset
                        .as_ref()
                        .is_some_and(|(_, val)| !val.trim().is_empty() && val.trim() != "0");
                    if expects_embedded {
                        bail!("bundle child `{file_name}` is missing from ZIP");
                    }
                    if let Some((key, val)) = &declared_offset {
                        replacement.push_attribute((key.as_slice(), val.as_bytes()));
                    }
                    if let Some((key, val)) = &declared_size {
                        replacement.push_attribute((key.as_slice(), val.as_bytes()));
                    }
                }
                Some(if matches!(event, Event::Start(_)) {
                    Event::Start(replacement)
                } else {
                    Event::Empty(replacement)
                })
            }
            Event::Eof => break,
            _ => None,
        };
        writer.write_event(updated.unwrap_or(event))?;
    }
    Ok(writer.into_inner())
}

/// Stage a cleartext `.msix`, `.appx`, `.msixbundle`, or `.appxbundle` archive for signing,
/// inserting a `PKCX` placeholder `AppxSignature.p7x` as the final ZIP entry.
///
/// # Errors
///
/// Returns an error if `package` is not a valid package/bundle ZIP, uses an unsupported
/// digest algorithm, references missing embedded children, or embeds encrypted children.
pub fn stage_msix_family_for_signature(
    package: &[u8],
    ext: &str,
    hash_kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    let ext_lower = ext.to_ascii_lowercase();
    if is_msix_bundle_extension(&ext_lower) {
        stage_msix_bundle_internal(package, hash_kind, true)
    } else {
        stage_flat_msix_internal(package, hash_kind, true)
    }
}

/// Restage an unsigned cleartext `.msix`, `.appx`, `.msixbundle`, or `.appxbundle` archive
/// into AppxPackaging ZIP64 layout with regenerated `AppxBlockMap.xml`, `[Content_Types].xml`,
/// and (for bundles) recalculated child `Offset`/`Size` attributes, without `AppxSignature.p7x`.
///
/// When `hash_kind` is `None`, any existing `AppxBlockMap.xml` `HashMethod` is preserved
/// (defaulting to SHA-256 when absent).
///
/// # Errors
///
/// Returns an error if `package` is already signed (`AppxSignature.p7x` present), uses an
/// encrypted extension, or has malformed manifest/ZIP state.
pub fn restage_unsigned_msix_family_bytes(
    package: &[u8],
    ext: &str,
    hash_kind: Option<PeAuthenticodeHashKind>,
) -> Result<Vec<u8>> {
    let ext_lower = ext.to_ascii_lowercase();
    if msix_digest::is_encrypted_msix_extension(&ext_lower) {
        bail!(
            "encrypted MSIX/AppX packages (.{ext_lower}) require Windows AppxSip OS delegation; portable cleartext package helpers cannot restage encrypted stores"
        );
    }
    if msix_digest::msix_signature_part_present(package)? {
        bail!(
            "MSIX/AppX package already contains AppxSignature.p7x; update the unsigned package before final signing"
        );
    }
    let resolved_hash = match hash_kind {
        Some(k) => k,
        None => msix_digest::detect_block_map_hash_kind(package)?
            .unwrap_or(PeAuthenticodeHashKind::Sha256),
    };
    let is_bundle = detect_is_bundle_archive(package, &ext_lower)?;
    if is_bundle {
        stage_msix_bundle_internal(package, resolved_hash, false)
    } else {
        stage_flat_msix_internal(package, resolved_hash, false)
    }
}

/// Update `Identity/@Publisher` (and bundle `Package/@Publisher` plus unsigned embedded child
/// manifests) on an unsigned MSIX/AppX package or bundle and restage it in AppxPackaging layout.
///
/// # Errors
///
/// Returns an error if `publisher` is empty, `package` is encrypted or already signed, or
/// required manifests are missing/malformed.
pub fn set_unsigned_msix_family_publisher_bytes(
    package: &[u8],
    ext: &str,
    publisher: &str,
) -> Result<Vec<u8>> {
    let ext_lower = ext.to_ascii_lowercase();
    if msix_digest::is_encrypted_msix_extension(&ext_lower) {
        bail!(
            "encrypted MSIX/AppX packages (.eappx/.emsix) require Windows AppxSip OS delegation; portable cleartext package helpers cannot inspect or update encrypted stores"
        );
    }
    if publisher.is_empty() {
        bail!("MSIX/AppX publisher cannot be empty");
    }
    if msix_digest::msix_signature_part_present(package)? {
        bail!(
            "MSIX/AppX package already contains AppxSignature.p7x; update the unsigned package before final signing"
        );
    }
    let hash_kind =
        msix_digest::detect_block_map_hash_kind(package)?.unwrap_or(PeAuthenticodeHashKind::Sha256);
    let is_bundle = detect_is_bundle_archive(package, &ext_lower)?;
    if is_bundle {
        set_bundle_publisher_and_restage(package, publisher, hash_kind)
    } else {
        set_flat_publisher_and_restage(package, publisher, hash_kind)
    }
}

/// Replace `AppxSignature.p7x` in a staged MSIX/AppX archive with `p7x`, copying every other
/// entry's compressed bytes verbatim so the signed `AXPC`/`AXCD` digests hold.
///
/// # Errors
///
/// Returns an error if `package` is not a readable staged archive or uses unsupported compression.
pub fn replace_msix_signature_part(package: &[u8], p7x: &[u8]) -> Result<Vec<u8>> {
    let mut source = ZipArchive::new(Cursor::new(package)).context("open staged MSIX ZIP")?;
    let mut entries = Vec::with_capacity(source.len());
    for i in 0..source.len() {
        let mut entry = source
            .by_index_raw(i)
            .context("read staged MSIX ZIP entry")?;
        let name = entry.name().to_owned();
        if name == "AppxSignature.p7x" {
            entries.push(AppxZipEntry::stored(name, p7x.to_vec()));
            continue;
        }
        let method = match entry.compression() {
            CompressionMethod::Stored => METHOD_STORED,
            CompressionMethod::Deflated => METHOD_DEFLATED,
            other => bail!("unsupported compression {other:?} in staged MSIX entry `{name}`"),
        };
        let crc32 = entry.crc32();
        let size = entry.size();
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        entries.push(AppxZipEntry::raw(name, method, crc32, size, data)?);
    }
    write_appx_zip(&entries)
}

fn detect_is_bundle_archive(package: &[u8], ext_lower: &str) -> Result<bool> {
    let mut archive = ZipArchive::new(Cursor::new(package)).context("open MSIX/AppX ZIP")?;
    let has_flat = archive.by_name("AppxManifest.xml").is_ok();
    let has_bundle = archive
        .by_name("AppxMetadata/AppxBundleManifest.xml")
        .is_ok();
    if is_msix_bundle_extension(ext_lower) {
        if !has_bundle {
            bail!("MSIX bundle is missing AppxMetadata/AppxBundleManifest.xml");
        }
        return Ok(true);
    }
    if matches!(ext_lower, "msix" | "appx") {
        if !has_flat {
            bail!("flat MSIX package is missing AppxManifest.xml");
        }
        return Ok(false);
    }
    if has_flat {
        Ok(false)
    } else if has_bundle {
        Ok(true)
    } else {
        bail!(
            "MSIX/AppX package is missing AppxManifest.xml (or AppxMetadata/AppxBundleManifest.xml for bundles)"
        )
    }
}

fn stage_flat_msix_internal(
    package: &[u8],
    hash_kind: PeAuthenticodeHashKind,
    include_signature_placeholder: bool,
) -> Result<Vec<u8>> {
    let mut source = ZipArchive::new(Cursor::new(package)).context("open MSIX ZIP")?;
    let mut payloads = Vec::new();
    let mut content_types = None;

    for i in 0..source.len() {
        let mut entry = source.by_index(i).context("read MSIX ZIP entry")?;
        let name = entry.name().replace('\\', "/");
        if name.ends_with('/') {
            continue;
        }
        match name.as_str() {
            "[Content_Types].xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                content_types = Some(data);
            }
            "AppxBlockMap.xml" | "AppxSignature.p7x" | "AppxMetadata/CodeIntegrity.cat" => {}
            _ => {
                let logical_name = msix_digest::decode_opc_zip_part_name(&name)?;
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                payloads.push((logical_name, data));
            }
        }
    }

    if !payloads.iter().any(|(name, _)| name == "AppxManifest.xml") {
        bail!("flat MSIX package is missing AppxManifest.xml");
    }
    let part_names: Vec<&str> = payloads.iter().map(|(name, _)| name.as_str()).collect();
    let content_types = if include_signature_placeholder {
        msix_digest::appx_content_types_for_signing(content_types.as_deref(), &part_names, false)?
    } else {
        msix_digest::appx_content_types_for_unsigned_package(
            content_types.as_deref(),
            &part_names,
            AppxPackageLayout::Flat,
        )?
    };
    let mut entries = payloads
        .iter()
        .map(|(logical_name, data)| {
            let opc_name = msix_digest::encode_opc_part_name(logical_name);
            AppxZipEntry::payload(opc_name, data)
        })
        .collect::<Result<Vec<_>>>()?;
    let block_map = build_flat_msix_block_map(&payloads, &entries, hash_kind)?;

    entries.push(AppxZipEntry::payload(
        "AppxBlockMap.xml",
        block_map.as_bytes(),
    )?);
    entries.push(AppxZipEntry::payload(
        "[Content_Types].xml",
        content_types.as_bytes(),
    )?);
    if include_signature_placeholder {
        entries.push(AppxZipEntry::stored("AppxSignature.p7x", b"PKCX".to_vec()));
    }
    write_appx_zip(&entries)
}

fn stage_msix_bundle_internal(
    package: &[u8],
    hash_kind: PeAuthenticodeHashKind,
    include_signature_placeholder: bool,
) -> Result<Vec<u8>> {
    let mut source = ZipArchive::new(Cursor::new(package)).context("open MSIX bundle ZIP")?;
    let mut child_payloads: Vec<(String, Vec<u8>)> = Vec::new();
    let mut bundle_manifest: Option<Vec<u8>> = None;
    let mut bundle_content_types: Option<Vec<u8>> = None;

    for i in 0..source.len() {
        let mut entry = source.by_index(i).context("read MSIX bundle ZIP entry")?;
        let name = entry.name().replace('\\', "/");
        if name.ends_with('/') {
            continue;
        }
        match name.as_str() {
            "AppxMetadata/AppxBundleManifest.xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                bundle_manifest = Some(data);
            }
            "[Content_Types].xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                bundle_content_types = Some(data);
            }
            "AppxBlockMap.xml"
            | "AppxSignature.p7x"
            | "AppxManifest.xml"
            | "AppxMetadata/CodeIntegrity.cat" => {}
            _ => {
                let logical_name = msix_digest::decode_opc_zip_part_name(&name)?;
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                child_payloads.push((logical_name, data));
            }
        }
    }

    let manifest = bundle_manifest.ok_or_else(|| {
        anyhow::anyhow!("MSIX bundle is missing AppxMetadata/AppxBundleManifest.xml")
    })?;
    let mut part_names: Vec<&str> = child_payloads
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    part_names.push("AppxMetadata/AppxBundleManifest.xml");
    let content_types = if include_signature_placeholder {
        msix_digest::appx_content_types_for_signing(
            bundle_content_types.as_deref(),
            &part_names,
            true,
        )?
    } else {
        msix_digest::appx_content_types_for_unsigned_package(
            bundle_content_types.as_deref(),
            &part_names,
            AppxPackageLayout::Bundle,
        )?
    };
    for (name, _data) in &child_payloads {
        let child_ext = name
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .unwrap_or_default();
        if msix_digest::is_encrypted_msix_extension(&child_ext) {
            bail!(
                "cleartext MSIX bundle contains encrypted child package `{name}`; encrypted children require Windows AppxSip OS delegation"
            );
        }
    }
    let manifest = bundle_manifest_for_stored_children(&manifest, &child_payloads)?;
    let block_map = build_msix_bundle_block_map(&manifest, hash_kind)?;

    let mut entries: Vec<AppxZipEntry> = child_payloads
        .into_iter()
        .map(|(logical_name, data)| {
            AppxZipEntry::stored(msix_digest::encode_opc_part_name(&logical_name), data)
        })
        .collect();
    entries.push(AppxZipEntry::stored(
        "AppxMetadata/AppxBundleManifest.xml",
        manifest,
    ));
    entries.push(AppxZipEntry::payload(
        "AppxBlockMap.xml",
        block_map.as_bytes(),
    )?);
    entries.push(AppxZipEntry::payload(
        "[Content_Types].xml",
        content_types.as_bytes(),
    )?);
    if include_signature_placeholder {
        entries.push(AppxZipEntry::stored("AppxSignature.p7x", b"PKCX".to_vec()));
    }
    write_appx_zip(&entries)
}

fn set_flat_publisher_and_restage(
    package: &[u8],
    publisher: &str,
    hash_kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    let mut source = ZipArchive::new(Cursor::new(package)).context("open MSIX/AppX ZIP")?;
    let mut payloads = Vec::new();
    let mut content_types = None;
    let mut updated_manifest = false;

    for i in 0..source.len() {
        let mut entry = source.by_index(i).context("read MSIX/AppX ZIP entry")?;
        let name = entry.name().replace('\\', "/");
        if name.ends_with('/') {
            continue;
        }
        match name.as_str() {
            "[Content_Types].xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                content_types = Some(data);
            }
            "AppxBlockMap.xml" | "AppxSignature.p7x" | "AppxMetadata/CodeIntegrity.cat" => {}
            "AppxManifest.xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                let rewritten = rewrite_xml_publisher(&data, &[b"Identity"], publisher)
                    .context("rewrite AppxManifest.xml Publisher")?;
                payloads.push((name, rewritten));
                updated_manifest = true;
            }
            _ => {
                let logical_name = msix_digest::decode_opc_zip_part_name(&name)?;
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                payloads.push((logical_name, data));
            }
        }
    }
    if !updated_manifest {
        bail!("flat MSIX package is missing AppxManifest.xml");
    }

    let part_names: Vec<&str> = payloads.iter().map(|(name, _)| name.as_str()).collect();
    let content_types = msix_digest::appx_content_types_for_unsigned_package(
        content_types.as_deref(),
        &part_names,
        AppxPackageLayout::Flat,
    )?;
    let mut entries = payloads
        .iter()
        .map(|(logical_name, data)| {
            AppxZipEntry::payload(msix_digest::encode_opc_part_name(logical_name), data)
        })
        .collect::<Result<Vec<_>>>()?;
    let block_map = build_flat_msix_block_map(&payloads, &entries, hash_kind)?;
    entries.push(AppxZipEntry::payload(
        "AppxBlockMap.xml",
        block_map.as_bytes(),
    )?);
    entries.push(AppxZipEntry::payload(
        "[Content_Types].xml",
        content_types.as_bytes(),
    )?);
    write_appx_zip(&entries)
}

fn set_bundle_publisher_and_restage(
    package: &[u8],
    publisher: &str,
    hash_kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    let mut source = ZipArchive::new(Cursor::new(package)).context("open MSIX/AppX bundle ZIP")?;
    let mut child_payloads: Vec<(String, Vec<u8>)> = Vec::new();
    let mut bundle_manifest: Option<Vec<u8>> = None;
    let mut bundle_content_types: Option<Vec<u8>> = None;

    for i in 0..source.len() {
        let mut entry = source.by_index(i).context("read MSIX bundle ZIP entry")?;
        let name = entry.name().replace('\\', "/");
        if name.ends_with('/') {
            continue;
        }
        match name.as_str() {
            "AppxMetadata/AppxBundleManifest.xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                let rewritten = rewrite_xml_publisher(&data, &[b"Identity", b"Package"], publisher)
                    .context("rewrite AppxBundleManifest.xml Publisher")?;
                bundle_manifest = Some(rewritten);
            }
            "[Content_Types].xml" => {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                bundle_content_types = Some(data);
            }
            "AppxBlockMap.xml"
            | "AppxSignature.p7x"
            | "AppxManifest.xml"
            | "AppxMetadata/CodeIntegrity.cat" => {}
            _ => {
                let logical_name = msix_digest::decode_opc_zip_part_name(&name)?;
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;
                let child_ext = logical_name
                    .rsplit_once('.')
                    .map(|(_, ext)| ext.to_ascii_lowercase())
                    .unwrap_or_default();
                if msix_digest::is_encrypted_msix_extension(&child_ext) {
                    bail!(
                        "cleartext MSIX bundle contains encrypted child package `{logical_name}`; encrypted children require Windows AppxSip OS delegation"
                    );
                }
                if is_cleartext_msix_family_extension(&child_ext) {
                    if msix_digest::msix_signature_part_present(&data)? {
                        bail!(
                            "bundle child `{logical_name}` already contains AppxSignature.p7x; update unsigned children before changing bundle publisher"
                        );
                    }
                    let updated_child =
                        set_unsigned_msix_family_publisher_bytes(&data, &child_ext, publisher)
                            .with_context(|| {
                                format!("update Publisher in bundle child `{logical_name}`")
                            })?;
                    child_payloads.push((logical_name, updated_child));
                } else {
                    child_payloads.push((logical_name, data));
                }
            }
        }
    }

    let manifest = bundle_manifest.ok_or_else(|| {
        anyhow::anyhow!("MSIX bundle is missing AppxMetadata/AppxBundleManifest.xml")
    })?;
    let mut part_names: Vec<&str> = child_payloads
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    part_names.push("AppxMetadata/AppxBundleManifest.xml");
    let content_types = msix_digest::appx_content_types_for_unsigned_package(
        bundle_content_types.as_deref(),
        &part_names,
        AppxPackageLayout::Bundle,
    )?;
    let manifest = bundle_manifest_for_stored_children(&manifest, &child_payloads)?;
    let block_map = build_msix_bundle_block_map(&manifest, hash_kind)?;

    let mut entries: Vec<AppxZipEntry> = child_payloads
        .into_iter()
        .map(|(logical_name, data)| {
            AppxZipEntry::stored(msix_digest::encode_opc_part_name(&logical_name), data)
        })
        .collect();
    entries.push(AppxZipEntry::stored(
        "AppxMetadata/AppxBundleManifest.xml",
        manifest,
    ));
    entries.push(AppxZipEntry::payload(
        "AppxBlockMap.xml",
        block_map.as_bytes(),
    )?);
    entries.push(AppxZipEntry::payload(
        "[Content_Types].xml",
        content_types.as_bytes(),
    )?);
    write_appx_zip(&entries)
}

fn rewrite_xml_publisher(
    xml: &[u8],
    target_local_names: &[&[u8]],
    publisher: &str,
) -> Result<Vec<u8>> {
    let mut reader = Reader::from_reader(xml);
    let mut writer = Writer::new(Vec::with_capacity(xml.len() + publisher.len()));
    loop {
        let event = reader.read_event().context("parse manifest XML")?;
        let updated = match &event {
            Event::Start(element) | Event::Empty(element)
                if target_local_names
                    .iter()
                    .any(|&name| element.local_name().as_ref() == name) =>
            {
                let replacement = replace_element_publisher(element, publisher)?;
                Some(if matches!(event, Event::Start(_)) {
                    Event::Start(replacement)
                } else {
                    Event::Empty(replacement)
                })
            }
            Event::Eof => break,
            _ => None,
        };
        writer.write_event(updated.unwrap_or(event))?;
    }
    Ok(writer.into_inner())
}

fn replace_element_publisher<'a>(
    element: &BytesStart<'a>,
    publisher: &str,
) -> Result<BytesStart<'static>> {
    let insert_if_missing = element.local_name().as_ref() == b"Identity";
    let mut replacement = element.to_owned();
    replacement.clear_attributes();
    let mut replaced = false;
    for attribute in element.attributes() {
        let attribute = attribute.context("read XML attribute")?;
        if attribute.key.as_ref() == b"Publisher" {
            replacement.push_attribute(("Publisher", publisher));
            replaced = true;
        } else {
            replacement.push_attribute(attribute);
        }
    }
    if !replaced && insert_if_missing {
        replacement.push_attribute(("Publisher", publisher));
    }
    Ok(replacement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Decompress, FlushDecompress};

    #[test]
    fn each_deflated_block_inflates_independently() {
        let data: Vec<u8> = (0..(APPX_BLOCK_SIZE * 2 + 1234))
            .map(|i| ((i / 17) & 0xff) as u8)
            .collect();
        let (compressed, sizes) = deflate_appx_blocks(&data).unwrap();
        assert_eq!(sizes.len(), data.len().div_ceil(APPX_BLOCK_SIZE));

        let mut cursor = 0usize;
        for (block, size) in data.chunks(APPX_BLOCK_SIZE).zip(&sizes) {
            let end = cursor + usize::try_from(*size).unwrap();
            let mut decoded = vec![0u8; block.len() + 16];
            let mut inflate = Decompress::new(false);
            inflate
                .decompress(
                    &compressed[cursor..end],
                    &mut decoded,
                    FlushDecompress::Sync,
                )
                .unwrap();
            let written = usize::try_from(inflate.total_out()).unwrap();
            assert_eq!(&decoded[..written], block);
            cursor = end;
        }
        assert!(
            compressed.len() > cursor,
            "stream must end with final block"
        );
    }

    #[test]
    fn payload_entry_stores_media_empty_and_incompressible_files() {
        assert_eq!(AppxZipEntry::payload("empty.txt", b"").unwrap().method, 0);
        assert_eq!(
            AppxZipEntry::payload("Assets/logo.png", &[7; 4096])
                .unwrap()
                .method,
            0
        );
        let mut state = 0x1234_5678u32;
        let noise: Vec<u8> = (0..1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let entry = AppxZipEntry::payload("noise.bin", &noise).unwrap();
        assert_eq!(entry.method, 0);

        let text = AppxZipEntry::payload("index.db", &[b'a'; 70_000]).unwrap();
        assert_eq!(text.method, 8);
        assert_eq!(text.block_sizes.unwrap().len(), 2);
    }

    #[test]
    fn u32_field_enforces_non_sentinel_4gib_boundary() {
        assert_eq!(
            u32_field(u64::from(u32::MAX) - 1, "test size").unwrap(),
            u32::MAX - 1
        );
        assert!(
            u32_field(u64::from(u32::MAX), "test size")
                .unwrap_err()
                .to_string()
                .contains("exceeds 4 GiB")
        );
        assert!(
            u32_field(u64::from(u32::MAX) + 1, "test size")
                .unwrap_err()
                .to_string()
                .contains("exceeds 4 GiB")
        );
    }

    #[test]
    fn bundle_manifest_supports_sparse_external_and_embedded_children() {
        let sparse_manifest = br#"<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Packages><Package Type="application" FileName="external-x64.msix"/><Package Type="application" FileName="flat-zero.msix" Offset="0" Size="1234"/></Packages></Bundle>"#;
        let updated = bundle_manifest_for_stored_children(sparse_manifest, &[]).unwrap();
        let xml = std::str::from_utf8(&updated).unwrap();
        assert!(
            xml.contains(r#"FileName="external-x64.msix""#)
                && !xml.contains(r#"external-x64.msix" Offset="#),
            "sparse /fb child without Offset must stay external: {xml}"
        );
        assert!(
            xml.contains(r#"FileName="flat-zero.msix" Offset="0" Size="1234""#),
            "flat-bundle Offset=0 reference must be preserved: {xml}"
        );

        let missing_embedded = br#"<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Packages><Package Type="application" FileName="embedded.msix" Offset="73" Size="500"/></Packages></Bundle>"#;
        assert!(
            bundle_manifest_for_stored_children(missing_embedded, &[])
                .unwrap_err()
                .to_string()
                .contains("missing from ZIP")
        );
    }

    #[test]
    fn bundle_block_map_uses_canonical_sha384_and_sha512_uris() {
        let sha384 =
            build_msix_bundle_block_map(b"<Bundle/>", PeAuthenticodeHashKind::Sha384).unwrap();
        assert!(
            sha384.contains(r#"HashMethod="http://www.w3.org/2001/04/xmldsig-more#sha384""#),
            "unexpected SHA-384 URI: {sha384}"
        );
        let sha512 =
            build_msix_bundle_block_map(b"<Bundle/>", PeAuthenticodeHashKind::Sha512).unwrap();
        assert!(
            sha512.contains(r#"HashMethod="http://www.w3.org/2001/04/xmlenc#sha512""#),
            "unexpected SHA-512 URI: {sha512}"
        );
    }

    #[test]
    fn bundle_publisher_rewrite_preserves_xsd_valid_package_elements() {
        let xml = br#"<Bundle SchemaVersion="4.0" xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Demo" Publisher="CN=Old" Version="1.0.0.0"/><Packages><Package Type="application" Version="1.0.0.0" Architecture="x64" FileName="app.msix" Offset="73" Size="500"/></Packages></Bundle>"#;
        let rewritten = String::from_utf8(
            rewrite_xml_publisher(xml, &[b"Identity", b"Package"], "CN=New, O=\"Lab & Co\"")
                .unwrap(),
        )
        .unwrap();
        assert!(
            rewritten.contains(r#"Identity Name="Demo" Publisher="CN=New, O=&quot;Lab &amp; Co&quot;" Version="1.0.0.0""#),
            "Identity@Publisher was not updated: {rewritten}"
        );
        assert!(
            !rewritten.contains(r#"Package Type="application" Version="1.0.0.0" Architecture="x64" FileName="app.msix" Offset="73" Size="500" Publisher="#)
                && rewritten.matches("Publisher=").count() == 1,
            "Package element must not gain a schema-invalid Publisher attribute: {rewritten}"
        );
    }
}
