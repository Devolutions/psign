//! MSIX / APPX **flat package** and **bundle** digest (`AppxSip.dll`) vs PKCS#7 `SpcIndirectData` APPX blob.
//!
//! Digest layout follows **osslsigncode** [`appx.c`](https://github.com/mtrojnar/osslsigncode/blob/master/appx.c):
//! strip **PKCX** from `AppxSignature.p7x`, parse Authenticode `SpcIndirectData`, then compare the
//! **APPX + AXPC + AXCD + AXCT + AXBM [+ AXCI]** blob with hashes recomputed from the ZIP layout.
//!
//! **Bundles** (`.msixbundle` / `.appxbundle`, or any ZIP that contains `AppxMetadata/AppxBundleManifest.xml`)
//! use the **same** ZIP hash pipeline as flat packages in `appx.c` (`appx_calculate_hashes`); only the
//! **SpcSipInfo** UUID embedded at **sign** time differs (`APPXBUNDLE_UUID` vs `APPX_UUID`). Windows may route
//! verification through **`AppxBundleSip*`** COM helpers, but the recomputed PKCS#7 indirect digest matches this
//! implementation (aligned with **`AppxSip.dll`** behavior; see **`docs/windows-signing-components.md`**).

use crate::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use base64::Engine as _;
use digest::Digest;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::path::Path;
use zip::CompressionMethod;
use zip::read::ZipArchive;
use zip::read::ZipFile;

const APP_SIGNATURE: &[u8] = b"AppxSignature.p7x";
const CONTENT_TYPES: &[u8] = b"[Content_Types].xml";
const BLOCK_MAP: &[u8] = b"AppxBlockMap.xml";
const APP_MANIFEST: &[u8] = b"AppxManifest.xml";
const BUNDLE_MANIFEST: &[u8] = b"AppxMetadata/AppxBundleManifest.xml";
const CODE_INTEGRITY: &[u8] = b"AppxMetadata/CodeIntegrity.cat";

const SIG_APPX: &[u8] = b"APPX";
const TAG_AXPC: &[u8] = b"AXPC";
const TAG_AXCD: &[u8] = b"AXCD";
const TAG_AXCT: &[u8] = b"AXCT";
const TAG_AXBM: &[u8] = b"AXBM";
const TAG_AXCI: &[u8] = b"AXCI";

const HASH_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const HASH_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const HASH_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

const ZIP64_EXTRA_ID: u16 = 0x0001;

const LH_SIG: u32 = 0x0403_4b50;
const CD_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOC_SIG: u32 = 0x0706_4b50;

const DATA_DESCRIPTOR_BIT: u16 = 1 << 3;
const DD_SIG: u32 = 0x0807_4b50;

const APPX_BLOCK_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
struct AppxDigestParts {
    axpc: Vec<u8>,
    axcd: Vec<u8>,
    axct: Vec<u8>,
    axbm: Vec<u8>,
    axci: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct ClassicEocd {
    disk_number: u16,
    disk_with_central_directory: u16,
    number_of_files_on_this_disk: u16,
    number_of_files: u16,
    central_directory_size: u32,
    central_directory_offset: u32,
    zip_file_comment: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Zip64Locator {
    disk_with_central_directory: u32,
    end_of_central_directory_offset: u64,
    number_of_disks: u32,
}

#[derive(Clone, Debug)]
struct Zip64Eocd {
    record_size: u64,
    version_made_by: u16,
    version_needed_to_extract: u16,
    disk_number: u32,
    disk_with_central_directory: u32,
    number_of_files_on_this_disk: u64,
    number_of_files: u64,
    central_directory_size: u64,
    central_directory_offset: u64,
    tail_after_fixed: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ZipTail {
    classic: ClassicEocd,
    zip64_eocd: Option<Zip64Eocd>,
    locator: Option<Zip64Locator>,
    zip64_eocd_offset: Option<u64>,
    eocd_offset: usize,
    central_directory_offset: u64,
    central_directory_size: u64,
}

#[derive(Clone, Debug)]
struct AppxBlockMapFile {
    name: String,
    normalized_name: String,
    declared_size: u64,
    lfh_size: Option<u64>,
    blocks: Vec<AppxBlockMapBlock>,
}

#[derive(Clone, Debug)]
struct AppxBlockMapBlock {
    hash: Vec<u8>,
    compressed_size: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct AppxPackageInventory {
    has_code_integrity: bool,
}

#[derive(Clone, Debug, Default)]
struct AppxContentTypes {
    defaults: HashMap<String, String>,
    overrides: HashMap<String, String>,
}

enum RunningHasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl RunningHasher {
    fn new(kind: PeAuthenticodeHashKind) -> Self {
        match kind {
            PeAuthenticodeHashKind::Sha1 => Self::Sha1(sha1::Sha1::new()),
            PeAuthenticodeHashKind::Sha256 => Self::Sha256(sha2::Sha256::new()),
            PeAuthenticodeHashKind::Sha384 => Self::Sha384(sha2::Sha384::new()),
            PeAuthenticodeHashKind::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(h) => digest::Digest::update(h, bytes),
            Self::Sha256(h) => digest::Digest::update(h, bytes),
            Self::Sha384(h) => digest::Digest::update(h, bytes),
            Self::Sha512(h) => digest::Digest::update(h, bytes),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha1(h) => digest::Digest::finalize(h).to_vec(),
            Self::Sha256(h) => digest::Digest::finalize(h).to_vec(),
            Self::Sha384(h) => digest::Digest::finalize(h).to_vec(),
            Self::Sha512(h) => digest::Digest::finalize(h).to_vec(),
        }
    }
}

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("read past end at {off}"))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("read past end at {off}"))
}

fn read_u64_le(buf: &[u8], off: usize) -> Result<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("read past end at {off}"))
}

fn strip_pkcx(data: &[u8]) -> Result<&[u8]> {
    if data.len() < 4 || &data[..4] != b"PKCX" {
        return Err(anyhow!(
            "AppxSignature.p7x did not start with PKCX (Windows P7X wrapper)"
        ));
    }
    Ok(&data[4..])
}

fn hash_kind_from_block_map_uri(uri: &str) -> Result<PeAuthenticodeHashKind> {
    let uri = uri.trim();
    if uri == HASH_SHA256 {
        Ok(PeAuthenticodeHashKind::Sha256)
    } else if uri == HASH_SHA384 {
        Ok(PeAuthenticodeHashKind::Sha384)
    } else if uri == HASH_SHA512 {
        Ok(PeAuthenticodeHashKind::Sha512)
    } else {
        Err(anyhow!(
            "unsupported AppxBlockMap HashMethod URI `{uri}` (expected SHA256/384/512 URIs)"
        ))
    }
}

fn xml_attr(
    reader: &Reader<Cursor<&[u8]>>,
    e: &BytesStart<'_>,
    name: &[u8],
) -> Result<Option<String>> {
    for attr in e.attributes() {
        let attr = attr.map_err(|e| anyhow!("AppxBlockMap.xml attribute parse failed: {e}"))?;
        if attr.key.as_ref() == name {
            let value = attr
                .decode_and_unescape_value(reader.decoder())
                .map_err(|e| anyhow!("AppxBlockMap.xml attribute decode failed: {e}"))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn required_xml_attr(
    reader: &Reader<Cursor<&[u8]>>,
    e: &BytesStart<'_>,
    name: &[u8],
) -> Result<String> {
    xml_attr(reader, e, name)?.ok_or_else(|| {
        anyhow!(
            "AppxBlockMap.xml `{}` element missing `{}` attribute",
            std::str::from_utf8(e.local_name().as_ref()).unwrap_or("?"),
            std::str::from_utf8(name).unwrap_or("?")
        )
    })
}

fn optional_u64_xml_attr(
    reader: &Reader<Cursor<&[u8]>>,
    e: &BytesStart<'_>,
    name: &[u8],
) -> Result<Option<u64>> {
    xml_attr(reader, e, name)?
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                anyhow!(
                    "AppxBlockMap.xml `{}` element has invalid `{}` value",
                    std::str::from_utf8(e.local_name().as_ref()).unwrap_or("?"),
                    std::str::from_utf8(name).unwrap_or("?")
                )
            })
        })
        .transpose()
}

fn normalize_appx_part_name(name: &str) -> Result<String> {
    if name.is_empty() || name.bytes().any(|b| b == 0) {
        return Err(anyhow!(
            "AppxBlockMap.xml contains an empty or NUL part name"
        ));
    }
    let normalized = name.replace('\\', "/");
    if normalized.starts_with('/') || normalized.contains(':') {
        return Err(anyhow!(
            "AppxBlockMap.xml part `{name}` is absolute or drive-qualified"
        ));
    }
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(anyhow!(
                "AppxBlockMap.xml part `{name}` contains an invalid path segment"
            ));
        }
    }
    Ok(normalized)
}

fn parse_block_map_xml(xml: &[u8]) -> Result<(PeAuthenticodeHashKind, Vec<AppxBlockMapFile>)> {
    let mut reader = Reader::from_reader(Cursor::new(xml));
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut kind = None;
    let mut files = Vec::new();
    let mut current: Option<AppxBlockMapFile> = None;
    let mut seen_names = HashSet::new();
    let mut in_block_map = false;

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| anyhow!("AppxBlockMap.xml parse failed: {e}"))?
        {
            Event::Start(e) if e.local_name().as_ref() == b"BlockMap" => {
                if kind.is_some() {
                    return Err(anyhow!("duplicate AppxBlockMap.xml BlockMap root"));
                }
                let hash_method = required_xml_attr(&reader, &e, b"HashMethod")?;
                kind = Some(hash_kind_from_block_map_uri(&hash_method)?);
                in_block_map = true;
            }
            Event::Empty(e) if e.local_name().as_ref() == b"BlockMap" => {
                if kind.is_some() {
                    return Err(anyhow!("duplicate AppxBlockMap.xml BlockMap root"));
                }
                let hash_method = required_xml_attr(&reader, &e, b"HashMethod")?;
                kind = Some(hash_kind_from_block_map_uri(&hash_method)?);
            }
            Event::Start(e) if e.local_name().as_ref() == b"File" => {
                if !in_block_map {
                    return Err(anyhow!("AppxBlockMap.xml File outside BlockMap"));
                }
                if current.is_some() {
                    return Err(anyhow!("nested AppxBlockMap.xml File elements are invalid"));
                }
                let name = required_xml_attr(&reader, &e, b"Name")?;
                let normalized_name = normalize_appx_part_name(&name)?;
                if !seen_names.insert(normalized_name.clone()) {
                    return Err(anyhow!("duplicate AppxBlockMap.xml File entry `{name}`"));
                }
                let declared_size = required_xml_attr(&reader, &e, b"Size")?
                    .parse::<u64>()
                    .map_err(|_| anyhow!("AppxBlockMap.xml File `{name}` has invalid Size"))?;
                let lfh_size = optional_u64_xml_attr(&reader, &e, b"LfhSize")?;
                current = Some(AppxBlockMapFile {
                    name,
                    normalized_name,
                    declared_size,
                    lfh_size,
                    blocks: Vec::new(),
                });
            }
            Event::Empty(e) if e.local_name().as_ref() == b"File" => {
                if !in_block_map {
                    return Err(anyhow!("AppxBlockMap.xml File outside BlockMap"));
                }
                let name = required_xml_attr(&reader, &e, b"Name")?;
                let normalized_name = normalize_appx_part_name(&name)?;
                if !seen_names.insert(normalized_name.clone()) {
                    return Err(anyhow!("duplicate AppxBlockMap.xml File entry `{name}`"));
                }
                let declared_size = required_xml_attr(&reader, &e, b"Size")?
                    .parse::<u64>()
                    .map_err(|_| anyhow!("AppxBlockMap.xml File `{name}` has invalid Size"))?;
                let lfh_size = optional_u64_xml_attr(&reader, &e, b"LfhSize")?;
                files.push(AppxBlockMapFile {
                    name,
                    normalized_name,
                    declared_size,
                    lfh_size,
                    blocks: Vec::new(),
                });
            }
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"Block" => {
                let Some(file) = current.as_mut() else {
                    return Err(anyhow!("AppxBlockMap.xml Block outside File"));
                };
                let encoded = required_xml_attr(&reader, &e, b"Hash")?;
                let hash = base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|e| anyhow!("AppxBlockMap.xml Block Hash is not base64: {e}"))?;
                let compressed_size = optional_u64_xml_attr(&reader, &e, b"Size")?;
                file.blocks.push(AppxBlockMapBlock {
                    hash,
                    compressed_size,
                });
            }
            Event::End(e) if e.local_name().as_ref() == b"BlockMap" => {
                if current.is_some() {
                    return Err(anyhow!("AppxBlockMap.xml BlockMap ended inside File"));
                }
                in_block_map = false;
            }
            Event::End(e) if e.local_name().as_ref() == b"File" => {
                let file = current
                    .take()
                    .ok_or_else(|| anyhow!("AppxBlockMap.xml unexpected File end"))?;
                files.push(file);
            }
            Event::Start(e) | Event::Empty(e) => {
                return Err(anyhow!(
                    "unexpected AppxBlockMap.xml element `{}`",
                    std::str::from_utf8(e.local_name().as_ref()).unwrap_or("?")
                ));
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if current.is_some() {
        return Err(anyhow!("unterminated AppxBlockMap.xml File element"));
    }
    let kind = kind.ok_or_else(|| anyhow!("AppxBlockMap.xml missing HashMethod"))?;
    let expected_len = kind.digest_output_len();
    for file in &files {
        for block in &file.blocks {
            if block.hash.len() != expected_len {
                return Err(anyhow!(
                    "AppxBlockMap.xml File `{}` has {}-byte block hash, expected {expected_len}",
                    file.name,
                    block.hash.len()
                ));
            }
        }
    }
    Ok((kind, files))
}

fn validate_content_types_xml(xml: &[u8]) -> Result<AppxContentTypes> {
    let mut reader = Reader::from_reader(Cursor::new(xml));
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut in_types = false;
    let mut saw_types = false;
    let mut content_types = AppxContentTypes::default();

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| anyhow!("[Content_Types].xml parse failed: {e}"))?
        {
            Event::Start(e) if e.local_name().as_ref() == b"Types" => {
                if saw_types {
                    return Err(anyhow!("duplicate [Content_Types].xml Types root"));
                }
                saw_types = true;
                in_types = true;
            }
            Event::Empty(e) if e.local_name().as_ref() == b"Types" => {
                if saw_types {
                    return Err(anyhow!("duplicate [Content_Types].xml Types root"));
                }
                saw_types = true;
            }
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"Default" => {
                if !in_types {
                    return Err(anyhow!("[Content_Types].xml Default outside Types"));
                }
                let extension = required_xml_attr(&reader, &e, b"Extension")?;
                let content_type = required_xml_attr(&reader, &e, b"ContentType")?;
                if extension.is_empty() || extension.contains('/') || extension.contains('\\') {
                    return Err(anyhow!(
                        "[Content_Types].xml Default has invalid Extension `{extension}`"
                    ));
                }
                if content_type.is_empty() {
                    return Err(anyhow!(
                        "[Content_Types].xml Default `{extension}` has empty ContentType"
                    ));
                }
                let key = extension.to_ascii_lowercase();
                if content_types.defaults.insert(key, content_type).is_some() {
                    return Err(anyhow!(
                        "duplicate [Content_Types].xml Default for extension `{extension}`"
                    ));
                }
            }
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"Override" => {
                if !in_types {
                    return Err(anyhow!("[Content_Types].xml Override outside Types"));
                }
                let part_name = required_xml_attr(&reader, &e, b"PartName")?;
                let content_type = required_xml_attr(&reader, &e, b"ContentType")?;
                if !part_name.starts_with('/') {
                    return Err(anyhow!(
                        "[Content_Types].xml Override PartName `{part_name}` is not absolute"
                    ));
                }
                if content_type.is_empty() {
                    return Err(anyhow!(
                        "[Content_Types].xml Override `{part_name}` has empty ContentType"
                    ));
                }
                let normalized = normalize_appx_part_name(&part_name[1..])?;
                let key = normalized.to_ascii_lowercase();
                if content_types.overrides.insert(key, content_type).is_some() {
                    return Err(anyhow!(
                        "duplicate [Content_Types].xml Override for part `{part_name}`"
                    ));
                }
            }
            Event::End(e) if e.local_name().as_ref() == b"Types" => {
                in_types = false;
            }
            Event::End(e) if matches!(e.local_name().as_ref(), b"Default" | b"Override") => {}
            Event::Start(e) | Event::Empty(e) => {
                return Err(anyhow!(
                    "unexpected [Content_Types].xml element `{}`",
                    std::str::from_utf8(e.local_name().as_ref()).unwrap_or("?")
                ));
            }
            Event::Text(e) => {
                let text = e
                    .decode()
                    .map_err(|e| anyhow!("[Content_Types].xml text decode failed: {e}"))?;
                if !text.trim().is_empty() {
                    return Err(anyhow!("[Content_Types].xml contains non-whitespace text"));
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    if !saw_types {
        return Err(anyhow!("[Content_Types].xml missing Types root"));
    }
    if in_types {
        return Err(anyhow!("unterminated [Content_Types].xml Types root"));
    }
    Ok(content_types)
}

fn content_type_for_part<'a>(content_types: &'a AppxContentTypes, part: &str) -> Option<&'a str> {
    let normalized = normalize_appx_part_name(part).ok()?;
    let folded = normalized.to_ascii_lowercase();
    if let Some(content_type) = content_types.overrides.get(&folded) {
        return Some(content_type);
    }
    let extension = normalized.rsplit_once('.')?.1.to_ascii_lowercase();
    content_types.defaults.get(&extension).map(String::as_str)
}

fn require_content_type(
    content_types: &AppxContentTypes,
    part: &'static [u8],
    expected: &str,
) -> Result<()> {
    let part = ascii_part(part);
    let Some(actual) = content_type_for_part(content_types, part) else {
        return Err(anyhow!(
            "[Content_Types].xml does not declare a content type for `{part}`"
        ));
    };
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(anyhow!(
            "[Content_Types].xml content type for `{part}` is `{actual}`, expected `{expected}`"
        ));
    }
    Ok(())
}

fn validate_reserved_content_types(
    content_types: &AppxContentTypes,
    inventory: AppxPackageInventory,
    ext: &str,
) -> Result<()> {
    require_content_type(
        content_types,
        BLOCK_MAP,
        "application/vnd.ms-appx.blockmap+xml",
    )?;
    require_content_type(
        content_types,
        APP_SIGNATURE,
        "application/vnd.ms-appx.signature",
    )?;
    if inventory.has_code_integrity {
        require_content_type(
            content_types,
            CODE_INTEGRITY,
            "application/vnd.ms-pkiseccat",
        )?;
    }
    if matches!(ext, "msixbundle" | "appxbundle") {
        require_content_type(
            content_types,
            BUNDLE_MANIFEST,
            "application/vnd.ms-appx.bundlemanifest+xml",
        )?;
    } else {
        require_content_type(
            content_types,
            APP_MANIFEST,
            "application/vnd.ms-appx.manifest+xml",
        )?;
    }
    Ok(())
}

fn parse_signed_appx_blob(data: &[u8]) -> Result<(usize, AppxDigestParts)> {
    if data.len() < 4 || &data[..4] != SIG_APPX {
        return Err(anyhow!(
            "PKCS#7 indirect digest is not an APPX blob (missing APPX prefix)"
        ));
    }
    let mut md_len_opt = None;
    for &candidate in &[20usize, 32, 48, 64] {
        let mut pos = 4usize;
        let mut ok = true;
        let tags = [TAG_AXPC, TAG_AXCD, TAG_AXCT, TAG_AXBM];
        for t in tags {
            if pos + 4 + candidate > data.len() || &data[pos..pos + 4] != t {
                ok = false;
                break;
            }
            pos += 4 + candidate;
        }
        if !ok {
            continue;
        }
        if pos == data.len() {
            md_len_opt = Some((candidate, false));
            break;
        }
        if pos + 4 + candidate <= data.len() && &data[pos..pos + 4] == TAG_AXCI {
            pos += 4 + candidate;
            if pos == data.len() {
                md_len_opt = Some((candidate, true));
                break;
            }
        }
    }
    let (md_len, has_ci) = md_len_opt.ok_or_else(|| {
        anyhow!("could not parse APPX indirect digest blob (expected AXPC..AXBM [+ AXCI])")
    })?;

    let mut pos = 4usize;
    let mut take = |tag: &[u8]| -> Result<Vec<u8>> {
        if pos + 4 + md_len > data.len() || &data[pos..pos + 4] != tag {
            return Err(anyhow!("unexpected APPX digest tag"));
        }
        pos += 4;
        let d = data[pos..pos + md_len].to_vec();
        pos += md_len;
        Ok(d)
    };

    let axpc = take(TAG_AXPC)?;
    let axcd = take(TAG_AXCD)?;
    let axct = take(TAG_AXCT)?;
    let axbm = take(TAG_AXBM)?;
    let axci = if has_ci { Some(take(TAG_AXCI)?) } else { None };
    if pos != data.len() {
        return Err(anyhow!("trailing bytes in APPX indirect digest blob"));
    }
    Ok((
        md_len,
        AppxDigestParts {
            axpc,
            axcd,
            axct,
            axbm,
            axci,
        },
    ))
}

fn find_classic_eocd(buf: &[u8]) -> Result<(usize, ClassicEocd)> {
    const HEADER_SIZE: u64 = 22;
    let file_length = buf.len() as u64;
    if file_length < HEADER_SIZE {
        return Err(anyhow!("buffer too small for EOCD"));
    }
    let search_upper_bound = file_length.saturating_sub(HEADER_SIZE + u16::MAX as u64);
    let mut pos = file_length - HEADER_SIZE;
    while pos >= search_upper_bound {
        let p = pos as usize;
        if read_u32_le(buf, p)? == EOCD_SIG {
            let disk_number = read_u16_le(buf, p + 4)?;
            let disk_with_central_directory = read_u16_le(buf, p + 6)?;
            let number_of_files_on_this_disk = read_u16_le(buf, p + 8)?;
            let number_of_files = read_u16_le(buf, p + 10)?;
            let central_directory_size = read_u32_le(buf, p + 12)?;
            let central_directory_offset = read_u32_le(buf, p + 16)?;
            let zip_file_comment_length = read_u16_le(buf, p + 20)? as usize;
            let cstart = p + 22;
            let cend = cstart
                .checked_add(zip_file_comment_length)
                .ok_or_else(|| anyhow!("EOCD comment overflow"))?;
            if cend != buf.len() {
                pos = match pos.checked_sub(1) {
                    Some(p) => p,
                    None => break,
                };
                continue;
            }
            let zip_file_comment = buf
                .get(cstart..cend)
                .ok_or_else(|| anyhow!("EOCD comment out of range"))?
                .to_vec();
            return Ok((
                p,
                ClassicEocd {
                    disk_number,
                    disk_with_central_directory,
                    number_of_files_on_this_disk,
                    number_of_files,
                    central_directory_size,
                    central_directory_offset,
                    zip_file_comment,
                },
            ));
        }
        pos = match pos.checked_sub(1) {
            Some(p) => p,
            None => break,
        };
    }
    Err(anyhow!("could not find ZIP end-of-central-directory"))
}

fn parse_zip64_locator(buf: &[u8], off: usize) -> Result<Zip64Locator> {
    if read_u32_le(buf, off)? != ZIP64_LOC_SIG {
        return Err(anyhow!("invalid ZIP64 locator signature"));
    }
    let locator = Zip64Locator {
        disk_with_central_directory: read_u32_le(buf, off + 4)?,
        end_of_central_directory_offset: read_u64_le(buf, off + 8)?,
        number_of_disks: read_u32_le(buf, off + 16)?,
    };
    if locator.disk_with_central_directory != 0 || locator.number_of_disks != 1 {
        return Err(anyhow!(
            "multi-disk ZIP64 archives are not valid APPX/MSIX packages"
        ));
    }
    Ok(locator)
}

fn find_zip64_eocd(
    buf: &[u8],
    nominal_offset: usize,
    search_upper_bound: usize,
) -> Result<(usize, Zip64Eocd, u64)> {
    let mut pos = nominal_offset;
    while pos <= search_upper_bound {
        if read_u32_le(buf, pos)? == ZIP64_EOCD_SIG {
            let archive_offset_u64 = (pos as u64).saturating_sub(
                u64::try_from(nominal_offset).map_err(|_| anyhow!("nominal offset"))?,
            );
            let record_size = read_u64_le(buf, pos + 4)?;
            if record_size < 44 {
                return Err(anyhow!(
                    "ZIP64 end-of-central-directory record is too small"
                ));
            }
            let version_made_by = read_u16_le(buf, pos + 12)?;
            let version_needed_to_extract = read_u16_le(buf, pos + 14)?;
            let disk_number = read_u32_le(buf, pos + 16)?;
            let disk_with_central_directory = read_u32_le(buf, pos + 20)?;
            if disk_number != 0 || disk_with_central_directory != 0 {
                return Err(anyhow!(
                    "multi-disk ZIP64 archives are not valid APPX/MSIX packages"
                ));
            }
            let number_of_files_on_this_disk = read_u64_le(buf, pos + 24)?;
            let number_of_files = read_u64_le(buf, pos + 32)?;
            let central_directory_size = read_u64_le(buf, pos + 40)?;
            let central_directory_offset = read_u64_le(buf, pos + 48)?;
            let fixed_after_record_size = 44usize;
            let total_record_content =
                usize::try_from(record_size).map_err(|_| anyhow!("zip64"))?;
            let tail_len = total_record_content - fixed_after_record_size;
            let tail_start = pos + 12 + fixed_after_record_size;
            let tail_end = tail_start
                .checked_add(tail_len)
                .ok_or_else(|| anyhow!("zip64 tail overflow"))?;
            let tail_after_fixed = buf
                .get(tail_start..tail_end)
                .ok_or_else(|| anyhow!("zip64 tail out of range"))?
                .to_vec();
            return Ok((
                pos,
                Zip64Eocd {
                    record_size,
                    version_made_by,
                    version_needed_to_extract,
                    disk_number,
                    disk_with_central_directory,
                    number_of_files_on_this_disk,
                    number_of_files,
                    central_directory_size,
                    central_directory_offset,
                    tail_after_fixed,
                },
                archive_offset_u64,
            ));
        }
        pos += 1;
    }
    Err(anyhow!("could not find ZIP64 end-of-central-directory"))
}

fn parse_zip_tail(buf: &[u8]) -> Result<ZipTail> {
    let (cde_pos, classic) = find_classic_eocd(buf)?;
    if classic.disk_number != 0 || classic.disk_with_central_directory != 0 {
        return Err(anyhow!(
            "multi-disk ZIP archives are not valid APPX/MSIX packages"
        ));
    }
    let file_len = buf.len();
    let comment_len = classic.zip_file_comment.len();
    let mut locator = None;
    let mut zip64_eocd = None;
    let mut zip64_eocd_offset = None;
    let mut central_directory_offset = u64::from(classic.central_directory_offset);
    let mut central_directory_size = u64::from(classic.central_directory_size);

    let locator_seek = file_len
        .checked_sub(20 + 22 + comment_len)
        .filter(|&x| x <= file_len);
    if let Some(off) = locator_seek
        && off + 20 <= buf.len()
        && read_u32_le(buf, off)? == ZIP64_LOC_SIG
    {
        let loc = parse_zip64_locator(buf, off)?;
        locator = Some(loc.clone());
        let nominal = usize::try_from(loc.end_of_central_directory_offset)
            .map_err(|_| anyhow!("zip64 nominal offset"))?;
        let search_upper = cde_pos.saturating_sub(60);
        let (zpos, z64, _ao) = find_zip64_eocd(buf, nominal, search_upper)?;
        if z64.number_of_files_on_this_disk != z64.number_of_files {
            return Err(anyhow!(
                "multi-disk ZIP64 entry counts are not valid APPX/MSIX packages"
            ));
        }
        central_directory_offset = if classic.central_directory_offset == u32::MAX {
            z64.central_directory_offset
        } else {
            u64::from(classic.central_directory_offset)
        };
        central_directory_size = if classic.central_directory_size == u32::MAX {
            z64.central_directory_size
        } else {
            u64::from(classic.central_directory_size)
        };
        zip64_eocd_offset = Some(u64::try_from(zpos).map_err(|_| anyhow!("zip64 EOCD offset"))?);
        zip64_eocd = Some(z64);
    }
    if locator.is_none() {
        if classic.number_of_files_on_this_disk == u16::MAX
            || classic.number_of_files == u16::MAX
            || classic.central_directory_size == u32::MAX
            || classic.central_directory_offset == u32::MAX
        {
            return Err(anyhow!(
                "classic EOCD uses ZIP64 sentinel values but ZIP64 locator is missing"
            ));
        }
        let cde_pos_u64 = u64::try_from(cde_pos).map_err(|_| anyhow!("cde position"))?;
        cde_pos_u64
            .checked_sub(classic.central_directory_size as u64)
            .and_then(|x| x.checked_sub(classic.central_directory_offset as u64))
            .ok_or_else(|| anyhow!("invalid EOCD central directory size/offset"))?;
    }
    let eocd_offset_u64 = u64::try_from(cde_pos).map_err(|_| anyhow!("eocd offset"))?;
    let cd_end = central_directory_offset
        .checked_add(central_directory_size)
        .ok_or_else(|| anyhow!("central directory extent overflow"))?;
    let expected_cd_end = zip64_eocd_offset.unwrap_or(eocd_offset_u64);
    if cd_end != expected_cd_end {
        return Err(anyhow!(
            "central directory extent does not end at EOCD/ZIP64 EOCD (offset={central_directory_offset}, size={central_directory_size}, expected_end={expected_cd_end})"
        ));
    }

    Ok(ZipTail {
        classic,
        zip64_eocd,
        locator,
        zip64_eocd_offset,
        eocd_offset: cde_pos,
        central_directory_offset,
        central_directory_size,
    })
}

fn parse_zip64_cd_extra(
    extra: &[u8],
    fixed_comp: u32,
    fixed_uncomp: u32,
    fixed_off: u32,
    fixed_disk: u16,
) -> (bool, bool, bool, bool, u32) {
    let mut needs_uncomp = fixed_uncomp == u32::MAX;
    let mut needs_comp = fixed_comp == u32::MAX;
    let mut needs_off = fixed_off == u32::MAX;
    let mut needs_disk = fixed_disk == u16::MAX;
    let mut disk = fixed_disk as u32;

    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let id = u16::from_le_bytes(extra[i..i + 2].try_into().unwrap());
        let sz = u16::from_le_bytes(extra[i + 2..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + sz > extra.len() {
            break;
        }
        let chunk = &extra[i..i + sz];
        if id == ZIP64_EXTRA_ID {
            let mut r = 0usize;
            if needs_uncomp && r + 8 <= chunk.len() {
                r += 8;
                needs_uncomp = false;
            }
            if needs_comp && r + 8 <= chunk.len() {
                r += 8;
                needs_comp = false;
            }
            if needs_off && r + 8 <= chunk.len() {
                r += 8;
                needs_off = false;
            }
            if needs_disk && r + 4 <= chunk.len() {
                disk = u32::from_le_bytes(chunk[r..r + 4].try_into().unwrap());
                needs_disk = false;
            }
        }
        i += sz;
    }

    (
        fixed_uncomp == u32::MAX,
        fixed_comp == u32::MAX,
        fixed_off == u32::MAX,
        fixed_disk == u16::MAX,
        disk,
    )
}

fn write_local_header_normalized(
    hasher: &mut RunningHasher,
    buf: &[u8],
    zf: &ZipFile<'_>,
) -> Result<()> {
    let hs = usize::try_from(zf.header_start()).map_err(|_| anyhow!("header_start"))?;
    if read_u32_le(buf, hs)? != LH_SIG {
        return Err(anyhow!("bad local file header signature"));
    }
    let version = read_u16_le(buf, hs + 4)?;
    let flags = read_u16_le(buf, hs + 6)?;
    let compression = read_u16_le(buf, hs + 8)?;
    let mod_time = read_u16_le(buf, hs + 10)?;
    let mod_date = read_u16_le(buf, hs + 12)?;

    let crc32 = zf.crc32();
    let compressed_size = zf.compressed_size();
    let uncompressed_size = zf.size();
    let name = zf.name_raw();
    let extra = zf.extra_data();

    hasher.update(&LH_SIG.to_le_bytes());
    hasher.update(&version.to_le_bytes());
    hasher.update(&flags.to_le_bytes());
    hasher.update(&compression.to_le_bytes());
    hasher.update(&mod_time.to_le_bytes());
    hasher.update(&mod_date.to_le_bytes());

    if flags & DATA_DESCRIPTOR_BIT != 0 {
        hasher.update(&[0u8; 12]);
    } else {
        let comp_zip64 = compressed_size > u64::from(u32::MAX);
        let uncomp_zip64 = uncompressed_size > u64::from(u32::MAX);
        hasher.update(&crc32.to_le_bytes());
        hasher.update(
            &(if comp_zip64 {
                u32::MAX
            } else {
                compressed_size as u32
            })
            .to_le_bytes(),
        );
        hasher.update(
            &(if uncomp_zip64 {
                u32::MAX
            } else {
                uncompressed_size as u32
            })
            .to_le_bytes(),
        );
    }

    hasher.update(&(name.len() as u16).to_le_bytes());
    hasher.update(&(extra.len() as u16).to_le_bytes());
    hasher.update(name);
    hasher.update(extra);
    Ok(())
}

fn append_data_descriptor(
    hasher: &mut RunningHasher,
    buf: &[u8],
    zf: &ZipFile<'_>,
    package_zip64: bool,
) -> Result<()> {
    let hs = usize::try_from(zf.header_start()).map_err(|_| anyhow!("header_start"))?;
    let flags = read_u16_le(buf, hs + 6)?;
    if flags & DATA_DESCRIPTOR_BIT == 0 {
        return Ok(());
    }
    hasher.update(&DD_SIG.to_le_bytes());
    hasher.update(&zf.crc32().to_le_bytes());
    if package_zip64 {
        hasher.update(&zf.compressed_size().to_le_bytes());
        hasher.update(&zf.size().to_le_bytes());
    } else {
        let cs = u32::try_from(zf.compressed_size())
            .map_err(|_| anyhow!("ZIP64 package flag required for large data descriptor"))?;
        let us = u32::try_from(zf.size()).map_err(|_| anyhow!("ZIP64 package flag required"))?;
        hasher.update(&cs.to_le_bytes());
        hasher.update(&us.to_le_bytes());
    }
    Ok(())
}

fn payload_and_descriptor_len(buf: &[u8], zf: &ZipFile<'_>, package_zip64: bool) -> Result<u64> {
    let hs = usize::try_from(zf.header_start()).map_err(|_| anyhow!("header_start"))?;
    let flags = read_u16_le(buf, hs + 6)?;
    let cs = zf.compressed_size();
    let dd_extra = if flags & DATA_DESCRIPTOR_BIT != 0 {
        if package_zip64 { 24u64 } else { 16u64 }
    } else {
        0u64
    };
    Ok(cs.saturating_add(dd_extra))
}

fn hash_zip_file_data(
    buf: &[u8],
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    tail: &ZipTail,
    kind: PeAuthenticodeHashKind,
) -> Result<(Vec<u8>, u64)> {
    let package_zip64 = tail.locator.is_some();
    let mut hasher = RunningHasher::new(kind);
    let mut cd_cursor: u64 = 0;
    let n = archive.len();
    for i in 0..n {
        let zf = archive.by_index(i)?;
        if zf.name_raw() == APP_SIGNATURE {
            continue;
        }
        let name = zf.name();
        if name.ends_with('/') || name.ends_with('\\') {
            continue;
        }
        match zf.compression() {
            CompressionMethod::Stored | CompressionMethod::Deflated => {}
            other => {
                return Err(anyhow!(
                    "unsupported ZIP compression {other:?} for MSIX digest (need Stored/Deflated)"
                ));
            }
        }
        write_local_header_normalized(&mut hasher, buf, &zf)?;
        let hl = u64::try_from(30 + zf.name_raw().len() + zf.extra_data().len())
            .map_err(|_| anyhow!("local header length"))?;
        cd_cursor = cd_cursor
            .checked_add(hl)
            .ok_or_else(|| anyhow!("cursor overflow"))?;

        let ds = usize::try_from(zf.data_start()).map_err(|_| anyhow!("data_start"))?;
        let cs = usize::try_from(zf.compressed_size()).map_err(|_| anyhow!("compressed_size"))?;
        let end = ds
            .checked_add(cs)
            .ok_or_else(|| anyhow!("payload overflow"))?;
        let slice = buf
            .get(ds..end)
            .ok_or_else(|| anyhow!("compressed payload out of range"))?;
        hasher.update(slice);
        append_data_descriptor(&mut hasher, buf, &zf, package_zip64)?;

        let inc = payload_and_descriptor_len(buf, &zf, package_zip64)?;
        cd_cursor = cd_cursor
            .checked_add(inc)
            .ok_or_else(|| anyhow!("cursor overflow"))?;
    }
    Ok((hasher.finalize(), cd_cursor))
}

fn hash_cd_and_eocd(
    buf: &[u8],
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    tail: &ZipTail,
    kind: PeAuthenticodeHashKind,
    cd_offset_virtual: u64,
) -> Result<Vec<u8>> {
    let mut hasher = RunningHasher::new(kind);
    let mut cd_size: u64 = 0;
    let mut no_entries: u16 = 0;

    let n = archive.len();
    for i in 0..n {
        let zf = archive.by_index(i)?;
        if zf.name_raw() == APP_SIGNATURE {
            continue;
        }
        let name = zf.name();
        if name.ends_with('/') || name.ends_with('\\') {
            continue;
        }

        let central_off = usize::try_from(zf.central_header_start())
            .map_err(|_| anyhow!("central_header_start"))?;
        if read_u32_le(buf, central_off)? != CD_SIG {
            return Err(anyhow!("bad central directory signature"));
        }

        let version_made_by = read_u16_le(buf, central_off + 4)?;
        let version_needed = read_u16_le(buf, central_off + 6)?;
        let flags = read_u16_le(buf, central_off + 8)?;
        let compression = read_u16_le(buf, central_off + 10)?;
        let mod_time = read_u16_le(buf, central_off + 12)?;
        let mod_date = read_u16_le(buf, central_off + 14)?;
        let crc32 = read_u32_le(buf, central_off + 16)?;
        let comp32 = read_u32_le(buf, central_off + 20)?;
        let uncomp32 = read_u32_le(buf, central_off + 24)?;
        let file_name_length = read_u16_le(buf, central_off + 28)? as usize;
        let extra_field_length = read_u16_le(buf, central_off + 30)? as usize;
        let file_comment_length = read_u16_le(buf, central_off + 32)? as usize;
        let disk_start = read_u16_le(buf, central_off + 34)?;
        let internal_attr = read_u16_le(buf, central_off + 36)?;
        let external_attr = read_u32_le(buf, central_off + 38)?;
        let local_off32 = read_u32_le(buf, central_off + 42)?;

        let base = central_off + 46;
        let name_end = base
            .checked_add(file_name_length)
            .ok_or_else(|| anyhow!("name"))?;
        let extra_end = name_end
            .checked_add(extra_field_length)
            .ok_or_else(|| anyhow!("extra"))?;
        let record_end = extra_end
            .checked_add(file_comment_length)
            .ok_or_else(|| anyhow!("comment"))?;
        if record_end > buf.len() {
            return Err(anyhow!("central directory entry out of range"));
        }
        let fname = &buf[base..name_end];
        let extra = &buf[name_end..extra_end];
        let fcomment = &buf[extra_end..record_end];

        let (uncomp_z64, comp_z64, off_z64, disk_z64, disk_u32) =
            parse_zip64_cd_extra(extra, comp32, uncomp32, local_off32, disk_start);

        let uncomp_u64 = zf.size();
        let comp_u64 = zf.compressed_size();
        let off_u64 = zf.header_start();

        let uncomp_z64 = uncomp_z64 || uncomp_u64 > u64::from(u32::MAX);
        let comp_z64 = comp_z64 || comp_u64 > u64::from(u32::MAX);
        let off_z64 = off_z64 || off_u64 > u64::from(u32::MAX);

        let mut syn = Vec::new();
        let mut pay = Vec::new();
        if uncomp_z64 {
            pay.extend_from_slice(&uncomp_u64.to_le_bytes());
        }
        if comp_z64 {
            pay.extend_from_slice(&comp_u64.to_le_bytes());
        }
        if off_z64 {
            pay.extend_from_slice(&off_u64.to_le_bytes());
        }
        if disk_z64 {
            pay.extend_from_slice(&disk_u32.to_le_bytes());
        }
        if !pay.is_empty() {
            syn.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
            syn.extend_from_slice(&(pay.len() as u16).to_le_bytes());
            syn.extend_from_slice(&pay);
        }

        hasher.update(&CD_SIG.to_le_bytes());
        hasher.update(&version_made_by.to_le_bytes());
        hasher.update(&version_needed.to_le_bytes());
        hasher.update(&flags.to_le_bytes());
        hasher.update(&compression.to_le_bytes());
        hasher.update(&mod_time.to_le_bytes());
        hasher.update(&mod_date.to_le_bytes());
        hasher.update(&crc32.to_le_bytes());
        hasher.update(
            &(if comp_z64 {
                u32::MAX
            } else {
                u32::try_from(comp_u64).map_err(|_| anyhow!("compressed size overflow"))?
            })
            .to_le_bytes(),
        );
        hasher.update(
            &(if uncomp_z64 {
                u32::MAX
            } else {
                u32::try_from(uncomp_u64).map_err(|_| anyhow!("uncompressed size overflow"))?
            })
            .to_le_bytes(),
        );
        hasher.update(&(fname.len() as u16).to_le_bytes());
        let syn_len_u16 =
            u16::try_from(syn.len()).map_err(|_| anyhow!("synthetic extra too large"))?;
        hasher.update(&syn_len_u16.to_le_bytes());
        hasher.update(&(fcomment.len() as u16).to_le_bytes());
        hasher.update(&(if disk_z64 { u16::MAX } else { disk_start }).to_le_bytes());
        hasher.update(&internal_attr.to_le_bytes());
        hasher.update(&external_attr.to_le_bytes());
        hasher.update(
            &(if off_z64 {
                u32::MAX
            } else {
                u32::try_from(off_u64).map_err(|_| anyhow!("local header offset overflow"))?
            })
            .to_le_bytes(),
        );
        hasher.update(fname);
        hasher.update(&syn);
        hasher.update(fcomment);

        let written = 46u64
            .saturating_add(fname.len() as u64)
            .saturating_add(u64::from(syn_len_u16))
            .saturating_add(fcomment.len() as u64);
        cd_size = cd_size
            .checked_add(written)
            .ok_or_else(|| anyhow!("cd_size overflow"))?;
        no_entries = no_entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("too many entries"))?;
    }

    let no_entries_u64 = u64::from(no_entries);

    if let Some(z) = &tail.zip64_eocd {
        let loc = tail
            .locator
            .as_ref()
            .ok_or_else(|| anyhow!("ZIP64 EOCD without locator"))?;
        hasher.update(&ZIP64_EOCD_SIG.to_le_bytes());
        hasher.update(&z.record_size.to_le_bytes());
        hasher.update(&z.version_made_by.to_le_bytes());
        hasher.update(&z.version_needed_to_extract.to_le_bytes());
        hasher.update(&z.disk_number.to_le_bytes());
        hasher.update(&z.disk_with_central_directory.to_le_bytes());
        hasher.update(&no_entries_u64.to_le_bytes());
        hasher.update(&no_entries_u64.to_le_bytes());
        hasher.update(&cd_size.to_le_bytes());
        hasher.update(&cd_offset_virtual.to_le_bytes());
        hasher.update(&z.tail_after_fixed);

        hasher.update(&ZIP64_LOC_SIG.to_le_bytes());
        hasher.update(&loc.disk_with_central_directory.to_le_bytes());
        hasher.update(&(cd_offset_virtual.saturating_add(cd_size)).to_le_bytes());
        hasher.update(&loc.number_of_disks.to_le_bytes());
    }

    let c = &tail.classic;
    hasher.update(&EOCD_SIG.to_le_bytes());
    hasher.update(&0u16.to_le_bytes());
    hasher.update(&0u16.to_le_bytes());
    hasher.update(
        &(if c.number_of_files_on_this_disk != u16::MAX {
            no_entries
        } else {
            u16::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(
        &(if c.number_of_files != u16::MAX {
            no_entries
        } else {
            u16::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(
        &(if c.central_directory_size != u32::MAX {
            u32::try_from(cd_size).map_err(|_| anyhow!("cd_size does not fit u32"))?
        } else {
            u32::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(
        &(if c.central_directory_offset != u32::MAX {
            u32::try_from(cd_offset_virtual).map_err(|_| anyhow!("cd_offset does not fit u32"))?
        } else {
            u32::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(&(c.zip_file_comment.len() as u16).to_le_bytes());
    hasher.update(&c.zip_file_comment);

    Ok(hasher.finalize())
}

fn read_zip_entry_raw(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Vec<u8>> {
    let mut f = archive.by_name(name)?;
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    Ok(v)
}

fn ascii_part(bytes: &'static [u8]) -> &'static str {
    std::str::from_utf8(bytes).expect("APPX part constants are ASCII")
}

fn canonical_reserved_part(normalized_name: &str) -> Option<&'static str> {
    [
        CONTENT_TYPES,
        BLOCK_MAP,
        APP_SIGNATURE,
        APP_MANIFEST,
        BUNDLE_MANIFEST,
        CODE_INTEGRITY,
    ]
    .into_iter()
    .map(ascii_part)
    .find(|reserved| normalized_name.eq_ignore_ascii_case(reserved))
}

fn validate_package_part_inventory(
    archive: &ZipArchive<Cursor<&[u8]>>,
    ext: &str,
) -> Result<AppxPackageInventory> {
    let is_bundle = matches!(ext, "msixbundle" | "appxbundle");
    let mut seen = HashSet::new();
    let mut seen_casefolded = HashMap::<String, String>::new();
    let mut required_counts = HashMap::<&'static str, usize>::new();

    for name in archive.file_names() {
        if name.ends_with('/') || name.ends_with('\\') {
            continue;
        }
        if name.contains('\\') {
            return Err(anyhow!(
                "APPX/MSIX ZIP entry `{name}` uses backslashes; package part names must use `/`"
            ));
        }
        let normalized = normalize_appx_part_name(name)?;
        if !seen.insert(normalized.clone()) {
            return Err(anyhow!("duplicate APPX/MSIX ZIP part `{normalized}`"));
        }
        let folded = normalized.to_ascii_lowercase();
        if let Some(previous) = seen_casefolded.insert(folded, normalized.clone()) {
            return Err(anyhow!(
                "duplicate APPX/MSIX ZIP part after case-insensitive normalization: `{previous}` / `{normalized}`"
            ));
        }
        if let Some(canonical) = canonical_reserved_part(&normalized) {
            if normalized != canonical {
                return Err(anyhow!(
                    "reserved APPX/MSIX part `{normalized}` must use canonical path `{canonical}`"
                ));
            }
            *required_counts.entry(canonical).or_default() += 1;
        }
        if is_bundle {
            let child_ext = normalized
                .rsplit_once('.')
                .map(|(_, ext)| ext.to_ascii_lowercase());
            if child_ext
                .as_deref()
                .is_some_and(is_encrypted_msix_extension)
            {
                return Err(anyhow!(
                    "cleartext APPX/MSIX bundle contains encrypted child package `{normalized}`"
                ));
            }
        }
    }

    for required in [CONTENT_TYPES, BLOCK_MAP, APP_SIGNATURE] {
        let required = ascii_part(required);
        if required_counts.get(required).copied().unwrap_or(0) != 1 {
            return Err(anyhow!(
                "APPX/MSIX package must contain exactly one required part `{required}`"
            ));
        }
    }

    let flat_manifest = ascii_part(APP_MANIFEST);
    let bundle_manifest = ascii_part(BUNDLE_MANIFEST);
    if is_bundle {
        if required_counts.get(bundle_manifest).copied().unwrap_or(0) != 1 {
            return Err(anyhow!(
                "APPX/MSIX bundle must contain exactly one required part `{bundle_manifest}`"
            ));
        }
        if required_counts.get(flat_manifest).copied().unwrap_or(0) != 0 {
            return Err(anyhow!(
                "APPX/MSIX bundle must not contain top-level `{flat_manifest}`"
            ));
        }
    } else {
        if required_counts.get(flat_manifest).copied().unwrap_or(0) != 1 {
            return Err(anyhow!(
                "APPX/MSIX package must contain exactly one required part `{flat_manifest}`"
            ));
        }
        if required_counts.get(bundle_manifest).copied().unwrap_or(0) != 0 {
            return Err(anyhow!(
                "flat APPX/MSIX package must not contain bundle part `{bundle_manifest}`"
            ));
        }
    }

    let code_integrity = ascii_part(CODE_INTEGRITY);
    let code_integrity_count = required_counts.get(code_integrity).copied().unwrap_or(0);
    if code_integrity_count > 1 {
        return Err(anyhow!(
            "APPX/MSIX package must contain at most one `{code_integrity}`"
        ));
    }

    Ok(AppxPackageInventory {
        has_code_integrity: code_integrity_count == 1,
    })
}

fn hash_bytes(kind: PeAuthenticodeHashKind, bytes: &[u8]) -> Vec<u8> {
    let mut h = RunningHasher::new(kind);
    h.update(bytes);
    h.finalize()
}

fn data_descriptor_len_and_validate(buf: &[u8], off: usize, zf: &ZipFile<'_>) -> Result<u64> {
    let has_sig = buf
        .get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) == DD_SIG)
        .unwrap_or(false);
    let cursor = off + if has_sig { 4 } else { 0 };
    let crc = read_u32_le(buf, cursor)?;
    if crc != zf.crc32() {
        return Err(anyhow!(
            "ZIP data descriptor CRC does not match central directory"
        ));
    }
    let classic_matches = read_u32_le(buf, cursor + 4)
        .ok()
        .zip(read_u32_le(buf, cursor + 8).ok())
        .is_some_and(|(compressed_size, uncompressed_size)| {
            u64::from(compressed_size) == zf.compressed_size()
                && u64::from(uncompressed_size) == zf.size()
        });
    if classic_matches {
        return Ok(if has_sig { 16 } else { 12 });
    }

    let zip64_matches = read_u64_le(buf, cursor + 4)
        .ok()
        .zip(read_u64_le(buf, cursor + 12).ok())
        .is_some_and(|(compressed_size, uncompressed_size)| {
            compressed_size == zf.compressed_size() && uncompressed_size == zf.size()
        });
    if zip64_matches {
        Ok(if has_sig { 24 } else { 20 })
    } else {
        let compressed_size = read_u64_le(buf, cursor + 4)?;
        let uncompressed_size = read_u64_le(buf, cursor + 12)?;
        Err(anyhow!(
            "ZIP data descriptor sizes do not match central directory (compressed={compressed_size}, uncompressed={uncompressed_size})"
        ))
    }
}

fn local_file_record_extent(buf: &[u8], zf: &ZipFile<'_>) -> Result<(u64, u64)> {
    let header_start = zf.header_start();
    let hs = usize::try_from(header_start).map_err(|_| anyhow!("header_start"))?;
    if read_u32_le(buf, hs)? != LH_SIG {
        return Err(anyhow!("bad local file header signature"));
    }
    let flags = read_u16_le(buf, hs + 6)?;
    if flags & 0x2041 != 0 {
        return Err(anyhow!(
            "encrypted ZIP local file records are not valid cleartext APPX/MSIX packages"
        ));
    }
    let compression = read_u16_le(buf, hs + 8)?;
    if !matches!(compression, 0 | 8) {
        return Err(anyhow!(
            "unsupported ZIP compression method {compression} in APPX/MSIX local file record"
        ));
    }
    if !matches!(
        zf.compression(),
        CompressionMethod::Stored | CompressionMethod::Deflated
    ) {
        return Err(anyhow!(
            "unsupported ZIP compression method {:?} in APPX/MSIX central directory",
            zf.compression()
        ));
    }
    let name_len = read_u16_le(buf, hs + 26)? as u64;
    let extra_len = read_u16_le(buf, hs + 28)? as u64;
    let name_start = hs
        .checked_add(30)
        .ok_or_else(|| anyhow!("local file name offset overflow"))?;
    let name_len_usize = usize::try_from(name_len).map_err(|_| anyhow!("name length"))?;
    let name_end = name_start
        .checked_add(name_len_usize)
        .ok_or_else(|| anyhow!("local file name extent overflow"))?;
    let local_name = buf
        .get(name_start..name_end)
        .ok_or_else(|| anyhow!("local file name out of range"))?;
    if local_name != zf.name_raw() {
        return Err(anyhow!(
            "ZIP local file name does not match central directory for `{}`",
            zf.name()
        ));
    }
    let expected_data_start = header_start
        .checked_add(30)
        .and_then(|x| x.checked_add(name_len))
        .and_then(|x| x.checked_add(extra_len))
        .ok_or_else(|| anyhow!("local file header extent overflow"))?;
    if zf.data_start() != expected_data_start {
        return Err(anyhow!(
            "local file header/data offset mismatch for `{}`",
            zf.name()
        ));
    }
    let compressed_end = zf
        .data_start()
        .checked_add(zf.compressed_size())
        .ok_or_else(|| anyhow!("compressed payload extent overflow"))?;
    if flags & DATA_DESCRIPTOR_BIT == 0 {
        let crc = read_u32_le(buf, hs + 14)?;
        let compressed_size = u64::from(read_u32_le(buf, hs + 18)?);
        let uncompressed_size = u64::from(read_u32_le(buf, hs + 22)?);
        if crc != zf.crc32() {
            return Err(anyhow!(
                "ZIP local file CRC does not match central directory for `{}`",
                zf.name()
            ));
        }
        if compressed_size != u64::from(u32::MAX) && compressed_size != zf.compressed_size() {
            return Err(anyhow!(
                "ZIP local compressed size does not match central directory for `{}`",
                zf.name()
            ));
        }
        if uncompressed_size != u64::from(u32::MAX) && uncompressed_size != zf.size() {
            return Err(anyhow!(
                "ZIP local uncompressed size does not match central directory for `{}`",
                zf.name()
            ));
        }
    }
    let descriptor_len = if flags & DATA_DESCRIPTOR_BIT != 0 {
        data_descriptor_len_and_validate(
            buf,
            usize::try_from(compressed_end).map_err(|_| anyhow!("compressed end"))?,
            zf,
        )?
    } else {
        0
    };
    let end = compressed_end
        .checked_add(descriptor_len)
        .ok_or_else(|| anyhow!("local file record extent overflow"))?;
    Ok((header_start, end))
}

fn validate_central_directory_records(buf: &[u8], tail: &ZipTail) -> Result<()> {
    let count = tail
        .zip64_eocd
        .as_ref()
        .map(|z64| z64.number_of_files)
        .unwrap_or(u64::from(tail.classic.number_of_files));
    if count > 0xA00000 {
        return Err(anyhow!(
            "APPX/MSIX ZIP has too many central directory entries"
        ));
    }
    let mut cursor = usize::try_from(tail.central_directory_offset)
        .map_err(|_| anyhow!("central directory offset"))?;
    let cd_end = tail
        .central_directory_offset
        .checked_add(tail.central_directory_size)
        .ok_or_else(|| anyhow!("central directory extent overflow"))?;
    let cd_end = usize::try_from(cd_end).map_err(|_| anyhow!("central directory end"))?;
    let mut seen = 0u64;
    while cursor < cd_end {
        if read_u32_le(buf, cursor)? != CD_SIG {
            return Err(anyhow!("bad central directory signature"));
        }
        let flags = read_u16_le(buf, cursor + 8)?;
        if flags & 0x2041 != 0 {
            return Err(anyhow!(
                "encrypted ZIP central directory records are not valid cleartext APPX/MSIX packages"
            ));
        }
        let compression = read_u16_le(buf, cursor + 10)?;
        if !matches!(compression, 0 | 8) {
            return Err(anyhow!(
                "unsupported ZIP compression method {compression} in APPX/MSIX central directory"
            ));
        }
        let file_name_length = read_u16_le(buf, cursor + 28)? as usize;
        let extra_field_length = read_u16_le(buf, cursor + 30)? as usize;
        let file_comment_length = read_u16_le(buf, cursor + 32)? as usize;
        let disk_start = read_u16_le(buf, cursor + 34)?;
        if disk_start != 0 {
            return Err(anyhow!("central directory entry starts on a non-zero disk"));
        }
        if file_comment_length != 0 {
            return Err(anyhow!(
                "central directory file comments are not valid in APPX/MSIX packages"
            ));
        }
        cursor = cursor
            .checked_add(46)
            .and_then(|x| x.checked_add(file_name_length))
            .and_then(|x| x.checked_add(extra_field_length))
            .and_then(|x| x.checked_add(file_comment_length))
            .ok_or_else(|| anyhow!("central directory record overflow"))?;
        if cursor > cd_end {
            return Err(anyhow!("central directory record extends past directory"));
        }
        seen += 1;
    }
    if seen != count {
        return Err(anyhow!(
            "central directory entry count {seen} does not match EOCD count {count}"
        ));
    }
    Ok(())
}

fn validate_zip_file_layout(
    buf: &[u8],
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    tail: &ZipTail,
) -> Result<()> {
    validate_central_directory_records(buf, tail)?;
    let mut extents = Vec::new();
    for i in 0..archive.len() {
        let zf = archive.by_index(i)?;
        let name = zf.name().to_owned();
        let (start, end) = local_file_record_extent(buf, &zf)?;
        extents.push((start, end, name));
    }
    extents.sort_by_key(|(start, _, _)| *start);
    let Some((first_start, _, first_name)) = extents.first() else {
        return Err(anyhow!("APPX/MSIX ZIP has no local file records"));
    };
    if *first_start != 0 {
        return Err(anyhow!(
            "APPX/MSIX ZIP has leading bytes before first local file `{first_name}`"
        ));
    }
    for pair in extents.windows(2) {
        let (_, prev_end, prev_name) = &pair[0];
        let (next_start, _, next_name) = &pair[1];
        if next_start < prev_end {
            return Err(anyhow!(
                "APPX/MSIX ZIP local file records overlap (`{prev_name}` / `{next_name}`)"
            ));
        }
        if next_start > prev_end {
            return Err(anyhow!(
                "APPX/MSIX ZIP has a gap between local file records `{prev_name}` and `{next_name}`"
            ));
        }
    }
    let (_, last_end, last_name) = extents.last().expect("nonempty extents");
    if *last_end != tail.central_directory_offset {
        return Err(anyhow!(
            "APPX/MSIX ZIP has a gap before the central directory after `{last_name}`"
        ));
    }
    let cd_end = tail
        .central_directory_offset
        .checked_add(tail.central_directory_size)
        .ok_or_else(|| anyhow!("central directory extent overflow"))?;
    let expected_cd_end = tail
        .zip64_eocd_offset
        .unwrap_or(u64::try_from(tail.eocd_offset).map_err(|_| anyhow!("eocd offset"))?);
    if cd_end != expected_cd_end {
        return Err(anyhow!(
            "APPX/MSIX ZIP central directory does not end at EOCD/ZIP64 EOCD"
        ));
    }
    Ok(())
}

fn archive_file_index_by_normalized_name(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
) -> Result<HashMap<String, usize>> {
    let mut files = HashMap::new();
    for i in 0..archive.len() {
        let zf = archive.by_index(i)?;
        if zf.name().ends_with('/') || zf.name().ends_with('\\') {
            continue;
        }
        let normalized = normalize_appx_part_name(zf.name())?;
        if files.insert(normalized.clone(), i).is_some() {
            return Err(anyhow!(
                "duplicate ZIP entry after APPX path normalization: `{normalized}`"
            ));
        }
    }
    Ok(files)
}

fn validate_block_map_file_hashes(
    buf: &[u8],
    kind: PeAuthenticodeHashKind,
    block_map_files: &[AppxBlockMapFile],
) -> Result<()> {
    // Native AppxSip.dll enables AppxPackaging block-hash validation and then
    // streams each payload through IAppxFile; this mirrors that check without COM.
    let mut archive = ZipArchive::new(Cursor::new(buf))?;
    let file_index = archive_file_index_by_normalized_name(&mut archive)?;
    let mut archive = ZipArchive::new(Cursor::new(buf))?;

    for block_file in block_map_files {
        if matches!(
            block_file.normalized_name.as_str(),
            "AppxBlockMap.xml" | "[Content_Types].xml" | "AppxSignature.p7x"
        ) {
            return Err(anyhow!(
                "AppxBlockMap.xml must not list metadata part `{}` as payload",
                block_file.name
            ));
        }
        let Some(&index) = file_index.get(&block_file.normalized_name) else {
            return Err(anyhow!(
                "AppxBlockMap.xml File `{}` is missing from package ZIP",
                block_file.name
            ));
        };

        let mut zf = archive.by_index(index)?;
        if let Some(lfh_size) = block_file.lfh_size {
            let actual_lfh_size = zf
                .data_start()
                .checked_sub(zf.header_start())
                .ok_or_else(|| anyhow!("local file header size underflow"))?;
            if lfh_size != actual_lfh_size {
                return Err(anyhow!(
                    "AppxBlockMap.xml File `{}` LfhSize {lfh_size} does not match ZIP local header size {actual_lfh_size}",
                    block_file.name
                ));
            }
        }
        let mut data = Vec::new();
        zf.read_to_end(&mut data)?;
        let data_len = u64::try_from(data.len()).map_err(|_| anyhow!("file too large"))?;
        if data_len != block_file.declared_size {
            return Err(anyhow!(
                "AppxBlockMap.xml File `{}` Size {} does not match uncompressed size {data_len}",
                block_file.name,
                block_file.declared_size
            ));
        }
        if data.is_empty() {
            if !block_file.blocks.is_empty() {
                return Err(anyhow!(
                    "AppxBlockMap.xml File `{}` is empty but has block hashes",
                    block_file.name
                ));
            }
            continue;
        }
        if block_file.blocks.is_empty() {
            return Err(anyhow!(
                "AppxBlockMap.xml File `{}` has content but no block hashes",
                block_file.name
            ));
        }

        let mut offset = 0usize;
        for (block_index, block) in block_file.blocks.iter().enumerate() {
            if offset >= data.len() {
                return Err(anyhow!(
                    "AppxBlockMap.xml File `{}` has too many block hashes",
                    block_file.name
                ));
            }
            let end = offset.saturating_add(APPX_BLOCK_SIZE).min(data.len());
            let actual = hash_bytes(kind, &data[offset..end]);
            if actual.as_slice() != block.hash.as_slice() {
                return Err(anyhow!(
                    "AppxBlockMap.xml File `{}` block {block_index} hash mismatch",
                    block_file.name
                ));
            }
            if let Some(compressed_size) = block.compressed_size
                && compressed_size == 0
            {
                return Err(anyhow!(
                    "AppxBlockMap.xml File `{}` block {block_index} has zero Size",
                    block_file.name
                ));
            }
            offset = end;
        }
        if offset != data.len() {
            return Err(anyhow!(
                "AppxBlockMap.xml File `{}` has too few block hashes",
                block_file.name
            ));
        }
    }

    Ok(())
}

fn cleartext_msix_extension_for_name(name: &str) -> Option<&'static str> {
    let lower = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    if lower.ends_with(".msix") {
        Some("msix")
    } else if lower.ends_with(".appx") {
        Some("appx")
    } else if lower.ends_with(".msixbundle") {
        Some("msixbundle")
    } else if lower.ends_with(".appxbundle") {
        Some("appxbundle")
    } else {
        None
    }
}

fn verify_bundle_child_packages(buf: &[u8]) -> Result<()> {
    let mut archive = ZipArchive::new(Cursor::new(buf))?;
    let mut children = Vec::new();
    for i in 0..archive.len() {
        let mut zf = archive.by_index(i)?;
        if zf.name().ends_with('/') || zf.name().ends_with('\\') {
            continue;
        }
        let normalized = normalize_appx_part_name(zf.name())?;
        let Some(ext) = cleartext_msix_extension_for_name(&normalized) else {
            continue;
        };
        let mut child = Vec::new();
        zf.read_to_end(&mut child)?;
        children.push((normalized, ext, child));
    }

    for (name, ext, child) in children {
        verify_msix_digest_consistency_bytes(&child, ext).map_err(|e| {
            anyhow!("bundle child package `{name}` failed MSIX SIP validation: {e}")
        })?;
    }

    Ok(())
}

/// Encrypted package extensions (`CryptSIPDll*` **`EappxSip*`** / **`EappxBundleSip*`** rows). Cleartext ZIP hash parity ([`verify_msix_digest_consistency`]) does **not** apply.
///
/// `ext` should be the path extension in ASCII lowercase (no dot).
#[inline]
pub fn is_encrypted_msix_extension(ext: &str) -> bool {
    matches!(ext, "eappx" | "eappxbundle" | "emsix" | "emsixbundle")
}

/// Compare PKCS#7 APPX indirect blob with osslsigncode-style MSIX / APPX bundle ZIP hashes (`AppxSip.dll` semantics).
pub fn verify_msix_digest_consistency(path: &Path) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if is_encrypted_msix_extension(&ext) {
        return Err(anyhow!(
            "Rust MSIX SIP digest parity applies only to cleartext OPC/ZIP packages (.msix, .appx, bundles); \
             encrypted packages (.eappx, .emsix, …) use AppxSip `EappxSip*` / Windows crypto — rely on WinVerifyTrust"
        ));
    }
    if !matches!(ext.as_str(), "msix" | "appx" | "msixbundle" | "appxbundle") {
        return Err(anyhow!(
            "Rust MSIX SIP digest check applies only to `.msix` / `.appx` / `.msixbundle` / `.appxbundle` files"
        ));
    }

    let buf = std::fs::read(path)?;
    verify_msix_digest_consistency_bytes(&buf, &ext)
}

fn verify_msix_digest_consistency_bytes(buf: &[u8], ext: &str) -> Result<()> {
    let tail = parse_zip_tail(buf)?;
    let mut layout_archive = ZipArchive::new(Cursor::new(buf))?;
    validate_zip_file_layout(buf, &mut layout_archive, &tail)?;
    let mut archive = ZipArchive::new(Cursor::new(buf))?;
    let inventory = validate_package_part_inventory(&archive, ext)?;

    let p7x = read_zip_entry_raw(&mut archive, std::str::from_utf8(APP_SIGNATURE)?)?;
    let pkcs7 = strip_pkcx(&p7x)?;
    let sig = AuthenticodeSignature::from_bytes(pkcs7)
        .map_err(|e| anyhow!("MSIX PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();

    let (piece_len, parts) = parse_signed_appx_blob(embedded)?;

    let block_map_bytes = read_zip_entry_raw(&mut archive, std::str::from_utf8(BLOCK_MAP)?)?;
    let (kind, block_map_files) = parse_block_map_xml(&block_map_bytes)?;
    let ct_raw = read_zip_entry_raw(&mut archive, std::str::from_utf8(CONTENT_TYPES)?)?;
    let content_types = validate_content_types_xml(&ct_raw)?;
    validate_reserved_content_types(&content_types, inventory, ext)?;
    let expected_piece = kind.digest_output_len();
    if piece_len != expected_piece {
        return Err(anyhow!(
            "PKCS#7 APPX digest width {piece_len} does not match AppxBlockMap HashMethod ({expected_piece})"
        ));
    }

    let bm_raw = read_zip_entry_raw(&mut archive, std::str::from_utf8(BLOCK_MAP)?)?;

    let ci_raw = if inventory.has_code_integrity {
        Some(read_zip_entry_raw(
            &mut archive,
            std::str::from_utf8(CODE_INTEGRITY)?,
        )?)
    } else {
        None
    };

    if inventory.has_code_integrity != parts.axci.is_some() {
        return Err(anyhow!(
            "CodeIntegrity.cat presence does not match PKCS#7 AXCI block"
        ));
    }

    let ct_hash = hash_bytes(kind, &ct_raw);
    let bm_hash = hash_bytes(kind, &bm_raw);
    let ci_hash = match (&ci_raw, &parts.axci) {
        (Some(data), Some(_)) => Some(hash_bytes(kind, data)),
        (None, None) => None,
        _ => unreachable!(),
    };

    let mut archive2 = ZipArchive::new(Cursor::new(buf))?;
    let (data_hash, cd_off_virt) = hash_zip_file_data(buf, &mut archive2, &tail, kind)?;
    let mut archive3 = ZipArchive::new(Cursor::new(buf))?;
    let cd_hash = hash_cd_and_eocd(buf, &mut archive3, &tail, kind, cd_off_virt)?;

    let check = |label: &str, a: &[u8], b: &[u8]| -> Result<()> {
        if a != b {
            return Err(anyhow!(
                "MSIX Authenticode {label} mismatch (Rust SIP vs PKCS#7 APPX blob)"
            ));
        }
        Ok(())
    };

    check("AXPC (payload)", &data_hash, &parts.axpc)?;
    check("AXCD (central directory)", &cd_hash, &parts.axcd)?;
    check("AXCT ([Content_Types].xml)", &ct_hash, &parts.axct)?;
    check("AXBM (AppxBlockMap.xml)", &bm_hash, &parts.axbm)?;
    if let (Some(ch), Some(sig_ci)) = (&ci_hash, &parts.axci) {
        check("AXCI (CodeIntegrity.cat)", ch, sig_ci)?;
    }
    validate_block_map_file_hashes(buf, kind, &block_map_files)?;
    if matches!(ext, "msixbundle" | "appxbundle") {
        verify_bundle_child_packages(buf)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::FileOptions;

    fn block_map_xml_for_file(name: &str, size: usize, hash: &[u8]) -> Vec<u8> {
        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" HashMethod="{HASH_SHA256}"><File Name="{name}" Size="{size}"><Block Hash="{hash_b64}"/></File></BlockMap>"#
        )
        .into_bytes()
    }

    fn zip_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, bytes) in entries {
                writer.start_file(*name, options).expect("start zip file");
                writer.write_all(bytes).expect("write zip file");
            }
            writer.finish().expect("finish zip");
        }
        out.into_inner()
    }

    fn find_eocd_for_test(zip: &[u8]) -> usize {
        zip.windows(4)
            .rposition(|w| w == EOCD_SIG.to_le_bytes())
            .expect("EOCD")
    }

    fn read_u32_test(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    fn write_u16_test(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32_test(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn first_central_directory_offset(zip: &[u8]) -> usize {
        let eocd = find_eocd_for_test(zip);
        read_u32_test(zip, eocd + 16) as usize
    }

    fn first_local_header_offset(zip: &[u8]) -> usize {
        let cd_offset = first_central_directory_offset(zip);
        read_u32_test(zip, cd_offset + 42) as usize
    }

    fn zip_with_gap_before_central_directory() -> Vec<u8> {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let eocd = find_eocd_for_test(&zip);
        let cd_offset = read_u32_test(&zip, eocd + 16) as usize;
        let gap = b"GAP";
        zip.splice(cd_offset..cd_offset, gap.iter().copied());
        let new_eocd = eocd + gap.len();
        write_u32_test(&mut zip, new_eocd + 16, (cd_offset + gap.len()) as u32);
        zip
    }

    fn zip_with_gap_between_local_files() -> Vec<u8> {
        let mut zip = zip_with_entries(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let eocd = find_eocd_for_test(&zip);
        let cd_offset = read_u32_test(&zip, eocd + 16) as usize;
        let first_name_len = read_u16_le(&zip, cd_offset + 28).unwrap() as usize;
        let first_extra_len = read_u16_le(&zip, cd_offset + 30).unwrap() as usize;
        let first_comment_len = read_u16_le(&zip, cd_offset + 32).unwrap() as usize;
        let second_cd = cd_offset + 46 + first_name_len + first_extra_len + first_comment_len;
        let second_local = read_u32_test(&zip, second_cd + 42) as usize;

        let gap = b"GAP";
        zip.splice(second_local..second_local, gap.iter().copied());
        let new_cd_offset = cd_offset + gap.len();
        let new_eocd = eocd + gap.len();
        let new_second_cd = second_cd + gap.len();
        write_u32_test(
            &mut zip,
            new_second_cd + 42,
            (second_local + gap.len()) as u32,
        );
        write_u32_test(&mut zip, new_eocd + 16, new_cd_offset as u32);
        zip
    }

    fn zip_with_central_directory_file_comment() -> Vec<u8> {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let eocd = find_eocd_for_test(&zip);
        let cd_offset = read_u32_test(&zip, eocd + 16) as usize;
        let cd_size = read_u32_test(&zip, eocd + 12);
        let name_len = read_u16_le(&zip, cd_offset + 28).unwrap() as usize;
        let extra_len = read_u16_le(&zip, cd_offset + 30).unwrap() as usize;
        let comment = b"cmt";
        let comment_at = cd_offset + 46 + name_len + extra_len;
        zip.splice(comment_at..comment_at, comment.iter().copied());
        write_u16_test(&mut zip, cd_offset + 32, comment.len() as u16);
        let new_eocd = eocd + comment.len();
        write_u32_test(&mut zip, new_eocd + 12, cd_size + comment.len() as u32);
        zip
    }

    fn zip_with_leading_bytes() -> Vec<u8> {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let prefix = b"PX";
        let old_eocd = find_eocd_for_test(&zip);
        let old_cd_offset = read_u32_test(&zip, old_eocd + 16) as usize;
        let cd_size = read_u32_test(&zip, old_eocd + 12) as usize;
        zip.splice(0..0, prefix.iter().copied());
        let new_cd_offset = old_cd_offset + prefix.len();
        let new_eocd = old_eocd + prefix.len();
        write_u32_test(&mut zip, new_eocd + 16, new_cd_offset as u32);

        let mut cd_cursor = new_cd_offset;
        let cd_end = new_cd_offset + cd_size;
        while cd_cursor < cd_end {
            assert_eq!(read_u32_test(&zip, cd_cursor), CD_SIG);
            let name_len = read_u16_le(&zip, cd_cursor + 28).unwrap() as usize;
            let extra_len = read_u16_le(&zip, cd_cursor + 30).unwrap() as usize;
            let comment_len = read_u16_le(&zip, cd_cursor + 32).unwrap() as usize;
            let local_off = read_u32_test(&zip, cd_cursor + 42);
            write_u32_test(&mut zip, cd_cursor + 42, local_off + prefix.len() as u32);
            cd_cursor += 46 + name_len + extra_len + comment_len;
        }
        zip
    }

    fn fixture_path(rel: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(rel)
    }

    fn appx_with_tampered_manifest(original: &[u8]) -> Vec<u8> {
        let mut source = ZipArchive::new(Cursor::new(original)).expect("open source appx");
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for i in 0..source.len() {
                let mut zf = source.by_index(i).expect("source entry");
                if zf.name().ends_with('/') || zf.name().ends_with('\\') {
                    continue;
                }
                let name = zf.name().to_owned();
                let mut data = Vec::new();
                zf.read_to_end(&mut data).expect("read source entry");
                if name == "AppxManifest.xml" {
                    data = b"tampered manifest".to_vec();
                }
                writer.start_file(name, options).expect("start entry");
                writer.write_all(&data).expect("write entry");
            }
            writer.finish().expect("finish appx");
        }
        out.into_inner()
    }

    #[test]
    fn parse_appx_blob_roundtrip_widths() {
        let mut blob = Vec::from(SIG_APPX);
        let z = [7u8; 32];
        for t in [TAG_AXPC, TAG_AXCD, TAG_AXCT, TAG_AXBM] {
            blob.extend_from_slice(t);
            blob.extend_from_slice(&z);
        }
        let (ml, p) = parse_signed_appx_blob(&blob).unwrap();
        assert_eq!(ml, 32);
        assert!(p.axci.is_none());

        blob.extend_from_slice(TAG_AXCI);
        blob.extend_from_slice(&z);
        let (ml2, p2) = parse_signed_appx_blob(&blob).unwrap();
        assert_eq!(ml2, 32);
        assert!(p2.axci.is_some());
    }

    #[test]
    fn hash_method_parses_sha256_uri() {
        let xml = br#"<?xml version="1.0"?><BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256" />"#;
        assert_eq!(
            parse_block_map_xml(xml).unwrap().0,
            PeAuthenticodeHashKind::Sha256
        );
    }

    #[test]
    fn block_map_parser_rejects_file_outside_root_and_duplicate_root() {
        let file_outside_root = br#"<File Name="payload.txt" Size="1"><Block Hash="AAAA"/></File>"#;
        let err = parse_block_map_xml(file_outside_root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("File outside BlockMap"), "{msg}");

        let duplicate_root = br#"<BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256" /><BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256" />"#;
        let err = parse_block_map_xml(duplicate_root).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("duplicate"), "{msg}");
    }

    #[test]
    fn block_map_parser_rejects_missing_or_unsupported_hash_method() {
        let missing = br#"<BlockMap><File Name="payload.txt" Size="1"><Block Hash="AAAA"/></File></BlockMap>"#;
        let err = parse_block_map_xml(missing).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("HashMethod"), "{msg}");

        let unsupported = br#"<BlockMap HashMethod="http://example.invalid/sha3-256"><File Name="payload.txt" Size="1"><Block Hash="AAAA"/></File></BlockMap>"#;
        let err = parse_block_map_xml(unsupported).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported"), "{msg}");
    }

    #[test]
    fn content_types_validation_rejects_malformed_overrides() {
        let no_absolute_part = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/></Types>"#;
        let err = validate_content_types_xml(no_absolute_part).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("not absolute"), "{msg}");

        let duplicate_default = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="a"/><Default Extension="XML" ContentType="b"/></Types>"#;
        let err = validate_content_types_xml(duplicate_default).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("duplicate"), "{msg}");
    }

    #[test]
    fn content_types_validation_rejects_text_and_code_integrity_mismatch() {
        let text = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">not allowed</Types>"#;
        let err = validate_content_types_xml(text).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("non-whitespace text"), "{msg}");

        let xml = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/><Override PartName="/AppxSignature.p7x" ContentType="application/vnd.ms-appx.signature"/><Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/><Override PartName="/AppxMetadata/CodeIntegrity.cat" ContentType="application/octet-stream"/></Types>"#;
        let content_types = validate_content_types_xml(xml).unwrap();
        let inventory = AppxPackageInventory {
            has_code_integrity: true,
        };
        let err = validate_reserved_content_types(&content_types, inventory, "appx").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("CodeIntegrity.cat"), "{msg}");
    }

    #[test]
    fn content_types_validation_rejects_reserved_content_type_mismatch() {
        let xml = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Override PartName="/AppxBlockMap.xml" ContentType="application/xml"/><Override PartName="/AppxSignature.p7x" ContentType="application/vnd.ms-appx.signature"/></Types>"#;
        let content_types = validate_content_types_xml(xml).unwrap();
        let inventory = AppxPackageInventory {
            has_code_integrity: false,
        };
        let err = validate_reserved_content_types(&content_types, inventory, "appx").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("AppxBlockMap.xml"), "{msg}");

        let missing_manifest_type = br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/><Override PartName="/AppxSignature.p7x" ContentType="application/vnd.ms-appx.signature"/></Types>"#;
        let content_types = validate_content_types_xml(missing_manifest_type).unwrap();
        let err = validate_reserved_content_types(&content_types, inventory, "appx").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("AppxManifest.xml"), "{msg}");
    }

    #[test]
    fn encrypted_msix_extension_is_detected() {
        assert!(is_encrypted_msix_extension("emsix"));
        assert!(is_encrypted_msix_extension("eappxbundle"));
        assert!(!is_encrypted_msix_extension("msix"));
    }

    #[test]
    fn verify_rejects_all_encrypted_msix_extensions() {
        let dir = std::env::temp_dir();
        for ext in ["eappx", "eappxbundle", "emsix", "emsixbundle"] {
            let p = dir.join(format!("psign_fake_encrypted.{ext}"));
            std::fs::write(&p, b"not-a-real-package").expect("write temp");
            let err = verify_msix_digest_consistency(&p).unwrap_err();
            let _ = std::fs::remove_file(&p);
            let msg = format!("{err:#}");
            assert!(
                msg.contains("encrypted") && msg.contains("Eappx"),
                "unexpected message for {ext}: {msg}"
            );
        }
    }

    #[test]
    fn zip_tail_rejects_trailing_garbage_after_eocd() {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        zip.extend_from_slice(b"trailing");
        let err = parse_zip_tail(&zip).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("central-directory") || msg.contains("EOCD"),
            "{msg}"
        );
    }

    #[test]
    fn zip_tail_rejects_multidisk_classic_eocd() {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let eocd = find_eocd_for_test(&zip);
        write_u16_test(&mut zip, eocd + 4, 1);
        let err = parse_zip_tail(&zip).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("multi-disk"), "unexpected message: {msg}");
    }

    #[test]
    fn zip_tail_rejects_zip64_sentinel_without_locator() {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let eocd = find_eocd_for_test(&zip);
        write_u32_test(&mut zip, eocd + 12, u32::MAX);
        let err = parse_zip_tail(&zip).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ZIP64") && msg.contains("locator"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn zip_tail_rejects_central_directory_extent_mismatch() {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let eocd = find_eocd_for_test(&zip);
        let cd_size = read_u32_test(&zip, eocd + 12);
        write_u32_test(&mut zip, eocd + 12, cd_size - 1);
        let err = parse_zip_tail(&zip).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("central directory extent"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn zip_layout_rejects_gap_before_central_directory() {
        let zip = zip_with_gap_before_central_directory();
        let tail = parse_zip_tail(&zip).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();
        let err = validate_zip_file_layout(&zip, &mut archive, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("gap before the central directory"), "{msg}");
    }

    #[test]
    fn zip_layout_rejects_gap_between_local_file_records() {
        let zip = zip_with_gap_between_local_files();
        let tail = parse_zip_tail(&zip).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();
        let err = validate_zip_file_layout(&zip, &mut archive, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("gap between local file records"), "{msg}");
    }

    #[test]
    fn zip_layout_rejects_central_directory_file_comments() {
        let zip = zip_with_central_directory_file_comment();
        let tail = parse_zip_tail(&zip).unwrap();
        let err = validate_central_directory_records(&zip, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("file comments"), "{msg}");
    }

    #[test]
    fn zip_layout_rejects_leading_bytes_before_first_local_file() {
        let zip = zip_with_leading_bytes();
        let tail = parse_zip_tail(&zip).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();
        let err = validate_zip_file_layout(&zip, &mut archive, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("leading bytes"), "{msg}");
    }

    #[test]
    fn zip_layout_rejects_local_and_central_name_mismatch() {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let local = first_local_header_offset(&zip);
        let name_start = local + 30;
        zip[name_start] = b'b';

        let tail = parse_zip_tail(&zip).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();
        let err = validate_zip_file_layout(&zip, &mut archive, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("local file name"), "{msg}");
    }

    #[test]
    fn zip_layout_rejects_local_crc_and_size_mismatch() {
        let mut crc_zip = zip_with_entries(&[("a.txt", b"a")]);
        let local = first_local_header_offset(&crc_zip);
        write_u32_test(&mut crc_zip, local + 14, 0x1234_5678);
        let tail = parse_zip_tail(&crc_zip).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(crc_zip.as_slice())).unwrap();
        let err = validate_zip_file_layout(&crc_zip, &mut archive, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("CRC"), "{msg}");

        let mut size_zip = zip_with_entries(&[("a.txt", b"a")]);
        let local = first_local_header_offset(&size_zip);
        write_u32_test(&mut size_zip, local + 22, 99);
        let tail = parse_zip_tail(&size_zip).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(size_zip.as_slice())).unwrap();
        let err = validate_zip_file_layout(&size_zip, &mut archive, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("uncompressed size"), "{msg}");
    }

    #[test]
    fn zip_layout_rejects_encrypted_or_unsupported_compression_bits() {
        let mut encrypted = zip_with_entries(&[("a.txt", b"a")]);
        let cd = first_central_directory_offset(&encrypted);
        let local = first_local_header_offset(&encrypted);
        write_u16_test(&mut encrypted, cd + 8, 1);
        write_u16_test(&mut encrypted, local + 6, 1);
        let tail = parse_zip_tail(&encrypted).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(encrypted.as_slice())).unwrap();
        let err = validate_zip_file_layout(&encrypted, &mut archive, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("encrypted ZIP"), "{msg}");

        let mut unsupported = zip_with_entries(&[("a.txt", b"a")]);
        let cd = first_central_directory_offset(&unsupported);
        let local = first_local_header_offset(&unsupported);
        write_u16_test(&mut unsupported, cd + 10, 99);
        write_u16_test(&mut unsupported, local + 8, 99);
        let tail = parse_zip_tail(&unsupported).unwrap();
        let err = validate_central_directory_records(&unsupported, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported ZIP compression"), "{msg}");
    }

    #[test]
    fn zip_layout_rejects_central_directory_entry_count_mismatch() {
        let mut zip = zip_with_entries(&[("a.txt", b"a")]);
        let eocd = find_eocd_for_test(&zip);
        write_u16_test(&mut zip, eocd + 8, 2);
        write_u16_test(&mut zip, eocd + 10, 2);

        let tail = parse_zip_tail(&zip).unwrap();
        let err = validate_central_directory_records(&zip, &tail).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("entry count"), "{msg}");
    }

    #[test]
    fn package_inventory_rejects_missing_required_and_noncanonical_reserved_parts() {
        let missing_manifest = zip_with_entries(&[
            ("[Content_Types].xml", b""),
            ("AppxBlockMap.xml", b""),
            ("AppxSignature.p7x", b""),
        ]);
        let archive = ZipArchive::new(Cursor::new(missing_manifest.as_slice())).unwrap();
        let err = validate_package_part_inventory(&archive, "appx").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("AppxManifest.xml"), "{msg}");

        let wrong_case = zip_with_entries(&[
            ("[Content_Types].xml", b""),
            ("AppxBlockMap.xml", b""),
            ("AppxSignature.p7x", b""),
            ("appxmanifest.xml", b""),
        ]);
        let archive = ZipArchive::new(Cursor::new(wrong_case.as_slice())).unwrap();
        let err = validate_package_part_inventory(&archive, "appx").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("canonical path"), "{msg}");
    }

    #[test]
    fn package_inventory_rejects_case_colliding_parts_and_encrypted_bundle_children() {
        let duplicate_payload = zip_with_entries(&[
            ("[Content_Types].xml", b""),
            ("AppxBlockMap.xml", b""),
            ("AppxSignature.p7x", b""),
            ("AppxManifest.xml", b""),
            ("payload.txt", b""),
            ("Payload.txt", b""),
        ]);
        let archive = ZipArchive::new(Cursor::new(duplicate_payload.as_slice())).unwrap();
        let err = validate_package_part_inventory(&archive, "appx").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("case-insensitive"), "{msg}");

        let encrypted_child = zip_with_entries(&[
            ("[Content_Types].xml", b""),
            ("AppxBlockMap.xml", b""),
            ("AppxSignature.p7x", b""),
            ("AppxMetadata/AppxBundleManifest.xml", b""),
            ("child.emsix", b""),
        ]);
        let archive = ZipArchive::new(Cursor::new(encrypted_child.as_slice())).unwrap();
        let err = validate_package_part_inventory(&archive, "appxbundle").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("encrypted child"), "{msg}");
    }

    #[test]
    fn block_map_validation_accepts_matching_payload_hash() {
        let payload = b"manifest bytes";
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, payload);
        let block_map = block_map_xml_for_file("AppxManifest.xml", payload.len(), &hash);
        let (kind, files) = parse_block_map_xml(&block_map).unwrap();
        let zip = zip_with_entries(&[("AppxManifest.xml", payload)]);

        validate_block_map_file_hashes(&zip, kind, &files).unwrap();
    }

    #[test]
    fn block_map_validation_accepts_multiple_payload_blocks() {
        let mut payload = vec![0x41; APPX_BLOCK_SIZE + 17];
        payload[APPX_BLOCK_SIZE] = 0x42;
        let first = hash_bytes(PeAuthenticodeHashKind::Sha256, &payload[..APPX_BLOCK_SIZE]);
        let second = hash_bytes(PeAuthenticodeHashKind::Sha256, &payload[APPX_BLOCK_SIZE..]);
        let first_b64 = base64::engine::general_purpose::STANDARD.encode(first);
        let second_b64 = base64::engine::general_purpose::STANDARD.encode(second);
        let block_map = format!(
            r#"<?xml version="1.0"?><BlockMap HashMethod="{HASH_SHA256}"><File Name="large.bin" Size="{}"><Block Hash="{first_b64}"/><Block Hash="{second_b64}"/></File></BlockMap>"#,
            payload.len()
        );
        let (kind, files) = parse_block_map_xml(block_map.as_bytes()).unwrap();
        let zip = zip_with_entries(&[("large.bin", &payload)]);

        validate_block_map_file_hashes(&zip, kind, &files).unwrap();
    }

    #[test]
    fn block_map_validation_rejects_tampered_payload_hash() {
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, b"expected bytes");
        let block_map = block_map_xml_for_file("AppxManifest.xml", 14, &hash);
        let (kind, files) = parse_block_map_xml(&block_map).unwrap();
        let zip = zip_with_entries(&[("AppxManifest.xml", b"tampered bytes")]);

        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("hash mismatch"), "unexpected message: {msg}");
    }

    #[test]
    fn block_map_validation_rejects_declared_size_mismatch() {
        let payload = b"abc";
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, payload);
        let block_map = block_map_xml_for_file("AppxManifest.xml", 99, &hash);
        let (kind, files) = parse_block_map_xml(&block_map).unwrap();
        let zip = zip_with_entries(&[("AppxManifest.xml", payload)]);

        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Size 99"), "unexpected message: {msg}");
    }

    #[test]
    fn block_map_validation_rejects_missing_payload() {
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, b"abc");
        let block_map = block_map_xml_for_file("Missing.txt", 3, &hash);
        let (kind, files) = parse_block_map_xml(&block_map).unwrap();
        let zip = zip_with_entries(&[("Other.txt", b"abc")]);

        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing from package"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn block_map_validation_rejects_wrong_lfh_size() {
        let payload = b"abc";
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, payload);
        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);
        let block_map = format!(
            r#"<BlockMap HashMethod="{HASH_SHA256}"><File Name="payload.txt" Size="{}" LfhSize="999"><Block Hash="{hash_b64}"/></File></BlockMap>"#,
            payload.len()
        );
        let (kind, files) = parse_block_map_xml(block_map.as_bytes()).unwrap();
        let zip = zip_with_entries(&[("payload.txt", payload)]);

        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("LfhSize"), "{msg}");
    }

    #[test]
    fn block_map_validation_rejects_bad_block_size_attribute() {
        let payload = b"abc";
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, payload);
        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);
        let bad_size = format!(
            r#"<BlockMap HashMethod="{HASH_SHA256}"><File Name="payload.txt" Size="{}"><Block Hash="{hash_b64}" Size="not-a-number"/></File></BlockMap>"#,
            payload.len()
        );
        let err = parse_block_map_xml(bad_size.as_bytes()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid `Size`"), "{msg}");

        let zero_size = format!(
            r#"<BlockMap HashMethod="{HASH_SHA256}"><File Name="payload.txt" Size="{}"><Block Hash="{hash_b64}" Size="0"/></File></BlockMap>"#,
            payload.len()
        );
        let (kind, files) = parse_block_map_xml(zero_size.as_bytes()).unwrap();
        let zip = zip_with_entries(&[("payload.txt", payload)]);
        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("zero Size"), "{msg}");
    }

    #[test]
    fn block_map_validation_rejects_metadata_and_block_count_mismatches() {
        let metadata_payload = b"metadata is not payload";
        let metadata_hash = hash_bytes(PeAuthenticodeHashKind::Sha256, metadata_payload);
        let metadata_block_map =
            block_map_xml_for_file("AppxBlockMap.xml", metadata_payload.len(), &metadata_hash);
        let (kind, files) = parse_block_map_xml(&metadata_block_map).unwrap();
        let zip = zip_with_entries(&[("AppxBlockMap.xml", metadata_payload)]);
        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("metadata part"), "{msg}");

        let content_without_hashes =
            br#"<BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"><File Name="payload.txt" Size="3"/></BlockMap>"#;
        let (kind, files) = parse_block_map_xml(content_without_hashes).unwrap();
        let zip = zip_with_entries(&[("payload.txt", b"abc")]);
        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no block hashes"), "{msg}");

        let empty_hash = hash_bytes(PeAuthenticodeHashKind::Sha256, b"");
        let empty_with_hashes = block_map_xml_for_file("empty.txt", 0, &empty_hash);
        let (kind, files) = parse_block_map_xml(&empty_with_hashes).unwrap();
        let zip = zip_with_entries(&[("empty.txt", b"")]);
        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("empty but has block hashes"), "{msg}");

        let payload = b"abc";
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, payload);
        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);
        let too_many = format!(
            r#"<BlockMap HashMethod="{HASH_SHA256}"><File Name="payload.txt" Size="{}"><Block Hash="{hash_b64}"/><Block Hash="{hash_b64}"/></File></BlockMap>"#,
            payload.len()
        );
        let (kind, files) = parse_block_map_xml(too_many.as_bytes()).unwrap();
        let zip = zip_with_entries(&[("payload.txt", payload)]);
        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("too many block hashes"), "{msg}");
    }

    #[test]
    fn block_map_validation_rejects_duplicate_zip_names_after_normalization() {
        let payload = b"abc";
        let hash = hash_bytes(PeAuthenticodeHashKind::Sha256, payload);
        let block_map = block_map_xml_for_file("dir/file.txt", payload.len(), &hash);
        let (kind, files) = parse_block_map_xml(&block_map).unwrap();
        let zip = zip_with_entries(&[("dir/file.txt", payload), ("dir\\file.txt", payload)]);

        let err = validate_block_map_file_hashes(&zip, kind, &files).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("duplicate ZIP entry"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn block_map_parser_rejects_traversal_names_and_bad_hashes() {
        let traversal = br#"<?xml version="1.0"?><BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"><File Name="..\evil.txt" Size="1"><Block Hash="AAAA"/></File></BlockMap>"#;
        let err = parse_block_map_xml(traversal).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("invalid path segment"),
            "unexpected message: {msg}"
        );

        let bad_hash = br#"<?xml version="1.0"?><BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"><File Name="ok.txt" Size="1"><Block Hash="not-base64!"/></File></BlockMap>"#;
        let err = parse_block_map_xml(bad_hash).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("base64"), "unexpected message: {msg}");
    }

    #[test]
    fn signed_appxbundle_fixture_recursively_verifies_child_package() {
        let bundle = fixture_path("tests/fixtures/generated-signed/msix/sample.appxbundle");
        verify_msix_digest_consistency(&bundle).unwrap();
    }

    #[test]
    fn bundle_child_package_validation_rejects_stale_child_signature() {
        let child_path = fixture_path("tests/fixtures/generated-signed/msix/sample.appx");
        let child = std::fs::read(child_path).expect("read child appx fixture");
        let tampered_child = appx_with_tampered_manifest(&child);
        let bundle = zip_with_entries(&[("tampered.appx", &tampered_child)]);

        let err = verify_bundle_child_packages(&bundle).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("bundle child package `tampered.appx`"),
            "unexpected message: {msg}"
        );
    }
}
