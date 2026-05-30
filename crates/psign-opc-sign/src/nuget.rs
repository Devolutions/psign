use crate::opc::{
    PackageSummary, current_zip_datetime, inspect_package_path, normalize_zip_part_name,
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;
use zip::write::FileOptions;

pub const PACKAGE_SIGNATURE_FILE_NAME: &str = ".signature.p7s";
pub const SIGNATURE_CONTENT_VERSION: &str = "1";

fn nuget_zip_options(compression: zip::CompressionMethod, modified: zip::DateTime) -> FileOptions {
    FileOptions::default()
        .compression_method(compression)
        .last_modified_time(modified)
}

fn normalize_nuget_zip_metadata(bytes: &mut [u8]) -> Result<()> {
    let eocd = bytes
        .windows(4)
        .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
        .ok_or_else(|| anyhow!("ZIP central directory end not found"))?;
    if eocd + 22 > bytes.len() {
        return Err(anyhow!("truncated ZIP central directory end"));
    }

    let central_dir_size = u32::from_le_bytes(
        bytes[eocd + 12..eocd + 16]
            .try_into()
            .expect("central directory size slice"),
    ) as usize;
    let central_dir_offset = u32::from_le_bytes(
        bytes[eocd + 16..eocd + 20]
            .try_into()
            .expect("central directory offset slice"),
    ) as usize;
    let central_dir_end = central_dir_offset
        .checked_add(central_dir_size)
        .ok_or_else(|| anyhow!("ZIP central directory size overflow"))?;
    if central_dir_end > bytes.len() {
        return Err(anyhow!("ZIP central directory extends past end of file"));
    }

    let mut pos = central_dir_offset;
    while pos < central_dir_end {
        if pos + 46 > bytes.len() || bytes[pos..pos + 4] != [0x50, 0x4b, 0x01, 0x02] {
            return Err(anyhow!("invalid ZIP central directory entry"));
        }
        bytes[pos + 5] = 0;
        bytes[pos + 38..pos + 42].fill(0);

        let name_len = u16::from_le_bytes(
            bytes[pos + 28..pos + 30]
                .try_into()
                .expect("file name length slice"),
        ) as usize;
        let extra_len = u16::from_le_bytes(
            bytes[pos + 30..pos + 32]
                .try_into()
                .expect("extra field length slice"),
        ) as usize;
        let comment_len = u16::from_le_bytes(
            bytes[pos + 32..pos + 34]
                .try_into()
                .expect("file comment length slice"),
        ) as usize;
        pos = pos
            .checked_add(46)
            .and_then(|n| n.checked_add(name_len))
            .and_then(|n| n.checked_add(extra_len))
            .and_then(|n| n.checked_add(comment_len))
            .ok_or_else(|| anyhow!("ZIP central directory entry size overflow"))?;
    }
    if pos != central_dir_end {
        return Err(anyhow!("ZIP central directory entry length mismatch"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NuGetHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl NuGetHashAlgorithm {
    pub fn oid(self) -> &'static str {
        match self {
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub fn hash(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }

    pub fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "2.16.840.1.101.3.4.2.1" => Some(Self::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(Self::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(Self::Sha512),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NuGetPackageInfo {
    pub package: PackageSummary,
    pub signed: bool,
    pub signature_len: Option<u64>,
    pub signature_is_stored: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NuGetSignatureContent {
    pub hash_algorithm: NuGetHashAlgorithm,
    pub package_hash: Vec<u8>,
}

pub fn inspect_nupkg_path(path: &Path) -> Result<NuGetPackageInfo> {
    let package = inspect_package_path(path)?;
    let signature_len = package
        .entry(PACKAGE_SIGNATURE_FILE_NAME)
        .map(|e| e.uncompressed_size);
    let signature_is_stored = package
        .entry(PACKAGE_SIGNATURE_FILE_NAME)
        .map(|e| e.compression == "Stored");
    Ok(NuGetPackageInfo {
        package,
        signed: signature_len.is_some(),
        signature_len,
        signature_is_stored,
    })
}

pub fn unsigned_package_digest_path(path: &Path, algorithm: NuGetHashAlgorithm) -> Result<Vec<u8>> {
    let info = inspect_nupkg_path(path)?;
    if info.signed {
        return Err(anyhow!(
            "{} already contains {}; remove or overwrite the signature before computing the unsigned package digest",
            path.display(),
            PACKAGE_SIGNATURE_FILE_NAME
        ));
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(algorithm.hash(&bytes))
}

pub fn canonical_unsigned_package_bytes_path(path: &Path) -> Result<Vec<u8>> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    canonical_unsigned_package_bytes(reader)
        .with_context(|| format!("canonicalize unsigned NuGet package {}", path.display()))
}

pub fn canonical_unsigned_package_bytes<R>(reader: R) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    let mut out = std::io::Cursor::new(Vec::new());
    write_package_without_signature_impl(reader, &mut out, false)?;
    Ok(out.into_inner())
}

pub fn signed_package_unsigned_bytes_path(path: &Path) -> Result<Vec<u8>> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut out = std::io::Cursor::new(Vec::new());
    write_package_without_signature_impl(reader, &mut out, true)
        .with_context(|| format!("remove NuGet signature from {}", path.display()))?;
    Ok(out.into_inner())
}

pub fn signed_package_signature_content_path(
    path: &Path,
    algorithm: NuGetHashAlgorithm,
) -> Result<Vec<u8>> {
    let unsigned = signed_package_unsigned_bytes_path(path)?;
    Ok(signature_content_bytes(
        algorithm,
        &algorithm.hash(&unsigned),
    ))
}

pub fn package_hash_property_name(algorithm: NuGetHashAlgorithm) -> String {
    format!("{}-Hash", algorithm.oid())
}

pub fn unsigned_package_signature_content_path(
    path: &Path,
    algorithm: NuGetHashAlgorithm,
) -> Result<Vec<u8>> {
    let unsigned = canonical_unsigned_package_bytes_path(path)?;
    let digest = algorithm.hash(&unsigned);
    Ok(signature_content_bytes(algorithm, &digest))
}

pub fn signature_content_bytes(algorithm: NuGetHashAlgorithm, package_hash: &[u8]) -> Vec<u8> {
    format!(
        "Version:{}\n\n{}:{}\n\n",
        SIGNATURE_CONTENT_VERSION,
        package_hash_property_name(algorithm),
        BASE64_STANDARD.encode(package_hash)
    )
    .into_bytes()
}

pub fn parse_signature_content(bytes: &[u8]) -> Result<NuGetSignatureContent> {
    let text = std::str::from_utf8(bytes).context("NuGet signature content is not UTF-8")?;
    let mut sections = text.split("\n\n");
    let header = sections
        .next()
        .ok_or_else(|| anyhow!("NuGet signature content is missing header section"))?;
    let hash_section = sections
        .next()
        .ok_or_else(|| anyhow!("NuGet signature content is missing package hash section"))?;

    let mut version = None;
    for line in header.lines().filter(|line| !line.is_empty()) {
        let (key, value) = split_signature_content_pair(line)?;
        if key == "Version" {
            version = Some(value);
        }
    }
    match version {
        Some(SIGNATURE_CONTENT_VERSION) => {}
        Some(value) => {
            return Err(anyhow!(
                "unsupported NuGet signature content version {value}; expected {SIGNATURE_CONTENT_VERSION}"
            ));
        }
        None => return Err(anyhow!("NuGet signature content is missing Version")),
    }

    for line in hash_section.lines().filter(|line| !line.is_empty()) {
        let (key, value) = split_signature_content_pair(line)?;
        if let Some(oid) = key.strip_suffix("-Hash")
            && let Some(hash_algorithm) = NuGetHashAlgorithm::from_oid(oid)
        {
            let package_hash = BASE64_STANDARD
                .decode(value)
                .context("NuGet signature content package hash is not valid base64")?;
            if package_hash.is_empty() {
                return Err(anyhow!("NuGet signature content package hash is empty"));
            }
            return Ok(NuGetSignatureContent {
                hash_algorithm,
                package_hash,
            });
        }
    }

    Err(anyhow!(
        "NuGet signature content does not contain a supported package hash property"
    ))
}

pub fn verify_unsigned_package_signature_content_path(
    path: &Path,
    content: &[u8],
) -> Result<NuGetSignatureContent> {
    let parsed = parse_signature_content(content)?;
    let unsigned = canonical_unsigned_package_bytes_path(path)?;
    let actual = parsed.hash_algorithm.hash(&unsigned);
    if actual != parsed.package_hash {
        return Err(anyhow!(
            "NuGet package hash mismatch for {}; signature content records a different unsigned package digest",
            path.display()
        ));
    }
    Ok(parsed)
}

pub fn extract_signature_path(path: &Path) -> Result<Vec<u8>> {
    let reader = File::open(path).with_context(|| format!("open {}", path.display()))?;
    extract_signature(reader)
        .with_context(|| format!("extract NuGet signature from {}", path.display()))
}

pub fn extract_signature<R>(reader: R) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    let mut input = zip::ZipArchive::new(reader).context("open NuGet ZIP")?;
    let mut file = input
        .by_name(PACKAGE_SIGNATURE_FILE_NAME)
        .with_context(|| format!("package does not contain {PACKAGE_SIGNATURE_FILE_NAME}"))?;
    let mut signature = Vec::new();
    file.read_to_end(&mut signature)
        .context("read NuGet package signature")?;
    if signature.is_empty() {
        return Err(anyhow!("NuGet package signature payload is empty"));
    }
    Ok(signature)
}

pub fn write_package_without_signature<R, W>(reader: R, writer: W) -> Result<()>
where
    R: Read + Seek,
    W: Write + Seek,
{
    write_package_without_signature_impl(reader, writer, true)
}

fn write_package_without_signature_impl<R, W>(
    reader: R,
    mut writer: W,
    require_signature: bool,
) -> Result<()>
where
    R: Read + Seek,
    W: Write + Seek,
{
    let mut input = zip::ZipArchive::new(reader).context("open NuGet ZIP")?;
    let mut out = std::io::Cursor::new(Vec::new());
    let mut had_signature = false;

    {
        let mut output = zip::ZipWriter::new(&mut out);
        for i in 0..input.len() {
            let mut file = input.by_index(i).context("read NuGet ZIP entry")?;
            let name = normalize_zip_part_name(file.name())?;
            if name == PACKAGE_SIGNATURE_FILE_NAME {
                had_signature = true;
                continue;
            }

            let options = nuget_zip_options(file.compression(), file.last_modified());
            if file.is_dir() {
                output.add_directory(name, options)?;
            } else {
                output.start_file(name, options)?;
                std::io::copy(&mut file, &mut output)?;
            }
        }

        if require_signature && !had_signature {
            return Err(anyhow!(
                "package does not contain {PACKAGE_SIGNATURE_FILE_NAME}"
            ));
        }

        output.finish()?;
    }
    let mut bytes = out.into_inner();
    normalize_nuget_zip_metadata(&mut bytes)?;
    writer.write_all(&bytes)?;
    Ok(())
}

fn split_signature_content_pair(line: &str) -> Result<(&str, &str)> {
    line.split_once(':')
        .ok_or_else(|| anyhow!("invalid NuGet signature content line {line:?}"))
        .and_then(|(key, value)| {
            if key.is_empty() || value.is_empty() {
                Err(anyhow!("invalid NuGet signature content line {line:?}"))
            } else {
                Ok((key, value))
            }
        })
}

pub fn embed_signature_path(
    input: &Path,
    output: &Path,
    signature_der: &[u8],
    overwrite: bool,
) -> Result<()> {
    if signature_der.is_empty() {
        return Err(anyhow!("NuGet package signature payload is empty"));
    }
    let info = inspect_nupkg_path(input)?;
    if info.signed && !overwrite {
        return Err(anyhow!(
            "{} already contains {}; pass overwrite to replace it",
            input.display(),
            PACKAGE_SIGNATURE_FILE_NAME
        ));
    }
    let reader = File::open(input).with_context(|| format!("open {}", input.display()))?;
    let writer = File::create(output).with_context(|| format!("create {}", output.display()))?;
    embed_signature(reader, writer, signature_der, overwrite)
        .with_context(|| format!("embed NuGet signature into {}", output.display()))
}

pub fn embed_signature<R, W>(
    reader: R,
    mut writer: W,
    signature_der: &[u8],
    overwrite: bool,
) -> Result<()>
where
    R: Read + Seek,
    W: Write + Seek,
{
    if signature_der.is_empty() {
        return Err(anyhow!("NuGet package signature payload is empty"));
    }
    let mut input = zip::ZipArchive::new(reader).context("open NuGet ZIP")?;
    let mut out = std::io::Cursor::new(Vec::new());
    let mut had_signature = false;
    let signature_timestamp =
        current_zip_datetime().context("determine local ZIP timestamp for NuGet signature")?;

    {
        let mut output = zip::ZipWriter::new(&mut out);
        for i in 0..input.len() {
            let mut file = input.by_index(i).context("read NuGet ZIP entry")?;
            let name = normalize_zip_part_name(file.name())?;
            if name == PACKAGE_SIGNATURE_FILE_NAME {
                had_signature = true;
                if overwrite {
                    continue;
                }
                return Err(anyhow!(
                    "package already contains {}; pass overwrite to replace it",
                    PACKAGE_SIGNATURE_FILE_NAME
                ));
            }

            let options = nuget_zip_options(file.compression(), file.last_modified());
            if file.is_dir() {
                output.add_directory(name, options)?;
            } else {
                output.start_file(name, options)?;
                std::io::copy(&mut file, &mut output)?;
            }
        }

        if !had_signature || overwrite {
            output.start_file(
                PACKAGE_SIGNATURE_FILE_NAME,
                nuget_zip_options(zip::CompressionMethod::Stored, signature_timestamp),
            )?;
            output.write_all(signature_der)?;
        }

        output.finish()?;
    }
    let mut bytes = out.into_inner();
    normalize_nuget_zip_metadata(&mut bytes)?;
    writer.write_all(&bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::FileOptions;

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        zip_with_timestamps(
            &entries
                .iter()
                .map(|(name, bytes)| (*name, *bytes, zip::DateTime::default()))
                .collect::<Vec<_>>(),
        )
    }

    fn zip_with_timestamps(entries: &[(&str, &[u8], zip::DateTime)]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            for (name, bytes, modified) in entries {
                let options = if *name == PACKAGE_SIGNATURE_FILE_NAME {
                    FileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored)
                        .last_modified_time(*modified)
                } else {
                    FileOptions::default().last_modified_time(*modified)
                };
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        out.into_inner()
    }

    fn test_datetime(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> zip::DateTime {
        zip::DateTime::from_date_and_time(year, month, day, hour, minute, second)
            .expect("valid test timestamp")
    }

    fn zip_datetime_parts(dt: zip::DateTime) -> (u16, u8, u8, u8, u8, u8) {
        (
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
        )
    }

    fn eocd_offset(bytes: &[u8]) -> usize {
        bytes
            .windows(4)
            .rposition(|window| window == [0x50, 0x4b, 0x05, 0x06])
            .expect("EOCD")
    }

    fn central_directory_entries(bytes: &[u8]) -> Vec<(String, u8, u32)> {
        let eocd = eocd_offset(bytes);
        let central_dir_size =
            u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
        let central_dir_offset =
            u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let central_dir_end = central_dir_offset + central_dir_size;
        let mut entries = Vec::new();
        let mut pos = central_dir_offset;
        while pos < central_dir_end {
            assert_eq!(&bytes[pos..pos + 4], &[0x50, 0x4b, 0x01, 0x02]);
            let host_os = bytes[pos + 5];
            let external_attrs = u32::from_le_bytes(bytes[pos + 38..pos + 42].try_into().unwrap());
            let name_len =
                u16::from_le_bytes(bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(bytes[pos + 30..pos + 32].try_into().unwrap()) as usize;
            let comment_len =
                u16::from_le_bytes(bytes[pos + 32..pos + 34].try_into().unwrap()) as usize;
            let name = std::str::from_utf8(&bytes[pos + 46..pos + 46 + name_len])
                .expect("entry name")
                .to_owned();
            entries.push((name, host_os, external_attrs));
            pos += 46 + name_len + extra_len + comment_len;
        }
        entries
    }

    fn mark_central_directory_entries_as_unix(bytes: &mut [u8]) {
        let eocd = eocd_offset(bytes);
        let central_dir_size =
            u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) as usize;
        let central_dir_offset =
            u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let central_dir_end = central_dir_offset + central_dir_size;
        let mut pos = central_dir_offset;
        while pos < central_dir_end {
            bytes[pos + 5] = 3;
            bytes[pos + 38..pos + 42].copy_from_slice(&0xa1ed_0000u32.to_le_bytes());
            let name_len =
                u16::from_le_bytes(bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(bytes[pos + 30..pos + 32].try_into().unwrap()) as usize;
            let comment_len =
                u16::from_le_bytes(bytes[pos + 32..pos + 34].try_into().unwrap()) as usize;
            pos += 46 + name_len + extra_len + comment_len;
        }
    }

    fn assert_no_unix_central_directory_metadata(bytes: &[u8]) {
        for (name, host_os, external_attrs) in central_directory_entries(bytes) {
            assert_eq!(host_os, 0, "{name} host OS");
            assert_eq!(external_attrs, 0, "{name} external attributes");
        }
    }

    #[test]
    fn signature_file_name_is_case_sensitive() {
        let zip = zip_with(&[(PACKAGE_SIGNATURE_FILE_NAME, b"cms")]);
        let tmp = tempfile_path("signed.nupkg");
        std::fs::write(&tmp, zip).unwrap();

        let info = inspect_nupkg_path(&tmp).unwrap();

        assert!(info.signed);
        assert_eq!(info.signature_len, Some(3));
        assert_eq!(info.signature_is_stored, Some(true));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn hash_property_uses_nuget_oid() {
        assert_eq!(
            package_hash_property_name(NuGetHashAlgorithm::Sha256),
            "2.16.840.1.101.3.4.2.1-Hash"
        );
    }

    #[test]
    fn signature_content_round_trips_package_hash_property() {
        let bytes = signature_content_bytes(NuGetHashAlgorithm::Sha384, b"package-digest");

        let parsed = parse_signature_content(&bytes).unwrap();

        assert_eq!(parsed.hash_algorithm, NuGetHashAlgorithm::Sha384);
        assert_eq!(parsed.package_hash, b"package-digest");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "Version:1\n\n2.16.840.1.101.3.4.2.2-Hash:cGFja2FnZS1kaWdlc3Q=\n\n"
        );
    }

    #[test]
    fn signature_content_rejects_unsupported_version() {
        let err = parse_signature_content(
            b"Version:2\n\n2.16.840.1.101.3.4.2.1-Hash:cGFja2FnZS1kaWdlc3Q=\n\n",
        )
        .unwrap_err();

        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn unsigned_package_signature_content_verifies_matching_digest() {
        let zip = zip_with(&[("lib/net8.0/a.dll", b"pe")]);
        let tmp = tempfile_path("unsigned-for-content.nupkg");
        std::fs::write(&tmp, &zip).unwrap();

        let content =
            unsigned_package_signature_content_path(&tmp, NuGetHashAlgorithm::Sha256).unwrap();
        let parsed = verify_unsigned_package_signature_content_path(&tmp, &content).unwrap();
        let canonical = canonical_unsigned_package_bytes_path(&tmp).unwrap();

        assert_eq!(parsed.hash_algorithm, NuGetHashAlgorithm::Sha256);
        assert_eq!(
            parsed.package_hash,
            NuGetHashAlgorithm::Sha256.hash(&canonical)
        );
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn unsigned_package_signature_content_rejects_tampered_package() {
        let tmp = tempfile_path("tampered-for-content.nupkg");
        std::fs::write(&tmp, zip_with(&[("lib/net8.0/a.dll", b"pe")])).unwrap();
        let content =
            unsigned_package_signature_content_path(&tmp, NuGetHashAlgorithm::Sha256).unwrap();
        std::fs::write(&tmp, zip_with(&[("lib/net8.0/a.dll", b"changed")])).unwrap();

        let err = verify_unsigned_package_signature_content_path(&tmp, &content).unwrap_err();

        assert!(err.to_string().contains("hash mismatch"));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn embed_signature_adds_stored_root_signature() {
        let zip = zip_with(&[("lib/net8.0/a.dll", b"pe")]);
        let mut out = Cursor::new(Vec::new());

        embed_signature(Cursor::new(zip), &mut out, b"cms", false).unwrap();
        let signed = out.into_inner();
        let info = inspect_package_reader_for_test(signed.clone());

        assert_eq!(
            info.entry(PACKAGE_SIGNATURE_FILE_NAME)
                .map(|e| e.uncompressed_size),
            Some(3)
        );
        assert_eq!(
            info.entry(PACKAGE_SIGNATURE_FILE_NAME)
                .map(|e| e.compression.as_str()),
            Some("Stored")
        );
        assert_no_unix_central_directory_metadata(&signed);
        let mut archive = zip::ZipArchive::new(Cursor::new(signed)).unwrap();
        assert_eq!(
            archive
                .by_name(PACKAGE_SIGNATURE_FILE_NAME)
                .unwrap()
                .unix_mode(),
            None
        );
        assert_eq!(
            archive.by_name("lib/net8.0/a.dll").unwrap().unix_mode(),
            None
        );
    }

    #[test]
    fn embed_signature_preserves_existing_entry_timestamps() {
        let original = test_datetime(2001, 2, 3, 4, 5, 6);
        let zip = zip_with_timestamps(&[("lib/net8.0/a.dll", b"pe", original)]);
        let mut out = Cursor::new(Vec::new());

        embed_signature(Cursor::new(zip), &mut out, b"cms", false).unwrap();

        let mut archive = zip::ZipArchive::new(Cursor::new(out.into_inner())).unwrap();
        assert_eq!(
            zip_datetime_parts(archive.by_name("lib/net8.0/a.dll").unwrap().last_modified()),
            zip_datetime_parts(original)
        );
        assert_ne!(
            zip_datetime_parts(
                archive
                    .by_name(PACKAGE_SIGNATURE_FILE_NAME)
                    .unwrap()
                    .last_modified()
            ),
            zip_datetime_parts(zip::DateTime::default())
        );
    }

    #[test]
    fn embed_signature_rejects_existing_signature_without_overwrite() {
        let zip = zip_with(&[(PACKAGE_SIGNATURE_FILE_NAME, b"old")]);
        let err =
            embed_signature(Cursor::new(zip), Cursor::new(Vec::new()), b"new", false).unwrap_err();

        assert!(err.to_string().contains("already contains"));
    }

    #[test]
    fn embed_signature_replaces_existing_signature_with_overwrite() {
        let zip = zip_with(&[(PACKAGE_SIGNATURE_FILE_NAME, b"old")]);
        let mut out = Cursor::new(Vec::new());

        embed_signature(Cursor::new(zip), &mut out, b"new-signature", true).unwrap();
        let info = inspect_package_reader_for_test(out.into_inner());

        assert_eq!(
            info.entry(PACKAGE_SIGNATURE_FILE_NAME)
                .map(|e| e.uncompressed_size),
            Some(13)
        );
    }

    #[test]
    fn extract_signature_returns_embedded_signature_bytes() {
        let zip = zip_with(&[
            ("lib/net8.0/a.dll", b"pe"),
            (PACKAGE_SIGNATURE_FILE_NAME, b"cms"),
        ]);

        let signature = extract_signature(Cursor::new(zip)).unwrap();

        assert_eq!(signature, b"cms");
    }

    #[test]
    fn write_package_without_signature_removes_root_signature() {
        let zip = zip_with(&[
            ("lib/net8.0/a.dll", b"pe"),
            (PACKAGE_SIGNATURE_FILE_NAME, b"cms"),
        ]);
        let mut out = Cursor::new(Vec::new());

        write_package_without_signature(Cursor::new(zip), &mut out).unwrap();
        let info = inspect_package_reader_for_test(out.into_inner());

        assert!(info.entry(PACKAGE_SIGNATURE_FILE_NAME).is_none());
        assert_eq!(
            info.entry("lib/net8.0/a.dll").map(|e| e.uncompressed_size),
            Some(2)
        );
    }

    #[test]
    fn write_package_without_signature_preserves_existing_entry_timestamps() {
        let original = test_datetime(2004, 5, 6, 7, 8, 10);
        let zip = zip_with_timestamps(&[
            ("lib/net8.0/a.dll", b"pe", original),
            (
                PACKAGE_SIGNATURE_FILE_NAME,
                b"cms",
                test_datetime(2005, 6, 7, 8, 9, 10),
            ),
        ]);
        let mut out = Cursor::new(Vec::new());

        write_package_without_signature(Cursor::new(zip), &mut out).unwrap();

        let mut archive = zip::ZipArchive::new(Cursor::new(out.into_inner())).unwrap();
        assert_eq!(
            zip_datetime_parts(archive.by_name("lib/net8.0/a.dll").unwrap().last_modified()),
            zip_datetime_parts(original)
        );
    }

    #[test]
    fn embed_signature_clears_unix_central_directory_metadata() {
        let mut zip = zip_with(&[("lib/net8.0/a.dll", b"pe")]);
        mark_central_directory_entries_as_unix(&mut zip);
        assert!(
            central_directory_entries(&zip)
                .iter()
                .any(|(_, host_os, attrs)| *host_os == 3 && *attrs != 0)
        );
        let mut out = Cursor::new(Vec::new());

        embed_signature(Cursor::new(zip), &mut out, b"cms", false).unwrap();
        let signed = out.into_inner();

        assert_no_unix_central_directory_metadata(&signed);
    }

    #[test]
    fn write_package_without_signature_clears_unix_central_directory_metadata() {
        let mut zip = zip_with(&[
            ("lib/net8.0/a.dll", b"pe"),
            (PACKAGE_SIGNATURE_FILE_NAME, b"cms"),
        ]);
        mark_central_directory_entries_as_unix(&mut zip);
        let mut out = Cursor::new(Vec::new());

        write_package_without_signature(Cursor::new(zip), &mut out).unwrap();
        let unsigned = out.into_inner();

        assert_no_unix_central_directory_metadata(&unsigned);
    }

    #[test]
    fn canonical_unsigned_package_rejects_truncated_central_directory() {
        let mut zip = zip_with(&[("lib/net8.0/a.dll", b"pe")]);
        let eocd = eocd_offset(&zip);
        zip[eocd + 12..eocd + 16].copy_from_slice(&u32::MAX.to_le_bytes());

        let err = normalize_nuget_zip_metadata(&mut zip).unwrap_err();

        assert!(err.to_string().contains("central directory"));
    }

    fn inspect_package_reader_for_test(bytes: Vec<u8>) -> PackageSummary {
        crate::opc::inspect_package_reader(Cursor::new(bytes)).unwrap()
    }

    fn tempfile_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("psign-opc-sign-{}-{name}", std::process::id()));
        path
    }
}
