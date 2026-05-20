use anyhow::{Context, Result, anyhow};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use zip::ZipArchive;

pub const CONTENT_TYPES_PART: &str = "[Content_Types].xml";
pub const ROOT_RELATIONSHIPS_PART: &str = "_rels/.rels";
pub const OPC_SIGNATURE_ORIGIN_PART: &str = "package/services/digital-signature/origin.psdsor";
pub const OPC_SIGNATURES_PREFIX: &str = "package/services/digital-signature/xml-signature/";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageEntry {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub is_dir: bool,
    pub compression: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSummary {
    pub entries: Vec<PackageEntry>,
    pub has_content_types: bool,
    pub has_root_relationships: bool,
    pub has_opc_signature_origin: bool,
    pub opc_signature_parts: Vec<String>,
}

impl PackageSummary {
    pub fn contains_entry(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }

    pub fn entry(&self, name: &str) -> Option<&PackageEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

pub fn inspect_package_path(path: &Path) -> Result<PackageSummary> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    inspect_package_reader(file).with_context(|| format!("inspect OPC ZIP {}", path.display()))
}

pub fn inspect_package_reader<R>(reader: R) -> Result<PackageSummary>
where
    R: Read + Seek,
{
    let mut archive = ZipArchive::new(reader).context("open ZIP archive")?;
    let mut entries = Vec::with_capacity(archive.len());
    let mut has_content_types = false;
    let mut has_root_relationships = false;
    let mut has_opc_signature_origin = false;
    let mut opc_signature_parts = Vec::new();

    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .context("read ZIP central directory entry")?;
        let name = normalize_zip_part_name(file.name())?;
        has_content_types |= name == CONTENT_TYPES_PART;
        has_root_relationships |= name == ROOT_RELATIONSHIPS_PART;
        has_opc_signature_origin |= name == OPC_SIGNATURE_ORIGIN_PART;
        if name.starts_with(OPC_SIGNATURES_PREFIX)
            && name != OPC_SIGNATURE_ORIGIN_PART
            && !file.is_dir()
        {
            opc_signature_parts.push(name.clone());
        }
        entries.push(PackageEntry {
            name,
            compressed_size: file.compressed_size(),
            uncompressed_size: file.size(),
            is_dir: file.is_dir(),
            compression: format!("{:?}", file.compression()),
        });
    }

    opc_signature_parts.sort();
    Ok(PackageSummary {
        entries,
        has_content_types,
        has_root_relationships,
        has_opc_signature_origin,
        opc_signature_parts,
    })
}

pub fn normalize_zip_part_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(anyhow!("ZIP entry name is empty"));
    }
    if name.starts_with('/') {
        return Err(anyhow!("ZIP entry name must be relative: {name}"));
    }
    if name.contains('\\') {
        return Err(anyhow!("ZIP entry name must use '/' separators: {name}"));
    }
    if name
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(anyhow!("ZIP entry name contains dot segment: {name}"));
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::FileOptions;

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
    fn detects_opc_signature_parts() {
        let zip = zip_with(&[
            (CONTENT_TYPES_PART, br#"<Types/>"#),
            (ROOT_RELATIONSHIPS_PART, br#"<Relationships/>"#),
            (OPC_SIGNATURE_ORIGIN_PART, b""),
            (
                "package/services/digital-signature/xml-signature/sig1.psdsxs",
                br#"<Signature/>"#,
            ),
        ]);

        let summary = inspect_package_reader(Cursor::new(zip)).unwrap();

        assert!(summary.has_content_types);
        assert!(summary.has_root_relationships);
        assert!(summary.has_opc_signature_origin);
        assert_eq!(
            summary.opc_signature_parts,
            ["package/services/digital-signature/xml-signature/sig1.psdsxs"]
        );
    }

    #[test]
    fn rejects_backslash_entry_names() {
        let err = normalize_zip_part_name(r"_rels\.rels").unwrap_err();
        assert!(err.to_string().contains("separators"));
    }
}
