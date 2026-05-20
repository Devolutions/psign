use crate::opc::{PackageSummary, inspect_package_path};
use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::path::Path;

pub const PACKAGE_SIGNATURE_FILE_NAME: &str = ".signature.p7s";

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NuGetPackageInfo {
    pub package: PackageSummary,
    pub signed: bool,
    pub signature_len: Option<u64>,
    pub signature_is_stored: Option<bool>,
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

pub fn package_hash_property_name(algorithm: NuGetHashAlgorithm) -> String {
    format!("{}-Hash", algorithm.oid())
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
            for (name, bytes) in entries {
                let options = if *name == PACKAGE_SIGNATURE_FILE_NAME {
                    FileOptions::default().compression_method(zip::CompressionMethod::Stored)
                } else {
                    FileOptions::default()
                };
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        out.into_inner()
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

    fn tempfile_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("psign-opc-sign-{}-{name}", std::process::id()));
        path
    }
}
